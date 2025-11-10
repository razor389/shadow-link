// src/network/client.rs

use log::{error, info, warn};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};

use crate::network::framing::{read_message, write_message};
use crate::network::routing::api::RoutingService;
use crate::types::address::{PrivateAddress, PublicAddress};
use crate::types::argon2_params::SerializableArgon2Params;
use crate::types::message::Message;
use crate::types::node_info::{NodeInfo, NodeInfoExtended};
use crate::types::packet::Packet;
use crate::types::routing_prefix::RoutingPrefix;

pub type VerificationKeyBytes = [u8; 32];

pub struct Client {
    private_address: PrivateAddress,
    /// Local routing service (e.g. cached DHT entries)
    routing_service: Arc<dyn RoutingService>,
    pub max_prefix_length: u8,
    pub min_argon2_params: SerializableArgon2Params,
    pub require_exact_argon2: bool,
    pub min_pow_difficulty: usize,
    pub connected_node: Option<NodeInfoExtended>,
    pub incoming_tx: mpsc::Sender<Packet>,
    pub incoming_rx: Mutex<mpsc::Receiver<Packet>>,
    messages_received: Arc<Mutex<HashMap<VerificationKeyBytes, Vec<Packet>>>>,
    pub bootstrap_node_address: SocketAddr,
}

impl Client {
    pub fn new(
        routing_service: Arc<dyn RoutingService>,
        prefix: Option<RoutingPrefix>,
        length: Option<u8>,
        max_prefix_length: u8,
        min_argon2_params: SerializableArgon2Params,
        require_exact_argon2: bool,
        bootstrap_node_address: SocketAddr,
        min_pow_difficulty: usize,
    ) -> Self {
        let private_address = PrivateAddress::new(prefix, length);
        info!(
            "Client created with public address {:?}",
            private_address.public_address
        );
        let (tx, rx) = mpsc::channel(100);

        Client {
            private_address,
            routing_service,
            max_prefix_length,
            min_argon2_params,
            require_exact_argon2,
            min_pow_difficulty,
            connected_node: None,
            incoming_tx: tx,
            incoming_rx: Mutex::new(rx),
            messages_received: Arc::new(Mutex::new(HashMap::new())),
            bootstrap_node_address,
        }
    }

    pub async fn find_connect_subscribe(&mut self) {
        // Perform handshake with the bootstrap node
        if let Some(_node_info) = self.handshake_with_node(self.bootstrap_node_address).await {
            // Send FindNodePrefix message with our address prefix
            let address_prefix = self.get_routing_prefix();
            if let Some(nodes) = self
                .send_find_serving_nodes_request(self.bootstrap_node_address, address_prefix)
                .await
            {
                // Select a node matching our preferences
                if let Some(best_node) = self.select_best_node(nodes).await {
                    // Handshake and subscribe to the selected node
                    if let Some(node_info) = self.handshake_with_node(best_node.address).await {
                        self.connected_node = Some(node_info.clone());
                        let _ = self.subscribe_and_receive_messages(node_info.address).await;
                        info!("Connected to node {:?}", node_info.address);
                    }
                } else {
                    warn!("No suitable nodes found matching preferences");
                }
            } else {
                error!("Failed to receive nodes from bootstrap node");
            }
        } else {
            error!("Failed to handshake with bootstrap node");
        }
    }

    /// Perform handshake with node
    pub async fn handshake_with_node(&self, node_address: SocketAddr) -> Option<NodeInfoExtended> {
        match TcpStream::connect(node_address).await {
            Ok(mut stream) => match Self::perform_client_handshake(&mut stream).await {
                Ok(node_info) => Some(node_info),
                Err(e) => {
                    error!("Handshake with {} failed: {:?}", node_address, e);
                    None
                }
            },
            Err(e) => {
                error!("Failed to connect to node {}: {:?}", node_address, e);
                None
            }
        }
    }

    async fn perform_client_handshake(stream: &mut TcpStream) -> io::Result<NodeInfoExtended> {
        write_message(stream, &Message::ClientHandshake).await?;
        match read_message(stream).await? {
            Message::ClientHandshakeAck(node_info) => Ok(node_info),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected handshake response",
            )),
        }
    }

    fn get_routing_prefix(&self) -> RoutingPrefix {
        self.private_address.public_address.prefix
    }

    async fn send_find_serving_nodes_request(
        &self,
        node_address: SocketAddr,
        routing_prefix: RoutingPrefix,
    ) -> Option<Vec<NodeInfoExtended>> {
        match TcpStream::connect(node_address).await {
            Ok(mut stream) => {
                if let Err(e) = Self::perform_client_handshake(&mut stream).await {
                    error!(
                        "Failed to handshake with node {} during FindServingNodes: {:?}",
                        node_address, e
                    );
                    return None;
                }

                let message = Message::FindServingNodes(routing_prefix);
                if let Err(e) = write_message(&mut stream, &message).await {
                    error!("Failed to send FindServingNodes message: {:?}", e);
                    return None;
                }

                match read_message(&mut stream).await {
                    Ok(Message::NodesExtended(nodes)) => Some(nodes),
                    Ok(other) => {
                        warn!(
                            "Unexpected response to FindServingNodes from {}: {:?}",
                            node_address, other
                        );
                        None
                    }
                    Err(e) => {
                        error!("Failed to read NodesExtended response: {:?}", e);
                        None
                    }
                }
            }
            Err(e) => {
                error!("Failed to connect to node: {:?}", e);
                None
            }
        }
    }

    /// Function to handle incoming packets and store them
    pub async fn handle_incoming_packet(&self, packet: &Packet) {
        // Attempt to decrypt the packet
        if let Some((plaintext, sender_address_b58)) =
            packet.verify_and_decrypt(&self.private_address, self.min_pow_difficulty)
        {
            // Decode sender address and extract verifying key bytes
            if let Ok(decoded_sender_public_address) =
                PublicAddress::from_base58(&sender_address_b58)
            {
                let sender_verifying_key_bytes =
                    decoded_sender_public_address.verification_key.to_bytes();

                let mut messages = self.messages_received.lock().await;
                messages
                    .entry(sender_verifying_key_bytes)
                    .or_insert_with(Vec::new)
                    .push(packet.clone());

                info!(
                    "Stored message from sender {}: {:?}",
                    bs58::encode(sender_verifying_key_bytes).into_string(),
                    String::from_utf8_lossy(&plaintext)
                );
            } else {
                warn!("Failed to decode sender public address from Base58");
            }
        } else {
            warn!("Failed to decrypt or verify packet");
        }
    }

    /// Function to receive packets from the subscription channel
    pub async fn receive_packet(&self) -> Option<Packet> {
        let mut rx = self.incoming_rx.lock().await;
        rx.recv().await
    }

    pub async fn send_message(
        &self,
        recipient_public_address: PublicAddress,
        message: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let node = self.connected_node.as_ref().ok_or("No connected node")?;
        let pow_requirement = node.pow_difficulty.max(self.min_pow_difficulty);

        // 1) Build the packet
        let packet = Packet::create_signed_encrypted(
            &self.private_address.verification_signing_key,
            &self.private_address.public_address,
            &recipient_public_address,
            message,
            pow_requirement,
            node.max_ttl,
            self.min_argon2_params.max_params(&node.min_argon2_params),
        );

        // 2) *Hand-off* your handshake on one connection (so the node's loop sees it)
        {
            let mut hs = TcpStream::connect(node.address).await?;
            Self::perform_client_handshake(&mut hs).await?;
            // drop(hs) => node's handle_connection will loop around and see your next Subscribe or Packet
        }

        // 3) Send the packet on a *new* connection (no handshake)
        {
            let mut conn = TcpStream::connect(node.address).await?;
            let msg = Message::Packet(packet);
            write_message(&mut conn, &msg).await?;
        }

        Ok(())
    }

    pub async fn disconnect(&mut self) {
        if let Some(ref node_info) = self.connected_node {
            // Send Unsubscribe message
            match TcpStream::connect(node_info.address).await {
                Ok(mut stream) => {
                    let message = Message::Unsubscribe;
                    if let Err(e) = write_message(&mut stream, &message).await {
                        error!(
                            "Failed to send Unsubscribe to {}: {:?}",
                            node_info.address, e
                        );
                    } else {
                        // Wait for UnsubscribeAck
                        match read_message(&mut stream).await {
                            Ok(Message::UnsubscribeAck) => {
                                info!("Unsubscribed from node {}", node_info.address);
                            }
                            Ok(response) => {
                                warn!("Unexpected response to Unsubscribe: {:?}", response);
                            }
                            Err(e) => {
                                error!(
                                    "Failed to read UnsubscribeAck from {}: {:?}",
                                    node_info.address, e
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to connect to node {}: {:?}", node_info.address, e);
                }
            }
            self.connected_node = None;
        } else {
            warn!("No connected node to disconnect from");
        }
    }

    pub async fn subscribe_and_receive_messages(
        &self,
        node_address: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("Attempting to subscribe to node {}", node_address);

        let mut stream = TcpStream::connect(node_address).await?;

        // Perform handshake
        info!("Connected to node, performing handshake");
        Self::perform_client_handshake(&mut stream).await?;

        info!("Handshake completed, sending subscription request");

        // Send subscription message
        write_message(&mut stream, &Message::Subscribe).await?;

        // Create a channel for subscription confirmation
        let (confirm_tx, mut confirm_rx) = mpsc::channel::<bool>(1);
        let confirm_tx = Arc::new(confirm_tx);

        // Clone what we need for the spawned task
        let incoming_tx = self.incoming_tx.clone();

        // Create copies of what we need for message handling
        let messages_received = self.messages_received.clone();
        let private_address = self.private_address.clone();
        let min_pow_difficulty = self.min_pow_difficulty;

        // Spawn message handling task
        let confirm_tx_clone = confirm_tx.clone();

        let mut subscription_stream = stream;
        tokio::spawn(async move {
            info!("Starting message reception loop");

            // Send confirmation once we start listening
            let _ = confirm_tx_clone.send(true).await;

            loop {
                match read_message(&mut subscription_stream).await {
                    Ok(Message::Packet(packet)) => {
                        info!("Received packet from node");

                        // Handle packet manually here since we can't reference self
                            if let Some((plaintext, sender_address_b58)) =
                                packet.verify_and_decrypt(&private_address, min_pow_difficulty)
                        {
                            if let Ok(decoded_sender_public_address) =
                                PublicAddress::from_base58(&sender_address_b58)
                            {
                                let sender_verifying_key_bytes =
                                    decoded_sender_public_address.verification_key.to_bytes();

                                let mut messages = messages_received.lock().await;
                                messages
                                    .entry(sender_verifying_key_bytes)
                                    .or_insert_with(Vec::new)
                                    .push(packet.clone());

                                info!(
                                    "Stored message from sender {}: {:?}",
                                    bs58::encode(sender_verifying_key_bytes).into_string(),
                                    String::from_utf8_lossy(&plaintext)
                                );
                            }
                        }

                        // Forward to the channel for the test to monitor
                        if let Err(e) = incoming_tx.send(packet).await {
                            error!("Failed to forward packet to handler: {:?}", e);
                            break;
                        }
                    }
                    Ok(other) => {
                        warn!("Unexpected message on subscription stream: {:?}", other);
                    }
                    Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                        info!("Connection closed by node");
                        break;
                    }
                    Err(e) => {
                        error!("Error reading from stream: {:?}", e);
                        break;
                    }
                }
            }
        });

        // Wait for confirmation that message reception is ready
        match tokio::time::timeout(Duration::from_secs(5), confirm_rx.recv()).await {
            Ok(Some(true)) => {
                info!("Subscription confirmed and ready");
                Ok(())
            }
            _ => Err("Failed to confirm subscription setup".into()),
        }
    }

    async fn select_best_node(&self, nodes: Vec<NodeInfoExtended>) -> Option<NodeInfoExtended> {
        // Filter nodes based on:
        // 1. Argon2 parameters
        // 2. Prefix length <= max_prefix_length
        // 3. Node serves client prefix (should already be the case, but we double check)
        let mut matching_nodes: Vec<_> = nodes
            .into_iter()
            .filter(|node| {
                // Check Argon2 parameter requirements
                let argon2_match = if self.require_exact_argon2 {
                    node.min_argon2_params == self.min_argon2_params
                } else {
                    node.min_argon2_params.meets_min(&self.min_argon2_params)
                };

                // Check prefix length constraint
                let prefix_length_ok = node.routing_prefix.bit_length <= self.max_prefix_length;

                // Check prefix bits alignment
                let serves_prefix = node
                    .routing_prefix
                    .serves(&self.private_address.public_address.prefix);

                argon2_match && prefix_length_ok && serves_prefix
            })
            .collect();

        if matching_nodes.is_empty() {
            warn!("No nodes matching Argon2 preferences found");
            return None;
        }

        // Sort nodes by prefix length (longer prefixes first)
        matching_nodes.sort_by_key(|node| -(node.routing_prefix.bit_length as isize));

        // Return the node with the longest matching prefix
        matching_nodes.into_iter().next()
    }

    /// Return the full list of cached nodes from our routing service.
    pub async fn get_cached_nodes(&self) -> Vec<NodeInfo> {
        self.routing_service.all_nodes().await
    }

    /// Find the k closest nodes to a given prefix using our local DHT cache.
    pub async fn find_closest_nodes(&self, prefix: RoutingPrefix) -> Vec<NodeInfo> {
        self.routing_service.find_closest(&prefix).await
    }
}

// Helper functions primarily for integration tests. Hidden from docs in normal builds.
#[cfg_attr(not(any(test, feature = "test_helpers")), doc(hidden))]
impl Client {
    /// Expose our PublicAddress for tests only
    pub fn public_address_for_tests(&self) -> PublicAddress {
        self.private_address.public_address.clone()
    }

    /// Expose a reference to our PrivateAddress for decryption in tests only
    pub fn private_address_for_tests(&self) -> &PrivateAddress {
        &self.private_address
    }
}
