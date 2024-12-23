// src/network/client.rs

use tokio::sync::{mpsc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::collections::HashMap;
use std::net::SocketAddr;
use log::{info, warn, error};

use crate::types::address::{PrivateAddress, PublicAddress};
use crate::types::argon2_params::SerializableArgon2Params;
use crate::types::message::Message;
use crate::types::node_info::NodeInfoExtended;
use crate::types::packet::Packet;
use crate::types::routing_prefix::RoutingPrefix;

pub type VerificationKeyBytes = [u8;32];

pub struct Client {
    private_address: PrivateAddress,
    pub max_prefix_length: usize,
    pub min_argon2_params: SerializableArgon2Params,
    pub require_exact_argon2: bool,
    pub connected_node: Option<NodeInfoExtended>,
    pub incoming_tx: mpsc::Sender<Packet>,
    pub incoming_rx: Mutex<mpsc::Receiver<Packet>>,
    messages_received: Mutex<HashMap<VerificationKeyBytes, Vec<Packet>>>,
    pub bootstrap_node_address: SocketAddr,
}

impl Client {
    pub fn new(
        prefix: Option<RoutingPrefix>, 
        length: Option<u8>,
        max_prefix_length: usize,
        min_argon2_params: SerializableArgon2Params,
        require_exact_argon2: bool,
        bootstrap_node_address: SocketAddr,
    ) -> Self {
        let private_address = PrivateAddress::new(prefix, length);
        info!("Client created with public address {:?}", private_address.public_address);
        let (tx, rx) = mpsc::channel(100);

        Client {
            private_address,
            max_prefix_length,
            min_argon2_params,
            require_exact_argon2,
            connected_node: None,
            incoming_tx: tx,
            incoming_rx: Mutex::new(rx),
            messages_received: Mutex::new(HashMap::new()),
            bootstrap_node_address,
        }
    }

    pub async fn find_connect_subscribe(&mut self) {
        // Perform handshake with the bootstrap node
        if let Some(_node_info) = self.handshake_with_node(self.bootstrap_node_address).await {
            // Send FindNodePrefix message with our address prefix
            let address_prefix = self.get_routing_prefix();
            if let Some(nodes) = self.send_find_serving_nodes_request(self.bootstrap_node_address, address_prefix).await {
                // Select a node matching our preferences
                if let Some(best_node) = self.select_best_node(nodes).await {
                    // Handshake and subscribe to the selected node
                    if let Some(node_info) = self.handshake_with_node(best_node.address).await {
                        self.connected_node = Some(node_info.clone());
                        self.subscribe_and_receive_messages(node_info.address).await;
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
            Ok(mut stream) => {
                // Send ClientHandshake message
                let message = Message::ClientHandshake;
                let data = bincode::serialize(&message).expect("Failed to serialize message");
                if let Err(e) = stream.write_all(&data).await {
                    error!("Failed to send handshake to {}: {:?}", node_address, e);
                    return None;
                }
    
                // Receive Node's handshake acknowledgment
                let mut buffer = vec![0u8; 4096];
                let n = match stream.read(&mut buffer).await {
                    Ok(n) => n,
                    Err(e) => {
                        error!("Failed to read handshake ack from {}: {:?}", node_address, e);
                        return None;
                    }
                };
                let response: Message = match bincode::deserialize(&buffer[..n]) {
                    Ok(msg) => msg,
                    Err(e) => {
                        error!("Failed to deserialize handshake ack from {}: {:?}", node_address, e);
                        return None;
                    }
                };
    
                if let Message::ClientHandshakeAck(node_info) = response {
                    // Return node's info
                    Some(node_info)
                } else {
                    warn!("Unexpected response during handshake with {}", node_address);
                    None
                }
            }
            Err(e) => {
                error!("Failed to connect to node {}: {:?}", node_address, e);
                None
            }
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
                // Perform handshake before sending messages
                if let Some(_node_info) = self.handshake_with_node(node_address).await {
                    let message = Message::FindServingNodes(routing_prefix);
                    let data = bincode::serialize(&message).expect("Failed to serialize message");
    
                    if let Err(e) = stream.write_all(&data).await {
                        error!("Failed to send FindServingNodes message: {:?}", e);
                        return None;
                    }
    
                    let mut buffer = vec![0u8; 8192];
                    let n = match stream.read(&mut buffer).await {
                        Ok(n) => n,
                        Err(e) => {
                            error!("Failed to read NodesExtended response: {:?}", e);
                            return None;
                        }
                    };
    
                    if let Ok(Message::NodesExtended(nodes)) = bincode::deserialize(&buffer[..n]) {
                        Some(nodes)
                    } else {
                        warn!("Unexpected response to FindServingNodes");
                        None
                    }
                } else {
                    error!("Failed to handshake with node during FindServingNodes");
                    None
                }
            }
            Err(e) => {
                error!("Failed to connect to node: {:?}", e);
                None
            }
        }
    }
    
    
    /// Function to handle incoming packets and store them
    pub async fn handle_incoming_packet(&self, packet: Packet) {
        // Attempt to decrypt the packet
        // Now verify_and_decrypt returns (plaintext, sender_address_b58)
        if let Some((plaintext, sender_address_b58)) = packet.verify_and_decrypt(&self.private_address, packet.pow_difficulty) {
            // Decode sender address and extract verifying key bytes
            if let Ok(decoded_sender_public_address) = PublicAddress::from_base58(&sender_address_b58) {
                let sender_verifying_key_bytes = decoded_sender_public_address.verification_key.to_bytes();

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

    
    /// Send a message to a recipient
    pub async fn send_message(
        &self,
        recipient_public_address: PublicAddress,
        message: &[u8],
    ) {
        if let Some(ref connected_node) = self.connected_node {
            // Ensure message meets connected node's requirements
            let pow_difficulty = connected_node.pow_difficulty;
            let ttl = connected_node.max_ttl;
            let argon2_params = self.min_argon2_params.max_params(&connected_node.min_argon2_params);

            // Now we must pass the sender's public address to create_signed_encrypted
            let sender_public_address = &self.private_address.public_address;

            let packet = Packet::create_signed_encrypted(
                &self.private_address.verification_signing_key,
                sender_public_address,
                &recipient_public_address,
                message,
                pow_difficulty,
                ttl,
                argon2_params,
            );

            // Send the packet to the connected node
            let message = Message::Packet(packet);
            self.send_message_to_node(message, connected_node.address).await;
        } else {
            error!("No connected node to send the message through");
        }
    }

    async fn send_message_to_node(&self, message: Message, node_address: SocketAddr) {
        match TcpStream::connect(node_address).await {
            Ok(mut stream) => {
                let data = bincode::serialize(&message).expect("Failed to serialize message");
                if let Err(e) = stream.write_all(&data).await {
                    error!("Failed to send message to {}: {:?}", node_address, e);
                }
            }
            Err(e) => {
                error!("Failed to connect to node {}: {:?}", node_address, e);
            }
        }
    }

    pub async fn disconnect(&mut self) {
        if let Some(ref node_info) = self.connected_node {
            // Send Unsubscribe message
            match TcpStream::connect(node_info.address).await {
                Ok(mut stream) => {
                    let message = Message::Unsubscribe;
                    let data = bincode::serialize(&message).expect("Failed to serialize Unsubscribe message");
                    if let Err(e) = stream.write_all(&data).await {
                        error!("Failed to send Unsubscribe to {}: {:?}", node_info.address, e);
                    } else {
                        // Wait for UnsubscribeAck
                        let mut buffer = vec![0u8; 1024];
                        match stream.read(&mut buffer).await {
                            Ok(n) => {
                                if let Ok(response) = bincode::deserialize::<Message>(&buffer[..n]) {
                                    if let Message::UnsubscribeAck = response {
                                        info!("Unsubscribed from node {}", node_info.address);
                                    } else {
                                        warn!("Unexpected response to Unsubscribe: {:?}", response);
                                    }
                                } else {
                                    error!("Failed to deserialize UnsubscribeAck from {}", node_info.address);
                                }
                            }
                            Err(e) => {
                                error!("Failed to read UnsubscribeAck from {}: {:?}", node_info.address, e);
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

    pub async fn subscribe_and_receive_messages(&self, node_address: SocketAddr) {
        // Connect to the node
        match TcpStream::connect(node_address).await {
            Ok(stream) => {
                // Perform handshake before subscribing
                if let Some(_node_info) = self.handshake_with_node(node_address).await {
                    // Send a Subscribe message
                    let message = Message::Subscribe;
                    let data = match bincode::serialize(&message) {
                        Ok(data) => data,
                        Err(e) => {
                            error!("Failed to serialize Subscribe message: {:?}", e);
                            return;
                        }
                    };

                    let (mut read_half, mut write_half) = stream.into_split();

                    // Write to the stream using the write half
                    if let Err(e) = write_half.write_all(&data).await {
                        error!("Failed to send Subscribe message: {:?}", e);
                        return;
                    }

                    // Create a channel for messages
                    let (message_tx, mut message_rx) = mpsc::channel::<Message>(100);

                    // Spawn a task to read from the stream and send messages to the channel
                    let node_address_clone = node_address;
                    let message_tx_clone = message_tx.clone();
                    tokio::spawn(async move {
                        let mut buffer = vec![0u8; 8192];
                        loop {
                            match read_half.read(&mut buffer).await {
                                Ok(0) => {
                                    // Connection closed
                                    info!("Connection closed by node {}", node_address_clone);
                                    break;
                                }
                                Ok(n) => {
                                    if let Ok(message) = bincode::deserialize::<Message>(&buffer[..n]) {
                                        if let Err(e) = message_tx_clone.send(message).await {
                                            error!("Failed to send message to channel: {:?}", e);
                                            break;
                                        }
                                    } else {
                                        error!("Failed to deserialize message from node {}", node_address_clone);
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to read from node {}: {:?}", node_address_clone, e);
                                    break;
                                }
                            }
                        }
                    });

                    // Process messages from the channel
                    while let Some(message) = message_rx.recv().await {
                        match message {
                            Message::Packet(packet) => {
                                self.handle_incoming_packet(packet).await;
                            }
                            Message::UnsubscribeAck => {
                                info!("Unsubscribed from node {}", node_address);
                                break;
                            }
                            _ => {
                                // Ignore other messages
                            }
                        }
                    }
                } else {
                    error!("Failed to handshake with node {}", node_address);
                }
            }
            Err(e) => {
                error!("Failed to connect to node {}: {:?}", node_address, e);
            }
        }
    }
    
    async fn select_best_node(
        &self,
        nodes: Vec<NodeInfoExtended>,
    ) -> Option<NodeInfoExtended> {
        // Filter nodes based on Argon2 parameters and other preferences
        let mut matching_nodes: Vec<_> = nodes.into_iter().filter(|node| {
            if self.require_exact_argon2 {
                node.min_argon2_params == self.min_argon2_params
            } else {
                node.min_argon2_params.meets_min(&self.min_argon2_params)
            }
        }).collect();

        if matching_nodes.is_empty() {
            warn!("No nodes matching Argon2 preferences found");
            return None;
        }

        // Sort nodes by prefix length (longer prefixes first)
        matching_nodes.sort_by_key(|node| -(node.routing_prefix.bit_length as isize));

        // Return the node with the longest matching prefix
        matching_nodes.into_iter().next()
    }
}

// src/network/client.rs

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::address::PrivateAddress;
    use crate::types::argon2_params::SerializableArgon2Params;
    use crate::types::routing_prefix::RoutingPrefix;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use crate::network::node::Node;
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_client_creation() {
        let bootstrap_addr = SocketAddr::from_str("127.0.0.1:8083").unwrap();
        let client = Client::new(
            None,
            None,
            64,
            SerializableArgon2Params::default(),
            false,
            bootstrap_addr,
        );

        assert!(client.connected_node.is_none());
        assert_eq!(client.max_prefix_length, 64);
    }

    #[tokio::test]
    async fn test_client_handshake() {
        // Start a simple node
        let node_addr = SocketAddr::from_str("127.0.0.1:8084").unwrap();
        let node_prefix = RoutingPrefix::random(8);
        let _node = Node::new(
            node_prefix,
            node_addr,
            10,
            86400,
            SerializableArgon2Params::default(),
            Duration::from_secs(300),
            Duration::from_secs(600),
            Vec::new(),
            Duration::from_secs(3600),
        )
        .await;

        // Create a client
        let client = Client::new(
            None,
            None,
            64,
            SerializableArgon2Params::default(),
            false,
            node_addr,
        );

        // Perform handshake
        let node_info = client.handshake_with_node(node_addr).await;
        assert!(node_info.is_some());
    }

    #[tokio::test]
    async fn test_send_message_to_node_and_receive() {
        // Start a simple node
        let node_addr = SocketAddr::from_str("127.0.0.1:8085").unwrap();
        let node_prefix = RoutingPrefix::random(8);
        let _node = Node::new(
            node_prefix,
            node_addr,
            1,  // Simplified PoW difficulty for testing
            86400,
            SerializableArgon2Params::default(),
            Duration::from_secs(300),
            Duration::from_secs(600),
            Vec::new(),
            Duration::from_secs(3600),
        )
        .await;
    
        // Create a client
        let mut client = Client::new(
            None,
            None,
            64,
            SerializableArgon2Params::default(),
            false,
            node_addr,
        );
    
        // Perform handshake
        let node_info = client.handshake_with_node(node_addr).await;
        assert!(node_info.is_some());
    
        // Subscribe to the node
        client.subscribe_and_receive_messages(node_addr).await;
    
        // Create a recipient for the message
        let recipient_private_address = PrivateAddress::new(None, None);
        let recipient_public_address = recipient_private_address.public_address.clone();
    
        // Create and send a packet
        let message = b"Test message".to_vec();
        client.connected_node = node_info;
        client.send_message(recipient_public_address, &message).await;
    
        // Wait for the message to be processed
        tokio::time::sleep(Duration::from_millis(100)).await;
    
        // Check if the message was received
        let received_packets = client.messages_received.lock().await;
        assert!(!received_packets.is_empty());
    
        // Verify the content of the received message
        let mut message_found = false;
        for (_, packets) in received_packets.iter() {
            for packet in packets {
                if let Some((decrypted_message, _)) = packet.verify_and_decrypt(&client.private_address, 1) {
                    if decrypted_message == message {
                        message_found = true;
                        break;
                    }
                }
            }
            if message_found {
                break;
            }
        }
        assert!(message_found, "Message not received or not decrypted correctly");
    }
    
}