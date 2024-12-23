// src/network/client.rs

use tokio::sync::{mpsc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::collections::HashMap;
use std::net::SocketAddr;
use log::{debug, error, info, warn};

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

            // Connect and handshake with node
            match TcpStream::connect(connected_node.address).await {
                Ok(mut stream) => {
                    // Perform handshake first
                    info!("Performing handshake before sending message");
                    let handshake = Message::ClientHandshake;
                    if let Ok(data) = bincode::serialize(&handshake) {
                        if let Err(e) = stream.write_all(&data).await {
                            error!("Failed to send handshake: {:?}", e);
                            return;
                        }

                        // Await handshake response
                        let mut buffer = vec![0u8; 8192];
                        match stream.read(&mut buffer).await {
                            Ok(n) => {
                                if let Ok(Message::ClientHandshakeAck(_)) = bincode::deserialize(&buffer[..n]) {
                                    info!("Handshake successful, sending message");
                                    // Now send the packet
                                    let message = Message::Packet(packet);
                                    if let Ok(data) = bincode::serialize(&message) {
                                        if let Err(e) = stream.write_all(&data).await {
                                            error!("Failed to send message: {:?}", e);
                                        }
                                    }
                                } else {
                                    error!("Unexpected handshake response");
                                }
                            }
                            Err(e) => error!("Failed to read handshake response: {:?}", e),
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to connect to node {}: {:?}", connected_node.address, e);
                }
            }
        } else {
            error!("No connected node to send the message through");
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
        info!("Attempting to subscribe to node {}", node_address);
        
        // Connect to the node
        match TcpStream::connect(node_address).await {
            Ok(mut stream) => {
                // First perform handshake
                info!("Connected to node, performing handshake");
                let handshake = Message::ClientHandshake;
                let data = match bincode::serialize(&handshake) {
                    Ok(data) => data,
                    Err(e) => {
                        error!("Failed to serialize handshake: {:?}", e);
                        return;
                    }
                };

                if let Err(e) = stream.write_all(&data).await {
                    error!("Failed to send handshake: {:?}", e);
                    return;
                }

                // Wait for handshake acknowledgment
                let mut buffer = vec![0u8; 8192];
                let n = match stream.read(&mut buffer).await {
                    Ok(n) => n,
                    Err(e) => {
                        error!("Failed to read handshake response: {:?}", e);
                        return;
                    }
                };

                let handshake_response = match bincode::deserialize::<Message>(&buffer[..n]) {
                    Ok(msg) => msg,
                    Err(e) => {
                        error!("Failed to deserialize handshake response: {:?}", e);
                        return;
                    }
                };

                if !matches!(handshake_response, Message::ClientHandshakeAck(_)) {
                    error!("Unexpected handshake response");
                    return;
                }

                info!("Handshake completed, sending subscription request");

                // Send subscription message
                let subscribe_msg = Message::Subscribe;
                let data = match bincode::serialize(&subscribe_msg) {
                    Ok(data) => data,
                    Err(e) => {
                        error!("Failed to serialize Subscribe message: {:?}", e);
                        return;
                    }
                };

                if let Err(e) = stream.write_all(&data).await {
                    error!("Failed to send Subscribe message: {:?}", e);
                    return;
                }

                info!("Subscription request sent, starting message loop");

                // Main message loop
                loop {
                    let mut buffer = vec![0u8; 8192];
                    match stream.read(&mut buffer).await {
                        Ok(0) => {
                            info!("Connection closed by node");
                            break;
                        }
                        Ok(n) => {
                            match bincode::deserialize::<Message>(&buffer[..n]) {
                                Ok(Message::Packet(packet)) => {
                                    info!("Received packet from node");
                                    if let Err(e) = self.incoming_tx.send(packet).await {
                                        error!("Failed to forward packet to handler: {:?}", e);
                                    }
                                }
                                Ok(_) => {
                                    debug!("Received non-packet message");
                                }
                                Err(e) => {
                                    error!("Failed to deserialize message: {:?}", e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Error reading from stream: {:?}", e);
                            break;
                        }
                    }
                }
                info!("Subscription message loop ended");
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
    use crate::types::argon2_params::SerializableArgon2Params;
    use crate::types::routing_prefix::RoutingPrefix;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::Arc;
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
    async fn test_two_clients_send_and_receive_message() {
        use log::{info, warn};

        // Initialize logging for the test
        let _ = env_logger::try_init();
        info!("Starting two clients test");

        // --- Node Setup ---
        let node_prefix = RoutingPrefix {
            bit_length: 0,
            bits: None,
        };
        let node_addr = SocketAddr::from_str("127.0.0.1:8085").unwrap();

        info!("Creating node...");
        let _node = Node::new(
            node_prefix,
            node_addr,
            1,
            3600,
            SerializableArgon2Params::default(),
            Duration::from_secs(300),
            Duration::from_secs(600),
            Vec::new(),
            Duration::from_secs(3600),
        )
        .await;

        // Give node more time to start
        info!("Waiting for node to initialize...");
        tokio::time::sleep(Duration::from_secs(1)).await;

        // --- Client Setup ---
        info!("Creating clients...");
        let mut client1 = Client::new(
            None,
            None,
            64,
            SerializableArgon2Params::default(),
            false,
            node_addr,
        );

        let mut client2 = Client::new(
            None,
            None,
            64,
            SerializableArgon2Params::default(),
            false,
            node_addr,
        );

        // --- Connect Clients ---
        info!("Connecting client 1...");
        let client1_handshake = tokio::time::timeout(
            Duration::from_secs(5),
            client1.handshake_with_node(node_addr)
        ).await.expect("Client 1 handshake timeout")
        .expect("Client 1 handshake failed");
        client1.connected_node = Some(client1_handshake);
        info!("Client 1 connected successfully");

        info!("Connecting client 2...");
        let client2_handshake = tokio::time::timeout(
            Duration::from_secs(5),
            client2.handshake_with_node(node_addr)
        ).await.expect("Client 2 handshake timeout")
        .expect("Client 2 handshake failed");
        client2.connected_node = Some(client2_handshake);
        info!("Client 2 connected successfully");

        // Store client2's address and private address before wrapping
        let recipient_public_address = client2.private_address.public_address.clone();
        let client2_private_address = client2.private_address.clone();
        
        // --- Subscribe Client 2 ---
        info!("Starting Client 2 subscription...");
        let client2 = Arc::new(tokio::sync::Mutex::new(client2));
        
        // Subscribe client 2
        {
            let client2_guard = client2.lock().await;
            client2_guard.subscribe_and_receive_messages(node_addr).await;
            info!("Subscription initiated for client 2");
        }

        // Give subscription time to fully establish
        tokio::time::sleep(Duration::from_secs(2)).await;

        // --- Send Message ---
        info!("Sending test message...");
        let test_message = b"Hello from Client 1!".to_vec();
        
        tokio::time::timeout(
            Duration::from_secs(5),
            client1.send_message(recipient_public_address.clone(), &test_message)
        ).await.expect("Send message timeout");
        info!("Test message sent");

        // --- Wait for Message Receipt ---
        info!("Waiting for message receipt...");
        let message_received = tokio::time::timeout(
            Duration::from_secs(10),
            async {
                let start = tokio::time::Instant::now();
                while start.elapsed() < Duration::from_secs(8) {
                    let found = {
                        let client2_guard = client2.lock().await;
                        let messages = client2_guard.messages_received.lock().await;
                        
                        let mut message_found = false;
                        for packets in messages.values() {
                            for packet in packets {
                                if let Some((plaintext, _)) = packet.verify_and_decrypt(
                                    &client2_private_address, 
                                    1
                                ) {
                                    info!("Received message: {:?}", String::from_utf8_lossy(&plaintext));
                                    if plaintext == test_message {
                                        message_found = true;
                                        break;
                                    }
                                }
                            }
                            if message_found {
                                break;
                            }
                        }
                        message_found
                    };

                    if found {
                        return true;
                    }

                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                warn!("Message not found after timeout");
                false
            }
        ).await.expect("Message receipt timeout");

        assert!(message_received, "Message was not received within timeout period");
        info!("Test completed successfully");
    }
}