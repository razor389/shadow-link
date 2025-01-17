// src/network/node.rs

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio::sync::broadcast::{self, Sender as BroadcastSender};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use log::{info, warn, error};
use tokio::time::{sleep, Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::argon2_params::SerializableArgon2Params;
use crate::types::message::Message;
use crate::types::node_info::{generate_node_id, NodeId, NodeInfo, NodeInfoExtended};
use crate::types::packet::Packet;
use crate::types::routing_prefix::{PrefixDistance, RoutingPrefix};

use super::dht::RoutingTable; 

/// Kademlia Node
pub struct Node {
    pub id: NodeId,
    pub prefix: RoutingPrefix,
    pub address: SocketAddr,
    pub routing_table: Arc<Mutex<RoutingTable>>,
    pub packet_store: Arc<Mutex<HashMap<Vec<u8>, Packet>>>, // Store packets by pow_hash
    pub blacklist: Arc<Mutex<HashMap<IpAddr, Instant>>>, // IP blacklist with timeout
    pub network_tx: mpsc::Sender<NetworkMessage>,
    pub network_rx: Arc<Mutex<mpsc::Receiver<NetworkMessage>>>,
    pub pow_difficulty: usize, // Difficulty for PoW verification
    pub subscribers: Arc<Mutex<HashMap<SocketAddr, BroadcastSender<Packet>>>>, // List of subscriber channels
    pub max_ttl: u64, // Maximum allowed TTL in seconds
    pub min_argon2_params: SerializableArgon2Params, // Minimum Argon2 parameters
    pub cleanup_interval: Duration, 
    pub blacklist_duration: Duration,
    pub node_requirements: Arc<Mutex<HashMap<NodeId, NodeInfoExtended>>>,
    pub node_discovery_interval: Duration,
}

pub enum NetworkMessage {
    Incoming { stream: TcpStream },
    Outgoing { message: Message, address: SocketAddr },
}

impl Node {
    /// Create a new node
    pub async fn new(
        prefix: RoutingPrefix,
        address: SocketAddr,
        pow_difficulty: usize,
        max_ttl: u64, 
        min_argon2_params: SerializableArgon2Params, 
        cleanup_interval: Duration, 
        blacklist_duration: Duration,
        bootstrap_nodes: Vec<SocketAddr>,
        node_discovery_interval: Duration,
    ) -> Arc<Self> {
        let id = generate_node_id(&address, &prefix);

        let (network_tx, network_rx) = mpsc::channel(100);
        
        // Wrap the receiver in an Arc<Mutex<_>>.
        let network_rx = Arc::new(Mutex::new(network_rx));
        
        let node = Arc::new(Node {
            id,
            prefix: prefix.clone(),
            address,
            routing_table: Arc::new(Mutex::new(RoutingTable::new(id, prefix))),
            packet_store: Arc::new(Mutex::new(HashMap::new())),
            blacklist: Arc::new(Mutex::new(HashMap::new())),
            network_tx,
            network_rx,
            pow_difficulty,
            subscribers: Arc::new(Mutex::new(HashMap::new())),
            max_ttl,
            min_argon2_params,
            cleanup_interval,
            blacklist_duration,
            node_requirements: Arc::new(Mutex::new(HashMap::new())),
            node_discovery_interval,
        });

        let node_clone = node.clone();
        tokio::spawn(async move {
            node_clone.run().await;
        });

        // Spawn the cleanup task
        let node_clone_for_cleanup = node.clone();
        tokio::spawn(async move {
            node_clone_for_cleanup.cleanup_expired_packets().await;
        });

        // Bootstrap the node
        let node_clone = node.clone();
        tokio::spawn(async move {
            for bootstrap_addr in bootstrap_nodes {
                node_clone.bootstrap(bootstrap_addr).await;
            }
            // After bootstrapping all nodes, perform iterative discovery using its own prefix
            let own_prefix = node_clone.prefix;
            let discovered_nodes = node_clone.iterative_find_nodes(own_prefix).await;
            
            // Update routing table with discovered nodes to ensure they're integrated
            for node_info in discovered_nodes.iter() {
                node_clone.update_routing_table(node_info.clone()).await;
            }

            info!("After bootstrap, discovered {} nodes closer to our own prefix", discovered_nodes.len());

            // Start periodic find nodes task
            node_clone.start_periodic_find_nodes().await;
        });

        node
    }

    /// Main loop to accept incoming connections and handle network messages
    pub async fn run(self: Arc<Self>) {
        // Start listening for incoming connections
        let listener = TcpListener::bind(self.address).await.expect("Failed to bind");
        info!("Node {} listening on {}", hex::encode(self.id), self.address);

        // Clone the network_tx for the incoming connection handler
        let network_tx = self.network_tx.clone();

        // Spawn task to accept incoming connections
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        // Use the cloned network_tx to send incoming connections.
                        let _ = network_tx.send(NetworkMessage::Incoming { stream }).await;
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {:?}", e);
                    }
                }
            }
        });

        // Get the shared network_rx from self.
        let mut network_rx = self.network_rx.lock().await;

        // Handle network messages
        while let Some(message) = network_rx.recv().await {
            match message {
                NetworkMessage::Incoming { stream } => {
                    // Handle incoming connection
                    let node_clone = self.clone();
                    tokio::spawn(async move {
                        node_clone.handle_connection(stream).await;
                    });
                }
                NetworkMessage::Outgoing { message, address } => {
                    // Send message to address
                    let node_clone = self.clone();
                    tokio::spawn(async move {
                        node_clone.send_message(message, address).await;
                    });
                }
            }
        }
    }

    /// Periodically cleans up expired packets based on their TTL
    async fn cleanup_expired_packets(self: Arc<Self>) {
        loop {
            // Sleep for the defined cleanup interval before next cleanup
            tokio::time::sleep(self.cleanup_interval).await;

            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let expired_keys = {
                let store = self.packet_store.lock().await;
                store
                    .iter()
                    .filter_map(|(key, packet)| {
                        if packet.timestamp + packet.ttl <= current_time {
                            Some(key.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<Vec<u8>>>()
            };

            if !expired_keys.is_empty() {
                let mut store = self.packet_store.lock().await;
                for key in expired_keys {
                    if let Some(packet) = store.remove(&key) {
                        info!(
                            "Removed expired packet with pow_hash: {}",
                            hex::encode(&packet.pow_hash)
                        );
                    }
                }
            }

            // Cleanup expired blacklist entries
            let expired_blacklist = {
                let blacklist = self.blacklist.lock().await;
                blacklist
                    .iter()
                    .filter_map(|(ip, timeout)| {
                        if Instant::now() >= *timeout {
                            Some(*ip)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<IpAddr>>()
            };

            if !expired_blacklist.is_empty() {
                let mut blacklist = self.blacklist.lock().await;
                for ip in expired_blacklist {
                    blacklist.remove(&ip);
                    info!("Removed IP from blacklist: {}", ip);
                }
            }
        }
    }

    async fn bootstrap(&self, bootstrap_addr: SocketAddr) {
        // Attempt to connect to the bootstrap address
        let mut stream = match TcpStream::connect(bootstrap_addr).await {
            Ok(stream) => stream,
            Err(e) => {
                error!("Failed to connect to bootstrap node {}: {:?}", bootstrap_addr, e);
                return; // Exit if connection fails
            }
        };

        // Send handshake message
        if let Err(e) = self.send_handshake(&mut stream).await {
            error!("Failed to send handshake to {}: {:?}", bootstrap_addr, e);
            return;
        }

        // Receive handshake acknowledgment
        if let Err(e) = self.receive_handshake_ack(&mut stream).await {
            error!("Failed to receive handshake acknowledgment from {}: {:?}", bootstrap_addr, e);
            return;
        }

        // Optionally perform a `FindNode` request to discover more nodes
        if let Err(e) = self.find_node_request(&mut stream).await {
            error!("Failed to perform FindNode request with {}: {:?}", bootstrap_addr, e);
        }
    }

    /// Periodic task that picks random prefixes of the same bit_length as our own prefix
    /// and performs iterative find nodes to refresh and expand the routing table.
    async fn start_periodic_find_nodes(self: Arc<Self>) {
        let bit_length = self.prefix.bit_length;
        let interval = self.node_discovery_interval;
        tokio::spawn(async move {
            loop {
                sleep(interval).await;

                // Generate a random prefix with the same bit_length as our own prefix
                let random_prefix = RoutingPrefix::random(bit_length);

                info!("Performing periodic iterative_find_nodes for prefix {:?}", random_prefix);
                let discovered = self.iterative_find_nodes(random_prefix).await;

                // Integrate discovered nodes into routing table
                for node_info in discovered.iter() {
                    self.update_routing_table(node_info.clone()).await;
                }

                info!("Periodic find nodes: discovered {} nodes for random prefix", discovered.len());
            }
        });
    }

    /// Iterative find nodes method:
    /// Given a target_prefix, repeatedly queries the closest known nodes
    /// to find ever-closer nodes until no progress is made or a limit is reached.
    pub async fn iterative_find_nodes(&self, target_prefix: RoutingPrefix) -> Vec<NodeInfo> {
        // Start with the closest nodes we know from our own routing table
        let mut closest_nodes = self.find_closest_nodes(&target_prefix).await;

        // A set to avoid querying the same node multiple times
        let mut queried = HashSet::new();

        let max_iterations = 5; // Limit the number of iterations to prevent infinite loops
        let mut iteration = 0;

        loop {
            iteration += 1;
            if iteration > max_iterations {
                info!("Reached maximum iterations for iterative_find_nodes");
                break;
            }

            let mut made_progress = false;

            // Attempt to query each node in closest_nodes that we haven't queried yet
            for node in closest_nodes.clone() {
                if queried.contains(&node.id) {
                    continue; // Already queried this node
                }

                // Mark as queried
                queried.insert(node.id);

                // Attempt a query
                if let Some(new_nodes) = self.query_for_closest_nodes(&target_prefix, node.address).await {
                    // Incorporate new nodes into closest_nodes if they are closer
                    let original_len = closest_nodes.len();
                    // Insert new nodes and resort
                    closest_nodes.extend(new_nodes);
                    closest_nodes.sort_by_key(|n| n.routing_prefix.distance(&target_prefix));
                    closest_nodes.truncate(20); // K = 20

                    if closest_nodes.len() > original_len {
                        made_progress = true;
                    }
                }
            }

            // If no progress was made in this iteration, we're done
            if !made_progress {
                break;
            }
        }

        closest_nodes
    }

    /// Attempts to connect to a node, handshake, send a FindClosestNodes request, and return the nodes it provides.
    async fn query_for_closest_nodes(&self, target_prefix: &RoutingPrefix, node_address: SocketAddr) -> Option<Vec<NodeInfo>> {
        // Check if node is blacklisted
        if self.is_blacklisted(&node_address.ip()).await {
            return None;
        }

        // Attempt to connect
        let mut stream = match TcpStream::connect(node_address).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to connect to {}: {:?}", node_address, e);
                return None;
            }
        };

        // Perform handshake
        if self.send_handshake(&mut stream).await.is_err() {
            warn!("Failed to send handshake to {}", node_address);
            return None;
        }
        if self.receive_handshake_ack(&mut stream).await.is_err() {
            warn!("Failed to receive handshake ack from {}", node_address);
            return None;
        }

        // Send FindClosestNodes request
        let request = Message::FindClosestNodes(*target_prefix);
        let data = match bincode::serialize(&request) {
            Ok(d) => d,
            Err(e) => {
                error!("Serialization error: {:?}", e);
                return None;
            }
        };

        if let Err(e) = stream.write_all(&data).await {
            warn!("Failed to send FindClosestNodes to {}: {:?}", node_address, e);
            return None;
        }

        let mut buffer = vec![0u8; 8192];
        let n = match stream.read(&mut buffer).await {
            Ok(n) if n == 0 => {
                // Connection closed
                return None;
            }
            Ok(n) => n,
            Err(e) => {
                warn!("Failed to read from {}: {:?}", node_address, e);
                return None;
            }
        };

        let message: Message = match bincode::deserialize(&buffer[..n]) {
            Ok(m) => m,
            Err(e) => {
                warn!("Deserialization error from {}: {:?}", node_address, e);
                return None;
            }
        };

        if let Message::Nodes(nodes) = message {
            // Update our routing table with these nodes
            for node_info in &nodes {
                self.update_routing_table(node_info.clone()).await;
            }
            Some(nodes)
        } else {
            None
        }
    }

    async fn send_handshake(&self, stream: &mut TcpStream) -> io::Result<()> {
        let handshake = Message::Handshake(self.get_node_info_extended());
        let data = bincode::serialize(&handshake).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("Serialization error: {:?}", e))
        })?;
        stream.write_all(&data).await
    }

    async fn receive_handshake_ack(&self, stream: &mut TcpStream) -> io::Result<()> {
        let mut buffer = vec![0u8; 4096];
        let n = stream.read(&mut buffer).await?;
        let message: Message = bincode::deserialize(&buffer[..n]).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("Deserialization error: {:?}", e))
        })?;
        
        if let Message::HandshakeAck(node_info) = message {
            // Update routing table with the received node info
            self.update_routing_table_extended(node_info).await;
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid handshake acknowledgment"))
        }
    }

    async fn find_node_request(&self, stream: &mut TcpStream) -> io::Result<()> {
        let find_node = Message::FindClosestNodes(self.prefix);
        let data = bincode::serialize(&find_node).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("Serialization error: {:?}", e))
        })?;
        stream.write_all(&data).await?;

        let mut buffer = vec![0u8; 4096];
        let n = stream.read(&mut buffer).await?;
        let message: Message = bincode::deserialize(&buffer[..n]).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("Deserialization error: {:?}", e))
        })?;

        if let Message::Nodes(nodes) = message {
            for node_info in nodes {
                self.update_routing_table(node_info).await;
            }
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData, "Expected Nodes response"))
        }
    }


    /// Handle an incoming connection
    async fn handle_connection(self: Arc<Self>, mut stream: TcpStream) {
        let mut buffer = vec![0u8; 8192]; // Adjust buffer size as needed

        let peer_addr = match stream.peer_addr() {
            Ok(addr) => addr,
            Err(e) => {
                error!("Failed to get peer address: {:?}", e);
                return;
            }
        };

        let peer_ip = peer_addr.ip();

        // Check if the IP is blacklisted
        if self.is_blacklisted(&peer_ip).await {
            warn!("Connection from blacklisted IP: {}", peer_ip);
            return;
        }

        // Receive the handshake from the connecting node
        let n = match stream.read(&mut buffer).await {
            Ok(n) => n,
            Err(e) => {
                error!("Failed to read from stream: {:?}", e);
                return;
            }
        };
        
        let message: Message = match bincode::deserialize(&buffer[..n]) {
            Ok(msg) => msg,
            Err(e) => {
                error!("Failed to deserialize message: {:?}", e);
                return;
            }
        };

        match message {
            Message::ClientHandshake => {
                // Send node info to client
                let handshake_ack = Message::ClientHandshakeAck(self.get_node_info_extended());
                let data = bincode::serialize(&handshake_ack).expect("Failed to serialize handshake acknowledgement");
                stream.write_all(&data).await.expect("Failed to write handshake ack");
                // Proceed to handle further client messages
            }
            Message::Handshake(node_info) =>{
                self.update_routing_table_extended(node_info.clone()).await;

                // Send back our handshake
                let handshake_ack = Message::HandshakeAck(self.get_node_info_extended());
                let data = bincode::serialize(&handshake_ack).expect("Failed to serialize handshake acknowledgement");
                stream.write_all(&data).await.expect("Failed to write handshake ack");
            }
            _ =>{
                warn!("Expected handshake message");
                return;
            }
        }

        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    // Connection closed
                    break;
                }
                Ok(n) => {
                    // Deserialize the message
                    if let Ok(message) = bincode::deserialize::<Message>(&buffer[..n]) {
                        let sender_address = peer_addr;

                        match message {
                            Message::Subscribe => {
                                // Handle subscription
                                let node_clone = self.clone();
                                tokio::spawn(async move {
                                    node_clone.handle_subscribe(sender_address, stream).await;
                                });
                                // After subscribing, we no longer read from this stream
                                break;
                            }
                            Message::Unsubscribe => {
                                // Remove subscriber
                                {
                                    let mut subscribers = self.subscribers.lock().await;
                                    if subscribers.remove(&sender_address).is_some() {
                                        info!("Client {} unsubscribed", sender_address);
                                    } else {
                                        warn!("Client {} tried to unsubscribe but was not subscribed", sender_address);
                                    }
                                }
                                // Send acknowledgment
                                let ack = Message::UnsubscribeAck;
                                let data = match bincode::serialize(&ack) {
                                    Ok(data) => data,
                                    Err(e) => {
                                        error!("Failed to serialize UnsubscribeAck: {:?}", e);
                                        return;
                                    }
                                };
                                if let Err(e) = stream.write_all(&data).await {
                                    error!("Failed to send UnsubscribeAck to {}: {:?}", sender_address, e);
                                }
                                break;
                            }
                            Message::Ping => {
                                let response = Message::Pong;

                                // **Directly write back** to the same connection:
                                let data = bincode::serialize(&response)
                                    .expect("Failed to serialize Message::Pong");
                                if let Err(e) = stream.write_all(&data).await {
                                    error!("Failed to write Pong to stream: {:?}", e);
                                }
                            }
                            _ => {
                                self.handle_message(message, sender_address).await;
                            }
                        }
                    } else {
                        error!("Failed to deserialize message from {}", peer_ip);
                        self.blacklist_ip(&peer_ip).await;
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to read from connection: {:?}", e);
                    break;
                }
            }
        }
    }

    /// Handle an incoming message
    async fn handle_message(&self, message: Message, sender_address: SocketAddr) {
        match message {
            Message::FindClosestNodes(target_prefix) => {
                let closest_nodes = self.find_closest_nodes(&target_prefix).await;
                let response = Message::Nodes(closest_nodes);
                self.send_message(response, sender_address).await;
            }
            Message::FindServingNodes(target_prefix) => {
                // Get nodes serving this prefix
                let mut serving_nodes = self.find_nodes_serving_prefix(&target_prefix).await;
                // Sort by prefix length descending if necessary
                serving_nodes.sort_by_key(|node| -(node.routing_prefix.bit_length as isize));
        
                let response = Message::NodesExtended(serving_nodes);
                self.send_message(response, sender_address).await;
            }
            Message::Nodes(nodes) => {
                // Update routing table with received nodes
                for node_info in nodes {
                    self.update_routing_table(node_info).await;
                }
            }
            Message::Packet(packet) => {
                self.handle_packet(packet, sender_address).await;
            }
            Message::Ping => {
                let response = Message::Pong;
                self.send_message(response, sender_address).await;
            }
            Message::Pong => {
                // Update routing table to mark node as responsive
                self.mark_node_alive(sender_address).await;
            }
            _ => {
                warn!("Received unknown message type from {}", sender_address);
            }
        }
    }

    /// Handle a Subscribe message
    async fn handle_subscribe(self: Arc<Self>, sender_address: SocketAddr, mut stream: TcpStream) {
        let (tx, mut rx) = broadcast::channel::<Packet>(100);
    
        {
            let mut subscribers = self.subscribers.lock().await;
            subscribers.insert(sender_address, tx.clone());
        }
    
        info!("Client {} subscribed", sender_address);
    
        // Send all stored packets to the subscriber
        let packets = {
            let store = self.packet_store.lock().await;
            store.values().cloned().collect::<Vec<Packet>>()
        };
    
        // Send each stored packet
        for packet in packets {
            let message = Message::Packet(packet.clone());
            if let Ok(data) = bincode::serialize(&message) {
                if let Err(e) = stream.write_all(&data).await {
                    error!("Failed to send stored packet to subscriber: {:?}", e);
                    break;
                }
            }
        }
    
        // Continuously receive and forward new packets
        let self_clone = self.clone();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(packet) => {
                        let message = Message::Packet(packet);
                        match bincode::serialize(&message) {
                            Ok(data) => {
                                if let Err(e) = stream.write_all(&data).await {
                                    error!("Failed to send message to subscriber: {:?}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("Failed to serialize packet message: {:?}", e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Broadcast channel error: {:?}", e);
                        break;
                    }
                }
            }
    
            // Remove subscriber when done
            {
                let mut subscribers = self_clone.subscribers.lock().await;
                if subscribers.remove(&sender_address).is_some() {
                    info!("Client {} unsubscribed (stream closed)", sender_address);
                }
            }
        });
    }

    /// Handle a Packet message
    async fn handle_packet(&self, packet: Packet, sender_address: SocketAddr) {
        // Step 0: Check if we've already processed this packet
        {
            let store = self.packet_store.lock().await;
            if store.contains_key(&packet.pow_hash) {
                // We've already processed this exact packet. Skip.
                info!("Duplicate packet received from {} - ignoring.", sender_address);
                return;
            }
        }
        // Step 1: Verify TTL
        if packet.ttl > self.max_ttl {
            warn!(
                "Packet TTL {} exceeds max_ttl {} from {}",
                packet.ttl, self.max_ttl, sender_address
            );
            self.blacklist_ip(&sender_address.ip()).await;
            return;
        }

        // Step 2: Verify Argon2 parameters
        if !packet.argon2_params.meets_min(&self.min_argon2_params) {
            warn!(
                "Packet argon2_params {:?} below min_argon2_params {:?} from {}",
                packet.argon2_params, self.min_argon2_params, sender_address
            );
            self.blacklist_ip(&sender_address.ip()).await;
            return;
        }

        // Step 3: Verify PoW
        if !packet.verify_pow(self.pow_difficulty) {
            warn!("Invalid PoW from {}", sender_address);
            self.blacklist_ip(&sender_address.ip()).await;
            return;
        }

        // Step 4: Store the packet if we should
        if self.should_store_packet(&packet.routing_prefix) {
            info!("Storing packet for prefix {:?}", packet.routing_prefix);
            self.store_packet(packet.clone()).await; // Clone because we'll use it later
            info!("Stored packet on node {}", hex::encode(self.id));
        }

        // Step 5: Forward the packet to other nodes with matching prefixes
        self.forward_packet(packet, sender_address).await;
    }

    /// Determine if the node should store the packet based on its prefix
    fn should_store_packet(&self, recipient_prefix: &RoutingPrefix) -> bool {
        let should_store = self.prefix.serves(recipient_prefix);
        info!(
            "Node prefix: {:?}, Recipient prefix: {:?}, Should store: {}",
            self.prefix, recipient_prefix, should_store
        );
        should_store
    }

    /// Store a packet and notify subscribers
    async fn store_packet(&self, packet: Packet) {
        info!("Storing and broadcasting packet");
        
        // First store the packet
        {
            let mut store = self.packet_store.lock().await;
            store.insert(packet.pow_hash.clone(), packet.clone());
        }

        // Then notify all subscribers
        let subscribers = self.subscribers.lock().await;
        info!("Broadcasting to {} subscribers", subscribers.len());
        
        for (subscriber_addr, tx) in subscribers.iter() {
            info!("Broadcasting packet to subscriber {}", subscriber_addr);
            if let Err(e) = tx.send(packet.clone()) {
                warn!("Failed to send packet to subscriber {}: {:?}", subscriber_addr, e);
            }
        }
        
        info!("Packet stored and broadcast completed");
    }

    /// Forward a packet to nodes whose routing prefixes serve the packet's routing prefix
    async fn forward_packet(&self, packet: Packet, sender_address: SocketAddr) {
        let packet_routing_prefix = &packet.routing_prefix;

        // Get all nodes from the routing table
        let routing_table = self.routing_table.lock().await;
        let all_nodes = routing_table.get_all_nodes();
        drop(routing_table); // Release lock early

        // Get a snapshot of node requirements
        let node_requirements = self.node_requirements.lock().await;

        let mut nodes_to_send = Vec::new();

        for node in all_nodes {
            // Skip the sender to prevent loops
            if node.address == sender_address {
                continue;
            }

            // Get the node's requirements
            if let Some(reqs) = node_requirements.get(&node.id) {
                let node_routing_prefix = &node.routing_prefix;

                // Check if the node's routing prefix serves the packet's routing prefix
                if !node_routing_prefix.serves(packet_routing_prefix) {
                    continue; // Node does not serve the packet's routing prefix
                }

                // Check if the packet meets the node's requirements
                if packet.ttl > reqs.max_ttl || !packet.argon2_params.meets_min(&reqs.min_argon2_params) {
                    continue; // Requirements not met
                }

                nodes_to_send.push(node.clone());
            }
        }

        // Drop the lock on node_requirements
        drop(node_requirements);

        if nodes_to_send.is_empty() {
            warn!("No nodes to forward the packet with matching prefixes");
            return;
        }

        // Forward the packet to all matching nodes
        for node in nodes_to_send {
            let message = Message::Packet(packet.clone());
            self.send_message(message, node.address).await;
        }
    }

    /// Find nodes serving a given prefix
    async fn find_nodes_serving_prefix(&self, address_prefix: &RoutingPrefix) -> Vec<NodeInfoExtended> {
        let routing_table = self.routing_table.lock().await;
        let all_nodes = routing_table.get_all_nodes();
        drop(routing_table); // Release lock early

        let node_requirements = self.node_requirements.lock().await;

        let mut matching_nodes = Vec::new();
        for node in all_nodes {
            let node_prefix = &node.routing_prefix;

            // Use the serves method to check if the node serves the address_prefix
            if node_prefix.serves(address_prefix) {
                // Node matches, add to matching_nodes
                if let Some(node_info_extended) = node_requirements.get(&node.id) {
                    matching_nodes.push(node_info_extended.clone());
                } else {
                    // NodeInfoExtended not available; create a default one
                    let node_info_extended = NodeInfoExtended {
                        id: node.id,
                        address: node.address,
                        routing_prefix: node.routing_prefix.clone(),
                        pow_difficulty: self.pow_difficulty,
                        max_ttl: self.max_ttl,
                        min_argon2_params: SerializableArgon2Params::default(),
                    };
                    matching_nodes.push(node_info_extended);
                }
            }
        }
        matching_nodes
    }

    /// Find nodes closest to a target ID (address)
    async fn find_closest_nodes(&self, target_id: &RoutingPrefix) -> Vec<NodeInfo> {
        let routing_table = self.routing_table.lock().await;
        routing_table.find_closest_nodes(target_id)
    }

    /// Send a message to a specific address
    async fn send_message(&self, message: Message, address: SocketAddr) {
        // Check if the IP is blacklisted
        if self.is_blacklisted(&address.ip()).await {
            warn!("Attempted to send message to blacklisted IP: {}", address);
            return;
        }

        match TcpStream::connect(address).await {
            Ok(mut stream) => {
                let data = bincode::serialize(&message).expect("Failed to serialize message");
                if let Err(e) = stream.write_all(&data).await {
                    error!("Failed to send message to {}: {:?}", address, e);
                }
            }
            Err(e) => {
                error!("Failed to connect to {}: {:?}", address, e);
            }
        }
    }

    /// Update the routing table with a new node
    pub async fn update_routing_table(&self, node_info: NodeInfo) {
        // Check if the node's IP is blacklisted
        if self.is_blacklisted(&node_info.address.ip()).await {
            warn!("Ignoring node {} due to blacklist", node_info.address);
            return;
        }

        let mut routing_table = self.routing_table.lock().await;
        routing_table.update(node_info);
    }

    async fn update_routing_table_extended(&self, node_info: NodeInfoExtended) {
        // Update routing table and store node's requirements
        self.update_routing_table(NodeInfo {
            id: node_info.id,
            routing_prefix: node_info.routing_prefix,
            address: node_info.address,
        }).await;

        // Store node's requirements in a HashMap
        let mut node_requirements = self.node_requirements.lock().await;
        node_requirements.insert(node_info.id, node_info);
    }

    fn get_node_info_extended(&self) -> NodeInfoExtended {
        NodeInfoExtended {
            id: self.id,
            address: self.address,
            routing_prefix: self.prefix,
            pow_difficulty: self.pow_difficulty,
            max_ttl: self.max_ttl,
            min_argon2_params: self.min_argon2_params,
        }
    }

    /// Mark a node as alive in the routing table
    async fn mark_node_alive(&self, address: SocketAddr) {
        // Check if the IP is blacklisted
        if self.is_blacklisted(&address.ip()).await {
            warn!("Attempted to mark blacklisted node as alive: {}", address);
            return;
        }

        let mut routing_table = self.routing_table.lock().await;
        routing_table.mark_node_alive(address);
    }

    /// Blacklist an IP address
    async fn blacklist_ip(&self, ip: &IpAddr) {
        // Do not blacklist own IP
        if ip == &self.address.ip() {
            warn!("Attempted to blacklist own IP: {}", ip);
            return;
        }
        let mut blacklist = self.blacklist.lock().await;
        // Set a timeout for the blacklist (e.g., 10 minutes)
        let timeout = Instant::now() + self.blacklist_duration;
        blacklist.insert(*ip, timeout);

        // Remove the node from the routing table
        let mut routing_table = self.routing_table.lock().await;
        routing_table.remove_node_by_ip(ip);
        warn!("Blacklisted IP: {}", ip);
    }

    /// Check if an IP address is blacklisted (and remove if timeout has expired)
    async fn is_blacklisted(&self, ip: &IpAddr) -> bool {
        let mut blacklist = self.blacklist.lock().await;
        if let Some(&timeout) = blacklist.get(ip) {
            if Instant::now() >= timeout {
                blacklist.remove(ip);
                return false;
            }
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::authentication::Authentication;
    use crate::types::address::{PrivateAddress, PublicAddress};
    use crate::types::message::Message;
    use crate::types::packet::Packet;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use tokio::net::TcpStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_node_initialization() {
        let prefix = RoutingPrefix::random(8);
        let address = "127.0.0.1:8080".parse().unwrap();
        let pow_difficulty = 1;
        let max_ttl = 3600;
        let min_argon2_params = SerializableArgon2Params::default();
        let cleanup_interval = Duration::from_secs(60);
        let blacklist_duration = Duration::from_secs(600);
        let node_discovery_interval = Duration::from_secs(3600);
        let bootstrap_nodes = Vec::new();

        let node = Node::new(
            prefix,
            address,
            pow_difficulty,
            max_ttl,
            min_argon2_params,
            cleanup_interval,
            blacklist_duration,
            bootstrap_nodes,
            node_discovery_interval,
        )
        .await;

        assert_eq!(node.address, address);
        assert_eq!(node.pow_difficulty, pow_difficulty);
    }

    #[tokio::test]
    async fn test_send_message_to_node() {
        // Start a simple node
        let addr = SocketAddr::from_str("127.0.0.1:8081").unwrap();
        let prefix = RoutingPrefix::random(8);
        let node = Node::new(
            prefix,
            addr,
            1, // pow_difficulty
            86400, // max_ttl
            SerializableArgon2Params::default(),
            Duration::from_secs(300), // cleanup_interval
            Duration::from_secs(600), // blacklist_duration
            Vec::new(), // bootstrap_nodes
            Duration::from_secs(3600), // node_discovery_interval
        )
        .await;

        // Create a TCP stream to send a message
        let mut stream = TcpStream::connect(addr).await.unwrap();

        // Perform Handshake
        let handshake = Message::Handshake(node.get_node_info_extended());
        let data = bincode::serialize(&handshake).unwrap();
        stream.write_all(&data).await.unwrap();

        // Receive HandshakeAck
        let mut buffer = vec![0; 4096];
        let n = stream.read(&mut buffer).await.unwrap();
        let _response: Message = bincode::deserialize(&buffer[..n]).unwrap();

        // Serialize and send a Ping message
        let message = Message::Ping;
        let data = bincode::serialize(&message).unwrap();
        stream.write_all(&data).await.unwrap();

        // Read response from the node
        let mut buffer = vec![0; 1024];
        let n = stream.read(&mut buffer).await.unwrap();
        let response: Message = bincode::deserialize(&buffer[..n]).unwrap();

        // Check if the response is a Pong message
        assert!(matches!(response, Message::Pong));
    }

    #[tokio::test]
    async fn test_send_and_receive_packet() {
        let node_addr = SocketAddr::from_str("127.0.0.1:8082").unwrap();
        let node_prefix = RoutingPrefix { bit_length: 8, bits: Some(0b11001010) };

        let node = Node::new(
            node_prefix,
            node_addr,
            1, // Simplified PoW difficulty
            3600,
            SerializableArgon2Params::default(),
            Duration::from_secs(300),
            Duration::from_secs(600),
            Vec::new(),
            Duration::from_secs(3600),
        )
        .await;

        // Create a test packet
        let sender_auth = Authentication::new();
        let recipient_private_address = PrivateAddress::new(Some(RoutingPrefix { bit_length: 8, bits: Some(0b11001010) }), None);
        let recipient_public_address = recipient_private_address.public_address.clone();
        let sender_public_address = PublicAddress {
            prefix: RoutingPrefix::random(8),
            one_time_address: recipient_public_address.one_time_address,
            encryption_key: recipient_public_address.encryption_key,
            verification_key: sender_auth.verifying_key(),
            checksum: [0u8; 4],
        };

        let message = b"Test packet message".to_vec();
        let packet = Packet::create_signed_encrypted(
            &sender_auth,
            &sender_public_address,
            &recipient_public_address,
            &message,
            node.pow_difficulty,
            node.max_ttl,
            node.min_argon2_params,
        );

        // Perform Handshake
        let mut stream = TcpStream::connect(node_addr).await.unwrap();
        let handshake = Message::Handshake(node.get_node_info_extended());
        let data = bincode::serialize(&handshake).unwrap();
        stream.write_all(&data).await.unwrap();

        // Receive HandshakeAck
        let mut buffer = vec![0; 4096];
        let n = stream.read(&mut buffer).await.unwrap();
        let _response: Message = bincode::deserialize(&buffer[..n]).unwrap();

        // Serialize and send the packet
        let data = bincode::serialize(&Message::Packet(packet.clone())).unwrap();
        stream.write_all(&data).await.unwrap();

        // Allow some time for the node to process the packet
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check if the packet was stored
        let packet_store = node.packet_store.lock().await;
        assert!(packet_store.contains_key(&packet.pow_hash));
    }
}