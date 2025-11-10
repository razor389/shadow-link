// src/network/node.rs

use ed25519_dalek::{Signature, VerifyingKey};
use log::{info, warn};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast::{self, Sender as BroadcastSender};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Duration, Instant};

use crate::crypto::authentication::Authentication;
use crate::network::framing::{read_message, write_message};
use crate::network::routing::api::RoutingService;
use crate::types::argon2_params::SerializableArgon2Params;
use crate::types::message::Message;
use crate::types::node_info::{generate_node_id, NodeInfo, NodeInfoExtended};
use crate::types::packet::Packet;
use crate::types::routing_prefix::RoutingPrefix;

use rand::{rngs::OsRng, RngCore};

const HANDSHAKE_DOMAIN: &[u8] = b"shadowlink-node-handshake";

/// Internal network message enum
pub enum NetworkMessage {
    Incoming {
        stream: TcpStream,
    },
    Outgoing {
        message: Message,
        address: SocketAddr,
    },
}

/// Core Node struct
pub struct Node {
    pub id: [u8; 20],
    pub prefix: RoutingPrefix,
    pub address: SocketAddr,
    pub routing_service: Arc<dyn RoutingService>,
    pub packet_store: Arc<Mutex<HashMap<Vec<u8>, Packet>>>,
    pub blacklist: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    pub network_tx: mpsc::Sender<NetworkMessage>,
    pub network_rx: Arc<Mutex<mpsc::Receiver<NetworkMessage>>>,
    pub pow_difficulty: usize,
    pub auth: Authentication,
    pub subscribers: Arc<Mutex<HashMap<SocketAddr, BroadcastSender<Packet>>>>,
    pub max_ttl: u64,
    pub min_argon2_params: SerializableArgon2Params,
    pub cleanup_interval: Duration,
    pub blacklist_duration: Duration,
    pub node_requirements: Arc<Mutex<HashMap<[u8; 20], NodeInfoExtended>>>,
    pub node_discovery_interval: Duration,
}

impl Node {
    /// Create and spawn tasks
    pub async fn new(
        routing_service: Arc<dyn RoutingService>,
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
        let routing_service = routing_service.clone();
        let (tx, rx) = mpsc::channel(100);
        let node = Arc::new(Node {
            id,
            prefix: prefix.clone(),
            address,
            routing_service,
            packet_store: Arc::new(Mutex::new(HashMap::new())),
            blacklist: Arc::new(Mutex::new(HashMap::new())),
            network_tx: tx,
            network_rx: Arc::new(Mutex::new(rx)),
            pow_difficulty,
            auth: Authentication::new(),
            subscribers: Arc::new(Mutex::new(HashMap::new())),
            max_ttl,
            min_argon2_params,
            cleanup_interval,
            blacklist_duration,
            node_requirements: Arc::new(Mutex::new(HashMap::new())),
            node_discovery_interval,
        });
        // accept loop
        let ncl = node.clone();
        tokio::spawn(async move { ncl.run().await });
        // cleanup
        let ncl2 = node.clone();
        tokio::spawn(async move { ncl2.cleanup_expired_packets().await });
        // bootstrap/discovery
        let nboot = node.clone();
        tokio::spawn(async move {
            for b in bootstrap_nodes {
                nboot.bootstrap(b).await;
            }
            let discovered = nboot.iterative_find_nodes(prefix.clone()).await;
            for ni in discovered {
                nboot.update_routing_table(ni).await;
            }
            nboot.start_periodic_find_nodes().await;
        });
        node
    }

    /// Accept incoming and outgoing messages
    async fn run(self: Arc<Self>) {
        let listener = TcpListener::bind(self.address).await.expect("bind failed");
        let tx = self.network_tx.clone();
        tokio::spawn(async move {
            loop {
                if let Ok((s, _)) = listener.accept().await {
                    let _ = tx.send(NetworkMessage::Incoming { stream: s }).await;
                }
            }
        });
        let mut rx = self.network_rx.lock().await;
        while let Some(msg) = rx.recv().await {
            match msg {
                NetworkMessage::Incoming { stream } => {
                    let me = self.clone();
                    tokio::spawn(async move { me.handle_connection(stream).await });
                }
                NetworkMessage::Outgoing { message, address } => {
                    let me = self.clone();
                    tokio::spawn(async move { me.send_message(message, address).await });
                }
            }
        }
    }

    /// Cleanup expired entries
    async fn cleanup_expired_packets(self: Arc<Self>) {
        loop {
            sleep(self.cleanup_interval).await;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            self.packet_store
                .lock()
                .await
                .retain(|_, p| p.timestamp + p.ttl > now);
            self.blacklist
                .lock()
                .await
                .retain(|_, &mut t| Instant::now() < t);
        }
    }

    /// Bootstrap handshake
    async fn bootstrap(&self, addr: SocketAddr) {
        if let Ok(mut s) = TcpStream::connect(addr).await {
            if self.perform_node_handshake(&mut s).await.is_ok() {
                let _ = self.find_node_request(&mut s).await;
            }
        }
    }

    /// Periodic rediscovery
    async fn start_periodic_find_nodes(self: Arc<Self>) {
        let interval = self.node_discovery_interval;
        let bitlen = self.prefix.bit_length;
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                sleep(interval).await;
                let targ = RoutingPrefix::random(bitlen);
                let nds = me.iterative_find_nodes(targ).await;
                for ni in nds {
                    me.update_routing_table(ni).await;
                }
            }
        });
    }

    /// Kademlia iterative lookup
    pub async fn iterative_find_nodes(&self, target: RoutingPrefix) -> Vec<NodeInfo> {
        let mut cls = self.routing_service.find_closest(&target).await;
        let mut seen = HashSet::new();
        for _ in 0..5 {
            let mut prog = false;
            for ni in cls.clone() {
                if seen.insert(ni.id) {
                    if let Some(m) = self.query_for_closest_nodes(&target, ni.address).await {
                        cls.extend(m);
                        cls.sort_by_key(|n| n.routing_prefix.distance(&target).unwrap_or(u64::MAX));
                        cls.truncate(20);
                        prog = true;
                    }
                }
            }
            if !prog {
                break;
            }
        }
        cls
    }

    /// RPC to node
    async fn query_for_closest_nodes(
        &self,
        target: &RoutingPrefix,
        addr: SocketAddr,
    ) -> Option<Vec<NodeInfo>> {
        if self.is_blacklisted(&addr.ip()).await {
            return None;
        }
        let mut s = TcpStream::connect(addr).await.ok()?;
        self.perform_node_handshake(&mut s).await.ok()?;
        let req = Message::FindClosestNodes(*target);
        write_message(&mut s, &req).await.ok()?;
        if let Message::Nodes(ls) = read_message(&mut s).await.ok()? {
            for ni in &ls {
                self.update_routing_table(ni.clone()).await;
            }
            Some(ls)
        } else {
            None
        }
    }

    /// Accept incoming and outgoing messages
    async fn handle_connection(self: Arc<Self>, mut stream: TcpStream) {
        let peer = stream.peer_addr().unwrap_or(self.address);
        if self.is_blacklisted(&peer.ip()).await {
            return;
        }
        let mut pending_node_handshake: Option<(NodeInfoExtended, [u8; 32])> = None;

        loop {
            let msg = match read_message(&mut stream).await {
                Ok(m) => m,
                Err(err) => {
                    warn!("Dropping connection from {}: {:?}", peer, err);
                    return;
                }
            };

            match msg {
                // 1) Keep reading after a client handshake
                Message::ClientHandshake => {
                    let ack = Message::ClientHandshakeAck(self.get_node_info_extended());
                    let _ = write_message(&mut stream, &ack).await;
                    continue;
                }

                // 2) Same for internal node handshakes
                Message::Handshake(ni) => {
                    let nonce = Self::generate_handshake_nonce();
                    pending_node_handshake = Some((ni.clone(), nonce));
                    let _ = write_message(&mut stream, &Message::HandshakeChallenge(nonce)).await;
                    continue;
                }
                Message::HandshakeResponse(signature) => {
                    if let Some((pending, nonce)) = pending_node_handshake.take() {
                        if Self::verify_handshake_response(&pending, &nonce, signature.as_slice()) {
                            self.update_routing_table_extended(pending.clone()).await;
                            let ack = Message::HandshakeAck(self.get_node_info_extended());
                            let _ = write_message(&mut stream, &ack).await;
                        } else {
                            warn!("Invalid handshake signature from {}", peer);
                            return;
                        }
                    } else {
                        warn!("Unexpected handshake response from {}", peer);
                        return;
                    }
                    continue;
                }

                // 3) When a client subscribes, hand the socket off to handle_subscribe
                Message::Subscribe => {
                    let me = self.clone();
                    let peer_addr = peer;
                    tokio::spawn(async move {
                        me.handle_subscribe(peer_addr, stream).await;
                    });
                    return;
                }

                // 4) Unsubscribe is also long-lived
                Message::Unsubscribe => {
                    self.handle_unsubscribe(peer, stream).await;
                    return;
                }

                // 5) Anything else is a one-off RPC or packet
                other => {
                    self.handle_message(other, peer).await;
                    return;
                }
            }
        }
    }

    /// Dispatch protocol messages    /// Dispatch protocol messages
    async fn handle_message(&self, msg: Message, sender: SocketAddr) {
        match msg {
            Message::FindClosestNodes(p) => {
                let ls = self.routing_service.find_closest(&p).await;
                self.send_message(Message::Nodes(ls), sender).await;
            }
            Message::FindServingNodes(p) => {
                let ext = self.find_nodes_serving(&p).await;
                self.send_message(Message::NodesExtended(ext), sender).await;
            }
            Message::Packet(pkt) => {
                self.handle_packet(pkt, sender).await;
            }
            Message::Ping => {
                self.send_message(Message::Pong, sender).await;
            }
            Message::Pong => {
                self.routing_service.mark_alive(sender).await;
            }
            _ => {
                warn!("Unexpected message from {}", sender);
            }
        }
    }

    /// Manage new subscriptions
    async fn handle_subscribe(self: Arc<Self>, _peer: SocketAddr, mut st: TcpStream) {
        let (tx, mut rx) = broadcast::channel(100);
        self.subscribers.lock().await.insert(_peer, tx.clone());
        for pkt in self.packet_store.lock().await.values().cloned() {
            let _ = write_message(&mut st, &Message::Packet(pkt)).await;
        }
        let me = self.clone();
        let peer_addr = _peer;
        tokio::spawn(async move {
            while let Ok(pkt) = rx.recv().await {
                if write_message(&mut st, &Message::Packet(pkt)).await.is_err() {
                    break;
                }
            }
            me.subscribers.lock().await.remove(&peer_addr);
        });
    }

    /// Manage unsubscribes
    async fn handle_unsubscribe(&self, peer: SocketAddr, mut st: TcpStream) {
        self.subscribers.lock().await.remove(&peer);
        let _ = write_message(&mut st, &Message::UnsubscribeAck).await;
    }

    /// Process and forward a packet
    async fn handle_packet(&self, packet: Packet, sender: SocketAddr) {
        info!(
            "Node prefix: {:?}, Packet prefix: {:?}, Serves: {}",
            self.prefix,
            packet.routing_prefix,
            self.prefix.serves(&packet.routing_prefix)
        );
        if self
            .packet_store
            .lock()
            .await
            .contains_key(&packet.pow_hash)
        {
            return;
        }
        if packet.ttl > self.max_ttl {
            self.blacklist_ip(&sender.ip()).await;
            return;
        }
        if !packet.argon2_params.meets_min(&self.min_argon2_params) {
            self.blacklist_ip(&sender.ip()).await;
            return;
        }
        if !packet.verify_pow(self.pow_difficulty) {
            self.blacklist_ip(&sender.ip()).await;
            return;
        }
        if self.prefix.serves(&packet.routing_prefix) {
            self.packet_store
                .lock()
                .await
                .insert(packet.pow_hash.clone(), packet.clone());
            for tx in self.subscribers.lock().await.values() {
                let _ = tx.send(packet.clone());
            }
        }
        self.forward_packet(packet, sender).await;
    }

    /// Forward to peers based on requirements
    async fn forward_packet(&self, packet: Packet, sender: SocketAddr) {
        let nodes = self
            .routing_service
            .find_closest(&packet.routing_prefix)
            .await;
        let reqs = self.node_requirements.lock().await.clone();
        for ni in nodes {
            if ni.address == sender {
                continue;
            }
            if let Some(r) = reqs.get(&ni.id) {
                if packet.ttl > r.max_ttl || !packet.argon2_params.meets_min(&r.min_argon2_params) {
                    continue;
                }
                self.send_message(Message::Packet(packet.clone()), r.address)
                    .await;
            }
        }
    }

    /// Get serving nodes with extended info
    async fn find_nodes_serving(&self, p: &RoutingPrefix) -> Vec<NodeInfoExtended> {
        let bas = self.routing_service.find_closest(p).await;
        let reqs = self.node_requirements.lock().await;
        bas.into_iter()
            .filter_map(|ni| reqs.get(&ni.id).cloned())
            .collect()
    }

    /// Complete authenticated handshake with a peer node.
    async fn perform_node_handshake(&self, st: &mut TcpStream) -> io::Result<NodeInfoExtended> {
        write_message(st, &Message::Handshake(self.get_node_info_extended())).await?;
        loop {
            match read_message(st).await? {
                Message::HandshakeChallenge(nonce) => {
                    let signature = self.sign_handshake_response(&nonce).to_vec();
                    write_message(st, &Message::HandshakeResponse(signature)).await?;
                }
                Message::HandshakeAck(ni) => {
                    self.update_routing_table_extended(ni.clone()).await;
                    return Ok(ni);
                }
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Unexpected handshake message: {:?}", other),
                    ));
                }
            }
        }
    }

    /// Simple find-node
    async fn find_node_request(&self, st: &mut TcpStream) -> io::Result<()> {
        let msg = Message::FindClosestNodes(self.prefix);
        write_message(st, &msg).await?;
        if let Message::Nodes(ls) = read_message(st).await? {
            for ni in ls {
                self.update_routing_table(ni).await;
            }
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "Bad resp"))
        }
    }

    /// Insert into routing
    async fn update_routing_table(&self, ni: NodeInfo) {
        self.routing_service.insert(ni).await;
    }

    /// Insert and store extended
    async fn update_routing_table_extended(&self, ni: NodeInfoExtended) {
        let b = NodeInfo {
            id: ni.id,
            routing_prefix: ni.routing_prefix,
            address: ni.address,
        };
        self.routing_service.insert(b).await;
        self.node_requirements.lock().await.insert(ni.id, ni);
    }

    /// Own info
    fn get_node_info_extended(&self) -> NodeInfoExtended {
        NodeInfoExtended {
            id: self.id,
            address: self.address,
            routing_prefix: self.prefix,
            pow_difficulty: self.pow_difficulty,
            max_ttl: self.max_ttl,
            min_argon2_params: self.min_argon2_params,
            verifying_key: self.auth.verifying_key().to_bytes(),
        }
    }

    fn generate_handshake_nonce() -> [u8; 32] {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    fn sign_handshake_response(&self, nonce: &[u8; 32]) -> [u8; 64] {
        let payload = Self::handshake_payload(&self.id, nonce);
        self.auth.sign_message(&payload).to_bytes()
    }

    fn verify_handshake_response(info: &NodeInfoExtended, nonce: &[u8; 32], signature: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        if let Ok(verifying_key) = VerifyingKey::from_bytes(&info.verifying_key) {
            let sig = Signature::from_bytes(&sig_bytes);
            let payload = Self::handshake_payload(&info.id, nonce);
            return Authentication::verify_message_with_key(&payload, &sig, &verifying_key);
        }
        false
    }

    fn handshake_payload(node_id: &[u8; 20], nonce: &[u8; 32]) -> Vec<u8> {
        let mut payload =
            Vec::with_capacity(HANDSHAKE_DOMAIN.len() + node_id.len() + nonce.len());
        payload.extend_from_slice(HANDSHAKE_DOMAIN);
        payload.extend_from_slice(node_id);
        payload.extend_from_slice(nonce);
        payload
    }

    /// Blacklist and remove
    async fn blacklist_ip(&self, ip: &IpAddr) {
        if *ip == self.address.ip() {
            return;
        }
        self.blacklist
            .lock()
            .await
            .insert(*ip, Instant::now() + self.blacklist_duration);
        self.routing_service.remove_by_ip(*ip).await;
    }

    /// Check blacklist
    async fn is_blacklisted(&self, ip: &IpAddr) -> bool {
        let mut b = self.blacklist.lock().await;
        if let Some(&t) = b.get(ip) {
            if Instant::now() >= t {
                b.remove(ip);
                false
            } else {
                true
            }
        } else {
            false
        }
    }

    /// Send a network message
    async fn send_message(&self, message: Message, addr: SocketAddr) {
        if self.is_blacklisted(&addr.ip()).await {
            return;
        }
        if let Ok(mut s) = TcpStream::connect(addr).await {
            let _ = write_message(&mut s, &message).await;
        }
    }
}
