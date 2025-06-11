// src/network/node.rs

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::sync::broadcast::{self, Sender as BroadcastSender};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use log::{info, warn};
use tokio::time::{sleep, Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::network::routing::api::RoutingService;
use crate::types::argon2_params::SerializableArgon2Params;
use crate::types::message::Message;
use crate::types::node_info::{generate_node_id, NodeInfo, NodeInfoExtended};
use crate::types::packet::Packet;
use crate::types::routing_prefix::RoutingPrefix;

/// Internal network message enum
pub enum NetworkMessage {
    Incoming { stream: TcpStream },
    Outgoing { message: Message, address: SocketAddr },
}

/// Core Node struct
pub struct Node {
    pub id: [u8;20],
    pub prefix: RoutingPrefix,
    pub address: SocketAddr,
    pub routing_service: Arc<dyn RoutingService>,
    pub packet_store: Arc<Mutex<HashMap<Vec<u8>,Packet>>>,
    pub blacklist: Arc<Mutex<HashMap<IpAddr,Instant>>>,
    pub network_tx: mpsc::Sender<NetworkMessage>,
    pub network_rx: Arc<Mutex<mpsc::Receiver<NetworkMessage>>>,
    pub pow_difficulty: usize,
    pub subscribers: Arc<Mutex<HashMap<SocketAddr,BroadcastSender<Packet>>>>,
    pub max_ttl: u64,
    pub min_argon2_params: SerializableArgon2Params,
    pub cleanup_interval: Duration,
    pub blacklist_duration: Duration,
    pub node_requirements: Arc<Mutex<HashMap<[u8;20],NodeInfoExtended>>>,
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
        let id = generate_node_id(&address,&prefix);
        let routing_service = routing_service.clone();
        let (tx,rx) = mpsc::channel(100);
        let node = Arc::new(Node{
            id,
            prefix:prefix.clone(),
            address,
            routing_service,
            packet_store:Arc::new(Mutex::new(HashMap::new())),
            blacklist:Arc::new(Mutex::new(HashMap::new())),
            network_tx:tx,
            network_rx:Arc::new(Mutex::new(rx)),
            pow_difficulty,
            subscribers:Arc::new(Mutex::new(HashMap::new())),
            max_ttl,
            min_argon2_params,
            cleanup_interval,
            blacklist_duration,
            node_requirements:Arc::new(Mutex::new(HashMap::new())),
            node_discovery_interval,
        });
        // accept loop
        let ncl = node.clone();
        tokio::spawn(async move{ncl.run().await});
        // cleanup
        let ncl2 = node.clone();
        tokio::spawn(async move{ncl2.cleanup_expired_packets().await});
        // bootstrap/discovery
        let nboot = node.clone();
        tokio::spawn(async move{
            for b in bootstrap_nodes{nboot.bootstrap(b).await;}
            let discovered = nboot.iterative_find_nodes(prefix.clone()).await;
            for ni in discovered{nboot.update_routing_table(ni).await;}
            nboot.start_periodic_find_nodes().await;
        });
        node
    }

    /// Accept incoming and outgoing messages
    async fn run(self:Arc<Self>){
        let listener = TcpListener::bind(self.address).await.expect("bind failed");
        let tx = self.network_tx.clone();
        tokio::spawn(async move{
            loop{
                if let Ok((s,_))=listener.accept().await{let _=tx.send(NetworkMessage::Incoming{stream:s}).await;}
            }
        });
        let mut rx=self.network_rx.lock().await;
        while let Some(msg)=rx.recv().await{
            match msg{
                NetworkMessage::Incoming{stream}=>{
                    let me=self.clone();
                    tokio::spawn(async move{me.handle_connection(stream).await});
                }
                NetworkMessage::Outgoing{message,address}=>{
                    let me=self.clone();
                    tokio::spawn(async move{me.send_message(message,address).await});
                }
            }
        }
    }

    /// Cleanup expired entries
    async fn cleanup_expired_packets(self:Arc<Self>){
        loop{
            sleep(self.cleanup_interval).await;
            let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            self.packet_store.lock().await.retain(|_,p|p.timestamp+p.ttl>now);
            self.blacklist.lock().await.retain(|_,&mut t|Instant::now()<t);
        }
    }

    /// Bootstrap handshake
    async fn bootstrap(&self,addr:SocketAddr){
        if let Ok(mut s)=TcpStream::connect(addr).await{let _=self.send_handshake(&mut s).await;let _=self.receive_handshake_ack(&mut s).await;let _=self.find_node_request(&mut s).await;}
    }

    /// Periodic rediscovery
    async fn start_periodic_find_nodes(self:Arc<Self>){
        let interval=self.node_discovery_interval;
        let bitlen=self.prefix.bit_length;
        let me=self.clone();
        tokio::spawn(async move{
            loop{
                sleep(interval).await;
                let targ=RoutingPrefix::random(bitlen);
                let nds=me.iterative_find_nodes(targ).await;
                for ni in nds{me.update_routing_table(ni).await;}
            }
        });
    }

    /// Kademlia iterative lookup
    pub async fn iterative_find_nodes(&self,target:RoutingPrefix)->Vec<NodeInfo>{
        let mut cls=self.routing_service.find_closest(&target).await;
        let mut seen=HashSet::new();
        for _ in 0..5{
            let mut prog=false;
            for ni in cls.clone(){
                if seen.insert(ni.id){
                    if let Some(m)=self.query_for_closest_nodes(&target,ni.address).await{cls.extend(m);
                        cls.sort_by_key(|n| n.routing_prefix.distance(&target).unwrap_or(u64::MAX));
                        cls.truncate(20);
                        prog=true;
                    }
                }
            }
            if !prog{break;}
        }
        cls
    }

    /// RPC to node
    async fn query_for_closest_nodes(&self,target:&RoutingPrefix,addr:SocketAddr)->Option<Vec<NodeInfo>>{
        if self.is_blacklisted(&addr.ip()).await{return None;}
        let mut s=TcpStream::connect(addr).await.ok()?;
        let _=self.send_handshake(&mut s).await.ok()?;
        let _=self.receive_handshake_ack(&mut s).await.ok()?;
        let req=Message::FindClosestNodes(*target);
        let d=bincode::serialize(&req).ok()?;
        s.write_all(&d).await.ok()?;
        let mut buf=vec![0;8192];
        let n=s.read(&mut buf).await.ok()?;
        if let Message::Nodes(ls)=bincode::deserialize(&buf[..n]).ok()?{
            for ni in &ls{self.update_routing_table(ni.clone()).await;}
            Some(ls)
        } else { None }
    }

    /// Accept incoming and outgoing messages
    async fn handle_connection(self: Arc<Self>, mut stream: TcpStream) {
        let peer = stream.peer_addr().unwrap_or(self.address);
        if self.is_blacklisted(&peer.ip()).await {
            return;
        }

        loop {
            // read the next message
            let mut buf = vec![0; 8192];
            let n = match stream.read(&mut buf).await {
                Ok(0) => return,              // client closed
                Ok(n) => n,
                Err(_)   => return,           // read error
            };

            let msg: Message = match bincode::deserialize(&buf[..n]) {
                Ok(m) => m,
                Err(_) => {
                    self.blacklist_ip(&peer.ip()).await;
                    return;
                }
            };

            match msg {
                // 1) Keep reading after a client handshake
                Message::ClientHandshake => {
                    let ack = Message::ClientHandshakeAck(self.get_node_info_extended());
                    let _ = stream.write_all(&bincode::serialize(&ack).unwrap()).await;
                    continue;
                }

                // 2) Same for internal node handshakes
                Message::Handshake(ni) => {
                    self.update_routing_table_extended(ni.clone()).await;
                    let ack = Message::HandshakeAck(self.get_node_info_extended());
                    let _ = stream.write_all(&bincode::serialize(&ack).unwrap()).await;
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
    async fn handle_message(&self,msg:Message,sender:SocketAddr){
        match msg{
            Message::FindClosestNodes(p)=>{
                let ls=self.routing_service.find_closest(&p).await;
                self.send_message(Message::Nodes(ls),sender).await;
            }
            Message::FindServingNodes(p)=>{
                let ext=self.find_nodes_serving(&p).await;
                self.send_message(Message::NodesExtended(ext),sender).await;
            }
            Message::Packet(pkt)=>{ self.handle_packet(pkt,sender).await; }
            Message::Ping=>{ self.send_message(Message::Pong,sender).await; }
            Message::Pong=>{ self.routing_service.mark_alive(sender).await; }
            _=>{ warn!("Unexpected message from {}",sender); }
        }
    }

    /// Manage new subscriptions
    async fn handle_subscribe(self: Arc<Self>,_peer:SocketAddr,mut st:TcpStream){
        let (tx,mut rx)=broadcast::channel(100);
        self.subscribers.lock().await.insert(_peer,tx.clone());
        for pkt in self.packet_store.lock().await.values().cloned(){
            let d=bincode::serialize(&Message::Packet(pkt)).unwrap();
            let _=st.write_all(&d).await;
        }
        let me=self.clone();
        let peer_addr = _peer;
        tokio::spawn(async move{
            while let Ok(pkt)=rx.recv().await {
                let d=bincode::serialize(&Message::Packet(pkt)).unwrap();
                if st.write_all(&d).await.is_err() { break; }
            }
            me.subscribers.lock().await.remove(&peer_addr);
        });
    }

    /// Manage unsubscribes
    async fn handle_unsubscribe(&self,peer:SocketAddr,mut st:TcpStream){
        self.subscribers.lock().await.remove(&peer);
        let _=st.write_all(&bincode::serialize(&Message::UnsubscribeAck).unwrap()).await;
    }

    /// Process and forward a packet
    async fn handle_packet(&self,packet:Packet,sender:SocketAddr){
        info!("Node prefix: {:?}, Packet prefix: {:?}, Serves: {}", 
            self.prefix, packet.routing_prefix, 
            self.prefix.serves(&packet.routing_prefix));
        if self.packet_store.lock().await.contains_key(&packet.pow_hash){ return; }
        if packet.ttl>self.max_ttl{ self.blacklist_ip(&sender.ip()).await; return; }
        if !packet.argon2_params.meets_min(&self.min_argon2_params){ self.blacklist_ip(&sender.ip()).await; return; }
        if !packet.verify_pow(self.pow_difficulty){ self.blacklist_ip(&sender.ip()).await; return; }
        if self.prefix.serves(&packet.routing_prefix) {
            self.packet_store.lock().await.insert(packet.pow_hash.clone(), packet.clone());
            for tx in self.subscribers.lock().await.values() {
                let _ = tx.send(packet.clone());
            }
        }
        self.forward_packet(packet,sender).await;
    }

    /// Forward to peers based on requirements
    async fn forward_packet(&self,packet:Packet,sender:SocketAddr){
        let nodes=self.routing_service.find_closest(&packet.routing_prefix).await;
        let reqs=self.node_requirements.lock().await.clone();
        for ni in nodes {
            if ni.address==sender { continue; }
            if let Some(r)=reqs.get(&ni.id) {
                if packet.ttl>r.max_ttl || !packet.argon2_params.meets_min(&r.min_argon2_params) { continue; }
                self.send_message(Message::Packet(packet.clone()), r.address).await;
            }
        }
    }

    /// Get serving nodes with extended info
    async fn find_nodes_serving(&self,p:&RoutingPrefix)->Vec<NodeInfoExtended>{
        let bas=self.routing_service.find_closest(p).await;
        let reqs=self.node_requirements.lock().await;
        bas.into_iter().filter_map(|ni| reqs.get(&ni.id).cloned()).collect()
    }

    /// Send handshake
    async fn send_handshake(&self,st:&mut TcpStream)->io::Result<()> {
        let msg=Message::Handshake(self.get_node_info_extended());
        let d=bincode::serialize(&msg).map_err(|e|io::Error::new(io::ErrorKind::Other,e))?;
        st.write_all(&d).await
    }

    /// Receive handshake ack
    async fn receive_handshake_ack(&self,st:&mut TcpStream)->io::Result<()> {
        let mut buf=vec![0;4096];
        let n=st.read(&mut buf).await?;
        if let Message::HandshakeAck(ni)=bincode::deserialize(&buf[..n]).map_err(|e|io::Error::new(io::ErrorKind::Other,e))? {
            self.update_routing_table_extended(ni).await;
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::Other,"Bad ack"))
        }
    }

    /// Simple find-node
    async fn find_node_request(&self,st:&mut TcpStream)->io::Result<()> {
        let msg=Message::FindClosestNodes(self.prefix);
        let d=bincode::serialize(&msg).map_err(|e|io::Error::new(io::ErrorKind::Other,e))?;
        st.write_all(&d).await?;
        let mut buf=vec![0;4096];
        let n=st.read(&mut buf).await?;
        if let Message::Nodes(ls)=bincode::deserialize(&buf[..n]).map_err(|e|io::Error::new(io::ErrorKind::Other,e))? {
            for ni in ls { self.update_routing_table(ni).await; }
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::Other,"Bad resp"))
        }
    }

    /// Insert into routing
    async fn update_routing_table(&self,ni:NodeInfo){ self.routing_service.insert(ni).await; }

    /// Insert and store extended
    async fn update_routing_table_extended(&self,ni:NodeInfoExtended){
        let b=NodeInfo{id:ni.id,routing_prefix:ni.routing_prefix,address:ni.address};
        self.routing_service.insert(b).await;
        self.node_requirements.lock().await.insert(ni.id,ni);
    }

    /// Own info
    fn get_node_info_extended(&self)->NodeInfoExtended{
        NodeInfoExtended{
            id:self.id,
            address:self.address,
            routing_prefix:self.prefix,
            pow_difficulty:self.pow_difficulty,
            max_ttl:self.max_ttl,
            min_argon2_params:self.min_argon2_params,
        }
    }

    /// Blacklist and remove
    async fn blacklist_ip(&self,ip:&IpAddr){
        if *ip==self.address.ip() { return; }
        self.blacklist.lock().await.insert(*ip,Instant::now()+self.blacklist_duration);
        self.routing_service.remove_by_ip(*ip).await;
    }

    /// Check blacklist
    async fn is_blacklisted(&self,ip:&IpAddr)->bool{
        let mut b=self.blacklist.lock().await;
        if let Some(&t)=b.get(ip) {
            if Instant::now()>=t { b.remove(ip); false } else { true }
        } else { false }
    }

    /// Send a network message
    async fn send_message(&self,message:Message,addr:SocketAddr){
        if self.is_blacklisted(&addr.ip()).await { return; }
        if let Ok(mut s)=TcpStream::connect(addr).await {
            let d=bincode::serialize(&message).unwrap();
            let _=s.write_all(&d).await;
        }
    }
}
