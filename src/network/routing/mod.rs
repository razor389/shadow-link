//! Abstraction layer for routing table operations.
//!
//! `RoutingManager` encapsulates the underlying DHT-based `RoutingTable` and
//! provides a stable interface for insertion, removal, and lookups, hiding
//! locking and internal details.

pub mod api;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::types::node_info::NodeInfo;
use crate::types::routing_prefix::RoutingPrefix;
use crate::network::routing::api::RoutingService;
use async_trait::async_trait;
use super::dht::RoutingTable;

/// High-level manager for routing table interactions.
#[derive(Clone)]
pub struct RoutingManager {
    inner: Arc<Mutex<RoutingTable>>,
}

impl RoutingManager {
    /// Create a new routing manager with the given node ID and prefix.
    pub fn new(node_id: [u8; 20], prefix: RoutingPrefix) -> Self {
        let table = RoutingTable::new(node_id, prefix);
        RoutingManager {
            inner: Arc::new(Mutex::new(table)),
        }
    }

    /// Insert or update node information in the routing table.
    pub async fn insert(&self, node_info: NodeInfo) {
        let mut tbl = self.inner.lock().await;
        tbl.update(node_info);
    }

    /// Remove a node by its IP address.
    pub async fn remove_by_ip(&self, ip: IpAddr) {
        let mut tbl = self.inner.lock().await;
        tbl.remove_node_by_ip(&ip);
    }

    /// Mark a node as alive (moves it to end of its k-bucket).
    pub async fn mark_alive(&self, addr: SocketAddr) {
        let mut tbl = self.inner.lock().await;
        tbl.mark_node_alive(addr);
    }

    /// Get a snapshot of all known nodes.
    pub async fn all_nodes(&self) -> Vec<NodeInfo> {
        let tbl = self.inner.lock().await;
        tbl.get_all_nodes()
    }

    /// Find up to `k` closest nodes to the given routing prefix.
    pub async fn find_closest_nodes(&self, prefix: &RoutingPrefix) -> Vec<NodeInfo> {
        let mut nodes = self.all_nodes().await;
        nodes.sort_by(|a, b| {
            let da = a.routing_prefix.distance(prefix).unwrap_or(u64::MAX);
            let db = b.routing_prefix.distance(prefix).unwrap_or(u64::MAX);
            da.cmp(&db)
        });
        nodes.truncate(super::dht::K); // Use K from DHT
        nodes
    }
}

#[async_trait]
impl RoutingService for RoutingManager {
    async fn insert(&self, node: NodeInfo) {
        self.insert(node).await;
    }

    async fn remove_by_ip(&self, ip: IpAddr) {
        self.remove_by_ip(ip).await;
    }

    async fn mark_alive(&self, addr: SocketAddr) {
        self.mark_alive(addr).await;
    }

    async fn all_nodes(&self) -> Vec<NodeInfo> {
        self.all_nodes().await
    }

    async fn find_closest(&self, prefix: &RoutingPrefix) -> Vec<NodeInfo> {
        self.find_closest_nodes(prefix).await
    }
}
