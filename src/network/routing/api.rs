use std::net::{IpAddr, SocketAddr};
use async_trait::async_trait;
use crate::types::node_info::NodeInfo;
use crate::types::routing_prefix::RoutingPrefix;

/// Abstraction layer for DHT / routing operations.
#[async_trait]
pub trait RoutingService: Send + Sync {
    /// Insert or update node information in the routing structure.
    async fn insert(&self, node: NodeInfo);

    /// Remove a node by its IP address.
    async fn remove_by_ip(&self, ip: IpAddr);

    /// Mark a node as alive (recently seen).
    async fn mark_alive(&self, addr: SocketAddr);

    /// Get a snapshot of all known nodes.
    async fn all_nodes(&self) -> Vec<NodeInfo>;

    /// Find up to `k` closest nodes to the given routing prefix.
    async fn find_closest(&self, prefix: &RoutingPrefix) -> Vec<NodeInfo>;

    /// Deprecated: pure DHT interface, delegates to find_closest by default.
    async fn find_serving(&self, prefix: &RoutingPrefix) -> Vec<NodeInfo> {
        self.find_closest(prefix).await
    }
}
