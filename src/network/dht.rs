// src/network/dht.rs

use std::net::{IpAddr, SocketAddr};

use crate::types::{
    node_info::{NodeId, NodeInfo},
    routing_prefix::RoutingPrefix,
};

/// The maximum number of nodes per k-bucket (k)
pub const K: usize = 20;

/// Kademlia-like Routing Table, but using a tree-based distance.
pub struct RoutingTable {
    pub id: NodeId,
    pub prefix: RoutingPrefix,
    pub k_buckets: Vec<KBucket>,
}

pub struct KBucket {
    pub nodes: Vec<NodeInfo>,
}

impl RoutingTable {
    pub fn new(id: NodeId, prefix: RoutingPrefix) -> Self {
        // Buckets indexed by tree distance [0..=MAX_DIST]
        const MAX_DIST: usize = 64;
        let mut k_buckets = Vec::with_capacity(MAX_DIST + 1);
        for _ in 0..=MAX_DIST {
            k_buckets.push(KBucket::new());
        }
        RoutingTable { id, prefix, k_buckets }
    }

    /// Get all nodes in the routing table
    pub fn get_all_nodes(&self) -> Vec<NodeInfo> {
        let mut nodes = Vec::new();
        for bucket in &self.k_buckets {
            nodes.extend(bucket.nodes.clone());
        }
        nodes
    }

    /// Find the k closest nodes to the target prefix (by tree distance).
    pub fn find_closest_nodes(&self, target_prefix: &RoutingPrefix) -> Vec<NodeInfo> {
        let mut all_nodes = self.get_all_nodes();

        all_nodes.sort_by(|a, b| {
            let da = a.routing_prefix.distance(target_prefix).unwrap_or(u64::MAX);
            let db = b.routing_prefix.distance(target_prefix).unwrap_or(u64::MAX);
            da.cmp(&db)
        });

        all_nodes.truncate(K);
        all_nodes
    }

    /// Update the routing table with a new node
    pub fn update(&mut self, node_info: NodeInfo) {
        if node_info.id == self.id {
            return;
        }

        if let Some(dist) = self.prefix.distance(&node_info.routing_prefix) {
            let idx = (dist as usize).min(self.k_buckets.len() - 1);
            let bucket = &mut self.k_buckets[idx];

            if let Some(pos) = bucket.nodes.iter().position(|n| n.id == node_info.id) {
                let node = bucket.nodes.remove(pos);
                bucket.nodes.push(node);
            } else if bucket.nodes.len() < K {
                bucket.nodes.push(node_info);
            } else {
                bucket.nodes.remove(0);
                bucket.nodes.push(node_info);
            }
        }
    }

    /// Remove a node by IP address from the routing table
    pub fn remove_node_by_ip(&mut self, ip: &IpAddr) {
        for bucket in &mut self.k_buckets {
            bucket.nodes.retain(|n| &n.address.ip() != ip);
        }
    }

    /// Mark a node as 'alive' => move it to the end of its bucket
    pub fn mark_node_alive(&mut self, address: SocketAddr) {
        for bucket in &mut self.k_buckets {
            if let Some(pos) = bucket.nodes.iter().position(|n| n.address == address) {
                let node = bucket.nodes.remove(pos);
                bucket.nodes.push(node);
                return;
            }
        }
    }
}

impl KBucket {
    pub fn new() -> Self {
        KBucket { nodes: Vec::new() }
    }
}