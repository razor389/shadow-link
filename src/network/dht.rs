// src/network/dht.rs

use std::net::{IpAddr, SocketAddr};
use crate::types::{node_info::{NodeId, NodeInfo}, routing_prefix::RoutingPrefix};

/// The maximum number of nodes per k-bucket (k)
const K: usize = 20;
/// The minimum acceptable bucket index (nodes with a lower index are considered too far)
const MIN_ACCEPTABLE_BUCKET_INDEX: usize = 5;

/// Kademlia Routing Table
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
        let mut k_buckets = Vec::new();
        for _ in 0..64 { // Adjusted to 64 buckets
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

    /// Find the k closest nodes to the target prefix
    pub fn find_closest_nodes(&self, target_prefix: &RoutingPrefix) -> Vec<NodeInfo> {
        let mut all_nodes = Vec::new();

        // Collect all nodes from the k-buckets
        for bucket in &self.k_buckets {
            all_nodes.extend(bucket.nodes.clone());
        }

        // Sort nodes by XOR distance to the target prefix
        all_nodes.sort_by(|a, b| {
            a.routing_prefix.xor_distance(target_prefix)
                .unwrap_or(u64::MAX)
                .cmp(&b.routing_prefix.xor_distance(target_prefix).unwrap_or(u64::MAX))
        });

        // Truncate the result to return up to K nodes
        all_nodes.truncate(K);
        all_nodes
    }

    /// Update the routing table with a new node
    pub fn update(&mut self, node_info: NodeInfo) {
        if let Some(distance) = self.prefix.xor_distance(&node_info.routing_prefix) {
            if distance == 0 {
                // Do not add own node or identical nodes
                return;
            }

            let leading_zeros = distance.leading_zeros();

            if leading_zeros >= 64 {
                // Invalid distance (only possible if distance == 0, already handled)
                return;
            }

            // Calculate the bucket index based on Kademlia's convention
            // Bucket 0: [2^63, 2^64), Bucket 1: [2^62, 2^63), ..., Bucket 63: [2^0, 2^1)
            let bucket_index = (63 - leading_zeros) as usize;

            if bucket_index >= self.k_buckets.len() {
                return; // Ignore nodes that are out of bounds (shouldn't happen)
            }

            // **Add this check for MIN_ACCEPTABLE_BUCKET_INDEX**
            if bucket_index < MIN_ACCEPTABLE_BUCKET_INDEX {
                return; // Ignore nodes that are too far
            }

            let bucket = &mut self.k_buckets[bucket_index];

            // Check if the node is already in the bucket
            if let Some(pos) = bucket.nodes.iter().position(|n| n.id == node_info.id) {
                // Move the node to the end to mark it as recently seen
                let node = bucket.nodes.remove(pos);
                bucket.nodes.push(node);
            } else {
                if bucket.nodes.len() < K {
                    bucket.nodes.push(node_info);
                } else {
                    // Bucket is full; replace the least recently seen node
                    bucket.nodes.remove(0);
                    bucket.nodes.push(node_info);
                }
            }
        }
    }

    /// Remove a node by IP address from the routing table
    pub fn remove_node_by_ip(&mut self, ip: &IpAddr) {
        for bucket in &mut self.k_buckets {
            bucket.nodes.retain(|n| &n.address.ip() != ip);
        }
    }

    /// Mark a node as alive
    pub fn mark_node_alive(&mut self, address: SocketAddr) {
        for bucket in &mut self.k_buckets {
            if let Some(pos) = bucket.nodes.iter().position(|n| n.address == address) {
                // Move the node to the end to mark it as recently seen
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        node_info::NodeInfo,
        routing_prefix::RoutingPrefix,
    };

    /// Helper function to create a RoutingPrefix with bits aligned to higher bits
    fn create_prefix(bit_length: u8, bits: u64) -> RoutingPrefix {
        assert!(bit_length <= 64, "bit_length must be <= 64");
        if bit_length == 0 {
            RoutingPrefix {
                bit_length,
                bits: None,
            }
        } else if bit_length == 64 {
            RoutingPrefix {
                bit_length,
                bits: Some(bits),
            }
        } else {
            let bits_aligned = (bits & ((1u64 << bit_length) - 1)) << (64 - bit_length);
            RoutingPrefix {
                bit_length,
                bits: Some(bits_aligned),
            }
        }
    }

    /// Helper function to generate NodeInfo with specific parameters
    fn generate_node_info(id_value: u8, prefix_bits: u64, address: &str) -> NodeInfo {
        NodeInfo {
            id: [id_value; 20],
            routing_prefix: RoutingPrefix {
                bit_length: 8,
                bits: Some(prefix_bits << (64 - 8)), // Align to higher bits
            },
            address: address.parse().unwrap(),
        }
    }

    #[test]
    fn test_routing_table_new() {
        // Create a new routing table
        let id = [0u8; 20];
        let routing_table_prefix_bits = 0b10101011u64; // Controlled prefix
        let prefix = create_prefix(8, routing_table_prefix_bits);
        let routing_table = RoutingTable::new(id, prefix.clone());

        // Check that the routing table is initialized correctly
        assert_eq!(routing_table.id, id, "Routing table ID mismatch");
        assert_eq!(routing_table.prefix, prefix, "Routing table prefix mismatch");
        assert_eq!(routing_table.k_buckets.len(), 64, "Incorrect number of k_buckets");
        // Check that all buckets are empty
        for bucket in &routing_table.k_buckets {
            assert!(bucket.nodes.is_empty(), "Bucket should be empty");
        }
    }

    #[test]
    fn test_routing_table_update_and_get_all_nodes() {
        let id = [0u8; 20];
        let routing_table_prefix_bits = 0b10101011u64; // Controlled prefix
        let prefix = create_prefix(8, routing_table_prefix_bits);
        let mut routing_table = RoutingTable::new(id, prefix);

        // Create some NodeInfo instances
        let node1 = generate_node_info(1, 0b10101010, "127.0.0.1:8080"); // Same bucket
        let node2 = generate_node_info(2, 0b10101010, "127.0.0.2:8080"); // Same bucket

        // Update the routing table with the nodes
        routing_table.update(node1.clone());
        routing_table.update(node2.clone());

        // Get all nodes and check
        let nodes = routing_table.get_all_nodes();
        assert_eq!(nodes.len(), 2, "Routing table should have 2 nodes");
        assert!(nodes.contains(&node1), "Routing table should contain node1");
        assert!(nodes.contains(&node2), "Routing table should contain node2");
    }

    #[test]
    fn test_routing_table_find_closest_nodes() {
        let id = [0u8; 20];
        let routing_table_prefix_bits = 0b00001111u64; // Controlled prefix
        let prefix = create_prefix(8, routing_table_prefix_bits);
        let mut routing_table = RoutingTable::new(id, prefix.clone());

        // Create some NodeInfo instances with different prefixes
        let target_prefix = create_prefix(8, 0b00001111u64); // Target prefix same as routing table

        let node1 = generate_node_info(1, 0b00001110, "127.0.0.1:8080"); // Distance=0b00000001
        let node2 = generate_node_info(2, 0b00001100, "127.0.0.2:8080"); // Distance=0b00000011
        let node3 = generate_node_info(3, 0b11110000, "127.0.0.3:8080"); // Distance=0b11111111

        // Update the routing table with the nodes
        routing_table.update(node1.clone());
        routing_table.update(node2.clone());
        routing_table.update(node3.clone());

        // Find closest nodes to target_prefix
        let closest_nodes = routing_table.find_closest_nodes(&target_prefix);

        // Should return node1, node2, node3 in order of closeness
        assert_eq!(closest_nodes.len(), 3, "Should return all 3 nodes");

        // Check the order based on distance
        assert_eq!(closest_nodes[0], node1, "node1 should be the closest");
        assert_eq!(closest_nodes[1], node2, "node2 should be the second closest");
        assert_eq!(closest_nodes[2], node3, "node3 should be the farthest");
    }

    #[test]
    fn test_routing_table_remove_node_by_ip() {
        let id = [0u8; 20];
        let routing_table_prefix_bits = 0b10101011u64; // Controlled prefix
        let prefix = create_prefix(8, routing_table_prefix_bits);
        let mut routing_table = RoutingTable::new(id, prefix);

        let node = generate_node_info(1, 0b10101010, "127.0.0.1:8080"); // Same bucket

        routing_table.update(node.clone());
        assert_eq!(routing_table.get_all_nodes().len(), 1, "Routing table should have 1 node");

        routing_table.remove_node_by_ip(&node.address.ip());
        assert_eq!(routing_table.get_all_nodes().len(), 0, "Routing table should be empty after removal");
    }

    #[test]
    fn test_routing_table_mark_node_alive() {
        let id = [0u8; 20];
        let routing_table_prefix_bits = 0b10101011u64; // Controlled prefix
        let prefix = create_prefix(8, routing_table_prefix_bits);
        let mut routing_table = RoutingTable::new(id, prefix);

        let node1 = generate_node_info(1, 0b10101010, "127.0.0.1:8080"); // Same bucket
        let node2 = generate_node_info(2, 0b10101010, "127.0.0.2:8080"); // Same bucket

        // Update routing table with nodes
        routing_table.update(node1.clone());
        routing_table.update(node2.clone());

        // Initially, node2 is the most recently seen node in its bucket
        // Mark node1 as alive, it should become the most recently seen node

        routing_table.mark_node_alive(node1.address);

        // Verify that node1 is now the most recently seen node in its bucket
        if let Some(distance) = routing_table.prefix.xor_distance(&node1.routing_prefix) {
            let bucket_index = (63 - distance.leading_zeros()) as usize; // Corrected calculation
            let bucket = &routing_table.k_buckets[bucket_index];
            let last_node = bucket.nodes.last().unwrap();
            assert_eq!(last_node.id, node1.id, "node1 should be the most recently seen node");
        } else {
            panic!("Failed to compute distance");
        }
    }

    #[test]
    fn test_routing_table_bucket_overflow() {
        // Test that the routing table handles bucket overflow correctly
        let id = [0u8; 20];
        let routing_table_prefix_bits = 0b10101011u64; // Controlled prefix
        let prefix = create_prefix(8, routing_table_prefix_bits);
        let mut routing_table = RoutingTable::new(id, prefix);

        // Generate K + 1 nodes that should all go into the same bucket
        let mut nodes = Vec::new();
        for i in 0..(K as u8 + 1) {
            let node = generate_node_info(
                i,
                0b10101010, // Node prefix bits
                &format!("127.0.0.{}:8080", i),
            );
            nodes.push(node);
        }

        // Update the routing table with all nodes
        for node in &nodes {
            routing_table.update(node.clone());
        }

        // The bucket should contain only K nodes
        if let Some(distance) = routing_table.prefix.xor_distance(&nodes[0].routing_prefix) {
            let bucket_index = (63 - distance.leading_zeros()) as usize; // Corrected calculation
            let bucket = &routing_table.k_buckets[bucket_index];
            assert_eq!(bucket.nodes.len(), K, "Bucket should contain K nodes");
        } else {
            panic!("Failed to compute distance");
        }

        // The least recently seen node (first inserted) should have been replaced
        let all_nodes = routing_table.get_all_nodes();
        assert!(!all_nodes.contains(&nodes[0]), "The first node should have been removed");
        for node in &nodes[1..] {
            assert!(all_nodes.contains(node), "Node {:?} should be present", node);
        }
    }

    #[test]
    fn test_routing_table_ignore_far_nodes() {
        // Nodes that are too far (bucket index < MIN_ACCEPTABLE_BUCKET_INDEX) should be ignored
        let id = [0u8; 20];
        let routing_table_prefix_bits = 0xFF00000000000000u64; // Controlled prefix
        let prefix = create_prefix(64, routing_table_prefix_bits);
        let mut routing_table = RoutingTable::new(id.clone(), prefix.clone());

        // Create a distant node with distance=1<<4=16, which results in bucket_index=4
        let distance_bits = 1u64 << 4; // 0x0000000000000010
        let node_prefix_bits = routing_table_prefix_bits ^ distance_bits; // 0xFF00000000000000 ^ 0x10 = 0xFF00000000000010
        let distant_prefix = create_prefix(64, node_prefix_bits);
        let distant_node = NodeInfo {
            id: [1u8; 20],
            routing_prefix: distant_prefix,
            address: "127.0.0.1:8080".parse().unwrap(),
        };

        routing_table.update(distant_node);

        // The node should not be added to the routing table because it's too far
        let nodes = routing_table.get_all_nodes();
        assert!(nodes.is_empty(), "Distant node should be ignored");
    }

}
