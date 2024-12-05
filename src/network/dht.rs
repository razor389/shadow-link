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
        for _ in 0..65 {
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
        all_nodes.sort_by_key(|node| node.routing_prefix.xor_distance(target_prefix));

        // Truncate the result to return up to K nodes
        all_nodes.truncate(K);
        all_nodes
    }

    /// Update the routing table with a new node
    pub fn update(&mut self, node_info: NodeInfo) {
        if let Some(distance) = self.prefix.xor_distance(&node_info.routing_prefix) {
            // Calculate the bucket index based on the leading zeros in the XOR distance
            let bucket_index = distance.leading_zeros() as usize;

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
                    // Bucket is full; implement replacement policies if needed
                    // For simplicity, we'll replace the least recently seen node
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

    fn generate_node_info(id_value: u8, prefix_bits: u64, address: &str) -> NodeInfo {
        NodeInfo {
            id: [id_value; 20],
            routing_prefix: RoutingPrefix {
                bit_length: 8,
                bits: Some(prefix_bits),
            },
            address: address.parse().unwrap(),
        }
    }

    #[test]
    fn test_routing_table_new() {
        // Create a new routing table
        let id = [0u8; 20];
        let prefix = RoutingPrefix::random(8);
        let routing_table = RoutingTable::new(id, prefix.clone());

        // Check that the routing table is initialized correctly
        assert_eq!(routing_table.id, id);
        assert_eq!(routing_table.prefix, prefix);
        assert_eq!(routing_table.k_buckets.len(), 65); // Updated to 65
        // Check that all buckets are empty
        for bucket in &routing_table.k_buckets {
            assert!(bucket.nodes.is_empty());
        }
    }

    #[test]
    fn test_routing_table_update_and_get_all_nodes() {
        let id = [0u8; 20];
        let prefix = RoutingPrefix::random(8);
        let mut routing_table = RoutingTable::new(id, prefix);

        // Create some NodeInfo instances
        let node1 = generate_node_info(1, 0b10101010, "127.0.0.1:8080");
        let node2 = generate_node_info(2, 0b01010101, "127.0.0.2:8080");

        // Update the routing table with the nodes
        routing_table.update(node1.clone());
        routing_table.update(node2.clone());

        // Get all nodes and check
        let nodes = routing_table.get_all_nodes();
        assert_eq!(nodes.len(), 2);
        assert!(nodes.contains(&node1));
        assert!(nodes.contains(&node2));
    }

    #[test]
    fn test_routing_table_find_closest_nodes() {
        let id = [0u8; 20];
        let prefix = RoutingPrefix {
            bit_length: 8,
            bits: Some(0b00001111),
        };
        let mut routing_table = RoutingTable::new(id, prefix);

        // Create some NodeInfo instances with different prefixes
        let target_prefix = RoutingPrefix {
            bit_length: 8,
            bits: Some(0b00001111),
        };

        let node1 = generate_node_info(1, 0b00001110, "127.0.0.1:8080");
        let node2 = generate_node_info(2, 0b00001100, "127.0.0.2:8080");
        let node3 = generate_node_info(3, 0b11110000, "127.0.0.3:8080");

        // Update the routing table with the nodes
        routing_table.update(node1.clone());
        routing_table.update(node2.clone());
        routing_table.update(node3.clone());

        // Find closest nodes to target_prefix
        let closest_nodes = routing_table.find_closest_nodes(&target_prefix);

        // Should return node1 and node2 (node3 is farther away)
        assert_eq!(closest_nodes.len(), 3); // Since K=20, and we have 3 nodes
        // Nodes should be sorted by distance, so node1 and node2 should be first
        assert_eq!(closest_nodes[0], node1);
        assert_eq!(closest_nodes[1], node2);
        assert_eq!(closest_nodes[2], node3);
    }

    #[test]
    fn test_routing_table_remove_node_by_ip() {
        let id = [0u8; 20];
        let prefix = RoutingPrefix::random(8);
        let mut routing_table = RoutingTable::new(id, prefix);

        let node = generate_node_info(1, 0b10101010, "127.0.0.1:8080");

        routing_table.update(node.clone());
        assert_eq!(routing_table.get_all_nodes().len(), 1);

        routing_table.remove_node_by_ip(&node.address.ip());
        assert_eq!(routing_table.get_all_nodes().len(), 0);
    }

    #[test]
    fn test_routing_table_mark_node_alive() {
        let id = [0u8; 20];
        let prefix = RoutingPrefix::random(8);
        let mut routing_table = RoutingTable::new(id, prefix);

        let node1 = generate_node_info(1, 0b10101010, "127.0.0.1:8080");
        let node2 = generate_node_info(2, 0b01010101, "127.0.0.2:8080");

        // Update routing table with nodes
        routing_table.update(node1.clone());
        routing_table.update(node2.clone());

        // Initially, node2 is the most recently seen node in its bucket
        // Mark node1 as alive, it should become the most recently seen node

        routing_table.mark_node_alive(node1.address);

        // Verify that node1 is now the most recently seen node in its bucket
        if let Some(distance) = routing_table.prefix.xor_distance(&node1.routing_prefix) {
            let bucket_index = distance.leading_zeros() as usize;
            let bucket = &routing_table.k_buckets[bucket_index];
            let last_node = bucket.nodes.last().unwrap();
            assert_eq!(last_node.id, node1.id);
        } else {
            panic!("Failed to compute distance");
        }
    }

    #[test]
    fn test_routing_table_bucket_overflow() {
        // Test that the routing table handles bucket overflow correctly
        let id = [0u8; 20];
        let prefix = RoutingPrefix::random(8);
        let mut routing_table = RoutingTable::new(id, prefix);

        // Generate K + 1 nodes that should all go into the same bucket
        let mut nodes = Vec::new();
        for i in 0..(K as u8 + 1) {
            let node = generate_node_info(
                i,
                0b10101010, // Same prefix bits to ensure they go into the same bucket
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
            let bucket_index = distance.leading_zeros() as usize;
            let bucket = &routing_table.k_buckets[bucket_index];
            assert_eq!(bucket.nodes.len(), K);
        } else {
            panic!("Failed to compute distance");
        }

        // The least recently seen node (first inserted) should have been replaced
        let all_nodes = routing_table.get_all_nodes();
        assert!(!all_nodes.contains(&nodes[0])); // The first node should have been removed
        for node in &nodes[1..] {
            assert!(all_nodes.contains(node));
        }
    }

    #[test]
    fn test_routing_table_ignore_far_nodes() {
        // Nodes that are too far (bucket index < MIN_ACCEPTABLE_BUCKET_INDEX) should be ignored
        let id = [0u8; 20];
        let prefix = RoutingPrefix::random(64);
        let mut routing_table = RoutingTable::new(id, prefix.clone());

        // Create a distant node
        let distant_prefix = RoutingPrefix {
            bit_length: 64,
            bits: Some(!prefix.bits.unwrap()), // Maximize distance (minimal leading zeros)
        };
        let distant_node = NodeInfo {
            id: [1u8; 20],
            routing_prefix: distant_prefix,
            address: "127.0.0.1:8080".parse().unwrap(),
        };

        routing_table.update(distant_node);

        // The node should not be added to the routing table
        let nodes = routing_table.get_all_nodes();
        assert!(nodes.is_empty(), "Distant node should be ignored");
    }

}
