// src/network/dht.rs

use std::net::{IpAddr, SocketAddr};
use crate::types::{node_info::{NodeId, NodeInfo}, routing_prefix::RoutingPrefix};

/// The maximum number of nodes per k-bucket (k)
const K: usize = 20;
/// The maximum acceptable bucket index (nodes with a higher index are considered too far)
const MAX_ACCEPTABLE_BUCKET_INDEX: usize = 58; // 64 - MIN_ACCEPTABLE_BUCKET_INDEX from original

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
        for _ in 0..64 { // Still using 64 buckets
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
            let (dist_a, len_a) = a.routing_prefix.xor_distance(target_prefix);
            let (dist_b, len_b) = b.routing_prefix.xor_distance(target_prefix);

            match (dist_a, dist_b) {
                (None, None) => len_b.cmp(&len_a), // Both match, prefer longer matching prefix
                (None, Some(_)) => std::cmp::Ordering::Less, // None (matching) comes first
                (Some(_), None) => std::cmp::Ordering::Greater,
                (Some(dist_a), Some(dist_b)) => dist_a.cmp(&dist_b) // Normal distance comparison
            }
        });

        // Truncate the result to return up to K nodes
        all_nodes.truncate(K);
        all_nodes
    }

    /// Update the routing table with a new node
    pub fn update(&mut self, node_info: NodeInfo) {
        // Don't add our own node
        if node_info.id == self.id {
            return;
        }

        let (first_diff_bit, _effective_bit_length) = self.prefix.xor_distance(&node_info.routing_prefix);

        match first_diff_bit {
            None => {
                // Handle nodes with matching prefixes (up to effective_bit_length)
                let bucket = &mut self.k_buckets[0];
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
            Some(distance) => {
                // Find the position of the first 1 in the distance (first differing bit)
                let bucket_index = (distance + 1) as usize;

                if bucket_index >= self.k_buckets.len() {
                    return; // Ignore nodes that are out of bounds
                }

                // Don't store nodes that are too far away
                if bucket_index > MAX_ACCEPTABLE_BUCKET_INDEX {
                    return;
                }

                let bucket = &mut self.k_buckets[bucket_index];

                // Check if the node is already in the bucket
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
        } else {
            let bits_aligned = (bits & ((1u64 << bit_length) - 1)) << (64 - bit_length); // Left-align bits
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
                bits: Some(prefix_bits & 0xFF), // Align to lower bits
            },
            address: address.parse().unwrap(),
        }
    }

    #[test]
    fn test_routing_table_new() {
        let id = [0u8; 20];
        let routing_table_prefix_bits = 0b10101011u64;
        let prefix = create_prefix(8, routing_table_prefix_bits);
        let routing_table = RoutingTable::new(id, prefix.clone());

        assert_eq!(routing_table.id, id);
        assert_eq!(routing_table.prefix, prefix);
        assert_eq!(routing_table.k_buckets.len(), 64);
        for bucket in &routing_table.k_buckets {
            assert!(bucket.nodes.is_empty());
        }
    }

    #[test]
    fn test_routing_table_update_and_get_all_nodes() {
        let id = [0u8; 20];
        let routing_table_prefix_bits = 0b10101011u64;
        let prefix = create_prefix(8, routing_table_prefix_bits);
        let mut routing_table = RoutingTable::new(id, prefix);

        let node1 = generate_node_info(1, 0b10101010, "127.0.0.1:8080");
        let node2 = generate_node_info(2, 0b10101010, "127.0.0.2:8080");

        routing_table.update(node1.clone());
        routing_table.update(node2.clone());

        let nodes = routing_table.get_all_nodes();
        assert_eq!(nodes.len(), 2);
        assert!(nodes.contains(&node1));
        assert!(nodes.contains(&node2));
    }

    #[test]
    fn test_routing_table_find_closest_nodes() {
        let id = [0u8; 20];
        let routing_table_prefix_bits = 0b00001111u64;
        let prefix = create_prefix(8, routing_table_prefix_bits);
        let mut routing_table = RoutingTable::new(id, prefix.clone());

        let target_prefix = create_prefix(8, 0b00001111u64);

        let node1 = generate_node_info(1, 0b00001110, "127.0.0.1:8080");
        let node2 = generate_node_info(2, 0b00001100, "127.0.0.2:8080");
        let node3 = generate_node_info(3, 0b11110000, "127.0.0.3:8080");

        routing_table.update(node1.clone());
        routing_table.update(node2.clone());
        routing_table.update(node3.clone());

        let closest_nodes = routing_table.find_closest_nodes(&target_prefix);

        assert_eq!(closest_nodes.len(), 3);
        assert_eq!(closest_nodes[0], node1);
        assert_eq!(closest_nodes[1], node2);
        assert_eq!(closest_nodes[2], node3);
    }

    #[test]
    fn test_routing_table_remove_node_by_ip() {
        let id = [0u8; 20];
        let routing_table_prefix_bits = 0b10101011u64;
        let prefix = create_prefix(8, routing_table_prefix_bits);
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
        let routing_table_prefix_bits = 0b10101011u64;
        let prefix = create_prefix(8, routing_table_prefix_bits);
        let mut routing_table = RoutingTable::new(id, prefix);

        let node1 = generate_node_info(1, 0b10101010, "127.0.0.1:8080");
        let node2 = generate_node_info(2, 0b10101010, "127.0.0.2:8080");

        routing_table.update(node1.clone());
        routing_table.update(node2.clone());

        routing_table.mark_node_alive(node1.address);

        // Get the bucket index from XOR distance
        let (distance_opt, effective_bit_length) = routing_table.prefix.xor_distance(&node1.routing_prefix);
        match distance_opt {
            Some(distance) => {
                let first_diff_pos = effective_bit_length as u32 - distance.leading_zeros();
                let bucket_index = first_diff_pos as usize;
                let bucket = &routing_table.k_buckets[bucket_index];
                let last_node = bucket.nodes.last().unwrap();
                assert_eq!(last_node.id, node1.id, "Node1 should be the most recently seen node");
            }
            None => {
                // If distance is None, check bucket 0
                let bucket = &routing_table.k_buckets[0];
                let last_node = bucket.nodes.last().unwrap();
                assert_eq!(last_node.id, node1.id, "Node1 should be the most recently seen node in bucket 0");
            }
        }
    }

    #[test]
    fn test_routing_table_bucket_overflow() {
        let id = [0u8; 20];
        let routing_table_prefix_bits = 0b10101011u64;
        let prefix = create_prefix(8, routing_table_prefix_bits);
        let mut routing_table = RoutingTable::new(id, prefix);

        let mut nodes = Vec::new();
        for i in 0..(K as u8 + 1) {
            let node = generate_node_info(
                i,
                0b10101010,
                &format!("127.0.0.{}:8080", i),
            );
            nodes.push(node);
        }

        for node in &nodes {
            routing_table.update(node.clone());
        }

        let (distance_opt, effective_bit_length) = routing_table.prefix.xor_distance(&nodes[0].routing_prefix);
        match distance_opt {
            Some(distance) => {
                let first_diff_pos = effective_bit_length as u32 - distance.leading_zeros();
                let bucket_index = first_diff_pos as usize;
                let bucket = &routing_table.k_buckets[bucket_index];
                assert_eq!(bucket.nodes.len(), K, "Bucket should contain K nodes");

                let all_nodes = routing_table.get_all_nodes();
                assert!(!all_nodes.contains(&nodes[0]), "First node should have been removed");
                for node in &nodes[1..] {
                    assert!(all_nodes.contains(node), "Later nodes should be present");
                }
            }
            None => {
                // If distance is None, check bucket 0
                let bucket = &routing_table.k_buckets[0];
                assert_eq!(bucket.nodes.len(), K, "Bucket 0 should contain K nodes");
                
                let all_nodes = routing_table.get_all_nodes();
                assert!(!all_nodes.contains(&nodes[0]), "First node should have been removed");
                for node in &nodes[1..K+1] {
                    assert!(all_nodes.contains(node), "Later nodes should be present");
                }
            }
        }
    }

    #[test]
    fn test_routing_table_ignore_far_nodes() {
        let id = [0u8; 20];
        // Create routing table with prefix 0
        let routing_table_prefix = create_prefix(64, 0);
        let mut routing_table = RoutingTable::new(id, routing_table_prefix);

        // Create node with bit set in position 61 counting from right
        let far_node_bits = 1u64 << 60;  // Will create distance in position 61
        let far_node = NodeInfo {
            id: [1u8; 20],
            routing_prefix: create_prefix(64, far_node_bits),
            address: "127.0.0.1:8080".parse().unwrap(),
        };

        // Debug print the nodes' prefixes and distance
        println!("Routing table prefix bits: {:064b}", routing_table_prefix.bits.unwrap_or(0));
        println!("Far node prefix bits:      {:064b}", far_node.routing_prefix.bits.unwrap_or(0));

        let (distance_opt, effective_bit_length) = routing_table.prefix.xor_distance(&far_node.routing_prefix);
        match distance_opt {
            Some(distance) => {
                println!("XOR distance bits:         {:064b}", distance);
                println!("Effective bit length:      {}", effective_bit_length);
                println!("Leading zeros:             {}", distance.leading_zeros());
                let first_diff_pos = effective_bit_length as u32 - distance.leading_zeros();
                println!("First differing position:  {}", first_diff_pos);
                println!("MAX_ACCEPTABLE_BUCKET_INDEX: {}", MAX_ACCEPTABLE_BUCKET_INDEX);
            }
            None => println!("Got None distance"),
        }

        routing_table.update(far_node.clone());

        // Verify no nodes were added
        let nodes = routing_table.get_all_nodes();
        assert!(nodes.is_empty(), "Node should be rejected as too far");

        // Verify the bucket index calculation
        if let Some(distance) = distance_opt {
            let first_diff_pos = effective_bit_length as u32 - distance.leading_zeros();
            assert!(first_diff_pos as usize > MAX_ACCEPTABLE_BUCKET_INDEX,
                "Bucket index {} should be greater than MAX_ACCEPTABLE_BUCKET_INDEX {}",
                first_diff_pos,
                MAX_ACCEPTABLE_BUCKET_INDEX);
        }
    }

    #[test]
    fn test_bucket_index_ordering() {
        let id = [0u8; 20];
        let prefix = create_prefix(5, 0b10110);
        let mut routing_table = RoutingTable::new(id, prefix.clone());

        let node1 = NodeInfo {
            id: [1u8; 20],
            routing_prefix: create_prefix(5, 0b10111),
            address: "127.0.0.1:8080".parse().unwrap(),
        };

        let node2 = NodeInfo {
            id: [2u8; 20],
            routing_prefix: create_prefix(5, 0b10100),
            address: "127.0.0.2:8080".parse().unwrap(),
        };

        routing_table.update(node1.clone());
        routing_table.update(node2.clone());

        let find_bucket_index = |node: &NodeInfo| -> Option<usize> {
            routing_table.k_buckets.iter().position(|bucket| {
                bucket.nodes.iter().any(|n| n.id == node.id)
            })
        };

        let node1_index = find_bucket_index(&node1).unwrap();
        let node2_index = find_bucket_index(&node2).unwrap();

        assert!(node1_index < node2_index, 
            "Node with prefix 10111 should be in a lower bucket than node with prefix 10100");
    }
}
