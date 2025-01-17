// src/network/dht.rs

use std::net::{IpAddr, SocketAddr};

use crate::types::{
    node_info::{NodeId, NodeInfo},
    routing_prefix::{PrefixDistance, RoutingPrefix},
};

/// The maximum number of nodes per k-bucket (k)
const K: usize = 20;


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
        let mut k_buckets = Vec::new();
        // We keep 64 buckets, same as old code
        for _ in 0..64 {
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

        // Sort by tree distance
        all_nodes.sort_by(|a, b| {
            // distance(...) returns Option<u64>, so unwrap_or is a fallback
            let da = a.routing_prefix.distance(target_prefix).unwrap_or(u64::MAX);
            let db = b.routing_prefix.distance(target_prefix).unwrap_or(u64::MAX);
            da.cmp(&db)
        });

        // Truncate to up to K nodes
        all_nodes.truncate(K);
        all_nodes
    }

    /// Update the routing table with a new node
    ///
    /// In the old XOR approach, we used the "first differing bit" to pick a bucket.
    /// Here, we'll do a simpler approach: we take the *tree distance* and treat it
    /// as a "bucket index" (plus 1). That's just one possible interpretation.
    pub fn update(&mut self, node_info: NodeInfo) {
        // Don't add our own node
        if node_info.id == self.id {
            return;
        }

        // Get the tree distance
        let distance_opt = self.prefix.distance(&node_info.routing_prefix);
        match distance_opt {
            None => return, // Skip nodes with incompatible prefixes
            Some(distance) => {
                // The bucket index should reflect the distance in the tree
                let bucket_index = distance as usize;
                if bucket_index >= self.k_buckets.len() {
                    return;
                }

                let bucket = &mut self.k_buckets[bucket_index];
                if let Some(pos) = bucket.nodes.iter().position(|n| n.id == node_info.id) {
                    // Move to end if already present
                    let node = bucket.nodes.remove(pos);
                    bucket.nodes.push(node);
                } else if bucket.nodes.len() < K {
                    // Add if bucket not full
                    bucket.nodes.push(node_info);
                } else {
                    // Replace oldest if bucket full
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

    /// Mark a node as "alive" => move it to the end of its bucket
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

// ------------------------------ TESTS --------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{node_info::NodeInfo, routing_prefix::RoutingPrefix};

    /// Helper function to create a prefix with certain bit_length/bits.
    fn create_prefix(bit_length: u8, bits: u64) -> RoutingPrefix {
        assert!(bit_length <= 64);
        if bit_length == 0 {
            RoutingPrefix {
                bit_length: 0,
                bits: None,
            }
        } else {
            // We'll mask the bits to ensure only the relevant bits are set
            let mask = if bit_length == 64 {
                u64::MAX
            } else {
                (1u64 << bit_length) - 1
            };
            let masked_bits = bits & mask;
            RoutingPrefix {
                bit_length,
                bits: Some(masked_bits),
            }
        }
    }

    /// Helper function to generate a NodeInfo
    fn generate_node_info(id_value: u8, prefix_bits: u64, address: &str) -> NodeInfo {
        NodeInfo {
            id: [id_value; 20],
            routing_prefix: RoutingPrefix {
                bit_length: 8,
                bits: Some(prefix_bits & 0xFF), // bottom 8 bits
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

        // target prefix
        let target_prefix = create_prefix(8, 0b00001111u64);

        let node1 = generate_node_info(1, 0b00001110, "127.0.0.1:8080");
        let node2 = generate_node_info(2, 0b00001100, "127.0.0.2:8080");
        let node3 = generate_node_info(3, 0b11110000, "127.0.0.3:8080");

        routing_table.update(node1.clone());
        routing_table.update(node2.clone());
        routing_table.update(node3.clone());

        let closest_nodes = routing_table.find_closest_nodes(&target_prefix);

        // The test below expects node1 < node2 < node3 in distance from 00001111
        assert_eq!(closest_nodes.len(), 3);
        assert_eq!(closest_nodes[0], node1);
        assert_eq!(closest_nodes[1], node2);
        assert_eq!(closest_nodes[2], node3);
    }

    #[test]
    fn test_routing_table_remove_node_by_ip() {
        let id = [0u8; 20];
        let prefix = create_prefix(8, 0b10101011);
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
        let prefix = create_prefix(8, 0b10101011);
        let mut routing_table = RoutingTable::new(id, prefix);

        let node1 = generate_node_info(1, 0b10101010, "127.0.0.1:8080");
        let node2 = generate_node_info(2, 0b10101010, "127.0.0.2:8080");

        routing_table.update(node1.clone());
        routing_table.update(node2.clone());

        // Mark node1 alive => we should move it to the end of its bucket
        routing_table.mark_node_alive(node1.address);

        // Check that it's at the end of the bucket
        let bucket_with_node1 = routing_table
            .k_buckets
            .iter()
            .find(|b| b.nodes.iter().any(|n| n.id == node1.id))
            .expect("No bucket found for node1");

        assert_eq!(
            bucket_with_node1.nodes.last().unwrap().id,
            node1.id,
            "Node1 should be the most recently seen node"
        );
    }

    #[test]
    fn test_routing_table_bucket_overflow() {
        let id = [0u8; 20];
        let prefix = create_prefix(8, 0b10101011);
        let mut routing_table = RoutingTable::new(id, prefix);

        // We'll add K+1 nodes that end up in the same bucket
        let mut nodes = Vec::new();
        for i in 0..(K as u8 + 1) {
            let node = generate_node_info(i, 0b10101010, &format!("127.0.0.{}:8080", i));
            nodes.push(node);
        }

        // Insert them all
        for node in &nodes {
            routing_table.update(node.clone());
        }

        // We expect bucket to have exactly K nodes
        // and the oldest one removed (which is nodes[0])
        let all_nodes = routing_table.get_all_nodes();
        assert_eq!(all_nodes.len(), K);
        assert!(!all_nodes.contains(&nodes[0]), "First node should have been removed");
        for node in &nodes[1..] {
            assert!(all_nodes.contains(node), "Later nodes should be present");
        }
    }

    #[test]
    fn test_routing_table_ignore_far_nodes() {
        let id = [0u8; 20];
        // Suppose we define a prefix with bit_length=64, bits=0 => "root at full length"
        let routing_table_prefix = create_prefix(64, 0);
        let mut routing_table = RoutingTable::new(id, routing_table_prefix);

        // A node that is "far" from 0, say prefix bits=1<<60
        let far_node_bits = 1u64 << 60;
        let far_node = NodeInfo {
            id: [1u8; 20],
            routing_prefix: create_prefix(64, far_node_bits),
            address: "127.0.0.1:8080".parse().unwrap(),
        };

        // We'll check the distance
        let distance_opt = routing_table.prefix.distance(&far_node.routing_prefix);
        println!("Distance between table prefix and far node: {:?}", distance_opt);

        routing_table.update(far_node.clone());

        // If that distance was big => bucket_index might exceed MAX_ACCEPTABLE_BUCKET_INDEX => ignore
        // So we expect no node was inserted
        let nodes = routing_table.get_all_nodes();
        assert!(nodes.is_empty(), "Far node should be ignored as too far");
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

        // We just check which bucket they ended in. The test used to rely on XOR logic.
        // Now, let's see if "node1" got a smaller distance than "node2" => ends in a lower bucket index.
        let dist1 = prefix.distance(&node1.routing_prefix).unwrap_or(u64::MAX);
        let dist2 = prefix.distance(&node2.routing_prefix).unwrap_or(u64::MAX);
        assert!(
            dist1 < dist2,
            "We expect node1's prefix 10111 is closer to 10110 than node2 10100 in tree distance"
        );

        let find_bucket_index = |node: &NodeInfo| -> Option<usize> {
            // look for which bucket the node is in
            routing_table.k_buckets.iter().position(|bucket| {
                bucket.nodes.iter().any(|n| n.id == node.id)
            })
        };

        let node1_index = find_bucket_index(&node1).unwrap();
        let node2_index = find_bucket_index(&node2).unwrap();

        // we expect node1_index < node2_index if dist1 < dist2
        assert!(
            node1_index < node2_index,
            "Node1 should be stored in a lower bucket index than Node2 if it's closer"
        );
    }
}
