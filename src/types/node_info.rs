// src/types/node_info.rs

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{argon2_params::SerializableArgon2Params, routing_prefix::RoutingPrefix};

pub type NodeId = [u8; 20]; // 160-bit node ID

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct NodeInfo {
    pub id: NodeId,                     // Node ID (160-bit hash)
    pub routing_prefix: RoutingPrefix,  // Routing Prefix served by node
    pub address: SocketAddr,            // Node's network address
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeInfoExtended {
    pub id: NodeId,
    pub address: SocketAddr,
    pub routing_prefix: RoutingPrefix,
    pub pow_difficulty: usize,
    pub max_ttl: u64,
    pub min_argon2_params: SerializableArgon2Params,
}

/// Generates a node ID by hashing the socket address and routing prefix
pub fn generate_node_id(addr: &SocketAddr, routing_prefix: &RoutingPrefix) -> NodeId {
    let mut hasher = Sha256::new();

    // Hash the SocketAddr
    let addr_bytes = match addr {
        SocketAddr::V4(addr_v4) => addr_v4.ip().octets().to_vec(),
        SocketAddr::V6(addr_v6) => addr_v6.ip().octets().to_vec(),
    };
    let port_bytes = addr.port().to_be_bytes();
    hasher.update(&addr_bytes);
    hasher.update(&port_bytes);

    // Hash the RoutingPrefix
    let routing_prefix_bytes = routing_prefix.to_bytes();
    hasher.update(&routing_prefix_bytes);

    // Finalize the hash and extract the first 20 bytes
    let result = hasher.finalize();
    let mut id = [0u8; 20];
    id.copy_from_slice(&result[..20]);

    id
}