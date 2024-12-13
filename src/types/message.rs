// src/types/message.rs

use serde::{Deserialize, Serialize};

use super::{node_info::{NodeInfo, NodeInfoExtended}, packet::Packet, routing_prefix::RoutingPrefix};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
    /// Find nodes closest to a given RoutingPrefix, returns Message::Nodes
    FindClosestNodes(RoutingPrefix),
    /// Find nodes that serve (match) a given RoutingPrefix, returns Message::NodesExtended
    FindServingNodes(RoutingPrefix),
    Nodes(Vec<NodeInfo>),                   // Response containing a list of NodeInfo
    NodesExtended(Vec<NodeInfoExtended>),   // Response with extended node info
    Packet(Packet),                         // A packet sent between nodes or to clients
    Ping,                                   // Ping message for node liveness checks
    Pong,                                   // Pong response
    Subscribe,                              // Client subscribes to receive all stored packets
    Unsubscribe,                            // Client requests to unsubscribe
    UnsubscribeAck,                         // Acknowledgment of unsubscription (optional)
    Handshake(NodeInfoExtended),            // Handshake with node
    HandshakeAck(NodeInfoExtended),         // Acknowledgment variant
    ClientHandshake,                        // Client initiates handshake
    ClientHandshakeAck(NodeInfoExtended),   // Node responds with its info
}