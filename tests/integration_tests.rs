#![cfg(feature = "test_helpers")]

// tests/integration_tests.rs

use log::info;
use shadow_link_rust::network::client::Client;
use shadow_link_rust::network::node::Node;
use shadow_link_rust::network::routing::RoutingManager;
use shadow_link_rust::types::argon2_params::SerializableArgon2Params;
use shadow_link_rust::types::routing_prefix::RoutingPrefix;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout, Duration};

/// Initialize logger for tests
fn init_logger() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .is_test(true)
        .try_init();
}

/// Single-node loopback test: client sends a message to itself via one node.
#[tokio::test]
async fn single_node_loopback() {
    init_logger();

    let prefix = RoutingPrefix::root();

    // Bind a listener to get an available port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_addr = listener.local_addr().unwrap();
    drop(listener);

    info!("Starting node at {}", node_addr);

    // Create routing manager and node
    let routing = Arc::new(RoutingManager::new([0u8; 20], prefix.clone()));
    let _node = Node::new(
        routing.clone(),
        prefix.clone(),
        node_addr,
        0,    // PoW difficulty 0 for speed
        3600, // max TTL
        SerializableArgon2Params::default(),
        Duration::from_secs(60),   // cleanup interval (longer for tests)
        Duration::from_secs(600),  // blacklist duration
        vec![],                    // no bootstrap
        Duration::from_secs(3600), // discovery interval
    )
    .await;

    // Give the node time to start listening
    sleep(Duration::from_millis(100)).await;

    // Create client, subscribe
    let mut client = Client::new(
        routing.clone(),
        None, // No prefix - will use root
        None, // No length - will use root
        64,   // max prefix length
        SerializableArgon2Params::default(),
        false,     // exact argon2 not required
        node_addr, // bootstrap node addr
    );

    info!(
        "Client created with address: {}",
        client.public_address_for_tests().to_base58()
    );

    // Perform handshake and subscription
    let node_info = client
        .handshake_with_node(node_addr)
        .await
        .expect("Handshake failed");
    info!("Handshake successful with node");

    client.connected_node = Some(node_info.clone());
    client
        .subscribe_and_receive_messages(node_addr)
        .await
        .expect("Subscription failed");
    info!("Subscription successful");

    // Give subscription time to establish
    sleep(Duration::from_millis(100)).await;

    // Send message to self
    let pub_addr = client.public_address_for_tests();
    info!(
        "Sending message to self at address: {}",
        pub_addr.to_base58()
    );

    client
        .send_message(pub_addr.clone(), b"hello loop")
        .await
        .unwrap();
    info!("Message sent");

    // Receive packet with longer timeout
    let pkt = timeout(Duration::from_secs(10), client.receive_packet())
        .await
        .expect("Timeout waiting for packet")
        .expect("Did not receive packet");

    info!("Packet received");

    // Verify & decrypt
    let (plaintext, sender_addr) = pkt
        .verify_and_decrypt(client.private_address_for_tests(), 0)
        .expect("Failed to decrypt");

    assert_eq!(plaintext, b"hello loop");
    assert_eq!(sender_addr, client.public_address_for_tests().to_base58());

    info!("Test passed!");
}

/// Two-node relay test: client1 -> nodeA -> nodeB -> client2
#[tokio::test]
async fn two_node_relay() {
    init_logger();

    let prefix = RoutingPrefix::root();

    // Bind two listeners
    let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_a = listener_a.local_addr().unwrap();
    drop(listener_a);

    let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_b = listener_b.local_addr().unwrap();
    drop(listener_b);

    info!("Starting nodes at {} and {}", addr_a, addr_b);

    // Routing services and nodes
    let routing_a = Arc::new(RoutingManager::new([0u8; 20], prefix.clone()));
    let routing_b = Arc::new(RoutingManager::new([1u8; 20], prefix.clone()));

    let _node_a = Node::new(
        routing_a.clone(),
        prefix.clone(),
        addr_a,
        0,
        3600,
        SerializableArgon2Params::default(),
        Duration::from_secs(60),
        Duration::from_secs(600),
        vec![addr_b],
        Duration::from_secs(3600),
    )
    .await;

    let _node_b = Node::new(
        routing_b.clone(),
        prefix.clone(),
        addr_b,
        0,
        3600,
        SerializableArgon2Params::default(),
        Duration::from_secs(60),
        Duration::from_secs(600),
        vec![addr_a],
        Duration::from_secs(3600),
    )
    .await;

    // Give nodes time to connect to each other
    sleep(Duration::from_millis(500)).await;

    // Client1 on nodeA
    let mut client1 = Client::new(
        routing_a.clone(),
        None,
        None,
        64,
        SerializableArgon2Params::default(),
        false,
        addr_a,
    );

    info!(
        "Client1 address: {}",
        client1.public_address_for_tests().to_base58()
    );

    // Handshake and subscribe client1
    let node_info1 = client1
        .handshake_with_node(addr_a)
        .await
        .expect("Handshake client1 failed");
    client1.connected_node = Some(node_info1.clone());
    client1
        .subscribe_and_receive_messages(addr_a)
        .await
        .expect("Subscription client1 failed");

    // Client2 on nodeB
    let mut client2 = Client::new(
        routing_b.clone(),
        None,
        None,
        64,
        SerializableArgon2Params::default(),
        false,
        addr_b,
    );

    info!(
        "Client2 address: {}",
        client2.public_address_for_tests().to_base58()
    );

    // Handshake and subscribe client2
    let node_info2 = client2
        .handshake_with_node(addr_b)
        .await
        .expect("Handshake client2 failed");
    client2.connected_node = Some(node_info2.clone());
    client2
        .subscribe_and_receive_messages(addr_b)
        .await
        .expect("Subscription client2 failed");

    // Give subscriptions time to establish
    sleep(Duration::from_millis(500)).await;

    // Client1 sends to client2
    let addr2 = client2.public_address_for_tests();
    info!("Client1 sending to client2 at: {}", addr2.to_base58());

    client1
        .send_message(addr2.clone(), b"relay test")
        .await
        .unwrap();
    info!("Message sent from client1");

    // Client2 should receive via nodeB with longer timeout
    let pkt = timeout(Duration::from_secs(10), client2.receive_packet())
        .await
        .expect("Timeout waiting for packet on client2")
        .expect("Did not receive packet on client2");

    info!("Packet received by client2");

    let (plaintext, sender_addr) = pkt
        .verify_and_decrypt(client2.private_address_for_tests(), 0)
        .expect("Decrypt failed for client2");

    assert_eq!(plaintext, b"relay test");
    assert_eq!(sender_addr, client1.public_address_for_tests().to_base58());

    info!("Test passed!");
}
