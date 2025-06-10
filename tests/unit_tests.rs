use shadow_link_rust::types::routing_prefix::RoutingPrefix;
use shadow_link_rust::crypto::pow::{PoW, PoWAlgorithm};
use argon2::Params as Argon2Params;
use shadow_link_rust::crypto::authentication::Authentication;
use shadow_link_rust::crypto::encryption::Encryption;
use shadow_link_rust::types::address::PrivateAddress;
use shadow_link_rust::types::packet::Packet;
use shadow_link_rust::types::argon2_params::SerializableArgon2Params;
use shadow_link_rust::network::dht::RoutingTable;
use shadow_link_rust::types::node_info::NodeInfo;

use std::net::SocketAddr;
// --- RoutingPrefix Tests ---
#[test]
fn routing_prefix_serialize_deserialize() {
    let p = RoutingPrefix::new(5, 0b10101);
    let bytes = p.to_bytes();
    let (p2, consumed) = RoutingPrefix::from_bytes(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(p, p2);
}

#[test]
fn routing_prefix_serves_and_distance() {
    let parent = RoutingPrefix::new(3, 0b101);
    let child  = RoutingPrefix::new(5, 0b10110);
    assert!(parent.serves(&child));
    assert!(!child.serves(&parent));
    let a = RoutingPrefix::new(4, 0b1100);
    let b = RoutingPrefix::new(4, 0b1001);
    assert_eq!(a.common_prefix_len(&b), 1);
    assert_eq!(a.distance(&b).unwrap(), (4-1 + 4-1) as u64);
}

// --- PoW Tests ---
#[test]
fn pow_basic_calculate_and_verify() {
    let data = b"hello world";
    let params = Argon2Params::default();
    let pow = PoW::new(data, 1, PoWAlgorithm::Argon2id(params)).unwrap();
    let (hash, nonce) = pow.calculate_pow();
    assert!(pow.verify_pow(&hash, nonce));
}

// --- Authentication Tests ---
#[test]
fn authentication_sign_and_verify() {
    let auth = Authentication::new();
    let msg  = b"test message";
    let sig  = auth.sign_message(msg);
    let vk   = auth.verifying_key();
    assert!(Authentication::verify_message_with_key(msg, &sig, &vk));
}

// --- Encryption Tests ---
#[test]
fn encryption_round_trip() {
    // Generate two keypairs
    let alice_priv = PrivateAddress::new(None, None);
    let bob_priv   = PrivateAddress::new(None, None);

    // Encrypt from Alice to Bob
    let (ciphertext, nonce, r_a, r_e, stealth) =
        Encryption::encrypt_for_recipient(
            &alice_priv.verification_signing_key,
            &alice_priv.public_address,
            &bob_priv.public_address,
            b"secret message",
        );

    // Decrypt at Bob
    let (plaintext, from_b58) =
        Encryption::decrypt_for_recipient(
            &ciphertext,
            &nonce,
            &r_a,
            &r_e,
            &stealth,
            &bob_priv,
        ).expect("Failed to decrypt");

    assert_eq!(plaintext, b"secret message");
    assert_eq!(from_b58, alice_priv.public_address.to_base58());
}

// --- Packet Tests ---
#[test]
fn packet_create_and_verify() {
    let alice_priv = PrivateAddress::new(None, None);
    let bob_priv   = PrivateAddress::new(None, None);

    let argon2_params = SerializableArgon2Params::default();
    let packet = Packet::create_signed_encrypted(
        &alice_priv.verification_signing_key,
        &alice_priv.public_address,
        &bob_priv.public_address,
        b"payload",
        0,            // zero PoW difficulty for speed
        3600,         // ttl
        argon2_params.clone(),
    );

    // PoW at difficulty 0 should always verify
    assert!(packet.verify_pow(0));

    // Verify and decrypt
    let (decrypted, from) =
        packet.verify_and_decrypt(&bob_priv, 0)
            .expect("Packet verify_and_decrypt failed");

    assert_eq!(decrypted, b"payload");
    assert_eq!(from, alice_priv.public_address.to_base58());
}

// --- RoutingTable Tests ---
#[test]
fn routing_table_insert_and_find() {
    let mut table = RoutingTable::new([0u8;20], RoutingPrefix::root());

    // Node serving prefix bit 0
    let node0 = NodeInfo {
        id: [1u8;20],
        routing_prefix: RoutingPrefix::new(1, 0b0),
        address: "127.0.0.1:1000".parse::<SocketAddr>().unwrap(),
    };
    // Node serving prefix bit 1
    let node1 = NodeInfo {
        id: [2u8;20],
        routing_prefix: RoutingPrefix::new(1, 0b1),
        address: "127.0.0.1:1001".parse::<SocketAddr>().unwrap(),
    };

    table.update(node0.clone());
    table.update(node1.clone());

    let all = table.get_all_nodes();
    assert_eq!(all.len(), 2);

    // Find closest to prefix 0b0
    let target = RoutingPrefix::new(1, 0b0);
    let closest = table.find_closest_nodes(&target);
    assert_eq!(closest.len(), 2);
    assert_eq!(closest[0].id, node0.id);
    assert_eq!(closest[1].id, node1.id);
}
