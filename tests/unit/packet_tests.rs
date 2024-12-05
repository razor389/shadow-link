// Import your crate as an external crate
use shadow_link_rust::*;

// Import necessary modules from your crate
use shadow_link_rust::crypto::authentication::Authentication;
use shadow_link_rust::types::address::{PrivateAddress, PublicAddress};
use shadow_link_rust::types::argon2_params::SerializableArgon2Params;
use shadow_link_rust::types::packet::Packet;
use std::time::{Duration, SystemTime};


#[test]
fn test_packet_creation_and_decryption() {
    // Create sender authentication
    let sender_auth = Authentication::new();

    // Create recipient private and public addresses
    let recipient_private_address = PrivateAddress::new(None);
    let recipient_public_address = recipient_private_address.public_address.clone();

    // Message to send
    let message = b"Hello, recipient!";

    // PoW parameters
    let pow_difficulty = 10;
    let ttl = 3600; // 1 hour
    let argon2_params = SerializableArgon2Params::default();

    // Create packet
    let packet = Packet::create_signed_encrypted(
        &sender_auth,
        &recipient_public_address,
        message,
        pow_difficulty,
        ttl,
        argon2_params,
    );

    // Serialize packet
    let serialized_packet = packet.serialize();

    // Deserialize packet
    let deserialized_packet = Packet::deserialize(&serialized_packet);

    // Verify and decrypt
    if let Some((decrypted_message, sender_verifying_key_bytes)) =
        deserialized_packet.verify_and_decrypt(&recipient_private_address, pow_difficulty)
    {
        assert_eq!(message.to_vec(), decrypted_message);
        assert_eq!(
            sender_verifying_key_bytes,
            sender_auth.verifying_key().to_bytes()
        );
    } else {
        panic!("Failed to verify and decrypt the packet.");
    }
}

#[test]
fn test_wrong_recipient_cannot_decrypt() {
    // Create sender authentication
    let sender_auth = Authentication::new();

    // Create recipient private and public addresses
    let intended_recipient_private = PrivateAddress::new(None);
    let intended_recipient_public = intended_recipient_private.public_address.clone();

    // Create wrong recipient
    let wrong_recipient_private = PrivateAddress::new(None);

    // Message to send
    let message = b"Secret message";

    // PoW parameters
    let pow_difficulty = 10;
    let ttl = 3600;
    let argon2_params = SerializableArgon2Params::default();

    // Create packet intended for the intended recipient
    let packet = Packet::create_signed_encrypted(
        &sender_auth,
        &intended_recipient_public,
        message,
        pow_difficulty,
        ttl,
        argon2_params,
    );

    // Wrong recipient attempts to decrypt
    let result = packet.verify_and_decrypt(&wrong_recipient_private, pow_difficulty);

    assert!(result.is_none(), "Wrong recipient should not decrypt the packet");
}

#[test]
fn test_signature_verification_failure() {
    // Create sender authentication
    let sender_auth = Authentication::new();

    // Create recipient private and public addresses
    let recipient_private_address = PrivateAddress::new(None);
    let recipient_public_address = recipient_private_address.public_address.clone();

    // Message to send
    let message = b"Important message";

    // PoW parameters
    let pow_difficulty = 10;
    let ttl = 3600;
    let argon2_params = SerializableArgon2Params::default();

    // Create packet
    let mut packet = Packet::create_signed_encrypted(
        &sender_auth,
        &recipient_public_address,
        message,
        pow_difficulty,
        ttl,
        argon2_params,
    );

    // Tamper with the signature
    let mut decrypted_payload_bytes = packet.ciphertext.clone();

    // Flip a bit in the ciphertext to simulate tampering
    if let Some(byte) = decrypted_payload_bytes.get_mut(0) {
        *byte ^= 0x01;
    }

    packet.ciphertext = decrypted_payload_bytes;

    // Attempt to verify and decrypt
    let result = packet.verify_and_decrypt(&recipient_private_address, pow_difficulty);

    assert!(result.is_none(), "Tampered packet should fail verification");
}

#[test]
fn test_invalid_pow_rejection() {
    // Create sender authentication
    let sender_auth = Authentication::new();

    // Create recipient private and public addresses
    let recipient_private_address = PrivateAddress::new(None);
    let recipient_public_address = recipient_private_address.public_address.clone();

    // Message to send
    let message = b"Test message";

    // PoW parameters
    let pow_difficulty = 10;
    let ttl = 3600;
    let argon2_params = SerializableArgon2Params::default();

    // Create packet
    let mut packet = Packet::create_signed_encrypted(
        &sender_auth,
        &recipient_public_address,
        message,
        pow_difficulty,
        ttl,
        argon2_params,
    );

    // Tamper with the PoW nonce
    packet.pow_nonce += 1;

    // Attempt to verify and decrypt
    let result = packet.verify_and_decrypt(&recipient_private_address, pow_difficulty);

    assert!(result.is_none(), "Packet with invalid PoW should be rejected");
}

#[test]
fn test_packet_expiry() {
    // Create sender authentication
    let sender_auth = Authentication::new();

    // Create recipient private and public addresses
    let recipient_private_address = PrivateAddress::new(None);
    let recipient_public_address = recipient_private_address.public_address.clone();

    // Message to send
    let message = b"Expired message";

    // PoW parameters
    let pow_difficulty = 10;
    let ttl = 1; // Set TTL to 1 second
    let argon2_params = SerializableArgon2Params::default();

    // Create packet
    let packet = Packet::create_signed_encrypted(
        &sender_auth,
        &recipient_public_address,
        message,
        pow_difficulty,
        ttl,
        argon2_params,
    );

    // Simulate waiting for TTL to expire
    std::thread::sleep(Duration::from_secs(2));

    // Check if packet has expired
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    assert!(
        packet.timestamp + packet.ttl < current_time,
        "Packet should be expired"
    );

    // Attempt to verify and decrypt
    let result = packet.verify_and_decrypt(&recipient_private_address, pow_difficulty);

    // Depending on implementation, you may need to handle TTL checking in the verify_and_decrypt function
    // For this test, we'll assume the packet is considered invalid if expired
    assert!(
        result.is_none(),
        "Expired packet should not be decrypted"
    );
}

#[test]
fn test_stealth_address_mismatch() {
    // Create sender authentication
    let sender_auth = Authentication::new();

    // Create intended recipient
    let intended_recipient_private = PrivateAddress::new(None);
    let intended_recipient_public = intended_recipient_private.public_address.clone();

    // Create another recipient who should not receive the packet
    let other_recipient_private = PrivateAddress::new(None);

    // Message to send
    let message = b"Stealth message";

    // PoW parameters
    let pow_difficulty = 10;
    let ttl = 3600;
    let argon2_params = SerializableArgon2Params::default();

    // Create packet intended for the intended recipient
    let packet = Packet::create_signed_encrypted(
        &sender_auth,
        &intended_recipient_public,
        message,
        pow_difficulty,
        ttl,
        argon2_params,
    );

    // Other recipient attempts to verify and decrypt
    let result = packet.verify_and_decrypt(&other_recipient_private, pow_difficulty);

    assert!(
        result.is_none(),
        "Recipient with mismatching stealth address should not decrypt the packet"
    );
}
