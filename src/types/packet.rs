// src/types/packet.rs
#![allow(non_snake_case)]
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use bincode;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use rand::rngs::OsRng;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Sha512, Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use zstd::stream::{decode_all, encode_all};
use crate::crypto::authentication::Authentication;
use crate::utils::random_scalar;
use crate::types::address::{PublicAddress, PrivateAddress};
use crate::types::argon2_params::SerializableArgon2Params;
use crate::crypto::pow::{PoW, PoWAlgorithm};
#[allow(unused_imports)]
use log::{info, debug, warn, error};

use crate::types::routing_prefix::RoutingPrefix;

use super::address::StealthAddress;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Packet {
    pub routing_prefix: RoutingPrefix,
    pub ephemeral_address_public_key: [u8; 32], // Sender's ephemeral public address key (R_a)
    pub ephemeral_encryption_public_key: [u8; 32], // Sender's ephemeral public encryption key (R_e)
    pub stealth_address: StealthAddress, // Stealth address derived for the recipient
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub pow_nonce: u64,
    pub pow_hash: Vec<u8>,
    pub pow_difficulty: usize,
    pub timestamp: u64,
    pub ttl: u64,
    pub argon2_params: SerializableArgon2Params,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedPayload {
    pub signature: Vec<u8>,
    pub verifying_key: [u8; 32], // Sender's verification key
    pub compressed_message: Vec<u8>,
}

impl Packet {
    pub fn new(
        routing_prefix: RoutingPrefix,
        ephemeral_address_public_key: [u8; 32],
        ephemeral_encryption_public_key: [u8; 32],
        stealth_address: StealthAddress,
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
        pow_nonce: u64,
        pow_hash: Vec<u8>,
        pow_difficulty: usize,
        timestamp: u64,
        ttl: u64,
        argon2_params: SerializableArgon2Params,
    ) -> Self {
        Packet {
            routing_prefix,
            ephemeral_address_public_key,
            ephemeral_encryption_public_key,
            stealth_address,
            nonce,
            ciphertext,
            pow_nonce,
            pow_hash,
            pow_difficulty,
            timestamp,
            ttl,
            argon2_params,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self).expect("Failed to serialize packet")
    }

    pub fn deserialize(data: &[u8]) -> Packet {
        bincode::deserialize(data).expect("Failed to deserialize packet")
    }

    pub fn create_signed_encrypted(
        auth: &Authentication,
        recipient_address: &PublicAddress,
        message: &[u8],
        pow_difficulty: usize,
        ttl: u64,
        argon2_params: SerializableArgon2Params,
    ) -> Self {
        info!("Creating signed and encrypted packet");

        let mut rng = OsRng;

        // Generate sender's ephemeral address scalar 'r_a'
        let r_a_scalar = random_scalar(&mut rng);

        // Generate sender's ephemeral encryption scalar 'r_e'
        let r_e_scalar = random_scalar(&mut rng);

        // Compute ephemeral public keys
        let R_a_point = &r_a_scalar * &RISTRETTO_BASEPOINT_POINT;
        let R_e_point = &r_e_scalar * &RISTRETTO_BASEPOINT_POINT;

        let R_a_bytes = R_a_point.compress().to_bytes();
        let R_e_bytes = R_e_point.compress().to_bytes();

        // Compute stealth address: P = recipient_encryption_key + H(r_a * recipient_one_time_address) * G
        let recipient_one_time_point = recipient_address.one_time_address;

        // Compute H_s = H(r_a * recipient_one_time_address)
        let r_a_times_one_time_point = &r_a_scalar * &recipient_one_time_point;
        let r_a_times_one_time_bytes = r_a_times_one_time_point.compress().to_bytes();
        let mut hasher = Sha512::new();
        hasher.update(r_a_times_one_time_bytes);
        let H_s_scalar = Scalar::from_hash(hasher);

        // Compute stealth address point
        let stealth_address_point = recipient_address.encryption_key + &H_s_scalar * &RISTRETTO_BASEPOINT_POINT;
        let stealth_address_bytes = stealth_address_point.compress().to_bytes();

        // Compute shared secret for encryption key: S_e = r_e * recipient_encryption_key
        let recipient_encryption_point = recipient_address.encryption_key;
        let S_e_point = &r_e_scalar * &recipient_encryption_point;
        let S_e_bytes = S_e_point.compress().to_bytes();

        // Derive encryption key from S_e
        let encryption_key_hash = Sha256::digest(&S_e_bytes);
        let encryption_key = encryption_key_hash;

        let key = Key::<Aes256Gcm>::from_slice(&encryption_key);
        let cipher = Aes256Gcm::new(key);

        // Generate nonce
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Compress the message
        let compressed_message = encode_all(&message[..], 0).expect("Failed to compress message");

        // Sign the compressed message
        let signature = auth.sign_message(&compressed_message).to_bytes().to_vec();

        // Create EncryptedPayload
        let encrypted_payload = EncryptedPayload {
            signature,
            verifying_key: auth.verifying_key().to_bytes(),
            compressed_message,
        };

        // Serialize EncryptedPayload
        let encrypted_payload_bytes = bincode::serialize(&encrypted_payload)
            .expect("Failed to serialize EncryptedPayload");

        // Encrypt the payload
        let ciphertext = cipher
            .encrypt(nonce, encrypted_payload_bytes.as_ref())
            .expect("Encryption failed");

        // Prepare the Packet data
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut packet = Packet {
            routing_prefix: recipient_address.prefix.clone(),
            ephemeral_address_public_key: R_a_bytes,
            ephemeral_encryption_public_key: R_e_bytes,
            stealth_address: stealth_address_bytes,
            nonce: nonce_bytes,
            ciphertext,
            pow_nonce: 0,
            pow_hash: Vec::new(),
            pow_difficulty,
            timestamp,
            ttl,
            argon2_params: argon2_params.clone(),
        };

        // Perform PoW
        let packet_data = packet.serialize();
        let argon2_params_native = argon2_params.to_argon2_params();
        let pow = PoW::new(
            &packet_data,
            pow_difficulty,
            PoWAlgorithm::Argon2id(argon2_params_native),
        )
        .unwrap();

        let (pow_hash, pow_nonce) = pow.calculate_pow();

        // Update Packet with PoW results
        packet.pow_nonce = pow_nonce;
        packet.pow_hash = pow_hash;

        packet
    }

    pub fn verify_and_decrypt(
        &self,
        recipient_private_address: &PrivateAddress,
        pow_difficulty: usize,
    ) -> Option<(Vec<u8>, [u8; 32])> {
        info!("Verifying and decrypting packet");

        // Verify PoW
        let packet_without_pow = Packet {
            pow_nonce: 0,
            pow_hash: Vec::new(),
            ..self.clone()
        };

        let packet_data = packet_without_pow.serialize();
        let argon2_params_native = self.argon2_params.to_argon2_params();
        let pow = PoW::new(
            &packet_data,
            pow_difficulty,
            PoWAlgorithm::Argon2id(argon2_params_native),
        )
        .unwrap();

        if !pow.verify_pow(&self.pow_hash, self.pow_nonce) {
            return None;
        }

        // Reconstruct ephemeral public keys
        let R_a_point = CompressedRistretto(self.ephemeral_address_public_key)
            .decompress()
            .expect("Invalid ephemeral address public key");
        let R_e_point = CompressedRistretto(self.ephemeral_encryption_public_key)
            .decompress()
            .expect("Invalid ephemeral encryption public key");

        // Compute H_s = H(k_a * R_a)
        let k_a_scalar = recipient_private_address.one_time_scalar;
        let k_a_R_a_point = k_a_scalar * R_a_point;
        let k_a_R_a_bytes = k_a_R_a_point.compress().to_bytes();

        let mut hasher = Sha512::new();
        hasher.update(k_a_R_a_bytes);
        let H_s_scalar = Scalar::from_hash(hasher);

        // Compute expected stealth address: P' = R_a + H_s * G
        let expected_stealth_address_point = recipient_private_address.encryption_scalar * &RISTRETTO_BASEPOINT_POINT + &H_s_scalar * &RISTRETTO_BASEPOINT_POINT;
        let expected_stealth_address_bytes = expected_stealth_address_point.compress().to_bytes();

        // Check if the stealth address matches
        if expected_stealth_address_bytes != self.stealth_address {
            return None; // Packet is not intended for this recipient
        }

        // Compute shared secret for decryption key: S_e = k_e * R_e
        let k_e_scalar = recipient_private_address.encryption_scalar;
        let S_e_point = k_e_scalar * R_e_point;
        let S_e_bytes = S_e_point.compress().to_bytes();

        // Derive decryption key from S_e
        let decryption_key_hash = Sha256::digest(&S_e_bytes);
        let decryption_key = decryption_key_hash;

        let key = Key::<Aes256Gcm>::from_slice(&decryption_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&self.nonce);

        // Decrypt the payload
        let decrypted_payload_bytes = cipher.decrypt(nonce, self.ciphertext.as_ref()).ok()?;

        // Deserialize EncryptedPayload
        let encrypted_payload: EncryptedPayload =
            bincode::deserialize(&decrypted_payload_bytes).ok()?;

        // Verify the signature
        let sender_verifying_key =
            VerifyingKey::from_bytes(&encrypted_payload.verifying_key).ok()?;

        // Convert the signature Vec<u8> to &[u8; 64]
        let signature_bytes: &[u8; 64] = encrypted_payload.signature.as_slice().try_into().ok()?;
        let signature = Signature::from_bytes(signature_bytes);

        if sender_verifying_key
            .verify(&encrypted_payload.compressed_message, &signature)
            .is_err()
        {
            return None; // Signature verification failed
        }
        // Decompress the message
        let decompressed_message =
            decode_all(&encrypted_payload.compressed_message[..]).ok()?;

        // Return the message and sender's verification key
        Some((decompressed_message, encrypted_payload.verifying_key))
    }

    pub fn verify_pow(&self, pow_difficulty: usize) -> bool {
        // Reconstruct the packet data without PoW fields
        let packet_without_pow = Packet {
            pow_nonce: 0,
            pow_hash: Vec::new(),
            ..self.clone()
        };

        let packet_data = packet_without_pow.serialize();

        let argon2_params_native = self.argon2_params.to_argon2_params();

        let pow = PoW::new(
            &packet_data,
            pow_difficulty,
            PoWAlgorithm::Argon2id(argon2_params_native),
        )
        .unwrap();

        pow.verify_pow(&self.pow_hash, self.pow_nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::authentication::Authentication;
    use crate::types::address::PrivateAddress;
    use crate::types::argon2_params::SerializableArgon2Params;

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
        let pow_difficulty = 1;
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

        // Check that the routing prefix matches
        assert_eq!(
            deserialized_packet.routing_prefix,
            recipient_public_address.prefix
        );

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
        let pow_difficulty = 1;
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
        let pow_difficulty = 1;
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
        let pow_difficulty = 1;
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
        let pow_difficulty = 1;
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
}