// src/types/packet.rs
#![allow(non_snake_case)]
use bincode;
use serde::{Deserialize, Serialize};
use crate::crypto::authentication::Authentication;
use crate::crypto::encryption::Encryption;
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

    /// Create a signed, encrypted packet. Now requires the sender's public address so we can embed it.
    pub fn create_signed_encrypted(
        auth: &Authentication,
        sender_public_address: &PublicAddress,
        recipient_address: &PublicAddress,
        message: &[u8],
        pow_difficulty: usize,
        ttl: u64,
        argon2_params: SerializableArgon2Params,
    ) -> Self {
        info!("Creating signed and encrypted packet");
    
        // Encrypt for recipient, embedding sender's address in the payload
        let (ciphertext, nonce, ephemeral_address_public_key, ephemeral_encryption_public_key, stealth_address) 
            = Encryption::encrypt_for_recipient(
                auth,
                sender_public_address,
                recipient_address,
                message
            );
    
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    
        let mut packet = Packet {
            routing_prefix: recipient_address.prefix.clone(),
            ephemeral_address_public_key,
            ephemeral_encryption_public_key,
            stealth_address,
            nonce,
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
        ).unwrap();
    
        let (pow_hash, pow_nonce) = pow.calculate_pow();
        packet.pow_nonce = pow_nonce;
        packet.pow_hash = pow_hash;
    
        packet
    }

    /// Verify and decrypt the packet, returning the decrypted message and the sender's Base58-encoded public address
    pub fn verify_and_decrypt(
        &self,
        recipient_private_address: &PrivateAddress,
        pow_difficulty: usize,
    ) -> Option<(Vec<u8>, String)> {
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
        ).unwrap();
    
        if !pow.verify_pow(&self.pow_hash, self.pow_nonce) {
            return None;
        }
    
        // Decrypt and verify signature
        Encryption::decrypt_for_recipient(
            &self.ciphertext,
            &self.nonce,
            &self.ephemeral_address_public_key,
            &self.ephemeral_encryption_public_key,
            &self.stealth_address,
            recipient_private_address,
        )
    }    

    pub fn verify_pow(&self, pow_difficulty: usize) -> bool {
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
    use crate::types::address::PrivateAddress;
    use crate::types::argon2_params::SerializableArgon2Params;
    use crate::types::address::PublicAddress;

    #[test]
    fn test_packet_creation_and_decryption() {
        // Create sender private/public addresses and auth
        let sender_private_address = PrivateAddress::new(None, None);
        let sender_public_address = sender_private_address.public_address.clone();
        let sender_auth = sender_private_address.verification_signing_key.clone();

        // Create recipient private and public addresses
        let recipient_private_address = PrivateAddress::new(None, None);
        let recipient_public_address = recipient_private_address.public_address.clone();

        // Message to send
        let message = b"Hello, recipient!";

        // PoW parameters
        let pow_difficulty = 1;
        let ttl = 3600; // 1 hour
        let argon2_params = SerializableArgon2Params::default();

        // Create packet (now requires sender's public address as well)
        let packet = Packet::create_signed_encrypted(
            &sender_auth,
            &sender_public_address,
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
        if let Some((decrypted_message, sender_address_string)) =
            deserialized_packet.verify_and_decrypt(&recipient_private_address, pow_difficulty)
        {
            assert_eq!(message.to_vec(), decrypted_message);

            // Decode the sender's public address from Base58
            let decoded_sender_public_address = PublicAddress::from_base58(&sender_address_string)
                .expect("Failed to decode sender public address");

            // Compare verification keys
            assert_eq!(
                decoded_sender_public_address.verification_key.to_bytes(),
                sender_auth.verifying_key().to_bytes()
            );
        } else {
            panic!("Failed to verify and decrypt the packet.");
        }
    }

    #[test]
    fn test_wrong_recipient_cannot_decrypt() {
        let sender_private_address = PrivateAddress::new(None, None);
        let sender_public_address = sender_private_address.public_address.clone();
        let sender_auth = sender_private_address.verification_signing_key.clone();

        let intended_recipient_private = PrivateAddress::new(None, None);
        let intended_recipient_public = intended_recipient_private.public_address.clone();

        let wrong_recipient_private = PrivateAddress::new(None, None);

        let message = b"Secret message";

        let pow_difficulty = 1;
        let ttl = 3600;
        let argon2_params = SerializableArgon2Params::default();

        let packet = Packet::create_signed_encrypted(
            &sender_auth,
            &sender_public_address,
            &intended_recipient_public,
            message,
            pow_difficulty,
            ttl,
            argon2_params,
        );

        let result = packet.verify_and_decrypt(&wrong_recipient_private, pow_difficulty);
        assert!(result.is_none(), "Wrong recipient should not decrypt the packet");
    }

    #[test]
    fn test_signature_verification_failure() {
        let sender_private_address = PrivateAddress::new(None, None);
        let sender_public_address = sender_private_address.public_address.clone();
        let sender_auth = sender_private_address.verification_signing_key.clone();

        let recipient_private_address = PrivateAddress::new(None, None);
        let recipient_public_address = recipient_private_address.public_address.clone();

        let message = b"Important message";

        let pow_difficulty = 1;
        let ttl = 3600;
        let argon2_params = SerializableArgon2Params::default();

        let mut packet = Packet::create_signed_encrypted(
            &sender_auth,
            &sender_public_address,
            &recipient_public_address,
            message,
            pow_difficulty,
            ttl,
            argon2_params,
        );

        // Tamper with the ciphertext
        let mut decrypted_payload_bytes = packet.ciphertext.clone();
        if let Some(byte) = decrypted_payload_bytes.get_mut(0) {
            *byte ^= 0x01;
        }
        packet.ciphertext = decrypted_payload_bytes;

        let result = packet.verify_and_decrypt(&recipient_private_address, pow_difficulty);
        assert!(result.is_none(), "Tampered packet should fail verification");
    }

    #[test]
    fn test_invalid_pow_rejection() {
        let sender_private_address = PrivateAddress::new(None, None);
        let sender_public_address = sender_private_address.public_address.clone();
        let sender_auth = sender_private_address.verification_signing_key.clone();

        let recipient_private_address = PrivateAddress::new(None, None);
        let recipient_public_address = recipient_private_address.public_address.clone();

        let message = b"Test message";

        let pow_difficulty = 1;
        let ttl = 3600;
        let argon2_params = SerializableArgon2Params::default();

        let mut packet = Packet::create_signed_encrypted(
            &sender_auth,
            &sender_public_address,
            &recipient_public_address,
            message,
            pow_difficulty,
            ttl,
            argon2_params,
        );

        // Tamper with the PoW nonce
        packet.pow_nonce += 1;

        let result = packet.verify_and_decrypt(&recipient_private_address, pow_difficulty);
        assert!(result.is_none(), "Packet with invalid PoW should be rejected");
    }

    #[test]
    fn test_stealth_address_mismatch() {
        let sender_private_address = PrivateAddress::new(None, None);
        let sender_public_address = sender_private_address.public_address.clone();
        let sender_auth = sender_private_address.verification_signing_key.clone();

        let intended_recipient_private = PrivateAddress::new(None, None);
        let intended_recipient_public = intended_recipient_private.public_address.clone();

        let other_recipient_private = PrivateAddress::new(None, None);

        let message = b"Stealth message";

        let pow_difficulty = 1;
        let ttl = 3600;
        let argon2_params = SerializableArgon2Params::default();

        let packet = Packet::create_signed_encrypted(
            &sender_auth,
            &sender_public_address,
            &intended_recipient_public,
            message,
            pow_difficulty,
            ttl,
            argon2_params,
        );

        let result = packet.verify_and_decrypt(&other_recipient_private, pow_difficulty);
        assert!(
            result.is_none(),
            "Recipient with mismatching stealth address should not decrypt the packet"
        );
    }
}
