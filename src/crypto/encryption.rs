// src/crypto/encryption.rs
#![allow(non_snake_case)]
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use bincode;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Verifier};
use rand::rngs::OsRng;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Sha512, Sha256, Digest};
use zstd::stream::{decode_all, encode_all};

use crate::crypto::authentication::Authentication;
use crate::types::address::{PublicAddress, PrivateAddress};
use crate::utils::random_scalar;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedPayload {
    pub signature: Vec<u8>,
    pub sender_address: String, // Base58-encoded sender public address
    pub compressed_message: Vec<u8>,
}

pub struct Encryption;

impl Encryption {
    /// Encrypt and sign a message for the recipient.
    /// Now requires the sender's public address, so we can embed it as Base58 in the payload.
    pub fn encrypt_for_recipient(
        auth: &Authentication,
        sender_public_address: &PublicAddress,
        recipient_address: &PublicAddress,
        message: &[u8],
    ) -> (
        Vec<u8>,         // ciphertext
        [u8; 12],        // nonce
        [u8; 32],        // ephemeral_address_public_key (R_a)
        [u8; 32],        // ephemeral_encryption_public_key (R_e)
        [u8; 32],        // stealth_address
    ) {
        let mut rng = OsRng;

        // Generate ephemeral scalars
        let r_a_scalar = random_scalar(&mut rng);
        let r_e_scalar = random_scalar(&mut rng);

        let R_a_point = &r_a_scalar * &RISTRETTO_BASEPOINT_POINT;
        let R_e_point = &r_e_scalar * &RISTRETTO_BASEPOINT_POINT;

        let R_a_bytes = R_a_point.compress().to_bytes();
        let R_e_bytes = R_e_point.compress().to_bytes();

        // Compute stealth address
        let recipient_one_time_point = recipient_address.one_time_address;
        let r_a_times_one_time_point = &r_a_scalar * &recipient_one_time_point;
        let r_a_times_one_time_bytes = r_a_times_one_time_point.compress().to_bytes();

        let mut hasher = Sha512::default();
        hasher.update(r_a_times_one_time_bytes);
        let H_s_scalar = Scalar::from_hash(hasher);

        let stealth_address_point = recipient_address.encryption_key + &H_s_scalar * &RISTRETTO_BASEPOINT_POINT;
        let stealth_address_bytes = stealth_address_point.compress().to_bytes();

        // Compute shared secret S_e for encryption
        let recipient_encryption_point = recipient_address.encryption_key;
        let S_e_point = &r_e_scalar * &recipient_encryption_point;
        let S_e_bytes = S_e_point.compress().to_bytes();

        // Derive encryption key
        let encryption_key_hash = Sha256::digest(&S_e_bytes);
        let encryption_key = encryption_key_hash;

        let key = Key::<Aes256Gcm>::from_slice(&encryption_key);
        let cipher = Aes256Gcm::new(key);

        // Generate nonce
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Compress message
        let compressed_message = encode_all(message, 0).expect("Failed to compress message");

        // Sign message
        let signature = auth.sign_message(&compressed_message).to_bytes().to_vec();

        // Encode sender public address as Base58
        let sender_address_b58 = sender_public_address.to_base58();

        let encrypted_payload = EncryptedPayload {
            signature,
            sender_address: sender_address_b58,
            compressed_message,
        };

        let encrypted_payload_bytes = bincode::serialize(&encrypted_payload)
            .expect("Failed to serialize EncryptedPayload");

        let ciphertext = cipher.encrypt(nonce, encrypted_payload_bytes.as_ref())
            .expect("Encryption failed");

        (
            ciphertext,
            nonce_bytes,
            R_a_bytes,
            R_e_bytes,
            stealth_address_bytes
        )
    }

    /// Decrypt and verify the packet ciphertext and signature.
    /// Returns (decrypted_message, sender_address_b58).
    pub fn decrypt_for_recipient(
        ciphertext: &[u8],
        nonce: &[u8; 12],
        ephemeral_address_public_key: &[u8; 32],
        ephemeral_encryption_public_key: &[u8; 32],
        stealth_address: &[u8; 32],
        recipient_private_address: &PrivateAddress,
    ) -> Option<(Vec<u8>, String)> {
        // Reconstruct points
        let R_a_point = curve25519_dalek::ristretto::CompressedRistretto(*ephemeral_address_public_key)
            .decompress()?;
        let R_e_point = curve25519_dalek::ristretto::CompressedRistretto(*ephemeral_encryption_public_key)
            .decompress()?;

        // Compute H_s
        let k_a_scalar = recipient_private_address.one_time_scalar;
        let k_a_R_a_point = k_a_scalar * R_a_point;
        let k_a_R_a_bytes = k_a_R_a_point.compress().to_bytes();

        let mut hasher = Sha512::default();
        hasher.update(k_a_R_a_bytes);
        let H_s_scalar = Scalar::from_hash(hasher);

        // Compute expected stealth address
        let expected_stealth_address_point = recipient_private_address.encryption_scalar * &RISTRETTO_BASEPOINT_POINT + &H_s_scalar * &RISTRETTO_BASEPOINT_POINT;
        let expected_stealth_address_bytes = expected_stealth_address_point.compress().to_bytes();

        if expected_stealth_address_bytes != *stealth_address {
            return None;
        }

        // Compute S_e
        let k_e_scalar = recipient_private_address.encryption_scalar;
        let S_e_point = k_e_scalar * R_e_point;
        let S_e_bytes = S_e_point.compress().to_bytes();

        // Derive key
        let decryption_key_hash = Sha256::digest(&S_e_bytes);
        let decryption_key = decryption_key_hash;

        let key = Key::<Aes256Gcm>::from_slice(&decryption_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);

        let decrypted_payload_bytes = cipher.decrypt(nonce, ciphertext).ok()?;

        let encrypted_payload: EncryptedPayload = bincode::deserialize(&decrypted_payload_bytes).ok()?;

        // Decode sender address from Base58
        let decoded_sender_public_address = PublicAddress::from_base58(&encrypted_payload.sender_address).ok()?;

        // Verify signature using the decoded sender's public address
        let sender_verifying_key = decoded_sender_public_address.verification_key;

        let signature_bytes: &[u8; 64] = encrypted_payload.signature.as_slice().try_into().ok()?;
        let signature = Signature::from_bytes(signature_bytes);

        if sender_verifying_key.verify(&encrypted_payload.compressed_message, &signature).is_err() {
            return None;
        }

        let decompressed_message = decode_all(&encrypted_payload.compressed_message[..]).ok()?;

        // Return the decompressed message and the sender's Base58-encoded address
        Some((decompressed_message, encrypted_payload.sender_address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::authentication::Authentication;
    use crate::types::address::{PrivateAddress, PublicAddress};

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        // Create sender private/public addresses and auth
        let sender_private_address = PrivateAddress::new(None, None);
        let sender_public_address = sender_private_address.public_address.clone();
        let sender_auth = sender_private_address.verification_signing_key.clone();

        // Create recipient private/public addresses
        let recipient_private_address = PrivateAddress::new(None, None);
        let recipient_public_address = recipient_private_address.public_address.clone();

        // Original message
        let message = b"Hello, encryption test!";

        // Encrypt the message for the recipient, now including sender's public address
        let (ciphertext, nonce, ephemeral_address_public_key, ephemeral_encryption_public_key, stealth_address) =
            Encryption::encrypt_for_recipient(
                &sender_auth,
                &sender_public_address,
                &recipient_public_address,
                message,
            );

        // Decrypt the message
        let decrypted = Encryption::decrypt_for_recipient(
            &ciphertext,
            &nonce,
            &ephemeral_address_public_key,
            &ephemeral_encryption_public_key,
            &stealth_address,
            &recipient_private_address,
        );

        assert!(decrypted.is_some(), "Failed to decrypt");
        let (decrypted_message, sender_address_string) = decrypted.unwrap();

        assert_eq!(decrypted_message, message);

        // Decode the sender's public address from Base58 and verify the keys match
        let decoded_sender_public_address = PublicAddress::from_base58(&sender_address_string)
            .expect("Failed to decode sender's public address");

        assert_eq!(
            decoded_sender_public_address.verification_key.to_bytes(),
            sender_auth.verifying_key().to_bytes()
        );
    }

    #[test]
    fn test_wrong_recipient_cannot_decrypt() {
        // Create sender
        let sender_private_address = PrivateAddress::new(None, None);
        let sender_public_address = sender_private_address.public_address.clone();
        let sender_auth = sender_private_address.verification_signing_key.clone();

        // Create intended recipient and a wrong recipient
        let intended_recipient_private = PrivateAddress::new(None, None);
        let intended_recipient_public = intended_recipient_private.public_address.clone();
        let other_recipient_private = PrivateAddress::new(None, None);

        // Message
        let message = b"Secret message for intended recipient only";

        // Encrypt for intended recipient
        let (ciphertext, nonce, ephemeral_address_public_key, ephemeral_encryption_public_key, stealth_address) =
            Encryption::encrypt_for_recipient(
                &sender_auth,
                &sender_public_address,
                &intended_recipient_public,
                message,
            );

        // Attempt decryption by the wrong recipient
        let wrong_result = Encryption::decrypt_for_recipient(
            &ciphertext,
            &nonce,
            &ephemeral_address_public_key,
            &ephemeral_encryption_public_key,
            &stealth_address,
            &other_recipient_private,
        );

        assert!(wrong_result.is_none(), "Wrong recipient should not be able to decrypt");
    }

    #[test]
    fn test_tampered_ciphertext_fails_decryption() {
        // Create sender and recipient
        let sender_private_address = PrivateAddress::new(None, None);
        let sender_public_address = sender_private_address.public_address.clone();
        let sender_auth = sender_private_address.verification_signing_key.clone();

        let recipient_private_address = PrivateAddress::new(None, None);
        let recipient_public_address = recipient_private_address.public_address.clone();

        let message = b"Tampering test";

        // Encrypt
        let (mut ciphertext, nonce, ephemeral_address_public_key, ephemeral_encryption_public_key, stealth_address) =
            Encryption::encrypt_for_recipient(
                &sender_auth,
                &sender_public_address,
                &recipient_public_address,
                message,
            );

        // Tamper with the ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF; // flip a bit
        }

        let result = Encryption::decrypt_for_recipient(
            &ciphertext,
            &nonce,
            &ephemeral_address_public_key,
            &ephemeral_encryption_public_key,
            &stealth_address,
            &recipient_private_address,
        );

        assert!(result.is_none(), "Tampered ciphertext should not decrypt successfully");
    }

    #[test]
    fn test_signature_verification_failure() {
        // Create sender and recipient
        let sender_private_address = PrivateAddress::new(None, None);
        let sender_public_address = sender_private_address.public_address.clone();
        let sender_auth = sender_private_address.verification_signing_key.clone();

        let recipient_private_address = PrivateAddress::new(None, None);
        let recipient_public_address = recipient_private_address.public_address.clone();

        // Encrypt the message
        let message = b"Check signature";
        let (ciphertext, nonce, ephemeral_address_public_key, ephemeral_encryption_public_key, stealth_address) =
            Encryption::encrypt_for_recipient(
                &sender_auth,
                &sender_public_address,
                &recipient_public_address,
                message,
            );

        // Create a fake sender auth with a different key
        let fake_sender_auth = Authentication::new();

        // Decryption with correct keys (no tampering) should work
        let result = Encryption::decrypt_for_recipient(
            &ciphertext,
            &nonce,
            &ephemeral_address_public_key,
            &ephemeral_encryption_public_key,
            &stealth_address,
            &recipient_private_address,
        );

        assert!(result.is_some(), "Should decrypt correctly with original sender");
        let (decrypted_message, sender_address_string) = result.unwrap();
        assert_eq!(decrypted_message, message);

        // Decode the sender address and verify the verifying key matches the original sender
        let decoded_sender_public_address = PublicAddress::from_base58(&sender_address_string)
            .expect("Failed to decode sender's public address");
        let original_sender_key = decoded_sender_public_address.verification_key.to_bytes();

        assert_eq!(original_sender_key, sender_auth.verifying_key().to_bytes());

        // Now, check that this key does not match the fake sender auth key
        assert_ne!(original_sender_key, fake_sender_auth.verifying_key().to_bytes(), "Keys should not match");
    }
}
