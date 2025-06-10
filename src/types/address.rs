// src/types/address.rs

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Sha256, Digest};
use bs58;
use rand::rngs::OsRng;
use std::convert::TryInto;
use crate::crypto::authentication::Authentication;
use crate::utils::random_scalar;
use crate::types::routing_prefix::RoutingPrefix;

pub type StealthAddress = [u8; 32];

#[derive(Debug, Clone)]
pub struct PublicAddress {
    pub prefix: RoutingPrefix,
    pub one_time_address: RistrettoPoint,
    pub encryption_key: RistrettoPoint,
    pub verification_key: VerifyingKey,
    pub checksum: [u8; 4],
}

#[derive(Debug, Clone)]
pub struct PrivateAddress {
    pub one_time_scalar: Scalar,
    pub encryption_scalar: Scalar,
    pub verification_signing_key: Authentication,
    pub public_address: PublicAddress,
}

impl PrivateAddress {
    /// Creates a new private address with an optional prefix
    pub fn new(prefix: Option<RoutingPrefix>, length: Option<u8>) -> Self {
        let mut rng = OsRng;
    
        let prefix = match (prefix, length) {
            // If a prefix is provided, use it directly
            (Some(p), _) => p,
            // If a length is provided but no prefix, generate a random prefix with that length
            (None, Some(bit_length)) => {
                assert!(bit_length <= 64, "bit_length must be <= 64");
                RoutingPrefix::random(bit_length)
            },
            // If neither a prefix nor a length is provided, use a zero-length prefix (None prefix)
            (None, None) => RoutingPrefix::default(),
        };
    
        // Generate random scalars
        let one_time_scalar = random_scalar(&mut rng);
        let encryption_scalar = random_scalar(&mut rng);
    
        // Compute public keys
        let one_time_address = &one_time_scalar * &RISTRETTO_BASEPOINT_POINT;
        let encryption_key = &encryption_scalar * &RISTRETTO_BASEPOINT_POINT;
    
        // Generate signing key
        let verification_signing_key = SigningKey::generate(&mut rng);
        let verification_key = verification_signing_key.verifying_key();
        let auth = Authentication::new_from_signing_key(verification_signing_key);
    
        // Calculate checksum
        let checksum = calculate_checksum(
            &prefix,
            &one_time_address,
            &encryption_key,
            &verification_key,
        );
    
        let public_address = PublicAddress {
            prefix,
            one_time_address,
            encryption_key,
            verification_key,
            checksum,
        };
    
        PrivateAddress {
            one_time_scalar,
            encryption_scalar,
            verification_signing_key: auth,
            public_address,
        }
    }    
}

impl PublicAddress {
    /// Calculate the checksum for the address
    #[allow(dead_code)]
    fn calculate_checksum(
        prefix: &RoutingPrefix,
        one_time_address: &RistrettoPoint,
        encryption_key: &RistrettoPoint,
        verification_key: &VerifyingKey,
    ) -> [u8; 4] {
        calculate_checksum(prefix, one_time_address, encryption_key, verification_key)
    }

    /// Encode the address to Base58
    pub fn to_base58(&self) -> String {
        let prefix_bytes = self.prefix.to_bytes();
        let total_len = prefix_bytes.len() + 32 + 32 + 32 + 4;
        let mut raw = Vec::with_capacity(total_len);
        raw.extend_from_slice(&prefix_bytes);
        raw.extend_from_slice(self.one_time_address.compress().as_bytes());
        raw.extend_from_slice(self.encryption_key.compress().as_bytes());
        raw.extend_from_slice(&self.verification_key.to_bytes());
        raw.extend_from_slice(&self.checksum);
        bs58::encode(raw).into_string()
    }


    /// Decode a Base58-encoded address
    #[allow(unused_assignments)]
    pub fn from_base58(address: &str) -> Result<Self, &'static str> {
        let raw = bs58::decode(address)
            .into_vec()
            .map_err(|_| "Invalid Base58 encoding")?;
        let raw_len = raw.len();
        if raw_len < 1 + 32 + 32 + 32 + 4 {
            return Err("Address is too short");
        }

        let mut index = 0;

        // Parse the RoutingPrefix
        let (prefix, prefix_len) = RoutingPrefix::from_bytes(&raw[index..])?;
        index += prefix_len;

        // Check if there's enough data left
        if raw_len < index + 32 + 32 + 32 + 4 {
            return Err("Address is too short");
        }

        // Read one_time_address
        let one_time_address_bytes: [u8; 32] = raw[index..index + 32]
            .try_into()
            .map_err(|_| "Invalid one-time address bytes")?;
        let one_time_address = CompressedRistretto(one_time_address_bytes)
            .decompress()
            .ok_or("Invalid one-time address point")?;
        index += 32;

        // Read encryption_key
        let encryption_key_bytes: [u8; 32] = raw[index..index + 32]
            .try_into()
            .map_err(|_| "Invalid encryption key bytes")?;
        let encryption_key = CompressedRistretto(encryption_key_bytes)
            .decompress()
            .ok_or("Invalid encryption key point")?;
        index += 32;

        // Read verification_key
        let verification_key_bytes: [u8; 32] = raw[index..index + 32]
            .try_into()
            .map_err(|_| "Invalid verification key bytes")?;
        let verification_key = VerifyingKey::from_bytes(&verification_key_bytes)
            .map_err(|_| "Invalid Ed25519 public key")?;
        index += 32;

        // Read checksum
        let checksum: [u8; 4] = raw[index..index + 4]
            .try_into()
            .map_err(|_| "Invalid checksum bytes")?;
        index += 4;

        // Verify checksum
        let calculated_checksum = calculate_checksum(
            &prefix,
            &one_time_address,
            &encryption_key,
            &verification_key,
        );
        if checksum != calculated_checksum {
            return Err("Invalid checksum");
        }

        Ok(PublicAddress {
            prefix,
            one_time_address,
            encryption_key,
            verification_key,
            checksum,
        })
    }

}

/// Helper function to calculate the checksum
fn calculate_checksum(
    prefix: &RoutingPrefix,
    one_time_address: &RistrettoPoint,
    encryption_key: &RistrettoPoint,
    verification_key: &VerifyingKey,
) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(prefix.to_bytes());
    hasher.update(one_time_address.compress().as_bytes());
    hasher.update(encryption_key.compress().as_bytes());
    hasher.update(verification_key.to_bytes());
    let hash = hasher.finalize();
    [hash[0], hash[1], hash[2], hash[3]]
}

