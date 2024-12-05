// src/types/address.rs

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Sha256, Digest};
use bs58;
use rand::rngs::OsRng;
use rand_core::RngCore;
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
    pub fn new(prefix: Option<RoutingPrefix>) -> Self {
        let mut rng = OsRng;

        // Determine the prefix
        let prefix = prefix.unwrap_or_else(|| {
            // Generate a random bit length between 1 and 64
            let bit_length = (rng.next_u32() % 65) as u8;
            RoutingPrefix::random(bit_length)
        });

        // Generate random private scalars
        let one_time_scalar = random_scalar(&mut rng);
        let encryption_scalar = random_scalar(&mut rng);

        // Compute public keys
        let one_time_address = &one_time_scalar * &RISTRETTO_BASEPOINT_POINT;
        let encryption_key = &encryption_scalar * &RISTRETTO_BASEPOINT_POINT;

        // Generate Ed25519 signing key
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



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_address_creation() {
        let private_address = PrivateAddress::new(None);
        let public_address = private_address.public_address.clone();
        assert_eq!(
            &private_address.one_time_scalar * &RISTRETTO_BASEPOINT_POINT,
            public_address.one_time_address
        );
        assert_eq!(
            &private_address.encryption_scalar * &RISTRETTO_BASEPOINT_POINT,
            public_address.encryption_key
        );
        assert_eq!(
            private_address.verification_signing_key.verifying_key(),
            public_address.verification_key
        );
    }

    #[test]
    fn test_public_address_encoding_decoding() {
        let private_address = PrivateAddress::new(None);
        let public_address = private_address.public_address.clone();
        let encoded = public_address.to_base58();
        let decoded = PublicAddress::from_base58(&encoded).expect("Failed to decode address");
        assert_eq!(public_address.prefix.bit_length, decoded.prefix.bit_length);
        assert_eq!(public_address.prefix.bits, decoded.prefix.bits);
        assert_eq!(
            public_address.one_time_address.compress().as_bytes(),
            decoded.one_time_address.compress().as_bytes()
        );
        assert_eq!(
            public_address.encryption_key.compress().as_bytes(),
            decoded.encryption_key.compress().as_bytes()
        );
        assert_eq!(
            public_address.verification_key.to_bytes(),
            decoded.verification_key.to_bytes()
        );
        assert_eq!(public_address.checksum, decoded.checksum);
    }

    #[test]
    fn test_invalid_checksum() {
        let private_address = PrivateAddress::new(None);
        let public_address = private_address.public_address.clone();
        let mut encoded = public_address.to_base58();
        // Corrupt the encoding by changing characters
        let len = encoded.len();
        encoded.replace_range(len - 5..len - 1, "abcd");
        assert!(PublicAddress::from_base58(&encoded).is_err());
    }

    #[test]
    fn test_routing_prefix_none() {
        // Create a RoutingPrefix with no bits
        let prefix = RoutingPrefix {
            bit_length: 0,
            bits: None,
        };
        let bytes = prefix.to_bytes();
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0], 0);

        let (decoded_prefix, len) = RoutingPrefix::from_bytes(&bytes).unwrap();
        assert_eq!(len, 1);
        assert_eq!(decoded_prefix, prefix);
    }

    #[test]
    fn test_private_address_creation_with_no_prefix() {
        let prefix = RoutingPrefix {
            bit_length: 0,
            bits: None,
        };
        let private_address = PrivateAddress::new(Some(prefix.clone()));
        let public_address = private_address.public_address.clone();
        assert_eq!(public_address.prefix, prefix);
    }

    #[test]
    fn test_public_address_encoding_decoding_with_no_prefix() {
        let prefix = RoutingPrefix {
            bit_length: 0,
            bits: None,
        };
        let private_address = PrivateAddress::new(Some(prefix.clone()));
        let public_address = private_address.public_address.clone();
        let encoded = public_address.to_base58();
        let decoded = PublicAddress::from_base58(&encoded).expect("Failed to decode address");
        assert_eq!(public_address.prefix, decoded.prefix);
    }
}
