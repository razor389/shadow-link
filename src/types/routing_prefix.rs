// src/types/routing_prefix.rs

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::utils::create_mask;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RoutingPrefix {
    pub bit_length: u8,
    pub bits: Option<u64>, // Stores up to 64 bits aligned to higher bits
}

impl RoutingPrefix {
    /// Generate a random RoutingPrefix with a given bit length
    pub fn random(bit_length: u8) -> Self {
        assert!(bit_length <= 64, "bit_length must be between 0 and 64");
        if bit_length == 0 {
            // No bits
            RoutingPrefix {
                bit_length,
                bits: None,
            }
        } else if bit_length == 64 {
            // All bits used
            let bits = OsRng.next_u64();
            RoutingPrefix {
                bit_length,
                bits: Some(bits),
            }
        } else {
            let mut rng = OsRng;
            let bits_random = rng.next_u64() & ((1u64 << bit_length) - 1);
            let bits = bits_random << (64 - bit_length); // Align to higher bits
            RoutingPrefix {
                bit_length,
                bits: Some(bits),
            }
        }
    }

    /// Returns true if self serves the given prefix.
    /// A prefix serves another if its bit_length is less than or equal to the other's,
    /// and its bits match the other's bits up to its bit_length.
    pub fn serves(&self, other: &RoutingPrefix) -> bool {
        // Self's bit length must be less than or equal to other's bit length
        if self.bit_length > other.bit_length {
            return false;
        }
        // Zero-length prefix serves all prefixes
        if self.bit_length == 0 {
            return true;
        }
        // Create a mask for self's bit length
        let mask = create_mask(self.bit_length);
        let self_bits = self.bits.unwrap_or(0) & mask;
        let other_bits = other.bits.unwrap_or(0) & mask;
        self_bits == other_bits
    }

    /// Calculate the number of bytes needed to store the bits
    pub fn num_bytes(&self) -> usize {
        if self.bit_length == 0 {
            0
        } else {
            ((self.bit_length + 7) / 8) as usize
        }
    }

    /// Serialize the RoutingPrefix into bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + 8); // 1 byte for bit_length, up to 8 bytes for bits
        bytes.push(self.bit_length);
        if let Some(bits) = self.bits {
            let num_bytes = self.num_bytes();
            let bits_bytes = bits.to_be_bytes(); // Big-endian
            bytes.extend_from_slice(&bits_bytes[..num_bytes]); // Take the necessary high-order bytes
        }
        bytes
    }

    /// Deserialize a RoutingPrefix from bytes
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), &'static str> {
        if data.is_empty() {
            return Err("Data too short for RoutingPrefix");
        }
        let bit_length = data[0];
        if bit_length > 64 {
            return Err("Invalid bit length");
        }
        let num_bytes = if bit_length == 0 { 0 } else { ((bit_length + 7) / 8) as usize };
        if data.len() < 1 + num_bytes {
            return Err("Data too short for RoutingPrefix bits");
        }
        let bits = if bit_length == 0 {
            None
        } else {
            let bits_bytes = &data[1..1 + num_bytes];
            let mut bits_array = [0u8; 8];
            bits_array[..num_bytes].copy_from_slice(bits_bytes);
            let bits = u64::from_be_bytes(bits_array);
            // Mask the bits to the bit_length
            let bits = bits & create_mask(bit_length);
            Some(bits)
        };
        Ok((
            RoutingPrefix {
                bit_length,
                bits,
            },
            1 + num_bytes,
        ))
    }

    /// Calculate the XOR distance between two RoutingPrefixes
    pub fn xor_distance(&self, other: &Self) -> Option<u64> {
        // If either of the prefixes has no bits, return None
        if self.bits.is_none() || other.bits.is_none() {
            return None;
        }

        // Determine the effective bit length to use (minimum of the two bit lengths)
        let effective_bit_length = self.bit_length.min(other.bit_length);

        // Mask both bits to the effective bit length
        let mask = create_mask(effective_bit_length);
        let self_bits = self.bits.unwrap() & mask;
        let other_bits = other.bits.unwrap() & mask;

        // Compute the XOR distance
        Some(self_bits ^ other_bits)
    }
}

// Implement Default for RoutingPrefix
impl Default for RoutingPrefix {
    fn default() -> Self {
        RoutingPrefix {
            bit_length: 0,
            bits: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to create a RoutingPrefix with bits aligned to higher bits
    fn create_prefix(bit_length: u8, bits: u64) -> RoutingPrefix {
        assert!(bit_length <= 64, "bit_length must be <= 64");
        if bit_length == 0 {
            RoutingPrefix {
                bit_length,
                bits: None,
            }
        } else if bit_length == 64 {
            RoutingPrefix {
                bit_length,
                bits: Some(bits),
            }
        } else {
            let bits_aligned = (bits & ((1u64 << bit_length) - 1)) << (64 - bit_length);
            RoutingPrefix {
                bit_length,
                bits: Some(bits_aligned),
            }
        }
    }

    #[test]
    fn test_serves_method() {
        let prefix_a = create_prefix(3, 0b101); // 101 shifted to higher bits
        let prefix_b = create_prefix(8, 0b10110000); // 10110000 shifted
        let prefix_c = create_prefix(8, 0b10101000); // 10101000 shifted
        let prefix_d = create_prefix(8, 0b11010000); // 11010000 shifted
        let prefix_e = create_prefix(3, 0b110); // 110 shifted to higher bits

        // prefix_a serves prefix_b
        assert!(prefix_a.serves(&prefix_b), "prefix_a should serve prefix_b");

        // prefix_a serves prefix_c
        assert!(prefix_a.serves(&prefix_c), "prefix_a should serve prefix_c");

        // prefix_a does not serve prefix_d
        assert!(!prefix_a.serves(&prefix_d), "prefix_a should not serve prefix_d");

        // prefix_e does not serve prefix_b
        assert!(!prefix_e.serves(&prefix_b), "prefix_e should not serve prefix_b");
        assert!(prefix_e.serves(&prefix_d), "prefix_e should serve prefix_d");

        // Zero-length prefix serves all prefixes
        let prefix_zero = create_prefix(0, 0);
        assert!(prefix_zero.serves(&prefix_a));
        assert!(prefix_zero.serves(&prefix_b));
        assert!(prefix_zero.serves(&prefix_d));

        // Any prefix serves itself
        assert!(prefix_a.serves(&prefix_a));
        assert!(prefix_b.serves(&prefix_b));
    }

    #[test]
    fn test_random_routing_prefix() {
        // Test random generation for various bit lengths
        for &bit_length in &[0, 1, 3, 8, 16, 32, 64] {
            let prefix = RoutingPrefix::random(bit_length);
            assert_eq!(prefix.bit_length, bit_length);
            if bit_length == 0 {
                assert!(prefix.bits.is_none());
            } else {
                assert!(prefix.bits.is_some());
                // Ensure the bits fit within the bit length
                let bits = prefix.bits.unwrap();
                let mask = create_mask(bit_length);
                assert_eq!(bits & !mask, 0, "Bits exceed bit_length");
            }
        }
    }

    #[test]
    fn test_to_and_from_bytes() {
        // Test serialization and deserialization
        let prefixes = vec![
            create_prefix(0, 0),
            create_prefix(1, 1),
            create_prefix(3, 0b101),
            create_prefix(8, 0b10110000),
            create_prefix(16, 0b1011000011110000),
            create_prefix(32, 0b10110000111100001011000011110000),
            create_prefix(64, !0u64),
        ];

        for prefix in prefixes {
            let serialized = prefix.to_bytes();
            let (deserialized, consumed) = RoutingPrefix::from_bytes(&serialized).unwrap();
            assert_eq!(prefix, deserialized);
            assert_eq!(consumed, serialized.len());
        }
    }

    #[test]
    fn test_from_bytes_errors() {
        // Test deserialization errors with invalid inputs
        let invalid_data = vec![
            vec![],                  // Empty data
            vec![65],                // Invalid bit length (>64)
            vec![3],                 // Missing bits for bit_length=3 (needs 1 byte)
            vec![16, 0xAA],          // bit_length=16 requires 2 bytes, only 1 provided
            vec![32, 0xAA, 0xBB],    // bit_length=32 requires 4 bytes, only 2 provided
            vec![255],               // Invalid bit length (>64)
        ];

        for data in invalid_data {
            let result = RoutingPrefix::from_bytes(&data);
            assert!(
                result.is_err(),
                "Expected error for invalid data: {:?}",
                data
            );
        }
    }

    #[test]
    fn test_xor_distance() {
        // Test XOR distance calculation
        let prefix1 = create_prefix(8, 0b10101010); // 10101010 shifted
        let prefix2 = create_prefix(8, 0b11001100); // 11001100 shifted
        let prefix3 = create_prefix(4, 0b1100);     // 1100 shifted

        // Same bit length
        assert_eq!(
            prefix1.xor_distance(&prefix2),
            Some((0b10101010 ^ 0b11001100) << (64 - 8)),
            "XOR distance between prefix1 and prefix2"
        );

        // Different bit lengths
        assert_eq!(
            prefix1.xor_distance(&prefix3),
            Some((0b1010 ^ 0b1100) << (64 - 4)),
            "XOR distance between prefix1 and prefix3 with effective bit length 4"
        );

        // One prefix has no bits
        let prefix_none = create_prefix(0, 0);
        assert_eq!(
            prefix1.xor_distance(&prefix_none),
            None,
            "XOR distance when one prefix has no bits"
        );
    }

    #[test]
    fn test_edge_cases() {
        // Test edge cases like maximum bit length and zero bit length
        let max_prefix = RoutingPrefix::random(64);
        assert_eq!(max_prefix.bit_length, 64);
        assert!(max_prefix.bits.is_some());

        let zero_prefix = RoutingPrefix::random(0);
        assert_eq!(zero_prefix.bit_length, 0);
        assert!(zero_prefix.bits.is_none());
    }

    #[test]
    fn test_serialization_consistency() {
        // Ensure that serialization and deserialization are consistent across multiple rounds
        let prefix = RoutingPrefix::random(32);
        let serialized = prefix.to_bytes();
        let (deserialized, _) = RoutingPrefix::from_bytes(&serialized).unwrap();
        let re_serialized = deserialized.to_bytes();
        assert_eq!(serialized, re_serialized, "Serialization consistency");
    }

    #[test]
    fn test_bits_masking() {
        // Ensure that bits are properly masked according to bit_length
        let prefix = create_prefix(10, 0b1111111111); // 10 bits set
        let expected_bits = 0b1111111111 << (64 - 10); // Masked to first 10 bits
        let masked_bits = prefix.bits.unwrap() & create_mask(prefix.bit_length);
        assert_eq!(
            masked_bits, expected_bits,
            "Bits should be masked to bit_length"
        );
    }
}
