// src/types/routing_prefix.rs

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::utils::create_mask;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RoutingPrefix {
    pub bit_length: u8,
    pub bits: Option<u64>, // Stores up to 64 bits
}

impl RoutingPrefix {
    /// Generate a random RoutingPrefix with a given bit length
    pub fn random(bit_length: u8) -> Self {
        assert!(bit_length <= 64, "bit_length must be between 0 and 64");
        if bit_length == 0 {
            // No bits
            RoutingPrefix {
                bit_length: 0,
                bits: None,
            }
        } else {
            let mut rng = OsRng;
            let bits = rng.next_u64() >> (64 - bit_length);
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
            bytes.extend_from_slice(&bits_bytes[8 - num_bytes..]); // Take least significant bytes
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
            bits_array[8 - num_bytes..].copy_from_slice(bits_bytes);
            let bits = u64::from_be_bytes(bits_array);
            // Mask the bits to the bit_length
            let bits = bits & (!0u64 >> (64 - bit_length));
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

        // Mask the bits to the effective bit length
        let mask = !0u64 >> (64 - effective_bit_length);

        // Compute the XOR distance
        let self_bits = self.bits.unwrap() & mask;
        let other_bits = other.bits.unwrap() & mask;

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

    #[test]
    fn test_random_routing_prefix() {
        // Test random generation for various bit lengths
        for &bit_length in &[0, 1, 8, 16, 32, 64] {
            let prefix = RoutingPrefix::random(bit_length);
            assert_eq!(prefix.bit_length, bit_length);
            if bit_length == 0 {
                assert!(prefix.bits.is_none());
            } else {
                assert!(prefix.bits.is_some());
                // Ensure the bits fit within the bit length
                let bits = prefix.bits.unwrap();
                let mask = !0u64 >> (64 - bit_length);
                assert_eq!(bits & !mask, 0, "Bits exceed bit_length");
            }
        }
    }

    #[test]
    fn test_all_zero_bits() {
        let prefix = RoutingPrefix {
            bit_length: 8,
            bits: Some(0),
        };
        assert_eq!(prefix.bit_length, 8);
        assert_eq!(prefix.bits, Some(0));

        let serialized = prefix.to_bytes();
        let (deserialized, consumed) = RoutingPrefix::from_bytes(&serialized).unwrap();
        assert_eq!(prefix, deserialized);
        assert_eq!(consumed, serialized.len());
    }

    #[test]
    fn test_num_bytes() {
        // Test num_bytes calculation
        let test_cases = [
            (0, 0),
            (1, 1),
            (7, 1),
            (8, 1),
            (9, 2),
            (15, 2),
            (16, 2),
            (17, 3),
            (24, 3),
            (31, 4),
            (32, 4),
            (33, 5),
            (40, 5),
            (48, 6),
            (56, 7),
            (64, 8),
        ];
        for &(bit_length, expected_bytes) in &test_cases {
            let prefix = RoutingPrefix::random(bit_length);
            assert_eq!(
                prefix.num_bytes(),
                expected_bytes,
                "Failed for bit_length {}",
                bit_length
            );
        }
    }

    #[test]
    fn test_to_and_from_bytes() {
        // Test serialization and deserialization
        let prefixes = vec![
            RoutingPrefix::random(0),
            RoutingPrefix::random(1),
            RoutingPrefix::random(8),
            RoutingPrefix::random(16),
            RoutingPrefix::random(32),
            RoutingPrefix::random(64),
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
            vec![8],                 // Missing bits for bit_length 8 (needs 1 byte)
            vec![16, 0xAA],          // Missing one byte for bit_length 16 (needs 2 bytes)
            vec![32, 0xAA, 0xBB],    // Missing two bytes for bit_length 32 (needs 4 bytes)
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
        let prefix1 = RoutingPrefix {
            bit_length: 8,
            bits: Some(0b10101010),
        };
        let prefix2 = RoutingPrefix {
            bit_length: 8,
            bits: Some(0b11001100),
        };
        let prefix3 = RoutingPrefix {
            bit_length: 4,
            bits: Some(0b1100),
        };

        // Same bit length
        assert_eq!(
            prefix1.xor_distance(&prefix2),
            Some(0b01100110),
            "XOR distance between prefix1 and prefix2"
        );

        // Different bit lengths
        assert_eq!(
            prefix1.xor_distance(&prefix3),
            Some(0b1010 ^ 0b1100),
            "XOR distance between prefix1 and prefix3 with effective bit length 4"
        );

        // One prefix has no bits
        let prefix_none = RoutingPrefix {
            bit_length: 0,
            bits: None,
        };
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
        let prefix = RoutingPrefix {
            bit_length: 10,
            bits: Some(0xFFFF),
        };
        let expected_bits = 0x03FF; // Only lower 10 bits should be set
        let masked_bits = prefix.bits.unwrap() & (!0u64 >> (64 - prefix.bit_length));
        assert_eq!(
            masked_bits, expected_bits,
            "Bits should be masked to bit_length"
        );
    }
    
    #[test]
    fn test_serves_method() {
        let prefix_a = RoutingPrefix {
            bit_length: 8,
            bits: Some(0b10101010),
        };
        let prefix_b = RoutingPrefix {
            bit_length: 16,
            bits: Some(0b1010101011110000),
        };
        let prefix_c = RoutingPrefix {
            bit_length: 8,
            bits: Some(0b10101011),
        };
        let prefix_d = RoutingPrefix {
            bit_length: 0,
            bits: None,
        };

        // prefix_a serves prefix_b
        assert!(prefix_a.serves(&prefix_b));

        // prefix_b does not serve prefix_a
        assert!(!prefix_b.serves(&prefix_a));

        // prefix_a does not serve prefix_c (bits don't match)
        assert!(!prefix_a.serves(&prefix_c));

        // Zero-length prefix serves all prefixes
        assert!(prefix_d.serves(&prefix_a));
        assert!(prefix_d.serves(&prefix_b));
        assert!(prefix_d.serves(&prefix_c));

        // Any prefix serves itself
        assert!(prefix_a.serves(&prefix_a));
        assert!(prefix_b.serves(&prefix_b));
    }

}
