// src/types/routing_prefix.rs

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RoutingPrefix {
    pub bit_length: u8,
    pub bits: Option<u64>, // None represents the prefix that serves all, otherwise stores up to 64 bits in their natural order (right-aligned)
}

impl RoutingPrefix {
    /// Generate a random RoutingPrefix with a given bit length
    pub fn random(bit_length: u8) -> Self {
        assert!(bit_length <= 64, "bit_length must be between 0 and 64");
        if bit_length == 0 {
            // No bits (serves all)
            RoutingPrefix {
                bit_length,
                bits: None,
            }
        } else {
            let mut rng = OsRng;
            let mask = if bit_length == 64 {
                !0u64 // All bits set for 64-bit length
            } else {
                (1u64 << bit_length) - 1
            };
            let bits = rng.next_u64() & mask; // Generate random bits, right-aligned
            RoutingPrefix {
                bit_length,
                bits: Some(bits),
            }
        }
    }

    /// Returns true if self serves the given prefix.
    pub fn serves(&self, other: &RoutingPrefix) -> bool {
        match (self.bits, other.bits) {
            (None, _) => true, // None (bit_length 0) serves all
            (_, None) => false, // Non-none prefix doesn't serve None
            (Some(self_bits), Some(other_bits)) => {
                if self.bit_length > other.bit_length {
                    return false;
                }
                // Compare only the relevant bits, no need to shift if we mask first
                let mask = (1u64 << self.bit_length) - 1;
                (self_bits & mask) == (other_bits >> (other.bit_length - self.bit_length)) & mask
            }
        }
    }

    /// Calculate the number of bytes needed to store the prefix
    pub fn num_bytes(&self) -> usize {
        if self.bit_length == 0 {
            0
        } else {
            (self.bit_length as usize + 7) / 8
        }
    }

    /// Serialize the RoutingPrefix into bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let num_bytes = self.num_bytes();
        let mut bytes = Vec::with_capacity(1 + num_bytes);
        bytes.push(self.bit_length);
        if let Some(bits) = self.bits {
            let bits_bytes = bits.to_be_bytes(); // Big-endian
            bytes.extend_from_slice(&bits_bytes[8 - num_bytes..]); // Take the necessary high-order bytes
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

        let num_bytes = (bit_length + 7) / 8; // Correctly calculate num_bytes

        if data.len() < 1 + num_bytes as usize { // Cast num_bytes to usize for comparison
            return Err("Data too short for RoutingPrefix bits");
        }

        let bits = if bit_length == 0 {
            None
        } else {
            let mut bits_bytes = [0u8; 8];
            bits_bytes[8 - num_bytes as usize..].copy_from_slice(&data[1..1 + num_bytes as usize]);
            Some(u64::from_be_bytes(bits_bytes))
        };

        Ok((
            RoutingPrefix {
                bit_length,
                bits,
            },
            1 + num_bytes as usize, // Return consumed bytes as usize
        ))
    }

    /// Calculate the XOR distance between two RoutingPrefixes
    pub fn xor_distance(&self, other: &Self) -> (Option<u64>, u8) {
        match (self.bits, other.bits) {
            (None, None) => (None, 0), // Both are "serves all", so no distance
            (Some(self_bits), Some(other_bits)) => {
                let effective_bit_length = self.bit_length.min(other.bit_length);
                let self_aligned = self_bits << (64 - self.bit_length);
                let other_aligned = other_bits << (64 - other.bit_length);
                let xor_result = self_aligned ^ other_aligned;

                if xor_result == 0 {
                    (None, effective_bit_length)
                } else {
                    (Some(xor_result.leading_zeros() as u64), effective_bit_length)
                }
            },
            _ => (None, 0), // One is "serves all", the other is not
        }
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
    fn test_serves_method() {
        let prefix_a = RoutingPrefix { bit_length: 3, bits: Some(0b101) };
        let prefix_b = RoutingPrefix { bit_length: 8, bits: Some(0b10110000) };
        let prefix_c = RoutingPrefix { bit_length: 8, bits: Some(0b10101000) };
        let prefix_d = RoutingPrefix { bit_length: 8, bits: Some(0b11010000) };
        let prefix_e = RoutingPrefix { bit_length: 3, bits: Some(0b110) };

        assert!(prefix_a.serves(&prefix_b), "prefix_a should serve prefix_b");
        assert!(prefix_a.serves(&prefix_c), "prefix_a should serve prefix_c");
        assert!(!prefix_a.serves(&prefix_d), "prefix_a should not serve prefix_d");
        assert!(!prefix_e.serves(&prefix_b), "prefix_e should not serve prefix_b");

        let prefix_zero = RoutingPrefix { bit_length: 0, bits: None };
        assert!(prefix_zero.serves(&prefix_a));
        assert!(prefix_zero.serves(&prefix_b));
        assert!(prefix_zero.serves(&prefix_d));

        assert!(prefix_a.serves(&prefix_a));
        assert!(prefix_b.serves(&prefix_b));

        // Test cases where the second prefix has None bits
        let prefix_f = RoutingPrefix { bit_length: 5, bits: Some(0b10110) };
        assert!(!prefix_f.serves(&prefix_zero), "prefix_f should not serve prefix_zero");
    }

    #[test]
    fn test_random_routing_prefix() {
        for &bit_length in &[0, 1, 3, 8, 16, 32, 64] {
            let prefix = RoutingPrefix::random(bit_length);
            assert_eq!(prefix.bit_length, bit_length);
            if bit_length == 0 {
                assert!(prefix.bits.is_none());
            } else {
                assert!(prefix.bits.is_some());
                let bits = prefix.bits.unwrap();

                if bit_length == 64 {
                    // Special handling for 64-bit length
                    assert!(bits <= ::std::u64::MAX);
                }
                else {
                    let mask = (1u64 << bit_length) - 1;
                    assert_eq!(bits & !mask, 0, "Bits exceed bit_length");
                }
            }
        }
    }

    #[test]
    fn test_to_and_from_bytes() {
        let prefixes = vec![
            RoutingPrefix { bit_length: 0, bits: None },
            RoutingPrefix { bit_length: 1, bits: Some(1) },
            RoutingPrefix { bit_length: 3, bits: Some(0b101) },
            RoutingPrefix { bit_length: 8, bits: Some(0b10110000) },
            RoutingPrefix { bit_length: 16, bits: Some(0b1011000011110000) },
            RoutingPrefix { bit_length: 32, bits: Some(0b10110000111100001011000011110000) },
            RoutingPrefix { bit_length: 64, bits: Some(!0u64) },
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
        let invalid_data = vec![
            vec![],
            vec![65],
            vec![3],
            vec![16, 0xAA],
            vec![32, 0xAA, 0xBB],
            vec![255],
        ];

        for data in invalid_data {
            let result = RoutingPrefix::from_bytes(&data);
            assert!(result.is_err(), "Expected error for invalid data: {:?}", data);
        }
    }

    #[test]
    fn test_xor_distance() {
        let prefix1 = RoutingPrefix { bit_length: 3, bits: Some(0b101) };
        let prefix2 = RoutingPrefix { bit_length: 3, bits: Some(0b100) };
        let (distance_opt, effective_length) = prefix1.xor_distance(&prefix2);
        assert_eq!(effective_length, 3);
        assert!(distance_opt.is_some());
        assert_eq!(distance_opt.unwrap(), 2);

        let (distance_opt, effective_length) = prefix1.xor_distance(&prefix1);
        assert_eq!(distance_opt, None);
        assert_eq!(effective_length, 3);

        let prefix3 = RoutingPrefix { bit_length: 4, bits: Some(0b1010) };
        let prefix4 = RoutingPrefix { bit_length: 3, bits: Some(0b101) };
        let (distance_opt, effective_length) = prefix3.xor_distance(&prefix4);
        assert_eq!(distance_opt, None);
        assert_eq!(effective_length, 3);

        let prefix_none = RoutingPrefix { bit_length: 0, bits: None };
        let (distance_opt, effective_length) = prefix1.xor_distance(&prefix_none);
        assert_eq!(distance_opt, None);
        assert_eq!(effective_length, 0);

        let (distance_opt, effective_length) = prefix_none.xor_distance(&prefix_none);
        assert_eq!(distance_opt, None);
        assert_eq!(effective_length, 0);

        // Test with maximum bit length (64)
        let prefix_max1 = RoutingPrefix { bit_length: 64, bits: Some(0xFFFFFFFFFFFFFFFF) };
        let prefix_max2 = RoutingPrefix { bit_length: 64, bits: Some(0x7FFFFFFFFFFFFFFF) };
        let (distance_opt, effective_length) = prefix_max1.xor_distance(&prefix_max2);
        assert_eq!(effective_length, 64);
        assert!(distance_opt.is_some());
        assert_eq!(distance_opt.unwrap(), 0);
    }

    #[test]
    fn test_edge_cases() {
        let max_prefix = RoutingPrefix::random(64);
        assert_eq!(max_prefix.bit_length, 64);
        assert!(max_prefix.bits.is_some());

        let zero_prefix = RoutingPrefix::random(0);
        assert_eq!(zero_prefix.bit_length, 0);
        assert!(zero_prefix.bits.is_none());
    }

    #[test]
    fn test_serialization_consistency() {
        let prefix = RoutingPrefix::random(32);
        let serialized = prefix.to_bytes();
        let (deserialized, _) = RoutingPrefix::from_bytes(&serialized).unwrap();
        let re_serialized = deserialized.to_bytes();
        assert_eq!(serialized, re_serialized, "Serialization consistency");
    }

    #[test]
    fn test_bits_masking() {
        let prefix = RoutingPrefix { bit_length: 10, bits: Some(0b1111111111) };
        let mask = (1u64 << 10) - 1;
        assert_eq!(prefix.bits.unwrap() & mask, 0b1111111111, "Bits should be masked correctly");
    }
}