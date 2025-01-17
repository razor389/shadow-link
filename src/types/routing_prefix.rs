use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// A trait for computing a distance between two routing prefixes.
pub trait PrefixDistance {
    /// Returns the numeric distance between `self` and `other`, if applicable.
    /// In a tree-based approach, we usually always have some path, so `Some(...)`.
    /// If you wanted to allow "unreachable" states, you could return `None`.
    fn distance(&self, other: &Self) -> Option<u64>;

    /// Returns how many bits (from the left) `self` and `other` share in common.
    fn common_prefix_len(&self, other: &Self) -> u8;
}

/// A prefix used for routing in a binary tree.
///
/// - `bit_length = 0` => root prefix (`bits = None`).
/// - `bit_length > 0` => actual prefix, with `bits` right-aligned to `bit_length`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingPrefix {
    pub bit_length: u8,        // In [0..=64]
    pub bits: Option<u64>,     // None if bit_length=0; else Some(...) masked to that many bits
}

impl RoutingPrefix {
    /// Construct a new `RoutingPrefix`.
    ///
    /// # Panics
    /// - if `bit_length>0 && bits=None`
    /// - if `bit_length=0 && bits!=None`
    /// - if `bits` has bits set above `bit_length`
    pub fn new(bit_length: u8, bits: Option<u64>) -> Self {
        if bit_length == 0 {
            // Must have bits=None
            assert!(
                bits.is_none(),
                "For bit_length=0, bits must be None (the root)."
            );
            return RoutingPrefix { bit_length: 0, bits: None };
        } else {
            // Must have Some(...) bits and ensure no bits above bit_length are set
            let some_bits = bits.expect("For bit_length>0, bits cannot be None.");
            let mask = if bit_length == 64 {
                u64::MAX
            } else {
                (1 << bit_length) - 1
            };
            assert_eq!(
                some_bits & !mask,
                0,
                "Some bits are out of range for the given bit_length."
            );
            RoutingPrefix { bit_length, bits }
        }
    }

    /// Convenience constructor for the "root" prefix: `(bit_length=0, bits=None)`.
    pub fn root() -> Self {
        RoutingPrefix {
            bit_length: 0,
            bits: None,
        }
    }

    /// Generate a random prefix with a specified bit length.
    ///
    /// - If `bit_length=0`, returns root.
    /// - Otherwise, picks random bits in [0 .. 2^bit_length).
    pub fn random(bit_length: u8) -> Self {
        assert!(bit_length <= 64, "bit_length must be <= 64");
        if bit_length == 0 {
            return Self::root();
        }
        let mask = if bit_length == 64 {
            u64::MAX
        } else {
            (1u64 << bit_length) - 1
        };
        let mut rng = OsRng;
        let r = rng.next_u64() & mask;
        RoutingPrefix {
            bit_length,
            bits: Some(r),
        }
    }

    /// Serialize to bytes:
    /// - 1 byte for `bit_length`
    /// - if `bit_length>0`, next `ceil(bit_length/8)` bytes for the bits.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(self.bit_length);
        if self.bit_length > 0 {
            let some_bits = self.bits.unwrap();
            let num_bytes = ((self.bit_length + 7) / 8) as usize;
            let be_bytes = some_bits.to_be_bytes(); // 8 bytes
            // we want the last `num_bytes` from be_bytes
            let offset = 8 - num_bytes;
            v.extend_from_slice(&be_bytes[offset..]);
        }
        v
    }

    /// Deserialize from bytes, returning `(prefix, bytes_consumed)`.
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), &'static str> {
        if data.is_empty() {
            return Err("No data for RoutingPrefix");
        }
        let bit_length = data[0];
        if bit_length == 0 {
            // then bits must be None
            Ok((RoutingPrefix::root(), 1))
        } else {
            if bit_length > 64 {
                return Err("bit_length too large (>64)");
            }
            let num_bytes = ((bit_length + 7) / 8) as usize;
            if data.len() < 1 + num_bytes {
                return Err("not enough bytes for bits");
            }
            let bytes_slice = &data[1..1 + num_bytes];
            let mut buf = [0u8; 8];
            let offset = 8 - num_bytes;
            buf[offset..].copy_from_slice(bytes_slice);
            let raw = u64::from_be_bytes(buf);

            let mask = if bit_length == 64 {
                u64::MAX
            } else {
                (1 << bit_length) - 1
            };
            let masked = raw & mask;

            let rp = RoutingPrefix {
                bit_length,
                bits: Some(masked),
            };
            Ok((rp, 1 + num_bytes))
        }
    }

    /// Returns `true` if `self` "serves" `other` in a tree sense:
    /// - root (bit_length=0) serves anything
    /// - otherwise, `self` must match the top `self.bit_length` bits of `other`.
    pub fn serves(&self, other: &RoutingPrefix) -> bool {
        if self.bit_length == 0 {
            return true; // root serves all
        }
        if self.bit_length > other.bit_length {
            return false; // can't serve if I'm "longer" than them
        }
        // Compare bits
        let some_bits = self.bits.unwrap();
        let other_bits = other.bits.unwrap_or(0);
        // shift `other_bits` so we compare only the top portion
        let shift = other.bit_length - self.bit_length;
        let truncated = other_bits >> shift;
        truncated == some_bits
    }
}

/// Implement the tree-based distance approach on `RoutingPrefix`.
impl PrefixDistance for RoutingPrefix {
    fn distance(&self, other: &Self) -> Option<u64> {
        // Tree distance = (#up) + (#down).
        // If cpl = common prefix length (in bits):
        //   up from self: (self.bit_length - cpl)
        //   down to other: (other.bit_length - cpl)
        // So total = (self.bit_length - cpl) + (other.bit_length - cpl).
        let cpl = self.common_prefix_len(other);
        let dist = (self.bit_length - cpl) + (other.bit_length - cpl);
        Some(dist as u64)
    }

    fn common_prefix_len(&self, other: &Self) -> u8 {
        if self.bit_length == 0 || other.bit_length == 0 {
            // If either is root, we say cpl=0 unless both are root, but that also yields 0.
            return 0;
        }
        // If both have bits, do a top-bit compare up to min length:
        let (Some(a), Some(b)) = (self.bits, other.bits) else {
            return 0;
        };

        let min_len = self.bit_length.min(other.bit_length);
        // We shift both up so that the "significant" bits are in the leftmost side of a 64-bit.
        // Then we count how many leading zeros match.
        let shift_a = 64 - self.bit_length;
        let shift_b = 64 - other.bit_length;
        let a_aligned = a << shift_a;
        let b_aligned = b << shift_b;

        let xor_val = a_aligned ^ b_aligned;
        let leading_zeros = xor_val.leading_zeros();
        // Convert to bits, clamp to min_len
        let cpl = (leading_zeros as u8).min(min_len);
        cpl
    }
}

impl Default for RoutingPrefix {
    fn default() -> Self {
        Self::root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::routing_prefix::PrefixDistance;

    #[test]
    fn test_root_prefix() {
        let root = RoutingPrefix::root();
        assert_eq!(root.bit_length, 0);
        assert_eq!(root.bits, None);
        // root serves anything
        let rp = RoutingPrefix::new(3, Some(0b101));
        assert!(root.serves(&rp));
        // also root serves itself
        assert!(root.serves(&root));
    }

    #[test]
    fn test_new() {
        let rp = RoutingPrefix::new(3, Some(0b101));
        assert_eq!(rp.bit_length, 3);
        assert_eq!(rp.bits, Some(0b101));
    }

    #[test]
    fn test_serves() {
        let a = RoutingPrefix::new(3, Some(0b101));
        let b = RoutingPrefix::new(5, Some(0b10110));
        assert!(a.serves(&b), "3-bit prefix 101 should serve 10110");
        assert!(!b.serves(&a), "Longer prefix does not serve shorter unless exact match");
    }

    #[test]
    fn test_tree_distance() {
        let a = RoutingPrefix::new(3, Some(0b101));
        let b = RoutingPrefix::new(5, Some(0b10110));
        // common_prefix_len = 3, so distance = (3-3) + (5-3) = 2
        assert_eq!(a.distance(&b), Some(2));

        let c = RoutingPrefix::root();
        // c is root => cpl=0 => distance= 3 + 0=3 for (a, c)
        // or 5 + 0=5 for (b, c)
        assert_eq!(a.distance(&c), Some(3));
        assert_eq!(b.distance(&c), Some(5));
    }

    #[test]
    fn test_to_from_bytes() {
        let rp = RoutingPrefix::new(5, Some(0b10110));
        let bytes = rp.to_bytes();
        let (decoded, used) = RoutingPrefix::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, rp);
        assert_eq!(used, bytes.len());
    }

    #[test]
    fn test_distance_trait() {
        // Just verifying we can call the trait directly
        let p1 = RoutingPrefix::new(4, Some(0b1010));
        let p2 = RoutingPrefix::new(4, Some(0b1011));
        // cpl=3 => distance= (4-3)+(4-3)= 2
        assert_eq!(PrefixDistance::distance(&p1, &p2), Some(2));
        assert_eq!(p1.common_prefix_len(&p2), 3);
    }
}
