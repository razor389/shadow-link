// src/types/routing_prefix.rs

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

/// A prefix used for routing.
///
/// - `bit_length = 0` => This is the "root" prefix (serves everything).
///   In this case, `bits` must be `None`.
///
/// - `bit_length > 0` => We have an actual prefix of length `bit_length`,
///   and `bits` is `Some(...)` storing those bits (right-aligned).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingPrefix {
    pub bit_length: u8,         // number of bits in [0..=64]
    pub bits: Option<u64>,      // None if bit_length=0, else Some(u64) masked to bit_length
}

impl RoutingPrefix {
    /// Construct a new `RoutingPrefix`.
    ///
    /// # Panics
    /// - if `bit_length > 0` but `bits = None`
    /// - if `bit_length=0` but `bits != None`
    /// - if `bits` has bits set above `bit_length`
    pub fn new(bit_length: u8, bits: Option<u64>) -> Self {
        if bit_length == 0 {
            // must have bits=None
            assert!(bits.is_none(), "For bit_length=0, bits must be None");
            return RoutingPrefix { bit_length: 0, bits: None };
        } else {
            // must have bits=Some(...)
            let some_bits = bits.expect("For bit_length>0, bits cannot be None");
            let mask = if bit_length == 64 {
                u64::MAX
            } else {
                (1 << bit_length) - 1
            };
            // ensure no bits above bit_length
            assert_eq!(some_bits & !mask, 0, "bits out of range for the given bit_length");
            return RoutingPrefix { bit_length, bits: Some(some_bits) };
        }
    }

    /// Special constructor for `(0, None)` root prefix.
    pub fn root() -> Self {
        RoutingPrefix { bit_length: 0, bits: None }
    }

    /// Generate a random prefix with a specified bit length.
    /// 
    /// - If `bit_length=0`, returns `(0, None)`.
    /// - Otherwise, picks random bits in `[0 .. 2^bit_length)`.
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
        RoutingPrefix { bit_length, bits: Some(r) }
    }

    /// Returns `true` if `self` *serves* `other`. That is:
    ///
    /// - If `self.bit_length=0`, it serves all (always returns `true`).
    /// - If `self.bit_length > other.bit_length`, it cannot serve (return `false`).
    /// - Otherwise, the top `self.bit_length` bits of `other` must match `self.bits`.
    ///
    /// Example:
    /// - `(0, None)` serves anything.
    /// - `(3, Some(0b101))` serves `(5, Some(0b10110))`.
    /// - `(3, Some(0b101))` does **not** serve `(3, Some(0b111))`.
    pub fn serves(&self, other: &RoutingPrefix) -> bool {
        // if self is root => true
        if self.bit_length == 0 {
            return true;
        }
        // if self.bit_length > other.bit_length => false
        if self.bit_length > other.bit_length {
            return false;
        }
        // Compare bits
        let self_bits = self.bits.expect("bit_length>0 => bits=Some(...)");
        let other_bits = other.bits.expect("bit_length>0 => bits=Some(...) if other.bit_length>0");
        // shift `other_bits` right by (other.bit_length - self.bit_length)
        // so that we compare them in the same alignment
        let shift = other.bit_length - self.bit_length;
        let truncated = other_bits >> shift;
        truncated == self_bits
    }

    /// Serialize to bytes:
    /// - 1 byte for `bit_length`
    /// - if bit_length>0, next `ceil(bit_length/8)` bytes for the bits
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

    /// Deserialize from bytes, returning `(prefix, consumed_length)`.
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
                return Err("bit_length too large");
            }
            let num_bytes = ((bit_length + 7) / 8) as usize;
            if data.len() < 1 + num_bytes {
                return Err("not enough bytes for bits");
            }
            let bytes_slice = &data[1..1+num_bytes];
            let mut buf = [0u8; 8];
            let offset = 8 - num_bytes;
            buf[offset..].copy_from_slice(bytes_slice);
            let raw = u64::from_be_bytes(buf);
            // mask out anything above bit_length
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
}

impl Default for RoutingPrefix {
    fn default() -> Self {
        RoutingPrefix::root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_root_prefix() {
        let root = RoutingPrefix::root();
        assert_eq!(root.bit_length, 0);
        assert_eq!(root.bits, None);
        // root serves everything
        let rp = RoutingPrefix::new(3, Some(0b101));
        assert!(root.serves(&rp));
        // also root serves itself
        assert!(root.serves(&root));
    }

    #[test]
    fn test_default_is_root() {
        let rp = RoutingPrefix::default();
        assert_eq!(rp.bit_length, 0);
        assert_eq!(rp.bits, None);
    }

    #[test]
    fn test_new_zero_ok() {
        let rp = RoutingPrefix::new(0, None);
        assert_eq!(rp.bit_length, 0);
        assert_eq!(rp.bits, None);
    }

    #[test]
    #[should_panic(expected="For bit_length=0, bits must be None")]
    fn test_new_zero_with_bits_panics() {
        let _ = RoutingPrefix::new(0, Some(123));
    }

    #[test]
    fn test_new_valid_some_bits() {
        let rp = RoutingPrefix::new(3, Some(0b101));
        assert_eq!(rp.bit_length, 3);
        assert_eq!(rp.bits, Some(0b101));
    }

    #[test]
    #[should_panic(expected="bits out of range")]
    fn test_new_bad_bits() {
        // bit_length=3 but bits=0b1000 => that's 8 decimal, i.e. 4 bits set
        let _rp = RoutingPrefix::new(3, Some(0b1000));
    }

    #[test]
    fn test_random_zero() {
        let rp = RoutingPrefix::random(0);
        assert_eq!(rp.bit_length, 0);
        assert!(rp.bits.is_none());
    }

    #[test]
    fn test_random_nonzero() {
        for _ in 0..10 {
            let rp = RoutingPrefix::random(5);
            assert_eq!(rp.bit_length, 5);
            let bits = rp.bits.unwrap();
            assert!(bits < 32, "bits should be < 2^5=32");
        }
    }

    #[test]
    fn test_serves() {
        let root = RoutingPrefix::root();
        let a = RoutingPrefix::new(3, Some(0b101));
        let b = RoutingPrefix::new(5, Some(0b10110));
        assert!(root.serves(&a));
        assert!(root.serves(&b));

        // a serves b because 0b101 is the first 3 bits of 0b10110
        assert!(a.serves(&b));
        // but b does not serve a
        assert!(!b.serves(&a));

        // same length
        let c = RoutingPrefix::new(3, Some(0b110));
        assert!(!a.serves(&c));
    }

    #[test]
    fn test_to_from_bytes_root() {
        let root = RoutingPrefix::root();
        let encoded = root.to_bytes();
        assert_eq!(encoded, vec![0u8]); // single byte of 0
        let (decoded, used) = RoutingPrefix::from_bytes(&encoded).unwrap();
        assert_eq!(used, 1);
        assert_eq!(decoded, root);
    }

    #[test]
    fn test_to_from_bytes_regular() {
        let rp = RoutingPrefix::new(5, Some(0b10110));
        let encoded = rp.to_bytes();
        let (decoded, used) = RoutingPrefix::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, rp);
        assert_eq!(used, encoded.len());
    }

    #[test]
    fn test_to_from_bytes_short_data() {
        // says bit_length=5, but we only provide 1 byte => not enough
        let data = vec![5u8, 0xFF];
        let result = RoutingPrefix::from_bytes(&data);
        assert!(result.is_err());
    }
}
