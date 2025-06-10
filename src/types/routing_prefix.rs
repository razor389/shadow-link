// src/types/routing_prefix.rs

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

/// A prefix used for routing in a binary tree, left-aligned in a u64.
/// - `bit_length = 0` root case (bits=0)
/// - otherwise, top `bit_length` bits of `bits` are significant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingPrefix {
    pub bit_length: u8,  // number of significant bits [0..=64]
    pub bits: u64,       // left-aligned: significant bits in high-order bits
}

impl RoutingPrefix {
    /// Create a new prefix, left-aligning the low `bit_length` bits of `bits`.
    pub fn new(bit_length: u8, bits: u64) -> Self {
        assert!(bit_length <= 64, "bit_length must be <= 64");
        let aligned = if bit_length == 0 {
            0
        } else {
            // mask off any low bits beyond bit_length, then shift left
            let mask = (!0u64) << (64 - bit_length);
            (bits << (64 - bit_length)) & mask
        };
        RoutingPrefix { bit_length, bits: aligned }
    }

    /// Root prefix (serves all)
    pub fn root() -> Self {
        RoutingPrefix { bit_length: 0, bits: 0 }
    }

    /// Generate a random prefix of given length
    pub fn random(bit_length: u8) -> Self {
        assert!(bit_length <= 64, "bit_length must be <= 64");
        if bit_length == 0 {
            return Self::root();
        }
        let mut rng = OsRng;
        let raw = rng.next_u64();
        RoutingPrefix::new(bit_length, raw)
    }

    /// Serialize to bytes: 1 byte length + ceil(length/8) bytes value
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(self.bit_length);
        if self.bit_length > 0 {
            let byte_len = ((self.bit_length + 7) / 8) as usize;
            let be = self.bits.to_be_bytes();
            v.extend_from_slice(&be[..byte_len]);
        }
        v
    }

    /// Deserialize, returning (prefix, bytes_consumed)
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), &'static str> {
        if data.is_empty() {
            return Err("empty data");
        }
        let bit_length = data[0];
        if bit_length > 64 {
            return Err("bit_length > 64");
        }
        if bit_length == 0 {
            return Ok((Self::root(), 1));
        }
        let byte_len = ((bit_length + 7) / 8) as usize;
        if data.len() < 1 + byte_len {
            return Err("not enough bytes");
        }
        let mut buf = [0u8; 8];
        buf[..byte_len].copy_from_slice(&data[1..1+byte_len]);
        let raw = u64::from_be_bytes(buf);
        Ok((Self { bit_length, bits: raw }, 1 + byte_len))
    }

    /// Returns `true` if `self` "serves" `other` in a tree sense:
    /// - root (bit_length=0) serves anything
    /// - otherwise, the top `bit_length` bits must match.
    pub fn serves(&self, other: &RoutingPrefix) -> bool {
        if self.bit_length == 0 {
            return true;
        }
        if self.bit_length > other.bit_length {
            return false;
        }
        let mask = (!0u64) << (64 - self.bit_length);
        (self.bits & mask) == (other.bits & mask)
    }

    /// Count common leading bits
    pub fn common_prefix_len(&self, other: &Self) -> u8 {
        if self.bit_length == 0 || other.bit_length == 0 {
            return 0;
        }
        let xor = self.bits ^ other.bits;
        let lz = xor.leading_zeros() as u8;
        lz.min(self.bit_length.min(other.bit_length))
    }

    /// Tree-based distance: (#up + #down)
    pub fn distance(&self, other: &Self) -> Option<u64> {
        let cpl = self.common_prefix_len(other);
        Some((self.bit_length - cpl + other.bit_length - cpl) as u64)
    }
}

impl PrefixDistance for RoutingPrefix {
    fn distance(&self, other: &Self) -> Option<u64> {
        self.distance(other)
    }

    fn common_prefix_len(&self, other: &Self) -> u8 {
        self.common_prefix_len(other)
    }
}

impl Default for RoutingPrefix {
    fn default() -> Self {
        Self::root()
    }
}