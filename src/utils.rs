// src/utils.rs

use curve25519_dalek::Scalar;
use rand::rngs::OsRng;
use rand_core::RngCore;

/// Helper function to generate a random scalar
pub fn random_scalar(rng: &mut OsRng) -> Scalar {
    let mut random_bytes = [0u8; 64];
    rng.fill_bytes(&mut random_bytes);
    Scalar::from_bytes_mod_order_wide(&random_bytes)
}

/// Creates a mask for the first `bit_length` bits in higher bits.
/// For example, bit_length=3 => 0b111000...0000 (bits 63,62,61 set)
pub fn create_mask(bit_length: u8) -> u64 {
    match bit_length {
        0 => 0,
        64 => !0u64, // All bits set
        _ => (!0u64) << (64 - bit_length),
    }
}
