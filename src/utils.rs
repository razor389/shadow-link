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

pub fn create_mask(bit_length: u8) -> u64 {
    if bit_length == 0 {
        0
    } else {
        (!0u64) << (64 - bit_length) >> (64 - bit_length)
    }
}
