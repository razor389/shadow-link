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
