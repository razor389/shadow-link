// src/types/argon2_params.rs

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerializableArgon2Params {
    pub m_cost: u32,                  // Memory cost
    pub t_cost: u32,                  // Time cost (iterations)
    pub p_cost: u32,                  // Parallelism (threads)
    pub output_length: Option<usize>, // Output length in bytes
}

impl SerializableArgon2Params {
    /// Convert to `argon2::Params`
    pub fn to_argon2_params(&self) -> argon2::Params {
        argon2::Params::new(
            self.m_cost,
            self.t_cost,
            self.p_cost,
            self.output_length,
        )
        .expect("Invalid Argon2 parameters")
    }

    /// Create from `argon2::Params`
    pub fn from_argon2_params(params: &argon2::Params) -> Self {
        SerializableArgon2Params {
            m_cost: params.m_cost(),
            t_cost: params.t_cost(),
            p_cost: params.p_cost(),
            output_length: params.output_len(),
        }
    }

    /// Check if `self` meets or exceeds the minimum parameters
    pub fn meets_min(&self, min: &SerializableArgon2Params) -> bool {
        self.m_cost >= min.m_cost
            && self.t_cost >= min.t_cost
            && self.p_cost >= min.p_cost
            && match (self.output_length, min.output_length) {
                (Some(a), Some(b)) => a >= b,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => true,
            }
    }

    /// Returns a new `SerializableArgon2Params` that is the maximum of `self` and `other`
    pub fn max_params(&self, other: &SerializableArgon2Params) -> SerializableArgon2Params {
        SerializableArgon2Params {
            m_cost: self.m_cost.max(other.m_cost),
            t_cost: self.t_cost.max(other.t_cost),
            p_cost: self.p_cost.max(other.p_cost),
            output_length: match (self.output_length, other.output_length) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            },
        }
    }
}

// Implement Default for SerializableArgon2Params
impl Default for SerializableArgon2Params {
    fn default() -> Self {
        // Use different defaults based on whether we're testing
        #[cfg(test)]
        {
            // Easier parameters for testing
            SerializableArgon2Params {
                m_cost: 8,           // Low memory cost for faster tests
                t_cost: 1,           // Minimal time cost
                p_cost: 1,           // Single thread
                output_length: Some(32), // Standard output length
            }
        }
        #[cfg(not(test))]
        {
            // Use Argon2 default parameters for production
            let default_params = argon2::Params::default();
            SerializableArgon2Params {
                m_cost: default_params.m_cost(),
                t_cost: default_params.t_cost(),
                p_cost: default_params.p_cost(),
                output_length: default_params.output_len(),
            }
        }
    }
}

