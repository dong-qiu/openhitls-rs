//! Hash-based conditioning function for entropy (NIST SP 800-90B §3.1.5).
//!
//! Converts raw noise bytes (with potentially low min-entropy) into
//! full-entropy output using SHA-256 as a derivation function.
//! The input must contain enough entropy bits to guarantee the output
//! is computationally indistinguishable from uniform random.

use crate::sha2::Sha256;
use hitls_types::CryptoError;

/// SHA-256 output length in bytes.
const SHA256_OUTPUT_LEN: usize = 32;

/// Security margin in bits added to entropy requirement (FIPS 140-3).
const SECURITY_MARGIN_BITS: usize = 64;

/// Hash-based conditioning function using SHA-256.
///
/// Applies the derivation function:
///   output = SHA-256(0x01 || output_len_bytes || raw_entropy)
///
/// The input must have at least `needed_input_len()` bytes of raw noise
/// at the given min-entropy rate to produce full-entropy output.
pub struct HashConditioner {
    output_len: usize,
}

impl HashConditioner {
    /// Create a new SHA-256 hash conditioner.
    pub fn new() -> Self {
        HashConditioner {
            output_len: SHA256_OUTPUT_LEN,
        }
    }

    /// Condition raw entropy bytes into full-entropy 32-byte output.
    ///
    /// Implements: SHA-256(0x01 || be32(output_len) || raw_entropy)
    pub fn condition(&self, raw_entropy: &[u8]) -> Result<[u8; SHA256_OUTPUT_LEN], CryptoError> {
        let mut hasher = Sha256::new();
        // Counter byte (single-block DF)
        hasher.update(&[0x01])?;
        // Output length in bytes, big-endian 4 bytes
        let out_len_bytes = (self.output_len as u32).to_be_bytes();
        hasher.update(&out_len_bytes)?;
        // Raw entropy data
        hasher.update(raw_entropy)?;
        hasher.finish()
    }

    /// Output length of the conditioned entropy (32 bytes for SHA-256).
    pub fn output_len(&self) -> usize {
        self.output_len
    }

    /// Minimum input bytes needed to produce full-entropy output.
    ///
    /// For FIPS 140-3 compliance, the input must contain:
    ///   (output_bits + security_margin) / min_entropy_per_byte
    /// bits of entropy. When min_entropy_per_byte = 8 (full entropy source
    /// like getrandom), this equals 40 bytes. For lower-entropy sources,
    /// more raw bytes are needed.
    pub fn needed_input_len(&self, min_entropy_per_byte: u32) -> usize {
        if min_entropy_per_byte == 0 {
            return usize::MAX;
        }
        let needed_bits = self.output_len * 8 + SECURITY_MARGIN_BITS;
        // Ceiling division
        needed_bits.div_ceil(min_entropy_per_byte as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conditioner_output_length() {
        let cond = HashConditioner::new();
        assert_eq!(cond.output_len(), 32);

        let input = vec![0xAB; 64];
        let output = cond.condition(&input).unwrap();
        assert_eq!(output.len(), 32);
        // Output should not be all zeros
        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_conditioner_deterministic() {
        let cond = HashConditioner::new();
        let input = b"deterministic input for conditioning test";
        let out1 = cond.condition(input).unwrap();
        let out2 = cond.condition(input).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_conditioner_needed_input_len() {
        let cond = HashConditioner::new();

        // Full entropy source (8 bits/byte): need (256+64)/8 = 40 bytes
        assert_eq!(cond.needed_input_len(8), 40);

        // 1 bit/byte source: need (256+64)/1 = 320 bytes
        assert_eq!(cond.needed_input_len(1), 320);

        // 5 bits/byte source: need ceil(320/5) = 64 bytes
        assert_eq!(cond.needed_input_len(5), 64);

        // 0 bits/byte (degenerate): returns usize::MAX
        assert_eq!(cond.needed_input_len(0), usize::MAX);
    }
}
