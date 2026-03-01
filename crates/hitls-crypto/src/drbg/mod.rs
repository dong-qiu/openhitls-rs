//! Deterministic Random Bit Generators (NIST SP 800-90A).
//!
//! Provides four DRBG variants:
//! - HMAC-DRBG (Section 10.1.2) — using HMAC-SHA-256
//! - CTR-DRBG (Section 10.2) — using AES-256
//! - SM4-CTR-DRBG (Section 10.2) — using SM4
//! - Hash-DRBG (Section 10.1.1) — using SHA-256/384/512

use hitls_types::CryptoError;

/// Maximum number of generate requests before reseed is required (NIST SP 800-90A).
pub(crate) const RESEED_INTERVAL: u64 = 1 << 48;

/// Obtain entropy from the system source.
///
/// When the `entropy` feature is enabled, raw bytes are health-tested
/// (NIST SP 800-90B RCT + APT) and conditioned before use.
/// Otherwise, `getrandom` is used directly.
pub(crate) fn get_system_entropy(buf: &mut [u8]) -> Result<(), CryptoError> {
    #[cfg(feature = "entropy")]
    {
        let mut es = crate::entropy::EntropySource::new(crate::entropy::EntropyConfig::default());
        es.get_entropy(buf)?;
    }
    #[cfg(not(feature = "entropy"))]
    {
        getrandom::getrandom(buf).map_err(|_| CryptoError::BnRandGenFail)?;
    }
    Ok(())
}

/// Increment a 128-bit big-endian counter in-place.
pub(crate) fn increment_counter(v: &mut [u8; 16]) {
    for i in (0..16).rev() {
        v[i] = v[i].wrapping_add(1);
        if v[i] != 0 {
            break;
        }
    }
}

/// Common DRBG interface (NIST SP 800-90A).
pub trait Drbg {
    /// Generate pseudorandom bytes with optional additional input.
    fn generate(
        &mut self,
        output: &mut [u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), CryptoError>;

    /// Reseed the DRBG with fresh entropy.
    fn reseed(
        &mut self,
        entropy: &[u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), CryptoError>;

    /// Generate `len` pseudorandom bytes (convenience method).
    fn generate_bytes(&mut self, len: usize) -> Result<Vec<u8>, CryptoError> {
        let mut output = vec![0u8; len];
        self.generate(&mut output, None)?;
        Ok(output)
    }
}

mod hmac_drbg;
pub use hmac_drbg::HmacDrbg;

pub mod ctr_drbg;
pub use ctr_drbg::CtrDrbg;

#[cfg(feature = "sm4")]
pub mod sm4_ctr_drbg;
#[cfg(feature = "sm4")]
pub use sm4_ctr_drbg::Sm4CtrDrbg;

pub mod hash_drbg;
pub use hash_drbg::HashDrbg;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_increment_counter_no_carry() {
        let mut v = [0u8; 16];
        v[15] = 0x41;
        increment_counter(&mut v);
        assert_eq!(v[15], 0x42);
        assert_eq!(v[14], 0);
    }

    #[test]
    fn test_increment_counter_carry_propagation() {
        // All 0xFF — should wrap to all zeros
        let mut v = [0xFFu8; 16];
        increment_counter(&mut v);
        assert_eq!(v, [0u8; 16]);
    }

    #[test]
    fn test_increment_counter_partial_carry() {
        // 0x...00FF → 0x...0100 (single-byte carry)
        let mut v = [0u8; 16];
        v[15] = 0xFF;
        increment_counter(&mut v);
        assert_eq!(v[15], 0x00);
        assert_eq!(v[14], 0x01);
        assert_eq!(v[13], 0x00);
    }

    #[test]
    fn test_increment_counter_multi_byte_carry() {
        // 0x...00FFFF → 0x...010000 (two-byte carry)
        let mut v = [0u8; 16];
        v[14] = 0xFF;
        v[15] = 0xFF;
        increment_counter(&mut v);
        assert_eq!(v[15], 0x00);
        assert_eq!(v[14], 0x00);
        assert_eq!(v[13], 0x01);
        assert_eq!(v[12], 0x00);
    }

    #[test]
    fn test_hmac_drbg_generate() {
        let seed = [0x42u8; 48]; // entropy || nonce
        let mut drbg = HmacDrbg::new(&seed).unwrap();
        let mut out = [0u8; 32];
        drbg.generate(&mut out, None).unwrap();
        // Should not be all zeros
        assert!(out.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_generate_bytes_convenience() {
        let seed = [0x42u8; 48];
        let mut drbg = HmacDrbg::new(&seed).unwrap();

        // Various lengths via the Drbg trait default method
        let out1 = drbg.generate_bytes(1).unwrap();
        assert_eq!(out1.len(), 1);

        let out17 = drbg.generate_bytes(17).unwrap();
        assert_eq!(out17.len(), 17);

        let out256 = drbg.generate_bytes(256).unwrap();
        assert_eq!(out256.len(), 256);
        // Output should not be all zeros
        assert!(out256.iter().any(|&b| b != 0));

        // Zero length
        let out0 = drbg.generate_bytes(0).unwrap();
        assert!(out0.is_empty());
    }
}
