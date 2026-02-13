//! HMAC-DRBG (Deterministic Random Bit Generator) implementation.
//!
//! Provides cryptographic random number generation based on NIST SP 800-90A
//! using HMAC-SHA-256 as the underlying primitive.

use crate::hmac::Hmac;
use crate::provider::Digest;
use crate::sha2::Sha256;
use hitls_types::CryptoError;
use zeroize::Zeroize;

/// Maximum number of generate requests before reseed is required.
const RESEED_INTERVAL: u64 = 1 << 48;

/// HMAC output size for SHA-256.
const HMAC_SIZE: usize = 32;

/// HMAC-DRBG context using SHA-256 (NIST SP 800-90A Section 10.1.2).
pub struct HmacDrbg {
    /// HMAC key K (32 bytes).
    k: [u8; HMAC_SIZE],
    /// HMAC value V (32 bytes).
    v: [u8; HMAC_SIZE],
    /// Number of generate requests since last (re)seed.
    reseed_counter: u64,
}

impl Drop for HmacDrbg {
    fn drop(&mut self) {
        self.k.zeroize();
        self.v.zeroize();
    }
}

fn sha256_factory() -> Box<dyn Digest> {
    Box::new(Sha256::new())
}

/// Compute HMAC-SHA-256(key, data) and return 32-byte result.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; HMAC_SIZE], CryptoError> {
    let mut out = [0u8; HMAC_SIZE];
    let mut ctx = Hmac::new(sha256_factory, key)?;
    ctx.update(data)?;
    ctx.finish(&mut out)?;
    Ok(out)
}

impl HmacDrbg {
    /// Instantiate a new HMAC-DRBG from seed material (entropy + nonce + personalization).
    ///
    /// The `seed_material` should contain at least 256 bits of entropy.
    pub fn new(seed_material: &[u8]) -> Result<Self, CryptoError> {
        // K = 0x00...00
        let k = [0x00u8; HMAC_SIZE];
        // V = 0x01...01
        let v = [0x01u8; HMAC_SIZE];

        let mut drbg = HmacDrbg {
            k,
            v,
            reseed_counter: 0,
        };

        drbg.update(Some(seed_material))?;
        drbg.reseed_counter = 1;

        Ok(drbg)
    }

    /// Instantiate from the system entropy source.
    ///
    /// When the `entropy` feature is enabled, raw bytes are health-tested
    /// (NIST SP 800-90B RCT + APT) and conditioned before use.
    /// Otherwise, `getrandom` is used directly.
    pub fn from_system_entropy(seed_len: usize) -> Result<Self, CryptoError> {
        let mut entropy = vec![0u8; seed_len];
        #[cfg(feature = "entropy")]
        {
            let mut es =
                crate::entropy::EntropySource::new(crate::entropy::EntropyConfig::default());
            es.get_entropy(&mut entropy)?;
        }
        #[cfg(not(feature = "entropy"))]
        {
            getrandom::getrandom(&mut entropy).map_err(|_| CryptoError::BnRandGenFail)?;
        }
        let result = Self::new(&entropy);
        entropy.zeroize();
        result
    }

    /// HMAC-DRBG Update function (SP 800-90A Section 10.1.2.2).
    fn update(&mut self, provided_data: Option<&[u8]>) -> Result<(), CryptoError> {
        // K = HMAC(K, V || 0x00 || provided_data)
        let mut msg = Vec::with_capacity(HMAC_SIZE + 1 + provided_data.map_or(0, |d| d.len()));
        msg.extend_from_slice(&self.v);
        msg.push(0x00);
        if let Some(data) = provided_data {
            msg.extend_from_slice(data);
        }
        self.k = hmac_sha256(&self.k, &msg)?;

        // V = HMAC(K, V)
        self.v = hmac_sha256(&self.k, &self.v)?;

        // If provided_data is non-empty, do second round
        if let Some(data) = provided_data {
            if !data.is_empty() {
                // K = HMAC(K, V || 0x01 || provided_data)
                msg.clear();
                msg.extend_from_slice(&self.v);
                msg.push(0x01);
                msg.extend_from_slice(data);
                self.k = hmac_sha256(&self.k, &msg)?;

                // V = HMAC(K, V)
                self.v = hmac_sha256(&self.k, &self.v)?;
            }
        }

        Ok(())
    }

    /// Generate pseudorandom bytes (SP 800-90A Section 10.1.2.5).
    pub fn generate(
        &mut self,
        output: &mut [u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), CryptoError> {
        if self.reseed_counter > RESEED_INTERVAL {
            return Err(CryptoError::DrbgInvalidState);
        }

        // Process additional input
        if let Some(data) = additional_input {
            if !data.is_empty() {
                self.update(Some(data))?;
            }
        }

        // Generate output blocks
        let mut offset = 0;
        while offset < output.len() {
            self.v = hmac_sha256(&self.k, &self.v)?;

            let remaining = output.len() - offset;
            let copy_len = remaining.min(HMAC_SIZE);
            output[offset..offset + copy_len].copy_from_slice(&self.v[..copy_len]);
            offset += copy_len;
        }

        // Final update
        self.update(additional_input)?;
        self.reseed_counter += 1;

        Ok(())
    }

    /// Generate `len` pseudorandom bytes (convenience method).
    pub fn generate_bytes(&mut self, len: usize) -> Result<Vec<u8>, CryptoError> {
        let mut output = vec![0u8; len];
        self.generate(&mut output, None)?;
        Ok(output)
    }

    /// Reseed the DRBG with fresh entropy (SP 800-90A Section 10.1.2.4).
    pub fn reseed(
        &mut self,
        entropy: &[u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), CryptoError> {
        let mut seed_material = entropy.to_vec();
        if let Some(data) = additional_input {
            seed_material.extend_from_slice(data);
        }

        self.update(Some(&seed_material))?;
        seed_material.zeroize();
        self.reseed_counter = 1;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_drbg_instantiate() {
        let seed = b"test seed material with sufficient entropy for HMAC-DRBG";
        let drbg = HmacDrbg::new(seed).unwrap();
        assert_eq!(drbg.reseed_counter, 1);
    }

    #[test]
    fn test_hmac_drbg_generate() {
        let seed = b"test seed material with sufficient entropy for HMAC-DRBG";
        let mut drbg = HmacDrbg::new(seed).unwrap();

        let output1 = drbg.generate_bytes(32).unwrap();
        let output2 = drbg.generate_bytes(32).unwrap();

        assert_eq!(output1.len(), 32);
        assert_eq!(output2.len(), 32);
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_hmac_drbg_reseed() {
        let seed = b"initial seed for HMAC-DRBG";
        let mut drbg = HmacDrbg::new(seed).unwrap();

        let _ = drbg.generate_bytes(32).unwrap();
        assert_eq!(drbg.reseed_counter, 2);

        drbg.reseed(b"new entropy for reseed", None).unwrap();
        assert_eq!(drbg.reseed_counter, 1);
    }

    #[test]
    fn test_hmac_drbg_additional_input() {
        let seed = b"seed for additional input test";
        let mut drbg = HmacDrbg::new(seed).unwrap();

        let mut output = vec![0u8; 64];
        drbg.generate(&mut output, Some(b"additional input data"))
            .unwrap();

        assert_eq!(output.len(), 64);
        // Should not be all zeros
        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_hmac_drbg_deterministic() {
        let seed = b"deterministic test seed for HMAC-DRBG";

        let mut drbg1 = HmacDrbg::new(seed).unwrap();
        let out1 = drbg1.generate_bytes(64).unwrap();

        let mut drbg2 = HmacDrbg::new(seed).unwrap();
        let out2 = drbg2.generate_bytes(64).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_hmac_drbg_large_output() {
        let seed = b"seed for large output test";
        let mut drbg = HmacDrbg::new(seed).unwrap();

        // Request more than one HMAC block
        let output = drbg.generate_bytes(100).unwrap();
        assert_eq!(output.len(), 100);
    }
}
