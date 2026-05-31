//! HMAC-DRBG (Deterministic Random Bit Generator) implementation.
//!
//! Provides cryptographic random number generation based on NIST SP 800-90A
//! Section 10.1.2. Supported HMAC families: SHA-1, SHA-224, SHA-256,
//! SHA-384, SHA-512.

use crate::hmac::Hmac;
use crate::provider::Digest;
use crate::sha1::Sha1;
use crate::sha2::{Sha224, Sha256, Sha384, Sha512};
use hitls_types::CryptoError;
use zeroize::Zeroize;

use super::RESEED_INTERVAL;

/// HMAC family selection for HMAC-DRBG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacDrbgType {
    /// HMAC-SHA-1 (output=20).
    Sha1,
    /// HMAC-SHA-224 (output=28).
    Sha224,
    /// HMAC-SHA-256 (output=32). Default.
    Sha256,
    /// HMAC-SHA-384 (output=48).
    Sha384,
    /// HMAC-SHA-512 (output=64).
    Sha512,
}

impl HmacDrbgType {
    /// HMAC output size in bytes.
    fn output_size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// HMAC digest factory.
    fn new_hash(self) -> Box<dyn Digest> {
        match self {
            Self::Sha1 => Box::new(Sha1::new()),
            Self::Sha224 => Box::new(Sha224::new()),
            Self::Sha256 => Box::new(Sha256::new()),
            Self::Sha384 => Box::new(Sha384::new()),
            Self::Sha512 => Box::new(Sha512::new()),
        }
    }
}

/// HMAC-DRBG context (NIST SP 800-90A Section 10.1.2).
pub struct HmacDrbg {
    /// HMAC key K (output_size bytes).
    k: Vec<u8>,
    /// HMAC value V (output_size bytes).
    v: Vec<u8>,
    /// HMAC family.
    ty: HmacDrbgType,
    /// Number of generate requests since last (re)seed.
    reseed_counter: u64,
}

impl Drop for HmacDrbg {
    fn drop(&mut self) {
        self.k.zeroize();
        self.v.zeroize();
    }
}

/// Compute HMAC-`ty`(key, data) into `out` (sized to `ty.output_size()`).
fn hmac(ty: HmacDrbgType, key: &[u8], data: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    let factory: fn() -> Box<dyn Digest> = match ty {
        HmacDrbgType::Sha1 => || Box::new(Sha1::new()) as Box<dyn Digest>,
        HmacDrbgType::Sha224 => || Box::new(Sha224::new()) as Box<dyn Digest>,
        HmacDrbgType::Sha256 => || Box::new(Sha256::new()) as Box<dyn Digest>,
        HmacDrbgType::Sha384 => || Box::new(Sha384::new()) as Box<dyn Digest>,
        HmacDrbgType::Sha512 => || Box::new(Sha512::new()) as Box<dyn Digest>,
    };
    let mut ctx = Hmac::new(factory, key)?;
    ctx.update(data)?;
    ctx.finish(out)?;
    Ok(())
}

impl HmacDrbg {
    /// Instantiate HMAC-DRBG-SHA-256 (the historical default) from seed
    /// material (entropy + nonce + personalization).
    pub fn new(seed_material: &[u8]) -> Result<Self, CryptoError> {
        Self::with(HmacDrbgType::Sha256, seed_material)
    }

    /// Instantiate HMAC-DRBG of the given type from seed material.
    pub fn with(ty: HmacDrbgType, seed_material: &[u8]) -> Result<Self, CryptoError> {
        let out_size = ty.output_size();
        // K = 0x00...00, V = 0x01...01 (NIST SP 800-90A §10.1.2.3 step 2).
        let mut drbg = HmacDrbg {
            k: vec![0x00u8; out_size],
            v: vec![0x01u8; out_size],
            ty,
            reseed_counter: 0,
        };
        drbg.update(Some(seed_material))?;
        drbg.reseed_counter = 1;
        Ok(drbg)
    }

    /// Instantiate HMAC-DRBG-SHA-256 from the system entropy source.
    pub fn from_system_entropy(seed_len: usize) -> Result<Self, CryptoError> {
        Self::from_system_entropy_with(HmacDrbgType::Sha256, seed_len)
    }

    /// Instantiate HMAC-DRBG of the given type from the system entropy
    /// source.
    pub fn from_system_entropy_with(
        ty: HmacDrbgType,
        seed_len: usize,
    ) -> Result<Self, CryptoError> {
        let mut entropy = vec![0u8; seed_len];
        super::get_system_entropy(&mut entropy)?;
        let result = Self::with(ty, &entropy);
        entropy.zeroize();
        result
    }

    /// HMAC-DRBG Update function (SP 800-90A Section 10.1.2.2).
    fn update(&mut self, provided_data: Option<&[u8]>) -> Result<(), CryptoError> {
        let out_size = self.ty.output_size();
        let mut k_new = vec![0u8; out_size];
        let mut v_new = vec![0u8; out_size];

        // K = HMAC(K, V || 0x00 || provided_data)
        let mut msg = Vec::with_capacity(out_size + 1 + provided_data.map_or(0, |d| d.len()));
        msg.extend_from_slice(&self.v);
        msg.push(0x00);
        if let Some(data) = provided_data {
            msg.extend_from_slice(data);
        }
        hmac(self.ty, &self.k, &msg, &mut k_new)?;
        self.k.copy_from_slice(&k_new);

        // V = HMAC(K, V)
        hmac(self.ty, &self.k, &self.v, &mut v_new)?;
        self.v.copy_from_slice(&v_new);

        // If provided_data is non-empty, do second round.
        if let Some(data) = provided_data {
            if !data.is_empty() {
                // K = HMAC(K, V || 0x01 || provided_data)
                msg.clear();
                msg.extend_from_slice(&self.v);
                msg.push(0x01);
                msg.extend_from_slice(data);
                hmac(self.ty, &self.k, &msg, &mut k_new)?;
                self.k.copy_from_slice(&k_new);

                // V = HMAC(K, V)
                hmac(self.ty, &self.k, &self.v, &mut v_new)?;
                self.v.copy_from_slice(&v_new);
            }
        }

        k_new.zeroize();
        v_new.zeroize();
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

        if let Some(data) = additional_input {
            if !data.is_empty() {
                self.update(Some(data))?;
            }
        }

        let out_size = self.ty.output_size();
        let mut v_new = vec![0u8; out_size];
        let mut offset = 0;
        while offset < output.len() {
            hmac(self.ty, &self.k, &self.v, &mut v_new)?;
            self.v.copy_from_slice(&v_new);

            let remaining = output.len() - offset;
            let copy_len = remaining.min(out_size);
            output[offset..offset + copy_len].copy_from_slice(&self.v[..copy_len]);
            offset += copy_len;
        }
        v_new.zeroize();

        self.update(additional_input)?;
        self.reseed_counter += 1;

        Ok(())
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

impl super::Drbg for HmacDrbg {
    fn generate(
        &mut self,
        output: &mut [u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), CryptoError> {
        HmacDrbg::generate(self, output, additional_input)
    }

    fn reseed(
        &mut self,
        entropy: &[u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), CryptoError> {
        HmacDrbg::reseed(self, entropy, additional_input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drbg::Drbg;

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

        let output = drbg.generate_bytes(100).unwrap();
        assert_eq!(output.len(), 100);
    }

    #[test]
    fn test_hmac_drbg_reseed_diverges() {
        let seed = b"identical seed for both DRBGs in reseed divergence test";
        let mut drbg1 = HmacDrbg::new(seed).unwrap();
        let mut drbg2 = HmacDrbg::new(seed).unwrap();

        let out1a = drbg1.generate_bytes(32).unwrap();
        let out2a = drbg2.generate_bytes(32).unwrap();
        assert_eq!(out1a, out2a);

        drbg1.reseed(b"new entropy for divergence", None).unwrap();

        let out1b = drbg1.generate_bytes(32).unwrap();
        let out2b = drbg2.generate_bytes(32).unwrap();
        assert_ne!(out1b, out2b);
    }

    #[test]
    fn test_hmac_drbg_additional_input_changes_output() {
        let seed = b"seed for additional input divergence test HMAC-DRBG";
        let mut drbg1 = HmacDrbg::new(seed).unwrap();
        let mut drbg2 = HmacDrbg::new(seed).unwrap();

        let mut out1 = vec![0u8; 32];
        drbg1.generate(&mut out1, Some(b"extra")).unwrap();

        let mut out2 = vec![0u8; 32];
        drbg2.generate(&mut out2, None).unwrap();

        assert_ne!(out1, out2);
    }

    #[test]
    fn test_hmac_drbg_sha1_variants_distinct() {
        let seed = b"variant distinctness seed material with enough entropy";
        let mut sha1 = HmacDrbg::with(HmacDrbgType::Sha1, seed).unwrap();
        let mut sha512 = HmacDrbg::with(HmacDrbgType::Sha512, seed).unwrap();
        let o1 = sha1.generate_bytes(20).unwrap();
        let o2 = sha512.generate_bytes(20).unwrap();
        assert_ne!(o1, o2);
    }
}
