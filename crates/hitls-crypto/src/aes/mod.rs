//! AES (Advanced Encryption Standard) block cipher implementation.
//!
//! Provides AES-128, AES-192, and AES-256 block cipher operations with
//! automatic hardware acceleration when available:
//! - **ARMv8**: Crypto Extension (`aese`/`aesd` + `aesmc`/`aesimc`)
//! - **x86-64**: AES-NI (`aesenc`/`aesdec`)
//! - **Fallback**: Pure-Rust S-box table lookup
//!
//! For modes of operation (CBC, GCM, CTR, etc.) see the [`modes`](crate::modes) module.

mod soft;

#[cfg(target_arch = "aarch64")]
mod aes_neon;

#[cfg(target_arch = "x86_64")]
mod aes_ni;

use hitls_types::CryptoError;

/// AES block size in bytes (128 bits).
pub const AES_BLOCK_SIZE: usize = 16;

/// Runtime dispatch enum for AES implementations.
enum AesImpl {
    Soft(soft::SoftAesKey),
    #[cfg(target_arch = "aarch64")]
    Neon(aes_neon::NeonAesKey),
    #[cfg(target_arch = "x86_64")]
    Ni(aes_ni::NiAesKey),
}

impl Clone for AesImpl {
    fn clone(&self) -> Self {
        match self {
            Self::Soft(k) => Self::Soft(k.clone()),
            #[cfg(target_arch = "aarch64")]
            Self::Neon(k) => Self::Neon(k.clone()),
            #[cfg(target_arch = "x86_64")]
            Self::Ni(k) => Self::Ni(k.clone()),
        }
    }
}

/// Detect the best available AES implementation at runtime.
fn detect_impl(key: &[u8]) -> Result<AesImpl, CryptoError> {
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("aes") {
            return Ok(AesImpl::Neon(aes_neon::NeonAesKey::new(key)?));
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("aes") {
            return Ok(AesImpl::Ni(aes_ni::NiAesKey::new(key)?));
        }
    }
    Ok(AesImpl::Soft(soft::SoftAesKey::new(key)?))
}

/// An AES key with precomputed round keys and automatic hardware acceleration.
///
/// On construction, the best available implementation is selected:
/// ARMv8 Crypto Extension > x86-64 AES-NI > software S-box fallback.
#[derive(Clone)]
pub struct AesKey {
    inner: AesImpl,
}

impl AesKey {
    /// Create a new AES key from raw bytes (16, 24, or 32 bytes).
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            inner: detect_impl(key)?,
        })
    }

    /// Create a new AES key using the software-only implementation.
    /// Useful for testing and cross-validation.
    #[cfg(test)]
    pub fn new_soft(key: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            inner: AesImpl::Soft(soft::SoftAesKey::new(key)?),
        })
    }

    /// Encrypt a single 16-byte block in place.
    #[inline]
    pub fn encrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError> {
        match &self.inner {
            AesImpl::Soft(k) => k.encrypt_block(block),
            #[cfg(target_arch = "aarch64")]
            AesImpl::Neon(k) => k.encrypt_block(block),
            #[cfg(target_arch = "x86_64")]
            AesImpl::Ni(k) => k.encrypt_block(block),
        }
    }

    /// Decrypt a single 16-byte block in place.
    #[inline]
    pub fn decrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError> {
        match &self.inner {
            AesImpl::Soft(k) => k.decrypt_block(block),
            #[cfg(target_arch = "aarch64")]
            AesImpl::Neon(k) => k.decrypt_block(block),
            #[cfg(target_arch = "x86_64")]
            AesImpl::Ni(k) => k.decrypt_block(block),
        }
    }

    /// Encrypt 4 blocks in place, exploiting AES pipeline parallelism.
    ///
    /// On hardware AES (NEON/NI), all 4 blocks flow through each round
    /// simultaneously, hiding the 4-cycle latency. Software falls back
    /// to sequential single-block encryption.
    #[inline]
    pub fn encrypt_4_blocks(&self, blocks: &mut [[u8; 16]; 4]) -> Result<(), CryptoError> {
        match &self.inner {
            AesImpl::Soft(k) => k.encrypt_4_blocks(blocks),
            #[cfg(target_arch = "aarch64")]
            AesImpl::Neon(k) => k.encrypt_4_blocks(blocks),
            #[cfg(target_arch = "x86_64")]
            AesImpl::Ni(k) => k.encrypt_4_blocks(blocks),
        }
    }

    /// Return the key length in bytes.
    #[inline]
    pub fn key_len(&self) -> usize {
        match &self.inner {
            AesImpl::Soft(k) => k.key_len(),
            #[cfg(target_arch = "aarch64")]
            AesImpl::Neon(k) => k.key_len(),
            #[cfg(target_arch = "x86_64")]
            AesImpl::Ni(k) => k.key_len(),
        }
    }

    /// Returns true if the hardware-accelerated implementation is active.
    #[cfg(test)]
    fn is_hardware_accelerated(&self) -> bool {
        match &self.inner {
            AesImpl::Soft(_) => false,
            #[cfg(target_arch = "aarch64")]
            AesImpl::Neon(_) => true,
            #[cfg(target_arch = "x86_64")]
            AesImpl::Ni(_) => true,
        }
    }
}

impl crate::provider::BlockCipher for AesKey {
    fn block_size(&self) -> usize {
        AES_BLOCK_SIZE
    }
    fn key_size(&self) -> usize {
        self.key_len()
    }
    fn set_encrypt_key(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        *self = AesKey::new(key)?;
        Ok(())
    }
    fn set_decrypt_key(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        self.set_encrypt_key(key)
    }
    fn encrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError> {
        self.encrypt_block(block)
    }
    fn decrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError> {
        self.decrypt_block(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_utils::hex::{hex, to_hex};

    // FIPS 197 Appendix B: AES-128
    #[test]
    fn test_aes128_encrypt() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let pt = hex("3243f6a8885a308d313198a2e0370734");
        let expected = "3925841d02dc09fbdc118597196a0b32";
        let cipher = AesKey::new(&key).unwrap();
        let mut block = pt;
        cipher.encrypt_block(&mut block).unwrap();
        assert_eq!(to_hex(&block), expected);
    }

    #[test]
    fn test_aes128_decrypt() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let ct = hex("3925841d02dc09fbdc118597196a0b32");
        let expected = "3243f6a8885a308d313198a2e0370734";
        let cipher = AesKey::new(&key).unwrap();
        let mut block = ct;
        cipher.decrypt_block(&mut block).unwrap();
        assert_eq!(to_hex(&block), expected);
    }

    // FIPS 197 Appendix C.3: AES-256
    #[test]
    fn test_aes256_encrypt() {
        let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let pt = hex("00112233445566778899aabbccddeeff");
        let expected = "8ea2b7ca516745bfeafc49904b496089";
        let cipher = AesKey::new(&key).unwrap();
        let mut block = pt;
        cipher.encrypt_block(&mut block).unwrap();
        assert_eq!(to_hex(&block), expected);
    }

    #[test]
    fn test_aes256_roundtrip() {
        let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let pt = hex("00112233445566778899aabbccddeeff");
        let cipher = AesKey::new(&key).unwrap();
        let mut block = pt.clone();
        cipher.encrypt_block(&mut block).unwrap();
        cipher.decrypt_block(&mut block).unwrap();
        assert_eq!(block, pt.as_slice());
    }

    // AES-192 roundtrip
    #[test]
    fn test_aes192_roundtrip() {
        let key = hex("000102030405060708090a0b0c0d0e0f1011121314151617");
        let pt = hex("00112233445566778899aabbccddeeff");
        let cipher = AesKey::new(&key).unwrap();
        let mut block = pt.clone();
        cipher.encrypt_block(&mut block).unwrap();
        assert_ne!(block, pt.as_slice());
        cipher.decrypt_block(&mut block).unwrap();
        assert_eq!(block, pt.as_slice());
    }

    #[test]
    fn test_aes_invalid_key_len() {
        assert!(AesKey::new(&[0u8; 15]).is_err());
        assert!(AesKey::new(&[0u8; 17]).is_err());
    }

    // Explicitly test software fallback with FIPS vectors
    #[test]
    fn test_aes_software_forced() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let pt = hex("3243f6a8885a308d313198a2e0370734");
        let expected = "3925841d02dc09fbdc118597196a0b32";
        let cipher = AesKey::new_soft(&key).unwrap();
        let mut block = pt;
        cipher.encrypt_block(&mut block).unwrap();
        assert_eq!(to_hex(&block), expected);
        cipher.decrypt_block(&mut block).unwrap();
        assert_eq!(to_hex(&block), "3243f6a8885a308d313198a2e0370734");
    }

    // Cross-check hardware vs software for all key sizes
    #[test]
    fn test_aes_hardware_consistency() {
        let cipher_hw = AesKey::new(&[0x42u8; 16]).unwrap();
        if !cipher_hw.is_hardware_accelerated() {
            // No hardware AES available; skip
            return;
        }

        for key_len in [16, 24, 32] {
            let key: Vec<u8> = (0..key_len).map(|i| i as u8).collect();
            let hw = AesKey::new(&key).unwrap();
            let sw = AesKey::new_soft(&key).unwrap();

            // Test multiple blocks
            for seed in 0u8..16 {
                let pt: Vec<u8> = (0..16u8).map(|i| i.wrapping_add(seed)).collect();

                let mut hw_block = pt.clone();
                let mut sw_block = pt.clone();
                hw.encrypt_block(&mut hw_block).unwrap();
                sw.encrypt_block(&mut sw_block).unwrap();
                assert_eq!(
                    hw_block, sw_block,
                    "encrypt mismatch key_len={key_len} seed={seed}"
                );

                hw.decrypt_block(&mut hw_block).unwrap();
                sw.decrypt_block(&mut sw_block).unwrap();
                assert_eq!(
                    hw_block, sw_block,
                    "decrypt mismatch key_len={key_len} seed={seed}"
                );
                assert_eq!(hw_block, pt.as_slice());
            }
        }
    }

    // Roundtrip all key sizes with auto-dispatch
    #[test]
    fn test_aes_roundtrip_all_key_sizes() {
        for key_len in [16, 24, 32] {
            let key: Vec<u8> = (0..key_len).map(|i| (i * 7 + 3) as u8).collect();
            let cipher = AesKey::new(&key).unwrap();
            for seed in 0u8..8 {
                let pt: Vec<u8> = (0..16).map(|i| i ^ seed).collect();
                let mut block = pt.clone();
                cipher.encrypt_block(&mut block).unwrap();
                assert_ne!(block, pt.as_slice());
                cipher.decrypt_block(&mut block).unwrap();
                assert_eq!(block, pt.as_slice());
            }
        }
    }

    #[test]
    fn test_aes_invalid_block_length() {
        let cipher = AesKey::new(&[0x42u8; 16]).unwrap();
        // 0 bytes
        assert!(cipher.encrypt_block(&mut []).is_err());
        // 15 bytes (too short)
        assert!(cipher.encrypt_block(&mut [0u8; 15]).is_err());
        // 17 bytes (too long)
        assert!(cipher.encrypt_block(&mut [0u8; 17]).is_err());
        // 32 bytes (double block, not supported for single-block API)
        assert!(cipher.encrypt_block(&mut [0u8; 32]).is_err());
    }

    // ===================================================================
    // Phase T154 — HW↔SW cross-validation: AES stress tests
    // ===================================================================

    /// Stress test AES-128 SW vs HW with 256 random blocks.
    #[test]
    fn test_aes128_soft_vs_hw_stress() {
        let key = [0x2Bu8; 16];
        let hw = AesKey::new(&key).unwrap();
        let sw = AesKey::new_soft(&key).unwrap();

        for seed in 0u8..=255 {
            let mut block_hw: [u8; 16] = core::array::from_fn(|i| seed.wrapping_add(i as u8));
            let mut block_sw = block_hw;

            hw.encrypt_block(&mut block_hw).unwrap();
            sw.encrypt_block(&mut block_sw).unwrap();
            assert_eq!(block_hw, block_sw, "encrypt mismatch at seed={seed}");

            hw.decrypt_block(&mut block_hw).unwrap();
            sw.decrypt_block(&mut block_sw).unwrap();
            assert_eq!(block_hw, block_sw, "decrypt mismatch at seed={seed}");
        }
    }

    /// Stress test AES-256 SW vs HW with 256 random blocks.
    #[test]
    fn test_aes256_soft_vs_hw_stress() {
        let key: [u8; 32] = core::array::from_fn(|i| (i * 7 + 0x5A) as u8);
        let hw = AesKey::new(&key).unwrap();
        let sw = AesKey::new_soft(&key).unwrap();

        for seed in 0u8..=255 {
            let mut block_hw: [u8; 16] = core::array::from_fn(|i| seed ^ (i as u8));
            let mut block_sw = block_hw;

            hw.encrypt_block(&mut block_hw).unwrap();
            sw.encrypt_block(&mut block_sw).unwrap();
            assert_eq!(block_hw, block_sw, "encrypt mismatch at seed={seed}");

            hw.decrypt_block(&mut block_hw).unwrap();
            sw.decrypt_block(&mut block_sw).unwrap();
            assert_eq!(block_hw, block_sw, "decrypt mismatch at seed={seed}");
        }
    }

    mod proptests {
        use super::super::AesKey;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            #[test]
            fn prop_aes128_block_roundtrip(
                key in prop::array::uniform16(any::<u8>()),
                block in prop::array::uniform16(any::<u8>()),
            ) {
                let cipher = AesKey::new(&key).unwrap();
                let mut buf = block;
                cipher.encrypt_block(&mut buf).unwrap();
                cipher.decrypt_block(&mut buf).unwrap();
                prop_assert_eq!(buf, block);
            }

            #[test]
            fn prop_aes256_block_roundtrip(
                key in prop::array::uniform32(any::<u8>()),
                block in prop::array::uniform16(any::<u8>()),
            ) {
                let cipher = AesKey::new(&key).unwrap();
                let mut buf = block;
                cipher.encrypt_block(&mut buf).unwrap();
                cipher.decrypt_block(&mut buf).unwrap();
                prop_assert_eq!(buf, block);
            }
        }
    }
}
