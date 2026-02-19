//! SM4-CTR-DRBG (Counter-mode DRBG using SM4 as the block cipher).
//!
//! Implements NIST SP 800-90A Section 10.2 using SM4 instead of AES.
//! SM4: 128-bit key, 128-bit block → seed_len = 32 bytes.

use crate::sm4::Sm4Key;
use hitls_types::CryptoError;
use zeroize::Zeroize;

/// SM4 key length in bytes.
const KEY_LEN: usize = 16;
/// SM4 block size in bytes.
const BLOCK_LEN: usize = 16;
/// Seed length = key length + block length (32 bytes for SM4).
const SEED_LEN: usize = KEY_LEN + BLOCK_LEN;
/// Maximum number of generate requests before reseed is required.
const RESEED_INTERVAL: u64 = 1 << 48;

/// CTR-DRBG context using SM4 (NIST SP 800-90A Section 10.2).
pub struct Sm4CtrDrbg {
    /// SM4 key (16 bytes).
    key: [u8; KEY_LEN],
    /// Counter block V (16 bytes).
    v: [u8; BLOCK_LEN],
    /// Number of generate requests since last (re)seed.
    reseed_counter: u64,
}

impl Drop for Sm4CtrDrbg {
    fn drop(&mut self) {
        self.key.zeroize();
        self.v.zeroize();
    }
}

/// Encrypt a single SM4 block in-place.
fn sm4_encrypt_block(key: &[u8; KEY_LEN], block: &mut [u8; BLOCK_LEN]) -> Result<(), CryptoError> {
    let cipher = Sm4Key::new(key)?;
    cipher.encrypt_block(block)
}

/// Increment a 128-bit counter (big-endian).
fn increment_counter(v: &mut [u8; BLOCK_LEN]) {
    for i in (0..BLOCK_LEN).rev() {
        v[i] = v[i].wrapping_add(1);
        if v[i] != 0 {
            break;
        }
    }
}

impl Sm4CtrDrbg {
    /// Instantiate SM4-CTR-DRBG without derivation function (SP 800-90A §10.2.1.3).
    ///
    /// `seed_material` must be exactly `SEED_LEN` (32) bytes.
    pub fn new(seed_material: &[u8]) -> Result<Self, CryptoError> {
        if seed_material.len() != SEED_LEN {
            return Err(CryptoError::InvalidArg);
        }

        let mut drbg = Sm4CtrDrbg {
            key: [0u8; KEY_LEN],
            v: [0u8; BLOCK_LEN],
            reseed_counter: 0,
        };

        drbg.update(seed_material)?;
        drbg.reseed_counter = 1;

        Ok(drbg)
    }

    /// CTR-DRBG Update function (SP 800-90A §10.2.1.2).
    fn update(&mut self, provided_data: &[u8]) -> Result<(), CryptoError> {
        let mut temp = [0u8; SEED_LEN];
        let mut offset = 0;

        while offset < SEED_LEN {
            increment_counter(&mut self.v);
            let mut block = self.v;
            sm4_encrypt_block(&self.key, &mut block)?;

            let copy_len = (SEED_LEN - offset).min(BLOCK_LEN);
            temp[offset..offset + copy_len].copy_from_slice(&block[..copy_len]);
            offset += copy_len;
        }

        // XOR with provided_data
        let data_len = provided_data.len().min(SEED_LEN);
        for i in 0..data_len {
            temp[i] ^= provided_data[i];
        }

        // Split into new Key and V
        self.key.copy_from_slice(&temp[..KEY_LEN]);
        self.v.copy_from_slice(&temp[KEY_LEN..SEED_LEN]);

        temp.zeroize();
        Ok(())
    }

    /// Generate pseudorandom bytes (SP 800-90A §10.2.1.5).
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
                let mut adin = [0u8; SEED_LEN];
                let copy_len = data.len().min(SEED_LEN);
                adin[..copy_len].copy_from_slice(&data[..copy_len]);
                self.update(&adin)?;
                adin.zeroize();
            }
        }

        // Generate output blocks
        let mut offset = 0;
        while offset < output.len() {
            increment_counter(&mut self.v);
            let mut block = self.v;
            sm4_encrypt_block(&self.key, &mut block)?;

            let remaining = output.len() - offset;
            let copy_len = remaining.min(BLOCK_LEN);
            output[offset..offset + copy_len].copy_from_slice(&block[..copy_len]);
            offset += copy_len;
        }

        // Final update
        let final_data = if let Some(data) = additional_input {
            if !data.is_empty() {
                let mut adin = [0u8; SEED_LEN];
                let copy_len = data.len().min(SEED_LEN);
                adin[..copy_len].copy_from_slice(&data[..copy_len]);
                adin
            } else {
                [0u8; SEED_LEN]
            }
        } else {
            [0u8; SEED_LEN]
        };

        self.update(&final_data)?;
        self.reseed_counter += 1;

        Ok(())
    }

    /// Generate `len` pseudorandom bytes (convenience method).
    pub fn generate_bytes(&mut self, len: usize) -> Result<Vec<u8>, CryptoError> {
        let mut output = vec![0u8; len];
        self.generate(&mut output, None)?;
        Ok(output)
    }

    /// Reseed the DRBG with fresh entropy (SP 800-90A §10.2.1.6).
    pub fn reseed(
        &mut self,
        entropy: &[u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), CryptoError> {
        if entropy.len() != SEED_LEN {
            return Err(CryptoError::InvalidArg);
        }

        let mut seed_material = [0u8; SEED_LEN];
        seed_material.copy_from_slice(entropy);

        if let Some(data) = additional_input {
            let copy_len = data.len().min(SEED_LEN);
            for i in 0..copy_len {
                seed_material[i] ^= data[i];
            }
        }

        self.update(&seed_material)?;
        seed_material.zeroize();
        self.reseed_counter = 1;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm4_ctr_drbg_generate() {
        let seed = [0x42u8; SEED_LEN];
        let mut drbg = Sm4CtrDrbg::new(&seed).unwrap();

        let output1 = drbg.generate_bytes(32).unwrap();
        let output2 = drbg.generate_bytes(32).unwrap();

        assert_eq!(output1.len(), 32);
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_sm4_ctr_drbg_reseed() {
        let seed = [0x42u8; SEED_LEN];
        let mut drbg = Sm4CtrDrbg::new(&seed).unwrap();

        let _ = drbg.generate_bytes(32).unwrap();
        assert_eq!(drbg.reseed_counter, 2);

        let new_entropy = [0x55u8; SEED_LEN];
        drbg.reseed(&new_entropy, None).unwrap();
        assert_eq!(drbg.reseed_counter, 1);
    }

    #[test]
    fn test_sm4_ctr_drbg_deterministic() {
        let seed = [0xAB; SEED_LEN];

        let mut drbg1 = Sm4CtrDrbg::new(&seed).unwrap();
        let out1 = drbg1.generate_bytes(64).unwrap();

        let mut drbg2 = Sm4CtrDrbg::new(&seed).unwrap();
        let out2 = drbg2.generate_bytes(64).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_sm4_ctr_drbg_vs_aes_different_output() {
        use crate::drbg::CtrDrbg;

        // Same seed, but AES-256 CTR-DRBG needs 48 bytes, SM4 needs 32
        let sm4_seed = [0x42u8; SEED_LEN];
        let aes_seed = [0x42u8; 48]; // AES-256 seed length

        let mut sm4_drbg = Sm4CtrDrbg::new(&sm4_seed).unwrap();
        let mut aes_drbg = CtrDrbg::new(&aes_seed).unwrap();

        let sm4_out = sm4_drbg.generate_bytes(32).unwrap();
        let aes_out = aes_drbg.generate_bytes(32).unwrap();

        // Different ciphers produce different output
        assert_ne!(sm4_out, aes_out);
    }
}
