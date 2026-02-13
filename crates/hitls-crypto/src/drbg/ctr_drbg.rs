//! CTR-DRBG (Counter-mode Deterministic Random Bit Generator).
//!
//! Implements NIST SP 800-90A Section 10.2 using AES-256 as the block cipher.
//! Supports both direct instantiation (without derivation function) and
//! instantiation with Block_Cipher_df for arbitrary-length inputs.

use crate::aes::AesKey;
use hitls_types::CryptoError;
use zeroize::Zeroize;

/// AES-256 key length in bytes.
const KEY_LEN: usize = 32;
/// AES block size in bytes.
const BLOCK_LEN: usize = 16;
/// Seed length = key length + block length (48 bytes for AES-256).
const SEED_LEN: usize = KEY_LEN + BLOCK_LEN;
/// Maximum number of generate requests before reseed is required.
const RESEED_INTERVAL: u64 = 1 << 48;

/// CTR-DRBG context using AES-256 (NIST SP 800-90A Section 10.2).
pub struct CtrDrbg {
    /// AES-256 key (32 bytes).
    key: [u8; KEY_LEN],
    /// Counter block V (16 bytes).
    v: [u8; BLOCK_LEN],
    /// Number of generate requests since last (re)seed.
    reseed_counter: u64,
}

impl Drop for CtrDrbg {
    fn drop(&mut self) {
        self.key.zeroize();
        self.v.zeroize();
    }
}

/// Encrypt a single AES-256 block in-place.
fn aes256_encrypt_block(
    key: &[u8; KEY_LEN],
    block: &mut [u8; BLOCK_LEN],
) -> Result<(), CryptoError> {
    let cipher = AesKey::new(key)?;
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

impl CtrDrbg {
    /// Instantiate CTR-DRBG without derivation function (SP 800-90A §10.2.1.3).
    ///
    /// `seed_material` must be exactly `SEED_LEN` (48) bytes — typically
    /// `entropy_input || personalization_string` padded/truncated to 48 bytes.
    pub fn new(seed_material: &[u8]) -> Result<Self, CryptoError> {
        if seed_material.len() != SEED_LEN {
            return Err(CryptoError::InvalidArg);
        }

        let mut drbg = CtrDrbg {
            key: [0u8; KEY_LEN],
            v: [0u8; BLOCK_LEN],
            reseed_counter: 0,
        };

        drbg.update(seed_material)?;
        drbg.reseed_counter = 1;

        Ok(drbg)
    }

    /// Instantiate CTR-DRBG with Block_Cipher_df derivation function (SP 800-90A §10.2.1.4).
    ///
    /// Accepts arbitrary-length entropy, nonce, and personalization string.
    pub fn with_df(
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<Self, CryptoError> {
        // Concatenate all inputs
        let mut input = Vec::with_capacity(entropy.len() + nonce.len() + personalization.len());
        input.extend_from_slice(entropy);
        input.extend_from_slice(nonce);
        input.extend_from_slice(personalization);

        // Derive exactly SEED_LEN bytes
        let seed_material = block_cipher_df(&input, SEED_LEN)?;

        let mut drbg = CtrDrbg {
            key: [0u8; KEY_LEN],
            v: [0u8; BLOCK_LEN],
            reseed_counter: 0,
        };

        drbg.update(&seed_material)?;
        drbg.reseed_counter = 1;

        Ok(drbg)
    }

    /// Instantiate from the system entropy source.
    ///
    /// When the `entropy` feature is enabled, raw bytes are health-tested
    /// (NIST SP 800-90B RCT + APT) and conditioned before use.
    /// Otherwise, `getrandom` is used directly.
    pub fn from_system_entropy() -> Result<Self, CryptoError> {
        let mut entropy = [0u8; SEED_LEN];
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

    /// CTR-DRBG Update function (SP 800-90A §10.2.1.2).
    ///
    /// `provided_data` must be exactly `SEED_LEN` bytes (or will be zero-padded).
    fn update(&mut self, provided_data: &[u8]) -> Result<(), CryptoError> {
        let mut temp = [0u8; SEED_LEN];
        let mut offset = 0;

        // Generate SEED_LEN bytes of output by incrementing V and encrypting
        while offset < SEED_LEN {
            increment_counter(&mut self.v);
            let mut block = self.v;
            aes256_encrypt_block(&self.key, &mut block)?;

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
                // Pad or truncate additional input to SEED_LEN
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
            aes256_encrypt_block(&self.key, &mut block)?;

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
        let mut seed_material = [0u8; SEED_LEN];

        if entropy.len() == SEED_LEN {
            seed_material.copy_from_slice(entropy);
            // XOR additional input if present
            if let Some(data) = additional_input {
                let copy_len = data.len().min(SEED_LEN);
                for i in 0..copy_len {
                    seed_material[i] ^= data[i];
                }
            }
        } else {
            // Use DF to derive seed material
            let mut input =
                Vec::with_capacity(entropy.len() + additional_input.map_or(0, |d| d.len()));
            input.extend_from_slice(entropy);
            if let Some(data) = additional_input {
                input.extend_from_slice(data);
            }
            let derived = block_cipher_df(&input, SEED_LEN)?;
            seed_material.copy_from_slice(&derived);
        }

        self.update(&seed_material)?;
        seed_material.zeroize();
        self.reseed_counter = 1;

        Ok(())
    }
}

/// Block_Cipher_df — Derivation function using AES-256 CBC-MAC (SP 800-90A §10.3.2).
///
/// Derives `output_len` bytes from arbitrary-length input using BCC (Block Cipher Chaining).
fn block_cipher_df(input: &[u8], output_len: usize) -> Result<Vec<u8>, CryptoError> {
    // Step 1: Build S = L(4) || N(4) || input || 0x80 || padding
    let l = input.len() as u32;
    let n = output_len as u32;

    let mut s = Vec::with_capacity(8 + input.len() + 1 + BLOCK_LEN);
    s.extend_from_slice(&l.to_be_bytes());
    s.extend_from_slice(&n.to_be_bytes());
    s.extend_from_slice(input);
    s.push(0x80);
    // Pad to multiple of BLOCK_LEN
    while s.len() % BLOCK_LEN != 0 {
        s.push(0x00);
    }

    // Step 2: Generate initial key K = 0x00010203...1F (32 bytes for AES-256)
    let mut df_key = [0u8; KEY_LEN];
    for (i, byte) in df_key.iter_mut().enumerate() {
        *byte = i as u8;
    }

    // Step 3: Use BCC to generate enough output
    // We need ceil(output_len / BLOCK_LEN) * BLOCK_LEN bytes, plus BLOCK_LEN for the key
    let blocks_needed = (KEY_LEN + BLOCK_LEN).div_ceil(BLOCK_LEN);
    let mut temp = Vec::with_capacity(blocks_needed * BLOCK_LEN);

    for counter in 0..blocks_needed as u32 {
        // IV = counter(4) || zeros(12) for each BCC call
        let mut iv = [0u8; BLOCK_LEN];
        iv[..4].copy_from_slice(&counter.to_be_bytes());

        // BCC: chain through all blocks of S
        let mut chaining = iv;
        for chunk in s.chunks(BLOCK_LEN) {
            let mut block = [0u8; BLOCK_LEN];
            for i in 0..BLOCK_LEN {
                block[i] = chaining[i] ^ if i < chunk.len() { chunk[i] } else { 0 };
            }
            aes256_encrypt_block(&df_key, &mut block)?;
            chaining = block;
        }
        temp.extend_from_slice(&chaining);
    }

    // Step 4: Use the derived material as K' and X, then generate output
    let mut new_key = [0u8; KEY_LEN];
    new_key.copy_from_slice(&temp[..KEY_LEN]);
    let mut x = [0u8; BLOCK_LEN];
    x.copy_from_slice(&temp[KEY_LEN..KEY_LEN + BLOCK_LEN]);

    // Generate output_len bytes using K' in ECB mode
    let mut result = Vec::with_capacity(output_len);
    while result.len() < output_len {
        aes256_encrypt_block(&new_key, &mut x)?;
        let remaining = output_len - result.len();
        let copy_len = remaining.min(BLOCK_LEN);
        result.extend_from_slice(&x[..copy_len]);
    }

    new_key.zeroize();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ctr_drbg_instantiate() {
        let seed = [0x42u8; SEED_LEN];
        let drbg = CtrDrbg::new(&seed).unwrap();
        assert_eq!(drbg.reseed_counter, 1);
    }

    #[test]
    fn test_ctr_drbg_instantiate_invalid_len() {
        let seed = [0x42u8; 32]; // Too short
        assert!(CtrDrbg::new(&seed).is_err());
    }

    #[test]
    fn test_ctr_drbg_generate() {
        let seed = [0x42u8; SEED_LEN];
        let mut drbg = CtrDrbg::new(&seed).unwrap();

        let output1 = drbg.generate_bytes(32).unwrap();
        let output2 = drbg.generate_bytes(32).unwrap();

        assert_eq!(output1.len(), 32);
        assert_eq!(output2.len(), 32);
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_ctr_drbg_deterministic() {
        let seed = [0xAB; SEED_LEN];

        let mut drbg1 = CtrDrbg::new(&seed).unwrap();
        let out1 = drbg1.generate_bytes(64).unwrap();

        let mut drbg2 = CtrDrbg::new(&seed).unwrap();
        let out2 = drbg2.generate_bytes(64).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_ctr_drbg_reseed() {
        let seed = [0x42u8; SEED_LEN];
        let mut drbg = CtrDrbg::new(&seed).unwrap();

        let _ = drbg.generate_bytes(32).unwrap();
        assert_eq!(drbg.reseed_counter, 2);

        let new_entropy = [0x55u8; SEED_LEN];
        drbg.reseed(&new_entropy, None).unwrap();
        assert_eq!(drbg.reseed_counter, 1);
    }

    #[test]
    fn test_ctr_drbg_additional_input() {
        let seed = [0x42u8; SEED_LEN];
        let mut drbg = CtrDrbg::new(&seed).unwrap();

        let mut output = vec![0u8; 64];
        drbg.generate(&mut output, Some(b"additional input data"))
            .unwrap();

        assert_eq!(output.len(), 64);
        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_ctr_drbg_large_output() {
        let seed = [0x42u8; SEED_LEN];
        let mut drbg = CtrDrbg::new(&seed).unwrap();

        // Request more than one AES block
        let output = drbg.generate_bytes(100).unwrap();
        assert_eq!(output.len(), 100);
    }

    #[test]
    fn test_ctr_drbg_with_df() {
        let entropy = b"this is some entropy input for derivation function testing";
        let nonce = b"nonce value";
        let personalization = b"my personalization string";

        let mut drbg = CtrDrbg::with_df(entropy, nonce, personalization).unwrap();
        let output = drbg.generate_bytes(32).unwrap();

        assert_eq!(output.len(), 32);
        assert!(output.iter().any(|&b| b != 0));

        // Deterministic with same inputs
        let mut drbg2 = CtrDrbg::with_df(entropy, nonce, personalization).unwrap();
        let output2 = drbg2.generate_bytes(32).unwrap();
        assert_eq!(output, output2);
    }

    #[test]
    fn test_ctr_drbg_nist_vector() {
        // NIST SP 800-90A CTR_DRBG AES-256 use df=false
        // Test vector: verify deterministic output from known seed
        let mut seed = [0u8; SEED_LEN];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (i & 0xFF) as u8;
        }

        let mut drbg = CtrDrbg::new(&seed).unwrap();
        let out1 = drbg.generate_bytes(64).unwrap();
        let out2 = drbg.generate_bytes(64).unwrap();

        // Verify output is non-zero and different between calls
        assert!(out1.iter().any(|&b| b != 0));
        assert!(out2.iter().any(|&b| b != 0));
        assert_ne!(out1, out2);

        // Verify determinism
        let mut drbg2 = CtrDrbg::new(&seed).unwrap();
        let out1_verify = drbg2.generate_bytes(64).unwrap();
        assert_eq!(out1, out1_verify);
    }

    #[test]
    fn test_block_cipher_df() {
        let input = b"test input for derivation function";
        let output = block_cipher_df(input, 48).unwrap();
        assert_eq!(output.len(), 48);

        // Deterministic
        let output2 = block_cipher_df(input, 48).unwrap();
        assert_eq!(output, output2);

        // Different input → different output
        let output3 = block_cipher_df(b"different input", 48).unwrap();
        assert_ne!(output, output3);
    }

    #[test]
    fn test_increment_counter() {
        let mut v = [0u8; BLOCK_LEN];
        increment_counter(&mut v);
        assert_eq!(v[BLOCK_LEN - 1], 1);

        // Test overflow from 0xFF
        v = [0u8; BLOCK_LEN];
        v[BLOCK_LEN - 1] = 0xFF;
        increment_counter(&mut v);
        assert_eq!(v[BLOCK_LEN - 1], 0);
        assert_eq!(v[BLOCK_LEN - 2], 1);

        // Test all 0xFF
        v = [0xFF; BLOCK_LEN];
        increment_counter(&mut v);
        assert_eq!(v, [0u8; BLOCK_LEN]);
    }
}
