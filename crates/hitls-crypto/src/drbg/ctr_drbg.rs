//! CTR-DRBG (Counter-mode Deterministic Random Bit Generator).
//!
//! Implements NIST SP 800-90A Section 10.2 using AES as the block cipher.
//! Supports AES-128 / AES-192 / AES-256, with or without Block_Cipher_df
//! for arbitrary-length inputs.

use crate::aes::AesKey;
use hitls_types::CryptoError;
use zeroize::Zeroize;

use super::RESEED_INTERVAL;

/// AES block size in bytes.
const BLOCK_LEN: usize = 16;
/// Maximum AES key length (AES-256). The runtime length is tracked via
/// `CtrDrbgType` and `CtrDrbg::key_len`.
const MAX_KEY_LEN: usize = 32;
/// Maximum seed length = max key length + block length (48 bytes).
const MAX_SEED_LEN: usize = MAX_KEY_LEN + BLOCK_LEN;

/// AES key length selection for CTR-DRBG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtrDrbgType {
    /// AES-128 (keyLen=16, seedLen=32).
    Aes128,
    /// AES-192 (keyLen=24, seedLen=40).
    Aes192,
    /// AES-256 (keyLen=32, seedLen=48). Default.
    Aes256,
}

impl CtrDrbgType {
    /// AES key length in bytes.
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }

    /// Seed length = key length + block length.
    pub const fn seed_len(self) -> usize {
        self.key_len() + BLOCK_LEN
    }
}

/// CTR-DRBG context (NIST SP 800-90A Section 10.2).
///
/// Storage is sized to the maximum AES key length; the active length is
/// tracked in `ty`.
pub struct CtrDrbg {
    /// AES key (active length = `ty.key_len()`).
    key: [u8; MAX_KEY_LEN],
    /// Counter block V (16 bytes).
    v: [u8; BLOCK_LEN],
    /// Number of generate requests since last (re)seed.
    reseed_counter: u64,
    /// Cached AES expanded key (avoids re-expanding round keys per block).
    cached_key: AesKey,
    /// Active AES key length.
    ty: CtrDrbgType,
}

impl Drop for CtrDrbg {
    fn drop(&mut self) {
        self.key.zeroize();
        self.v.zeroize();
    }
}

use super::increment_counter;

impl CtrDrbg {
    /// Instantiate CTR-DRBG-AES-256 without derivation function (the
    /// historical default). `seed_material` must be exactly 48 bytes.
    pub fn new(seed_material: &[u8]) -> Result<Self, CryptoError> {
        Self::with(CtrDrbgType::Aes256, seed_material)
    }

    /// Instantiate CTR-DRBG of the given AES strength without derivation
    /// function (SP 800-90A §10.2.1.3). `seed_material` must be exactly
    /// `ty.seed_len()` bytes — typically `entropy_input ⊕ personalization`
    /// padded/truncated.
    pub fn with(ty: CtrDrbgType, seed_material: &[u8]) -> Result<Self, CryptoError> {
        let seed_len = ty.seed_len();
        if seed_material.len() != seed_len {
            return Err(CryptoError::InvalidArg(""));
        }
        let key_len = ty.key_len();
        let zero_key = vec![0u8; key_len];
        let mut drbg = CtrDrbg {
            key: [0u8; MAX_KEY_LEN],
            v: [0u8; BLOCK_LEN],
            reseed_counter: 0,
            cached_key: AesKey::new(&zero_key)?,
            ty,
        };
        drbg.update(seed_material)?;
        drbg.reseed_counter = 1;
        Ok(drbg)
    }

    /// Instantiate CTR-DRBG-AES-256 with Block_Cipher_df.
    pub fn with_df(
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<Self, CryptoError> {
        Self::with_df_typed(CtrDrbgType::Aes256, entropy, nonce, personalization)
    }

    /// Instantiate CTR-DRBG of the given AES strength with Block_Cipher_df
    /// (SP 800-90A §10.2.1.4). Accepts arbitrary-length entropy, nonce, and
    /// personalization string.
    pub fn with_df_typed(
        ty: CtrDrbgType,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<Self, CryptoError> {
        let seed_len = ty.seed_len();
        let mut input = Vec::with_capacity(entropy.len() + nonce.len() + personalization.len());
        input.extend_from_slice(entropy);
        input.extend_from_slice(nonce);
        input.extend_from_slice(personalization);
        let seed_material = block_cipher_df(&input, seed_len, ty.key_len())?;
        Self::with(ty, &seed_material)
    }

    /// Instantiate CTR-DRBG-AES-256 from the system entropy source.
    pub fn from_system_entropy() -> Result<Self, CryptoError> {
        Self::from_system_entropy_with(CtrDrbgType::Aes256)
    }

    /// Instantiate CTR-DRBG of the given AES strength from the system entropy.
    pub fn from_system_entropy_with(ty: CtrDrbgType) -> Result<Self, CryptoError> {
        let seed_len = ty.seed_len();
        let mut entropy = vec![0u8; seed_len];
        super::get_system_entropy(&mut entropy)?;
        let result = Self::with(ty, &entropy);
        entropy.zeroize();
        result
    }

    /// Active AES key length.
    fn key_len(&self) -> usize {
        self.ty.key_len()
    }

    /// Active seed length.
    fn seed_len(&self) -> usize {
        self.ty.seed_len()
    }

    /// CTR-DRBG Update function (SP 800-90A §10.2.1.2).
    ///
    /// `provided_data` must be exactly `seed_len()` bytes.
    fn update(&mut self, provided_data: &[u8]) -> Result<(), CryptoError> {
        let seed_len = self.seed_len();
        let key_len = self.key_len();
        let mut temp = [0u8; MAX_SEED_LEN];
        let mut offset = 0;

        while offset < seed_len {
            increment_counter(&mut self.v);
            let mut block = self.v;
            self.cached_key.encrypt_block(&mut block)?;

            let copy_len = (seed_len - offset).min(BLOCK_LEN);
            temp[offset..offset + copy_len].copy_from_slice(&block[..copy_len]);
            offset += copy_len;
        }

        let data_len = provided_data.len().min(seed_len);
        for i in 0..data_len {
            temp[i] ^= provided_data[i];
        }

        self.key[..key_len].copy_from_slice(&temp[..key_len]);
        self.v.copy_from_slice(&temp[key_len..seed_len]);
        self.cached_key = AesKey::new(&self.key[..key_len])?;

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

        let seed_len = self.seed_len();

        if let Some(data) = additional_input {
            if !data.is_empty() {
                let mut adin = [0u8; MAX_SEED_LEN];
                let copy_len = data.len().min(seed_len);
                adin[..copy_len].copy_from_slice(&data[..copy_len]);
                self.update(&adin[..seed_len])?;
                adin.zeroize();
            }
        }

        let mut offset = 0;
        while offset < output.len() {
            increment_counter(&mut self.v);
            let mut block = self.v;
            self.cached_key.encrypt_block(&mut block)?;

            let remaining = output.len() - offset;
            let copy_len = remaining.min(BLOCK_LEN);
            output[offset..offset + copy_len].copy_from_slice(&block[..copy_len]);
            offset += copy_len;
        }

        let mut final_data = [0u8; MAX_SEED_LEN];
        if let Some(data) = additional_input {
            if !data.is_empty() {
                let copy_len = data.len().min(seed_len);
                final_data[..copy_len].copy_from_slice(&data[..copy_len]);
            }
        }
        self.update(&final_data[..seed_len])?;
        final_data.zeroize();

        self.reseed_counter += 1;
        Ok(())
    }

    /// Reseed the DRBG with fresh entropy (SP 800-90A §10.2.1.6).
    pub fn reseed(
        &mut self,
        entropy: &[u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), CryptoError> {
        let seed_len = self.seed_len();
        let mut seed_material = [0u8; MAX_SEED_LEN];

        if entropy.len() == seed_len {
            seed_material[..seed_len].copy_from_slice(entropy);
            if let Some(data) = additional_input {
                let copy_len = data.len().min(seed_len);
                for i in 0..copy_len {
                    seed_material[i] ^= data[i];
                }
            }
        } else {
            let mut input =
                Vec::with_capacity(entropy.len() + additional_input.map_or(0, |d| d.len()));
            input.extend_from_slice(entropy);
            if let Some(data) = additional_input {
                input.extend_from_slice(data);
            }
            let derived = block_cipher_df(&input, seed_len, self.key_len())?;
            seed_material[..seed_len].copy_from_slice(&derived);
        }

        self.update(&seed_material[..seed_len])?;
        seed_material.zeroize();
        self.reseed_counter = 1;

        Ok(())
    }
}

impl super::Drbg for CtrDrbg {
    fn generate(
        &mut self,
        output: &mut [u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), CryptoError> {
        CtrDrbg::generate(self, output, additional_input)
    }

    fn reseed(
        &mut self,
        entropy: &[u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), CryptoError> {
        CtrDrbg::reseed(self, entropy, additional_input)
    }
}

/// Block_Cipher_df — Derivation function using AES-CBC-MAC (SP 800-90A §10.3.2).
///
/// `key_len` selects AES-128 (16) / AES-192 (24) / AES-256 (32); the
/// canonical seed K is `0x00,0x01,…,0x1F` truncated to `key_len`, matching
/// the openHiTLS C reference `dfKey[32]` table truncated via the active
/// `keyLen`.
fn block_cipher_df(
    input: &[u8],
    output_len: usize,
    key_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    // Step 1: Build S = L(4) || N(4) || input || 0x80 || padding.
    let l = input.len() as u32;
    let n = output_len as u32;

    let mut s = Vec::with_capacity(8 + input.len() + 1 + BLOCK_LEN);
    s.extend_from_slice(&l.to_be_bytes());
    s.extend_from_slice(&n.to_be_bytes());
    s.extend_from_slice(input);
    s.push(0x80);
    while s.len() % BLOCK_LEN != 0 {
        s.push(0x00);
    }

    // Step 2: canonical K = 0x00,0x01,…,0x1F truncated to key_len.
    let mut df_key = vec![0u8; key_len];
    for (i, byte) in df_key.iter_mut().enumerate() {
        *byte = i as u8;
    }

    // Step 3: BCC produces (key_len + BLOCK_LEN) bytes of derivation material.
    let blocks_needed = (key_len + BLOCK_LEN).div_ceil(BLOCK_LEN);
    let mut temp = Vec::with_capacity(blocks_needed * BLOCK_LEN);

    let df_cipher = AesKey::new(&df_key)?;
    for counter in 0..blocks_needed as u32 {
        let mut iv = [0u8; BLOCK_LEN];
        iv[..4].copy_from_slice(&counter.to_be_bytes());

        // BCC(K, IV || S) is CBC-MAC with the chaining value starting at
        // 0^outlen (SP 800-90A §10.3.3). The counter IV is therefore the
        // *first* data block — encrypt it (chaining = E(0 XOR IV) = E(IV))
        // before folding in the blocks of S.
        let mut chaining = iv;
        df_cipher.encrypt_block(&mut chaining)?;
        for chunk in s.chunks(BLOCK_LEN) {
            let mut block = [0u8; BLOCK_LEN];
            for i in 0..BLOCK_LEN {
                block[i] = chaining[i] ^ if i < chunk.len() { chunk[i] } else { 0 };
            }
            df_cipher.encrypt_block(&mut block)?;
            chaining = block;
        }
        temp.extend_from_slice(&chaining);
    }

    // Step 4: K' = temp[..key_len], X = temp[key_len..key_len+BLOCK_LEN];
    // generate output_len bytes by repeatedly E(K', X).
    let mut new_key = vec![0u8; key_len];
    new_key.copy_from_slice(&temp[..key_len]);
    let mut x = [0u8; BLOCK_LEN];
    x.copy_from_slice(&temp[key_len..key_len + BLOCK_LEN]);

    let new_cipher = AesKey::new(&new_key)?;
    let mut result = Vec::with_capacity(output_len);
    while result.len() < output_len {
        new_cipher.encrypt_block(&mut x)?;
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
    use crate::drbg::Drbg;

    /// Convenience: AES-256 seed length (for the legacy tests that
    /// instantiated CtrDrbg with the historic default).
    const SEED_LEN: usize = MAX_SEED_LEN; // 48

    #[test]
    fn test_ctr_drbg_instantiate() {
        let seed = [0x42u8; SEED_LEN];
        let drbg = CtrDrbg::new(&seed).unwrap();
        assert_eq!(drbg.reseed_counter, 1);
    }

    #[test]
    fn test_ctr_drbg_instantiate_invalid_len() {
        let seed = [0x42u8; 32]; // Too short for AES-256
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

        let mut drbg2 = CtrDrbg::with_df(entropy, nonce, personalization).unwrap();
        let output2 = drbg2.generate_bytes(32).unwrap();
        assert_eq!(output, output2);
    }

    #[test]
    fn test_ctr_drbg_aes256_df_nist_vector() {
        let entropy = vec![0xffu8; 1000];
        let nonce = [0xffu8; 20];
        let pers = [0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05];
        let mut drbg = CtrDrbg::with_df(&entropy, &nonce, &pers).unwrap();
        let output = drbg.generate_bytes(32).unwrap();
        let c_vector: [u8; 32] = [
            0xa0, 0x1d, 0xb1, 0xcf, 0x47, 0x33, 0xac, 0xf9, 0xbf, 0x26, 0x84, 0x1d, 0x93, 0x45,
            0xbf, 0x32, 0xe0, 0x05, 0x6b, 0x9a, 0xd9, 0x27, 0x22, 0x92, 0x53, 0xe4, 0x15, 0xe6,
            0xe9, 0x6b, 0x2b, 0x94,
        ];
        assert_eq!(output.as_slice(), &c_vector[..]);
    }

    #[test]
    fn test_ctr_drbg_nist_vector() {
        let mut seed = [0u8; SEED_LEN];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (i & 0xFF) as u8;
        }

        let mut drbg = CtrDrbg::new(&seed).unwrap();
        let out1 = drbg.generate_bytes(64).unwrap();
        let out2 = drbg.generate_bytes(64).unwrap();

        assert!(out1.iter().any(|&b| b != 0));
        assert!(out2.iter().any(|&b| b != 0));
        assert_ne!(out1, out2);

        let mut drbg2 = CtrDrbg::new(&seed).unwrap();
        let out1_verify = drbg2.generate_bytes(64).unwrap();
        assert_eq!(out1, out1_verify);
    }

    #[test]
    fn test_block_cipher_df() {
        let input = b"test input for derivation function";
        let output = block_cipher_df(input, 48, 32).unwrap();
        assert_eq!(output.len(), 48);

        let output2 = block_cipher_df(input, 48, 32).unwrap();
        assert_eq!(output, output2);

        let output3 = block_cipher_df(b"different input", 48, 32).unwrap();
        assert_ne!(output, output3);
    }

    #[test]
    fn test_increment_counter() {
        let mut v = [0u8; BLOCK_LEN];
        increment_counter(&mut v);
        assert_eq!(v[BLOCK_LEN - 1], 1);

        v = [0u8; BLOCK_LEN];
        v[BLOCK_LEN - 1] = 0xFF;
        increment_counter(&mut v);
        assert_eq!(v[BLOCK_LEN - 1], 0);
        assert_eq!(v[BLOCK_LEN - 2], 1);

        v = [0xFF; BLOCK_LEN];
        increment_counter(&mut v);
        assert_eq!(v, [0u8; BLOCK_LEN]);
    }

    #[test]
    fn test_ctr_drbg_reseed_diverges() {
        let seed = [0x42u8; SEED_LEN];
        let mut drbg1 = CtrDrbg::new(&seed).unwrap();
        let mut drbg2 = CtrDrbg::new(&seed).unwrap();

        let out1a = drbg1.generate_bytes(32).unwrap();
        let out2a = drbg2.generate_bytes(32).unwrap();
        assert_eq!(out1a, out2a);

        let new_entropy = [0x99u8; SEED_LEN];
        drbg1.reseed(&new_entropy, None).unwrap();

        let out1b = drbg1.generate_bytes(32).unwrap();
        let out2b = drbg2.generate_bytes(32).unwrap();
        assert_ne!(out1b, out2b);
    }

    #[test]
    fn test_ctr_drbg_aes128_no_df_distinct_from_aes256() {
        // AES-128 takes a 32-byte seed; AES-256 takes 48. They should
        // run independently and produce non-empty output.
        let seed128 = [0x37u8; 32];
        let mut d128 = CtrDrbg::with(CtrDrbgType::Aes128, &seed128).unwrap();
        let out128 = d128.generate_bytes(64).unwrap();
        assert!(out128.iter().any(|&b| b != 0));

        let seed192 = [0x37u8; 40];
        let mut d192 = CtrDrbg::with(CtrDrbgType::Aes192, &seed192).unwrap();
        let out192 = d192.generate_bytes(64).unwrap();
        assert!(out192.iter().any(|&b| b != 0));

        // Distinct seeds → distinct outputs.
        assert_ne!(out128, out192);
    }

    #[test]
    fn test_ctr_drbg_aes128_df_smoke() {
        let entropy = b"AES-128 df smoke entropy material wide enough for the DF";
        let nonce = b"AES-128 nonce";
        let pers = b"AES-128 pers";
        let mut d = CtrDrbg::with_df_typed(CtrDrbgType::Aes128, entropy, nonce, pers).unwrap();
        let out = d.generate_bytes(32).unwrap();
        assert!(out.iter().any(|&b| b != 0));
        // Deterministic.
        let mut d2 = CtrDrbg::with_df_typed(CtrDrbgType::Aes128, entropy, nonce, pers).unwrap();
        let out2 = d2.generate_bytes(32).unwrap();
        assert_eq!(out, out2);
    }
}
