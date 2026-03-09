//! Hardware-accelerated AES implementation using x86-64 AES-NI intrinsics.
//!
//! This module is only compiled on `x86_64` targets (gated via `#[cfg(target_arch = "x86_64")]`
//! at the module declaration in `mod.rs`). It provides a `NiAesKey` struct that uses AES-NI
//! instructions for fast single-block encrypt/decrypt.

use core::arch::x86_64::*;

use hitls_types::CryptoError;
use zeroize::Zeroize;

use super::AES_BLOCK_SIZE;

// ---------------------------------------------------------------------------
// S-box and round constants (duplicated from soft.rs for software key expansion
// of AES-192 and AES-256).
// ---------------------------------------------------------------------------

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RCON: [u32; 10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000,
];

/// Apply the AES S-box to each byte of a 32-bit word.
fn sub_word(w: u32) -> u32 {
    let b = w.to_be_bytes();
    u32::from_be_bytes([
        SBOX[b[0] as usize],
        SBOX[b[1] as usize],
        SBOX[b[2] as usize],
        SBOX[b[3] as usize],
    ])
}

// ---------------------------------------------------------------------------
// Software key expansion (reused for all key sizes: 128, 192, 256)
// ---------------------------------------------------------------------------

/// Expand an AES key into `4 * (nr + 1)` round-key words using the FIPS 197 algorithm.
/// Returns `(round_key_words, nr)`.
fn expand_key(key: &[u8]) -> Result<(Vec<u32>, usize), CryptoError> {
    let nk = match key.len() {
        16 => 4,
        24 => 6,
        32 => 8,
        _ => return Err(CryptoError::InvalidKey),
    };
    let nr = nk + 6;
    let total_words = 4 * (nr + 1);
    let mut w = vec![0u32; total_words];

    for i in 0..nk {
        w[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }

    for i in nk..total_words {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            temp = sub_word(temp.rotate_left(8)) ^ RCON[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            temp = sub_word(temp);
        }
        w[i] = w[i - nk] ^ temp;
    }

    Ok((w, nr))
}

/// Convert round-key words (big-endian u32 groups of 4) into `[u8; 16]` blocks.
fn words_to_blocks(words: &[u32], nr: usize) -> Vec<[u8; 16]> {
    let mut blocks = Vec::with_capacity(nr + 1);
    for round in 0..=nr {
        let mut blk = [0u8; 16];
        for col in 0..4 {
            let bytes = words[round * 4 + col].to_be_bytes();
            blk[col * 4] = bytes[0];
            blk[col * 4 + 1] = bytes[1];
            blk[col * 4 + 2] = bytes[2];
            blk[col * 4 + 3] = bytes[3];
        }
        blocks.push(blk);
    }
    blocks
}

// ---------------------------------------------------------------------------
// AES-NI low-level helpers
// ---------------------------------------------------------------------------

/// Load a 128-bit key from a `[u8; 16]` array into an `__m128i` register.
#[inline(always)]
unsafe fn load_key(key: &[u8; 16]) -> __m128i {
    // SAFETY: SIMD intrinsic with valid pointer.
    unsafe { _mm_loadu_si128(key.as_ptr() as *const __m128i) }
}

/// Store a 128-bit register back into a `[u8; 16]` array.
#[inline(always)]
unsafe fn store_block(reg: __m128i, out: &mut [u8; 16]) {
    // SAFETY: SIMD intrinsic with valid pointer.
    unsafe { _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, reg) }
}

// ---------------------------------------------------------------------------
// Prepare decryption keys using _mm_aesimc_si128
// ---------------------------------------------------------------------------

/// Derive the equivalent inverse cipher round keys from the encryption round keys.
///
/// ```text
/// dec_keys[0]           = enc_keys[rounds]
/// dec_keys[i]           = InvMixColumns(enc_keys[rounds - i])  for i in 1..rounds
/// dec_keys[rounds]      = enc_keys[0]
/// ```
#[target_feature(enable = "aes")]
unsafe fn prepare_dec_keys(enc_keys: &[[u8; 16]], rounds: usize) -> Vec<[u8; 16]> {
    // SAFETY: caller guarantees CPU feature availability (aes).
    unsafe {
        let mut dec = vec![[0u8; 16]; rounds + 1];
        dec[0] = enc_keys[rounds];
        for i in 1..rounds {
            let ek = load_key(&enc_keys[rounds - i]);
            let dk = _mm_aesimc_si128(ek);
            store_block(dk, &mut dec[i]);
        }
        dec[rounds] = enc_keys[0];
        dec
    }
}

// ---------------------------------------------------------------------------
// Single-block encrypt / decrypt with AES-NI
// ---------------------------------------------------------------------------

/// Encrypt a single 16-byte block in place using AES-NI instructions.
#[target_feature(enable = "aes")]
unsafe fn encrypt_block_ni(block: &mut [u8; 16], enc_keys: &[[u8; 16]], rounds: usize) {
    // SAFETY: caller guarantees CPU feature availability (aes).
    unsafe {
        let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);
        state = _mm_xor_si128(state, load_key(&enc_keys[0]));
        for rk in enc_keys.iter().take(rounds).skip(1) {
            state = _mm_aesenc_si128(state, load_key(rk));
        }
        state = _mm_aesenclast_si128(state, load_key(&enc_keys[rounds]));
        _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
    }
}

/// Decrypt a single 16-byte block in place using AES-NI instructions.
#[target_feature(enable = "aes")]
unsafe fn decrypt_block_ni(block: &mut [u8; 16], dec_keys: &[[u8; 16]], rounds: usize) {
    // SAFETY: caller guarantees CPU feature availability (aes).
    unsafe {
        let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);
        state = _mm_xor_si128(state, load_key(&dec_keys[0]));
        for rk in dec_keys.iter().take(rounds).skip(1) {
            state = _mm_aesdec_si128(state, load_key(rk));
        }
        state = _mm_aesdeclast_si128(state, load_key(&dec_keys[rounds]));
        _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
    }
}

/// Encrypt 4 blocks in parallel using AES-NI pipeline.
#[target_feature(enable = "aes")]
unsafe fn encrypt_4_blocks_ni(blocks: &mut [[u8; 16]; 4], enc_keys: &[[u8; 16]], rounds: usize) {
    // SAFETY: caller guarantees CPU feature availability (aes).
    unsafe {
        let mut s0 = _mm_loadu_si128(blocks[0].as_ptr() as *const __m128i);
        let mut s1 = _mm_loadu_si128(blocks[1].as_ptr() as *const __m128i);
        let mut s2 = _mm_loadu_si128(blocks[2].as_ptr() as *const __m128i);
        let mut s3 = _mm_loadu_si128(blocks[3].as_ptr() as *const __m128i);

        let rk0 = load_key(&enc_keys[0]);
        s0 = _mm_xor_si128(s0, rk0);
        s1 = _mm_xor_si128(s1, rk0);
        s2 = _mm_xor_si128(s2, rk0);
        s3 = _mm_xor_si128(s3, rk0);

        for rk in enc_keys.iter().take(rounds).skip(1) {
            let k = load_key(rk);
            s0 = _mm_aesenc_si128(s0, k);
            s1 = _mm_aesenc_si128(s1, k);
            s2 = _mm_aesenc_si128(s2, k);
            s3 = _mm_aesenc_si128(s3, k);
        }

        let kf = load_key(&enc_keys[rounds]);
        s0 = _mm_aesenclast_si128(s0, kf);
        s1 = _mm_aesenclast_si128(s1, kf);
        s2 = _mm_aesenclast_si128(s2, kf);
        s3 = _mm_aesenclast_si128(s3, kf);

        _mm_storeu_si128(blocks[0].as_mut_ptr() as *mut __m128i, s0);
        _mm_storeu_si128(blocks[1].as_mut_ptr() as *mut __m128i, s1);
        _mm_storeu_si128(blocks[2].as_mut_ptr() as *mut __m128i, s2);
        _mm_storeu_si128(blocks[3].as_mut_ptr() as *mut __m128i, s3);
    }
}

// ---------------------------------------------------------------------------
// VAES 256-bit: encrypt 4 blocks using 2×__m256i (2 blocks each)
// ---------------------------------------------------------------------------

/// Encrypt 4 blocks in parallel using VAES 256-bit instructions.
///
/// Packs blocks[0..1] into one __m256i and blocks[2..3] into another,
/// then processes all 4 blocks with just 2 VAES instructions per round
/// (vs 4 AES-NI instructions in the non-VAES path).
#[cfg(all(target_arch = "x86_64", has_vaes_intrinsics))]
#[allow(clippy::incompatible_msrv)]
#[target_feature(enable = "vaes,avx2")]
unsafe fn encrypt_4_blocks_vaes(blocks: &mut [[u8; 16]; 4], enc_keys: &[[u8; 16]], rounds: usize) {
    // SAFETY: caller guarantees CPU feature availability (vaes, avx2).
    unsafe {
        let mut s01 = _mm256_loadu_si256(blocks[0].as_ptr() as *const __m256i);
        let mut s23 = _mm256_loadu_si256(blocks[2].as_ptr() as *const __m256i);

        let rk0 = _mm256_broadcastsi128_si256(load_key(&enc_keys[0]));
        s01 = _mm256_xor_si256(s01, rk0);
        s23 = _mm256_xor_si256(s23, rk0);

        for rk in enc_keys.iter().take(rounds).skip(1) {
            let k = _mm256_broadcastsi128_si256(load_key(rk));
            s01 = _mm256_aesenc_epi128(s01, k);
            s23 = _mm256_aesenc_epi128(s23, k);
        }

        let kf = _mm256_broadcastsi128_si256(load_key(&enc_keys[rounds]));
        s01 = _mm256_aesenclast_epi128(s01, kf);
        s23 = _mm256_aesenclast_epi128(s23, kf);

        _mm256_storeu_si256(blocks[0].as_mut_ptr() as *mut __m256i, s01);
        _mm256_storeu_si256(blocks[2].as_mut_ptr() as *mut __m256i, s23);
    }
}

// ---------------------------------------------------------------------------
// NiAesKey — public(crate) struct
// ---------------------------------------------------------------------------

/// AES key using AES-NI hardware acceleration.
///
/// Holds precomputed encryption and decryption round keys as `[u8; 16]` blocks
/// so they can be directly loaded into `__m128i` registers.
#[derive(Clone)]
pub(crate) struct NiAesKey {
    enc_keys: Vec<[u8; 16]>,
    dec_keys: Vec<[u8; 16]>,
    rounds: usize,
    key_bytes: Vec<u8>,
}

impl Drop for NiAesKey {
    fn drop(&mut self) {
        for k in &mut self.enc_keys {
            k.zeroize();
        }
        for k in &mut self.dec_keys {
            k.zeroize();
        }
        self.key_bytes.zeroize();
    }
}

impl NiAesKey {
    /// Create a new AES-NI key from raw bytes (16, 24, or 32 bytes).
    ///
    /// Performs software key expansion (FIPS 197) and then prepares the
    /// inverse-cipher round keys via `_mm_aesimc_si128`.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let (words, nr) = expand_key(key)?;
        let enc_keys = words_to_blocks(&words, nr);

        // Safety: We only call this constructor when AES-NI is detected.
        let dec_keys = unsafe { prepare_dec_keys(&enc_keys, nr) };

        Ok(Self {
            enc_keys,
            dec_keys,
            rounds: nr,
            key_bytes: key.to_vec(),
        })
    }

    /// Encrypt a single 16-byte block in place.
    pub fn encrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError> {
        if block.len() != AES_BLOCK_SIZE {
            return Err(CryptoError::InvalidArg("invalid AES block size"));
        }

        let blk: &mut [u8; 16] = block.try_into().expect("block length validated above");
        // Safety: NiAesKey is only instantiated when AES-NI is available.
        unsafe {
            encrypt_block_ni(blk, &self.enc_keys, self.rounds);
        }
        Ok(())
    }

    /// Decrypt a single 16-byte block in place.
    pub fn decrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError> {
        if block.len() != AES_BLOCK_SIZE {
            return Err(CryptoError::InvalidArg("invalid AES block size"));
        }

        let blk: &mut [u8; 16] = block.try_into().expect("block length validated above");
        // Safety: NiAesKey is only instantiated when AES-NI is available.
        unsafe {
            decrypt_block_ni(blk, &self.dec_keys, self.rounds);
        }
        Ok(())
    }

    /// Encrypt 4 blocks in place using pipelined AES instructions.
    ///
    /// Uses VAES 256-bit when available (2 instructions per round for 4 blocks),
    /// falling back to AES-NI 128-bit pipeline (4 instructions per round).
    pub fn encrypt_4_blocks(&self, blocks: &mut [[u8; 16]; 4]) -> Result<(), CryptoError> {
        #[cfg(has_vaes_intrinsics)]
        {
            if is_x86_feature_detected!("vaes") {
                // SAFETY: NiAesKey is only instantiated when AES is detected,
                // and we just verified VAES + AVX2 support.
                unsafe { encrypt_4_blocks_vaes(blocks, &self.enc_keys, self.rounds) }
                return Ok(());
            }
        }
        unsafe { encrypt_4_blocks_ni(blocks, &self.enc_keys, self.rounds) }
        Ok(())
    }

    /// Return the key length in bytes.
    pub fn key_len(&self) -> usize {
        self.key_bytes.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_utils::hex::{hex, to_hex};

    // FIPS 197 Appendix B: AES-128
    #[test]
    fn test_aes128_ni_encrypt() {
        if !is_x86_feature_detected!("aes") {
            return;
        }
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let pt = hex("3243f6a8885a308d313198a2e0370734");
        let expected = "3925841d02dc09fbdc118597196a0b32";
        let cipher = NiAesKey::new(&key).unwrap();
        let mut block = pt;
        cipher.encrypt_block(&mut block).unwrap();
        assert_eq!(to_hex(&block), expected);
    }

    #[test]
    fn test_aes128_ni_decrypt() {
        if !is_x86_feature_detected!("aes") {
            return;
        }
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let ct = hex("3925841d02dc09fbdc118597196a0b32");
        let expected = "3243f6a8885a308d313198a2e0370734";
        let cipher = NiAesKey::new(&key).unwrap();
        let mut block = ct;
        cipher.decrypt_block(&mut block).unwrap();
        assert_eq!(to_hex(&block), expected);
    }

    // FIPS 197 Appendix C.3: AES-256
    #[test]
    fn test_aes256_ni_encrypt() {
        if !is_x86_feature_detected!("aes") {
            return;
        }
        let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let pt = hex("00112233445566778899aabbccddeeff");
        let expected = "8ea2b7ca516745bfeafc49904b496089";
        let cipher = NiAesKey::new(&key).unwrap();
        let mut block = pt;
        cipher.encrypt_block(&mut block).unwrap();
        assert_eq!(to_hex(&block), expected);
    }

    #[test]
    fn test_aes256_ni_roundtrip() {
        if !is_x86_feature_detected!("aes") {
            return;
        }
        let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let pt = hex("00112233445566778899aabbccddeeff");
        let cipher = NiAesKey::new(&key).unwrap();
        let mut block = pt.clone();
        cipher.encrypt_block(&mut block).unwrap();
        cipher.decrypt_block(&mut block).unwrap();
        assert_eq!(block, pt.as_slice());
    }

    // AES-192 roundtrip
    #[test]
    fn test_aes192_ni_roundtrip() {
        if !is_x86_feature_detected!("aes") {
            return;
        }
        let key = hex("000102030405060708090a0b0c0d0e0f1011121314151617");
        let pt = hex("00112233445566778899aabbccddeeff");
        let cipher = NiAesKey::new(&key).unwrap();
        let mut block = pt.clone();
        cipher.encrypt_block(&mut block).unwrap();
        assert_ne!(block, pt.as_slice());
        cipher.decrypt_block(&mut block).unwrap();
        assert_eq!(block, pt.as_slice());
    }

    #[test]
    fn test_aes_ni_invalid_key_len() {
        assert!(NiAesKey::new(&[0u8; 15]).is_err());
        assert!(NiAesKey::new(&[0u8; 17]).is_err());
    }

    #[test]
    fn test_aes_ni_invalid_block_len() {
        if !is_x86_feature_detected!("aes") {
            return;
        }
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let cipher = NiAesKey::new(&key).unwrap();
        let mut short = [0u8; 8];
        assert!(cipher.encrypt_block(&mut short).is_err());
        assert!(cipher.decrypt_block(&mut short).is_err());
    }

    // Cross-check: NI encrypt must match software encrypt.
    #[test]
    fn test_ni_matches_software_aes128() {
        if !is_x86_feature_detected!("aes") {
            return;
        }
        use super::super::soft::SoftAesKey;

        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let pt = hex("6bc1bee22e409f96e93d7e117393172a");

        let ni = NiAesKey::new(&key).unwrap();
        let sw = SoftAesKey::new(&key).unwrap();

        let mut ni_block = pt.clone();
        let mut sw_block = pt.clone();

        ni.encrypt_block(&mut ni_block).unwrap();
        sw.encrypt_block(&mut sw_block).unwrap();
        assert_eq!(ni_block, sw_block, "NI and software encrypt must match");

        ni.decrypt_block(&mut ni_block).unwrap();
        sw.decrypt_block(&mut sw_block).unwrap();
        assert_eq!(ni_block, sw_block, "NI and software decrypt must match");
    }

    #[test]
    fn test_ni_matches_software_aes192() {
        if !is_x86_feature_detected!("aes") {
            return;
        }
        use super::super::soft::SoftAesKey;

        let key = hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
        let pt = hex("6bc1bee22e409f96e93d7e117393172a");

        let ni = NiAesKey::new(&key).unwrap();
        let sw = SoftAesKey::new(&key).unwrap();

        let mut ni_block = pt.clone();
        let mut sw_block = pt.clone();

        ni.encrypt_block(&mut ni_block).unwrap();
        sw.encrypt_block(&mut sw_block).unwrap();
        assert_eq!(
            ni_block, sw_block,
            "AES-192: NI and software encrypt must match"
        );

        ni.decrypt_block(&mut ni_block).unwrap();
        sw.decrypt_block(&mut sw_block).unwrap();
        assert_eq!(
            ni_block, sw_block,
            "AES-192: NI and software decrypt must match"
        );
    }

    #[test]
    fn test_ni_matches_software_aes256() {
        if !is_x86_feature_detected!("aes") {
            return;
        }
        use super::super::soft::SoftAesKey;

        let key = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let pt = hex("6bc1bee22e409f96e93d7e117393172a");

        let ni = NiAesKey::new(&key).unwrap();
        let sw = SoftAesKey::new(&key).unwrap();

        let mut ni_block = pt.clone();
        let mut sw_block = pt.clone();

        ni.encrypt_block(&mut ni_block).unwrap();
        sw.encrypt_block(&mut sw_block).unwrap();
        assert_eq!(
            ni_block, sw_block,
            "AES-256: NI and software encrypt must match"
        );

        ni.decrypt_block(&mut ni_block).unwrap();
        sw.decrypt_block(&mut sw_block).unwrap();
        assert_eq!(
            ni_block, sw_block,
            "AES-256: NI and software decrypt must match"
        );
    }
}
