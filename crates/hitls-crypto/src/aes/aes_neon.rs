//! Hardware-accelerated AES implementation using ARMv8 Crypto Extension (NEON) intrinsics.
//!
//! This module is only compiled on `aarch64` targets (gated at the module declaration in `mod.rs`).
//! It uses the ARMv8 AES instructions (`AESE`, `AESMC`, `AESD`, `AESIMC`) for high-performance
//! single-block encrypt/decrypt operations.

use core::arch::aarch64::{
    vaesdq_u8, vaeseq_u8, vaesimcq_u8, vaesmcq_u8, veorq_u8, vld1q_u8, vst1q_u8,
};

use hitls_types::CryptoError;
use zeroize::Zeroize;

use super::AES_BLOCK_SIZE;

// ---------------------------------------------------------------------------
// Key expansion constants (duplicated from mod.rs / soft.rs to avoid coupling)
// ---------------------------------------------------------------------------

/// Forward S-box (FIPS 197) — used only for key expansion.
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

/// Round constants for key expansion.
const RCON: [u32; 10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000,
];

/// Apply the S-box to each byte of a 32-bit word (big-endian).
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
// Key expansion: produces round keys as `[u8; 16]` byte arrays.
//
// Each group of 4 consecutive u32 words (in big-endian) is serialised into a
// 16-byte array that can be loaded directly with `vld1q_u8`.
// ---------------------------------------------------------------------------

/// Expand a raw AES key into `(rounds + 1)` round-key blocks.
fn expand_round_keys(key: &[u8]) -> Result<(Vec<[u8; 16]>, usize), CryptoError> {
    let nk = match key.len() {
        16 => 4,
        24 => 6,
        32 => 8,
        _ => return Err(CryptoError::InvalidKey),
    };
    let nr = nk + 6; // number of rounds
    let total_words = 4 * (nr + 1);
    let mut w = vec![0u32; total_words];

    // Copy the key into the first `nk` words.
    for i in 0..nk {
        w[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }

    // Key schedule.
    for i in nk..total_words {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            temp = sub_word(temp.rotate_left(8)) ^ RCON[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            temp = sub_word(temp);
        }
        w[i] = w[i - nk] ^ temp;
    }

    // Convert groups of 4 u32 words into [u8; 16] round-key blocks.
    let num_keys = nr + 1;
    let mut keys = vec![[0u8; 16]; num_keys];
    for r in 0..num_keys {
        for col in 0..4 {
            let bytes = w[r * 4 + col].to_be_bytes();
            let off = col * 4;
            keys[r][off] = bytes[0];
            keys[r][off + 1] = bytes[1];
            keys[r][off + 2] = bytes[2];
            keys[r][off + 3] = bytes[3];
        }
    }

    // Zeroize the intermediate word buffer.
    w.zeroize();

    Ok((keys, nr))
}

// ---------------------------------------------------------------------------
// Decrypt-key preparation (requires NEON AES intrinsics).
// ---------------------------------------------------------------------------

/// Prepare the decryption round keys from the encryption round keys.
///
/// dec_keys[0]       = enc_keys[rounds]
/// dec_keys[i]       = InvMixColumns(enc_keys[rounds - i])   for 1 <= i < rounds
/// dec_keys[rounds]  = enc_keys[0]
///
/// # Safety
///
/// Caller must ensure the CPU supports the ARMv8 AES and NEON extensions.
#[target_feature(enable = "aes,neon")]
unsafe fn prepare_dec_keys(enc_keys: &[[u8; 16]], rounds: usize) -> Vec<[u8; 16]> {
    let mut dec = vec![[0u8; 16]; rounds + 1];
    // First decrypt key is the last encrypt key.
    dec[0] = enc_keys[rounds];
    // Inner keys go through InvMixColumns.
    for i in 1..rounds {
        let rk = vld1q_u8(enc_keys[rounds - i].as_ptr());
        let dk = vaesimcq_u8(rk);
        vst1q_u8(dec[i].as_mut_ptr(), dk);
    }
    // Last decrypt key is the first encrypt key.
    dec[rounds] = enc_keys[0];
    dec
}

// ---------------------------------------------------------------------------
// NEON AES encrypt / decrypt helpers.
// ---------------------------------------------------------------------------

/// Encrypt a single 16-byte block using ARMv8 AES instructions.
///
/// # Safety
///
/// Caller must ensure the CPU supports the ARMv8 AES and NEON extensions.
#[target_feature(enable = "aes,neon")]
unsafe fn neon_encrypt_block(block: &mut [u8; 16], enc_keys: &[[u8; 16]], rounds: usize) {
    let mut state = vld1q_u8(block.as_ptr());

    // Rounds 0 .. rounds-2: AESE (XOR + SubBytes + ShiftRows) then AESMC (MixColumns).
    for rk_bytes in enc_keys.iter().take(rounds - 1) {
        let rk = vld1q_u8(rk_bytes.as_ptr());
        state = vaeseq_u8(state, rk);
        state = vaesmcq_u8(state);
    }

    // Last round: AESE (no MixColumns) then XOR with final round key.
    let rk_last = vld1q_u8(enc_keys[rounds - 1].as_ptr());
    state = vaeseq_u8(state, rk_last);
    let rk_final = vld1q_u8(enc_keys[rounds].as_ptr());
    state = veorq_u8(state, rk_final);

    vst1q_u8(block.as_mut_ptr(), state);
}

/// Decrypt a single 16-byte block using ARMv8 AES instructions.
///
/// # Safety
///
/// Caller must ensure the CPU supports the ARMv8 AES and NEON extensions.
#[target_feature(enable = "aes,neon")]
unsafe fn neon_decrypt_block(block: &mut [u8; 16], dec_keys: &[[u8; 16]], rounds: usize) {
    let mut state = vld1q_u8(block.as_ptr());

    // Rounds 0 .. rounds-2: AESD (XOR + InvSubBytes + InvShiftRows) then AESIMC (InvMixColumns).
    for rk_bytes in dec_keys.iter().take(rounds - 1) {
        let rk = vld1q_u8(rk_bytes.as_ptr());
        state = vaesdq_u8(state, rk);
        state = vaesimcq_u8(state);
    }

    // Last round: AESD (no InvMixColumns) then XOR with final round key.
    let rk_last = vld1q_u8(dec_keys[rounds - 1].as_ptr());
    state = vaesdq_u8(state, rk_last);
    let rk_final = vld1q_u8(dec_keys[rounds].as_ptr());
    state = veorq_u8(state, rk_final);

    vst1q_u8(block.as_mut_ptr(), state);
}

// ---------------------------------------------------------------------------
// Public type.
// ---------------------------------------------------------------------------

/// AES key backed by ARMv8 Crypto Extension (NEON) intrinsics.
///
/// Stores both encryption and pre-computed decryption round keys so that
/// encrypt/decrypt do not need to derive them on each call.
#[derive(Clone)]
pub(crate) struct NeonAesKey {
    /// Encryption round keys (rounds + 1 entries).
    enc_keys: Vec<[u8; 16]>,
    /// Decryption round keys (rounds + 1 entries), with inner keys through InvMixColumns.
    dec_keys: Vec<[u8; 16]>,
    /// Number of AES rounds (10 / 12 / 14).
    rounds: usize,
    /// Original key bytes (kept for `key_len()`).
    key_bytes: Vec<u8>,
}

impl Drop for NeonAesKey {
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

impl NeonAesKey {
    /// Create a new NEON-accelerated AES key from raw bytes (16, 24, or 32 bytes).
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let (enc_keys, rounds) = expand_round_keys(key)?;

        // Safety: This module is only compiled on aarch64 and the caller is expected
        // to have verified CPU feature support (the module is gated in mod.rs).
        let dec_keys = unsafe { prepare_dec_keys(&enc_keys, rounds) };

        Ok(Self {
            enc_keys,
            dec_keys,
            rounds,
            key_bytes: key.to_vec(),
        })
    }

    /// Encrypt a single 16-byte block in place.
    pub fn encrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError> {
        if block.len() != AES_BLOCK_SIZE {
            return Err(CryptoError::InvalidArg);
        }

        let buf: &mut [u8; 16] = block.try_into().map_err(|_| CryptoError::InvalidArg)?;

        // Safety: module only compiled on aarch64 with AES feature support.
        unsafe {
            neon_encrypt_block(buf, &self.enc_keys, self.rounds);
        }

        Ok(())
    }

    /// Decrypt a single 16-byte block in place.
    pub fn decrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError> {
        if block.len() != AES_BLOCK_SIZE {
            return Err(CryptoError::InvalidArg);
        }

        let buf: &mut [u8; 16] = block.try_into().map_err(|_| CryptoError::InvalidArg)?;

        // Safety: module only compiled on aarch64 with AES feature support.
        unsafe {
            neon_decrypt_block(buf, &self.dec_keys, self.rounds);
        }

        Ok(())
    }

    /// Return the key length in bytes.
    pub fn key_len(&self) -> usize {
        self.key_bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // FIPS 197 Appendix B: AES-128
    #[test]
    fn test_neon_aes128_encrypt() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let pt = hex_to_bytes("3243f6a8885a308d313198a2e0370734");
        let expected = "3925841d02dc09fbdc118597196a0b32";
        let cipher = NeonAesKey::new(&key).unwrap();
        let mut block = pt;
        cipher.encrypt_block(&mut block).unwrap();
        assert_eq!(hex(&block), expected);
    }

    #[test]
    fn test_neon_aes128_decrypt() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let ct = hex_to_bytes("3925841d02dc09fbdc118597196a0b32");
        let expected = "3243f6a8885a308d313198a2e0370734";
        let cipher = NeonAesKey::new(&key).unwrap();
        let mut block = ct;
        cipher.decrypt_block(&mut block).unwrap();
        assert_eq!(hex(&block), expected);
    }

    // FIPS 197 Appendix C.3: AES-256
    #[test]
    fn test_neon_aes256_encrypt() {
        let key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let pt = hex_to_bytes("00112233445566778899aabbccddeeff");
        let expected = "8ea2b7ca516745bfeafc49904b496089";
        let cipher = NeonAesKey::new(&key).unwrap();
        let mut block = pt;
        cipher.encrypt_block(&mut block).unwrap();
        assert_eq!(hex(&block), expected);
    }

    #[test]
    fn test_neon_aes256_roundtrip() {
        let key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let pt = hex_to_bytes("00112233445566778899aabbccddeeff");
        let cipher = NeonAesKey::new(&key).unwrap();
        let mut block = pt.clone();
        cipher.encrypt_block(&mut block).unwrap();
        cipher.decrypt_block(&mut block).unwrap();
        assert_eq!(block, pt.as_slice());
    }

    // AES-192 roundtrip
    #[test]
    fn test_neon_aes192_roundtrip() {
        let key = hex_to_bytes("000102030405060708090a0b0c0d0e0f1011121314151617");
        let pt = hex_to_bytes("00112233445566778899aabbccddeeff");
        let cipher = NeonAesKey::new(&key).unwrap();
        let mut block = pt.clone();
        cipher.encrypt_block(&mut block).unwrap();
        assert_ne!(block, pt.as_slice());
        cipher.decrypt_block(&mut block).unwrap();
        assert_eq!(block, pt.as_slice());
    }

    #[test]
    fn test_neon_aes_invalid_key_len() {
        assert!(NeonAesKey::new(&[0u8; 15]).is_err());
        assert!(NeonAesKey::new(&[0u8; 17]).is_err());
    }

    #[test]
    fn test_neon_aes_invalid_block_len() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let cipher = NeonAesKey::new(&key).unwrap();
        let mut short = [0u8; 15];
        assert!(cipher.encrypt_block(&mut short).is_err());
        assert!(cipher.decrypt_block(&mut short).is_err());
        let mut long = [0u8; 17];
        assert!(cipher.encrypt_block(&mut long).is_err());
        assert!(cipher.decrypt_block(&mut long).is_err());
    }

    #[test]
    fn test_neon_key_len() {
        let k16 = NeonAesKey::new(&[0u8; 16]).unwrap();
        assert_eq!(k16.key_len(), 16);
        let k24 = NeonAesKey::new(&[0u8; 24]).unwrap();
        assert_eq!(k24.key_len(), 24);
        let k32 = NeonAesKey::new(&[0u8; 32]).unwrap();
        assert_eq!(k32.key_len(), 32);
    }
}
