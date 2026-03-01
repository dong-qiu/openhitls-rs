//! GCM (Galois/Counter Mode) authenticated encryption.
//!
//! Implements GCM as defined in NIST SP 800-38D.
//! Provides authenticated encryption with associated data (AEAD).
//! Supports AES-GCM and SM4-GCM via the `BlockCipher` trait.

use crate::aes::AesKey;
use crate::provider::BlockCipher;
use hitls_types::CryptoError;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const GCM_TAG_SIZE: usize = 16;

// Reduction table for 4-bit GHASH: TABLE_P4[i] = i * R >> 120, where R = 0xE1 << 120.
const TABLE_P4: [u64; 16] = [
    0x0000000000000000,
    0x1c20000000000000,
    0x3840000000000000,
    0x2460000000000000,
    0x7080000000000000,
    0x6ca0000000000000,
    0x48c0000000000000,
    0x54e0000000000000,
    0xe100000000000000,
    0xfd20000000000000,
    0xd940000000000000,
    0xc560000000000000,
    0x9180000000000000,
    0x8da0000000000000,
    0xa9c0000000000000,
    0xb5e0000000000000,
];

/// GF(2^128) element as (high, low) u64 pair.
#[derive(Clone, Copy, Default)]
pub(crate) struct Gf128 {
    h: u64,
    l: u64,
}

impl Gf128 {
    pub(crate) fn from_bytes(b: &[u8; 16]) -> Self {
        Self {
            h: u64::from_be_bytes(b[..8].try_into().unwrap()),
            l: u64::from_be_bytes(b[8..].try_into().unwrap()),
        }
    }

    pub(crate) fn to_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.h.to_be_bytes());
        out[8..].copy_from_slice(&self.l.to_be_bytes());
        out
    }

    fn xor(self, other: Self) -> Self {
        Self {
            h: self.h ^ other.h,
            l: self.l ^ other.l,
        }
    }

    /// Right shift by 4 bits in GF(2^128).
    fn shr4(self) -> Self {
        Self {
            h: self.h >> 4,
            l: (self.l >> 4) | (self.h << 60),
        }
    }
}

/// Precomputed GHASH table (16 entries for 4-bit multiplication).
/// Also stores the raw H value for hardware-accelerated paths.
///
/// Construct once per key and reuse across multiple GCM operations
/// to avoid redundant table computation.
pub struct GhashTable {
    table: [Gf128; 16],
    /// Raw hash subkey H (big-endian bytes) for hardware GHASH.
    h_raw: [u8; 16],
    /// Whether hardware GHASH is available.
    use_hw: bool,
}

impl GhashTable {
    /// Build a GHASH table from a pre-expanded block cipher.
    ///
    /// Computes H = Encrypt(0^128) and builds the 4-bit multiplication table.
    /// Use this to pre-compute the table once per key.
    pub fn from_cipher<C: BlockCipher>(cipher: &C) -> Result<Self, CryptoError> {
        let mut h_block = [0u8; 16];
        cipher.encrypt_block(&mut h_block)?;
        Ok(Self::new(&h_block))
    }

    pub(crate) fn new(h: &[u8; 16]) -> Self {
        let mut table = [Gf128::default(); 16];
        // table[0] = 0 (already default)
        table[8] = Gf128::from_bytes(h);

        // Build by halving: table[4] = table[8] >> 1, etc.
        // >> 1 in GF(2^128): shift right, reduce if low bit was set
        let mut cur = table[8];
        for &idx in &[4u8, 2, 1] {
            let carry = (cur.l & 1) != 0;
            cur = Gf128 {
                h: cur.h >> 1,
                l: (cur.l >> 1) | (cur.h << 63),
            };
            if carry {
                cur.h ^= 0xe100000000000000;
            }
            table[idx as usize] = cur;
        }

        // Fill remaining entries by XOR
        for i in 2..16u8 {
            if i.count_ones() > 1 {
                // Find highest set bit
                let msb = 1u8 << (7 - i.leading_zeros());
                table[i as usize] = table[msb as usize].xor(table[(i ^ msb) as usize]);
            }
        }

        let use_hw = detect_ghash_hw();
        Self {
            table,
            h_raw: *h,
            use_hw,
        }
    }

    /// GHASH multiplication: result = result XOR block, then multiply by H.
    /// Uses hardware acceleration (PMULL/PCLMULQDQ) when available.
    pub(crate) fn ghash_block(&self, state: &mut Gf128, block: &[u8; 16]) {
        if self.use_hw {
            let mut state_bytes = state.to_bytes();
            ghash_block_hw(&self.h_raw, &mut state_bytes, block);
            *state = Gf128::from_bytes(&state_bytes);
            return;
        }
        self.ghash_block_soft(state, block);
    }

    /// Software-only GHASH block multiply (4-bit table lookup).
    fn ghash_block_soft(&self, state: &mut Gf128, block: &[u8; 16]) {
        let input = Gf128::from_bytes(block);
        let mut z = Gf128::default();
        let x = state.xor(input);

        // Process each byte from low to high (LSB-first for correct GF multiplication)
        let x_bytes = x.to_bytes();
        for &byte in x_bytes.iter().rev() {
            // Low nibble first (less significant within byte)
            let lo = (byte & 0x0f) as usize;
            let rem_bits = (z.l & 0x0f) as usize;
            z = z.shr4();
            z.h ^= TABLE_P4[rem_bits];
            z = z.xor(self.table[lo]);

            // High nibble second (more significant within byte)
            let hi = (byte >> 4) as usize;
            let rem_bits = (z.l & 0x0f) as usize;
            z = z.shr4();
            z.h ^= TABLE_P4[rem_bits];
            z = z.xor(self.table[hi]);
        }

        *state = z;
    }

    /// GHASH over variable-length data (pad to block boundary).
    ///
    /// When hardware GHASH is available, keeps state as bytes throughout the loop
    /// to avoid per-block Gf128↔bytes conversion (1 conversion pair vs 2N).
    pub(crate) fn ghash_data(&self, state: &mut Gf128, data: &[u8]) {
        if self.use_hw && !data.is_empty() {
            let mut state_bytes = state.to_bytes();
            for chunk in data.chunks(16) {
                let mut block = [0u8; 16];
                block[..chunk.len()].copy_from_slice(chunk);
                ghash_block_hw(&self.h_raw, &mut state_bytes, &block);
            }
            *state = Gf128::from_bytes(&state_bytes);
            return;
        }
        for chunk in data.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            self.ghash_block(state, &block);
        }
    }
}

/// Detect whether hardware GHASH is available.
fn detect_ghash_hw() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("aes") {
            return true;
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("pclmulqdq") {
            return true;
        }
    }
    false
}

/// Hardware-accelerated GHASH block multiply (dispatches to platform intrinsics).
#[inline]
fn ghash_block_hw(h: &[u8; 16], state: &mut [u8; 16], block: &[u8; 16]) {
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: detect_ghash_hw() verified "aes" feature (includes PMULL)
        unsafe {
            super::ghash_arm::ghash_block_arm(h, state, block);
        }
        return;
    }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: detect_ghash_hw() verified "pclmulqdq" feature
        unsafe {
            super::ghash_x86::ghash_block_x86(h, state, block);
        }
        return;
    }
    #[allow(unreachable_code)]
    {
        let _ = (h, state, block);
    }
}

/// Increment the last 4 bytes of a 16-byte counter (big-endian INC32).
fn inc32(counter: &mut [u8; 16]) {
    let ctr =
        u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]).wrapping_add(1);
    counter[12..16].copy_from_slice(&ctr.to_be_bytes());
}

/// Internal GCM encrypt/decrypt with a pre-built GHASH table (generic over block cipher).
fn gcm_crypt_with_table<C: BlockCipher>(
    cipher: &C,
    table: &GhashTable,
    nonce: &[u8],
    aad: &[u8],
    input: &[u8],
    encrypting: bool,
) -> Result<(Vec<u8>, [u8; GCM_TAG_SIZE]), CryptoError> {
    let block_size = cipher.block_size();

    // Compute J0 (initial counter)
    let mut j0 = [0u8; 16];
    if nonce.len() == 12 {
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
    } else {
        // GHASH the nonce
        let mut state = Gf128::default();
        table.ghash_data(&mut state, nonce);
        // Append length block
        let mut len_block = [0u8; 16];
        len_block[8..16].copy_from_slice(&((nonce.len() as u64 * 8).to_be_bytes()));
        table.ghash_block(&mut state, &len_block);
        j0 = state.to_bytes();
    }

    // EK0 = Encrypt(J0)
    let mut ek0 = j0;
    cipher.encrypt_block(&mut ek0)?;

    // CTR encryption starting from inc32(J0)
    let mut counter = j0;
    inc32(&mut counter);

    let mut output = input.to_vec();
    for chunk in output.chunks_mut(block_size) {
        let mut keystream = counter;
        cipher.encrypt_block(&mut keystream)?;
        for (d, &k) in chunk.iter_mut().zip(keystream.iter()) {
            *d ^= k;
        }
        inc32(&mut counter);
    }

    // GHASH: process AAD, then ciphertext
    let mut ghash_state = Gf128::default();
    table.ghash_data(&mut ghash_state, aad);

    let ciphertext_for_hash = if encrypting { &output } else { input };
    table.ghash_data(&mut ghash_state, ciphertext_for_hash);

    // Length block: [len(AAD) in bits || len(C) in bits]
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&((aad.len() as u64 * 8).to_be_bytes()));
    len_block[8..16].copy_from_slice(&((ciphertext_for_hash.len() as u64 * 8).to_be_bytes()));
    table.ghash_block(&mut ghash_state, &len_block);

    // Tag = GHASH ^ EK0
    let tag_gf = ghash_state;
    let mut tag = tag_gf.to_bytes();
    for (t, &e) in tag.iter_mut().zip(ek0.iter()) {
        *t ^= e;
    }

    Ok((output, tag))
}

/// Internal GCM encrypt/decrypt (generic over block cipher).
/// Computes GHASH table on each call — use `gcm_crypt_with_table` for repeated operations.
fn gcm_crypt_generic<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8],
    aad: &[u8],
    input: &[u8],
    encrypting: bool,
) -> Result<(Vec<u8>, [u8; GCM_TAG_SIZE]), CryptoError> {
    let table = GhashTable::from_cipher(cipher)?;
    gcm_crypt_with_table(cipher, &table, nonce, aad, input, encrypting)
}

/// Encrypt and authenticate data using AES-GCM.
/// Returns ciphertext || 16-byte tag.
pub fn gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = AesKey::new(key)?;
    let (mut ct, tag) = gcm_crypt_generic(&cipher, nonce, aad, plaintext, true)?;
    ct.extend_from_slice(&tag);
    Ok(ct)
}

/// Decrypt and verify data using AES-GCM.
/// `ciphertext` includes the appended 16-byte tag.
/// Returns plaintext on success, or error if authentication fails.
pub fn gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < GCM_TAG_SIZE {
        return Err(CryptoError::InvalidArg);
    }
    let ct_len = ciphertext.len() - GCM_TAG_SIZE;
    let (ct_data, received_tag) = ciphertext.split_at(ct_len);

    let cipher = AesKey::new(key)?;
    let (mut plaintext, computed_tag) = gcm_crypt_generic(&cipher, nonce, aad, ct_data, false)?;

    // Constant-time tag comparison
    if computed_tag.ct_eq(received_tag).unwrap_u8() != 1 {
        plaintext.zeroize();
        return Err(CryptoError::AeadTagVerifyFail);
    }

    Ok(plaintext)
}

/// Encrypt using a pre-expanded cipher and GHASH table (avoids per-record key expansion).
pub fn gcm_encrypt_with<C: BlockCipher>(
    cipher: &C,
    table: &GhashTable,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let (mut ct, tag) = gcm_crypt_with_table(cipher, table, nonce, aad, plaintext, true)?;
    ct.extend_from_slice(&tag);
    Ok(ct)
}

/// Decrypt using a pre-expanded cipher and GHASH table (avoids per-record key expansion).
pub fn gcm_decrypt_with<C: BlockCipher>(
    cipher: &C,
    table: &GhashTable,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < GCM_TAG_SIZE {
        return Err(CryptoError::InvalidArg);
    }
    let ct_len = ciphertext.len() - GCM_TAG_SIZE;
    let (ct_data, received_tag) = ciphertext.split_at(ct_len);

    let (mut plaintext, computed_tag) =
        gcm_crypt_with_table(cipher, table, nonce, aad, ct_data, false)?;

    if computed_tag.ct_eq(received_tag).unwrap_u8() != 1 {
        plaintext.zeroize();
        return Err(CryptoError::AeadTagVerifyFail);
    }

    Ok(plaintext)
}

/// Encrypt and authenticate data using SM4-GCM.
/// Returns ciphertext || 16-byte tag.
#[cfg(feature = "sm4")]
pub fn sm4_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = crate::sm4::Sm4Key::new(key)?;
    let (mut ct, tag) = gcm_crypt_generic(&cipher, nonce, aad, plaintext, true)?;
    ct.extend_from_slice(&tag);
    Ok(ct)
}

/// Decrypt and verify data using SM4-GCM.
/// `ciphertext` includes the appended 16-byte tag.
/// Returns plaintext on success, or error if authentication fails.
#[cfg(feature = "sm4")]
pub fn sm4_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < GCM_TAG_SIZE {
        return Err(CryptoError::InvalidArg);
    }
    let ct_len = ciphertext.len() - GCM_TAG_SIZE;
    let (ct_data, received_tag) = ciphertext.split_at(ct_len);

    let cipher = crate::sm4::Sm4Key::new(key)?;
    let (mut plaintext, computed_tag) = gcm_crypt_generic(&cipher, nonce, aad, ct_data, false)?;

    if computed_tag.ct_eq(received_tag).unwrap_u8() != 1 {
        plaintext.zeroize();
        return Err(CryptoError::AeadTagVerifyFail);
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_utils::hex::{hex, to_hex};

    // NIST SP 800-38D Test Case 1: empty PT, empty AAD
    #[test]
    fn test_gcm_case1() {
        let key = hex("00000000000000000000000000000000");
        let nonce = hex("000000000000000000000000");
        let expected_tag = "58e2fccefa7e3061367f1d57a4e7455a";

        let result = gcm_encrypt(&key, &nonce, &[], &[]).unwrap();
        assert_eq!(result.len(), GCM_TAG_SIZE);
        assert_eq!(to_hex(&result), expected_tag);

        // Decrypt
        let pt = gcm_decrypt(&key, &nonce, &[], &result).unwrap();
        assert!(pt.is_empty());
    }

    // NIST SP 800-38D Test Case 2: 16 bytes PT, empty AAD
    #[test]
    fn test_gcm_case2() {
        let key = hex("00000000000000000000000000000000");
        let nonce = hex("000000000000000000000000");
        let pt = hex("00000000000000000000000000000000");
        let expected_ct = "0388dace60b6a392f328c2b971b2fe78";
        let expected_tag = "ab6e47d42cec13bdf53a67b21257bddf";

        let result = gcm_encrypt(&key, &nonce, &[], &pt).unwrap();
        assert_eq!(to_hex(&result[..16]), expected_ct);
        assert_eq!(to_hex(&result[16..]), expected_tag);

        let decrypted = gcm_decrypt(&key, &nonce, &[], &result).unwrap();
        assert_eq!(decrypted, pt);
    }

    // NIST SP 800-38D Test Case 4: 60-byte PT with AAD
    #[test]
    fn test_gcm_case3() {
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let nonce = hex("cafebabefacedbaddecaf888");
        let pt = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let expected_ct = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091";
        let expected_tag = "5bc94fbc3221a5db94fae95ae7121a47";

        let result = gcm_encrypt(&key, &nonce, &aad, &pt).unwrap();
        let ct_len = pt.len();
        assert_eq!(to_hex(&result[..ct_len]), expected_ct);
        assert_eq!(to_hex(&result[ct_len..]), expected_tag);

        let decrypted = gcm_decrypt(&key, &nonce, &aad, &result).unwrap();
        assert_eq!(decrypted, pt);
    }

    // Test authentication failure
    #[test]
    fn test_gcm_auth_failure() {
        let key = hex("00000000000000000000000000000000");
        let nonce = hex("000000000000000000000000");
        let pt = hex("00000000000000000000000000000000");

        let mut result = gcm_encrypt(&key, &nonce, &[], &pt).unwrap();
        // Tamper with ciphertext
        result[0] ^= 1;
        assert!(gcm_decrypt(&key, &nonce, &[], &result).is_err());
    }

    // Test too-short ciphertext
    #[test]
    fn test_gcm_short_ciphertext() {
        let key = hex("00000000000000000000000000000000");
        let nonce = hex("000000000000000000000000");
        assert!(gcm_decrypt(&key, &nonce, &[], &[0u8; 15]).is_err());
    }

    #[cfg(feature = "sm4")]
    #[test]
    fn test_sm4_gcm_encrypt_decrypt_roundtrip() {
        use super::sm4_gcm_decrypt;
        use super::sm4_gcm_encrypt;

        let key = [0x42u8; 16]; // SM4 128-bit key
        let nonce = [0x01u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello SM4-GCM authenticated encryption";

        let ct = sm4_gcm_encrypt(&key, &nonce, aad, plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len() + 16); // ciphertext + 16-byte tag

        let pt = sm4_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_gcm_invalid_key_length() {
        let nonce = hex("000000000000000000000000");
        // 15-byte key — not a valid AES key length
        assert!(gcm_encrypt(&[0u8; 15], &nonce, &[], &[1, 2, 3]).is_err());
        assert!(gcm_encrypt(&[0u8; 17], &nonce, &[], &[1, 2, 3]).is_err());
        assert!(gcm_encrypt(&[], &nonce, &[], &[1, 2, 3]).is_err());
    }

    // NIST SP 800-38D Test Case 14: AES-256 with AAD
    #[test]
    fn test_gcm_aes256_nist_case14() {
        let key = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let nonce = hex("cafebabefacedbaddecaf888");
        let pt = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let expected_ct = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662";
        let expected_tag = "76fc6ece0f4e1768cddf8853bb2d551b";

        let result = gcm_encrypt(&key, &nonce, &aad, &pt).unwrap();
        let ct_len = pt.len();
        assert_eq!(to_hex(&result[..ct_len]), expected_ct);
        assert_eq!(to_hex(&result[ct_len..]), expected_tag);

        let decrypted = gcm_decrypt(&key, &nonce, &aad, &result).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_gcm_empty_plaintext_with_aad() {
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let nonce = hex("cafebabefacedbaddecaf888");
        let aad = b"some authenticated data";

        // Empty plaintext + AAD → result is tag-only (16 bytes)
        let result = gcm_encrypt(&key, &nonce, aad, &[]).unwrap();
        assert_eq!(result.len(), GCM_TAG_SIZE);

        // Decrypt → empty plaintext
        let pt = gcm_decrypt(&key, &nonce, aad, &result).unwrap();
        assert!(pt.is_empty());

        // Wrong AAD → authentication failure
        assert!(matches!(
            gcm_decrypt(&key, &nonce, b"wrong aad", &result),
            Err(CryptoError::AeadTagVerifyFail)
        ));
    }

    #[cfg(feature = "sm4")]
    #[test]
    fn test_sm4_gcm_tampered_tag() {
        use super::sm4_gcm_decrypt;
        use super::sm4_gcm_encrypt;

        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let plaintext = b"secret message";

        let mut ct = sm4_gcm_encrypt(&key, &nonce, &[], plaintext).unwrap();
        // Tamper with the tag (last 16 bytes)
        let len = ct.len();
        ct[len - 1] ^= 0x01;
        assert!(sm4_gcm_decrypt(&key, &nonce, &[], &ct).is_err());
    }

    /// GCM with 8-byte nonce (non-standard, uses GHASH for J0).
    #[test]
    fn test_gcm_nonce_8_bytes() {
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let nonce = hex("cafebabefacedb"); // 7 bytes
        let pt = b"test data for short nonce";
        let ct = gcm_encrypt(&key, &nonce, &[], pt).unwrap();
        let recovered = gcm_decrypt(&key, &nonce, &[], &ct).unwrap();
        assert_eq!(&recovered, pt);
    }

    /// GCM with 1-byte nonce boundary.
    #[test]
    fn test_gcm_nonce_1_byte() {
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let nonce = vec![0x42u8]; // 1 byte
        let pt = b"one byte nonce test";
        let ct = gcm_encrypt(&key, &nonce, &[], pt).unwrap();
        let recovered = gcm_decrypt(&key, &nonce, &[], &ct).unwrap();
        assert_eq!(&recovered, pt);
    }

    /// GCM with 64-byte long nonce.
    #[test]
    fn test_gcm_nonce_64_bytes() {
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let nonce = vec![0xAB; 64]; // 64 bytes
        let pt = b"long nonce test";
        let ct = gcm_encrypt(&key, &nonce, &[], pt).unwrap();
        let recovered = gcm_decrypt(&key, &nonce, &[], &ct).unwrap();
        assert_eq!(&recovered, pt);
    }

    /// GCM with precomputed GhashTable reuse.
    #[test]
    fn test_gcm_with_precomputed_table() {
        use super::gcm_decrypt_with;
        use super::gcm_encrypt_with;
        use super::GhashTable;
        use crate::aes::AesKey;

        let key_bytes = hex("feffe9928665731c6d6a8f9467308308");
        let aes_key = AesKey::new(&key_bytes).unwrap();

        let table = GhashTable::from_cipher(&aes_key).unwrap();

        let nonce = hex("cafebabefacedbaddecaf888");
        let pt1 = b"first message";
        let pt2 = b"second message";

        // Encrypt two messages with the same key/table
        let ct1 = gcm_encrypt_with(&aes_key, &table, &nonce, &[], pt1).unwrap();
        let nonce2 = hex("cafebabefacedbaddecaf889");
        let ct2 = gcm_encrypt_with(&aes_key, &table, &nonce2, &[], pt2).unwrap();

        let r1 = gcm_decrypt_with(&aes_key, &table, &nonce, &[], &ct1).unwrap();
        let r2 = gcm_decrypt_with(&aes_key, &table, &nonce2, &[], &ct2).unwrap();
        assert_eq!(&r1, pt1);
        assert_eq!(&r2, pt2);
    }

    /// GCM decrypt with tampered ciphertext → tag verification failure.
    #[test]
    fn test_gcm_decrypt_tampered() {
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let nonce = hex("cafebabefacedbaddecaf888");
        let pt = b"hello world";
        let mut ct = gcm_encrypt(&key, &nonce, &[], pt).unwrap();
        // Tamper with ciphertext byte (not tag)
        ct[0] ^= 0x01;
        assert!(matches!(
            gcm_decrypt(&key, &nonce, &[], &ct),
            Err(CryptoError::AeadTagVerifyFail)
        ));
    }

    /// GCM with 16-byte nonce (non-standard, triggers GHASH J0 computation).
    #[test]
    fn test_gcm_nonce_16_bytes() {
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let nonce = vec![0xAB; 16];
        let pt = b"sixteen byte nonce test";
        let ct = gcm_encrypt(&key, &nonce, &[], pt).unwrap();
        let recovered = gcm_decrypt(&key, &nonce, &[], &ct).unwrap();
        assert_eq!(&recovered, pt);
    }

    /// GCM with large AAD (multiple GHASH blocks).
    #[test]
    fn test_gcm_large_aad_multi_block() {
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let nonce = hex("cafebabefacedbaddecaf888");
        let aad = vec![0x42u8; 256]; // 256 bytes = 16 GHASH blocks
        let pt = b"test with large AAD";
        let ct = gcm_encrypt(&key, &nonce, &aad, pt).unwrap();
        let recovered = gcm_decrypt(&key, &nonce, &aad, &ct).unwrap();
        assert_eq!(&recovered, pt);

        // Wrong AAD → auth failure
        let mut wrong_aad = aad.clone();
        wrong_aad[100] ^= 0x01;
        assert!(matches!(
            gcm_decrypt(&key, &nonce, &wrong_aad, &ct),
            Err(CryptoError::AeadTagVerifyFail)
        ));
    }

    /// gcm_decrypt_with should reject short ciphertext.
    #[test]
    fn test_gcm_decrypt_with_short_ciphertext() {
        use super::gcm_decrypt_with;
        use super::GhashTable;
        use crate::aes::AesKey;

        let key_bytes = hex("feffe9928665731c6d6a8f9467308308");
        let aes_key = AesKey::new(&key_bytes).unwrap();
        let table = GhashTable::from_cipher(&aes_key).unwrap();
        let nonce = hex("cafebabefacedbaddecaf888");

        // Less than 16 bytes (tag size) → error
        assert!(gcm_decrypt_with(&aes_key, &table, &nonce, &[], &[0u8; 15]).is_err());
        assert!(gcm_decrypt_with(&aes_key, &table, &nonce, &[], &[0u8; 0]).is_err());
    }

    /// gcm_encrypt_with + gcm_decrypt_with roundtrip with AAD.
    #[test]
    fn test_gcm_encrypt_with_aad_roundtrip() {
        use super::{gcm_decrypt_with, gcm_encrypt_with, GhashTable};
        use crate::aes::AesKey;

        let key_bytes = hex("feffe9928665731c6d6a8f9467308308");
        let aes_key = AesKey::new(&key_bytes).unwrap();
        let table = GhashTable::from_cipher(&aes_key).unwrap();
        let nonce = hex("cafebabefacedbaddecaf888");
        let aad = b"authenticated header data";
        let pt = b"precomputed table with AAD test";

        let ct = gcm_encrypt_with(&aes_key, &table, &nonce, aad, pt).unwrap();
        let recovered = gcm_decrypt_with(&aes_key, &table, &nonce, aad, &ct).unwrap();
        assert_eq!(&recovered, pt);

        // Wrong AAD → auth failure
        assert!(gcm_decrypt_with(&aes_key, &table, &nonce, b"wrong", &ct).is_err());
    }

    mod proptests {
        use super::super::{gcm_decrypt, gcm_encrypt};
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            #[test]
            fn prop_gcm_encrypt_decrypt(
                key in prop::array::uniform16(any::<u8>()),
                nonce in prop::array::uniform12(any::<u8>()),
                aad in proptest::collection::vec(any::<u8>(), 0..64),
                pt in proptest::collection::vec(any::<u8>(), 0..128),
            ) {
                let ct = gcm_encrypt(&key, &nonce, &aad, &pt).unwrap();
                let recovered = gcm_decrypt(&key, &nonce, &aad, &ct).unwrap();
                prop_assert_eq!(recovered, pt);
            }
        }
    }
}
