//! GCM (Galois/Counter Mode) authenticated encryption.
//!
//! Implements GCM as defined in NIST SP 800-38D.
//! Provides authenticated encryption with associated data (AEAD).
//! Supports AES-GCM and SM4-GCM via the `BlockCipher` trait.

use crate::aes::AesKey;
use crate::provider::BlockCipher;
use hitls_types::CryptoError;
use subtle::ConstantTimeEq;

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
pub(crate) struct GhashTable {
    table: [Gf128; 16],
}

impl GhashTable {
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

        Self { table }
    }

    /// GHASH multiplication: result = result XOR block, then multiply by H.
    pub(crate) fn ghash_block(&self, state: &mut Gf128, block: &[u8; 16]) {
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
    pub(crate) fn ghash_data(&self, state: &mut Gf128, data: &[u8]) {
        for chunk in data.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            self.ghash_block(state, &block);
        }
    }
}

/// Increment the last 4 bytes of a 16-byte counter (big-endian INC32).
fn inc32(counter: &mut [u8; 16]) {
    let ctr =
        u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]).wrapping_add(1);
    counter[12..16].copy_from_slice(&ctr.to_be_bytes());
}

/// Internal GCM encrypt/decrypt (generic over block cipher).
fn gcm_crypt_generic(
    cipher: &dyn BlockCipher,
    nonce: &[u8],
    aad: &[u8],
    input: &[u8],
    encrypting: bool,
) -> Result<(Vec<u8>, [u8; GCM_TAG_SIZE]), CryptoError> {
    let block_size = cipher.block_size();

    // Compute H = Encrypt(0^128)
    let mut h_block = [0u8; 16];
    cipher.encrypt_block(&mut h_block)?;
    let table = GhashTable::new(&h_block);

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
    let (plaintext, computed_tag) = gcm_crypt_generic(&cipher, nonce, aad, ct_data, false)?;

    // Constant-time tag comparison
    if computed_tag.ct_eq(received_tag).unwrap_u8() != 1 {
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
    let (plaintext, computed_tag) = gcm_crypt_generic(&cipher, nonce, aad, ct_data, false)?;

    if computed_tag.ct_eq(received_tag).unwrap_u8() != 1 {
        return Err(CryptoError::AeadTagVerifyFail);
    }

    Ok(plaintext)
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

    // NIST SP 800-38D Test Case 1: empty PT, empty AAD
    #[test]
    fn test_gcm_case1() {
        let key = hex_to_bytes("00000000000000000000000000000000");
        let nonce = hex_to_bytes("000000000000000000000000");
        let expected_tag = "58e2fccefa7e3061367f1d57a4e7455a";

        let result = gcm_encrypt(&key, &nonce, &[], &[]).unwrap();
        assert_eq!(result.len(), GCM_TAG_SIZE);
        assert_eq!(hex(&result), expected_tag);

        // Decrypt
        let pt = gcm_decrypt(&key, &nonce, &[], &result).unwrap();
        assert!(pt.is_empty());
    }

    // NIST SP 800-38D Test Case 2: 16 bytes PT, empty AAD
    #[test]
    fn test_gcm_case2() {
        let key = hex_to_bytes("00000000000000000000000000000000");
        let nonce = hex_to_bytes("000000000000000000000000");
        let pt = hex_to_bytes("00000000000000000000000000000000");
        let expected_ct = "0388dace60b6a392f328c2b971b2fe78";
        let expected_tag = "ab6e47d42cec13bdf53a67b21257bddf";

        let result = gcm_encrypt(&key, &nonce, &[], &pt).unwrap();
        assert_eq!(hex(&result[..16]), expected_ct);
        assert_eq!(hex(&result[16..]), expected_tag);

        let decrypted = gcm_decrypt(&key, &nonce, &[], &result).unwrap();
        assert_eq!(decrypted, pt);
    }

    // NIST SP 800-38D Test Case 4: 60-byte PT with AAD
    #[test]
    fn test_gcm_case3() {
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308");
        let nonce = hex_to_bytes("cafebabefacedbaddecaf888");
        let pt = hex_to_bytes(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let aad = hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let expected_ct = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091";
        let expected_tag = "5bc94fbc3221a5db94fae95ae7121a47";

        let result = gcm_encrypt(&key, &nonce, &aad, &pt).unwrap();
        let ct_len = pt.len();
        assert_eq!(hex(&result[..ct_len]), expected_ct);
        assert_eq!(hex(&result[ct_len..]), expected_tag);

        let decrypted = gcm_decrypt(&key, &nonce, &aad, &result).unwrap();
        assert_eq!(decrypted, pt);
    }

    // Test authentication failure
    #[test]
    fn test_gcm_auth_failure() {
        let key = hex_to_bytes("00000000000000000000000000000000");
        let nonce = hex_to_bytes("000000000000000000000000");
        let pt = hex_to_bytes("00000000000000000000000000000000");

        let mut result = gcm_encrypt(&key, &nonce, &[], &pt).unwrap();
        // Tamper with ciphertext
        result[0] ^= 1;
        assert!(gcm_decrypt(&key, &nonce, &[], &result).is_err());
    }

    // Test too-short ciphertext
    #[test]
    fn test_gcm_short_ciphertext() {
        let key = hex_to_bytes("00000000000000000000000000000000");
        let nonce = hex_to_bytes("000000000000000000000000");
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
}
