//! CCM (Counter with CBC-MAC) authenticated encryption.
//!
//! Implements CCM mode as defined in NIST SP 800-38C.
//! Supports AES and SM4 as the underlying block cipher.

use crate::aes::{AesKey, AES_BLOCK_SIZE};
use hitls_types::CryptoError;
use subtle::ConstantTimeEq;

const BLOCK_SIZE: usize = AES_BLOCK_SIZE; // 16 bytes for both AES and SM4

/// Internal trait for a 128-bit block cipher.
trait BlockCipher {
    fn encrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError>;
}

impl BlockCipher for AesKey {
    fn encrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError> {
        self.encrypt_block(block)
    }
}

#[cfg(feature = "sm4")]
impl BlockCipher for crate::sm4::Sm4Key {
    fn encrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError> {
        self.encrypt_block(block)
    }
}

// ---------------------------------------------------------------------------
// AES-CCM public API
// ---------------------------------------------------------------------------

/// Encrypt and authenticate data using AES-CCM mode.
///
/// # Parameters
/// - `key`: AES key (16, 24, or 32 bytes).
/// - `nonce`: Nonce (7-13 bytes; 12 is typical for TLS).
/// - `aad`: Additional authenticated data.
/// - `plaintext`: Data to encrypt.
/// - `tag_len`: Desired tag length (4, 6, 8, 10, 12, 14, or 16).
///
/// # Returns
/// Ciphertext || tag.
pub fn ccm_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let cipher = AesKey::new(key)?;
    ccm_encrypt_impl(&cipher, nonce, aad, plaintext, tag_len)
}

/// Decrypt and verify data using AES-CCM mode.
pub fn ccm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let cipher = AesKey::new(key)?;
    ccm_decrypt_impl(&cipher, nonce, aad, ciphertext, tag_len)
}

// ---------------------------------------------------------------------------
// SM4-CCM public API
// ---------------------------------------------------------------------------

/// Encrypt and authenticate data using SM4-CCM mode.
///
/// # Parameters
/// - `key`: SM4 key (16 bytes).
/// - `nonce`: Nonce (7-13 bytes; 12 is typical for TLS).
/// - `aad`: Additional authenticated data.
/// - `plaintext`: Data to encrypt.
/// - `tag_len`: Desired tag length (4, 6, 8, 10, 12, 14, or 16).
///
/// # Returns
/// Ciphertext || tag.
#[cfg(feature = "sm4")]
pub fn sm4_ccm_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let cipher = crate::sm4::Sm4Key::new(key)?;
    ccm_encrypt_impl(&cipher, nonce, aad, plaintext, tag_len)
}

/// Decrypt and verify data using SM4-CCM mode.
#[cfg(feature = "sm4")]
pub fn sm4_ccm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let cipher = crate::sm4::Sm4Key::new(key)?;
    ccm_decrypt_impl(&cipher, nonce, aad, ciphertext, tag_len)
}

// ---------------------------------------------------------------------------
// Generic CCM implementation
// ---------------------------------------------------------------------------

fn ccm_encrypt_impl<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    validate_params(nonce, tag_len)?;

    // Step 1: CBC-MAC to compute authentication tag
    let tag = cbc_mac(cipher, nonce, aad, plaintext, tag_len)?;

    // Step 2: CTR encryption
    let mut ctr_block = format_ctr_block(nonce, 0);
    let mut s0 = ctr_block;
    cipher.encrypt_block(&mut s0)?;

    // Encrypt plaintext using CTR starting from counter 1
    let mut ciphertext = plaintext.to_vec();
    let mut counter = 1u32;
    for chunk in ciphertext.chunks_mut(BLOCK_SIZE) {
        ctr_block = format_ctr_block(nonce, counter);
        cipher.encrypt_block(&mut ctr_block)?;
        for (c, &k) in chunk.iter_mut().zip(ctr_block.iter()) {
            *c ^= k;
        }
        counter += 1;
    }

    // Encrypt tag with S0
    let mut encrypted_tag = vec![0u8; tag_len];
    for (i, t) in encrypted_tag.iter_mut().enumerate() {
        *t = tag[i] ^ s0[i];
    }

    ciphertext.extend_from_slice(&encrypted_tag);
    Ok(ciphertext)
}

fn ccm_decrypt_impl<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    validate_params(nonce, tag_len)?;
    if ciphertext.len() < tag_len {
        return Err(CryptoError::InvalidArg);
    }

    let ct_len = ciphertext.len() - tag_len;
    let ct_data = &ciphertext[..ct_len];
    let received_tag = &ciphertext[ct_len..];

    // Step 1: CTR decryption
    let mut ctr_block = format_ctr_block(nonce, 0);
    let mut s0 = ctr_block;
    cipher.encrypt_block(&mut s0)?;

    let mut plaintext = ct_data.to_vec();
    let mut counter = 1u32;
    for chunk in plaintext.chunks_mut(BLOCK_SIZE) {
        ctr_block = format_ctr_block(nonce, counter);
        cipher.encrypt_block(&mut ctr_block)?;
        for (p, &k) in chunk.iter_mut().zip(ctr_block.iter()) {
            *p ^= k;
        }
        counter += 1;
    }

    // Step 2: CBC-MAC on decrypted plaintext
    let expected_tag = cbc_mac(cipher, nonce, aad, &plaintext, tag_len)?;

    // Decrypt received tag with S0
    let mut decrypted_tag = vec![0u8; tag_len];
    for (i, t) in decrypted_tag.iter_mut().enumerate() {
        *t = received_tag[i] ^ s0[i];
    }

    // Constant-time tag comparison
    if expected_tag[..tag_len].ct_eq(&decrypted_tag).unwrap_u8() != 1 {
        return Err(CryptoError::AeadTagVerifyFail);
    }

    Ok(plaintext)
}

fn validate_params(nonce: &[u8], tag_len: usize) -> Result<(), CryptoError> {
    // Nonce length: 7-13 bytes
    if nonce.len() < 7 || nonce.len() > 13 {
        return Err(CryptoError::InvalidArg);
    }
    // Tag length: must be even, 4-16
    if !(4..=16).contains(&tag_len) || tag_len % 2 != 0 {
        return Err(CryptoError::InvalidArg);
    }
    Ok(())
}

/// Format a CTR block: flags || nonce || counter.
fn format_ctr_block(nonce: &[u8], counter: u32) -> [u8; BLOCK_SIZE] {
    let q = 15 - nonce.len(); // number of bytes for counter field
    let mut block = [0u8; BLOCK_SIZE];
    block[0] = (q - 1) as u8; // flags for CTR: just L-1
    block[1..1 + nonce.len()].copy_from_slice(nonce);

    // Write counter in big-endian in the last q bytes
    let counter_bytes = counter.to_be_bytes();
    for i in 0..q {
        if i < 4 {
            block[BLOCK_SIZE - 1 - i] = counter_bytes[3 - i];
        }
    }
    block
}

/// Compute the CBC-MAC tag for CCM.
fn cbc_mac<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> Result<[u8; BLOCK_SIZE], CryptoError> {
    let q = 15 - nonce.len();

    // B0: flags || nonce || Q (plaintext length)
    let mut b0 = [0u8; BLOCK_SIZE];
    let has_aad = if aad.is_empty() { 0u8 } else { 0x40 };
    let t_field = (((tag_len - 2) / 2) as u8) << 3;
    let q_field = (q - 1) as u8;
    b0[0] = has_aad | t_field | q_field;
    b0[1..1 + nonce.len()].copy_from_slice(nonce);

    // Encode plaintext length in last q bytes (big-endian)
    let pt_len = plaintext.len();
    let len_bytes = pt_len.to_be_bytes();
    let len_bytes_start = len_bytes.len() - q;
    b0[BLOCK_SIZE - q..].copy_from_slice(&len_bytes[len_bytes_start..]);

    // Start CBC-MAC: X_1 = E_K(B_0)
    let mut x = b0;
    cipher.encrypt_block(&mut x)?;

    // Process AAD
    if !aad.is_empty() {
        let mut aad_encoded = Vec::new();

        // Encode AAD length
        if aad.len() < 0xFF00 {
            aad_encoded.push((aad.len() >> 8) as u8);
            aad_encoded.push((aad.len() & 0xFF) as u8);
        } else {
            aad_encoded.push(0xFF);
            aad_encoded.push(0xFE);
            aad_encoded.extend_from_slice(&(aad.len() as u32).to_be_bytes());
        }
        aad_encoded.extend_from_slice(aad);

        // Pad to block boundary
        while aad_encoded.len() % BLOCK_SIZE != 0 {
            aad_encoded.push(0);
        }

        for chunk in aad_encoded.chunks(BLOCK_SIZE) {
            for (xi, &bi) in x.iter_mut().zip(chunk.iter()) {
                *xi ^= bi;
            }
            cipher.encrypt_block(&mut x)?;
        }
    }

    // Process plaintext
    if !plaintext.is_empty() {
        let mut padded_pt = plaintext.to_vec();
        while padded_pt.len() % BLOCK_SIZE != 0 {
            padded_pt.push(0);
        }

        for chunk in padded_pt.chunks(BLOCK_SIZE) {
            for (xi, &bi) in x.iter_mut().zip(chunk.iter()) {
                *xi ^= bi;
            }
            cipher.encrypt_block(&mut x)?;
        }
    }

    Ok(x)
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

    // NIST SP 800-38C Example 1 (RFC 3610 Packet Vector #1)
    #[test]
    fn test_ccm_nist_example1() {
        let key = hex_to_bytes("404142434445464748494a4b4c4d4e4f");
        let nonce = hex_to_bytes("10111213141516");
        let aad = hex_to_bytes("0001020304050607");
        let pt = hex_to_bytes("20212223");
        let tag_len = 4;

        let ct = ccm_encrypt(&key, &nonce, &aad, &pt, tag_len).unwrap();

        // Decrypt and verify
        let decrypted = ccm_decrypt(&key, &nonce, &aad, &ct, tag_len).unwrap();
        assert_eq!(decrypted, pt);
    }

    // NIST SP 800-38C Example 2
    #[test]
    fn test_ccm_nist_example2() {
        let key = hex_to_bytes("404142434445464748494a4b4c4d4e4f");
        let nonce = hex_to_bytes("1011121314151617");
        let aad = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        let pt = hex_to_bytes("202122232425262728292a2b2c2d2e2f");
        let tag_len = 6;

        let ct = ccm_encrypt(&key, &nonce, &aad, &pt, tag_len).unwrap();

        let decrypted = ccm_decrypt(&key, &nonce, &aad, &ct, tag_len).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_ccm_auth_failure() {
        let key = [0x42u8; 16];
        let nonce = [0u8; 12];
        let aad = b"authenticated data";
        let pt = b"secret message";

        let mut ct = ccm_encrypt(&key, &nonce, aad, pt, 16).unwrap();
        // Tamper
        ct[0] ^= 0xff;
        assert!(ccm_decrypt(&key, &nonce, aad, &ct, 16).is_err());
    }

    #[test]
    fn test_ccm_empty_plaintext() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let ct = ccm_encrypt(&key, &nonce, b"aad", &[], 8).unwrap();
        assert_eq!(ct.len(), 8); // tag only
        let pt = ccm_decrypt(&key, &nonce, b"aad", &ct, 8).unwrap();
        assert!(pt.is_empty());
    }

    #[cfg(feature = "sm4")]
    #[test]
    fn test_sm4_ccm_roundtrip() {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello SM4-CCM";

        let ct = sm4_ccm_encrypt(&key, &nonce, aad, plaintext, 16).unwrap();
        assert_eq!(ct.len(), plaintext.len() + 16);

        let pt = sm4_ccm_decrypt(&key, &nonce, aad, &ct, 16).unwrap();
        assert_eq!(pt, plaintext);
    }
}
