//! CFB (Cipher Feedback) mode of operation.
//!
//! Implements CFB-128 as defined in NIST SP 800-38A §6.3.
//! Uses AES as the underlying block cipher.

use crate::aes::{AesKey, AES_BLOCK_SIZE};
use hitls_types::CryptoError;

/// Encrypt data using CFB-128 mode with AES.
///
/// No padding needed — handles arbitrary-length plaintext.
pub fn cfb_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if iv.len() != AES_BLOCK_SIZE {
        return Err(CryptoError::InvalidIvLength);
    }
    let cipher = AesKey::new(key)?;

    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut feedback = [0u8; AES_BLOCK_SIZE];
    feedback.copy_from_slice(iv);

    for chunk in plaintext.chunks(AES_BLOCK_SIZE) {
        let mut keystream = feedback;
        cipher.encrypt_block(&mut keystream)?;

        let mut ct_block = [0u8; AES_BLOCK_SIZE];
        for (i, &p) in chunk.iter().enumerate() {
            ct_block[i] = p ^ keystream[i];
        }
        ciphertext.extend_from_slice(&ct_block[..chunk.len()]);

        // Update feedback: use full block (pad with zeros for partial)
        if chunk.len() == AES_BLOCK_SIZE {
            feedback.copy_from_slice(&ct_block);
        } else {
            feedback = [0u8; AES_BLOCK_SIZE];
            feedback[..chunk.len()].copy_from_slice(&ct_block[..chunk.len()]);
        }
    }

    Ok(ciphertext)
}

/// Decrypt data using CFB-128 mode with AES.
pub fn cfb_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if iv.len() != AES_BLOCK_SIZE {
        return Err(CryptoError::InvalidIvLength);
    }
    let cipher = AesKey::new(key)?;

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut feedback = [0u8; AES_BLOCK_SIZE];
    feedback.copy_from_slice(iv);

    for chunk in ciphertext.chunks(AES_BLOCK_SIZE) {
        let mut keystream = feedback;
        cipher.encrypt_block(&mut keystream)?;

        for (i, &c) in chunk.iter().enumerate() {
            plaintext.push(c ^ keystream[i]);
        }

        // Update feedback with ciphertext
        if chunk.len() == AES_BLOCK_SIZE {
            feedback.copy_from_slice(chunk);
        } else {
            feedback = [0u8; AES_BLOCK_SIZE];
            feedback[..chunk.len()].copy_from_slice(chunk);
        }
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

    // NIST SP 800-38A CFB128-AES128 roundtrip + first block verification
    #[test]
    fn test_cfb_aes128_roundtrip() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        let pt = hex_to_bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");

        let ct = cfb_encrypt(&key, &iv, &pt).unwrap();
        assert_eq!(ct.len(), pt.len());

        // First block: C1 = P1 XOR E_K(IV) — same as OFB/CTR first block
        assert_eq!(hex(&ct[..16]), "3b3fd92eb72dad20333449f8e83cfb4a");

        let decrypted = cfb_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_cfb_partial_block() {
        let key = [0x42u8; 16];
        let iv = [0u8; 16];
        let pt = b"Hello, CFB!"; // 11 bytes, not block-aligned

        let ct = cfb_encrypt(&key, &iv, pt).unwrap();
        assert_eq!(ct.len(), pt.len());

        let decrypted = cfb_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_cfb_empty() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let ct = cfb_encrypt(&key, &iv, &[]).unwrap();
        assert!(ct.is_empty());
        let pt = cfb_decrypt(&key, &iv, &ct).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn test_cfb_invalid_iv_length() {
        let key = [0u8; 16];
        let pt = b"test data";
        // Too short: 0, 12, 15 bytes
        for len in [0, 12, 15, 17] {
            let iv = vec![0u8; len];
            assert!(
                cfb_encrypt(&key, &iv, pt).is_err(),
                "encrypt should reject IV of length {len}"
            );
            assert!(
                cfb_decrypt(&key, &iv, pt).is_err(),
                "decrypt should reject IV of length {len}"
            );
        }
    }

    #[test]
    fn test_cfb_aes256_roundtrip() {
        // AES-256 CFB with 32-byte key, 64-byte plaintext
        let key = hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        let pt = hex_to_bytes(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        );

        let ct = cfb_encrypt(&key, &iv, &pt).unwrap();
        assert_eq!(ct.len(), pt.len());
        assert_ne!(ct, pt);

        let decrypted = cfb_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }
}
