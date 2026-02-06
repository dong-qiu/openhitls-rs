//! ECB (Electronic Codebook) mode of operation.
//!
//! **Security warning**: ECB mode does not provide semantic security and
//! should generally not be used. It is provided for completeness and
//! specific low-level use cases only.

use crate::aes::{AesKey, AES_BLOCK_SIZE};
use hitls_types::CryptoError;

/// Encrypt data using ECB mode with AES.
/// Input must be a multiple of 16 bytes (no padding).
pub fn ecb_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if plaintext.len() % AES_BLOCK_SIZE != 0 || plaintext.is_empty() {
        return Err(CryptoError::InvalidArg);
    }
    let cipher = AesKey::new(key)?;
    let mut output = plaintext.to_vec();
    for chunk in output.chunks_mut(AES_BLOCK_SIZE) {
        cipher.encrypt_block(chunk)?;
    }
    Ok(output)
}

/// Decrypt data using ECB mode with AES.
/// Input must be a multiple of 16 bytes.
pub fn ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() % AES_BLOCK_SIZE != 0 || ciphertext.is_empty() {
        return Err(CryptoError::InvalidArg);
    }
    let cipher = AesKey::new(key)?;
    let mut output = ciphertext.to_vec();
    for chunk in output.chunks_mut(AES_BLOCK_SIZE) {
        cipher.decrypt_block(chunk)?;
    }
    Ok(output)
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

    // NIST SP 800-38A F.1.1: AES-128 ECB
    #[test]
    fn test_ecb_aes128() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let pt = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a");
        let expected = "3ad77bb40d7a3660a89ecaf32466ef97";

        let ct = ecb_encrypt(&key, &pt).unwrap();
        assert_eq!(hex(&ct), expected);

        let decrypted = ecb_decrypt(&key, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_ecb_multi_block() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let pt = hex_to_bytes(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        );

        let ct = ecb_encrypt(&key, &pt).unwrap();
        let decrypted = ecb_decrypt(&key, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_ecb_invalid_length() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        assert!(ecb_encrypt(&key, &[0u8; 15]).is_err());
        assert!(ecb_encrypt(&key, &[]).is_err());
    }
}
