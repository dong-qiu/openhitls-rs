//! CBC (Cipher Block Chaining) mode of operation.

use crate::aes::{AesKey, AES_BLOCK_SIZE};
use hitls_types::CryptoError;
use subtle::ConstantTimeEq;

/// Encrypt data using CBC mode with AES and PKCS#7 padding.
pub fn cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if iv.len() != AES_BLOCK_SIZE {
        return Err(CryptoError::InvalidIvLength);
    }
    let cipher = AesKey::new(key)?;

    // PKCS#7 padding
    let pad_len = AES_BLOCK_SIZE - (plaintext.len() % AES_BLOCK_SIZE);
    let mut data = plaintext.to_vec();
    data.extend(vec![pad_len as u8; pad_len]);

    let mut prev = [0u8; AES_BLOCK_SIZE];
    prev.copy_from_slice(iv);

    for chunk in data.chunks_mut(AES_BLOCK_SIZE) {
        for i in 0..AES_BLOCK_SIZE {
            chunk[i] ^= prev[i];
        }
        cipher.encrypt_block(chunk)?;
        prev.copy_from_slice(chunk);
    }
    Ok(data)
}

/// Decrypt data using CBC mode with AES and remove PKCS#7 padding.
pub fn cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if iv.len() != AES_BLOCK_SIZE {
        return Err(CryptoError::InvalidIvLength);
    }
    if ciphertext.len() % AES_BLOCK_SIZE != 0 || ciphertext.is_empty() {
        return Err(CryptoError::InvalidArg);
    }
    let cipher = AesKey::new(key)?;

    let mut output = ciphertext.to_vec();
    let mut prev = [0u8; AES_BLOCK_SIZE];
    prev.copy_from_slice(iv);

    for chunk in output.chunks_mut(AES_BLOCK_SIZE) {
        let ct_copy: [u8; AES_BLOCK_SIZE] = chunk.try_into().unwrap();
        cipher.decrypt_block(chunk)?;
        for i in 0..AES_BLOCK_SIZE {
            chunk[i] ^= prev[i];
        }
        prev = ct_copy;
    }

    // PKCS#7 unpad (constant-time check)
    let pad_val = *output.last().ok_or(CryptoError::InvalidPadding)? as usize;
    if pad_val == 0 || pad_val > AES_BLOCK_SIZE {
        return Err(CryptoError::InvalidPadding);
    }
    let pad_byte = pad_val as u8;
    let mut valid = 1u8;
    for &b in &output[output.len() - pad_val..] {
        valid &= b.ct_eq(&pad_byte).unwrap_u8();
    }
    if valid != 1 {
        return Err(CryptoError::InvalidPadding);
    }
    output.truncate(output.len() - pad_val);
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

    // NIST SP 800-38A F.2.1: AES-128 CBC (without padding — aligned input)
    #[test]
    fn test_cbc_aes128_roundtrip() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        let pt = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a");

        let ct = cbc_encrypt(&key, &iv, &pt).unwrap();
        // ct has padding block appended
        let decrypted = cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_cbc_padding_short() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        let pt = b"Hello, World!"; // 13 bytes, needs 3 bytes padding

        let ct = cbc_encrypt(&key, &iv, pt).unwrap();
        assert_eq!(ct.len(), 16); // One padded block
        let decrypted = cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_cbc_padding_aligned() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        let pt = [0xaau8; 16]; // Exactly one block — gets full padding block

        let ct = cbc_encrypt(&key, &iv, &pt).unwrap();
        assert_eq!(ct.len(), 32); // Original block + padding block
        let decrypted = cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_cbc_empty() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f");

        let ct = cbc_encrypt(&key, &iv, b"").unwrap();
        assert_eq!(ct.len(), 16); // Padding-only block
        let decrypted = cbc_decrypt(&key, &iv, &ct).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_cbc_invalid_iv() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        assert!(cbc_encrypt(&key, &[0u8; 15], b"test").is_err());
    }

    // NIST SP 800-38A F.2.1: verify first ciphertext block
    #[test]
    fn test_cbc_aes128_nist_vector() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        let pt = hex_to_bytes(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        );
        // Expected ciphertext blocks (without padding)
        let expected_ct = "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7";

        let ct = cbc_encrypt(&key, &iv, &pt).unwrap();
        // First 64 bytes of ct should match (the last 16 bytes are padding)
        assert_eq!(hex(&ct[..64]), expected_ct);
    }
}
