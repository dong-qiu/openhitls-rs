//! CBC (Cipher Block Chaining) mode of operation.

use hitls_types::CryptoError;

/// Encrypt data using CBC mode.
pub fn cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    todo!("CBC encryption not yet implemented")
}

/// Decrypt data using CBC mode.
pub fn cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    todo!("CBC decryption not yet implemented")
}
