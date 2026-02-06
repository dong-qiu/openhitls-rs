//! CFB (Cipher Feedback) mode of operation.

use hitls_types::CryptoError;

/// Encrypt data using CFB mode.
pub fn cfb_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    todo!("CFB encryption not yet implemented")
}

/// Decrypt data using CFB mode.
pub fn cfb_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    todo!("CFB decryption not yet implemented")
}
