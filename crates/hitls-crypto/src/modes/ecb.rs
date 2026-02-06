//! ECB (Electronic Codebook) mode of operation.
//!
//! **Security warning**: ECB mode does not provide semantic security and
//! should generally not be used. It is provided for completeness and
//! specific low-level use cases only.

use hitls_types::CryptoError;

/// Encrypt data using ECB mode.
pub fn ecb_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    todo!("ECB encryption not yet implemented")
}

/// Decrypt data using ECB mode.
pub fn ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    todo!("ECB decryption not yet implemented")
}
