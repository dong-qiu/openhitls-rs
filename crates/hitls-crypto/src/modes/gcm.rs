//! GCM (Galois/Counter Mode) authenticated encryption.

use hitls_types::CryptoError;

/// Encrypt and authenticate data using GCM mode.
pub fn gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    todo!("GCM encryption not yet implemented")
}

/// Decrypt and verify data using GCM mode.
pub fn gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    todo!("GCM decryption not yet implemented")
}
