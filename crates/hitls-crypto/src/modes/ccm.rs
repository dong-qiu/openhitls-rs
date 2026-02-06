//! CCM (Counter with CBC-MAC) authenticated encryption.

use hitls_types::CryptoError;

/// Encrypt and authenticate data using CCM mode.
pub fn ccm_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    todo!("CCM encryption not yet implemented")
}

/// Decrypt and verify data using CCM mode.
pub fn ccm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    todo!("CCM decryption not yet implemented")
}
