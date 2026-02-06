//! XTS (XEX-based Tweaked-codebook mode with ciphertext Stealing).
//!
//! XTS mode is designed for disk encryption and operates on data units
//! (typically 512-byte sectors). It requires two keys of equal size.

use hitls_types::CryptoError;

/// Encrypt a data unit using XTS mode.
pub fn xts_encrypt(
    key1: &[u8],
    key2: &[u8],
    tweak: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    todo!("XTS encryption not yet implemented")
}

/// Decrypt a data unit using XTS mode.
pub fn xts_decrypt(
    key1: &[u8],
    key2: &[u8],
    tweak: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    todo!("XTS decryption not yet implemented")
}
