//! CTR (Counter) mode of operation.

use hitls_types::CryptoError;

/// Encrypt or decrypt data using CTR mode (symmetric operation).
pub fn ctr_crypt(key: &[u8], nonce: &[u8], data: &mut [u8]) -> Result<(), CryptoError> {
    todo!("CTR mode not yet implemented")
}
