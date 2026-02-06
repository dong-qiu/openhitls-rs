//! OFB (Output Feedback) mode of operation.

use hitls_types::CryptoError;

/// Encrypt or decrypt data using OFB mode (symmetric operation).
pub fn ofb_crypt(key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), CryptoError> {
    todo!("OFB mode not yet implemented")
}
