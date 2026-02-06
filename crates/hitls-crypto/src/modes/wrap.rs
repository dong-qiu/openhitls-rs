//! AES Key Wrap (RFC 3394) and Key Wrap with Padding (RFC 5649).

use hitls_types::CryptoError;

/// Wrap a key using AES Key Wrap (RFC 3394).
pub fn key_wrap(kek: &[u8], plaintext_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    todo!("Key wrap not yet implemented")
}

/// Unwrap a key using AES Key Wrap (RFC 3394).
pub fn key_unwrap(kek: &[u8], wrapped_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    todo!("Key unwrap not yet implemented")
}
