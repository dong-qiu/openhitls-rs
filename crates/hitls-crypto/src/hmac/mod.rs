//! HMAC (Hash-based Message Authentication Code) implementation.
//!
//! HMAC provides message authentication using a cryptographic hash function
//! combined with a secret key, as defined in RFC 2104. It can be used with
//! any hash function that implements the [`Digest`](crate::provider::Digest) trait.

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// HMAC context parameterized over a hash function.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Hmac {
    /// The HMAC key (padded to block size).
    key: Vec<u8>,
}

impl Hmac {
    /// Create a new HMAC instance with the given key and hash algorithm.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        todo!("HMAC initialization not yet implemented")
    }

    /// Feed data into the HMAC computation.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        todo!("HMAC update not yet implemented")
    }

    /// Finalize the HMAC computation and write the result to `out`.
    pub fn finish(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        todo!("HMAC finalization not yet implemented")
    }

    /// Reset the HMAC state for reuse with the same key.
    pub fn reset(&mut self) {
        todo!("HMAC reset not yet implemented")
    }
}
