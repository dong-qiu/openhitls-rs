//! GMAC (Galois Message Authentication Code) implementation.
//!
//! GMAC is the authentication-only variant of GCM mode. It provides
//! message authentication using the GHASH universal hash function over
//! GF(2^128) combined with a block cipher encryption step.

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// GMAC context.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Gmac {
    /// The hash subkey H = E_K(0).
    hash_subkey: [u8; 16],
}

impl Gmac {
    /// Create a new GMAC instance with the given block cipher key.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        todo!("GMAC initialization not yet implemented")
    }

    /// Set the IV / nonce for a new authentication operation.
    pub fn set_iv(&mut self, iv: &[u8]) -> Result<(), CryptoError> {
        todo!("GMAC set IV not yet implemented")
    }

    /// Feed authenticated data into the GMAC computation.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        todo!("GMAC update not yet implemented")
    }

    /// Finalize the GMAC computation and write the tag to `out`.
    pub fn finish(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        todo!("GMAC finalization not yet implemented")
    }

    /// Reset the GMAC state for reuse with the same key.
    pub fn reset(&mut self) {
        todo!("GMAC reset not yet implemented")
    }
}
