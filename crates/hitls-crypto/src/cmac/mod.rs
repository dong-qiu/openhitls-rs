//! CMAC (Cipher-based Message Authentication Code) implementation.
//!
//! CMAC provides message authentication using a block cipher (typically AES)
//! as defined in NIST SP 800-38B and RFC 4493. It operates on top of any
//! cipher implementing the [`BlockCipher`](crate::provider::BlockCipher) trait.

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// CMAC context.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Cmac {
    /// Subkey K1 derived from the block cipher.
    k1: Vec<u8>,
    /// Subkey K2 derived from the block cipher.
    k2: Vec<u8>,
}

impl Cmac {
    /// Create a new CMAC instance with the given block cipher key.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        todo!("CMAC initialization not yet implemented")
    }

    /// Feed data into the CMAC computation.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        todo!("CMAC update not yet implemented")
    }

    /// Finalize the CMAC computation and write the result to `out`.
    pub fn finish(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        todo!("CMAC finalization not yet implemented")
    }

    /// Reset the CMAC state for reuse with the same key.
    pub fn reset(&mut self) {
        todo!("CMAC reset not yet implemented")
    }
}
