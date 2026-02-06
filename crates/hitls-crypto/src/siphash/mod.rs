//! SipHash implementation.
//!
//! SipHash is a fast, short-input pseudorandom function family designed
//! by Jean-Philippe Aumasson and Daniel J. Bernstein. It is commonly used
//! for hash table protection against hash-flooding DoS attacks.

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// SipHash context (SipHash-2-4 by default).
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SipHash {
    /// The 128-bit key split into two 64-bit halves.
    k0: u64,
    k1: u64,
}

impl SipHash {
    /// Create a new SipHash instance with a 16-byte key.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        todo!("SipHash initialization not yet implemented")
    }

    /// Feed data into the SipHash computation.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        todo!("SipHash update not yet implemented")
    }

    /// Finalize and return the 64-bit SipHash value.
    pub fn finish(&self) -> Result<u64, CryptoError> {
        todo!("SipHash finalization not yet implemented")
    }

    /// Reset the state for a new computation with the same key.
    pub fn reset(&mut self) {
        todo!("SipHash reset not yet implemented")
    }
}
