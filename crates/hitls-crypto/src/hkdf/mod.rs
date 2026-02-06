//! HKDF (HMAC-based Extract-and-Expand Key Derivation Function).
//!
//! HKDF is a key derivation function defined in RFC 5869. It consists of
//! two stages: extract (to produce a pseudorandom key from input keying
//! material) and expand (to derive output keying material of any length).

use hitls_types::CryptoError;

/// HKDF context.
pub struct Hkdf {
    /// The pseudorandom key (PRK) produced by the extract step.
    prk: Vec<u8>,
}

impl Hkdf {
    /// Create a new HKDF instance by performing the extract step.
    ///
    /// `salt` is optional (use an empty slice for none).
    /// `ikm` is the input keying material.
    pub fn new(salt: &[u8], ikm: &[u8]) -> Result<Self, CryptoError> {
        todo!("HKDF extract not yet implemented")
    }

    /// Perform the expand step to derive `okm_len` bytes of output keying material.
    pub fn expand(&self, info: &[u8], okm_len: usize) -> Result<Vec<u8>, CryptoError> {
        todo!("HKDF expand not yet implemented")
    }

    /// One-shot: extract and expand in a single call.
    pub fn derive(
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        todo!("HKDF one-shot derive not yet implemented")
    }
}
