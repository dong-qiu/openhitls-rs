//! XMSS (eXtended Merkle Signature Scheme) implementation.
//!
//! XMSS is a stateful, hash-based digital signature scheme defined in
//! RFC 8391. It provides post-quantum security but requires careful state
//! management to avoid one-time key reuse. Each key pair can produce a
//! fixed number of signatures determined by the tree height.

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// An XMSS key pair for digital signatures.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct XmssKeyPair {
    /// The verification (public) key (root + OID).
    public_key: Vec<u8>,
    /// The signing (private) key (includes state index).
    private_key: Vec<u8>,
}

impl XmssKeyPair {
    /// Generate a new XMSS key pair for the given parameter set.
    pub fn generate(parameter_set: &str) -> Result<Self, CryptoError> {
        todo!("XMSS key generation not yet implemented")
    }

    /// Sign a message, returning the signature bytes.
    ///
    /// This advances the internal state. The caller must persist the
    /// updated key to avoid one-time key reuse.
    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        todo!("XMSS signing not yet implemented")
    }

    /// Verify a signature against a message.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        todo!("XMSS verification not yet implemented")
    }

    /// Return the number of remaining signatures available.
    pub fn remaining_signatures(&self) -> u64 {
        todo!("XMSS remaining signatures count not yet implemented")
    }

    /// Return the verification (public) key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}
