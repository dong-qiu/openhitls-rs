//! ML-DSA (Module-Lattice Digital Signature Algorithm) implementation.
//!
//! ML-DSA (formerly CRYSTALS-Dilithium) is a post-quantum digital signature
//! scheme standardized by NIST in FIPS 204. It provides EUF-CMA security
//! based on the hardness of the Module Learning With Errors (MLWE) and
//! Module Short Integer Solution (MSIS) problems.
//! Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87.

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// An ML-DSA key pair for digital signatures.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct MlDsaKeyPair {
    /// The verification (public) key.
    public_key: Vec<u8>,
    /// The signing (private) key.
    private_key: Vec<u8>,
}

impl MlDsaKeyPair {
    /// Generate a new ML-DSA key pair for the given parameter set.
    ///
    /// `parameter_set` should be 44, 65, or 87.
    pub fn generate(parameter_set: u32) -> Result<Self, CryptoError> {
        todo!("ML-DSA key generation not yet implemented")
    }

    /// Sign a message, returning the signature bytes.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        todo!("ML-DSA signing not yet implemented")
    }

    /// Verify a signature against a message.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        todo!("ML-DSA verification not yet implemented")
    }

    /// Return the verification (public) key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}
