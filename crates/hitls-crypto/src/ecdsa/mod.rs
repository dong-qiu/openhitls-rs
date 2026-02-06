//! ECDSA (Elliptic Curve Digital Signature Algorithm) implementation.
//!
//! Provides ECDSA key generation, signing, and verification as defined in
//! FIPS 186-4 and ANSI X9.62. Operates over curves provided by the
//! [`ecc`](crate::ecc) module.

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// An ECDSA key pair for signing and verification.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct EcdsaKeyPair {
    /// The private scalar d (big-endian bytes).
    private_key: Vec<u8>,
    /// The public point Q encoded in uncompressed form.
    public_key: Vec<u8>,
}

impl EcdsaKeyPair {
    /// Generate a new ECDSA key pair for the given curve.
    pub fn generate(curve_id: u32) -> Result<Self, CryptoError> {
        todo!("ECDSA key generation not yet implemented")
    }

    /// Create an ECDSA key pair from existing private key bytes.
    pub fn from_private_key(curve_id: u32, private_key: &[u8]) -> Result<Self, CryptoError> {
        todo!("ECDSA key pair from private key not yet implemented")
    }

    /// Sign a message digest, returning the DER-encoded (r, s) signature.
    pub fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CryptoError> {
        todo!("ECDSA signing not yet implemented")
    }

    /// Verify a DER-encoded signature against a message digest.
    pub fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        todo!("ECDSA verification not yet implemented")
    }

    /// Return the public key in uncompressed point encoding.
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }
}
