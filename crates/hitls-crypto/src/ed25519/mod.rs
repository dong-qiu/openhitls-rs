//! Ed25519 digital signature algorithm.
//!
//! Ed25519 is an EdDSA signature scheme using SHA-512 and Curve25519,
//! as defined in RFC 8032. It provides high-speed signing and verification
//! with 128-bit security.

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// Ed25519 key size in bytes.
pub const ED25519_KEY_SIZE: usize = 32;

/// Ed25519 signature size in bytes.
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// An Ed25519 key pair for signing and verification.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Ed25519KeyPair {
    /// The 32-byte private seed.
    private_key: [u8; ED25519_KEY_SIZE],
    /// The 32-byte public key.
    public_key: [u8; ED25519_KEY_SIZE],
}

impl Ed25519KeyPair {
    /// Generate a new random Ed25519 key pair.
    pub fn generate() -> Result<Self, CryptoError> {
        todo!("Ed25519 key generation not yet implemented")
    }

    /// Create an Ed25519 key pair from a 32-byte private seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self, CryptoError> {
        todo!("Ed25519 key pair from seed not yet implemented")
    }

    /// Sign a message, returning the 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; ED25519_SIGNATURE_SIZE], CryptoError> {
        todo!("Ed25519 signing not yet implemented")
    }

    /// Verify a signature against a message.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        todo!("Ed25519 verification not yet implemented")
    }

    /// Return the 32-byte public key.
    pub fn public_key(&self) -> &[u8; ED25519_KEY_SIZE] {
        &self.public_key
    }
}
