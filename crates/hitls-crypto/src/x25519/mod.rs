//! X25519 Diffie-Hellman key exchange.
//!
//! X25519 is an elliptic-curve Diffie-Hellman function using Curve25519,
//! as defined in RFC 7748. It provides fast key agreement with 128-bit security.

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// X25519 key size in bytes (256 bits).
pub const X25519_KEY_SIZE: usize = 32;

/// An X25519 private key (scalar).
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct X25519PrivateKey {
    /// The 32-byte private scalar.
    key: [u8; X25519_KEY_SIZE],
}

/// An X25519 public key (u-coordinate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X25519PublicKey {
    /// The 32-byte public key (u-coordinate on Curve25519).
    key: [u8; X25519_KEY_SIZE],
}

impl X25519PrivateKey {
    /// Generate a new random X25519 private key.
    pub fn generate() -> Result<Self, CryptoError> {
        todo!("X25519 private key generation not yet implemented")
    }

    /// Create an X25519 private key from 32 raw bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        todo!("X25519 private key construction not yet implemented")
    }

    /// Compute the corresponding public key.
    pub fn public_key(&self) -> X25519PublicKey {
        todo!("X25519 public key derivation not yet implemented")
    }

    /// Perform the X25519 Diffie-Hellman function with a peer's public key.
    pub fn diffie_hellman(&self, peer_public: &X25519PublicKey) -> Result<Vec<u8>, CryptoError> {
        todo!("X25519 Diffie-Hellman not yet implemented")
    }
}

impl X25519PublicKey {
    /// Create an X25519 public key from 32 raw bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        todo!("X25519 public key construction not yet implemented")
    }

    /// Return the raw 32-byte public key.
    pub fn as_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.key
    }
}
