//! ECDH (Elliptic Curve Diffie-Hellman) key agreement.
//!
//! Provides ECDH key pair generation and shared secret computation as
//! defined in NIST SP 800-56A. Operates over curves provided by the
//! [`ecc`](crate::ecc) module.

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// An ECDH key pair for key agreement.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct EcdhKeyPair {
    /// The private scalar (big-endian bytes).
    private_key: Vec<u8>,
    /// The public point encoded in uncompressed form.
    public_key: Vec<u8>,
}

impl EcdhKeyPair {
    /// Generate a new ECDH key pair for the given curve.
    pub fn generate(curve_id: u32) -> Result<Self, CryptoError> {
        todo!("ECDH key generation not yet implemented")
    }

    /// Create an ECDH key pair from existing private key bytes.
    pub fn from_private_key(curve_id: u32, private_key: &[u8]) -> Result<Self, CryptoError> {
        todo!("ECDH key pair from private key not yet implemented")
    }

    /// Compute the shared secret from the peer's public key.
    ///
    /// Returns the x-coordinate of the shared point.
    pub fn compute_shared_secret(&self, peer_public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        todo!("ECDH shared secret computation not yet implemented")
    }

    /// Return the public key in uncompressed point encoding.
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }
}
