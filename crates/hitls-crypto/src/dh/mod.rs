//! DH (Diffie-Hellman) key exchange over finite fields.
//!
//! Provides classic Diffie-Hellman key agreement using MODP groups as
//! defined in RFC 3526 and RFC 7919. Supports both predefined groups
//! (ffdhe2048, ffdhe3072, etc.) and custom parameters.

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// Diffie-Hellman domain parameters (p, g).
#[derive(Debug, Clone)]
pub struct DhParams {
    /// The prime modulus p.
    p: Vec<u8>,
    /// The generator g.
    g: Vec<u8>,
}

impl DhParams {
    /// Create DH parameters from a prime and generator.
    pub fn new(p: &[u8], g: &[u8]) -> Result<Self, CryptoError> {
        todo!("DH parameter construction not yet implemented")
    }

    /// Return the size of the prime in bytes.
    pub fn prime_size(&self) -> usize {
        self.p.len()
    }
}

/// A Diffie-Hellman key pair.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct DhKeyPair {
    /// The private exponent x.
    private_key: Vec<u8>,
    /// The public value y = g^x mod p.
    public_key: Vec<u8>,
}

impl DhKeyPair {
    /// Generate a new DH key pair from the given parameters.
    pub fn generate(params: &DhParams) -> Result<Self, CryptoError> {
        todo!("DH key generation not yet implemented")
    }

    /// Compute the shared secret from the peer's public value.
    pub fn compute_shared_secret(
        &self,
        params: &DhParams,
        peer_public_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        todo!("DH shared secret computation not yet implemented")
    }

    /// Return the public value bytes.
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }
}
