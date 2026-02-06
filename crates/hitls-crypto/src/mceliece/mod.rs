//! Classic McEliece key encapsulation mechanism.
//!
//! Classic McEliece is a code-based, post-quantum key encapsulation mechanism
//! with very small ciphertexts but large public keys. It is based on the
//! Niederreiter dual of the McEliece cryptosystem using binary Goppa codes,
//! and has a long history of cryptanalytic study.

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// A Classic McEliece key pair for key encapsulation.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct McElieceKeyPair {
    /// The encapsulation (public) key.
    encapsulation_key: Vec<u8>,
    /// The decapsulation (private) key.
    decapsulation_key: Vec<u8>,
}

impl McElieceKeyPair {
    /// Generate a new Classic McEliece key pair for the given parameter set.
    pub fn generate(parameter_set: &str) -> Result<Self, CryptoError> {
        todo!("Classic McEliece key generation not yet implemented")
    }

    /// Encapsulate: produce a shared secret and ciphertext.
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        todo!("Classic McEliece encapsulation not yet implemented")
    }

    /// Decapsulate: recover the shared secret from a ciphertext.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        todo!("Classic McEliece decapsulation not yet implemented")
    }

    /// Return the encapsulation (public) key bytes.
    pub fn encapsulation_key(&self) -> &[u8] {
        &self.encapsulation_key
    }
}
