//! HPKE (Hybrid Public Key Encryption) implementation.
//!
//! HPKE combines a KEM, KDF, and AEAD to provide public-key encryption
//! as defined in RFC 9180. It supports four modes: Base, PSK, Auth,
//! and AuthPSK, enabling flexible sender authentication and key agreement.

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// HPKE encryption context.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct HpkeCtx {
    /// The derived encryption key.
    key: Vec<u8>,
    /// The base nonce.
    base_nonce: Vec<u8>,
    /// The current sequence number.
    seq: u64,
}

impl HpkeCtx {
    /// Set up an HPKE sender context (Base mode).
    pub fn setup_sender(
        recipient_public_key: &[u8],
        info: &[u8],
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        todo!("HPKE sender setup not yet implemented")
    }

    /// Set up an HPKE recipient context (Base mode).
    pub fn setup_recipient(
        private_key: &[u8],
        enc: &[u8],
        info: &[u8],
    ) -> Result<Self, CryptoError> {
        todo!("HPKE recipient setup not yet implemented")
    }

    /// Encrypt a plaintext with associated data.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        todo!("HPKE seal not yet implemented")
    }

    /// Decrypt a ciphertext with associated data.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        todo!("HPKE open not yet implemented")
    }

    /// Export a secret of `len` bytes from the HPKE context.
    pub fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, CryptoError> {
        todo!("HPKE export not yet implemented")
    }
}
