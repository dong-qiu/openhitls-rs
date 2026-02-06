//! AES (Advanced Encryption Standard) block cipher implementation.
//!
//! Provides AES-128, AES-192, and AES-256 block cipher operations.
//! This module implements the low-level block encrypt/decrypt; for modes of
//! operation (CBC, GCM, CTR, etc.) see the [`modes`](crate::modes) module.

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// AES block size in bytes (128 bits).
pub const AES_BLOCK_SIZE: usize = 16;

/// An AES key with precomputed round keys.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct AesKey {
    /// The raw key bytes.
    key: Vec<u8>,
    /// Precomputed round keys for encryption.
    round_keys: Vec<u32>,
}

impl AesKey {
    /// Create a new AES key from raw bytes.
    ///
    /// Accepts 16, 24, or 32-byte keys for AES-128, AES-192, and AES-256.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        todo!("AES key expansion not yet implemented")
    }

    /// Encrypt a single 16-byte block in place.
    pub fn encrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError> {
        todo!("AES block encryption not yet implemented")
    }

    /// Decrypt a single 16-byte block in place.
    pub fn decrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError> {
        todo!("AES block decryption not yet implemented")
    }

    /// Return the key length in bytes.
    pub fn key_len(&self) -> usize {
        self.key.len()
    }
}
