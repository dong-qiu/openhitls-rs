//! SM4 block cipher implementation.
//!
//! SM4 is a 128-bit block cipher standardized by the Chinese government
//! (GB/T 32907-2016). It uses a 128-bit key and is widely used in Chinese
//! commercial cryptography.

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// SM4 block size in bytes (128 bits).
pub const SM4_BLOCK_SIZE: usize = 16;

/// SM4 key size in bytes (128 bits).
pub const SM4_KEY_SIZE: usize = 16;

/// An SM4 key with precomputed round keys.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Sm4Key {
    /// Precomputed round keys (32 rounds).
    round_keys: [u32; 32],
}

impl Sm4Key {
    /// Create a new SM4 key from 16 raw bytes.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        todo!("SM4 key expansion not yet implemented")
    }

    /// Encrypt a single 16-byte block in place.
    pub fn encrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError> {
        todo!("SM4 block encryption not yet implemented")
    }

    /// Decrypt a single 16-byte block in place.
    pub fn decrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError> {
        todo!("SM4 block decryption not yet implemented")
    }
}
