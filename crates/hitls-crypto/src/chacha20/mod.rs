//! ChaCha20 stream cipher implementation.
//!
//! ChaCha20 is a high-speed stream cipher designed by Daniel J. Bernstein.
//! It is commonly used with Poly1305 for authenticated encryption
//! (ChaCha20-Poly1305, RFC 8439).

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// ChaCha20 key size in bytes (256 bits).
pub const CHACHA20_KEY_SIZE: usize = 32;

/// ChaCha20 nonce size in bytes (96 bits).
pub const CHACHA20_NONCE_SIZE: usize = 12;

/// ChaCha20 stream cipher context.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct ChaCha20 {
    /// The 256-bit key.
    key: [u8; CHACHA20_KEY_SIZE],
}

impl ChaCha20 {
    /// Create a new ChaCha20 cipher with the given 32-byte key.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        todo!("ChaCha20 initialization not yet implemented")
    }

    /// Encrypt or decrypt data in place (XOR with keystream).
    ///
    /// ChaCha20 is symmetric: encryption and decryption are the same operation.
    pub fn apply_keystream(
        &self,
        nonce: &[u8],
        counter: u32,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        todo!("ChaCha20 keystream generation not yet implemented")
    }
}
