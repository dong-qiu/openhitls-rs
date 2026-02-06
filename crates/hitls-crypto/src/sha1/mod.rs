//! SHA-1 message digest algorithm.
//!
//! SHA-1 produces a 160-bit (20-byte) hash value. It is defined in FIPS 180-4.
//!
//! **Security warning**: SHA-1 is considered cryptographically weak due to
//! demonstrated collision attacks. It is provided for legacy compatibility
//! and should not be used for new security applications.

use hitls_types::CryptoError;

/// SHA-1 output size in bytes.
pub const SHA1_OUTPUT_SIZE: usize = 20;

/// SHA-1 block size in bytes.
pub const SHA1_BLOCK_SIZE: usize = 64;

/// SHA-1 hash context.
#[derive(Clone)]
pub struct Sha1 {
    /// Internal state (five 32-bit words).
    state: [u32; 5],
    /// Number of bytes processed so far.
    count: u64,
    /// Partial block buffer.
    buffer: [u8; SHA1_BLOCK_SIZE],
    /// Number of bytes in the buffer.
    buffer_len: usize,
}

impl Sha1 {
    /// Create a new SHA-1 hash context.
    pub fn new() -> Self {
        todo!("SHA-1 initialization not yet implemented")
    }

    /// Feed data into the hash computation.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        todo!("SHA-1 update not yet implemented")
    }

    /// Finalize the hash and return the 20-byte digest.
    pub fn finish(&mut self) -> Result<[u8; SHA1_OUTPUT_SIZE], CryptoError> {
        todo!("SHA-1 finalization not yet implemented")
    }

    /// Reset the hash context for a new computation.
    pub fn reset(&mut self) {
        todo!("SHA-1 reset not yet implemented")
    }

    /// One-shot: compute the SHA-1 digest of `data`.
    pub fn digest(data: &[u8]) -> Result<[u8; SHA1_OUTPUT_SIZE], CryptoError> {
        let mut ctx = Self::new();
        ctx.update(data)?;
        ctx.finish()
    }
}
