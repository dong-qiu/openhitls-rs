//! MD5 message digest algorithm.
//!
//! MD5 produces a 128-bit (16-byte) hash value. It is defined in RFC 1321.
//!
//! **Security warning**: MD5 is cryptographically broken and should not be
//! used for security purposes. It is provided only for legacy compatibility
//! and non-security applications (e.g., checksums).

use hitls_types::CryptoError;

/// MD5 output size in bytes.
pub const MD5_OUTPUT_SIZE: usize = 16;

/// MD5 block size in bytes.
pub const MD5_BLOCK_SIZE: usize = 64;

/// MD5 hash context.
#[derive(Clone)]
pub struct Md5 {
    /// Internal state (four 32-bit words: A, B, C, D).
    state: [u32; 4],
    /// Number of bytes processed so far.
    count: u64,
    /// Partial block buffer.
    buffer: [u8; MD5_BLOCK_SIZE],
    /// Number of bytes in the buffer.
    buffer_len: usize,
}

impl Md5 {
    /// Create a new MD5 hash context.
    pub fn new() -> Self {
        todo!("MD5 initialization not yet implemented")
    }

    /// Feed data into the hash computation.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        todo!("MD5 update not yet implemented")
    }

    /// Finalize the hash and return the 16-byte digest.
    pub fn finish(&mut self) -> Result<[u8; MD5_OUTPUT_SIZE], CryptoError> {
        todo!("MD5 finalization not yet implemented")
    }

    /// Reset the hash context for a new computation.
    pub fn reset(&mut self) {
        todo!("MD5 reset not yet implemented")
    }

    /// One-shot: compute the MD5 digest of `data`.
    pub fn digest(data: &[u8]) -> Result<[u8; MD5_OUTPUT_SIZE], CryptoError> {
        let mut ctx = Self::new();
        ctx.update(data)?;
        ctx.finish()
    }
}
