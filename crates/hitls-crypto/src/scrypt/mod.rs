//! scrypt password-based key derivation function.
//!
//! scrypt is a memory-hard key derivation function designed by Colin Percival
//! (RFC 7914). It is intentionally expensive in both CPU and memory to resist
//! brute-force attacks using custom hardware (ASICs/FPGAs).

use hitls_types::CryptoError;

/// Derive a key from a password using scrypt.
///
/// # Parameters
/// - `password`: the password bytes.
/// - `salt`: the salt bytes (should be random, at least 16 bytes).
/// - `n`: the CPU/memory cost parameter (must be a power of 2).
/// - `r`: the block size parameter.
/// - `p`: the parallelization parameter.
/// - `dk_len`: the desired derived key length in bytes.
///
/// # Returns
/// The derived key of `dk_len` bytes.
pub fn scrypt(
    password: &[u8],
    salt: &[u8],
    n: u32,
    r: u32,
    p: u32,
    dk_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    todo!("scrypt key derivation not yet implemented")
}
