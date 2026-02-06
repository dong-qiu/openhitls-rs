//! PBKDF2 (Password-Based Key Derivation Function 2) implementation.
//!
//! PBKDF2 is defined in RFC 8018 (PKCS#5 v2.1). It derives cryptographic
//! keys from a password by applying a pseudorandom function (typically
//! HMAC-SHA-256) iteratively to increase computational cost and resist
//! brute-force attacks.

use hitls_types::CryptoError;

/// Derive a key from a password using PBKDF2.
///
/// # Parameters
/// - `password`: the password bytes.
/// - `salt`: the salt bytes (should be random, at least 16 bytes).
/// - `iterations`: the iteration count (NIST recommends at least 10,000).
/// - `dk_len`: the desired derived key length in bytes.
///
/// # Returns
/// The derived key of `dk_len` bytes.
pub fn pbkdf2(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    dk_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    todo!("PBKDF2 key derivation not yet implemented")
}
