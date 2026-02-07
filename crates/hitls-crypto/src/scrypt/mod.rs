//! scrypt password-based key derivation function (RFC 7914).
//!
//! scrypt is a memory-hard key derivation function designed by Colin Percival.
//! It is intentionally expensive in both CPU and memory to resist brute-force
//! attacks using custom hardware (ASICs/FPGAs).

use crate::pbkdf2;
use hitls_types::CryptoError;

/// Derive a key from a password using scrypt.
///
/// # Parameters
/// - `password`: the password bytes.
/// - `salt`: the salt bytes (should be random, at least 16 bytes).
/// - `n`: the CPU/memory cost parameter (must be a power of 2, > 1).
/// - `r`: the block size parameter (> 0).
/// - `p`: the parallelization parameter (> 0).
/// - `dk_len`: the desired derived key length in bytes.
pub fn scrypt(
    password: &[u8],
    salt: &[u8],
    n: u32,
    r: u32,
    p: u32,
    dk_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    // Validate parameters
    if n == 0 || n & (n - 1) != 0 || n < 2 {
        return Err(CryptoError::InvalidArg);
    }
    if r == 0 || p == 0 || dk_len == 0 {
        return Err(CryptoError::InvalidArg);
    }
    // r * p must not overflow
    let rp = (r as u64)
        .checked_mul(p as u64)
        .ok_or(CryptoError::InvalidArg)?;
    if rp >= (1 << 30) {
        return Err(CryptoError::InvalidArg);
    }

    let block_size = 128 * r as usize;

    // Step 1: B = PBKDF2-HMAC-SHA256(password, salt, 1, p * 128 * r)
    let mut b = pbkdf2::pbkdf2(password, salt, 1, p as usize * block_size)?;

    // Step 2: ROMix each block
    for i in 0..p as usize {
        let start = i * block_size;
        let mut block = b[start..start + block_size].to_vec();
        romix(&mut block, n as usize, r as usize);
        b[start..start + block_size].copy_from_slice(&block);
    }

    // Step 3: output = PBKDF2-HMAC-SHA256(password, B, 1, dk_len)
    pbkdf2::pbkdf2(password, &b, 1, dk_len)
}

/// ROMix: the sequential memory-hard function.
fn romix(block: &mut [u8], n: usize, r: usize) {
    let block_size = 128 * r;
    let mut v: Vec<Vec<u8>> = Vec::with_capacity(n);

    // Build lookup table V
    let mut x = block.to_vec();
    for _ in 0..n {
        v.push(x.clone());
        block_mix(&mut x, r);
    }

    // Mix phase
    for _ in 0..n {
        // j = Integerify(X) mod N
        // Integerify takes the last 64 bytes of X, interprets first 8 bytes as LE u64
        let offset = block_size - 64;
        let j_bytes: [u8; 8] = x[offset..offset + 8].try_into().unwrap();
        let j = u64::from_le_bytes(j_bytes) as usize & (n - 1);

        // X = X XOR V[j]
        for (xi, &vi) in x.iter_mut().zip(v[j].iter()) {
            *xi ^= vi;
        }
        block_mix(&mut x, r);
    }

    block.copy_from_slice(&x);
}

/// BlockMix using Salsa20/8 core.
fn block_mix(block: &mut [u8], r: usize) {
    let num_blocks = 2 * r;
    let mut x = [0u8; 64];
    // x = B[2r-1]
    x.copy_from_slice(&block[(num_blocks - 1) * 64..num_blocks * 64]);

    let mut y = vec![vec![0u8; 64]; num_blocks];

    for i in 0..num_blocks {
        // T = X XOR B[i]
        for (xj, &bj) in x.iter_mut().zip(block[i * 64..(i + 1) * 64].iter()) {
            *xj ^= bj;
        }
        salsa20_8_core(&mut x);
        y[i] = x.to_vec();
    }

    // Output: Y[0] || Y[2] || ... || Y[2r-2] || Y[1] || Y[3] || ... || Y[2r-1]
    let mut pos = 0;
    for i in (0..num_blocks).step_by(2) {
        block[pos..pos + 64].copy_from_slice(&y[i]);
        pos += 64;
    }
    for i in (1..num_blocks).step_by(2) {
        block[pos..pos + 64].copy_from_slice(&y[i]);
        pos += 64;
    }
}

/// Salsa20/8 core (8-round variant of Salsa20).
fn salsa20_8_core(block: &mut [u8; 64]) {
    let mut x = [0u32; 16];
    for i in 0..16 {
        x[i] = u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap());
    }

    let input = x;

    // 8 rounds (4 double rounds)
    for _ in 0..4 {
        // Column round
        salsa_qr(&mut x, 0, 4, 8, 12);
        salsa_qr(&mut x, 5, 9, 13, 1);
        salsa_qr(&mut x, 10, 14, 2, 6);
        salsa_qr(&mut x, 15, 3, 7, 11);
        // Row round
        salsa_qr(&mut x, 0, 1, 2, 3);
        salsa_qr(&mut x, 5, 6, 7, 4);
        salsa_qr(&mut x, 10, 11, 8, 9);
        salsa_qr(&mut x, 15, 12, 13, 14);
    }

    // Add input
    for i in 0..16 {
        x[i] = x[i].wrapping_add(input[i]);
    }

    // Serialize back
    for i in 0..16 {
        block[4 * i..4 * i + 4].copy_from_slice(&x[i].to_le_bytes());
    }
}

/// Salsa20 quarter round.
#[inline]
fn salsa_qr(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[b] ^= x[a].wrapping_add(x[d]).rotate_left(7);
    x[c] ^= x[b].wrapping_add(x[a]).rotate_left(9);
    x[d] ^= x[c].wrapping_add(x[b]).rotate_left(13);
    x[a] ^= x[d].wrapping_add(x[c]).rotate_left(18);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // RFC 7914 §12 Test Vector 1
    #[test]
    fn test_scrypt_rfc7914_vector1() {
        let password = b"";
        let salt = b"";
        let n = 16;
        let r = 1;
        let p = 1;
        let dk_len = 64;

        let dk = scrypt(password, salt, n, r, p, dk_len).unwrap();
        assert_eq!(
            hex(&dk),
            "77d6576238657b203b19ca42c18a0497\
             f16b4844e3074ae8dfdffa3fede21442\
             fcd0069ded0948f8326a753a0fc81f17\
             e8d3e0fb2e0d3628cf35e20c38d18906"
                .replace('\n', "")
        );
    }

    // RFC 7914 §12 Test Vector 2
    #[test]
    fn test_scrypt_rfc7914_vector2() {
        let password = b"password";
        let salt = b"NaCl";
        let n = 1024;
        let r = 8;
        let p = 16;
        let dk_len = 64;

        let dk = scrypt(password, salt, n, r, p, dk_len).unwrap();
        assert_eq!(
            hex(&dk),
            "fdbabe1c9d3472007856e7190d01e9fe\
             7c6ad7cbc8237830e77376634b373162\
             2eaf30d92e22a3886ff109279d9830da\
             c727afb94a83ee6d8360cbdfa2cc0640"
                .replace('\n', "")
        );
    }

    // RFC 7914 §8 Salsa20/8 Core test vector
    #[test]
    fn test_salsa20_8_core() {
        let input = hex_to_bytes(
            "7e879a214f3ec9867ca940e641718f26\
             baee555b8c61c1b50df846116dcd3b1d\
             ee24f319df9b3d8514121e4b5ac5aa32\
             76021d2909c74829edebc68db8b8c25e",
        );
        let expected = hex_to_bytes(
            "a41f859c6608cc993b81cacb020cef05\
             044b2181a2fd337dfd7b1c6396682f29\
             b4393168e3c9e6bcfe6bc5b7a06d96ba\
             e424cc102c91745c24ad673dc7618f81",
        );
        let mut block: [u8; 64] = input.try_into().unwrap();
        super::salsa20_8_core(&mut block);
        assert_eq!(hex(&block), hex(&expected));
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_scrypt_invalid_params() {
        // N not power of 2
        assert!(scrypt(b"pw", b"salt", 3, 1, 1, 32).is_err());
        // N = 0
        assert!(scrypt(b"pw", b"salt", 0, 1, 1, 32).is_err());
        // N = 1
        assert!(scrypt(b"pw", b"salt", 1, 1, 1, 32).is_err());
        // r = 0
        assert!(scrypt(b"pw", b"salt", 16, 0, 1, 32).is_err());
        // p = 0
        assert!(scrypt(b"pw", b"salt", 16, 1, 0, 32).is_err());
    }
}
