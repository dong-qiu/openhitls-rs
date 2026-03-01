//! Polynomial operations for ML-KEM.
//!
//! CBD sampling, compression/decompression, byte encoding/decoding,
//! and rejection sampling from SHAKE XOF output.

use crate::mlkem::ntt::{self, Poly, N, Q};
use crate::sha3::{Sha3_256, Sha3_512, Shake128, Shake256};
use hitls_types::CryptoError;

/// Centered Binomial Distribution sampling with eta = 2.
///
/// Input: 128 bytes from PRF. Output: polynomial with coefficients in [-2, 2].
pub(crate) fn cbd2(buf: &[u8]) -> Poly {
    debug_assert!(buf.len() >= 128);
    let mut r = [0i16; N];
    // Each 32-bit word yields 8 coefficients (4 bits each for eta=2)
    // 32 iterations × 4 bytes = 128 bytes, 32 × 8 = 256 coefficients
    for i in 0..N / 8 {
        let t = u32::from_le_bytes([buf[4 * i], buf[4 * i + 1], buf[4 * i + 2], buf[4 * i + 3]]);
        let d = (t & 0x5555_5555) + ((t >> 1) & 0x5555_5555);
        for j in 0..8 {
            let a = ((d >> (4 * j)) & 0x3) as i16;
            let b = ((d >> (4 * j + 2)) & 0x3) as i16;
            r[8 * i + j] = a - b;
        }
    }
    r
}

/// Centered Binomial Distribution sampling with eta = 3.
///
/// Input: 192 bytes from PRF. Output: polynomial with coefficients in [-3, 3].
pub(crate) fn cbd3(buf: &[u8]) -> Poly {
    debug_assert!(buf.len() >= 192);
    let mut r = [0i16; N];
    for i in 0..N / 4 {
        let t = u32::from_le_bytes([buf[3 * i], buf[3 * i + 1], buf[3 * i + 2], 0]) & 0x00FF_FFFF;
        let d = (t & 0x0024_9249) + ((t >> 1) & 0x0024_9249) + ((t >> 2) & 0x0024_9249);
        for j in 0..4 {
            let a = ((d >> (6 * j)) & 0x7) as i16;
            let b = ((d >> (6 * j + 3)) & 0x7) as i16;
            r[4 * i + j] = a - b;
        }
    }
    r
}

/// Sample a polynomial using CBD with the given eta.
pub(crate) fn sample_cbd(buf: &[u8], eta: usize) -> Result<Poly, CryptoError> {
    match eta {
        2 => Ok(cbd2(buf)),
        3 => Ok(cbd3(buf)),
        _ => Err(CryptoError::InvalidArg),
    }
}

/// Compress a coefficient: round(x * 2^d / q) mod 2^d.
#[inline]
fn compress_coeff(x: i16, d: u32) -> u16 {
    // Ensure x is in [0, q)
    let x = ((x as i32 % Q as i32) + Q as i32) as u32;
    (((x as u64) << d).wrapping_add(Q as u64 / 2) / Q as u64) as u16 & ((1u16 << d) - 1)
}

/// Decompress a coefficient: round(y * q / 2^d).
#[inline]
fn decompress_coeff(y: u16, d: u32) -> i16 {
    ((y as u32 * Q as u32 + (1 << (d - 1))) >> d) as i16
}

/// Compress a polynomial into caller-provided buffer (zero-allocation).
///
/// Uses byte-aligned bulk packing for d=4,5,10,11 (ML-KEM parameter values).
pub(crate) fn poly_compress_into(r: &Poly, d: u32, out: &mut [u8]) {
    match d {
        4 => {
            // 2 coefficients → 1 byte (4+4 bits)
            for i in 0..N / 2 {
                let a = compress_coeff(r[2 * i], 4) as u8;
                let b = compress_coeff(r[2 * i + 1], 4) as u8;
                out[i] = a | (b << 4);
            }
        }
        5 => {
            // 8 coefficients → 5 bytes (8×5 = 40 bits)
            for i in 0..N / 8 {
                let c: [u16; 8] = std::array::from_fn(|j| compress_coeff(r[8 * i + j], 5));
                let o = &mut out[5 * i..5 * i + 5];
                o[0] = (c[0] | (c[1] << 5)) as u8;
                o[1] = ((c[1] >> 3) | (c[2] << 2) | (c[3] << 7)) as u8;
                o[2] = ((c[3] >> 1) | (c[4] << 4)) as u8;
                o[3] = ((c[4] >> 4) | (c[5] << 1) | (c[6] << 6)) as u8;
                o[4] = ((c[6] >> 2) | (c[7] << 3)) as u8;
            }
        }
        10 => {
            // 4 coefficients → 5 bytes (4×10 = 40 bits)
            for i in 0..N / 4 {
                let c: [u16; 4] = std::array::from_fn(|j| compress_coeff(r[4 * i + j], 10));
                let o = &mut out[5 * i..5 * i + 5];
                o[0] = c[0] as u8;
                o[1] = ((c[0] >> 8) | (c[1] << 2)) as u8;
                o[2] = ((c[1] >> 6) | (c[2] << 4)) as u8;
                o[3] = ((c[2] >> 4) | (c[3] << 6)) as u8;
                o[4] = (c[3] >> 2) as u8;
            }
        }
        11 => {
            // 8 coefficients → 11 bytes (8×11 = 88 bits)
            for i in 0..N / 8 {
                let c: [u16; 8] = std::array::from_fn(|j| compress_coeff(r[8 * i + j], 11));
                let o = &mut out[11 * i..11 * i + 11];
                o[0] = c[0] as u8;
                o[1] = ((c[0] >> 8) | (c[1] << 3)) as u8;
                o[2] = ((c[1] >> 5) | (c[2] << 6)) as u8;
                o[3] = (c[2] >> 2) as u8;
                o[4] = ((c[2] >> 10) | (c[3] << 1)) as u8;
                o[5] = ((c[3] >> 7) | (c[4] << 4)) as u8;
                o[6] = ((c[4] >> 4) | (c[5] << 7)) as u8;
                o[7] = (c[5] >> 1) as u8;
                o[8] = ((c[5] >> 9) | (c[6] << 2)) as u8;
                o[9] = ((c[6] >> 6) | (c[7] << 5)) as u8;
                o[10] = (c[7] >> 3) as u8;
            }
        }
        _ => {
            // Generic bit-by-bit fallback
            out[..N * d as usize / 8].fill(0);
            let mut bit_pos = 0usize;
            for &coeff in r.iter() {
                let val = compress_coeff(coeff, d);
                for j in 0..d as usize {
                    if val & (1 << j) != 0 {
                        out[bit_pos / 8] |= 1 << (bit_pos % 8);
                    }
                    bit_pos += 1;
                }
            }
        }
    }
}

/// Compress a polynomial (allocating wrapper for tests).
pub(crate) fn poly_compress(r: &Poly, d: u32) -> Vec<u8> {
    let mut out = vec![0u8; N * d as usize / 8];
    poly_compress_into(r, d, &mut out);
    out
}

/// Decompress a polynomial from d-bit packed representation.
///
/// Uses byte-aligned bulk unpacking for d=4,5,10,11 (ML-KEM parameter values).
pub(crate) fn poly_decompress(data: &[u8], d: u32) -> Poly {
    let mut r = [0i16; N];
    match d {
        4 => {
            // 1 byte → 2 coefficients
            for i in 0..N / 2 {
                r[2 * i] = decompress_coeff(data[i] as u16 & 0xF, 4);
                r[2 * i + 1] = decompress_coeff((data[i] >> 4) as u16, 4);
            }
        }
        5 => {
            // 5 bytes → 8 coefficients
            for i in 0..N / 8 {
                let b = &data[5 * i..5 * i + 5];
                let mask = (1u16 << 5) - 1;
                r[8 * i] = decompress_coeff(b[0] as u16 & mask, 5);
                r[8 * i + 1] =
                    decompress_coeff(((b[0] as u16 >> 5) | ((b[1] as u16) << 3)) & mask, 5);
                r[8 * i + 2] = decompress_coeff((b[1] as u16 >> 2) & mask, 5);
                r[8 * i + 3] =
                    decompress_coeff(((b[1] as u16 >> 7) | ((b[2] as u16) << 1)) & mask, 5);
                r[8 * i + 4] =
                    decompress_coeff(((b[2] as u16 >> 4) | ((b[3] as u16) << 4)) & mask, 5);
                r[8 * i + 5] = decompress_coeff((b[3] as u16 >> 1) & mask, 5);
                r[8 * i + 6] =
                    decompress_coeff(((b[3] as u16 >> 6) | ((b[4] as u16) << 2)) & mask, 5);
                r[8 * i + 7] = decompress_coeff((b[4] as u16 >> 3) & mask, 5);
            }
        }
        10 => {
            // 5 bytes → 4 coefficients
            let mask = (1u16 << 10) - 1;
            for i in 0..N / 4 {
                let b = &data[5 * i..5 * i + 5];
                r[4 * i] = decompress_coeff((b[0] as u16 | ((b[1] as u16) << 8)) & mask, 10);
                r[4 * i + 1] =
                    decompress_coeff(((b[1] as u16 >> 2) | ((b[2] as u16) << 6)) & mask, 10);
                r[4 * i + 2] =
                    decompress_coeff(((b[2] as u16 >> 4) | ((b[3] as u16) << 4)) & mask, 10);
                r[4 * i + 3] =
                    decompress_coeff(((b[3] as u16 >> 6) | ((b[4] as u16) << 2)) & mask, 10);
            }
        }
        11 => {
            // 11 bytes → 8 coefficients
            let mask = (1u16 << 11) - 1;
            for i in 0..N / 8 {
                let b = &data[11 * i..11 * i + 11];
                r[8 * i] = decompress_coeff((b[0] as u16 | ((b[1] as u16) << 8)) & mask, 11);
                r[8 * i + 1] =
                    decompress_coeff(((b[1] as u16 >> 3) | ((b[2] as u16) << 5)) & mask, 11);
                r[8 * i + 2] = decompress_coeff(
                    ((b[2] as u16 >> 6) | ((b[3] as u16) << 2) | ((b[4] as u16) << 10)) & mask,
                    11,
                );
                r[8 * i + 3] =
                    decompress_coeff(((b[4] as u16 >> 1) | ((b[5] as u16) << 7)) & mask, 11);
                r[8 * i + 4] =
                    decompress_coeff(((b[5] as u16 >> 4) | ((b[6] as u16) << 4)) & mask, 11);
                r[8 * i + 5] = decompress_coeff(
                    ((b[6] as u16 >> 7) | ((b[7] as u16) << 1) | ((b[8] as u16) << 9)) & mask,
                    11,
                );
                r[8 * i + 6] =
                    decompress_coeff(((b[8] as u16 >> 2) | ((b[9] as u16) << 6)) & mask, 11);
                r[8 * i + 7] =
                    decompress_coeff(((b[9] as u16 >> 5) | ((b[10] as u16) << 3)) & mask, 11);
            }
        }
        _ => {
            // Generic bit-by-bit fallback
            let mut bit_pos = 0usize;
            for coeff in r.iter_mut() {
                let mut val = 0u16;
                for j in 0..d as usize {
                    if data[bit_pos / 8] & (1 << (bit_pos % 8)) != 0 {
                        val |= 1 << j;
                    }
                    bit_pos += 1;
                }
                *coeff = decompress_coeff(val, d);
            }
        }
    }
    r
}

/// Encode a polynomial into caller-provided buffer (zero-allocation).
///
/// Uses byte-aligned bulk packing for d=1,12 (ML-KEM encode values).
pub(crate) fn byte_encode_into(poly: &Poly, d: usize, out: &mut [u8]) {
    // Normalize coefficient to [0, q)
    #[inline]
    fn normalize(c: i16) -> u16 {
        ((c as i32 % Q as i32 + Q as i32) % Q as i32) as u16
    }

    match d {
        1 => {
            // 8 coefficients → 1 byte (message encoding)
            for i in 0..N / 8 {
                let mut byte = 0u8;
                for j in 0..8 {
                    byte |= (normalize(poly[8 * i + j]) as u8 & 1) << j;
                }
                out[i] = byte;
            }
        }
        12 => {
            // 2 coefficients → 3 bytes (2×12 = 24 bits, NTT encoding)
            for i in 0..N / 2 {
                let a = normalize(poly[2 * i]);
                let b = normalize(poly[2 * i + 1]);
                out[3 * i] = a as u8;
                out[3 * i + 1] = ((a >> 8) | (b << 4)) as u8;
                out[3 * i + 2] = (b >> 4) as u8;
            }
        }
        _ => {
            // Generic bit-by-bit fallback
            out[..N * d / 8].fill(0);
            let mut bit_pos = 0usize;
            for &coeff in poly.iter() {
                let val = normalize(coeff);
                for j in 0..d {
                    if val & (1 << j) != 0 {
                        out[bit_pos / 8] |= 1 << (bit_pos % 8);
                    }
                    bit_pos += 1;
                }
            }
        }
    }
}

/// Encode a polynomial with d-bit coefficients into bytes (allocating wrapper).
pub(crate) fn byte_encode(poly: &Poly, d: usize) -> Vec<u8> {
    let mut out = vec![0u8; N * d / 8];
    byte_encode_into(poly, d, &mut out);
    out
}

/// Decode a polynomial from d-bit packed bytes.
///
/// Uses byte-aligned bulk unpacking for d=1,12 (ML-KEM decode values).
pub(crate) fn byte_decode(data: &[u8], d: usize) -> Poly {
    let mut r = [0i16; N];
    match d {
        1 => {
            // 1 byte → 8 coefficients (message decoding)
            for i in 0..N / 8 {
                let byte = data[i];
                for j in 0..8 {
                    r[8 * i + j] = ((byte >> j) & 1) as i16;
                }
            }
        }
        12 => {
            // 3 bytes → 2 coefficients (NTT decoding)
            for i in 0..N / 2 {
                let b = &data[3 * i..3 * i + 3];
                r[2 * i] = (b[0] as i16 | ((b[1] as i16 & 0xF) << 8)) & 0xFFF;
                r[2 * i + 1] = ((b[1] as i16 >> 4) | ((b[2] as i16) << 4)) & 0xFFF;
            }
        }
        _ => {
            // Generic bit-by-bit fallback
            let mut bit_pos = 0usize;
            for coeff in r.iter_mut() {
                let mut val = 0u16;
                for j in 0..d {
                    if data[bit_pos / 8] & (1 << (bit_pos % 8)) != 0 {
                        val |= 1 << j;
                    }
                    bit_pos += 1;
                }
                *coeff = val as i16;
            }
        }
    }
    r
}

/// Encode a message (32 bytes) into a polynomial.
///
/// Each bit of m becomes a coefficient: 0 → 0, 1 → round(q/2).
pub(crate) fn msg_to_poly(msg: &[u8; 32]) -> Poly {
    let mut r = [0i16; N];
    for i in 0..32 {
        for j in 0..8 {
            if msg[i] & (1 << j) != 0 {
                r[8 * i + j] = (Q + 1) / 2; // round(q/2) = 1665
            }
        }
    }
    r
}

/// Decode a polynomial back to a 32-byte message.
///
/// Each coefficient is compressed to 1 bit.
pub(crate) fn poly_to_msg(poly: &Poly) -> [u8; 32] {
    let mut msg = [0u8; 32];
    for i in 0..N {
        // Compress to 1 bit: round(2*x/q) mod 2
        let t = compress_coeff(poly[i], 1);
        if t & 1 != 0 {
            msg[i / 8] |= 1 << (i % 8);
        }
    }
    msg
}

/// Rejection sampling: generate a polynomial from SHAKE128 XOF output.
///
/// Parse 3-byte chunks into two 12-bit candidates, reject if >= q.
/// Squeezes in 504-byte blocks (3 × SHAKE-128 rate) to minimize allocations.
pub(crate) fn rej_sample(xof: &mut Shake128) -> Poly {
    let mut r = [0i16; N];
    let mut ctr = 0;
    // Squeeze 504 bytes at once (3 SHAKE-128 blocks of 168 bytes).
    // This yields ~336 12-bit candidates; we need ~341 on average (256/0.75).
    while ctr < N {
        let mut block = [0u8; 504];
        xof.squeeze_into(&mut block);
        let mut pos = 0;
        while pos + 2 < block.len() && ctr < N {
            let d1 = (block[pos] as u16) | ((block[pos + 1] as u16 & 0x0F) << 8);
            let d2 = ((block[pos + 1] as u16) >> 4) | ((block[pos + 2] as u16) << 4);
            pos += 3;
            if d1 < Q as u16 {
                r[ctr] = d1 as i16;
                ctr += 1;
            }
            if ctr < N && d2 < Q as u16 {
                r[ctr] = d2 as i16;
                ctr += 1;
            }
        }
    }
    r
}

/// ExpandA: generate the k×k matrix A from seed ρ using SHAKE128.
///
/// Each A[i][j] is sampled via SHAKE128(ρ || j || i).
pub(crate) fn expand_a(rho: &[u8; 32], k: usize) -> Vec<Vec<Poly>> {
    let mut a = vec![vec![[0i16; N]; k]; k];
    for (i, row) in a.iter_mut().enumerate() {
        for (j, entry) in row.iter_mut().enumerate() {
            let mut xof = Shake128::new();
            xof.update(rho).unwrap();
            xof.update(&[j as u8, i as u8]).unwrap();
            *entry = rej_sample(&mut xof);
        }
    }
    a
}

/// PRF: SHAKE256(seed || nonce) squeezed into caller-provided buffer.
pub(crate) fn prf_into(seed: &[u8], nonce: u8, output: &mut [u8]) {
    let mut xof = Shake256::new();
    xof.update(seed).unwrap();
    xof.update(&[nonce]).unwrap();
    xof.squeeze_into(output);
}

/// H: SHA3-256 hash.
pub(crate) fn hash_h(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(data).unwrap()
}

/// G: SHA3-512 hash.
pub(crate) fn hash_g(data: &[u8]) -> [u8; 64] {
    Sha3_512::digest(data).unwrap()
}

/// J: SHAKE256(input) squeezed into caller-provided buffer.
pub(crate) fn hash_j_into(input: &[u8], output: &mut [u8]) {
    let mut xof = Shake256::new();
    xof.update(input).unwrap();
    xof.squeeze_into(output);
}

/// Matrix-vector product in NTT domain: r = A_hat * s_hat.
///
/// A is k×k, s is k polynomials. r is k polynomials.
pub(crate) fn matvec_mul(a_hat: &[Vec<Poly>], s_hat: &[Poly], k: usize) -> Vec<Poly> {
    let mut r = vec![[0i16; N]; k];
    for i in 0..k {
        ntt::basemul_acc(&mut r[i], &a_hat[i], s_hat);
    }
    r
}

/// Transpose matrix-vector product in NTT domain: r = A_hat^T * s_hat.
pub(crate) fn matvec_mul_t(a_hat: &[Vec<Poly>], s_hat: &[Poly], k: usize) -> Vec<Poly> {
    let mut r = vec![[0i16; N]; k];
    for i in 0..k {
        // Column i of A^T = row i of A
        let col: Vec<Poly> = (0..k).map(|j| a_hat[j][i]).collect();
        ntt::basemul_acc(&mut r[i], &col, s_hat);
    }
    r
}

/// Inner product of two vectors of polynomials in NTT domain.
pub(crate) fn inner_product(a: &[Poly], b: &[Poly]) -> Poly {
    let mut r = [0i16; N];
    ntt::basemul_acc(&mut r, a, b);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbd2_range() {
        let buf = [0x55u8; 128]; // Arbitrary data
        let poly = cbd2(&buf);
        for &c in &poly {
            assert!((-2..=2).contains(&c), "CBD2 coeff out of range: {c}");
        }
    }

    #[test]
    fn test_cbd3_range() {
        let buf = [0xAAu8; 192];
        let poly = cbd3(&buf);
        for &c in &poly {
            assert!((-3..=3).contains(&c), "CBD3 coeff out of range: {c}");
        }
    }

    #[test]
    fn test_compress_decompress() {
        // Compress then decompress should be approximately identity
        for d in [1u32, 4, 5, 10, 11] {
            let x: i16 = 1234;
            let c = compress_coeff(x, d);
            let y = decompress_coeff(c, d);
            // The error should be small: |x - y| < q / 2^d
            let err = ((x - y) as i32 + Q as i32) % Q as i32;
            let err = if err > Q as i32 / 2 {
                Q as i32 - err
            } else {
                err
            };
            let max_err = Q as i32 / (1 << d) + 1;
            assert!(err <= max_err, "d={d}: err={err} > max_err={max_err}");
        }
    }

    #[test]
    fn test_byte_encode_decode_roundtrip() {
        for d in [1usize, 4, 10, 12] {
            let mut poly = [0i16; N];
            let max_val = if d == 12 { Q - 1 } else { (1i16 << d) - 1 };
            for (i, coeff) in poly.iter_mut().enumerate() {
                *coeff = (i as i16 * 13 + 7) % (max_val + 1);
            }
            let encoded = byte_encode(&poly, d);
            let decoded = byte_decode(&encoded, d);
            for i in 0..N {
                let expected = ((poly[i] as i32 % Q as i32 + Q as i32) % Q as i32) as u16;
                let expected_masked = expected & ((1u16 << d) - 1);
                assert_eq!(
                    decoded[i] as u16, expected_masked,
                    "d={d}, i={i}: expected {expected_masked}, got {}",
                    decoded[i]
                );
            }
        }
    }

    #[test]
    fn test_msg_poly_roundtrip() {
        let msg: [u8; 32] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC,
            0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xAA, 0x55, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88,
        ];
        let poly = msg_to_poly(&msg);
        let recovered = poly_to_msg(&poly);
        assert_eq!(msg, recovered);
    }

    #[test]
    fn test_cbd2_zero_input() {
        let buf = [0u8; 128];
        let poly = cbd2(&buf);
        // All zero input → all zero coefficients (a=0, b=0 for each)
        for &c in &poly {
            assert_eq!(c, 0, "CBD2 of zero input should produce zero coefficients");
        }
    }

    #[test]
    fn test_cbd3_zero_input() {
        let buf = [0u8; 192];
        let poly = cbd3(&buf);
        for &c in &poly {
            assert_eq!(c, 0, "CBD3 of zero input should produce zero coefficients");
        }
    }

    #[test]
    fn test_sample_cbd_invalid_eta() {
        let buf = [0u8; 192];
        assert!(sample_cbd(&buf, 2).is_ok());
        assert!(sample_cbd(&buf, 3).is_ok());
        assert!(sample_cbd(&buf, 1).is_err());
        assert!(sample_cbd(&buf, 4).is_err());
        assert!(sample_cbd(&buf, 0).is_err());
    }

    #[test]
    fn test_poly_compress_decompress_full() {
        // Create a polynomial with known values and roundtrip through compress/decompress
        let mut poly = [0i16; N];
        for (i, c) in poly.iter_mut().enumerate() {
            *c = (i as i16 * 37 + 11) % Q;
        }
        for d in [4u32, 5, 10, 11] {
            let compressed = poly_compress(&poly, d);
            let decompressed = poly_decompress(&compressed, d);
            // Each coefficient error should be bounded by q / 2^(d+1)
            for i in 0..N {
                let orig = ((poly[i] as i32 % Q as i32) + Q as i32) % Q as i32;
                let recov = decompressed[i] as i32;
                let err = (orig - recov + Q as i32) % Q as i32;
                let err = err.min(Q as i32 - err);
                let max_err = Q as i32 / (1 << d) + 1;
                assert!(
                    err <= max_err,
                    "d={d}, i={i}: err={err} > max_err={max_err}"
                );
            }
        }
    }

    #[test]
    fn test_msg_all_zeros_all_ones() {
        // All zeros → all zero coefficients → recovers all zeros
        let zeros = [0u8; 32];
        let poly_z = msg_to_poly(&zeros);
        for &c in &poly_z {
            assert_eq!(c, 0);
        }
        assert_eq!(poly_to_msg(&poly_z), zeros);

        // All ones → all coefficients = round(q/2)
        let ones = [0xFFu8; 32];
        let poly_o = msg_to_poly(&ones);
        let half_q = (Q + 1) / 2;
        for &c in &poly_o {
            assert_eq!(c, half_q);
        }
        assert_eq!(poly_to_msg(&poly_o), ones);
    }
}
