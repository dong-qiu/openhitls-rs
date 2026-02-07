//! Polynomial operations for ML-KEM.
//!
//! CBD sampling, compression/decompression, byte encoding/decoding,
//! and rejection sampling from SHAKE XOF output.

use crate::mlkem::ntt::{self, Poly, N, Q};
use crate::sha3::{Sha3_256, Sha3_512, Shake128, Shake256};

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
pub(crate) fn sample_cbd(buf: &[u8], eta: usize) -> Poly {
    match eta {
        2 => cbd2(buf),
        3 => cbd3(buf),
        _ => panic!("Unsupported eta: {eta}"),
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

/// Compress a polynomial (each coefficient to d bits).
pub(crate) fn poly_compress(r: &Poly, d: u32) -> Vec<u8> {
    let mut out = vec![0u8; N * d as usize / 8];
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
    out
}

/// Decompress a polynomial from d-bit packed representation.
pub(crate) fn poly_decompress(data: &[u8], d: u32) -> Poly {
    let mut r = [0i16; N];
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
    r
}

/// Encode a polynomial with d-bit coefficients into bytes.
///
/// Each coefficient is treated as an unsigned value in [0, 2^d).
pub(crate) fn byte_encode(poly: &Poly, d: usize) -> Vec<u8> {
    let mut out = vec![0u8; N * d / 8];
    let mut bit_pos = 0usize;
    for &coeff in poly.iter() {
        let val = ((coeff as i32 % Q as i32 + Q as i32) % Q as i32) as u16;
        for j in 0..d {
            if val & (1 << j) != 0 {
                out[bit_pos / 8] |= 1 << (bit_pos % 8);
            }
            bit_pos += 1;
        }
    }
    out
}

/// Decode a polynomial from d-bit packed bytes.
pub(crate) fn byte_decode(data: &[u8], d: usize) -> Poly {
    let mut r = [0i16; N];
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
pub(crate) fn rej_sample(xof: &mut Shake128) -> Poly {
    let mut r = [0i16; N];
    let mut ctr = 0;
    while ctr < N {
        let buf = xof.squeeze(3).unwrap();
        let d1 = (buf[0] as u16) | ((buf[1] as u16 & 0x0F) << 8);
        let d2 = ((buf[1] as u16) >> 4) | ((buf[2] as u16) << 4);
        if d1 < Q as u16 {
            r[ctr] = d1 as i16;
            ctr += 1;
            if ctr >= N {
                break;
            }
        }
        if d2 < Q as u16 {
            r[ctr] = d2 as i16;
            ctr += 1;
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

/// PRF: SHAKE256(seed || nonce) → output_len bytes.
pub(crate) fn prf(seed: &[u8], nonce: u8, output_len: usize) -> Vec<u8> {
    let mut xof = Shake256::new();
    xof.update(seed).unwrap();
    xof.update(&[nonce]).unwrap();
    xof.squeeze(output_len).unwrap()
}

/// H: SHA3-256 hash.
pub(crate) fn hash_h(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(data).unwrap()
}

/// G: SHA3-512 hash.
pub(crate) fn hash_g(data: &[u8]) -> [u8; 64] {
    Sha3_512::digest(data).unwrap()
}

/// J: SHAKE256(input) → output_len bytes.
pub(crate) fn hash_j(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut xof = Shake256::new();
    xof.update(input).unwrap();
    xof.squeeze(output_len).unwrap()
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
}
