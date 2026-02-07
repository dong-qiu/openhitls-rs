//! Polynomial operations for ML-DSA (FIPS 204).
//!
//! Power2Round, Decompose, HighBits/LowBits, MakeHint/UseHint,
//! rejection sampling, bit packing, and hash wrappers.

use crate::mldsa::ntt::{self, Poly, D, N, Q};
use crate::sha3::{Shake128, Shake256};

// ─── Power2Round / Decompose / Hints ────────────────────────────

/// Power2Round: decompose r into (r1, r0) such that r ≡ r1·2^D + r0.
/// r must be in [0, q). Returns r1 in [0, (q-1)/2^D] and r0 in [-(2^{D-1}-1), 2^{D-1}].
#[inline]
pub(crate) fn power2round(r: i32) -> (i32, i32) {
    let r1 = (r + (1 << (D - 1)) - 1) >> D;
    let r0 = r - (r1 << D);
    (r1, r0)
}

/// Decompose: for a in [0, q), compute (a1, a0) where a ≡ a1·2γ₂ + a0.
/// Returns a0 ∈ (-γ₂, γ₂] and a1.
pub(crate) fn decompose(a: i32, gamma2: i32) -> (i32, i32) {
    let mut a1 = (a + 127) >> 7;
    if gamma2 == (Q - 1) / 32 {
        // gamma2 = 261888
        a1 = (a1 * 1025 + (1 << 21)) >> 22;
        a1 &= 15;
    } else {
        // gamma2 = 95232 = (Q-1)/88
        a1 = (a1 * 11275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    }
    let mut a0 = a - a1 * 2 * gamma2;
    // Adjust: if a0 > gamma2, reduce
    a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;
    (a1, a0)
}

/// HighBits: return the high part of a decomposition.
#[inline]
pub(crate) fn highbits(r: i32, gamma2: i32) -> i32 {
    decompose(r, gamma2).0
}

/// LowBits: return the low part of a decomposition.
#[inline]
pub(crate) fn lowbits(r: i32, gamma2: i32) -> i32 {
    decompose(r, gamma2).1
}

/// MakeHint: determine if adding z to r changes the high bits.
pub(crate) fn make_hint(z: i32, r: i32, gamma2: i32) -> bool {
    let r1 = highbits(r, gamma2);
    let v1 = highbits(ntt::freeze(r + z), gamma2);
    r1 != v1
}

/// UseHint: recover the correct high bits using a hint.
pub(crate) fn use_hint(hint: bool, r: i32, gamma2: i32) -> i32 {
    let (r1, r0) = decompose(r, gamma2);
    if !hint {
        return r1;
    }
    let m = if gamma2 == (Q - 1) / 32 { 16 } else { 44 };
    if r0 > 0 {
        (r1 + 1) % m
    } else {
        (r1 - 1 + m) % m
    }
}

// ─── Rejection sampling ─────────────────────────────────────────

/// Sample a polynomial in NTT domain from SHAKE128 (ExpandA, Algorithm 30).
/// Input: seed ρ and matrix indices (i, j).
pub(crate) fn rej_ntt_poly(rho: &[u8; 32], i: u8, j: u8) -> Poly {
    let mut xof = Shake128::new();
    xof.update(rho).unwrap();
    xof.update(&[j, i]).unwrap();

    let mut r = [0i32; N];
    let mut ctr = 0;
    while ctr < N {
        let buf = xof.squeeze(3).unwrap();
        let mut t = (buf[0] as u32) | ((buf[1] as u32) << 8) | ((buf[2] as u32) << 16);
        t &= 0x7F_FFFF; // 23-bit candidate
        if t < Q as u32 {
            r[ctr] = t as i32;
            ctr += 1;
        }
    }
    r
}

/// ExpandA: generate the k×l matrix A from seed ρ.
pub(crate) fn expand_a(rho: &[u8; 32], k: usize, l: usize) -> Vec<Vec<Poly>> {
    let mut a = vec![vec![[0i32; N]; l]; k];
    for (i, row) in a.iter_mut().enumerate() {
        for (j, entry) in row.iter_mut().enumerate() {
            *entry = rej_ntt_poly(rho, i as u8, j as u8);
        }
    }
    a
}

/// Sample a polynomial with coefficients in [-eta, eta] using rejection (ExpandS).
pub(crate) fn rej_bounded_poly(sigma: &[u8], eta: usize, nonce: u16) -> Poly {
    let mut xof = Shake256::new();
    xof.update(sigma).unwrap();
    xof.update(&nonce.to_le_bytes()).unwrap();

    let mut r = [0i32; N];
    let mut ctr = 0;
    while ctr < N {
        let buf = xof.squeeze(1).unwrap();
        let b0 = (buf[0] & 0x0F) as i32;
        let b1 = (buf[0] >> 4) as i32;
        if eta == 2 {
            if b0 < 15 {
                r[ctr] = 2 - (b0 % 5);
                ctr += 1;
            }
            if ctr < N && b1 < 15 {
                r[ctr] = 2 - (b1 % 5);
                ctr += 1;
            }
        } else {
            // eta == 4
            if b0 < 9 {
                r[ctr] = 4 - b0;
                ctr += 1;
            }
            if ctr < N && b1 < 9 {
                r[ctr] = 4 - b1;
                ctr += 1;
            }
        }
    }
    r
}

/// ExpandMask: sample a polynomial with coefficients in [-gamma1+1, gamma1].
pub(crate) fn sample_mask_poly(seed: &[u8], nonce: u16, gamma1: i32) -> Poly {
    let mut xof = Shake256::new();
    xof.update(seed).unwrap();
    xof.update(&nonce.to_le_bytes()).unwrap();

    let bits = if gamma1 == (1 << 17) { 18 } else { 20 }; // gamma1 = 2^17 or 2^19
    let bytes_needed = N * bits / 8;
    let buf = xof.squeeze(bytes_needed).unwrap();

    let mut r = [0i32; N];
    if bits == 18 {
        // Pack 4 coefficients per 9 bytes (4 × 18 = 72 bits = 9 bytes)
        for i in 0..N / 4 {
            let off = 9 * i;
            r[4 * i] = (buf[off] as i32)
                | ((buf[off + 1] as i32) << 8)
                | ((buf[off + 2] as i32 & 0x03) << 16);
            r[4 * i] &= 0x3FFFF;
            r[4 * i] = gamma1 - r[4 * i];

            r[4 * i + 1] = ((buf[off + 2] as i32) >> 2)
                | ((buf[off + 3] as i32) << 6)
                | ((buf[off + 4] as i32 & 0x0F) << 14);
            r[4 * i + 1] &= 0x3FFFF;
            r[4 * i + 1] = gamma1 - r[4 * i + 1];

            r[4 * i + 2] = ((buf[off + 4] as i32) >> 4)
                | ((buf[off + 5] as i32) << 4)
                | ((buf[off + 6] as i32 & 0x3F) << 12);
            r[4 * i + 2] &= 0x3FFFF;
            r[4 * i + 2] = gamma1 - r[4 * i + 2];

            r[4 * i + 3] = ((buf[off + 6] as i32) >> 6)
                | ((buf[off + 7] as i32) << 2)
                | ((buf[off + 8] as i32) << 10);
            r[4 * i + 3] &= 0x3FFFF;
            r[4 * i + 3] = gamma1 - r[4 * i + 3];
        }
    } else {
        // bits == 20: Pack 4 coefficients per 10 bytes (5 bytes per 2 coefficients)
        for i in 0..N / 2 {
            let off = 5 * i;
            r[2 * i] = (buf[off] as i32)
                | ((buf[off + 1] as i32) << 8)
                | ((buf[off + 2] as i32 & 0x0F) << 16);
            r[2 * i] &= 0xFFFFF;
            r[2 * i] = gamma1 - r[2 * i];
            r[2 * i + 1] = ((buf[off + 2] as i32) >> 4)
                | ((buf[off + 3] as i32) << 4)
                | ((buf[off + 4] as i32) << 12);
            r[2 * i + 1] &= 0xFFFFF;
            r[2 * i + 1] = gamma1 - r[2 * i + 1];
        }
    }
    r
}

/// SampleInBall: generate a sparse polynomial c with exactly τ non-zero coefficients (±1).
pub(crate) fn sample_in_ball(seed: &[u8], tau: usize) -> Poly {
    let mut xof = Shake256::new();
    xof.update(seed).unwrap();

    let sign_bytes = xof.squeeze(8).unwrap();
    let mut signs: u64 = 0;
    for (i, &byte) in sign_bytes.iter().enumerate() {
        signs |= (byte as u64) << (8 * i);
    }

    let mut c = [0i32; N];
    for i in (N - tau)..N {
        // Sample j uniformly from [0, i]
        let mut j;
        loop {
            let buf = xof.squeeze(1).unwrap();
            j = buf[0] as usize;
            if j <= i {
                break;
            }
        }
        c[i] = c[j];
        c[j] = 1 - 2 * (signs & 1) as i32;
        signs >>= 1;
    }
    c
}

// ─── Bit packing ────────────────────────────────────────────────

/// Pack t1 (10-bit coefficients) into bytes. Each coefficient in [0, 1023].
pub(crate) fn pack_t1(poly: &Poly) -> Vec<u8> {
    let mut out = vec![0u8; 320]; // 256 * 10 / 8
    for i in 0..N / 4 {
        let idx = 4 * i;
        out[5 * i] = poly[idx] as u8;
        out[5 * i + 1] = ((poly[idx] >> 8) | (poly[idx + 1] << 2)) as u8;
        out[5 * i + 2] = ((poly[idx + 1] >> 6) | (poly[idx + 2] << 4)) as u8;
        out[5 * i + 3] = ((poly[idx + 2] >> 4) | (poly[idx + 3] << 6)) as u8;
        out[5 * i + 4] = (poly[idx + 3] >> 2) as u8;
    }
    out
}

/// Unpack t1 from 10-bit packed bytes.
pub(crate) fn unpack_t1(data: &[u8]) -> Poly {
    let mut r = [0i32; N];
    for i in 0..N / 4 {
        let idx = 4 * i;
        r[idx] = ((data[5 * i] as i32) | ((data[5 * i + 1] as i32) << 8)) & 0x3FF;
        r[idx + 1] = (((data[5 * i + 1] as i32) >> 2) | ((data[5 * i + 2] as i32) << 6)) & 0x3FF;
        r[idx + 2] = (((data[5 * i + 2] as i32) >> 4) | ((data[5 * i + 3] as i32) << 4)) & 0x3FF;
        r[idx + 3] = (((data[5 * i + 3] as i32) >> 6) | ((data[5 * i + 4] as i32) << 2)) & 0x3FF;
    }
    r
}

/// Pack t0 (13-bit signed coefficients). Each coefficient in [-(2^{D-1}-1), 2^{D-1}].
pub(crate) fn pack_t0(poly: &Poly) -> Vec<u8> {
    let mut out = vec![0u8; 416]; // 256 * 13 / 8
    for i in 0..N / 8 {
        let mut t = [0i32; 8];
        for j in 0..8 {
            t[j] = (1 << (D - 1)) - poly[8 * i + j]; // Map to unsigned
        }
        out[13 * i] = t[0] as u8;
        out[13 * i + 1] = (t[0] >> 8) as u8 | ((t[1] << 5) as u8);
        out[13 * i + 2] = (t[1] >> 3) as u8;
        out[13 * i + 3] = (t[1] >> 11) as u8 | ((t[2] << 2) as u8);
        out[13 * i + 4] = (t[2] >> 6) as u8 | ((t[3] << 7) as u8);
        out[13 * i + 5] = (t[3] >> 1) as u8;
        out[13 * i + 6] = (t[3] >> 9) as u8 | ((t[4] << 4) as u8);
        out[13 * i + 7] = (t[4] >> 4) as u8;
        out[13 * i + 8] = (t[4] >> 12) as u8 | ((t[5] << 1) as u8);
        out[13 * i + 9] = (t[5] >> 7) as u8 | ((t[6] << 6) as u8);
        out[13 * i + 10] = (t[6] >> 2) as u8;
        out[13 * i + 11] = (t[6] >> 10) as u8 | ((t[7] << 3) as u8);
        out[13 * i + 12] = (t[7] >> 5) as u8;
    }
    out
}

/// Unpack t0 from 13-bit packed bytes.
pub(crate) fn unpack_t0(data: &[u8]) -> Poly {
    let mut r = [0i32; N];
    for i in 0..N / 8 {
        r[8 * i] = (data[13 * i] as i32) | ((data[13 * i + 1] as i32 & 0x1F) << 8);
        r[8 * i + 1] = ((data[13 * i + 1] as i32) >> 5)
            | ((data[13 * i + 2] as i32) << 3)
            | ((data[13 * i + 3] as i32 & 0x03) << 11);
        r[8 * i + 2] = ((data[13 * i + 3] as i32) >> 2) | ((data[13 * i + 4] as i32 & 0x7F) << 6);
        r[8 * i + 3] = ((data[13 * i + 4] as i32) >> 7)
            | ((data[13 * i + 5] as i32) << 1)
            | ((data[13 * i + 6] as i32 & 0x0F) << 9);
        r[8 * i + 4] = ((data[13 * i + 6] as i32) >> 4)
            | ((data[13 * i + 7] as i32) << 4)
            | ((data[13 * i + 8] as i32 & 0x01) << 12);
        r[8 * i + 5] = ((data[13 * i + 8] as i32) >> 1) | ((data[13 * i + 9] as i32 & 0x3F) << 7);
        r[8 * i + 6] = ((data[13 * i + 9] as i32) >> 6)
            | ((data[13 * i + 10] as i32) << 2)
            | ((data[13 * i + 11] as i32 & 0x07) << 10);
        r[8 * i + 7] = ((data[13 * i + 11] as i32) >> 3) | ((data[13 * i + 12] as i32) << 5);
        // Convert from unsigned to signed
        for j in 0..8 {
            r[8 * i + j] = (1 << (D - 1)) - (r[8 * i + j] & 0x1FFF);
        }
    }
    r
}

/// Pack eta-bounded polynomial. Coefficients in [-eta, eta].
pub(crate) fn pack_eta(poly: &Poly, eta: usize) -> Vec<u8> {
    if eta == 2 {
        // 3-bit packing: 8 coefficients per 3 bytes
        let mut out = vec![0u8; 96]; // 256 * 3 / 8
        for i in 0..N / 8 {
            let mut t = [0u8; 8];
            for j in 0..8 {
                t[j] = (eta as i32 - poly[8 * i + j]) as u8;
            }
            out[3 * i] = t[0] | (t[1] << 3) | (t[2] << 6);
            out[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
            out[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
        }
        out
    } else {
        // eta == 4: 4-bit packing: 2 coefficients per byte
        let mut out = vec![0u8; 128]; // 256 * 4 / 8
        for i in 0..N / 2 {
            let t0 = (eta as i32 - poly[2 * i]) as u8;
            let t1 = (eta as i32 - poly[2 * i + 1]) as u8;
            out[i] = t0 | (t1 << 4);
        }
        out
    }
}

/// Unpack eta-bounded polynomial.
pub(crate) fn unpack_eta(data: &[u8], eta: usize) -> Poly {
    let mut r = [0i32; N];
    if eta == 2 {
        for i in 0..N / 8 {
            r[8 * i] = (data[3 * i] & 0x07) as i32;
            r[8 * i + 1] = ((data[3 * i] >> 3) & 0x07) as i32;
            r[8 * i + 2] = (((data[3 * i] >> 6) | (data[3 * i + 1] << 2)) & 0x07) as i32;
            r[8 * i + 3] = ((data[3 * i + 1] >> 1) & 0x07) as i32;
            r[8 * i + 4] = ((data[3 * i + 1] >> 4) & 0x07) as i32;
            r[8 * i + 5] = (((data[3 * i + 1] >> 7) | (data[3 * i + 2] << 1)) & 0x07) as i32;
            r[8 * i + 6] = ((data[3 * i + 2] >> 2) & 0x07) as i32;
            r[8 * i + 7] = ((data[3 * i + 2] >> 5) & 0x07) as i32;
            for j in 0..8 {
                r[8 * i + j] = eta as i32 - r[8 * i + j];
            }
        }
    } else {
        // eta == 4
        for i in 0..N / 2 {
            r[2 * i] = (data[i] & 0x0F) as i32;
            r[2 * i + 1] = (data[i] >> 4) as i32;
            r[2 * i] = eta as i32 - r[2 * i];
            r[2 * i + 1] = eta as i32 - r[2 * i + 1];
        }
    }
    r
}

/// Pack z polynomial (gamma1-bounded signed coefficients).
pub(crate) fn pack_z(poly: &Poly, gamma1: i32) -> Vec<u8> {
    if gamma1 == (1 << 17) {
        // 18-bit packing
        let mut out = vec![0u8; 576]; // 256 * 18 / 8
        for i in 0..N / 4 {
            let mut t = [0i32; 4];
            for j in 0..4 {
                t[j] = gamma1 - poly[4 * i + j];
            }
            out[9 * i] = t[0] as u8;
            out[9 * i + 1] = (t[0] >> 8) as u8;
            out[9 * i + 2] = ((t[0] >> 16) | (t[1] << 2)) as u8;
            out[9 * i + 3] = (t[1] >> 6) as u8;
            out[9 * i + 4] = ((t[1] >> 14) | (t[2] << 4)) as u8;
            out[9 * i + 5] = (t[2] >> 4) as u8;
            out[9 * i + 6] = ((t[2] >> 12) | (t[3] << 6)) as u8;
            out[9 * i + 7] = (t[3] >> 2) as u8;
            out[9 * i + 8] = (t[3] >> 10) as u8;
        }
        out
    } else {
        // gamma1 == 2^19, 20-bit packing
        let mut out = vec![0u8; 640]; // 256 * 20 / 8
        for i in 0..N / 2 {
            let t0 = gamma1 - poly[2 * i];
            let t1 = gamma1 - poly[2 * i + 1];
            out[5 * i] = t0 as u8;
            out[5 * i + 1] = (t0 >> 8) as u8;
            out[5 * i + 2] = ((t0 >> 16) | (t1 << 4)) as u8;
            out[5 * i + 3] = (t1 >> 4) as u8;
            out[5 * i + 4] = (t1 >> 12) as u8;
        }
        out
    }
}

/// Unpack z polynomial.
pub(crate) fn unpack_z(data: &[u8], gamma1: i32) -> Poly {
    let mut r = [0i32; N];
    if gamma1 == (1 << 17) {
        for i in 0..N / 4 {
            r[4 * i] = (data[9 * i] as i32)
                | ((data[9 * i + 1] as i32) << 8)
                | ((data[9 * i + 2] as i32 & 0x03) << 16);
            r[4 * i + 1] = ((data[9 * i + 2] as i32) >> 2)
                | ((data[9 * i + 3] as i32) << 6)
                | ((data[9 * i + 4] as i32 & 0x0F) << 14);
            r[4 * i + 2] = ((data[9 * i + 4] as i32) >> 4)
                | ((data[9 * i + 5] as i32) << 4)
                | ((data[9 * i + 6] as i32 & 0x3F) << 12);
            r[4 * i + 3] = ((data[9 * i + 6] as i32) >> 6)
                | ((data[9 * i + 7] as i32) << 2)
                | ((data[9 * i + 8] as i32) << 10);
            for j in 0..4 {
                r[4 * i + j] &= 0x3FFFF;
                r[4 * i + j] = gamma1 - r[4 * i + j];
            }
        }
    } else {
        // gamma1 == 2^19
        for i in 0..N / 2 {
            r[2 * i] = (data[5 * i] as i32)
                | ((data[5 * i + 1] as i32) << 8)
                | ((data[5 * i + 2] as i32 & 0x0F) << 16);
            r[2 * i + 1] = ((data[5 * i + 2] as i32) >> 4)
                | ((data[5 * i + 3] as i32) << 4)
                | ((data[5 * i + 4] as i32) << 12);
            r[2 * i] &= 0xFFFFF;
            r[2 * i + 1] &= 0xFFFFF;
            r[2 * i] = gamma1 - r[2 * i];
            r[2 * i + 1] = gamma1 - r[2 * i + 1];
        }
    }
    r
}

/// Pack w1 coefficients (for challenge hash computation).
/// ML-DSA-44: gamma2=(Q-1)/88, w1 in [0, 43], 6-bit packing → 192 bytes
/// ML-DSA-65/87: gamma2=(Q-1)/32, w1 in [0, 15], 4-bit packing → 128 bytes
pub(crate) fn pack_w1(poly: &Poly, gamma2: i32) -> Vec<u8> {
    if gamma2 == (Q - 1) / 88 {
        // 6-bit packing
        let mut out = vec![0u8; 192]; // 256 * 6 / 8
        for i in 0..N / 4 {
            out[3 * i] = (poly[4 * i] | (poly[4 * i + 1] << 6)) as u8;
            out[3 * i + 1] = ((poly[4 * i + 1] >> 2) | (poly[4 * i + 2] << 4)) as u8;
            out[3 * i + 2] = ((poly[4 * i + 2] >> 4) | (poly[4 * i + 3] << 2)) as u8;
        }
        out
    } else {
        // 4-bit packing
        let mut out = vec![0u8; 128]; // 256 * 4 / 8
        for i in 0..N / 2 {
            out[i] = (poly[2 * i] | (poly[2 * i + 1] << 4)) as u8;
        }
        out
    }
}

// ─── Hash wrappers ──────────────────────────────────────────────

/// H: SHAKE256(input, output_len).
pub(crate) fn hash_h(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut xof = Shake256::new();
    xof.update(input).unwrap();
    xof.squeeze(output_len).unwrap()
}

/// H with two inputs concatenated.
pub(crate) fn hash_h2(a: &[u8], b: &[u8], output_len: usize) -> Vec<u8> {
    let mut xof = Shake256::new();
    xof.update(a).unwrap();
    xof.update(b).unwrap();
    xof.squeeze(output_len).unwrap()
}

// ─── Vector/Matrix operations ───────────────────────────────────

/// Matrix-vector product in NTT domain: r = A * s.
pub(crate) fn matvec_mul(a_hat: &[Vec<Poly>], s_hat: &[Poly], k: usize, l: usize) -> Vec<Poly> {
    let mut r = vec![[0i32; N]; k];
    for i in 0..k {
        for j in 0..l {
            ntt::pointwise_mul_acc(&mut r[i], &a_hat[i][j], &s_hat[j]);
        }
    }
    r
}

/// Compute infinity norm of a polynomial.
pub(crate) fn poly_chknorm(poly: &Poly, bound: i32) -> bool {
    for &c in poly.iter() {
        let t = if c < 0 { -c } else { c };
        if t >= bound {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_power2round() {
        // power2round(r) = (r1, r0) where r1 * 2^D + r0 = r
        for r in [0, 1, 4095, 4096, 8380416, 100000] {
            let (r1, r0) = power2round(r);
            assert_eq!(
                r1 * (1 << D) + r0,
                r,
                "Power2Round failed for r={r}: r1={r1}, r0={r0}"
            );
        }
    }

    #[test]
    fn test_decompose_lowbits_highbits() {
        let gamma2 = (Q - 1) / 32; // 261888
        for a in [0, 1000, 261888, 523776, 8380416] {
            let (a1, a0) = decompose(a, gamma2);
            let reconstructed = a1 * 2 * gamma2 + a0;
            let diff = ((reconstructed - a) % Q + Q) % Q;
            assert!(
                diff == 0 || diff == Q,
                "Decompose failed for a={a}: a1={a1}, a0={a0}, reconstructed={reconstructed}"
            );
            assert!(a0 >= -gamma2 && a0 <= gamma2, "a0 out of range: {a0}");
        }
    }

    #[test]
    fn test_pack_unpack_t1() {
        let mut poly = [0i32; N];
        for (i, coeff) in poly.iter_mut().enumerate() {
            *coeff = (i as i32 * 3 + 7) % 1024;
        }
        let packed = pack_t1(&poly);
        let unpacked = unpack_t1(&packed);
        assert_eq!(poly, unpacked);
    }

    #[test]
    fn test_pack_unpack_t0() {
        let mut poly = [0i32; N];
        for (i, coeff) in poly.iter_mut().enumerate() {
            let val = (i as i32 * 13 + 3) % (1 << D);
            *coeff = val - (1 << (D - 1));
            if *coeff > (1 << (D - 1)) {
                *coeff -= 1 << D;
            }
        }
        let packed = pack_t0(&poly);
        let unpacked = unpack_t0(&packed);
        for i in 0..N {
            assert_eq!(
                poly[i], unpacked[i],
                "t0 mismatch at {i}: expected {}, got {}",
                poly[i], unpacked[i]
            );
        }
    }

    #[test]
    fn test_pack_unpack_eta() {
        for eta in [2usize, 4] {
            let mut poly = [0i32; N];
            for (i, coeff) in poly.iter_mut().enumerate() {
                *coeff = (i as i32 % (2 * eta as i32 + 1)) - eta as i32;
            }
            let packed = pack_eta(&poly, eta);
            let unpacked = unpack_eta(&packed, eta);
            for i in 0..N {
                assert_eq!(
                    poly[i], unpacked[i],
                    "eta={eta} mismatch at {i}: expected {}, got {}",
                    poly[i], unpacked[i]
                );
            }
        }
    }

    #[test]
    fn test_pack_unpack_z() {
        for gamma1 in [1i32 << 17, 1i32 << 19] {
            let mut poly = [0i32; N];
            for (i, coeff) in poly.iter_mut().enumerate() {
                *coeff = (i as i32 * 97) % (2 * gamma1) - gamma1 + 1;
            }
            let packed = pack_z(&poly, gamma1);
            let unpacked = unpack_z(&packed, gamma1);
            for i in 0..N {
                assert_eq!(
                    poly[i], unpacked[i],
                    "gamma1={gamma1} z mismatch at {i}: expected {}, got {}",
                    poly[i], unpacked[i]
                );
            }
        }
    }
}
