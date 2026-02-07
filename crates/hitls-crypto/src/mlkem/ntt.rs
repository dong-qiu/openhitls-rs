//! NTT (Number Theoretic Transform) for ML-KEM.
//!
//! Operates on polynomials in Z_q[X]/(X^256+1) with q = 3329.
//! Uses Montgomery arithmetic with R = 2^16.

/// ML-KEM modulus.
pub(crate) const Q: i16 = 3329;

/// Number of polynomial coefficients.
pub(crate) const N: usize = 256;

/// q^{-1} mod 2^16 (for Montgomery reduction).
const QINV: i16 = -3327; // 3329 * (-3327) ≡ 1 mod 2^16

/// Montgomery form of 128^{-1}: R^2/128 mod q = 2^25 mod q = 1441.
const F_INV128: i16 = 1441;

/// Polynomial type: 256 coefficients in Z_q.
pub(crate) type Poly = [i16; N];

/// Zetas table in Montgomery form (zeta = 17, a primitive 256th root of unity).
/// Indexed in bit-reversed order for Cooley-Tukey and Gentleman-Sande butterflies.
pub(crate) const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246,
    778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
    603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
    -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

/// Montgomery reduction: compute a * R^{-1} mod q.
#[inline]
pub(crate) fn montgomery_reduce(a: i32) -> i16 {
    let t = (a as i16).wrapping_mul(QINV);
    ((a - t as i32 * Q as i32) >> 16) as i16
}

/// Barrett reduction: reduce a modulo q to [-q/2, q/2].
#[inline]
pub(crate) fn barrett_reduce(a: i16) -> i16 {
    let v = ((1i32 << 26) + Q as i32 / 2) / Q as i32; // 20159
    let t = ((a as i32 * v + (1 << 25)) >> 26) as i16;
    a - t * Q
}

/// Multiply a and b in Montgomery domain: a * b * R^{-1} mod q.
#[inline]
pub(crate) fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce(a as i32 * b as i32)
}

/// Forward NTT (Cooley-Tukey butterflies).
///
/// Transforms polynomial from normal domain to NTT domain.
pub(crate) fn ntt(r: &mut Poly) {
    let mut k: usize = 1;
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..start + len {
                let t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] += t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Inverse NTT (Gentleman-Sande butterflies).
///
/// Transforms polynomial from NTT domain back to normal domain.
pub(crate) fn invntt(r: &mut Poly) {
    let mut k: usize = 127;
    let mut len = 2;
    while len <= 128 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k -= 1;
            for j in start..start + len {
                let t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] -= t;
                r[j + len] = fqmul(zeta, r[j + len]);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    // Normalize by 128^{-1} in Montgomery form
    for coeff in r.iter_mut() {
        *coeff = fqmul(*coeff, F_INV128);
    }
}

/// Pointwise multiplication of two NTT-domain polynomials.
///
/// Uses base-case multiplication for degree-1 factors.
pub(crate) fn basemul_acc(r: &mut Poly, a: &[Poly], b: &[Poly]) {
    debug_assert_eq!(a.len(), b.len());
    // Zero the result
    *r = [0i16; N];
    for (ap, bp) in a.iter().zip(b.iter()) {
        let mut t = [0i16; N];
        // 64 base-case multiplications over degree-1 factors
        for i in 0..64 {
            let idx = 4 * i;
            let zeta = fqmul(ZETAS[64 + i], ZETAS[64 + i]); // Not needed like this

            // Actually use the correct zeta for each basemul pair
            // In NTT domain, pairs (r[2i], r[2i+1]) share a base-case zeta
            basemul(
                &mut t[idx..idx + 2],
                &ap[idx..idx + 2],
                &bp[idx..idx + 2],
                ZETAS[64 + i],
            );
            basemul(
                &mut t[idx + 2..idx + 4],
                &ap[idx + 2..idx + 4],
                &bp[idx + 2..idx + 4],
                -ZETAS[64 + i],
            );
        }
        for (ri, &ti) in r.iter_mut().zip(t.iter()) {
            *ri = barrett_reduce(*ri + ti);
        }
    }
}

/// Base-case multiplication for a pair of coefficients.
fn basemul(r: &mut [i16], a: &[i16], b: &[i16], zeta: i16) {
    r[0] = fqmul(a[1], b[1]);
    r[0] = fqmul(r[0], zeta);
    r[0] += fqmul(a[0], b[0]);
    r[1] = fqmul(a[0], b[1]);
    r[1] += fqmul(a[1], b[0]);
}

/// R² mod q = 2^32 mod 3329 = 1353. Used by `to_mont` to convert to Montgomery form.
const R2_MOD_Q: i16 = 1353;

/// Convert polynomial coefficients to Montgomery representation.
///
/// Multiplies each coefficient by R = 2^16 mod q. This is needed after basemul
/// (which introduces R^{-1}) to cancel the Montgomery factor before adding
/// non-Montgomery values (e.g., NTT(e)).
pub(crate) fn to_mont(r: &mut Poly) {
    for coeff in r.iter_mut() {
        // fqmul(x, R²) = x * R² * R^{-1} = x * R
        *coeff = fqmul(*coeff, R2_MOD_Q);
    }
}

/// Reduce all coefficients of a polynomial using Barrett reduction.
pub(crate) fn reduce_poly(r: &mut Poly) {
    for coeff in r.iter_mut() {
        *coeff = barrett_reduce(*coeff);
    }
}

/// Add two polynomials: r = a + b.
pub(crate) fn poly_add(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        r[i] = a[i] + b[i];
    }
}

/// Subtract two polynomials: r = a - b.
pub(crate) fn poly_sub(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        r[i] = a[i] - b[i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_invntt_roundtrip() {
        // F_INV128 = 1441 = R²/128 mod q (Kyber reference convention).
        // Standalone NTT → INTT returns result * R mod q (since basemul's R⁻¹ is absent).
        // Apply montgomery_reduce to convert from Montgomery form back to normal.
        let mut f = [0i16; N];
        for (i, coeff) in f.iter_mut().enumerate() {
            *coeff = (i as i16 * 7 + 3) % Q;
        }
        let orig = f;
        ntt(&mut f);
        invntt(&mut f);
        for i in 0..N {
            // montgomery_reduce(x) = x * R^{-1} mod q, undoing the extra R factor
            let recovered = montgomery_reduce(f[i] as i32);
            let expected = ((orig[i] as i32 % Q as i32 + Q as i32) % Q as i32) as i16;
            let got = ((recovered as i32 % Q as i32 + Q as i32) % Q as i32) as i16;
            assert_eq!(
                got, expected,
                "Mismatch at {i}: got {got}, expected {expected}"
            );
        }
    }

    #[test]
    fn test_montgomery_reduce() {
        // montgomery_reduce(a) = a * R^{-1} mod q
        // For a = R = 2^16 = 65536: result should be 1
        let r = montgomery_reduce(65536);
        let r_reduced = ((r % Q) + Q) % Q;
        assert_eq!(r_reduced, 1);
    }

    #[test]
    fn test_barrett_reduce() {
        assert_eq!(barrett_reduce(3329), 0);
        assert_eq!(barrett_reduce(-3329), 0);
        assert_eq!(barrett_reduce(0), 0);
        let r = barrett_reduce(1000);
        assert_eq!(r, 1000);
    }
}
