//! NTT (Number Theoretic Transform) for ML-DSA.
//!
//! Operates on polynomials in Z_q[X]/(X^256+1) with q = 8380417.
//! Uses Montgomery arithmetic with R = 2^32.

/// ML-DSA modulus: q = 2^23 - 2^13 + 1.
pub(crate) const Q: i32 = 8380417;

/// Number of polynomial coefficients.
pub(crate) const N: usize = 256;

/// D parameter for Power2Round (FIPS 204).
pub(crate) const D: u32 = 13;

/// q^{-1} mod 2^32 (for Montgomery reduction).
const QINV: i32 = 58728449;

/// Montgomery form of 256^{-1}: (R^2 / 256) mod q = 41978.
/// Used to normalize INTT output (corrects both 256× scaling and basemul's R^{-1}).
const F_INV256: i32 = 41978;

/// R^2 mod q = 2365951. Used by `to_mont` to convert to Montgomery form.
const R2_MOD_Q: i32 = 2365951;

/// Polynomial type: 256 coefficients in Z_q.
pub(crate) type Poly = [i32; N];

/// Zetas table in Montgomery form (ψ = 1753, a primitive 512th root of unity mod q).
/// zetas[k] = ψ^{bitrev8(k)} * R mod q for k=1..255; zetas[0] = 0 (unused).
pub(crate) const ZETAS: [i32; 256] = [
    0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347, 2353451, -359251,
    -2091905, 3119733, -2884855, 3111497, 2680103, 2725464, 1024112, -1079900, 3585928, -549488,
    -1119584, 2619752, -2108549, -2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497,
    280005, 2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439, -3861115,
    -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267, -1643818, 3505694,
    -3821735, 3507263, -2140649, -1600420, 3699596, 811944, 531354, 954230, 3881043, 3900724,
    -2556880, 2071892, -2797779, -3930395, -1528703, -3677745, -3041255, -1452451, 3475950,
    2176455, -1585221, -1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
    3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047, -671102, -1228525,
    -22981, -1308169, -381987, 1349076, 1852771, -1430430, -3343383, 264944, 508951, 3097992,
    44288, -1100098, 904516, 3958618, -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969,
    -1316856, 189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330, 1285669,
    -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961, 2091667, 3407706, 2316500,
    3817976, -3342478, 2244091, -2446433, -3562462, 266997, 2434439, -1235728, 3513181, -3520352,
    -3759364, -1197226, -3193378, 900702, 1859098, 909542, 819034, 495491, -1613174, -43260,
    -522500, -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838, 342297,
    286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044, 2842341, 2691481, -2590150,
    1265009, 4055324, 1247620, 2486353, 1595974, -3767016, 1250494, 2635921, -3548272, -2994039,
    1869119, 1903435, -1050970, -1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115,
    -1962642, -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031, -542412,
    -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993, -2013608, 2432395, 2454455,
    -164721, 1957272, 3369112, 185531, -1207385, -3183426, 162844, 1616392, 3014001, 810149,
    1652634, -3694233, -1799107, -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735,
    472078, -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893, -2939036,
    -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687, -554416, 3919660, -48306,
    -1362209, 3937738, 1400424, -846154, 1976782,
];

/// Montgomery reduction: compute a * R^{-1} mod q.
#[inline]
pub(crate) fn montgomery_reduce(a: i64) -> i32 {
    let t = (a as i32).wrapping_mul(QINV);
    ((a - t as i64 * Q as i64) >> 32) as i32
}

/// Reduce a modulo q to range roughly (-q, q).
#[inline]
pub(crate) fn reduce32(a: i32) -> i32 {
    // Barrett-like: t = round(a * 2^{-23}), then a - t*q
    let t = (a + (1 << 22)) >> 23;
    a - t * Q
}

/// Conditional add q: if a is negative, add q.
#[inline]
pub(crate) fn caddq(a: i32) -> i32 {
    let mut r = a;
    r += (r >> 31) & Q;
    r
}

/// Freeze: reduce to [0, q).
#[inline]
pub(crate) fn freeze(a: i32) -> i32 {
    caddq(reduce32(a))
}

/// Multiply a and b in Montgomery domain: a * b * R^{-1} mod q.
#[inline]
pub(crate) fn fqmul(a: i32, b: i32) -> i32 {
    montgomery_reduce(a as i64 * b as i64)
}

/// Forward NTT (Cooley-Tukey butterflies, 8 layers).
///
/// Transforms polynomial from normal domain to NTT domain.
pub(crate) fn ntt(a: &mut Poly) {
    let mut k: usize = 0;
    let mut len = 128;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            k += 1;
            let zeta = ZETAS[k];
            for j in start..start + len {
                let t = fqmul(zeta, a[j + len]);
                a[j + len] = a[j] - t;
                a[j] += t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Inverse NTT (Gentleman-Sande butterflies, 8 layers).
///
/// Transforms polynomial from NTT domain back to normal domain.
/// Includes normalization by 256^{-1} and Montgomery correction.
pub(crate) fn invntt(a: &mut Poly) {
    let mut k: usize = 256;
    let mut len = 1;
    while len <= 128 {
        let mut start = 0;
        while start < N {
            k -= 1;
            let zeta = -ZETAS[k];
            for j in start..start + len {
                let t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = fqmul(zeta, a[j + len]);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    // Normalize by (256^{-1} * R) in Montgomery form = F_INV256
    for coeff in a.iter_mut() {
        *coeff = fqmul(F_INV256, *coeff);
    }
}

/// Convert polynomial to Montgomery representation.
///
/// Multiplies each coefficient by R = 2^32 mod q.
pub(crate) fn to_mont(r: &mut Poly) {
    for coeff in r.iter_mut() {
        *coeff = fqmul(*coeff, R2_MOD_Q);
    }
}

/// Pointwise multiplication of two NTT-domain polynomials.
pub(crate) fn pointwise_mul(c: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        c[i] = fqmul(a[i], b[i]);
    }
}

/// Pointwise multiply-accumulate: c += a * b (in NTT domain).
pub(crate) fn pointwise_mul_acc(c: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        c[i] += fqmul(a[i], b[i]);
    }
}

/// Reduce all coefficients using reduce32.
pub(crate) fn reduce_poly(r: &mut Poly) {
    for coeff in r.iter_mut() {
        *coeff = reduce32(*coeff);
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

/// Shift left by D bits (multiply by 2^D).
pub(crate) fn poly_shiftl(r: &mut Poly) {
    for coeff in r.iter_mut() {
        *coeff <<= D;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_invntt_roundtrip() {
        // With F_INV256 = 41978 (R^2/256 mod q), standalone NTT → INTT
        // returns result * R mod q. Apply montgomery_reduce to recover.
        let mut f = [0i32; N];
        for (i, coeff) in f.iter_mut().enumerate() {
            *coeff = (i as i32 * 13 + 5) % Q;
        }
        let orig = f;
        ntt(&mut f);
        invntt(&mut f);
        for i in 0..N {
            let recovered = montgomery_reduce(f[i] as i64);
            let expected = ((orig[i] % Q) + Q) % Q;
            let got = ((recovered % Q) + Q) % Q;
            assert_eq!(
                got, expected,
                "Mismatch at {i}: got {got}, expected {expected}"
            );
        }
    }

    #[test]
    fn test_montgomery_reduce() {
        // montgomery_reduce(R) = R * R^{-1} mod q = 1
        let r = montgomery_reduce(1i64 << 32);
        let r_red = ((r % Q) + Q) % Q;
        assert_eq!(r_red, 1);
    }

    #[test]
    fn test_reduce32() {
        assert!(reduce32(Q).abs() <= Q / 2 + 1);
        assert_eq!(reduce32(0), 0);
        let r = reduce32(1000);
        assert_eq!(r, 1000);
    }

    #[test]
    fn test_freeze() {
        assert_eq!(freeze(Q), 0);
        assert_eq!(freeze(0), 0);
        assert_eq!(freeze(-1), Q - 1);
        assert_eq!(freeze(Q + 5), 5);
    }
}
