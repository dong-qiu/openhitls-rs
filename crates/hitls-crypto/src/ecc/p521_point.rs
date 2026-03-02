//! P-521 specialized Jacobian point arithmetic.
//!
//! Uses [`P521FieldElement`] for all field operations, avoiding BigNum heap
//! allocation overhead. Key optimizations:
//! - w=4 fixed-window scalar multiplication for arbitrary points
//! - Precomputed comb table (131 groups × 16 affine points) for base point G
//! - Mixed Jacobian-affine addition (saves 1 sqr + 4 mul per addition)
//! - Batch inversion for efficient table generation

use std::sync::OnceLock;

use super::p521_field::P521FieldElement;
use hitls_bignum::BigNum;
use hitls_types::CryptoError;

/// P-521 base point Gx (big-endian, 66 bytes).
const P521_GX: [u8; 66] = [
    0x00, 0xC6, 0x85, 0x8E, 0x06, 0xB7, 0x04, 0x04, 0xE9, 0xCD, 0x9E, 0x3E, 0xCB, 0x66, 0x23, 0x95,
    0xB4, 0x42, 0x9C, 0x64, 0x81, 0x39, 0x05, 0x3F, 0xB5, 0x21, 0xF8, 0x28, 0xAF, 0x60, 0x6B, 0x4D,
    0x3D, 0xBA, 0xA1, 0x4B, 0x5E, 0x77, 0xEF, 0xE7, 0x59, 0x28, 0xFE, 0x1D, 0xC1, 0x27, 0xA2, 0xFF,
    0xA8, 0xDE, 0x33, 0x48, 0xB3, 0xC1, 0x85, 0x6A, 0x42, 0x9B, 0xF9, 0x7E, 0x7E, 0x31, 0xC2, 0xE5,
    0xBD, 0x66,
];

/// P-521 base point Gy (big-endian, 66 bytes).
const P521_GY: [u8; 66] = [
    0x01, 0x18, 0x39, 0x29, 0x6A, 0x78, 0x9A, 0x3B, 0xC0, 0x04, 0x5C, 0x8A, 0x5F, 0xB4, 0x2C, 0x7D,
    0x1B, 0xD9, 0x98, 0xF5, 0x44, 0x49, 0x57, 0x9B, 0x44, 0x68, 0x17, 0xAF, 0xBD, 0x17, 0x27, 0x3E,
    0x66, 0x2C, 0x97, 0xEE, 0x72, 0x99, 0x5E, 0xF4, 0x26, 0x40, 0xC5, 0x50, 0xB9, 0x01, 0x3F, 0xAD,
    0x07, 0x61, 0x35, 0x3C, 0x70, 0x86, 0xA2, 0x72, 0xC2, 0x40, 0x88, 0xBE, 0x94, 0x76, 0x9F, 0xD1,
    0x66, 0x50,
];

// Comb table: 131 groups × 16 entries (ceil(521/4) = 131 nibbles)
const NUM_GROUPS: usize = 131;
const GROUP_SIZE: usize = 16;
const COORD_BYTES: usize = 66;

// ========================================================================
// Point types
// ========================================================================

/// A P-521 point in Jacobian projective coordinates.
///
/// Represents affine point (X/Z², Y/Z³). Point at infinity has Z = 0.
#[derive(Clone, Copy)]
pub(crate) struct P521JacobianPoint {
    x: P521FieldElement,
    y: P521FieldElement,
    z: P521FieldElement,
}

impl P521JacobianPoint {
    /// Point at infinity (identity element).
    pub fn infinity() -> Self {
        Self {
            x: P521FieldElement::ONE,
            y: P521FieldElement::ONE,
            z: P521FieldElement::ZERO,
        }
    }

    /// Create a Jacobian point from affine coordinates (Z = 1).
    pub fn from_affine(x: &P521FieldElement, y: &P521FieldElement) -> Self {
        Self {
            x: *x,
            y: *y,
            z: P521FieldElement::ONE,
        }
    }

    /// Check if this is the point at infinity.
    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Convert to affine coordinates. Returns None for point at infinity.
    pub fn to_affine(self) -> Option<(P521FieldElement, P521FieldElement)> {
        if self.is_infinity() {
            return None;
        }
        let z_inv = self.z.inv();
        let z_inv2 = z_inv.sqr();
        let z_inv3 = z_inv2.mul(&z_inv);
        Some((self.x.mul(&z_inv2), self.y.mul(&z_inv3)))
    }
}

/// A P-521 affine point (for precomputed table entries).
#[derive(Clone, Copy)]
pub(crate) struct P521AffinePoint {
    x: P521FieldElement,
    y: P521FieldElement,
}

// ========================================================================
// Point arithmetic
// ========================================================================

/// Point doubling using a=-3 optimization: R = 2*P.
///
/// Cost: 4M + 4S (using M = 3*(X-Z²)*(X+Z²) since a=-3).
pub(crate) fn p521_point_double(p: &P521JacobianPoint) -> P521JacobianPoint {
    if p.is_infinity() {
        return *p;
    }

    let xx = p.x.sqr();
    let zz = p.z.sqr();
    let yy = p.y.sqr();
    let yyyy = yy.sqr();

    // S = 2*((X+YY)^2 - XX - YYYY)
    let s = p.x.add(&yy).sqr().sub(&xx).sub(&yyyy);
    let s = s.add(&s);

    // M = 3*(X-ZZ)*(X+ZZ) [since a = -3]
    let m = p.x.sub(&zz).mul(&p.x.add(&zz));
    let m = m.add(&m).add(&m);

    // T = M^2 - 2*S
    let t = m.sqr().sub(&s).sub(&s);

    // X3 = T
    let x3 = t;

    // Y3 = M*(S-T) - 8*YYYY
    let yyyy8 = yyyy.add(&yyyy);
    let yyyy8 = yyyy8.add(&yyyy8);
    let yyyy8 = yyyy8.add(&yyyy8);
    let y3 = m.mul(&s.sub(&t)).sub(&yyyy8);

    // Z3 = (Y+Z)^2 - YY - ZZ
    let z3 = p.y.add(&p.z).sqr().sub(&yy).sub(&zz);

    P521JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Full Jacobian point addition: R = P + Q.
///
/// Cost: 12M + 4S. Handles all special cases (infinity, doubling).
pub(crate) fn p521_point_add(p: &P521JacobianPoint, q: &P521JacobianPoint) -> P521JacobianPoint {
    if p.is_infinity() {
        return *q;
    }
    if q.is_infinity() {
        return *p;
    }

    let z1z1 = p.z.sqr();
    let z2z2 = q.z.sqr();
    let u1 = p.x.mul(&z2z2);
    let u2 = q.x.mul(&z1z1);
    let s1 = p.y.mul(&z2z2).mul(&q.z);
    let s2 = q.y.mul(&z1z1).mul(&p.z);

    let h = u2.sub(&u1);
    let r = s2.sub(&s1);

    if h.is_zero() {
        if r.is_zero() {
            return p521_point_double(p);
        }
        return P521JacobianPoint::infinity();
    }

    let hh = h.sqr();
    let hhh = hh.mul(&h);
    let v = u1.mul(&hh);

    let x3 = r.sqr().sub(&hhh).sub(&v).sub(&v);
    let y3 = r.mul(&v.sub(&x3)).sub(&s1.mul(&hhh));
    let z3 = p.z.mul(&q.z).mul(&h);

    P521JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Mixed Jacobian-affine point addition: R = P + Q_affine.
///
/// Q is affine (Z=1), saving multiplications. Cost: 8M + 3S.
fn p521_point_add_mixed(p: &P521JacobianPoint, q: &P521AffinePoint) -> P521JacobianPoint {
    if p.is_infinity() {
        if q.x.is_zero() && q.y.is_zero() {
            return P521JacobianPoint::infinity();
        }
        return P521JacobianPoint::from_affine(&q.x, &q.y);
    }
    if q.x.is_zero() && q.y.is_zero() {
        return *p;
    }

    let z1z1 = p.z.sqr();
    let u2 = q.x.mul(&z1z1);
    let s2 = q.y.mul(&z1z1).mul(&p.z);

    let h = u2.sub(&p.x);
    let r = s2.sub(&p.y);

    if h.is_zero() {
        if r.is_zero() {
            return p521_point_double(p);
        }
        return P521JacobianPoint::infinity();
    }

    let hh = h.sqr();
    let hhh = hh.mul(&h);
    let v = p.x.mul(&hh);

    let x3 = r.sqr().sub(&hhh).sub(&v).sub(&v);
    let y3 = r.mul(&v.sub(&x3)).sub(&p.y.mul(&hhh));
    let z3 = p.z.mul(&h);

    P521JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

// ========================================================================
// Precomputed base table
// ========================================================================

/// Get (or lazily build) the comb table for base point G.
///
/// Table layout: `table[group * GROUP_SIZE + j]` = (j * 2^(4*group)) * G as affine.
/// Group `i` corresponds to nibble `i` (bits [4i+3 : 4i]).
fn p521_base_table() -> &'static [P521AffinePoint] {
    static TABLE: OnceLock<Box<[P521AffinePoint]>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = vec![
            P521AffinePoint {
                x: P521FieldElement::ZERO,
                y: P521FieldElement::ZERO,
            };
            NUM_GROUPS * GROUP_SIZE
        ];

        let gx = P521FieldElement::from_bytes(&P521_GX);
        let gy = P521FieldElement::from_bytes(&P521_GY);
        let g = P521JacobianPoint::from_affine(&gx, &gy);

        // Compute base point for each group:
        // group_base[0] = G, group_base[i] = 2^(4*i) * G
        let mut group_bases = vec![P521JacobianPoint::infinity(); NUM_GROUPS];
        group_bases[0] = g;
        for i in 1..NUM_GROUPS {
            let mut pt = group_bases[i - 1];
            for _ in 0..4 {
                pt = p521_point_double(&pt);
            }
            group_bases[i] = pt;
        }

        // Phase 1: Compute all Jacobian points for the table.
        // For each group, table entries [1..15] = [base, 2*base, ..., 15*base].
        let total_jac = NUM_GROUPS * 15;
        let mut jac_points = vec![P521JacobianPoint::infinity(); total_jac];
        for (group, base) in group_bases.iter().enumerate() {
            let offset = group * 15;
            jac_points[offset] = *base; // 1 * base
            jac_points[offset + 1] = p521_point_double(base); // 2 * base
            for j in 2..15 {
                jac_points[offset + j] = p521_point_add(&jac_points[offset + j - 1], base);
            }
        }

        // Phase 2: Batch inversion of all Z coordinates.
        let n = total_jac;
        let mut prods = vec![P521FieldElement::ONE; n];
        prods[0] = jac_points[0].z;
        for i in 1..n {
            prods[i] = prods[i - 1].mul(&jac_points[i].z);
        }

        let mut z_inv = vec![P521FieldElement::ZERO; n];

        // Single inversion of the accumulated product
        let mut inv = prods[n - 1].inv();

        // Backward pass: unwind to get individual inverses
        for i in (1..n).rev() {
            z_inv[i] = inv.mul(&prods[i - 1]);
            inv = inv.mul(&jac_points[i].z);
        }
        z_inv[0] = inv;

        // Phase 3: Convert to affine using inverted Z values.
        for (idx, (pt, zi)) in jac_points.iter().zip(z_inv.iter()).enumerate() {
            let group = idx / 15;
            let j = (idx % 15) + 1; // j = 1..15
            let zi2 = zi.sqr();
            let zi3 = zi2.mul(zi);
            table[group * GROUP_SIZE + j] = P521AffinePoint {
                x: pt.x.mul(&zi2),
                y: pt.y.mul(&zi3),
            };
        }

        table.into_boxed_slice()
    })
}

// ========================================================================
// Scalar multiplication
// ========================================================================

/// Scalar multiplication using w=4 fixed-window method: R = k * P.
pub(crate) fn p521_scalar_mul(k: &BigNum, point: &P521JacobianPoint) -> P521JacobianPoint {
    if k.is_zero() || point.is_infinity() {
        return P521JacobianPoint::infinity();
    }

    // Precompute table[0..16] = [O, P, 2P, ..., 15P]
    let mut table = [P521JacobianPoint::infinity(); 16];
    table[1] = *point;
    table[2] = p521_point_double(point);
    for i in 3..16usize {
        table[i] = p521_point_add(&table[i - 1], point);
    }

    let bits = k.bit_len();
    let num_windows = bits.div_ceil(4);
    let mut result = P521JacobianPoint::infinity();

    for win_idx in (0..num_windows).rev() {
        // Double 4 times
        for _ in 0..4 {
            result = p521_point_double(&result);
        }

        // Get 4-bit window value
        let base = win_idx * 4;
        let mut w = 0usize;
        for j in 0..4 {
            let bit_pos = base + j;
            if bit_pos < bits && k.get_bit(bit_pos) != 0 {
                w |= 1 << j;
            }
        }

        if w != 0 {
            result = p521_point_add(&result, &table[w]);
        }
    }

    result
}

/// Scalar multiplication with base point using precomputed comb table: R = k * G.
///
/// Splits the 521-bit scalar into 131 nibbles, looks up one affine point per
/// nibble from the precomputed table, and sums them via mixed additions.
/// Cost: ~131 mixed additions, 0 doublings.
pub(crate) fn p521_scalar_mul_base(k: &BigNum) -> P521JacobianPoint {
    if k.is_zero() {
        return P521JacobianPoint::infinity();
    }

    let table = p521_base_table();
    let k_bytes = match k.to_bytes_be_padded(COORD_BYTES) {
        Ok(b) => b,
        Err(_) => {
            // Fallback for oversized scalars
            let gx = P521FieldElement::from_bytes(&P521_GX);
            let gy = P521FieldElement::from_bytes(&P521_GY);
            let g = P521JacobianPoint::from_affine(&gx, &gy);
            return p521_scalar_mul(k, &g);
        }
    };

    let mut result = P521JacobianPoint::infinity();

    for group in (0..NUM_GROUPS).rev() {
        // Extract 4-bit nibble for this group.
        // Nibble `i` covers bits [4i+3 : 4i].
        // In big-endian bytes: byte = 65 - i/2, shift = (i%2)*4.
        let byte_idx = 65 - group / 2;
        let nibble = ((k_bytes[byte_idx] >> ((group & 1) * 4)) & 0x0F) as usize;

        if nibble != 0 {
            result = p521_point_add_mixed(&result, &table[group * GROUP_SIZE + nibble]);
        }
    }

    result
}

/// Combined scalar multiplication: R = k1*G + k2*Q.
///
/// Uses the precomputed base table for k1*G (fast) and w=4 window for k2*Q,
/// then adds the results.
pub(crate) fn p521_scalar_mul_add(
    k1: &BigNum,
    k2: &BigNum,
    q: &P521JacobianPoint,
) -> P521JacobianPoint {
    if k1.is_zero() && k2.is_zero() {
        return P521JacobianPoint::infinity();
    }
    if k1.is_zero() {
        return p521_scalar_mul(k2, q);
    }
    if k2.is_zero() {
        return p521_scalar_mul_base(k1);
    }

    // k1*G via precomputed table + k2*Q via windowed method
    let r1 = p521_scalar_mul_base(k1);
    let r2 = p521_scalar_mul(k2, q);
    p521_point_add(&r1, &r2)
}

// ========================================================================
// BigNum conversion helpers
// ========================================================================

/// Convert BigNum affine coordinates to a P521JacobianPoint.
pub(crate) fn bignum_to_p521_point(
    x: &BigNum,
    y: &BigNum,
) -> Result<P521JacobianPoint, CryptoError> {
    let x_vec = x.to_bytes_be_padded(COORD_BYTES)?;
    let y_vec = y.to_bytes_be_padded(COORD_BYTES)?;
    let x_arr: &[u8; 66] = x_vec
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidArg("P-521 x coordinate must be 66 bytes"))?;
    let y_arr: &[u8; 66] = y_vec
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidArg("P-521 y coordinate must be 66 bytes"))?;
    let x_fe = P521FieldElement::from_bytes(x_arr);
    let y_fe = P521FieldElement::from_bytes(y_arr);
    Ok(P521JacobianPoint::from_affine(&x_fe, &y_fe))
}

/// Convert a P521JacobianPoint back to affine BigNum coordinates.
///
/// Returns `Ok(None)` for the point at infinity.
pub(crate) fn p521_point_to_affine(
    point: &P521JacobianPoint,
) -> Result<Option<(BigNum, BigNum)>, CryptoError> {
    match point.to_affine() {
        Some((x_fe, y_fe)) => {
            let x = BigNum::from_bytes_be(&x_fe.to_bytes());
            let y = BigNum::from_bytes_be(&y_fe.to_bytes());
            Ok(Some((x, y)))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc::curves::get_curve_params;
    use crate::ecc::point as generic;
    use hitls_types::EccCurveId;

    fn p521_generator() -> P521JacobianPoint {
        let gx = P521FieldElement::from_bytes(&P521_GX);
        let gy = P521FieldElement::from_bytes(&P521_GY);
        P521JacobianPoint::from_affine(&gx, &gy)
    }

    #[test]
    fn test_infinity_is_infinity() {
        assert!(P521JacobianPoint::infinity().is_infinity());
    }

    #[test]
    fn test_generator_not_infinity() {
        assert!(!p521_generator().is_infinity());
    }

    #[test]
    fn test_generator_affine_roundtrip() {
        let g = p521_generator();
        let (x, y) = g.to_affine().unwrap();
        assert_eq!(x.to_bytes(), P521_GX);
        assert_eq!(y.to_bytes(), P521_GY);
    }

    #[test]
    fn test_double_equals_add() {
        let g = p521_generator();
        let two_g_dbl = p521_point_double(&g);
        let two_g_add = p521_point_add(&g, &g);

        let (x1, y1) = two_g_dbl.to_affine().unwrap();
        let (x2, y2) = two_g_add.to_affine().unwrap();
        assert_eq!(x1, x2);
        assert_eq!(y1, y2);
    }

    #[test]
    fn test_scalar_mul_base_one() {
        let one = BigNum::from_u64(1);
        let result = p521_scalar_mul_base(&one);
        let (x, y) = result.to_affine().unwrap();
        assert_eq!(x.to_bytes(), P521_GX);
        assert_eq!(y.to_bytes(), P521_GY);
    }

    #[test]
    fn test_scalar_mul_base_zero() {
        let zero = BigNum::zero();
        assert!(p521_scalar_mul_base(&zero).is_infinity());
    }

    #[test]
    fn test_scalar_mul_base_order_is_infinity() {
        let params = get_curve_params(EccCurveId::NistP521).unwrap();
        let result = p521_scalar_mul_base(&params.n);
        assert!(result.is_infinity());
    }

    #[test]
    fn test_scalar_mul_base_2g_matches_generic() {
        let params = get_curve_params(EccCurveId::NistP521).unwrap();
        let two = BigNum::from_u64(2);

        // P-521 specialized path
        let p521_result = p521_scalar_mul_base(&two);
        let (px, py) = p521_result.to_affine().unwrap();

        // Generic BigNum path
        let g = generic::JacobianPoint::from_affine(&params.gx, &params.gy);
        let gen_result = generic::scalar_mul(&two, &g, &params).unwrap();
        let (gx, gy) = gen_result.to_affine(&params.p).unwrap().unwrap();

        assert_eq!(
            BigNum::from_bytes_be(&px.to_bytes()),
            gx,
            "2G x-coordinates differ"
        );
        assert_eq!(
            BigNum::from_bytes_be(&py.to_bytes()),
            gy,
            "2G y-coordinates differ"
        );
    }

    #[test]
    fn test_scalar_mul_base_7g_matches_generic() {
        let params = get_curve_params(EccCurveId::NistP521).unwrap();
        let k = BigNum::from_u64(7);

        let p521_result = p521_scalar_mul_base(&k);
        let (px, py) = p521_result.to_affine().unwrap();

        let g = generic::JacobianPoint::from_affine(&params.gx, &params.gy);
        let gen_result = generic::scalar_mul(&k, &g, &params).unwrap();
        let (gx, gy) = gen_result.to_affine(&params.p).unwrap().unwrap();

        assert_eq!(BigNum::from_bytes_be(&px.to_bytes()), gx);
        assert_eq!(BigNum::from_bytes_be(&py.to_bytes()), gy);
    }

    #[test]
    fn test_scalar_mul_add_consistency() {
        let k1 = BigNum::from_u64(3);
        let k2 = BigNum::from_u64(5);

        // Q = 2G
        let q = p521_point_double(&p521_generator());

        // Combined: k1*G + k2*Q
        let combined = p521_scalar_mul_add(&k1, &k2, &q);
        let (cx, cy) = combined.to_affine().unwrap();

        // Separate: k1*G + k2*Q
        let part1 = p521_scalar_mul_base(&k1);
        let part2 = p521_scalar_mul(&k2, &q);
        let separate = p521_point_add(&part1, &part2);
        let (sx, sy) = separate.to_affine().unwrap();

        assert_eq!(cx, sx);
        assert_eq!(cy, sy);
    }

    #[test]
    fn test_scalar_mul_add_matches_generic() {
        let params = get_curve_params(EccCurveId::NistP521).unwrap();
        let k1 = BigNum::from_u64(3);
        let k2 = BigNum::from_u64(5);

        // Q = 2G (as P521JacobianPoint)
        let q_p521 = p521_point_double(&p521_generator());

        // P-521 fast path
        let p521_result = p521_scalar_mul_add(&k1, &k2, &q_p521);
        let (px, py) = p521_result.to_affine().unwrap();

        // Generic BigNum path
        let g = generic::JacobianPoint::from_affine(&params.gx, &params.gy);
        let q_gen = generic::point_double(
            &generic::JacobianPoint::from_affine(&params.gx, &params.gy),
            &params,
        )
        .unwrap();
        let gen_result = generic::scalar_mul_add(&k1, &g, &k2, &q_gen, &params).unwrap();
        let (gx, gy) = gen_result.to_affine(&params.p).unwrap().unwrap();

        assert_eq!(BigNum::from_bytes_be(&px.to_bytes()), gx);
        assert_eq!(BigNum::from_bytes_be(&py.to_bytes()), gy);
    }

    #[test]
    fn test_bignum_conversion_roundtrip() {
        let params = get_curve_params(EccCurveId::NistP521).unwrap();
        let pt = bignum_to_p521_point(&params.gx, &params.gy).unwrap();
        let (x, y) = p521_point_to_affine(&pt).unwrap().unwrap();
        assert_eq!(x, params.gx);
        assert_eq!(y, params.gy);
    }

    #[test]
    fn test_point_add_identity() {
        let g = p521_generator();
        let inf = P521JacobianPoint::infinity();

        // G + O = G
        let r1 = p521_point_add(&g, &inf);
        let (x1, y1) = r1.to_affine().unwrap();
        assert_eq!(x1.to_bytes(), P521_GX);
        assert_eq!(y1.to_bytes(), P521_GY);

        // O + G = G
        let r2 = p521_point_add(&inf, &g);
        let (x2, y2) = r2.to_affine().unwrap();
        assert_eq!(x2.to_bytes(), P521_GX);
        assert_eq!(y2.to_bytes(), P521_GY);
    }

    #[test]
    fn test_add_inverse_is_infinity() {
        // G + (-G) = O
        // P-521 prime p as 66 bytes
        let p_bytes: [u8; 66] = {
            let mut b = [0xFFu8; 66];
            b[0] = 0x01;
            b[1] = 0xFF;
            b
        };
        let p_fe = P521FieldElement::from_bytes(&p_bytes);
        let gx = P521FieldElement::from_bytes(&P521_GX);
        let gy = P521FieldElement::from_bytes(&P521_GY);
        let neg_gy = p_fe.sub(&gy);

        let g = P521JacobianPoint::from_affine(&gx, &gy);
        let neg_g = P521JacobianPoint::from_affine(&gx, &neg_gy);

        let result = p521_point_add(&g, &neg_g);
        assert!(result.is_infinity());
    }

    #[test]
    fn test_mixed_addition_matches_full_add() {
        let g = p521_generator();
        let two_g = p521_point_double(&g);
        let (two_gx, two_gy) = two_g.to_affine().unwrap();
        let two_g_aff = P521AffinePoint {
            x: two_gx,
            y: two_gy,
        };

        // G + 2G via full Jacobian add
        let full = p521_point_add(&g, &two_g);
        let (fx, fy) = full.to_affine().unwrap();

        // G + 2G via mixed add
        let mixed = p521_point_add_mixed(&g, &two_g_aff);
        let (mx, my) = mixed.to_affine().unwrap();

        assert_eq!(fx, mx, "mixed add x differs");
        assert_eq!(fy, my, "mixed add y differs");
    }

    #[test]
    fn test_base_table_consistency() {
        let table = p521_base_table();

        // table[0][1] should be the generator G
        let entry = &table[1];
        assert_eq!(entry.x.to_bytes(), P521_GX, "table[0][1].x != Gx");
        assert_eq!(entry.y.to_bytes(), P521_GY, "table[0][1].y != Gy");

        // table[0][2] should be 2G
        let two_g = p521_point_double(&p521_generator());
        let (two_gx, two_gy) = two_g.to_affine().unwrap();
        let entry2 = &table[2];
        assert_eq!(entry2.x, two_gx, "table[0][2].x != 2Gx");
        assert_eq!(entry2.y, two_gy, "table[0][2].y != 2Gy");

        // table[1][1] should be 16*G = 2^4 * G
        let k16 = BigNum::from_u64(16);
        let sixteen_g = p521_scalar_mul(&k16, &p521_generator());
        let (sgx, sgy) = sixteen_g.to_affine().unwrap();
        let entry_1_1 = &table[GROUP_SIZE + 1];
        assert_eq!(entry_1_1.x, sgx, "table[1][1].x != 16*Gx");
        assert_eq!(entry_1_1.y, sgy, "table[1][1].y != 16*Gy");
    }

    #[test]
    fn test_precomputed_base_mul_matches_windowed() {
        let k = BigNum::from_u64(123456789);

        let precomp = p521_scalar_mul_base(&k);
        let (px, py) = precomp.to_affine().unwrap();

        let g = p521_generator();
        let windowed = p521_scalar_mul(&k, &g);
        let (wx, wy) = windowed.to_affine().unwrap();

        assert_eq!(px, wx);
        assert_eq!(py, wy);
    }

    #[test]
    fn test_p521_base_mul_vs_windowed_multiple_scalars() {
        let g = p521_generator();
        let test_scalars: Vec<BigNum> = vec![
            BigNum::from_u64(1),
            BigNum::from_u64(2),
            BigNum::from_u64(255),
            BigNum::from_u64(65537),
            BigNum::from_u64(0xDEADBEEF),
            BigNum::from_u64(u64::MAX),
        ];

        for k in &test_scalars {
            let precomp = p521_scalar_mul_base(k);
            let windowed = p521_scalar_mul(k, &g);

            let (px, py) = precomp.to_affine().unwrap();
            let (wx, wy) = windowed.to_affine().unwrap();

            assert_eq!(px, wx, "X mismatch for scalar {k:?}");
            assert_eq!(py, wy, "Y mismatch for scalar {k:?}");
        }
    }

    #[test]
    fn test_p521_scalar_mul_add_decomposition() {
        let g = p521_generator();

        // Q = 42*G
        let k42 = BigNum::from_u64(42);
        let q = p521_scalar_mul(&k42, &g);

        // k1=7, k2=11
        let k1 = BigNum::from_u64(7);
        let k2 = BigNum::from_u64(11);

        // Combined
        let combined = p521_scalar_mul_add(&k1, &k2, &q);
        let (cx, cy) = combined.to_affine().unwrap();

        // Manual: 7*G + 11*(42*G) = 7*G + 462*G = 469*G
        let k469 = BigNum::from_u64(469);
        let expected = p521_scalar_mul_base(&k469);
        let (ex, ey) = expected.to_affine().unwrap();

        assert_eq!(cx, ex, "scalar_mul_add X mismatch");
        assert_eq!(cy, ey, "scalar_mul_add Y mismatch");
    }

    #[test]
    fn test_precomputed_base_mul_large_scalar() {
        let params = get_curve_params(EccCurveId::NistP521).unwrap();

        // n-1 (should give -G, i.e. (Gx, p-Gy))
        let k = params.n.sub(&BigNum::from_u64(1));
        let result = p521_scalar_mul_base(&k);
        let (rx, ry) = result.to_affine().unwrap();

        let gx = P521FieldElement::from_bytes(&P521_GX);
        let gy = P521FieldElement::from_bytes(&P521_GY);
        assert_eq!(rx, gx, "(n-1)*G should have Gx");
        assert_eq!(ry, gy.neg(), "(n-1)*G should have -Gy");
    }
}
