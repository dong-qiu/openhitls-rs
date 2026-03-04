//! P-384 specialized Jacobian point arithmetic.
//!
//! Uses [`P384FieldElement`] for all field operations, avoiding BigNum heap
//! allocation overhead. Key optimizations:
//! - w=4 fixed-window scalar multiplication for arbitrary points
//! - Precomputed comb table (96 groups × 16 affine points) for base point G
//! - Mixed Jacobian-affine addition (saves 1 sqr + 4 mul per addition)
//! - Batch inversion for efficient table generation

use std::sync::OnceLock;

use super::p384_field::P384FieldElement;
use hitls_bignum::BigNum;
use hitls_types::CryptoError;

/// P-384 base point Gx (big-endian).
const P384_GX: [u8; 48] = [
    0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37, 0x8E, 0xB1, 0xC7, 0x1E, 0xF3, 0x20, 0xAD, 0x74,
    0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98, 0x59, 0xF7, 0x41, 0xE0, 0x82, 0x54, 0x2A, 0x38,
    0x55, 0x02, 0xF2, 0x5D, 0xBF, 0x55, 0x29, 0x6C, 0x3A, 0x54, 0x5E, 0x38, 0x72, 0x76, 0x0A, 0xB7,
];

/// P-384 base point Gy (big-endian).
const P384_GY: [u8; 48] = [
    0x36, 0x17, 0xDE, 0x4A, 0x96, 0x26, 0x2C, 0x6F, 0x5D, 0x9E, 0x98, 0xBF, 0x92, 0x92, 0xDC, 0x29,
    0xF8, 0xF4, 0x1D, 0xBD, 0x28, 0x9A, 0x14, 0x7C, 0xE9, 0xDA, 0x31, 0x13, 0xB5, 0xF0, 0xB8, 0xC0,
    0x0A, 0x60, 0xB1, 0xCE, 0x1D, 0x7E, 0x81, 0x9D, 0x7A, 0x43, 0x1D, 0x7C, 0x90, 0xEA, 0x0E, 0x5F,
];

// ========================================================================
// Point types
// ========================================================================

/// A P-384 point in Jacobian projective coordinates.
///
/// Represents affine point (X/Z^2, Y/Z^3). Point at infinity has Z = 0.
#[derive(Clone, Copy)]
pub(crate) struct P384JacobianPoint {
    x: P384FieldElement,
    y: P384FieldElement,
    z: P384FieldElement,
}

impl P384JacobianPoint {
    /// Point at infinity (identity element).
    pub fn infinity() -> Self {
        Self {
            x: P384FieldElement::ONE,
            y: P384FieldElement::ONE,
            z: P384FieldElement::ZERO,
        }
    }

    /// Create from affine coordinates (Z = 1).
    pub fn from_affine(x: &P384FieldElement, y: &P384FieldElement) -> Self {
        Self {
            x: *x,
            y: *y,
            z: P384FieldElement::ONE,
        }
    }

    /// Check if this is the point at infinity.
    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Convert to affine coordinates. Returns `None` if at infinity.
    pub fn to_affine(self) -> Option<(P384FieldElement, P384FieldElement)> {
        if self.is_infinity() {
            return None;
        }
        let z_inv = self.z.inv();
        let z_inv2 = z_inv.sqr();
        let z_inv3 = z_inv2.mul(&z_inv);
        Some((self.x.mul(&z_inv2), self.y.mul(&z_inv3)))
    }
}

/// A P-384 point in affine coordinates (x, y).
///
/// Used for precomputed tables where Z=1 is implicit, enabling cheaper
/// mixed Jacobian-affine additions.
#[derive(Clone, Copy)]
struct P384AffinePoint {
    x: P384FieldElement,
    y: P384FieldElement,
}

impl P384AffinePoint {
    /// Check if this represents the point at infinity.
    fn is_infinity(&self) -> bool {
        self.x.is_zero() && self.y.is_zero()
    }
}

// ========================================================================
// Point arithmetic
// ========================================================================

/// Point doubling: R = 2A.
///
/// Optimized for P-384 (a = -3): uses M = 3*(X+Z^2)*(X-Z^2).
fn p384_point_double(a: &P384JacobianPoint) -> P384JacobianPoint {
    if a.is_infinity() || a.y.is_zero() {
        return P384JacobianPoint::infinity();
    }

    // M = 3*(X + Z^2)*(X - Z^2)  [since a = -3]
    let z_sq = a.z.sqr();
    let x_plus = a.x.add(&z_sq);
    let x_minus = a.x.sub(&z_sq);
    let m3 = x_plus.mul(&x_minus);
    let m = m3.add(&m3).add(&m3);

    // S = 4*X*Y^2
    let y_sq = a.y.sqr();
    let xy2 = a.x.mul(&y_sq);
    let s = xy2.add(&xy2).add(&xy2).add(&xy2);

    // X3 = M^2 - 2*S
    let m_sq = m.sqr();
    let x3 = m_sq.sub(&s).sub(&s);

    // Y3 = M*(S - X3) - 8*Y^4
    let y4 = y_sq.sqr();
    let y4_2 = y4.add(&y4);
    let y4_4 = y4_2.add(&y4_2);
    let y4_8 = y4_4.add(&y4_4);
    let y3 = m.mul(&s.sub(&x3)).sub(&y4_8);

    // Z3 = 2*Y*Z
    let yz = a.y.mul(&a.z);
    let z3 = yz.add(&yz);

    P384JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Point addition: R = A + B (full Jacobian-Jacobian).
fn p384_point_add(a: &P384JacobianPoint, b: &P384JacobianPoint) -> P384JacobianPoint {
    if a.is_infinity() {
        return *b;
    }
    if b.is_infinity() {
        return *a;
    }

    let z2_sq = b.z.sqr();
    let u1 = a.x.mul(&z2_sq);
    let z1_sq = a.z.sqr();
    let u2 = b.x.mul(&z1_sq);

    let s1 = a.y.mul(&z2_sq.mul(&b.z));
    let s2 = b.y.mul(&z1_sq.mul(&a.z));

    let h = u2.sub(&u1);
    let r = s2.sub(&s1);

    if h.is_zero() {
        return if r.is_zero() {
            p384_point_double(a)
        } else {
            P384JacobianPoint::infinity()
        };
    }

    let h_sq = h.sqr();
    let h_cu = h_sq.mul(&h);
    let u1h2 = u1.mul(&h_sq);

    // X3 = R^2 - H^3 - 2*U1*H^2
    let x3 = r.sqr().sub(&h_cu).sub(&u1h2).sub(&u1h2);

    // Y3 = R*(U1*H^2 - X3) - S1*H^3
    let y3 = r.mul(&u1h2.sub(&x3)).sub(&s1.mul(&h_cu));

    // Z3 = H * Z1 * Z2
    let z3 = h.mul(&a.z).mul(&b.z);

    P384JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Mixed Jacobian-affine point addition: R = Jac + Aff.
///
/// When the second operand is in affine form (Z=1), we skip computing
/// Z2^2, Z2^3, and reduce Z3 = H*Z1 (vs H*Z1*Z2).
/// Cost: 8 mul + 3 sqr (vs 12 mul + 4 sqr for full Jacobian).
fn p384_point_add_mixed(jac: &P384JacobianPoint, aff: &P384AffinePoint) -> P384JacobianPoint {
    if aff.is_infinity() {
        return *jac;
    }
    if jac.is_infinity() {
        return P384JacobianPoint::from_affine(&aff.x, &aff.y);
    }

    // Since Z2 = 1: U1 = X1, S1 = Y1
    // U2 = X2 * Z1^2, S2 = Y2 * Z1^3
    let z1_sq = jac.z.sqr();
    let z1_cu = z1_sq.mul(&jac.z);
    let u2 = aff.x.mul(&z1_sq);
    let s2 = aff.y.mul(&z1_cu);

    let h = u2.sub(&jac.x);
    let r = s2.sub(&jac.y);

    if h.is_zero() {
        return if r.is_zero() {
            p384_point_double(jac)
        } else {
            P384JacobianPoint::infinity()
        };
    }

    let h_sq = h.sqr();
    let h_cu = h_sq.mul(&h);
    let u1h2 = jac.x.mul(&h_sq);

    // X3 = R^2 - H^3 - 2*U1*H^2
    let x3 = r.sqr().sub(&h_cu).sub(&u1h2).sub(&u1h2);

    // Y3 = R*(U1*H^2 - X3) - S1*H^3  (S1 = Y1)
    let y3 = r.mul(&u1h2.sub(&x3)).sub(&jac.y.mul(&h_cu));

    // Z3 = H * Z1  (since Z2 = 1)
    let z3 = h.mul(&jac.z);

    P384JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

// ========================================================================
// Precomputed base point table
// ========================================================================

/// Number of 4-bit groups in a 384-bit scalar.
const NUM_GROUPS: usize = 96;
/// Number of entries per group (0..15).
const GROUP_SIZE: usize = 16;

/// Returns a lazily-initialized precomputed table of base point multiples.
///
/// The table has 96 groups of 16 affine points each:
/// - Group `i` stores `[O, 1·B_i, 2·B_i, ..., 15·B_i]` where `B_i = 2^(4i)·G`.
/// - At runtime, a 384-bit scalar is split into 96 nibbles and each nibble
///   selects one affine point; the result is their sum via mixed additions.
/// - This eliminates all 384 point doublings from base-point scalar mul.
///
/// Uses Montgomery's batch inversion trick for efficient Jacobian→affine conversion.
fn p384_base_table() -> &'static [P384AffinePoint] {
    static TABLE: OnceLock<Vec<P384AffinePoint>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let zero_aff = P384AffinePoint {
            x: P384FieldElement::ZERO,
            y: P384FieldElement::ZERO,
        };
        let mut table = vec![zero_aff; NUM_GROUPS * GROUP_SIZE];

        let gx = P384FieldElement::from_bytes(&P384_GX);
        let gy = P384FieldElement::from_bytes(&P384_GY);
        let mut base = P384JacobianPoint::from_affine(&gx, &gy);

        // Phase 1: Compute all Jacobian points.
        let mut jac_points: Vec<P384JacobianPoint> = Vec::with_capacity(NUM_GROUPS * 15);

        for _group in 0..NUM_GROUPS {
            jac_points.push(base); // j=1: base itself
            let mut accum = base;
            for _j in 2..GROUP_SIZE {
                accum = p384_point_add(&accum, &base);
                jac_points.push(accum);
            }
            // Advance base: B_{i+1} = 16 * B_i
            for _ in 0..4 {
                base = p384_point_double(&base);
            }
        }

        // Phase 2: Batch inversion of all Z coordinates (Montgomery's trick).
        let n = jac_points.len();
        let mut z_inv = vec![P384FieldElement::ZERO; n];

        // Forward pass: running products
        let mut prods = vec![P384FieldElement::ONE; n];
        prods[0] = jac_points[0].z;
        for i in 1..n {
            prods[i] = prods[i - 1].mul(&jac_points[i].z);
        }

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
            table[group * GROUP_SIZE + j] = P384AffinePoint {
                x: pt.x.mul(&zi2),
                y: pt.y.mul(&zi3),
            };
        }

        table
    })
}

// ========================================================================
// Scalar multiplication
// ========================================================================

/// Scalar multiplication using w=4 fixed-window method: R = k * P.
pub(crate) fn p384_scalar_mul(k: &BigNum, point: &P384JacobianPoint) -> P384JacobianPoint {
    if k.is_zero() || point.is_infinity() {
        return P384JacobianPoint::infinity();
    }

    // Precompute table[0..16] = [O, P, 2P, ..., 15P]
    let mut table = [P384JacobianPoint::infinity(); 16];
    table[1] = *point;
    table[2] = p384_point_double(point);
    for i in 3..16usize {
        table[i] = p384_point_add(&table[i - 1], point);
    }

    let bits = k.bit_len();
    let num_windows = bits.div_ceil(4);
    let mut result = P384JacobianPoint::infinity();

    for win_idx in (0..num_windows).rev() {
        // Double 4 times
        for _ in 0..4 {
            result = p384_point_double(&result);
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
            result = p384_point_add(&result, &table[w]);
        }
    }

    result
}

/// Scalar multiplication with base point using precomputed comb table: R = k * G.
///
/// Splits the 384-bit scalar into 96 nibbles, looks up one affine point per
/// nibble from the precomputed table, and sums them via mixed additions.
/// Cost: ~96 mixed additions, 0 doublings (vs ~384 doublings + ~72 additions).
pub(crate) fn p384_scalar_mul_base(k: &BigNum) -> P384JacobianPoint {
    if k.is_zero() {
        return P384JacobianPoint::infinity();
    }

    let table = p384_base_table();
    let Ok(k_bytes) = k.to_bytes_be_padded(48) else {
        // Fallback for oversized scalars (shouldn't happen in practice)
        let gx = P384FieldElement::from_bytes(&P384_GX);
        let gy = P384FieldElement::from_bytes(&P384_GY);
        let g = P384JacobianPoint::from_affine(&gx, &gy);
        return p384_scalar_mul(k, &g);
    };

    let mut result = P384JacobianPoint::infinity();

    for group in (0..NUM_GROUPS).rev() {
        // Extract 4-bit nibble for this group.
        // Nibble `i` covers bits [4i+3 : 4i].
        // In big-endian bytes: byte = 47 - i/2, shift = (i%2)*4.
        let byte_idx = 47 - group / 2;
        let nibble = ((k_bytes[byte_idx] >> ((group & 1) * 4)) & 0x0F) as usize;

        if nibble != 0 {
            result = p384_point_add_mixed(&result, &table[group * GROUP_SIZE + nibble]);
        }
    }

    result
}

/// Combined scalar multiplication: R = k1*G + k2*Q.
///
/// Uses the precomputed base table for k1*G (fast) and w=4 window for k2*Q,
/// then adds the results.
pub(crate) fn p384_scalar_mul_add(
    k1: &BigNum,
    k2: &BigNum,
    q: &P384JacobianPoint,
) -> P384JacobianPoint {
    if k1.is_zero() && k2.is_zero() {
        return P384JacobianPoint::infinity();
    }
    if k1.is_zero() {
        return p384_scalar_mul(k2, q);
    }
    if k2.is_zero() {
        return p384_scalar_mul_base(k1);
    }

    // k1*G via precomputed table + k2*Q via windowed method
    let r1 = p384_scalar_mul_base(k1);
    let r2 = p384_scalar_mul(k2, q);
    p384_point_add(&r1, &r2)
}

// ========================================================================
// BigNum conversion helpers
// ========================================================================

/// Convert BigNum affine coordinates to a P384JacobianPoint.
pub(crate) fn bignum_to_p384_point(
    x: &BigNum,
    y: &BigNum,
) -> Result<P384JacobianPoint, CryptoError> {
    let x_vec = x.to_bytes_be_padded(48)?;
    let y_vec = y.to_bytes_be_padded(48)?;
    let x_arr: &[u8; 48] = x_vec
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidArg("P-384 x coordinate must be 48 bytes"))?;
    let y_arr: &[u8; 48] = y_vec
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidArg("P-384 y coordinate must be 48 bytes"))?;
    let x_fe = P384FieldElement::from_bytes(x_arr);
    let y_fe = P384FieldElement::from_bytes(y_arr);
    Ok(P384JacobianPoint::from_affine(&x_fe, &y_fe))
}

/// Convert a P384JacobianPoint back to affine BigNum coordinates.
///
/// Returns `Ok(None)` for the point at infinity.
pub(crate) fn p384_point_to_affine(
    point: &P384JacobianPoint,
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

    fn p384_generator() -> P384JacobianPoint {
        let gx = P384FieldElement::from_bytes(&P384_GX);
        let gy = P384FieldElement::from_bytes(&P384_GY);
        P384JacobianPoint::from_affine(&gx, &gy)
    }

    #[test]
    fn test_infinity_is_infinity() {
        assert!(P384JacobianPoint::infinity().is_infinity());
    }

    #[test]
    fn test_generator_not_infinity() {
        assert!(!p384_generator().is_infinity());
    }

    #[test]
    fn test_generator_affine_roundtrip() {
        let g = p384_generator();
        let (x, y) = g.to_affine().unwrap();
        assert_eq!(x.to_bytes(), P384_GX);
        assert_eq!(y.to_bytes(), P384_GY);
    }

    #[test]
    fn test_double_equals_add() {
        let g = p384_generator();
        let two_g_dbl = p384_point_double(&g);
        let two_g_add = p384_point_add(&g, &g);

        let (x1, y1) = two_g_dbl.to_affine().unwrap();
        let (x2, y2) = two_g_add.to_affine().unwrap();
        assert_eq!(x1, x2);
        assert_eq!(y1, y2);
    }

    #[test]
    fn test_scalar_mul_base_one() {
        let one = BigNum::from_u64(1);
        let result = p384_scalar_mul_base(&one);
        let (x, y) = result.to_affine().unwrap();
        assert_eq!(x.to_bytes(), P384_GX);
        assert_eq!(y.to_bytes(), P384_GY);
    }

    #[test]
    fn test_scalar_mul_base_zero() {
        let zero = BigNum::zero();
        assert!(p384_scalar_mul_base(&zero).is_infinity());
    }

    #[test]
    fn test_scalar_mul_base_order_is_infinity() {
        let params = get_curve_params(EccCurveId::NistP384).unwrap();
        let result = p384_scalar_mul_base(&params.n);
        assert!(result.is_infinity());
    }

    #[test]
    fn test_scalar_mul_base_2g_matches_generic() {
        let params = get_curve_params(EccCurveId::NistP384).unwrap();
        let two = BigNum::from_u64(2);

        // P-384 specialized path
        let p384_result = p384_scalar_mul_base(&two);
        let (px, py) = p384_result.to_affine().unwrap();

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
        let params = get_curve_params(EccCurveId::NistP384).unwrap();
        let k = BigNum::from_u64(7);

        let p384_result = p384_scalar_mul_base(&k);
        let (px, py) = p384_result.to_affine().unwrap();

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
        let q = p384_point_double(&p384_generator());

        // Combined: k1*G + k2*Q
        let combined = p384_scalar_mul_add(&k1, &k2, &q);
        let (cx, cy) = combined.to_affine().unwrap();

        // Separate: k1*G + k2*Q
        let part1 = p384_scalar_mul_base(&k1);
        let part2 = p384_scalar_mul(&k2, &q);
        let separate = p384_point_add(&part1, &part2);
        let (sx, sy) = separate.to_affine().unwrap();

        assert_eq!(cx, sx);
        assert_eq!(cy, sy);
    }

    #[test]
    fn test_scalar_mul_add_matches_generic() {
        let params = get_curve_params(EccCurveId::NistP384).unwrap();
        let k1 = BigNum::from_u64(3);
        let k2 = BigNum::from_u64(5);

        // Q = 2G (as P384JacobianPoint)
        let q_p384 = p384_point_double(&p384_generator());

        // P-384 fast path
        let p384_result = p384_scalar_mul_add(&k1, &k2, &q_p384);
        let (px, py) = p384_result.to_affine().unwrap();

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
        let params = get_curve_params(EccCurveId::NistP384).unwrap();
        let pt = bignum_to_p384_point(&params.gx, &params.gy).unwrap();
        let (x, y) = p384_point_to_affine(&pt).unwrap().unwrap();
        assert_eq!(x, params.gx);
        assert_eq!(y, params.gy);
    }

    #[test]
    fn test_point_add_identity() {
        let g = p384_generator();
        let inf = P384JacobianPoint::infinity();

        // G + O = G
        let r1 = p384_point_add(&g, &inf);
        let (x1, y1) = r1.to_affine().unwrap();
        assert_eq!(x1.to_bytes(), P384_GX);
        assert_eq!(y1.to_bytes(), P384_GY);

        // O + G = G
        let r2 = p384_point_add(&inf, &g);
        let (x2, y2) = r2.to_affine().unwrap();
        assert_eq!(x2.to_bytes(), P384_GX);
        assert_eq!(y2.to_bytes(), P384_GY);
    }

    #[test]
    fn test_add_inverse_is_infinity() {
        // G + (-G) = O
        let p_bytes: [u8; 48] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let p_fe = P384FieldElement::from_bytes(&p_bytes);
        let gx = P384FieldElement::from_bytes(&P384_GX);
        let gy = P384FieldElement::from_bytes(&P384_GY);
        let neg_gy = p_fe.sub(&gy);

        let g = P384JacobianPoint::from_affine(&gx, &gy);
        let neg_g = P384JacobianPoint::from_affine(&gx, &neg_gy);

        let result = p384_point_add(&g, &neg_g);
        assert!(result.is_infinity());
    }

    #[test]
    fn test_mixed_addition_matches_full_add() {
        let g = p384_generator();
        let two_g = p384_point_double(&g);
        let (two_gx, two_gy) = two_g.to_affine().unwrap();
        let two_g_aff = P384AffinePoint {
            x: two_gx,
            y: two_gy,
        };

        // G + 2G via full Jacobian add
        let full = p384_point_add(&g, &two_g);
        let (fx, fy) = full.to_affine().unwrap();

        // G + 2G via mixed add
        let mixed = p384_point_add_mixed(&g, &two_g_aff);
        let (mx, my) = mixed.to_affine().unwrap();

        assert_eq!(fx, mx, "mixed add x differs");
        assert_eq!(fy, my, "mixed add y differs");
    }

    #[test]
    fn test_mixed_addition_with_infinity() {
        let g = p384_generator();
        let (gx, gy) = g.to_affine().unwrap();
        let g_aff = P384AffinePoint { x: gx, y: gy };
        let inf_aff = P384AffinePoint {
            x: P384FieldElement::ZERO,
            y: P384FieldElement::ZERO,
        };

        // inf + G_aff = G
        let r1 = p384_point_add_mixed(&P384JacobianPoint::infinity(), &g_aff);
        let (x1, y1) = r1.to_affine().unwrap();
        assert_eq!(x1.to_bytes(), P384_GX);
        assert_eq!(y1.to_bytes(), P384_GY);

        // G + inf_aff = G
        let r2 = p384_point_add_mixed(&g, &inf_aff);
        let (x2, y2) = r2.to_affine().unwrap();
        assert_eq!(x2.to_bytes(), P384_GX);
        assert_eq!(y2.to_bytes(), P384_GY);
    }

    #[test]
    fn test_base_table_consistency() {
        let table = p384_base_table();

        // table[0][1] should be the generator G
        let entry = &table[1];
        assert_eq!(entry.x.to_bytes(), P384_GX, "table[0][1].x != Gx");
        assert_eq!(entry.y.to_bytes(), P384_GY, "table[0][1].y != Gy");

        // table[0][2] should be 2G
        let two_g = p384_point_double(&p384_generator());
        let (two_gx, two_gy) = two_g.to_affine().unwrap();
        let entry2 = &table[2];
        assert_eq!(entry2.x, two_gx, "table[0][2].x != 2Gx");
        assert_eq!(entry2.y, two_gy, "table[0][2].y != 2Gy");

        // table[1][1] should be 16*G = 2^4 * G
        let k16 = BigNum::from_u64(16);
        let sixteen_g = p384_scalar_mul(&k16, &p384_generator());
        let (sgx, sgy) = sixteen_g.to_affine().unwrap();
        let entry_1_1 = &table[GROUP_SIZE + 1];
        assert_eq!(entry_1_1.x, sgx, "table[1][1].x != 16*Gx");
        assert_eq!(entry_1_1.y, sgy, "table[1][1].y != 16*Gy");
    }

    #[test]
    fn test_precomputed_base_mul_matches_windowed() {
        let k = BigNum::from_u64(123456789);

        let precomp = p384_scalar_mul_base(&k);
        let (px, py) = precomp.to_affine().unwrap();

        let g = p384_generator();
        let windowed = p384_scalar_mul(&k, &g);
        let (wx, wy) = windowed.to_affine().unwrap();

        assert_eq!(px, wx);
        assert_eq!(py, wy);
    }

    #[test]
    fn test_p384_base_mul_vs_windowed_multiple_scalars() {
        let g = p384_generator();
        let test_scalars: Vec<BigNum> = vec![
            BigNum::from_u64(1),
            BigNum::from_u64(2),
            BigNum::from_u64(255),
            BigNum::from_u64(65537),
            BigNum::from_u64(0xDEADBEEF),
            BigNum::from_u64(u64::MAX),
        ];

        for k in &test_scalars {
            let precomp = p384_scalar_mul_base(k);
            let windowed = p384_scalar_mul(k, &g);

            let (px, py) = precomp.to_affine().unwrap();
            let (wx, wy) = windowed.to_affine().unwrap();

            assert_eq!(px, wx, "X mismatch for scalar {k:?}");
            assert_eq!(py, wy, "Y mismatch for scalar {k:?}");
        }
    }

    #[test]
    fn test_p384_scalar_mul_add_decomposition() {
        let g = p384_generator();

        // Q = 42*G
        let k42 = BigNum::from_u64(42);
        let q = p384_scalar_mul(&k42, &g);

        // k1=7, k2=11
        let k1 = BigNum::from_u64(7);
        let k2 = BigNum::from_u64(11);

        // Combined
        let combined = p384_scalar_mul_add(&k1, &k2, &q);
        let (cx, cy) = combined.to_affine().unwrap();

        // Manual: 7*G + 11*(42*G) = 7*G + 462*G = 469*G
        let k469 = BigNum::from_u64(469);
        let expected = p384_scalar_mul_base(&k469);
        let (ex, ey) = expected.to_affine().unwrap();

        assert_eq!(cx, ex, "scalar_mul_add X mismatch");
        assert_eq!(cy, ey, "scalar_mul_add Y mismatch");
    }

    #[test]
    fn test_precomputed_base_mul_large_scalar() {
        let params = get_curve_params(EccCurveId::NistP384).unwrap();

        // n-1 (should give -G, i.e. (Gx, p-Gy))
        let k = params.n.sub(&BigNum::from_u64(1));
        let result = p384_scalar_mul_base(&k);
        let (rx, ry) = result.to_affine().unwrap();

        let gx = P384FieldElement::from_bytes(&P384_GX);
        let gy = P384FieldElement::from_bytes(&P384_GY);
        assert_eq!(rx, gx, "(n-1)*G should have Gx");
        assert_eq!(ry, gy.neg(), "(n-1)*G should have -Gy");
    }
}
