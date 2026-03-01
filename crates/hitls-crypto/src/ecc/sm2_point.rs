//! SM2 specialized Jacobian point arithmetic.
//!
//! Uses [`Sm2FieldElement`] for all field operations, avoiding BigNum heap
//! allocation overhead. Key optimizations:
//! - w=4 fixed-window scalar multiplication for arbitrary points
//! - Precomputed comb table (64 groups × 16 affine points) for base point G
//! - Mixed Jacobian-affine addition (saves 1 sqr + 4 mul per addition)
//! - Batch inversion for efficient table generation

use std::sync::OnceLock;

use super::sm2_field::Sm2FieldElement;
use hitls_bignum::BigNum;
use hitls_types::CryptoError;

/// SM2 base point Gx (big-endian).
const SM2_GX: [u8; 32] = [
    0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
    0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
];

/// SM2 base point Gy (big-endian).
const SM2_GY: [u8; 32] = [
    0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
    0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
];

// ========================================================================
// Point types
// ========================================================================

/// An SM2 point in Jacobian projective coordinates.
///
/// Represents affine point (X/Z^2, Y/Z^3). Point at infinity has Z = 0.
#[derive(Clone, Copy)]
pub(crate) struct Sm2JacobianPoint {
    x: Sm2FieldElement,
    y: Sm2FieldElement,
    z: Sm2FieldElement,
}

impl Sm2JacobianPoint {
    /// Point at infinity (identity element).
    pub fn infinity() -> Self {
        Self {
            x: Sm2FieldElement::ONE,
            y: Sm2FieldElement::ONE,
            z: Sm2FieldElement::ZERO,
        }
    }

    /// Create from affine coordinates (Z = 1).
    pub fn from_affine(x: &Sm2FieldElement, y: &Sm2FieldElement) -> Self {
        Self {
            x: *x,
            y: *y,
            z: Sm2FieldElement::ONE,
        }
    }

    /// Check if this is the point at infinity.
    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Convert to affine coordinates. Returns `None` if at infinity.
    pub fn to_affine(self) -> Option<(Sm2FieldElement, Sm2FieldElement)> {
        if self.is_infinity() {
            return None;
        }
        let z_inv = self.z.inv();
        let z_inv2 = z_inv.sqr();
        let z_inv3 = z_inv2.mul(&z_inv);
        Some((self.x.mul(&z_inv2), self.y.mul(&z_inv3)))
    }
}

/// An SM2 point in affine coordinates (x, y).
///
/// Used for precomputed tables where Z=1 is implicit, enabling cheaper
/// mixed Jacobian-affine additions.
#[derive(Clone, Copy)]
struct Sm2AffinePoint {
    x: Sm2FieldElement,
    y: Sm2FieldElement,
}

impl Sm2AffinePoint {
    fn is_infinity(&self) -> bool {
        self.x.is_zero() && self.y.is_zero()
    }
}

// ========================================================================
// Point arithmetic
// ========================================================================

/// Point doubling: R = 2A.
///
/// Optimized for SM2 (a = -3): uses M = 3*(X+Z^2)*(X-Z^2).
fn sm2_point_double(a: &Sm2JacobianPoint) -> Sm2JacobianPoint {
    if a.is_infinity() || a.y.is_zero() {
        return Sm2JacobianPoint::infinity();
    }

    let z_sq = a.z.sqr();
    let x_plus = a.x.add(&z_sq);
    let x_minus = a.x.sub(&z_sq);
    let m3 = x_plus.mul(&x_minus);
    let m = m3.add(&m3).add(&m3);

    let y_sq = a.y.sqr();
    let xy2 = a.x.mul(&y_sq);
    let s = xy2.add(&xy2).add(&xy2).add(&xy2);

    let m_sq = m.sqr();
    let x3 = m_sq.sub(&s).sub(&s);

    let y4 = y_sq.sqr();
    let y4_2 = y4.add(&y4);
    let y4_4 = y4_2.add(&y4_2);
    let y4_8 = y4_4.add(&y4_4);
    let y3 = m.mul(&s.sub(&x3)).sub(&y4_8);

    let yz = a.y.mul(&a.z);
    let z3 = yz.add(&yz);

    Sm2JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Point addition: R = A + B (full Jacobian-Jacobian).
fn sm2_point_add(a: &Sm2JacobianPoint, b: &Sm2JacobianPoint) -> Sm2JacobianPoint {
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
            sm2_point_double(a)
        } else {
            Sm2JacobianPoint::infinity()
        };
    }

    let h_sq = h.sqr();
    let h_cu = h_sq.mul(&h);
    let u1h2 = u1.mul(&h_sq);

    let x3 = r.sqr().sub(&h_cu).sub(&u1h2).sub(&u1h2);
    let y3 = r.mul(&u1h2.sub(&x3)).sub(&s1.mul(&h_cu));
    let z3 = h.mul(&a.z).mul(&b.z);

    Sm2JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Mixed Jacobian-affine point addition: R = Jac + Aff.
///
/// Cost: 8 mul + 3 sqr (vs 12 mul + 4 sqr for full Jacobian).
fn sm2_point_add_mixed(jac: &Sm2JacobianPoint, aff: &Sm2AffinePoint) -> Sm2JacobianPoint {
    if aff.is_infinity() {
        return *jac;
    }
    if jac.is_infinity() {
        return Sm2JacobianPoint::from_affine(&aff.x, &aff.y);
    }

    let z1_sq = jac.z.sqr();
    let z1_cu = z1_sq.mul(&jac.z);
    let u2 = aff.x.mul(&z1_sq);
    let s2 = aff.y.mul(&z1_cu);

    let h = u2.sub(&jac.x);
    let r = s2.sub(&jac.y);

    if h.is_zero() {
        return if r.is_zero() {
            sm2_point_double(jac)
        } else {
            Sm2JacobianPoint::infinity()
        };
    }

    let h_sq = h.sqr();
    let h_cu = h_sq.mul(&h);
    let u1h2 = jac.x.mul(&h_sq);

    let x3 = r.sqr().sub(&h_cu).sub(&u1h2).sub(&u1h2);
    let y3 = r.mul(&u1h2.sub(&x3)).sub(&jac.y.mul(&h_cu));
    let z3 = h.mul(&jac.z);

    Sm2JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

// ========================================================================
// Precomputed base point table
// ========================================================================

const NUM_GROUPS: usize = 64;
const GROUP_SIZE: usize = 16;

/// Returns a lazily-initialized precomputed table of base point multiples.
///
/// The table has 64 groups of 16 affine points each:
/// - Group `i` stores `[O, 1·B_i, 2·B_i, ..., 15·B_i]` where `B_i = 2^(4i)·G`.
fn sm2_base_table() -> &'static [Sm2AffinePoint] {
    static TABLE: OnceLock<Vec<Sm2AffinePoint>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let zero_aff = Sm2AffinePoint {
            x: Sm2FieldElement::ZERO,
            y: Sm2FieldElement::ZERO,
        };
        let mut table = vec![zero_aff; NUM_GROUPS * GROUP_SIZE];

        let gx = Sm2FieldElement::from_bytes(&SM2_GX);
        let gy = Sm2FieldElement::from_bytes(&SM2_GY);
        let mut base = Sm2JacobianPoint::from_affine(&gx, &gy);

        // Phase 1: Compute all Jacobian points.
        let mut jac_points: Vec<Sm2JacobianPoint> = Vec::with_capacity(NUM_GROUPS * 15);

        for _group in 0..NUM_GROUPS {
            jac_points.push(base);
            let mut accum = base;
            for _j in 2..GROUP_SIZE {
                accum = sm2_point_add(&accum, &base);
                jac_points.push(accum);
            }
            for _ in 0..4 {
                base = sm2_point_double(&base);
            }
        }

        // Phase 2: Batch inversion (Montgomery's trick).
        let n = jac_points.len();
        let mut z_inv = vec![Sm2FieldElement::ZERO; n];

        let mut prods = vec![Sm2FieldElement::ONE; n];
        prods[0] = jac_points[0].z;
        for i in 1..n {
            prods[i] = prods[i - 1].mul(&jac_points[i].z);
        }

        let mut inv = prods[n - 1].inv();

        for i in (1..n).rev() {
            z_inv[i] = inv.mul(&prods[i - 1]);
            inv = inv.mul(&jac_points[i].z);
        }
        z_inv[0] = inv;

        // Phase 3: Convert to affine.
        for (idx, (pt, zi)) in jac_points.iter().zip(z_inv.iter()).enumerate() {
            let group = idx / 15;
            let j = (idx % 15) + 1;
            let zi2 = zi.sqr();
            let zi3 = zi2.mul(zi);
            table[group * GROUP_SIZE + j] = Sm2AffinePoint {
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
pub(crate) fn sm2_scalar_mul(k: &BigNum, point: &Sm2JacobianPoint) -> Sm2JacobianPoint {
    if k.is_zero() || point.is_infinity() {
        return Sm2JacobianPoint::infinity();
    }

    let mut table = [Sm2JacobianPoint::infinity(); 16];
    table[1] = *point;
    table[2] = sm2_point_double(point);
    for i in 3..16usize {
        table[i] = sm2_point_add(&table[i - 1], point);
    }

    let bits = k.bit_len();
    let num_windows = bits.div_ceil(4);
    let mut result = Sm2JacobianPoint::infinity();

    for win_idx in (0..num_windows).rev() {
        for _ in 0..4 {
            result = sm2_point_double(&result);
        }

        let base = win_idx * 4;
        let mut w = 0usize;
        for j in 0..4 {
            let bit_pos = base + j;
            if bit_pos < bits && k.get_bit(bit_pos) != 0 {
                w |= 1 << j;
            }
        }

        if w != 0 {
            result = sm2_point_add(&result, &table[w]);
        }
    }

    result
}

/// Scalar multiplication with base point using precomputed comb table: R = k * G.
pub(crate) fn sm2_scalar_mul_base(k: &BigNum) -> Sm2JacobianPoint {
    if k.is_zero() {
        return Sm2JacobianPoint::infinity();
    }

    let table = sm2_base_table();
    let k_bytes = match k.to_bytes_be_padded(32) {
        Ok(b) => b,
        Err(_) => {
            let gx = Sm2FieldElement::from_bytes(&SM2_GX);
            let gy = Sm2FieldElement::from_bytes(&SM2_GY);
            let g = Sm2JacobianPoint::from_affine(&gx, &gy);
            return sm2_scalar_mul(k, &g);
        }
    };

    let mut result = Sm2JacobianPoint::infinity();

    for group in (0..NUM_GROUPS).rev() {
        let byte_idx = 31 - group / 2;
        let nibble = ((k_bytes[byte_idx] >> ((group & 1) * 4)) & 0x0F) as usize;

        if nibble != 0 {
            result = sm2_point_add_mixed(&result, &table[group * GROUP_SIZE + nibble]);
        }
    }

    result
}

/// Combined scalar multiplication: R = k1*G + k2*Q.
pub(crate) fn sm2_scalar_mul_add(
    k1: &BigNum,
    k2: &BigNum,
    q: &Sm2JacobianPoint,
) -> Sm2JacobianPoint {
    if k1.is_zero() && k2.is_zero() {
        return Sm2JacobianPoint::infinity();
    }
    if k1.is_zero() {
        return sm2_scalar_mul(k2, q);
    }
    if k2.is_zero() {
        return sm2_scalar_mul_base(k1);
    }

    let r1 = sm2_scalar_mul_base(k1);
    let r2 = sm2_scalar_mul(k2, q);
    sm2_point_add(&r1, &r2)
}

// ========================================================================
// BigNum conversion helpers
// ========================================================================

/// Convert BigNum affine coordinates to an Sm2JacobianPoint.
pub(crate) fn bignum_to_sm2_point(x: &BigNum, y: &BigNum) -> Result<Sm2JacobianPoint, CryptoError> {
    let x_vec = x.to_bytes_be_padded(32)?;
    let y_vec = y.to_bytes_be_padded(32)?;
    let x_arr: &[u8; 32] = x_vec
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidArg(""))?;
    let y_arr: &[u8; 32] = y_vec
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidArg(""))?;
    let x_fe = Sm2FieldElement::from_bytes(x_arr);
    let y_fe = Sm2FieldElement::from_bytes(y_arr);
    Ok(Sm2JacobianPoint::from_affine(&x_fe, &y_fe))
}

/// Convert an Sm2JacobianPoint back to affine BigNum coordinates.
pub(crate) fn sm2_point_to_affine(
    point: &Sm2JacobianPoint,
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

    fn sm2_generator() -> Sm2JacobianPoint {
        let gx = Sm2FieldElement::from_bytes(&SM2_GX);
        let gy = Sm2FieldElement::from_bytes(&SM2_GY);
        Sm2JacobianPoint::from_affine(&gx, &gy)
    }

    #[test]
    fn test_infinity_is_infinity() {
        assert!(Sm2JacobianPoint::infinity().is_infinity());
    }

    #[test]
    fn test_generator_not_infinity() {
        assert!(!sm2_generator().is_infinity());
    }

    #[test]
    fn test_generator_affine_roundtrip() {
        let g = sm2_generator();
        let (x, y) = g.to_affine().unwrap();
        assert_eq!(x.to_bytes(), SM2_GX);
        assert_eq!(y.to_bytes(), SM2_GY);
    }

    #[test]
    fn test_double_equals_add() {
        let g = sm2_generator();
        let two_g_dbl = sm2_point_double(&g);
        let two_g_add = sm2_point_add(&g, &g);

        let (x1, y1) = two_g_dbl.to_affine().unwrap();
        let (x2, y2) = two_g_add.to_affine().unwrap();
        assert_eq!(x1, x2);
        assert_eq!(y1, y2);
    }

    #[test]
    fn test_scalar_mul_base_one() {
        let one = BigNum::from_u64(1);
        let result = sm2_scalar_mul_base(&one);
        let (x, y) = result.to_affine().unwrap();
        assert_eq!(x.to_bytes(), SM2_GX);
        assert_eq!(y.to_bytes(), SM2_GY);
    }

    #[test]
    fn test_scalar_mul_base_zero() {
        let zero = BigNum::zero();
        assert!(sm2_scalar_mul_base(&zero).is_infinity());
    }

    #[test]
    fn test_scalar_mul_base_order_is_infinity() {
        let params = get_curve_params(EccCurveId::Sm2Prime256).unwrap();
        let result = sm2_scalar_mul_base(&params.n);
        assert!(result.is_infinity());
    }

    #[test]
    fn test_scalar_mul_base_2g_matches_generic() {
        let params = get_curve_params(EccCurveId::Sm2Prime256).unwrap();
        let two = BigNum::from_u64(2);

        let sm2_result = sm2_scalar_mul_base(&two);
        let (px, py) = sm2_result.to_affine().unwrap();

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
        let params = get_curve_params(EccCurveId::Sm2Prime256).unwrap();
        let k = BigNum::from_u64(7);

        let sm2_result = sm2_scalar_mul_base(&k);
        let (px, py) = sm2_result.to_affine().unwrap();

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
        let q = sm2_point_double(&sm2_generator());

        let combined = sm2_scalar_mul_add(&k1, &k2, &q);
        let (cx, cy) = combined.to_affine().unwrap();

        let part1 = sm2_scalar_mul_base(&k1);
        let part2 = sm2_scalar_mul(&k2, &q);
        let separate = sm2_point_add(&part1, &part2);
        let (sx, sy) = separate.to_affine().unwrap();

        assert_eq!(cx, sx);
        assert_eq!(cy, sy);
    }

    #[test]
    fn test_scalar_mul_add_matches_generic() {
        let params = get_curve_params(EccCurveId::Sm2Prime256).unwrap();
        let k1 = BigNum::from_u64(3);
        let k2 = BigNum::from_u64(5);

        let q_sm2 = sm2_point_double(&sm2_generator());

        let sm2_result = sm2_scalar_mul_add(&k1, &k2, &q_sm2);
        let (px, py) = sm2_result.to_affine().unwrap();

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
        let params = get_curve_params(EccCurveId::Sm2Prime256).unwrap();
        let pt = bignum_to_sm2_point(&params.gx, &params.gy).unwrap();
        let (x, y) = sm2_point_to_affine(&pt).unwrap().unwrap();
        assert_eq!(x, params.gx);
        assert_eq!(y, params.gy);
    }

    #[test]
    fn test_point_add_identity() {
        let g = sm2_generator();
        let inf = Sm2JacobianPoint::infinity();

        let r1 = sm2_point_add(&g, &inf);
        let (x1, y1) = r1.to_affine().unwrap();
        assert_eq!(x1.to_bytes(), SM2_GX);
        assert_eq!(y1.to_bytes(), SM2_GY);

        let r2 = sm2_point_add(&inf, &g);
        let (x2, y2) = r2.to_affine().unwrap();
        assert_eq!(x2.to_bytes(), SM2_GX);
        assert_eq!(y2.to_bytes(), SM2_GY);
    }

    #[test]
    fn test_mixed_addition_matches_full_add() {
        let g = sm2_generator();
        let two_g = sm2_point_double(&g);
        let (two_gx, two_gy) = two_g.to_affine().unwrap();
        let two_g_aff = Sm2AffinePoint {
            x: two_gx,
            y: two_gy,
        };

        let full = sm2_point_add(&g, &two_g);
        let (fx, fy) = full.to_affine().unwrap();

        let mixed = sm2_point_add_mixed(&g, &two_g_aff);
        let (mx, my) = mixed.to_affine().unwrap();

        assert_eq!(fx, mx, "mixed add x differs");
        assert_eq!(fy, my, "mixed add y differs");
    }

    #[test]
    fn test_base_table_consistency() {
        let table = sm2_base_table();

        let entry = &table[1];
        assert_eq!(entry.x.to_bytes(), SM2_GX, "table[0][1].x != Gx");
        assert_eq!(entry.y.to_bytes(), SM2_GY, "table[0][1].y != Gy");

        let two_g = sm2_point_double(&sm2_generator());
        let (two_gx, two_gy) = two_g.to_affine().unwrap();
        let entry2 = &table[2];
        assert_eq!(entry2.x, two_gx, "table[0][2].x != 2Gx");
        assert_eq!(entry2.y, two_gy, "table[0][2].y != 2Gy");

        let k16 = BigNum::from_u64(16);
        let sixteen_g = sm2_scalar_mul(&k16, &sm2_generator());
        let (sgx, sgy) = sixteen_g.to_affine().unwrap();
        let entry_1_1 = &table[GROUP_SIZE + 1];
        assert_eq!(entry_1_1.x, sgx, "table[1][1].x != 16*Gx");
        assert_eq!(entry_1_1.y, sgy, "table[1][1].y != 16*Gy");
    }

    #[test]
    fn test_precomputed_base_mul_matches_windowed() {
        let k = BigNum::from_u64(123456789);

        let precomp = sm2_scalar_mul_base(&k);
        let (px, py) = precomp.to_affine().unwrap();

        let g = sm2_generator();
        let windowed = sm2_scalar_mul(&k, &g);
        let (wx, wy) = windowed.to_affine().unwrap();

        assert_eq!(px, wx);
        assert_eq!(py, wy);
    }

    #[test]
    fn test_precomputed_base_mul_large_scalar() {
        let params = get_curve_params(EccCurveId::Sm2Prime256).unwrap();

        let k = params.n.sub(&BigNum::from_u64(1));
        let result = sm2_scalar_mul_base(&k);
        let (rx, ry) = result.to_affine().unwrap();

        let gx = Sm2FieldElement::from_bytes(&SM2_GX);
        let gy = Sm2FieldElement::from_bytes(&SM2_GY);
        assert_eq!(rx, gx, "(n-1)*G should have Gx");
        assert_eq!(ry, gy.neg(), "(n-1)*G should have -Gy");
    }
}
