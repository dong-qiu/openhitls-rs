//! Jacobian coordinate elliptic curve point arithmetic.
//!
//! Uses Jacobian projective coordinates (X, Y, Z) representing affine point
//! (X/Z², Y/Z³). The point at infinity is represented by Z = 0.
//! All arithmetic is performed modulo the curve's prime p.

use hitls_bignum::BigNum;
use hitls_types::CryptoError;

use super::curves::CurveParams;

/// A point in Jacobian projective coordinates.
#[derive(Clone)]
pub(crate) struct JacobianPoint {
    pub x: BigNum,
    pub y: BigNum,
    pub z: BigNum,
}

impl JacobianPoint {
    /// The point at infinity (identity element).
    pub fn infinity() -> Self {
        JacobianPoint {
            x: BigNum::from_u64(1),
            y: BigNum::from_u64(1),
            z: BigNum::zero(),
        }
    }

    /// Create a Jacobian point from affine coordinates (Z = 1).
    pub fn from_affine(x: &BigNum, y: &BigNum) -> Self {
        JacobianPoint {
            x: x.clone(),
            y: y.clone(),
            z: BigNum::from_u64(1),
        }
    }

    /// Check if this point is the point at infinity.
    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Convert from Jacobian to affine coordinates: (X/Z², Y/Z³).
    /// Returns None if the point is at infinity.
    pub fn to_affine(&self, p: &BigNum) -> Result<Option<(BigNum, BigNum)>, CryptoError> {
        if self.is_infinity() {
            return Ok(None);
        }

        let z_inv = self.z.mod_inv(p)?;
        let z_inv2 = z_inv.mod_mul(&z_inv, p)?;
        let z_inv3 = z_inv2.mod_mul(&z_inv, p)?;

        let x_aff = self.x.mod_mul(&z_inv2, p)?;
        let y_aff = self.y.mod_mul(&z_inv3, p)?;

        Ok(Some((x_aff, y_aff)))
    }
}

/// Jacobian point addition: R = A + B.
pub(crate) fn point_add(
    a: &JacobianPoint,
    b: &JacobianPoint,
    params: &CurveParams,
) -> Result<JacobianPoint, CryptoError> {
    let p = &params.p;

    if a.is_infinity() {
        return Ok(b.clone());
    }
    if b.is_infinity() {
        return Ok(a.clone());
    }

    let z2_sq = b.z.mod_mul(&b.z, p)?;
    let u1 = a.x.mod_mul(&z2_sq, p)?;

    let z1_sq = a.z.mod_mul(&a.z, p)?;
    let u2 = b.x.mod_mul(&z1_sq, p)?;

    let z2_cu = z2_sq.mod_mul(&b.z, p)?;
    let s1 = a.y.mod_mul(&z2_cu, p)?;

    let z1_cu = z1_sq.mod_mul(&a.z, p)?;
    let s2 = b.y.mod_mul(&z1_cu, p)?;

    let h = u2.mod_sub(&u1, p)?;
    let r = s2.mod_sub(&s1, p)?;

    if h.is_zero() {
        if r.is_zero() {
            return point_double(a, params);
        }
        return Ok(JacobianPoint::infinity());
    }

    let h_sq = h.mod_mul(&h, p)?;
    let h_cu = h_sq.mod_mul(&h, p)?;
    let u1_h_sq = u1.mod_mul(&h_sq, p)?;

    // X3 = R² - H³ - 2·U1·H²
    let r_sq = r.mod_mul(&r, p)?;
    let x3 = r_sq.mod_sub(&h_cu, p)?;
    let x3 = x3.mod_sub(&u1_h_sq, p)?;
    let x3 = x3.mod_sub(&u1_h_sq, p)?;

    // Y3 = R·(U1·H² - X3) - S1·H³
    let diff = u1_h_sq.mod_sub(&x3, p)?;
    let y3 = r.mod_mul(&diff, p)?;
    let s1_h_cu = s1.mod_mul(&h_cu, p)?;
    let y3 = y3.mod_sub(&s1_h_cu, p)?;

    // Z3 = H·Z1·Z2
    let z3 = h.mod_mul(&a.z, p)?;
    let z3 = z3.mod_mul(&b.z, p)?;

    Ok(JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    })
}

/// Jacobian point doubling: R = 2A.
///
/// Uses the optimized formula `M = 3·(X+Z²)·(X-Z²)` for curves with a = p-3
/// (NIST curves, SM2). Falls back to generic `M = 3·X² + a·Z⁴` for other
/// curves (Brainpool).
pub(crate) fn point_double(
    a: &JacobianPoint,
    params: &CurveParams,
) -> Result<JacobianPoint, CryptoError> {
    let p = &params.p;

    if a.is_infinity() || a.y.is_zero() {
        return Ok(JacobianPoint::infinity());
    }

    let two = BigNum::from_u64(2);
    let three = BigNum::from_u64(3);
    let four = BigNum::from_u64(4);
    let eight = BigNum::from_u64(8);

    // S = 4·X·Y²
    let y_sq = a.y.mod_mul(&a.y, p)?;
    let s = a.x.mod_mul(&y_sq, p)?;
    let s = s.mod_mul(&four, p)?;

    // M depends on whether a = p - 3
    let m = if params.a_is_minus_3 {
        // M = 3·(X + Z²)·(X - Z²) when a = -3
        let z_sq = a.z.mod_mul(&a.z, p)?;
        let x_plus_zsq = a.x.mod_add(&z_sq, p)?;
        let x_minus_zsq = a.x.mod_sub(&z_sq, p)?;
        let m = x_plus_zsq.mod_mul(&x_minus_zsq, p)?;
        m.mod_mul(&three, p)?
    } else {
        // M = 3·X² + a·Z⁴ (generic formula)
        let x_sq = a.x.mod_mul(&a.x, p)?;
        let three_x_sq = x_sq.mod_mul(&three, p)?;
        let z_sq = a.z.mod_mul(&a.z, p)?;
        let z4 = z_sq.mod_mul(&z_sq, p)?;
        let a_z4 = params.a.mod_mul(&z4, p)?;
        three_x_sq.mod_add(&a_z4, p)?
    };

    // X3 = M² - 2·S
    let m_sq = m.mod_mul(&m, p)?;
    let two_s = s.mod_mul(&two, p)?;
    let x3 = m_sq.mod_sub(&two_s, p)?;

    // Y3 = M·(S - X3) - 8·Y⁴
    let s_minus_x3 = s.mod_sub(&x3, p)?;
    let y3 = m.mod_mul(&s_minus_x3, p)?;
    let y4 = y_sq.mod_mul(&y_sq, p)?;
    let eight_y4 = y4.mod_mul(&eight, p)?;
    let y3 = y3.mod_sub(&eight_y4, p)?;

    // Z3 = 2·Y·Z
    let z3 = a.y.mod_mul(&a.z, p)?;
    let z3 = z3.mod_mul(&two, p)?;

    Ok(JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    })
}

/// Scalar multiplication: R = k * P using double-and-add (MSB to LSB).
pub(crate) fn scalar_mul(
    k: &BigNum,
    point: &JacobianPoint,
    params: &CurveParams,
) -> Result<JacobianPoint, CryptoError> {
    if k.is_zero() || point.is_infinity() {
        return Ok(JacobianPoint::infinity());
    }

    let bits = k.bit_len();
    let mut result = JacobianPoint::infinity();

    for i in (0..bits).rev() {
        result = point_double(&result, params)?;
        if k.get_bit(i) != 0 {
            result = point_add(&result, point, params)?;
        }
    }

    Ok(result)
}

/// Combined scalar multiplication using Shamir's trick: R = k1*G + k2*Q.
pub(crate) fn scalar_mul_add(
    k1: &BigNum,
    g: &JacobianPoint,
    k2: &BigNum,
    q: &JacobianPoint,
    params: &CurveParams,
) -> Result<JacobianPoint, CryptoError> {
    if k1.is_zero() && k2.is_zero() {
        return Ok(JacobianPoint::infinity());
    }
    if k1.is_zero() {
        return scalar_mul(k2, q, params);
    }
    if k2.is_zero() {
        return scalar_mul(k1, g, params);
    }

    let g_plus_q = point_add(g, q, params)?;

    let bits1 = k1.bit_len();
    let bits2 = k2.bit_len();
    let max_bits = bits1.max(bits2);

    let mut result = JacobianPoint::infinity();

    for i in (0..max_bits).rev() {
        result = point_double(&result, params)?;

        let b1 = if i < bits1 { k1.get_bit(i) } else { 0 };
        let b2 = if i < bits2 { k2.get_bit(i) } else { 0 };

        match (b1, b2) {
            (1, 1) => result = point_add(&result, &g_plus_q, params)?,
            (1, 0) => result = point_add(&result, g, params)?,
            (0, 1) => result = point_add(&result, q, params)?,
            _ => {}
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc::curves::get_curve_params;
    use hitls_types::EccCurveId;

    fn p256_params() -> CurveParams {
        get_curve_params(EccCurveId::NistP256).unwrap()
    }

    fn p256_generator(params: &CurveParams) -> JacobianPoint {
        JacobianPoint::from_affine(&params.gx, &params.gy)
    }

    #[test]
    fn infinity_is_infinity() {
        let inf = JacobianPoint::infinity();
        assert!(inf.is_infinity());
        assert!(inf.z.is_zero());
    }

    #[test]
    fn from_affine_to_affine_roundtrip() {
        let params = p256_params();
        let g = p256_generator(&params);
        assert!(!g.is_infinity());
        let (x, y) = g.to_affine(&params.p).unwrap().unwrap();
        assert_eq!(x, params.gx);
        assert_eq!(y, params.gy);
    }

    #[test]
    fn infinity_to_affine_returns_none() {
        let params = p256_params();
        let inf = JacobianPoint::infinity();
        assert!(inf.to_affine(&params.p).unwrap().is_none());
    }

    #[test]
    fn point_add_identity() {
        let params = p256_params();
        let g = p256_generator(&params);
        let inf = JacobianPoint::infinity();
        // G + O = G
        let r = point_add(&g, &inf, &params).unwrap();
        let (rx, ry) = r.to_affine(&params.p).unwrap().unwrap();
        assert_eq!(rx, params.gx);
        assert_eq!(ry, params.gy);
        // O + G = G
        let r2 = point_add(&inf, &g, &params).unwrap();
        let (rx2, ry2) = r2.to_affine(&params.p).unwrap().unwrap();
        assert_eq!(rx2, params.gx);
        assert_eq!(ry2, params.gy);
    }

    #[test]
    fn point_add_inverse_gives_infinity() {
        let params = p256_params();
        let g = p256_generator(&params);
        // -G has negated y coordinate: (gx, p - gy)
        let neg_gy = params.p.sub(&params.gy);
        let neg_g = JacobianPoint::from_affine(&params.gx, &neg_gy);
        let r = point_add(&g, &neg_g, &params).unwrap();
        assert!(r.is_infinity());
    }

    #[test]
    fn point_double_matches_add() {
        let params = p256_params();
        let g = p256_generator(&params);
        let two_g = point_double(&g, &params).unwrap();
        assert!(!two_g.is_infinity());
        // 2G via add(G, G) should match
        let two_g_add = point_add(&g, &g, &params).unwrap();
        let (x1, y1) = two_g.to_affine(&params.p).unwrap().unwrap();
        let (x2, y2) = two_g_add.to_affine(&params.p).unwrap().unwrap();
        assert_eq!(x1, x2);
        assert_eq!(y1, y2);
    }

    #[test]
    fn scalar_mul_by_one() {
        let params = p256_params();
        let g = p256_generator(&params);
        let one = BigNum::from_u64(1);
        let r = scalar_mul(&one, &g, &params).unwrap();
        let (rx, ry) = r.to_affine(&params.p).unwrap().unwrap();
        assert_eq!(rx, params.gx);
        assert_eq!(ry, params.gy);
    }

    #[test]
    fn scalar_mul_by_zero_gives_infinity() {
        let params = p256_params();
        let g = p256_generator(&params);
        let zero = BigNum::zero();
        let r = scalar_mul(&zero, &g, &params).unwrap();
        assert!(r.is_infinity());
    }

    #[test]
    fn scalar_mul_by_order_gives_infinity() {
        let params = p256_params();
        let g = p256_generator(&params);
        let r = scalar_mul(&params.n, &g, &params).unwrap();
        assert!(r.is_infinity());
    }

    #[test]
    fn scalar_mul_add_consistency() {
        let params = p256_params();
        let g = p256_generator(&params);
        let k1 = BigNum::from_u64(3);
        let k2 = BigNum::from_u64(5);
        let q = point_double(&g, &params).unwrap();
        // k1*G + k2*Q via Shamir's trick
        let combined = scalar_mul_add(&k1, &g, &k2, &q, &params).unwrap();
        // k1*G + k2*Q via separate operations
        let part1 = scalar_mul(&k1, &g, &params).unwrap();
        let part2 = scalar_mul(&k2, &q, &params).unwrap();
        let separate = point_add(&part1, &part2, &params).unwrap();
        let (cx, cy) = combined.to_affine(&params.p).unwrap().unwrap();
        let (sx, sy) = separate.to_affine(&params.p).unwrap().unwrap();
        assert_eq!(cx, sx);
        assert_eq!(cy, sy);
    }
}
