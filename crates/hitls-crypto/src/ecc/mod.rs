//! Elliptic Curve Cryptography (ECC) core primitives.
//!
//! Provides fundamental elliptic curve types including points, groups (curves),
//! and scalar arithmetic over NIST P-256 and P-384 Weierstrass curves.
//! This module underpins higher-level protocols such as ECDSA and ECDH.

pub(crate) mod curves;
pub(crate) mod point;

use hitls_bignum::BigNum;
use hitls_types::{CryptoError, EccCurveId};

use curves::{get_curve_params, CurveParams};
use point::{point_add as jac_point_add, scalar_mul, scalar_mul_add, JacobianPoint};

/// An elliptic curve group (curve and its parameters).
#[derive(Clone)]
pub struct EcGroup {
    curve_id: EccCurveId,
    params: CurveParams,
}

impl std::fmt::Debug for EcGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcGroup")
            .field("curve_id", &self.curve_id)
            .finish()
    }
}

impl EcGroup {
    /// Create an `EcGroup` for a named curve.
    pub fn new(curve_id: EccCurveId) -> Result<Self, CryptoError> {
        let params = get_curve_params(curve_id)?;
        Ok(EcGroup { curve_id, params })
    }

    /// Return the curve identifier.
    pub fn curve_id(&self) -> EccCurveId {
        self.curve_id
    }

    /// Return the field element size in bytes.
    pub fn field_size(&self) -> usize {
        self.params.field_size
    }

    /// Return the order size in bytes.
    pub fn order_size(&self) -> usize {
        self.params.field_size
    }

    /// Return a reference to the curve order n.
    pub fn order(&self) -> &BigNum {
        &self.params.n
    }

    /// Return a reference to the curve parameters.
    pub(crate) fn params(&self) -> &CurveParams {
        &self.params
    }

    /// Return the base point G.
    pub fn generator(&self) -> EcPoint {
        EcPoint {
            x: self.params.gx.clone(),
            y: self.params.gy.clone(),
            infinity: false,
        }
    }

    /// Scalar multiplication: R = k * P.
    pub fn scalar_mul(&self, k: &BigNum, point: &EcPoint) -> Result<EcPoint, CryptoError> {
        if point.infinity {
            return Ok(EcPoint::infinity());
        }
        let jp = JacobianPoint::from_affine(&point.x, &point.y);
        let result = scalar_mul(k, &jp, &self.params)?;
        jacobian_to_ecpoint(&result, &self.params)
    }

    /// Scalar multiplication with the base point: R = k * G.
    pub fn scalar_mul_base(&self, k: &BigNum) -> Result<EcPoint, CryptoError> {
        let g = JacobianPoint::from_affine(&self.params.gx, &self.params.gy);
        let result = scalar_mul(k, &g, &self.params)?;
        jacobian_to_ecpoint(&result, &self.params)
    }

    /// Point addition: R = P + Q.
    pub fn point_add(&self, p: &EcPoint, q: &EcPoint) -> Result<EcPoint, CryptoError> {
        if p.infinity {
            return Ok(q.clone());
        }
        if q.infinity {
            return Ok(p.clone());
        }
        let jp = JacobianPoint::from_affine(&p.x, &p.y);
        let jq = JacobianPoint::from_affine(&q.x, &q.y);
        let result = jac_point_add(&jp, &jq, &self.params)?;
        jacobian_to_ecpoint(&result, &self.params)
    }

    /// Point negation: R = -P (returns (x, p - y)).
    pub fn point_negate(&self, point: &EcPoint) -> Result<EcPoint, CryptoError> {
        if point.infinity {
            return Ok(EcPoint::infinity());
        }
        let neg_y = self.params.p.sub(&point.y);
        Ok(EcPoint::new(point.x.clone(), neg_y))
    }

    /// Combined scalar multiplication: R = k1*G + k2*Q (Shamir's trick).
    pub fn scalar_mul_add(
        &self,
        k1: &BigNum,
        k2: &BigNum,
        q: &EcPoint,
    ) -> Result<EcPoint, CryptoError> {
        if q.infinity {
            return self.scalar_mul_base(k1);
        }
        let g = JacobianPoint::from_affine(&self.params.gx, &self.params.gy);
        let qj = JacobianPoint::from_affine(&q.x, &q.y);
        let result = scalar_mul_add(k1, &g, k2, &qj, &self.params)?;
        jacobian_to_ecpoint(&result, &self.params)
    }
}

/// A point on an elliptic curve (affine coordinates).
#[derive(Debug, Clone)]
pub struct EcPoint {
    x: BigNum,
    y: BigNum,
    infinity: bool,
}

impl EcPoint {
    /// Create a new point from affine coordinates.
    pub fn new(x: BigNum, y: BigNum) -> Self {
        EcPoint {
            x,
            y,
            infinity: false,
        }
    }

    /// Create the point at infinity (identity element).
    pub fn infinity() -> Self {
        EcPoint {
            x: BigNum::zero(),
            y: BigNum::zero(),
            infinity: true,
        }
    }

    /// Check whether this point is the point at infinity.
    pub fn is_infinity(&self) -> bool {
        self.infinity
    }

    /// Return a reference to the x-coordinate.
    pub fn x(&self) -> &BigNum {
        &self.x
    }

    /// Return a reference to the y-coordinate.
    pub fn y(&self) -> &BigNum {
        &self.y
    }

    /// Check whether this point lies on the given curve.
    ///
    /// Verifies y² ≡ x³ + ax + b (mod p).
    pub fn is_on_curve(&self, group: &EcGroup) -> Result<bool, CryptoError> {
        if self.infinity {
            return Ok(true);
        }

        let p = &group.params.p;

        // y² mod p
        let y_sq = self.y.mod_mul(&self.y, p)?;

        // x³ + ax + b mod p
        let x_sq = self.x.mod_mul(&self.x, p)?;
        let x_cu = x_sq.mod_mul(&self.x, p)?;
        let ax = self.x.mod_mul(&group.params.a, p)?;
        let rhs = x_cu.mod_add(&ax, p)?.mod_add(&group.params.b, p)?;

        Ok(y_sq == rhs)
    }

    /// Encode the point in uncompressed form: 0x04 || x || y.
    pub fn to_uncompressed(&self, group: &EcGroup) -> Result<Vec<u8>, CryptoError> {
        if self.infinity {
            return Err(CryptoError::EccPointAtInfinity);
        }

        let fs = group.field_size();
        let mut out = Vec::with_capacity(1 + 2 * fs);
        out.push(0x04);
        out.extend_from_slice(&self.x.to_bytes_be_padded(fs)?);
        out.extend_from_slice(&self.y.to_bytes_be_padded(fs)?);
        Ok(out)
    }

    /// Decode a point from its uncompressed representation.
    ///
    /// Validates the format (0x04 prefix) and checks the point is on the curve.
    pub fn from_uncompressed(group: &EcGroup, data: &[u8]) -> Result<Self, CryptoError> {
        let fs = group.field_size();
        let expected_len = 1 + 2 * fs;

        if data.len() != expected_len || data[0] != 0x04 {
            return Err(CryptoError::EccInvalidPublicKey);
        }

        let x = BigNum::from_bytes_be(&data[1..1 + fs]);
        let y = BigNum::from_bytes_be(&data[1 + fs..]);

        let point = EcPoint::new(x, y);

        // Validate the point is on the curve
        if !point.is_on_curve(group)? {
            return Err(CryptoError::EccPointNotOnCurve);
        }

        Ok(point)
    }
}

impl PartialEq for EcPoint {
    fn eq(&self, other: &Self) -> bool {
        if self.infinity && other.infinity {
            return true;
        }
        if self.infinity != other.infinity {
            return false;
        }
        self.x == other.x && self.y == other.y
    }
}

impl Eq for EcPoint {}

/// Convert a JacobianPoint to an EcPoint (affine).
fn jacobian_to_ecpoint(jp: &JacobianPoint, params: &CurveParams) -> Result<EcPoint, CryptoError> {
    if jp.is_infinity() {
        return Ok(EcPoint::infinity());
    }
    match jp.to_affine(&params.p)? {
        Some((x, y)) => Ok(EcPoint::new(x, y)),
        None => Ok(EcPoint::infinity()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_on_curve_p256() {
        let group = EcGroup::new(EccCurveId::NistP256).unwrap();
        let g = group.generator();
        assert!(g.is_on_curve(&group).unwrap());
    }

    #[test]
    fn test_generator_on_curve_p384() {
        let group = EcGroup::new(EccCurveId::NistP384).unwrap();
        let g = group.generator();
        assert!(g.is_on_curve(&group).unwrap());
    }

    #[test]
    fn test_double_equals_add_p256() {
        let group = EcGroup::new(EccCurveId::NistP256).unwrap();
        let g = group.generator();

        // 2G via scalar_mul
        let two_g = group.scalar_mul_base(&BigNum::from_u64(2)).unwrap();

        // G + G via adding
        let g_plus_g = group
            .scalar_mul_add(&BigNum::from_u64(1), &BigNum::from_u64(1), &g)
            .unwrap();

        assert_eq!(two_g, g_plus_g);
        assert!(two_g.is_on_curve(&group).unwrap());
    }

    #[test]
    fn test_order_times_g_is_infinity_p256() {
        let group = EcGroup::new(EccCurveId::NistP256).unwrap();
        let n = group.order().clone();
        let result = group.scalar_mul_base(&n).unwrap();
        assert!(result.is_infinity());
    }

    #[test]
    fn test_point_encoding_roundtrip_p256() {
        let group = EcGroup::new(EccCurveId::NistP256).unwrap();
        let g = group.generator();

        let encoded = g.to_uncompressed(&group).unwrap();
        assert_eq!(encoded.len(), 65); // 1 + 32 + 32
        assert_eq!(encoded[0], 0x04);

        let decoded = EcPoint::from_uncompressed(&group, &encoded).unwrap();
        assert_eq!(g, decoded);
    }

    #[test]
    fn test_invalid_point_rejected() {
        let group = EcGroup::new(EccCurveId::NistP256).unwrap();
        // A point not on the curve
        let bad_point = EcPoint::new(BigNum::from_u64(1), BigNum::from_u64(2));
        assert!(!bad_point.is_on_curve(&group).unwrap());
    }

    #[test]
    fn test_scalar_mul_small_values_p256() {
        let group = EcGroup::new(EccCurveId::NistP256).unwrap();

        // 1*G = G
        let one_g = group.scalar_mul_base(&BigNum::from_u64(1)).unwrap();
        let g = group.generator();
        assert_eq!(one_g, g);

        // 3*G should be on curve
        let three_g = group.scalar_mul_base(&BigNum::from_u64(3)).unwrap();
        assert!(three_g.is_on_curve(&group).unwrap());
        assert!(!three_g.is_infinity());
    }

    #[test]
    fn test_infinity_encoding_error() {
        let group = EcGroup::new(EccCurveId::NistP256).unwrap();
        let inf = EcPoint::infinity();
        assert!(inf.to_uncompressed(&group).is_err());
    }

    // --- P-192 tests ---

    #[test]
    fn test_generator_on_curve_p192() {
        let group = EcGroup::new(EccCurveId::NistP192).unwrap();
        let g = group.generator();
        assert!(g.is_on_curve(&group).unwrap());
    }

    #[test]
    fn test_point_encoding_roundtrip_p192() {
        let group = EcGroup::new(EccCurveId::NistP192).unwrap();
        let g = group.generator();
        let encoded = g.to_uncompressed(&group).unwrap();
        assert_eq!(encoded.len(), 1 + 2 * 24); // 49 bytes
        assert_eq!(encoded[0], 0x04);
        let decoded = EcPoint::from_uncompressed(&group, &encoded).unwrap();
        assert_eq!(g, decoded);
    }

    #[test]
    fn test_scalar_mul_small_values_p192() {
        let group = EcGroup::new(EccCurveId::NistP192).unwrap();
        let one_g = group.scalar_mul_base(&BigNum::from_u64(1)).unwrap();
        assert_eq!(one_g, group.generator());
        let three_g = group.scalar_mul_base(&BigNum::from_u64(3)).unwrap();
        assert!(three_g.is_on_curve(&group).unwrap());
        assert!(!three_g.is_infinity());
    }

    #[test]
    fn test_order_times_g_is_infinity_p192() {
        let group = EcGroup::new(EccCurveId::NistP192).unwrap();
        let n = group.order().clone();
        let result = group.scalar_mul_base(&n).unwrap();
        assert!(result.is_infinity());
    }

    // --- P-224 tests ---

    #[test]
    fn test_generator_on_curve_p224() {
        let group = EcGroup::new(EccCurveId::NistP224).unwrap();
        let g = group.generator();
        assert!(g.is_on_curve(&group).unwrap());
    }

    #[test]
    fn test_point_encoding_roundtrip_p224() {
        let group = EcGroup::new(EccCurveId::NistP224).unwrap();
        let g = group.generator();
        let encoded = g.to_uncompressed(&group).unwrap();
        assert_eq!(encoded.len(), 1 + 2 * 28); // 57 bytes
        assert_eq!(encoded[0], 0x04);
        let decoded = EcPoint::from_uncompressed(&group, &encoded).unwrap();
        assert_eq!(g, decoded);
    }

    #[test]
    fn test_scalar_mul_small_values_p224() {
        let group = EcGroup::new(EccCurveId::NistP224).unwrap();
        let one_g = group.scalar_mul_base(&BigNum::from_u64(1)).unwrap();
        assert_eq!(one_g, group.generator());
        let three_g = group.scalar_mul_base(&BigNum::from_u64(3)).unwrap();
        assert!(three_g.is_on_curve(&group).unwrap());
        assert!(!three_g.is_infinity());
    }

    #[test]
    fn test_order_times_g_is_infinity_p224() {
        let group = EcGroup::new(EccCurveId::NistP224).unwrap();
        let n = group.order().clone();
        let result = group.scalar_mul_base(&n).unwrap();
        assert!(result.is_infinity());
    }

    // --- P-521 tests ---

    #[test]
    fn test_generator_on_curve_p521() {
        let group = EcGroup::new(EccCurveId::NistP521).unwrap();
        let g = group.generator();
        assert!(g.is_on_curve(&group).unwrap());
    }

    #[test]
    fn test_point_encoding_roundtrip_p521() {
        let group = EcGroup::new(EccCurveId::NistP521).unwrap();
        let g = group.generator();
        let encoded = g.to_uncompressed(&group).unwrap();
        assert_eq!(encoded.len(), 1 + 2 * 66); // 133 bytes
        assert_eq!(encoded[0], 0x04);
        let decoded = EcPoint::from_uncompressed(&group, &encoded).unwrap();
        assert_eq!(g, decoded);
    }

    #[test]
    fn test_scalar_mul_small_values_p521() {
        let group = EcGroup::new(EccCurveId::NistP521).unwrap();
        let one_g = group.scalar_mul_base(&BigNum::from_u64(1)).unwrap();
        assert_eq!(one_g, group.generator());
        let three_g = group.scalar_mul_base(&BigNum::from_u64(3)).unwrap();
        assert!(three_g.is_on_curve(&group).unwrap());
    }

    #[test]
    #[ignore] // Slow for 521-bit curve in debug mode
    fn test_order_times_g_is_infinity_p521() {
        let group = EcGroup::new(EccCurveId::NistP521).unwrap();
        let n = group.order().clone();
        let result = group.scalar_mul_base(&n).unwrap();
        assert!(result.is_infinity());
    }

    // --- Brainpool P-256r1 tests ---

    #[test]
    fn test_generator_on_curve_bp256() {
        let group = EcGroup::new(EccCurveId::BrainpoolP256r1).unwrap();
        let g = group.generator();
        assert!(g.is_on_curve(&group).unwrap());
    }

    #[test]
    fn test_point_encoding_roundtrip_bp256() {
        let group = EcGroup::new(EccCurveId::BrainpoolP256r1).unwrap();
        let g = group.generator();
        let encoded = g.to_uncompressed(&group).unwrap();
        assert_eq!(encoded.len(), 65);
        let decoded = EcPoint::from_uncompressed(&group, &encoded).unwrap();
        assert_eq!(g, decoded);
    }

    #[test]
    fn test_scalar_mul_small_values_bp256() {
        let group = EcGroup::new(EccCurveId::BrainpoolP256r1).unwrap();
        let one_g = group.scalar_mul_base(&BigNum::from_u64(1)).unwrap();
        assert_eq!(one_g, group.generator());
        let two_g = group.scalar_mul_base(&BigNum::from_u64(2)).unwrap();
        assert!(two_g.is_on_curve(&group).unwrap());
        assert!(!two_g.is_infinity());
    }

    #[test]
    fn test_order_times_g_is_infinity_bp256() {
        let group = EcGroup::new(EccCurveId::BrainpoolP256r1).unwrap();
        let n = group.order().clone();
        let result = group.scalar_mul_base(&n).unwrap();
        assert!(result.is_infinity());
    }

    #[test]
    fn test_double_equals_add_bp256() {
        let group = EcGroup::new(EccCurveId::BrainpoolP256r1).unwrap();
        let g = group.generator();
        let two_g = group.scalar_mul_base(&BigNum::from_u64(2)).unwrap();
        let g_plus_g = group
            .scalar_mul_add(&BigNum::from_u64(1), &BigNum::from_u64(1), &g)
            .unwrap();
        assert_eq!(two_g, g_plus_g);
        assert!(two_g.is_on_curve(&group).unwrap());
    }

    // --- Brainpool P-384r1 tests ---

    #[test]
    fn test_generator_on_curve_bp384() {
        let group = EcGroup::new(EccCurveId::BrainpoolP384r1).unwrap();
        let g = group.generator();
        assert!(g.is_on_curve(&group).unwrap());
    }

    #[test]
    fn test_point_encoding_roundtrip_bp384() {
        let group = EcGroup::new(EccCurveId::BrainpoolP384r1).unwrap();
        let g = group.generator();
        let encoded = g.to_uncompressed(&group).unwrap();
        assert_eq!(encoded.len(), 1 + 2 * 48);
        let decoded = EcPoint::from_uncompressed(&group, &encoded).unwrap();
        assert_eq!(g, decoded);
    }

    // --- Brainpool P-512r1 tests ---

    #[test]
    fn test_generator_on_curve_bp512() {
        let group = EcGroup::new(EccCurveId::BrainpoolP512r1).unwrap();
        let g = group.generator();
        assert!(g.is_on_curve(&group).unwrap());
    }

    #[test]
    fn test_point_encoding_roundtrip_bp512() {
        let group = EcGroup::new(EccCurveId::BrainpoolP512r1).unwrap();
        let g = group.generator();
        let encoded = g.to_uncompressed(&group).unwrap();
        assert_eq!(encoded.len(), 1 + 2 * 64);
        let decoded = EcPoint::from_uncompressed(&group, &encoded).unwrap();
        assert_eq!(g, decoded);
    }

    #[test]
    fn test_ecc_scalar_mul_zero() {
        let group = EcGroup::new(EccCurveId::NistP256).unwrap();
        let result = group.scalar_mul_base(&BigNum::zero()).unwrap();
        assert!(result.is_infinity());
    }

    #[test]
    fn test_ecc_point_add_with_negate() {
        let group = EcGroup::new(EccCurveId::NistP256).unwrap();
        let g = group.generator();
        let neg_g = group.point_negate(&g).unwrap();
        let sum = group.point_add(&g, &neg_g).unwrap();
        assert!(sum.is_infinity(), "P + (-P) should be point at infinity");
    }
}
