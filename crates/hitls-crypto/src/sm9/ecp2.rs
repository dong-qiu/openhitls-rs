//! G2 point operations on the twist E'(Fp²): y² = x³ + 5u.
//!
//! Uses Jacobian projective coordinates over Fp2.

use hitls_bignum::BigNum;
use hitls_types::CryptoError;

use super::curve;
use super::fp::Fp;
use super::fp2::Fp2;

/// Point on E'(Fp²) in Jacobian coordinates.
#[derive(Clone, Debug)]
pub(crate) struct EcPointG2 {
    pub x: Fp2,
    pub y: Fp2,
    pub z: Fp2,
}

impl EcPointG2 {
    pub fn infinity() -> Self {
        Self {
            x: Fp2::one(),
            y: Fp2::one(),
            z: Fp2::zero(),
        }
    }

    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    pub fn from_affine(x: Fp2, y: Fp2) -> Self {
        Self {
            x,
            y,
            z: Fp2::one(),
        }
    }

    /// Generator P2.
    pub fn generator() -> Self {
        let x = Fp2::new(
            Fp::from_bignum(curve::p2_x0()),
            Fp::from_bignum(curve::p2_x1()),
        );
        let y = Fp2::new(
            Fp::from_bignum(curve::p2_y0()),
            Fp::from_bignum(curve::p2_y1()),
        );
        Self::from_affine(x, y)
    }

    /// Convert to affine.
    pub fn to_affine(&self) -> Result<(Fp2, Fp2), CryptoError> {
        if self.is_infinity() {
            return Err(CryptoError::InvalidArg);
        }
        let z_inv = self.z.inv()?;
        let z2 = z_inv.sqr()?;
        let z3 = z2.mul(&z_inv)?;
        Ok((self.x.mul(&z2)?, self.y.mul(&z3)?))
    }

    /// Point doubling (a=0 for twisted curve).
    pub fn double(&self) -> Result<Self, CryptoError> {
        if self.is_infinity() {
            return Ok(self.clone());
        }
        let a = self.x.sqr()?;
        let b = self.y.sqr()?;
        let c = b.sqr()?;
        let t = self.x.add(&b)?;
        let d = t.sqr()?.sub(&a)?.sub(&c)?.double()?;
        let e = a.double()?.add(&a)?; // 3X²
        let f = e.sqr()?;

        let x3 = f.sub(&d.double()?)?;
        let y3 = e.mul(&d.sub(&x3)?)?.sub(&c.double()?.double()?.double()?)?;
        let z3 = self.y.mul(&self.z)?.double()?;

        Ok(Self {
            x: x3,
            y: y3,
            z: z3,
        })
    }

    /// Point addition.
    pub fn add(&self, other: &Self) -> Result<Self, CryptoError> {
        if self.is_infinity() {
            return Ok(other.clone());
        }
        if other.is_infinity() {
            return Ok(self.clone());
        }

        let z1_sq = self.z.sqr()?;
        let z2_sq = other.z.sqr()?;
        let u1 = self.x.mul(&z2_sq)?;
        let u2 = other.x.mul(&z1_sq)?;
        let s1 = self.y.mul(&z2_sq)?.mul(&other.z)?;
        let s2 = other.y.mul(&z1_sq)?.mul(&self.z)?;

        if u1 == u2 {
            if s1 == s2 {
                return self.double();
            } else {
                return Ok(Self::infinity());
            }
        }

        let h = u2.sub(&u1)?;
        let r = s2.sub(&s1)?;
        let h_sq = h.sqr()?;
        let h_cu = h_sq.mul(&h)?;
        let u1h2 = u1.mul(&h_sq)?;

        let x3 = r.sqr()?.sub(&h_cu)?.sub(&u1h2.double()?)?;
        let y3 = r.mul(&u1h2.sub(&x3)?)?.sub(&s1.mul(&h_cu)?)?;
        let z3 = self.z.mul(&other.z)?.mul(&h)?;

        Ok(Self {
            x: x3,
            y: y3,
            z: z3,
        })
    }

    /// Scalar multiplication [k]Q.
    pub fn scalar_mul(&self, k: &BigNum) -> Result<Self, CryptoError> {
        let bits = k.to_bytes_be();
        let mut result = Self::infinity();
        let mut started = false;
        for byte in &bits {
            for bit in (0..8).rev() {
                if started {
                    result = result.double()?;
                }
                if (byte >> bit) & 1 == 1 {
                    if started {
                        result = result.add(self)?;
                    } else {
                        result = self.clone();
                        started = true;
                    }
                }
            }
        }
        Ok(result)
    }

    /// Negate.
    pub fn negate(&self) -> Result<Self, CryptoError> {
        Ok(Self {
            x: self.x.clone(),
            y: self.y.neg()?,
            z: self.z.clone(),
        })
    }

    /// Serialize to 128 bytes.
    /// SM9 convention: x1(32) || x0(32) || y1(32) || y0(32)
    /// where element = c0 + c1·u.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let (ax, ay) = self.to_affine()?;
        let mut out = Vec::with_capacity(128);
        // SM9: coefficient of u first, then constant
        out.extend_from_slice(&ax.c1.to_bytes_be());
        out.extend_from_slice(&ax.c0.to_bytes_be());
        out.extend_from_slice(&ay.c1.to_bytes_be());
        out.extend_from_slice(&ay.c0.to_bytes_be());
        Ok(out)
    }

    /// Deserialize from 128 bytes.
    /// SM9 convention: x1(32) || x0(32) || y1(32) || y0(32).
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() != 128 {
            return Err(CryptoError::InvalidArg);
        }
        let x = Fp2::new(
            Fp::from_bytes_be(&data[32..64])?, // c0
            Fp::from_bytes_be(&data[..32])?,   // c1
        );
        let y = Fp2::new(
            Fp::from_bytes_be(&data[96..128])?, // c0
            Fp::from_bytes_be(&data[64..96])?,  // c1
        );
        Ok(Self::from_affine(x, y))
    }
}

impl PartialEq for EcPointG2 {
    fn eq(&self, other: &Self) -> bool {
        if self.is_infinity() && other.is_infinity() {
            return true;
        }
        if self.is_infinity() || other.is_infinity() {
            return false;
        }
        let z1_sq = self.z.sqr().unwrap();
        let z2_sq = other.z.sqr().unwrap();
        let lx = self.x.mul(&z2_sq).unwrap();
        let rx = other.x.mul(&z1_sq).unwrap();
        let ly = self.y.mul(&z2_sq).unwrap().mul(&other.z).unwrap();
        let ry = other.y.mul(&z1_sq).unwrap().mul(&self.z).unwrap();
        lx == rx && ly == ry
    }
}

impl Eq for EcPointG2 {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g2_infinity_properties() {
        let inf = EcPointG2::infinity();
        assert!(inf.is_infinity());
        let gen = EcPointG2::generator();
        assert!(!gen.is_infinity());
    }

    #[test]
    fn test_g2_add_identity() {
        let g = EcPointG2::generator();
        let inf = EcPointG2::infinity();
        // P + O == P
        let r1 = g.add(&inf).unwrap();
        assert_eq!(r1, g);
        // O + P == P
        let r2 = inf.add(&g).unwrap();
        assert_eq!(r2, g);
    }

    #[test]
    fn test_g2_double_equals_add_self() {
        let g = EcPointG2::generator();
        let doubled = g.double().unwrap();
        let added = g.add(&g).unwrap();
        assert_eq!(doubled, added);
    }

    #[test]
    fn test_g2_negate_then_add_gives_infinity() {
        let g = EcPointG2::generator();
        let neg_g = g.negate().unwrap();
        let result = g.add(&neg_g).unwrap();
        assert!(result.is_infinity());
    }

    #[test]
    fn test_g2_serialize_roundtrip() {
        let g = EcPointG2::generator();
        let bytes = g.to_bytes().unwrap();
        assert_eq!(bytes.len(), 128);
        let recovered = EcPointG2::from_bytes(&bytes).unwrap();
        assert_eq!(recovered, g);
    }

    #[test]
    fn test_g2_point_double_correctness() {
        // Double the generator, then verify the result is on the twist curve
        // y^2 = x^3 + 5u, and that 2G != G and 2G != O.
        let g = EcPointG2::generator();
        let g2 = g.double().unwrap();

        assert!(!g2.is_infinity(), "2G should not be infinity");
        assert_ne!(g2, g, "2G should differ from G");

        // Verify 2G is on the curve: y^2 = x^3 + 5u
        let (x, y) = g2.to_affine().unwrap();
        let y2 = y.sqr().unwrap();
        let x3 = x.sqr().unwrap().mul(&x).unwrap();
        let b_twist = Fp2::new(Fp::zero(), Fp::from_u64(5));
        let rhs = x3.add(&b_twist).unwrap();
        assert_eq!(y2, rhs, "2G must satisfy y^2 = x^3 + 5u");

        // Also verify 4G = double(2G) is consistent with 2G + 2G
        let g4_via_double = g2.double().unwrap();
        let g4_via_add = g2.add(&g2).unwrap();
        assert_eq!(g4_via_double, g4_via_add, "double(2G) should equal 2G + 2G");
    }

    #[test]
    fn test_g2_point_add_identity_non_generator() {
        // Test P + O = P and O + P = P for a non-generator point (2G)
        let g = EcPointG2::generator();
        let p = g.double().unwrap();
        let inf = EcPointG2::infinity();

        let r1 = p.add(&inf).unwrap();
        assert_eq!(r1, p, "P + O should equal P");

        let r2 = inf.add(&p).unwrap();
        assert_eq!(r2, p, "O + P should equal P");

        // O + O = O
        let r3 = inf.add(&inf).unwrap();
        assert!(r3.is_infinity(), "O + O should be O");
    }

    #[test]
    fn test_g2_point_add_inverse_non_generator() {
        // Test P + (-P) = O for a non-generator point
        let g = EcPointG2::generator();
        let three = BigNum::from_u64(3);
        let p = g.scalar_mul(&three).unwrap();

        let neg_p = p.negate().unwrap();
        let result = p.add(&neg_p).unwrap();
        assert!(result.is_infinity(), "P + (-P) should be infinity");

        // Also verify (-P) + P = O
        let result2 = neg_p.add(&p).unwrap();
        assert!(result2.is_infinity(), "(-P) + P should be infinity");
    }

    #[test]
    fn test_g2_point_scalar_mul_identity() {
        // 1 * G = G
        let g = EcPointG2::generator();
        let one = BigNum::from_u64(1);
        let result = g.scalar_mul(&one).unwrap();
        assert_eq!(result, g, "1 * G should equal G");

        // 1 * (2G) = 2G
        let g2 = g.double().unwrap();
        let result2 = g2.scalar_mul(&one).unwrap();
        assert_eq!(result2, g2, "1 * 2G should equal 2G");
    }

    #[test]
    fn test_g2_point_scalar_mul_order() {
        // n * G = O where n is the group order
        let g = EcPointG2::generator();
        let n = curve::order();
        let result = g.scalar_mul(&n).unwrap();
        assert!(result.is_infinity(), "n * G should be infinity");

        // (n-1) * G should NOT be infinity, and (n-1)*G + G = O
        let n_minus_1 = n.sub(&BigNum::from_u64(1));
        let almost = g.scalar_mul(&n_minus_1).unwrap();
        assert!(!almost.is_infinity(), "(n-1)*G should not be infinity");
        let sum = almost.add(&g).unwrap();
        assert!(sum.is_infinity(), "(n-1)*G + G should be infinity");

        // Equivalently, (n-1)*G = -G
        let neg_g = g.negate().unwrap();
        assert_eq!(almost, neg_g, "(n-1)*G should equal -G");
    }

    #[test]
    fn test_g2_point_from_bytes_invalid() {
        // Construct 128 bytes that do NOT represent a valid point on the twist curve.
        // Use the generator's x-coordinate but a corrupted y-coordinate.
        let g = EcPointG2::generator();
        let mut bytes = g.to_bytes().unwrap();
        assert_eq!(bytes.len(), 128);

        // Corrupt the y-coordinate (bytes 64..128 contain y1 || y0)
        bytes[64] ^= 0xFF;
        bytes[65] ^= 0xFF;

        // from_bytes itself doesn't validate on-curve, so the point will parse but
        // won't satisfy the curve equation. Verify this:
        let bad_point = EcPointG2::from_bytes(&bytes).unwrap();
        let (bx, by) = bad_point.to_affine().unwrap();
        let y2 = by.sqr().unwrap();
        let x3 = bx.sqr().unwrap().mul(&bx).unwrap();
        let b_twist = Fp2::new(Fp::zero(), Fp::from_u64(5));
        let rhs = x3.add(&b_twist).unwrap();
        assert_ne!(y2, rhs, "Corrupted point should NOT be on the curve");

        // Also test wrong length inputs
        assert!(
            EcPointG2::from_bytes(&[0u8; 127]).is_err(),
            "127 bytes should fail"
        );
        assert!(
            EcPointG2::from_bytes(&[0u8; 129]).is_err(),
            "129 bytes should fail"
        );
        assert!(
            EcPointG2::from_bytes(&[]).is_err(),
            "empty input should fail"
        );
    }

    #[test]
    fn test_g2_multi_scalar_mul_consistency() {
        // Compute a*P + b*Q using separate scalar_mul + add,
        // then verify against (a+b*k)*G where P = G, Q = k*G.
        let g = EcPointG2::generator();
        let a = BigNum::from_u64(7);
        let b = BigNum::from_u64(13);
        let k = BigNum::from_u64(5);

        let q = g.scalar_mul(&k).unwrap(); // Q = 5G

        // Method 1: a*P + b*Q = 7*G + 13*(5*G), where P = G
        let ap = g.scalar_mul(&a).unwrap();
        let bq = q.scalar_mul(&b).unwrap();
        let result1 = ap.add(&bq).unwrap();

        // Method 2: (a + b*k)*G = (7 + 65)*G = 72*G
        let bk = b.mul(&k);
        let combined = a.add(&bk);
        let result2 = g.scalar_mul(&combined).unwrap();

        assert_eq!(
            result1, result2,
            "a*P + b*Q should equal (a+b*k)*G when Q = k*G"
        );

        // Verify commutativity: a*P + b*Q = b*Q + a*P
        let result3 = bq.add(&ap).unwrap();
        assert_eq!(result1, result3, "addition should be commutative");
    }

    #[test]
    fn test_g2_point_affine_jacobian_roundtrip() {
        // Convert generator to affine and back, verify equality
        let g = EcPointG2::generator();
        let (ax, ay) = g.to_affine().unwrap();
        let recovered = EcPointG2::from_affine(ax, ay);
        assert_eq!(
            recovered, g,
            "affine->jacobian roundtrip should preserve the point"
        );

        // Also test with a non-trivial Jacobian representation (Z != 1)
        // After doubling, Z will generally not be 1
        let g2 = g.double().unwrap();
        assert_ne!(
            g2.z,
            Fp2::one(),
            "doubled point should have non-trivial Z coordinate"
        );
        let (ax2, ay2) = g2.to_affine().unwrap();
        let g2_recovered = EcPointG2::from_affine(ax2, ay2);
        assert_eq!(
            g2_recovered, g2,
            "affine->jacobian roundtrip for doubled point should preserve the point"
        );

        // Infinity cannot be converted to affine (no affine representation)
        let inf = EcPointG2::infinity();
        assert!(
            inf.to_affine().is_err(),
            "converting infinity to affine should return an error"
        );
    }
}
