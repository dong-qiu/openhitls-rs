//! Fp2 = Fp[u] / (u² + 2) arithmetic for SM9 BN256.

use hitls_types::CryptoError;

use super::fp::Fp;

/// Element of Fp2 = a0 + a1·u where u² = -2.
#[derive(Clone, Debug)]
pub(crate) struct Fp2 {
    pub c0: Fp,
    pub c1: Fp,
}

impl Fp2 {
    pub fn zero() -> Self {
        Self {
            c0: Fp::zero(),
            c1: Fp::zero(),
        }
    }

    pub fn one() -> Self {
        Self {
            c0: Fp::one(),
            c1: Fp::zero(),
        }
    }

    pub fn new(c0: Fp, c1: Fp) -> Self {
        Self { c0, c1 }
    }

    pub fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    /// (a0 + a1·u) + (b0 + b1·u) = (a0+b0) + (a1+b1)·u
    pub fn add(&self, other: &Fp2) -> Result<Fp2, CryptoError> {
        Ok(Fp2 {
            c0: self.c0.add(&other.c0)?,
            c1: self.c1.add(&other.c1)?,
        })
    }

    pub fn sub(&self, other: &Fp2) -> Result<Fp2, CryptoError> {
        Ok(Fp2 {
            c0: self.c0.sub(&other.c0)?,
            c1: self.c1.sub(&other.c1)?,
        })
    }

    pub fn neg(&self) -> Result<Fp2, CryptoError> {
        Ok(Fp2 {
            c0: self.c0.neg()?,
            c1: self.c1.neg()?,
        })
    }

    pub fn double(&self) -> Result<Fp2, CryptoError> {
        Ok(Fp2 {
            c0: self.c0.double()?,
            c1: self.c1.double()?,
        })
    }

    /// (a0 + a1·u)(b0 + b1·u) = (a0·b0 - 2·a1·b1) + (a0·b1 + a1·b0)·u
    pub fn mul(&self, other: &Fp2) -> Result<Fp2, CryptoError> {
        let t0 = self.c0.add(&self.c1)?;
        let t1 = other.c0.add(&other.c1)?;
        let t0 = t0.mul(&t1)?; // (a0+a1)(b0+b1)
        let v0 = self.c0.mul(&other.c0)?; // a0·b0
        let v1 = self.c1.mul(&other.c1)?; // a1·b1
        let c1 = t0.sub(&v0)?.sub(&v1)?; // a0·b1 + a1·b0
        let c0 = v0.sub(&v1.double()?)?; // a0·b0 - 2·a1·b1
        Ok(Fp2 { c0, c1 })
    }

    /// (a0 + a1·u)² = (a0² - 2·a1²) + (2·a0·a1)·u
    pub fn sqr(&self) -> Result<Fp2, CryptoError> {
        let t0 = self.c0.add(&self.c1)?;
        let t1 = self.c0.sub(&self.c1)?;
        // Use: (a0+a1)(a0-a1) = a0² - a1²
        // But we need a0² - 2·a1², so adjust:
        // c0 = a0² - 2·a1² = (a0+a1)(a0-a1) - a1²
        let a1_sq = self.c1.sqr()?;
        let c0 = t0.mul(&t1)?.sub(&a1_sq)?;
        let c1 = self.c0.mul(&self.c1)?.double()?;
        Ok(Fp2 { c0, c1 })
    }

    /// (a0 + a1·u)⁻¹ = (a0 - a1·u) / (a0² + 2·a1²)
    pub fn inv(&self) -> Result<Fp2, CryptoError> {
        let a0_sq = self.c0.sqr()?;
        let a1_sq = self.c1.sqr()?;
        let denom = a0_sq.add(&a1_sq.double()?)?; // a0² + 2·a1²
        let inv_d = denom.inv()?;
        Ok(Fp2 {
            c0: self.c0.mul(&inv_d)?,
            c1: self.c1.neg()?.mul(&inv_d)?,
        })
    }

    /// Multiply by scalar in Fp.
    pub fn mul_fp(&self, s: &Fp) -> Result<Fp2, CryptoError> {
        Ok(Fp2 {
            c0: self.c0.mul(s)?,
            c1: self.c1.mul(s)?,
        })
    }

    /// Multiply by u: (a0 + a1·u)·u = -2·a1 + a0·u
    pub fn mul_u(&self) -> Result<Fp2, CryptoError> {
        Ok(Fp2 {
            c0: self.c1.double()?.neg()?,
            c1: self.c0.clone(),
        })
    }

    /// Frobenius: conjugate (a0 + a1·u) → (a0 - a1·u)
    pub fn frobenius(&self) -> Result<Fp2, CryptoError> {
        Ok(Fp2 {
            c0: self.c0.clone(),
            c1: self.c1.neg()?,
        })
    }

    pub fn to_bytes_be(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&self.c0.to_bytes_be());
        out.extend_from_slice(&self.c1.to_bytes_be());
        out
    }

    pub fn from_bytes_be(data: &[u8]) -> Result<Fp2, CryptoError> {
        if data.len() < 64 {
            return Err(CryptoError::InvalidArg);
        }
        Ok(Fp2 {
            c0: Fp::from_bytes_be(&data[..32])?,
            c1: Fp::from_bytes_be(&data[32..64])?,
        })
    }
}

impl PartialEq for Fp2 {
    fn eq(&self, other: &Self) -> bool {
        self.c0 == other.c0 && self.c1 == other.c1
    }
}

impl Eq for Fp2 {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm9::fp::Fp;

    fn fp2(a: u64, b: u64) -> Fp2 {
        Fp2::new(Fp::from_u64(a), Fp::from_u64(b))
    }

    #[test]
    fn test_fp2_add_sub_identity() {
        let a = fp2(3, 7);
        let zero = Fp2::zero();
        // a + 0 = a
        assert_eq!(a.add(&zero).unwrap(), a);
        // a - a = 0
        let diff = a.sub(&a).unwrap();
        assert!(diff.is_zero());
        assert_eq!(diff, zero);
    }

    #[test]
    fn test_fp2_mul_one_commutativity() {
        let a = fp2(5, 11);
        let one = Fp2::one();
        // a * 1 = a
        assert_eq!(a.mul(&one).unwrap(), a);
        // commutativity: a * b = b * a
        let b = fp2(13, 17);
        assert_eq!(a.mul(&b).unwrap(), b.mul(&a).unwrap());
    }

    #[test]
    fn test_fp2_neg_double() {
        let a = fp2(42, 99);
        // neg(neg(a)) = a
        assert_eq!(a.neg().unwrap().neg().unwrap(), a);
        // a + neg(a) = 0
        assert!(a.add(&a.neg().unwrap()).unwrap().is_zero());
        // double(a) = a + a
        assert_eq!(a.double().unwrap(), a.add(&a).unwrap());
    }

    #[test]
    fn test_fp2_sqr_inv_mul_u_frobenius() {
        let a = fp2(5, 3);
        // sqr(a) = a * a
        assert_eq!(a.sqr().unwrap(), a.mul(&a).unwrap());
        // a * inv(a) = 1
        let inv_a = a.inv().unwrap();
        assert_eq!(a.mul(&inv_a).unwrap(), Fp2::one());
        // mul_u: (a0 + a1·u)·u = -2·a1 + a0·u
        let mu = a.mul_u().unwrap();
        let expected = Fp2::new(a.c1.double().unwrap().neg().unwrap(), a.c0.clone());
        assert_eq!(mu, expected);
        // frobenius: (a0 + a1·u) → (a0 - a1·u)
        let frob = a.frobenius().unwrap();
        assert_eq!(frob, Fp2::new(a.c0.clone(), a.c1.neg().unwrap()));
    }

    #[test]
    fn test_fp2_serialization_and_mul_fp() {
        let a = fp2(0xDEAD, 0xBEEF);
        // bytes roundtrip
        let bytes = a.to_bytes_be();
        assert_eq!(bytes.len(), 64);
        let b = Fp2::from_bytes_be(&bytes).unwrap();
        assert_eq!(a, b);
        // mul_fp: a.mul_fp(s) = (c0*s, c1*s)
        let s = Fp::from_u64(7);
        let result = a.mul_fp(&s).unwrap();
        assert_eq!(result.c0, a.c0.mul(&s).unwrap());
        assert_eq!(result.c1, a.c1.mul(&s).unwrap());
    }
}
