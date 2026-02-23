//! Fp4 = Fp2[v] / (v² - u) arithmetic for SM9 BN256.

use hitls_types::CryptoError;

use super::fp2::Fp2;

/// Element of Fp4 = c0 + c1·v where v² = u.
#[derive(Clone, Debug)]
pub(crate) struct Fp4 {
    pub c0: Fp2,
    pub c1: Fp2,
}

impl Fp4 {
    pub fn zero() -> Self {
        Self {
            c0: Fp2::zero(),
            c1: Fp2::zero(),
        }
    }

    pub fn one() -> Self {
        Self {
            c0: Fp2::one(),
            c1: Fp2::zero(),
        }
    }

    pub fn new(c0: Fp2, c1: Fp2) -> Self {
        Self { c0, c1 }
    }

    pub fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    pub fn add(&self, other: &Fp4) -> Result<Fp4, CryptoError> {
        Ok(Fp4 {
            c0: self.c0.add(&other.c0)?,
            c1: self.c1.add(&other.c1)?,
        })
    }

    pub fn sub(&self, other: &Fp4) -> Result<Fp4, CryptoError> {
        Ok(Fp4 {
            c0: self.c0.sub(&other.c0)?,
            c1: self.c1.sub(&other.c1)?,
        })
    }

    pub fn neg(&self) -> Result<Fp4, CryptoError> {
        Ok(Fp4 {
            c0: self.c0.neg()?,
            c1: self.c1.neg()?,
        })
    }

    pub fn double(&self) -> Result<Fp4, CryptoError> {
        Ok(Fp4 {
            c0: self.c0.double()?,
            c1: self.c1.double()?,
        })
    }

    /// (c0 + c1·v)(d0 + d1·v) = (c0·d0 + c1·d1·u) + (c0·d1 + c1·d0)·v
    /// where v² = u, and mul_u handles u multiplication in Fp2.
    pub fn mul(&self, other: &Fp4) -> Result<Fp4, CryptoError> {
        let v0 = self.c0.add(&self.c1)?;
        let v1 = other.c0.add(&other.c1)?;
        let v0 = v0.mul(&v1)?; // (c0+c1)(d0+d1)
        let v1 = self.c1.mul(&other.c1)?; // c1·d1
        let v2 = self.c0.mul(&other.c0)?; // c0·d0
        let r1 = v0.sub(&v2)?.sub(&v1)?; // c0·d1 + c1·d0
        let r0 = v1.mul_u()?.add(&v2)?; // c1·d1·u + c0·d0
        Ok(Fp4 { c0: r0, c1: r1 })
    }

    pub fn sqr(&self) -> Result<Fp4, CryptoError> {
        self.mul(self)
    }

    pub fn inv(&self) -> Result<Fp4, CryptoError> {
        // (c0 + c1·v)⁻¹ = (c0 - c1·v) / (c0² - c1²·u)
        let t0 = self.c0.sqr()?;
        let t1 = self.c1.sqr()?.mul_u()?;
        let denom = t0.sub(&t1)?;
        let inv_d = denom.inv()?;
        Ok(Fp4 {
            c0: self.c0.mul(&inv_d)?,
            c1: self.c1.neg()?.mul(&inv_d)?,
        })
    }

    /// Multiply by v: (c0 + c1·v)·v = c1·u + c0·v
    pub fn mul_v(&self) -> Result<Fp4, CryptoError> {
        Ok(Fp4 {
            c0: self.c1.mul_u()?,
            c1: self.c0.clone(),
        })
    }

    /// Conjugation: (c0 + c1·v) → (c0 - c1·v).
    /// This is the Frobenius σ_p^2 on Fp4, which maps v → -v.
    pub fn conjugate(&self) -> Result<Fp4, CryptoError> {
        Ok(Fp4 {
            c0: self.c0.clone(),
            c1: self.c1.neg()?,
        })
    }

    /// Multiply by Fp2 scalar.
    pub fn mul_fp2(&self, s: &Fp2) -> Result<Fp4, CryptoError> {
        Ok(Fp4 {
            c0: self.c0.mul(s)?,
            c1: self.c1.mul(s)?,
        })
    }
}

impl PartialEq for Fp4 {
    fn eq(&self, other: &Self) -> bool {
        self.c0 == other.c0 && self.c1 == other.c1
    }
}

impl Eq for Fp4 {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm9::fp::Fp;
    use crate::sm9::fp2::Fp2;

    fn fp4(a: u64, b: u64, c: u64, d: u64) -> Fp4 {
        Fp4::new(
            Fp2::new(Fp::from_u64(a), Fp::from_u64(b)),
            Fp2::new(Fp::from_u64(c), Fp::from_u64(d)),
        )
    }

    #[test]
    fn test_fp4_add_sub_identity() {
        let a = fp4(3, 7, 11, 13);
        let zero = Fp4::zero();
        // a + 0 = a
        assert_eq!(a.add(&zero).unwrap(), a);
        // a - a = 0
        let diff = a.sub(&a).unwrap();
        assert!(diff.is_zero());
        assert_eq!(diff, zero);
    }

    #[test]
    fn test_fp4_mul_one_commutativity() {
        let a = fp4(5, 11, 17, 23);
        let one = Fp4::one();
        // a * 1 = a
        assert_eq!(a.mul(&one).unwrap(), a);
        // commutativity: a * b = b * a
        let b = fp4(29, 31, 37, 41);
        assert_eq!(a.mul(&b).unwrap(), b.mul(&a).unwrap());
    }

    #[test]
    fn test_fp4_neg_double() {
        let a = fp4(42, 99, 7, 13);
        // neg(neg(a)) = a
        assert_eq!(a.neg().unwrap().neg().unwrap(), a);
        // a + neg(a) = 0
        assert!(a.add(&a.neg().unwrap()).unwrap().is_zero());
        // double(a) = a + a
        assert_eq!(a.double().unwrap(), a.add(&a).unwrap());
    }

    #[test]
    fn test_fp4_sqr_inv() {
        let a = fp4(5, 3, 7, 11);
        // sqr(a) = a * a
        assert_eq!(a.sqr().unwrap(), a.mul(&a).unwrap());
        // a * inv(a) = 1
        let inv_a = a.inv().unwrap();
        assert_eq!(a.mul(&inv_a).unwrap(), Fp4::one());
    }

    #[test]
    fn test_fp4_mul_v_conjugate_mul_fp2() {
        let a = fp4(5, 3, 7, 11);
        // mul_v: (c0 + c1·v)·v = c1·u + c0·v
        let mv = a.mul_v().unwrap();
        let expected = Fp4::new(a.c1.mul_u().unwrap(), a.c0.clone());
        assert_eq!(mv, expected);
        // conjugate(conjugate(a)) = a
        assert_eq!(a.conjugate().unwrap().conjugate().unwrap(), a);
        // conjugate: (c0 + c1·v) → (c0 - c1·v)
        let conj = a.conjugate().unwrap();
        assert_eq!(conj, Fp4::new(a.c0.clone(), a.c1.neg().unwrap()));
        // mul_fp2: scalar multiplication
        let s = Fp2::new(Fp::from_u64(7), Fp::from_u64(13));
        let result = a.mul_fp2(&s).unwrap();
        assert_eq!(result.c0, a.c0.mul(&s).unwrap());
        assert_eq!(result.c1, a.c1.mul(&s).unwrap());
    }
}
