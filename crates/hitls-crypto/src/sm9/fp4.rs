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
