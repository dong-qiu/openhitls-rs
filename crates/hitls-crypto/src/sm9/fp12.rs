//! Fp12 = Fp4[w] / (w³ - v) arithmetic for SM9 BN256.

use hitls_types::CryptoError;

use super::fp4::Fp4;

/// Element of Fp12 = c0 + c1·w + c2·w² where w³ = v.
#[derive(Clone, Debug)]
pub(crate) struct Fp12 {
    pub c0: Fp4,
    pub c1: Fp4,
    pub c2: Fp4,
}

impl Fp12 {
    pub fn zero() -> Self {
        Self {
            c0: Fp4::zero(),
            c1: Fp4::zero(),
            c2: Fp4::zero(),
        }
    }

    pub fn one() -> Self {
        Self {
            c0: Fp4::one(),
            c1: Fp4::zero(),
            c2: Fp4::zero(),
        }
    }

    pub fn new(c0: Fp4, c1: Fp4, c2: Fp4) -> Self {
        Self { c0, c1, c2 }
    }

    pub fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero() && self.c2.is_zero()
    }

    pub fn add(&self, other: &Fp12) -> Result<Fp12, CryptoError> {
        Ok(Fp12 {
            c0: self.c0.add(&other.c0)?,
            c1: self.c1.add(&other.c1)?,
            c2: self.c2.add(&other.c2)?,
        })
    }

    pub fn sub(&self, other: &Fp12) -> Result<Fp12, CryptoError> {
        Ok(Fp12 {
            c0: self.c0.sub(&other.c0)?,
            c1: self.c1.sub(&other.c1)?,
            c2: self.c2.sub(&other.c2)?,
        })
    }

    pub fn neg(&self) -> Result<Fp12, CryptoError> {
        Ok(Fp12 {
            c0: self.c0.neg()?,
            c1: self.c1.neg()?,
            c2: self.c2.neg()?,
        })
    }

    /// Karatsuba-like multiplication in Fp12.
    pub fn mul(&self, other: &Fp12) -> Result<Fp12, CryptoError> {
        let v0 = self.c0.mul(&other.c0)?;
        let v1 = self.c1.mul(&other.c1)?;
        let v2 = self.c2.mul(&other.c2)?;

        let t0 = self.c1.add(&self.c2)?;
        let t1 = other.c1.add(&other.c2)?;
        let v3 = t0.mul(&t1)?; // (c1+c2)(d1+d2)

        let t0 = self.c0.add(&self.c1)?;
        let t1 = other.c0.add(&other.c1)?;
        let v4 = t0.mul(&t1)?; // (c0+c1)(d0+d1)

        let t0 = self.c0.add(&self.c2)?;
        let t1 = other.c0.add(&other.c2)?;
        let v5 = t0.mul(&t1)?; // (c0+c2)(d0+d2)

        // r0 = v0 + (v3 - v1 - v2)·v
        let t = v3.sub(&v1)?.sub(&v2)?.mul_v()?;
        let r0 = v0.add(&t)?;

        // r1 = (v4 - v0 - v1) + v2·v
        let r1 = v4.sub(&v0)?.sub(&v1)?.add(&v2.mul_v()?)?;

        // r2 = (v5 - v0 - v2) + v1
        let r2 = v5.sub(&v0)?.sub(&v2)?.add(&v1)?;

        Ok(Fp12 {
            c0: r0,
            c1: r1,
            c2: r2,
        })
    }

    pub fn sqr(&self) -> Result<Fp12, CryptoError> {
        self.mul(self)
    }

    pub fn inv(&self) -> Result<Fp12, CryptoError> {
        // Use adjugate method
        let c0_sq = self.c0.sqr()?;
        let c1_sq = self.c1.sqr()?;
        let c2_sq = self.c2.sqr()?;
        let c0c1 = self.c0.mul(&self.c1)?;
        let c0c2 = self.c0.mul(&self.c2)?;
        let c1c2 = self.c1.mul(&self.c2)?;

        // A = c0² - c1·c2·v
        let a = c0_sq.sub(&c1c2.mul_v()?)?;
        // B = c2²·v - c0·c1
        let b = c2_sq.mul_v()?.sub(&c0c1)?;
        // C = c1² - c0·c2
        let c = c1_sq.sub(&c0c2)?;

        // det = c0·A + c2·B·v + c1·C·v
        let det = self
            .c0
            .mul(&a)?
            .add(&self.c2.mul(&b)?.mul_v()?)?
            .add(&self.c1.mul(&c)?.mul_v()?)?;

        let inv_det = det.inv()?;

        Ok(Fp12 {
            c0: a.mul(&inv_det)?,
            c1: b.mul(&inv_det)?,
            c2: c.mul(&inv_det)?,
        })
    }

    /// Exponentiation by a BigNum scalar.
    pub fn pow(&self, exp: &hitls_bignum::BigNum) -> Result<Fp12, CryptoError> {
        let bits = exp.to_bytes_be();
        let mut result = Fp12::one();
        let mut started = false;
        for byte in &bits {
            for bit in (0..8).rev() {
                if started {
                    result = result.sqr()?;
                }
                if (byte >> bit) & 1 == 1 {
                    if started {
                        result = result.mul(self)?;
                    } else {
                        result = self.clone();
                        started = true;
                    }
                }
            }
        }
        Ok(result)
    }

    /// Frobenius endomorphism: raise to the q-th power.
    ///
    /// For our tower Fp2[u] → Fp4[v] → Fp12[w]:
    ///   f^p = frob4(c0) + γ·frob4(c1)·w + γ²·frob4(c2)·w²
    /// where γ = u^((p-1)/6) ∈ Fp, and frob4 is the Fp4 Frobenius.
    pub fn frobenius(&self) -> Result<Fp12, CryptoError> {
        use super::fp::Fp;
        use super::fp2::Fp2;
        use super::pairing::fp2_pow;

        let p = super::curve::p();
        let xi = Fp2::new(Fp::zero(), Fp::one()); // u

        // γ = u^((p-1)/6) ∈ Fp
        let p_minus_1 = p.sub(&hitls_bignum::BigNum::from_u64(1));
        let (exp6, _) = p_minus_1.div_rem(&hitls_bignum::BigNum::from_u64(6))?;
        let gamma = fp2_pow(&xi, &exp6)?;
        let gamma_sq = gamma.sqr()?;

        // Fp4 Frobenius: (a + b·v)^p = conj(a) + β·conj(b)·v
        // where β = u^((p-1)/2) = γ³
        let beta = gamma.mul(&gamma)?.mul(&gamma)?; // γ³

        // Apply Fp4 Frobenius to c0, c1, c2
        let frob4 = |fp4: &Fp4| -> Result<Fp4, CryptoError> {
            let a_conj = fp4.c0.frobenius()?;
            let b_conj = fp4.c1.frobenius()?;
            let b_scaled = b_conj.mul(&beta)?;
            Ok(Fp4::new(a_conj, b_scaled))
        };

        let c0_frob = frob4(&self.c0)?;
        let c1_frob = frob4(&self.c1)?;
        let c2_frob = frob4(&self.c2)?;

        // c1_frob * γ (multiply Fp4 by Fp2 scalar)
        let c1_out = c1_frob.mul_fp2(&gamma)?;
        // c2_frob * γ² (multiply Fp4 by Fp2 scalar)
        let c2_out = c2_frob.mul_fp2(&gamma_sq)?;

        Ok(Fp12::new(c0_frob, c1_out, c2_out))
    }

    /// Frobenius squared: raise to q².
    pub fn frobenius2(&self) -> Result<Fp12, CryptoError> {
        let f1 = self.frobenius()?;
        f1.frobenius()
    }

    /// Frobenius cubed: raise to q³.
    pub fn frobenius3(&self) -> Result<Fp12, CryptoError> {
        let f2 = self.frobenius2()?;
        f2.frobenius()
    }
}

impl PartialEq for Fp12 {
    fn eq(&self, other: &Self) -> bool {
        self.c0 == other.c0 && self.c1 == other.c1 && self.c2 == other.c2
    }
}

impl Eq for Fp12 {}
