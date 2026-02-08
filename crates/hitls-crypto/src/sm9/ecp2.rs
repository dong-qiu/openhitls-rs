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
