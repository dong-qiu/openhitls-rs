//! G1 point operations on E(Fp): y² = x³ + 5.
//!
//! Uses Jacobian projective coordinates (X, Y, Z) where
//! affine (x, y) = (X/Z², Y/Z³).

use hitls_bignum::BigNum;
use hitls_types::CryptoError;

use super::curve;
use super::fp::Fp;

/// Point on E(Fp) in Jacobian coordinates.
#[derive(Clone, Debug)]
pub(crate) struct EcPointG1 {
    pub x: Fp,
    pub y: Fp,
    pub z: Fp,
}

impl EcPointG1 {
    pub fn infinity() -> Self {
        Self {
            x: Fp::one(),
            y: Fp::one(),
            z: Fp::zero(),
        }
    }

    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Create from affine coordinates.
    pub fn from_affine(x: Fp, y: Fp) -> Self {
        Self { x, y, z: Fp::one() }
    }

    /// Generator P1.
    pub fn generator() -> Self {
        Self::from_affine(
            Fp::from_bignum(curve::p1_x()),
            Fp::from_bignum(curve::p1_y()),
        )
    }

    /// Convert to affine (x, y).
    pub fn to_affine(&self) -> Result<(Fp, Fp), CryptoError> {
        if self.is_infinity() {
            return Err(CryptoError::InvalidArg);
        }
        let z_inv = self.z.inv()?;
        let z2 = z_inv.sqr()?;
        let z3 = z2.mul(&z_inv)?;
        Ok((self.x.mul(&z2)?, self.y.mul(&z3)?))
    }

    /// Point doubling (Jacobian).
    pub fn double(&self) -> Result<Self, CryptoError> {
        if self.is_infinity() {
            return Ok(self.clone());
        }
        // a = 0 for BN256, so simplified formula
        let a = self.x.sqr()?; // X²
        let b = self.y.sqr()?; // Y²
        let c = b.sqr()?; // Y⁴
        let t = self.x.add(&b)?;
        let d = t.sqr()?.sub(&a)?.sub(&c)?.double()?; // 2((X+Y²)²-X²-Y⁴) = 4XY²
        let e = a.double()?.add(&a)?; // 3X² (since a=0, no 3aZ⁴ term)
        let f = e.sqr()?; // (3X²)²

        let x3 = f.sub(&d.double()?)?; // E² - 2D
        let y3 = e.mul(&d.sub(&x3)?)?.sub(&c.double()?.double()?.double()?)?;
        let z3 = self.y.mul(&self.z)?.double()?; // 2YZ

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

    /// Scalar multiplication [k]P.
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

    /// Negate: (X, Y, Z) → (X, -Y, Z)
    pub fn negate(&self) -> Result<Self, CryptoError> {
        Ok(Self {
            x: self.x.clone(),
            y: self.y.neg()?,
            z: self.z.clone(),
        })
    }

    /// Serialize to 64 bytes (uncompressed affine: x || y, big-endian).
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let (ax, ay) = self.to_affine()?;
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&ax.to_bytes_be());
        out.extend_from_slice(&ay.to_bytes_be());
        Ok(out)
    }

    /// Deserialize from 64 bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() != 64 {
            return Err(CryptoError::InvalidArg);
        }
        let x = Fp::from_bytes_be(&data[..32])?;
        let y = Fp::from_bytes_be(&data[32..64])?;
        Ok(Self::from_affine(x, y))
    }
}

impl PartialEq for EcPointG1 {
    fn eq(&self, other: &Self) -> bool {
        if self.is_infinity() && other.is_infinity() {
            return true;
        }
        if self.is_infinity() || other.is_infinity() {
            return false;
        }
        // Compare in projective: X1·Z2² == X2·Z1² && Y1·Z2³ == Y2·Z1³
        let z1_sq = self.z.sqr().unwrap();
        let z2_sq = other.z.sqr().unwrap();
        let lx = self.x.mul(&z2_sq).unwrap();
        let rx = other.x.mul(&z1_sq).unwrap();
        let ly = self.y.mul(&z2_sq).unwrap().mul(&other.z).unwrap();
        let ry = other.y.mul(&z1_sq).unwrap().mul(&self.z).unwrap();
        lx == rx && ly == ry
    }
}

impl Eq for EcPointG1 {}
