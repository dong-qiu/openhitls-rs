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
            return Err(CryptoError::InvalidArg(""));
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

    /// Scalar multiplication [k]P using w=4 fixed-window method.
    ///
    /// Precomputes [0P, 1P, 2P, ..., 15P], then processes scalar 4 bits at a time.
    /// Reduces point additions from ~256 (binary) to ~64 (windowed) for 256-bit scalars.
    pub fn scalar_mul(&self, k: &BigNum) -> Result<Self, CryptoError> {
        let bytes = k.to_bytes_be();
        if bytes.is_empty() || bytes.iter().all(|&b| b == 0) {
            return Ok(Self::infinity());
        }

        // Precompute table: table[i] = i * P for i = 0..16
        let mut table = Vec::with_capacity(16);
        table.push(Self::infinity()); // 0P
        table.push(self.clone()); // 1P
        let p2 = self.double()?; // 2P
        table.push(p2.clone());
        for i in 3..16u32 {
            table.push(table[(i - 1) as usize].add(self)?);
        }

        let mut result = Self::infinity();
        let mut started = false;

        for &byte in &bytes {
            // Process high nibble (bits 7-4)
            let hi = (byte >> 4) & 0xF;
            if started {
                result = result.double()?;
                result = result.double()?;
                result = result.double()?;
                result = result.double()?;
            }
            if hi != 0 {
                if started {
                    result = result.add(&table[hi as usize])?;
                } else {
                    result = table[hi as usize].clone();
                    started = true;
                }
            }

            // Process low nibble (bits 3-0)
            let lo = byte & 0xF;
            if started {
                result = result.double()?;
                result = result.double()?;
                result = result.double()?;
                result = result.double()?;
            }
            if lo != 0 {
                if started {
                    result = result.add(&table[lo as usize])?;
                } else {
                    result = table[lo as usize].clone();
                    started = true;
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
            return Err(CryptoError::InvalidArg(""));
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
        let z1_sq = self.z.sqr().expect("field sqr");
        let z2_sq = other.z.sqr().expect("field sqr");
        let lx = self.x.mul(&z2_sq).expect("field mul");
        let rx = other.x.mul(&z1_sq).expect("field mul");
        let ly = self.y.mul(&z2_sq).expect("field mul").mul(&other.z).expect("field mul");
        let ry = other.y.mul(&z1_sq).expect("field mul").mul(&self.z).expect("field mul");
        lx == rx && ly == ry
    }
}

impl Eq for EcPointG1 {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_on_curve() {
        // Check y² = x³ + 5 (mod p) for P1
        let g = EcPointG1::generator();
        let (gx, gy) = g.to_affine().unwrap();
        let y_sq = gy.sqr().unwrap();
        let x_cu = gx.sqr().unwrap().mul(&gx).unwrap();
        let b = Fp::from_bignum(curve::b_coeff());
        let rhs = x_cu.add(&b).unwrap();
        assert_eq!(y_sq, rhs);
    }

    #[test]
    fn infinity_add_generator() {
        let inf = EcPointG1::infinity();
        let g = EcPointG1::generator();
        let r = inf.add(&g).unwrap();
        assert_eq!(r, g);
    }

    #[test]
    fn negate_add_gives_infinity() {
        let g = EcPointG1::generator();
        let neg_g = g.negate().unwrap();
        let r = g.add(&neg_g).unwrap();
        assert!(r.is_infinity());
    }

    #[test]
    fn scalar_mul_by_order_gives_infinity() {
        let g = EcPointG1::generator();
        let n = curve::order();
        let r = g.scalar_mul(&n).unwrap();
        assert!(r.is_infinity());
    }

    #[test]
    fn serialization_roundtrip() {
        let g = EcPointG1::generator();
        let bytes = g.to_bytes().unwrap();
        assert_eq!(bytes.len(), 64);
        let g2 = EcPointG1::from_bytes(&bytes).unwrap();
        assert_eq!(g, g2);
    }

    #[test]
    fn double_equals_add_self() {
        let g = EcPointG1::generator();
        let doubled = g.double().unwrap();
        let added = g.add(&g).unwrap();
        assert_eq!(doubled, added);
    }

    #[test]
    fn scalar_mul_small_values() {
        let g = EcPointG1::generator();
        // [1]G = G
        let g1 = g.scalar_mul(&BigNum::from_u64(1)).unwrap();
        assert_eq!(g1, g);
        // [2]G = G + G
        let g2 = g.scalar_mul(&BigNum::from_u64(2)).unwrap();
        assert_eq!(g2, g.double().unwrap());
        // [3]G = [2]G + G
        let g3 = g.scalar_mul(&BigNum::from_u64(3)).unwrap();
        let g2_plus_g = g2.add(&g).unwrap();
        assert_eq!(g3, g2_plus_g);
    }

    #[test]
    fn add_commutativity() {
        let g = EcPointG1::generator();
        let g2 = g.double().unwrap();
        let g3 = g2.add(&g).unwrap();
        // G + 2G == 2G + G
        let a = g.add(&g2).unwrap();
        let b = g2.add(&g).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, g3);
    }

    #[test]
    fn from_bytes_wrong_length() {
        assert!(EcPointG1::from_bytes(&[0u8; 63]).is_err());
        assert!(EcPointG1::from_bytes(&[0u8; 65]).is_err());
        assert!(EcPointG1::from_bytes(&[]).is_err());
    }

    #[test]
    fn infinity_properties() {
        let inf = EcPointG1::infinity();
        assert!(inf.is_infinity());
        // to_affine on infinity → error
        assert!(inf.to_affine().is_err());
        // double(inf) = inf
        let doubled = inf.double().unwrap();
        assert!(doubled.is_infinity());
        // two infinities are equal
        assert_eq!(inf, EcPointG1::infinity());
    }
}
