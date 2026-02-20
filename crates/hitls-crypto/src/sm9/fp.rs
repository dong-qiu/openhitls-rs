//! Fp arithmetic for BN256 (256-bit prime field).

use hitls_bignum::BigNum;
use hitls_types::CryptoError;

use super::curve;

/// Element of Fp (integers mod p).
#[derive(Clone, Debug)]
pub(crate) struct Fp {
    pub val: BigNum,
}

impl Fp {
    pub fn zero() -> Self {
        Self {
            val: BigNum::from_u64(0),
        }
    }

    pub fn one() -> Self {
        Self {
            val: BigNum::from_u64(1),
        }
    }

    pub fn from_bignum(v: BigNum) -> Self {
        Self { val: v }
    }

    pub fn from_u64(v: u64) -> Self {
        Self {
            val: BigNum::from_u64(v),
        }
    }

    fn p() -> BigNum {
        curve::p()
    }

    pub fn add(&self, other: &Fp) -> Result<Fp, CryptoError> {
        let p = Self::p();
        Ok(Fp {
            val: self.val.mod_add(&other.val, &p)?,
        })
    }

    pub fn sub(&self, other: &Fp) -> Result<Fp, CryptoError> {
        let p = Self::p();
        // (a - b) mod p = (a + p - b) mod p
        let tmp = self.val.add(&p).sub(&other.val);
        Ok(Fp {
            val: tmp.mod_reduce(&p)?,
        })
    }

    pub fn mul(&self, other: &Fp) -> Result<Fp, CryptoError> {
        let p = Self::p();
        Ok(Fp {
            val: self.val.mod_mul(&other.val, &p)?,
        })
    }

    pub fn sqr(&self) -> Result<Fp, CryptoError> {
        self.mul(self)
    }

    pub fn neg(&self) -> Result<Fp, CryptoError> {
        let p = Self::p();
        if self.val.is_zero() {
            return Ok(Fp::zero());
        }
        Ok(Fp {
            val: p.sub(&self.val),
        })
    }

    pub fn inv(&self) -> Result<Fp, CryptoError> {
        let p = Self::p();
        Ok(Fp {
            val: self.val.mod_inv(&p)?,
        })
    }

    pub fn is_zero(&self) -> bool {
        self.val.is_zero()
    }

    pub fn double(&self) -> Result<Fp, CryptoError> {
        self.add(self)
    }

    /// Multiply by small constant.
    pub fn mul_u64(&self, c: u64) -> Result<Fp, CryptoError> {
        let p = Self::p();
        let cv = BigNum::from_u64(c);
        Ok(Fp {
            val: self.val.mod_mul(&cv, &p)?,
        })
    }

    pub fn to_bytes_be(&self) -> Vec<u8> {
        let mut bytes = self.val.to_bytes_be();
        // Pad to 32 bytes
        while bytes.len() < 32 {
            bytes.insert(0, 0);
        }
        bytes
    }

    pub fn from_bytes_be(data: &[u8]) -> Result<Fp, CryptoError> {
        Ok(Fp {
            val: BigNum::from_bytes_be(data),
        })
    }
}

impl PartialEq for Fp {
    fn eq(&self, other: &Self) -> bool {
        self.val == other.val
    }
}

impl Eq for Fp {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_sub_identity() {
        let a = Fp::from_u64(42);
        let zero = Fp::zero();
        // a + 0 = a
        assert_eq!(a.add(&zero).unwrap(), a);
        // a - a = 0
        assert_eq!(a.sub(&a).unwrap(), zero);
    }

    #[test]
    fn mul_one_identity() {
        let a = Fp::from_u64(123456789);
        let one = Fp::one();
        assert_eq!(a.mul(&one).unwrap(), a);
    }

    #[test]
    fn inv_mul_gives_one() {
        let a = Fp::from_u64(7);
        let a_inv = a.inv().unwrap();
        let product = a.mul(&a_inv).unwrap();
        assert_eq!(product, Fp::one());
    }

    #[test]
    fn neg_double_neg() {
        let a = Fp::from_u64(999);
        let neg_a = a.neg().unwrap();
        let neg_neg_a = neg_a.neg().unwrap();
        assert_eq!(neg_neg_a, a);
    }

    #[test]
    fn serialization_roundtrip() {
        let a = Fp::from_u64(0xDEADBEEF);
        let bytes = a.to_bytes_be();
        assert_eq!(bytes.len(), 32);
        let b = Fp::from_bytes_be(&bytes).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn zero_neg_is_zero() {
        let z = Fp::zero();
        assert_eq!(z.neg().unwrap(), Fp::zero());
        assert!(z.is_zero());
    }
}
