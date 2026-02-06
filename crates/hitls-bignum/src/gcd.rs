//! GCD and modular inverse operations.

use crate::bignum::BigNum;
use hitls_types::CryptoError;

impl BigNum {
    /// Compute the greatest common divisor of self and other using the Euclidean algorithm.
    pub fn gcd(&self, other: &BigNum) -> Result<BigNum, CryptoError> {
        if self.is_zero() && other.is_zero() {
            return Err(CryptoError::InvalidArg);
        }
        if self.is_zero() {
            let mut r = other.clone();
            r.set_negative(false);
            return Ok(r);
        }
        if other.is_zero() {
            let mut r = self.clone();
            r.set_negative(false);
            return Ok(r);
        }

        // Work with absolute values
        let mut a = self.clone();
        a.set_negative(false);
        let mut b = other.clone();
        b.set_negative(false);

        // Ensure a >= b
        if a < b {
            std::mem::swap(&mut a, &mut b);
        }

        // Euclidean algorithm: repeatedly compute a mod b
        loop {
            let (_, rem) = a.div_rem(&b)?;
            if rem.is_zero() {
                return Ok(b);
            }
            a = b;
            b = rem;
        }
    }

    /// Compute the modular inverse: self^(-1) mod modulus.
    ///
    /// Returns `Err(BnNoInverse)` if gcd(self, modulus) != 1.
    pub fn mod_inv(&self, modulus: &BigNum) -> Result<BigNum, CryptoError> {
        if modulus.is_zero() || modulus.is_one() {
            return Err(CryptoError::InvalidArg);
        }

        let one = BigNum::from_u64(1);
        let zero = BigNum::zero();

        // Extended Euclidean algorithm
        // We track: a = old_r, b = r, old_s, s such that
        // old_r = old_s * self + old_t * modulus (we only need old_s)
        let mut old_r = self.mod_reduce(modulus)?;
        if old_r.is_zero() {
            return Err(CryptoError::BnNoInverse);
        }
        let mut r = modulus.clone();

        let mut old_s = one.clone();
        let mut s = zero;

        while !r.is_zero() {
            let (quotient, remainder) = old_r.div_rem(&r)?;
            old_r = r;
            r = remainder;

            // new_s = old_s - quotient * s
            let qs = quotient.mul(&s);
            let new_s = old_s.sub(&qs);
            old_s = s;
            s = new_s;
        }

        // old_r should be 1 (gcd)
        if !old_r.is_one() {
            return Err(CryptoError::BnNoInverse);
        }

        // Ensure result is positive
        if old_s.is_negative() {
            old_s = old_s.add(modulus);
        }
        old_s.mod_reduce(modulus)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcd_basic() {
        let a = BigNum::from_u64(12);
        let b = BigNum::from_u64(8);
        assert_eq!(a.gcd(&b).unwrap(), BigNum::from_u64(4));
    }

    #[test]
    fn test_gcd_coprime() {
        let a = BigNum::from_u64(17);
        let b = BigNum::from_u64(13);
        assert_eq!(a.gcd(&b).unwrap(), BigNum::from_u64(1));
    }

    #[test]
    fn test_gcd_same() {
        let a = BigNum::from_u64(42);
        assert_eq!(a.gcd(&a).unwrap(), BigNum::from_u64(42));
    }

    #[test]
    fn test_gcd_one_zero() {
        let a = BigNum::from_u64(42);
        let z = BigNum::zero();
        assert_eq!(a.gcd(&z).unwrap(), BigNum::from_u64(42));
        assert_eq!(z.gcd(&a).unwrap(), BigNum::from_u64(42));
    }

    #[test]
    fn test_gcd_both_zero() {
        let z = BigNum::zero();
        assert!(z.gcd(&z).is_err());
    }

    #[test]
    fn test_mod_inv_basic() {
        // 3 * 5 = 15 ≡ 1 (mod 7)
        let a = BigNum::from_u64(3);
        let m = BigNum::from_u64(7);
        let inv = a.mod_inv(&m).unwrap();
        assert_eq!(inv, BigNum::from_u64(5));
    }

    #[test]
    fn test_mod_inv_verify() {
        // Verify a * a^(-1) ≡ 1 (mod m)
        let a = BigNum::from_u64(17);
        let m = BigNum::from_u64(97);
        let inv = a.mod_inv(&m).unwrap();
        let product = a.mul(&inv).mod_reduce(&m).unwrap();
        assert_eq!(product, BigNum::from_u64(1));
    }

    #[test]
    fn test_mod_inv_no_inverse() {
        // gcd(6, 9) = 3 ≠ 1, no inverse
        let a = BigNum::from_u64(6);
        let m = BigNum::from_u64(9);
        assert!(a.mod_inv(&m).is_err());
    }
}
