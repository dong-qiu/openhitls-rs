//! Prime number generation and testing.

use crate::bignum::BigNum;
use hitls_types::CryptoError;

/// Small primes for trial division.
const SMALL_PRIMES: [u64; 15] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47];

impl BigNum {
    /// Check if this number is probably prime using Miller-Rabin test.
    ///
    /// `rounds` specifies the number of Miller-Rabin rounds (more rounds = higher confidence).
    pub fn is_probably_prime(&self, rounds: usize) -> Result<bool, CryptoError> {
        if self.is_zero() || self.is_negative() {
            return Ok(false);
        }

        let n = self.clone();

        // Check small primes
        for &p in &SMALL_PRIMES {
            let p_bn = BigNum::from_u64(p);
            if n == p_bn {
                return Ok(true);
            }
            let (_, rem) = n.div_rem(&p_bn)?;
            if rem.is_zero() {
                return Ok(false);
            }
        }

        // Miller-Rabin
        // Write n - 1 as 2^r * d
        let one = BigNum::from_u64(1);
        let n_minus_one = n.sub(&one);

        let mut d = n_minus_one.clone();
        let mut r = 0usize;
        while d.limbs()[0] & 1 == 0 {
            d = d.shr(1);
            r += 1;
        }

        // Test with small prime witnesses
        let witnesses: Vec<u64> = SMALL_PRIMES.iter().copied().take(rounds).collect();

        for &a_val in &witnesses {
            let a = BigNum::from_u64(a_val);
            if a.cmp_abs(&n) != std::cmp::Ordering::Less {
                continue;
            }

            let mut x = a.mod_exp(&d, &n)?;

            if x == one || x == n_minus_one {
                continue;
            }

            let mut composite = true;
            for _ in 0..r - 1 {
                x = x.mul(&x).mod_reduce(&n)?;
                if x == n_minus_one {
                    composite = false;
                    break;
                }
            }

            if composite {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_small_primes() {
        for &p in &SMALL_PRIMES {
            let n = BigNum::from_u64(p);
            assert!(n.is_probably_prime(10).unwrap(), "{p} should be prime");
        }
    }

    #[test]
    fn test_composite() {
        let n = BigNum::from_u64(15); // 3 * 5
        assert!(!n.is_probably_prime(10).unwrap());
    }

    #[test]
    fn test_large_prime() {
        // Mersenne prime 2^61 - 1
        let n = BigNum::from_u64((1u64 << 61) - 1);
        assert!(n.is_probably_prime(10).unwrap());
    }
}
