//! Prime number generation and testing.

use crate::bignum::BigNum;
use crate::montgomery::MontgomeryCtx;
use hitls_types::CryptoError;

/// Small primes for trial division.
const SMALL_PRIMES: [u64; 15] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47];

impl BigNum {
    /// Generate a random probable prime of the given bit length.
    ///
    /// If `safe` is true, generates a safe prime p where (p-1)/2 is also prime.
    /// Returns error if `bits < 2` or if no prime is found within 10000 attempts.
    pub fn gen_prime(bits: usize, safe: bool) -> Result<Self, CryptoError> {
        if bits < 2 {
            return Err(CryptoError::InvalidArg("prime bits must be >= 2"));
        }
        let rounds = if bits >= 512 { 5 } else { 10 };
        let max_attempts = 10_000;

        if safe {
            // Safe prime: p = 2q + 1 where q is also prime
            for _ in 0..max_attempts {
                let q = BigNum::random(bits - 1, true)?;
                if !q.is_probably_prime(rounds)? {
                    continue;
                }
                // p = 2q + 1
                let p = q.shl(1).add(&BigNum::from_u64(1));
                if p.bit_len() == bits && p.is_probably_prime(rounds)? {
                    return Ok(p);
                }
            }
        } else {
            for _ in 0..max_attempts {
                let candidate = BigNum::random(bits, true)?;
                if candidate.is_probably_prime(rounds)? {
                    return Ok(candidate);
                }
            }
        }

        Err(CryptoError::BnRandGenFail)
    }

    /// Check if this number is probably prime using Miller-Rabin test.
    ///
    /// `rounds` specifies the number of Miller-Rabin rounds (more rounds = higher confidence).
    /// Uses a single Montgomery context for all witnesses and dedicated mont_sqr in the
    /// inner loop, eliminating redundant R² computations and leveraging cross-product
    /// symmetry in squaring.
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

        // Create Montgomery context ONCE for all witnesses
        let ctx = MontgomeryCtx::new(&n)?;
        let one_mont = ctx.to_mont(&one)?;
        let n_minus_one_mont = ctx.to_mont(&n_minus_one)?;

        // Test with small prime witnesses
        let witnesses: Vec<u64> = SMALL_PRIMES.iter().copied().take(rounds).collect();

        for &a_val in &witnesses {
            let a = BigNum::from_u64(a_val);
            if a.cmp_abs(&n) != std::cmp::Ordering::Less {
                continue;
            }

            // Get x in Montgomery form (avoids from_mont + to_mont roundtrip)
            let mut x_mont = ctx.mont_exp_mont(&a, &d)?;

            if x_mont == one_mont || x_mont == n_minus_one_mont {
                continue;
            }

            let mut composite = true;
            for _ in 0..r - 1 {
                x_mont = ctx.mont_sqr(&x_mont);
                if x_mont == n_minus_one_mont {
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
    fn test_zero_not_prime() {
        assert!(!BigNum::zero().is_probably_prime(10).unwrap());
    }

    #[test]
    fn test_negative_not_prime() {
        let mut neg = BigNum::from_u64(7);
        neg.set_negative(true);
        assert!(!neg.is_probably_prime(10).unwrap());
    }

    #[test]
    fn test_even_composites() {
        for &n in &[4u64, 6, 8, 100, 1000, 10000] {
            let bn = BigNum::from_u64(n);
            assert!(
                !bn.is_probably_prime(10).unwrap(),
                "{n} should not be prime"
            );
        }
    }

    #[test]
    fn test_medium_primes() {
        for &p in &[53u64, 97, 997, 7919, 104729] {
            let bn = BigNum::from_u64(p);
            assert!(bn.is_probably_prime(10).unwrap(), "{p} should be prime");
        }
    }

    #[test]
    fn test_carmichael_composite() {
        // 561 = 3 × 11 × 17 is the smallest Carmichael number
        let n = BigNum::from_u64(561);
        assert!(!n.is_probably_prime(15).unwrap(), "561 should not be prime");

        // 1105 = 5 × 13 × 17 is another Carmichael number
        let n2 = BigNum::from_u64(1105);
        assert!(
            !n2.is_probably_prime(15).unwrap(),
            "1105 should not be prime"
        );
    }

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

    #[test]
    fn test_gen_prime_small() {
        let p = BigNum::gen_prime(16, false).unwrap();
        assert_eq!(p.bit_len(), 16);
        assert!(p.is_probably_prime(10).unwrap());
    }

    #[test]
    fn test_gen_prime_exact_bits() {
        for bits in [8, 32, 64, 128] {
            let p = BigNum::gen_prime(bits, false).unwrap();
            assert_eq!(p.bit_len(), bits, "gen_prime({bits}) wrong bit_len");
            assert!(p.is_probably_prime(10).unwrap());
        }
    }

    #[test]
    fn test_gen_prime_invalid() {
        assert!(BigNum::gen_prime(0, false).is_err());
        assert!(BigNum::gen_prime(1, false).is_err());
    }

    #[test]
    #[ignore] // Safe prime generation is slow
    fn test_gen_prime_safe() {
        let p = BigNum::gen_prime(32, true).unwrap();
        assert!(p.is_probably_prime(10).unwrap());
        // (p-1)/2 should also be prime
        let q = p.sub(&BigNum::from_u64(1)).shr(1);
        assert!(q.is_probably_prime(10).unwrap());
    }
}
