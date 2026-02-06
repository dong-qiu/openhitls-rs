//! Montgomery multiplication context for modular exponentiation.

use crate::bignum::{BigNum, DoubleLimb, Limb, LIMB_BITS};
use hitls_types::CryptoError;

/// Montgomery multiplication context.
///
/// Precomputes values needed for efficient modular multiplication
/// using the Montgomery form: R = 2^(m_size * LIMB_BITS).
pub struct MontgomeryCtx {
    /// The modulus N (must be odd).
    modulus: BigNum,
    /// Number of limbs in the modulus.
    m_size: usize,
    /// N' such that N[0] * N' ≡ -1 (mod 2^64).
    n_prime: u64,
    /// R² mod N, used for encoding into Montgomery form.
    r_squared: BigNum,
}

impl MontgomeryCtx {
    /// Create a new Montgomery context for the given odd modulus.
    pub fn new(modulus: &BigNum) -> Result<Self, CryptoError> {
        if modulus.is_zero() {
            return Err(CryptoError::BnDivisionByZero);
        }
        if modulus.limbs()[0] & 1 == 0 {
            return Err(CryptoError::InvalidArg);
        }

        let m_size = modulus.num_limbs();
        let n_prime = compute_n_prime(modulus.limbs()[0]);

        // Compute R² mod N where R = 2^(m_size * 64)
        // R² = 2^(2 * m_size * 64)
        let r_squared = compute_r_squared(modulus, m_size);

        Ok(MontgomeryCtx {
            modulus: modulus.clone(),
            m_size,
            n_prime,
            r_squared,
        })
    }

    /// Return a reference to the modulus.
    pub fn modulus(&self) -> &BigNum {
        &self.modulus
    }

    /// Convert a value into Montgomery form: aR mod N.
    pub fn to_mont(&self, a: &BigNum) -> Result<BigNum, CryptoError> {
        let a_reduced = a.mod_reduce(&self.modulus)?;
        let product = a_reduced.mul(&self.r_squared);
        Ok(self.mont_reduce(&product))
    }

    /// Convert from Montgomery form back to normal: a * R^(-1) mod N.
    pub fn from_mont(&self, a_mont: &BigNum) -> BigNum {
        self.mont_reduce(a_mont)
    }

    /// Montgomery multiplication: (a * b * R^(-1)) mod N.
    /// Both a and b must be in Montgomery form.
    pub fn mont_mul(&self, a: &BigNum, b: &BigNum) -> BigNum {
        let product = a.mul(b);
        self.mont_reduce(&product)
    }

    /// Montgomery squaring: (a² * R^(-1)) mod N.
    pub fn mont_sqr(&self, a: &BigNum) -> BigNum {
        let sq = a.sqr();
        self.mont_reduce(&sq)
    }

    /// Montgomery REDC: given T, compute T * R^(-1) mod N.
    ///
    /// Algorithm (from HAC 14.32):
    /// ```text
    /// for i = 0 to m_size-1:
    ///   q_i = t[i] * n_prime mod 2^64
    ///   T = T + q_i * N * 2^(i*64)
    /// T = T >> (m_size * 64)
    /// if T >= N: T = T - N
    /// return T
    /// ```
    fn mont_reduce(&self, t: &BigNum) -> BigNum {
        let m = self.m_size;
        let mod_limbs = self.modulus.limbs();

        // Work buffer: need at least 2*m + 1 limbs
        let mut work = vec![0u64; 2 * m + 2];
        let t_limbs = t.limbs();
        let copy_len = t_limbs.len().min(work.len());
        work[..copy_len].copy_from_slice(&t_limbs[..copy_len]);

        for i in 0..m {
            let q = work[i].wrapping_mul(self.n_prime);

            // Add q * N shifted by i positions
            let mut carry: u64 = 0;
            for j in 0..m {
                let prod = q as DoubleLimb * mod_limbs[j] as DoubleLimb
                    + work[i + j] as DoubleLimb
                    + carry as DoubleLimb;
                work[i + j] = prod as Limb;
                carry = (prod >> LIMB_BITS) as u64;
            }
            // Propagate carry
            let mut k = i + m;
            while carry != 0 && k < work.len() {
                let sum = work[k] as DoubleLimb + carry as DoubleLimb;
                work[k] = sum as Limb;
                carry = (sum >> LIMB_BITS) as u64;
                k += 1;
            }
        }

        // Result is in work[m..2m]
        let result_limbs: Vec<u64> = work[m..m + m].to_vec();
        let mut result = BigNum::from_limbs(result_limbs);

        // Final subtraction if result >= modulus
        if result >= self.modulus {
            result = result.sub(&self.modulus);
        }

        result
    }

    /// Windowed Montgomery exponentiation: base^exp mod N.
    ///
    /// Uses variable window size based on exponent length for efficiency.
    pub fn mont_exp(&self, base: &BigNum, exp: &BigNum) -> Result<BigNum, CryptoError> {
        if exp.is_zero() {
            // a^0 = 1 (mod N), but if N==1 then result is 0
            if self.modulus.is_one() {
                return Ok(BigNum::zero());
            }
            return Ok(BigNum::from_u64(1));
        }

        let exp_bits = exp.bit_len();
        let w = get_window_size(exp_bits);
        let table_size = 1usize << w;

        // Precompute table[i] = base^i in Montgomery form for i = 0..2^w-1
        let base_mont = self.to_mont(base)?;
        let mut table = Vec::with_capacity(table_size);
        // table[0] = R mod N (Montgomery form of 1)
        table.push(self.to_mont(&BigNum::from_u64(1))?);
        // table[1] = base in Montgomery form
        table.push(base_mont.clone());
        // table[i] = table[i-1] * base_mont
        for i in 2..table_size {
            let val = self.mont_mul(&table[i - 1], &base_mont);
            table.push(val);
        }

        // Process exponent from MSB to LSB in w-bit windows
        let mut result = table[0].clone(); // Start with 1 in Montgomery form

        // Process bits from most significant, in windows of size w
        let mut i = exp_bits;
        while i > 0 {
            let window_bits = if i >= w { w } else { i };
            i -= window_bits;

            // Square w times
            for _ in 0..window_bits {
                result = self.mont_sqr(&result);
            }

            // Extract window value
            let mut window_val = 0u64;
            for b in 0..window_bits {
                window_val |= exp.get_bit(i + b) << b;
            }

            if window_val != 0 {
                result = self.mont_mul(&result, &table[window_val as usize]);
            }
        }

        // Convert back from Montgomery form
        Ok(self.from_mont(&result))
    }
}

/// Compute R² mod N where R = 2^(m_size * 64).
fn compute_r_squared(modulus: &BigNum, m_size: usize) -> BigNum {
    // R² = 2^(2 * m_size * 64) mod N
    // Build 2^(2*m_size*64) using shl, then reduce mod N
    let mut r2 = BigNum::from_u64(1);
    r2 = r2.shl(2 * m_size * LIMB_BITS);
    r2.mod_reduce(modulus).unwrap_or_else(|_| BigNum::zero())
}

/// Compute N' such that N[0] * N' ≡ -1 (mod 2^64).
///
/// Uses Newton's method: x = x * (2 - n0 * x), iterated to converge mod 2^64.
fn compute_n_prime(n0: u64) -> u64 {
    let mut x: u64 = 1;
    for _ in 0..63 {
        x = x.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(x)));
    }
    x.wrapping_neg()
}

/// Determine window size for modular exponentiation based on exponent bit length.
fn get_window_size(bits: usize) -> usize {
    if bits > 512 {
        6
    } else if bits > 256 {
        5
    } else if bits > 128 {
        4
    } else if bits > 64 {
        3
    } else if bits > 32 {
        2
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_n_prime() {
        // For an odd number n, n * n_prime ≡ -1 (mod 2^64)
        let n: u64 = 0xFFFF_FFFF_FFFF_FFEF;
        let np = compute_n_prime(n);
        assert_eq!(n.wrapping_mul(np), u64::MAX);
    }

    #[test]
    fn test_montgomery_ctx_creation() {
        let modulus = BigNum::from_u64(0xFFFFFFFFFFFFFFC5);
        let ctx = MontgomeryCtx::new(&modulus).unwrap();
        let check = modulus.limbs()[0].wrapping_mul(ctx.n_prime);
        assert_eq!(check, u64::MAX);
    }

    #[test]
    fn test_montgomery_roundtrip() {
        // to_mont then from_mont should give back the original value
        let modulus = BigNum::from_u64(0xFFFFFFFFFFFFFFC5); // large odd number
        let ctx = MontgomeryCtx::new(&modulus).unwrap();

        let a = BigNum::from_u64(42);
        let a_mont = ctx.to_mont(&a).unwrap();
        let a_back = ctx.from_mont(&a_mont);
        assert_eq!(a, a_back);
    }

    #[test]
    fn test_montgomery_mul() {
        let modulus = BigNum::from_u64(97); // small odd prime
        let ctx = MontgomeryCtx::new(&modulus).unwrap();

        let a = BigNum::from_u64(45);
        let b = BigNum::from_u64(67);

        let a_mont = ctx.to_mont(&a).unwrap();
        let b_mont = ctx.to_mont(&b).unwrap();
        let c_mont = ctx.mont_mul(&a_mont, &b_mont);
        let c = ctx.from_mont(&c_mont);

        // 45 * 67 = 3015, 3015 mod 97 = 3015 - 31*97 = 3015 - 3007 = 8
        assert_eq!(c, BigNum::from_u64(8));
    }

    #[test]
    fn test_mont_exp_basic() {
        let modulus = BigNum::from_u64(97);
        let ctx = MontgomeryCtx::new(&modulus).unwrap();

        // 3^4 = 81 mod 97 = 81
        let result = ctx
            .mont_exp(&BigNum::from_u64(3), &BigNum::from_u64(4))
            .unwrap();
        assert_eq!(result, BigNum::from_u64(81));
    }

    #[test]
    fn test_mont_exp_fermat() {
        // Fermat's little theorem: a^(p-1) ≡ 1 (mod p) for prime p
        let p = BigNum::from_u64(97);
        let ctx = MontgomeryCtx::new(&p).unwrap();
        let p_minus_1 = BigNum::from_u64(96);

        for a_val in [2u64, 3, 5, 42, 96] {
            let result = ctx.mont_exp(&BigNum::from_u64(a_val), &p_minus_1).unwrap();
            assert_eq!(result, BigNum::from_u64(1), "Fermat failed for a={a_val}");
        }
    }

    #[test]
    fn test_window_size() {
        assert_eq!(get_window_size(16), 1);
        assert_eq!(get_window_size(33), 2);
        assert_eq!(get_window_size(65), 3);
        assert_eq!(get_window_size(129), 4);
        assert_eq!(get_window_size(257), 5);
        assert_eq!(get_window_size(513), 6);
    }

    #[test]
    fn test_even_modulus_rejected() {
        let modulus = BigNum::from_u64(100);
        assert!(MontgomeryCtx::new(&modulus).is_err());
    }
}
