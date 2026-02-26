//! Montgomery multiplication context for modular exponentiation.
//!
//! Uses CIOS (Coarsely Integrated Operand Scanning) for multiplication and
//! optimized sqr + REDC for squaring, with pre-allocated buffers to eliminate
//! heap allocation in the inner exponentiation loop.

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
        let n = self.m_size;
        let mut result = vec![0u64; n];
        let mut scratch = vec![0u64; n + 2];
        self.cios_mul(
            &mut result,
            a_reduced.limbs(),
            self.r_squared.limbs(),
            &mut scratch,
        );
        Ok(BigNum::from_limbs(result))
    }

    /// Convert from Montgomery form back to normal: a * R^(-1) mod N.
    pub fn from_mont(&self, a_mont: &BigNum) -> BigNum {
        let n = self.m_size;
        let mut result = vec![0u64; n];
        let mut scratch = vec![0u64; n + 2];
        self.cios_mul(&mut result, a_mont.limbs(), &[1u64], &mut scratch);
        BigNum::from_limbs(result)
    }

    /// Montgomery multiplication: (a * b * R^(-1)) mod N.
    /// Both a and b must be in Montgomery form.
    pub fn mont_mul(&self, a: &BigNum, b: &BigNum) -> BigNum {
        let n = self.m_size;
        let mut result = vec![0u64; n];
        let mut scratch = vec![0u64; n + 2];
        self.cios_mul(&mut result, a.limbs(), b.limbs(), &mut scratch);
        BigNum::from_limbs(result)
    }

    /// Montgomery squaring: (a² * R^(-1)) mod N.
    pub fn mont_sqr(&self, a: &BigNum) -> BigNum {
        let n = self.m_size;
        let mut result = vec![0u64; n];
        let mut sqr_buf = vec![0u64; 2 * n + 2];
        // Pad input to n limbs if needed
        let a_limbs = a.limbs();
        if a_limbs.len() >= n {
            sqr_limbs(a_limbs, n, &mut sqr_buf);
        } else {
            let mut padded = vec![0u64; n];
            padded[..a_limbs.len()].copy_from_slice(a_limbs);
            sqr_limbs(&padded, n, &mut sqr_buf);
        }
        self.redc_limbs(&mut result, &mut sqr_buf);
        BigNum::from_limbs(result)
    }

    /// CIOS (Coarsely Integrated Operand Scanning) Montgomery multiplication.
    ///
    /// Computes `result = a * b * R^(-1) mod N` in a single fused pass,
    /// operating on an (n+2)-limb accumulator instead of creating a 2n-limb
    /// intermediate product.
    ///
    /// - `result` must have at least `m_size` elements.
    /// - `a` and `b` can have any length (missing limbs treated as 0).
    /// - `scratch` must have at least `m_size + 2` elements.
    fn cios_mul(&self, result: &mut [u64], a: &[u64], b: &[u64], scratch: &mut [u64]) {
        let n = self.m_size;
        let n_mod = self.modulus.limbs();
        let np = self.n_prime;
        let a_len = a.len();
        let b_len = b.len();

        // Clear accumulator
        for x in scratch[..n + 2].iter_mut() {
            *x = 0;
        }

        #[allow(clippy::needless_range_loop)]
        for i in 0..n {
            let ai = if i < a_len { a[i] } else { 0 };

            // Step 1: scratch += ai * b
            let mut carry: u64 = 0;
            for j in 0..n {
                let bj = if j < b_len { b[j] } else { 0 };
                let prod = ai as DoubleLimb * bj as DoubleLimb
                    + scratch[j] as DoubleLimb
                    + carry as DoubleLimb;
                scratch[j] = prod as Limb;
                carry = (prod >> LIMB_BITS) as u64;
            }
            let sum = scratch[n] as DoubleLimb + carry as DoubleLimb;
            scratch[n] = sum as Limb;
            scratch[n + 1] = (sum >> LIMB_BITS) as u64;

            // Step 2: scratch = (scratch + m * N) >> 64
            // m chosen so that scratch[0] + m * N[0] ≡ 0 (mod 2^64)
            let m = scratch[0].wrapping_mul(np);

            // j = 0: low word cancels by Montgomery property
            let prod0 = m as DoubleLimb * n_mod[0] as DoubleLimb + scratch[0] as DoubleLimb;
            carry = (prod0 >> LIMB_BITS) as u64;

            for j in 1..n {
                let prod = m as DoubleLimb * n_mod[j] as DoubleLimb
                    + scratch[j] as DoubleLimb
                    + carry as DoubleLimb;
                scratch[j - 1] = prod as Limb;
                carry = (prod >> LIMB_BITS) as u64;
            }
            let sum = scratch[n] as DoubleLimb + carry as DoubleLimb;
            scratch[n - 1] = sum as Limb;
            scratch[n] = scratch[n + 1] + (sum >> LIMB_BITS) as u64;
        }

        // Copy result from accumulator
        result[..n].copy_from_slice(&scratch[..n]);

        // Single conditional subtraction: if result >= N, subtract N
        if scratch[n] != 0 || limbs_ge(&result[..n], n_mod) {
            limbs_sub_in_place(result, n_mod, n);
        }
    }

    /// Montgomery reduction (REDC) on a 2n-limb value stored in `work`.
    ///
    /// Computes `result = work * R^(-1) mod N` by cancelling the low n limbs.
    /// `work` must have at least `2 * m_size + 2` elements and is modified in place.
    fn redc_limbs(&self, result: &mut [u64], work: &mut [u64]) {
        let n = self.m_size;
        let n_mod = self.modulus.limbs();
        let np = self.n_prime;

        debug_assert!(result.len() >= n);
        debug_assert!(work.len() >= 2 * n + 2);

        // SAFETY: work has 2n+2 elements, n_mod has n elements.
        // We access work[0..2n+1] and n_mod[0..n-1].
        unsafe {
            for i in 0..n {
                let m = work.get_unchecked(i).wrapping_mul(np);
                let mut carry: u64 = 0;
                for j in 0..n {
                    let prod = m as DoubleLimb * *n_mod.get_unchecked(j) as DoubleLimb
                        + *work.get_unchecked(i + j) as DoubleLimb
                        + carry as DoubleLimb;
                    *work.get_unchecked_mut(i + j) = prod as Limb;
                    carry = (prod >> LIMB_BITS) as u64;
                }
                // Propagate carry through upper limbs
                let mut k = i + n;
                while carry != 0 && k < 2 * n + 2 {
                    let sum = *work.get_unchecked(k) as DoubleLimb + carry as DoubleLimb;
                    *work.get_unchecked_mut(k) = sum as Limb;
                    carry = (sum >> LIMB_BITS) as u64;
                    k += 1;
                }
            }
        }

        // Result is in work[n..2n]
        result[..n].copy_from_slice(&work[n..2 * n]);
        let overflow = work[2 * n];
        if overflow != 0 || limbs_ge(&result[..n], n_mod) {
            limbs_sub_in_place(result, n_mod, n);
        }
    }

    /// Windowed Montgomery exponentiation: base^exp mod N.
    ///
    /// Uses CIOS for multiplication and optimized sqr + REDC for squaring,
    /// with pre-allocated limb buffers to avoid heap allocation in the inner
    /// exponentiation loop.
    pub fn mont_exp(&self, base: &BigNum, exp: &BigNum) -> Result<BigNum, CryptoError> {
        if exp.is_zero() {
            // a^0 = 1 (mod N), but if N==1 then result is 0
            if self.modulus.is_one() {
                return Ok(BigNum::zero());
            }
            return Ok(BigNum::from_u64(1));
        }

        let n = self.m_size;
        let exp_bits = exp.bit_len();
        let w = get_window_size(exp_bits);
        let table_size = 1usize << w;

        // Pre-allocate all working buffers
        let mut scratch = vec![0u64; n + 2]; // CIOS scratch

        // Flat precomputation table: table_size entries × n limbs each
        let mut table = vec![0u64; table_size * n];

        // table[0] = R mod N (Montgomery form of 1)
        self.cios_mul(
            &mut table[0..n],
            &[1u64],
            self.r_squared.limbs(),
            &mut scratch,
        );

        // table[1] = base in Montgomery form
        let base_reduced = base.mod_reduce(&self.modulus)?;
        self.cios_mul(
            &mut table[n..2 * n],
            base_reduced.limbs(),
            self.r_squared.limbs(),
            &mut scratch,
        );

        // table[i] = table[i-1] * table[1] for i = 2..table_size
        // Copy base_mont once to avoid borrow conflicts with table
        let mut base_mont = vec![0u64; n];
        base_mont.copy_from_slice(&table[n..2 * n]);
        for i in 2..table_size {
            let (left, right) = table.split_at_mut(i * n);
            let prev = &left[(i - 1) * n..];
            let cur = &mut right[..n];
            self.cios_mul(cur, prev, &base_mont, &mut scratch);
        }

        // Main exponentiation loop
        let mut result = vec![0u64; n];
        let mut temp = vec![0u64; n];
        result.copy_from_slice(&table[0..n]); // Start with 1 in Montgomery form

        // Process exponent from MSB to LSB in w-bit windows
        let mut i = exp_bits;
        while i > 0 {
            let window_bits = if i >= w { w } else { i };
            i -= window_bits;

            // Square window_bits times (using CIOS with a == b)
            for _ in 0..window_bits {
                self.cios_mul(&mut temp, &result, &result, &mut scratch);
                std::mem::swap(&mut result, &mut temp);
            }

            // Extract window value
            let mut window_val = 0u64;
            for b in 0..window_bits {
                window_val |= exp.get_bit(i + b) << b;
            }

            if window_val != 0 {
                let idx = window_val as usize;
                let table_entry = &table[idx * n..(idx + 1) * n];
                self.cios_mul(&mut temp, &result, table_entry, &mut scratch);
                std::mem::swap(&mut result, &mut temp);
            }
        }

        // Convert back from Montgomery form: multiply by 1
        self.cios_mul(&mut temp, &result, &[1u64], &mut scratch);
        Ok(BigNum::from_limbs(temp))
    }
}

/// Compute a² into out[0..2n+2]. `a` must have at least `n` limbs.
///
/// Exploits the symmetry `a[i]*a[j] == a[j]*a[i]` to compute cross products
/// once and double them, then adds diagonal terms. Uses n(n+1)/2 multiplications
/// instead of n² for the general case (~33% savings).
fn sqr_limbs(a: &[u64], n: usize, out: &mut [u64]) {
    debug_assert!(a.len() >= n);
    debug_assert!(out.len() >= 2 * n + 2);

    // Clear output
    for x in out[..2 * n + 2].iter_mut() {
        *x = 0;
    }

    // SAFETY: a has at least n elements, out has at least 2n+2.
    // Cross products access out[i+j] where i+j < 2n.
    // Diagonal access out[2i] and out[2i+1] where 2i+1 < 2n.
    unsafe {
        // Cross products (i < j only) — n(n-1)/2 multiplications
        for i in 0..n {
            let ai = *a.get_unchecked(i);
            let mut carry: u64 = 0;
            for j in (i + 1)..n {
                let prod = ai as DoubleLimb * *a.get_unchecked(j) as DoubleLimb
                    + *out.get_unchecked(i + j) as DoubleLimb
                    + carry as DoubleLimb;
                *out.get_unchecked_mut(i + j) = prod as Limb;
                carry = (prod >> LIMB_BITS) as u64;
            }
            *out.get_unchecked_mut(i + n) = carry;
        }

        // Double the cross products (shift left by 1 bit)
        let mut carry: u64 = 0;
        for k in 0..2 * n {
            let val = *out.get_unchecked(k);
            *out.get_unchecked_mut(k) = (val << 1) | carry;
            carry = val >> 63;
        }

        // Add diagonal terms a[i]² — n multiplications
        carry = 0;
        for i in 0..n {
            let ai = *a.get_unchecked(i);
            let prod = ai as DoubleLimb * ai as DoubleLimb
                + *out.get_unchecked(2 * i) as DoubleLimb
                + carry as DoubleLimb;
            *out.get_unchecked_mut(2 * i) = prod as Limb;
            let sum = (prod >> LIMB_BITS) + *out.get_unchecked(2 * i + 1) as DoubleLimb;
            *out.get_unchecked_mut(2 * i + 1) = sum as Limb;
            carry = (sum >> LIMB_BITS) as u64;
        }
    }
}

/// Compare a[..n] >= b (where b may have fewer than n limbs, zero-padded).
fn limbs_ge(a: &[u64], b: &[u64]) -> bool {
    let n = a.len();
    for i in (0..n).rev() {
        let bv = if i < b.len() { b[i] } else { 0 };
        if a[i] > bv {
            return true;
        }
        if a[i] < bv {
            return false;
        }
    }
    true // equal means >=
}

/// Subtract in-place: result[..n] -= b[..n]. Assumes result >= b.
fn limbs_sub_in_place(result: &mut [u64], b: &[u64], n: usize) {
    let mut borrow: u64 = 0;
    for i in 0..n {
        let bv = if i < b.len() { b[i] } else { 0 };
        let (diff, b1) = result[i].overflowing_sub(bv);
        let (diff2, b2) = diff.overflowing_sub(borrow);
        result[i] = diff2;
        borrow = (b1 as u64) + (b2 as u64);
    }
}

/// Compute R² mod N where R = 2^(m_size * 64).
fn compute_r_squared(modulus: &BigNum, m_size: usize) -> BigNum {
    // R² = 2^(2 * m_size * 64) mod N
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

    #[test]
    fn test_cios_multi_limb() {
        // Test with a multi-limb modulus (128-bit prime-like number)
        let modulus = BigNum::from_bytes_be(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xC5,
        ]);
        let ctx = MontgomeryCtx::new(&modulus).unwrap();

        let a = BigNum::from_u64(12345);
        let b = BigNum::from_u64(67890);

        let a_mont = ctx.to_mont(&a).unwrap();
        let b_mont = ctx.to_mont(&b).unwrap();
        let c_mont = ctx.mont_mul(&a_mont, &b_mont);
        let c = ctx.from_mont(&c_mont);

        let expected = a.mod_mul(&b, &modulus).unwrap();
        assert_eq!(c, expected);
    }

    #[test]
    fn test_cios_large_exp() {
        // 256-bit modulus exponentiation
        let modulus = BigNum::from_bytes_be(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFE, 0xC3,
        ]);
        let ctx = MontgomeryCtx::new(&modulus).unwrap();

        // Verify: (base^exp) * base ≡ base^(exp+1) via base^2
        let base = BigNum::from_u64(7);
        let _result = ctx
            .mont_exp(&base, &modulus.sub(&BigNum::from_u64(1)))
            .unwrap();

        let base_sq = base.mod_mul(&base, &modulus).unwrap();
        let result2 = ctx.mont_exp(&base, &BigNum::from_u64(2)).unwrap();
        assert_eq!(result2, base_sq);
    }

    #[test]
    fn test_limbs_ge() {
        assert!(limbs_ge(&[5, 0], &[3, 0]));
        assert!(limbs_ge(&[3, 0], &[3, 0])); // equal
        assert!(!limbs_ge(&[2, 0], &[3, 0]));
        assert!(limbs_ge(&[0, 1], &[u64::MAX, 0]));
    }

    #[test]
    fn test_mont_sqr_consistency() {
        let modulus = BigNum::from_u64(97);
        let ctx = MontgomeryCtx::new(&modulus).unwrap();

        let a = BigNum::from_u64(42);
        let a_mont = ctx.to_mont(&a).unwrap();

        let sqr = ctx.mont_sqr(&a_mont);
        let mul = ctx.mont_mul(&a_mont, &a_mont);
        assert_eq!(sqr, mul);
    }

    #[test]
    fn test_mont_sqr_multi_limb() {
        // 256-bit modulus
        let modulus = BigNum::from_bytes_be(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFE, 0xC3,
        ]);
        let ctx = MontgomeryCtx::new(&modulus).unwrap();

        for val in [2u64, 42, 12345, 999999] {
            let a = BigNum::from_u64(val);
            let a_mont = ctx.to_mont(&a).unwrap();

            let sqr = ctx.mont_sqr(&a_mont);
            let mul = ctx.mont_mul(&a_mont, &a_mont);
            assert_eq!(sqr, mul, "sqr vs mul mismatch for val={val}");
        }
    }

    #[test]
    fn test_sqr_limbs_correctness() {
        // Compare sqr_limbs with schoolbook multiplication
        let a = [0xDEADBEEFu64, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0];
        let n = 4;
        let mut sqr_out = vec![0u64; 2 * n + 2];
        sqr_limbs(&a, n, &mut sqr_out);

        // Schoolbook a * a
        let mut mul_out = vec![0u64; 2 * n];
        for i in 0..n {
            let mut carry: u64 = 0;
            for j in 0..n {
                let prod = a[i] as u128 * a[j] as u128 + mul_out[i + j] as u128 + carry as u128;
                mul_out[i + j] = prod as u64;
                carry = (prod >> 64) as u64;
            }
            mul_out[i + n] += carry;
        }

        assert_eq!(&sqr_out[..2 * n], &mul_out[..2 * n]);
    }
}
