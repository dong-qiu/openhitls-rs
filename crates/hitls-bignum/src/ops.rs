//! Basic arithmetic operations for BigNum.

use crate::bignum::{BigNum, DoubleLimb, Limb, LIMB_BITS};
use hitls_types::CryptoError;

impl BigNum {
    /// Add two BigNums: self + other.
    pub fn add(&self, other: &BigNum) -> BigNum {
        if self.is_negative() == other.is_negative() {
            let mut result = add_unsigned(self.limbs(), other.limbs());
            result.set_negative(self.is_negative());
            result
        } else if self.is_negative() {
            // (-a) + b = b - a
            sub_unsigned(other.limbs(), self.limbs())
        } else {
            // a + (-b) = a - b
            sub_unsigned(self.limbs(), other.limbs())
        }
    }

    /// Subtract: self - other.
    pub fn sub(&self, other: &BigNum) -> BigNum {
        if self.is_negative() != other.is_negative() {
            let mut result = add_unsigned(self.limbs(), other.limbs());
            result.set_negative(self.is_negative());
            result
        } else if self.is_negative() {
            // (-a) - (-b) = b - a
            sub_unsigned(other.limbs(), self.limbs())
        } else {
            sub_unsigned(self.limbs(), other.limbs())
        }
    }

    /// Multiply: self * other.
    pub fn mul(&self, other: &BigNum) -> BigNum {
        let mut result = mul_unsigned(self.limbs(), other.limbs());
        result.set_negative(self.is_negative() != other.is_negative());
        result
    }

    /// Division with remainder: returns (quotient, remainder).
    pub fn div_rem(&self, divisor: &BigNum) -> Result<(BigNum, BigNum), CryptoError> {
        if divisor.is_zero() {
            return Err(CryptoError::BnDivisionByZero);
        }
        // TODO: Implement Knuth's Algorithm D
        // Placeholder: simple binary long division
        let (q, r) = div_rem_unsigned(self.limbs(), divisor.limbs());
        Ok((q, r))
    }

    /// Modular reduction: self mod modulus.
    ///
    /// For negative values, returns `modulus - (|self| mod modulus)` so that
    /// the result is always in `[0, modulus)`.  This is required for correct
    /// RSA CRT recombination where intermediate differences can be negative.
    pub fn mod_reduce(&self, modulus: &BigNum) -> Result<BigNum, CryptoError> {
        let (_, r) = self.div_rem(modulus)?;
        if self.is_negative() && !r.is_zero() {
            Ok(modulus.sub(&r))
        } else {
            Ok(r)
        }
    }

    /// Modular exponentiation: self^exp mod modulus.
    ///
    /// Uses Montgomery multiplication for odd moduli, falls back to
    /// simple square-and-multiply for even moduli.
    pub fn mod_exp(&self, exp: &BigNum, modulus: &BigNum) -> Result<BigNum, CryptoError> {
        if modulus.is_zero() {
            return Err(CryptoError::BnDivisionByZero);
        }

        // Use Montgomery path for odd moduli
        if modulus.is_odd() {
            let ctx = crate::montgomery::MontgomeryCtx::new(modulus)?;
            return ctx.mont_exp(self, exp);
        }

        // Fallback: simple square-and-multiply for even moduli
        let mut result = BigNum::from_u64(1);
        let mut base = self.mod_reduce(modulus)?;
        let exp_bits = exp.bit_len();

        for i in 0..exp_bits {
            let limb_idx = i / LIMB_BITS;
            let bit_idx = i % LIMB_BITS;
            if limb_idx < exp.limbs().len() && (exp.limbs()[limb_idx] >> bit_idx) & 1 == 1 {
                result = result.mul(&base).mod_reduce(modulus)?;
            }
            base = base.mul(&base).mod_reduce(modulus)?;
        }

        Ok(result)
    }

    /// Modular addition: (self + other) mod modulus.
    pub fn mod_add(&self, other: &BigNum, modulus: &BigNum) -> Result<BigNum, CryptoError> {
        let sum = self.add(other);
        sum.mod_reduce(modulus)
    }

    /// Modular subtraction: (self - other) mod modulus.
    pub fn mod_sub(&self, other: &BigNum, modulus: &BigNum) -> Result<BigNum, CryptoError> {
        let diff = self.sub(other);
        if diff.is_negative() {
            // Add modulus to make it positive
            let adjusted = diff.add(modulus);
            adjusted.mod_reduce(modulus)
        } else {
            diff.mod_reduce(modulus)
        }
    }

    /// Modular multiplication: (self * other) mod modulus.
    pub fn mod_mul(&self, other: &BigNum, modulus: &BigNum) -> Result<BigNum, CryptoError> {
        let product = self.mul(other);
        product.mod_reduce(modulus)
    }

    /// Shift left by `bits` positions.
    pub fn shl(&self, bits: usize) -> BigNum {
        if self.is_zero() || bits == 0 {
            return self.clone();
        }
        let word_shift = bits / LIMB_BITS;
        let bit_shift = bits % LIMB_BITS;
        let src = self.limbs();
        let old_len = src.len();
        let new_len = old_len + word_shift + if bit_shift > 0 { 1 } else { 0 };
        let mut limbs = vec![0u64; new_len];

        if bit_shift == 0 {
            limbs[word_shift..word_shift + old_len].copy_from_slice(&src[..old_len]);
        } else {
            let mut carry = 0u64;
            for i in 0..old_len {
                let shifted = (src[i] << bit_shift) | carry;
                limbs[i + word_shift] = shifted;
                carry = src[i] >> (LIMB_BITS - bit_shift);
            }
            if carry != 0 {
                limbs[old_len + word_shift] = carry;
            }
        }

        let mut result = BigNum::from_limbs(limbs);
        result.set_negative(self.is_negative());
        result
    }

    /// Shift right by `bits` positions.
    pub fn shr(&self, bits: usize) -> BigNum {
        if self.is_zero() || bits == 0 {
            return self.clone();
        }
        let word_shift = bits / LIMB_BITS;
        let bit_shift = bits % LIMB_BITS;
        let src = self.limbs();

        if word_shift >= src.len() {
            return BigNum::zero();
        }

        let new_len = src.len() - word_shift;
        let mut limbs = vec![0u64; new_len];

        if bit_shift == 0 {
            limbs[..new_len].copy_from_slice(&src[word_shift..word_shift + new_len]);
        } else {
            for i in 0..new_len {
                limbs[i] = src[i + word_shift] >> bit_shift;
                if i + word_shift + 1 < src.len() {
                    limbs[i] |= src[i + word_shift + 1] << (LIMB_BITS - bit_shift);
                }
            }
        }

        let mut result = BigNum::from_limbs(limbs);
        result.set_negative(self.is_negative());
        result
    }

    /// Optimized squaring: self * self.
    ///
    /// Exploits the symmetry a[i]*a[j] == a[j]*a[i] to compute cross-products
    /// once and double them, then add diagonal terms.
    pub fn sqr(&self) -> BigNum {
        let a = self.limbs();
        let n = a.len();
        if n == 0 || self.is_zero() {
            return BigNum::zero();
        }

        let mut result = vec![0u64; 2 * n];

        // Cross products (i < j only)
        for i in 0..n {
            let mut carry: u64 = 0;
            for j in (i + 1)..n {
                let prod = a[i] as DoubleLimb * a[j] as DoubleLimb
                    + result[i + j] as DoubleLimb
                    + carry as DoubleLimb;
                result[i + j] = prod as Limb;
                carry = (prod >> LIMB_BITS) as u64;
            }
            result[i + n] = carry;
        }

        // Double the cross products
        let mut carry = 0u64;
        for limb in result.iter_mut() {
            let shifted = (*limb as DoubleLimb) * 2 + carry as DoubleLimb;
            *limb = shifted as Limb;
            carry = (shifted >> LIMB_BITS) as u64;
        }

        // Add diagonal terms a[i]^2
        let mut carry: u64 = 0;
        for i in 0..n {
            let prod = a[i] as DoubleLimb * a[i] as DoubleLimb
                + result[2 * i] as DoubleLimb
                + carry as DoubleLimb;
            result[2 * i] = prod as Limb;
            let sum = (prod >> LIMB_BITS) as DoubleLimb + result[2 * i + 1] as DoubleLimb;
            result[2 * i + 1] = sum as Limb;
            carry = (sum >> LIMB_BITS) as u64;
        }

        BigNum::from_limbs(result)
    }

    /// Compare absolute values. Returns Ordering.
    pub fn cmp_abs(&self, other: &BigNum) -> std::cmp::Ordering {
        let a_bits = self.bit_len();
        let b_bits = other.bit_len();
        if a_bits != b_bits {
            return a_bits.cmp(&b_bits);
        }
        // Same bit length, compare limbs from most significant
        let max_limbs = self.limbs().len().max(other.limbs().len());
        for i in (0..max_limbs).rev() {
            let a = if i < self.limbs().len() {
                self.limbs()[i]
            } else {
                0
            };
            let b = if i < other.limbs().len() {
                other.limbs()[i]
            } else {
                0
            };
            if a != b {
                return a.cmp(&b);
            }
        }
        std::cmp::Ordering::Equal
    }
}

/// Add two unsigned limb arrays.
fn add_unsigned(a: &[Limb], b: &[Limb]) -> BigNum {
    let max_len = a.len().max(b.len());
    let mut limbs = vec![0u64; max_len + 1];
    let mut carry: u64 = 0;

    for i in 0..max_len {
        let av = if i < a.len() { a[i] } else { 0 };
        let bv = if i < b.len() { b[i] } else { 0 };
        let sum = av as DoubleLimb + bv as DoubleLimb + carry as DoubleLimb;
        limbs[i] = sum as Limb;
        carry = (sum >> LIMB_BITS) as u64;
    }
    limbs[max_len] = carry;

    let mut bn = BigNum::from_u64(0);
    *bn.limbs_mut() = limbs;
    // Normalize to remove leading zeros
    while bn.limbs().len() > 1 && *bn.limbs().last().unwrap() == 0 {
        bn.limbs_mut().pop();
    }
    bn
}

/// Subtract unsigned: a - b (assuming a >= b for positive result).
fn sub_unsigned(a: &[Limb], b: &[Limb]) -> BigNum {
    // First determine which is larger
    let mut cmp = std::cmp::Ordering::Equal;
    let max_len = a.len().max(b.len());
    for i in (0..max_len).rev() {
        let av = if i < a.len() { a[i] } else { 0 };
        let bv = if i < b.len() { b[i] } else { 0 };
        if av != bv {
            cmp = av.cmp(&bv);
            break;
        }
    }

    let (larger, smaller, negative) = match cmp {
        std::cmp::Ordering::Less => (b, a, true),
        std::cmp::Ordering::Equal => return BigNum::zero(),
        std::cmp::Ordering::Greater => (a, b, false),
    };

    let mut limbs = vec![0u64; larger.len()];
    let mut borrow: u64 = 0;

    for i in 0..larger.len() {
        let lv = larger[i];
        let sv = if i < smaller.len() { smaller[i] } else { 0 };
        let (diff, b1) = lv.overflowing_sub(sv);
        let (diff2, b2) = diff.overflowing_sub(borrow);
        limbs[i] = diff2;
        borrow = (b1 as u64) + (b2 as u64);
    }

    let mut bn = BigNum::from_u64(0);
    *bn.limbs_mut() = limbs;
    bn.set_negative(negative);
    while bn.limbs().len() > 1 && *bn.limbs().last().unwrap() == 0 {
        bn.limbs_mut().pop();
    }
    bn
}

/// Multiply two unsigned limb arrays.
fn mul_unsigned(a: &[Limb], b: &[Limb]) -> BigNum {
    if a.iter().all(|&l| l == 0) || b.iter().all(|&l| l == 0) {
        return BigNum::zero();
    }

    let mut limbs = vec![0u64; a.len() + b.len()];

    for i in 0..a.len() {
        let mut carry: u64 = 0;
        for j in 0..b.len() {
            let prod = a[i] as DoubleLimb * b[j] as DoubleLimb
                + limbs[i + j] as DoubleLimb
                + carry as DoubleLimb;
            limbs[i + j] = prod as Limb;
            carry = (prod >> LIMB_BITS) as u64;
        }
        limbs[i + b.len()] = carry;
    }

    let mut bn = BigNum::from_u64(0);
    *bn.limbs_mut() = limbs;
    while bn.limbs().len() > 1 && *bn.limbs().last().unwrap() == 0 {
        bn.limbs_mut().pop();
    }
    bn
}

/// Division of unsigned values using Knuth's Algorithm D (word-at-a-time).
///
/// Returns (quotient, remainder). Assumes divisor is non-zero.
fn div_rem_unsigned(a: &[Limb], b: &[Limb]) -> (BigNum, BigNum) {
    // Trim leading zeros from inputs
    let a_len = trim_len(a);
    let b_len = trim_len(b);

    if b_len == 0 {
        return (BigNum::zero(), BigNum::zero());
    }

    // Single-limb divisor: use simple path
    if b_len == 1 {
        return div_rem_single(a, a_len, b[0]);
    }

    // If dividend < divisor, quotient is 0
    if a_len < b_len {
        return (BigNum::zero(), BigNum::from_limbs(a[..a_len].to_vec()));
    }

    // Compare when same length
    if a_len == b_len {
        let mut less = false;
        for i in (0..a_len).rev() {
            if a[i] != b[i] {
                less = a[i] < b[i];
                break;
            }
        }
        if less {
            return (BigNum::zero(), BigNum::from_limbs(a[..a_len].to_vec()));
        }
    }

    knuth_div_rem(&a[..a_len], &b[..b_len])
}

/// Knuth's Algorithm D for multi-word division.
fn knuth_div_rem(a: &[Limb], b: &[Limb]) -> (BigNum, BigNum) {
    let n = b.len();
    let m = a.len() - n;

    // D1. Normalize: shift so that the MSB of divisor's top limb is set
    let shift = b[n - 1].leading_zeros();

    // Shifted divisor
    let mut v = vec![0u64; n];
    if shift > 0 {
        for i in (1..n).rev() {
            v[i] = (b[i] << shift) | (b[i - 1] >> (64 - shift));
        }
        v[0] = b[0] << shift;
    } else {
        v[..n].copy_from_slice(&b[..n]);
    }

    // Shifted dividend (n+m+1 limbs)
    let mut u = vec![0u64; a.len() + 1];
    if shift > 0 {
        u[a.len()] = a[a.len() - 1] >> (64 - shift);
        for i in (1..a.len()).rev() {
            u[i] = (a[i] << shift) | (a[i - 1] >> (64 - shift));
        }
        u[0] = a[0] << shift;
    } else {
        u[..a.len()].copy_from_slice(a);
    }

    let mut q_limbs = vec![0u64; m + 1];

    // D2-D7. Main loop
    for j in (0..=m).rev() {
        // D3. Estimate quotient digit qhat
        let u_hi = u[j + n] as DoubleLimb;
        let u_lo = u[j + n - 1] as DoubleLimb;
        let dividend = (u_hi << LIMB_BITS) | u_lo;
        let v_top = v[n - 1] as DoubleLimb;

        let mut qhat = dividend / v_top;
        let mut rhat = dividend % v_top;

        // Refine qhat estimate
        loop {
            if qhat >= (1u128 << LIMB_BITS)
                || (n >= 2
                    && qhat * v[n - 2] as DoubleLimb
                        > ((rhat << LIMB_BITS) | u[j + n - 2] as DoubleLimb))
            {
                qhat -= 1;
                rhat += v_top;
                if rhat < (1u128 << LIMB_BITS) {
                    continue;
                }
            }
            break;
        }

        // D4. Multiply and subtract: u[j..j+n] -= qhat * v
        let mut borrow: i128 = 0;
        for i in 0..n {
            let prod = qhat * v[i] as DoubleLimb;
            let diff = u[j + i] as i128 - borrow - prod as u64 as i128;
            u[j + i] = diff as u64;
            borrow = (prod >> LIMB_BITS) as i128 - (diff >> LIMB_BITS);
        }
        let diff = u[j + n] as i128 - borrow;
        u[j + n] = diff as u64;

        // D5. Set quotient digit
        q_limbs[j] = qhat as u64;

        // D6. Add back if we subtracted too much (rare)
        if diff < 0 {
            q_limbs[j] -= 1;
            let mut carry: u64 = 0;
            for i in 0..n {
                let sum = u[j + i] as DoubleLimb + v[i] as DoubleLimb + carry as DoubleLimb;
                u[j + i] = sum as u64;
                carry = (sum >> LIMB_BITS) as u64;
            }
            u[j + n] = u[j + n].wrapping_add(carry);
        }
    }

    // D8. Unnormalize remainder
    let mut rem = vec![0u64; n];
    if shift > 0 {
        for i in 0..n - 1 {
            rem[i] = (u[i] >> shift) | (u[i + 1] << (64 - shift));
        }
        rem[n - 1] = u[n - 1] >> shift;
    } else {
        rem[..n].copy_from_slice(&u[..n]);
    }

    (BigNum::from_limbs(q_limbs), BigNum::from_limbs(rem))
}

/// Fast path for single-limb divisor.
fn div_rem_single(a: &[Limb], a_len: usize, d: u64) -> (BigNum, BigNum) {
    if a_len == 0 {
        return (BigNum::zero(), BigNum::zero());
    }
    let mut q = vec![0u64; a_len];
    let mut rem: u64 = 0;
    for i in (0..a_len).rev() {
        let dividend = (rem as DoubleLimb) << LIMB_BITS | a[i] as DoubleLimb;
        q[i] = (dividend / d as DoubleLimb) as u64;
        rem = (dividend % d as DoubleLimb) as u64;
    }
    (BigNum::from_limbs(q), BigNum::from_u64(rem))
}

/// Return length after trimming leading zero limbs (at least 0).
fn trim_len(limbs: &[Limb]) -> usize {
    let mut len = limbs.len();
    while len > 0 && limbs[len - 1] == 0 {
        len -= 1;
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let a = BigNum::from_u64(100);
        let b = BigNum::from_u64(200);
        let c = a.add(&b);
        assert_eq!(c, BigNum::from_u64(300));
    }

    #[test]
    fn test_sub() {
        let a = BigNum::from_u64(300);
        let b = BigNum::from_u64(100);
        let c = a.sub(&b);
        assert_eq!(c, BigNum::from_u64(200));
    }

    #[test]
    fn test_mul() {
        let a = BigNum::from_u64(12345);
        let b = BigNum::from_u64(67890);
        let c = a.mul(&b);
        assert_eq!(c, BigNum::from_u64(12345u64 * 67890));
    }

    #[test]
    fn test_div_rem() {
        let a = BigNum::from_u64(100);
        let b = BigNum::from_u64(7);
        let (q, r) = a.div_rem(&b).unwrap();
        assert_eq!(q, BigNum::from_u64(14));
        assert_eq!(r, BigNum::from_u64(2));
    }

    #[test]
    fn test_div_by_zero() {
        let a = BigNum::from_u64(100);
        let b = BigNum::zero();
        assert!(a.div_rem(&b).is_err());
    }

    #[test]
    fn test_shl() {
        let a = BigNum::from_u64(1);
        assert_eq!(a.shl(0), BigNum::from_u64(1));
        assert_eq!(a.shl(1), BigNum::from_u64(2));
        assert_eq!(a.shl(10), BigNum::from_u64(1024));
        assert_eq!(a.shl(63), BigNum::from_u64(1u64 << 63));
        // Multi-limb shift
        let shifted = a.shl(64);
        assert_eq!(shifted.bit_len(), 65);
        assert_eq!(shifted.limbs()[0], 0);
        assert_eq!(shifted.limbs()[1], 1);
    }

    #[test]
    fn test_shr() {
        let a = BigNum::from_u64(1024);
        assert_eq!(a.shr(0), BigNum::from_u64(1024));
        assert_eq!(a.shr(1), BigNum::from_u64(512));
        assert_eq!(a.shr(10), BigNum::from_u64(1));
        assert_eq!(a.shr(11), BigNum::zero());
    }

    #[test]
    fn test_shl_shr_roundtrip() {
        let a = BigNum::from_u64(0xDEADBEEFCAFEBABE);
        for shift in [1, 7, 13, 32, 63, 64, 65, 128] {
            let b = a.shl(shift).shr(shift);
            assert_eq!(a, b, "shift roundtrip failed for shift={shift}");
        }
    }

    #[test]
    fn test_sqr() {
        let a = BigNum::from_u64(12345);
        let sqr = a.sqr();
        let mul = a.mul(&a);
        assert_eq!(sqr, mul);
    }

    #[test]
    fn test_sqr_large() {
        // Multi-limb squaring
        let a = BigNum::from_bytes_be(&[0xFF; 16]); // 128-bit number
        let sqr = a.sqr();
        let mul = a.mul(&a);
        assert_eq!(sqr, mul);
    }

    #[test]
    fn test_mod_add() {
        let a = BigNum::from_u64(90);
        let b = BigNum::from_u64(20);
        let m = BigNum::from_u64(97);
        assert_eq!(a.mod_add(&b, &m).unwrap(), BigNum::from_u64(13));
    }

    #[test]
    fn test_mod_sub() {
        let a = BigNum::from_u64(10);
        let b = BigNum::from_u64(20);
        let m = BigNum::from_u64(97);
        // 10 - 20 = -10, -10 + 97 = 87
        assert_eq!(a.mod_sub(&b, &m).unwrap(), BigNum::from_u64(87));
    }

    #[test]
    fn test_mod_mul() {
        let a = BigNum::from_u64(45);
        let b = BigNum::from_u64(67);
        let m = BigNum::from_u64(97);
        // 45 * 67 = 3015, 3015 mod 97 = 8
        assert_eq!(a.mod_mul(&b, &m).unwrap(), BigNum::from_u64(8));
    }

    #[test]
    fn test_div_large() {
        // q*b + r == a for multi-limb numbers
        let a = BigNum::from_bytes_be(&[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ]);
        let b = BigNum::from_bytes_be(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01]);
        let (q, r) = a.div_rem(&b).unwrap();
        let reconstructed = q.mul(&b).add(&r);
        assert_eq!(reconstructed, a);
    }

    #[test]
    fn test_rsa_small_example() {
        // RSA with small primes: p=61, q=53, n=3233, e=17, d=413
        let n = BigNum::from_u64(3233);
        let e = BigNum::from_u64(17);
        let d = BigNum::from_u64(413);

        // Test encrypt/decrypt for several messages
        for m_val in [42u64, 100, 1234, 3000] {
            let m = BigNum::from_u64(m_val);
            let c = m.mod_exp(&e, &n).unwrap(); // encrypt
            let decrypted = c.mod_exp(&d, &n).unwrap(); // decrypt
            assert_eq!(decrypted, m, "RSA roundtrip failed for m={m_val}");
        }
    }

    #[test]
    fn test_ord() {
        let a = BigNum::from_u64(100);
        let b = BigNum::from_u64(200);
        assert!(a < b);
        assert!(b > a);

        let mut neg = BigNum::from_u64(100);
        neg.set_negative(true);
        assert!(neg < BigNum::zero());
        assert!(neg < a);
    }

    #[test]
    fn test_div_by_one_and_mod_one() {
        let one = BigNum::from_u64(1);

        // 12345 / 1 = (12345, 0)
        let val = BigNum::from_u64(12345);
        let (q, r) = val.div_rem(&one).unwrap();
        assert_eq!(q, val);
        assert_eq!(r, BigNum::zero());

        // 12345 mod 1 = 0
        let m = val.mod_reduce(&one).unwrap();
        assert_eq!(m, BigNum::zero());

        // 0 / 1 = (0, 0)
        let (q0, r0) = BigNum::zero().div_rem(&one).unwrap();
        assert_eq!(q0, BigNum::zero());
        assert_eq!(r0, BigNum::zero());
    }

    #[test]
    fn test_mod_reduce_negative() {
        // (-7) mod 5 should be 3  (since -7 = -2*5 + 3)
        let mut neg7 = BigNum::from_u64(7);
        neg7.set_negative(true);
        let m = BigNum::from_u64(5);
        let r = neg7.mod_reduce(&m).unwrap();
        assert_eq!(r, BigNum::from_u64(3));

        // (-17) mod 5 should be 3  (since -17 = -4*5 + 3)
        let mut neg17 = BigNum::from_u64(17);
        neg17.set_negative(true);
        let r = neg17.mod_reduce(&m).unwrap();
        assert_eq!(r, BigNum::from_u64(3));

        // (-10) mod 5 should be 0  (exactly divisible)
        let mut neg10 = BigNum::from_u64(10);
        neg10.set_negative(true);
        let r = neg10.mod_reduce(&m).unwrap();
        assert_eq!(r, BigNum::zero());

        // (-1) mod 97 should be 96
        let mut neg1 = BigNum::from_u64(1);
        neg1.set_negative(true);
        let m97 = BigNum::from_u64(97);
        let r = neg1.mod_reduce(&m97).unwrap();
        assert_eq!(r, BigNum::from_u64(96));

        // Positive values should be unchanged
        let pos7 = BigNum::from_u64(7);
        let r = pos7.mod_reduce(&m).unwrap();
        assert_eq!(r, BigNum::from_u64(2));
    }

    #[test]
    fn test_sqr_mul_consistency() {
        let values = [
            BigNum::from_u64(0),
            BigNum::from_u64(1),
            BigNum::from_u64(7),
            BigNum::from_u64(12345),
            BigNum::from_u64(1).shl(128), // 2^128
        ];
        for x in &values {
            let sq = x.sqr();
            let mul = x.mul(x);
            assert_eq!(
                sq.to_bytes_be(),
                mul.to_bytes_be(),
                "sqr vs mul mismatch for {:?}",
                x.to_bytes_be()
            );
        }
    }
}
