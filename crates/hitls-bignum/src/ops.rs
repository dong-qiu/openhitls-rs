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
    pub fn mod_reduce(&self, modulus: &BigNum) -> Result<BigNum, CryptoError> {
        let (_, r) = self.div_rem(modulus)?;
        Ok(r)
    }

    /// Modular exponentiation: self^exp mod modulus.
    pub fn mod_exp(&self, exp: &BigNum, modulus: &BigNum) -> Result<BigNum, CryptoError> {
        if modulus.is_zero() {
            return Err(CryptoError::BnDivisionByZero);
        }
        // TODO: Use Montgomery multiplication for production
        // Simple square-and-multiply for now
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

/// Simple binary long division for unsigned values.
fn div_rem_unsigned(a: &[Limb], b: &[Limb]) -> (BigNum, BigNum) {
    let a_bn = {
        let mut bn = BigNum::from_u64(0);
        *bn.limbs_mut() = a.to_vec();
        bn
    };
    let b_bn = {
        let mut bn = BigNum::from_u64(0);
        *bn.limbs_mut() = b.to_vec();
        bn
    };

    if a_bn.cmp_abs(&b_bn) == std::cmp::Ordering::Less {
        return (BigNum::zero(), a_bn);
    }

    let bits = a_bn.bit_len();
    let mut quotient = BigNum::zero();
    *quotient.limbs_mut() = vec![0u64; (bits + LIMB_BITS - 1) / LIMB_BITS];
    let mut remainder = BigNum::zero();

    for i in (0..bits).rev() {
        // Shift remainder left by 1
        let mut carry = 0u64;
        for limb in remainder.limbs_mut().iter_mut() {
            let new_carry = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = new_carry;
        }
        if carry != 0 {
            remainder.limbs_mut().push(carry);
        }

        // Set bit 0 of remainder to bit i of a
        let limb_idx = i / LIMB_BITS;
        let bit_idx = i % LIMB_BITS;
        if limb_idx < a.len() {
            let bit = (a[limb_idx] >> bit_idx) & 1;
            if remainder.limbs().is_empty() {
                *remainder.limbs_mut() = vec![bit];
            } else {
                remainder.limbs_mut()[0] |= bit;
            }
        }

        // If remainder >= divisor, subtract
        if remainder.cmp_abs(&b_bn) != std::cmp::Ordering::Less {
            remainder = sub_unsigned(remainder.limbs(), b_bn.limbs());
        } else {
            continue;
        }

        // Set quotient bit
        let q_limb_idx = i / LIMB_BITS;
        let q_bit_idx = i % LIMB_BITS;
        if q_limb_idx < quotient.limbs().len() {
            quotient.limbs_mut()[q_limb_idx] |= 1u64 << q_bit_idx;
        }
    }

    // Normalize
    while quotient.limbs().len() > 1 && *quotient.limbs().last().unwrap() == 0 {
        quotient.limbs_mut().pop();
    }
    while remainder.limbs().len() > 1 && *remainder.limbs().last().unwrap() == 0 {
        remainder.limbs_mut().pop();
    }

    (quotient, remainder)
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
}
