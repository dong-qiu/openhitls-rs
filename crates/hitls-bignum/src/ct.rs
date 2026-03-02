//! Constant-time operations for big numbers.
//!
//! These operations avoid data-dependent branching to prevent timing side-channel attacks.

use crate::bignum::BigNum;
use subtle::{Choice, ConstantTimeEq};

impl BigNum {
    /// Constant-time equality comparison.
    pub fn ct_eq(&self, other: &BigNum) -> Choice {
        let max_len = self.limbs().len().max(other.limbs().len());
        let mut result: u8 = 1;

        // Compare sign
        result &= (self.is_negative() as u8)
            .ct_eq(&(other.is_negative() as u8))
            .unwrap_u8();

        // Compare limbs
        for i in 0..max_len {
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
            result &= a.ct_eq(&b).unwrap_u8();
        }

        Choice::from(result)
    }

    /// Constant-time conditional select: returns `a` if choice == 0, `b` if choice == 1.
    pub fn ct_select(a: &BigNum, b: &BigNum, choice: Choice) -> BigNum {
        let mask = (choice.unwrap_u8() as u64).wrapping_neg(); // 0 or 0xFFFF...
        let max_len = a.limbs().len().max(b.limbs().len());
        let mut limbs = vec![0u64; max_len];

        for (i, limb) in limbs.iter_mut().enumerate() {
            let av = if i < a.limbs().len() { a.limbs()[i] } else { 0 };
            let bv = if i < b.limbs().len() { b.limbs()[i] } else { 0 };
            *limb = av ^ (mask & (av ^ bv));
        }

        let neg_a = a.is_negative() as u64;
        let neg_b = b.is_negative() as u64;
        let neg = neg_a ^ (mask & (neg_a ^ neg_b));

        let mut result = BigNum::from_limbs(limbs);
        result.set_negative(neg != 0);
        result
    }

    /// Constant-time conditional subtraction: if self >= modulus, return self - modulus,
    /// otherwise return self. The comparison and selection are done in constant time.
    pub fn ct_sub_if_gte(&self, modulus: &BigNum) -> BigNum {
        let max_len = self.limbs().len().max(modulus.limbs().len());

        // Compute self - modulus
        let mut diff = vec![0u64; max_len];
        let mut borrow: u64 = 0;
        let self_limbs = self.limbs();
        let mod_limbs = modulus.limbs();
        for (i, d) in diff.iter_mut().enumerate() {
            let a = if i < self_limbs.len() {
                self_limbs[i]
            } else {
                0
            };
            let b = if i < mod_limbs.len() { mod_limbs[i] } else { 0 };
            let (d1, b1) = a.overflowing_sub(b);
            let (d2, b2) = d1.overflowing_sub(borrow);
            *d = d2;
            borrow = (b1 as u64) + (b2 as u64);
        }

        // If borrow == 0, self >= modulus, use diff; otherwise use self
        let use_diff = Choice::from((borrow == 0) as u8);
        let diff_bn = BigNum::from_limbs(diff);
        BigNum::ct_select(self, &diff_bn, use_diff)
    }
}

impl ConstantTimeEq for BigNum {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.ct_eq(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_eq_different_lengths() {
        // Same value but potentially different limb counts
        let a = BigNum::from_u64(42);
        let b = BigNum::from_limbs(vec![42, 0, 0]); // extra zero limbs get normalized
        assert_eq!(a.ct_eq(&b).unwrap_u8(), 1);

        // Large multi-limb value
        let bytes = vec![0x01; 16]; // 128-bit value
        let c = BigNum::from_bytes_be(&bytes);
        let d = BigNum::from_bytes_be(&bytes);
        assert_eq!(c.ct_eq(&d).unwrap_u8(), 1);

        // Zero with different representations
        let z1 = BigNum::zero();
        let z2 = BigNum::from_u64(0);
        assert_eq!(z1.ct_eq(&z2).unwrap_u8(), 1);
    }

    #[test]
    fn test_ct_eq_negative() {
        let mut neg5 = BigNum::from_u64(5);
        neg5.set_negative(true);
        let mut neg5b = BigNum::from_u64(5);
        neg5b.set_negative(true);
        let pos5 = BigNum::from_u64(5);

        // -5 == -5
        assert_eq!(neg5.ct_eq(&neg5b).unwrap_u8(), 1);
        // -5 != 5
        assert_eq!(neg5.ct_eq(&pos5).unwrap_u8(), 0);

        // -0 == 0 (is_negative returns false for zero regardless of sign flag)
        let mut neg0 = BigNum::zero();
        neg0.set_negative(true);
        let pos0 = BigNum::zero();
        // Both should report is_negative() as false
        assert!(!neg0.is_negative());
        assert_eq!(neg0.ct_eq(&pos0).unwrap_u8(), 1);
    }

    #[test]
    fn test_ct_select_negative() {
        let pos = BigNum::from_u64(10);
        let mut neg = BigNum::from_u64(20);
        neg.set_negative(true);

        let r0 = BigNum::ct_select(&pos, &neg, Choice::from(0));
        assert_eq!(r0, pos);
        assert!(!r0.is_negative());

        let r1 = BigNum::ct_select(&pos, &neg, Choice::from(1));
        assert_eq!(r1, neg);
        assert!(r1.is_negative());
    }

    #[test]
    fn test_ct_sub_if_gte_multi_limb() {
        // Multi-limb: 2^64 + 100
        let mut big = BigNum::from_limbs(vec![100, 1]);
        let modulus = BigNum::from_limbs(vec![50, 1]); // 2^64 + 50

        // big (2^64+100) >= modulus (2^64+50), should subtract → 50
        let result = big.ct_sub_if_gte(&modulus);
        assert_eq!(result, BigNum::from_u64(50));

        // Smaller than modulus: should keep original
        big = BigNum::from_u64(10);
        let result2 = big.ct_sub_if_gte(&modulus);
        assert_eq!(result2, BigNum::from_u64(10));
    }

    #[test]
    fn test_constant_time_eq_trait() {
        use subtle::ConstantTimeEq;
        let a = BigNum::from_u64(12345);
        let b = BigNum::from_u64(12345);
        let c = BigNum::from_u64(54321);

        // Trait method should work the same as inherent method
        assert_eq!(ConstantTimeEq::ct_eq(&a, &b).unwrap_u8(), 1);
        assert_eq!(ConstantTimeEq::ct_eq(&a, &c).unwrap_u8(), 0);
    }

    #[test]
    fn test_ct_eq() {
        let a = BigNum::from_u64(42);
        let b = BigNum::from_u64(42);
        let c = BigNum::from_u64(43);

        assert_eq!(a.ct_eq(&b).unwrap_u8(), 1);
        assert_eq!(a.ct_eq(&c).unwrap_u8(), 0);
    }

    #[test]
    fn test_ct_select() {
        let a = BigNum::from_u64(10);
        let b = BigNum::from_u64(20);

        let r0 = BigNum::ct_select(&a, &b, Choice::from(0));
        let r1 = BigNum::ct_select(&a, &b, Choice::from(1));

        assert_eq!(r0, a);
        assert_eq!(r1, b);
    }

    #[test]
    fn test_ct_sub_if_gte() {
        let modulus = BigNum::from_u64(97);

        // Value >= modulus: should subtract
        let a = BigNum::from_u64(100);
        assert_eq!(a.ct_sub_if_gte(&modulus), BigNum::from_u64(3));

        // Value < modulus: should keep
        let b = BigNum::from_u64(50);
        assert_eq!(b.ct_sub_if_gte(&modulus), BigNum::from_u64(50));

        // Value == modulus: should subtract to 0
        let c = BigNum::from_u64(97);
        assert_eq!(c.ct_sub_if_gte(&modulus), BigNum::from_u64(0));
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            #[test]
            fn prop_ct_eq_reflexive(val in any::<u64>()) {
                let a = BigNum::from_u64(val);
                prop_assert_eq!(a.ct_eq(&a).unwrap_u8(), 1);
            }

            #[test]
            fn prop_ct_select_choice0(
                a_val in any::<u64>(),
                b_val in any::<u64>(),
            ) {
                let a = BigNum::from_u64(a_val);
                let b = BigNum::from_u64(b_val);
                let r = BigNum::ct_select(&a, &b, Choice::from(0));
                prop_assert_eq!(r, a);
            }

            #[test]
            fn prop_ct_select_choice1(
                a_val in any::<u64>(),
                b_val in any::<u64>(),
            ) {
                let a = BigNum::from_u64(a_val);
                let b = BigNum::from_u64(b_val);
                let r = BigNum::ct_select(&a, &b, Choice::from(1));
                prop_assert_eq!(r, b);
            }
        }
    }
}
