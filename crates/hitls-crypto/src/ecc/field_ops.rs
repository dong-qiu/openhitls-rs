//! Shared multi-limb unsigned arithmetic for field element implementations.
//!
//! Provides const-generic helpers for N-limb addition, subtraction, comparison,
//! and in-place variants. Used by P-256, P-384, P-521, and SM2 specialized fields.

use core::cmp::Ordering;

/// N-limb addition: returns (result, carry).
#[inline]
pub(crate) fn add_limbs<const N: usize>(a: &[u64; N], b: &[u64; N]) -> ([u64; N], u64) {
    let mut r = [0u64; N];
    let mut carry = 0u64;

    for i in 0..N {
        let sum = u128::from(a[i]) + u128::from(b[i]) + u128::from(carry);
        r[i] = sum as u64;
        carry = (sum >> 64) as u64;
    }

    (r, carry)
}

/// N-limb subtraction: returns (result, borrow). Borrow is 1 if a < b.
#[inline]
pub(crate) fn sub_limbs<const N: usize>(a: &[u64; N], b: &[u64; N]) -> ([u64; N], u64) {
    let mut r = [0u64; N];
    let mut borrow = 0i128;

    for i in 0..N {
        let diff = i128::from(a[i]) - i128::from(b[i]) + borrow;
        r[i] = diff as u64;
        borrow = diff >> 64; // arithmetic shift: -1 if borrow, 0 otherwise
    }

    (r, if borrow < 0 { 1 } else { 0 })
}

/// Compare two N-limb numbers (little-endian limb order).
#[inline]
pub(crate) fn cmp_limbs<const N: usize>(a: &[u64; N], b: &[u64; N]) -> Ordering {
    let mut i = N - 1;
    loop {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => {}
            other => return other,
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    Ordering::Equal
}

/// In-place N-limb addition: a += b, ignoring overflow.
#[inline]
pub(crate) fn add_assign_limbs<const N: usize>(a: &mut [u64; N], b: &[u64; N]) {
    let mut carry = 0u64;
    for i in 0..N {
        let sum = u128::from(a[i]) + u128::from(b[i]) + u128::from(carry);
        a[i] = sum as u64;
        carry = (sum >> 64) as u64;
    }
}

/// In-place N-limb subtraction: a -= b, ignoring underflow.
#[inline]
pub(crate) fn sub_assign_limbs<const N: usize>(a: &mut [u64; N], b: &[u64; N]) {
    let mut borrow = 0i128;
    for i in 0..N {
        let diff = i128::from(a[i]) - i128::from(b[i]) + borrow;
        a[i] = diff as u64;
        borrow = diff >> 64;
    }
}

/// Schoolbook N×N multiplication producing a 2N-limb product.
///
/// Writes the full 2N-limb result into `t` (which must be zeroed on entry).
#[inline]
pub(crate) fn schoolbook_mul<const N: usize, const N2: usize>(
    a: &[u64; N],
    b: &[u64; N],
    t: &mut [u64; N2],
) {
    for i in 0..N {
        let mut carry: u64 = 0;
        for j in 0..N {
            let product =
                u128::from(a[i]) * u128::from(b[j]) + u128::from(t[i + j]) + u128::from(carry);
            t[i + j] = product as u64;
            carry = (product >> 64) as u64;
        }
        t[i + N] = carry;
    }
}

/// Schoolbook squaring using cross-product symmetry.
///
/// Computes upper-triangle cross products, doubles them, then adds diagonal terms.
/// For N limbs: N*(N-1)/2 cross multiplies + N diagonal = N*(N+1)/2 total
/// vs N² for full schoolbook multiplication.
///
/// Writes the full 2N-limb result into `t` (which must be zeroed on entry).
#[inline]
pub(crate) fn schoolbook_sqr<const N: usize, const N2: usize>(
    a: &[u64; N],
    t: &mut [u64; N2],
) {
    // Cross-products (upper triangle): sum of a[i]*a[j] for i < j
    for i in 0..N {
        let mut carry = 0u64;
        for j in (i + 1)..N {
            let prod =
                u128::from(a[i]) * u128::from(a[j]) + u128::from(t[i + j]) + u128::from(carry);
            t[i + j] = prod as u64;
            carry = (prod >> 64) as u64;
        }
        t[i + N] = carry;
    }

    // Double all cross-products (left shift by 1)
    let last = N2 - 1;
    for i in (1..N2).rev() {
        t[i] = (t[i] << 1) | (t[i - 1] >> 63);
    }
    t[0] = 0; // no cross products at index 0

    // Add diagonal terms a[i]²
    let mut carry = 0u128;
    for i in 0..N {
        let diag = u128::from(a[i]) * u128::from(a[i]);
        let sum = u128::from(t[2 * i]) + (diag & 0xFFFF_FFFF_FFFF_FFFF) + carry;
        t[2 * i] = sum as u64;
        carry = (sum >> 64) + (diag >> 64);

        let sum2 = u128::from(t[2 * i + 1]) + carry;
        t[2 * i + 1] = sum2 as u64;
        carry = sum2 >> 64;
    }
    let _ = last; // suppress unused warning
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_limbs_4() {
        let a = [1u64, 0, 0, 0];
        let b = [2u64, 0, 0, 0];
        let (r, carry) = add_limbs(&a, &b);
        assert_eq!(r, [3, 0, 0, 0]);
        assert_eq!(carry, 0);
    }

    #[test]
    fn test_add_limbs_carry() {
        let a = [u64::MAX, 0, 0, 0];
        let b = [1u64, 0, 0, 0];
        let (r, carry) = add_limbs(&a, &b);
        assert_eq!(r, [0, 1, 0, 0]);
        assert_eq!(carry, 0);
    }

    #[test]
    fn test_sub_limbs_4() {
        let a = [5u64, 0, 0, 0];
        let b = [3u64, 0, 0, 0];
        let (r, borrow) = sub_limbs(&a, &b);
        assert_eq!(r, [2, 0, 0, 0]);
        assert_eq!(borrow, 0);
    }

    #[test]
    fn test_sub_limbs_borrow() {
        let a = [0u64, 0, 0, 0];
        let b = [1u64, 0, 0, 0];
        let (_, borrow) = sub_limbs(&a, &b);
        assert_eq!(borrow, 1);
    }

    #[test]
    fn test_cmp_limbs_4() {
        let a = [1u64, 0, 0, 0];
        let b = [2u64, 0, 0, 0];
        assert_eq!(cmp_limbs(&a, &b), Ordering::Less);
        assert_eq!(cmp_limbs(&b, &a), Ordering::Greater);
        assert_eq!(cmp_limbs(&a, &a), Ordering::Equal);

        let c = [0u64, 0, 0, 1];
        let d = [u64::MAX, u64::MAX, u64::MAX, 0];
        assert_eq!(cmp_limbs(&c, &d), Ordering::Greater);
    }

    #[test]
    fn test_cmp_limbs_6() {
        let a = [1u64, 0, 0, 0, 0, 0];
        let b = [2u64, 0, 0, 0, 0, 0];
        assert_eq!(cmp_limbs(&a, &b), Ordering::Less);

        let c = [0u64, 0, 0, 0, 0, 1];
        let d = [u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, 0];
        assert_eq!(cmp_limbs(&c, &d), Ordering::Greater);
    }

    #[test]
    fn test_schoolbook_mul_small() {
        let a: [u64; 2] = [3, 0];
        let b: [u64; 2] = [7, 0];
        let mut t = [0u64; 4];
        schoolbook_mul(&a, &b, &mut t);
        assert_eq!(t[0], 21);
        assert_eq!(t[1], 0);
    }

    #[test]
    fn test_schoolbook_sqr_matches_mul() {
        let a: [u64; 4] = [0xDEAD_BEEF, 0xCAFE_BABE, 0x1234_5678, 0x9ABC_DEF0];
        let mut t_mul = [0u64; 8];
        let mut t_sqr = [0u64; 8];
        schoolbook_mul(&a, &a, &mut t_mul);
        schoolbook_sqr(&a, &mut t_sqr);
        assert_eq!(t_mul, t_sqr);
    }

    #[test]
    fn test_add_assign_limbs() {
        let mut a = [5u64, 0, 0, 0];
        let b = [3u64, 0, 0, 0];
        add_assign_limbs(&mut a, &b);
        assert_eq!(a, [8, 0, 0, 0]);
    }

    #[test]
    fn test_sub_assign_limbs() {
        let mut a = [5u64, 0, 0, 0];
        let b = [3u64, 0, 0, 0];
        sub_assign_limbs(&mut a, &b);
        assert_eq!(a, [2, 0, 0, 0]);
    }
}
