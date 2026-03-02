//! P-521 specialized field element arithmetic using direct Mersenne reduction.
//!
//! P-521 uses the Mersenne prime p = 2^521 - 1, enabling ultra-fast modular reduction:
//! after multiplication, split the product at bit 521 and add high half to low half
//! (since 2^521 ≡ 1 mod p). No Montgomery form needed.
//!
//! Elements are stored as 9×u64 in little-endian limb order, with the top limb
//! carrying only 9 bits (521 - 8×64 = 9).

use core::cmp::Ordering;
use hitls_bignum::BigNum;

/// The P-521 prime p = 2^521 - 1 (all-ones Mersenne prime).
/// Stored as 9×u64 in little-endian limb order. Top limb = 0x1FF (9 bits).
const P: [u64; 9] = [
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0x0000_0000_0000_01FF,
];

/// Mask for the top limb: only the lower 9 bits are valid.
const TOP_MASK: u64 = 0x1FF;

/// Number of limbs in a P-521 field element.
const NLIMBS: usize = 9;

// ========================================================================
// P521FieldElement
// ========================================================================

/// A P-521 field element stored directly (NOT Montgomery form).
///
/// 9×u64 in little-endian limb order. Top limb has 9 valid bits.
/// All values are fully reduced modulo p = 2^521 - 1.
#[derive(Clone, Copy, Debug)]
pub(crate) struct P521FieldElement(pub [u64; NLIMBS]);

impl PartialEq for P521FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for P521FieldElement {}

impl P521FieldElement {
    /// The additive identity (zero).
    pub const ZERO: Self = Self([0; NLIMBS]);

    /// The multiplicative identity (one).
    pub const ONE: Self = Self([1, 0, 0, 0, 0, 0, 0, 0, 0]);

    /// Create a field element from a 66-byte big-endian encoding.
    pub fn from_bytes(bytes: &[u8; 66]) -> Self {
        let mut limbs = [0u64; NLIMBS];
        // Byte 0 is MSB. Limb 0 is LSB.
        // bytes[65-64] → limb 0, bytes[63-56] → limb 1, etc.
        for (i, limb) in limbs[..8].iter_mut().enumerate() {
            let base = 65 - i * 8;
            for j in 0..8 {
                *limb |= (bytes[base - j] as u64) << (j * 8);
            }
        }
        // Top limb (limb 8): bytes[0..2] (2 bytes, but only 9 bits)
        limbs[8] = ((bytes[0] as u64) << 8) | (bytes[1] as u64);
        Self(limbs)
    }

    /// Encode as a 66-byte big-endian representation.
    pub fn to_bytes(self) -> [u8; 66] {
        let mut out = [0u8; 66];
        let a = &self.0;
        // Top limb → bytes[0..2]
        out[0] = (a[8] >> 8) as u8;
        out[1] = a[8] as u8;
        // Limbs 7..0 → bytes[2..66]
        for i in (0..8).rev() {
            let base = 2 + (7 - i) * 8;
            for j in 0..8 {
                out[base + j] = (a[i] >> ((7 - j) * 8)) as u8;
            }
        }
        out
    }

    /// Field addition: (a + b) mod p.
    pub fn add(&self, other: &Self) -> Self {
        let mut r = [0u64; NLIMBS];
        let mut carry = 0u64;
        for ((r_limb, &a), &b) in r.iter_mut().zip(&self.0).zip(&other.0) {
            let sum = (a as u128) + (b as u128) + (carry as u128);
            *r_limb = sum as u64;
            carry = (sum >> 64) as u64;
        }
        // Fold overflow: since p = 2^521 - 1, bits above 521 just add back in.
        let top_overflow = r[8] >> 9;
        r[8] &= TOP_MASK;
        // Add overflow back to limb 0
        let mut c = top_overflow;
        for limb in &mut r {
            if c == 0 {
                break;
            }
            let sum = (*limb as u128) + (c as u128);
            *limb = sum as u64;
            c = (sum >> 64) as u64;
        }
        // One more fold if needed (can happen after adding carry)
        let top2 = r[8] >> 9;
        r[8] &= TOP_MASK;
        if top2 != 0 {
            let sum = (r[0] as u128) + (top2 as u128);
            r[0] = sum as u64;
            // No further propagation needed since top2 <= 1
        }
        // Final conditional subtraction
        Self(r).reduce_once()
    }

    /// Field subtraction: (a - b) mod p.
    pub fn sub(&self, other: &Self) -> Self {
        // Compute a - b. Since a,b < p, result may be negative.
        let mut r = [0u64; NLIMBS];
        let mut borrow = 0i128;
        for ((r_limb, &a), &b) in r.iter_mut().zip(&self.0).zip(&other.0) {
            let diff = (a as i128) - (b as i128) + borrow;
            *r_limb = diff as u64;
            borrow = diff >> 64;
        }
        if borrow < 0 {
            // Result was negative, add p = 2^521 - 1
            let mut carry = 0u128;
            for i in 0..NLIMBS {
                let sum = (r[i] as u128) + (P[i] as u128) + carry;
                r[i] = sum as u64;
                carry = sum >> 64;
            }
            r[8] &= TOP_MASK;
        }
        Self(r)
    }

    /// Field negation: (-a) mod p.
    pub fn neg(&self) -> Self {
        if self.is_zero() {
            return *self;
        }
        let mut r = [0u64; NLIMBS];
        let mut borrow = 0i128;
        for i in 0..NLIMBS {
            let diff = (P[i] as i128) - (self.0[i] as i128) + borrow;
            r[i] = diff as u64;
            borrow = diff >> 64;
        }
        Self(r)
    }

    /// Field multiplication: (a * b) mod p using schoolbook + Mersenne reduction.
    ///
    /// 9×9 schoolbook multiplication (81 limb muls) produces an 18-limb product.
    /// Mersenne reduction: split at bit 521, add high half to low half.
    pub fn mul(&self, other: &Self) -> Self {
        let a = &self.0;
        let b = &other.0;

        // Schoolbook multiplication → 18-limb product
        let mut t = [0u64; 18];
        for i in 0..NLIMBS {
            let mut carry = 0u64;
            for j in 0..NLIMBS {
                let prod = (a[i] as u128) * (b[j] as u128) + (t[i + j] as u128) + (carry as u128);
                t[i + j] = prod as u64;
                carry = (prod >> 64) as u64;
            }
            t[i + NLIMBS] = carry;
        }

        mersenne_reduce(t)
    }

    /// Field squaring: a² mod p using cross-product symmetry + Mersenne reduction.
    ///
    /// Uses 36 cross-product multiplies + 9 diagonal = 45 limb muls (vs 81 schoolbook).
    pub fn sqr(&self) -> Self {
        let a = &self.0;
        let mut t = [0u64; 18];

        // Cross-products (upper triangle): sum of a[i]*a[j] for i < j
        for i in 0..NLIMBS {
            let mut carry = 0u64;
            for j in (i + 1)..NLIMBS {
                let prod = (a[i] as u128) * (a[j] as u128) + (t[i + j] as u128) + (carry as u128);
                t[i + j] = prod as u64;
                carry = (prod >> 64) as u64;
            }
            t[i + NLIMBS] = carry;
        }

        // Double all cross-products (left shift by 1)
        for i in (1..18).rev() {
            t[i] = (t[i] << 1) | (t[i - 1] >> 63);
        }
        t[0] = 0; // no cross products at index 0

        // Add diagonal terms a[i]²
        let mut carry = 0u128;
        for i in 0..NLIMBS {
            let diag = (a[i] as u128) * (a[i] as u128);
            let sum = (t[2 * i] as u128) + (diag & 0xFFFF_FFFF_FFFF_FFFF) + carry;
            t[2 * i] = sum as u64;
            carry = (sum >> 64) + (diag >> 64);

            let sum2 = (t[2 * i + 1] as u128) + carry;
            t[2 * i + 1] = sum2 as u64;
            carry = sum2 >> 64;
        }

        mersenne_reduce(t)
    }

    /// Repeated squaring: self^(2^n).
    pub fn square_times(&self, n: usize) -> Self {
        let mut r = *self;
        for _ in 0..n {
            r = r.sqr();
        }
        r
    }

    /// Field inversion: a^(p-2) mod p via addition chain.
    ///
    /// p-2 = 2^521 - 3 = (2^519 - 1) * 4 + 1
    ///
    /// Chain: x1→x2→x3→x4→x7→x8→x16→x32→x64→x128→x256→x512→x519
    /// Then: result = x519^4 * x1
    /// Total: ~524S + 13M
    pub fn inv(&self) -> Self {
        let x1 = *self;
        let x2 = x1.sqr().mul(&x1);
        let x3 = x2.sqr().mul(&x1);
        let x4 = x3.sqr().mul(&x1);
        let x7 = x4.square_times(3).mul(&x3);
        let x8 = x7.sqr().mul(&x1);
        let x16 = x8.square_times(8).mul(&x8);
        let x32 = x16.square_times(16).mul(&x16);
        let x64 = x32.square_times(32).mul(&x32);
        let x128 = x64.square_times(64).mul(&x64);
        let x256 = x128.square_times(128).mul(&x128);
        let x512 = x256.square_times(256).mul(&x256);
        let x519 = x512.square_times(7).mul(&x7);

        // p-2 = (2^519-1)*4 + 1  → x519^4 * x1
        x519.square_times(2).mul(&x1)
    }

    /// Check if this element is zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u64; NLIMBS]
    }

    /// Conditional subtraction: if self >= p, subtract p.
    fn reduce_once(self) -> Self {
        if cmp_u521(&self.0, &P) != Ordering::Less {
            let mut r = self.0;
            sub_borrow_u521(&mut r, &P);
            Self(r)
        } else {
            self
        }
    }
}

// ========================================================================
// Mersenne reduction
// ========================================================================

/// Reduce an 18-limb product modulo p = 2^521 - 1.
///
/// Split the 1042-bit product at bit 521:
/// - Low 521 bits: t[0..8] plus lower 9 bits of t[8]
/// - High bits: upper 55 bits of t[8] and t[9..17]
///
/// Since 2^521 ≡ 1 (mod p), we add high to low.
fn mersenne_reduce(t: [u64; 18]) -> P521FieldElement {
    // Extract high part (bits 521..1041), shifted down by 521 bits.
    // bit 521 is at t[8] bit 9, so high = t[8]>>9 | t[9]<<55 | ...
    let mut high = [0u64; NLIMBS];
    for i in 0..8 {
        high[i] = (t[i + 8] >> 9) | (t[i + 9] << 55);
    }
    high[8] = t[16] >> 9; // t[17] should be 0 for properly bounded inputs

    // Low part: t[0..8] plus lower 9 bits of t[8]
    let mut low = [0u64; NLIMBS];
    low[..8].copy_from_slice(&t[..8]);
    low[8] = t[8] & TOP_MASK;

    // Add high + low
    let mut r = [0u64; NLIMBS];
    let mut carry = 0u128;
    for i in 0..NLIMBS {
        let sum = (low[i] as u128) + (high[i] as u128) + carry;
        r[i] = sum as u64;
        carry = sum >> 64;
    }

    // Fold overflow (bits above 521 add back in)
    let top_overflow = r[8] >> 9;
    r[8] &= TOP_MASK;
    let c = top_overflow + (carry as u64);
    if c > 0 {
        let sum = (r[0] as u128) + (c as u128);
        r[0] = sum as u64;
        if (sum >> 64) != 0 {
            // Propagate carry (extremely rare)
            for limb in r.iter_mut().skip(1) {
                let s = (*limb as u128) + 1;
                *limb = s as u64;
                if (s >> 64) == 0 {
                    break;
                }
            }
            // One more fold
            let top2 = r[8] >> 9;
            r[8] &= TOP_MASK;
            if top2 != 0 {
                r[0] = r[0].wrapping_add(top2);
            }
        }
    }

    // Final conditional subtraction
    P521FieldElement(r).reduce_once()
}

// ========================================================================
// 521-bit arithmetic helpers
// ========================================================================

fn cmp_u521(a: &[u64; NLIMBS], b: &[u64; NLIMBS]) -> Ordering {
    let mut i = NLIMBS - 1;
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

fn sub_borrow_u521(a: &mut [u64; NLIMBS], b: &[u64; NLIMBS]) {
    let mut borrow = 0i128;
    for i in 0..NLIMBS {
        let diff = (a[i] as i128) - (b[i] as i128) + borrow;
        a[i] = diff as u64;
        borrow = diff >> 64;
    }
}

// ========================================================================
// BigNum conversions
// ========================================================================

impl P521FieldElement {
    /// Convert from a BigNum (assumed < p) to a field element.
    pub fn from_bignum(bn: &BigNum) -> Self {
        let limbs = bn.limbs();
        let mut arr = [0u64; NLIMBS];
        let len = limbs.len().min(NLIMBS);
        arr[..len].copy_from_slice(&limbs[..len]);
        Self(arr)
    }

    /// Convert back to a BigNum.
    pub fn to_bignum(self) -> BigNum {
        BigNum::from_limbs(self.0.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_and_one() {
        assert!(P521FieldElement::ZERO.is_zero());
        assert!(!P521FieldElement::ONE.is_zero());
    }

    #[test]
    fn test_from_to_bytes_roundtrip() {
        let mut bytes = [0u8; 66];
        bytes[65] = 42; // value = 42
        let fe = P521FieldElement::from_bytes(&bytes);
        assert_eq!(fe.0[0], 42);
        let out = fe.to_bytes();
        assert_eq!(out, bytes);
    }

    #[test]
    fn test_from_to_bytes_large() {
        // P-521 generator x-coordinate
        let gx_bytes: [u8; 66] = [
            0x00, 0xC6, 0x85, 0x8E, 0x06, 0xB7, 0x04, 0x04, 0xE9, 0xCD, 0x9E, 0x3E, 0xCB, 0x66,
            0x23, 0x95, 0xB4, 0x42, 0x9C, 0x64, 0x81, 0x39, 0x05, 0x3F, 0xB5, 0x21, 0xF8, 0x28,
            0xAF, 0x60, 0x6B, 0x4D, 0x3D, 0xBA, 0xA1, 0x4B, 0x5E, 0x77, 0xEF, 0xE7, 0x59, 0x28,
            0xFE, 0x1D, 0xC1, 0x27, 0xA2, 0xFF, 0xA8, 0xDE, 0x33, 0x48, 0xB3, 0xC1, 0x85, 0x6A,
            0x42, 0x9B, 0xF9, 0x7E, 0x7E, 0x31, 0xC2, 0xE5, 0xBD, 0x66,
        ];
        let fe = P521FieldElement::from_bytes(&gx_bytes);
        let out = fe.to_bytes();
        assert_eq!(out, gx_bytes);
    }

    #[test]
    fn test_add_zero() {
        let a = P521FieldElement::from_bytes(&{
            let mut b = [0u8; 66];
            b[65] = 42;
            b
        });
        let r = a.add(&P521FieldElement::ZERO);
        assert_eq!(r, a);
    }

    #[test]
    fn test_add_commutative() {
        let a = P521FieldElement::from_bytes(&{
            let mut b = [0u8; 66];
            b[65] = 7;
            b
        });
        let b = P521FieldElement::from_bytes(&{
            let mut b = [0u8; 66];
            b[65] = 11;
            b
        });
        assert_eq!(a.add(&b), b.add(&a));
    }

    #[test]
    fn test_sub_self_is_zero() {
        let a = P521FieldElement::from_bytes(&{
            let mut b = [0u8; 66];
            b[65] = 42;
            b
        });
        assert!(a.sub(&a).is_zero());
    }

    #[test]
    fn test_add_sub_inverse() {
        let a = P521FieldElement::from_bytes(&{
            let mut b = [0u8; 66];
            b[65] = 7;
            b
        });
        let b = P521FieldElement::from_bytes(&{
            let mut b = [0u8; 66];
            b[65] = 11;
            b
        });
        assert_eq!(a.add(&b).sub(&b), a);
    }

    #[test]
    fn test_mul_one() {
        let a = P521FieldElement::from_bytes(&{
            let mut b = [0u8; 66];
            b[65] = 42;
            b
        });
        assert_eq!(a.mul(&P521FieldElement::ONE), a);
    }

    #[test]
    fn test_mul_commutative() {
        let a = P521FieldElement::from_bytes(&{
            let mut b = [0u8; 66];
            b[65] = 7;
            b
        });
        let b = P521FieldElement::from_bytes(&{
            let mut b = [0u8; 66];
            b[65] = 11;
            b
        });
        assert_eq!(a.mul(&b), b.mul(&a));
    }

    #[test]
    fn test_mul_small_values() {
        let a = P521FieldElement::from_bytes(&{
            let mut b = [0u8; 66];
            b[65] = 7;
            b
        });
        let b = P521FieldElement::from_bytes(&{
            let mut b = [0u8; 66];
            b[65] = 11;
            b
        });
        let c = a.mul(&b);
        let expected = P521FieldElement::from_bytes(&{
            let mut b = [0u8; 66];
            b[65] = 77;
            b
        });
        assert_eq!(c, expected);
    }

    #[test]
    fn test_sqr_equals_mul() {
        let a = P521FieldElement::from_bytes(&{
            let mut b = [0u8; 66];
            b[65] = 42;
            b[63] = 0xDE;
            b[62] = 0xAD;
            b
        });
        assert_eq!(a.sqr(), a.mul(&a));
    }

    #[test]
    fn test_sqr_large_value() {
        // Use generator x-coordinate
        let gx_bytes: [u8; 66] = [
            0x00, 0xC6, 0x85, 0x8E, 0x06, 0xB7, 0x04, 0x04, 0xE9, 0xCD, 0x9E, 0x3E, 0xCB, 0x66,
            0x23, 0x95, 0xB4, 0x42, 0x9C, 0x64, 0x81, 0x39, 0x05, 0x3F, 0xB5, 0x21, 0xF8, 0x28,
            0xAF, 0x60, 0x6B, 0x4D, 0x3D, 0xBA, 0xA1, 0x4B, 0x5E, 0x77, 0xEF, 0xE7, 0x59, 0x28,
            0xFE, 0x1D, 0xC1, 0x27, 0xA2, 0xFF, 0xA8, 0xDE, 0x33, 0x48, 0xB3, 0xC1, 0x85, 0x6A,
            0x42, 0x9B, 0xF9, 0x7E, 0x7E, 0x31, 0xC2, 0xE5, 0xBD, 0x66,
        ];
        let gx = P521FieldElement::from_bytes(&gx_bytes);
        assert_eq!(gx.sqr(), gx.mul(&gx));
    }

    #[test]
    fn test_inv_correctness() {
        let a = P521FieldElement::from_bytes(&{
            let mut b = [0u8; 66];
            b[65] = 7;
            b
        });
        let a_inv = a.inv();
        let product = a.mul(&a_inv);
        assert_eq!(product, P521FieldElement::ONE);
    }

    #[test]
    fn test_inv_large_value() {
        let gx_bytes: [u8; 66] = [
            0x00, 0xC6, 0x85, 0x8E, 0x06, 0xB7, 0x04, 0x04, 0xE9, 0xCD, 0x9E, 0x3E, 0xCB, 0x66,
            0x23, 0x95, 0xB4, 0x42, 0x9C, 0x64, 0x81, 0x39, 0x05, 0x3F, 0xB5, 0x21, 0xF8, 0x28,
            0xAF, 0x60, 0x6B, 0x4D, 0x3D, 0xBA, 0xA1, 0x4B, 0x5E, 0x77, 0xEF, 0xE7, 0x59, 0x28,
            0xFE, 0x1D, 0xC1, 0x27, 0xA2, 0xFF, 0xA8, 0xDE, 0x33, 0x48, 0xB3, 0xC1, 0x85, 0x6A,
            0x42, 0x9B, 0xF9, 0x7E, 0x7E, 0x31, 0xC2, 0xE5, 0xBD, 0x66,
        ];
        let a = P521FieldElement::from_bytes(&gx_bytes);
        let a_inv = a.inv();
        let product = a.mul(&a_inv);
        assert_eq!(product, P521FieldElement::ONE);
    }

    #[test]
    fn test_neg_add_is_zero() {
        let a = P521FieldElement::from_bytes(&{
            let mut b = [0u8; 66];
            b[65] = 42;
            b
        });
        assert!(a.add(&a.neg()).is_zero());
    }

    #[test]
    fn test_neg_of_zero() {
        assert!(P521FieldElement::ZERO.neg().is_zero());
    }

    #[test]
    fn test_p_reduces_to_zero() {
        // P should reduce to zero
        let fe = P521FieldElement(P);
        let reduced = fe.reduce_once();
        assert!(reduced.is_zero());
    }

    #[test]
    fn test_square_times() {
        let a = P521FieldElement::from_bytes(&{
            let mut b = [0u8; 66];
            b[65] = 3;
            b
        });
        let manual = a.sqr().sqr().sqr();
        let fast = a.square_times(3);
        assert_eq!(manual, fast);
    }

    #[test]
    fn test_mul_distributive() {
        let a = P521FieldElement::from_bytes(&{
            let mut b = [0u8; 66];
            b[65] = 3;
            b
        });
        let b = P521FieldElement::from_bytes(&{
            let mut bytes = [0u8; 66];
            bytes[65] = 5;
            bytes
        });
        let c = P521FieldElement::from_bytes(&{
            let mut bytes = [0u8; 66];
            bytes[65] = 7;
            bytes
        });
        // a*(b+c) = a*b + a*c
        let lhs = a.mul(&b.add(&c));
        let rhs = a.mul(&b).add(&a.mul(&c));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_inv_matches_bignum() {
        let p_bn = BigNum::from_bytes_be(&{
            let mut bytes = [0xFFu8; 66];
            bytes[0] = 0x01;
            bytes[1] = 0xFF;
            bytes
        });
        let val = BigNum::from_u64(42);
        let inv_bn = val.mod_inv(&p_bn).unwrap();

        let val_fe = P521FieldElement::from_bytes(&{
            let mut b = [0u8; 66];
            b[65] = 42;
            b
        });
        let inv_fe = val_fe.inv();
        let inv_fe_bn = inv_fe.to_bignum();

        assert_eq!(inv_fe_bn, inv_bn);
    }

    #[test]
    fn test_bignum_roundtrip() {
        let bn = BigNum::from_u64(12345);
        let fe = P521FieldElement::from_bignum(&bn);
        let back = fe.to_bignum();
        assert_eq!(bn, back);
    }

    #[test]
    fn test_mul_near_p() {
        // p-1 * p-1 should work correctly
        let p_minus_1 = P521FieldElement({
            let mut limbs = P;
            limbs[0] -= 1; // p - 1
            limbs
        });
        let result = p_minus_1.mul(&p_minus_1);
        // (p-1)^2 mod p = (-1)^2 mod p = 1
        assert_eq!(result, P521FieldElement::ONE);
    }

    #[test]
    fn test_add_wrapping_near_p() {
        let p_minus_1 = P521FieldElement({
            let mut limbs = P;
            limbs[0] -= 1;
            limbs
        });
        let two = P521FieldElement::from_bytes(&{
            let mut b = [0u8; 66];
            b[65] = 2;
            b
        });
        // (p-1) + 2 = p + 1 ≡ 1 (mod p)
        let result = p_minus_1.add(&two);
        assert_eq!(result, P521FieldElement::ONE);
    }
}
