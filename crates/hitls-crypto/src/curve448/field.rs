//! Field arithmetic over GF(2^448 − 2^224 − 1) using 8×56-bit limb representation.
//!
//! The prime p = 2^448 − 2^224 − 1 is the "Goldilocks" prime, which allows
//! efficient reduction via the identity 2^448 ≡ 2^224 + 1 (mod p).
//!
//! Uses Karatsuba multiplication with 4-limb (224-bit) splits, exploiting the
//! Goldilocks structure for 48 u128 multiplies per field mul (vs 256 u32 muls
//! in the old 16×28-bit representation).

/// A field element in GF(p) where p = 2^448 − 2^224 − 1.
///
/// Stored in radix-2^56 representation: value = Σ l[i] × 2^(56i), i=0..7.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Fe448(pub(crate) [u64; 8]);

const MASK56: u64 = (1u64 << 56) - 1;

impl Fe448 {
    /// The zero element.
    pub fn zero() -> Self {
        Fe448([0; 8])
    }

    /// The one element.
    pub fn one() -> Self {
        let mut r = [0u64; 8];
        r[0] = 1;
        Fe448(r)
    }

    /// Addition: h = f + g.
    pub fn add(&self, rhs: &Fe448) -> Fe448 {
        let mut r = [0u64; 8];
        for (i, ri) in r.iter_mut().enumerate() {
            *ri = self.0[i] + rhs.0[i];
        }
        Fe448(r).carry()
    }

    /// Subtraction: h = f - g.
    /// Add 2*p to avoid underflow before carry propagation.
    pub fn sub(&self, rhs: &Fe448) -> Fe448 {
        // p = 2^448 - 2^224 - 1 = (2^448 - 1) - 2^224
        // In radix 2^56: p[0..3] = MASK56, p[4] = MASK56-1, p[5..7] = MASK56
        // 2p[i]: doubled values
        let two_p: [u64; 8] = [
            2 * MASK56,
            2 * MASK56,
            2 * MASK56,
            2 * MASK56,
            2 * (MASK56 - 1),
            2 * MASK56,
            2 * MASK56,
            2 * MASK56,
        ];

        let mut r = [0u128; 8];
        for i in 0..8 {
            r[i] = (self.0[i] as u128 + two_p[i] as u128) - rhs.0[i] as u128;
        }

        // Carry propagate with Goldilocks folding
        let mut out = [0u64; 8];
        let mut carry = 0i128;
        for i in 0..8 {
            let val = r[i] as i128 + carry;
            out[i] = (val as u64) & MASK56;
            carry = val >> 56;
        }
        // Wrap carry: 2^448 ≡ 2^224 + 1
        // carry goes to limb 0 and limb 4 independently
        let val = out[0] as i128 + carry;
        out[0] = (val as u64) & MASK56;
        let c_lo = val >> 56;
        if c_lo != 0 {
            out[1] = ((out[1] as i128) + c_lo) as u64;
        }

        let val = out[4] as i128 + carry;
        out[4] = (val as u64) & MASK56;
        let c_hi = val >> 56;
        if c_hi != 0 {
            out[5] = ((out[5] as i128) + c_hi) as u64;
        }

        Fe448(out)
    }

    /// Subtraction without full carry: add 2p bias only.
    /// Safe only when result feeds directly into mul/square (bounded output).
    pub fn sub_fast(&self, rhs: &Fe448) -> Fe448 {
        let two_p: [u64; 8] = [
            2 * MASK56,
            2 * MASK56,
            2 * MASK56,
            2 * MASK56,
            2 * (MASK56 - 1),
            2 * MASK56,
            2 * MASK56,
            2 * MASK56,
        ];
        let mut r = [0u64; 8];
        for i in 0..8 {
            r[i] = self.0[i] + two_p[i] - rhs.0[i];
        }
        Fe448(r)
    }

    /// Negation: h = -f (mod p).
    pub fn neg(&self) -> Fe448 {
        Fe448::zero().sub(self)
    }

    /// Multiplication: h = f * g.
    ///
    /// Uses Karatsuba with 4-limb (224-bit) splits and Goldilocks reduction.
    /// Total: 48 u128 multiplies.
    pub fn mul(&self, rhs: &Fe448) -> Fe448 {
        let a = &self.0;
        let b = &rhs.0;

        // Karatsuba: split at 4 limbs (224 bits)
        let p0 = mul_4x4([a[0], a[1], a[2], a[3]], [b[0], b[1], b[2], b[3]]);
        let p2 = mul_4x4([a[4], a[5], a[6], a[7]], [b[4], b[5], b[6], b[7]]);

        let mid_a = [a[0] + a[4], a[1] + a[5], a[2] + a[6], a[3] + a[7]];
        let mid_b = [b[0] + b[4], b[1] + b[5], b[2] + b[6], b[3] + b[7]];
        let p1 = mul_4x4(mid_a, mid_b);

        let mut cross = [0i128; 7];
        for i in 0..7 {
            cross[i] = p1[i] - p0[i] - p2[i];
        }

        goldilocks_reduce(&p0, &cross, &p2)
    }

    /// Squaring: h = f^2.
    ///
    /// Uses Karatsuba with cross-product symmetry: 30 u128 multiplies.
    pub fn square(&self) -> Fe448 {
        let a = &self.0;

        let p0 = sqr_4x4([a[0], a[1], a[2], a[3]]);
        let p2 = sqr_4x4([a[4], a[5], a[6], a[7]]);

        let mid = [a[0] + a[4], a[1] + a[5], a[2] + a[6], a[3] + a[7]];
        let p1 = sqr_4x4(mid);

        let mut cross = [0i128; 7];
        for i in 0..7 {
            cross[i] = p1[i] - p0[i] - p2[i];
        }

        goldilocks_reduce(&p0, &cross, &p2)
    }

    /// Multiply by a small constant: h = f * c.
    pub fn mul_small(&self, c: u32) -> Fe448 {
        let mut acc = [0u128; 8];
        for (i, a) in acc.iter_mut().enumerate() {
            *a = self.0[i] as u128 * c as u128;
        }
        // Carry propagate
        let mut r = [0u64; 8];
        let mut carry = 0u128;
        for i in 0..8 {
            let val = acc[i] + carry;
            r[i] = (val as u64) & MASK56;
            carry = val >> 56;
        }
        // Top carry folds: 2^448 ≡ 2^224 + 1
        r[0] += carry as u64;
        r[4] += carry as u64;
        // One more carry pass
        for i in 0..7 {
            let c = r[i] >> 56;
            r[i] &= MASK56;
            r[i + 1] += c;
            if c == 0 {
                break;
            }
        }
        Fe448(r)
    }

    /// Carry propagation for u64 limbs.
    fn carry(&self) -> Fe448 {
        let mut r = self.0;

        // Linear carry propagation
        for i in 0..7 {
            let c = r[i] >> 56;
            r[i] &= MASK56;
            r[i + 1] += c;
        }
        let c = r[7] >> 56;
        r[7] &= MASK56;

        // Goldilocks fold: 2^448 ≡ 2^224 + 1
        r[0] += c;
        r[4] += c;

        // One more carry if needed
        for i in 0..7 {
            let c = r[i] >> 56;
            r[i] &= MASK56;
            r[i + 1] += c;
            if c == 0 {
                break;
            }
        }

        Fe448(r)
    }

    /// Full reduction modulo p = 2^448 − 2^224 − 1.
    /// Ensures the result is in [0, p).
    pub fn reduce(&self) -> Fe448 {
        let mut r = self.carry().0;

        // Subtracting p is equivalent to adding (1 + 2^224) and checking overflow.
        let mut test = r;
        test[0] = test[0].wrapping_add(1);
        test[4] = test[4].wrapping_add(1);

        // Propagate carries
        for i in 0..7 {
            test[i + 1] += test[i] >> 56;
            test[i] &= MASK56;
        }
        let overflow = test[7] >> 56;
        test[7] &= MASK56;

        // If overflow > 0, r >= p. Use test (which is r - p).
        if overflow > 0 {
            r = test;
        }

        Fe448(r)
    }

    /// Repeated squaring helper: compute self^(2^n).
    pub fn square_times(&self, n: usize) -> Fe448 {
        let mut t = *self;
        for _ in 0..n {
            t = t.square();
        }
        t
    }

    /// Modular inversion: h = f^(p−2) mod p using Fermat's little theorem.
    pub fn invert(&self) -> Fe448 {
        self.pow_p_minus_2()
    }

    /// Compute self^(p-2) for inversion using compact addition chain.
    fn pow_p_minus_2(&self) -> Fe448 {
        // p - 2 = 2^448 - 2^224 - 3
        let a = *self;
        let a3 = a.square().mul(&a);
        let a7 = a3.square().mul(&a);
        let a_6 = a7.square_times(3).mul(&a7);
        let a_12 = a_6.square_times(6).mul(&a_6);
        let a_24 = a_12.square_times(12).mul(&a_12);
        let a_48 = a_24.square_times(24).mul(&a_24);
        let a_96 = a_48.square_times(48).mul(&a_48);
        let a_192 = a_96.square_times(96).mul(&a_96);
        let a_222 = a_192.square_times(24).mul(&a_24).square_times(6).mul(&a_6);
        let a_223 = a_222.square().mul(&a);
        let t = a_223.square_times(225);
        let tail = a_222.square_times(2).mul(&a);
        t.mul(&tail)
    }

    /// Compute sqrt(self) = self^((p+1)/4) mod p.
    /// Since p ≡ 3 (mod 4), this works directly.
    pub fn sqrt(&self) -> Fe448 {
        // (p+1)/4 = (2^448 - 2^224) / 4 = 2^446 - 2^222 = (2^224 - 1) * 2^222
        let a = *self;
        let a3 = a.square().mul(&a);
        let a7 = a3.square().mul(&a);
        let a_6 = a7.square_times(3).mul(&a7);
        let a_12 = a_6.square_times(6).mul(&a_6);
        let a_24 = a_12.square_times(12).mul(&a_12);
        let a_48 = a_24.square_times(24).mul(&a_24);
        let a_96 = a_48.square_times(48).mul(&a_48);
        let a_192 = a_96.square_times(96).mul(&a_96);
        let a_222 = a_192.square_times(24).mul(&a_24).square_times(6).mul(&a_6);
        let a_224 = a_222.square_times(2).mul(&a3);
        a_224.square_times(222)
    }

    /// Decode a 56-byte little-endian representation into a field element.
    pub fn from_bytes(bytes: &[u8; 56]) -> Fe448 {
        let mut r = [0u64; 8];
        // 7 bytes per limb (56 bits = 7 bytes exactly), 8 limbs = 56 bytes
        for (i, ri) in r.iter_mut().enumerate() {
            let base = i * 7;
            let mut buf = [0u8; 8];
            buf[..7].copy_from_slice(&bytes[base..base + 7]);
            *ri = u64::from_le_bytes(buf) & MASK56;
        }
        Fe448(r)
    }

    /// Encode a field element to a 56-byte little-endian representation.
    pub fn to_bytes(self) -> [u8; 56] {
        let h = self.reduce().0;
        let mut out = [0u8; 56];
        for (i, &limb) in h.iter().enumerate() {
            let base = i * 7;
            let bytes = limb.to_le_bytes();
            out[base..base + 7].copy_from_slice(&bytes[..7]);
        }
        out
    }

    /// Constant-time conditional swap: swap self and other if swap == 1.
    pub fn conditional_swap(&mut self, other: &mut Fe448, swap: u8) {
        let mask = (-(swap as i64)) as u64;
        for i in 0..8 {
            let t = mask & (self.0[i] ^ other.0[i]);
            self.0[i] ^= t;
            other.0[i] ^= t;
        }
    }

    /// Returns 1 if the field element is negative (LSB of canonical encoding is 1).
    pub fn is_negative(&self) -> u8 {
        let bytes = self.to_bytes();
        bytes[0] & 1
    }

    /// Check if the element is zero.
    pub fn is_zero(&self) -> bool {
        let r = self.reduce();
        r.0.iter().all(|&x| x == 0)
    }
}

/// Schoolbook 4×4 multiplication: 16 u128 multiplies → 7 output limbs.
#[inline]
fn mul_4x4(a: [u64; 4], b: [u64; 4]) -> [i128; 7] {
    let mut r = [0i128; 7];
    for i in 0..4 {
        for j in 0..4 {
            r[i + j] += a[i] as i128 * b[j] as i128;
        }
    }
    r
}

/// Schoolbook 4×4 squaring with cross-product symmetry: 10 u128 multiplies → 7 limbs.
#[inline]
fn sqr_4x4(a: [u64; 4]) -> [i128; 7] {
    let mut r = [0i128; 7];
    // Diagonal terms
    for i in 0..4 {
        r[2 * i] += a[i] as i128 * a[i] as i128;
    }
    // Doubled cross terms
    for i in 0..4 {
        for j in (i + 1)..4 {
            r[i + j] += 2 * (a[i] as i128 * a[j] as i128);
        }
    }
    r
}

/// Goldilocks reduction: combine p0 (pos 0..6), cross (pos 4..10), p2 (pos 8..14)
/// into 8 limbs using 2^448 ≡ 2^224 + 1.
///
/// Fold schedule (position j ≥ 8 maps to (j-4) + (j-8)):
///   pos 8..11 → simple fold to (j-4) + (j-8)
///   pos 12..14 → double cascade: 2×(j-8) + (j-12)
#[inline]
fn goldilocks_reduce(p0: &[i128; 7], cross: &[i128; 7], p2: &[i128; 7]) -> Fe448 {
    let mut acc = [0i128; 8];

    // p0 at positions 0..6
    for i in 0..7 {
        acc[i] += p0[i];
    }

    // cross at positions 4..10, with Goldilocks fold for 8..10
    for i in 0..4 {
        acc[i + 4] += cross[i];
    }
    for i in 4..7 {
        acc[i - 4] += cross[i]; // fold pos (i+4) → pos (i-4)
        acc[i] += cross[i]; // fold pos (i+4) → pos i
    }

    // p2 at positions 8..14, with cascaded fold for 12..14
    for i in 0..4 {
        acc[i] += p2[i]; // fold pos (i+8) → pos i
        acc[i + 4] += p2[i]; // fold pos (i+8) → pos (i+4)
    }
    for i in 4..7 {
        acc[i - 4] += p2[i]; // cascade: pos(i+8)→pos(i+4)→pos(i-4) (×1)
        acc[i] += 2 * p2[i]; // cascade: pos(i+8)→pos i (×1) + pos(i+4)→pos i (×1) = ×2
    }

    carry_wide_signed(&acc)
}

/// Carry propagation for signed i128 accumulators with Goldilocks folding.
#[inline]
fn carry_wide_signed(acc: &[i128; 8]) -> Fe448 {
    let mut c = *acc;

    // First pass: carry propagation
    for i in 0..7 {
        let carry = c[i] >> 56;
        c[i] -= carry << 56;
        c[i + 1] += carry;
    }
    let carry = c[7] >> 56;
    c[7] -= carry << 56;

    // Goldilocks fold of top carry
    c[0] += carry;
    c[4] += carry;

    // Second pass to normalize
    for i in 0..7 {
        let carry = c[i] >> 56;
        c[i] -= carry << 56;
        c[i + 1] += carry;
    }
    let carry = c[7] >> 56;
    c[7] -= carry << 56;
    c[0] += carry;
    c[4] += carry;

    Fe448([
        c[0] as u64,
        c[1] as u64,
        c[2] as u64,
        c[3] as u64,
        c[4] as u64,
        c[5] as u64,
        c[6] as u64,
        c[7] as u64,
    ])
}

impl PartialEq for Fe448 {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.to_bytes().ct_eq(&other.to_bytes()).into()
    }
}

impl Eq for Fe448 {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_one() {
        let z = Fe448::zero();
        let o = Fe448::one();
        assert!(z.is_zero());
        assert!(!o.is_zero());
    }

    #[test]
    fn test_add_sub_roundtrip() {
        let a = Fe448::from_bytes(&[0x42; 56]);
        let b = Fe448::from_bytes(&[0x37; 56]);
        let c = a.add(&b);
        let d = c.sub(&b);
        assert_eq!(a.to_bytes(), d.to_bytes());
    }

    #[test]
    fn test_mul_one_identity() {
        let a = Fe448::from_bytes(&[0xAB; 56]);
        let one = Fe448::one();
        let b = a.mul(&one);
        assert_eq!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn test_mul_square_consistency() {
        let a = Fe448::from_bytes(&[0x12; 56]);
        let sq = a.square();
        let mul_self = a.mul(&a);
        assert_eq!(sq.to_bytes(), mul_self.to_bytes());
    }

    #[test]
    fn test_invert() {
        let mut bytes = [0u8; 56];
        bytes[0] = 42;
        let a = Fe448::from_bytes(&bytes);
        let a_inv = a.invert();
        let product = a.mul(&a_inv);
        assert_eq!(product.to_bytes(), Fe448::one().to_bytes());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut bytes = [0u8; 56];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let a = Fe448::from_bytes(&bytes);
        let encoded = a.to_bytes();
        let b = Fe448::from_bytes(&encoded);
        assert_eq!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn test_conditional_swap() {
        let mut a = Fe448::one();
        let mut bytes2 = [0u8; 56];
        bytes2[0] = 2;
        let mut b = Fe448::from_bytes(&bytes2);

        // swap = 0: no swap
        a.conditional_swap(&mut b, 0);
        assert_eq!(a.to_bytes()[0], 1);
        assert_eq!(b.to_bytes()[0], 2);

        // swap = 1: swap
        a.conditional_swap(&mut b, 1);
        assert_eq!(a.to_bytes()[0], 2);
        assert_eq!(b.to_bytes()[0], 1);
    }

    #[test]
    fn test_goldilocks_reduction() {
        // Test that p ≡ 0: construct p and verify it reduces to 0.
        // p = 2^448 - 2^224 - 1
        // In 8×u64: p[0] = MASK56-1, p[1..3] = MASK56, p[4] = MASK56-1, p[5..7] = MASK56
        let mut p_limbs = [MASK56; 8];
        p_limbs[4] = MASK56 - 1;
        let p_val = Fe448(p_limbs);
        assert!(p_val.reduce().is_zero());
    }

    #[test]
    fn test_neg_roundtrip() {
        let mut bytes = [0u8; 56];
        bytes[0] = 42;
        bytes[7] = 0xFF;
        let a = Fe448::from_bytes(&bytes);
        let neg_a = a.neg();
        // a + (-a) should be zero
        let sum = a.add(&neg_a);
        assert!(sum.is_zero());
    }

    #[test]
    fn test_neg_zero() {
        let z = Fe448::zero();
        let neg_z = z.neg();
        assert!(neg_z.is_zero());
    }

    #[test]
    fn test_mul_small() {
        let a = Fe448::from_bytes(&[0x03; 56]);
        // a * 2 should equal a + a
        let doubled = a.mul_small(2);
        let added = a.add(&a);
        assert_eq!(doubled.to_bytes(), added.to_bytes());
    }

    #[test]
    fn test_mul_small_zero() {
        let a = Fe448::from_bytes(&[0xAB; 56]);
        let zero = a.mul_small(0);
        assert!(zero.is_zero());
    }

    #[test]
    fn test_mul_small_one() {
        let a = Fe448::from_bytes(&[0x42; 56]);
        let same = a.mul_small(1);
        assert_eq!(a.to_bytes(), same.to_bytes());
    }

    #[test]
    fn test_sqrt_of_square() {
        // sqrt(a^2) should be either a or -a
        let mut bytes = [0u8; 56];
        bytes[0] = 9; // small value for cleaner test
        let a = Fe448::from_bytes(&bytes);
        let a_sq = a.square();
        let root = a_sq.sqrt();
        let root_sq = root.square();
        // root^2 should equal a^2
        assert_eq!(root_sq.to_bytes(), a_sq.to_bytes());
    }

    #[test]
    fn test_distributive_law() {
        // a * (b + c) == a*b + a*c
        let a = Fe448::from_bytes(&[0x11; 56]);
        let b = Fe448::from_bytes(&[0x22; 56]);
        let c = Fe448::from_bytes(&[0x33; 56]);

        let lhs = a.mul(&b.add(&c));
        let rhs = a.mul(&b).add(&a.mul(&c));
        assert_eq!(lhs.to_bytes(), rhs.to_bytes());
    }

    #[test]
    fn test_mul_commutativity() {
        let a = Fe448::from_bytes(&[0xAB; 56]);
        let b = Fe448::from_bytes(&[0xCD; 56]);
        assert_eq!(a.mul(&b).to_bytes(), b.mul(&a).to_bytes());
    }

    #[test]
    fn test_is_negative() {
        // is_negative checks bit 0 of canonical encoding
        let one = Fe448::one();
        assert_eq!(one.is_negative(), 1); // 1 is odd

        let two = Fe448::one().add(&Fe448::one());
        assert_eq!(two.is_negative(), 0); // 2 is even
    }

    #[test]
    fn test_partial_eq_same_value() {
        let a = Fe448::from_bytes(&[0x42; 56]);
        let b = Fe448::from_bytes(&[0x42; 56]);
        assert_eq!(a, b);
    }

    #[test]
    fn test_partial_eq_different_values() {
        let a = Fe448::from_bytes(&[0x42; 56]);
        let b = Fe448::from_bytes(&[0x43; 56]);
        assert_ne!(a, b);
    }

    #[test]
    fn test_sub_self_is_zero() {
        let a = Fe448::from_bytes(&[0xFF; 56]);
        let diff = a.sub(&a);
        assert!(diff.is_zero());
    }

    #[test]
    fn test_invert_one() {
        // 1^(-1) = 1
        let one = Fe448::one();
        let inv = one.invert();
        assert_eq!(inv.to_bytes(), one.to_bytes());
    }

    #[test]
    fn test_sub_fast_consistency() {
        // sub_fast should produce same result as sub (modulo carry)
        let a = Fe448::from_bytes(&[0x42; 56]);
        let b = Fe448::from_bytes(&[0x37; 56]);
        let slow = a.sub(&b);
        let fast = a.sub_fast(&b);
        // The results should be equal after reduction
        assert_eq!(slow.to_bytes(), fast.reduce().to_bytes());
    }
}
