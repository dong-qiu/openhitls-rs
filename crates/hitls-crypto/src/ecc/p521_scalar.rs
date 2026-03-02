//! P-521 scalar field element arithmetic using 9×u64 Montgomery form.
//!
//! Provides fast modular arithmetic over the P-521 curve order `n` for ECDSA signing.
//! All elements are stored in Montgomery form: `a_mont = a * R mod n`, where `R = 2^576`.
//! (R = 2^576 since we use 9 limbs × 64 bits, even though n is only 521 bits.)

use core::cmp::Ordering;
use hitls_bignum::BigNum;

/// Number of limbs.
const NLIMBS: usize = 9;

/// The P-521 curve order n.
/// n = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA
///       51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
/// Stored as 9×u64 in little-endian limb order.
const N: [u64; NLIMBS] = [
    0xBB6F_B71E_9138_6409,
    0x3BB5_C9B8_899C_47AE,
    0x7FCC_0148_F709_A5D0,
    0x5186_8783_BF2F_966B,
    0xFFFF_FFFF_FFFF_FFFA,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0x0000_0000_0000_01FF,
];

/// Montgomery constant: N0 = -n[0]^(-1) mod 2^64.
/// Computed at compile time via Newton's method.
const N0: u64 = {
    let n0 = N[0];
    let mut x: u64 = 1;
    let mut i = 0u32;
    while i < 63 {
        x = x.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(x)));
        i += 1;
    }
    x.wrapping_neg()
};

// ========================================================================
// Const-eval helpers for computing R2 and ONE at compile time
// ========================================================================

/// Const comparison: a >= b.
const fn const_ge(a: &[u64; NLIMBS], b: &[u64; NLIMBS]) -> bool {
    let mut i: usize = NLIMBS - 1;
    loop {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    true // equal means >=
}

/// Const subtraction: a - b (assumes a >= b).
const fn const_sub(a: [u64; NLIMBS], b: &[u64; NLIMBS]) -> [u64; NLIMBS] {
    let mut r = [0u64; NLIMBS];
    let mut borrow: u64 = 0;
    let mut i = 0;
    while i < NLIMBS {
        let (d0, b0) = a[i].overflowing_sub(b[i]);
        let (d1, b1) = d0.overflowing_sub(borrow);
        r[i] = d1;
        borrow = (b0 as u64) + (b1 as u64);
        i += 1;
    }
    r
}

/// Compute R mod n = 2^576 mod n via 576 modular doublings of 1.
const ONE_LIMBS: [u64; NLIMBS] = {
    let mut val = [0u64; NLIMBS];
    val[0] = 1;
    let mut i = 0u32;
    while i < 576 {
        let top = val[NLIMBS - 1] >> 63;
        let mut j = NLIMBS - 1;
        while j > 0 {
            val[j] = (val[j] << 1) | (val[j - 1] >> 63);
            j -= 1;
        }
        val[0] <<= 1;
        if top != 0 || const_ge(&val, &N) {
            val = const_sub(val, &N);
        }
        i += 1;
    }
    val
};

/// R^2 mod n, where R = 2^576. Precomputed via 1152 modular doublings of 1.
const R2: [u64; NLIMBS] = {
    let mut val = [0u64; NLIMBS];
    val[0] = 1;
    let mut i = 0u32;
    while i < 1152 {
        let top = val[NLIMBS - 1] >> 63;
        let mut j = NLIMBS - 1;
        while j > 0 {
            val[j] = (val[j] << 1) | (val[j - 1] >> 63);
            j -= 1;
        }
        val[0] <<= 1;
        if top != 0 || const_ge(&val, &N) {
            val = const_sub(val, &N);
        }
        i += 1;
    }
    val
};

// ========================================================================
// P521ScalarElement
// ========================================================================

/// A P-521 scalar field element in Montgomery form (mod n).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct P521ScalarElement(pub [u64; NLIMBS]);

impl P521ScalarElement {
    /// The additive identity (zero).
    pub const ZERO: Self = Self([0; NLIMBS]);

    /// The multiplicative identity (one) in Montgomery form: R mod n.
    pub const ONE: Self = Self(ONE_LIMBS);

    /// Convert from a BigNum (assumed < n) to Montgomery form.
    pub fn from_bignum(bn: &BigNum) -> Self {
        let limbs = bn.limbs();
        let mut arr = [0u64; NLIMBS];
        let len = limbs.len().min(NLIMBS);
        arr[..len].copy_from_slice(&limbs[..len]);
        Self(arr).mont_mul(&Self(R2))
    }

    /// Convert from Montgomery form back to a BigNum.
    pub fn to_bignum(self) -> BigNum {
        let normal = self.mont_mul(&Self({
            let mut one = [0u64; NLIMBS];
            one[0] = 1;
            one
        }));
        BigNum::from_limbs(normal.0.to_vec())
    }

    /// Scalar field addition: (a + b) mod n.
    pub fn add(&self, other: &Self) -> Self {
        let (mut r, carry) = add_limbs(&self.0, &other.0);
        if carry != 0 || cmp_limbs(&r, &N) != Ordering::Less {
            sub_borrow_limbs(&mut r, &N);
        }
        Self(r)
    }

    /// Scalar field multiplication: (a * b) mod n in Montgomery form.
    pub fn mul(&self, other: &Self) -> Self {
        self.mont_mul(other)
    }

    /// Scalar field squaring: a² mod n in Montgomery form.
    pub fn sqr(&self) -> Self {
        self.mont_sqr()
    }

    /// Scalar field inversion via Fermat's little theorem: a^(n-2) mod n.
    ///
    /// n-2 in binary (bits 520..0):
    /// - bits 520..259: 262 ones
    /// - bit 258: 0
    /// - bit 257: 1
    /// - bit 256: 0
    /// - bits 255..0: lower 256 bits from limbs 3..0
    pub fn inv(&self) -> Self {
        // Build a^(2^k - 1) for various k using addition chains
        let x1 = *self;
        let x2 = x1.sqr().mul(&x1); // a^(2^2-1)

        let x4 = {
            let mut t = x2;
            for _ in 0..2 {
                t = t.sqr();
            }
            t.mul(&x2) // a^(2^4-1)
        };

        let x8 = {
            let mut t = x4;
            for _ in 0..4 {
                t = t.sqr();
            }
            t.mul(&x4) // a^(2^8-1)
        };

        let x16 = {
            let mut t = x8;
            for _ in 0..8 {
                t = t.sqr();
            }
            t.mul(&x8)
        };

        let x32 = {
            let mut t = x16;
            for _ in 0..16 {
                t = t.sqr();
            }
            t.mul(&x16)
        };

        let x64 = {
            let mut t = x32;
            for _ in 0..32 {
                t = t.sqr();
            }
            t.mul(&x32)
        };

        let x128 = {
            let mut t = x64;
            for _ in 0..64 {
                t = t.sqr();
            }
            t.mul(&x64) // a^(2^128-1)
        };

        // x130 = a^(2^130-1) = x128^(2^2) * x2
        let x130 = {
            let mut t = x128;
            for _ in 0..2 {
                t = t.sqr();
            }
            t.mul(&x2)
        };

        // x132 = a^(2^132-1) = x130^(2^2) * x2
        let x132 = {
            let mut t = x130;
            for _ in 0..2 {
                t = t.sqr();
            }
            t.mul(&x2)
        };

        // x262 = a^(2^262-1) = x132^(2^130) * x130
        let x262 = {
            let mut t = x132;
            for _ in 0..130 {
                t = t.sqr();
            }
            t.mul(&x130)
        };

        // Start with the 262 leading 1-bits of n-2
        let mut e = x262;

        // Build nibble table [a^0, a^1, ..., a^15]
        let mut table = [Self::ZERO; 16];
        table[0] = Self::ONE;
        table[1] = x1;
        let mut i = 2;
        while i < 16 {
            table[i] = table[i - 1].mul(&x1);
            i += 1;
        }

        // Process 3-bit window for bits 258,257,256 = 0,1,0 = value 2
        for _ in 0..3 {
            e = e.sqr();
        }
        e = e.mul(&table[2]);

        // Process 64 nibbles from MSB to LSB (bits 255..0)
        // Lower 256 bits of n-2 (limbs 3..0, big-endian nibbles):
        // 0x51868783BF2F966B 7FCC0148F709A5D0 3BB5C9B8899C47AE BB6FB71E91386407
        #[rustfmt::skip]
        const NIBBLES: [u8; 64] = [
            0x5, 0x1, 0x8, 0x6, 0x8, 0x7, 0x8, 0x3,
            0xB, 0xF, 0x2, 0xF, 0x9, 0x6, 0x6, 0xB,
            0x7, 0xF, 0xC, 0xC, 0x0, 0x1, 0x4, 0x8,
            0xF, 0x7, 0x0, 0x9, 0xA, 0x5, 0xD, 0x0,
            0x3, 0xB, 0xB, 0x5, 0xC, 0x9, 0xB, 0x8,
            0x8, 0x9, 0x9, 0xC, 0x4, 0x7, 0xA, 0xE,
            0xB, 0xB, 0x6, 0xF, 0xB, 0x7, 0x1, 0xE,
            0x9, 0x1, 0x3, 0x8, 0x6, 0x4, 0x0, 0x7,
        ];

        for &nib in &NIBBLES {
            for _ in 0..4 {
                e = e.sqr();
            }
            if nib != 0 {
                e = e.mul(&table[nib as usize]);
            }
        }

        e
    }

    /// Montgomery multiplication: (a * b * R^(-1)) mod n.
    fn mont_mul(&self, other: &Self) -> Self {
        let a = &self.0;
        let b = &other.0;

        let mut t = [0u64; 2 * NLIMBS];
        for i in 0..NLIMBS {
            let mut carry: u64 = 0;
            for j in 0..NLIMBS {
                let product =
                    (a[i] as u128) * (b[j] as u128) + (t[i + j] as u128) + (carry as u128);
                t[i + j] = product as u64;
                carry = (product >> 64) as u64;
            }
            t[i + NLIMBS] = carry;
        }

        scalar_mont_reduce(t)
    }

    /// Montgomery squaring using cross-product symmetry.
    fn mont_sqr(&self) -> Self {
        let a = &self.0;
        let mut t = [0u64; 2 * NLIMBS];

        // Cross-products (upper triangle)
        for i in 0..NLIMBS {
            let mut carry = 0u64;
            for j in (i + 1)..NLIMBS {
                let prod = (a[i] as u128) * (a[j] as u128) + (t[i + j] as u128) + (carry as u128);
                t[i + j] = prod as u64;
                carry = (prod >> 64) as u64;
            }
            t[i + NLIMBS] = carry;
        }

        // Double cross-products (left shift by 1)
        for i in (1..(2 * NLIMBS)).rev() {
            t[i] = (t[i] << 1) | (t[i - 1] >> 63);
        }
        t[0] = 0;

        // Add diagonal terms
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

        scalar_mont_reduce(t)
    }
}

/// Generic 9-limb Montgomery reduction for the P-521 order n.
fn scalar_mont_reduce(mut t: [u64; 2 * NLIMBS]) -> P521ScalarElement {
    let mut overflow: u64 = 0;

    for i in 0..NLIMBS {
        let m = t[i].wrapping_mul(N0);

        let mut carry: u64 = 0;
        for j in 0..NLIMBS {
            let product = (m as u128) * (N[j] as u128) + (t[i + j] as u128) + (carry as u128);
            t[i + j] = product as u64;
            carry = (product >> 64) as u64;
        }

        for item in &mut t[(i + NLIMBS)..(2 * NLIMBS)] {
            if carry == 0 {
                break;
            }
            let s = (*item as u128) + (carry as u128);
            *item = s as u64;
            carry = (s >> 64) as u64;
        }

        overflow += carry;
    }

    let mut r = [0u64; NLIMBS];
    r.copy_from_slice(&t[NLIMBS..2 * NLIMBS]);

    if overflow != 0 || cmp_limbs(&r, &N) != Ordering::Less {
        sub_borrow_limbs(&mut r, &N);
    }

    P521ScalarElement(r)
}

// ========================================================================
// Arithmetic helpers
// ========================================================================

fn add_limbs(a: &[u64; NLIMBS], b: &[u64; NLIMBS]) -> ([u64; NLIMBS], u64) {
    let mut r = [0u64; NLIMBS];
    let mut carry = 0u64;
    for i in 0..NLIMBS {
        let sum = (a[i] as u128) + (b[i] as u128) + (carry as u128);
        r[i] = sum as u64;
        carry = (sum >> 64) as u64;
    }
    (r, carry)
}

fn cmp_limbs(a: &[u64; NLIMBS], b: &[u64; NLIMBS]) -> Ordering {
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

fn sub_borrow_limbs(a: &mut [u64; NLIMBS], b: &[u64; NLIMBS]) {
    let mut borrow = 0i128;
    for i in 0..NLIMBS {
        let diff = (a[i] as i128) - (b[i] as i128) + borrow;
        a[i] = diff as u64;
        borrow = diff >> 64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_n0_correctness() {
        let product = N0.wrapping_mul(N[0]);
        assert_eq!(product, u64::MAX);
    }

    #[test]
    fn test_one_constant() {
        let one = P521ScalarElement::ONE;
        let normal = one.mont_mul(&P521ScalarElement({
            let mut arr = [0u64; NLIMBS];
            arr[0] = 1;
            arr
        }));
        assert_eq!(normal.0, {
            let mut arr = [0u64; NLIMBS];
            arr[0] = 1;
            arr
        });
    }

    #[test]
    fn test_from_to_bignum_roundtrip() {
        let bn = BigNum::from_u64(42);
        let se = P521ScalarElement::from_bignum(&bn);
        let back = se.to_bignum();
        assert_eq!(bn, back);
    }

    #[test]
    fn test_mul_identity() {
        let a = P521ScalarElement::from_bignum(&BigNum::from_u64(12345));
        assert_eq!(a.mul(&P521ScalarElement::ONE), a);
    }

    #[test]
    fn test_mul_small_values() {
        let a = P521ScalarElement::from_bignum(&BigNum::from_u64(7));
        let b = P521ScalarElement::from_bignum(&BigNum::from_u64(11));
        let c = a.mul(&b);
        let expected = P521ScalarElement::from_bignum(&BigNum::from_u64(77));
        assert_eq!(c, expected);
    }

    #[test]
    fn test_add_small_values() {
        let a = P521ScalarElement::from_bignum(&BigNum::from_u64(3));
        let b = P521ScalarElement::from_bignum(&BigNum::from_u64(5));
        let c = a.add(&b);
        let expected = P521ScalarElement::from_bignum(&BigNum::from_u64(8));
        assert_eq!(c, expected);
    }

    #[test]
    fn test_sqr_equals_mul() {
        let a = P521ScalarElement::from_bignum(&BigNum::from_u64(12345));
        assert_eq!(a.sqr(), a.mul(&a));
    }

    #[test]
    fn test_inv_correctness() {
        let a = P521ScalarElement::from_bignum(&BigNum::from_u64(7));
        let a_inv = a.inv();
        let product = a.mul(&a_inv);
        assert_eq!(product, P521ScalarElement::ONE);
    }

    #[test]
    fn test_inv_larger_value() {
        let bytes = hitls_utils::hex::hex(
            "DEADBEEFCAFEBABE0123456789ABCDEF00112233445566778899AABBCCDDEEFF\
             0011223344556677DEADBEEFCAFEBABE0123456789ABCDEF0011223344556677",
        );
        let bn = BigNum::from_bytes_be(&bytes);
        let n_bn = BigNum::from_bytes_be(&hitls_utils::hex::hex(
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA\
             51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
        ));
        let bn_reduced = bn.mod_reduce(&n_bn).unwrap();
        let a = P521ScalarElement::from_bignum(&bn_reduced);
        let a_inv = a.inv();
        let product = a.mul(&a_inv);
        assert_eq!(product, P521ScalarElement::ONE);
    }

    #[test]
    fn test_inv_matches_bignum() {
        let n_bn = BigNum::from_bytes_be(&hitls_utils::hex::hex(
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA\
             51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
        ));
        let k = BigNum::from_u64(42);
        let k_inv_bignum = k.mod_inv(&n_bn).unwrap();

        let k_se = P521ScalarElement::from_bignum(&k);
        let k_inv_se = k_se.inv().to_bignum();

        assert_eq!(k_inv_se, k_inv_bignum);
    }
}
