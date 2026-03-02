//! P-384 scalar field element arithmetic using 6×u64 Montgomery form.
//!
//! Provides fast modular arithmetic over the P-384 curve order `n` for ECDSA signing.
//! All elements are stored in Montgomery form: `a_mont = a * R mod n`, where `R = 2^384`.

use core::cmp::Ordering;
use hitls_bignum::BigNum;

/// The P-384 curve order n.
/// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF
///       581A0DB248B0A77AECEC196ACCC52973
/// Stored as 6×u64 in little-endian limb order.
const N: [u64; 6] = [
    0xECEC_196A_CCC5_2973,
    0x581A_0DB2_48B0_A77A,
    0xC763_4D81_F437_2DDF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
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
const fn const_ge(a: &[u64; 6], b: &[u64; 6]) -> bool {
    let mut i: usize = 5;
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

/// Const subtraction: a - b (assumes a >= b or handles wrapping).
const fn const_sub(a: [u64; 6], b: &[u64; 6]) -> [u64; 6] {
    let mut r = [0u64; 6];
    let mut borrow: u64 = 0;
    let mut i = 0;
    while i < 6 {
        let (d0, b0) = a[i].overflowing_sub(b[i]);
        let (d1, b1) = d0.overflowing_sub(borrow);
        r[i] = d1;
        borrow = (b0 as u64) + (b1 as u64);
        i += 1;
    }
    r
}

/// Compute R mod n = 2^384 mod n via 384 modular doublings of 1.
const ONE_LIMBS: [u64; 6] = {
    let mut val = [0u64; 6];
    val[0] = 1;
    let mut i = 0u32;
    while i < 384 {
        let top = val[5] >> 63;
        val[5] = (val[5] << 1) | (val[4] >> 63);
        val[4] = (val[4] << 1) | (val[3] >> 63);
        val[3] = (val[3] << 1) | (val[2] >> 63);
        val[2] = (val[2] << 1) | (val[1] >> 63);
        val[1] = (val[1] << 1) | (val[0] >> 63);
        val[0] <<= 1;
        if top != 0 || const_ge(&val, &N) {
            val = const_sub(val, &N);
        }
        i += 1;
    }
    val
};

/// R^2 mod n, where R = 2^384. Precomputed via 768 modular doublings of 1.
const R2: [u64; 6] = {
    let mut val = [0u64; 6];
    val[0] = 1;
    let mut i = 0u32;
    while i < 768 {
        let top = val[5] >> 63;
        val[5] = (val[5] << 1) | (val[4] >> 63);
        val[4] = (val[4] << 1) | (val[3] >> 63);
        val[3] = (val[3] << 1) | (val[2] >> 63);
        val[2] = (val[2] << 1) | (val[1] >> 63);
        val[1] = (val[1] << 1) | (val[0] >> 63);
        val[0] <<= 1;
        if top != 0 || const_ge(&val, &N) {
            val = const_sub(val, &N);
        }
        i += 1;
    }
    val
};

// ========================================================================
// P384ScalarElement
// ========================================================================

/// A P-384 scalar field element in Montgomery form (mod n).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct P384ScalarElement(pub [u64; 6]);

impl P384ScalarElement {
    /// The additive identity (zero).
    pub const ZERO: Self = Self([0, 0, 0, 0, 0, 0]);

    /// The multiplicative identity (one) in Montgomery form: R mod n.
    pub const ONE: Self = Self(ONE_LIMBS);

    /// Convert from a BigNum (assumed < n) to Montgomery form.
    pub fn from_bignum(bn: &BigNum) -> Self {
        let limbs = bn.limbs();
        let mut arr = [0u64; 6];
        let len = limbs.len().min(6);
        arr[..len].copy_from_slice(&limbs[..len]);
        Self(arr).mont_mul(&Self(R2))
    }

    /// Convert from Montgomery form back to a BigNum.
    pub fn to_bignum(self) -> BigNum {
        let normal = self.mont_mul(&Self([1, 0, 0, 0, 0, 0]));
        BigNum::from_limbs(normal.0.to_vec())
    }

    /// Scalar field addition: (a + b) mod n.
    pub fn add(&self, other: &Self) -> Self {
        let (mut r, carry) = add_u384(&self.0, &other.0);
        if carry != 0 || cmp_u384(&r, &N) != Ordering::Less {
            sub_borrow_u384(&mut r, &N);
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
    pub fn inv(&self) -> Self {
        // Precompute x_k = a^(2^k - 1)
        let x1 = *self;
        let x2 = x1.sqr().mul(&x1);

        let x4 = {
            let mut t = x2;
            for _ in 0..2 {
                t = t.sqr();
            }
            t.mul(&x2)
        };

        let x8 = {
            let mut t = x4;
            for _ in 0..4 {
                t = t.sqr();
            }
            t.mul(&x4)
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

        let x96 = {
            let mut t = x64;
            for _ in 0..32 {
                t = t.sqr();
            }
            t.mul(&x32)
        };

        let x192 = {
            let mut t = x96;
            for _ in 0..96 {
                t = t.sqr();
            }
            t.mul(&x96)
        };

        // n-2 top 192 bits are all 1s
        let mut e = x192;

        // Lower 192 bits of n-2:
        // C7634D81 F4372DDF 581A0DB2 48B0A77A ECEC196A CCC52971
        // Process as 48 nibbles from MSB to LSB using a 4-bit window.
        let mut table = [Self::ZERO; 16];
        table[0] = Self::ONE;
        table[1] = x1;
        let mut i = 2;
        while i < 16 {
            table[i] = table[i - 1].mul(&x1);
            i += 1;
        }

        const NIBBLES: [u8; 48] = [
            0xC, 0x7, 0x6, 0x3, 0x4, 0xD, 0x8, 0x1, 0xF, 0x4, 0x3, 0x7, 0x2, 0xD, 0xD, 0xF, 0x5,
            0x8, 0x1, 0xA, 0x0, 0xD, 0xB, 0x2, 0x4, 0x8, 0xB, 0x0, 0xA, 0x7, 0x7, 0xA, 0xE, 0xC,
            0xE, 0xC, 0x1, 0x9, 0x6, 0xA, 0xC, 0xC, 0xC, 0x5, 0x2, 0x9, 0x7, 0x1,
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

        let mut t = [0u64; 12];
        for i in 0..6 {
            let mut carry: u64 = 0;
            for j in 0..6 {
                let product =
                    (a[i] as u128) * (b[j] as u128) + (t[i + j] as u128) + (carry as u128);
                t[i + j] = product as u64;
                carry = (product >> 64) as u64;
            }
            t[i + 6] = carry;
        }

        scalar_mont_reduce(t)
    }

    /// Montgomery squaring using cross-product symmetry (21 vs 36 multiplies).
    fn mont_sqr(&self) -> Self {
        let a = &self.0;
        let mut t = [0u64; 12];

        // Upper triangle cross products (i < j)
        let mut carry: u64;

        // Row 0: a[0] * a[1..6]
        let p = (a[0] as u128) * (a[1] as u128);
        t[1] = p as u64;
        carry = (p >> 64) as u64;

        let p = (a[0] as u128) * (a[2] as u128) + (carry as u128);
        t[2] = p as u64;
        carry = (p >> 64) as u64;

        let p = (a[0] as u128) * (a[3] as u128) + (carry as u128);
        t[3] = p as u64;
        carry = (p >> 64) as u64;

        let p = (a[0] as u128) * (a[4] as u128) + (carry as u128);
        t[4] = p as u64;
        carry = (p >> 64) as u64;

        let p = (a[0] as u128) * (a[5] as u128) + (carry as u128);
        t[5] = p as u64;
        t[6] = (p >> 64) as u64;

        // Row 1: a[1] * a[2..6]
        let p = (a[1] as u128) * (a[2] as u128) + (t[3] as u128);
        t[3] = p as u64;
        carry = (p >> 64) as u64;

        let p = (a[1] as u128) * (a[3] as u128) + (t[4] as u128) + (carry as u128);
        t[4] = p as u64;
        carry = (p >> 64) as u64;

        let p = (a[1] as u128) * (a[4] as u128) + (t[5] as u128) + (carry as u128);
        t[5] = p as u64;
        carry = (p >> 64) as u64;

        let p = (a[1] as u128) * (a[5] as u128) + (t[6] as u128) + (carry as u128);
        t[6] = p as u64;
        t[7] = (p >> 64) as u64;

        // Row 2: a[2] * a[3..6]
        let p = (a[2] as u128) * (a[3] as u128) + (t[5] as u128);
        t[5] = p as u64;
        carry = (p >> 64) as u64;

        let p = (a[2] as u128) * (a[4] as u128) + (t[6] as u128) + (carry as u128);
        t[6] = p as u64;
        carry = (p >> 64) as u64;

        let p = (a[2] as u128) * (a[5] as u128) + (t[7] as u128) + (carry as u128);
        t[7] = p as u64;
        t[8] = (p >> 64) as u64;

        // Row 3: a[3] * a[4..6]
        let p = (a[3] as u128) * (a[4] as u128) + (t[7] as u128);
        t[7] = p as u64;
        carry = (p >> 64) as u64;

        let p = (a[3] as u128) * (a[5] as u128) + (t[8] as u128) + (carry as u128);
        t[8] = p as u64;
        t[9] = (p >> 64) as u64;

        // Row 4: a[4] * a[5]
        let p = (a[4] as u128) * (a[5] as u128) + (t[9] as u128);
        t[9] = p as u64;
        t[10] = (p >> 64) as u64;

        // Double cross products
        t[11] = t[10] >> 63;
        t[10] = (t[10] << 1) | (t[9] >> 63);
        t[9] = (t[9] << 1) | (t[8] >> 63);
        t[8] = (t[8] << 1) | (t[7] >> 63);
        t[7] = (t[7] << 1) | (t[6] >> 63);
        t[6] = (t[6] << 1) | (t[5] >> 63);
        t[5] = (t[5] << 1) | (t[4] >> 63);
        t[4] = (t[4] << 1) | (t[3] >> 63);
        t[3] = (t[3] << 1) | (t[2] >> 63);
        t[2] = (t[2] << 1) | (t[1] >> 63);
        t[1] <<= 1;

        // Diagonal terms
        let d = (a[0] as u128) * (a[0] as u128);
        t[0] = d as u64;
        let mut c = d >> 64;

        let s = (t[1] as u128) + c;
        t[1] = s as u64;
        c = s >> 64;

        let d = (a[1] as u128) * (a[1] as u128) + (t[2] as u128) + c;
        t[2] = d as u64;
        c = d >> 64;

        let s = (t[3] as u128) + c;
        t[3] = s as u64;
        c = s >> 64;

        let d = (a[2] as u128) * (a[2] as u128) + (t[4] as u128) + c;
        t[4] = d as u64;
        c = d >> 64;

        let s = (t[5] as u128) + c;
        t[5] = s as u64;
        c = s >> 64;

        let d = (a[3] as u128) * (a[3] as u128) + (t[6] as u128) + c;
        t[6] = d as u64;
        c = d >> 64;

        let s = (t[7] as u128) + c;
        t[7] = s as u64;
        c = s >> 64;

        let d = (a[4] as u128) * (a[4] as u128) + (t[8] as u128) + c;
        t[8] = d as u64;
        c = d >> 64;

        let s = (t[9] as u128) + c;
        t[9] = s as u64;
        c = s >> 64;

        let d = (a[5] as u128) * (a[5] as u128) + (t[10] as u128) + c;
        t[10] = d as u64;
        c = d >> 64;

        t[11] = ((t[11] as u128) + c) as u64;

        scalar_mont_reduce(t)
    }
}

/// Generic 6-limb Montgomery reduction for the P-384 order n.
fn scalar_mont_reduce(mut t: [u64; 12]) -> P384ScalarElement {
    let mut overflow: u64 = 0;

    for i in 0..6 {
        let m = t[i].wrapping_mul(N0);

        let mut carry: u64 = 0;
        for j in 0..6 {
            let product = (m as u128) * (N[j] as u128) + (t[i + j] as u128) + (carry as u128);
            t[i + j] = product as u64;
            carry = (product >> 64) as u64;
        }

        for item in &mut t[(i + 6)..12] {
            if carry == 0 {
                break;
            }
            let s = (*item as u128) + (carry as u128);
            *item = s as u64;
            carry = (s >> 64) as u64;
        }

        overflow += carry;
    }

    let mut r = [t[6], t[7], t[8], t[9], t[10], t[11]];

    if overflow != 0 || cmp_u384(&r, &N) != Ordering::Less {
        sub_borrow_u384(&mut r, &N);
    }

    P384ScalarElement(r)
}

// ========================================================================
// 384-bit arithmetic helpers
// ========================================================================

fn add_u384(a: &[u64; 6], b: &[u64; 6]) -> ([u64; 6], u64) {
    let mut r = [0u64; 6];
    let mut carry = 0u64;
    for i in 0..6 {
        let sum = (a[i] as u128) + (b[i] as u128) + (carry as u128);
        r[i] = sum as u64;
        carry = (sum >> 64) as u64;
    }
    (r, carry)
}

fn cmp_u384(a: &[u64; 6], b: &[u64; 6]) -> Ordering {
    let mut i = 5;
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

fn sub_borrow_u384(a: &mut [u64; 6], b: &[u64; 6]) {
    let mut borrow = 0i128;
    for i in 0..6 {
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
        let one = P384ScalarElement::ONE;
        let normal = one.mont_mul(&P384ScalarElement([1, 0, 0, 0, 0, 0]));
        assert_eq!(normal.0, [1, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_from_to_bignum_roundtrip() {
        let bn = BigNum::from_u64(42);
        let se = P384ScalarElement::from_bignum(&bn);
        let back = se.to_bignum();
        assert_eq!(bn, back);
    }

    #[test]
    fn test_mul_identity() {
        let a = P384ScalarElement::from_bignum(&BigNum::from_u64(12345));
        assert_eq!(a.mul(&P384ScalarElement::ONE), a);
    }

    #[test]
    fn test_mul_small_values() {
        let a = P384ScalarElement::from_bignum(&BigNum::from_u64(7));
        let b = P384ScalarElement::from_bignum(&BigNum::from_u64(11));
        let c = a.mul(&b);
        let expected = P384ScalarElement::from_bignum(&BigNum::from_u64(77));
        assert_eq!(c, expected);
    }

    #[test]
    fn test_add_small_values() {
        let a = P384ScalarElement::from_bignum(&BigNum::from_u64(3));
        let b = P384ScalarElement::from_bignum(&BigNum::from_u64(5));
        let c = a.add(&b);
        let expected = P384ScalarElement::from_bignum(&BigNum::from_u64(8));
        assert_eq!(c, expected);
    }

    #[test]
    fn test_sqr_equals_mul() {
        let a = P384ScalarElement::from_bignum(&BigNum::from_u64(12345));
        assert_eq!(a.sqr(), a.mul(&a));
    }

    #[test]
    fn test_inv_correctness() {
        let a = P384ScalarElement::from_bignum(&BigNum::from_u64(7));
        let a_inv = a.inv();
        let product = a.mul(&a_inv);
        assert_eq!(product, P384ScalarElement::ONE);
    }

    #[test]
    fn test_inv_larger_value() {
        let bytes = hitls_utils::hex::hex(
            "DEADBEEFCAFEBABE0123456789ABCDEF00112233445566778899AABBCCDDEEFF\
             0011223344556677",
        );
        let bn = BigNum::from_bytes_be(&bytes);
        let n_bn = BigNum::from_bytes_be(&hitls_utils::hex::hex(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF\
             581A0DB248B0A77AECEC196ACCC52973",
        ));
        let bn_reduced = bn.mod_reduce(&n_bn).unwrap();
        let a = P384ScalarElement::from_bignum(&bn_reduced);
        let a_inv = a.inv();
        let product = a.mul(&a_inv);
        assert_eq!(product, P384ScalarElement::ONE);
    }

    #[test]
    fn test_inv_matches_bignum() {
        let n_bn = BigNum::from_bytes_be(&hitls_utils::hex::hex(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF\
             581A0DB248B0A77AECEC196ACCC52973",
        ));
        let k = BigNum::from_u64(42);
        let k_inv_bignum = k.mod_inv(&n_bn).unwrap();

        let k_se = P384ScalarElement::from_bignum(&k);
        let k_inv_se = k_se.inv().to_bignum();

        assert_eq!(k_inv_se, k_inv_bignum);
    }
}
