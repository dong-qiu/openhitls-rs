//! P-256 scalar field element arithmetic using 4×u64 Montgomery form.
//!
//! Provides fast modular arithmetic over the P-256 curve order `n` for ECDSA signing.
//! All elements are stored in Montgomery form: `a_mont = a * R mod n`, where `R = 2^256`.

use core::cmp::Ordering;
use hitls_bignum::BigNum;

/// The P-256 curve order n.
/// n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
/// Stored as 4×u64 in little-endian limb order.
const N: [u64; 4] = [
    0xF3B9_CAC2_FC63_2551,
    0xBCE6_FAAD_A717_9E84,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_0000_0000,
];

/// Montgomery constant: N0 = -n[0]^(-1) mod 2^64.
/// Computed at compile time via Newton's method.
const N0: u64 = {
    let n0: u64 = 0xF3B9_CAC2_FC63_2551;
    let mut x: u64 = 1;
    let mut i = 0u32;
    while i < 63 {
        x = x.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(x)));
        i += 1;
    }
    // Now n0 * x ≡ 1 (mod 2^64). We want -(n0^(-1)) = -x.
    x.wrapping_neg()
};

// ========================================================================
// Const-eval helpers for computing R2 and ONE at compile time
// ========================================================================

/// Const comparison: a >= b.
const fn const_ge(a: &[u64; 4], b: &[u64; 4]) -> bool {
    let mut i: usize = 3;
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
const fn const_sub(a: [u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut borrow: u64 = 0;

    let (d0, b0) = a[0].overflowing_sub(b[0]);
    let (d0, b1) = d0.overflowing_sub(borrow);
    r[0] = d0;
    borrow = (b0 as u64) + (b1 as u64);

    let (d1, b0) = a[1].overflowing_sub(b[1]);
    let (d1, b1) = d1.overflowing_sub(borrow);
    r[1] = d1;
    borrow = (b0 as u64) + (b1 as u64);

    let (d2, b0) = a[2].overflowing_sub(b[2]);
    let (d2, b1) = d2.overflowing_sub(borrow);
    r[2] = d2;
    borrow = (b0 as u64) + (b1 as u64);

    let (d3, _b0) = a[3].overflowing_sub(b[3]);
    let (d3, _b1) = d3.overflowing_sub(borrow);
    r[3] = d3;

    r
}

/// Compute R mod n = 2^256 mod n via 256 modular doublings of 1.
const ONE_LIMBS: [u64; 4] = {
    let mut val = [0u64; 4];
    val[0] = 1;
    let mut i = 0u32;
    while i < 256 {
        let top = val[3] >> 63;
        val[3] = (val[3] << 1) | (val[2] >> 63);
        val[2] = (val[2] << 1) | (val[1] >> 63);
        val[1] = (val[1] << 1) | (val[0] >> 63);
        val[0] = val[0] << 1;
        if top != 0 || const_ge(&val, &N) {
            val = const_sub(val, &N);
        }
        i += 1;
    }
    val
};

/// R^2 mod n, where R = 2^256. Precomputed via 512 modular doublings of 1.
const R2: [u64; 4] = {
    let mut val = [0u64; 4];
    val[0] = 1;
    let mut i = 0u32;
    while i < 512 {
        let top = val[3] >> 63;
        val[3] = (val[3] << 1) | (val[2] >> 63);
        val[2] = (val[2] << 1) | (val[1] >> 63);
        val[1] = (val[1] << 1) | (val[0] >> 63);
        val[0] = val[0] << 1;
        if top != 0 || const_ge(&val, &N) {
            val = const_sub(val, &N);
        }
        i += 1;
    }
    val
};

// ========================================================================
// P256ScalarElement
// ========================================================================

/// A P-256 scalar field element in Montgomery form (mod n).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct P256ScalarElement(pub [u64; 4]);

impl P256ScalarElement {
    /// The additive identity (zero).
    pub const ZERO: Self = Self([0, 0, 0, 0]);

    /// The multiplicative identity (one) in Montgomery form: R mod n.
    pub const ONE: Self = Self(ONE_LIMBS);

    /// Convert from a BigNum (assumed < n) to Montgomery form.
    pub fn from_bignum(bn: &BigNum) -> Self {
        let limbs = bn.limbs();
        let mut arr = [0u64; 4];
        let len = limbs.len().min(4);
        arr[..len].copy_from_slice(&limbs[..len]);
        Self(arr).mont_mul(&Self(R2))
    }

    /// Convert from Montgomery form back to a BigNum.
    pub fn to_bignum(self) -> BigNum {
        let normal = self.mont_mul(&Self([1, 0, 0, 0]));
        BigNum::from_limbs(normal.0.to_vec())
    }

    /// Scalar field addition: (a + b) mod n.
    pub fn add(&self, other: &Self) -> Self {
        let (mut r, carry) = add_u256(&self.0, &other.0);
        if carry != 0 || cmp_u256(&r, &N) != Ordering::Less {
            sub_borrow_u256(&mut r, &N);
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

        // n-2 = FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF_BCE6FAAD_A7179E84_F3B9CAC2_FC63254F
        //
        // Bits 255-224: 32 ones
        let mut e = x32;

        // Bits 223-192: 32 zeros
        for _ in 0..32 {
            e = e.sqr();
        }

        // Bits 191-128: 64 ones
        for _ in 0..64 {
            e = e.sqr();
        }
        e = e.mul(&x64);

        // Bits 127-0: BCE6FAAD_A7179E84_F3B9CAC2_FC63254F
        // Process as 32 nibbles (4 bits each) from MSB to LSB.
        let mut table = [Self::ZERO; 16];
        table[0] = Self::ONE;
        table[1] = x1;
        let mut i = 2;
        while i < 16 {
            table[i] = table[i - 1].mul(&x1);
            i += 1;
        }

        const NIBBLES: [u8; 32] = [
            0xB, 0xC, 0xE, 0x6, 0xF, 0xA, 0xA, 0xD, 0xA, 0x7, 0x1, 0x7, 0x9, 0xE, 0x8, 0x4, 0xF,
            0x3, 0xB, 0x9, 0xC, 0xA, 0xC, 0x2, 0xF, 0xC, 0x6, 0x3, 0x2, 0x5, 0x4, 0xF,
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

        let mut t = [0u64; 8];
        for i in 0..4 {
            let mut carry: u64 = 0;
            for j in 0..4 {
                let product =
                    (a[i] as u128) * (b[j] as u128) + (t[i + j] as u128) + (carry as u128);
                t[i + j] = product as u64;
                carry = (product >> 64) as u64;
            }
            t[i + 4] = carry;
        }

        scalar_mont_reduce(t)
    }

    /// Montgomery squaring using cross-product symmetry (10 vs 16 multiplies).
    fn mont_sqr(&self) -> Self {
        let a = &self.0;
        let mut t = [0u64; 8];

        // Cross products (upper triangle): 6 multiplies
        let p = (a[0] as u128) * (a[1] as u128);
        t[1] = p as u64;
        let mut carry = (p >> 64) as u64;

        let p = (a[0] as u128) * (a[2] as u128) + (carry as u128);
        t[2] = p as u64;
        carry = (p >> 64) as u64;

        let p = (a[0] as u128) * (a[3] as u128) + (carry as u128);
        t[3] = p as u64;
        carry = (p >> 64) as u64;
        t[4] = carry;

        let p = (a[1] as u128) * (a[2] as u128) + (t[3] as u128);
        t[3] = p as u64;
        carry = (p >> 64) as u64;

        let p = (a[1] as u128) * (a[3] as u128) + (t[4] as u128) + (carry as u128);
        t[4] = p as u64;
        carry = (p >> 64) as u64;
        t[5] = carry;

        let p = (a[2] as u128) * (a[3] as u128) + (t[5] as u128);
        t[5] = p as u64;
        t[6] = (p >> 64) as u64;

        // Double cross products
        t[7] = t[6] >> 63;
        t[6] = (t[6] << 1) | (t[5] >> 63);
        t[5] = (t[5] << 1) | (t[4] >> 63);
        t[4] = (t[4] << 1) | (t[3] >> 63);
        t[3] = (t[3] << 1) | (t[2] >> 63);
        t[2] = (t[2] << 1) | (t[1] >> 63);
        t[1] <<= 1;

        // Diagonal terms: 4 multiplies
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

        t[7] = ((t[7] as u128) + c) as u64;

        scalar_mont_reduce(t)
    }
}

/// Generic 4-limb Montgomery reduction for the P-256 order n.
fn scalar_mont_reduce(mut t: [u64; 8]) -> P256ScalarElement {
    let mut overflow: u64 = 0;

    for i in 0..4 {
        let m = t[i].wrapping_mul(N0);

        let mut carry: u64 = 0;
        for j in 0..4 {
            let product = (m as u128) * (N[j] as u128) + (t[i + j] as u128) + (carry as u128);
            t[i + j] = product as u64;
            carry = (product >> 64) as u64;
        }

        for item in &mut t[(i + 4)..8] {
            if carry == 0 {
                break;
            }
            let s = (*item as u128) + (carry as u128);
            *item = s as u64;
            carry = (s >> 64) as u64;
        }

        overflow += carry;
    }

    let mut r = [t[4], t[5], t[6], t[7]];

    if overflow != 0 || cmp_u256(&r, &N) != Ordering::Less {
        sub_borrow_u256(&mut r, &N);
    }

    P256ScalarElement(r)
}

// ========================================================================
// 256-bit arithmetic helpers
// ========================================================================

fn add_u256(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut r = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let sum = (a[i] as u128) + (b[i] as u128) + (carry as u128);
        r[i] = sum as u64;
        carry = (sum >> 64) as u64;
    }
    (r, carry)
}

fn cmp_u256(a: &[u64; 4], b: &[u64; 4]) -> Ordering {
    let mut i = 3;
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

fn sub_borrow_u256(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut borrow = 0i128;
    for i in 0..4 {
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
        let one = P256ScalarElement::ONE;
        let normal = one.mont_mul(&P256ScalarElement([1, 0, 0, 0]));
        assert_eq!(normal.0, [1, 0, 0, 0]);
    }

    #[test]
    fn test_from_to_bignum_roundtrip() {
        let bn = BigNum::from_u64(42);
        let se = P256ScalarElement::from_bignum(&bn);
        let back = se.to_bignum();
        assert_eq!(bn, back);
    }

    #[test]
    fn test_mul_identity() {
        let a = P256ScalarElement::from_bignum(&BigNum::from_u64(12345));
        assert_eq!(a.mul(&P256ScalarElement::ONE), a);
    }

    #[test]
    fn test_mul_small_values() {
        let a = P256ScalarElement::from_bignum(&BigNum::from_u64(7));
        let b = P256ScalarElement::from_bignum(&BigNum::from_u64(11));
        let c = a.mul(&b);
        let expected = P256ScalarElement::from_bignum(&BigNum::from_u64(77));
        assert_eq!(c, expected);
    }

    #[test]
    fn test_add_small_values() {
        let a = P256ScalarElement::from_bignum(&BigNum::from_u64(3));
        let b = P256ScalarElement::from_bignum(&BigNum::from_u64(5));
        let c = a.add(&b);
        let expected = P256ScalarElement::from_bignum(&BigNum::from_u64(8));
        assert_eq!(c, expected);
    }

    #[test]
    fn test_sqr_equals_mul() {
        let a = P256ScalarElement::from_bignum(&BigNum::from_u64(12345));
        assert_eq!(a.sqr(), a.mul(&a));
    }

    #[test]
    fn test_inv_correctness() {
        let a = P256ScalarElement::from_bignum(&BigNum::from_u64(7));
        let a_inv = a.inv();
        let product = a.mul(&a_inv);
        assert_eq!(product, P256ScalarElement::ONE);
    }

    #[test]
    fn test_inv_larger_value() {
        let bytes = hitls_utils::hex::hex(
            "DEADBEEFCAFEBABE0123456789ABCDEF00112233445566778899AABBCCDDEEFF",
        );
        let bn = BigNum::from_bytes_be(&bytes);
        let n_bn = BigNum::from_bytes_be(&hitls_utils::hex::hex(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        ));
        let bn_reduced = bn.mod_reduce(&n_bn).unwrap();
        let a = P256ScalarElement::from_bignum(&bn_reduced);
        let a_inv = a.inv();
        let product = a.mul(&a_inv);
        assert_eq!(product, P256ScalarElement::ONE);
    }

    #[test]
    fn test_inv_matches_bignum() {
        let n_bn = BigNum::from_bytes_be(&hitls_utils::hex::hex(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        ));
        let k = BigNum::from_u64(42);
        let k_inv_bignum = k.mod_inv(&n_bn).unwrap();

        let k_se = P256ScalarElement::from_bignum(&k);
        let k_inv_se = k_se.inv().to_bignum();

        assert_eq!(k_inv_se, k_inv_bignum);
    }
}
