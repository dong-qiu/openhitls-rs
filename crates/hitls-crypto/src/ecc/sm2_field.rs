//! SM2 specialized field element arithmetic using 4×u64 Montgomery form.
//!
//! All elements are stored in Montgomery form: `a_mont = a * R mod p`, where `R = 2^256`.
//! This allows fast modular multiplication via Montgomery reduction.
//!
//! The SM2 prime is `p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF`.

use core::cmp::Ordering;

/// The SM2 prime p = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF.
/// Stored as 4×u64 in little-endian limb order.
const P: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_0000_0000,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFE_FFFF_FFFF,
];

/// R^2 mod p, where R = 2^256 (precomputed for Montgomery conversion).
const R2: [u64; 4] = [
    0x0000_0002_0000_0003,
    0x0000_0002_FFFF_FFFF,
    0x0000_0001_0000_0001,
    0x0000_0004_0000_0002,
];

/// Montgomery constant: N0 = -p^(-1) mod 2^64.
///
/// Since p[0] = 0xFFFF_FFFF_FFFF_FFFF = -1 mod 2^64,
/// p^(-1) mod 2^64 = -1 mod 2^64, so N0 = 1.
const _N0: u64 = 1;

/// An SM2 field element in Montgomery form.
///
/// Internal representation: 4 × u64 limbs in little-endian order, where
/// the stored value `v` represents the field element `v * R^(-1) mod p`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Sm2FieldElement(pub [u64; 4]);

impl Sm2FieldElement {
    /// The additive identity (zero).
    pub const ZERO: Self = Self([0, 0, 0, 0]);

    /// The multiplicative identity (one) in Montgomery form: R mod p.
    pub const ONE: Self = Self([
        0x0000_0000_0000_0001,
        0x0000_0000_FFFF_FFFF,
        0x0000_0000_0000_0000,
        0x0000_0001_0000_0000,
    ]);

    /// Convert from 32-byte big-endian representation to Montgomery form.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        limbs[3] = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        limbs[2] = u64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        limbs[1] = u64::from_be_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        limbs[0] = u64::from_be_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]);
        // Convert to Montgomery form: multiply by R^2 and reduce
        Self(limbs).mont_mul(&Self(R2))
    }

    /// Convert from Montgomery form to 32-byte big-endian representation.
    pub fn to_bytes(self) -> [u8; 32] {
        // Montgomery reduction: multiply by 1 to convert out of Montgomery form
        let normal = self.mont_mul(&Self([1, 0, 0, 0]));
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&normal.0[3].to_be_bytes());
        out[8..16].copy_from_slice(&normal.0[2].to_be_bytes());
        out[16..24].copy_from_slice(&normal.0[1].to_be_bytes());
        out[24..32].copy_from_slice(&normal.0[0].to_be_bytes());
        out
    }

    /// Field addition: (a + b) mod p.
    pub fn add(&self, other: &Self) -> Self {
        let (mut r, carry) = add_u256(&self.0, &other.0);
        if carry != 0 || cmp_u256(&r, &P) != Ordering::Less {
            sub_borrow_u256(&mut r, &P);
        }
        Self(r)
    }

    /// Field subtraction: (a - b) mod p.
    pub fn sub(&self, other: &Self) -> Self {
        let (mut r, borrow) = sub_u256(&self.0, &other.0);
        if borrow != 0 {
            add_carry_u256(&mut r, &P);
        }
        Self(r)
    }

    /// Field negation: (-a) mod p.
    pub fn neg(&self) -> Self {
        if self.is_zero() {
            return *self;
        }
        let (r, _) = sub_u256(&P, &self.0);
        Self(r)
    }

    /// Check if zero.
    pub fn is_zero(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    /// Field multiplication: (a * b) mod p in Montgomery form.
    pub fn mul(&self, other: &Self) -> Self {
        self.mont_mul(other)
    }

    /// Field squaring: a^2 mod p in Montgomery form.
    ///
    /// Uses dedicated squaring exploiting a[i]*a[j] = a[j]*a[i] symmetry:
    /// 10 u64×u64 multiplies (6 cross + 4 diagonal) vs 16 for schoolbook.
    pub fn sqr(&self) -> Self {
        self.mont_sqr()
    }

    /// Field inversion using Fermat's little theorem: a^(-1) = a^(p-2) mod p.
    ///
    /// SM2 p-2 = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFD
    /// Binary (MSB): [31 ones][0][128 ones][32 zeros][30 ones][0][1]
    /// Total: 281 sqr + 17 mul.
    pub fn inv(&self) -> Self {
        let x1 = *self;
        let x2 = x1.sqr().mul(&x1);
        let x3 = x2.sqr().mul(&x1);
        let x4 = {
            let mut t = x2;
            for _ in 0..2 {
                t = t.sqr();
            }
            t.mul(&x2)
        };
        let x6 = {
            let mut t = x3;
            for _ in 0..3 {
                t = t.sqr();
            }
            t.mul(&x3)
        };
        let x8 = {
            let mut t = x4;
            for _ in 0..4 {
                t = t.sqr();
            }
            t.mul(&x4)
        };
        let x14 = {
            let mut t = x8;
            for _ in 0..6 {
                t = t.sqr();
            }
            t.mul(&x6)
        };
        let x16 = {
            let mut t = x8;
            for _ in 0..8 {
                t = t.sqr();
            }
            t.mul(&x8)
        };
        let x30 = {
            let mut t = x16;
            for _ in 0..14 {
                t = t.sqr();
            }
            t.mul(&x14)
        };
        let x31 = x30.sqr().mul(&x1);
        let x32 = {
            let mut t = x16;
            for _ in 0..16 {
                t = t.sqr();
            }
            t.mul(&x16)
        };

        // Build p-2:
        // Bits 255..225: 31 ones
        let mut e = x31;

        // Bit 224: 0
        e = e.sqr();

        // Bits 223..192: 32 ones (first block of 128 ones)
        for _ in 0..32 {
            e = e.sqr();
        }
        e = e.mul(&x32);

        // Bits 191..160: 32 ones
        for _ in 0..32 {
            e = e.sqr();
        }
        e = e.mul(&x32);

        // Bits 159..128: 32 ones
        for _ in 0..32 {
            e = e.sqr();
        }
        e = e.mul(&x32);

        // Bits 127..96: 32 ones
        for _ in 0..32 {
            e = e.sqr();
        }
        e = e.mul(&x32);

        // Bits 95..64: 32 zeros
        for _ in 0..32 {
            e = e.sqr();
        }

        // Bits 63..32: 32 ones
        for _ in 0..32 {
            e = e.sqr();
        }
        e = e.mul(&x32);

        // Bits 31..2: 30 ones
        for _ in 0..30 {
            e = e.sqr();
        }
        e = e.mul(&x30);

        // Bit 1: 0
        e = e.sqr();

        // Bit 0: 1
        e = e.sqr();
        e = e.mul(&x1);

        e
    }

    /// Montgomery multiplication: computes (a * b * R^(-1)) mod p.
    ///
    /// Uses schoolbook 4-limb multiplication (16 u64×u64 multiplies) followed
    /// by SM2 specialized Montgomery reduction exploiting P[0]=-1.
    fn mont_mul(&self, other: &Self) -> Self {
        let a = &self.0;
        let b = &other.0;

        // Compute 512-bit product: t = a * b (8 limbs)
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

        sm2_mont_reduce(t)
    }

    /// Montgomery squaring exploiting a[i]*a[j] = a[j]*a[i] symmetry.
    ///
    /// Computes upper triangle cross products (6 multiplies), doubles them,
    /// then adds diagonal terms (4 multiplies). Total: 10 vs 16 for schoolbook.
    fn mont_sqr(&self) -> Self {
        let a = &self.0;
        let mut t = [0u64; 8];

        // Upper triangle cross products (i < j), accumulated row by row.
        let mut carry: u64;
        let p = (a[0] as u128) * (a[1] as u128);
        t[1] = p as u64;
        carry = (p >> 64) as u64;

        let p = (a[0] as u128) * (a[2] as u128) + (carry as u128);
        t[2] = p as u64;
        carry = (p >> 64) as u64;

        let p = (a[0] as u128) * (a[3] as u128) + (carry as u128);
        t[3] = p as u64;
        carry = (p >> 64) as u64;
        t[4] = carry;

        // Row 1: a[1] * a[2..4]
        let p = (a[1] as u128) * (a[2] as u128) + (t[3] as u128);
        t[3] = p as u64;
        carry = (p >> 64) as u64;

        let p = (a[1] as u128) * (a[3] as u128) + (t[4] as u128) + (carry as u128);
        t[4] = p as u64;
        carry = (p >> 64) as u64;
        t[5] = carry;

        // Row 2: a[2] * a[3]
        let p = (a[2] as u128) * (a[3] as u128) + (t[5] as u128);
        t[5] = p as u64;
        t[6] = (p >> 64) as u64;

        // Double the cross products (left shift by 1 across all 8 limbs).
        t[7] = t[6] >> 63;
        t[6] = (t[6] << 1) | (t[5] >> 63);
        t[5] = (t[5] << 1) | (t[4] >> 63);
        t[4] = (t[4] << 1) | (t[3] >> 63);
        t[3] = (t[3] << 1) | (t[2] >> 63);
        t[2] = (t[2] << 1) | (t[1] >> 63);
        t[1] <<= 1;

        // Add diagonal terms a[i]^2 at positions (2*i, 2*i+1).
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

        sm2_mont_reduce(t)
    }
}

// ========================================================================
// SM2 specialized Montgomery reduction
// ========================================================================

/// SM2 specialized Montgomery reduction.
///
/// Exploits the structure of the SM2 prime for faster reduction:
/// - P[0] = 0xFFFF_FFFF_FFFF_FFFF: `m * P[0] + t[i] = m * 2^64` (no multiply needed)
///
/// Cost: 3 muls per iteration × 4 = 12 muls total (vs 16 for generic).
fn sm2_mont_reduce(mut t: [u64; 8]) -> Sm2FieldElement {
    let mut overflow: u64 = 0;

    for i in 0..4 {
        let m = t[i]; // N0 = 1, so m = t[i]

        // j=0: P[0] = 0xFFFF_FFFF_FFFF_FFFF
        // m * P[0] + t[i] = m * (2^64 - 1) + m = m * 2^64
        // Low 64 bits = 0 (eliminates t[i]), carry = m.
        let mut carry: u64 = m;

        // j=1: P[1] = 0xFFFF_FFFF_0000_0000 (1 multiply)
        let p =
            (m as u128) * (0xFFFF_FFFF_0000_0000u64 as u128) + (t[i + 1] as u128) + (carry as u128);
        t[i + 1] = p as u64;
        carry = (p >> 64) as u64;

        // j=2: P[2] = 0xFFFF_FFFF_FFFF_FFFF (1 multiply)
        // m * P[2] + t[i+2] + carry fits in u128: max = (2^64-1)^2 + 2*(2^64-1) = 2^128-1.
        let p =
            (m as u128) * (0xFFFF_FFFF_FFFF_FFFFu64 as u128) + (t[i + 2] as u128) + (carry as u128);
        t[i + 2] = p as u64;
        carry = (p >> 64) as u64;

        // j=3: P[3] = 0xFFFF_FFFE_FFFF_FFFF (1 multiply)
        let p =
            (m as u128) * (0xFFFF_FFFE_FFFF_FFFFu64 as u128) + (t[i + 3] as u128) + (carry as u128);
        t[i + 3] = p as u64;
        carry = (p >> 64) as u64;

        // Propagate carry through remaining limbs
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

    // Result is in t[4..8]
    let mut r = [t[4], t[5], t[6], t[7]];

    // Final conditional subtraction: if overflow or r >= p, subtract p
    if overflow != 0 || cmp_u256(&r, &P) != Ordering::Less {
        sub_borrow_u256(&mut r, &P);
    }

    Sm2FieldElement(r)
}

// ========================================================================
// 256-bit unsigned arithmetic helpers
// ========================================================================

/// 256-bit addition: returns (result, carry).
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

/// 256-bit subtraction: returns (result, borrow). Borrow is 1 if a < b.
fn sub_u256(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut r = [0u64; 4];
    let mut borrow = 0i128;

    for i in 0..4 {
        let diff = (a[i] as i128) - (b[i] as i128) + borrow;
        r[i] = diff as u64;
        borrow = diff >> 64; // arithmetic shift: -1 if borrow, 0 otherwise
    }

    (r, if borrow < 0 { 1 } else { 0 })
}

/// Compare two 256-bit numbers (little-endian limb order).
fn cmp_u256(a: &[u64; 4], b: &[u64; 4]) -> Ordering {
    for i in (0..4).rev() {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

/// In-place 256-bit addition: a += b, ignoring overflow.
fn add_carry_u256(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut carry = 0u64;
    for i in 0..4 {
        let sum = (a[i] as u128) + (b[i] as u128) + (carry as u128);
        a[i] = sum as u64;
        carry = (sum >> 64) as u64;
    }
}

/// In-place 256-bit subtraction: a -= b, ignoring underflow.
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

    /// Helper: create a field element from a decimal value (for small test values).
    fn fe_from_u64(val: u64) -> Sm2FieldElement {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&val.to_be_bytes());
        Sm2FieldElement::from_bytes(&bytes)
    }

    #[test]
    fn test_from_bytes_to_bytes_roundtrip() {
        let original = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let fe = Sm2FieldElement::from_bytes(&original);
        let recovered = fe.to_bytes();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_from_bytes_to_bytes_zero() {
        let zero_bytes = [0u8; 32];
        let fe = Sm2FieldElement::from_bytes(&zero_bytes);
        assert_eq!(fe, Sm2FieldElement::ZERO);
        assert_eq!(fe.to_bytes(), zero_bytes);
    }

    #[test]
    fn test_from_bytes_to_bytes_one() {
        let mut one_bytes = [0u8; 32];
        one_bytes[31] = 1;
        let fe = Sm2FieldElement::from_bytes(&one_bytes);
        assert_eq!(fe, Sm2FieldElement::ONE);
        assert_eq!(fe.to_bytes(), one_bytes);
    }

    #[test]
    fn test_one_constant() {
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(Sm2FieldElement::ONE.to_bytes(), expected);
    }

    #[test]
    fn test_add_identity() {
        let a = fe_from_u64(42);
        assert_eq!(a.add(&Sm2FieldElement::ZERO), a);
        assert_eq!(Sm2FieldElement::ZERO.add(&a), a);
    }

    #[test]
    fn test_add_small_values() {
        let a = fe_from_u64(3);
        let b = fe_from_u64(5);
        let c = a.add(&b);
        let expected = fe_from_u64(8);
        assert_eq!(c, expected);
    }

    #[test]
    fn test_sub_identity() {
        let a = fe_from_u64(42);
        assert_eq!(a.sub(&Sm2FieldElement::ZERO), a);
    }

    #[test]
    fn test_sub_self_is_zero() {
        let a = fe_from_u64(12345);
        assert_eq!(a.sub(&a), Sm2FieldElement::ZERO);
    }

    #[test]
    fn test_sub_small_values() {
        let a = fe_from_u64(10);
        let b = fe_from_u64(3);
        let c = a.sub(&b);
        let expected = fe_from_u64(7);
        assert_eq!(c, expected);
    }

    #[test]
    fn test_sub_wraps_mod_p() {
        // 3 - 5 = -2 mod p = p - 2
        let a = fe_from_u64(3);
        let b = fe_from_u64(5);
        let c = a.sub(&b);

        // SM2 p - 2
        let pm2_bytes: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFD,
        ];
        let expected = Sm2FieldElement::from_bytes(&pm2_bytes);
        assert_eq!(c, expected);
    }

    #[test]
    fn test_neg_zero() {
        assert_eq!(Sm2FieldElement::ZERO.neg(), Sm2FieldElement::ZERO);
    }

    #[test]
    fn test_neg_and_add() {
        let a = fe_from_u64(12345);
        let neg_a = a.neg();
        assert_eq!(a.add(&neg_a), Sm2FieldElement::ZERO);
    }

    #[test]
    fn test_neg_of_3() {
        let a = fe_from_u64(3);
        let neg_a = a.neg();

        // SM2 p - 3
        let pm3_bytes: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFC,
        ];
        let expected = Sm2FieldElement::from_bytes(&pm3_bytes);
        assert_eq!(neg_a, expected);
    }

    #[test]
    fn test_mul_identity() {
        let a = fe_from_u64(42);
        assert_eq!(a.mul(&Sm2FieldElement::ONE), a);
        assert_eq!(Sm2FieldElement::ONE.mul(&a), a);
    }

    #[test]
    fn test_mul_zero() {
        let a = fe_from_u64(42);
        assert_eq!(a.mul(&Sm2FieldElement::ZERO), Sm2FieldElement::ZERO);
    }

    #[test]
    fn test_mul_small_values() {
        let a = fe_from_u64(7);
        let b = fe_from_u64(11);
        let c = a.mul(&b);
        let expected = fe_from_u64(77);
        assert_eq!(c, expected);
    }

    #[test]
    fn test_mul_commutativity() {
        let a = fe_from_u64(1234567);
        let b = fe_from_u64(7654321);
        assert_eq!(a.mul(&b), b.mul(&a));
    }

    #[test]
    fn test_sqr_equals_mul_self() {
        let a = fe_from_u64(12345);
        assert_eq!(a.sqr(), a.mul(&a));
    }

    #[test]
    fn test_sqr_small_value() {
        let a = fe_from_u64(7);
        let expected = fe_from_u64(49);
        assert_eq!(a.sqr(), expected);
    }

    #[test]
    fn test_inv_of_one() {
        assert_eq!(Sm2FieldElement::ONE.inv(), Sm2FieldElement::ONE);
    }

    #[test]
    fn test_inv_correctness() {
        let a = fe_from_u64(7);
        let a_inv = a.inv();
        let product = a.mul(&a_inv);
        assert_eq!(product, Sm2FieldElement::ONE);
    }

    #[test]
    fn test_inv_of_larger_value() {
        let bytes: [u8; 32] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88,
        ];
        let a = Sm2FieldElement::from_bytes(&bytes);
        let a_inv = a.inv();
        assert_eq!(a.mul(&a_inv), Sm2FieldElement::ONE);
    }

    #[test]
    fn test_double_inv() {
        let a = fe_from_u64(42);
        assert_eq!(a.inv().inv(), a);
    }

    #[test]
    fn test_distributive_law() {
        let a = fe_from_u64(7);
        let b = fe_from_u64(11);
        let c = fe_from_u64(13);
        let lhs = a.mul(&b.add(&c));
        let rhs = a.mul(&b).add(&a.mul(&c));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_add_sub_inverse() {
        let a = fe_from_u64(999);
        let b = fe_from_u64(777);
        assert_eq!(a.add(&b).sub(&b), a);
    }

    #[test]
    fn test_mul_associativity() {
        let a = fe_from_u64(7);
        let b = fe_from_u64(11);
        let c = fe_from_u64(13);
        assert_eq!(a.mul(&b).mul(&c), a.mul(&b.mul(&c)));
    }

    #[test]
    fn test_large_values_roundtrip() {
        // SM2 p - 1
        let pm1_bytes: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFE,
        ];
        let fe = Sm2FieldElement::from_bytes(&pm1_bytes);
        assert_eq!(fe.to_bytes(), pm1_bytes);

        // (p-1) + 1 = 0 mod p
        let sum = fe.add(&Sm2FieldElement::ONE);
        assert_eq!(sum, Sm2FieldElement::ZERO);
    }

    #[test]
    fn test_is_zero() {
        assert!(Sm2FieldElement::ZERO.is_zero());
        assert!(!Sm2FieldElement::ONE.is_zero());
        assert!(!fe_from_u64(42).is_zero());
    }

    #[test]
    fn test_cmp_u256_helper() {
        let a = [1u64, 0, 0, 0];
        let b = [2u64, 0, 0, 0];
        assert_eq!(cmp_u256(&a, &b), Ordering::Less);
        assert_eq!(cmp_u256(&b, &a), Ordering::Greater);
        assert_eq!(cmp_u256(&a, &a), Ordering::Equal);

        let c = [0u64, 0, 0, 1];
        let d = [u64::MAX, u64::MAX, u64::MAX, 0];
        assert_eq!(cmp_u256(&c, &d), Ordering::Greater);
    }

    #[test]
    fn test_large_mul_roundtrip() {
        let a_bytes: [u8; 32] = [
            0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB,
        ];
        let b_bytes: [u8; 32] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
            0xDD, 0xEE, 0xFF, 0x00,
        ];
        let a = Sm2FieldElement::from_bytes(&a_bytes);
        let b = Sm2FieldElement::from_bytes(&b_bytes);

        // a * b * b^(-1) = a
        let product = a.mul(&b);
        let b_inv = b.inv();
        assert_eq!(product.mul(&b_inv), a);
    }

    #[test]
    fn test_repeated_squaring_consistency() {
        let a = fe_from_u64(3);
        let a2 = a.sqr();
        let a4 = a2.sqr();
        let a8 = a4.sqr();
        let a16 = a8.sqr();

        // 3^16 = 43046721
        let expected = fe_from_u64(43046721);
        assert_eq!(a16, expected);
    }

    #[test]
    fn test_inv_of_p_minus_one() {
        // (p-1)^(-1) = p-1 (since (p-1)^2 = 1 mod p)
        let pm1_bytes: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFE,
        ];
        let pm1 = Sm2FieldElement::from_bytes(&pm1_bytes);
        assert_eq!(pm1.inv(), pm1);
    }

    #[test]
    fn test_mont_sqr_equals_mont_mul_large() {
        let a_bytes: [u8; 32] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88,
        ];
        let a = Sm2FieldElement::from_bytes(&a_bytes);
        assert_eq!(a.sqr(), a.mul(&a));
    }

    #[test]
    fn test_mont_sqr_equals_mont_mul_near_p() {
        // SM2 p - 2
        let pm2_bytes: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFD,
        ];
        let a = Sm2FieldElement::from_bytes(&pm2_bytes);
        assert_eq!(a.sqr(), a.mul(&a));
    }
}
