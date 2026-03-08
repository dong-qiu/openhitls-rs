//! P-384 specialized field element arithmetic using 6×u64 Montgomery form.
//!
//! All elements are stored in Montgomery form: `a_mont = a * R mod p`, where `R = 2^384`.
//! This allows fast modular multiplication via Montgomery reduction.
//!
//! The P-384 prime is `p = 2^384 - 2^128 - 2^96 + 2^32 - 1`.

use core::cmp::Ordering;
use hitls_bignum::BigNum;

use super::field_ops::{add_assign_limbs, add_limbs, cmp_limbs, sub_assign_limbs, sub_limbs};

/// The P-384 prime p = 2^384 - 2^128 - 2^96 + 2^32 - 1.
/// Stored as 6×u64 in little-endian limb order.
const P: [u64; 6] = [
    0x0000_0000_FFFF_FFFF,
    0xFFFF_FFFF_0000_0000,
    0xFFFF_FFFF_FFFF_FFFE,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
];

/// R^2 mod p, where R = 2^384 (precomputed for Montgomery conversion).
const R2: [u64; 6] = const_compute_r2();

/// Montgomery constant: N0 = -p^(-1) mod 2^64.
///
/// P\[0\] = 0x00000000FFFFFFFF. Using Newton's method:
/// p^(-1) mod 2^64 = 0xFFFFFFFF00000001, so N0 = 0x0000000100000001.
const N0: u64 = const_compute_n0();

// ========================================================================
// Compile-time constant computation helpers
// ========================================================================

/// Compare two 384-bit numbers at const time. Returns true if a >= b.
const fn const_ge(a: &[u64; 6], b: &[u64; 6]) -> bool {
    let mut i = 5;
    loop {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
        if i == 0 {
            return true; // equal
        }
        i -= 1;
    }
}

/// Subtract b from a at const time: a - b, assuming a >= b. Returns result.
const fn const_sub(a: &[u64; 6], b: &[u64; 6]) -> [u64; 6] {
    let mut r = [0u64; 6];
    let mut borrow: u64 = 0;
    let mut i = 0;
    while i < 6 {
        let (diff, b1) = a[i].overflowing_sub(b[i]);
        let (diff2, b2) = diff.overflowing_sub(borrow);
        r[i] = diff2;
        borrow = (b1 as u64) + (b2 as u64);
        i += 1;
    }
    r
}

/// Add two 384-bit numbers at const time. Returns (result, carry).
const fn const_add(a: &[u64; 6], b: &[u64; 6]) -> ([u64; 6], u64) {
    let mut r = [0u64; 6];
    let mut carry: u64 = 0;
    let mut i = 0;
    while i < 6 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        r[i] = s2;
        carry = (c1 as u64) + (c2 as u64);
        i += 1;
    }
    (r, carry)
}

/// Compute R mod p = 2^384 mod p by doubling 1, 384 times.
const fn const_compute_r_mod_p() -> [u64; 6] {
    let mut val = [0u64; 6];
    val[0] = 1; // start with 1

    let mut k = 0;
    while k < 384 {
        // Double: val = val + val
        let (sum, carry) = const_add(&val, &val);
        val = sum;
        // If carry or val >= P, subtract P
        if carry != 0 || const_ge(&val, &P) {
            val = const_sub(&val, &P);
        }
        k += 1;
    }
    val
}

/// Compute R^2 mod p by doubling R mod p, 384 times.
const fn const_compute_r2() -> [u64; 6] {
    let mut val = const_compute_r_mod_p();

    let mut k = 0;
    while k < 384 {
        let (sum, carry) = const_add(&val, &val);
        val = sum;
        if carry != 0 || const_ge(&val, &P) {
            val = const_sub(&val, &P);
        }
        k += 1;
    }
    val
}

/// Compute N0 = -p^(-1) mod 2^64 using Newton's method.
///
/// Starts with x = 1 and iterates x = x * (2 - p0 * x) mod 2^64,
/// then returns (2^64 - x) mod 2^64.
const fn const_compute_n0() -> u64 {
    let p0: u64 = P[0]; // 0x00000000FFFFFFFF
    let mut x: u64 = 1;
    let mut i = 0;
    while i < 64 {
        x = x.wrapping_mul(2u64.wrapping_sub(p0.wrapping_mul(x)));
        i += 1;
    }
    // x = p^(-1) mod 2^64, return -x mod 2^64
    x.wrapping_neg()
}

// ========================================================================
// P384FieldElement
// ========================================================================

/// A P-384 field element in Montgomery form.
///
/// Internal representation: 6 × u64 limbs in little-endian order, where
/// the stored value `v` represents the field element `v * R^(-1) mod p`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct P384FieldElement(pub [u64; 6]);

impl P384FieldElement {
    /// The additive identity (zero).
    pub const ZERO: Self = Self([0, 0, 0, 0, 0, 0]);

    /// The multiplicative identity (one) in Montgomery form: R mod p.
    pub const ONE: Self = Self(const_compute_r_mod_p());

    /// Convert from 48-byte big-endian representation to Montgomery form.
    pub fn from_bytes(bytes: &[u8; 48]) -> Self {
        let mut limbs = [0u64; 6];
        limbs[5] = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        limbs[4] = u64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        limbs[3] = u64::from_be_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        limbs[2] = u64::from_be_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]);
        limbs[1] = u64::from_be_bytes([
            bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37], bytes[38], bytes[39],
        ]);
        limbs[0] = u64::from_be_bytes([
            bytes[40], bytes[41], bytes[42], bytes[43], bytes[44], bytes[45], bytes[46], bytes[47],
        ]);
        // Convert to Montgomery form: multiply by R^2 and reduce
        Self(limbs).mont_mul(&Self(R2))
    }

    /// Convert from Montgomery form to 48-byte big-endian representation.
    pub fn to_bytes(self) -> [u8; 48] {
        // Montgomery reduction: multiply by 1 to convert out of Montgomery form
        let normal = self.mont_mul(&Self([1, 0, 0, 0, 0, 0]));
        let mut out = [0u8; 48];
        out[0..8].copy_from_slice(&normal.0[5].to_be_bytes());
        out[8..16].copy_from_slice(&normal.0[4].to_be_bytes());
        out[16..24].copy_from_slice(&normal.0[3].to_be_bytes());
        out[24..32].copy_from_slice(&normal.0[2].to_be_bytes());
        out[32..40].copy_from_slice(&normal.0[1].to_be_bytes());
        out[40..48].copy_from_slice(&normal.0[0].to_be_bytes());
        out
    }

    /// Convert from a BigNum (assumed < p) to Montgomery form.
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

    /// Field addition: (a + b) mod p.
    pub fn add(&self, other: &Self) -> Self {
        let (mut r, carry) = add_limbs(&self.0, &other.0);
        if carry != 0 || cmp_limbs(&r, &P) != Ordering::Less {
            sub_assign_limbs(&mut r, &P);
        }
        Self(r)
    }

    /// Field subtraction: (a - b) mod p.
    pub fn sub(&self, other: &Self) -> Self {
        let (mut r, borrow) = sub_limbs(&self.0, &other.0);
        if borrow != 0 {
            add_assign_limbs(&mut r, &P);
        }
        Self(r)
    }

    /// Field negation: (-a) mod p.
    pub fn neg(&self) -> Self {
        if self.is_zero() {
            return *self;
        }
        let (r, _) = sub_limbs(&P, &self.0);
        Self(r)
    }

    /// Check if zero.
    pub fn is_zero(&self) -> bool {
        self.0[0] == 0
            && self.0[1] == 0
            && self.0[2] == 0
            && self.0[3] == 0
            && self.0[4] == 0
            && self.0[5] == 0
    }

    /// Field multiplication: (a * b) mod p in Montgomery form.
    pub fn mul(&self, other: &Self) -> Self {
        self.mont_mul(other)
    }

    /// Field squaring: a^2 mod p in Montgomery form.
    ///
    /// Uses dedicated squaring exploiting a[i]*a[j] = a[j]*a[i] symmetry:
    /// 15 cross-product multiplies + 6 diagonal = 21 total vs 36 for schoolbook.
    pub fn sqr(&self) -> Self {
        self.mont_sqr()
    }

    /// Field inversion using Fermat's little theorem: a^(-1) = a^(p-2) mod p.
    ///
    /// Uses an optimized addition chain with precomputed powers.
    /// p-2 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    ///        FEFFFFFFFF0000000000000000FFFFFFFD
    ///
    /// Bit structure (MSB to LSB):
    ///   bits 383..129: 255 ones
    ///   bit 128: 0
    ///   bits 127..96: 32 ones
    ///   bits 95..32: 64 zeros
    ///   bits 31..2: 30 ones
    ///   bit 1: 0
    ///   bit 0: 1
    pub fn inv(&self) -> Self {
        // Precompute x_n = a^(2^n - 1) for needed values of n.
        let x1 = *self;
        let x2 = x1.sqr().mul(&x1); // a^(2^2 - 1) = a^3

        // x3 = a^(2^3 - 1) = a^7
        let x3 = x2.sqr().mul(&x1);

        // x6 = a^(2^6 - 1) = a^63
        let x6 = {
            let mut t = x3;
            for _ in 0..3 {
                t = t.sqr();
            }
            t.mul(&x3)
        };

        // x12 = a^(2^12 - 1)
        let x12 = {
            let mut t = x6;
            for _ in 0..6 {
                t = t.sqr();
            }
            t.mul(&x6)
        };

        // x15 = a^(2^15 - 1)
        let x15 = {
            let mut t = x12;
            for _ in 0..3 {
                t = t.sqr();
            }
            t.mul(&x3)
        };

        // x30 = a^(2^30 - 1)
        let x30 = {
            let mut t = x15;
            for _ in 0..15 {
                t = t.sqr();
            }
            t.mul(&x15)
        };

        // x32 = a^(2^32 - 1) = x30^4 * x2
        let x32 = {
            let mut t = x30;
            for _ in 0..2 {
                t = t.sqr();
            }
            t.mul(&x2)
        };

        // x60 = a^(2^60 - 1)
        let x60 = {
            let mut t = x30;
            for _ in 0..30 {
                t = t.sqr();
            }
            t.mul(&x30)
        };

        // x120 = a^(2^120 - 1)
        let x120 = {
            let mut t = x60;
            for _ in 0..60 {
                t = t.sqr();
            }
            t.mul(&x60)
        };

        // x240 = a^(2^240 - 1)
        let x240 = {
            let mut t = x120;
            for _ in 0..120 {
                t = t.sqr();
            }
            t.mul(&x120)
        };

        // x255 = a^(2^255 - 1)
        let x255 = {
            let mut t = x240;
            for _ in 0..15 {
                t = t.sqr();
            }
            t.mul(&x15)
        };

        // Now build the exponent p-2 using the precomputed powers:
        // Bits 383..129: 255 ones (handled by x255)
        let mut e = x255;

        // Bit 128: 0 (just square)
        e = e.sqr();

        // Bits 127..96: 32 ones
        for _ in 0..32 {
            e = e.sqr();
        }
        e = e.mul(&x32);

        // Bits 95..32: 64 zeros
        for _ in 0..64 {
            e = e.sqr();
        }

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
    /// Uses schoolbook 6-limb multiplication (36 u64×u64 multiplies) followed
    /// by P-384 specialized Montgomery reduction exploiting the prime structure.
    fn mont_mul(&self, other: &Self) -> Self {
        let a = &self.0;
        let b = &other.0;

        // Compute 768-bit product: t = a * b (12 limbs)
        let mut t = [0u64; 12];

        // Schoolbook multiplication using u128 to capture carries
        for i in 0..6 {
            let mut carry: u64 = 0;
            for j in 0..6 {
                let product =
                    u128::from(a[i]) * u128::from(b[j]) + u128::from(t[i + j]) + u128::from(carry);
                t[i + j] = product as u64;
                carry = (product >> 64) as u64;
            }
            t[i + 6] = carry;
        }

        p384_mont_reduce(t)
    }

    /// Montgomery squaring exploiting a[i]*a[j] = a[j]*a[i] symmetry.
    ///
    /// Computes upper triangle cross products (15 multiplies), doubles them,
    /// then adds diagonal terms (6 multiplies). Total: 21 vs 36 for schoolbook.
    fn mont_sqr(&self) -> Self {
        let a = &self.0;
        let mut t = [0u64; 12];

        // Upper triangle cross products (i < j), accumulated row by row.

        // Row 0: a[0] * a[1..6]
        let mut carry: u64;
        let p = u128::from(a[0]) * u128::from(a[1]);
        t[1] = p as u64;
        carry = (p >> 64) as u64;

        let p = u128::from(a[0]) * u128::from(a[2]) + u128::from(carry);
        t[2] = p as u64;
        carry = (p >> 64) as u64;

        let p = u128::from(a[0]) * u128::from(a[3]) + u128::from(carry);
        t[3] = p as u64;
        carry = (p >> 64) as u64;

        let p = u128::from(a[0]) * u128::from(a[4]) + u128::from(carry);
        t[4] = p as u64;
        carry = (p >> 64) as u64;

        let p = u128::from(a[0]) * u128::from(a[5]) + u128::from(carry);
        t[5] = p as u64;
        t[6] = (p >> 64) as u64;

        // Row 1: a[1] * a[2..6]
        let p = u128::from(a[1]) * u128::from(a[2]) + u128::from(t[3]);
        t[3] = p as u64;
        carry = (p >> 64) as u64;

        let p = u128::from(a[1]) * u128::from(a[3]) + u128::from(t[4]) + u128::from(carry);
        t[4] = p as u64;
        carry = (p >> 64) as u64;

        let p = u128::from(a[1]) * u128::from(a[4]) + u128::from(t[5]) + u128::from(carry);
        t[5] = p as u64;
        carry = (p >> 64) as u64;

        let p = u128::from(a[1]) * u128::from(a[5]) + u128::from(t[6]) + u128::from(carry);
        t[6] = p as u64;
        t[7] = (p >> 64) as u64;

        // Row 2: a[2] * a[3..6]
        let p = u128::from(a[2]) * u128::from(a[3]) + u128::from(t[5]);
        t[5] = p as u64;
        carry = (p >> 64) as u64;

        let p = u128::from(a[2]) * u128::from(a[4]) + u128::from(t[6]) + u128::from(carry);
        t[6] = p as u64;
        carry = (p >> 64) as u64;

        let p = u128::from(a[2]) * u128::from(a[5]) + u128::from(t[7]) + u128::from(carry);
        t[7] = p as u64;
        t[8] = (p >> 64) as u64;

        // Row 3: a[3] * a[4..6]
        let p = u128::from(a[3]) * u128::from(a[4]) + u128::from(t[7]);
        t[7] = p as u64;
        carry = (p >> 64) as u64;

        let p = u128::from(a[3]) * u128::from(a[5]) + u128::from(t[8]) + u128::from(carry);
        t[8] = p as u64;
        t[9] = (p >> 64) as u64;

        // Row 4: a[4] * a[5]
        let p = u128::from(a[4]) * u128::from(a[5]) + u128::from(t[9]);
        t[9] = p as u64;
        t[10] = (p >> 64) as u64;

        // Double the cross products (left shift by 1 across all 12 limbs).
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
        // t[0] stays 0

        // Add diagonal terms a[i]^2 at positions (2*i, 2*i+1).
        let d = u128::from(a[0]) * u128::from(a[0]);
        t[0] = d as u64;
        let mut c = d >> 64;

        let s = u128::from(t[1]) + c;
        t[1] = s as u64;
        c = s >> 64;

        let d = u128::from(a[1]) * u128::from(a[1]) + u128::from(t[2]) + c;
        t[2] = d as u64;
        c = d >> 64;

        let s = u128::from(t[3]) + c;
        t[3] = s as u64;
        c = s >> 64;

        let d = u128::from(a[2]) * u128::from(a[2]) + u128::from(t[4]) + c;
        t[4] = d as u64;
        c = d >> 64;

        let s = u128::from(t[5]) + c;
        t[5] = s as u64;
        c = s >> 64;

        let d = u128::from(a[3]) * u128::from(a[3]) + u128::from(t[6]) + c;
        t[6] = d as u64;
        c = d >> 64;

        let s = u128::from(t[7]) + c;
        t[7] = s as u64;
        c = s >> 64;

        let d = u128::from(a[4]) * u128::from(a[4]) + u128::from(t[8]) + c;
        t[8] = d as u64;
        c = d >> 64;

        let s = u128::from(t[9]) + c;
        t[9] = s as u64;
        c = s >> 64;

        let d = u128::from(a[5]) * u128::from(a[5]) + u128::from(t[10]) + c;
        t[10] = d as u64;
        c = d >> 64;

        t[11] = (u128::from(t[11]) + c) as u64;

        p384_mont_reduce(t)
    }
}

// ========================================================================
// P-384 specialized Montgomery reduction
// ========================================================================

/// P-384 specialized Montgomery reduction.
///
/// Exploits the structure of the P-384 prime for faster reduction.
/// The prime limbs are:
/// - P\[0\] = 0x00000000FFFFFFFF
/// - P\[1\] = 0xFFFFFFFF00000000
/// - P\[2\] = 0xFFFFFFFFFFFFFFFE
/// - P\[3\] = P\[4\] = P\[5\] = 0xFFFFFFFFFFFFFFFF
///
/// For each iteration i, computes m = t\[i\] * N0, then adds m * P to t\[i..\].
fn p384_mont_reduce(mut t: [u64; 12]) -> P384FieldElement {
    let mut overflow: u64 = 0;

    for i in 0..6 {
        let m = u128::from(t[i]).wrapping_mul(u128::from(N0)) as u64;

        // j=0: P[0] = 0x00000000FFFFFFFF
        let p = u128::from(m) * u128::from(P[0]) + u128::from(t[i]);
        // Low 64 bits should cancel t[i]; carry propagates.
        debug_assert_eq!(p as u64, 0);
        let mut carry = (p >> 64) as u64;

        // j=1: P[1] = 0xFFFFFFFF00000000
        let p = u128::from(m) * u128::from(P[1]) + u128::from(t[i + 1]) + u128::from(carry);
        t[i + 1] = p as u64;
        carry = (p >> 64) as u64;

        // j=2: P[2] = 0xFFFFFFFFFFFFFFFE
        let p = u128::from(m) * u128::from(P[2]) + u128::from(t[i + 2]) + u128::from(carry);
        t[i + 2] = p as u64;
        carry = (p >> 64) as u64;

        // j=3: P[3] = 0xFFFFFFFFFFFFFFFF
        let p = u128::from(m) * u128::from(P[3]) + u128::from(t[i + 3]) + u128::from(carry);
        t[i + 3] = p as u64;
        carry = (p >> 64) as u64;

        // j=4: P[4] = 0xFFFFFFFFFFFFFFFF
        let p = u128::from(m) * u128::from(P[4]) + u128::from(t[i + 4]) + u128::from(carry);
        t[i + 4] = p as u64;
        carry = (p >> 64) as u64;

        // j=5: P[5] = 0xFFFFFFFFFFFFFFFF
        let p = u128::from(m) * u128::from(P[5]) + u128::from(t[i + 5]) + u128::from(carry);
        t[i + 5] = p as u64;
        carry = (p >> 64) as u64;

        // Propagate carry through remaining limbs
        for item in &mut t[(i + 6)..12] {
            if carry == 0 {
                break;
            }
            let s = u128::from(*item) + u128::from(carry);
            *item = s as u64;
            carry = (s >> 64) as u64;
        }

        overflow += carry;
    }

    // Result is in t[6..12]
    let mut r = [t[6], t[7], t[8], t[9], t[10], t[11]];

    // Final conditional subtraction: if overflow or r >= p, subtract p
    if overflow != 0 || cmp_limbs(&r, &P) != Ordering::Less {
        sub_assign_limbs(&mut r, &P);
    }

    P384FieldElement(r)
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a field element from a decimal value (for small test values).
    fn fe_from_u64(val: u64) -> P384FieldElement {
        let mut bytes = [0u8; 48];
        bytes[40..48].copy_from_slice(&val.to_be_bytes());
        P384FieldElement::from_bytes(&bytes)
    }

    #[test]
    fn test_const_r_mod_p() {
        // R mod p = 2^384 mod p
        // Expected: 0x000000000000000000000000000000000000000000000000
        //            000000000000000100000000FFFFFFFFFFFFFFFF00000001
        let one = P384FieldElement::ONE;
        let expected = [
            0xFFFF_FFFF_0000_0001u64,
            0x0000_0000_FFFF_FFFFu64,
            0x0000_0000_0000_0001u64,
            0x0000_0000_0000_0000u64,
            0x0000_0000_0000_0000u64,
            0x0000_0000_0000_0000u64,
        ];
        assert_eq!(one.0, expected);
    }

    #[test]
    fn test_const_r2_mod_p() {
        // R^2 mod p precomputed
        let expected = [
            0xFFFF_FFFE_0000_0001u64,
            0x0000_0002_0000_0000u64,
            0xFFFF_FFFE_0000_0000u64,
            0x0000_0002_0000_0000u64,
            0x0000_0000_0000_0001u64,
            0x0000_0000_0000_0000u64,
        ];
        assert_eq!(R2, expected);
    }

    #[test]
    fn test_const_n0() {
        // N0 = 0x0000000100000001
        assert_eq!(N0, 0x0000_0001_0000_0001u64);
        // Verify: N0 * P[0] ≡ -1 (mod 2^64)
        let product = N0.wrapping_mul(P[0]);
        assert_eq!(product, u64::MAX);
    }

    #[test]
    fn test_from_bytes_to_bytes_roundtrip() {
        let original = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
            0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
        ];
        let fe = P384FieldElement::from_bytes(&original);
        let recovered = fe.to_bytes();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_from_bytes_to_bytes_zero() {
        let zero_bytes = [0u8; 48];
        let fe = P384FieldElement::from_bytes(&zero_bytes);
        assert_eq!(fe, P384FieldElement::ZERO);
        assert_eq!(fe.to_bytes(), zero_bytes);
    }

    #[test]
    fn test_from_bytes_to_bytes_one() {
        let mut one_bytes = [0u8; 48];
        one_bytes[47] = 1;
        let fe = P384FieldElement::from_bytes(&one_bytes);
        assert_eq!(fe, P384FieldElement::ONE);
        assert_eq!(fe.to_bytes(), one_bytes);
    }

    #[test]
    fn test_one_constant() {
        let mut expected = [0u8; 48];
        expected[47] = 1;
        assert_eq!(P384FieldElement::ONE.to_bytes(), expected);
    }

    #[test]
    fn test_add_identity() {
        let a = fe_from_u64(42);
        assert_eq!(a.add(&P384FieldElement::ZERO), a);
        assert_eq!(P384FieldElement::ZERO.add(&a), a);
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
        assert_eq!(a.sub(&P384FieldElement::ZERO), a);
    }

    #[test]
    fn test_sub_self_is_zero() {
        let a = fe_from_u64(12345);
        assert_eq!(a.sub(&a), P384FieldElement::ZERO);
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

        // p - 2 in big-endian:
        // FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE
        // FFFFFFFF0000000000000000FFFFFFFD
        let pm2_bytes: [u8; 48] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFD,
        ];
        let expected = P384FieldElement::from_bytes(&pm2_bytes);
        assert_eq!(c, expected);
    }

    #[test]
    fn test_neg_zero() {
        assert_eq!(P384FieldElement::ZERO.neg(), P384FieldElement::ZERO);
    }

    #[test]
    fn test_neg_and_add() {
        let a = fe_from_u64(12345);
        let neg_a = a.neg();
        assert_eq!(a.add(&neg_a), P384FieldElement::ZERO);
    }

    #[test]
    fn test_neg_of_3() {
        let a = fe_from_u64(3);
        let neg_a = a.neg();

        // p - 3 in big-endian
        let pm3_bytes: [u8; 48] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFC,
        ];
        let expected = P384FieldElement::from_bytes(&pm3_bytes);
        assert_eq!(neg_a, expected);
    }

    #[test]
    fn test_mul_identity() {
        let a = fe_from_u64(42);
        assert_eq!(a.mul(&P384FieldElement::ONE), a);
        assert_eq!(P384FieldElement::ONE.mul(&a), a);
    }

    #[test]
    fn test_mul_zero() {
        let a = fe_from_u64(42);
        assert_eq!(a.mul(&P384FieldElement::ZERO), P384FieldElement::ZERO);
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
        assert_eq!(P384FieldElement::ONE.inv(), P384FieldElement::ONE);
    }

    #[test]
    fn test_inv_correctness() {
        // a * a^(-1) = 1
        let a = fe_from_u64(7);
        let a_inv = a.inv();
        let product = a.mul(&a_inv);
        assert_eq!(product, P384FieldElement::ONE);
    }

    #[test]
    fn test_inv_known_value() {
        // 7^(-1) mod p (precomputed)
        let a = fe_from_u64(7);
        let a_inv = a.inv();
        let a_inv_bytes = a_inv.to_bytes();

        let expected: [u8; 48] = [
            0x24, 0x92, 0x49, 0x24, 0x92, 0x49, 0x24, 0x92, 0x49, 0x24, 0x92, 0x49, 0x24, 0x92,
            0x49, 0x24, 0x92, 0x49, 0x24, 0x92, 0x49, 0x24, 0x92, 0x49, 0x24, 0x92, 0x49, 0x24,
            0x92, 0x49, 0x24, 0x92, 0x24, 0x92, 0x49, 0x24, 0x6D, 0xB6, 0xDB, 0x6D, 0xB6, 0xDB,
            0x6D, 0xB7, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(a_inv_bytes, expected);
    }

    #[test]
    fn test_inv_of_larger_value() {
        let bytes: [u8; 48] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01, 0x02,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let a = P384FieldElement::from_bytes(&bytes);
        let a_inv = a.inv();
        assert_eq!(a.mul(&a_inv), P384FieldElement::ONE);
    }

    #[test]
    fn test_double_inv() {
        // (a^(-1))^(-1) = a
        let a = fe_from_u64(42);
        assert_eq!(a.inv().inv(), a);
    }

    #[test]
    fn test_distributive_law() {
        // a * (b + c) = a*b + a*c
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
        // p - 1
        let pm1_bytes: [u8; 48] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFE,
        ];
        let fe = P384FieldElement::from_bytes(&pm1_bytes);
        assert_eq!(fe.to_bytes(), pm1_bytes);

        // (p-1) + 1 = 0 mod p
        let sum = fe.add(&P384FieldElement::ONE);
        assert_eq!(sum, P384FieldElement::ZERO);
    }

    #[test]
    fn test_is_zero() {
        assert!(P384FieldElement::ZERO.is_zero());
        assert!(!P384FieldElement::ONE.is_zero());
        assert!(!fe_from_u64(42).is_zero());
    }

    #[test]
    fn test_cmp_limbs_helper() {
        let a = [1u64, 0, 0, 0, 0, 0];
        let b = [2u64, 0, 0, 0, 0, 0];
        assert_eq!(cmp_limbs(&a, &b), Ordering::Less);
        assert_eq!(cmp_limbs(&b, &a), Ordering::Greater);
        assert_eq!(cmp_limbs(&a, &a), Ordering::Equal);

        let c = [0u64, 0, 0, 0, 0, 1];
        let d = [u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, 0];
        assert_eq!(cmp_limbs(&c, &d), Ordering::Greater);
    }

    #[test]
    fn test_large_mul_roundtrip() {
        // Test with two large values near p
        let a_bytes: [u8; 48] = [
            0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98,
        ];
        let b_bytes: [u8; 48] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
            0xDD, 0xEE, 0xFF, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x01, 0x23,
            0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        ];
        let a = P384FieldElement::from_bytes(&a_bytes);
        let b = P384FieldElement::from_bytes(&b_bytes);

        // a * b * b^(-1) = a
        let product = a.mul(&b);
        let b_inv = b.inv();
        assert_eq!(product.mul(&b_inv), a);
    }

    #[test]
    fn test_repeated_squaring_consistency() {
        // a^16 computed via repeated squaring should equal 3^16 = 43046721
        let a = fe_from_u64(3);
        let a2 = a.sqr();
        let a4 = a2.sqr();
        let a8 = a4.sqr();
        let a16 = a8.sqr();

        let expected = fe_from_u64(43046721);
        assert_eq!(a16, expected);
    }

    #[test]
    fn test_inv_of_p_minus_one() {
        // (p-1)^(-1) = p-1 (since (p-1)^2 = 1 mod p)
        let pm1_bytes: [u8; 48] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFE,
        ];
        let pm1 = P384FieldElement::from_bytes(&pm1_bytes);
        assert_eq!(pm1.inv(), pm1);
    }

    #[test]
    fn test_mont_sqr_equals_mont_mul_large() {
        // Test dedicated sqr vs mul(self) on large values near p
        let a_bytes: [u8; 48] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0xA1, 0xB2,
            0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
        ];
        let a = P384FieldElement::from_bytes(&a_bytes);
        assert_eq!(a.sqr(), a.mul(&a));
    }

    #[test]
    fn test_mont_sqr_equals_mont_mul_near_p() {
        // p - 2
        let pm2_bytes: [u8; 48] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFD,
        ];
        let a = P384FieldElement::from_bytes(&pm2_bytes);
        assert_eq!(a.sqr(), a.mul(&a));
    }

    #[test]
    fn test_from_to_bignum_roundtrip() {
        let bn = BigNum::from_u64(42);
        let fe = P384FieldElement::from_bignum(&bn);
        let back = fe.to_bignum();
        assert_eq!(bn, back);
    }

    #[test]
    fn test_from_to_bignum_large() {
        let bytes = hitls_utils::hex::hex(
            "DEADBEEFCAFEBABE0123456789ABCDEFFEDCBA98765432101122334455667788\
             99AABBCCDDEEFF0001020304050607",
        );
        let bn = BigNum::from_bytes_be(&bytes);
        let fe = P384FieldElement::from_bignum(&bn);
        let back = fe.to_bignum();
        assert_eq!(bn, back);
    }

    #[test]
    fn test_from_bignum_mul() {
        let a = P384FieldElement::from_bignum(&BigNum::from_u64(7));
        let b = P384FieldElement::from_bignum(&BigNum::from_u64(11));
        let c = a.mul(&b);
        let expected = P384FieldElement::from_bignum(&BigNum::from_u64(77));
        assert_eq!(c, expected);
    }

    #[test]
    fn test_from_bignum_inv() {
        let a = P384FieldElement::from_bignum(&BigNum::from_u64(42));
        let a_inv = a.inv();
        assert_eq!(a.mul(&a_inv), P384FieldElement::ONE);
    }
}
