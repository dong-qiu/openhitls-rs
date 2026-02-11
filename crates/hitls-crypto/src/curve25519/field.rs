//! Field arithmetic over GF(2^255 - 19) using the Fp51 representation.
//!
//! Each field element is stored as 5 limbs of at most 51 bits each.
//! Intermediate products use u128 to avoid overflow.

/// A field element in GF(p) where p = 2^255 - 19.
///
/// Stored in radix-2^51 representation: value = l[0] + l[1]*2^51 + ... + l[4]*2^204.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Fe25519(pub(crate) [u64; 5]);

const MASK51: u64 = (1u64 << 51) - 1;

impl Fe25519 {
    /// The zero element.
    pub fn zero() -> Self {
        Fe25519([0; 5])
    }

    /// The one element.
    pub fn one() -> Self {
        Fe25519([1, 0, 0, 0, 0])
    }

    /// Addition: h = f + g.
    pub fn add(&self, rhs: &Fe25519) -> Fe25519 {
        Fe25519([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
        ])
    }

    /// Subtraction: h = f - g.
    /// We add 2*p to ensure the result stays non-negative before carry propagation.
    pub fn sub(&self, rhs: &Fe25519) -> Fe25519 {
        // 2*p in Fp51: each limb gets 2 * (2^51 - 1) except l[0] gets 2*(2^51 - 19)
        // Simpler: add a multiple of p large enough to keep limbs positive.
        // 2p = 2^256 - 38. In Fp51: (2^51 - 38, 2^51 - 2, 2^51 - 2, 2^51 - 2, 2^51 - 2)
        // But we need to avoid underflow more carefully. Use a large multiple.
        let two_p: [u64; 5] = [
            0xFFFFFFFFFFFDA, // 2*(2^51 - 19) = 2^52 - 38
            0xFFFFFFFFFFFFE, // 2*(2^51 - 1) = 2^52 - 2
            0xFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFE,
        ];
        Fe25519([
            (self.0[0] + two_p[0]) - rhs.0[0],
            (self.0[1] + two_p[1]) - rhs.0[1],
            (self.0[2] + two_p[2]) - rhs.0[2],
            (self.0[3] + two_p[3]) - rhs.0[3],
            (self.0[4] + two_p[4]) - rhs.0[4],
        ])
        .carry()
    }

    /// Negation: h = -f (mod p).
    pub fn neg(&self) -> Fe25519 {
        Fe25519::zero().sub(self)
    }

    /// Multiplication: h = f * g.
    pub fn mul(&self, rhs: &Fe25519) -> Fe25519 {
        let f = &self.0;
        let g = &rhs.0;

        // Pre-multiply limbs that will be multiplied by 19
        let g1_19 = 19u128 * g[1] as u128;
        let g2_19 = 19u128 * g[2] as u128;
        let g3_19 = 19u128 * g[3] as u128;
        let g4_19 = 19u128 * g[4] as u128;

        let h0 = f[0] as u128 * g[0] as u128
            + g1_19 * f[4] as u128
            + g2_19 * f[3] as u128
            + g3_19 * f[2] as u128
            + g4_19 * f[1] as u128;

        let h1 = f[0] as u128 * g[1] as u128
            + f[1] as u128 * g[0] as u128
            + g2_19 * f[4] as u128
            + g3_19 * f[3] as u128
            + g4_19 * f[2] as u128;

        let h2 = f[0] as u128 * g[2] as u128
            + f[1] as u128 * g[1] as u128
            + f[2] as u128 * g[0] as u128
            + g3_19 * f[4] as u128
            + g4_19 * f[3] as u128;

        let h3 = f[0] as u128 * g[3] as u128
            + f[1] as u128 * g[2] as u128
            + f[2] as u128 * g[1] as u128
            + f[3] as u128 * g[0] as u128
            + g4_19 * f[4] as u128;

        let h4 = f[0] as u128 * g[4] as u128
            + f[1] as u128 * g[3] as u128
            + f[2] as u128 * g[2] as u128
            + f[3] as u128 * g[1] as u128
            + f[4] as u128 * g[0] as u128;

        Self::carry128([h0, h1, h2, h3, h4])
    }

    /// Squaring: h = f^2 (optimized, symmetric terms doubled).
    pub fn square(&self) -> Fe25519 {
        let f = &self.0;

        let f0_2 = 2 * f[0] as u128;
        let f1_2 = 2 * f[1] as u128;
        let f2_2 = 2 * f[2] as u128;
        let f3_2 = 2 * f[3] as u128;

        let f1_38 = 38u128 * f[1] as u128;
        let f2_19 = 19u128 * f[2] as u128;
        let f3_38 = 38u128 * f[3] as u128;
        let f4_19 = 19u128 * f[4] as u128;

        let h0 = f[0] as u128 * f[0] as u128 + f1_38 * f[4] as u128 + f2_19 * f3_2;

        let h1 =
            f0_2 * f[1] as u128 + f2_19 * f[4] as u128 * 2 + 19u128 * f[3] as u128 * f[3] as u128;

        let h2 = f0_2 * f[2] as u128 + f[1] as u128 * f[1] as u128 + f3_38 * f[4] as u128;

        let h3 = f0_2 * f[3] as u128 + f1_2 * f[2] as u128 + f4_19 * f[4] as u128;

        let h4 = f0_2 * f[4] as u128 + f1_2 * f[3] as u128 + f[2] as u128 * f[2] as u128;

        Self::carry128([h0, h1, h2, h3, h4])
    }

    /// Multiply by the constant 121666 (used in X25519, a24 = (A-2)/4 = 121665, a24+1 = 121666).
    pub fn mul121666(&self) -> Fe25519 {
        let c: u64 = 121666;
        let h0 = self.0[0] as u128 * c as u128;
        let h1 = self.0[1] as u128 * c as u128;
        let h2 = self.0[2] as u128 * c as u128;
        let h3 = self.0[3] as u128 * c as u128;
        let h4 = self.0[4] as u128 * c as u128;
        Self::carry128([h0, h1, h2, h3, h4])
    }

    /// Carry propagation for u128 intermediate limbs.
    fn carry128(h: [u128; 5]) -> Fe25519 {
        let mut c: u128;
        let mut r = [0u64; 5];

        c = h[0] >> 51;
        r[0] = (h[0] as u64) & MASK51;
        let h1 = h[1] + c;

        c = h1 >> 51;
        r[1] = (h1 as u64) & MASK51;
        let h2 = h[2] + c;

        c = h2 >> 51;
        r[2] = (h2 as u64) & MASK51;
        let h3 = h[3] + c;

        c = h3 >> 51;
        r[3] = (h3 as u64) & MASK51;
        let h4 = h[4] + c;

        c = h4 >> 51;
        r[4] = (h4 as u64) & MASK51;

        // Top carry folds back as *19
        r[0] += (c as u64) * 19;

        // One more carry from r[0] if needed
        c = (r[0] >> 51) as u128;
        r[0] &= MASK51;
        r[1] += c as u64;

        Fe25519(r)
    }

    /// Carry propagation for u64 limbs (used after add/sub).
    fn carry(&self) -> Fe25519 {
        let mut r = self.0;

        let c = r[0] >> 51;
        r[0] &= MASK51;
        r[1] += c;

        let c = r[1] >> 51;
        r[1] &= MASK51;
        r[2] += c;

        let c = r[2] >> 51;
        r[2] &= MASK51;
        r[3] += c;

        let c = r[3] >> 51;
        r[3] &= MASK51;
        r[4] += c;

        let c = r[4] >> 51;
        r[4] &= MASK51;
        r[0] += c * 19;

        // One more carry if r[0] overflowed
        let c = r[0] >> 51;
        r[0] &= MASK51;
        r[1] += c;

        Fe25519(r)
    }

    /// Full reduction modulo p = 2^255 - 19.
    /// Ensures the result is in [0, p).
    pub fn reduce(&self) -> Fe25519 {
        let mut r = self.carry().0;

        // Compute r - p and check if positive
        // p in Fp51: (2^51 - 19, 2^51 - 1, 2^51 - 1, 2^51 - 1, 2^51 - 1)
        // If r >= p, subtract p. We do this by adding 19 and checking if bit 255 is set.
        let mut q = (r[0] + 19) >> 51;
        q = (r[1] + q) >> 51;
        q = (r[2] + q) >> 51;
        q = (r[3] + q) >> 51;
        q = (r[4] + q) >> 51;

        // q is 1 if r >= p, 0 otherwise
        r[0] += 19 * q;

        let c = r[0] >> 51;
        r[0] &= MASK51;
        r[1] += c;

        let c = r[1] >> 51;
        r[1] &= MASK51;
        r[2] += c;

        let c = r[2] >> 51;
        r[2] &= MASK51;
        r[3] += c;

        let c = r[3] >> 51;
        r[3] &= MASK51;
        r[4] += c;

        r[4] &= MASK51;

        Fe25519(r)
    }

    /// Modular inversion: h = f^(p-2) mod p using Fermat's little theorem.
    pub fn invert(&self) -> Fe25519 {
        // Compute f^(p-2) = f^(2^255 - 21) via an addition chain.
        let f = *self;

        let z2 = f.square();
        let z8 = z2.square().square();
        let z9 = f.mul(&z8);
        let z11 = z2.mul(&z9);
        let z22 = z11.square();
        let z_5_0 = z9.mul(&z22); // 2^5 - 1

        let mut t = z_5_0.square();
        for _ in 1..5 {
            t = t.square();
        }
        let z_10_0 = t.mul(&z_5_0); // 2^10 - 1

        t = z_10_0.square();
        for _ in 1..10 {
            t = t.square();
        }
        let z_20_0 = t.mul(&z_10_0); // 2^20 - 1

        t = z_20_0.square();
        for _ in 1..20 {
            t = t.square();
        }
        t = t.mul(&z_20_0); // 2^40 - 1

        t = t.square();
        for _ in 1..10 {
            t = t.square();
        }
        let z_50_0 = t.mul(&z_10_0); // 2^50 - 1

        t = z_50_0.square();
        for _ in 1..50 {
            t = t.square();
        }
        let z_100_0 = t.mul(&z_50_0); // 2^100 - 1

        t = z_100_0.square();
        for _ in 1..100 {
            t = t.square();
        }
        t = t.mul(&z_100_0); // 2^200 - 1

        t = t.square();
        for _ in 1..50 {
            t = t.square();
        }
        t = t.mul(&z_50_0); // 2^250 - 1

        // 5 squares: 2^255 - 32
        t = t.square(); // 2^251 - 2
        t = t.square(); // 2^252 - 4
        t = t.square(); // 2^253 - 8
        t = t.square(); // 2^254 - 16
        t = t.square(); // 2^255 - 32
        t.mul(&z11) // 2^255 - 32 + 11 = 2^255 - 21 = p - 2
    }

    /// Compute f^((p-5)/8) = f^(2^252 - 3), used for square root in Ed25519 point decompression.
    pub fn pow25523(&self) -> Fe25519 {
        let f = *self;

        let z2 = f.square();
        let z8 = z2.square().square();
        let z9 = f.mul(&z8);
        let z11 = z2.mul(&z9);
        let z22 = z11.square();
        let z_5_0 = z9.mul(&z22);

        let mut t = z_5_0.square();
        for _ in 1..5 {
            t = t.square();
        }
        let z_10_0 = t.mul(&z_5_0);

        t = z_10_0.square();
        for _ in 1..10 {
            t = t.square();
        }
        let z_20_0 = t.mul(&z_10_0);

        t = z_20_0.square();
        for _ in 1..20 {
            t = t.square();
        }
        t = t.mul(&z_20_0);

        t = t.square();
        for _ in 1..10 {
            t = t.square();
        }
        let z_50_0 = t.mul(&z_10_0);

        t = z_50_0.square();
        for _ in 1..50 {
            t = t.square();
        }
        let z_100_0 = t.mul(&z_50_0);

        t = z_100_0.square();
        for _ in 1..100 {
            t = t.square();
        }
        t = t.mul(&z_100_0);

        t = t.square();
        for _ in 1..50 {
            t = t.square();
        }
        t = t.mul(&z_50_0);

        t = t.square();
        t = t.square();
        t.mul(&f) // 2^252 - 3
    }

    /// Decode a 32-byte little-endian representation into a field element.
    pub fn from_bytes(bytes: &[u8; 32]) -> Fe25519 {
        let load8 = |b: &[u8]| -> u64 {
            let mut r = 0u64;
            for (i, &byte) in b.iter().enumerate().take(8.min(b.len())) {
                r |= (byte as u64) << (8 * i);
            }
            r
        };

        let mut h = [0u64; 5];
        h[0] = load8(&bytes[0..]) & MASK51;
        h[1] = (load8(&bytes[6..]) >> 3) & MASK51;
        h[2] = (load8(&bytes[12..]) >> 6) & MASK51;
        h[3] = (load8(&bytes[19..]) >> 1) & MASK51;
        h[4] = (load8(&bytes[24..]) >> 12) & MASK51;

        Fe25519(h)
    }

    /// Encode a field element to a 32-byte little-endian representation.
    pub fn to_bytes(self) -> [u8; 32] {
        let h = self.reduce().0;
        let mut out = [0u8; 32];

        // Pack 5 × 51-bit limbs into 32 bytes (256 bits, LE).
        // Reconstruct a 256-bit value from 5 limbs and serialize.
        let mut bits = [0u64; 4]; // 4 × 64 = 256 bits, LE
                                  // h[0] occupies bits [0, 51)
        bits[0] = h[0]; // bits 0..50

        // h[1] occupies bits [51, 102)
        bits[0] |= h[1] << 51; // bits 51..63 into bits[0]
        bits[1] = h[1] >> 13; // bits 64..101

        // h[2] occupies bits [102, 153)
        bits[1] |= h[2] << 38; // bits 102..127
        bits[2] = h[2] >> 26; // bits 128..152

        // h[3] occupies bits [153, 204)
        bits[2] |= h[3] << 25; // bits 153..191
        bits[3] = h[3] >> 39; // bits 192..203

        // h[4] occupies bits [204, 255)
        bits[3] |= h[4] << 12; // bits 204..255

        for (i, &word) in bits.iter().enumerate() {
            let start = i * 8;
            for j in 0..8 {
                if start + j < 32 {
                    out[start + j] = (word >> (j * 8)) as u8;
                }
            }
        }

        out
    }

    /// Constant-time conditional swap: swap self and other if swap == 1.
    pub fn conditional_swap(&mut self, other: &mut Fe25519, swap: u8) {
        let mask = (-(swap as i64)) as u64;
        for i in 0..5 {
            let t = mask & (self.0[i] ^ other.0[i]);
            self.0[i] ^= t;
            other.0[i] ^= t;
        }
    }

    /// Returns 1 if the field element is negative (i.e., the least significant
    /// bit of the canonical encoding is 1), 0 otherwise.
    pub fn is_negative(&self) -> u8 {
        let bytes = self.to_bytes();
        bytes[0] & 1
    }

    /// Check if the element is zero.
    pub fn is_zero(&self) -> bool {
        let r = self.reduce();
        r.0[0] == 0 && r.0[1] == 0 && r.0[2] == 0 && r.0[3] == 0 && r.0[4] == 0
    }
}

impl PartialEq for Fe25519 {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.to_bytes().ct_eq(&other.to_bytes()).into()
    }
}

impl Eq for Fe25519 {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_one() {
        let z = Fe25519::zero();
        let o = Fe25519::one();
        assert!(z.is_zero());
        assert!(!o.is_zero());
    }

    #[test]
    fn test_add_sub_roundtrip() {
        let a = Fe25519([1234567, 2345678, 3456789, 4567890, 5678901]);
        let b = Fe25519([9876543, 8765432, 7654321, 6543210, 5432109]);
        let c = a.add(&b);
        let d = c.sub(&b);
        assert_eq!(a.to_bytes(), d.to_bytes());
    }

    #[test]
    fn test_mul_one_identity() {
        let a = Fe25519([123456789, 987654321, 111111111, 222222222, 333333333]);
        let one = Fe25519::one();
        let b = a.mul(&one);
        assert_eq!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn test_mul_square_consistency() {
        let a = Fe25519([12345, 67890, 11111, 22222, 33333]);
        let sq = a.square();
        let mul_self = a.mul(&a);
        assert_eq!(sq.to_bytes(), mul_self.to_bytes());
    }

    #[test]
    fn test_invert() {
        let a = Fe25519([42, 0, 0, 0, 0]);
        let a_inv = a.invert();
        let product = a.mul(&a_inv);
        assert_eq!(product.to_bytes(), Fe25519::one().to_bytes());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let a = Fe25519([
            0x123456789abcd,
            0x23456789abcde,
            0x3456789abcdef,
            0x456789abcdef0,
            0x56789abcdef01,
        ]);
        let bytes = a.to_bytes();
        let b = Fe25519::from_bytes(&bytes);
        assert_eq!(a.reduce().to_bytes(), b.to_bytes());
    }

    #[test]
    fn test_conditional_swap() {
        let mut a = Fe25519([1, 0, 0, 0, 0]);
        let mut b = Fe25519([2, 0, 0, 0, 0]);

        // swap = 0: no swap
        a.conditional_swap(&mut b, 0);
        assert_eq!(a.0[0], 1);
        assert_eq!(b.0[0], 2);

        // swap = 1: swap
        a.conditional_swap(&mut b, 1);
        assert_eq!(a.0[0], 2);
        assert_eq!(b.0[0], 1);
    }
}
