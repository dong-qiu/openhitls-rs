//! Field arithmetic over GF(2^448 − 2^224 − 1) using 16×28-bit limb representation.
//!
//! The prime p = 2^448 − 2^224 − 1 is the "Goldilocks" prime, which allows
//! efficient reduction via the identity 2^448 ≡ 2^224 + 1 (mod p).

/// A field element in GF(p) where p = 2^448 − 2^224 − 1.
///
/// Stored in radix-2^28 representation: value = Σ l[i] × 2^(28i), i=0..15.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Fe448(pub(crate) [u32; 16]);

const LIMB_BITS: u32 = 28;
const MASK28: u32 = (1u32 << 28) - 1;

impl Fe448 {
    /// The zero element.
    pub fn zero() -> Self {
        Fe448([0; 16])
    }

    /// The one element.
    pub fn one() -> Self {
        let mut r = [0u32; 16];
        r[0] = 1;
        Fe448(r)
    }

    /// Addition: h = f + g.
    pub fn add(&self, rhs: &Fe448) -> Fe448 {
        let mut r = [0u32; 16];
        for (i, ri) in r.iter_mut().enumerate() {
            *ri = self.0[i] + rhs.0[i];
        }
        Fe448(r).carry()
    }

    /// Subtraction: h = f - g.
    /// Add 2*p to avoid underflow before carry propagation.
    pub fn sub(&self, rhs: &Fe448) -> Fe448 {
        // 2*p in 16×28-bit limbs:
        // p = 2^448 − 2^224 − 1
        // In limb form, p has all limbs = 2^28 - 1 = MASK28, except:
        //   limb 0 has MASK28 - 1 + 1 ... actually let me compute carefully.
        // p = 2^448 - 2^224 - 1
        // In base 2^28, limb i represents bits [28i, 28(i+1)).
        // 2^224 = 2^(28*8), so it affects limb 8.
        // 2^448 = 2^(28*16), which overflows beyond our 16 limbs.
        // p = (2^448 - 1) - 2^224
        //   = (all 1s in 448 bits) - 2^224
        // All limbs of (2^448 - 1) are MASK28.
        // Subtracting 2^224: limb 8 -= 1.
        // So p[i] = MASK28 for i != 8, p[8] = MASK28 - 1.
        // 2*p[i] = 2*MASK28 for i != 8, 2*p[8] = 2*(MASK28 - 1).

        let two_p_normal = 2 * MASK28;
        let two_p_8 = 2 * (MASK28 - 1);

        let mut r = [0u64; 16];
        for (i, ri) in r.iter_mut().enumerate() {
            let bias = if i == 8 { two_p_8 } else { two_p_normal };
            *ri = (self.0[i] as u64 + bias as u64) - rhs.0[i] as u64;
        }

        // Carry propagate
        let mut out = [0u32; 16];
        let mut carry = 0i64;
        for i in 0..16 {
            let val = r[i] as i64 + carry;
            out[i] = (val as u32) & MASK28;
            carry = val >> LIMB_BITS;
        }
        // Wrap carry: top carry goes to limb 0 (× 1) and limb 8 (× 1)
        // because 2^448 ≡ 2^224 + 1 (mod p)
        let val = out[0] as i64 + carry;
        out[0] = (val as u32) & MASK28;
        let carry2 = val >> LIMB_BITS;
        out[1] = ((out[1] as i64) + carry2) as u32;

        let val = out[8] as i64 + carry;
        out[8] = (val as u32) & MASK28;
        let carry2 = val >> LIMB_BITS;
        out[9] = ((out[9] as i64) + carry2) as u32;

        Fe448(out)
    }

    /// Negation: h = -f (mod p).
    pub fn neg(&self) -> Fe448 {
        Fe448::zero().sub(self)
    }

    /// Multiplication: h = f * g using Goldilocks Karatsuba.
    ///
    /// Exploits the structure p = 2^448 − 2^224 − 1 by splitting each operand
    /// into two 224-bit halves and using the identity 2^448 ≡ 2^224 + 1.
    pub fn mul(&self, rhs: &Fe448) -> Fe448 {
        // Split: f = f_lo + f_hi * 2^224, g = g_lo + g_hi * 2^224
        // where f_lo, f_hi, g_lo, g_hi are 8-limb (224-bit) values.
        //
        // f * g = f_lo*g_lo + (f_lo*g_hi + f_hi*g_lo)*2^224 + f_hi*g_hi*2^448
        // Since 2^448 ≡ 2^224 + 1:
        // f * g ≡ (f_lo*g_lo + f_hi*g_hi) + (f_lo*g_hi + f_hi*g_lo + f_hi*g_hi)*2^224

        let f = &self.0;
        let g = &rhs.0;

        // Compute partial products in u64 accumulators
        let mut lo_lo = [0u64; 15]; // f_lo * g_lo (8×8 schoolbook)
        let mut hi_hi = [0u64; 15]; // f_hi * g_hi
        let mut lo_hi = [0u64; 15]; // f_lo * g_hi
        let mut hi_lo = [0u64; 15]; // f_hi * g_lo

        for i in 0..8 {
            for j in 0..8 {
                lo_lo[i + j] += f[i] as u64 * g[j] as u64;
                hi_hi[i + j] += f[i + 8] as u64 * g[j + 8] as u64;
                lo_hi[i + j] += f[i] as u64 * g[j + 8] as u64;
                hi_lo[i + j] += f[i + 8] as u64 * g[j] as u64;
            }
        }

        // Combine: result = (lo_lo + hi_hi) + (lo_hi + hi_lo + hi_hi) * 2^224
        // In limb terms: limb i gets (lo_lo + hi_hi)[i] and limb (i+8) gets cross terms
        let mut acc = [0u64; 16];

        // Add lo_lo[0..15] to acc[0..15]
        for i in 0..15 {
            acc[i % 16] += lo_lo[i];
        }

        // Add hi_hi[0..15] to acc[0..15] (contributes to low half due to 2^448 ≡ 2^224+1)
        for i in 0..15 {
            acc[i % 16] += hi_hi[i];
        }

        // Add (lo_hi + hi_lo + hi_hi)[0..15] shifted by 8 limbs (× 2^224)
        for i in 0..15 {
            let cross = lo_hi[i] + hi_lo[i] + hi_hi[i];
            let target = (i + 8) % 16;
            acc[target] += cross;
            // If i + 8 >= 16, we've wrapped around past 2^448, so also add to (target + 8)
            // because 2^448 ≡ 2^224 + 1
            if i + 8 >= 16 {
                acc[(target + 8) % 16] += cross;
                acc[target % 16] += cross; // already added above, need to fix
                                           // Actually, let me redo this more carefully.
            }
        }

        // The above logic is getting complex. Let me use a cleaner approach:
        // Build a 32-limb product, then reduce.
        Self::mul_and_reduce(f, g)
    }

    /// Full 32-limb schoolbook multiply followed by Goldilocks reduction.
    fn mul_and_reduce(f: &[u32; 16], g: &[u32; 16]) -> Fe448 {
        // Schoolbook: 16×16 → 31 limbs of partial sums in u64
        let mut prod = [0u64; 31];
        for i in 0..16 {
            for j in 0..16 {
                prod[i + j] += f[i] as u64 * g[j] as u64;
            }
        }

        // Reduce: 2^448 ≡ 2^224 + 1 (mod p).
        // Limb 16 corresponds to 2^(28*16) = 2^448 ≡ 2^224 + 1.
        // So prod[16+k] * 2^(28*(16+k)) ≡ prod[16+k] * (2^(28*(8+k)) + 2^(28*k)).
        // In other words, fold prod[16..30] into prod[0..14] and prod[8..22].
        let mut acc = [0u64; 16];
        for i in 0..16 {
            acc[i] += prod[i];
        }
        for i in 0..15 {
            // prod[16+i] folds to limb i (×1) and limb i+8 (×1)
            acc[i] += prod[16 + i];
            acc[(i + 8) % 16] += prod[16 + i];
            // When i+8 >= 16 (i.e., i >= 8), we wrap again: limb (i+8-16)
            // gets an additional fold due to 2^(28*(i+8)) with i+8 >= 16
            // means 2^(448 + 28*(i-8)) which again ≡ 2^(224+28*(i-8)) + 2^(28*(i-8)).
            // But (i+8)%16 = i-8 when i>=8, and we already added to acc[i-8].
            // The second fold: when i+8>=16, also add to acc[(i+8-16)+8] = acc[i].
            // But that's acc[i] which already has prod[16+i]. We need to also add
            // to acc[i] again? No — let me think more carefully.
            //
            // For i < 8: target = i and i+8. Both < 16. Fine.
            // For i >= 8: (i+8)%16 = i-8 < 8. So we add to acc[i] and acc[i-8].
            // But wait: when i >= 8, prod[16+i] * 2^(28*(16+i)) maps to:
            //   2^(28*(16+i)) = 2^448 * 2^(28*i) ≡ (2^224 + 1) * 2^(28*i)
            //     = 2^(28*(i+8)) + 2^(28*i)
            //   Now 2^(28*(i+8)): when i+8 >= 16 (i >= 8):
            //     2^(28*(i+8)) = 2^(28*16) * 2^(28*(i-8)) = 2^448 * 2^(28*(i-8))
            //     ≡ (2^224 + 1) * 2^(28*(i-8)) = 2^(28*(i-8+8)) + 2^(28*(i-8))
            //     = 2^(28*i) + 2^(28*(i-8))
            //   So total: 2^(28*i) + 2^(28*(i-8)) + 2^(28*i) = 2*2^(28*i) + 2^(28*(i-8))
            //
            // So for i >= 8: prod[16+i] contributes:
            //   2× to acc[i] and 1× to acc[i-8]
            // For i < 8: prod[16+i] contributes:
            //   1× to acc[i] and 1× to acc[i+8]
            if i >= 8 {
                // We already added 1× to acc[i] and 1× to acc[i-8] above.
                // Need one more × to acc[i].
                acc[i] += prod[16 + i];
            }
        }

        // Carry propagate with Goldilocks folding
        Self::carry_wide(&mut acc)
    }

    /// Carry propagate a 16-limb u64 accumulator, folding overflow via Goldilocks.
    fn carry_wide(acc: &mut [u64; 16]) -> Fe448 {
        let mut r = [0u32; 16];

        // First pass: propagate carries linearly
        let mut carry: u64 = 0;
        for i in 0..16 {
            let val = acc[i] + carry;
            r[i] = (val as u32) & MASK28;
            carry = val >> LIMB_BITS;
        }

        // Top carry folds back: 2^448 ≡ 2^224 + 1
        // carry * 2^448 ≡ carry * (2^224 + 1) = carry * 2^(28*8) + carry
        let c = carry;
        let val = r[0] as u64 + c;
        r[0] = (val as u32) & MASK28;
        let mut c2 = val >> LIMB_BITS;
        // Propagate carry through limbs 1..7
        for limb in r.iter_mut().take(8).skip(1) {
            let val = *limb as u64 + c2;
            *limb = (val as u32) & MASK28;
            c2 = val >> LIMB_BITS;
            if c2 == 0 {
                break;
            }
        }

        let val = r[8] as u64 + c + c2;
        r[8] = (val as u32) & MASK28;
        let mut c3 = val >> LIMB_BITS;
        for limb in r.iter_mut().take(16).skip(9) {
            let val = *limb as u64 + c3;
            *limb = (val as u32) & MASK28;
            c3 = val >> LIMB_BITS;
            if c3 == 0 {
                break;
            }
        }

        // If there's still carry, do one more fold (extremely unlikely)
        if c3 > 0 {
            let val = r[0] as u64 + c3;
            r[0] = (val as u32) & MASK28;
            let val = r[8] as u64 + c3;
            r[8] = (val as u32) & MASK28;
        }

        Fe448(r)
    }

    /// Squaring: h = f^2 (slightly optimized by exploiting symmetry).
    pub fn square(&self) -> Fe448 {
        let f = &self.0;

        // Schoolbook with doubled cross-terms
        let mut prod = [0u64; 31];
        for i in 0..16 {
            prod[2 * i] += f[i] as u64 * f[i] as u64;
            for j in (i + 1)..16 {
                prod[i + j] += 2 * (f[i] as u64 * f[j] as u64);
            }
        }

        // Same reduction as mul
        let mut acc = [0u64; 16];
        for i in 0..16 {
            acc[i] += prod[i];
        }
        for i in 0..15 {
            acc[i] += prod[16 + i];
            acc[(i + 8) % 16] += prod[16 + i];
            if i >= 8 {
                acc[i] += prod[16 + i];
            }
        }

        Self::carry_wide(&mut acc)
    }

    /// Multiply by a small constant: h = f * c.
    pub fn mul_small(&self, c: u32) -> Fe448 {
        let mut acc = [0u64; 16];
        for (i, a) in acc.iter_mut().enumerate() {
            *a = self.0[i] as u64 * c as u64;
        }
        Self::carry_wide(&mut acc)
    }

    /// Carry propagation for u32 limbs.
    fn carry(&self) -> Fe448 {
        let mut r = self.0;

        // Linear carry propagation
        for i in 0..15 {
            let c = r[i] >> LIMB_BITS;
            r[i] &= MASK28;
            r[i + 1] += c;
        }
        let c = r[15] >> LIMB_BITS;
        r[15] &= MASK28;

        // Goldilocks fold: 2^448 ≡ 2^224 + 1
        r[0] += c;
        r[8] += c;

        // One more carry if needed
        for i in 0..15 {
            let c = r[i] >> LIMB_BITS;
            r[i] &= MASK28;
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

        // Subtracting p is equivalent to adding (1 + 2^224) and subtracting 2^448.
        // If (r + 1 + 2^224) overflows 448 bits, then r >= p, and the lower 448 bits
        // of the sum equal r - p.

        let mut test = [0u64; 16];
        for i in 0..16 {
            test[i] = r[i] as u64;
        }
        test[0] += 1;
        test[8] += 1;

        // Propagate carries
        for i in 0..15 {
            test[i + 1] += test[i] >> LIMB_BITS;
            test[i] &= MASK28 as u64;
        }
        let overflow = test[15] >> LIMB_BITS;
        test[15] &= MASK28 as u64;

        // If overflow > 0, r >= p. Use test (which is r - p).
        if overflow > 0 {
            for i in 0..16 {
                r[i] = test[i] as u32;
            }
        }

        Fe448(r)
    }

    /// Modular inversion: h = f^(p−2) mod p using Fermat's little theorem.
    ///
    /// Uses an addition chain for p − 2 = 2^448 − 2^224 − 3.
    pub fn invert(&self) -> Fe448 {
        // p - 2 = 2^448 - 2^224 - 3
        // = (2^224 - 1) * 2^224 + (2^224 - 3)
        // Strategy: build up powers using repeated squaring.

        let x1 = *self; // x
        let x2 = x1.square().mul(&x1); // x^3
        let x3 = x2.square().mul(&x1); // x^7
        let x6 = {
            let mut t = x3;
            for _ in 0..3 {
                t = t.square();
            }
            t.mul(&x3)
        }; // x^(2^6 - 1)
        let x12 = {
            let mut t = x6;
            for _ in 0..6 {
                t = t.square();
            }
            t.mul(&x6)
        }; // x^(2^12 - 1)
        let x24 = {
            let mut t = x12;
            for _ in 0..12 {
                t = t.square();
            }
            t.mul(&x12)
        }; // x^(2^24 - 1)
        let x48 = {
            let mut t = x24;
            for _ in 0..24 {
                t = t.square();
            }
            t.mul(&x24)
        }; // x^(2^48 - 1)
        let x96 = {
            let mut t = x48;
            for _ in 0..48 {
                t = t.square();
            }
            t.mul(&x48)
        }; // x^(2^96 - 1)
        let x192 = {
            let mut t = x96;
            for _ in 0..96 {
                t = t.square();
            }
            t.mul(&x96)
        }; // x^(2^192 - 1)

        // x^(2^224 - 1)
        let x224_m1 = {
            let mut t = x192;
            for _ in 0..32 {
                t = t.square();
            }
            // Need x^(2^32 - 1) to multiply in
            let x32 = {
                let mut s = x24;
                for _ in 0..8 {
                    s = s.square();
                }
                s.mul(&{
                    let mut s2 = x3;
                    for _ in 0..5 {
                        s2 = s2.square();
                    }
                    s2.mul(&x3).square().square().mul(&x1)
                })
            };
            t.mul(&x32)
        };

        // Actually, let me use a simpler addition chain.
        // p - 2 = 2^448 - 2^224 - 3
        // = (2^224 - 1) * (2^224 + 1) - 2
        // Hmm, let me just compute x^(2^224-1), then use it.

        // x^(2^224-1) is what we need.
        // Then x^((2^224-1)*2^224) = x^(2^448 - 2^224)
        // And x^(2^448 - 2^224 - 3) = x^(2^448 - 2^224) * x^(-3)
        // No, that won't work. Let me use a different approach.

        // p - 2 = 2^448 - 2^224 - 3
        // Binary of p-2: 224 ones, then 223 ones, then 01 (i.e., ...11111101)
        // Actually: p = 2^448 - 2^224 - 1
        //   = 1...1 0...0 1...1  (224 ones, 224 bits where top is 0 and rest are 1)
        //   Actually: 2^448 - 1 = 448 ones
        //   Subtract 2^224: clear bit 224 and borrow
        //   = bits[447..225] = all 1s (223 bits), bit[224] = 0,
        //     minus borrow through: 2^448 - 1 - 2^224
        //     = (2^224 - 1) * 2^224 + (2^224 - 1)
        //     Hmm: 2^448 - 2^224 - 1 = (2^224 - 1) << 224 | (2^224 - 1)
        //     No: (2^224 - 1) * 2^224 = 2^448 - 2^224
        //     2^448 - 2^224 - 1 = (2^224 - 1)*2^224 + 2^224 - 1 - ... no.
        //     2^448 - 2^224 - 1 = let's think in binary:
        //       2^448 - 1 = 448 ones
        //       subtract 2^224: borrow chain...
        //       = bits 447..225 all 1 (223 ones), bit 224 = 0, bits 223..0 all 1 (224 ones)
        //     So p = 0xFFFFFFFF...FE...FFFFFFFF (223 F nibbles, then E, then 224/4=56 F nibbles)
        //
        //   p - 2 = p minus 2 in binary:
        //     bit 0 was 1, becomes 1-2 = borrow: bit 0 = 1, bit 1 was 1, becomes 0. Done.
        //     So p-2 in binary: bits 447..2 same as p, bit 1 = 0, bit 0 = 1.
        //     = 223 ones, 0, 222 ones, 0, 1
        //     Nope let me just verify:
        //     p   = ...1111 0 1111...1111 1
        //     p-2 = ...1111 0 1111...1111 01  (bit 1 cleared)
        //     So p-2 = ...1111 0 1111...1101
        //     Bits from MSB: 223 ones, one 0, 220 ones, one 0, one 1
        //
        // Given the complexity, let me just use a clean square-and-multiply chain.

        self.pow_p_minus_2()
    }

    /// Compute self^(p-2) for inversion.
    fn pow_p_minus_2(&self) -> Fe448 {
        // p - 2 = 2^448 - 2^224 - 3
        // Let's compute using repeated squaring with a clean chain.
        //
        // Strategy: Compute x^(2^k - 1) for various k, then combine.
        // x^1 = self
        let a = *self;
        let a2 = a.square(); // a^2
        let a3 = a2.mul(&a); // a^3
        let a6 = a3.square(); // a^6
        let a7 = a6.mul(&a); // a^7
        let a8 = a7.mul(&a); // a^8 (= 2^3)

        // a^(2^4 - 1) = a^15
        let a15 = {
            let mut t = a8;
            t = t.square(); // a^16
            t.mul(&a7) // a^(16-1) ... no, a^(16+7) = a^23. Wrong.
        };
        // Let me be more careful with addition chains for (2^k - 1).

        // x^(2^2 - 1) = x^3 = a3
        // x^(2^3 - 1) = x^7 = a7
        // x^(2^6 - 1): square a7 three times → a^(7*8) = a^56, mul by a7 → a^63 = 2^6 - 1
        let a_6 = {
            let mut t = a7;
            for _ in 0..3 {
                t = t.square();
            }
            t.mul(&a7)
        };
        // x^(2^12 - 1)
        let a_12 = {
            let mut t = a_6;
            for _ in 0..6 {
                t = t.square();
            }
            t.mul(&a_6)
        };
        // x^(2^24 - 1)
        let a_24 = {
            let mut t = a_12;
            for _ in 0..12 {
                t = t.square();
            }
            t.mul(&a_12)
        };
        // x^(2^48 - 1)
        let a_48 = {
            let mut t = a_24;
            for _ in 0..24 {
                t = t.square();
            }
            t.mul(&a_24)
        };
        // x^(2^96 - 1)
        let a_96 = {
            let mut t = a_48;
            for _ in 0..48 {
                t = t.square();
            }
            t.mul(&a_48)
        };
        // x^(2^192 - 1)
        let a_192 = {
            let mut t = a_96;
            for _ in 0..96 {
                t = t.square();
            }
            t.mul(&a_96)
        };
        // x^(2^222 - 1)
        let a_222 = {
            let mut t = a_192;
            // Need 30 more squarings then mul by x^(2^30-1)
            for _ in 0..24 {
                t = t.square();
            }
            t = t.mul(&a_24);
            for _ in 0..6 {
                t = t.square();
            }
            t.mul(&a_6)
        };

        // Now build p - 2 = 2^448 - 2^224 - 3
        // In binary (from MSB, 448 bits total):
        //   bits 447..225: all 1 (223 ones)
        //   bit 224: 0
        //   bits 223..2: all 1 (222 ones)
        //   bit 1: 0
        //   bit 0: 1
        //
        // So: x^(p-2) = x^(2^448 - 2^224 - 3)
        //
        // Start with x^(2^222 - 1) [covers the 222 ones at bits 223..2]
        //
        // Actually, let's build from MSB:
        // We need exponent = (2^223 - 1) * 2^225 + (2^222 - 1) * 4 + 1
        // = (2^223 - 1) * 2^225 + 2^224 - 4 + 1
        // = (2^223 - 1) * 2^225 + 2^224 - 3
        // Verify: (2^223 - 1) * 2^225 = 2^448 - 2^225
        //         + 2^224 = 2^448 - 2^225 + 2^224 = 2^448 - 2^224
        //         - 3: 2^448 - 2^224 - 3 ✓
        //
        // So we need:
        // t = x^(2^223 - 1)
        // t = t^(2^225) [225 squarings]
        // t = t * x^(2^224 - 3)
        //
        // x^(2^223 - 1) = x^(2^222-1) * x^(2^222) * x ... no
        //   = square(x^(2^222-1)) * x = x^(2^223 - 2) * x = x^(2^223 - 1) ✓
        let a_223 = a_222.square().mul(&a); // x^(2^223 - 1)

        // Now 225 squarings
        let mut t = a_223;
        for _ in 0..225 {
            t = t.square();
        }
        // t = x^((2^223 - 1) * 2^225)

        // Now multiply by x^(2^224 - 3)
        // 2^224 - 3 = 2^224 - 4 + 1 = (2^222 - 1) * 4 + 1
        // x^(2^222-1) squared twice: x^((2^222-1)*4) = x^(2^224-4)
        // times x: x^(2^224-3)
        let tail = a_222.square().square().mul(&a); // x^(2^224 - 3)

        t.mul(&tail) // x^(p-2)
    }

    /// Compute sqrt(self) = self^((p+1)/4) mod p.
    /// Since p ≡ 3 (mod 4), this works directly.
    pub fn sqrt(&self) -> Fe448 {
        // (p+1)/4 = (2^448 - 2^224) / 4 = 2^446 - 2^222
        // So we need x^(2^446 - 2^222)
        // = x^(2^222 * (2^224 - 1))
        // = (x^(2^224 - 1))^(2^222)

        // Build x^(2^224 - 1) using addition chain
        let a = *self;
        let a3 = a.square().mul(&a);
        let a7 = a3.square().mul(&a);
        let a_6 = {
            let mut t = a7;
            for _ in 0..3 {
                t = t.square();
            }
            t.mul(&a7)
        };
        let a_12 = {
            let mut t = a_6;
            for _ in 0..6 {
                t = t.square();
            }
            t.mul(&a_6)
        };
        let a_24 = {
            let mut t = a_12;
            for _ in 0..12 {
                t = t.square();
            }
            t.mul(&a_12)
        };
        let a_48 = {
            let mut t = a_24;
            for _ in 0..24 {
                t = t.square();
            }
            t.mul(&a_24)
        };
        let a_96 = {
            let mut t = a_48;
            for _ in 0..48 {
                t = t.square();
            }
            t.mul(&a_48)
        };
        let a_192 = {
            let mut t = a_96;
            for _ in 0..96 {
                t = t.square();
            }
            t.mul(&a_96)
        };
        // x^(2^222 - 1)
        let a_222 = {
            let mut t = a_192;
            for _ in 0..24 {
                t = t.square();
            }
            t = t.mul(&a_24);
            for _ in 0..6 {
                t = t.square();
            }
            t.mul(&a_6)
        };
        // x^(2^224 - 1) = x^(2^222-1) * 4 then * x^3
        // Actually: x^(2^224 - 1) = (x^(2^222 - 1))^4 * x^3 = x^(4*(2^222-1)+3) = x^(2^224-1) ✓
        let a_224 = a_222.square().square().mul(&a3);

        // Now square 222 times: (x^(2^224-1))^(2^222) = x^((2^224-1)*2^222) = x^(2^446 - 2^222)
        let mut t = a_224;
        for _ in 0..222 {
            t = t.square();
        }
        t
    }

    /// Decode a 56-byte little-endian representation into a field element.
    pub fn from_bytes(bytes: &[u8; 56]) -> Fe448 {
        // Each limb is 28 bits = 3.5 bytes. Pack from LE bytes.
        let mut r = [0u32; 16];
        #[allow(clippy::needless_range_loop)]
        for i in 0..16 {
            // Limb i covers bits [28*i, 28*(i+1)).
            // Byte-level: bit 28*i starts at byte (28*i)/8 = 3.5*i
            let bit_start = 28 * i;
            let byte_start = bit_start / 8;
            let bit_offset = bit_start % 8;

            // Read 4 bytes (enough for 28 + bit_offset bits)
            let mut val = 0u32;
            for j in 0..4 {
                let idx = byte_start + j;
                if idx < 56 {
                    val |= (bytes[idx] as u32) << (j * 8);
                }
            }
            r[i] = (val >> bit_offset) & MASK28;
        }
        Fe448(r)
    }

    /// Encode a field element to a 56-byte little-endian representation.
    pub fn to_bytes(self) -> [u8; 56] {
        let h = self.reduce().0;
        let mut out = [0u8; 56];

        // Pack 16 × 28-bit limbs into 448 bits (56 bytes, LE).
        #[allow(clippy::needless_range_loop)]
        for i in 0..16 {
            let bit_start = 28 * i;
            let byte_start = bit_start / 8;
            let bit_offset = bit_start % 8;

            let val = (h[i] as u64) << bit_offset;
            for j in 0..4 {
                let idx = byte_start + j;
                if idx < 56 {
                    out[idx] |= (val >> (j * 8)) as u8;
                }
            }
        }

        out
    }

    /// Constant-time conditional swap: swap self and other if swap == 1.
    pub fn conditional_swap(&mut self, other: &mut Fe448, swap: u8) {
        let mask = (-(swap as i32)) as u32;
        for i in 0..16 {
            let t = mask & (self.0[i] ^ other.0[i]);
            self.0[i] ^= t;
            other.0[i] ^= t;
        }
    }

    /// Returns 1 if the field element is negative (LSB of canonical encoding is 1), 0 otherwise.
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
        // Ensure top bits are below p (should be fine for small values)
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
        // In limbs: all MASK28, except limb 8 is MASK28 - 1
        let mut p_limbs = [MASK28; 16];
        p_limbs[8] = MASK28 - 1;
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
}
