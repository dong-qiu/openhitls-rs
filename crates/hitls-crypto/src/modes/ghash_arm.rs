//! Hardware-accelerated GHASH implementation using ARMv8 PMULL (polynomial multiply).
//!
//! This module provides a single-block GHASH multiply function that leverages the
//! ARMv8 Cryptography Extensions `PMULL`/`PMULL2` instructions (carry-less multiply)
//! to perform GF(2^128) multiplication. On ARMv8 targets, the PMULL instructions
//! share the `aes` feature flag (FEAT_AES implies FEAT_PMULL).
//!
//! The GHASH universal hash function is defined in NIST SP 800-38D (GCM specification).
//! It operates in GF(2^128) with the irreducible polynomial:
//!
//!   P(x) = x^128 + x^7 + x^2 + x + 1
//!
//! GHASH uses the "reflected" bit-order convention: the most significant bit of each
//! byte is the coefficient of the lowest-degree polynomial term.
//!
//! # Algorithm
//!
//! The implementation converts inputs from GHASH's reflected convention to the
//! natural polynomial convention using `vrbitq_u8` (bit-reverse within each byte),
//! performs Karatsuba carry-less multiplication using `vmull_p64`, reduces the
//! 256-bit product modulo the GHASH polynomial, and converts back.
//!
//! After `vrbitq_u8`, bit k of each u64 lane directly corresponds to the coefficient
//! of x^k in the polynomial, which is exactly what `vmull_p64` expects:
//!   - lane 0: coefficients x^0 through x^63
//!   - lane 1: coefficients x^64 through x^127
//!
//! # Safety
//!
//! The public function requires the `aes` target feature (which implies PMULL support
//! on ARMv8). Callers must verify CPU support at runtime via
//! `std::arch::is_aarch64_feature_detected!("aes")` before invoking `ghash_block_arm`.

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

/// Hardware-accelerated GHASH block multiply using ARMv8 PMULL.
///
/// Computes: `state = (state XOR block) * H` in GF(2^128).
///
/// The inputs `h`, `state`, and `block` are all 16-byte arrays in big-endian byte
/// order (the standard GHASH wire format). Internally, the function handles the
/// reflected bit-order conversion required by the polynomial multiplication.
///
/// # Safety
///
/// This function uses ARMv8 NEON and PMULL intrinsics. The caller **must** ensure
/// the CPU supports the `aes` feature (which implies PMULL on ARMv8) before calling.
/// Verify with `std::arch::is_aarch64_feature_detected!("aes")`.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes")]
pub(super) unsafe fn ghash_block_arm(h: &[u8; 16], state: &mut [u8; 16], block: &[u8; 16]) {
    // SAFETY: caller guarantees CPU feature availability (aes/PMULL + neon).
    unsafe {
        // ---------------------------------------------------------------
        // Load and convert from GHASH reflected convention to natural polynomial.
        //
        // GHASH stores data in big-endian with the MSB of each byte as the
        // lowest-degree coefficient. vrbitq_u8 reverses bits within each byte,
        // converting to the convention where LSB = lowest degree, which is
        // exactly what vmull_p64 expects.
        //
        // After vrbitq_u8 and extracting u64 lanes (ARM little-endian):
        //   lane 0 (bytes 0-7): bit k = coefficient of x^k (k = 0..63)
        //   lane 1 (bytes 8-15): bit k = coefficient of x^(64+k) (k = 0..63)
        //
        // Full polynomial: a(x) = lane1 * x^64 + lane0
        // ---------------------------------------------------------------

        let h_be = vld1q_u8(h.as_ptr());
        let h_val = vrbitq_u8(h_be);

        let s_be = vld1q_u8(state.as_ptr());
        let b_be = vld1q_u8(block.as_ptr());
        let xor_be = veorq_u8(s_be, b_be);
        let x_val = vrbitq_u8(xor_be);

        // Extract 64-bit halves.
        let x_u64 = vreinterpretq_u64_u8(x_val);
        let h_u64 = vreinterpretq_u64_u8(h_val);

        let x_lo: u64 = vgetq_lane_u64(x_u64, 0); // x^0..x^63
        let x_hi: u64 = vgetq_lane_u64(x_u64, 1); // x^64..x^127
        let h_lo: u64 = vgetq_lane_u64(h_u64, 0);
        let h_hi: u64 = vgetq_lane_u64(h_u64, 1);

        // ---------------------------------------------------------------
        // Karatsuba carry-less multiplication
        //
        // Product of (x_hi*x^64 + x_lo) * (h_hi*x^64 + h_lo):
        //   p_hh = x_hi * h_hi                    (high * high, degree up to 126)
        //   p_ll = x_lo * h_lo                     (low * low, degree up to 126)
        //   p_mid = (x_hi ^ x_lo) * (h_hi ^ h_lo) (cross term)
        //   mid = p_mid ^ p_hh ^ p_ll
        //
        // 256-bit result: p_hh * x^128 + mid * x^64 + p_ll
        // ---------------------------------------------------------------
        let p_hh = vmull_p64(x_hi, h_hi);
        let p_ll = vmull_p64(x_lo, h_lo);
        let p_mid = vmull_p64(x_hi ^ x_lo, h_hi ^ h_lo);

        let hh_u8 = vreinterpretq_u8_p128(p_hh);
        let ll_u8 = vreinterpretq_u8_p128(p_ll);
        let mid_u8 = vreinterpretq_u8_p128(p_mid);

        let mid = veorq_u8(veorq_u8(mid_u8, hh_u8), ll_u8);

        // Assemble into two 128-bit halves:
        //   high_128 = upper 128 bits of the 256-bit product
        //   low_128 = lower 128 bits
        let zero = vdupq_n_u8(0);
        let mid_r64 = vextq_u8(mid, zero, 8); // mid >> 64
        let mid_l64 = vextq_u8(zero, mid, 8); // mid << 64

        let high_128 = veorq_u8(hh_u8, mid_r64);
        let low_128 = veorq_u8(ll_u8, mid_l64);

        // ---------------------------------------------------------------
        // Reduction modulo P(x) = x^128 + x^7 + x^2 + x + 1
        //
        // In the natural polynomial domain (after vrbitq_u8), the reduction
        // constant is q(x) = x^7 + x^2 + x + 1 = 0x87 (as u64).
        //
        // We need to reduce the 256-bit product [high_128 : low_128] mod P.
        // Since x^128 ≡ q(x) mod P, we have:
        //   high_128 * x^128 ≡ high_128 * q(x) mod P
        //
        // But high_128 * q(x) is at most degree 127 + 7 = 134, so bits 128-134
        // need a second reduction pass.
        //
        // The two-phase PMULL reduction works by exploiting the polynomial structure:
        //
        // Phase 1: Reduce the HIGH 128 bits.
        //   We compute high_128 * q(x) using two pmull operations (one for each 64-bit
        //   half of high_128), accumulate into the low part, and handle overflow.
        //
        // Actually, for the natural-order polynomial, we use the "schoolbook" reduction:
        //   result = low_128 ^ (high_128_lo * q) ^ ((high_128_hi * q) << 64)
        //   with any overflow from high_128_hi * q >= x^128 handled by another pass.
        //
        // Since q = 0x87 has degree 7, high_128_hi (degree up to 63) * q has degree
        // up to 70, which when shifted left by 64 gives degree up to 134. Bits 128-134
        // need one more reduction: those 7 bits times q (degree 7) = degree 14, which
        // fits in 128 bits.
        //
        // Two-pass approach:
        //   1. r = low_128 ^ pmull(high_lo, q) ^ (pmull(high_hi, q) << 64)
        //   2. overflow = pmull(high_hi, q) >> 64  (the bits that overflowed x^128)
        //   3. result = r ^ pmull(overflow, q)  (but overflow is at most 7 bits, so this fits)
        //
        // Alternative: use the standard swap-based two-phase reduction.
        // For the natural order, the reduction polynomial's "high" part is zero
        // (all terms are below degree 8), so we need a different strategy than
        // the reflected-domain approach.
        //
        // Let's use explicit reduction:
        // ---------------------------------------------------------------

        // Extract 64-bit halves of high_128 and low_128
        let high_u64 = vreinterpretq_u64_u8(high_128);
        let low_u64 = vreinterpretq_u64_u8(low_128);

        let high_lo: u64 = vgetq_lane_u64(high_u64, 0); // bits 128-191 of the 256-bit product
        let high_hi: u64 = vgetq_lane_u64(high_u64, 1); // bits 192-255

        let q: u64 = 0x87; // x^7 + x^2 + x + 1

        // First reduction: high_lo * q (degree up to 63+7=70, fits in 128 bits)
        let r1 = vmull_p64(high_lo, q);
        // This contributes to bits 0-70 of the result

        // Second reduction: high_hi * q (degree up to 63+7=70, fits in 128 bits)
        // But this is shifted left by 64, so it contributes to bits 64-134
        let r2 = vmull_p64(high_hi, q);
        let r2_u8 = vreinterpretq_u8_p128(r2);

        // r2 shifted left by 64: bits 64-134
        // The bits 128-134 (= r2 bits 64-70, i.e., r2's lane 1 bits 0-6) need further reduction
        let r2_shifted = vextq_u8(zero, r2_u8, 8); // r2 << 64 (low 64 bits of r2 go to lane 1)

        // Combine: intermediate = low_128 ^ r1 ^ r2_shifted
        let r1_u8 = vreinterpretq_u8_p128(r1);
        let intermediate = veorq_u8(veorq_u8(low_128, r1_u8), r2_shifted);

        // Now handle overflow: bits 128+ from r2 << 64
        // r2's lane 1 (bits 64-70 of r2 result) is the overflow
        let r2_u64 = vreinterpretq_u64_u8(r2_u8);
        let overflow: u64 = vgetq_lane_u64(r2_u64, 1); // at most 7 bits (bits 64-70 of r2)

        // Reduce overflow: overflow * q (degree up to 7+7=14, fits in one u64)
        let r3 = vmull_p64(overflow, q);
        let r3_u8 = vreinterpretq_u8_p128(r3);

        // XOR into the result (r3 only affects lane 0, since it's at most degree 14)
        let result = veorq_u8(intermediate, r3_u8);

        // ---------------------------------------------------------------
        // Convert back to GHASH reflected convention.
        // vrbitq_u8 reverses bits within each byte, undoing the initial conversion.
        // ---------------------------------------------------------------
        let result_be = vrbitq_u8(result);
        vst1q_u8(state.as_mut_ptr(), result_be);
    } // unsafe
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, target_arch = "aarch64"))]
mod tests {
    use super::*;
    use crate::modes::gcm::{Gf128, GhashTable};

    /// Verify that the ARM PMULL GHASH produces the same result as the
    /// software 4-bit table implementation for a single block operation
    /// using the NIST test vector H and block values.
    #[test]
    fn test_ghash_arm_matches_software() {
        if !std::arch::is_aarch64_feature_detected!("aes") {
            eprintln!("Skipping ARM GHASH test: CPU does not support PMULL");
            return;
        }

        // H = AES-128(0^128) with key = 0^128 from NIST GCM test case 2.
        let h: [u8; 16] = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let block: [u8; 16] = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
            0xfe, 0x78,
        ];

        // Software reference result.
        let table = GhashTable::new(&h);
        let mut soft_state = Gf128::default();
        table.ghash_block(&mut soft_state, &block);
        let soft_result = soft_state.to_bytes();

        // Hardware PMULL result.
        let mut hw_state = [0u8; 16];
        unsafe {
            ghash_block_arm(&h, &mut hw_state, &block);
        }

        assert_eq!(
            hw_state, soft_result,
            "ARM PMULL GHASH mismatch with software implementation"
        );
    }

    /// Test with a non-zero initial state (simulating the second block of GHASH).
    #[test]
    fn test_ghash_arm_nonzero_state() {
        if !std::arch::is_aarch64_feature_detected!("aes") {
            eprintln!("Skipping ARM GHASH test: CPU does not support PMULL");
            return;
        }

        let h: [u8; 16] = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let block1: [u8; 16] = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
            0xfe, 0x78,
        ];
        let block2: [u8; 16] = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a,
        ];

        // Software: process two blocks sequentially.
        let table = GhashTable::new(&h);
        let mut soft_state = Gf128::default();
        table.ghash_block(&mut soft_state, &block1);
        table.ghash_block(&mut soft_state, &block2);
        let soft_result = soft_state.to_bytes();

        // Hardware: process two blocks sequentially.
        let mut hw_state = [0u8; 16];
        unsafe {
            ghash_block_arm(&h, &mut hw_state, &block1);
            ghash_block_arm(&h, &mut hw_state, &block2);
        }

        assert_eq!(
            hw_state, soft_result,
            "ARM PMULL GHASH mismatch for multi-block processing"
        );
    }

    /// Test with the identity element: block of all zeros should leave
    /// the state unchanged when state is also zero (0 * H = 0).
    #[test]
    fn test_ghash_arm_zero_block() {
        if !std::arch::is_aarch64_feature_detected!("aes") {
            eprintln!("Skipping ARM GHASH test: CPU does not support PMULL");
            return;
        }

        let h: [u8; 16] = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let zero_block = [0u8; 16];

        let mut hw_state = [0u8; 16];
        unsafe {
            ghash_block_arm(&h, &mut hw_state, &zero_block);
        }
        assert_eq!(hw_state, [0u8; 16], "0 * H should equal 0");
    }

    /// Test with H = all zeros. Any value multiplied by zero in GF(2^128) is zero.
    #[test]
    fn test_ghash_arm_zero_h() {
        if !std::arch::is_aarch64_feature_detected!("aes") {
            eprintln!("Skipping ARM GHASH test: CPU does not support PMULL");
            return;
        }

        let h = [0u8; 16];
        let block: [u8; 16] = [
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00,
        ];

        let table = GhashTable::new(&h);
        let mut soft_state = Gf128::default();
        table.ghash_block(&mut soft_state, &block);
        let soft_result = soft_state.to_bytes();

        let mut hw_state = [0u8; 16];
        unsafe {
            ghash_block_arm(&h, &mut hw_state, &block);
        }

        assert_eq!(hw_state, soft_result);
        assert_eq!(hw_state, [0u8; 16], "anything * 0 should equal 0");
    }

    /// Test with all-ones H and block values.
    #[test]
    fn test_ghash_arm_all_ones() {
        if !std::arch::is_aarch64_feature_detected!("aes") {
            eprintln!("Skipping ARM GHASH test: CPU does not support PMULL");
            return;
        }

        let h = [0xffu8; 16];
        let block = [0xffu8; 16];

        let table = GhashTable::new(&h);
        let mut soft_state = Gf128::default();
        table.ghash_block(&mut soft_state, &block);
        let soft_result = soft_state.to_bytes();

        let mut hw_state = [0u8; 16];
        unsafe {
            ghash_block_arm(&h, &mut hw_state, &block);
        }

        assert_eq!(
            hw_state, soft_result,
            "ARM PMULL GHASH mismatch for all-ones input"
        );
    }

    /// Test multiple sequential blocks to simulate a full GHASH computation.
    #[test]
    fn test_ghash_arm_multi_block_sequence() {
        if !std::arch::is_aarch64_feature_detected!("aes") {
            eprintln!("Skipping ARM GHASH test: CPU does not support PMULL");
            return;
        }

        let h: [u8; 16] = [
            0xb8, 0x3b, 0x53, 0x37, 0x08, 0xbf, 0x53, 0x5d, 0x0a, 0xa6, 0xe5, 0x29, 0x80, 0xd5,
            0x3b, 0x78,
        ];

        let blocks: [[u8; 16]; 4] = [
            [
                0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
                0xbe, 0xef,
            ],
            [
                0xab, 0xad, 0xda, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
            [
                0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0,
                0xd4, 0x9c,
            ],
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0xe0,
            ],
        ];

        let table = GhashTable::new(&h);
        let mut soft_state = Gf128::default();
        for block in &blocks {
            table.ghash_block(&mut soft_state, block);
        }
        let soft_result = soft_state.to_bytes();

        let mut hw_state = [0u8; 16];
        unsafe {
            for block in &blocks {
                ghash_block_arm(&h, &mut hw_state, block);
            }
        }

        assert_eq!(
            hw_state, soft_result,
            "ARM PMULL GHASH mismatch for multi-block GHASH sequence"
        );
    }

    /// Exhaustive comparison with deterministic pseudo-random patterns.
    #[test]
    fn test_ghash_arm_exhaustive_patterns() {
        if !std::arch::is_aarch64_feature_detected!("aes") {
            eprintln!("Skipping ARM GHASH test: CPU does not support PMULL");
            return;
        }

        let mut seed: u64 = 0xDEADBEEF_CAFEBABE;

        for i in 0..100 {
            let mut h = [0u8; 16];
            let mut block = [0u8; 16];
            let mut init_state = [0u8; 16];

            for b in &mut h {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (seed >> 33) as u8;
            }
            for b in &mut block {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (seed >> 33) as u8;
            }
            for b in &mut init_state {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (seed >> 33) as u8;
            }

            let table = GhashTable::new(&h);
            let mut soft_state = Gf128::from_bytes(&init_state);
            table.ghash_block(&mut soft_state, &block);
            let soft_result = soft_state.to_bytes();

            let mut hw_state = init_state;
            unsafe {
                ghash_block_arm(&h, &mut hw_state, &block);
            }

            assert_eq!(
                hw_state, soft_result,
                "ARM PMULL GHASH mismatch at iteration {i}"
            );
        }
    }

    /// Single-byte variation test.
    #[test]
    fn test_ghash_arm_single_byte_sensitivity() {
        if !std::arch::is_aarch64_feature_detected!("aes") {
            eprintln!("Skipping ARM GHASH test: CPU does not support PMULL");
            return;
        }

        let h: [u8; 16] = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let block: [u8; 16] = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let mut hw_state1 = [0u8; 16];
        unsafe {
            ghash_block_arm(&h, &mut hw_state1, &block);
        }

        let mut block2 = block;
        block2[0] = 0x02;
        let mut hw_state2 = [0u8; 16];
        unsafe {
            ghash_block_arm(&h, &mut hw_state2, &block2);
        }

        assert_ne!(
            hw_state1, hw_state2,
            "Changing one byte must change the GHASH result"
        );

        let table = GhashTable::new(&h);

        let mut soft1 = Gf128::default();
        table.ghash_block(&mut soft1, &block);
        assert_eq!(hw_state1, soft1.to_bytes());

        let mut soft2 = Gf128::default();
        table.ghash_block(&mut soft2, &block2);
        assert_eq!(hw_state2, soft2.to_bytes());
    }
}
