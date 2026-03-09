//! Hardware-accelerated GHASH implementation using x86-64 PCLMULQDQ intrinsics.
//!
//! This module provides a single-block GHASH multiply function that uses
//! carry-less multiplication (CLMUL) instructions for fast GF(2^128) arithmetic.
//! It is only compiled on `x86_64` targets and requires runtime detection of
//! PCLMULQDQ, SSE2, and SSSE3 support before calling.
//!
//! GHASH uses reflected bit ordering internally. Byte-reversing the big-endian
//! inputs produces the reflected (POLYVAL) representation. The GHASH-to-POLYVAL
//! conversion requires multiplying the hash key H by x in the POLYVAL field
//! (the "mulX" step), per RFC 8452. The reduction uses the POLYVAL irreducible
//! polynomial x^128 + x^127 + x^126 + x^121 + 1.

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// Hardware-accelerated GHASH block multiply using PCLMULQDQ.
///
/// Computes `state = (state XOR block) * H` in GF(2^128) using the GHASH
/// polynomial x^128 + x^7 + x^2 + x + 1.
///
/// Internally, inputs are byte-reversed into POLYVAL representation. The hash
/// key H is further multiplied by x (mulX) to account for the GHASH-to-POLYVAL
/// conversion factor. Karatsuba carry-less multiplication and Barrett reduction
/// are then performed with the POLYVAL polynomial.
///
/// # Safety
///
/// Caller must ensure the CPU supports `pclmulqdq`, `sse2`, and `ssse3`
/// features. Use `is_x86_feature_detected!("pclmulqdq")` before calling.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq,sse2,ssse3")]
pub(super) unsafe fn ghash_block_x86(h: &[u8; 16], state: &mut [u8; 16], block: &[u8; 16]) {
    // SAFETY: caller guarantees CPU feature availability (pclmulqdq, sse2, ssse3).
    unsafe {
        // Byte-swap mask: GHASH uses big-endian byte order, but PCLMULQDQ operates
        // on little-endian 128-bit values. This mask reverses the 16 bytes,
        // converting from GHASH big-endian to POLYVAL (reflected) representation.
        let bswap_mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

        // POLYVAL reduction polynomial lower part: x^127 + x^126 + x^121 + 1
        let poly = _mm_set_epi64x(0xC200000000000000_u64 as i64, 1);

        // Load H and byte-swap to POLYVAL representation.
        let h_be = _mm_loadu_si128(h.as_ptr() as *const __m128i);
        let h_rev = _mm_shuffle_epi8(h_be, bswap_mask);

        // mulX: multiply H by x in GF(2^128) with the POLYVAL polynomial.
        // This is the GHASH-to-POLYVAL conversion factor (RFC 8452).
        // Left-shift by 1; if bit 127 overflows, XOR with the polynomial.
        let overflow = _mm_srai_epi32(h_rev, 31); // broadcast sign bit per dword
        let overflow = _mm_shuffle_epi32(overflow, 0xFF); // broadcast dword 3 to all
        let carry = _mm_srli_epi64(h_rev, 63); // MSB of each 64-bit lane
        let carry = _mm_slli_si128(carry, 8); // shift low carry to high lane
        let h_val = _mm_slli_epi64(h_rev, 1); // left shift each lane by 1
        let h_val = _mm_or_si128(h_val, carry); // fix lane boundary
        let h_val = _mm_xor_si128(h_val, _mm_and_si128(overflow, poly)); // reduce

        // Load state and block, byte-swap both
        let state_be = _mm_loadu_si128(state.as_ptr() as *const __m128i);
        let state_val = _mm_shuffle_epi8(state_be, bswap_mask);

        let block_be = _mm_loadu_si128(block.as_ptr() as *const __m128i);
        let block_val = _mm_shuffle_epi8(block_be, bswap_mask);

        // XOR state with block: a = state ^ block
        let a = _mm_xor_si128(state_val, block_val);

        // --- Karatsuba multiplication: a * H in GF(2^128) ---
        // Produces a 256-bit product in (hi, lo) where hi is the upper 128 bits.

        // lo = a_lo * h_lo
        let lo = _mm_clmulepi64_si128(a, h_val, 0x00);
        // hi = a_hi * h_hi
        let hi = _mm_clmulepi64_si128(a, h_val, 0x11);
        // Cross terms for middle bits
        let m1 = _mm_clmulepi64_si128(a, h_val, 0x01); // a_hi * h_lo
        let m2 = _mm_clmulepi64_si128(a, h_val, 0x10); // a_lo * h_hi
        let mid = _mm_xor_si128(m1, m2);

        // Fold the middle 128 bits into hi and lo:
        //   lo[127:64] ^= mid[63:0]    (shift mid left by 8 bytes)
        //   hi[63:0]   ^= mid[127:64]  (shift mid right by 8 bytes)
        let lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
        let hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));

        // --- Reduction modulo POLYVAL polynomial x^128 + x^127 + x^126 + x^121 + 1 ---
        // Uses CLMUL-based two-phase reduction. Each phase multiplies the low 64 bits
        // by the polynomial's high half (x^63 + x^62 + x^57 = 0xC200000000000000),
        // swaps the 64-bit halves (which accounts for the constant term), and XORs.

        // Step 1: multiply low 64 bits of `lo` by the polynomial high half
        let tmp = _mm_clmulepi64_si128(lo, poly, 0x10);
        // Swap the 64-bit halves of lo, then XOR with tmp
        let lo = _mm_shuffle_epi32(lo, 78); // 78 = 0b01001110 swaps halves
        let lo = _mm_xor_si128(lo, tmp);

        // Step 2: repeat the same reduction step on the partially-reduced value
        let tmp2 = _mm_clmulepi64_si128(lo, poly, 0x10);
        let lo = _mm_shuffle_epi32(lo, 78);
        let lo = _mm_xor_si128(lo, tmp2);

        // Final result: hi ^ reduced_lo
        let result = _mm_xor_si128(hi, lo);

        // Byte-swap back to big-endian and store
        let result_be = _mm_shuffle_epi8(result, bswap_mask);
        _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, result_be);
    } // unsafe
}

/// Precomputed GHASH powers for multi-block VPCLMULQDQ acceleration.
///
/// Stores H, H^2, H^3, H^4 in POLYVAL (reflected) representation after mulX
/// conversion. Built once per key and reused for all GCM operations.
#[cfg(all(target_arch = "x86_64", has_vaes_intrinsics))]
pub(super) struct GhashPowers {
    /// H^1, H^2, H^3, H^4 — each 16 bytes in POLYVAL representation.
    pub powers: [[u8; 16]; 4],
}

#[cfg(all(target_arch = "x86_64", has_vaes_intrinsics))]
impl GhashPowers {
    /// Build precomputed powers from raw H (big-endian GHASH key).
    ///
    /// # Safety
    /// Caller must ensure PCLMULQDQ, SSE2, SSSE3 are available.
    pub unsafe fn new(h: &[u8; 16]) -> Self {
        // SAFETY: caller guarantees CPU feature availability.
        unsafe {
            let bswap_mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            let poly = _mm_set_epi64x(0xC200000000000000_u64 as i64, 1);

            let h_be = _mm_loadu_si128(h.as_ptr() as *const __m128i);
            let h_rev = _mm_shuffle_epi8(h_be, bswap_mask);

            let overflow = _mm_srai_epi32(h_rev, 31);
            let overflow = _mm_shuffle_epi32(overflow, 0xFF);
            let carry = _mm_srli_epi64(h_rev, 63);
            let carry = _mm_slli_si128(carry, 8);
            let h_val = _mm_slli_epi64(h_rev, 1);
            let h_val = _mm_or_si128(h_val, carry);
            let h_val = _mm_xor_si128(h_val, _mm_and_si128(overflow, poly));

            let mut powers = [[0u8; 16]; 4];
            let mut cur = h_val;

            _mm_storeu_si128(powers[0].as_mut_ptr() as *mut __m128i, cur);

            for i in 1..4 {
                cur = gf128_mul_clmul(cur, h_val, poly);
                _mm_storeu_si128(powers[i].as_mut_ptr() as *mut __m128i, cur);
            }

            Self { powers }
        }
    }
}

/// GF(2^128) multiplication of two 128-bit values using CLMUL + Barrett reduction.
///
/// # Safety
/// Requires PCLMULQDQ.
#[cfg(all(target_arch = "x86_64", has_vaes_intrinsics))]
#[target_feature(enable = "pclmulqdq,sse2,ssse3")]
unsafe fn gf128_mul_clmul(a: __m128i, b: __m128i, poly: __m128i) -> __m128i {
    unsafe {
        let lo = _mm_clmulepi64_si128(a, b, 0x00);
        let hi = _mm_clmulepi64_si128(a, b, 0x11);
        let m1 = _mm_clmulepi64_si128(a, b, 0x01);
        let m2 = _mm_clmulepi64_si128(a, b, 0x10);
        let mid = _mm_xor_si128(m1, m2);
        let lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
        let hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));

        let tmp = _mm_clmulepi64_si128(lo, poly, 0x10);
        let lo = _mm_shuffle_epi32(lo, 78);
        let lo = _mm_xor_si128(lo, tmp);
        let tmp2 = _mm_clmulepi64_si128(lo, poly, 0x10);
        let lo = _mm_shuffle_epi32(lo, 78);
        let lo = _mm_xor_si128(lo, tmp2);
        _mm_xor_si128(hi, lo)
    }
}

/// Process 4 GHASH blocks in parallel using VPCLMULQDQ (256-bit carry-less multiply).
///
/// Computes state = (...((state ^ b0) * H^4) ^ b1) * H^3) ^ b2) * H^2) ^ b3) * H
/// using schoolbook multiplication with 256-bit VPCLMULQDQ instructions,
/// reducing the number of multiply instructions from 16 (4×4 Karatsuba) to 8.
///
/// # Safety
/// Caller must ensure VPCLMULQDQ, AVX2, PCLMULQDQ, SSE2, SSSE3 are available.
#[cfg(all(target_arch = "x86_64", has_vaes_intrinsics))]
#[allow(clippy::incompatible_msrv)]
#[target_feature(enable = "vpclmulqdq,avx2,pclmulqdq,sse2,ssse3")]
pub(super) unsafe fn ghash_4_blocks_vpclmul(
    powers: &GhashPowers,
    state: &mut [u8; 16],
    blocks: &[[u8; 16]; 4],
) {
    // SAFETY: caller guarantees CPU feature availability (vpclmulqdq, avx2, pclmulqdq, sse2, ssse3).
    unsafe {
        let bswap_mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        let bswap256 = _mm256_broadcastsi128_si256(bswap_mask);
        let poly128 = _mm_set_epi64x(0xC200000000000000_u64 as i64, 1);

        // Load state, byte-swap, XOR with first block
        let state_be = _mm_loadu_si128(state.as_ptr() as *const __m128i);
        let state_val = _mm_shuffle_epi8(state_be, bswap_mask);
        let block0_be = _mm_loadu_si128(blocks[0].as_ptr() as *const __m128i);
        let block0_val = _mm_shuffle_epi8(block0_be, bswap_mask);
        let a0 = _mm_xor_si128(state_val, block0_val);

        // Load blocks 1-3, byte-swap
        let a1_be = _mm_loadu_si128(blocks[1].as_ptr() as *const __m128i);
        let a1 = _mm_shuffle_epi8(a1_be, bswap_mask);
        let a2_be = _mm_loadu_si128(blocks[2].as_ptr() as *const __m128i);
        let a2 = _mm_shuffle_epi8(a2_be, bswap_mask);
        let a3_be = _mm_loadu_si128(blocks[3].as_ptr() as *const __m128i);
        let a3 = _mm_shuffle_epi8(a3_be, bswap_mask);

        // Load H powers: a0 uses H^4, a1 uses H^3, a2 uses H^2, a3 uses H^1
        let h4 = _mm_loadu_si128(powers.powers[3].as_ptr() as *const __m128i);
        let h3 = _mm_loadu_si128(powers.powers[2].as_ptr() as *const __m128i);
        let h2 = _mm_loadu_si128(powers.powers[1].as_ptr() as *const __m128i);
        let h1 = _mm_loadu_si128(powers.powers[0].as_ptr() as *const __m128i);

        // Pack into 256-bit registers for VPCLMULQDQ:
        // a_01 = [a0 | a1], h_43 = [h4 | h3]
        // a_23 = [a2 | a3], h_21 = [h2 | h1]
        let a_01 = _mm256_set_m128i(a1, a0);
        let a_23 = _mm256_set_m128i(a3, a2);
        let h_43 = _mm256_set_m128i(h3, h4);
        let h_21 = _mm256_set_m128i(h1, h2);

        // 256-bit Karatsuba: 4 multiplies yield products for 2 pairs simultaneously
        let lo_01 = _mm256_clmulepi64_epi128(a_01, h_43, 0x00);
        let hi_01 = _mm256_clmulepi64_epi128(a_01, h_43, 0x11);
        let m1_01 = _mm256_clmulepi64_epi128(a_01, h_43, 0x01);
        let m2_01 = _mm256_clmulepi64_epi128(a_01, h_43, 0x10);

        let lo_23 = _mm256_clmulepi64_epi128(a_23, h_21, 0x00);
        let hi_23 = _mm256_clmulepi64_epi128(a_23, h_21, 0x11);
        let m1_23 = _mm256_clmulepi64_epi128(a_23, h_21, 0x01);
        let m2_23 = _mm256_clmulepi64_epi128(a_23, h_21, 0x10);

        // XOR all partial products together (sum all 4 multiplications)
        let lo_all = _mm256_xor_si256(lo_01, lo_23);
        let hi_all = _mm256_xor_si256(hi_01, hi_23);
        let mid_all = _mm256_xor_si256(
            _mm256_xor_si256(m1_01, m2_01),
            _mm256_xor_si256(m1_23, m2_23),
        );

        // Reduce 256-bit halves to 128-bit by XORing high and low lanes
        let lo128 = _mm_xor_si128(
            _mm256_castsi256_si128(lo_all),
            _mm256_extracti128_si256(lo_all, 1),
        );
        let hi128 = _mm_xor_si128(
            _mm256_castsi256_si128(hi_all),
            _mm256_extracti128_si256(hi_all, 1),
        );
        let mid128 = _mm_xor_si128(
            _mm256_castsi256_si128(mid_all),
            _mm256_extracti128_si256(mid_all, 1),
        );

        // Fold middle bits
        let lo128 = _mm_xor_si128(lo128, _mm_slli_si128(mid128, 8));
        let hi128 = _mm_xor_si128(hi128, _mm_srli_si128(mid128, 8));

        // Barrett reduction
        let tmp = _mm_clmulepi64_si128(lo128, poly128, 0x10);
        let lo128 = _mm_shuffle_epi32(lo128, 78);
        let lo128 = _mm_xor_si128(lo128, tmp);
        let tmp2 = _mm_clmulepi64_si128(lo128, poly128, 0x10);
        let lo128 = _mm_shuffle_epi32(lo128, 78);
        let lo128 = _mm_xor_si128(lo128, tmp2);
        let result = _mm_xor_si128(hi128, lo128);

        // Byte-swap back and store
        let result_be = _mm_shuffle_epi8(result, bswap_mask);
        _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, result_be);
    } // unsafe
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Software reference GHASH block multiply for verification.
    /// Computes state = (state XOR block) * H in GF(2^128).
    fn ghash_block_software(h: &[u8; 16], state: &mut [u8; 16], block: &[u8; 16]) {
        // XOR state with block
        let mut v = [0u8; 16];
        for i in 0..16 {
            v[i] = state[i] ^ block[i];
        }

        // Multiply v by H in GF(2^128) with polynomial x^128+x^7+x^2+x+1.
        // Standard bit-by-bit multiplication in reflected representation.
        let mut z = [0u8; 16]; // accumulator
        let mut h_shifted = *h; // working copy of H

        for i in 0..128 {
            let byte_idx = i / 8;
            let bit_idx = 7 - (i % 8);
            if (v[byte_idx] >> bit_idx) & 1 == 1 {
                for j in 0..16 {
                    z[j] ^= h_shifted[j];
                }
            }
            // Multiply H by x (right shift in reflected representation)
            let carry = h_shifted[15] & 1;
            for j in (1..16).rev() {
                h_shifted[j] = (h_shifted[j] >> 1) | (h_shifted[j - 1] << 7);
            }
            h_shifted[0] >>= 1;
            // If carry, reduce by XORing with the polynomial (0xE1 at byte 0)
            if carry == 1 {
                h_shifted[0] ^= 0xE1;
            }
        }

        *state = z;
    }

    #[test]
    fn test_ghash_x86_matches_software_basic() {
        if !is_x86_feature_detected!("pclmulqdq") {
            eprintln!(
                "Skipping test_ghash_x86_matches_software_basic: \
                 PCLMULQDQ not supported"
            );
            return;
        }

        // H = AES-ECB(K=0, 0) for a zero key = 0x66e94bd4ef8a2c3b884cfa59ca342b2e
        let h: [u8; 16] = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];

        // Test case 1: both state and block zero -> result should be zero
        let block = [0u8; 16];
        let mut state_hw = [0u8; 16];
        let mut state_sw = [0u8; 16];

        unsafe { ghash_block_x86(&h, &mut state_hw, &block) };
        ghash_block_software(&h, &mut state_sw, &block);
        assert_eq!(state_hw, state_sw, "Mismatch on zero state/block");

        // Test case 2: zero state, non-zero block
        let block2: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let mut state_hw = [0u8; 16];
        let mut state_sw = [0u8; 16];

        unsafe { ghash_block_x86(&h, &mut state_hw, &block2) };
        ghash_block_software(&h, &mut state_sw, &block2);
        assert_eq!(state_hw, state_sw, "Mismatch on zero state, non-zero block");

        // Test case 3: non-zero state, non-zero block
        let block3: [u8; 16] = [
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
            0xbe, 0xef,
        ];
        let mut state_hw = [
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
            0x67, 0x89,
        ];
        let mut state_sw = state_hw;

        unsafe { ghash_block_x86(&h, &mut state_hw, &block3) };
        ghash_block_software(&h, &mut state_sw, &block3);
        assert_eq!(state_hw, state_sw, "Mismatch on non-zero state and block");
    }

    #[test]
    fn test_ghash_x86_matches_software_chained() {
        if !is_x86_feature_detected!("pclmulqdq") {
            eprintln!(
                "Skipping test_ghash_x86_matches_software_chained: \
                 PCLMULQDQ not supported"
            );
            return;
        }

        // Use H from NIST SP 800-38D Test Case 2 (AES-128, key=all-zeros)
        let h: [u8; 16] = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];

        // Chain several blocks (simulating multi-block GHASH)
        let blocks: [[u8; 16]; 4] = [
            [
                0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
                0xfe, 0x78,
            ],
            [
                0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
                0x26, 0x9a,
            ],
            [
                0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31,
                0x8a, 0x72,
            ],
            [
                0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6,
                0xb5, 0x25,
            ],
        ];

        let mut state_hw = [0u8; 16];
        let mut state_sw = [0u8; 16];

        for blk in &blocks {
            unsafe { ghash_block_x86(&h, &mut state_hw, blk) };
            ghash_block_software(&h, &mut state_sw, blk);
            assert_eq!(state_hw, state_sw, "Mismatch after chained GHASH block");
        }
    }

    #[test]
    fn test_ghash_x86_nist_test_case_2() {
        // NIST SP 800-38D, Test Case 2:
        //   Key = 00000000000000000000000000000000
        //   H   = 66e94bd4ef8a2c3b884cfa59ca342b2e
        //   Plaintext = 00000000000000000000000000000000
        //   CT  = 0388dace60b6a392f328c2b971b2fe78
        //   AAD = (empty)
        //   GHASH input: CT || len(A)=0 || len(C)=128
        //
        // The GHASH value before the final GCTR is computed by processing:
        //   Block 1: ciphertext = 0388dace60b6a392f328c2b971b2fe78
        //   Block 2: len block  = 00000000000000000000000000000080
        //
        // Expected GHASH = f38cbb1ad69223dcc3457ae5b6b0f885
        if !is_x86_feature_detected!("pclmulqdq") {
            eprintln!(
                "Skipping test_ghash_x86_nist_test_case_2: \
                 PCLMULQDQ not supported"
            );
            return;
        }

        let h: [u8; 16] = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];

        let ct_block: [u8; 16] = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
            0xfe, 0x78,
        ];

        // len(A) = 0 bits, len(C) = 128 bits = 0x80
        let len_block: [u8; 16] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x80,
        ];

        let expected_ghash: [u8; 16] = [
            0xf3, 0x8c, 0xbb, 0x1a, 0xd6, 0x92, 0x23, 0xdc, 0xc3, 0x45, 0x7a, 0xe5, 0xb6, 0xb0,
            0xf8, 0x85,
        ];

        // Hardware path
        let mut state_hw = [0u8; 16];
        unsafe {
            ghash_block_x86(&h, &mut state_hw, &ct_block);
            ghash_block_x86(&h, &mut state_hw, &len_block);
        }
        assert_eq!(
            state_hw, expected_ghash,
            "NIST Test Case 2 GHASH mismatch (hardware)"
        );

        // Verify software matches too
        let mut state_sw = [0u8; 16];
        ghash_block_software(&h, &mut state_sw, &ct_block);
        ghash_block_software(&h, &mut state_sw, &len_block);
        assert_eq!(
            state_sw, expected_ghash,
            "NIST Test Case 2 GHASH mismatch (software)"
        );
    }

    #[test]
    fn test_ghash_x86_nist_test_case_3() {
        // NIST SP 800-38D, Test Case 3:
        //   Key = feffe9928665731c6d6a8f9467308308
        //   H   = b83b533708bf535d0aa6e52980d53b78
        //   PT  = d9313225f88406e5a55909c5aff5269a
        //         86a7a9531534f7da2e4c303d8a318a72
        //         1c3c0c9595680953 2fcf0e2449a6b525
        //         b16aedf5aa0de657ba637b391aafd255
        //   IV  = cafebabefacedbaddecaf888
        //   AAD = (empty)
        //   CT  = 42831ec2217774244b7221b784d0d49c
        //         e3aa212f2c02a4e035c17e2329aca12e
        //         21d514b25466931c7d8f6a5aac84aa05
        //         1ba30b396a0aac973d58e091473f5985
        //
        // GHASH is computed over CT (4 blocks) + len block.
        // Expected GHASH = 7f1b32b81b820d02614f8895ac1d4eac
        if !is_x86_feature_detected!("pclmulqdq") {
            eprintln!(
                "Skipping test_ghash_x86_nist_test_case_3: \
                 PCLMULQDQ not supported"
            );
            return;
        }

        let h: [u8; 16] = [
            0xb8, 0x3b, 0x53, 0x37, 0x08, 0xbf, 0x53, 0x5d, 0x0a, 0xa6, 0xe5, 0x29, 0x80, 0xd5,
            0x3b, 0x78,
        ];

        let ct_blocks: [[u8; 16]; 4] = [
            [
                0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0,
                0xd4, 0x9c,
            ],
            [
                0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac,
                0xa1, 0x2e,
            ],
            [
                0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84,
                0xaa, 0x05,
            ],
            [
                0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91, 0x47, 0x3f,
                0x59, 0x85,
            ],
        ];

        // len(A)=0, len(C)=512 bits = 0x200
        let len_block: [u8; 16] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00,
        ];

        let expected_ghash: [u8; 16] = [
            0x7f, 0x1b, 0x32, 0xb8, 0x1b, 0x82, 0x0d, 0x02, 0x61, 0x4f, 0x88, 0x95, 0xac, 0x1d,
            0x4e, 0xac,
        ];

        let mut state_hw = [0u8; 16];
        unsafe {
            for blk in &ct_blocks {
                ghash_block_x86(&h, &mut state_hw, blk);
            }
            ghash_block_x86(&h, &mut state_hw, &len_block);
        }
        assert_eq!(
            state_hw, expected_ghash,
            "NIST Test Case 3 GHASH mismatch (hardware)"
        );

        // Cross-check with software
        let mut state_sw = [0u8; 16];
        for blk in &ct_blocks {
            ghash_block_software(&h, &mut state_sw, blk);
        }
        ghash_block_software(&h, &mut state_sw, &len_block);
        assert_eq!(
            state_sw, expected_ghash,
            "NIST Test Case 3 GHASH mismatch (software)"
        );
    }

    #[test]
    fn test_ghash_x86_nist_test_case_4() {
        // NIST SP 800-38D, Test Case 4 (with AAD):
        //   Key = feffe9928665731c6d6a8f9467308308
        //   H   = b83b533708bf535d0aa6e52980d53b78
        //   AAD = feedfacedeadbeeffeedfacedeadbeefabaddad2 (20 bytes)
        //   PT  = d9313225f88406e5a55909c5aff5269a
        //         86a7a9531534f7da2e4c303d8a318a72
        //         1c3c0c95956809532fcf0e2449a6b525
        //         b16aedf5aa0de657ba637b39  (60 bytes)
        //   CT  = 42831ec2217774244b7221b784d0d49c
        //         e3aa212f2c02a4e035c17e2329aca12e
        //         21d514b25466931c7d8f6a5aac84aa05
        //         1ba30b396a0aac973d58e091  (60 bytes)
        //
        // GHASH input blocks:
        //   AAD block 1: feedfacedeadbeeffeedfacedeadbeef (pad to 16)
        //   AAD block 2: abaddad200000000 0000000000000000 (pad)
        //   CT block 1:  42831ec2217774244b7221b784d0d49c
        //   CT block 2:  e3aa212f2c02a4e035c17e2329aca12e
        //   CT block 3:  21d514b25466931c7d8f6a5aac84aa05
        //   CT block 4:  1ba30b396a0aac973d58e09100000000 (pad)
        //   Len block:   00000000000000a000000000000001e0
        //
        // Expected GHASH = 698e57f70e6ecc7fd9463b7260a9ae5f
        if !is_x86_feature_detected!("pclmulqdq") {
            eprintln!(
                "Skipping test_ghash_x86_nist_test_case_4: \
                 PCLMULQDQ not supported"
            );
            return;
        }

        let h: [u8; 16] = [
            0xb8, 0x3b, 0x53, 0x37, 0x08, 0xbf, 0x53, 0x5d, 0x0a, 0xa6, 0xe5, 0x29, 0x80, 0xd5,
            0x3b, 0x78,
        ];

        // AAD padded blocks
        let aad_block1: [u8; 16] = [
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
            0xbe, 0xef,
        ];
        let aad_block2: [u8; 16] = [
            0xab, 0xad, 0xda, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        // CT padded blocks
        let ct_block1: [u8; 16] = [
            0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0,
            0xd4, 0x9c,
        ];
        let ct_block2: [u8; 16] = [
            0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac,
            0xa1, 0x2e,
        ];
        let ct_block3: [u8; 16] = [
            0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84,
            0xaa, 0x05,
        ];
        let ct_block4: [u8; 16] = [
            0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91, 0x00, 0x00,
            0x00, 0x00,
        ];

        // len(A)=160 bits=0xa0, len(C)=480 bits=0x1e0
        let len_block: [u8; 16] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0xe0,
        ];

        let expected_ghash: [u8; 16] = [
            0x69, 0x8e, 0x57, 0xf7, 0x0e, 0x6e, 0xcc, 0x7f, 0xd9, 0x46, 0x3b, 0x72, 0x60, 0xa9,
            0xae, 0x5f,
        ];

        let all_blocks: [&[u8; 16]; 7] = [
            &aad_block1,
            &aad_block2,
            &ct_block1,
            &ct_block2,
            &ct_block3,
            &ct_block4,
            &len_block,
        ];

        let mut state_hw = [0u8; 16];
        unsafe {
            for blk in &all_blocks {
                ghash_block_x86(&h, &mut state_hw, blk);
            }
        }
        assert_eq!(
            state_hw, expected_ghash,
            "NIST Test Case 4 GHASH mismatch (hardware)"
        );

        // Cross-check with software
        let mut state_sw = [0u8; 16];
        for blk in &all_blocks {
            ghash_block_software(&h, &mut state_sw, blk);
        }
        assert_eq!(
            state_sw, expected_ghash,
            "NIST Test Case 4 GHASH mismatch (software)"
        );
    }

    #[test]
    fn test_ghash_x86_matches_software_random_patterns() {
        // Test with various bit patterns to exercise edge cases
        if !is_x86_feature_detected!("pclmulqdq") {
            eprintln!(
                "Skipping test_ghash_x86_matches_software_random_patterns: \
                 PCLMULQDQ not supported"
            );
            return;
        }

        let test_cases: [([u8; 16], [u8; 16], [u8; 16]); 5] = [
            // (H, initial_state, block)
            (
                // All ones
                [0xFF; 16], [0xFF; 16], [0xFF; 16],
            ),
            (
                // H with single bit set
                [
                    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ],
                [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01,
                ],
                [0x00; 16],
            ),
            (
                // Alternating bits in H
                [
                    0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA,
                    0x55, 0xAA, 0x55,
                ],
                [
                    0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55,
                    0xAA, 0x55, 0xAA,
                ],
                [
                    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A,
                    0xBC, 0xDE, 0xF0,
                ],
            ),
            (
                // Low bit only in H
                [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01,
                ],
                [
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF,
                ],
                [
                    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ],
            ),
            (
                // Sequential bytes
                [
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                    0x0E, 0x0F, 0x10,
                ],
                [
                    0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04,
                    0x03, 0x02, 0x01,
                ],
                [
                    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA,
                    0xFE, 0xBA, 0xBE,
                ],
            ),
        ];

        for (i, (h, initial_state, block)) in test_cases.iter().enumerate() {
            let mut state_hw = *initial_state;
            let mut state_sw = *initial_state;

            unsafe { ghash_block_x86(h, &mut state_hw, block) };
            ghash_block_software(h, &mut state_sw, block);
            assert_eq!(state_hw, state_sw, "Pattern test case {i} mismatch");
        }
    }

    #[test]
    fn test_ghash_x86_identity_properties() {
        // Verify algebraic properties of GF(2^128) multiplication
        if !is_x86_feature_detected!("pclmulqdq") {
            eprintln!(
                "Skipping test_ghash_x86_identity_properties: \
                 PCLMULQDQ not supported"
            );
            return;
        }

        let h: [u8; 16] = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];

        // Property: GHASH with zero block on zero state = 0 * H = 0
        let mut state = [0u8; 16];
        let zero_block = [0u8; 16];
        unsafe { ghash_block_x86(&h, &mut state, &zero_block) };
        assert_eq!(state, [0u8; 16], "0 * H should be 0");

        // Property: state XOR block = 0 means multiplying 0 by H = 0
        let block_val: [u8; 16] = [
            0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0,
            0xd4, 0x9c,
        ];
        let mut state = block_val; // state == block, so XOR = 0
        unsafe { ghash_block_x86(&h, &mut state, &block_val) };
        assert_eq!(state, [0u8; 16], "(x XOR x) * H should be 0");

        // Property: H = 0 means result is always 0
        let h_zero = [0u8; 16];
        let mut state = [0xFFu8; 16];
        let block = [0xAAu8; 16];
        unsafe { ghash_block_x86(&h_zero, &mut state, &block) };
        assert_eq!(state, [0u8; 16], "anything * 0 should be 0");
    }
}
