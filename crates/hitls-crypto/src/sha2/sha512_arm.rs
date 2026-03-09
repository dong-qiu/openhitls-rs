//! ARMv8.2 hardware-accelerated SHA-512 compress function.
//!
//! Uses the ARMv8.2-A SHA-512 Cryptography Extensions via `core::arch::aarch64`
//! intrinsics. These instructions process two rounds at a time using 128-bit
//! NEON registers holding two u64 lanes each.
//!
//! The implementation follows the Linux kernel's `sha512-ce-core.S` pattern:
//! - 5-register state rotation (s0..s4 cycling through ab/cd/ef/gh roles)
//! - K+W halves swapped via `vextq_u64(v, v, 1)` before adding to state
//! - SHA512H called with pre-added state+K+W, two EXT intermediates
//! - SHA512SU1 called with EXT of message words for σ1 schedule update
//!
//! # Safety
//!
//! The public function requires the `sha3` target feature (which gates
//! SHA-512 instructions on aarch64) and `neon` at runtime.

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::{
    uint64x2_t, vaddq_u64, vdupq_n_u64, vextq_u64, vld1q_u64, vreinterpretq_u64_u8,
    vreinterpretq_u8_u64, vrev64q_u8, vsha512h2q_u64, vsha512hq_u64, vsha512su0q_u64,
    vsha512su1q_u64, vst1q_u64,
};

use super::K512;

/// Load two u64 message words from `block_ptr` at the given byte offset,
/// byte-swap from big-endian to native little-endian.
///
/// This function is `#[inline(always)]` without `#[target_feature]` so it
/// gets inlined into the caller which provides the required NEON features.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn load_be(block_ptr: *const u8, byte_offset: usize) -> uint64x2_t {
    // SAFETY: caller guarantees CPU feature availability and valid pointer.
    unsafe {
        let ptr = block_ptr.add(byte_offset) as *const u64;
        let raw = vld1q_u64(ptr);
        vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(raw)))
    }
}

/// ARMv8.2 SHA-512 hardware-accelerated compression function.
///
/// Processes a single 128-byte block and updates the 8-word state in place.
/// Uses the 5-register rotation pattern from the Linux kernel SHA-512 CE
/// implementation.
///
/// # Safety
///
/// Requires `sha3` and `neon` target features at runtime.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha3,neon")]
#[allow(clippy::incompatible_msrv)]
pub(super) unsafe fn sha512_compress_arm(state: &mut [u64; 8], block: &[u8]) {
    debug_assert!(block.len() >= 128);

    // SAFETY: caller guarantees CPU feature availability (sha3 + neon).
    unsafe {
        let block_ptr = block.as_ptr();
        let k_ptr = K512.as_ptr();

        // Load current hash state into four NEON registers.
        // s0={a,b}, s1={c,d}, s2={e,f}, s3={g,h}, s4=working register
        let mut s0 = vld1q_u64(state.as_ptr());
        let mut s1 = vld1q_u64(state.as_ptr().add(2));
        let mut s2 = vld1q_u64(state.as_ptr().add(4));
        let mut s3 = vld1q_u64(state.as_ptr().add(6));
        #[allow(unused_assignments)]
        let mut s4 = vdupq_n_u64(0); // 5th working register

        // Save initial state for Davies-Meyer feed-forward.
        let s0_save = s0;
        let s1_save = s1;
        let s2_save = s2;
        let s3_save = s3;

        // Load and byte-swap all 16 message words (8 pairs).
        let mut w0 = load_be(block_ptr, 0);
        let mut w1 = load_be(block_ptr, 16);
        let mut w2 = load_be(block_ptr, 32);
        let mut w3 = load_be(block_ptr, 48);
        let mut w4 = load_be(block_ptr, 64);
        let mut w5 = load_be(block_ptr, 80);
        let mut w6 = load_be(block_ptr, 96);
        let mut w7 = load_be(block_ptr, 112);

        // Process 80 rounds as 40 round-pairs using the 5-register rotation.
        //
        // Each dround processes 2 SHA-512 rounds:
        //   1. kw = K[t:t+1] + W[t:t+1], then swap halves
        //   2. v6 = EXT(i2, i3, 1) — intermediate from ef/gh-like registers
        //   3. v7 = EXT(i1, i2, 1) — intermediate from cd/ef-like registers
        //   4. i3 += swapped kw, then SHA512H(i3, v6, v7)
        //   5. i4 = i1 + SHA512H result (new ef)
        //   6. i3 = SHA512H2(SHA512H result, i1, i0) (new ab)
        //
        // The 5-register rotation cycles every 5 drounds:
        //   (s0,s1,s2,s3,s4), (s3,s0,s4,s2,s1), (s2,s3,s1,s4,s0),
        //   (s4,s2,s0,s1,s3), (s1,s4,s3,s0,s2)
        // After 40 drounds (8 full cycles), state is back in s0-s3.

        // One round-pair (2 SHA-512 rounds).
        macro_rules! dround {
            ($i0:ident, $i1:ident, $i2:ident, $i3:ident, $i4:ident, $ki:expr, $wi:expr) => {{
                let k = vld1q_u64(k_ptr.add($ki * 2));
                let kw = vaddq_u64(k, $wi);
                let v6 = vextq_u64($i2, $i3, 1);
                let kw_swap = vextq_u64(kw, kw, 1); // swap halves
                let v7 = vextq_u64($i1, $i2, 1);
                let t = vaddq_u64($i3, kw_swap);
                let t = vsha512hq_u64(t, v6, v7);
                $i4 = vaddq_u64($i1, t);
                $i3 = vsha512h2q_u64(t, $i1, $i0);
            }};
        }

        // Message schedule update: W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]
        // Pattern: msg_sched!(w[i], w[i+1], w[i+7], w[i+4], w[i+5]) (indices mod 8)
        macro_rules! msg_sched {
            ($wt:ident, $wn:ident, $w7:ident, $w4:ident, $w5:ident) => {{
                let ext_val = vextq_u64($w4, $w5, 1);
                $wt = vsha512su1q_u64(vsha512su0q_u64($wt, $wn), $w7, ext_val);
            }};
        }

        // Cycle 1: drounds 0-4 (rounds 0-9)
        dround!(s0, s1, s2, s3, s4, 0, w0);
        msg_sched!(w0, w1, w7, w4, w5);
        dround!(s3, s0, s4, s2, s1, 1, w1);
        msg_sched!(w1, w2, w0, w5, w6);
        dround!(s2, s3, s1, s4, s0, 2, w2);
        msg_sched!(w2, w3, w1, w6, w7);
        dround!(s4, s2, s0, s1, s3, 3, w3);
        msg_sched!(w3, w4, w2, w7, w0);
        dround!(s1, s4, s3, s0, s2, 4, w4);
        msg_sched!(w4, w5, w3, w0, w1);

        // Cycle 2: drounds 5-9 (rounds 10-19)
        dround!(s0, s1, s2, s3, s4, 5, w5);
        msg_sched!(w5, w6, w4, w1, w2);
        dround!(s3, s0, s4, s2, s1, 6, w6);
        msg_sched!(w6, w7, w5, w2, w3);
        dround!(s2, s3, s1, s4, s0, 7, w7);
        msg_sched!(w7, w0, w6, w3, w4);
        dround!(s4, s2, s0, s1, s3, 8, w0);
        msg_sched!(w0, w1, w7, w4, w5);
        dround!(s1, s4, s3, s0, s2, 9, w1);
        msg_sched!(w1, w2, w0, w5, w6);

        // Cycle 3: drounds 10-14 (rounds 20-29)
        dround!(s0, s1, s2, s3, s4, 10, w2);
        msg_sched!(w2, w3, w1, w6, w7);
        dround!(s3, s0, s4, s2, s1, 11, w3);
        msg_sched!(w3, w4, w2, w7, w0);
        dround!(s2, s3, s1, s4, s0, 12, w4);
        msg_sched!(w4, w5, w3, w0, w1);
        dround!(s4, s2, s0, s1, s3, 13, w5);
        msg_sched!(w5, w6, w4, w1, w2);
        dround!(s1, s4, s3, s0, s2, 14, w6);
        msg_sched!(w6, w7, w5, w2, w3);

        // Cycle 4: drounds 15-19 (rounds 30-39)
        dround!(s0, s1, s2, s3, s4, 15, w7);
        msg_sched!(w7, w0, w6, w3, w4);
        dround!(s3, s0, s4, s2, s1, 16, w0);
        msg_sched!(w0, w1, w7, w4, w5);
        dround!(s2, s3, s1, s4, s0, 17, w1);
        msg_sched!(w1, w2, w0, w5, w6);
        dround!(s4, s2, s0, s1, s3, 18, w2);
        msg_sched!(w2, w3, w1, w6, w7);
        dround!(s1, s4, s3, s0, s2, 19, w3);
        msg_sched!(w3, w4, w2, w7, w0);

        // Cycle 5: drounds 20-24 (rounds 40-49)
        dround!(s0, s1, s2, s3, s4, 20, w4);
        msg_sched!(w4, w5, w3, w0, w1);
        dround!(s3, s0, s4, s2, s1, 21, w5);
        msg_sched!(w5, w6, w4, w1, w2);
        dround!(s2, s3, s1, s4, s0, 22, w6);
        msg_sched!(w6, w7, w5, w2, w3);
        dround!(s4, s2, s0, s1, s3, 23, w7);
        msg_sched!(w7, w0, w6, w3, w4);
        dround!(s1, s4, s3, s0, s2, 24, w0);
        msg_sched!(w0, w1, w7, w4, w5);

        // Cycle 6: drounds 25-29 (rounds 50-59)
        dround!(s0, s1, s2, s3, s4, 25, w1);
        msg_sched!(w1, w2, w0, w5, w6);
        dround!(s3, s0, s4, s2, s1, 26, w2);
        msg_sched!(w2, w3, w1, w6, w7);
        dround!(s2, s3, s1, s4, s0, 27, w3);
        msg_sched!(w3, w4, w2, w7, w0);
        dround!(s4, s2, s0, s1, s3, 28, w4);
        msg_sched!(w4, w5, w3, w0, w1);
        dround!(s1, s4, s3, s0, s2, 29, w5);
        msg_sched!(w5, w6, w4, w1, w2);

        // Cycle 7: drounds 30-34 (rounds 60-69)
        // Last 2 drounds with schedule, then 3 without
        dround!(s0, s1, s2, s3, s4, 30, w6);
        msg_sched!(w6, w7, w5, w2, w3);
        dround!(s3, s0, s4, s2, s1, 31, w7);
        msg_sched!(w7, w0, w6, w3, w4);
        dround!(s2, s3, s1, s4, s0, 32, w0);
        dround!(s4, s2, s0, s1, s3, 33, w1);
        dround!(s1, s4, s3, s0, s2, 34, w2);

        // Cycle 8: drounds 35-39 (rounds 70-79) — no schedule updates
        dround!(s0, s1, s2, s3, s4, 35, w3);
        dround!(s3, s0, s4, s2, s1, 36, w4);
        dround!(s2, s3, s1, s4, s0, 37, w5);
        dround!(s4, s2, s0, s1, s3, 38, w6);
        dround!(s1, s4, s3, s0, s2, 39, w7);

        // Davies-Meyer feed-forward: add saved initial state.
        s0 = vaddq_u64(s0, s0_save);
        s1 = vaddq_u64(s1, s1_save);
        s2 = vaddq_u64(s2, s2_save);
        s3 = vaddq_u64(s3, s3_save);

        // Store updated state back.
        vst1q_u64(state.as_mut_ptr(), s0);
        vst1q_u64(state.as_mut_ptr().add(2), s1);
        vst1q_u64(state.as_mut_ptr().add(4), s2);
        vst1q_u64(state.as_mut_ptr().add(6), s3);
    } // unsafe
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests {
    use super::*;

    #[test]
    fn test_sha512_arm_matches_software() {
        if !std::arch::is_aarch64_feature_detected!("sha3") {
            eprintln!("Skipping ARM SHA-512 test: CPU does not support sha3 extension");
            return;
        }

        let h0 = super::super::H512;
        let mut block = [0u8; 128];
        block[0] = 0x80;

        let mut state_sw = h0;
        super::super::sha512_compress_soft(&mut state_sw, &block);

        let mut state_hw = h0;
        unsafe {
            sha512_compress_arm(&mut state_hw, &block);
        }

        assert_eq!(
            state_sw, state_hw,
            "ARM SHA-512 compress mismatch for empty-string block"
        );
    }

    #[test]
    fn test_sha512_arm_abc() {
        if !std::arch::is_aarch64_feature_detected!("sha3") {
            eprintln!("Skipping ARM SHA-512 test: CPU does not support sha3 extension");
            return;
        }

        let h0 = super::super::H512;
        let mut block = [0u8; 128];
        block[0] = b'a';
        block[1] = b'b';
        block[2] = b'c';
        block[3] = 0x80;
        block[127] = 0x18;

        let mut state_sw = h0;
        super::super::sha512_compress_soft(&mut state_sw, &block);

        let mut state_hw = h0;
        unsafe {
            sha512_compress_arm(&mut state_hw, &block);
        }

        assert_eq!(
            state_sw, state_hw,
            "ARM SHA-512 compress mismatch for 'abc' block"
        );
    }

    #[test]
    fn test_sha512_arm_all_ones_block() {
        if !std::arch::is_aarch64_feature_detected!("sha3") {
            eprintln!("Skipping ARM SHA-512 test: CPU does not support sha3 extension");
            return;
        }

        let h0 = super::super::H512;
        let block = [0xFFu8; 128];

        let mut state_sw = h0;
        super::super::sha512_compress_soft(&mut state_sw, &block);

        let mut state_hw = h0;
        unsafe {
            sha512_compress_arm(&mut state_hw, &block);
        }

        assert_eq!(
            state_sw, state_hw,
            "ARM SHA-512 compress mismatch for all-0xFF block"
        );
    }

    #[test]
    fn test_sha512_arm_multi_block() {
        if !std::arch::is_aarch64_feature_detected!("sha3") {
            eprintln!("Skipping ARM SHA-512 test: CPU does not support sha3 extension");
            return;
        }

        let h0 = super::super::H512;
        let blocks: Vec<[u8; 128]> = (0..8u8)
            .map(|i| core::array::from_fn(|j| i.wrapping_mul(j as u8).wrapping_add(0x37)))
            .collect();

        let mut state_sw = h0;
        let mut state_hw = h0;

        for block in &blocks {
            super::super::sha512_compress_soft(&mut state_sw, block);
            unsafe {
                sha512_compress_arm(&mut state_hw, block);
            }
        }

        assert_eq!(
            state_sw, state_hw,
            "ARM SHA-512 multi-block chaining diverged"
        );
    }
}
