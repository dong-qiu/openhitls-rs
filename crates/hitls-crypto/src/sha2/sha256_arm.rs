//! ARMv8 hardware-accelerated SHA-256 compress function.
//!
//! Uses the ARMv8 Cryptography Extensions (CE) SHA-256 instructions via
//! `core::arch::aarch64` intrinsics. These instructions process four rounds
//! at a time, making the full 64-round compression significantly faster
//! than the software implementation.
//!
//! # Safety
//!
//! The public function in this module requires the `sha2` and `neon` target
//! features to be available at runtime. Callers must verify CPU support
//! (e.g., via `std::arch::is_aarch64_feature_detected!("sha2")`) before
//! invoking `sha256_compress_arm`.

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::{
    uint32x4_t, vaddq_u32, vld1q_u32, vreinterpretq_u32_u8, vreinterpretq_u8_u32, vrev32q_u8,
    vsha256h2q_u32, vsha256hq_u32, vsha256su0q_u32, vsha256su1q_u32, vst1q_u32,
};

use super::K256;

/// Load a 128-bit message chunk from `block` at the given word offset,
/// byte-swap from big-endian (SHA-256 wire format) to native little-endian,
/// and add the corresponding four round constants.
///
/// # Safety
///
/// Requires `neon` and `sha2` target features. `ptr` must point to at least
/// `(offset + 4) * 4` valid bytes.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn load_msg_and_add_k(block_ptr: *const u32, k_ptr: *const u32) -> uint32x4_t {
    // Load 4 message words (little-endian on ARM)
    let msg = vld1q_u32(block_ptr);
    // Byte-swap each 32-bit lane to convert from big-endian (SHA-256) to native
    let msg = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg)));
    // Add round constants
    vaddq_u32(msg, vld1q_u32(k_ptr))
}

/// ARMv8 SHA-256 hardware-accelerated compression function.
///
/// Processes a single 64-byte block and updates the 8-word state in place.
/// This function performs all 64 SHA-256 rounds using the ARMv8 CE SHA-256
/// instructions (`vsha256hq_u32`, `vsha256h2q_u32`, `vsha256su0q_u32`,
/// `vsha256su1q_u32`), which compute four rounds per instruction pair.
///
/// # Safety
///
/// This function requires the CPU to support the `sha2` and `neon` SIMD
/// extensions. The caller **must** verify this at runtime before calling.
///
/// # Arguments
///
/// * `state` - The 8-word SHA-256 chaining value `[a, b, c, d, e, f, g, h]`.
/// * `block` - Exactly 64 bytes of message data to compress.
///
/// # Panics
///
/// Debug-asserts that `block.len() >= 64`.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha2,neon")]
pub(super) unsafe fn sha256_compress_arm(state: &mut [u32; 8], block: &[u8]) {
    debug_assert!(block.len() >= 64);

    let block_ptr = block.as_ptr() as *const u32;
    let k_ptr = K256.as_ptr();

    // Load current hash state into two NEON registers.
    // ARM SHA-256 intrinsics expect:
    //   abcd = (a, b, c, d) = state[0..4]
    //   efgh = (e, f, g, h) = state[4..8]
    let mut abcd = vld1q_u32(state.as_ptr());
    let mut efgh = vld1q_u32(state.as_ptr().add(4));

    // Save the initial state for the final addition (Davies-Meyer).
    let abcd_save = abcd;
    let efgh_save = efgh;

    // ---------------------------------------------------------------
    // Load and byte-swap all 16 message words (4 NEON registers).
    // We keep the raw (byte-swapped) messages in msg0..msg3 for the
    // message schedule, and compute msg + K separately for rounds.
    // ---------------------------------------------------------------
    let mut msg0 = vld1q_u32(block_ptr);
    msg0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg0)));
    let mut msg1 = vld1q_u32(block_ptr.add(4));
    msg1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg1)));
    let mut msg2 = vld1q_u32(block_ptr.add(8));
    msg2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg2)));
    let mut msg3 = vld1q_u32(block_ptr.add(12));
    msg3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg3)));

    // ---------------------------------------------------------------
    // Rounds 0–3
    // ---------------------------------------------------------------
    let mut tmp = vaddq_u32(msg0, vld1q_u32(k_ptr));
    let mut abcd_tmp = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_tmp, tmp);

    // ---------------------------------------------------------------
    // Rounds 4–7
    // ---------------------------------------------------------------
    tmp = vaddq_u32(msg1, vld1q_u32(k_ptr.add(4)));
    abcd_tmp = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_tmp, tmp);
    // Message schedule: update msg0 for rounds 16–19
    msg0 = vsha256su0q_u32(msg0, msg1);
    msg0 = vsha256su1q_u32(msg0, msg2, msg3);

    // ---------------------------------------------------------------
    // Rounds 8–11
    // ---------------------------------------------------------------
    tmp = vaddq_u32(msg2, vld1q_u32(k_ptr.add(8)));
    abcd_tmp = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_tmp, tmp);
    // Message schedule: update msg1 for rounds 20–23
    msg1 = vsha256su0q_u32(msg1, msg2);
    msg1 = vsha256su1q_u32(msg1, msg3, msg0);

    // ---------------------------------------------------------------
    // Rounds 12–15
    // ---------------------------------------------------------------
    tmp = vaddq_u32(msg3, vld1q_u32(k_ptr.add(12)));
    abcd_tmp = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_tmp, tmp);
    // Message schedule: update msg2 for rounds 24–27
    msg2 = vsha256su0q_u32(msg2, msg3);
    msg2 = vsha256su1q_u32(msg2, msg0, msg1);

    // ---------------------------------------------------------------
    // Rounds 16–19
    // ---------------------------------------------------------------
    tmp = vaddq_u32(msg0, vld1q_u32(k_ptr.add(16)));
    abcd_tmp = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_tmp, tmp);
    // Message schedule: update msg3 for rounds 28–31
    msg3 = vsha256su0q_u32(msg3, msg0);
    msg3 = vsha256su1q_u32(msg3, msg1, msg2);

    // ---------------------------------------------------------------
    // Rounds 20–23
    // ---------------------------------------------------------------
    tmp = vaddq_u32(msg1, vld1q_u32(k_ptr.add(20)));
    abcd_tmp = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_tmp, tmp);
    // Message schedule: update msg0 for rounds 32–35
    msg0 = vsha256su0q_u32(msg0, msg1);
    msg0 = vsha256su1q_u32(msg0, msg2, msg3);

    // ---------------------------------------------------------------
    // Rounds 24–27
    // ---------------------------------------------------------------
    tmp = vaddq_u32(msg2, vld1q_u32(k_ptr.add(24)));
    abcd_tmp = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_tmp, tmp);
    // Message schedule: update msg1 for rounds 36–39
    msg1 = vsha256su0q_u32(msg1, msg2);
    msg1 = vsha256su1q_u32(msg1, msg3, msg0);

    // ---------------------------------------------------------------
    // Rounds 28–31
    // ---------------------------------------------------------------
    tmp = vaddq_u32(msg3, vld1q_u32(k_ptr.add(28)));
    abcd_tmp = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_tmp, tmp);
    // Message schedule: update msg2 for rounds 40–43
    msg2 = vsha256su0q_u32(msg2, msg3);
    msg2 = vsha256su1q_u32(msg2, msg0, msg1);

    // ---------------------------------------------------------------
    // Rounds 32–35
    // ---------------------------------------------------------------
    tmp = vaddq_u32(msg0, vld1q_u32(k_ptr.add(32)));
    abcd_tmp = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_tmp, tmp);
    // Message schedule: update msg3 for rounds 44–47
    msg3 = vsha256su0q_u32(msg3, msg0);
    msg3 = vsha256su1q_u32(msg3, msg1, msg2);

    // ---------------------------------------------------------------
    // Rounds 36–39
    // ---------------------------------------------------------------
    tmp = vaddq_u32(msg1, vld1q_u32(k_ptr.add(36)));
    abcd_tmp = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_tmp, tmp);
    // Message schedule: update msg0 for rounds 48–51
    msg0 = vsha256su0q_u32(msg0, msg1);
    msg0 = vsha256su1q_u32(msg0, msg2, msg3);

    // ---------------------------------------------------------------
    // Rounds 40–43
    // ---------------------------------------------------------------
    tmp = vaddq_u32(msg2, vld1q_u32(k_ptr.add(40)));
    abcd_tmp = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_tmp, tmp);
    // Message schedule: update msg1 for rounds 52–55
    msg1 = vsha256su0q_u32(msg1, msg2);
    msg1 = vsha256su1q_u32(msg1, msg3, msg0);

    // ---------------------------------------------------------------
    // Rounds 44–47
    // ---------------------------------------------------------------
    tmp = vaddq_u32(msg3, vld1q_u32(k_ptr.add(44)));
    abcd_tmp = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_tmp, tmp);
    // Message schedule: update msg2 for rounds 56–59
    msg2 = vsha256su0q_u32(msg2, msg3);
    msg2 = vsha256su1q_u32(msg2, msg0, msg1);

    // ---------------------------------------------------------------
    // Rounds 48–51
    // ---------------------------------------------------------------
    tmp = vaddq_u32(msg0, vld1q_u32(k_ptr.add(48)));
    abcd_tmp = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_tmp, tmp);
    // Message schedule: update msg3 for rounds 60–63
    msg3 = vsha256su0q_u32(msg3, msg0);
    msg3 = vsha256su1q_u32(msg3, msg1, msg2);

    // ---------------------------------------------------------------
    // Rounds 52–55
    // ---------------------------------------------------------------
    tmp = vaddq_u32(msg1, vld1q_u32(k_ptr.add(52)));
    abcd_tmp = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_tmp, tmp);

    // ---------------------------------------------------------------
    // Rounds 56–59
    // ---------------------------------------------------------------
    tmp = vaddq_u32(msg2, vld1q_u32(k_ptr.add(56)));
    abcd_tmp = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_tmp, tmp);

    // ---------------------------------------------------------------
    // Rounds 60–63
    // ---------------------------------------------------------------
    tmp = vaddq_u32(msg3, vld1q_u32(k_ptr.add(60)));
    abcd_tmp = abcd;
    abcd = vsha256hq_u32(abcd, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_tmp, tmp);

    // ---------------------------------------------------------------
    // Davies-Meyer feed-forward: add saved initial state.
    // ---------------------------------------------------------------
    abcd = vaddq_u32(abcd, abcd_save);
    efgh = vaddq_u32(efgh, efgh_save);

    // ---------------------------------------------------------------
    // Store the updated state back.
    // ---------------------------------------------------------------
    vst1q_u32(state.as_mut_ptr(), abcd);
    vst1q_u32(state.as_mut_ptr().add(4), efgh);
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests {
    use super::*;

    /// Verify that the ARM hardware SHA-256 compress produces identical
    /// results to the software implementation for the empty-string hash.
    ///
    /// SHA-256("") = e3b0c44298fc1c14...
    /// We manually construct the padded single block and compress it.
    #[test]
    fn test_sha256_arm_matches_software() {
        // Check that the CPU actually supports SHA-2 instructions.
        if !std::arch::is_aarch64_feature_detected!("sha2") {
            eprintln!("Skipping ARM SHA-256 test: CPU does not support sha2 extension");
            return;
        }

        // SHA-256 initial state
        let h0: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        // Padded block for the empty message:
        // 0x80 followed by zeros, then 64-bit big-endian length = 0
        let mut block = [0u8; 64];
        block[0] = 0x80;
        // Length in bits = 0, already zero.

        // Software compress
        let mut state_sw = h0;
        super::super::sha256_compress(&mut state_sw, &block);

        // Hardware compress
        let mut state_hw = h0;
        unsafe {
            sha256_compress_arm(&mut state_hw, &block);
        }

        assert_eq!(
            state_sw, state_hw,
            "ARM SHA-256 compress mismatch for empty-string block"
        );

        // Also verify the final hash is the known SHA-256("") digest.
        let expected: [u32; 8] = [
            0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b,
            0x7852b855,
        ];
        assert_eq!(state_hw, expected, "SHA-256('') digest mismatch");
    }

    /// Test with the classic "abc" message (a single 64-byte padded block).
    #[test]
    fn test_sha256_arm_abc() {
        if !std::arch::is_aarch64_feature_detected!("sha2") {
            eprintln!("Skipping ARM SHA-256 test: CPU does not support sha2 extension");
            return;
        }

        let h0: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        // Padded block for "abc" (3 bytes = 24 bits)
        let mut block = [0u8; 64];
        block[0] = b'a';
        block[1] = b'b';
        block[2] = b'c';
        block[3] = 0x80;
        // Length in bits = 24 = 0x18, stored as big-endian u64 at offset 56
        block[63] = 0x18;

        let mut state_sw = h0;
        super::super::sha256_compress(&mut state_sw, &block);

        let mut state_hw = h0;
        unsafe {
            sha256_compress_arm(&mut state_hw, &block);
        }

        assert_eq!(
            state_sw, state_hw,
            "ARM SHA-256 compress mismatch for 'abc' block"
        );

        // SHA-256("abc") = ba7816bf 8f01cfea 414140de 5dae2223
        //                   b00361a3 96177a9c b410ff61 f20015ad
        let expected: [u32; 8] = [
            0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
            0xf20015ad,
        ];
        assert_eq!(state_hw, expected, "SHA-256('abc') digest mismatch");
    }

    /// Test with a block of all 0xFF bytes to exercise different bit patterns.
    #[test]
    fn test_sha256_arm_all_ones_block() {
        if !std::arch::is_aarch64_feature_detected!("sha2") {
            eprintln!("Skipping ARM SHA-256 test: CPU does not support sha2 extension");
            return;
        }

        let h0: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let block = [0xFFu8; 64];

        let mut state_sw = h0;
        super::super::sha256_compress(&mut state_sw, &block);

        let mut state_hw = h0;
        unsafe {
            sha256_compress_arm(&mut state_hw, &block);
        }

        assert_eq!(
            state_sw, state_hw,
            "ARM SHA-256 compress mismatch for all-0xFF block"
        );
    }
}
