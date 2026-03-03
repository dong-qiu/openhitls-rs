//! SHA-1 hardware acceleration using ARMv8 Crypto Extension instructions.
//!
//! Uses `vsha1cq_u32`, `vsha1pq_u32`, `vsha1mq_u32` (hash update),
//! `vsha1h_u32` (fixed rotate), and `vsha1su0q_u32`/`vsha1su1q_u32`
//! (message schedule) for high-performance SHA-1 compression.

use core::arch::aarch64::*;

/// SHA-1 compress using ARMv8 Crypto Extension.
///
/// # Safety
///
/// Caller must ensure the CPU supports the ARMv8 SHA-1 Crypto Extension
/// (detected via `is_aarch64_feature_detected!("sha2")`).
#[target_feature(enable = "sha2,neon")]
pub(crate) unsafe fn sha1_compress_arm(state: &mut [u32; 5], block: &[u8]) {
    // Load state: abcd in one uint32x4_t, e as scalar
    let abcd_init = vld1q_u32(state.as_ptr());
    let e_init = state[4];

    let mut abcd = abcd_init;
    let mut e = e_init;

    // Load 16 message words (big-endian -> native via vreinterpretq)
    let mut w0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr())));
    let mut w1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(16))));
    let mut w2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(32))));
    let mut w3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(48))));

    // Rounds 0-3 (Choose)
    let mut tmp = vaddq_u32(w0, vdupq_n_u32(0x5a827999));
    let mut e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    abcd = vsha1cq_u32(abcd, e, tmp);
    w0 = vsha1su1q_u32(vsha1su0q_u32(w0, w1, w2), w3);

    // Rounds 4-7
    tmp = vaddq_u32(w1, vdupq_n_u32(0x5a827999));
    e = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    abcd = vsha1cq_u32(abcd, e0, tmp);
    w1 = vsha1su1q_u32(vsha1su0q_u32(w1, w2, w3), w0);

    // Rounds 8-11
    tmp = vaddq_u32(w2, vdupq_n_u32(0x5a827999));
    e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    abcd = vsha1cq_u32(abcd, e, tmp);
    w2 = vsha1su1q_u32(vsha1su0q_u32(w2, w3, w0), w1);

    // Rounds 12-15
    tmp = vaddq_u32(w3, vdupq_n_u32(0x5a827999));
    e = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    abcd = vsha1cq_u32(abcd, e0, tmp);
    w3 = vsha1su1q_u32(vsha1su0q_u32(w3, w0, w1), w2);

    // Rounds 16-19 (Choose)
    tmp = vaddq_u32(w0, vdupq_n_u32(0x5a827999));
    e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    abcd = vsha1cq_u32(abcd, e, tmp);
    w0 = vsha1su1q_u32(vsha1su0q_u32(w0, w1, w2), w3);

    // Rounds 20-23 (Parity)
    tmp = vaddq_u32(w1, vdupq_n_u32(0x6ed9eba1));
    e = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    abcd = vsha1pq_u32(abcd, e0, tmp);
    w1 = vsha1su1q_u32(vsha1su0q_u32(w1, w2, w3), w0);

    // Rounds 24-27
    tmp = vaddq_u32(w2, vdupq_n_u32(0x6ed9eba1));
    e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    abcd = vsha1pq_u32(abcd, e, tmp);
    w2 = vsha1su1q_u32(vsha1su0q_u32(w2, w3, w0), w1);

    // Rounds 28-31
    tmp = vaddq_u32(w3, vdupq_n_u32(0x6ed9eba1));
    e = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    abcd = vsha1pq_u32(abcd, e0, tmp);
    w3 = vsha1su1q_u32(vsha1su0q_u32(w3, w0, w1), w2);

    // Rounds 32-35
    tmp = vaddq_u32(w0, vdupq_n_u32(0x6ed9eba1));
    e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    abcd = vsha1pq_u32(abcd, e, tmp);
    w0 = vsha1su1q_u32(vsha1su0q_u32(w0, w1, w2), w3);

    // Rounds 36-39
    tmp = vaddq_u32(w1, vdupq_n_u32(0x6ed9eba1));
    e = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    abcd = vsha1pq_u32(abcd, e0, tmp);
    w1 = vsha1su1q_u32(vsha1su0q_u32(w1, w2, w3), w0);

    // Rounds 40-43 (Majority)
    tmp = vaddq_u32(w2, vdupq_n_u32(0x8f1bbcdc));
    e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    abcd = vsha1mq_u32(abcd, e, tmp);
    w2 = vsha1su1q_u32(vsha1su0q_u32(w2, w3, w0), w1);

    // Rounds 44-47
    tmp = vaddq_u32(w3, vdupq_n_u32(0x8f1bbcdc));
    e = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    abcd = vsha1mq_u32(abcd, e0, tmp);
    w3 = vsha1su1q_u32(vsha1su0q_u32(w3, w0, w1), w2);

    // Rounds 48-51
    tmp = vaddq_u32(w0, vdupq_n_u32(0x8f1bbcdc));
    e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    abcd = vsha1mq_u32(abcd, e, tmp);
    w0 = vsha1su1q_u32(vsha1su0q_u32(w0, w1, w2), w3);

    // Rounds 52-55
    tmp = vaddq_u32(w1, vdupq_n_u32(0x8f1bbcdc));
    e = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    abcd = vsha1mq_u32(abcd, e0, tmp);
    w1 = vsha1su1q_u32(vsha1su0q_u32(w1, w2, w3), w0);

    // Rounds 56-59
    tmp = vaddq_u32(w2, vdupq_n_u32(0x8f1bbcdc));
    e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    abcd = vsha1mq_u32(abcd, e, tmp);
    w2 = vsha1su1q_u32(vsha1su0q_u32(w2, w3, w0), w1);

    // Rounds 60-63 (Parity)
    tmp = vaddq_u32(w3, vdupq_n_u32(0xca62c1d6));
    e = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    abcd = vsha1pq_u32(abcd, e0, tmp);
    w3 = vsha1su1q_u32(vsha1su0q_u32(w3, w0, w1), w2);

    // Rounds 64-67
    tmp = vaddq_u32(w0, vdupq_n_u32(0xca62c1d6));
    e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    abcd = vsha1pq_u32(abcd, e, tmp);

    // Rounds 68-71
    tmp = vaddq_u32(w1, vdupq_n_u32(0xca62c1d6));
    e = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    abcd = vsha1pq_u32(abcd, e0, tmp);

    // Rounds 72-75
    tmp = vaddq_u32(w2, vdupq_n_u32(0xca62c1d6));
    e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    abcd = vsha1pq_u32(abcd, e, tmp);

    // Rounds 76-79
    tmp = vaddq_u32(w3, vdupq_n_u32(0xca62c1d6));
    e = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    abcd = vsha1pq_u32(abcd, e0, tmp);

    // Add initial state
    abcd = vaddq_u32(abcd, abcd_init);
    e = e.wrapping_add(e_init);

    // Store back
    vst1q_u32(state.as_mut_ptr(), abcd);
    state[4] = e;
}
