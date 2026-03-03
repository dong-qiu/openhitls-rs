//! ChaCha20 block function using ARMv8 NEON intrinsics.
//!
//! Vectorizes the four parallel quarter-round operations within a single
//! ChaCha20 block by packing the 16-word state into 4 row vectors.

use core::arch::aarch64::*;

/// Rotate each u32 lane left by 16 bits using half-word reversal.
#[inline(always)]
unsafe fn vrotl16(v: uint32x4_t) -> uint32x4_t {
    vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(v)))
}

/// Rotate each u32 lane left by 12 bits.
#[inline(always)]
unsafe fn vrotl12(v: uint32x4_t) -> uint32x4_t {
    vorrq_u32(vshlq_n_u32::<12>(v), vshrq_n_u32::<20>(v))
}

/// Rotate each u32 lane left by 8 bits using byte table lookup.
#[inline(always)]
unsafe fn vrotl8(v: uint32x4_t) -> uint32x4_t {
    let idx = vld1q_u8([3u8, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14].as_ptr());
    vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(v), idx))
}

/// Rotate each u32 lane left by 7 bits.
#[inline(always)]
unsafe fn vrotl7(v: uint32x4_t) -> uint32x4_t {
    vorrq_u32(vshlq_n_u32::<7>(v), vshrq_n_u32::<25>(v))
}

/// Compute a ChaCha20 64-byte keystream block using NEON.
///
/// # Safety
/// Requires the `neon` target feature (always available on aarch64).
#[target_feature(enable = "neon")]
pub(super) unsafe fn chacha20_block_neon(
    key: &[u8; 32],
    counter: u32,
    nonce: &[u8; 12],
) -> [u8; 64] {
    // Row 0: constants "expand 32-byte k"
    let consts: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
    let v0_init = vld1q_u32(consts.as_ptr());

    // Row 1: key[0..16], Row 2: key[16..32] — load as bytes to avoid alignment
    let v1_init = vreinterpretq_u32_u8(vld1q_u8(key.as_ptr()));
    let v2_init = vreinterpretq_u32_u8(vld1q_u8(key[16..].as_ptr()));

    // Row 3: counter || nonce
    let mut cn = [0u8; 16];
    cn[0..4].copy_from_slice(&counter.to_le_bytes());
    cn[4..16].copy_from_slice(nonce);
    let v3_init = vreinterpretq_u32_u8(vld1q_u8(cn.as_ptr()));

    let (mut v0, mut v1, mut v2, mut v3) = (v0_init, v1_init, v2_init, v3_init);

    // 10 double rounds (20 rounds total)
    for _ in 0..10 {
        // Column round — operates on all 4 columns simultaneously
        v0 = vaddq_u32(v0, v1);
        v3 = veorq_u32(v3, v0);
        v3 = vrotl16(v3);
        v2 = vaddq_u32(v2, v3);
        v1 = veorq_u32(v1, v2);
        v1 = vrotl12(v1);
        v0 = vaddq_u32(v0, v1);
        v3 = veorq_u32(v3, v0);
        v3 = vrotl8(v3);
        v2 = vaddq_u32(v2, v3);
        v1 = veorq_u32(v1, v2);
        v1 = vrotl7(v1);

        // Diagonal round — rotate rows to align diagonals, then column ops
        v1 = vextq_u32::<1>(v1, v1);
        v2 = vextq_u32::<2>(v2, v2);
        v3 = vextq_u32::<3>(v3, v3);

        v0 = vaddq_u32(v0, v1);
        v3 = veorq_u32(v3, v0);
        v3 = vrotl16(v3);
        v2 = vaddq_u32(v2, v3);
        v1 = veorq_u32(v1, v2);
        v1 = vrotl12(v1);
        v0 = vaddq_u32(v0, v1);
        v3 = veorq_u32(v3, v0);
        v3 = vrotl8(v3);
        v2 = vaddq_u32(v2, v3);
        v1 = veorq_u32(v1, v2);
        v1 = vrotl7(v1);

        // Un-rotate rows
        v1 = vextq_u32::<3>(v1, v1);
        v2 = vextq_u32::<2>(v2, v2);
        v3 = vextq_u32::<1>(v3, v3);
    }

    // Add initial state
    v0 = vaddq_u32(v0, v0_init);
    v1 = vaddq_u32(v1, v1_init);
    v2 = vaddq_u32(v2, v2_init);
    v3 = vaddq_u32(v3, v3_init);

    // Store as little-endian bytes
    let mut out = [0u8; 64];
    vst1q_u8(out.as_mut_ptr(), vreinterpretq_u8_u32(v0));
    vst1q_u8(out[16..].as_mut_ptr(), vreinterpretq_u8_u32(v1));
    vst1q_u8(out[32..].as_mut_ptr(), vreinterpretq_u8_u32(v2));
    vst1q_u8(out[48..].as_mut_ptr(), vreinterpretq_u8_u32(v3));

    out
}

/// Compute two ChaCha20 64-byte keystream blocks (128 bytes) for consecutive counters.
///
/// # Safety
/// Requires the `neon` target feature.
#[target_feature(enable = "neon")]
pub(super) unsafe fn chacha20_2_blocks_neon(
    key: &[u8; 32],
    counter: u32,
    nonce: &[u8; 12],
) -> [u8; 128] {
    // Shared setup
    let consts: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
    let v0_init = vld1q_u32(consts.as_ptr());
    let v1_init = vreinterpretq_u32_u8(vld1q_u8(key.as_ptr()));
    let v2_init = vreinterpretq_u32_u8(vld1q_u8(key[16..].as_ptr()));

    // Row 3 differs only in counter
    let mut cn_a = [0u8; 16];
    cn_a[0..4].copy_from_slice(&counter.to_le_bytes());
    cn_a[4..16].copy_from_slice(nonce);
    let v3a_init = vreinterpretq_u32_u8(vld1q_u8(cn_a.as_ptr()));

    let mut cn_b = [0u8; 16];
    cn_b[0..4].copy_from_slice(&counter.wrapping_add(1).to_le_bytes());
    cn_b[4..16].copy_from_slice(nonce);
    let v3b_init = vreinterpretq_u32_u8(vld1q_u8(cn_b.as_ptr()));

    let (mut v0a, mut v1a, mut v2a, mut v3a) = (v0_init, v1_init, v2_init, v3a_init);
    let (mut v0b, mut v1b, mut v2b, mut v3b) = (v0_init, v1_init, v2_init, v3b_init);

    for _ in 0..10 {
        // Column round — interleaved A and B
        v0a = vaddq_u32(v0a, v1a);
        v0b = vaddq_u32(v0b, v1b);
        v3a = veorq_u32(v3a, v0a);
        v3b = veorq_u32(v3b, v0b);
        v3a = vrotl16(v3a);
        v3b = vrotl16(v3b);
        v2a = vaddq_u32(v2a, v3a);
        v2b = vaddq_u32(v2b, v3b);
        v1a = veorq_u32(v1a, v2a);
        v1b = veorq_u32(v1b, v2b);
        v1a = vrotl12(v1a);
        v1b = vrotl12(v1b);
        v0a = vaddq_u32(v0a, v1a);
        v0b = vaddq_u32(v0b, v1b);
        v3a = veorq_u32(v3a, v0a);
        v3b = veorq_u32(v3b, v0b);
        v3a = vrotl8(v3a);
        v3b = vrotl8(v3b);
        v2a = vaddq_u32(v2a, v3a);
        v2b = vaddq_u32(v2b, v3b);
        v1a = veorq_u32(v1a, v2a);
        v1b = veorq_u32(v1b, v2b);
        v1a = vrotl7(v1a);
        v1b = vrotl7(v1b);

        // Diagonal round — rotate rows
        v1a = vextq_u32::<1>(v1a, v1a);
        v1b = vextq_u32::<1>(v1b, v1b);
        v2a = vextq_u32::<2>(v2a, v2a);
        v2b = vextq_u32::<2>(v2b, v2b);
        v3a = vextq_u32::<3>(v3a, v3a);
        v3b = vextq_u32::<3>(v3b, v3b);

        v0a = vaddq_u32(v0a, v1a);
        v0b = vaddq_u32(v0b, v1b);
        v3a = veorq_u32(v3a, v0a);
        v3b = veorq_u32(v3b, v0b);
        v3a = vrotl16(v3a);
        v3b = vrotl16(v3b);
        v2a = vaddq_u32(v2a, v3a);
        v2b = vaddq_u32(v2b, v3b);
        v1a = veorq_u32(v1a, v2a);
        v1b = veorq_u32(v1b, v2b);
        v1a = vrotl12(v1a);
        v1b = vrotl12(v1b);
        v0a = vaddq_u32(v0a, v1a);
        v0b = vaddq_u32(v0b, v1b);
        v3a = veorq_u32(v3a, v0a);
        v3b = veorq_u32(v3b, v0b);
        v3a = vrotl8(v3a);
        v3b = vrotl8(v3b);
        v2a = vaddq_u32(v2a, v3a);
        v2b = vaddq_u32(v2b, v3b);
        v1a = veorq_u32(v1a, v2a);
        v1b = veorq_u32(v1b, v2b);
        v1a = vrotl7(v1a);
        v1b = vrotl7(v1b);

        // Un-rotate rows
        v1a = vextq_u32::<3>(v1a, v1a);
        v1b = vextq_u32::<3>(v1b, v1b);
        v2a = vextq_u32::<2>(v2a, v2a);
        v2b = vextq_u32::<2>(v2b, v2b);
        v3a = vextq_u32::<1>(v3a, v3a);
        v3b = vextq_u32::<1>(v3b, v3b);
    }

    // Add initial state
    v0a = vaddq_u32(v0a, v0_init);
    v1a = vaddq_u32(v1a, v1_init);
    v2a = vaddq_u32(v2a, v2_init);
    v3a = vaddq_u32(v3a, v3a_init);
    v0b = vaddq_u32(v0b, v0_init);
    v1b = vaddq_u32(v1b, v1_init);
    v2b = vaddq_u32(v2b, v2_init);
    v3b = vaddq_u32(v3b, v3b_init);

    let mut out = [0u8; 128];
    vst1q_u8(out.as_mut_ptr(), vreinterpretq_u8_u32(v0a));
    vst1q_u8(out[16..].as_mut_ptr(), vreinterpretq_u8_u32(v1a));
    vst1q_u8(out[32..].as_mut_ptr(), vreinterpretq_u8_u32(v2a));
    vst1q_u8(out[48..].as_mut_ptr(), vreinterpretq_u8_u32(v3a));
    vst1q_u8(out[64..].as_mut_ptr(), vreinterpretq_u8_u32(v0b));
    vst1q_u8(out[80..].as_mut_ptr(), vreinterpretq_u8_u32(v1b));
    vst1q_u8(out[96..].as_mut_ptr(), vreinterpretq_u8_u32(v2b));
    vst1q_u8(out[112..].as_mut_ptr(), vreinterpretq_u8_u32(v3b));

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_neon_matches_scalar() {
        // RFC 8439 §2.3.2 test vector
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let counter = 1u32;

        let scalar = crate::chacha20::chacha20_block_soft(&key, counter, &nonce);
        let neon = unsafe { chacha20_block_neon(&key, counter, &nonce) };
        assert_eq!(scalar, neon, "NEON block must match scalar block");
    }

    #[test]
    fn test_neon_counter_zero() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];

        let scalar = crate::chacha20::chacha20_block_soft(&key, 0, &nonce);
        let neon = unsafe { chacha20_block_neon(&key, 0, &nonce) };
        assert_eq!(scalar, neon);
    }

    #[test]
    fn test_neon_all_ff_key() {
        let key = [0xFFu8; 32];
        let nonce = [0xFFu8; 12];

        let scalar = crate::chacha20::chacha20_block_soft(&key, u32::MAX, &nonce);
        let neon = unsafe { chacha20_block_neon(&key, u32::MAX, &nonce) };
        assert_eq!(scalar, neon);
    }
}
