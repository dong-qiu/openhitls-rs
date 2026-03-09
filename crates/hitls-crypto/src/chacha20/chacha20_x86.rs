//! ChaCha20 block function using x86_64 SSE2 intrinsics.
//!
//! Vectorizes the four parallel quarter-round operations within a single
//! ChaCha20 block by packing the 16-word state into 4 row vectors.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// Rotate each u32 lane left by 16 bits.
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn rotl16(v: __m128i) -> __m128i {
    _mm_or_si128(_mm_slli_epi32::<16>(v), _mm_srli_epi32::<16>(v))
}

/// Rotate each u32 lane left by 12 bits.
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn rotl12(v: __m128i) -> __m128i {
    _mm_or_si128(_mm_slli_epi32::<12>(v), _mm_srli_epi32::<20>(v))
}

/// Rotate each u32 lane left by 8 bits.
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn rotl8(v: __m128i) -> __m128i {
    _mm_or_si128(_mm_slli_epi32::<8>(v), _mm_srli_epi32::<24>(v))
}

/// Rotate each u32 lane left by 7 bits.
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn rotl7(v: __m128i) -> __m128i {
    _mm_or_si128(_mm_slli_epi32::<7>(v), _mm_srli_epi32::<25>(v))
}

/// Compute a ChaCha20 64-byte keystream block using SSE2.
///
/// # Safety
/// Requires the `sse2` target feature (always available on x86_64).
#[target_feature(enable = "sse2")]
pub(super) unsafe fn chacha20_block_x86(
    key: &[u8; 32],
    counter: u32,
    nonce: &[u8; 12],
) -> [u8; 64] {
    // SAFETY: caller guarantees CPU supports sse2.
    unsafe {
        // Row 0: constants
        let consts: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
        let v0_init = _mm_loadu_si128(consts.as_ptr() as *const __m128i);

        // Row 1: key[0..16], Row 2: key[16..32]
        let v1_init = _mm_loadu_si128(key.as_ptr() as *const __m128i);
        let v2_init = _mm_loadu_si128(key[16..].as_ptr() as *const __m128i);

        // Row 3: counter || nonce
        let mut cn = [0u8; 16];
        cn[0..4].copy_from_slice(&counter.to_le_bytes());
        cn[4..16].copy_from_slice(nonce);
        let v3_init = _mm_loadu_si128(cn.as_ptr() as *const __m128i);

        let (mut v0, mut v1, mut v2, mut v3) = (v0_init, v1_init, v2_init, v3_init);

        // 10 double rounds
        for _ in 0..10 {
            // Column round
            v0 = _mm_add_epi32(v0, v1);
            v3 = _mm_xor_si128(v3, v0);
            v3 = rotl16(v3);
            v2 = _mm_add_epi32(v2, v3);
            v1 = _mm_xor_si128(v1, v2);
            v1 = rotl12(v1);
            v0 = _mm_add_epi32(v0, v1);
            v3 = _mm_xor_si128(v3, v0);
            v3 = rotl8(v3);
            v2 = _mm_add_epi32(v2, v3);
            v1 = _mm_xor_si128(v1, v2);
            v1 = rotl7(v1);

            // Diagonal round: rotate rows
            v1 = _mm_shuffle_epi32::<0x39>(v1); // [1,2,3,0]
            v2 = _mm_shuffle_epi32::<0x4E>(v2); // [2,3,0,1]
            v3 = _mm_shuffle_epi32::<0x93>(v3); // [3,0,1,2]

            v0 = _mm_add_epi32(v0, v1);
            v3 = _mm_xor_si128(v3, v0);
            v3 = rotl16(v3);
            v2 = _mm_add_epi32(v2, v3);
            v1 = _mm_xor_si128(v1, v2);
            v1 = rotl12(v1);
            v0 = _mm_add_epi32(v0, v1);
            v3 = _mm_xor_si128(v3, v0);
            v3 = rotl8(v3);
            v2 = _mm_add_epi32(v2, v3);
            v1 = _mm_xor_si128(v1, v2);
            v1 = rotl7(v1);

            // Un-rotate rows
            v1 = _mm_shuffle_epi32::<0x93>(v1); // [3,0,1,2]
            v2 = _mm_shuffle_epi32::<0x4E>(v2); // [2,3,0,1]
            v3 = _mm_shuffle_epi32::<0x39>(v3); // [1,2,3,0]
        }

        // Add initial state
        v0 = _mm_add_epi32(v0, v0_init);
        v1 = _mm_add_epi32(v1, v1_init);
        v2 = _mm_add_epi32(v2, v2_init);
        v3 = _mm_add_epi32(v3, v3_init);

        // Store as little-endian bytes
        let mut out = [0u8; 64];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, v0);
        _mm_storeu_si128(out[16..].as_mut_ptr() as *mut __m128i, v1);
        _mm_storeu_si128(out[32..].as_mut_ptr() as *mut __m128i, v2);
        _mm_storeu_si128(out[48..].as_mut_ptr() as *mut __m128i, v3);

        out
    }
}

/// Compute two ChaCha20 64-byte keystream blocks (128 bytes) for consecutive counters.
///
/// # Safety
/// Requires the `sse2` target feature.
#[target_feature(enable = "sse2")]
pub(super) unsafe fn chacha20_2_blocks_x86(
    key: &[u8; 32],
    counter: u32,
    nonce: &[u8; 12],
) -> [u8; 128] {
    // SAFETY: caller guarantees CPU supports sse2.
    unsafe {
        let consts: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
        let v0_init = _mm_loadu_si128(consts.as_ptr() as *const __m128i);
        let v1_init = _mm_loadu_si128(key.as_ptr() as *const __m128i);
        let v2_init = _mm_loadu_si128(key[16..].as_ptr() as *const __m128i);

        let mut cn_a = [0u8; 16];
        cn_a[0..4].copy_from_slice(&counter.to_le_bytes());
        cn_a[4..16].copy_from_slice(nonce);
        let v3a_init = _mm_loadu_si128(cn_a.as_ptr() as *const __m128i);

        let mut cn_b = [0u8; 16];
        cn_b[0..4].copy_from_slice(&counter.wrapping_add(1).to_le_bytes());
        cn_b[4..16].copy_from_slice(nonce);
        let v3b_init = _mm_loadu_si128(cn_b.as_ptr() as *const __m128i);

        let (mut v0a, mut v1a, mut v2a, mut v3a) = (v0_init, v1_init, v2_init, v3a_init);
        let (mut v0b, mut v1b, mut v2b, mut v3b) = (v0_init, v1_init, v2_init, v3b_init);

        for _ in 0..10 {
            // Column round — interleaved
            v0a = _mm_add_epi32(v0a, v1a);
            v0b = _mm_add_epi32(v0b, v1b);
            v3a = _mm_xor_si128(v3a, v0a);
            v3b = _mm_xor_si128(v3b, v0b);
            v3a = rotl16(v3a);
            v3b = rotl16(v3b);
            v2a = _mm_add_epi32(v2a, v3a);
            v2b = _mm_add_epi32(v2b, v3b);
            v1a = _mm_xor_si128(v1a, v2a);
            v1b = _mm_xor_si128(v1b, v2b);
            v1a = rotl12(v1a);
            v1b = rotl12(v1b);
            v0a = _mm_add_epi32(v0a, v1a);
            v0b = _mm_add_epi32(v0b, v1b);
            v3a = _mm_xor_si128(v3a, v0a);
            v3b = _mm_xor_si128(v3b, v0b);
            v3a = rotl8(v3a);
            v3b = rotl8(v3b);
            v2a = _mm_add_epi32(v2a, v3a);
            v2b = _mm_add_epi32(v2b, v3b);
            v1a = _mm_xor_si128(v1a, v2a);
            v1b = _mm_xor_si128(v1b, v2b);
            v1a = rotl7(v1a);
            v1b = rotl7(v1b);

            // Diagonal round
            v1a = _mm_shuffle_epi32::<0x39>(v1a);
            v1b = _mm_shuffle_epi32::<0x39>(v1b);
            v2a = _mm_shuffle_epi32::<0x4E>(v2a);
            v2b = _mm_shuffle_epi32::<0x4E>(v2b);
            v3a = _mm_shuffle_epi32::<0x93>(v3a);
            v3b = _mm_shuffle_epi32::<0x93>(v3b);

            v0a = _mm_add_epi32(v0a, v1a);
            v0b = _mm_add_epi32(v0b, v1b);
            v3a = _mm_xor_si128(v3a, v0a);
            v3b = _mm_xor_si128(v3b, v0b);
            v3a = rotl16(v3a);
            v3b = rotl16(v3b);
            v2a = _mm_add_epi32(v2a, v3a);
            v2b = _mm_add_epi32(v2b, v3b);
            v1a = _mm_xor_si128(v1a, v2a);
            v1b = _mm_xor_si128(v1b, v2b);
            v1a = rotl12(v1a);
            v1b = rotl12(v1b);
            v0a = _mm_add_epi32(v0a, v1a);
            v0b = _mm_add_epi32(v0b, v1b);
            v3a = _mm_xor_si128(v3a, v0a);
            v3b = _mm_xor_si128(v3b, v0b);
            v3a = rotl8(v3a);
            v3b = rotl8(v3b);
            v2a = _mm_add_epi32(v2a, v3a);
            v2b = _mm_add_epi32(v2b, v3b);
            v1a = _mm_xor_si128(v1a, v2a);
            v1b = _mm_xor_si128(v1b, v2b);
            v1a = rotl7(v1a);
            v1b = rotl7(v1b);

            // Un-rotate
            v1a = _mm_shuffle_epi32::<0x93>(v1a);
            v1b = _mm_shuffle_epi32::<0x93>(v1b);
            v2a = _mm_shuffle_epi32::<0x4E>(v2a);
            v2b = _mm_shuffle_epi32::<0x4E>(v2b);
            v3a = _mm_shuffle_epi32::<0x39>(v3a);
            v3b = _mm_shuffle_epi32::<0x39>(v3b);
        }

        v0a = _mm_add_epi32(v0a, v0_init);
        v1a = _mm_add_epi32(v1a, v1_init);
        v2a = _mm_add_epi32(v2a, v2_init);
        v3a = _mm_add_epi32(v3a, v3a_init);
        v0b = _mm_add_epi32(v0b, v0_init);
        v1b = _mm_add_epi32(v1b, v1_init);
        v2b = _mm_add_epi32(v2b, v2_init);
        v3b = _mm_add_epi32(v3b, v3b_init);

        let mut out = [0u8; 128];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, v0a);
        _mm_storeu_si128(out[16..].as_mut_ptr() as *mut __m128i, v1a);
        _mm_storeu_si128(out[32..].as_mut_ptr() as *mut __m128i, v2a);
        _mm_storeu_si128(out[48..].as_mut_ptr() as *mut __m128i, v3a);
        _mm_storeu_si128(out[64..].as_mut_ptr() as *mut __m128i, v0b);
        _mm_storeu_si128(out[80..].as_mut_ptr() as *mut __m128i, v1b);
        _mm_storeu_si128(out[96..].as_mut_ptr() as *mut __m128i, v2b);
        _mm_storeu_si128(out[112..].as_mut_ptr() as *mut __m128i, v3b);

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x86_matches_scalar() {
        if !is_x86_feature_detected!("sse2") {
            return;
        }
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
        let x86 = unsafe { chacha20_block_x86(&key, counter, &nonce) };
        assert_eq!(scalar, x86, "SSE2 block must match scalar block");
    }

    #[test]
    fn test_x86_counter_zero() {
        if !is_x86_feature_detected!("sse2") {
            return;
        }
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];

        let scalar = crate::chacha20::chacha20_block_soft(&key, 0, &nonce);
        let x86 = unsafe { chacha20_block_x86(&key, 0, &nonce) };
        assert_eq!(scalar, x86);
    }
}
