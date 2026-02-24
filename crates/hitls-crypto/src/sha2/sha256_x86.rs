//! x86-64 SHA-NI hardware-accelerated SHA-256 compress function.
//!
//! Uses Intel SHA Extensions (SHA-NI) available on modern x86-64 processors
//! (Intel Goldmont/Ice Lake+, AMD Zen+). Each `_mm_sha256rnds2_epu32` call
//! performs two SHA-256 rounds, so a pair of calls covers four rounds.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// SHA-256 block compression using x86 SHA-NI intrinsics.
///
/// Processes a single 64-byte block, updating the 8-word state in place.
///
/// # Safety
///
/// Caller must ensure the CPU supports `sha`, `sse2`, `ssse3`, and `sse4.1`
/// features (check with `is_x86_feature_detected!` before calling).
/// The `block` slice must be at least 64 bytes long.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
pub(super) unsafe fn sha256_compress_x86(state: &mut [u32; 8], block: &[u8]) {
    debug_assert!(block.len() >= 64);

    // Load current state into two 128-bit registers.
    // state0 holds [A, B, C, D], state1 holds [E, F, G, H] in memory order.
    let mut state0 = _mm_loadu_si128(state.as_ptr() as *const __m128i);
    let mut state1 = _mm_loadu_si128(state[4..].as_ptr() as *const __m128i);

    // SHA-NI expects a specific lane arrangement:
    //   state0 = (A, B, E, F)  — "ABEF"
    //   state1 = (C, D, G, H)  — "CDGH"
    //
    // Rearrange from standard [A,B,C,D] / [E,F,G,H] layout.
    let tmp = _mm_shuffle_epi32(state0, 0xB1); // [B, A, D, C]
    state1 = _mm_shuffle_epi32(state1, 0x1B); // [H, G, F, E]
    state0 = _mm_alignr_epi8(tmp, state1, 8); // ABEF
    state1 = _mm_blend_epi16(state1, tmp, 0xF0); // CDGH

    // Save initial state for the Davies-Meyer feed-forward at the end.
    let abef_save = state0;
    let cdgh_save = state1;

    // Byte-swap mask: SHA-256 message words are big-endian, x86 is little-endian.
    let shuf_mask = _mm_set_epi64x(
        0x0c0d0e0f_08090a0b_u64 as i64,
        0x04050607_00010203_u64 as i64,
    );

    // Load four 128-bit message chunks (16 bytes = 4 words each) and byte-swap.
    let mut msg0 = _mm_shuffle_epi8(_mm_loadu_si128(block.as_ptr() as *const __m128i), shuf_mask);
    let mut msg1 = _mm_shuffle_epi8(
        _mm_loadu_si128(block.as_ptr().add(16) as *const __m128i),
        shuf_mask,
    );
    let mut msg2 = _mm_shuffle_epi8(
        _mm_loadu_si128(block.as_ptr().add(32) as *const __m128i),
        shuf_mask,
    );
    let mut msg3 = _mm_shuffle_epi8(
        _mm_loadu_si128(block.as_ptr().add(48) as *const __m128i),
        shuf_mask,
    );

    let k = super::K256.as_ptr();
    let mut tmp: __m128i;

    // ===== Rounds 0–3 =====
    tmp = _mm_add_epi32(msg0, _mm_loadu_si128(k.add(0) as *const __m128i));
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
    tmp = _mm_shuffle_epi32(tmp, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    // ===== Rounds 4–7 =====
    tmp = _mm_add_epi32(msg1, _mm_loadu_si128(k.add(4) as *const __m128i));
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
    tmp = _mm_shuffle_epi32(tmp, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    // ===== Rounds 8–11 =====
    tmp = _mm_add_epi32(msg2, _mm_loadu_si128(k.add(8) as *const __m128i));
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
    tmp = _mm_shuffle_epi32(tmp, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    // ===== Rounds 12–15 =====
    tmp = _mm_add_epi32(msg3, _mm_loadu_si128(k.add(12) as *const __m128i));
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
    tmp = _mm_shuffle_epi32(tmp, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
    msg0 = _mm_add_epi32(msg0, _mm_alignr_epi8(msg3, msg2, 4));
    msg0 = _mm_sha256msg2_epu32(msg0, msg3);
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    // ===== Rounds 16–19 =====
    tmp = _mm_add_epi32(msg0, _mm_loadu_si128(k.add(16) as *const __m128i));
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
    tmp = _mm_shuffle_epi32(tmp, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
    msg1 = _mm_add_epi32(msg1, _mm_alignr_epi8(msg0, msg3, 4));
    msg1 = _mm_sha256msg2_epu32(msg1, msg0);
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    // ===== Rounds 20–23 =====
    tmp = _mm_add_epi32(msg1, _mm_loadu_si128(k.add(20) as *const __m128i));
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
    tmp = _mm_shuffle_epi32(tmp, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
    msg2 = _mm_add_epi32(msg2, _mm_alignr_epi8(msg1, msg0, 4));
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    // ===== Rounds 24–27 =====
    tmp = _mm_add_epi32(msg2, _mm_loadu_si128(k.add(24) as *const __m128i));
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
    tmp = _mm_shuffle_epi32(tmp, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
    msg3 = _mm_add_epi32(msg3, _mm_alignr_epi8(msg2, msg1, 4));
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    // ===== Rounds 28–31 =====
    tmp = _mm_add_epi32(msg3, _mm_loadu_si128(k.add(28) as *const __m128i));
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
    tmp = _mm_shuffle_epi32(tmp, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
    msg0 = _mm_add_epi32(msg0, _mm_alignr_epi8(msg3, msg2, 4));
    msg0 = _mm_sha256msg2_epu32(msg0, msg3);
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    // ===== Rounds 32–35 =====
    tmp = _mm_add_epi32(msg0, _mm_loadu_si128(k.add(32) as *const __m128i));
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
    tmp = _mm_shuffle_epi32(tmp, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
    msg1 = _mm_add_epi32(msg1, _mm_alignr_epi8(msg0, msg3, 4));
    msg1 = _mm_sha256msg2_epu32(msg1, msg0);
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    // ===== Rounds 36–39 =====
    tmp = _mm_add_epi32(msg1, _mm_loadu_si128(k.add(36) as *const __m128i));
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
    tmp = _mm_shuffle_epi32(tmp, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
    msg2 = _mm_add_epi32(msg2, _mm_alignr_epi8(msg1, msg0, 4));
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    // ===== Rounds 40–43 =====
    tmp = _mm_add_epi32(msg2, _mm_loadu_si128(k.add(40) as *const __m128i));
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
    tmp = _mm_shuffle_epi32(tmp, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
    msg3 = _mm_add_epi32(msg3, _mm_alignr_epi8(msg2, msg1, 4));
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    // ===== Rounds 44–47 =====
    tmp = _mm_add_epi32(msg3, _mm_loadu_si128(k.add(44) as *const __m128i));
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
    tmp = _mm_shuffle_epi32(tmp, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
    msg0 = _mm_add_epi32(msg0, _mm_alignr_epi8(msg3, msg2, 4));
    msg0 = _mm_sha256msg2_epu32(msg0, msg3);
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    // ===== Rounds 48–51 =====
    tmp = _mm_add_epi32(msg0, _mm_loadu_si128(k.add(48) as *const __m128i));
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
    tmp = _mm_shuffle_epi32(tmp, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
    msg1 = _mm_add_epi32(msg1, _mm_alignr_epi8(msg0, msg3, 4));
    msg1 = _mm_sha256msg2_epu32(msg1, msg0);

    // ===== Rounds 52–55 =====
    tmp = _mm_add_epi32(msg1, _mm_loadu_si128(k.add(52) as *const __m128i));
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
    tmp = _mm_shuffle_epi32(tmp, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
    msg2 = _mm_add_epi32(msg2, _mm_alignr_epi8(msg1, msg0, 4));
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);

    // ===== Rounds 56–59 =====
    tmp = _mm_add_epi32(msg2, _mm_loadu_si128(k.add(56) as *const __m128i));
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
    tmp = _mm_shuffle_epi32(tmp, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);
    msg3 = _mm_add_epi32(msg3, _mm_alignr_epi8(msg2, msg1, 4));
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);

    // ===== Rounds 60–63 =====
    tmp = _mm_add_epi32(msg3, _mm_loadu_si128(k.add(60) as *const __m128i));
    state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
    tmp = _mm_shuffle_epi32(tmp, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);

    // Davies-Meyer feed-forward: add the saved initial state.
    state0 = _mm_add_epi32(state0, abef_save);
    state1 = _mm_add_epi32(state1, cdgh_save);

    // Unshuffle back from SHA-NI layout (ABEF / CDGH) to standard (ABCD / EFGH).
    let tmp = _mm_shuffle_epi32(state0, 0x1B); // FEBA
    state1 = _mm_shuffle_epi32(state1, 0xB1); // DCHG
    state0 = _mm_blend_epi16(tmp, state1, 0xF0); // DCBA → stored as [A,B,C,D]
    state1 = _mm_alignr_epi8(state1, tmp, 8); // HGFE → stored as [E,F,G,H]

    // Store state back.
    _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, state0);
    _mm_storeu_si128(state[4..].as_mut_ptr() as *mut __m128i, state1);
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_sha256_compress_x86_matches_software() {
        if !is_x86_feature_detected!("sha")
            || !is_x86_feature_detected!("sse4.1")
            || !is_x86_feature_detected!("ssse3")
        {
            eprintln!("SHA-NI not available on this CPU, skipping test");
            return;
        }

        // SHA-256 initial state
        let h_init: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        // A single block: the message "abc" padded to 64 bytes per SHA-256 spec.
        let mut block = [0u8; 64];
        block[0] = 0x61; // 'a'
        block[1] = 0x62; // 'b'
        block[2] = 0x63; // 'c'
        block[3] = 0x80; // padding bit
                         // Length in bits = 24 = 0x18, stored in last 8 bytes big-endian.
        block[63] = 0x18;

        // Compute with the hardware path.
        let mut state_hw = h_init;
        unsafe {
            super::sha256_compress_x86(&mut state_hw, &block);
        }

        // Known SHA-256("abc") = ba7816bf 8f01cfea 414140de 5dae2223
        //                         b00361a3 96177a9c b410ff61 f20015ad
        let expected: [u32; 8] = [
            0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
            0xf20015ad,
        ];

        assert_eq!(
            state_hw, expected,
            "SHA-NI compress did not match expected SHA-256(\"abc\")"
        );
    }

    #[test]
    fn test_sha256_compress_x86_empty_message() {
        if !is_x86_feature_detected!("sha")
            || !is_x86_feature_detected!("sse4.1")
            || !is_x86_feature_detected!("ssse3")
        {
            eprintln!("SHA-NI not available on this CPU, skipping test");
            return;
        }

        let h_init: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        // Empty message: just the padding bit and zero length.
        let mut block = [0u8; 64];
        block[0] = 0x80;
        // Length = 0, already zero.

        let mut state_hw = h_init;
        unsafe {
            super::sha256_compress_x86(&mut state_hw, &block);
        }

        // SHA-256("") = e3b0c442 98fc1c14 9afbf4c8 996fb924
        //               27ae41e4 649b934c a495991b 7852b855
        let expected: [u32; 8] = [
            0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b,
            0x7852b855,
        ];

        assert_eq!(
            state_hw, expected,
            "SHA-NI compress did not match expected SHA-256(\"\")"
        );
    }
}
