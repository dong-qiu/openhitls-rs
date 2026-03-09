//! x86-64 SHA-NI hardware-accelerated SHA-256 compress function.
//!
//! Uses Intel SHA Extensions (SHA-NI) available on modern x86-64 processors
//! (Intel Goldmont/Ice Lake+, AMD Zen+). Each `_mm_sha256rnds2_epu32` call
//! performs two SHA-256 rounds, so a pair of calls covers four rounds.
//!
//! Based on the well-tested RustCrypto pattern: message schedule is computed
//! in full (sha256msg1 + alignr + sha256msg2) before overwriting registers,
//! avoiding corruption from partial sigma0 values.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// Compute the next 4 expanded message words from four 4-word blocks.
///
/// schedule(v0, v1, v2, v3) = sha256msg2(sha256msg1(v0, v1) + alignr(v3, v2, 4), v3)
///
/// This produces W[t..t+3] from W[t-16..t-13], W[t-12..t-9], W[t-8..t-5], W[t-4..t-1].
#[inline]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn schedule(v0: __m128i, v1: __m128i, v2: __m128i, v3: __m128i) -> __m128i {
    let t1 = _mm_sha256msg1_epu32(v0, v1);
    let t2 = _mm_alignr_epi8(v3, v2, 4);
    let t3 = _mm_add_epi32(t1, t2);
    _mm_sha256msg2_epu32(t3, v3)
}

/// Execute 4 SHA-256 rounds (2 calls to sha256rnds2, each doing 2 rounds).
#[inline]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn rounds4(
    abef: &mut __m128i,
    cdgh: &mut __m128i,
    msg: __m128i,
    k_ptr: *const u32,
    k_offset: usize,
) {
    // SAFETY: caller guarantees CPU feature availability and valid pointer.
    unsafe {
        let kv = _mm_loadu_si128(k_ptr.add(k_offset) as *const __m128i);
        let t1 = _mm_add_epi32(msg, kv);
        *cdgh = _mm_sha256rnds2_epu32(*cdgh, *abef, t1);
        let t2 = _mm_shuffle_epi32(t1, 0x0E);
        *abef = _mm_sha256rnds2_epu32(*abef, *cdgh, t2);
    }
}

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

    // SAFETY: caller guarantees CPU feature availability (sha, sse2, ssse3, sse4.1).
    unsafe {
        // Load current state into two 128-bit registers.
        // state0 holds [A, B, C, D], state1 holds [E, F, G, H] in memory order.
        let mut abef = _mm_loadu_si128(state.as_ptr() as *const __m128i);
        let mut cdgh = _mm_loadu_si128(state[4..].as_ptr() as *const __m128i);

        // SHA-NI expects a specific lane arrangement:
        //   abef = [F, E, B, A] in lane order  (bits [127:96]=A, [95:64]=B, [63:32]=E, [31:0]=F)
        //   cdgh = [H, G, D, C] in lane order  (bits [127:96]=C, [95:64]=D, [63:32]=G, [31:0]=H)
        //
        // Rearrange from standard [A,B,C,D] / [E,F,G,H] layout.
        let cdab = _mm_shuffle_epi32(abef, 0xB1); // [B, A, D, C]
        let efgh = _mm_shuffle_epi32(cdgh, 0x1B); // [H, G, F, E]
        abef = _mm_alignr_epi8(cdab, efgh, 8); // ABEF
        cdgh = _mm_blend_epi16(efgh, cdab, 0xF0); // CDGH

        // Save initial state for the Davies-Meyer feed-forward at the end.
        let abef_save = abef;
        let cdgh_save = cdgh;

        // Byte-swap mask: SHA-256 message words are big-endian, x86 is little-endian.
        let shuf_mask = _mm_set_epi64x(
            0x0c0d0e0f_08090a0b_u64 as i64,
            0x04050607_00010203_u64 as i64,
        );

        // Load four 128-bit message chunks (16 bytes = 4 words each) and byte-swap.
        let mut w0 = _mm_shuffle_epi8(_mm_loadu_si128(block.as_ptr() as *const __m128i), shuf_mask);
        let mut w1 = _mm_shuffle_epi8(
            _mm_loadu_si128(block.as_ptr().add(16) as *const __m128i),
            shuf_mask,
        );
        let mut w2 = _mm_shuffle_epi8(
            _mm_loadu_si128(block.as_ptr().add(32) as *const __m128i),
            shuf_mask,
        );
        let mut w3 = _mm_shuffle_epi8(
            _mm_loadu_si128(block.as_ptr().add(48) as *const __m128i),
            shuf_mask,
        );
        let mut w4: __m128i;

        let k = super::K256.as_ptr();

        // Rounds 0–15: use the original 16 message words directly, no schedule needed.
        rounds4(&mut abef, &mut cdgh, w0, k, 0); // rounds 0–3
        rounds4(&mut abef, &mut cdgh, w1, k, 4); // rounds 4–7
        rounds4(&mut abef, &mut cdgh, w2, k, 8); // rounds 8–11
        rounds4(&mut abef, &mut cdgh, w3, k, 12); // rounds 12–15

        // Rounds 16–63: compute message schedule on-the-fly using 5-register rotation.
        // schedule(a, b, c, d) computes W[t..t+3] from the preceding 16 words.
        w4 = schedule(w0, w1, w2, w3);
        rounds4(&mut abef, &mut cdgh, w4, k, 16); // rounds 16–19

        w0 = schedule(w1, w2, w3, w4);
        rounds4(&mut abef, &mut cdgh, w0, k, 20); // rounds 20–23

        w1 = schedule(w2, w3, w4, w0);
        rounds4(&mut abef, &mut cdgh, w1, k, 24); // rounds 24–27

        w2 = schedule(w3, w4, w0, w1);
        rounds4(&mut abef, &mut cdgh, w2, k, 28); // rounds 28–31

        w3 = schedule(w4, w0, w1, w2);
        rounds4(&mut abef, &mut cdgh, w3, k, 32); // rounds 32–35

        w4 = schedule(w0, w1, w2, w3);
        rounds4(&mut abef, &mut cdgh, w4, k, 36); // rounds 36–39

        w0 = schedule(w1, w2, w3, w4);
        rounds4(&mut abef, &mut cdgh, w0, k, 40); // rounds 40–43

        w1 = schedule(w2, w3, w4, w0);
        rounds4(&mut abef, &mut cdgh, w1, k, 44); // rounds 44–47

        w2 = schedule(w3, w4, w0, w1);
        rounds4(&mut abef, &mut cdgh, w2, k, 48); // rounds 48–51

        w3 = schedule(w4, w0, w1, w2);
        rounds4(&mut abef, &mut cdgh, w3, k, 52); // rounds 52–55

        w4 = schedule(w0, w1, w2, w3);
        rounds4(&mut abef, &mut cdgh, w4, k, 56); // rounds 56–59

        w0 = schedule(w1, w2, w3, w4);
        rounds4(&mut abef, &mut cdgh, w0, k, 60); // rounds 60–63

        // Davies-Meyer feed-forward: add the saved initial state.
        abef = _mm_add_epi32(abef, abef_save);
        cdgh = _mm_add_epi32(cdgh, cdgh_save);

        // Unshuffle back from SHA-NI layout (ABEF / CDGH) to standard (ABCD / EFGH).
        let feba = _mm_shuffle_epi32(abef, 0x1B);
        let dchg = _mm_shuffle_epi32(cdgh, 0xB1);
        let dcba = _mm_blend_epi16(feba, dchg, 0xF0); // [A, B, C, D]
        let hgfe = _mm_alignr_epi8(dchg, feba, 8); // [E, F, G, H]

        // Store state back.
        _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, dcba);
        _mm_storeu_si128(state[4..].as_mut_ptr() as *mut __m128i, hgfe);
    } // unsafe
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
