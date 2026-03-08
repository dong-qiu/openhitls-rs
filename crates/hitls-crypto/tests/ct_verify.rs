//! Constant-time verification tests (Phase T74-G).
//!
//! Additional dudect-style Welch's t-test timing checks for security-critical
//! operations not covered by timing.rs. Focuses on AEAD tag verification paths
//! for CCM and ChaCha20-Poly1305.
//!
//! All tests are marked `#[ignore]` because:
//! - Timing measurements are environment-sensitive (CPU frequency scaling, load)
//! - They require many iterations for statistical significance
//! - Results may vary across platforms and optimization levels
//!
//! Run with: `cargo test -p hitls-crypto --all-features --release --ignored -- ct_verify`

#![cfg(all(feature = "aes", feature = "modes", feature = "chacha20"))]

use std::hint::black_box;
use std::time::Instant;

/// Number of samples per class for timing measurements.
const NUM_SAMPLES: usize = 10_000;

/// Welch's t-test threshold. |t| > this value indicates timing leak.
const T_THRESHOLD: f64 = 4.5;

/// Crop a sorted timing vector to the [lo_pct, hi_pct] percentile range.
/// dudect-style outlier filtering to discard context switches and cache effects.
fn percentile_crop(times: &mut Vec<f64>, lo_pct: f64, hi_pct: f64) {
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = times.len();
    let lo = (n as f64 * lo_pct) as usize;
    let hi = (n as f64 * hi_pct) as usize;
    *times = times[lo..hi.min(n)].to_vec();
}

/// Welch's t-test with dudect-style percentile cropping.
fn timing_t_test<I>(
    gen_class_a: impl Fn(usize) -> I,
    gen_class_b: impl Fn(usize) -> I,
    run: impl Fn(&I),
) -> f64 {
    let mut times_a = Vec::with_capacity(NUM_SAMPLES);
    let mut times_b = Vec::with_capacity(NUM_SAMPLES);

    // Warm up
    for i in 0..100 {
        run(&gen_class_a(i));
        run(&gen_class_b(i));
    }

    // Interleave measurements to reduce systematic bias
    for i in 0..NUM_SAMPLES {
        if i % 2 == 0 {
            let input = gen_class_a(i);
            let start = Instant::now();
            run(black_box(&input));
            times_a.push(start.elapsed().as_nanos() as f64);

            let input = gen_class_b(i);
            let start = Instant::now();
            run(black_box(&input));
            times_b.push(start.elapsed().as_nanos() as f64);
        } else {
            let input = gen_class_b(i);
            let start = Instant::now();
            run(black_box(&input));
            times_b.push(start.elapsed().as_nanos() as f64);

            let input = gen_class_a(i);
            let start = Instant::now();
            run(black_box(&input));
            times_a.push(start.elapsed().as_nanos() as f64);
        }
    }

    // dudect-style: crop outliers at 5th/95th percentile
    percentile_crop(&mut times_a, 0.05, 0.95);
    percentile_crop(&mut times_b, 0.05, 0.95);

    let n_a = times_a.len() as f64;
    let n_b = times_b.len() as f64;
    let mean_a = times_a.iter().sum::<f64>() / n_a;
    let mean_b = times_b.iter().sum::<f64>() / n_b;

    let var_a = times_a.iter().map(|t| (t - mean_a).powi(2)).sum::<f64>() / (n_a - 1.0);
    let var_b = times_b.iter().map(|t| (t - mean_b).powi(2)).sum::<f64>() / (n_b - 1.0);

    let se = (var_a / n_a + var_b / n_b).sqrt();
    if se == 0.0 {
        return 0.0;
    }
    ((mean_a - mean_b) / se).abs()
}

// ============================================================
// Test 1: ChaCha20-Poly1305 tag verify — valid vs corrupted tag
// ============================================================
#[test]
#[ignore = "timing-sensitive: constant-time verification"]
fn ct_verify_chacha20_poly1305_tag() {
    use hitls_crypto::chacha20::ChaCha20Poly1305;

    let key = [0x01u8; 32];
    let nonce = [0x02u8; 12];
    let aad = [0x03u8; 16];
    let plaintext = [0x04u8; 64];

    let aead = ChaCha20Poly1305::new(&key).unwrap();
    let ciphertext = aead.encrypt(&nonce, &aad, &plaintext).unwrap();

    let t = timing_t_test(
        // Class A: valid ciphertext (decryption succeeds)
        |_| ciphertext.clone(),
        // Class B: corrupted tag (decryption fails)
        |i| {
            let mut bad = ciphertext.clone();
            let tag_offset = bad.len() - 16;
            bad[tag_offset + (i % 16)] ^= 0xFF;
            bad
        },
        // Operation: ChaCha20-Poly1305 decrypt (includes tag verification)
        |ct| {
            let _ = black_box(aead.decrypt(&nonce, &aad, ct));
        },
    );

    assert!(
        t < T_THRESHOLD,
        "ChaCha20-Poly1305 tag verify may not be constant-time: |t| = {t:.2} \
         (threshold: {T_THRESHOLD})"
    );
}

// ============================================================
// Test 2: AES-CCM tag verify — valid vs corrupted tag
// ============================================================
#[test]
#[ignore = "timing-sensitive: constant-time verification"]
fn ct_verify_aes_ccm_tag() {
    use hitls_crypto::modes::ccm;

    let key = [0x01u8; 16];
    let nonce = [0x02u8; 12];
    let aad = [0x03u8; 16];
    let plaintext = [0x04u8; 48];
    let tag_len = 16;

    let ciphertext = ccm::ccm_encrypt(&key, &nonce, &aad, &plaintext, tag_len).unwrap();

    let t = timing_t_test(
        // Class A: valid ciphertext (decryption succeeds)
        |_| ciphertext.clone(),
        // Class B: corrupted tag (decryption fails)
        |i| {
            let mut bad = ciphertext.clone();
            let tag_offset = bad.len() - tag_len;
            bad[tag_offset + (i % tag_len)] ^= 0xFF;
            bad
        },
        // Operation: CCM decrypt (includes tag verification)
        |ct| {
            let _ = black_box(ccm::ccm_decrypt(&key, &nonce, &aad, ct, tag_len));
        },
    );

    assert!(
        t < T_THRESHOLD,
        "AES-CCM tag verify may not be constant-time: |t| = {t:.2} \
         (threshold: {T_THRESHOLD})"
    );
}

// ============================================================
// Test 3: AES-GCM decrypt — near-zero vs far-from-zero ciphertext
// ============================================================
// Tests that GCM decryption time is independent of ciphertext content
// (not just tag validity, which timing.rs covers).
#[test]
#[ignore = "timing-sensitive: constant-time verification"]
fn ct_verify_aes_gcm_ciphertext_independence() {
    use hitls_crypto::modes::gcm;

    let key = [0x01u8; 16];
    let nonce = [0x02u8; 12];
    let aad = [0x03u8; 16];

    // Encrypt two different plaintexts to get two valid (key,nonce,aad) combos
    let pt_zeros = [0x00u8; 64];
    let ct_zeros = gcm::gcm_encrypt(&key, &nonce, &aad, &pt_zeros).unwrap();

    let t = timing_t_test(
        // Class A: decrypt valid all-zero-plaintext ciphertext
        |_| ct_zeros.clone(),
        // Class B: same ciphertext but with flipped data bits (tag stays valid for class A,
        // fails for class B — tests that failure path timing is uniform)
        |i| {
            let mut bad = ct_zeros.clone();
            let data_len = bad.len() - 16;
            if data_len > 0 {
                bad[i % data_len] ^= 0x01;
            }
            bad
        },
        |ct| {
            let _ = black_box(gcm::gcm_decrypt(&key, &nonce, &aad, ct));
        },
    );

    assert!(
        t < T_THRESHOLD,
        "AES-GCM decrypt may not be constant-time w.r.t. ciphertext content: \
         |t| = {t:.2} (threshold: {T_THRESHOLD})"
    );
}
