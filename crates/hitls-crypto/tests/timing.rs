//! Side-channel timing tests (Phase T156).
//!
//! These tests verify constant-time behavior of security-critical operations
//! using statistical timing analysis (Welch's t-test). A large |t| value
//! (> 4.5) indicates a statistically significant timing difference between
//! two input classes, suggesting non-constant-time behavior.
//!
//! All tests are marked `#[ignore]` because:
//! - Timing measurements are environment-sensitive (CPU frequency scaling, load)
//! - They require many iterations for statistical significance
//! - Results may vary across platforms and optimization levels
//!
//! Run with: `cargo test -p hitls-crypto --all-features --release --ignored -- timing`
//!
//! Note: Must use `--release` for meaningful results. Debug builds add
//! significant overhead that dominates the actual operation timing.

// Only compile when all required features are present — these tests need --all-features.
#![cfg(all(
    feature = "aes",
    feature = "hmac",
    feature = "sha2",
    feature = "ecdsa",
    feature = "rsa",
    feature = "x25519",
    feature = "sm2",
    feature = "ed25519",
    feature = "hkdf",
    feature = "modes",
    feature = "sm4"
))]

use std::hint::black_box;
use std::time::Instant;
use subtle::ConstantTimeEq;

/// Number of samples per class for timing measurements.
const NUM_SAMPLES: usize = 10_000;

/// Welch's t-test threshold. |t| > this value indicates timing leak.
/// dudect uses 4.5 as its threshold; we use the same.
const T_THRESHOLD: f64 = 4.5;

/// Crop a sorted timing vector to the [lo_pct, hi_pct] percentile range.
/// This is the dudect approach: discard outliers caused by context switches,
/// cache cold-starts, and OS interrupts before computing the t-statistic.
fn percentile_crop(times: &mut Vec<f64>, lo_pct: f64, hi_pct: f64) {
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = times.len();
    let lo = (n as f64 * lo_pct) as usize;
    let hi = (n as f64 * hi_pct) as usize;
    *times = times[lo..hi.min(n)].to_vec();
}

/// Welch's t-test with dudect-style percentile cropping.
///
/// Generates inputs from two classes, interleaves measurements to reduce
/// systematic bias, crops outliers at 5th/95th percentile, and computes
/// Welch's t-statistic.
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

    welch_t_statistic(&times_a, &times_b)
}

/// Compute Welch's t-statistic for two sample vectors.
fn welch_t_statistic(times_a: &[f64], times_b: &[f64]) -> f64 {
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
// Test 1: HMAC verify — valid vs invalid tag (same length)
// ============================================================
#[test]
#[ignore = "timing-sensitive: constant-time verification"]
fn test_hmac_verify_constant_time() {
    use hitls_crypto::hmac::Hmac;
    use hitls_crypto::sha2::Sha256;

    let key = [0x42u8; 32];
    let data = [0xABu8; 64];
    let valid_tag = Hmac::mac(|| Box::new(Sha256::new()), &key, &data).unwrap();

    let t = timing_t_test(
        // Class A: compare with valid tag
        |_| valid_tag.clone(),
        // Class B: compare with invalid tag (same length, different content)
        |i| {
            let mut bad = valid_tag.clone();
            let len = bad.len();
            bad[i % len] ^= 0xFF;
            bad
        },
        // Operation: constant-time comparison
        |tag| {
            let _ = black_box(valid_tag.as_slice().ct_eq(tag.as_slice()));
        },
    );

    assert!(
        t < T_THRESHOLD,
        "HMAC tag comparison may not be constant-time: |t| = {t:.2} (threshold: {T_THRESHOLD})"
    );
}

// ============================================================
// Test 2: AES-GCM tag verify — valid vs corrupted tag
// ============================================================
#[test]
#[ignore = "timing-sensitive: constant-time verification"]
fn test_aes_gcm_tag_verify_constant_time() {
    use hitls_crypto::modes::gcm;

    let key = [0x01u8; 16];
    let nonce = [0x02u8; 12];
    let aad = [0x03u8; 16];
    let plaintext = [0x04u8; 64];

    let ciphertext = gcm::gcm_encrypt(&key, &nonce, &aad, &plaintext).unwrap();

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
        // Operation: GCM decrypt (includes tag verification)
        |ct| {
            let _ = black_box(gcm::gcm_decrypt(&key, &nonce, &aad, ct));
        },
    );

    assert!(
        t < T_THRESHOLD,
        "GCM tag verification may not be constant-time: |t| = {t:.2} (threshold: {T_THRESHOLD})"
    );
}

// ============================================================
// Test 3: ECDSA verify — different message digests, same signature
// ============================================================
// Note: We test constant-time behavior w.r.t. the message digest (which
// feeds into scalar multiplication as a secret-adjacent value), NOT w.r.t.
// the signature itself. Corrupted DER signatures legitimately fail early
// at the parse stage, so comparing valid-vs-invalid-signature timings
// produces false positives and is not a meaningful security property.
#[test]
#[ignore = "timing-sensitive: constant-time verification"]
fn test_ecdsa_verify_constant_time() {
    use hitls_crypto::ecdsa::EcdsaKeyPair;
    use hitls_types::EccCurveId;

    let kp = EcdsaKeyPair::generate(EccCurveId::NistP256).unwrap();
    let digest_a = [0x55u8; 32];
    let sig = kp.sign(&digest_a).unwrap();

    let t = timing_t_test(
        // Class A: digest with many high bits
        |i| {
            let mut d = [0xFFu8; 32];
            d[0] = (i & 0xFF) as u8;
            d
        },
        // Class B: digest with many low bits
        |i| {
            let mut d = [0x01u8; 32];
            d[0] = (i & 0xFF) as u8;
            d
        },
        // Operation: ECDSA verify (both classes will fail since sig was
        // made for digest_a, but the full EC computation still runs)
        |digest| {
            let _ = black_box(kp.verify(digest, &sig));
        },
    );

    assert!(
        t < T_THRESHOLD,
        "ECDSA verify may not be constant-time: |t| = {t:.2} (threshold: {T_THRESHOLD})"
    );
}

// ============================================================
// Test 4: RSA PKCS#1 v1.5 verify — valid vs invalid signature
// ============================================================
#[test]
#[ignore = "timing-sensitive: constant-time verification"]
fn test_rsa_pkcs1_verify_constant_time() {
    use hitls_crypto::rsa::{RsaPadding, RsaPrivateKey};

    let priv_key = RsaPrivateKey::generate(2048).unwrap();
    let pub_key = priv_key.public_key();
    let digest = [0x42u8; 32];
    let valid_sig = priv_key.sign(RsaPadding::Pkcs1v15Sign, &digest).unwrap();

    let t = timing_t_test(
        // Class A: valid signature
        |_| valid_sig.clone(),
        // Class B: invalid signature (different content, same length)
        |i| {
            let mut bad = valid_sig.clone();
            let len = bad.len();
            bad[i % len] ^= 0x01;
            bad
        },
        // Operation: RSA PKCS#1v15 verify
        |sig| {
            let _ = black_box(pub_key.verify(RsaPadding::Pkcs1v15Sign, &digest, sig));
        },
    );

    assert!(
        t < T_THRESHOLD,
        "RSA PKCS#1v15 verify may not be constant-time: |t| = {t:.2} (threshold: {T_THRESHOLD})"
    );
}

// ============================================================
// Test 5: X25519 DH — different private keys, same public key
// ============================================================
#[test]
#[ignore = "timing-sensitive: constant-time verification"]
fn test_x25519_dh_constant_time() {
    use hitls_crypto::x25519::X25519PrivateKey;

    // Generate a fixed peer public key
    let peer_priv = X25519PrivateKey::generate().unwrap();
    let peer_pub = peer_priv.public_key();

    let t = timing_t_test(
        // Class A: private key with many set bits
        |i| {
            let mut key_bytes = [0xFFu8; 32];
            key_bytes[0] = (i & 0xFF) as u8;
            X25519PrivateKey::new(&key_bytes).unwrap()
        },
        // Class B: private key with few set bits
        |i| {
            let mut key_bytes = [0x01u8; 32];
            key_bytes[0] = (i & 0xFF) as u8;
            X25519PrivateKey::new(&key_bytes).unwrap()
        },
        // Operation: X25519 DH
        |priv_key| {
            let _ = black_box(priv_key.diffie_hellman(&peer_pub));
        },
    );

    assert!(
        t < T_THRESHOLD,
        "X25519 DH may not be constant-time: |t| = {t:.2} (threshold: {T_THRESHOLD})"
    );
}

// ============================================================
// Test 6: BigNum ct_eq — same vs different values
// ============================================================
#[test]
#[ignore = "timing-sensitive: constant-time verification"]
fn test_bignum_ct_eq_constant_time() {
    use hitls_bignum::BigNum;

    let a = BigNum::from_bytes_be(&[0xABu8; 32]);

    let t = timing_t_test(
        // Class A: equal values
        |_| BigNum::from_bytes_be(&[0xABu8; 32]),
        // Class B: different values
        |i| {
            let mut bytes = [0xABu8; 32];
            bytes[i % 32] ^= 0xFF;
            BigNum::from_bytes_be(&bytes)
        },
        // Operation: constant-time equality
        |b| {
            let _ = black_box(a.ct_eq(b));
        },
    );

    assert!(
        t < T_THRESHOLD,
        "BigNum ct_eq may not be constant-time: |t| = {t:.2} (threshold: {T_THRESHOLD})"
    );
}

// ============================================================
// Test 7: RSA OAEP decrypt — valid vs corrupted maskedDB
// ============================================================
#[test]
#[ignore = "timing-sensitive: constant-time verification"]
fn test_rsa_oaep_decrypt_constant_time() {
    use hitls_crypto::rsa::{RsaPadding, RsaPrivateKey};

    let priv_key = RsaPrivateKey::generate(2048).unwrap();
    let pub_key = priv_key.public_key();
    let msg = [0x42u8; 32];
    let valid_ct = pub_key.encrypt(RsaPadding::Oaep, &msg).unwrap();

    let t = timing_t_test(
        // Class A: valid ciphertext (decryption succeeds)
        |_| valid_ct.clone(),
        // Class B: corrupted ciphertext (maskedDB region altered → padding error)
        |i| {
            let mut bad = valid_ct.clone();
            let offset = 64 + (i % (bad.len().saturating_sub(65)));
            if offset < bad.len() {
                bad[offset] ^= 0xFF;
            }
            bad
        },
        // Operation: RSA OAEP decrypt
        |ct| {
            let _ = black_box(priv_key.decrypt(RsaPadding::Oaep, ct));
        },
    );

    assert!(
        t < T_THRESHOLD,
        "RSA OAEP decrypt may not be constant-time: |t| = {t:.2} (threshold: {T_THRESHOLD})"
    );
}

// ============================================================
// Test 8: RSA PKCS#1v15 decrypt — valid vs PS-too-short msg
// ============================================================
#[test]
#[ignore = "timing-sensitive: constant-time verification"]
fn test_rsa_pkcs1v15_decrypt_constant_time() {
    use hitls_crypto::rsa::{RsaPadding, RsaPrivateKey};

    let priv_key = RsaPrivateKey::generate(2048).unwrap();
    let pub_key = priv_key.public_key();
    let msg = [0x55u8; 64];
    let valid_ct = pub_key.encrypt(RsaPadding::Pkcs1v15Encrypt, &msg).unwrap();

    let t = timing_t_test(
        // Class A: valid ciphertext (decryption succeeds)
        |_| valid_ct.clone(),
        // Class B: corrupted ciphertext (different content → padding error)
        |i| {
            let mut bad = valid_ct.clone();
            let offset = 10 + (i % (bad.len().saturating_sub(11)));
            if offset < bad.len() {
                bad[offset] ^= 0x01;
            }
            bad
        },
        // Operation: RSA PKCS#1v15 decrypt
        |ct| {
            let _ = black_box(priv_key.decrypt(RsaPadding::Pkcs1v15Encrypt, ct));
        },
    );

    assert!(
        t < T_THRESHOLD,
        "RSA PKCS#1v15 decrypt may not be constant-time: |t| = {t:.2} (threshold: {T_THRESHOLD})"
    );
}

// ============================================================
// Test 9: SM2 sign — different message digests (scalar-dependent timing)
// ============================================================
#[test]
#[ignore = "timing-sensitive: constant-time verification"]
fn test_sm2_sign_constant_time() {
    use hitls_crypto::sm2::Sm2KeyPair;

    let kp = Sm2KeyPair::generate().unwrap();

    let t = timing_t_test(
        // Class A: digest with many high bits
        |i| {
            let mut msg = [0xFFu8; 32];
            msg[0] = (i & 0xFF) as u8;
            msg
        },
        // Class B: digest with many low bits
        |i| {
            let mut msg = [0x01u8; 32];
            msg[0] = (i & 0xFF) as u8;
            msg
        },
        // Operation: SM2 sign (exercises scalar multiplication)
        |msg| {
            let _ = black_box(kp.sign(msg));
        },
    );

    assert!(
        t < T_THRESHOLD,
        "SM2 sign may not be constant-time: |t| = {t:.2} (threshold: {T_THRESHOLD})"
    );
}

// ============================================================
// Test 10: Ed25519 sign — different messages (secret scalar mul)
// ============================================================
#[test]
#[ignore = "timing-sensitive: constant-time verification"]
fn test_ed25519_sign_constant_time() {
    use hitls_crypto::ed25519::Ed25519KeyPair;

    let kp = Ed25519KeyPair::generate().unwrap();

    let t = timing_t_test(
        // Class A: message with many high bits
        |i| {
            let mut msg = [0xFFu8; 64];
            msg[0] = (i & 0xFF) as u8;
            msg
        },
        // Class B: message with many low bits
        |i| {
            let mut msg = [0x00u8; 64];
            msg[0] = (i & 0xFF) as u8;
            msg
        },
        // Operation: Ed25519 sign (exercises secret scalar multiplication)
        |msg| {
            let _ = black_box(kp.sign(msg));
        },
    );

    assert!(
        t < T_THRESHOLD,
        "Ed25519 sign may not be constant-time: |t| = {t:.2} (threshold: {T_THRESHOLD})"
    );
}

// ============================================================
// Test 11: ECDSA P-256 sign — different digests (secret nonce scalar mul)
// ============================================================
#[test]
#[ignore = "timing-sensitive: constant-time verification"]
fn test_ecdsa_p256_sign_constant_time() {
    use hitls_crypto::ecdsa::EcdsaKeyPair;
    use hitls_types::EccCurveId;

    let kp = EcdsaKeyPair::generate(EccCurveId::NistP256).unwrap();

    let t = timing_t_test(
        // Class A: digest near curve order (large scalar)
        |i| {
            let mut d = [0xFFu8; 32];
            d[0] = (i & 0xFF) as u8;
            d
        },
        // Class B: small digest (small scalar)
        |i| {
            let mut d = [0x00u8; 32];
            d[31] = (i & 0xFF) as u8 | 0x01;
            d
        },
        // Operation: ECDSA sign (exercises secret nonce generation + scalar mul)
        |digest| {
            let _ = black_box(kp.sign(digest));
        },
    );

    assert!(
        t < T_THRESHOLD,
        "ECDSA P-256 sign may not be constant-time: |t| = {t:.2} (threshold: {T_THRESHOLD})"
    );
}

// ============================================================
// Test 12: SM4-GCM tag verify — valid vs corrupted tag
// ============================================================
#[test]
#[ignore = "timing-sensitive: constant-time verification"]
fn test_sm4_gcm_tag_verify_constant_time() {
    use hitls_crypto::modes::gcm;

    let key = [0x01u8; 16];
    let nonce = [0x02u8; 12];
    let aad = [0x03u8; 16];
    let plaintext = [0x04u8; 64];

    let ciphertext = gcm::sm4_gcm_encrypt(&key, &nonce, &aad, &plaintext).unwrap();

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
        // Operation: SM4-GCM decrypt (includes tag verification)
        |ct| {
            let _ = black_box(gcm::sm4_gcm_decrypt(&key, &nonce, &aad, ct));
        },
    );

    assert!(
        t < T_THRESHOLD,
        "SM4-GCM tag verify may not be constant-time: |t| = {t:.2} (threshold: {T_THRESHOLD})"
    );
}

// ============================================================
// Test 13: HKDF extract — different IKM values (secret-dependent)
// ============================================================
#[test]
#[ignore = "timing-sensitive: constant-time verification"]
fn test_hkdf_extract_constant_time() {
    use hitls_crypto::hkdf::Hkdf;

    let salt = [0x00u8; 32];

    let t = timing_t_test(
        // Class A: IKM with many high bits
        |i| {
            let mut ikm = [0xFFu8; 32];
            ikm[0] = (i & 0xFF) as u8;
            ikm
        },
        // Class B: IKM with many low bits
        |i| {
            let mut ikm = [0x00u8; 32];
            ikm[0] = (i & 0xFF) as u8;
            ikm
        },
        // Operation: HKDF extract (HMAC-based, should be constant-time)
        |ikm| {
            let _ = black_box(Hkdf::new(&salt, ikm));
        },
    );

    assert!(
        t < T_THRESHOLD,
        "HKDF extract may not be constant-time: |t| = {t:.2} (threshold: {T_THRESHOLD})"
    );
}
