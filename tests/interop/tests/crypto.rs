//! Crypto primitive roundtrip integration tests.

use hitls_integration_tests::*;

// -------------------------------------------------------
// 1. RSA sign + ECDSA sign same message
// -------------------------------------------------------
#[test]
fn test_rsa_and_ecdsa_sign_verify() {
    let message = b"cross-algorithm test message";

    // SHA-256 digest
    let digest = hitls_crypto::sha2::Sha256::digest(message).unwrap();

    // RSA PKCS#1v1.5 sign + verify
    let rsa_key = hitls_crypto::rsa::RsaPrivateKey::generate(2048).unwrap();
    let rsa_sig = rsa_key
        .sign(hitls_crypto::rsa::RsaPadding::Pkcs1v15Sign, &digest)
        .unwrap();
    let rsa_pub = rsa_key.public_key();
    let rsa_ok = rsa_pub
        .verify(
            hitls_crypto::rsa::RsaPadding::Pkcs1v15Sign,
            &digest,
            &rsa_sig,
        )
        .unwrap();
    assert!(rsa_ok, "RSA signature verification failed");

    // ECDSA P-256 sign + verify
    let ec_kp =
        hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
    let ec_sig = ec_kp.sign(&digest).unwrap();
    let ec_ok = ec_kp.verify(&digest, &ec_sig).unwrap();
    assert!(ec_ok, "ECDSA signature verification failed");

    // Cross-check: ECDSA sig should fail on RSA pubkey (type mismatch via different API)
    // Just verify both sigs are valid and different
    assert_ne!(rsa_sig, ec_sig);
}

// -------------------------------------------------------
// 2. AES-GCM encrypt + HMAC-SHA256 verify
// -------------------------------------------------------
#[test]
fn test_aes_gcm_encrypt_hmac_verify() {
    let plaintext = b"encrypt-then-mac test";
    let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let nonce = hex("000000000000000000000001");

    // AES-256-GCM encrypt (returns ct || tag)
    let ct_tag = hitls_crypto::modes::gcm::gcm_encrypt(&key, &nonce, b"aad", plaintext).unwrap();

    // Compute HMAC-SHA256 over ciphertext for integrity binding
    let hmac_key = hex("aabbccdd");
    let mac = hitls_crypto::hmac::Hmac::mac(
        || Box::new(hitls_crypto::sha2::Sha256::new()),
        &hmac_key,
        &ct_tag,
    )
    .unwrap();
    assert_eq!(mac.len(), 32);

    // Verify HMAC
    let mac2 = hitls_crypto::hmac::Hmac::mac(
        || Box::new(hitls_crypto::sha2::Sha256::new()),
        &hmac_key,
        &ct_tag,
    )
    .unwrap();
    assert_eq!(mac, mac2, "HMAC mismatch");

    // Decrypt
    let pt = hitls_crypto::modes::gcm::gcm_decrypt(&key, &nonce, b"aad", &ct_tag).unwrap();
    assert_eq!(pt, plaintext);
}

// -------------------------------------------------------
// 3. PBKDF2 -> AES key -> encrypt -> decrypt
// -------------------------------------------------------
#[test]
fn test_pbkdf2_to_aes_roundtrip() {
    let password = b"correct horse battery staple";
    let salt = hex("0011223344556677");

    // Derive 32-byte key
    let key = hitls_crypto::pbkdf2::pbkdf2(password, &salt, 1000, 32).unwrap();
    assert_eq!(key.len(), 32);

    // Encrypt with derived key
    let plaintext = b"PBKDF2 derived key encryption test";
    let nonce = hex("000000000000000000000001");
    let ct = hitls_crypto::modes::gcm::gcm_encrypt(&key, &nonce, b"", plaintext).unwrap();

    // Decrypt
    let pt = hitls_crypto::modes::gcm::gcm_decrypt(&key, &nonce, b"", &ct).unwrap();
    assert_eq!(pt, plaintext);
}

// -------------------------------------------------------
// 4. Ed25519 sign/verify with serialized keys
// -------------------------------------------------------
#[test]
fn test_ed25519_sign_verify_serialized() {
    let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
    let message = b"Ed25519 serialization test";

    // Sign
    let sig = kp.sign(message).unwrap();

    // Get public key bytes
    let pk_bytes = kp.public_key().to_vec();

    // Reconstruct from public key bytes only
    let verifier = hitls_crypto::ed25519::Ed25519KeyPair::from_public_key(&pk_bytes).unwrap();
    let ok = verifier.verify(message, &sig).unwrap();
    assert!(ok, "Ed25519 verify failed with reconstructed public key");

    // Tampered message should fail
    let bad_ok = verifier.verify(b"wrong message", &sig).unwrap();
    assert!(!bad_ok, "Ed25519 verify should fail for wrong message");
}

// -------------------------------------------------------
// 5. ECDSA P-384 sign/verify
// -------------------------------------------------------
#[test]
fn test_ecdsa_p384_sign_verify() {
    // P-384 ECDSA roundtrip
    let kp =
        hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP384).unwrap();
    let digest = hitls_crypto::sha2::Sha384::digest(b"P-384 ECDSA test message").unwrap();
    let sig = kp.sign(&digest).unwrap();
    let ok = kp.verify(&digest, &sig).unwrap();
    assert!(ok, "P-384 ECDSA verification failed");

    // Wrong digest should fail
    let bad = kp.verify(&[0u8; 48], &sig).unwrap();
    assert!(!bad, "P-384 ECDSA should reject wrong digest");
}

// -------------------------------------------------------
// 6. ML-KEM all parameter sets
// -------------------------------------------------------
#[test]
fn test_mlkem_all_params() {
    for &ps in &[512u32, 768, 1024] {
        let kp = hitls_crypto::mlkem::MlKemKeyPair::generate(ps).unwrap();
        let (ss1, ct) = kp.encapsulate().unwrap();
        let ss2 = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2, "ML-KEM-{ps} shared secret mismatch");
    }
}

// -------------------------------------------------------
// 7. ML-DSA sign/verify all param sets
// -------------------------------------------------------
#[test]
fn test_mldsa_all_params() {
    for &ps in &[44u32, 65, 87] {
        let kp = hitls_crypto::mldsa::MlDsaKeyPair::generate(ps).unwrap();
        let msg = format!("ML-DSA-{ps} test message");
        let sig = kp.sign(msg.as_bytes()).unwrap();
        let ok = kp.verify(msg.as_bytes(), &sig).unwrap();
        assert!(ok, "ML-DSA-{ps} verification failed");
    }
}

// -------------------------------------------------------
// 8. HybridKEM X25519+ML-KEM roundtrip
// -------------------------------------------------------
#[test]
fn test_hybridkem_roundtrip() {
    let kp = hitls_crypto::hybridkem::HybridKemKeyPair::generate(
        hitls_types::HybridKemParamId::X25519MlKem768,
    )
    .unwrap();
    let (ss1, ct) = kp.encapsulate().unwrap();
    let ss2 = kp.decapsulate(&ct).unwrap();
    assert_eq!(ss1, ss2, "HybridKEM shared secret mismatch");

    // Different encapsulation should produce different ciphertext
    let (ss3, ct2) = kp.encapsulate().unwrap();
    assert_ne!(ct, ct2, "two encapsulations should differ");
    // But decapsulated shared secrets should match their own ct
    let ss4 = kp.decapsulate(&ct2).unwrap();
    assert_eq!(ss3, ss4);
}
