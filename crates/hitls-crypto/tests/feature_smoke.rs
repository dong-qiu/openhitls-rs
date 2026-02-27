//! Feature flag combination smoke tests (Phase T158).
//!
//! Verifies basic functionality under different feature flag combinations.
//! Each test is guarded by `#[cfg(...)]` to only compile when the required
//! features are present, enabling CI matrix testing.

/// Smoke test for default features: AES + SHA-256 + HMAC.
#[cfg(all(feature = "aes", feature = "sha2", feature = "hmac"))]
#[test]
fn test_default_aes_sha2_hmac() {
    use hitls_crypto::aes::AesKey;
    use hitls_crypto::hmac::Hmac;
    use hitls_crypto::sha2::Sha256;

    // AES-128 encrypt
    let key = AesKey::new(&[0x42u8; 16]).unwrap();
    let mut block = [0u8; 16];
    key.encrypt_block(&mut block).unwrap();
    assert_ne!(
        block, [0u8; 16],
        "AES encrypt should produce non-zero output"
    );

    // SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(b"test").unwrap();
    let digest = hasher.finish().unwrap();
    assert_eq!(digest.len(), 32);

    // HMAC-SHA-256
    let mac = Hmac::mac(|| Box::new(Sha256::new()), b"key", b"data").unwrap();
    assert_eq!(mac.len(), 32);
}

/// Smoke test for SM algorithms: SM2 + SM3 + SM4.
#[cfg(all(feature = "sm2", feature = "sm3", feature = "sm4"))]
#[test]
fn test_sm_algorithms() {
    use hitls_crypto::sm3::Sm3;
    use hitls_crypto::sm4::Sm4Key;

    // SM4 encrypt
    let key = Sm4Key::new(&[0x01u8; 16]).unwrap();
    let mut block = [0u8; 16];
    key.encrypt_block(&mut block).unwrap();
    assert_ne!(
        block, [0u8; 16],
        "SM4 encrypt should produce non-zero output"
    );

    // SM3 hash
    let mut hasher = Sm3::new();
    hasher.update(b"test").unwrap();
    let digest = hasher.finish().unwrap();
    assert_eq!(digest.len(), 32);

    // SM2 key generation
    use hitls_crypto::sm2::Sm2KeyPair;
    let kp = Sm2KeyPair::generate().unwrap();
    let msg = b"sm2 smoke test";
    let sig = kp.sign(msg).unwrap();
    assert!(kp.verify(msg, &sig).unwrap());
}

/// Smoke test for post-quantum algorithms: ML-KEM + ML-DSA.
#[cfg(all(feature = "mlkem", feature = "mldsa"))]
#[test]
fn test_pqc_algorithms() {
    use hitls_crypto::mldsa::MlDsaKeyPair;
    use hitls_crypto::mlkem::MlKemKeyPair;

    // ML-KEM-768 encaps/decaps
    let kp = MlKemKeyPair::generate(768).unwrap();
    let (shared_secret, ciphertext) = kp.encapsulate().unwrap();
    let decapped = kp.decapsulate(&ciphertext).unwrap();
    assert_eq!(shared_secret, decapped);

    // ML-DSA-65 sign/verify
    let dsa_kp = MlDsaKeyPair::generate(65).unwrap();
    let msg = b"pqc smoke test";
    let sig = dsa_kp.sign(msg).unwrap();
    assert!(dsa_kp.verify(msg, &sig).unwrap());
}

/// Smoke test for minimal (no-default-features): basic types always available.
#[test]
fn test_minimal_no_default() {
    // CryptoError is always available
    let err = hitls_types::CryptoError::NullInput;
    let msg = format!("{err}");
    assert!(!msg.is_empty());

    // Algorithm IDs are always available
    let _hash_id = hitls_types::HashAlgId::Sha256;
    let _cipher_id = hitls_types::CipherAlgId::Aes128Cbc;
}
