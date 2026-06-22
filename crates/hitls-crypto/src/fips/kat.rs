//! Known Answer Tests (KAT) for FIPS 140-3 self-testing.
//!
//! Each KAT runs a single algorithm computation with a known input and
//! verifies the output matches the expected value from NIST CAVP or RFCs.

use hitls_types::CmvpError;
use hitls_utils::hex::hex;

/// Run all KAT self-tests. Returns on first failure.
pub(crate) fn run_all_kat() -> Result<(), CmvpError> {
    kat_sha256()?;
    kat_hmac_sha256()?;
    kat_aes128_gcm()?;
    kat_hmac_drbg()?;
    kat_hkdf_sha256()?;
    kat_ecdsa_p256()?;
    kat_entropy_health()?;
    // PQC CASTs — one known-answer test per approved family, on the
    // deterministic (decapsulate / verify) side so no keygen randomness is
    // needed. Vectors are the byte-exact FIPS 203/204/205 (NIST/C SDV) values
    // in `kat_vectors`. The boundary marks these families approved
    // (boundary.rs), so each must self-test before operational use.
    #[cfg(feature = "mlkem")]
    kat_mlkem()?;
    #[cfg(feature = "slh-dsa")]
    kat_slhdsa()?;
    Ok(())
}

/// SHA-256 KAT (NIST CAVP SHAVS).
fn kat_sha256() -> Result<(), CmvpError> {
    use crate::sha2::Sha256;

    // Input: 0x5738c929c4f4ccb6 (8 bytes)
    let msg = hex("5738c929c4f4ccb6");
    let expected = hex("963bb88f27f512777aab6c8b1a02c70ec0ad651d428f870036e1917120fb48bf");

    let mut hasher = Sha256::new();
    hasher
        .update(&msg)
        .map_err(|e| CmvpError::KatFailure(format!("SHA-256 update: {e}")))?;
    let digest = hasher
        .finish()
        .map_err(|e| CmvpError::KatFailure(format!("SHA-256 finish: {e}")))?;

    if digest[..] != expected[..] {
        return Err(CmvpError::KatFailure("SHA-256 digest mismatch".into()));
    }
    Ok(())
}

/// HMAC-SHA256 KAT (RFC 4231 Test Case 1).
fn kat_hmac_sha256() -> Result<(), CmvpError> {
    use crate::hmac::Hmac;
    use crate::sha2::Sha256;

    let key = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let msg = hex("4869205468657265"); // "Hi There"
    let expected = hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    let mut hmac = Hmac::new(
        || Box::new(Sha256::new()) as Box<dyn crate::provider::Digest>,
        &key,
    )
    .map_err(|e| CmvpError::KatFailure(format!("HMAC-SHA256 new: {e}")))?;
    hmac.update(&msg)
        .map_err(|e| CmvpError::KatFailure(format!("HMAC-SHA256 update: {e}")))?;
    let mut out = vec![0u8; 32];
    hmac.finish(&mut out)
        .map_err(|e| CmvpError::KatFailure(format!("HMAC-SHA256 finish: {e}")))?;

    if out != expected {
        return Err(CmvpError::KatFailure("HMAC-SHA256 MAC mismatch".into()));
    }
    Ok(())
}

/// AES-128-GCM KAT (NIST SP 800-38D).
fn kat_aes128_gcm() -> Result<(), CmvpError> {
    use crate::modes::gcm::{gcm_decrypt, gcm_encrypt};

    let key = hex("07a6be880a58f572dbc2ad74a56db8b6");
    let nonce = hex("95fc6654e6dc3a8adf5e7a69");
    let aad = hex(
        "de4269feea1a439d6e8990fd6f9f9d5bc67935294425255ea89b6f6772d680fd\
         656b06581a5d8bc5c017ab532b4a9b83a55fde58cdfb3d2a8fef3aa426bc59d3\
         e32f09d3cc20b1ceb9a9e349d1068a0aa3d39617fae0582ccef0",
    );
    let plaintext = hex("7680b48b5d28f38cdeab2d5851769394a3e141b990ec4bdf79a33e5315ac0338");
    let expected_ct = hex("095635c7e0eac0fc1059e67e1a936b6f72671121f96699fed520e5f8aff777f0");
    let expected_tag = hex("b2235f6d4bdd7b9c0901711048859d47");

    // Encrypt
    let ct_with_tag = gcm_encrypt(&key, &nonce, &aad, &plaintext)
        .map_err(|e| CmvpError::KatFailure(format!("AES-128-GCM encrypt: {e}")))?;

    let (ct, tag) = ct_with_tag.split_at(ct_with_tag.len() - 16);
    if ct != expected_ct.as_slice() {
        return Err(CmvpError::KatFailure(
            "AES-128-GCM ciphertext mismatch".into(),
        ));
    }
    if tag != expected_tag.as_slice() {
        return Err(CmvpError::KatFailure("AES-128-GCM tag mismatch".into()));
    }

    // Decrypt
    let pt = gcm_decrypt(&key, &nonce, &aad, &ct_with_tag)
        .map_err(|e| CmvpError::KatFailure(format!("AES-128-GCM decrypt: {e}")))?;
    if pt != plaintext {
        return Err(CmvpError::KatFailure(
            "AES-128-GCM plaintext mismatch".into(),
        ));
    }
    Ok(())
}

/// HMAC-DRBG SHA-256 KAT (NIST SP 800-90A).
fn kat_hmac_drbg() -> Result<(), CmvpError> {
    use crate::drbg::HmacDrbg;

    let entropy = hex("cdb0d9117cc6dbc9ef9dcb06a97579841d72dc18b2d46a1cb61e314012bdf416");
    let nonce = hex("d0c0d01d156016d0eb6b7e9c7c3c8da8");
    let pers = hex("6f0fb9eab3f9ea7ab0a719bfa879bf0aaed683307fda0c6d73ce018b6e34faaa");

    let entropy_reseed = hex("8ec6f7d5a8e2e88f43986f70b86e050d07c84b931bcf18e601c5a3eee3064c82");
    let addin_reseed = hex("1ab4ca9014fa98a55938316de8ba5a68c629b0741bdd058c4d70c91cda5099b3");
    let addin1 = hex("16e2d0721b58d839a122852abd3bf2c942a31c84d82fca74211871880d7162ff");
    let addin2 = hex("53686f042a7b087d5d2eca0d2a96de131f275ed7151189f7ca52deaa78b79fb2");

    let expected = hex(
        "dda04a2ca7b8147af1548f5d086591ca4fd951a345ce52b3cd49d47e84aa31a1\
         83e31fbc42a1ff1d95afec7143c8008c97bc2a9c091df0a763848391f68cb4a3\
         66ad89857ac725a53b303ddea767be8dc5f605b1b95f6d24c9f06be65a973a08\
         9320b3cc42569dcfd4b92b62a993785b0301b3fc452445656fce22664827b88f",
    );

    // Instantiate: entropy || nonce || personalization
    let mut seed = Vec::new();
    seed.extend_from_slice(&entropy);
    seed.extend_from_slice(&nonce);
    seed.extend_from_slice(&pers);
    let mut drbg =
        HmacDrbg::new(&seed).map_err(|e| CmvpError::KatFailure(format!("HMAC-DRBG new: {e}")))?;

    // Reseed
    drbg.reseed(&entropy_reseed, Some(&addin_reseed))
        .map_err(|e| CmvpError::KatFailure(format!("HMAC-DRBG reseed: {e}")))?;

    // Generate #1 (discard)
    let mut out1 = vec![0u8; expected.len()];
    drbg.generate(&mut out1, Some(&addin1))
        .map_err(|e| CmvpError::KatFailure(format!("HMAC-DRBG generate1: {e}")))?;

    // Generate #2 (compare)
    let mut out2 = vec![0u8; expected.len()];
    drbg.generate(&mut out2, Some(&addin2))
        .map_err(|e| CmvpError::KatFailure(format!("HMAC-DRBG generate2: {e}")))?;

    if out2 != expected {
        return Err(CmvpError::KatFailure("HMAC-DRBG output mismatch".into()));
    }
    Ok(())
}

/// HKDF-SHA256 KAT (RFC 5869 Appendix A Test Case 1).
fn kat_hkdf_sha256() -> Result<(), CmvpError> {
    use crate::hkdf::Hkdf;

    let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");
    let expected =
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

    let okm = Hkdf::derive(&salt, &ikm, &info, expected.len())
        .map_err(|e| CmvpError::KatFailure(format!("HKDF-SHA256: {e}")))?;

    if okm != expected {
        return Err(CmvpError::KatFailure("HKDF-SHA256 output mismatch".into()));
    }
    Ok(())
}

/// ECDSA P-256 KAT: sign-verify roundtrip with generated key.
///
/// This is a "conditional self-test" — we generate a key, sign a known
/// message, then verify the signature. The test passes if the verification
/// succeeds, confirming both sign and verify operations work correctly.
fn kat_ecdsa_p256() -> Result<(), CmvpError> {
    use crate::ecdsa::EcdsaKeyPair;
    use crate::sha2::Sha256;
    use hitls_types::EccCurveId;

    let msg = b"FIPS 140-3 ECDSA P-256 KAT self-test message";

    // Hash the message with SHA-256
    let mut hasher = Sha256::new();
    hasher
        .update(msg)
        .map_err(|e| CmvpError::KatFailure(format!("ECDSA SHA-256 update: {e}")))?;
    let digest = hasher
        .finish()
        .map_err(|e| CmvpError::KatFailure(format!("ECDSA SHA-256 finish: {e}")))?;

    // Generate key pair
    let kp = EcdsaKeyPair::generate(EccCurveId::NistP256)
        .map_err(|e| CmvpError::KatFailure(format!("ECDSA keygen: {e}")))?;

    // Sign
    let sig = kp
        .sign(&digest)
        .map_err(|e| CmvpError::KatFailure(format!("ECDSA sign: {e}")))?;

    // Verify
    let valid = kp
        .verify(&digest, &sig)
        .map_err(|e| CmvpError::KatFailure(format!("ECDSA verify: {e}")))?;
    if !valid {
        return Err(CmvpError::KatFailure(
            "ECDSA P-256 sign-verify roundtrip failed".into(),
        ));
    }
    Ok(())
}

/// Decode a compile-time hex string. The KAT vectors are always valid hex, so
/// a malformed digit is a build-integrity failure, surfaced as a KAT error.
#[cfg(any(feature = "mlkem", feature = "slh-dsa"))]
fn unhex(s: &str) -> Result<Vec<u8>, CmvpError> {
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return Err(CmvpError::KatFailure("odd-length KAT hex".into()));
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks(2) {
        let (h, l) = (
            nib(pair[0]).ok_or_else(|| CmvpError::KatFailure("bad KAT hex".into()))?,
            nib(pair[1]).ok_or_else(|| CmvpError::KatFailure("bad KAT hex".into()))?,
        );
        out.push((h << 4) | l);
    }
    Ok(out)
}

/// ML-KEM-512 KAT (FIPS 203): decapsulate a known ciphertext with a known
/// decapsulation key and check the shared secret matches.
#[cfg(feature = "mlkem")]
fn kat_mlkem() -> Result<(), CmvpError> {
    use super::kat_vectors as v;
    use crate::mlkem::MlKemKeyPair;
    let dk = unhex(v::MLKEM512_DK)?;
    let ct = unhex(v::MLKEM512_CT)?;
    let want_ss = unhex(v::MLKEM512_SS)?;
    let kp = MlKemKeyPair::from_decapsulation_key(512, &dk)
        .map_err(|e| CmvpError::KatFailure(format!("ML-KEM dk import: {e}")))?;
    let ss = kp
        .decapsulate(&ct)
        .map_err(|e| CmvpError::KatFailure(format!("ML-KEM decapsulate: {e}")))?;
    if ss != want_ss {
        return Err(CmvpError::KatFailure(
            "ML-KEM-512 decaps KAT mismatch".into(),
        ));
    }
    Ok(())
}

/// SLH-DSA SHA2-128s KAT (FIPS 205 §10.2 pure mode): verify a known signature
/// over the context-wrapped message `0x00 ‖ |ctx| ‖ ctx ‖ msg`.
#[cfg(feature = "slh-dsa")]
fn kat_slhdsa() -> Result<(), CmvpError> {
    use super::kat_vectors as v;
    use crate::slh_dsa::SlhDsaKeyPair;
    use hitls_types::SlhDsaParamId;
    let pk = unhex(v::SLHDSA128S_PK)?;
    let ctx = unhex(v::SLHDSA128S_CTX)?;
    let msg = unhex(v::SLHDSA128S_MSG)?;
    let sig = unhex(v::SLHDSA128S_SIG)?;
    let mut m = Vec::with_capacity(2 + ctx.len() + msg.len());
    m.push(0x00);
    m.push(ctx.len() as u8);
    m.extend_from_slice(&ctx);
    m.extend_from_slice(&msg);
    let kp = SlhDsaKeyPair::from_public_key(SlhDsaParamId::Sha2128s, &pk)
        .map_err(|e| CmvpError::KatFailure(format!("SLH-DSA pk import: {e}")))?;
    let valid = kp
        .verify(&m, &sig)
        .map_err(|e| CmvpError::KatFailure(format!("SLH-DSA verify: {e}")))?;
    if !valid {
        return Err(CmvpError::KatFailure(
            "SLH-DSA-128s verify KAT failed".into(),
        ));
    }
    Ok(())
}

/// Entropy health test KAT (NIST SP 800-90B §4.4).
///
/// Validates that:
/// 1. RCT correctly detects a stuck source (all-same samples)
/// 2. APT correctly detects a biased source (high repetition within window)
/// 3. Normal varying data passes both tests
fn kat_entropy_health() -> Result<(), CmvpError> {
    use crate::entropy::health::{AptTest, HealthTest, RctTest};
    use hitls_types::CryptoError;

    // 1. RCT must detect stuck source
    let mut rct = RctTest::new(5);
    let mut rct_failed = false;
    for _ in 0..10 {
        if rct.test(0x42).is_err() {
            rct_failed = true;
            break;
        }
    }
    if !rct_failed {
        return Err(CmvpError::KatFailure(
            "Entropy RCT failed to detect stuck source".into(),
        ));
    }

    // 2. APT must detect biased source
    let mut apt = AptTest::new(20, 15);
    let mut apt_failed = false;
    for _ in 0..20 {
        if apt.test(0x42).is_err() {
            apt_failed = true;
            break;
        }
    }
    if !apt_failed {
        return Err(CmvpError::KatFailure(
            "Entropy APT failed to detect biased source".into(),
        ));
    }

    // 3. Normal data must pass
    let mut ht = HealthTest::with_defaults();
    for i in 0u64..1000 {
        ht.test_sample(i).map_err(|e: CryptoError| {
            CmvpError::KatFailure(format!("Entropy health test failed on normal data: {e}"))
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kat_sha256() {
        kat_sha256().unwrap();
    }

    #[test]
    fn test_kat_hmac_sha256() {
        kat_hmac_sha256().unwrap();
    }

    #[test]
    fn test_kat_aes128_gcm() {
        kat_aes128_gcm().unwrap();
    }

    #[test]
    fn test_kat_hmac_drbg() {
        kat_hmac_drbg().unwrap();
    }

    #[test]
    fn test_kat_hkdf_sha256() {
        kat_hkdf_sha256().unwrap();
    }

    #[test]
    fn test_kat_ecdsa_p256() {
        kat_ecdsa_p256().unwrap();
    }

    #[test]
    fn test_kat_entropy_health() {
        kat_entropy_health().unwrap();
    }

    #[cfg(feature = "mlkem")]
    #[test]
    fn test_kat_mlkem() {
        kat_mlkem().unwrap();
    }

    #[cfg(feature = "slh-dsa")]
    #[test]
    fn test_kat_slhdsa() {
        kat_slhdsa().unwrap();
    }

    // Tamper checks: prove the KATs actually validate the vector and would
    // catch a broken implementation (a known-answer test that can't fail is
    // worthless). A flipped byte in the ciphertext/signature must change the
    // outcome.
    #[cfg(feature = "mlkem")]
    #[test]
    fn test_kat_mlkem_tamper_detected() {
        use crate::mlkem::MlKemKeyPair;
        let dk = unhex(super::super::kat_vectors::MLKEM512_DK).unwrap();
        let mut ct = unhex(super::super::kat_vectors::MLKEM512_CT).unwrap();
        let want = unhex(super::super::kat_vectors::MLKEM512_SS).unwrap();
        ct[0] ^= 0x01; // corrupt the ciphertext
        let kp = MlKemKeyPair::from_decapsulation_key(512, &dk).unwrap();
        // ML-KEM decaps is designed to return a (deterministic) pseudo-random
        // shared secret on a bad ciphertext rather than error — it must NOT
        // equal the KAT's expected value.
        let ss = kp.decapsulate(&ct).unwrap();
        assert_ne!(ss, want, "tampered ML-KEM ct must not yield the KAT secret");
    }

    #[cfg(feature = "slh-dsa")]
    #[test]
    fn test_kat_slhdsa_tamper_detected() {
        use crate::slh_dsa::SlhDsaKeyPair;
        use hitls_types::SlhDsaParamId;
        let pk = unhex(super::super::kat_vectors::SLHDSA128S_PK).unwrap();
        let ctx = unhex(super::super::kat_vectors::SLHDSA128S_CTX).unwrap();
        let msg = unhex(super::super::kat_vectors::SLHDSA128S_MSG).unwrap();
        let mut sig = unhex(super::super::kat_vectors::SLHDSA128S_SIG).unwrap();
        sig[0] ^= 0x01; // corrupt the signature
        let mut m = vec![0x00, ctx.len() as u8];
        m.extend_from_slice(&ctx);
        m.extend_from_slice(&msg);
        let kp = SlhDsaKeyPair::from_public_key(SlhDsaParamId::Sha2128s, &pk).unwrap();
        assert!(
            !matches!(kp.verify(&m, &sig), Ok(true)),
            "tampered SLH-DSA signature must not verify"
        );
    }

    #[test]
    fn test_run_all_kat() {
        run_all_kat().unwrap();
    }

    /// Verify RCT threshold boundary — 4 same samples should pass, 5 should fail.
    #[test]
    fn test_kat_entropy_rct_boundary() {
        use crate::entropy::health::RctTest;
        let mut rct = RctTest::new(5);
        // 4 repetitions should be OK
        for _ in 0..4 {
            rct.test(0x42).unwrap();
        }
        // 5th should fail
        assert!(rct.test(0x42).is_err(), "5th repetition should trigger RCT");
    }

    /// Verify APT window boundary — within window, cutoff samples trigger failure.
    #[test]
    fn test_kat_entropy_apt_boundary() {
        use crate::entropy::health::AptTest;
        // window_size=10, cutoff=8 → 8 matches within 10 samples triggers failure
        let mut apt = AptTest::new(10, 8);
        let mut failed = false;
        for _ in 0..10 {
            if apt.test(0x42).is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed, "APT should detect biased source within window");
    }

    /// Verify run_all_kat() can be called consecutively.
    #[test]
    fn test_kat_run_all_consecutive() {
        run_all_kat().unwrap();
        run_all_kat().unwrap();
    }
}
