#![no_main]
use hitls_types::EccCurveId;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [curve_sel(1B), mode_sel(1B), digest...]
    if data.len() < 2 {
        return;
    }

    let curve_sel = data[0];
    let mode_sel = data[1];
    let digest = &data[2..];

    let curve = match curve_sel % 3 {
        0 => EccCurveId::NistP256,
        1 => EccCurveId::NistP384,
        _ => EccCurveId::NistP521,
    };

    let kp = match hitls_crypto::ecdsa::EcdsaKeyPair::generate(curve) {
        Ok(k) => k,
        Err(_) => return,
    };

    // Sign the digest
    let sig = match kp.sign(digest) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Verify must succeed
    let valid = kp.verify(digest, &sig).unwrap_or(false);
    assert!(valid, "ECDSA roundtrip verification must succeed");

    if mode_sel % 2 == 1 && !digest.is_empty() {
        // Tamper mode: modify digest, verify must fail
        let mut tampered = digest.to_vec();
        tampered[0] ^= 0xFF;
        let invalid = kp.verify(&tampered, &sig).unwrap_or(false);
        assert!(!invalid, "ECDSA tampered verification must fail");
    }
});
