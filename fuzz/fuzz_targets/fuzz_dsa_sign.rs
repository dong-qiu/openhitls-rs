#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [mode_sel(1B), rest...]
    if data.is_empty() {
        return;
    }

    let mode_sel = data[0];
    let rest = &data[1..];

    // Small DSA parameters for fast iteration: p=23, q=11, g=4
    let p = &[23u8];
    let q = &[11u8];
    let g = &[4u8];

    let params = match hitls_crypto::dsa::DsaParams::new(p, q, g) {
        Ok(p) => p,
        Err(_) => return,
    };

    match mode_sel % 3 {
        0 => {
            // Mode 0: generate → sign → verify roundtrip
            let kp = match hitls_crypto::dsa::DsaKeyPair::generate(params) {
                Ok(k) => k,
                Err(_) => return,
            };
            let digest = if rest.is_empty() { &[0u8][..] } else { rest };
            let sig = match kp.sign(digest) {
                Ok(s) => s,
                Err(_) => return,
            };
            let valid = kp.verify(digest, &sig).unwrap_or(false);
            assert!(valid, "DSA sign/verify roundtrip must succeed");
        }
        1 => {
            // Mode 1: generate → verify fuzzed signature (must not panic)
            let kp = match hitls_crypto::dsa::DsaKeyPair::generate(params) {
                Ok(k) => k,
                Err(_) => return,
            };
            let _ = kp.verify(b"fuzz test", rest);
        }
        _ => {
            // Mode 2: from_private_key → sign → verify
            if rest.is_empty() {
                return;
            }
            let kp = match hitls_crypto::dsa::DsaKeyPair::from_private_key(params, rest) {
                Ok(k) => k,
                Err(_) => return,
            };
            let sig = match kp.sign(b"test message") {
                Ok(s) => s,
                Err(_) => return,
            };
            let valid = kp.verify(b"test message", &sig).unwrap_or(false);
            assert!(valid, "DSA from_private_key roundtrip must succeed");
        }
    }
});
