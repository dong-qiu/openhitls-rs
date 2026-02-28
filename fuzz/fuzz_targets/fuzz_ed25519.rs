#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [mode_sel(1B), rest...]
    if data.is_empty() {
        return;
    }

    let mode_sel = data[0];
    let rest = &data[1..];

    match mode_sel % 4 {
        0 => {
            // Mode 0: generate → sign(rest) → verify must succeed
            let kp = match hitls_crypto::ed25519::Ed25519KeyPair::generate() {
                Ok(k) => k,
                Err(_) => return,
            };
            let sig = match kp.sign(rest) {
                Ok(s) => s,
                Err(_) => return,
            };
            let valid = kp.verify(rest, &sig).unwrap_or(false);
            assert!(valid, "Ed25519 roundtrip must succeed");
        }
        1 => {
            // Mode 1: from_seed → sign → verify
            if rest.len() < 32 {
                return;
            }
            let kp = match hitls_crypto::ed25519::Ed25519KeyPair::from_seed(&rest[..32]) {
                Ok(k) => k,
                Err(_) => return,
            };
            let msg = &rest[32..];
            let sig = match kp.sign(msg) {
                Ok(s) => s,
                Err(_) => return,
            };
            let valid = kp.verify(msg, &sig).unwrap_or(false);
            assert!(valid, "Ed25519 from_seed roundtrip must succeed");
        }
        2 => {
            // Mode 2: from_public_key → verify fuzzed sig (must not panic)
            if rest.len() < 96 {
                return;
            }
            let kp =
                match hitls_crypto::ed25519::Ed25519KeyPair::from_public_key(&rest[..32]) {
                    Ok(k) => k,
                    Err(_) => return,
                };
            let _ = kp.verify(&rest[32..64], &rest[64..128.min(rest.len())]);
        }
        _ => {
            // Mode 3: generate → verify fuzzed signature
            let kp = match hitls_crypto::ed25519::Ed25519KeyPair::generate() {
                Ok(k) => k,
                Err(_) => return,
            };
            if rest.len() >= 64 {
                let _ = kp.verify(b"fuzz test", &rest[..64]);
            }
        }
    }
});
