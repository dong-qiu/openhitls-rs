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
            let kp = match hitls_crypto::ed448::Ed448KeyPair::generate() {
                Ok(k) => k,
                Err(_) => return,
            };
            let sig = match kp.sign(rest) {
                Ok(s) => s,
                Err(_) => return,
            };
            let valid = kp.verify(rest, &sig).unwrap_or(false);
            assert!(valid, "Ed448 roundtrip must succeed");
        }
        1 => {
            // Mode 1: from_seed → sign → verify
            if rest.len() < 57 {
                return;
            }
            let kp = match hitls_crypto::ed448::Ed448KeyPair::from_seed(&rest[..57]) {
                Ok(k) => k,
                Err(_) => return,
            };
            let msg = &rest[57..];
            let sig = match kp.sign(msg) {
                Ok(s) => s,
                Err(_) => return,
            };
            let valid = kp.verify(msg, &sig).unwrap_or(false);
            assert!(valid, "Ed448 from_seed roundtrip must succeed");
        }
        2 => {
            // Mode 2: sign_with_context → verify_with_context
            let kp = match hitls_crypto::ed448::Ed448KeyPair::generate() {
                Ok(k) => k,
                Err(_) => return,
            };
            let ctx_len = (rest.first().copied().unwrap_or(0) as usize).min(255);
            if rest.len() < 1 + ctx_len {
                return;
            }
            let ctx = &rest[1..1 + ctx_len];
            let msg = &rest[1 + ctx_len..];
            let sig = match kp.sign_with_context(msg, ctx) {
                Ok(s) => s,
                Err(_) => return,
            };
            let valid = kp.verify_with_context(msg, &sig, ctx).unwrap_or(false);
            assert!(valid, "Ed448 context roundtrip must succeed");
        }
        _ => {
            // Mode 3: fuzzed signature verify — must not panic
            let kp = match hitls_crypto::ed448::Ed448KeyPair::generate() {
                Ok(k) => k,
                Err(_) => return,
            };
            if rest.len() >= 114 {
                let _ = kp.verify(b"fuzz test", &rest[..114]);
            }
        }
    }
});
