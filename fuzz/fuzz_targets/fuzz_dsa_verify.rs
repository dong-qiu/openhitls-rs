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

    match mode_sel % 2 {
        0 => {
            // Mode 0: generate → sign → verify good; verify(fuzzed_sig=rest) — must not panic
            let kp = match hitls_crypto::dsa::DsaKeyPair::generate(params) {
                Ok(k) => k,
                Err(_) => return,
            };
            let digest = &[0x42u8; 4];
            let sig = match kp.sign(digest) {
                Ok(s) => s,
                Err(_) => return,
            };
            let valid = kp.verify(digest, &sig).unwrap_or(false);
            assert!(valid, "DSA sign/verify roundtrip must succeed");

            // Verify fuzzed signature — must not panic
            let _ = kp.verify(digest, rest);
        }
        _ => {
            // Mode 1: generate → verify(rest as msg, rest as sig) — must not panic
            let kp = match hitls_crypto::dsa::DsaKeyPair::generate(params) {
                Ok(k) => k,
                Err(_) => return,
            };
            let _ = kp.verify(b"fuzz", rest);
        }
    }
});
