#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [param_sel(1B), mode_sel(1B), rest...]
    if data.len() < 2 {
        return;
    }

    let param_sel = data[0];
    let mode_sel = data[1];
    let rest = &data[2..];

    let param = match param_sel % 3 {
        0 => 44u32,
        1 => 65,
        _ => 87,
    };

    let kp = match hitls_crypto::mldsa::MlDsaKeyPair::generate(param) {
        Ok(k) => k,
        Err(_) => return,
    };

    match mode_sel % 2 {
        0 => {
            // Mode 0: sign → verify roundtrip → tamper msg → verify must fail
            let sig = match kp.sign(rest) {
                Ok(s) => s,
                Err(_) => return,
            };
            let valid = kp.verify(rest, &sig).unwrap_or(false);
            assert!(valid, "ML-DSA roundtrip verification must succeed");
            // Tamper message
            if !rest.is_empty() {
                let mut tampered = rest.to_vec();
                tampered[0] ^= 0xFF;
                let invalid = kp.verify(&tampered, &sig).unwrap_or(false);
                assert!(!invalid, "ML-DSA tampered verification must fail");
            }
        }
        _ => {
            // Mode 1: verify fuzzed signature — must not panic
            let _ = kp.verify(b"fuzz test message", rest);
        }
    }
});
