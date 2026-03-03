#![no_main]
use hitls_types::SlhDsaParamId;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [param_sel(1B), mode_sel(1B), rest...]
    if data.len() < 2 {
        return;
    }

    let param_sel = data[0];
    let mode_sel = data[1];
    let rest = &data[2..];

    // Only use fast variants to keep keygen/sign tolerable
    let param = match param_sel % 2 {
        0 => SlhDsaParamId::Sha2128f,
        _ => SlhDsaParamId::Shake128f,
    };

    let kp = match hitls_crypto::slh_dsa::SlhDsaKeyPair::generate(param) {
        Ok(k) => k,
        Err(_) => return,
    };

    match mode_sel % 3 {
        0 => {
            // Mode 0: sign → verify roundtrip
            let sig = match kp.sign(rest) {
                Ok(s) => s,
                Err(_) => return,
            };
            let valid = kp.verify(rest, &sig).unwrap_or(false);
            assert!(valid, "SLH-DSA roundtrip verification must succeed");
        }
        1 => {
            // Mode 1: sign → tamper message → verify must fail
            let msg = b"SLH-DSA tamper test message";
            let sig = match kp.sign(msg) {
                Ok(s) => s,
                Err(_) => return,
            };
            let wrong_msg = b"SLH-DSA tamper WRONG message";
            let valid = kp.verify(wrong_msg, &sig).unwrap_or(false);
            assert!(!valid, "SLH-DSA verify must fail with wrong message");
        }
        _ => {
            // Mode 2: verify fuzzed signature — must not panic
            let _ = kp.verify(b"fuzz test message", rest);
        }
    }
});
