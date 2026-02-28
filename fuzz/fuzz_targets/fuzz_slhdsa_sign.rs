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

    match mode_sel % 2 {
        0 => {
            // Mode 0: sign → verify roundtrip
            let sig = match kp.sign(rest) {
                Ok(s) => s,
                Err(_) => return,
            };
            let valid = kp.verify(rest, &sig).unwrap_or(false);
            assert!(valid, "SLH-DSA roundtrip verification must succeed");
        }
        _ => {
            // Mode 1: verify fuzzed signature — must not panic
            let _ = kp.verify(b"fuzz test message", rest);
        }
    }
});
