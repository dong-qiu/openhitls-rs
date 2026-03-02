#![no_main]
use hitls_types::XmssParamId;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [mode_sel(1B), rest...]
    if data.is_empty() {
        return;
    }

    let mode_sel = data[0];
    let rest = &data[1..];

    // Use smallest parameter set (h=10, SHA-256, n=32) for fast iteration
    let param = XmssParamId::Sha2_10_256;

    match mode_sel % 2 {
        0 => {
            // Mode 0: generate → sign → verify → assert; tamper → verify fail
            let mut kp = match hitls_crypto::xmss::XmssKeyPair::generate(param) {
                Ok(k) => k,
                Err(_) => return,
            };
            let msg = if rest.is_empty() { &[0u8][..] } else { rest };
            let sig = match kp.sign(msg) {
                Ok(s) => s,
                Err(_) => return,
            };
            let valid = kp.verify(msg, &sig).unwrap_or(false);
            assert!(valid, "XMSS sign/verify roundtrip must succeed");

            // Tamper message
            if !msg.is_empty() {
                let mut tampered = msg.to_vec();
                tampered[0] ^= 0xFF;
                let invalid = kp.verify(&tampered, &sig).unwrap_or(false);
                assert!(!invalid, "XMSS tampered verify must fail");
            }
        }
        _ => {
            // Mode 1: generate → verify(fuzz msg, fuzz sig) — must not panic
            let kp = match hitls_crypto::xmss::XmssKeyPair::generate(param) {
                Ok(k) => k,
                Err(_) => return,
            };
            let _ = kp.verify(b"fuzz", rest);
        }
    }
});
