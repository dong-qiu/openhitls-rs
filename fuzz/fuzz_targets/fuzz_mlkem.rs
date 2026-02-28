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
        0 => 512u32,
        1 => 768,
        _ => 1024,
    };

    match mode_sel % 3 {
        0 => {
            // Mode 0: generate → encapsulate → tamper ct → decapsulate (implicit rejection)
            let kp = match hitls_crypto::mlkem::MlKemKeyPair::generate(param) {
                Ok(k) => k,
                Err(_) => return,
            };
            let (ss, ct) = match kp.encapsulate() {
                Ok(r) => r,
                Err(_) => return,
            };
            // Verify roundtrip
            let ss2 = match kp.decapsulate(&ct) {
                Ok(s) => s,
                Err(_) => return,
            };
            assert_eq!(ss, ss2);
            // Tamper ct with fuzz data and decapsulate — must not panic
            if !rest.is_empty() {
                let mut tampered = ct.clone();
                for (i, &b) in rest.iter().enumerate() {
                    tampered[i % tampered.len()] ^= b;
                }
                let _ = kp.decapsulate(&tampered);
            }
        }
        1 => {
            // Mode 1: generate → fuzzed ct → decapsulate (must not panic)
            let kp = match hitls_crypto::mlkem::MlKemKeyPair::generate(param) {
                Ok(k) => k,
                Err(_) => return,
            };
            let _ = kp.decapsulate(rest);
        }
        _ => {
            // Mode 2: fuzzed ek → from_encapsulation_key → encapsulate
            let kp = match hitls_crypto::mlkem::MlKemKeyPair::from_encapsulation_key(param, rest) {
                Ok(k) => k,
                Err(_) => return,
            };
            let _ = kp.encapsulate();
        }
    }
});
