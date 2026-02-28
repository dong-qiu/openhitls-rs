#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [mode_sel(1B), rest...]
    if data.is_empty() {
        return;
    }

    let mode_sel = data[0];
    let rest = &data[1..];

    let kp = match hitls_crypto::sm2::Sm2KeyPair::generate() {
        Ok(k) => k,
        Err(_) => return,
    };

    match mode_sel % 4 {
        0 => {
            // Mode 0: sign → verify roundtrip → tamper
            let sig = match kp.sign(rest) {
                Ok(s) => s,
                Err(_) => return,
            };
            let valid = kp.verify(rest, &sig).unwrap_or(false);
            assert!(valid, "SM2 sign/verify roundtrip must succeed");
            if !rest.is_empty() {
                let mut tampered = rest.to_vec();
                tampered[0] ^= 0xFF;
                let invalid = kp.verify(&tampered, &sig).unwrap_or(false);
                assert!(!invalid, "SM2 tampered verify must fail");
            }
        }
        1 => {
            // Mode 1: sign_with_id → verify_with_id
            if rest.is_empty() {
                return;
            }
            let id_len = (rest[0] as usize) % 64;
            let payload = &rest[1..];
            if payload.len() < id_len {
                return;
            }
            let id = &payload[..id_len];
            let msg = &payload[id_len..];
            let sig = match kp.sign_with_id(id, msg) {
                Ok(s) => s,
                Err(_) => return,
            };
            let valid = kp.verify_with_id(id, msg, &sig).unwrap_or(false);
            assert!(valid, "SM2 sign_with_id roundtrip must succeed");
        }
        2 => {
            // Mode 2: encrypt → decrypt roundtrip
            if rest.is_empty() {
                return;
            }
            let ct = match kp.encrypt(rest) {
                Ok(c) => c,
                Err(_) => return,
            };
            let pt = match kp.decrypt(&ct) {
                Ok(p) => p,
                Err(_) => return,
            };
            assert_eq!(rest, &pt[..], "SM2 encrypt/decrypt roundtrip must match");
        }
        _ => {
            // Mode 3: fuzzed decrypt — must not panic
            let _ = kp.decrypt(rest);
        }
    }
});
