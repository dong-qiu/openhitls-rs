#![no_main]
use hitls_crypto::sm9::{Sm9KeyType, Sm9MasterKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [mode_sel(1B), rest...]
    if data.is_empty() {
        return;
    }

    let mode_sel = data[0];
    let rest = &data[1..];

    match mode_sel % 3 {
        0 => {
            // Mode 0: sign system — master_keygen → extract_user_key → sign → verify
            let master = match Sm9MasterKey::generate(Sm9KeyType::Sign) {
                Ok(k) => k,
                Err(_) => return,
            };
            let user_id = b"alice@example.com";
            let user_key = match master.extract_user_key(user_id) {
                Ok(k) => k,
                Err(_) => return,
            };
            let msg = if rest.is_empty() { &[0u8][..] } else { rest };
            let sig = match user_key.sign(msg, master.master_public_key()) {
                Ok(s) => s,
                Err(_) => return,
            };
            let valid = master.verify(user_id, msg, &sig).unwrap_or(false);
            assert!(valid, "SM9 sign/verify roundtrip must succeed");
        }
        1 => {
            // Mode 1: encrypt system — master_keygen → encrypt → extract_user → decrypt
            let master = match Sm9MasterKey::generate(Sm9KeyType::Encrypt) {
                Ok(k) => k,
                Err(_) => return,
            };
            let user_id = b"bob@example.com";
            let user_key = match master.extract_user_key(user_id) {
                Ok(k) => k,
                Err(_) => return,
            };
            let pt = if rest.is_empty() { &[1u8][..] } else { rest };
            let ct = match master.encrypt(user_id, pt) {
                Ok(c) => c,
                Err(_) => return,
            };
            let decrypted = match user_key.decrypt(&ct) {
                Ok(p) => p,
                Err(_) => return,
            };
            assert_eq!(pt, &decrypted[..], "SM9 encrypt/decrypt roundtrip must match");
        }
        _ => {
            // Mode 2: verify fuzzed sig — must not panic
            let master = match Sm9MasterKey::generate(Sm9KeyType::Sign) {
                Ok(k) => k,
                Err(_) => return,
            };
            let _ = master.verify(b"user", b"msg", rest);
        }
    }
});
