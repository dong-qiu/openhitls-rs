#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

// Cache keygen (FrodoKEM-640 keygen is ~100ms)
static FRODO_KEY_SHAKE: OnceLock<hitls_crypto::frodokem::FrodoKemKeyPair> = OnceLock::new();

fn get_frodo_key() -> &'static hitls_crypto::frodokem::FrodoKemKeyPair {
    FRODO_KEY_SHAKE.get_or_init(|| {
        hitls_crypto::frodokem::FrodoKemKeyPair::generate(
            hitls_types::FrodoKemParamId::FrodoKem640Shake,
        )
        .expect("FrodoKEM-640-SHAKE keygen must succeed")
    })
}

fuzz_target!(|data: &[u8]| {
    // Input: [mode_sel(1B), rest...]
    if data.is_empty() {
        return;
    }

    let mode_sel = data[0];
    let rest = &data[1..];

    match mode_sel % 3 {
        0 => {
            // Mode 0: encapsulate → decapsulate → shared secrets must match
            let kp = get_frodo_key();
            let (ct, ss_enc) = match kp.encapsulate() {
                Ok(r) => r,
                Err(_) => return,
            };
            let ss_dec = match kp.decapsulate(&ct) {
                Ok(s) => s,
                Err(_) => return,
            };
            assert_eq!(ss_enc, ss_dec, "FrodoKEM roundtrip shared secrets must match");
        }
        1 => {
            // Mode 1: tamper ciphertext → decapsulate (implicit rejection)
            let kp = get_frodo_key();
            let (ct, _ss) = match kp.encapsulate() {
                Ok(r) => r,
                Err(_) => return,
            };
            if !rest.is_empty() {
                let mut tampered = ct.clone();
                let idx = rest[0] as usize % tampered.len();
                tampered[idx] ^= 0xFF;
                // Tampered ct should produce different shared secret (implicit rejection)
                let _ = kp.decapsulate(&tampered);
            }
        }
        _ => {
            // Mode 2: fuzzed ciphertext → decapsulate must not panic
            let kp = get_frodo_key();
            let _ = kp.decapsulate(rest);
        }
    }
});
