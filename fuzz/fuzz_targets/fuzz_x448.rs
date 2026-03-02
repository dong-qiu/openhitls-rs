#![no_main]
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
            // Mode 0: generate two keys → DH exchange → shared secrets must match
            let alice = match hitls_crypto::x448::X448PrivateKey::generate() {
                Ok(k) => k,
                Err(_) => return,
            };
            let bob = match hitls_crypto::x448::X448PrivateKey::generate() {
                Ok(k) => k,
                Err(_) => return,
            };
            let alice_pub = alice.public_key();
            let bob_pub = bob.public_key();
            let ss_alice = match alice.diffie_hellman(&bob_pub) {
                Ok(s) => s,
                Err(_) => return,
            };
            let ss_bob = match bob.diffie_hellman(&alice_pub) {
                Ok(s) => s,
                Err(_) => return,
            };
            assert_eq!(ss_alice, ss_bob, "X448 DH shared secrets must match");
        }
        1 => {
            // Mode 1: from_bytes → public_key → DH with generated key
            if rest.len() < 56 {
                return;
            }
            let priv_key = match hitls_crypto::x448::X448PrivateKey::new(&rest[..56]) {
                Ok(k) => k,
                Err(_) => return,
            };
            let pub_key = priv_key.public_key();
            let other = match hitls_crypto::x448::X448PrivateKey::generate() {
                Ok(k) => k,
                Err(_) => return,
            };
            let other_pub = other.public_key();
            let ss1 = match priv_key.diffie_hellman(&other_pub) {
                Ok(s) => s,
                Err(_) => return,
            };
            let ss2 = match other.diffie_hellman(&pub_key) {
                Ok(s) => s,
                Err(_) => return,
            };
            assert_eq!(ss1, ss2, "X448 from_bytes DH must match");
        }
        _ => {
            // Mode 2: fuzzed public key → DH must not panic
            if rest.len() < 56 {
                return;
            }
            let priv_key = match hitls_crypto::x448::X448PrivateKey::generate() {
                Ok(k) => k,
                Err(_) => return,
            };
            let fuzzed_pub = match hitls_crypto::x448::X448PublicKey::new(&rest[..56]) {
                Ok(k) => k,
                Err(_) => return,
            };
            let _ = priv_key.diffie_hellman(&fuzzed_pub);
        }
    }
});
