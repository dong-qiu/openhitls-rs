#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [mode_sel(1B), key(32B), nonce(12B), aad_len(1B), rest...]
    if data.len() < 1 + 32 + 12 + 1 {
        return;
    }

    let mode_sel = data[0];
    let key = &data[1..33];
    let nonce = &data[33..45];
    let aad_len = (data[45] as usize) % 64; // cap AAD to 63 bytes
    let rest = &data[46..];

    if rest.len() < aad_len {
        return;
    }
    let aad = &rest[..aad_len];
    let plaintext = &rest[aad_len..];

    let cipher = match hitls_crypto::chacha20::ChaCha20Poly1305::new(key) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Encrypt
    let ct = match cipher.encrypt(nonce, aad, plaintext) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Decrypt → must recover plaintext
    let pt = match cipher.decrypt(nonce, aad, &ct) {
        Ok(p) => p,
        Err(_) => panic!("ChaCha20-Poly1305 decrypt must succeed after encrypt"),
    };
    assert_eq!(pt, plaintext, "ChaCha20-Poly1305 roundtrip must be lossless");

    // Tamper mode: flip bit in ciphertext, decrypt must fail
    if mode_sel % 2 == 1 && !ct.is_empty() {
        let mut tampered = ct.clone();
        tampered[0] ^= 0x01;
        let result = cipher.decrypt(nonce, aad, &tampered);
        assert!(result.is_err(), "tampered ciphertext must fail decryption");
    }
});
