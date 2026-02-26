#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least: 16-byte key + 12-byte nonce + 1-byte aad_len + 16-byte tag = 45 bytes
    if data.len() < 45 {
        return;
    }

    // Split fuzz data: 16-byte key, 12-byte nonce, 1-byte AAD length, rest = ciphertext+tag
    let key = &data[..16];
    let nonce = &data[16..28];
    let aad_len = (data[28] as usize) % 64; // Cap AAD at 63 bytes
    let rest = &data[29..];
    let (aad, ct) = if aad_len < rest.len() {
        rest.split_at(aad_len)
    } else {
        (rest, &[][..])
    };

    // AES-128-GCM decrypt — ciphertext includes appended 16-byte tag
    let _ = hitls_crypto::modes::gcm::gcm_decrypt(key, nonce, aad, ct);

    // ChaCha20-Poly1305 decrypt with 32-byte key
    // Need at least: 32-byte key + 12-byte nonce + 16-byte tag = 60 bytes
    if data.len() >= 60 {
        let key32 = &data[..32];
        let nonce12 = &data[32..44];
        let ct2 = &data[44..];
        if let Ok(aead) = hitls_crypto::chacha20::ChaCha20Poly1305::new(key32) {
            let _ = aead.decrypt(nonce12, &[], ct2);
        }
    }
});
