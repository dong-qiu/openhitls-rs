#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [key_sel(1B), rest...]
    if data.len() < 2 {
        return;
    }

    let key_sel = data[0];
    let rest = &data[1..];

    // Select key size: 16 (AES-128), 24 (AES-192), or 32 (AES-256)
    let key_len = match key_sel % 3 {
        0 => 16,
        1 => 24,
        _ => 32,
    };

    if rest.len() < key_len + 16 {
        return;
    }

    let key = &rest[..key_len];
    let block_data = &rest[key_len..key_len + 16];

    let cipher = match hitls_crypto::aes::AesKey::new(key) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Encrypt → decrypt roundtrip
    let mut buf = [0u8; 16];
    buf.copy_from_slice(block_data);
    let original = buf;

    if cipher.encrypt_block(&mut buf).is_err() {
        return;
    }
    if cipher.decrypt_block(&mut buf).is_err() {
        return;
    }

    assert_eq!(buf, original, "AES block roundtrip must be lossless");
});
