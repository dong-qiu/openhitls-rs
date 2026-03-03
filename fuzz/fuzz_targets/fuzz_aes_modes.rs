#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Layout: [mode_sel(1B), key_material(32B), iv(16B), rest...]
    // Minimum: 1 + 32 + 16 = 49 bytes
    if data.len() < 49 {
        return;
    }

    let mode_sel = data[0];
    let key_material = &data[1..33]; // 32 bytes — used as key(s)
    let iv = &data[33..49]; // 16 bytes — iv/tweak/nonce
    let rest = &data[49..];

    match mode_sel % 6 {
        // --- AES-XTS roundtrip ---
        0 => {
            // XTS needs two 16-byte keys and ≥16 bytes input
            if rest.len() < 16 {
                return;
            }
            let key1 = &key_material[..16];
            let key2 = &key_material[16..32];
            if let Ok(ct) = hitls_crypto::modes::xts::xts_encrypt(key1, key2, iv, rest) {
                let pt = hitls_crypto::modes::xts::xts_decrypt(key1, key2, iv, &ct).unwrap();
                assert_eq!(pt, rest, "XTS roundtrip mismatch");
            }
        }
        // --- AES-CFB roundtrip ---
        1 => {
            let key = &key_material[..16]; // AES-128
            if let Ok(ct) = hitls_crypto::modes::cfb::cfb_encrypt(key, iv, rest) {
                let pt = hitls_crypto::modes::cfb::cfb_decrypt(key, iv, &ct).unwrap();
                assert_eq!(pt, rest, "CFB roundtrip mismatch");
            }
        }
        // --- AES-CTR roundtrip ---
        2 => {
            let key = &key_material[..16];
            let mut ct = rest.to_vec();
            if hitls_crypto::modes::ctr::ctr_crypt(key, iv, &mut ct).is_ok() {
                // Decrypt by applying CTR again
                let mut pt = ct.clone();
                hitls_crypto::modes::ctr::ctr_crypt(key, iv, &mut pt).unwrap();
                assert_eq!(pt, rest, "CTR roundtrip mismatch");
            }
        }
        // --- AES Key Wrap roundtrip ---
        3 => {
            let kek = &key_material[..16];
            // key_wrap needs ≥16 bytes and multiple of 8
            if rest.len() < 16 || rest.len() % 8 != 0 {
                return;
            }
            if let Ok(wrapped) = hitls_crypto::modes::wrap::key_wrap(kek, rest) {
                let unwrapped = hitls_crypto::modes::wrap::key_unwrap(kek, &wrapped).unwrap();
                assert_eq!(unwrapped, rest, "KeyWrap roundtrip mismatch");
            }
        }
        // --- AES Key Wrap fuzzed unwrap (must not panic) ---
        4 => {
            let kek = &key_material[..16];
            let _ = hitls_crypto::modes::wrap::key_unwrap(kek, rest);
        }
        // --- AES-CFB with AES-256 roundtrip ---
        _ => {
            let key = &key_material[..32]; // AES-256
            if let Ok(ct) = hitls_crypto::modes::cfb::cfb_encrypt(key, iv, rest) {
                let pt = hitls_crypto::modes::cfb::cfb_decrypt(key, iv, &ct).unwrap();
                assert_eq!(pt, rest, "CFB-256 roundtrip mismatch");
            }
        }
    }
});
