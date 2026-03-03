#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input layout: 1B salt_len + 1B ikm_len + 1B info_len + 1B okm_len + bytes
    // Minimum: 4 bytes
    if data.len() < 4 {
        return;
    }

    let salt_len = (data[0] as usize) % 64;
    let ikm_len = (data[1] as usize) % 64;
    let info_len = (data[2] as usize) % 64;
    let okm_len = ((data[3] as usize) % 255) + 1; // 1..256

    let rest = &data[4..];
    if rest.len() < salt_len + ikm_len + info_len {
        return;
    }

    let salt = &rest[..salt_len];
    let ikm = &rest[salt_len..salt_len + ikm_len];
    let info = &rest[salt_len + ikm_len..salt_len + ikm_len + info_len];

    // One-shot derive — determinism assertion
    let result1 = hitls_crypto::hkdf::Hkdf::derive(salt, ikm, info, okm_len);
    let result2 = hitls_crypto::hkdf::Hkdf::derive(salt, ikm, info, okm_len);
    match (&result1, &result2) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "HKDF derive must be deterministic"),
        (Err(_), Err(_)) => {}
        _ => panic!("HKDF derive must return consistent results"),
    }

    // Two-step: extract → expand, assert equivalence with one-shot
    if let Ok(hkdf) = hitls_crypto::hkdf::Hkdf::new(salt, ikm) {
        if let Ok(expanded) = hkdf.expand(info, okm_len) {
            if let Ok(derived) = &result1 {
                assert_eq!(&expanded, derived, "Two-step must match one-shot derive");
            }
        }
    }
});
