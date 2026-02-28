#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [dk_len_sel(1B), iter_sel(1B), salt_len(1B), rest...]
    if data.len() < 3 {
        return;
    }

    let dk_len = (data[0] as usize % 64) + 1; // 1-64 bytes
    let iterations = (data[1] as u32 % 10) + 1; // 1-10 iterations (cap for speed)
    let salt_len = (data[2] as usize).min(data.len() - 3);
    let rest = &data[3..];
    if rest.len() < salt_len {
        return;
    }
    let salt = &rest[..salt_len];
    let password = &rest[salt_len..];

    // Compute PBKDF2
    let result = match hitls_crypto::pbkdf2::pbkdf2(password, salt, iterations, dk_len) {
        Ok(r) => r,
        Err(_) => return,
    };

    assert_eq!(result.len(), dk_len, "PBKDF2 output length must match dk_len");

    // Determinism check: same inputs → same output
    let result2 = match hitls_crypto::pbkdf2::pbkdf2(password, salt, iterations, dk_len) {
        Ok(r) => r,
        Err(_) => return,
    };
    assert_eq!(result, result2, "PBKDF2 must be deterministic");
});
