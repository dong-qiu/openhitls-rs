#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [log_n(1B), r_sel(1B), pw_len(1B), salt_len(1B), rest...]
    if data.len() < 4 {
        return;
    }

    let log_n = data[0];
    let r_sel = data[1];
    let pw_len = data[2] as usize;
    let salt_len = data[3] as usize;
    let rest = &data[4..];

    // Bound parameters to keep runtime reasonable
    let n = 1u32 << ((log_n % 4) + 1); // 2, 4, 8, or 16
    let r = (r_sel % 2) as u32 + 1; // 1 or 2
    let p = 1u32;
    let dk_len = 32usize;

    // Extract password and salt from remaining data
    let pw_end = pw_len.min(rest.len());
    let password = &rest[..pw_end];
    let salt_start = pw_end;
    let salt_end = (salt_start + salt_len).min(rest.len());
    let salt = &rest[salt_start..salt_end];

    // Derive key twice with same parameters → must be deterministic
    let dk1 = match hitls_crypto::scrypt::scrypt(password, salt, n, r, p, dk_len) {
        Ok(d) => d,
        Err(_) => return,
    };
    let dk2 = match hitls_crypto::scrypt::scrypt(password, salt, n, r, p, dk_len) {
        Ok(d) => d,
        Err(_) => return,
    };

    assert_eq!(dk1, dk2, "scrypt must be deterministic");
    assert_eq!(dk1.len(), dk_len);
});
