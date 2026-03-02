#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [param_sel(1B), rest...]
    if data.is_empty() {
        return;
    }

    let param_sel = data[0];
    let rest = &data[1..];

    let param = match param_sel % 2 {
        0 => 44u32,
        _ => 65,
    };

    let kp = match hitls_crypto::mldsa::MlDsaKeyPair::generate(param) {
        Ok(k) => k,
        Err(_) => return,
    };

    // Verify fuzzed signature — must not panic
    let _ = kp.verify(b"fuzz test message", rest);
});
