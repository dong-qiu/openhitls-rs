#![no_main]
use hitls_types::SlhDsaParamId;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [param_sel(1B), rest...]
    if data.is_empty() {
        return;
    }

    let param_sel = data[0];
    let rest = &data[1..];

    // Only use fast variants to keep keygen tolerable
    let param = match param_sel % 2 {
        0 => SlhDsaParamId::Sha2128f,
        _ => SlhDsaParamId::Shake128f,
    };

    let kp = match hitls_crypto::slh_dsa::SlhDsaKeyPair::generate(param) {
        Ok(k) => k,
        Err(_) => return,
    };

    // Verify fuzzed signature — must not panic
    let _ = kp.verify(b"fuzz test message", rest);
});
