#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hitls_pki::pkcs8::parse_pkcs8_der(data);
});
