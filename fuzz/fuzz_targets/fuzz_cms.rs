#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hitls_pki::cms::CmsMessage::from_der(data);
});
