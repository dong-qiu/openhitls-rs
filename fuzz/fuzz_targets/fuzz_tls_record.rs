#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let layer = hitls_tls::record::RecordLayer::new();
    let _ = layer.parse_record(data);
});
