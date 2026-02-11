#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut decoder = hitls_utils::asn1::Decoder::new(data);
    while !decoder.is_empty() {
        if decoder.read_tlv().is_err() {
            break;
        }
    }
});
