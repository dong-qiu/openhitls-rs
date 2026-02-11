#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Dispatch on first byte as handshake type
    if data.is_empty() {
        return;
    }
    let _ = hitls_tls::handshake::codec::parse_handshake_header(data);
    // Also try specific decoders if data is large enough
    if data.len() >= 4 {
        let body = &data[4..];
        let _ = hitls_tls::handshake::codec::decode_client_hello(body);
        let _ = hitls_tls::handshake::codec::decode_server_hello(body);
    }
});
