#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Use first byte to dispatch across 3 TLCP-specific decoders
    let body = if data.len() > 1 { &data[1..] } else { &[] };
    match data[0] % 3 {
        0 => { let _ = hitls_tls::handshake::codec_tlcp::decode_tlcp_certificate(body); }
        1 => { let _ = hitls_tls::handshake::codec_tlcp::decode_ecc_server_key_exchange(body); }
        2 => { let _ = hitls_tls::handshake::codec_tlcp::decode_ecc_client_key_exchange(body); }
        _ => {}
    }
});
