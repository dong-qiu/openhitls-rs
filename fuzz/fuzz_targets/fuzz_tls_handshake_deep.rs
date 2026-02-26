#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Use first byte to dispatch across all handshake message decoders
    let body = if data.len() > 1 { &data[1..] } else { &[] };
    match data[0] % 10 {
        0 => { let _ = hitls_tls::handshake::codec::decode_client_hello(body); }
        1 => { let _ = hitls_tls::handshake::codec::decode_server_hello(body); }
        2 => { let _ = hitls_tls::handshake::codec::decode_encrypted_extensions(body); }
        3 => { let _ = hitls_tls::handshake::codec::decode_certificate(body); }
        4 => { let _ = hitls_tls::handshake::codec::decode_certificate_verify(body); }
        5 => { let _ = hitls_tls::handshake::codec::decode_finished(body, 32); }
        6 => { let _ = hitls_tls::handshake::codec::decode_key_update(body); }
        7 => { let _ = hitls_tls::handshake::codec::decode_new_session_ticket(body); }
        8 => { let _ = hitls_tls::handshake::codec::decode_certificate_request(body); }
        9 => { let _ = hitls_tls::handshake::codec::decode_compressed_certificate(body); }
        _ => {}
    }

    // Also exercise full header parsing on entire input
    let _ = hitls_tls::handshake::codec::parse_handshake_header(data);
});
