#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Use first byte to dispatch across all 20 TLS 1.2 message decoders
    let body = if data.len() > 1 { &data[1..] } else { &[] };
    match data[0] % 20 {
        0 => { let _ = hitls_tls::handshake::codec12::decode_server_key_exchange(body); }
        1 => { let _ = hitls_tls::handshake::codec12::decode_client_key_exchange(body); }
        2 => { let _ = hitls_tls::handshake::codec12::decode_server_key_exchange_dhe(body); }
        3 => { let _ = hitls_tls::handshake::codec12::decode_client_key_exchange_rsa(body); }
        4 => { let _ = hitls_tls::handshake::codec12::decode_client_key_exchange_dhe(body); }
        5 => { let _ = hitls_tls::handshake::codec12::decode_certificate_status12(body); }
        6 => { let _ = hitls_tls::handshake::codec12::decode_certificate12(body); }
        7 => { let _ = hitls_tls::handshake::codec12::decode_finished12(body); }
        8 => { let _ = hitls_tls::handshake::codec12::decode_certificate_request12(body); }
        9 => { let _ = hitls_tls::handshake::codec12::decode_certificate_verify12(body); }
        10 => { let _ = hitls_tls::handshake::codec12::decode_new_session_ticket12(body); }
        11 => { let _ = hitls_tls::handshake::codec12::decode_server_key_exchange_psk_hint(body); }
        12 => { let _ = hitls_tls::handshake::codec12::decode_server_key_exchange_dhe_psk(body); }
        13 => { let _ = hitls_tls::handshake::codec12::decode_client_key_exchange_psk(body); }
        14 => { let _ = hitls_tls::handshake::codec12::decode_client_key_exchange_dhe_psk(body); }
        15 => { let _ = hitls_tls::handshake::codec12::decode_client_key_exchange_ecdhe_psk(body); }
        16 => { let _ = hitls_tls::handshake::codec12::decode_client_key_exchange_rsa_psk(body); }
        17 => { let _ = hitls_tls::handshake::codec12::decode_server_key_exchange_ecdhe_psk(body); }
        18 => { let _ = hitls_tls::handshake::codec12::decode_server_key_exchange_dhe_anon(body); }
        19 => { let _ = hitls_tls::handshake::codec12::decode_server_key_exchange_ecdhe_anon(body); }
        _ => {}
    }
});
