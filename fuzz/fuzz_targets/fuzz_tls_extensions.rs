#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Use first byte to dispatch across all 34 extension parsers
    let body = if data.len() > 1 { &data[1..] } else { &[] };
    match data[0] % 34 {
        0 => { let _ = hitls_tls::handshake::extensions_codec::parse_key_share_ch(body); }
        1 => { let _ = hitls_tls::handshake::extensions_codec::parse_key_share_sh(body); }
        2 => { let _ = hitls_tls::handshake::extensions_codec::parse_key_share_hrr(body); }
        3 => { let _ = hitls_tls::handshake::extensions_codec::parse_signature_algorithms_ch(body); }
        4 => { let _ = hitls_tls::handshake::extensions_codec::parse_signature_algorithms_cert(body); }
        5 => { let _ = hitls_tls::handshake::extensions_codec::parse_alpn_ch(body); }
        6 => { let _ = hitls_tls::handshake::extensions_codec::parse_alpn_sh(body); }
        7 => { let _ = hitls_tls::handshake::extensions_codec::parse_server_name(body); }
        8 => { let _ = hitls_tls::handshake::extensions_codec::parse_pre_shared_key_ch(body); }
        9 => { let _ = hitls_tls::handshake::extensions_codec::parse_pre_shared_key_sh(body); }
        10 => { let _ = hitls_tls::handshake::extensions_codec::parse_supported_versions_ch(body); }
        11 => { let _ = hitls_tls::handshake::extensions_codec::parse_supported_versions_sh(body); }
        12 => { let _ = hitls_tls::handshake::extensions_codec::parse_supported_groups_ch(body); }
        13 => { let _ = hitls_tls::handshake::extensions_codec::parse_psk_key_exchange_modes(body); }
        14 => { let _ = hitls_tls::handshake::extensions_codec::parse_cookie(body); }
        15 => { let _ = hitls_tls::handshake::extensions_codec::parse_heartbeat(body); }
        16 => { let _ = hitls_tls::handshake::extensions_codec::parse_trusted_ca_keys(body); }
        17 => { let _ = hitls_tls::handshake::extensions_codec::parse_use_srtp(body); }
        18 => { let _ = hitls_tls::handshake::extensions_codec::parse_compress_certificate(body); }
        19 => { let _ = hitls_tls::handshake::extensions_codec::parse_extensions(body); }
        20 => { let _ = hitls_tls::handshake::extensions_codec::parse_ec_point_formats(body); }
        21 => { let _ = hitls_tls::handshake::extensions_codec::parse_renegotiation_info(body); }
        22 => { let _ = hitls_tls::handshake::extensions_codec::parse_extended_master_secret(body); }
        23 => { let _ = hitls_tls::handshake::extensions_codec::parse_encrypt_then_mac(body); }
        24 => { let _ = hitls_tls::handshake::extensions_codec::parse_session_ticket_ch(body); }
        25 => { let _ = hitls_tls::handshake::extensions_codec::parse_session_ticket_sh(body); }
        26 => { let _ = hitls_tls::handshake::extensions_codec::parse_record_size_limit(body); }
        27 => { let _ = hitls_tls::handshake::extensions_codec::parse_status_request_ch(body); }
        28 => { let _ = hitls_tls::handshake::extensions_codec::parse_status_request_cert_entry(body); }
        29 => { let _ = hitls_tls::handshake::extensions_codec::parse_max_fragment_length(body); }
        30 => { let _ = hitls_tls::handshake::extensions_codec::parse_certificate_authorities(body); }
        31 => { let _ = hitls_tls::handshake::extensions_codec::parse_padding(body); }
        32 => { let _ = hitls_tls::handshake::extensions_codec::parse_oid_filters(body); }
        33 => { let _ = hitls_tls::handshake::extensions_codec::parse_status_request_v2(body); }
        _ => {}
    }
});
