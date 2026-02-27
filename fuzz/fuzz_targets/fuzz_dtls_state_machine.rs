#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    // Use first byte to select which DTLS codec path to exercise.
    // This simulates injecting arbitrary DTLS record sequences into
    // the parsing layer that feeds the DTLS state machine.
    let selector = data[0];
    let body = &data[1..];

    match selector % 8 {
        // 0: Parse a raw DTLS record (13-byte header + fragment)
        0 => {
            let _ = hitls_tls::record::dtls::parse_dtls_record(body);
        }

        // 1: Parse a DTLS handshake header (12-byte header + body)
        1 => {
            let _ = hitls_tls::handshake::codec_dtls::parse_dtls_handshake_header(body);
        }

        // 2: Decode a DTLS ClientHello (with cookie field)
        2 => {
            let _ = hitls_tls::handshake::codec_dtls::decode_dtls_client_hello(body);
        }

        // 3: Decode a HelloVerifyRequest
        3 => {
            let _ = hitls_tls::handshake::codec_dtls::decode_hello_verify_request(body);
        }

        // 4: TLS→DTLS handshake conversion
        4 => {
            let msg_seq = if body.len() >= 2 {
                u16::from_be_bytes([body[0], body[1]])
            } else {
                0
            };
            let tls_msg = if body.len() > 2 { &body[2..] } else { &[] };
            let _ = hitls_tls::handshake::codec_dtls::tls_to_dtls_handshake(tls_msg, msg_seq);
        }

        // 5: DTLS→TLS handshake conversion (for transcript hash)
        5 => {
            let _ = hitls_tls::handshake::codec_dtls::dtls_to_tls_handshake(body);
        }

        // 6: Parse multiple DTLS records from a stream (simulates datagram sequence)
        6 => {
            let mut offset = 0;
            for _ in 0..16 {
                if offset >= body.len() {
                    break;
                }
                match hitls_tls::record::dtls::parse_dtls_record(&body[offset..]) {
                    Ok((_, consumed)) => {
                        offset += consumed;
                    }
                    Err(_) => break,
                }
            }
        }

        // 7: Parse DTLS record then handshake header from fragment
        7 => {
            if let Ok((record, _)) = hitls_tls::record::dtls::parse_dtls_record(body) {
                let _ =
                    hitls_tls::handshake::codec_dtls::parse_dtls_handshake_header(&record.fragment);
            }
        }

        _ => {}
    }
});
