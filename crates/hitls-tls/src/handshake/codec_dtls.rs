//! DTLS 1.2 handshake message codec (RFC 6347 §4.2).
//!
//! DTLS handshake header is 12 bytes:
//! `type(1) || length(3) || message_seq(2) || fragment_offset(3) || fragment_length(3)`
//!
//! This module also provides HelloVerifyRequest and DTLS-specific ClientHello
//! (with cookie field).

use crate::handshake::codec::{encode_extensions, parse_extensions_list, ClientHello};
use crate::handshake::HandshakeType;
use crate::record::dtls::DTLS12_VERSION;
use crate::CipherSuite;
use hitls_types::TlsError;

/// DTLS handshake header length: 12 bytes.
pub const DTLS_HS_HEADER_LEN: usize = 12;

/// A parsed DTLS handshake header.
#[derive(Debug, Clone)]
pub struct DtlsHandshakeHeader {
    pub msg_type: HandshakeType,
    /// Total message length (24-bit).
    pub length: u32,
    /// Message sequence number.
    pub message_seq: u16,
    /// Fragment offset (24-bit).
    pub fragment_offset: u32,
    /// Fragment length (24-bit).
    pub fragment_length: u32,
}

fn read_u24(data: &[u8]) -> u32 {
    ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32)
}

fn write_u24(buf: &mut Vec<u8>, val: u32) {
    buf.push((val >> 16) as u8);
    buf.push((val >> 8) as u8);
    buf.push(val as u8);
}

fn match_handshake_type(b: u8) -> Result<HandshakeType, TlsError> {
    match b {
        1 => Ok(HandshakeType::ClientHello),
        2 => Ok(HandshakeType::ServerHello),
        3 => Ok(HandshakeType::HelloVerifyRequest),
        4 => Ok(HandshakeType::NewSessionTicket),
        11 => Ok(HandshakeType::Certificate),
        12 => Ok(HandshakeType::ServerKeyExchange),
        13 => Ok(HandshakeType::CertificateRequest),
        14 => Ok(HandshakeType::ServerHelloDone),
        15 => Ok(HandshakeType::CertificateVerify),
        16 => Ok(HandshakeType::ClientKeyExchange),
        20 => Ok(HandshakeType::Finished),
        _ => Err(TlsError::HandshakeFailed(format!(
            "unknown handshake type: {b}"
        ))),
    }
}

/// Parse a DTLS handshake header (12 bytes).
///
/// Returns `(header, body_slice, total_bytes_consumed)`.
pub fn parse_dtls_handshake_header(
    data: &[u8],
) -> Result<(DtlsHandshakeHeader, &[u8], usize), TlsError> {
    if data.len() < DTLS_HS_HEADER_LEN {
        return Err(TlsError::HandshakeFailed(
            "DTLS handshake header too short".into(),
        ));
    }

    let msg_type = match_handshake_type(data[0])?;
    let length = read_u24(&data[1..4]);
    let message_seq = u16::from_be_bytes([data[4], data[5]]);
    let fragment_offset = read_u24(&data[6..9]);
    let fragment_length = read_u24(&data[9..12]);

    let total = DTLS_HS_HEADER_LEN + fragment_length as usize;
    if data.len() < total {
        return Err(TlsError::HandshakeFailed(
            "DTLS handshake fragment body truncated".into(),
        ));
    }

    let body = &data[DTLS_HS_HEADER_LEN..total];
    let header = DtlsHandshakeHeader {
        msg_type,
        length,
        message_seq,
        fragment_offset,
        fragment_length,
    };

    Ok((header, body, total))
}

/// Wrap a handshake body with the 12-byte DTLS header.
pub fn wrap_dtls_handshake(
    msg_type: HandshakeType,
    body: &[u8],
    message_seq: u16,
    fragment_offset: u32,
    fragment_length: u32,
) -> Vec<u8> {
    let total_length = body.len() as u32;
    let mut out = Vec::with_capacity(DTLS_HS_HEADER_LEN + body.len());
    out.push(msg_type as u8);
    // For non-fragmented messages, length == fragment_length == body.len()
    // For fragmented messages, length is the total message length
    write_u24(&mut out, total_length);
    out.extend_from_slice(&message_seq.to_be_bytes());
    write_u24(&mut out, fragment_offset);
    write_u24(&mut out, fragment_length);
    out.extend_from_slice(body);
    out
}

/// Wrap a complete (non-fragmented) handshake body with the DTLS header.
///
/// Sets `fragment_offset = 0` and `fragment_length = length`.
pub fn wrap_dtls_handshake_full(msg_type: HandshakeType, body: &[u8], message_seq: u16) -> Vec<u8> {
    let len = body.len() as u32;
    let mut out = Vec::with_capacity(DTLS_HS_HEADER_LEN + body.len());
    out.push(msg_type as u8);
    write_u24(&mut out, len);
    out.extend_from_slice(&message_seq.to_be_bytes());
    write_u24(&mut out, 0); // fragment_offset = 0
    write_u24(&mut out, len); // fragment_length = total length
    out.extend_from_slice(body);
    out
}

/// Convert a TLS handshake message (4-byte header) to DTLS format (12-byte header).
///
/// Used for non-fragmented messages: `fragment_offset=0, fragment_length=length`.
pub fn tls_to_dtls_handshake(tls_msg: &[u8], message_seq: u16) -> Result<Vec<u8>, TlsError> {
    if tls_msg.len() < 4 {
        return Err(TlsError::HandshakeFailed(
            "TLS handshake message too short for conversion".into(),
        ));
    }
    let msg_type = tls_msg[0];
    let length = read_u24(&tls_msg[1..4]);
    let body = &tls_msg[4..];
    if body.len() != length as usize {
        return Err(TlsError::HandshakeFailed(
            "TLS handshake message length mismatch".into(),
        ));
    }

    let mut out = Vec::with_capacity(DTLS_HS_HEADER_LEN + body.len());
    out.push(msg_type);
    write_u24(&mut out, length);
    out.extend_from_slice(&message_seq.to_be_bytes());
    write_u24(&mut out, 0); // fragment_offset = 0
    write_u24(&mut out, length); // fragment_length = total
    out.extend_from_slice(body);
    Ok(out)
}

/// Convert a DTLS handshake message (12-byte header) to TLS format (4-byte header).
///
/// Used before feeding into `TranscriptHash` (RFC 6347 §4.2.6):
/// "For the purposes of the handshake hash, ... the handshake headers are
///  serialized with the normal TLS handshake header format."
///
/// This only works for complete (non-fragmented or reassembled) messages.
pub fn dtls_to_tls_handshake(dtls_msg: &[u8]) -> Result<Vec<u8>, TlsError> {
    if dtls_msg.len() < DTLS_HS_HEADER_LEN {
        return Err(TlsError::HandshakeFailed(
            "DTLS handshake message too short for conversion".into(),
        ));
    }
    let msg_type = dtls_msg[0];
    let length = read_u24(&dtls_msg[1..4]);
    let body = &dtls_msg[DTLS_HS_HEADER_LEN..];
    if body.len() != length as usize {
        return Err(TlsError::HandshakeFailed(
            "DTLS message body length mismatch for transcript conversion".into(),
        ));
    }

    let mut out = Vec::with_capacity(4 + body.len());
    out.push(msg_type);
    write_u24(&mut out, length);
    out.extend_from_slice(body);
    Ok(out)
}

// ---------------------------------------------------------------------------
// HelloVerifyRequest (RFC 6347 §4.2.1)
// ---------------------------------------------------------------------------

/// HelloVerifyRequest message.
#[derive(Debug, Clone)]
pub struct HelloVerifyRequest {
    /// Server version (0xFEFD for DTLS 1.2).
    pub server_version: u16,
    /// Cookie (0..255 bytes).
    pub cookie: Vec<u8>,
}

/// Encode a HelloVerifyRequest body (without handshake header).
pub fn encode_hello_verify_request(hvr: &HelloVerifyRequest) -> Vec<u8> {
    let mut body = Vec::with_capacity(3 + hvr.cookie.len());
    body.extend_from_slice(&hvr.server_version.to_be_bytes());
    body.push(hvr.cookie.len() as u8);
    body.extend_from_slice(&hvr.cookie);
    body
}

/// Decode a HelloVerifyRequest from body bytes.
pub fn decode_hello_verify_request(data: &[u8]) -> Result<HelloVerifyRequest, TlsError> {
    if data.len() < 3 {
        return Err(TlsError::HandshakeFailed(
            "HelloVerifyRequest too short".into(),
        ));
    }
    let server_version = u16::from_be_bytes([data[0], data[1]]);
    let cookie_len = data[2] as usize;
    if data.len() < 3 + cookie_len {
        return Err(TlsError::HandshakeFailed(
            "HelloVerifyRequest cookie truncated".into(),
        ));
    }
    let cookie = data[3..3 + cookie_len].to_vec();
    Ok(HelloVerifyRequest {
        server_version,
        cookie,
    })
}

// ---------------------------------------------------------------------------
// DTLS ClientHello (with cookie field)
// ---------------------------------------------------------------------------

/// Encode a DTLS ClientHello as a complete handshake message body (without header).
///
/// DTLS ClientHello has an extra cookie field between session_id and cipher_suites:
/// `version(2) || random(32) || session_id(1+n) || cookie(1+n) || cipher_suites(2+2n) ||
///  compression(1+n) || extensions(2+n)`
pub fn encode_dtls_client_hello_body(ch: &ClientHello, cookie: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(256);

    // legacy_version = 0xFEFD (DTLS 1.2)
    body.extend_from_slice(&DTLS12_VERSION.to_be_bytes());

    // random
    body.extend_from_slice(&ch.random);

    // legacy_session_id
    body.push(ch.legacy_session_id.len() as u8);
    body.extend_from_slice(&ch.legacy_session_id);

    // cookie (DTLS-specific)
    body.push(cookie.len() as u8);
    body.extend_from_slice(cookie);

    // cipher_suites
    let suites_len = (ch.cipher_suites.len() * 2) as u16;
    body.extend_from_slice(&suites_len.to_be_bytes());
    for s in &ch.cipher_suites {
        body.extend_from_slice(&s.0.to_be_bytes());
    }

    // legacy_compression_methods = {0}
    body.push(1);
    body.push(0);

    // extensions
    let ext_data = encode_extensions(&ch.extensions);
    body.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_data);

    body
}

/// Decode a DTLS ClientHello body (has extra cookie field).
///
/// Returns `(ClientHello, cookie)`.
pub fn decode_dtls_client_hello(data: &[u8]) -> Result<(ClientHello, Vec<u8>), TlsError> {
    let err = |msg: &str| TlsError::HandshakeFailed(format!("DTLS ClientHello: {msg}"));
    let mut pos = 0;

    // version (2)
    if data.len() < pos + 2 {
        return Err(err("too short for version"));
    }
    pos += 2; // skip version

    // random (32)
    if data.len() < pos + 32 {
        return Err(err("too short for random"));
    }
    let mut random = [0u8; 32];
    random.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    // session_id
    if data.len() < pos + 1 {
        return Err(err("too short for session_id length"));
    }
    let sid_len = data[pos] as usize;
    pos += 1;
    if data.len() < pos + sid_len {
        return Err(err("too short for session_id"));
    }
    let legacy_session_id = data[pos..pos + sid_len].to_vec();
    pos += sid_len;

    // cookie (DTLS-specific)
    if data.len() < pos + 1 {
        return Err(err("too short for cookie length"));
    }
    let cookie_len = data[pos] as usize;
    pos += 1;
    if data.len() < pos + cookie_len {
        return Err(err("too short for cookie"));
    }
    let cookie = data[pos..pos + cookie_len].to_vec();
    pos += cookie_len;

    // cipher_suites
    if data.len() < pos + 2 {
        return Err(err("too short for cipher_suites length"));
    }
    let suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if suites_len % 2 != 0 || data.len() < pos + suites_len {
        return Err(err("invalid cipher_suites"));
    }
    let mut cipher_suites = Vec::with_capacity(suites_len / 2);
    for i in (0..suites_len).step_by(2) {
        let suite = u16::from_be_bytes([data[pos + i], data[pos + i + 1]]);
        cipher_suites.push(CipherSuite(suite));
    }
    pos += suites_len;

    // compression_methods
    if data.len() < pos + 1 {
        return Err(err("too short for compression methods"));
    }
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;

    // extensions (optional)
    let mut extensions = Vec::new();
    if pos + 2 <= data.len() {
        let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if data.len() >= pos + ext_len {
            extensions = parse_extensions_list(&data[pos..pos + ext_len])?;
        }
    }

    let ch = ClientHello {
        random,
        legacy_session_id,
        cipher_suites,
        extensions,
    };

    Ok((ch, cookie))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dtls_handshake_header_valid() {
        // Build a 12-byte header + 5-byte body
        let mut data = vec![
            1, // ClientHello
            0x00, 0x00, 0x05, // length = 5
            0x00, 0x01, // message_seq = 1
            0x00, 0x00, 0x00, // fragment_offset = 0
            0x00, 0x00, 0x05, // fragment_length = 5
        ];
        data.extend_from_slice(b"hello");

        let (header, body, consumed) = parse_dtls_handshake_header(&data).unwrap();
        assert_eq!(header.msg_type, HandshakeType::ClientHello);
        assert_eq!(header.length, 5);
        assert_eq!(header.message_seq, 1);
        assert_eq!(header.fragment_offset, 0);
        assert_eq!(header.fragment_length, 5);
        assert_eq!(body, b"hello");
        assert_eq!(consumed, 17);
    }

    #[test]
    fn test_parse_dtls_handshake_header_too_short() {
        let data = vec![1, 0x00, 0x00]; // only 3 bytes
        assert!(parse_dtls_handshake_header(&data).is_err());
    }

    #[test]
    fn test_wrap_dtls_handshake_roundtrip() {
        let body = b"test body data";
        let msg = wrap_dtls_handshake_full(HandshakeType::ServerHello, body, 3);

        let (header, parsed_body, consumed) = parse_dtls_handshake_header(&msg).unwrap();
        assert_eq!(header.msg_type, HandshakeType::ServerHello);
        assert_eq!(header.length, body.len() as u32);
        assert_eq!(header.message_seq, 3);
        assert_eq!(header.fragment_offset, 0);
        assert_eq!(header.fragment_length, body.len() as u32);
        assert_eq!(parsed_body, body);
        assert_eq!(consumed, msg.len());
    }

    #[test]
    fn test_tls_to_dtls_conversion() {
        // Build a TLS handshake message (4-byte header)
        let body = b"SH body";
        let mut tls_msg = vec![2]; // ServerHello
        write_u24(&mut tls_msg, body.len() as u32);
        tls_msg.extend_from_slice(body);

        let dtls_msg = tls_to_dtls_handshake(&tls_msg, 5).unwrap();
        assert_eq!(dtls_msg.len(), DTLS_HS_HEADER_LEN + body.len());

        let (header, parsed_body, _) = parse_dtls_handshake_header(&dtls_msg).unwrap();
        assert_eq!(header.msg_type, HandshakeType::ServerHello);
        assert_eq!(header.message_seq, 5);
        assert_eq!(header.fragment_offset, 0);
        assert_eq!(header.fragment_length, body.len() as u32);
        assert_eq!(parsed_body, body);
    }

    #[test]
    fn test_dtls_to_tls_conversion_for_transcript() {
        let body = b"certificate data";
        let dtls_msg = wrap_dtls_handshake_full(HandshakeType::Certificate, body, 2);

        let tls_msg = dtls_to_tls_handshake(&dtls_msg).unwrap();
        assert_eq!(tls_msg.len(), 4 + body.len());
        assert_eq!(tls_msg[0], HandshakeType::Certificate as u8);
        let length = read_u24(&tls_msg[1..4]);
        assert_eq!(length, body.len() as u32);
        assert_eq!(&tls_msg[4..], body);
    }

    #[test]
    fn test_encode_decode_hello_verify_request() {
        let hvr = HelloVerifyRequest {
            server_version: DTLS12_VERSION,
            cookie: vec![0x01, 0x02, 0x03, 0x04, 0x05],
        };

        let encoded = encode_hello_verify_request(&hvr);
        let decoded = decode_hello_verify_request(&encoded).unwrap();
        assert_eq!(decoded.server_version, DTLS12_VERSION);
        assert_eq!(decoded.cookie, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn test_encode_decode_dtls_client_hello_with_cookie() {
        let ch = ClientHello {
            random: [0x42; 32],
            legacy_session_id: vec![],
            cipher_suites: vec![
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            ],
            extensions: vec![],
        };
        let cookie = vec![0xAA, 0xBB, 0xCC];

        let body = encode_dtls_client_hello_body(&ch, &cookie);
        let (decoded_ch, decoded_cookie) = decode_dtls_client_hello(&body).unwrap();

        assert_eq!(decoded_ch.random, [0x42; 32]);
        assert_eq!(decoded_ch.cipher_suites.len(), 2);
        assert_eq!(
            decoded_ch.cipher_suites[0],
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        );
        assert_eq!(decoded_cookie, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_decode_dtls_client_hello_empty_cookie() {
        let ch = ClientHello {
            random: [0x11; 32],
            legacy_session_id: vec![],
            cipher_suites: vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            extensions: vec![],
        };
        let body = encode_dtls_client_hello_body(&ch, &[]);
        let (decoded_ch, decoded_cookie) = decode_dtls_client_hello(&body).unwrap();

        assert_eq!(decoded_ch.random, [0x11; 32]);
        assert!(decoded_cookie.is_empty());
    }
}
