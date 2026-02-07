//! TLS 1.3 handshake message encoding/decoding (RFC 8446 §4).

use crate::crypt::SignatureScheme;
use crate::extensions::{Extension, ExtensionType};
use crate::CipherSuite;
use hitls_types::TlsError;

use super::HandshakeType;

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// ClientHello message.
#[derive(Debug, Clone)]
pub struct ClientHello {
    pub random: [u8; 32],
    pub legacy_session_id: Vec<u8>,
    pub cipher_suites: Vec<CipherSuite>,
    pub extensions: Vec<Extension>,
}

/// ServerHello message.
#[derive(Debug, Clone)]
pub struct ServerHello {
    pub random: [u8; 32],
    pub legacy_session_id: Vec<u8>,
    pub cipher_suite: CipherSuite,
    pub extensions: Vec<Extension>,
}

/// EncryptedExtensions message.
#[derive(Debug, Clone)]
pub struct EncryptedExtensions {
    pub extensions: Vec<Extension>,
}

/// A single certificate entry in a Certificate message.
#[derive(Debug, Clone)]
pub struct CertificateEntry {
    pub cert_data: Vec<u8>,
    pub extensions: Vec<Extension>,
}

/// Certificate message.
#[derive(Debug, Clone)]
pub struct CertificateMsg {
    pub certificate_request_context: Vec<u8>,
    pub certificate_list: Vec<CertificateEntry>,
}

/// CertificateVerify message.
#[derive(Debug, Clone)]
pub struct CertificateVerifyMsg {
    pub algorithm: SignatureScheme,
    pub signature: Vec<u8>,
}

/// Finished message.
#[derive(Debug, Clone)]
pub struct FinishedMsg {
    pub verify_data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Handshake header
// ---------------------------------------------------------------------------

/// Parse a handshake header: msg_type(1) || length(3).
/// Returns (HandshakeType, body_slice, total_bytes_consumed).
pub fn parse_handshake_header(data: &[u8]) -> Result<(HandshakeType, &[u8], usize), TlsError> {
    if data.len() < 4 {
        return Err(TlsError::HandshakeFailed(
            "handshake header too short".into(),
        ));
    }
    let msg_type = match data[0] {
        1 => HandshakeType::ClientHello,
        2 => HandshakeType::ServerHello,
        4 => HandshakeType::NewSessionTicket,
        5 => HandshakeType::EndOfEarlyData,
        8 => HandshakeType::EncryptedExtensions,
        11 => HandshakeType::Certificate,
        13 => HandshakeType::CertificateRequest,
        15 => HandshakeType::CertificateVerify,
        20 => HandshakeType::Finished,
        24 => HandshakeType::KeyUpdate,
        254 => HandshakeType::MessageHash,
        _ => {
            return Err(TlsError::HandshakeFailed(format!(
                "unknown handshake type: {}",
                data[0]
            )))
        }
    };
    let length = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | (data[3] as usize);
    let total = 4 + length;
    if data.len() < total {
        return Err(TlsError::HandshakeFailed(
            "handshake message body truncated".into(),
        ));
    }
    Ok((msg_type, &data[4..total], total))
}

/// Wrap a handshake body with the 4-byte header.
fn wrap_handshake(msg_type: HandshakeType, body: &[u8]) -> Vec<u8> {
    let len = body.len();
    let mut out = Vec::with_capacity(4 + len);
    out.push(msg_type as u8);
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.extend_from_slice(body);
    out
}

// ---------------------------------------------------------------------------
// Encode ClientHello
// ---------------------------------------------------------------------------

/// Encode a ClientHello as a complete handshake message (header + body).
pub fn encode_client_hello(ch: &ClientHello) -> Vec<u8> {
    let mut body = Vec::with_capacity(256);

    // legacy_version = 0x0303 (TLS 1.2)
    body.extend_from_slice(&0x0303u16.to_be_bytes());

    // random
    body.extend_from_slice(&ch.random);

    // legacy_session_id
    body.push(ch.legacy_session_id.len() as u8);
    body.extend_from_slice(&ch.legacy_session_id);

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

    wrap_handshake(HandshakeType::ClientHello, &body)
}

// ---------------------------------------------------------------------------
// Decode ServerHello
// ---------------------------------------------------------------------------

/// Decode a ServerHello from handshake body bytes (after header).
pub fn decode_server_hello(data: &[u8]) -> Result<ServerHello, TlsError> {
    let mut pos = 0;
    let err = |msg: &str| TlsError::HandshakeFailed(format!("ServerHello: {msg}"));

    // legacy_version (2)
    if data.len() < pos + 2 {
        return Err(err("too short for version"));
    }
    let _version = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // random (32)
    if data.len() < pos + 32 {
        return Err(err("too short for random"));
    }
    let mut random = [0u8; 32];
    random.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    // legacy_session_id_echo
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

    // cipher_suite (2)
    if data.len() < pos + 2 {
        return Err(err("too short for cipher_suite"));
    }
    let cipher_suite = CipherSuite(u16::from_be_bytes([data[pos], data[pos + 1]]));
    pos += 2;

    // legacy_compression_method (1)
    if data.len() < pos + 1 {
        return Err(err("too short for compression"));
    }
    pos += 1; // must be 0

    // extensions
    let extensions = if data.len() > pos {
        parse_extensions_from(&data[pos..])?
    } else {
        vec![]
    };

    Ok(ServerHello {
        random,
        legacy_session_id,
        cipher_suite,
        extensions,
    })
}

// ---------------------------------------------------------------------------
// Decode EncryptedExtensions
// ---------------------------------------------------------------------------

/// Decode an EncryptedExtensions message from handshake body bytes.
pub fn decode_encrypted_extensions(data: &[u8]) -> Result<EncryptedExtensions, TlsError> {
    let extensions = parse_extensions_from(data)?;
    Ok(EncryptedExtensions { extensions })
}

// ---------------------------------------------------------------------------
// Decode Certificate
// ---------------------------------------------------------------------------

/// Decode a Certificate message from handshake body bytes.
pub fn decode_certificate(data: &[u8]) -> Result<CertificateMsg, TlsError> {
    let mut pos = 0;
    let err = |msg: &str| TlsError::HandshakeFailed(format!("Certificate: {msg}"));

    // certificate_request_context (length-prefixed, 1 byte length)
    if data.is_empty() {
        return Err(err("empty"));
    }
    let ctx_len = data[pos] as usize;
    pos += 1;
    if data.len() < pos + ctx_len {
        return Err(err("truncated context"));
    }
    let certificate_request_context = data[pos..pos + ctx_len].to_vec();
    pos += ctx_len;

    // certificate_list (3-byte length)
    if data.len() < pos + 3 {
        return Err(err("truncated list length"));
    }
    let list_len = read_u24(&data[pos..]) as usize;
    pos += 3;
    if data.len() < pos + list_len {
        return Err(err("truncated list"));
    }
    let list_end = pos + list_len;

    let mut certificate_list = Vec::new();
    while pos < list_end {
        // cert_data (3-byte length)
        if list_end - pos < 3 {
            return Err(err("truncated cert entry length"));
        }
        let cert_len = read_u24(&data[pos..]) as usize;
        pos += 3;
        if list_end - pos < cert_len {
            return Err(err("truncated cert data"));
        }
        let cert_data = data[pos..pos + cert_len].to_vec();
        pos += cert_len;

        // extensions (2-byte length)
        if list_end - pos < 2 {
            return Err(err("truncated cert extensions length"));
        }
        let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if list_end - pos < ext_len {
            return Err(err("truncated cert extensions"));
        }
        let extensions = if ext_len > 0 {
            parse_extensions_list(&data[pos..pos + ext_len])?
        } else {
            vec![]
        };
        pos += ext_len;

        certificate_list.push(CertificateEntry {
            cert_data,
            extensions,
        });
    }

    Ok(CertificateMsg {
        certificate_request_context,
        certificate_list,
    })
}

// ---------------------------------------------------------------------------
// Decode CertificateVerify
// ---------------------------------------------------------------------------

/// Decode a CertificateVerify message from handshake body bytes.
pub fn decode_certificate_verify(data: &[u8]) -> Result<CertificateVerifyMsg, TlsError> {
    let err = |msg: &str| TlsError::HandshakeFailed(format!("CertificateVerify: {msg}"));

    if data.len() < 4 {
        return Err(err("too short"));
    }

    let algorithm = SignatureScheme(u16::from_be_bytes([data[0], data[1]]));
    let sig_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 4 + sig_len {
        return Err(err("truncated signature"));
    }
    let signature = data[4..4 + sig_len].to_vec();

    Ok(CertificateVerifyMsg {
        algorithm,
        signature,
    })
}

// ---------------------------------------------------------------------------
// Decode Finished
// ---------------------------------------------------------------------------

/// Decode a Finished message from handshake body bytes.
pub fn decode_finished(data: &[u8], hash_len: usize) -> Result<FinishedMsg, TlsError> {
    if data.len() < hash_len {
        return Err(TlsError::HandshakeFailed(
            "Finished: verify_data too short".into(),
        ));
    }
    Ok(FinishedMsg {
        verify_data: data[..hash_len].to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Encode Finished
// ---------------------------------------------------------------------------

/// Encode a Finished message as a complete handshake message.
pub fn encode_finished(verify_data: &[u8]) -> Vec<u8> {
    wrap_handshake(HandshakeType::Finished, verify_data)
}

// ---------------------------------------------------------------------------
// Extension encoding/parsing helpers
// ---------------------------------------------------------------------------

/// Encode a list of extensions to bytes.
fn encode_extensions(exts: &[Extension]) -> Vec<u8> {
    let mut buf = Vec::new();
    for ext in exts {
        buf.extend_from_slice(&ext.extension_type.0.to_be_bytes());
        buf.extend_from_slice(&(ext.data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&ext.data);
    }
    buf
}

/// Parse extensions from data that starts with a 2-byte length prefix.
fn parse_extensions_from(data: &[u8]) -> Result<Vec<Extension>, TlsError> {
    if data.len() < 2 {
        return Ok(vec![]);
    }
    let ext_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + ext_len {
        return Err(TlsError::HandshakeFailed(
            "extensions data truncated".into(),
        ));
    }
    parse_extensions_list(&data[2..2 + ext_len])
}

/// Parse a raw extension list (no length prefix).
fn parse_extensions_list(data: &[u8]) -> Result<Vec<Extension>, TlsError> {
    let mut exts = Vec::new();
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let ext_type = ExtensionType(u16::from_be_bytes([data[pos], data[pos + 1]]));
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if data.len() < pos + ext_len {
            return Err(TlsError::HandshakeFailed("extension data truncated".into()));
        }
        exts.push(Extension {
            extension_type: ext_type,
            data: data[pos..pos + ext_len].to_vec(),
        });
        pos += ext_len;
    }
    Ok(exts)
}

/// Read a 3-byte big-endian integer.
fn read_u24(data: &[u8]) -> u32 {
    ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypt::SignatureScheme;
    use crate::extensions::ExtensionType;

    #[test]
    fn test_encode_decode_client_hello() {
        let ch = ClientHello {
            random: [0xAA; 32],
            legacy_session_id: vec![0x01, 0x02, 0x03],
            cipher_suites: vec![
                CipherSuite::TLS_AES_128_GCM_SHA256,
                CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
            ],
            extensions: vec![Extension {
                extension_type: ExtensionType::SUPPORTED_VERSIONS,
                data: vec![0x03, 0x02, 0x03, 0x04],
            }],
        };

        let encoded = encode_client_hello(&ch);

        // Parse back the header
        let (msg_type, body, total) = parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::ClientHello);
        assert_eq!(total, encoded.len());

        // Verify body structure
        assert_eq!(&body[0..2], &[0x03, 0x03]); // legacy_version
        assert_eq!(&body[2..34], &[0xAA; 32]); // random
        assert_eq!(body[34], 3); // session_id length
        assert_eq!(&body[35..38], &[0x01, 0x02, 0x03]);
        // cipher_suites_len = 4
        assert_eq!(&body[38..40], &[0x00, 0x04]);
        assert_eq!(&body[40..42], &0x1301u16.to_be_bytes()); // AES_128_GCM
        assert_eq!(&body[42..44], &0x1303u16.to_be_bytes()); // CHACHA20
                                                             // compression methods
        assert_eq!(&body[44..46], &[0x01, 0x00]);
    }

    #[test]
    fn test_decode_server_hello() {
        // Construct a minimal ServerHello body
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // version
        body.extend_from_slice(&[0xBB; 32]); // random
        body.push(0); // session_id length = 0
        body.extend_from_slice(&0x1301u16.to_be_bytes()); // cipher_suite
        body.push(0); // compression method

        // Extensions: supported_versions (0x002b) with data = 0x0304
        let ext_data = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        body.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_data);

        let sh = decode_server_hello(&body).unwrap();
        assert_eq!(sh.random, [0xBB; 32]);
        assert_eq!(sh.cipher_suite, CipherSuite::TLS_AES_128_GCM_SHA256);
        assert!(sh.legacy_session_id.is_empty());
        assert_eq!(sh.extensions.len(), 1);
        assert_eq!(
            sh.extensions[0].extension_type,
            ExtensionType::SUPPORTED_VERSIONS
        );
        assert_eq!(sh.extensions[0].data, vec![0x03, 0x04]);
    }

    #[test]
    fn test_decode_encrypted_extensions() {
        // Empty extensions
        let data = vec![0x00, 0x00];
        let ee = decode_encrypted_extensions(&data).unwrap();
        assert!(ee.extensions.is_empty());

        // One extension
        let mut data = Vec::new();
        let ext = vec![0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03]; // server_name, 3 bytes
        data.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        data.extend_from_slice(&ext);
        let ee = decode_encrypted_extensions(&data).unwrap();
        assert_eq!(ee.extensions.len(), 1);
        assert_eq!(ee.extensions[0].extension_type, ExtensionType::SERVER_NAME);
    }

    #[test]
    fn test_decode_certificate() {
        // Build a Certificate message body
        let cert_der = vec![0x30, 0x82, 0x01, 0x00]; // fake DER
        let mut body = Vec::new();
        body.push(0); // certificate_request_context length = 0

        // certificate list
        let mut list = Vec::new();
        // cert entry: cert_data (3-byte len) + extensions (2-byte len)
        let cert_len = cert_der.len();
        list.push((cert_len >> 16) as u8);
        list.push((cert_len >> 8) as u8);
        list.push(cert_len as u8);
        list.extend_from_slice(&cert_der);
        list.extend_from_slice(&[0x00, 0x00]); // no extensions

        let list_len = list.len();
        body.push((list_len >> 16) as u8);
        body.push((list_len >> 8) as u8);
        body.push(list_len as u8);
        body.extend_from_slice(&list);

        let cert_msg = decode_certificate(&body).unwrap();
        assert!(cert_msg.certificate_request_context.is_empty());
        assert_eq!(cert_msg.certificate_list.len(), 1);
        assert_eq!(cert_msg.certificate_list[0].cert_data, cert_der);
    }

    #[test]
    fn test_decode_certificate_verify() {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0804u16.to_be_bytes()); // rsa_pss_rsae_sha256
        let sig = vec![0x01; 64];
        body.extend_from_slice(&(sig.len() as u16).to_be_bytes());
        body.extend_from_slice(&sig);

        let cv = decode_certificate_verify(&body).unwrap();
        assert_eq!(cv.algorithm, SignatureScheme::RSA_PSS_RSAE_SHA256);
        assert_eq!(cv.signature.len(), 64);
    }

    #[test]
    fn test_decode_finished() {
        let verify_data = vec![0xAB; 32];
        let fm = decode_finished(&verify_data, 32).unwrap();
        assert_eq!(fm.verify_data, verify_data);

        // Too short
        assert!(decode_finished(&[0x00; 16], 32).is_err());
    }

    #[test]
    fn test_handshake_header_roundtrip() {
        let body = vec![1, 2, 3, 4, 5];
        let msg = wrap_handshake(HandshakeType::Finished, &body);
        let (ty, parsed_body, consumed) = parse_handshake_header(&msg).unwrap();
        assert_eq!(ty, HandshakeType::Finished);
        assert_eq!(parsed_body, &body);
        assert_eq!(consumed, msg.len());
    }
}
