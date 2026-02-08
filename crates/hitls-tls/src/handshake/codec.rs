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

/// SHA-256 hash of "HelloRetryRequest" — magic random value for HRR (RFC 8446 §4.1.3).
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// NewSessionTicket message (RFC 8446 §4.6.1).
#[derive(Debug, Clone)]
pub struct NewSessionTicketMsg {
    /// Ticket lifetime in seconds (max 604800 = 7 days).
    pub ticket_lifetime: u32,
    /// Random value added to the ticket age for obfuscation.
    pub ticket_age_add: u32,
    /// Ticket nonce (for PSK derivation).
    pub ticket_nonce: Vec<u8>,
    /// Opaque ticket value.
    pub ticket: Vec<u8>,
    /// Extensions (e.g., early_data max_size).
    pub extensions: Vec<Extension>,
}

/// CertificateRequest message (RFC 8446 §4.3.2 / §4.6.2).
#[derive(Debug, Clone)]
pub struct CertificateRequestMsg {
    /// certificate_request_context (opaque, 0-255 bytes).
    /// Empty for in-handshake CertReq; random for post-handshake.
    pub certificate_request_context: Vec<u8>,
    /// Extensions (must include signature_algorithms).
    pub extensions: Vec<Extension>,
}

/// Certificate compression algorithm (RFC 8879).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertCompressionAlgorithm(pub u16);

impl CertCompressionAlgorithm {
    pub const ZLIB: Self = Self(1);
    pub const BROTLI: Self = Self(2);
    pub const ZSTD: Self = Self(0x0100);
}

/// CompressedCertificate message (RFC 8879 §4).
#[derive(Debug, Clone)]
pub struct CompressedCertificateMsg {
    pub algorithm: CertCompressionAlgorithm,
    pub uncompressed_length: u32,
    pub compressed_data: Vec<u8>,
}

/// KeyUpdate request type (RFC 8446 §4.6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyUpdateRequest {
    UpdateNotRequested = 0,
    UpdateRequested = 1,
}

/// KeyUpdate message.
#[derive(Debug, Clone)]
pub struct KeyUpdateMsg {
    pub request_update: KeyUpdateRequest,
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
        25 => HandshakeType::CompressedCertificate,
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
pub(crate) fn wrap_handshake(msg_type: HandshakeType, body: &[u8]) -> Vec<u8> {
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
// Encode/Decode KeyUpdate
// ---------------------------------------------------------------------------

/// Encode a KeyUpdate message as a complete handshake message.
pub fn encode_key_update(ku: &KeyUpdateMsg) -> Vec<u8> {
    wrap_handshake(HandshakeType::KeyUpdate, &[ku.request_update as u8])
}

/// Decode a KeyUpdate message from handshake body bytes.
pub fn decode_key_update(data: &[u8]) -> Result<KeyUpdateMsg, TlsError> {
    if data.is_empty() {
        return Err(TlsError::HandshakeFailed("KeyUpdate: empty body".into()));
    }
    let request_update = match data[0] {
        0 => KeyUpdateRequest::UpdateNotRequested,
        1 => KeyUpdateRequest::UpdateRequested,
        v => {
            return Err(TlsError::HandshakeFailed(format!(
                "KeyUpdate: invalid request_update: {v}"
            )))
        }
    };
    Ok(KeyUpdateMsg { request_update })
}

// ---------------------------------------------------------------------------
// Encode/Decode CompressedCertificate (RFC 8879)
// ---------------------------------------------------------------------------

/// Encode a CompressedCertificate message as a complete handshake message.
pub fn encode_compressed_certificate(msg: &CompressedCertificateMsg) -> Vec<u8> {
    let mut body = Vec::with_capacity(5 + msg.compressed_data.len());
    // algorithm (2)
    body.extend_from_slice(&msg.algorithm.0.to_be_bytes());
    // uncompressed_length (3)
    body.push((msg.uncompressed_length >> 16) as u8);
    body.push((msg.uncompressed_length >> 8) as u8);
    body.push(msg.uncompressed_length as u8);
    // compressed_certificate_message (3-byte length + data)
    let len = msg.compressed_data.len();
    body.push((len >> 16) as u8);
    body.push((len >> 8) as u8);
    body.push(len as u8);
    body.extend_from_slice(&msg.compressed_data);
    wrap_handshake(HandshakeType::CompressedCertificate, &body)
}

/// Decode a CompressedCertificate message from handshake body bytes.
pub fn decode_compressed_certificate(data: &[u8]) -> Result<CompressedCertificateMsg, TlsError> {
    let err = |msg: &str| TlsError::HandshakeFailed(format!("CompressedCertificate: {msg}"));

    if data.len() < 8 {
        return Err(err("too short"));
    }

    let algorithm = CertCompressionAlgorithm(u16::from_be_bytes([data[0], data[1]]));
    let uncompressed_length = read_u24(&data[2..]);
    let compressed_len = read_u24(&data[5..]) as usize;

    if data.len() < 8 + compressed_len {
        return Err(err("truncated compressed data"));
    }
    let compressed_data = data[8..8 + compressed_len].to_vec();

    Ok(CompressedCertificateMsg {
        algorithm,
        uncompressed_length,
        compressed_data,
    })
}

/// Compress a Certificate message body using zlib.
#[cfg(feature = "cert-compression")]
pub fn compress_certificate_body(cert_body: &[u8]) -> Result<Vec<u8>, TlsError> {
    use flate2::read::ZlibEncoder;
    use flate2::Compression;
    use std::io::Read;

    let mut encoder = ZlibEncoder::new(cert_body, Compression::default());
    let mut compressed = Vec::new();
    encoder
        .read_to_end(&mut compressed)
        .map_err(|e| TlsError::HandshakeFailed(format!("zlib compress error: {e}")))?;
    Ok(compressed)
}

/// Decompress a CompressedCertificate body back to Certificate message body.
#[cfg(feature = "cert-compression")]
pub fn decompress_certificate_body(
    algorithm: CertCompressionAlgorithm,
    compressed: &[u8],
    uncompressed_length: u32,
) -> Result<Vec<u8>, TlsError> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    if algorithm != CertCompressionAlgorithm::ZLIB {
        return Err(TlsError::HandshakeFailed(format!(
            "unsupported cert compression algorithm: {}",
            algorithm.0
        )));
    }

    // Cap decompressed size at 16 MiB to prevent decompression bombs
    const MAX_DECOMPRESSED: u32 = 16 * 1024 * 1024;
    if uncompressed_length > MAX_DECOMPRESSED {
        return Err(TlsError::HandshakeFailed(
            "certificate uncompressed_length too large".into(),
        ));
    }

    let mut decoder = ZlibDecoder::new(compressed);
    let mut decompressed = Vec::with_capacity(uncompressed_length as usize);
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| TlsError::HandshakeFailed(format!("zlib decompress error: {e}")))?;

    if decompressed.len() != uncompressed_length as usize {
        return Err(TlsError::HandshakeFailed(format!(
            "certificate decompressed length mismatch: expected {}, got {}",
            uncompressed_length,
            decompressed.len()
        )));
    }

    Ok(decompressed)
}

// ---------------------------------------------------------------------------
// Encode/Decode NewSessionTicket
// ---------------------------------------------------------------------------

/// Encode a NewSessionTicket message as a complete handshake message.
pub fn encode_new_session_ticket(nst: &NewSessionTicketMsg) -> Vec<u8> {
    let mut body = Vec::with_capacity(32 + nst.ticket_nonce.len() + nst.ticket.len());

    // ticket_lifetime (4)
    body.extend_from_slice(&nst.ticket_lifetime.to_be_bytes());
    // ticket_age_add (4)
    body.extend_from_slice(&nst.ticket_age_add.to_be_bytes());
    // ticket_nonce (1-byte len + nonce)
    body.push(nst.ticket_nonce.len() as u8);
    body.extend_from_slice(&nst.ticket_nonce);
    // ticket (2-byte len + ticket)
    body.extend_from_slice(&(nst.ticket.len() as u16).to_be_bytes());
    body.extend_from_slice(&nst.ticket);
    // extensions (2-byte len + extensions)
    let ext_data = encode_extensions(&nst.extensions);
    body.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_data);

    wrap_handshake(HandshakeType::NewSessionTicket, &body)
}

/// Decode a NewSessionTicket message from handshake body bytes.
pub fn decode_new_session_ticket(data: &[u8]) -> Result<NewSessionTicketMsg, TlsError> {
    let mut pos = 0;
    let err = |msg: &str| TlsError::HandshakeFailed(format!("NewSessionTicket: {msg}"));

    // ticket_lifetime (4)
    if data.len() < pos + 4 {
        return Err(err("too short for lifetime"));
    }
    let ticket_lifetime =
        u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;

    // ticket_age_add (4)
    if data.len() < pos + 4 {
        return Err(err("too short for age_add"));
    }
    let ticket_age_add =
        u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;

    // ticket_nonce (1-byte len + nonce)
    if data.len() < pos + 1 {
        return Err(err("too short for nonce length"));
    }
    let nonce_len = data[pos] as usize;
    pos += 1;
    if data.len() < pos + nonce_len {
        return Err(err("truncated nonce"));
    }
    let ticket_nonce = data[pos..pos + nonce_len].to_vec();
    pos += nonce_len;

    // ticket (2-byte len + ticket)
    if data.len() < pos + 2 {
        return Err(err("too short for ticket length"));
    }
    let ticket_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if data.len() < pos + ticket_len {
        return Err(err("truncated ticket"));
    }
    let ticket = data[pos..pos + ticket_len].to_vec();
    pos += ticket_len;

    // extensions (2-byte len + extensions)
    let extensions = if data.len() > pos {
        parse_extensions_from(&data[pos..])?
    } else {
        vec![]
    };

    Ok(NewSessionTicketMsg {
        ticket_lifetime,
        ticket_age_add,
        ticket_nonce,
        ticket,
        extensions,
    })
}

// ---------------------------------------------------------------------------
// Encode EndOfEarlyData
// ---------------------------------------------------------------------------

/// Encode an EndOfEarlyData message as a complete handshake message (empty body).
pub fn encode_end_of_early_data() -> Vec<u8> {
    wrap_handshake(HandshakeType::EndOfEarlyData, &[])
}

// ---------------------------------------------------------------------------
// Encode/Decode CertificateRequest
// ---------------------------------------------------------------------------

/// Encode a CertificateRequest as a complete handshake message (header + body).
///
/// Format: context_len(1) || context || extensions_len(2) || extensions
pub fn encode_certificate_request(cr: &CertificateRequestMsg) -> Vec<u8> {
    let mut body = Vec::new();

    // certificate_request_context (1-byte length prefix)
    body.push(cr.certificate_request_context.len() as u8);
    body.extend_from_slice(&cr.certificate_request_context);

    // extensions (2-byte length prefix)
    let ext_bytes = encode_extensions(&cr.extensions);
    body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_bytes);

    wrap_handshake(HandshakeType::CertificateRequest, &body)
}

/// Decode a CertificateRequest from handshake body bytes (after header).
pub fn decode_certificate_request(data: &[u8]) -> Result<CertificateRequestMsg, TlsError> {
    let mut pos = 0;
    let err = |msg: &str| TlsError::HandshakeFailed(format!("CertificateRequest: {msg}"));

    if data.is_empty() {
        return Err(err("empty"));
    }

    // certificate_request_context
    let ctx_len = data[pos] as usize;
    pos += 1;
    if data.len() < pos + ctx_len {
        return Err(err("truncated context"));
    }
    let certificate_request_context = data[pos..pos + ctx_len].to_vec();
    pos += ctx_len;

    // extensions
    if data.len() < pos + 2 {
        return Err(err("truncated extensions length"));
    }
    let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if data.len() < pos + ext_len {
        return Err(err("truncated extensions"));
    }
    let extensions = if ext_len > 0 {
        parse_extensions_list(&data[pos..pos + ext_len])?
    } else {
        vec![]
    };

    Ok(CertificateRequestMsg {
        certificate_request_context,
        extensions,
    })
}

// ---------------------------------------------------------------------------
// Extension encoding/parsing helpers
// ---------------------------------------------------------------------------

/// Encode a list of extensions to bytes.
pub(crate) fn encode_extensions(exts: &[Extension]) -> Vec<u8> {
    let mut buf = Vec::new();
    for ext in exts {
        buf.extend_from_slice(&ext.extension_type.0.to_be_bytes());
        buf.extend_from_slice(&(ext.data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&ext.data);
    }
    buf
}

/// Parse extensions from data that starts with a 2-byte length prefix.
pub(crate) fn parse_extensions_from(data: &[u8]) -> Result<Vec<Extension>, TlsError> {
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
pub(crate) fn parse_extensions_list(data: &[u8]) -> Result<Vec<Extension>, TlsError> {
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
pub(crate) fn read_u24(data: &[u8]) -> u32 {
    ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32)
}

// ---------------------------------------------------------------------------
// Decode ClientHello
// ---------------------------------------------------------------------------

/// Decode a ClientHello from handshake body bytes (after header).
pub fn decode_client_hello(data: &[u8]) -> Result<ClientHello, TlsError> {
    let mut pos = 0;
    let err = |msg: &str| TlsError::HandshakeFailed(format!("ClientHello: {msg}"));

    // legacy_version (2)
    if data.len() < pos + 2 {
        return Err(err("too short for version"));
    }
    pos += 2; // skip legacy_version

    // random (32)
    if data.len() < pos + 32 {
        return Err(err("too short for random"));
    }
    let mut random = [0u8; 32];
    random.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    // legacy_session_id
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

    // cipher_suites
    if data.len() < pos + 2 {
        return Err(err("too short for cipher_suites length"));
    }
    let suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if data.len() < pos + suites_len || suites_len % 2 != 0 {
        return Err(err("invalid cipher_suites length"));
    }
    let mut cipher_suites = Vec::with_capacity(suites_len / 2);
    for i in (0..suites_len).step_by(2) {
        cipher_suites.push(CipherSuite(u16::from_be_bytes([
            data[pos + i],
            data[pos + i + 1],
        ])));
    }
    pos += suites_len;

    // legacy_compression_methods
    if data.len() < pos + 1 {
        return Err(err("too short for compression length"));
    }
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;

    // extensions
    let extensions = if data.len() > pos {
        parse_extensions_from(&data[pos..])?
    } else {
        vec![]
    };

    Ok(ClientHello {
        random,
        legacy_session_id,
        cipher_suites,
        extensions,
    })
}

// ---------------------------------------------------------------------------
// Encode ServerHello
// ---------------------------------------------------------------------------

/// Encode a ServerHello as a complete handshake message (header + body).
pub fn encode_server_hello(sh: &ServerHello) -> Vec<u8> {
    let mut body = Vec::with_capacity(128);

    // legacy_version = 0x0303
    body.extend_from_slice(&0x0303u16.to_be_bytes());

    // random
    body.extend_from_slice(&sh.random);

    // legacy_session_id_echo
    body.push(sh.legacy_session_id.len() as u8);
    body.extend_from_slice(&sh.legacy_session_id);

    // cipher_suite
    body.extend_from_slice(&sh.cipher_suite.0.to_be_bytes());

    // legacy_compression_method = 0
    body.push(0);

    // extensions
    let ext_data = encode_extensions(&sh.extensions);
    body.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_data);

    wrap_handshake(HandshakeType::ServerHello, &body)
}

// ---------------------------------------------------------------------------
// Encode EncryptedExtensions
// ---------------------------------------------------------------------------

/// Encode an EncryptedExtensions message as a complete handshake message.
pub fn encode_encrypted_extensions(ee: &EncryptedExtensions) -> Vec<u8> {
    let ext_data = encode_extensions(&ee.extensions);
    let mut body = Vec::with_capacity(2 + ext_data.len());
    body.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_data);
    wrap_handshake(HandshakeType::EncryptedExtensions, &body)
}

// ---------------------------------------------------------------------------
// Encode Certificate
// ---------------------------------------------------------------------------

/// Encode a Certificate message as a complete handshake message.
pub fn encode_certificate(cert_msg: &CertificateMsg) -> Vec<u8> {
    let mut body = Vec::with_capacity(256);

    // certificate_request_context
    body.push(cert_msg.certificate_request_context.len() as u8);
    body.extend_from_slice(&cert_msg.certificate_request_context);

    // Build certificate list
    let mut list = Vec::new();
    for entry in &cert_msg.certificate_list {
        // cert_data (3-byte length)
        let cert_len = entry.cert_data.len();
        list.push((cert_len >> 16) as u8);
        list.push((cert_len >> 8) as u8);
        list.push(cert_len as u8);
        list.extend_from_slice(&entry.cert_data);

        // extensions (2-byte length)
        let ext_data = encode_extensions(&entry.extensions);
        list.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        list.extend_from_slice(&ext_data);
    }

    // certificate_list (3-byte length)
    let list_len = list.len();
    body.push((list_len >> 16) as u8);
    body.push((list_len >> 8) as u8);
    body.push(list_len as u8);
    body.extend_from_slice(&list);

    wrap_handshake(HandshakeType::Certificate, &body)
}

// ---------------------------------------------------------------------------
// Encode CertificateVerify
// ---------------------------------------------------------------------------

/// Encode a CertificateVerify message as a complete handshake message.
pub fn encode_certificate_verify(cv: &CertificateVerifyMsg) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + cv.signature.len());
    body.extend_from_slice(&cv.algorithm.0.to_be_bytes());
    body.extend_from_slice(&(cv.signature.len() as u16).to_be_bytes());
    body.extend_from_slice(&cv.signature);
    wrap_handshake(HandshakeType::CertificateVerify, &body)
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
    fn test_decode_client_hello_roundtrip() {
        let ch = ClientHello {
            random: [0xCC; 32],
            legacy_session_id: vec![0x01, 0x02],
            cipher_suites: vec![
                CipherSuite::TLS_AES_128_GCM_SHA256,
                CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
            ],
            extensions: vec![Extension {
                extension_type: ExtensionType::SUPPORTED_VERSIONS,
                data: vec![0x02, 0x03, 0x04],
            }],
        };
        let encoded = encode_client_hello(&ch);
        let (msg_type, body, _) = parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::ClientHello);
        let decoded = decode_client_hello(body).unwrap();
        assert_eq!(decoded.random, [0xCC; 32]);
        assert_eq!(decoded.legacy_session_id, vec![0x01, 0x02]);
        assert_eq!(decoded.cipher_suites.len(), 2);
        assert_eq!(
            decoded.cipher_suites[0],
            CipherSuite::TLS_AES_128_GCM_SHA256
        );
        assert_eq!(decoded.extensions.len(), 1);
    }

    #[test]
    fn test_encode_server_hello() {
        let sh = ServerHello {
            random: [0xDD; 32],
            legacy_session_id: vec![],
            cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
            extensions: vec![Extension {
                extension_type: ExtensionType::SUPPORTED_VERSIONS,
                data: vec![0x03, 0x04],
            }],
        };
        let encoded = encode_server_hello(&sh);
        let (msg_type, body, total) = parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::ServerHello);
        assert_eq!(total, encoded.len());
        // Verify body structure
        assert_eq!(&body[0..2], &[0x03, 0x03]); // legacy_version
        assert_eq!(&body[2..34], &[0xDD; 32]); // random
        assert_eq!(body[34], 0); // session_id length = 0

        // Decode it back
        let decoded = decode_server_hello(body).unwrap();
        assert_eq!(decoded.random, [0xDD; 32]);
        assert_eq!(decoded.cipher_suite, CipherSuite::TLS_AES_128_GCM_SHA256);
    }

    #[test]
    fn test_encode_certificate_verify_roundtrip() {
        let cv = CertificateVerifyMsg {
            algorithm: SignatureScheme::ED25519,
            signature: vec![0xAB; 64],
        };
        let encoded = encode_certificate_verify(&cv);
        let (msg_type, body, _) = parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::CertificateVerify);
        let decoded = decode_certificate_verify(body).unwrap();
        assert_eq!(decoded.algorithm, SignatureScheme::ED25519);
        assert_eq!(decoded.signature, vec![0xAB; 64]);
    }

    #[test]
    fn test_encode_certificate_roundtrip() {
        let cert_msg = CertificateMsg {
            certificate_request_context: vec![],
            certificate_list: vec![
                CertificateEntry {
                    cert_data: vec![0x30, 0x82, 0x01, 0x00],
                    extensions: vec![],
                },
                CertificateEntry {
                    cert_data: vec![0x30, 0x82, 0x02, 0x00, 0xFF],
                    extensions: vec![],
                },
            ],
        };
        let encoded = encode_certificate(&cert_msg);
        let (msg_type, body, _) = parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::Certificate);
        let decoded = decode_certificate(body).unwrap();
        assert_eq!(decoded.certificate_list.len(), 2);
        assert_eq!(
            decoded.certificate_list[0].cert_data,
            vec![0x30, 0x82, 0x01, 0x00]
        );
        assert_eq!(decoded.certificate_list[1].cert_data.len(), 5);
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

    #[test]
    fn test_key_update_codec_roundtrip() {
        // UpdateRequested
        let ku = KeyUpdateMsg {
            request_update: KeyUpdateRequest::UpdateRequested,
        };
        let encoded = encode_key_update(&ku);
        let (msg_type, body, total) = parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::KeyUpdate);
        assert_eq!(total, encoded.len());
        assert_eq!(body.len(), 1);
        let decoded = decode_key_update(body).unwrap();
        assert_eq!(decoded.request_update, KeyUpdateRequest::UpdateRequested);

        // UpdateNotRequested
        let ku2 = KeyUpdateMsg {
            request_update: KeyUpdateRequest::UpdateNotRequested,
        };
        let encoded2 = encode_key_update(&ku2);
        let (_, body2, _) = parse_handshake_header(&encoded2).unwrap();
        let decoded2 = decode_key_update(body2).unwrap();
        assert_eq!(
            decoded2.request_update,
            KeyUpdateRequest::UpdateNotRequested
        );

        // Invalid value
        assert!(decode_key_update(&[2]).is_err());
        assert!(decode_key_update(&[]).is_err());
    }

    #[test]
    fn test_end_of_early_data_codec() {
        let encoded = encode_end_of_early_data();
        let (msg_type, body, total) = parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::EndOfEarlyData);
        assert_eq!(total, 4); // 4-byte header, empty body
        assert_eq!(encoded.len(), 4);
        assert!(body.is_empty());
    }

    #[test]
    fn test_new_session_ticket_codec_roundtrip() {
        let nst = NewSessionTicketMsg {
            ticket_lifetime: 3600,
            ticket_age_add: 0xDEADBEEF,
            ticket_nonce: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            ticket: vec![0xAA; 64],
            extensions: vec![],
        };
        let encoded = encode_new_session_ticket(&nst);
        let (msg_type, body, total) = parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::NewSessionTicket);
        assert_eq!(total, encoded.len());

        let decoded = decode_new_session_ticket(body).unwrap();
        assert_eq!(decoded.ticket_lifetime, 3600);
        assert_eq!(decoded.ticket_age_add, 0xDEADBEEF);
        assert_eq!(
            decoded.ticket_nonce,
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(decoded.ticket, vec![0xAA; 64]);
        assert!(decoded.extensions.is_empty());
    }

    #[test]
    fn test_certificate_request_codec() {
        use crate::extensions::ExtensionType;

        let cr = CertificateRequestMsg {
            certificate_request_context: vec![0x01, 0x02, 0x03],
            extensions: vec![Extension {
                extension_type: ExtensionType::SIGNATURE_ALGORITHMS,
                data: vec![0x00, 0x02, 0x08, 0x07], // list_len=2, ed25519=0x0807
            }],
        };
        let encoded = encode_certificate_request(&cr);
        let (msg_type, body, total) = parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::CertificateRequest);
        assert_eq!(total, encoded.len());

        let decoded = decode_certificate_request(body).unwrap();
        assert_eq!(decoded.certificate_request_context, vec![0x01, 0x02, 0x03]);
        assert_eq!(decoded.extensions.len(), 1);
        assert_eq!(
            decoded.extensions[0].extension_type,
            ExtensionType::SIGNATURE_ALGORITHMS
        );
    }

    #[test]
    fn test_compressed_certificate_codec_roundtrip() {
        let original = CompressedCertificateMsg {
            algorithm: CertCompressionAlgorithm::ZLIB,
            uncompressed_length: 1234,
            compressed_data: vec![0x78, 0x9C, 0x01, 0x02, 0x03, 0x04, 0x05],
        };

        let encoded = encode_compressed_certificate(&original);
        // Verify handshake type = 25 (CompressedCertificate)
        assert_eq!(encoded[0], 25);

        // Decode body (skip 4-byte handshake header)
        let body = &encoded[4..];
        let decoded = decode_compressed_certificate(body).unwrap();
        assert_eq!(decoded.algorithm, CertCompressionAlgorithm::ZLIB);
        assert_eq!(decoded.uncompressed_length, 1234);
        assert_eq!(decoded.compressed_data, original.compressed_data);
    }

    #[cfg(feature = "cert-compression")]
    #[test]
    fn test_compress_decompress_zlib() {
        // A sample Certificate message body (context_len=0, list with one small cert)
        let mut cert_body = Vec::new();
        cert_body.push(0); // empty context
        let fake_cert = vec![0x30, 0x82, 0x01, 0x00]; // minimal DER
        let mut list = Vec::new();
        // cert_data (3-byte len)
        list.push(0);
        list.push(0);
        list.push(fake_cert.len() as u8);
        list.extend_from_slice(&fake_cert);
        // extensions (2-byte len = 0)
        list.push(0);
        list.push(0);
        // list length
        let list_len = list.len();
        cert_body.push((list_len >> 16) as u8);
        cert_body.push((list_len >> 8) as u8);
        cert_body.push(list_len as u8);
        cert_body.extend_from_slice(&list);

        let compressed = compress_certificate_body(&cert_body).unwrap();
        assert!(!compressed.is_empty());
        // Should be able to decompress back
        let decompressed = decompress_certificate_body(
            CertCompressionAlgorithm::ZLIB,
            &compressed,
            cert_body.len() as u32,
        )
        .unwrap();
        assert_eq!(decompressed, cert_body);
    }
}
