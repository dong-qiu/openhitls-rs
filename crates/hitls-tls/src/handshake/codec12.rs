//! TLS 1.2 handshake message encoding/decoding.
//!
//! Handles ServerKeyExchange, ClientKeyExchange, ServerHelloDone,
//! Certificate (TLS 1.2 format), Finished (12-byte verify_data),
//! CertificateRequest (mTLS), and CertificateVerify.

use crate::crypt::SignatureScheme;
use crate::handshake::codec::{read_u24, wrap_handshake};
use crate::handshake::HandshakeType;
use hitls_types::TlsError;

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// ServerKeyExchange for ECDHE (RFC 4492 §5.4, RFC 8422 §5.4).
#[derive(Debug, Clone)]
pub struct ServerKeyExchange {
    /// Curve type (3 = named_curve).
    pub curve_type: u8,
    /// Named curve identifier (NamedGroup value).
    pub named_curve: u16,
    /// Server's ephemeral EC public key (uncompressed point).
    pub public_key: Vec<u8>,
    /// Signature algorithm used.
    pub signature_algorithm: SignatureScheme,
    /// Signature over client_random + server_random + server_key_exchange_params.
    pub signature: Vec<u8>,
}

/// ClientKeyExchange for ECDHE (RFC 4492 §5.7).
#[derive(Debug, Clone)]
pub struct ClientKeyExchange {
    /// Client's ephemeral EC public key (uncompressed point).
    pub public_key: Vec<u8>,
}

/// TLS 1.2 Certificate message (RFC 5246 §7.4.2).
///
/// Simpler than TLS 1.3: no request_context, no per-cert extensions.
#[derive(Debug, Clone)]
pub struct Certificate12 {
    /// List of DER-encoded certificates (leaf first).
    pub certificate_list: Vec<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Build the "server key exchange params" portion for signature verification.
///
/// ```text
/// params = curve_type(1) || named_curve(2) || point_len(1) || point
/// ```
pub fn build_ske_params(curve_type: u8, named_curve: u16, public_key: &[u8]) -> Vec<u8> {
    let mut params = Vec::with_capacity(4 + public_key.len());
    params.push(curve_type);
    params.extend_from_slice(&named_curve.to_be_bytes());
    params.push(public_key.len() as u8);
    params.extend_from_slice(public_key);
    params
}

/// Build the data to be signed for ServerKeyExchange.
///
/// ```text
/// signed_data = client_random(32) || server_random(32) || server_params
/// ```
pub fn build_ske_signed_data(
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    ske_params: &[u8],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(64 + ske_params.len());
    data.extend_from_slice(client_random);
    data.extend_from_slice(server_random);
    data.extend_from_slice(ske_params);
    data
}

/// Encode a ServerKeyExchange message (wrapped with handshake header).
pub fn encode_server_key_exchange(ske: &ServerKeyExchange) -> Vec<u8> {
    let params = build_ske_params(ske.curve_type, ske.named_curve, &ske.public_key);
    let sig_alg = ske.signature_algorithm.0.to_be_bytes();

    let mut body = Vec::with_capacity(params.len() + 2 + 2 + ske.signature.len());
    body.extend_from_slice(&params);
    body.extend_from_slice(&sig_alg);
    body.extend_from_slice(&(ske.signature.len() as u16).to_be_bytes());
    body.extend_from_slice(&ske.signature);

    wrap_handshake(HandshakeType::ServerKeyExchange, &body)
}

/// Decode a ServerKeyExchange message body (ECDHE).
pub fn decode_server_key_exchange(body: &[u8]) -> Result<ServerKeyExchange, TlsError> {
    if body.len() < 4 {
        return Err(TlsError::HandshakeFailed(
            "ServerKeyExchange too short".into(),
        ));
    }

    let curve_type = body[0];
    if curve_type != 3 {
        return Err(TlsError::HandshakeFailed(format!(
            "unsupported curve type: {curve_type} (expected 3=named_curve)"
        )));
    }

    let named_curve = u16::from_be_bytes([body[1], body[2]]);
    let point_len = body[3] as usize;

    if body.len() < 4 + point_len + 4 {
        return Err(TlsError::HandshakeFailed(
            "ServerKeyExchange body truncated".into(),
        ));
    }

    let public_key = body[4..4 + point_len].to_vec();
    let offset = 4 + point_len;

    let sig_alg = u16::from_be_bytes([body[offset], body[offset + 1]]);
    let sig_len = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;

    if body.len() < offset + 4 + sig_len {
        return Err(TlsError::HandshakeFailed(
            "ServerKeyExchange signature truncated".into(),
        ));
    }

    let signature = body[offset + 4..offset + 4 + sig_len].to_vec();

    Ok(ServerKeyExchange {
        curve_type,
        named_curve,
        public_key,
        signature_algorithm: SignatureScheme(sig_alg),
        signature,
    })
}

/// Encode a ClientKeyExchange message (ECDHE).
pub fn encode_client_key_exchange(cke: &ClientKeyExchange) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + cke.public_key.len());
    body.push(cke.public_key.len() as u8);
    body.extend_from_slice(&cke.public_key);
    wrap_handshake(HandshakeType::ClientKeyExchange, &body)
}

/// Decode a ClientKeyExchange message body (ECDHE).
pub fn decode_client_key_exchange(body: &[u8]) -> Result<ClientKeyExchange, TlsError> {
    if body.is_empty() {
        return Err(TlsError::HandshakeFailed(
            "ClientKeyExchange too short".into(),
        ));
    }
    let point_len = body[0] as usize;
    if body.len() < 1 + point_len {
        return Err(TlsError::HandshakeFailed(
            "ClientKeyExchange body truncated".into(),
        ));
    }
    Ok(ClientKeyExchange {
        public_key: body[1..1 + point_len].to_vec(),
    })
}

// ---------------------------------------------------------------------------
// DHE ServerKeyExchange
// ---------------------------------------------------------------------------

/// ServerKeyExchange for DHE (RFC 5246 §7.4.3).
#[derive(Debug, Clone)]
pub struct ServerKeyExchangeDhe {
    /// DH prime modulus p (big-endian).
    pub dh_p: Vec<u8>,
    /// DH generator g (big-endian).
    pub dh_g: Vec<u8>,
    /// Server's DH public value Ys (big-endian).
    pub dh_ys: Vec<u8>,
    /// Signature algorithm used.
    pub signature_algorithm: SignatureScheme,
    /// Signature over client_random + server_random + dh_params.
    pub signature: Vec<u8>,
}

/// Build the DHE "server key exchange params" portion for signature computation.
///
/// ```text
/// params = dh_p_len(2) || dh_p || dh_g_len(2) || dh_g || dh_Ys_len(2) || dh_Ys
/// ```
pub fn build_dhe_ske_params(dh_p: &[u8], dh_g: &[u8], dh_ys: &[u8]) -> Vec<u8> {
    let mut params = Vec::with_capacity(6 + dh_p.len() + dh_g.len() + dh_ys.len());
    params.extend_from_slice(&(dh_p.len() as u16).to_be_bytes());
    params.extend_from_slice(dh_p);
    params.extend_from_slice(&(dh_g.len() as u16).to_be_bytes());
    params.extend_from_slice(dh_g);
    params.extend_from_slice(&(dh_ys.len() as u16).to_be_bytes());
    params.extend_from_slice(dh_ys);
    params
}

/// Encode a DHE ServerKeyExchange message (wrapped with handshake header).
pub fn encode_server_key_exchange_dhe(ske: &ServerKeyExchangeDhe) -> Vec<u8> {
    let params = build_dhe_ske_params(&ske.dh_p, &ske.dh_g, &ske.dh_ys);
    let sig_alg = ske.signature_algorithm.0.to_be_bytes();
    let mut body = Vec::with_capacity(params.len() + 2 + 2 + ske.signature.len());
    body.extend_from_slice(&params);
    body.extend_from_slice(&sig_alg);
    body.extend_from_slice(&(ske.signature.len() as u16).to_be_bytes());
    body.extend_from_slice(&ske.signature);
    wrap_handshake(HandshakeType::ServerKeyExchange, &body)
}

/// Decode a DHE ServerKeyExchange message body.
pub fn decode_server_key_exchange_dhe(body: &[u8]) -> Result<ServerKeyExchangeDhe, TlsError> {
    if body.len() < 6 {
        return Err(TlsError::HandshakeFailed(
            "DHE ServerKeyExchange too short".into(),
        ));
    }
    let mut off = 0;
    // p
    let p_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + p_len + 2 {
        return Err(TlsError::HandshakeFailed("DHE SKE p truncated".into()));
    }
    let dh_p = body[off..off + p_len].to_vec();
    off += p_len;
    // g
    let g_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + g_len + 2 {
        return Err(TlsError::HandshakeFailed("DHE SKE g truncated".into()));
    }
    let dh_g = body[off..off + g_len].to_vec();
    off += g_len;
    // Ys
    let ys_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + ys_len + 4 {
        return Err(TlsError::HandshakeFailed("DHE SKE Ys truncated".into()));
    }
    let dh_ys = body[off..off + ys_len].to_vec();
    off += ys_len;
    // signature algorithm + signature
    let sig_alg = u16::from_be_bytes([body[off], body[off + 1]]);
    let sig_len = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
    off += 4;
    if body.len() < off + sig_len {
        return Err(TlsError::HandshakeFailed(
            "DHE SKE signature truncated".into(),
        ));
    }
    let signature = body[off..off + sig_len].to_vec();
    Ok(ServerKeyExchangeDhe {
        dh_p,
        dh_g,
        dh_ys,
        signature_algorithm: SignatureScheme(sig_alg),
        signature,
    })
}

// ---------------------------------------------------------------------------
// RSA ClientKeyExchange
// ---------------------------------------------------------------------------

/// ClientKeyExchange for RSA static key exchange (RFC 5246 §7.4.7.1).
#[derive(Debug, Clone)]
pub struct ClientKeyExchangeRsa {
    /// PKCS#1v1.5-encrypted premaster secret.
    pub encrypted_pms: Vec<u8>,
}

/// Encode an RSA ClientKeyExchange message.
/// Wire format: encrypted_pms_len(2) || encrypted_pms
pub fn encode_client_key_exchange_rsa(cke: &ClientKeyExchangeRsa) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + cke.encrypted_pms.len());
    body.extend_from_slice(&(cke.encrypted_pms.len() as u16).to_be_bytes());
    body.extend_from_slice(&cke.encrypted_pms);
    wrap_handshake(HandshakeType::ClientKeyExchange, &body)
}

/// Decode an RSA ClientKeyExchange message body.
pub fn decode_client_key_exchange_rsa(body: &[u8]) -> Result<ClientKeyExchangeRsa, TlsError> {
    if body.len() < 2 {
        return Err(TlsError::HandshakeFailed(
            "RSA ClientKeyExchange too short".into(),
        ));
    }
    let len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + len {
        return Err(TlsError::HandshakeFailed(
            "RSA ClientKeyExchange truncated".into(),
        ));
    }
    Ok(ClientKeyExchangeRsa {
        encrypted_pms: body[2..2 + len].to_vec(),
    })
}

// ---------------------------------------------------------------------------
// DHE ClientKeyExchange
// ---------------------------------------------------------------------------

/// ClientKeyExchange for DHE (RFC 5246 §7.4.7.2).
#[derive(Debug, Clone)]
pub struct ClientKeyExchangeDhe {
    /// Client's DH public value Yc (big-endian).
    pub dh_yc: Vec<u8>,
}

/// Encode a DHE ClientKeyExchange message.
/// Wire format: dh_Yc_len(2) || dh_Yc
pub fn encode_client_key_exchange_dhe(cke: &ClientKeyExchangeDhe) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + cke.dh_yc.len());
    body.extend_from_slice(&(cke.dh_yc.len() as u16).to_be_bytes());
    body.extend_from_slice(&cke.dh_yc);
    wrap_handshake(HandshakeType::ClientKeyExchange, &body)
}

/// Decode a DHE ClientKeyExchange message body.
pub fn decode_client_key_exchange_dhe(body: &[u8]) -> Result<ClientKeyExchangeDhe, TlsError> {
    if body.len() < 2 {
        return Err(TlsError::HandshakeFailed(
            "DHE ClientKeyExchange too short".into(),
        ));
    }
    let len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + len {
        return Err(TlsError::HandshakeFailed(
            "DHE ClientKeyExchange truncated".into(),
        ));
    }
    Ok(ClientKeyExchangeDhe {
        dh_yc: body[2..2 + len].to_vec(),
    })
}

/// Encode a ServerHelloDone message (empty body).
pub fn encode_server_hello_done() -> Vec<u8> {
    wrap_handshake(HandshakeType::ServerHelloDone, &[])
}

/// Encode a TLS 1.2 CertificateStatus message (RFC 6066 §8).
///
/// Format: status_type(1)=ocsp(1) || response_length(3) || ocsp_response
pub fn encode_certificate_status12(ocsp_response: &[u8]) -> Vec<u8> {
    let len = ocsp_response.len();
    let mut body = Vec::with_capacity(4 + len);
    body.push(0x01); // status_type = ocsp
    body.push((len >> 16) as u8);
    body.push((len >> 8) as u8);
    body.push(len as u8);
    body.extend_from_slice(ocsp_response);
    wrap_handshake(HandshakeType::CertificateStatus, &body)
}

/// Decode a TLS 1.2 CertificateStatus message body.
///
/// Returns the raw OCSP response DER.
pub fn decode_certificate_status12(body: &[u8]) -> Result<Vec<u8>, TlsError> {
    if body.len() < 4 {
        return Err(TlsError::HandshakeFailed(
            "CertificateStatus: too short".into(),
        ));
    }
    if body[0] != 0x01 {
        return Err(TlsError::HandshakeFailed(format!(
            "CertificateStatus: unsupported status_type {}",
            body[0]
        )));
    }
    let len = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | (body[3] as usize);
    if body.len() < 4 + len {
        return Err(TlsError::HandshakeFailed(
            "CertificateStatus: response truncated".into(),
        ));
    }
    Ok(body[4..4 + len].to_vec())
}

/// Encode a TLS 1.2 Certificate message.
pub fn encode_certificate12(cert: &Certificate12) -> Vec<u8> {
    // Total length of all certificates
    let total_len: usize = cert.certificate_list.iter().map(|c| 3 + c.len()).sum();

    let mut body = Vec::with_capacity(3 + total_len);
    // certificate_list length (3 bytes)
    body.push((total_len >> 16) as u8);
    body.push((total_len >> 8) as u8);
    body.push(total_len as u8);

    for cert_data in &cert.certificate_list {
        let len = cert_data.len();
        body.push((len >> 16) as u8);
        body.push((len >> 8) as u8);
        body.push(len as u8);
        body.extend_from_slice(cert_data);
    }

    wrap_handshake(HandshakeType::Certificate, &body)
}

/// Decode a TLS 1.2 Certificate message body.
pub fn decode_certificate12(body: &[u8]) -> Result<Certificate12, TlsError> {
    if body.len() < 3 {
        return Err(TlsError::HandshakeFailed("Certificate12 too short".into()));
    }

    let total_len = read_u24(body) as usize;
    if body.len() < 3 + total_len {
        return Err(TlsError::HandshakeFailed(
            "Certificate12 body truncated".into(),
        ));
    }

    let mut certs = Vec::new();
    let mut offset = 3;
    let end = 3 + total_len;

    while offset < end {
        if offset + 3 > end {
            return Err(TlsError::HandshakeFailed(
                "Certificate12 cert entry truncated".into(),
            ));
        }
        let cert_len = read_u24(&body[offset..]) as usize;
        offset += 3;
        if offset + cert_len > end {
            return Err(TlsError::HandshakeFailed(
                "Certificate12 cert data truncated".into(),
            ));
        }
        certs.push(body[offset..offset + cert_len].to_vec());
        offset += cert_len;
    }

    Ok(Certificate12 {
        certificate_list: certs,
    })
}

/// Encode a TLS 1.2 Finished message (12-byte verify_data).
pub fn encode_finished12(verify_data: &[u8]) -> Vec<u8> {
    wrap_handshake(HandshakeType::Finished, verify_data)
}

/// Decode a TLS 1.2 Finished message body.
pub fn decode_finished12(body: &[u8]) -> Result<Vec<u8>, TlsError> {
    if body.len() != 12 {
        return Err(TlsError::HandshakeFailed(format!(
            "Finished verify_data must be 12 bytes, got {}",
            body.len()
        )));
    }
    Ok(body.to_vec())
}

/// Encode a ChangeCipherSpec message body (not a handshake message — content type 20).
pub fn encode_change_cipher_spec() -> Vec<u8> {
    vec![0x01]
}

// ---------------------------------------------------------------------------
// CertificateRequest (TLS 1.2, RFC 5246 §7.4.4)
// ---------------------------------------------------------------------------

/// TLS 1.2 CertificateRequest message.
///
/// ```text
/// cert_types_len(1) || cert_types(variable) ||
/// sig_hash_algs_len(2) || sig_hash_algs(variable) ||
/// ca_list_len(2) || ca_entries(variable)
/// ```
#[derive(Debug, Clone)]
pub struct CertificateRequest12 {
    /// Supported certificate types: rsa_sign(1), ecdsa_sign(64).
    pub cert_types: Vec<u8>,
    /// Supported signature algorithms.
    pub sig_hash_algs: Vec<SignatureScheme>,
    /// Distinguished names of acceptable CAs (DER-encoded, can be empty).
    pub ca_names: Vec<Vec<u8>>,
}

/// Encode a TLS 1.2 CertificateRequest message (wrapped with handshake header).
pub fn encode_certificate_request12(cr: &CertificateRequest12) -> Vec<u8> {
    let mut body = Vec::new();

    // cert_types_len(1) || cert_types
    body.push(cr.cert_types.len() as u8);
    body.extend_from_slice(&cr.cert_types);

    // sig_hash_algs_len(2) || sig_hash_algs (each 2 bytes)
    let algs_len = (cr.sig_hash_algs.len() * 2) as u16;
    body.extend_from_slice(&algs_len.to_be_bytes());
    for alg in &cr.sig_hash_algs {
        body.extend_from_slice(&alg.0.to_be_bytes());
    }

    // ca_list_len(2) || (dn_len(2) || dn)*
    let ca_total: usize = cr.ca_names.iter().map(|dn| 2 + dn.len()).sum();
    body.extend_from_slice(&(ca_total as u16).to_be_bytes());
    for dn in &cr.ca_names {
        body.extend_from_slice(&(dn.len() as u16).to_be_bytes());
        body.extend_from_slice(dn);
    }

    wrap_handshake(HandshakeType::CertificateRequest, &body)
}

/// Decode a TLS 1.2 CertificateRequest message body.
pub fn decode_certificate_request12(body: &[u8]) -> Result<CertificateRequest12, TlsError> {
    if body.is_empty() {
        return Err(TlsError::HandshakeFailed(
            "CertificateRequest12 empty".into(),
        ));
    }

    let mut offset = 0;

    // cert_types
    let cert_types_len = body[offset] as usize;
    offset += 1;
    if body.len() < offset + cert_types_len {
        return Err(TlsError::HandshakeFailed(
            "CertificateRequest12 cert_types truncated".into(),
        ));
    }
    let cert_types = body[offset..offset + cert_types_len].to_vec();
    offset += cert_types_len;

    // sig_hash_algs
    if body.len() < offset + 2 {
        return Err(TlsError::HandshakeFailed(
            "CertificateRequest12 sig_algs_len truncated".into(),
        ));
    }
    let algs_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    offset += 2;
    if algs_len % 2 != 0 || body.len() < offset + algs_len {
        return Err(TlsError::HandshakeFailed(
            "CertificateRequest12 sig_algs truncated".into(),
        ));
    }
    let mut sig_hash_algs = Vec::with_capacity(algs_len / 2);
    for i in (0..algs_len).step_by(2) {
        let alg = u16::from_be_bytes([body[offset + i], body[offset + i + 1]]);
        sig_hash_algs.push(SignatureScheme(alg));
    }
    offset += algs_len;

    // ca_names
    if body.len() < offset + 2 {
        return Err(TlsError::HandshakeFailed(
            "CertificateRequest12 ca_list_len truncated".into(),
        ));
    }
    let ca_total = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    offset += 2;
    if body.len() < offset + ca_total {
        return Err(TlsError::HandshakeFailed(
            "CertificateRequest12 ca_list truncated".into(),
        ));
    }
    let ca_end = offset + ca_total;
    let mut ca_names = Vec::new();
    while offset < ca_end {
        if offset + 2 > ca_end {
            return Err(TlsError::HandshakeFailed(
                "CertificateRequest12 ca entry truncated".into(),
            ));
        }
        let dn_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
        offset += 2;
        if offset + dn_len > ca_end {
            return Err(TlsError::HandshakeFailed(
                "CertificateRequest12 ca DN truncated".into(),
            ));
        }
        ca_names.push(body[offset..offset + dn_len].to_vec());
        offset += dn_len;
    }

    Ok(CertificateRequest12 {
        cert_types,
        sig_hash_algs,
        ca_names,
    })
}

// ---------------------------------------------------------------------------
// CertificateVerify (TLS 1.2, RFC 5246 §7.4.8)
// ---------------------------------------------------------------------------

/// TLS 1.2 CertificateVerify message.
///
/// ```text
/// sig_algorithm(2) || sig_len(2) || signature(variable)
/// ```
#[derive(Debug, Clone)]
pub struct CertificateVerify12 {
    pub sig_algorithm: SignatureScheme,
    pub signature: Vec<u8>,
}

/// Encode a TLS 1.2 CertificateVerify message (wrapped with handshake header).
pub fn encode_certificate_verify12(cv: &CertificateVerify12) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + cv.signature.len());
    body.extend_from_slice(&cv.sig_algorithm.0.to_be_bytes());
    body.extend_from_slice(&(cv.signature.len() as u16).to_be_bytes());
    body.extend_from_slice(&cv.signature);
    wrap_handshake(HandshakeType::CertificateVerify, &body)
}

/// Decode a TLS 1.2 CertificateVerify message body.
pub fn decode_certificate_verify12(body: &[u8]) -> Result<CertificateVerify12, TlsError> {
    if body.len() < 4 {
        return Err(TlsError::HandshakeFailed(
            "CertificateVerify12 too short".into(),
        ));
    }
    let sig_alg = u16::from_be_bytes([body[0], body[1]]);
    let sig_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if body.len() < 4 + sig_len {
        return Err(TlsError::HandshakeFailed(
            "CertificateVerify12 signature truncated".into(),
        ));
    }
    Ok(CertificateVerify12 {
        sig_algorithm: SignatureScheme(sig_alg),
        signature: body[4..4 + sig_len].to_vec(),
    })
}

// ---------------------------------------------------------------------------
// NewSessionTicket (TLS 1.2, RFC 5077)
// ---------------------------------------------------------------------------

/// Encode a TLS 1.2 NewSessionTicket message (wrapped with handshake header).
///
/// ```text
/// ticket_lifetime_hint(4) || ticket_len(2) || ticket(variable)
/// ```
pub fn encode_new_session_ticket12(lifetime_hint: u32, ticket: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + 2 + ticket.len());
    body.extend_from_slice(&lifetime_hint.to_be_bytes());
    body.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
    body.extend_from_slice(ticket);
    wrap_handshake(HandshakeType::NewSessionTicket, &body)
}

/// Decode a TLS 1.2 NewSessionTicket message body.
///
/// Returns `(lifetime_hint, ticket_data)`.
pub fn decode_new_session_ticket12(body: &[u8]) -> Result<(u32, Vec<u8>), TlsError> {
    if body.len() < 6 {
        return Err(TlsError::HandshakeFailed(
            "NewSessionTicket12 too short".into(),
        ));
    }
    let lifetime = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let ticket_len = u16::from_be_bytes([body[4], body[5]]) as usize;
    if body.len() < 6 + ticket_len {
        return Err(TlsError::HandshakeFailed(
            "NewSessionTicket12 ticket truncated".into(),
        ));
    }
    Ok((lifetime, body[6..6 + ticket_len].to_vec()))
}

// ---------------------------------------------------------------------------
// PSK key exchange types and codecs (RFC 4279, RFC 5489)
// ---------------------------------------------------------------------------

/// ServerKeyExchange for plain PSK or RSA_PSK: just a PSK identity hint.
///
/// ```text
/// psk_identity_hint_len(2) || psk_identity_hint(variable)
/// ```
#[derive(Debug, Clone)]
pub struct ServerKeyExchangePskHint {
    /// PSK identity hint (may be empty).
    pub hint: Vec<u8>,
}

/// ServerKeyExchange for DHE_PSK (RFC 4279 §3): hint + DH params (unsigned).
///
/// ```text
/// psk_identity_hint_len(2) || hint || dh_p_len(2) || dh_p ||
/// dh_g_len(2) || dh_g || dh_Ys_len(2) || dh_Ys
/// ```
#[derive(Debug, Clone)]
pub struct ServerKeyExchangeDhePsk {
    pub hint: Vec<u8>,
    pub dh_p: Vec<u8>,
    pub dh_g: Vec<u8>,
    pub dh_ys: Vec<u8>,
}

/// ServerKeyExchange for ECDHE_PSK (RFC 5489 §2): hint + ECDHE params (unsigned).
///
/// ```text
/// psk_identity_hint_len(2) || hint || curve_type(1) || named_curve(2) ||
/// point_len(1) || point(variable)
/// ```
#[derive(Debug, Clone)]
pub struct ServerKeyExchangeEcdhePsk {
    pub hint: Vec<u8>,
    pub named_curve: u16,
    pub public_key: Vec<u8>,
}

/// ClientKeyExchange for plain PSK (RFC 4279 §2).
///
/// ```text
/// psk_identity_len(2) || psk_identity(variable)
/// ```
#[derive(Debug, Clone)]
pub struct ClientKeyExchangePsk {
    pub identity: Vec<u8>,
}

/// ClientKeyExchange for DHE_PSK (RFC 4279 §3).
///
/// ```text
/// psk_identity_len(2) || identity || dh_Yc_len(2) || dh_Yc
/// ```
#[derive(Debug, Clone)]
pub struct ClientKeyExchangeDhePsk {
    pub identity: Vec<u8>,
    pub dh_yc: Vec<u8>,
}

/// ClientKeyExchange for ECDHE_PSK (RFC 5489 §2).
///
/// ```text
/// psk_identity_len(2) || identity || point_len(1) || point(variable)
/// ```
#[derive(Debug, Clone)]
pub struct ClientKeyExchangeEcdhePsk {
    pub identity: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// ClientKeyExchange for RSA_PSK (RFC 4279 §4).
///
/// ```text
/// psk_identity_len(2) || identity || encrypted_pms_len(2) || encrypted_pms
/// ```
#[derive(Debug, Clone)]
pub struct ClientKeyExchangeRsaPsk {
    pub identity: Vec<u8>,
    pub encrypted_pms: Vec<u8>,
}

/// Build the PSK premaster secret (RFC 4279 §2).
///
/// ```text
/// pms = other_secret_len(2) || other_secret || psk_len(2) || psk
/// ```
///
/// For plain PSK: `other_secret` is N zero bytes where N = psk.len().
/// For DHE_PSK / ECDHE_PSK: `other_secret` is the DH/ECDH shared secret.
/// For RSA_PSK: `other_secret` is the 48-byte RSA premaster secret.
pub fn build_psk_pms(other_secret: &[u8], psk: &[u8]) -> Vec<u8> {
    let mut pms = Vec::with_capacity(4 + other_secret.len() + psk.len());
    pms.extend_from_slice(&(other_secret.len() as u16).to_be_bytes());
    pms.extend_from_slice(other_secret);
    pms.extend_from_slice(&(psk.len() as u16).to_be_bytes());
    pms.extend_from_slice(psk);
    pms
}

/// Encode a PSK ClientKeyExchange message.
pub fn encode_client_key_exchange_psk(cke: &ClientKeyExchangePsk) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + cke.identity.len());
    body.extend_from_slice(&(cke.identity.len() as u16).to_be_bytes());
    body.extend_from_slice(&cke.identity);
    wrap_handshake(HandshakeType::ClientKeyExchange, &body)
}

/// Encode a DHE_PSK ClientKeyExchange message.
pub fn encode_client_key_exchange_dhe_psk(cke: &ClientKeyExchangeDhePsk) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + cke.identity.len() + cke.dh_yc.len());
    body.extend_from_slice(&(cke.identity.len() as u16).to_be_bytes());
    body.extend_from_slice(&cke.identity);
    body.extend_from_slice(&(cke.dh_yc.len() as u16).to_be_bytes());
    body.extend_from_slice(&cke.dh_yc);
    wrap_handshake(HandshakeType::ClientKeyExchange, &body)
}

/// Encode an ECDHE_PSK ClientKeyExchange message.
pub fn encode_client_key_exchange_ecdhe_psk(cke: &ClientKeyExchangeEcdhePsk) -> Vec<u8> {
    let mut body = Vec::with_capacity(3 + cke.identity.len() + cke.public_key.len());
    body.extend_from_slice(&(cke.identity.len() as u16).to_be_bytes());
    body.extend_from_slice(&cke.identity);
    body.push(cke.public_key.len() as u8);
    body.extend_from_slice(&cke.public_key);
    wrap_handshake(HandshakeType::ClientKeyExchange, &body)
}

/// Encode an RSA_PSK ClientKeyExchange message.
pub fn encode_client_key_exchange_rsa_psk(cke: &ClientKeyExchangeRsaPsk) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + cke.identity.len() + cke.encrypted_pms.len());
    body.extend_from_slice(&(cke.identity.len() as u16).to_be_bytes());
    body.extend_from_slice(&cke.identity);
    body.extend_from_slice(&(cke.encrypted_pms.len() as u16).to_be_bytes());
    body.extend_from_slice(&cke.encrypted_pms);
    wrap_handshake(HandshakeType::ClientKeyExchange, &body)
}

/// Decode a PSK identity hint ServerKeyExchange body.
pub fn decode_server_key_exchange_psk_hint(
    body: &[u8],
) -> Result<ServerKeyExchangePskHint, TlsError> {
    if body.len() < 2 {
        return Err(TlsError::HandshakeFailed("PSK SKE hint too short".into()));
    }
    let hint_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + hint_len {
        return Err(TlsError::HandshakeFailed("PSK SKE hint truncated".into()));
    }
    Ok(ServerKeyExchangePskHint {
        hint: body[2..2 + hint_len].to_vec(),
    })
}

/// Decode a DHE_PSK ServerKeyExchange body (hint + unsigned DH params).
pub fn decode_server_key_exchange_dhe_psk(
    body: &[u8],
) -> Result<ServerKeyExchangeDhePsk, TlsError> {
    if body.len() < 2 {
        return Err(TlsError::HandshakeFailed("DHE_PSK SKE too short".into()));
    }
    let mut off = 0;
    // hint
    let hint_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + hint_len + 2 {
        return Err(TlsError::HandshakeFailed(
            "DHE_PSK SKE hint truncated".into(),
        ));
    }
    let hint = body[off..off + hint_len].to_vec();
    off += hint_len;
    // dh_p
    let p_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + p_len + 2 {
        return Err(TlsError::HandshakeFailed("DHE_PSK SKE p truncated".into()));
    }
    let dh_p = body[off..off + p_len].to_vec();
    off += p_len;
    // dh_g
    let g_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + g_len + 2 {
        return Err(TlsError::HandshakeFailed("DHE_PSK SKE g truncated".into()));
    }
    let dh_g = body[off..off + g_len].to_vec();
    off += g_len;
    // dh_Ys
    let ys_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + ys_len {
        return Err(TlsError::HandshakeFailed("DHE_PSK SKE Ys truncated".into()));
    }
    let dh_ys = body[off..off + ys_len].to_vec();
    Ok(ServerKeyExchangeDhePsk {
        hint,
        dh_p,
        dh_g,
        dh_ys,
    })
}

/// Encode a PSK hint-only ServerKeyExchange message (wrapped with handshake header).
pub fn encode_server_key_exchange_psk_hint(ske: &ServerKeyExchangePskHint) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + ske.hint.len());
    body.extend_from_slice(&(ske.hint.len() as u16).to_be_bytes());
    body.extend_from_slice(&ske.hint);
    wrap_handshake(HandshakeType::ServerKeyExchange, &body)
}

/// Encode a DHE_PSK ServerKeyExchange message (wrapped with handshake header).
pub fn encode_server_key_exchange_dhe_psk(ske: &ServerKeyExchangeDhePsk) -> Vec<u8> {
    let mut body = Vec::with_capacity(
        2 + ske.hint.len() + 6 + ske.dh_p.len() + ske.dh_g.len() + ske.dh_ys.len(),
    );
    body.extend_from_slice(&(ske.hint.len() as u16).to_be_bytes());
    body.extend_from_slice(&ske.hint);
    body.extend_from_slice(&(ske.dh_p.len() as u16).to_be_bytes());
    body.extend_from_slice(&ske.dh_p);
    body.extend_from_slice(&(ske.dh_g.len() as u16).to_be_bytes());
    body.extend_from_slice(&ske.dh_g);
    body.extend_from_slice(&(ske.dh_ys.len() as u16).to_be_bytes());
    body.extend_from_slice(&ske.dh_ys);
    wrap_handshake(HandshakeType::ServerKeyExchange, &body)
}

/// Encode an ECDHE_PSK ServerKeyExchange message (wrapped with handshake header).
pub fn encode_server_key_exchange_ecdhe_psk(ske: &ServerKeyExchangeEcdhePsk) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + ske.hint.len() + 4 + ske.public_key.len());
    body.extend_from_slice(&(ske.hint.len() as u16).to_be_bytes());
    body.extend_from_slice(&ske.hint);
    body.push(3); // curve_type = named_curve
    body.extend_from_slice(&ske.named_curve.to_be_bytes());
    body.push(ske.public_key.len() as u8);
    body.extend_from_slice(&ske.public_key);
    wrap_handshake(HandshakeType::ServerKeyExchange, &body)
}

/// Decode a PSK ClientKeyExchange body.
pub fn decode_client_key_exchange_psk(body: &[u8]) -> Result<ClientKeyExchangePsk, TlsError> {
    if body.len() < 2 {
        return Err(TlsError::HandshakeFailed("PSK CKE too short".into()));
    }
    let id_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + id_len {
        return Err(TlsError::HandshakeFailed(
            "PSK CKE identity truncated".into(),
        ));
    }
    Ok(ClientKeyExchangePsk {
        identity: body[2..2 + id_len].to_vec(),
    })
}

/// Decode a DHE_PSK ClientKeyExchange body.
pub fn decode_client_key_exchange_dhe_psk(
    body: &[u8],
) -> Result<ClientKeyExchangeDhePsk, TlsError> {
    if body.len() < 2 {
        return Err(TlsError::HandshakeFailed("DHE_PSK CKE too short".into()));
    }
    let mut off = 0;
    let id_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + id_len + 2 {
        return Err(TlsError::HandshakeFailed(
            "DHE_PSK CKE identity truncated".into(),
        ));
    }
    let identity = body[off..off + id_len].to_vec();
    off += id_len;
    let yc_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + yc_len {
        return Err(TlsError::HandshakeFailed("DHE_PSK CKE Yc truncated".into()));
    }
    let dh_yc = body[off..off + yc_len].to_vec();
    Ok(ClientKeyExchangeDhePsk { identity, dh_yc })
}

/// Decode an ECDHE_PSK ClientKeyExchange body.
pub fn decode_client_key_exchange_ecdhe_psk(
    body: &[u8],
) -> Result<ClientKeyExchangeEcdhePsk, TlsError> {
    if body.len() < 2 {
        return Err(TlsError::HandshakeFailed("ECDHE_PSK CKE too short".into()));
    }
    let mut off = 0;
    let id_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + id_len + 1 {
        return Err(TlsError::HandshakeFailed(
            "ECDHE_PSK CKE identity truncated".into(),
        ));
    }
    let identity = body[off..off + id_len].to_vec();
    off += id_len;
    let point_len = body[off] as usize;
    off += 1;
    if body.len() < off + point_len {
        return Err(TlsError::HandshakeFailed(
            "ECDHE_PSK CKE point truncated".into(),
        ));
    }
    let public_key = body[off..off + point_len].to_vec();
    Ok(ClientKeyExchangeEcdhePsk {
        identity,
        public_key,
    })
}

/// Decode an RSA_PSK ClientKeyExchange body.
pub fn decode_client_key_exchange_rsa_psk(
    body: &[u8],
) -> Result<ClientKeyExchangeRsaPsk, TlsError> {
    if body.len() < 2 {
        return Err(TlsError::HandshakeFailed("RSA_PSK CKE too short".into()));
    }
    let mut off = 0;
    let id_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + id_len + 2 {
        return Err(TlsError::HandshakeFailed(
            "RSA_PSK CKE identity truncated".into(),
        ));
    }
    let identity = body[off..off + id_len].to_vec();
    off += id_len;
    let enc_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + enc_len {
        return Err(TlsError::HandshakeFailed(
            "RSA_PSK CKE encrypted_pms truncated".into(),
        ));
    }
    let encrypted_pms = body[off..off + enc_len].to_vec();
    Ok(ClientKeyExchangeRsaPsk {
        identity,
        encrypted_pms,
    })
}

/// Decode an ECDHE_PSK ServerKeyExchange body (hint + unsigned ECDHE params).
pub fn decode_server_key_exchange_ecdhe_psk(
    body: &[u8],
) -> Result<ServerKeyExchangeEcdhePsk, TlsError> {
    if body.len() < 2 {
        return Err(TlsError::HandshakeFailed("ECDHE_PSK SKE too short".into()));
    }
    let mut off = 0;
    // hint
    let hint_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + hint_len + 4 {
        return Err(TlsError::HandshakeFailed(
            "ECDHE_PSK SKE hint truncated".into(),
        ));
    }
    let hint = body[off..off + hint_len].to_vec();
    off += hint_len;
    // curve_type (must be 3 = named_curve)
    let curve_type = body[off];
    if curve_type != 3 {
        return Err(TlsError::HandshakeFailed(format!(
            "unsupported curve type: {curve_type} (expected 3=named_curve)"
        )));
    }
    off += 1;
    let named_curve = u16::from_be_bytes([body[off], body[off + 1]]);
    off += 2;
    if off >= body.len() {
        return Err(TlsError::HandshakeFailed(
            "ECDHE_PSK SKE point truncated".into(),
        ));
    }
    let point_len = body[off] as usize;
    off += 1;
    if body.len() < off + point_len {
        return Err(TlsError::HandshakeFailed(
            "ECDHE_PSK SKE point data truncated".into(),
        ));
    }
    let public_key = body[off..off + point_len].to_vec();
    Ok(ServerKeyExchangeEcdhePsk {
        hint,
        named_curve,
        public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_server_key_exchange_roundtrip() {
        let ske = ServerKeyExchange {
            curve_type: 3,
            named_curve: 0x0017,        // secp256r1
            public_key: vec![0x04; 65], // uncompressed P-256 point
            signature_algorithm: SignatureScheme::RSA_PKCS1_SHA256,
            signature: vec![0xAA; 128],
        };

        let encoded = encode_server_key_exchange(&ske);
        // Parse header
        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::ServerKeyExchange);

        let decoded = decode_server_key_exchange(body).unwrap();
        assert_eq!(decoded.curve_type, 3);
        assert_eq!(decoded.named_curve, 0x0017);
        assert_eq!(decoded.public_key, vec![0x04; 65]);
        assert_eq!(
            decoded.signature_algorithm,
            SignatureScheme::RSA_PKCS1_SHA256
        );
        assert_eq!(decoded.signature, vec![0xAA; 128]);
    }

    #[test]
    fn test_encode_decode_client_key_exchange_roundtrip() {
        let cke = ClientKeyExchange {
            public_key: vec![0x04; 65],
        };

        let encoded = encode_client_key_exchange(&cke);
        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::ClientKeyExchange);

        let decoded = decode_client_key_exchange(body).unwrap();
        assert_eq!(decoded.public_key, vec![0x04; 65]);
    }

    #[test]
    fn test_encode_server_hello_done() {
        let encoded = encode_server_hello_done();
        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::ServerHelloDone);
        assert!(body.is_empty());
    }

    #[test]
    fn test_encode_decode_certificate12_roundtrip() {
        let cert = Certificate12 {
            certificate_list: vec![vec![0x30, 0x82, 0x01, 0x00], vec![0x30, 0x82, 0x02, 0x00]],
        };

        let encoded = encode_certificate12(&cert);
        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::Certificate);

        let decoded = decode_certificate12(body).unwrap();
        assert_eq!(decoded.certificate_list.len(), 2);
        assert_eq!(decoded.certificate_list[0], vec![0x30, 0x82, 0x01, 0x00]);
        assert_eq!(decoded.certificate_list[1], vec![0x30, 0x82, 0x02, 0x00]);
    }

    #[test]
    fn test_encode_decode_finished12() {
        let verify_data = vec![0xAA; 12];
        let encoded = encode_finished12(&verify_data);

        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::Finished);

        let decoded = decode_finished12(body).unwrap();
        assert_eq!(decoded, verify_data);
    }

    #[test]
    fn test_encode_change_cipher_spec() {
        let ccs = encode_change_cipher_spec();
        assert_eq!(ccs, vec![0x01]);
    }

    #[test]
    fn test_server_key_exchange_signed_params_construction() {
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];
        let params = build_ske_params(3, 0x0017, &[0x04; 65]);

        let signed_data = build_ske_signed_data(&client_random, &server_random, &params);
        // 32 + 32 + (1 + 2 + 1 + 65) = 133
        assert_eq!(signed_data.len(), 32 + 32 + 1 + 2 + 1 + 65);
        assert_eq!(&signed_data[..32], &[0x01u8; 32]);
        assert_eq!(&signed_data[32..64], &[0x02u8; 32]);
        assert_eq!(signed_data[64], 3); // curve_type
        assert_eq!(&signed_data[65..67], &[0x00, 0x17]); // named_curve
        assert_eq!(signed_data[67], 65); // point_len
    }

    #[test]
    fn test_decode_server_key_exchange_invalid() {
        // Too short
        assert!(decode_server_key_exchange(&[]).is_err());
        assert!(decode_server_key_exchange(&[3, 0, 0x17]).is_err());

        // Wrong curve type
        assert!(decode_server_key_exchange(&[2, 0, 0x17, 1, 0x04, 0x04, 0x01, 0, 0]).is_err());
    }

    #[test]
    fn test_decode_finished12_wrong_length() {
        assert!(decode_finished12(&[0xAA; 11]).is_err());
        assert!(decode_finished12(&[0xAA; 13]).is_err());
        assert!(decode_finished12(&[0xAA; 12]).is_ok());
    }

    #[test]
    fn test_encode_decode_certificate_request12_roundtrip() {
        let cr = CertificateRequest12 {
            cert_types: vec![1, 64], // rsa_sign, ecdsa_sign
            sig_hash_algs: vec![
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                SignatureScheme::RSA_PSS_RSAE_SHA256,
            ],
            ca_names: vec![],
        };

        let encoded = encode_certificate_request12(&cr);
        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::CertificateRequest);

        let decoded = decode_certificate_request12(body).unwrap();
        assert_eq!(decoded.cert_types, vec![1, 64]);
        assert_eq!(decoded.sig_hash_algs.len(), 2);
        assert_eq!(
            decoded.sig_hash_algs[0],
            SignatureScheme::ECDSA_SECP256R1_SHA256
        );
        assert_eq!(
            decoded.sig_hash_algs[1],
            SignatureScheme::RSA_PSS_RSAE_SHA256
        );
        assert!(decoded.ca_names.is_empty());
    }

    #[test]
    fn test_encode_decode_certificate_request12_with_ca_names() {
        let dn1 = vec![0x30, 0x0A, 0x31, 0x08]; // fake DER DN
        let dn2 = vec![0x30, 0x0C, 0x31, 0x0A, 0x30, 0x08];
        let cr = CertificateRequest12 {
            cert_types: vec![1],
            sig_hash_algs: vec![SignatureScheme::RSA_PKCS1_SHA256],
            ca_names: vec![dn1.clone(), dn2.clone()],
        };

        let encoded = encode_certificate_request12(&cr);
        let (_, body, _) = crate::handshake::codec::parse_handshake_header(&encoded).unwrap();

        let decoded = decode_certificate_request12(body).unwrap();
        assert_eq!(decoded.ca_names.len(), 2);
        assert_eq!(decoded.ca_names[0], dn1);
        assert_eq!(decoded.ca_names[1], dn2);
    }

    #[test]
    fn test_decode_certificate_request12_empty_error() {
        assert!(decode_certificate_request12(&[]).is_err());
    }

    #[test]
    fn test_encode_decode_certificate_verify12_roundtrip() {
        let cv = CertificateVerify12 {
            sig_algorithm: SignatureScheme::ECDSA_SECP256R1_SHA256,
            signature: vec![0xAB; 70],
        };

        let encoded = encode_certificate_verify12(&cv);
        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::CertificateVerify);

        let decoded = decode_certificate_verify12(body).unwrap();
        assert_eq!(
            decoded.sig_algorithm,
            SignatureScheme::ECDSA_SECP256R1_SHA256
        );
        assert_eq!(decoded.signature, cv.signature);
    }

    #[test]
    fn test_decode_certificate_verify12_too_short() {
        assert!(decode_certificate_verify12(&[0x04, 0x03]).is_err());
    }

    #[test]
    fn test_encode_decode_new_session_ticket12_roundtrip() {
        let ticket = vec![0xAB; 128];
        let encoded = encode_new_session_ticket12(3600, &ticket);

        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::NewSessionTicket);

        let (lifetime, decoded_ticket) = decode_new_session_ticket12(body).unwrap();
        assert_eq!(lifetime, 3600);
        assert_eq!(decoded_ticket, ticket);
    }

    #[test]
    fn test_decode_new_session_ticket12_too_short() {
        assert!(decode_new_session_ticket12(&[0x00; 5]).is_err());
    }

    #[test]
    fn test_decode_new_session_ticket12_empty_ticket() {
        let (lifetime, ticket) =
            decode_new_session_ticket12(&[0x00, 0x00, 0x0E, 0x10, 0x00, 0x00]).unwrap();
        assert_eq!(lifetime, 3600);
        assert!(ticket.is_empty());
    }

    #[test]
    fn test_encode_decode_dhe_ske_roundtrip() {
        let ske = ServerKeyExchangeDhe {
            dh_p: vec![0xFF; 256],  // 2048-bit prime
            dh_g: vec![0x02],       // generator = 2
            dh_ys: vec![0xAA; 256], // public value
            signature_algorithm: SignatureScheme::RSA_PSS_RSAE_SHA256,
            signature: vec![0xBB; 256],
        };

        let encoded = encode_server_key_exchange_dhe(&ske);
        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::ServerKeyExchange);

        let decoded = decode_server_key_exchange_dhe(body).unwrap();
        assert_eq!(decoded.dh_p, ske.dh_p);
        assert_eq!(decoded.dh_g, ske.dh_g);
        assert_eq!(decoded.dh_ys, ske.dh_ys);
        assert_eq!(
            decoded.signature_algorithm,
            SignatureScheme::RSA_PSS_RSAE_SHA256
        );
        assert_eq!(decoded.signature, ske.signature);
    }

    #[test]
    fn test_encode_decode_rsa_cke_roundtrip() {
        let cke = ClientKeyExchangeRsa {
            encrypted_pms: vec![0xCC; 256],
        };

        let encoded = encode_client_key_exchange_rsa(&cke);
        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::ClientKeyExchange);

        let decoded = decode_client_key_exchange_rsa(body).unwrap();
        assert_eq!(decoded.encrypted_pms, cke.encrypted_pms);
    }

    #[test]
    fn test_encode_decode_dhe_cke_roundtrip() {
        let cke = ClientKeyExchangeDhe {
            dh_yc: vec![0xDD; 256],
        };

        let encoded = encode_client_key_exchange_dhe(&cke);
        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::ClientKeyExchange);

        let decoded = decode_client_key_exchange_dhe(body).unwrap();
        assert_eq!(decoded.dh_yc, cke.dh_yc);
    }

    #[test]
    fn test_build_dhe_ske_params() {
        let p = vec![0xFF; 8];
        let g = vec![0x02];
        let ys = vec![0xAA; 8];
        let params = build_dhe_ske_params(&p, &g, &ys);
        // 2 + 8 + 2 + 1 + 2 + 8 = 23
        assert_eq!(params.len(), 23);
        assert_eq!(&params[0..2], &[0x00, 0x08]); // p_len
        assert_eq!(&params[2..10], &[0xFF; 8]); // p
        assert_eq!(&params[10..12], &[0x00, 0x01]); // g_len
        assert_eq!(params[12], 0x02); // g
        assert_eq!(&params[13..15], &[0x00, 0x08]); // ys_len
        assert_eq!(&params[15..23], &[0xAA; 8]); // ys
    }

    #[test]
    fn test_build_psk_pms() {
        let other_secret = vec![0x01, 0x02, 0x03, 0x04];
        let psk = vec![0xAA, 0xBB, 0xCC];
        let pms = build_psk_pms(&other_secret, &psk);
        // Format: uint16(len(other_secret)) || other_secret || uint16(len(psk)) || psk
        // = 2 + 4 + 2 + 3 = 11 bytes
        assert_eq!(pms.len(), 11);
        assert_eq!(&pms[0..2], &[0x00, 0x04]); // other_secret length
        assert_eq!(&pms[2..6], &[0x01, 0x02, 0x03, 0x04]); // other_secret
        assert_eq!(&pms[6..8], &[0x00, 0x03]); // psk length
        assert_eq!(&pms[8..11], &[0xAA, 0xBB, 0xCC]); // psk
    }

    #[test]
    fn test_build_psk_pms_plain() {
        // Plain PSK: other_secret is all zeros with the same length as psk
        let psk = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let other_secret = vec![0x00; psk.len()];
        let pms = build_psk_pms(&other_secret, &psk);
        // = 2 + 4 + 2 + 4 = 12 bytes
        assert_eq!(pms.len(), 12);
        assert_eq!(&pms[0..2], &[0x00, 0x04]); // other_secret length
        assert_eq!(&pms[2..6], &[0x00, 0x00, 0x00, 0x00]); // zeros
        assert_eq!(&pms[6..8], &[0x00, 0x04]); // psk length
        assert_eq!(&pms[8..12], &[0xDE, 0xAD, 0xBE, 0xEF]); // psk
    }

    #[test]
    fn test_encode_decode_psk_hint_ske_roundtrip() {
        let ske = ServerKeyExchangePskHint {
            hint: b"my_psk_hint".to_vec(),
        };

        let encoded = encode_server_key_exchange_psk_hint(&ske);
        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::ServerKeyExchange);

        let decoded = decode_server_key_exchange_psk_hint(body).unwrap();
        assert_eq!(decoded.hint, ske.hint);
    }

    #[test]
    fn test_encode_decode_dhe_psk_ske_roundtrip() {
        let ske = ServerKeyExchangeDhePsk {
            hint: b"dhe_psk_hint".to_vec(),
            dh_p: vec![0xFF; 128],
            dh_g: vec![0x02],
            dh_ys: vec![0xAA; 128],
        };

        let encoded = encode_server_key_exchange_dhe_psk(&ske);
        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::ServerKeyExchange);

        let decoded = decode_server_key_exchange_dhe_psk(body).unwrap();
        assert_eq!(decoded.hint, ske.hint);
        assert_eq!(decoded.dh_p, ske.dh_p);
        assert_eq!(decoded.dh_g, ske.dh_g);
        assert_eq!(decoded.dh_ys, ske.dh_ys);
    }

    #[test]
    fn test_encode_decode_ecdhe_psk_ske_roundtrip() {
        let ske = ServerKeyExchangeEcdhePsk {
            hint: b"ecdhe_psk_hint".to_vec(),
            named_curve: 0x0017, // secp256r1
            public_key: vec![0x04; 65],
        };

        let encoded = encode_server_key_exchange_ecdhe_psk(&ske);
        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::ServerKeyExchange);

        let decoded = decode_server_key_exchange_ecdhe_psk(body).unwrap();
        assert_eq!(decoded.hint, ske.hint);
        assert_eq!(decoded.named_curve, 0x0017);
        assert_eq!(decoded.public_key, ske.public_key);
    }

    #[test]
    fn test_encode_decode_psk_cke_roundtrip() {
        let cke = ClientKeyExchangePsk {
            identity: b"client_psk_identity".to_vec(),
        };

        let encoded = encode_client_key_exchange_psk(&cke);
        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::ClientKeyExchange);

        let decoded = decode_client_key_exchange_psk(body).unwrap();
        assert_eq!(decoded.identity, cke.identity);
    }

    #[test]
    fn test_encode_decode_dhe_psk_cke_roundtrip() {
        let cke = ClientKeyExchangeDhePsk {
            identity: b"dhe_psk_id".to_vec(),
            dh_yc: vec![0xDD; 128],
        };

        let encoded = encode_client_key_exchange_dhe_psk(&cke);
        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::ClientKeyExchange);

        let decoded = decode_client_key_exchange_dhe_psk(body).unwrap();
        assert_eq!(decoded.identity, cke.identity);
        assert_eq!(decoded.dh_yc, cke.dh_yc);
    }

    #[test]
    fn test_encode_decode_ecdhe_psk_cke_roundtrip() {
        let cke = ClientKeyExchangeEcdhePsk {
            identity: b"ecdhe_psk_id".to_vec(),
            public_key: vec![0x04; 65],
        };

        let encoded = encode_client_key_exchange_ecdhe_psk(&cke);
        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::ClientKeyExchange);

        let decoded = decode_client_key_exchange_ecdhe_psk(body).unwrap();
        assert_eq!(decoded.identity, cke.identity);
        assert_eq!(decoded.public_key, cke.public_key);
    }

    #[test]
    fn test_encode_decode_rsa_psk_cke_roundtrip() {
        let cke = ClientKeyExchangeRsaPsk {
            identity: b"rsa_psk_id".to_vec(),
            encrypted_pms: vec![0xCC; 256],
        };

        let encoded = encode_client_key_exchange_rsa_psk(&cke);
        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::ClientKeyExchange);

        let decoded = decode_client_key_exchange_rsa_psk(body).unwrap();
        assert_eq!(decoded.identity, cke.identity);
        assert_eq!(decoded.encrypted_pms, cke.encrypted_pms);
    }

    #[test]
    fn test_encode_decode_certificate_status12_roundtrip() {
        let ocsp_response = vec![0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB, 0xCC];
        let encoded = encode_certificate_status12(&ocsp_response);

        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::CertificateStatus);

        let decoded = decode_certificate_status12(body).unwrap();
        assert_eq!(decoded, ocsp_response);
    }

    #[test]
    fn test_encode_certificate_status12_wire_format() {
        let ocsp_response = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let encoded = encode_certificate_status12(&ocsp_response);

        // Handshake header: type(1) + length(3) = 4 bytes
        // Body: status_type(1) + response_length(3) + response(4) = 8 bytes
        // Total = 12 bytes
        assert_eq!(encoded.len(), 12);
        assert_eq!(encoded[0], 22); // HandshakeType::CertificateStatus
                                    // Body length = 8
        assert_eq!(&encoded[1..4], &[0x00, 0x00, 0x08]);
        // status_type = ocsp(1)
        assert_eq!(encoded[4], 0x01);
        // response length = 4
        assert_eq!(&encoded[5..8], &[0x00, 0x00, 0x04]);
        // response data
        assert_eq!(&encoded[8..12], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_decode_certificate_status12_too_short() {
        assert!(decode_certificate_status12(&[]).is_err());
        assert!(decode_certificate_status12(&[0x01, 0x00]).is_err());
        assert!(decode_certificate_status12(&[0x01, 0x00, 0x00]).is_err());
    }

    #[test]
    fn test_decode_certificate_status12_unsupported_type() {
        // status_type = 2 (not ocsp)
        let data = vec![0x02, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        assert!(decode_certificate_status12(&data).is_err());
    }

    #[test]
    fn test_decode_certificate_status12_truncated_response() {
        // Claims 10 bytes but only has 4
        let data = vec![0x01, 0x00, 0x00, 0x0A, 0xDE, 0xAD, 0xBE, 0xEF];
        assert!(decode_certificate_status12(&data).is_err());
    }

    #[test]
    fn test_encode_decode_certificate_status12_empty_response() {
        let ocsp_response = vec![];
        let encoded = encode_certificate_status12(&ocsp_response);

        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::CertificateStatus);

        let decoded = decode_certificate_status12(body).unwrap();
        assert!(decoded.is_empty());
    }
}
