//! TLS 1.2 handshake message encoding/decoding.
//!
//! Handles ServerKeyExchange, ClientKeyExchange, ServerHelloDone,
//! Certificate (TLS 1.2 format), and Finished (12-byte verify_data).

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

/// Encode a ServerHelloDone message (empty body).
pub fn encode_server_hello_done() -> Vec<u8> {
    wrap_handshake(HandshakeType::ServerHelloDone, &[])
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
}
