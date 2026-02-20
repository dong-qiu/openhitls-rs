//! TLCP (GM/T 0024) handshake message encoding/decoding.
//!
//! - Double Certificate: signing cert chain + encryption cert
//! - ECC static ClientKeyExchange: SM2-encrypted premaster secret
//! - ECC static ServerKeyExchange: signature over enc cert
//! - ECDHE ServerKeyExchange: reuses TLS 1.2 format (codec12.rs)

use crate::crypt::SignatureScheme;
use crate::handshake::codec::{read_u24, wrap_handshake};
use crate::handshake::HandshakeType;
use hitls_types::TlsError;

// ---------------------------------------------------------------------------
// Double Certificate
// ---------------------------------------------------------------------------

/// TLCP double certificate: signing cert chain + encryption cert.
///
/// In the wire format, all certs are in a single certificate_list.
/// Convention: sign_chain[0..n-1] then enc_cert as the last entry.
#[derive(Debug, Clone)]
pub struct TlcpCertificateMessage {
    /// Signing certificate chain (leaf first, then intermediates).
    pub sign_chain: Vec<Vec<u8>>,
    /// Encryption certificate (DER-encoded).
    pub enc_cert: Vec<u8>,
}

/// Encode a TLCP double-certificate message.
///
/// The wire format is identical to TLS 1.2 Certificate but the last
/// entry is the encryption certificate.
pub fn encode_tlcp_certificate(msg: &TlcpCertificateMessage) -> Vec<u8> {
    let total_len: usize =
        msg.sign_chain.iter().map(|c| 3 + c.len()).sum::<usize>() + 3 + msg.enc_cert.len();

    let mut body = Vec::with_capacity(3 + total_len);
    // certificate_list length (3 bytes)
    body.push((total_len >> 16) as u8);
    body.push((total_len >> 8) as u8);
    body.push(total_len as u8);

    // Signing chain certs
    for cert_data in &msg.sign_chain {
        let len = cert_data.len();
        body.push((len >> 16) as u8);
        body.push((len >> 8) as u8);
        body.push(len as u8);
        body.extend_from_slice(cert_data);
    }

    // Encryption cert (last entry)
    let len = msg.enc_cert.len();
    body.push((len >> 16) as u8);
    body.push((len >> 8) as u8);
    body.push(len as u8);
    body.extend_from_slice(&msg.enc_cert);

    wrap_handshake(HandshakeType::Certificate, &body)
}

/// Decode a TLCP double-certificate message.
///
/// Expects at least 2 certificates: sign cert(s) + enc cert.
/// The last certificate is the encryption cert; all others are the signing chain.
pub fn decode_tlcp_certificate(body: &[u8]) -> Result<TlcpCertificateMessage, TlsError> {
    if body.len() < 3 {
        return Err(TlsError::HandshakeFailed(
            "TLCP Certificate too short".into(),
        ));
    }

    let total_len = read_u24(body) as usize;
    if body.len() < 3 + total_len {
        return Err(TlsError::HandshakeFailed(
            "TLCP Certificate body truncated".into(),
        ));
    }

    let mut all_certs = Vec::new();
    let mut offset = 3;
    let end = 3 + total_len;

    while offset < end {
        if offset + 3 > end {
            return Err(TlsError::HandshakeFailed(
                "TLCP Certificate entry truncated".into(),
            ));
        }
        let cert_len = read_u24(&body[offset..]) as usize;
        offset += 3;
        if offset + cert_len > end {
            return Err(TlsError::HandshakeFailed(
                "TLCP Certificate data truncated".into(),
            ));
        }
        all_certs.push(body[offset..offset + cert_len].to_vec());
        offset += cert_len;
    }

    if all_certs.len() < 2 {
        return Err(TlsError::HandshakeFailed(
            "TLCP Certificate requires at least 2 certs (sign + enc)".into(),
        ));
    }

    let enc_cert = all_certs.pop().unwrap();
    let sign_chain = all_certs;

    Ok(TlcpCertificateMessage {
        sign_chain,
        enc_cert,
    })
}

// ---------------------------------------------------------------------------
// ECC Static ServerKeyExchange
// ---------------------------------------------------------------------------

/// ECC static ServerKeyExchange: signature over enc cert.
///
/// ```text
/// sig_algorithm(2) || sig_length(2) || signature
/// ```
///
/// The signed data is: `client_random(32) || server_random(32) || enc_cert_der`.
#[derive(Debug, Clone)]
pub struct EccServerKeyExchange {
    pub signature_algorithm: SignatureScheme,
    pub signature: Vec<u8>,
}

/// Build the data to be signed for ECC static ServerKeyExchange.
///
/// ```text
/// signed_data = client_random(32) || server_random(32) || enc_cert_der
/// ```
pub fn build_ecc_ske_signed_data(
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    enc_cert_der: &[u8],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(64 + enc_cert_der.len());
    data.extend_from_slice(client_random);
    data.extend_from_slice(server_random);
    data.extend_from_slice(enc_cert_der);
    data
}

/// Encode an ECC static ServerKeyExchange message.
pub fn encode_ecc_server_key_exchange(ske: &EccServerKeyExchange) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + ske.signature.len());
    body.extend_from_slice(&ske.signature_algorithm.0.to_be_bytes());
    body.extend_from_slice(&(ske.signature.len() as u16).to_be_bytes());
    body.extend_from_slice(&ske.signature);
    wrap_handshake(HandshakeType::ServerKeyExchange, &body)
}

/// Decode an ECC static ServerKeyExchange message body.
pub fn decode_ecc_server_key_exchange(body: &[u8]) -> Result<EccServerKeyExchange, TlsError> {
    if body.len() < 4 {
        return Err(TlsError::HandshakeFailed(
            "ECC ServerKeyExchange too short".into(),
        ));
    }

    let sig_alg = u16::from_be_bytes([body[0], body[1]]);
    let sig_len = u16::from_be_bytes([body[2], body[3]]) as usize;

    if body.len() < 4 + sig_len {
        return Err(TlsError::HandshakeFailed(
            "ECC ServerKeyExchange signature truncated".into(),
        ));
    }

    Ok(EccServerKeyExchange {
        signature_algorithm: SignatureScheme(sig_alg),
        signature: body[4..4 + sig_len].to_vec(),
    })
}

// ---------------------------------------------------------------------------
// ECC Static ClientKeyExchange
// ---------------------------------------------------------------------------

/// ECC static ClientKeyExchange: SM2-encrypted premaster secret.
///
/// ```text
/// length(2) || sm2_encrypted_premaster
/// ```
#[derive(Debug, Clone)]
pub struct EccClientKeyExchange {
    pub encrypted_premaster: Vec<u8>,
}

/// Encode an ECC static ClientKeyExchange message.
pub fn encode_ecc_client_key_exchange(cke: &EccClientKeyExchange) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + cke.encrypted_premaster.len());
    body.extend_from_slice(&(cke.encrypted_premaster.len() as u16).to_be_bytes());
    body.extend_from_slice(&cke.encrypted_premaster);
    wrap_handshake(HandshakeType::ClientKeyExchange, &body)
}

/// Decode an ECC static ClientKeyExchange message body.
pub fn decode_ecc_client_key_exchange(body: &[u8]) -> Result<EccClientKeyExchange, TlsError> {
    if body.len() < 2 {
        return Err(TlsError::HandshakeFailed(
            "ECC ClientKeyExchange too short".into(),
        ));
    }

    let len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + len {
        return Err(TlsError::HandshakeFailed(
            "ECC ClientKeyExchange data truncated".into(),
        ));
    }

    Ok(EccClientKeyExchange {
        encrypted_premaster: body[2..2 + len].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_tlcp_certificate_roundtrip() {
        let msg = TlcpCertificateMessage {
            sign_chain: vec![vec![0x30, 0x82, 0x01, 0x00]],
            enc_cert: vec![0x30, 0x82, 0x02, 0x00],
        };

        let encoded = encode_tlcp_certificate(&msg);
        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::Certificate);

        let decoded = decode_tlcp_certificate(body).unwrap();
        assert_eq!(decoded.sign_chain.len(), 1);
        assert_eq!(decoded.sign_chain[0], vec![0x30, 0x82, 0x01, 0x00]);
        assert_eq!(decoded.enc_cert, vec![0x30, 0x82, 0x02, 0x00]);
    }

    #[test]
    fn test_decode_tlcp_certificate_sign_plus_enc() {
        let msg = TlcpCertificateMessage {
            sign_chain: vec![
                vec![0x30; 10], // sign leaf
                vec![0x31; 20], // sign intermediate
            ],
            enc_cert: vec![0x32; 15],
        };

        let encoded = encode_tlcp_certificate(&msg);
        let (_, body, _) = crate::handshake::codec::parse_handshake_header(&encoded).unwrap();

        let decoded = decode_tlcp_certificate(body).unwrap();
        assert_eq!(decoded.sign_chain.len(), 2);
        assert_eq!(decoded.sign_chain[0], vec![0x30; 10]);
        assert_eq!(decoded.sign_chain[1], vec![0x31; 20]);
        assert_eq!(decoded.enc_cert, vec![0x32; 15]);
    }

    #[test]
    fn test_single_cert_error() {
        // Only 1 cert → should fail (need at least sign + enc)
        let mut body = Vec::new();
        let cert = vec![0x30; 10];
        let total_len = 3 + cert.len();
        body.push((total_len >> 16) as u8);
        body.push((total_len >> 8) as u8);
        body.push(total_len as u8);
        body.push((cert.len() >> 16) as u8);
        body.push((cert.len() >> 8) as u8);
        body.push(cert.len() as u8);
        body.extend_from_slice(&cert);

        assert!(decode_tlcp_certificate(&body).is_err());
    }

    #[test]
    fn test_encode_decode_ecc_client_key_exchange() {
        let cke = EccClientKeyExchange {
            encrypted_premaster: vec![0xAA; 128],
        };

        let encoded = encode_ecc_client_key_exchange(&cke);
        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::ClientKeyExchange);

        let decoded = decode_ecc_client_key_exchange(body).unwrap();
        assert_eq!(decoded.encrypted_premaster, vec![0xAA; 128]);
    }

    #[test]
    fn test_encode_decode_ecc_server_key_exchange() {
        let ske = EccServerKeyExchange {
            signature_algorithm: SignatureScheme::SM2_SM3,
            signature: vec![0xBB; 64],
        };

        let encoded = encode_ecc_server_key_exchange(&ske);
        let (msg_type, body, _) =
            crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        assert_eq!(msg_type, HandshakeType::ServerKeyExchange);

        let decoded = decode_ecc_server_key_exchange(body).unwrap();
        assert_eq!(decoded.signature_algorithm, SignatureScheme::SM2_SM3);
        assert_eq!(decoded.signature, vec![0xBB; 64]);
    }

    #[test]
    fn test_ecdhe_ske_with_sm2_curve() {
        // ECDHE SKE reuses codec12::ServerKeyExchange with named_curve = 0x0041
        use crate::handshake::codec12::{
            decode_server_key_exchange, encode_server_key_exchange, ServerKeyExchange,
        };

        let ske = ServerKeyExchange {
            curve_type: 3,
            named_curve: 0x0041, // SM2P256
            public_key: vec![0x04; 65],
            signature_algorithm: SignatureScheme::SM2_SM3,
            signature: vec![0xCC; 72],
        };

        let encoded = encode_server_key_exchange(&ske);
        let (_, body, _) = crate::handshake::codec::parse_handshake_header(&encoded).unwrap();
        let decoded = decode_server_key_exchange(body).unwrap();

        assert_eq!(decoded.named_curve, 0x0041);
        assert_eq!(decoded.signature_algorithm, SignatureScheme::SM2_SM3);
    }

    #[test]
    fn test_ecc_ske_signed_data() {
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];
        let enc_cert = vec![0x30; 100];

        let data = build_ecc_ske_signed_data(&client_random, &server_random, &enc_cert);
        assert_eq!(data.len(), 32 + 32 + 100);
        assert_eq!(&data[..32], &[0x01u8; 32]);
        assert_eq!(&data[32..64], &[0x02u8; 32]);
        assert_eq!(&data[64..], &[0x30u8; 100]);
    }

    // -------------------------------------------------------
    // Testing-Phase 88: codec_tlcp error path tests
    // -------------------------------------------------------

    #[test]
    fn test_decode_tlcp_certificate_too_short() {
        // Less than 3 bytes → error
        assert!(decode_tlcp_certificate(&[0x00]).is_err());
        assert!(decode_tlcp_certificate(&[0x00, 0x00]).is_err());
        assert!(decode_tlcp_certificate(&[]).is_err());
    }

    #[test]
    fn test_decode_tlcp_certificate_body_truncated() {
        // total_len says 100 but body only has 3 bytes
        let body = vec![0x00, 0x00, 0x64]; // total_len = 100
        assert!(decode_tlcp_certificate(&body).is_err());
    }

    #[test]
    fn test_decode_tlcp_certificate_entry_truncated() {
        // Valid total_len, but cert entry length exceeds remaining data
        // total_len = 6 (one cert entry header of 3 saying len=100, but only 3 bytes left)
        let body = vec![
            0x00, 0x00, 0x06, // total_len = 6
            0x00, 0x00, 0x64, // cert_len = 100, but only 3 bytes follow
            0x30, 0x30, 0x30,
        ];
        assert!(decode_tlcp_certificate(&body).is_err());
    }

    #[test]
    fn test_decode_ecc_server_key_exchange_too_short() {
        // Less than 4 bytes → error
        assert!(decode_ecc_server_key_exchange(&[0x00, 0x00]).is_err());
        assert!(decode_ecc_server_key_exchange(&[0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn test_decode_ecc_server_key_exchange_sig_truncated() {
        // Header says sig_len=64 but only 4 bytes of signature follow
        let mut body = vec![0x00, 0x00]; // sig_alg
        body.extend_from_slice(&(64u16).to_be_bytes()); // sig_len = 64
        body.extend_from_slice(&[0xAA; 4]); // only 4 bytes, not 64
        assert!(decode_ecc_server_key_exchange(&body).is_err());
    }

    #[test]
    fn test_decode_ecc_client_key_exchange_too_short() {
        // Less than 2 bytes → error
        assert!(decode_ecc_client_key_exchange(&[0x00]).is_err());
        assert!(decode_ecc_client_key_exchange(&[]).is_err());
    }

    #[test]
    fn test_decode_ecc_client_key_exchange_data_truncated() {
        // Length says 128 but only 10 bytes follow
        let mut body = vec![];
        body.extend_from_slice(&(128u16).to_be_bytes());
        body.extend_from_slice(&[0xBB; 10]);
        assert!(decode_ecc_client_key_exchange(&body).is_err());
    }
}
