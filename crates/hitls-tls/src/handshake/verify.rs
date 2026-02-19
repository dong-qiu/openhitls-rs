//! TLS 1.3 CertificateVerify signature verification (RFC 8446 §4.4.3).

use crate::crypt::SignatureScheme;
use hitls_pki::x509::{Certificate, SubjectPublicKeyInfo};
use hitls_types::{EccCurveId, TlsError};
use hitls_utils::asn1::Decoder;

/// Context string for server CertificateVerify.
const SERVER_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";

/// Context string for client CertificateVerify.
const CLIENT_CONTEXT: &[u8] = b"TLS 1.3, client CertificateVerify";

/// Build the content to be signed/verified in CertificateVerify.
///
/// Format: 64 spaces || context_string || 0x00 || transcript_hash
pub fn build_verify_content(transcript_hash: &[u8], is_server: bool) -> Vec<u8> {
    let context = if is_server {
        SERVER_CONTEXT
    } else {
        CLIENT_CONTEXT
    };
    let mut content = Vec::with_capacity(64 + context.len() + 1 + transcript_hash.len());
    content.extend_from_slice(&[0x20u8; 64]); // 64 spaces
    content.extend_from_slice(context);
    content.push(0x00);
    content.extend_from_slice(transcript_hash);
    content
}

/// Verify a CertificateVerify signature.
///
/// Parses the certificate's public key, constructs the verify content
/// from the transcript hash, and verifies the signature using the appropriate
/// algorithm. `is_server` selects the context string.
pub fn verify_certificate_verify(
    cert: &Certificate,
    scheme: SignatureScheme,
    signature: &[u8],
    transcript_hash: &[u8],
    is_server: bool,
) -> Result<(), TlsError> {
    let content = build_verify_content(transcript_hash, is_server);
    let spki = &cert.public_key;

    let ok = match scheme {
        SignatureScheme::RSA_PSS_RSAE_SHA256 => {
            let digest = compute_sha256(&content)?;
            verify_rsa_pss(spki, &digest, signature)?
        }
        SignatureScheme::RSA_PSS_RSAE_SHA384 => {
            let digest = compute_sha384(&content)?;
            verify_rsa_pss(spki, &digest, signature)?
        }
        SignatureScheme::RSA_PSS_RSAE_SHA512 => {
            let digest = compute_sha512(&content)?;
            verify_rsa_pss(spki, &digest, signature)?
        }
        SignatureScheme::ECDSA_SECP256R1_SHA256 => {
            let digest = compute_sha256(&content)?;
            verify_ecdsa(spki, EccCurveId::NistP256, &digest, signature)?
        }
        SignatureScheme::ECDSA_SECP384R1_SHA384 => {
            let digest = compute_sha384(&content)?;
            verify_ecdsa(spki, EccCurveId::NistP384, &digest, signature)?
        }
        SignatureScheme::ED25519 => {
            // Ed25519 signs the raw content, not a hash
            verify_ed25519(spki, &content, signature)?
        }
        SignatureScheme::ED448 => {
            // Ed448 signs the raw content, not a hash
            verify_ed448(spki, &content, signature)?
        }
        _ => {
            return Err(TlsError::HandshakeFailed(format!(
                "unsupported signature scheme: 0x{:04x}",
                scheme.0
            )))
        }
    };

    if ok {
        Ok(())
    } else {
        Err(TlsError::HandshakeFailed(
            "CertificateVerify signature verification failed".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

fn compute_sha256(data: &[u8]) -> Result<Vec<u8>, TlsError> {
    let mut h = hitls_crypto::sha2::Sha256::new();
    h.update(data).map_err(TlsError::CryptoError)?;
    Ok(h.finish().map_err(TlsError::CryptoError)?.to_vec())
}

fn compute_sha384(data: &[u8]) -> Result<Vec<u8>, TlsError> {
    let mut h = hitls_crypto::sha2::Sha384::new();
    h.update(data).map_err(TlsError::CryptoError)?;
    Ok(h.finish().map_err(TlsError::CryptoError)?.to_vec())
}

fn compute_sha512(data: &[u8]) -> Result<Vec<u8>, TlsError> {
    let mut h = hitls_crypto::sha2::Sha512::new();
    h.update(data).map_err(TlsError::CryptoError)?;
    Ok(h.finish().map_err(TlsError::CryptoError)?.to_vec())
}

// ---------------------------------------------------------------------------
// Algorithm-specific verification
// ---------------------------------------------------------------------------

fn verify_rsa_pss(
    spki: &SubjectPublicKeyInfo,
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, TlsError> {
    // RSA SPKI public_key is DER: SEQUENCE { modulus INTEGER, exponent INTEGER }
    let mut key_dec = Decoder::new(&spki.public_key);
    let mut seq = key_dec
        .read_sequence()
        .map_err(|e| TlsError::HandshakeFailed(format!("RSA key parse: {e}")))?;
    let n = seq
        .read_integer()
        .map_err(|e| TlsError::HandshakeFailed(format!("RSA modulus parse: {e}")))?;
    let e = seq
        .read_integer()
        .map_err(|e| TlsError::HandshakeFailed(format!("RSA exponent parse: {e}")))?;

    let rsa_pub = hitls_crypto::rsa::RsaPublicKey::new(n, e).map_err(TlsError::CryptoError)?;
    rsa_pub
        .verify(hitls_crypto::rsa::RsaPadding::Pss, digest, signature)
        .map_err(TlsError::CryptoError)
}

fn verify_ecdsa(
    spki: &SubjectPublicKeyInfo,
    curve_id: EccCurveId,
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, TlsError> {
    let verifier = hitls_crypto::ecdsa::EcdsaKeyPair::from_public_key(curve_id, &spki.public_key)
        .map_err(TlsError::CryptoError)?;
    verifier
        .verify(digest, signature)
        .map_err(TlsError::CryptoError)
}

fn verify_ed25519(
    spki: &SubjectPublicKeyInfo,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, TlsError> {
    let verifier = hitls_crypto::ed25519::Ed25519KeyPair::from_public_key(&spki.public_key)
        .map_err(TlsError::CryptoError)?;
    verifier
        .verify(message, signature)
        .map_err(TlsError::CryptoError)
}

fn verify_ed448(
    spki: &SubjectPublicKeyInfo,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, TlsError> {
    let verifier = hitls_crypto::ed448::Ed448KeyPair::from_public_key(&spki.public_key)
        .map_err(TlsError::CryptoError)?;
    verifier
        .verify(message, signature)
        .map_err(TlsError::CryptoError)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_verify_content() {
        let transcript_hash = vec![0xAA; 32];
        let content = build_verify_content(&transcript_hash, true);

        // 64 spaces + "TLS 1.3, server CertificateVerify" + 0x00 + hash
        assert_eq!(&content[..64], &[0x20u8; 64]);
        assert_eq!(&content[64..64 + SERVER_CONTEXT.len()], SERVER_CONTEXT);
        assert_eq!(content[64 + SERVER_CONTEXT.len()], 0x00);
        assert_eq!(&content[64 + SERVER_CONTEXT.len() + 1..], &transcript_hash);

        let client_content = build_verify_content(&transcript_hash, false);
        assert_eq!(
            &client_content[64..64 + CLIENT_CONTEXT.len()],
            CLIENT_CONTEXT
        );
        // Server and client contexts differ in content (not length)
        assert_ne!(content, client_content);
    }

    #[test]
    fn test_build_verify_content_lengths() {
        // Server context string
        let hash32 = vec![0xBB; 32];
        let content = build_verify_content(&hash32, true);
        assert_eq!(content.len(), 64 + SERVER_CONTEXT.len() + 1 + 32);

        // Client context string
        let content_client = build_verify_content(&hash32, false);
        assert_eq!(content_client.len(), 64 + CLIENT_CONTEXT.len() + 1 + 32);

        // With 48-byte hash (SHA-384)
        let hash48 = vec![0xCC; 48];
        let content48 = build_verify_content(&hash48, true);
        assert_eq!(content48.len(), 64 + SERVER_CONTEXT.len() + 1 + 48);
    }

    #[test]
    fn test_build_verify_content_empty_hash() {
        let content = build_verify_content(&[], true);
        assert_eq!(content.len(), 64 + SERVER_CONTEXT.len() + 1);
        // Last byte is the 0x00 separator
        assert_eq!(content[content.len() - 1], 0x00);
    }

    /// Helper: build a minimal Certificate with only the public_key field populated.
    fn make_cert_with_spki(algorithm_oid: Vec<u8>, public_key: Vec<u8>) -> Certificate {
        Certificate {
            raw: Vec::new(),
            version: 3,
            serial_number: vec![0x01],
            issuer: hitls_pki::x509::DistinguishedName {
                entries: Vec::new(),
            },
            subject: hitls_pki::x509::DistinguishedName {
                entries: Vec::new(),
            },
            not_before: 0,
            not_after: 0,
            public_key: SubjectPublicKeyInfo {
                algorithm_oid,
                algorithm_params: None,
                public_key,
            },
            extensions: Vec::new(),
            tbs_raw: Vec::new(),
            signature_algorithm: Vec::new(),
            signature_params: None,
            signature_value: Vec::new(),
        }
    }

    #[test]
    fn test_verify_certificate_verify_ed25519_roundtrip() {
        // Generate Ed25519 keypair
        let seed = vec![0x42; 32];
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(&seed).unwrap();
        let pub_key = kp.public_key().to_vec();

        // Sign using the signing module
        let transcript_hash = vec![0xAA; 32];
        let content = build_verify_content(&transcript_hash, true);
        let signature = kp.sign(&content).unwrap();

        // Build cert with Ed25519 public key
        // Ed25519 OID: 1.3.101.112 → 06 03 2b 65 70
        let cert = make_cert_with_spki(vec![0x2b, 0x65, 0x70], pub_key);

        // Verify should succeed
        verify_certificate_verify(
            &cert,
            SignatureScheme::ED25519,
            &signature,
            &transcript_hash,
            true,
        )
        .unwrap();
    }

    #[test]
    fn test_verify_certificate_verify_ed25519_wrong_signature() {
        let seed = vec![0x42; 32];
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(&seed).unwrap();
        let pub_key = kp.public_key().to_vec();

        let transcript_hash = vec![0xAA; 32];
        let content = build_verify_content(&transcript_hash, true);
        let mut signature = kp.sign(&content).unwrap();

        // Tamper with signature
        signature[0] ^= 0xFF;

        let cert = make_cert_with_spki(vec![0x2b, 0x65, 0x70], pub_key);

        let result = verify_certificate_verify(
            &cert,
            SignatureScheme::ED25519,
            &signature,
            &transcript_hash,
            true,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_certificate_verify_ed25519_wrong_transcript() {
        let seed = vec![0x42; 32];
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(&seed).unwrap();
        let pub_key = kp.public_key().to_vec();

        let transcript_hash = vec![0xAA; 32];
        let content = build_verify_content(&transcript_hash, true);
        let signature = kp.sign(&content).unwrap();

        // Verify with different transcript hash should fail
        let wrong_hash = vec![0xBB; 32];
        let cert = make_cert_with_spki(vec![0x2b, 0x65, 0x70], pub_key);

        let result = verify_certificate_verify(
            &cert,
            SignatureScheme::ED25519,
            &signature,
            &wrong_hash,
            true,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_certificate_verify_ed25519_server_vs_client() {
        let seed = vec![0x42; 32];
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(&seed).unwrap();
        let pub_key = kp.public_key().to_vec();

        let transcript_hash = vec![0xAA; 32];
        // Sign as server
        let content = build_verify_content(&transcript_hash, true);
        let signature = kp.sign(&content).unwrap();

        let cert = make_cert_with_spki(vec![0x2b, 0x65, 0x70], pub_key);

        // Verify as client should fail (different context string)
        let result = verify_certificate_verify(
            &cert,
            SignatureScheme::ED25519,
            &signature,
            &transcript_hash,
            false, // client context
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_certificate_verify_ecdsa_p256_roundtrip() {
        // Generate ECDSA P-256 keypair
        let kp = hitls_crypto::ecdsa::EcdsaKeyPair::generate(EccCurveId::NistP256).unwrap();
        let pub_key = kp.public_key_bytes().unwrap();

        let transcript_hash = vec![0xAA; 32];
        let content = build_verify_content(&transcript_hash, true);
        let digest = compute_sha256(&content).unwrap();
        let signature = kp.sign(&digest).unwrap();

        // ECDSA public key for SPKI: uncompressed point
        // P-256 OID: 1.2.840.10045.2.1 (ecPublicKey)
        let cert = make_cert_with_spki(vec![0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01], pub_key);

        verify_certificate_verify(
            &cert,
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            &signature,
            &transcript_hash,
            true,
        )
        .unwrap();
    }

    #[test]
    fn test_verify_certificate_verify_ecdsa_p384_roundtrip() {
        let kp = hitls_crypto::ecdsa::EcdsaKeyPair::generate(EccCurveId::NistP384).unwrap();
        let pub_key = kp.public_key_bytes().unwrap();

        let transcript_hash = vec![0xBB; 48];
        let content = build_verify_content(&transcript_hash, true);
        let digest = compute_sha384(&content).unwrap();
        let signature = kp.sign(&digest).unwrap();

        let cert = make_cert_with_spki(vec![0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01], pub_key);

        verify_certificate_verify(
            &cert,
            SignatureScheme::ECDSA_SECP384R1_SHA384,
            &signature,
            &transcript_hash,
            true,
        )
        .unwrap();
    }

    #[test]
    fn test_verify_certificate_verify_unsupported_scheme() {
        let seed = vec![0x42; 32];
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(&seed).unwrap();
        let pub_key = kp.public_key().to_vec();

        let cert = make_cert_with_spki(vec![0x2b, 0x65, 0x70], pub_key);

        let result = verify_certificate_verify(
            &cert,
            SignatureScheme(0x0000), // unsupported
            &[0xAA; 64],
            &[0xBB; 32],
            true,
        );
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("unsupported signature scheme"));
    }

    #[test]
    fn test_verify_certificate_verify_ed448_roundtrip() {
        let kp = hitls_crypto::ed448::Ed448KeyPair::generate().unwrap();
        let pub_key = kp.public_key().to_vec();

        let transcript_hash = vec![0xCC; 48];
        let content = build_verify_content(&transcript_hash, true);
        let signature = kp.sign(&content).unwrap();

        // Ed448 OID: 1.3.101.113 → 06 03 2b 65 71
        let cert = make_cert_with_spki(vec![0x2b, 0x65, 0x71], pub_key);

        verify_certificate_verify(
            &cert,
            SignatureScheme::ED448,
            &signature,
            &transcript_hash,
            true,
        )
        .unwrap();
    }

    #[test]
    fn test_verify_certificate_verify_ed448_wrong_signature() {
        let kp = hitls_crypto::ed448::Ed448KeyPair::generate().unwrap();
        let pub_key = kp.public_key().to_vec();

        let transcript_hash = vec![0xCC; 48];
        let content = build_verify_content(&transcript_hash, true);
        let mut signature = kp.sign(&content).unwrap();
        signature[0] ^= 0xFF; // tamper

        let cert = make_cert_with_spki(vec![0x2b, 0x65, 0x71], pub_key);

        let result = verify_certificate_verify(
            &cert,
            SignatureScheme::ED448,
            &signature,
            &transcript_hash,
            true,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_certificate_verify_ed25519_client_context_roundtrip() {
        let seed = vec![0x99; 32];
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(&seed).unwrap();
        let pub_key = kp.public_key().to_vec();

        let transcript_hash = vec![0xDD; 32];
        // Sign with client context
        let content = build_verify_content(&transcript_hash, false);
        let signature = kp.sign(&content).unwrap();

        let cert = make_cert_with_spki(vec![0x2b, 0x65, 0x70], pub_key);

        // Verify with client context → should succeed
        verify_certificate_verify(
            &cert,
            SignatureScheme::ED25519,
            &signature,
            &transcript_hash,
            false,
        )
        .unwrap();
    }
}
