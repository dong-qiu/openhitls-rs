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
}
