//! Server-side CertificateVerify signing dispatch (RFC 8446 §4.4.3).

use crate::config::ServerPrivateKey;
use crate::crypt::SignatureScheme;
use crate::handshake::verify::build_verify_content;
use hitls_types::{EccCurveId, TlsError};

/// Select a signature scheme that matches the server's key type
/// and is present in the client's `signature_algorithms` list.
pub fn select_signature_scheme(
    key: &ServerPrivateKey,
    client_schemes: &[SignatureScheme],
) -> Result<SignatureScheme, TlsError> {
    let candidates: &[SignatureScheme] = match key {
        ServerPrivateKey::Ed25519(_) => &[SignatureScheme::ED25519],
        ServerPrivateKey::Ecdsa { curve_id, .. } => match *curve_id {
            EccCurveId::NistP256 => &[SignatureScheme::ECDSA_SECP256R1_SHA256],
            EccCurveId::NistP384 => &[SignatureScheme::ECDSA_SECP384R1_SHA384],
            _ => {
                return Err(TlsError::HandshakeFailed(
                    "unsupported ECDSA curve for signing".into(),
                ))
            }
        },
        ServerPrivateKey::Rsa { .. } => &[
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PSS_RSAE_SHA384,
            SignatureScheme::RSA_PSS_RSAE_SHA512,
        ],
        #[cfg(feature = "tlcp")]
        ServerPrivateKey::Sm2 { .. } => &[SignatureScheme::SM2_SM3],
    };

    for candidate in candidates {
        if client_schemes.contains(candidate) {
            return Ok(*candidate);
        }
    }

    Err(TlsError::HandshakeFailed(
        "no common signature scheme".into(),
    ))
}

/// Sign CertificateVerify content using a private key.
///
/// Builds the verify content (64 spaces || context || 0x00 || transcript_hash)
/// and dispatches to the appropriate crypto signing API.
/// `is_server` selects the context string ("server"/"client" CertificateVerify).
pub fn sign_certificate_verify(
    key: &ServerPrivateKey,
    scheme: SignatureScheme,
    transcript_hash: &[u8],
    is_server: bool,
) -> Result<Vec<u8>, TlsError> {
    let content = build_verify_content(transcript_hash, is_server);

    match key {
        ServerPrivateKey::Ed25519(seed) => {
            let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(seed)
                .map_err(TlsError::CryptoError)?;
            let sig = kp.sign(&content).map_err(TlsError::CryptoError)?;
            Ok(sig.to_vec())
        }
        ServerPrivateKey::Ecdsa {
            curve_id,
            private_key,
        } => {
            let digest = match scheme {
                SignatureScheme::ECDSA_SECP256R1_SHA256 => compute_sha256(&content)?,
                SignatureScheme::ECDSA_SECP384R1_SHA384 => compute_sha384(&content)?,
                _ => return Err(TlsError::HandshakeFailed("ECDSA scheme mismatch".into())),
            };
            let kp = hitls_crypto::ecdsa::EcdsaKeyPair::from_private_key(*curve_id, private_key)
                .map_err(TlsError::CryptoError)?;
            kp.sign(&digest).map_err(TlsError::CryptoError)
        }
        ServerPrivateKey::Rsa { n, d, e, p, q } => {
            let digest = match scheme {
                SignatureScheme::RSA_PSS_RSAE_SHA256 => compute_sha256(&content)?,
                SignatureScheme::RSA_PSS_RSAE_SHA384 => compute_sha384(&content)?,
                SignatureScheme::RSA_PSS_RSAE_SHA512 => compute_sha512(&content)?,
                _ => return Err(TlsError::HandshakeFailed("RSA scheme mismatch".into())),
            };
            let rsa_key = hitls_crypto::rsa::RsaPrivateKey::new(n, d, e, p, q)
                .map_err(TlsError::CryptoError)?;
            rsa_key
                .sign(hitls_crypto::rsa::RsaPadding::Pss, &digest)
                .map_err(TlsError::CryptoError)
        }
        #[cfg(feature = "tlcp")]
        ServerPrivateKey::Sm2 { private_key } => {
            // SM2 signing: SM3 hash of content, then SM2 sign
            let kp = hitls_crypto::sm2::Sm2KeyPair::from_private_key(private_key)
                .map_err(TlsError::CryptoError)?;
            kp.sign(&content).map_err(TlsError::CryptoError)
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_signature_scheme_ed25519() {
        let key = ServerPrivateKey::Ed25519(vec![0x42; 32]);
        let client_schemes = vec![
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::ED25519,
        ];
        let scheme = select_signature_scheme(&key, &client_schemes).unwrap();
        assert_eq!(scheme, SignatureScheme::ED25519);
    }

    #[test]
    fn test_select_signature_scheme_no_match() {
        let key = ServerPrivateKey::Ed25519(vec![0x42; 32]);
        let client_schemes = vec![SignatureScheme::RSA_PSS_RSAE_SHA256];
        assert!(select_signature_scheme(&key, &client_schemes).is_err());
    }

    #[test]
    fn test_sign_and_verify_ed25519_roundtrip() {
        // Use a fixed seed and derive the public key from it
        let seed = vec![0x42; 32];
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(&seed).unwrap();
        let pub_key_bytes = kp.public_key().to_vec();

        let server_key = ServerPrivateKey::Ed25519(seed);
        let transcript_hash = vec![0xAA; 32];

        // Sign
        let signature = sign_certificate_verify(
            &server_key,
            SignatureScheme::ED25519,
            &transcript_hash,
            true,
        )
        .unwrap();
        assert_eq!(signature.len(), 64);

        // Verify using the public key (same as verify.rs does)
        let content = build_verify_content(&transcript_hash, true);
        let verifier =
            hitls_crypto::ed25519::Ed25519KeyPair::from_public_key(&pub_key_bytes).unwrap();
        let ok = verifier.verify(&content, &signature).unwrap();
        assert!(ok);
    }
}
