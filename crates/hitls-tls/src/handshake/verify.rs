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
    // Phase T98 — RFC 8446 §4.4.3: in TLS 1.3 CertificateVerify, the
    // following signature scheme codepoints are reserved for cert
    // chain signatures (`signature_algorithms_cert`) only and MUST
    // NOT appear here. tlsfuzzer's `test-tls13-certificate-verify.py`
    // probes a long list of forbidden codepoints expecting an
    // `illegal_parameter` alert.
    //
    // - rsa_pkcs1_*  (PKCS#1 v1.5 — RFC 8446 §4.4.3 explicitly
    //   forbids this in CV; only allowed for cert-chain sigs.)
    // - any *_sha1 / *_sha224 hash variant (SHA-1 / SHA-224
    //   deprecated — RFC 8446 §4.2.3 / §B.3.1.3.)
    //
    // Reason string contains the literal `"illegal_parameter"` so
    // `alert::tls_error_to_alert` routes it to the matching alert.
    if is_pkcs1_or_legacy_hash(scheme) {
        return Err(TlsError::HandshakeFailed(format!(
            "CertificateVerify: signature scheme 0x{:04x} is not allowed \
             for in-handshake CertificateVerify (RFC 8446 §4.4.3 / §4.2.3 — \
             alert: illegal_parameter)",
            scheme.0
        )));
    }
    // Phase T99 — rsa_pss_pss_* requires a cert with the id-RSASSA-PSS
    // SPKI OID (RFC 5756 / RFC 8446 §4.2.3). We don't accept PSS-OID
    // certs today, so any peer offering these schemes against our RSA
    // (id-rsaEncryption) cert is using a scheme/cert pairing the spec
    // forbids — alert is `illegal_parameter`.
    if matches!(
        scheme,
        SignatureScheme::RSA_PSS_PSS_SHA256
            | SignatureScheme::RSA_PSS_PSS_SHA384
            | SignatureScheme::RSA_PSS_PSS_SHA512
    ) {
        return Err(TlsError::HandshakeFailed(format!(
            "CertificateVerify: rsa_pss_pss_* (0x{:04x}) requires id-RSASSA-PSS \
             cert SPKI OID; we do not issue or accept PSS-only RSA certs \
             (RFC 8446 §4.2.3 — alert: illegal_parameter)",
            scheme.0
        )));
    }

    let content = build_verify_content(transcript_hash, is_server);
    let spki = &cert.public_key;

    // RFC 8446 §4.2.3 / §4.4.3: the CertificateVerify scheme MUST be
    // compatible with the peer certificate's public key. A scheme whose
    // algorithm / curve doesn't match the cert key (e.g. an
    // ecdsa_secp384r1_sha384 signature against a P-256 cert, or any ECDSA
    // scheme against an Ed25519 cert) is `illegal_parameter` — distinct from
    // a well-formed-but-wrong signature, which is `decrypt_error` below.
    {
        use hitls_utils::oid::known;
        let alg = spki.algorithm_oid.as_slice();
        let params = spki.algorithm_params.as_deref();
        let is_ec = alg == known::ec_public_key().to_der_value().as_slice();
        let compatible = match scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                is_ec && params == Some(known::prime256v1().to_der_value().as_slice())
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                is_ec && params == Some(known::secp384r1().to_der_value().as_slice())
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                is_ec && params == Some(known::secp521r1().to_der_value().as_slice())
            }
            SignatureScheme::ED25519 => alg == known::ed25519().to_der_value().as_slice(),
            SignatureScheme::ED448 => alg == known::ed448().to_der_value().as_slice(),
            SignatureScheme::RSA_PSS_RSAE_SHA256
            | SignatureScheme::RSA_PSS_RSAE_SHA384
            | SignatureScheme::RSA_PSS_RSAE_SHA512 => {
                alg == known::rsa_encryption().to_der_value().as_slice()
            }
            // Any other scheme is handled (rejected) by the match below.
            _ => true,
        };
        if !compatible {
            return Err(TlsError::HandshakeFailed(format!(
                "CertificateVerify: signature scheme 0x{:04x} is incompatible \
                 with the certificate public key (RFC 8446 §4.2.3 — \
                 alert: illegal_parameter)",
                scheme.0
            )));
        }
    }

    let ok = match scheme {
        SignatureScheme::RSA_PSS_RSAE_SHA256 => {
            let digest = compute_sha256(&content)?;
            verify_rsa_pss(
                spki,
                &digest,
                signature,
                hitls_crypto::rsa::RsaHashAlg::Sha256,
            )?
        }
        SignatureScheme::RSA_PSS_RSAE_SHA384 => {
            // Phase T95 — pair the digest with the matching PSS hash.
            // Pre-T95 verify_rsa_pss called `RsaPadding::Pss` (SHA-256
            // only) which would reject the 48-byte digest.
            let digest = compute_sha384(&content)?;
            verify_rsa_pss(
                spki,
                &digest,
                signature,
                hitls_crypto::rsa::RsaHashAlg::Sha384,
            )?
        }
        SignatureScheme::RSA_PSS_RSAE_SHA512 => {
            let digest = compute_sha512(&content)?;
            verify_rsa_pss(
                spki,
                &digest,
                signature,
                hitls_crypto::rsa::RsaHashAlg::Sha512,
            )?
        }
        SignatureScheme::ECDSA_SECP256R1_SHA256 => {
            let digest = compute_sha256(&content)?;
            // A malformed signature makes `verify_ecdsa` return `Err`; treat
            // that as a verification failure (→ decrypt_error below), not an
            // internal error. The scheme/curve was already confirmed to match
            // the cert key above, so the only variable input is the signature.
            verify_ecdsa(spki, EccCurveId::NistP256, &digest, signature).unwrap_or(false)
        }
        SignatureScheme::ECDSA_SECP384R1_SHA384 => {
            let digest = compute_sha384(&content)?;
            verify_ecdsa(spki, EccCurveId::NistP384, &digest, signature).unwrap_or(false)
        }
        SignatureScheme::ECDSA_SECP521R1_SHA512 => {
            let digest = compute_sha512(&content)?;
            verify_ecdsa(spki, EccCurveId::NistP521, &digest, signature).unwrap_or(false)
        }
        SignatureScheme::ED25519 => {
            // Ed25519 signs the raw content, not a hash
            verify_ed25519(spki, &content, signature).unwrap_or(false)
        }
        SignatureScheme::ED448 => {
            // Ed448 signs the raw content, not a hash
            verify_ed448(spki, &content, signature).unwrap_or(false)
        }
        _ => {
            // Phase T99 — schemes outside our supported set are a
            // protocol violation per RFC 8446 §4.4.3 (the peer signed
            // with a scheme we never advertised in `signature_algorithms`).
            // alert: illegal_parameter.
            return Err(TlsError::HandshakeFailed(format!(
                "CertificateVerify: unsupported signature scheme 0x{:04x} \
                 (not advertised in our signature_algorithms — \
                 RFC 8446 §4.4.3 — alert: illegal_parameter)",
                scheme.0
            )));
        }
    };

    if ok {
        Ok(())
    } else {
        // Phase T99 — RFC 8446 §6.2: "decrypt_error: A handshake (not
        // record layer) cryptographic operation failed, including being
        // unable to correctly verify a signature ...". The reason text
        // contains the substring `"decrypt_error"` so `tls_error_to_alert`
        // routes it to the matching wire alert.
        Err(TlsError::HandshakeFailed(
            "CertificateVerify signature verification failed \
             (RFC 8446 §6.2 — alert: decrypt_error)"
                .into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

fn compute_hash(
    mut hasher: impl hitls_crypto::provider::Digest,
    data: &[u8],
) -> Result<Vec<u8>, TlsError> {
    hasher.update(data).map_err(TlsError::CryptoError)?;
    let mut out = vec![0u8; hasher.output_size()];
    hasher.finish(&mut out).map_err(TlsError::CryptoError)?;
    Ok(out)
}

fn compute_sha256(data: &[u8]) -> Result<Vec<u8>, TlsError> {
    compute_hash(hitls_crypto::sha2::Sha256::new(), data)
}

fn compute_sha384(data: &[u8]) -> Result<Vec<u8>, TlsError> {
    compute_hash(hitls_crypto::sha2::Sha384::new(), data)
}

fn compute_sha512(data: &[u8]) -> Result<Vec<u8>, TlsError> {
    compute_hash(hitls_crypto::sha2::Sha512::new(), data)
}

/// Phase T98 — true if `scheme` is one of the codepoints reserved for
/// cert-chain signatures only (RFC 8446 §4.4.3) or uses a deprecated
/// hash (SHA-1 / SHA-224 per RFC 8446 §4.2.3 / §B.3.1.3).
///
/// The list mirrors the IANA SignatureScheme registry segments:
///   - `rsa_pkcs1_*` (0x0401..=0x0601, plus the legacy SHA-1/MD5
///     codepoints 0x0101 / 0x0201) — allowed in cert chain, NOT in CV.
///   - any *_sha1 codepoint (0x0203 ecdsa_sha1, 0x0201 rsa_pkcs1_sha1,
///     0x0202 dsa_sha1) — deprecated hash.
///   - SHA-224 variants (0x0303 / 0x0301 / 0x0302) — never widely
///     deployed and dropped from RFC 8446's recommended list.
fn is_pkcs1_or_legacy_hash(scheme: SignatureScheme) -> bool {
    matches!(
        scheme.0,
        // rsa_pkcs1_sha256 / sha384 / sha512 — explicit RFC 8446 §4.4.3 ban for CV.
        0x0401 | 0x0501 | 0x0601
        // *_sha1 family
        | 0x0201 // rsa_pkcs1_sha1
        | 0x0202 // dsa_sha1 (non-IANA; some impls)
        | 0x0203 // ecdsa_sha1
        // SHA-224 family
        | 0x0301 | 0x0302 | 0x0303
        // MD5
        | 0x0101
    )
}

// ---------------------------------------------------------------------------
// Algorithm-specific verification
// ---------------------------------------------------------------------------

fn verify_rsa_pss(
    spki: &SubjectPublicKeyInfo,
    digest: &[u8],
    signature: &[u8],
    alg: hitls_crypto::rsa::RsaHashAlg,
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
    // Phase T95 — verify_pss threads the hash algorithm through M' /
    // MGF1; the legacy `verify(RsaPadding::Pss, ...)` path is SHA-256 only.
    rsa_pub
        .verify_pss(digest, signature, alg)
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
        make_cert_with_spki_p(algorithm_oid, None, public_key)
    }

    // EC keys carry the named-curve OID in `algorithm_params`; the
    // §4.2.3 scheme/key compatibility check requires it, so EC tests must
    // populate it (real certs always do).
    fn make_cert_with_spki_p(
        algorithm_oid: Vec<u8>,
        algorithm_params: Option<Vec<u8>>,
        public_key: Vec<u8>,
    ) -> Certificate {
        Certificate {
            raw: Vec::new(),
            version: 3,
            serial_number: vec![0x01],
            issuer: hitls_pki::x509::DistinguishedName {
                entries: Vec::new(),
            },
            issuer_raw: Vec::new(),
            subject: hitls_pki::x509::DistinguishedName {
                entries: Vec::new(),
            },
            subject_raw: Vec::new(),
            not_before: 0,
            not_after: 0,
            public_key: SubjectPublicKeyInfo {
                algorithm_oid,
                algorithm_params,
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
        // P-256 OID: 1.2.840.10045.2.1 (ecPublicKey); curve prime256v1
        let cert = make_cert_with_spki_p(
            vec![0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
            Some(vec![0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
            pub_key,
        );

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
    fn test_verify_certificate_verify_scheme_cert_mismatch_illegal_parameter() {
        // RFC 8446 §4.2.3: a CV scheme whose curve doesn't match the cert key
        // (a P-256 cert with an ecdsa_secp384r1_sha384 scheme) is rejected with
        // illegal_parameter — before any signature math, so the signature bytes
        // are irrelevant.
        let kp = hitls_crypto::ecdsa::EcdsaKeyPair::generate(EccCurveId::NistP256).unwrap();
        let pub_key = kp.public_key_bytes().unwrap();
        let cert = make_cert_with_spki_p(
            vec![0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
            Some(vec![0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]), // prime256v1
            pub_key,
        );
        let err = verify_certificate_verify(
            &cert,
            SignatureScheme::ECDSA_SECP384R1_SHA384,
            &[0u8; 72],
            &[0xAA; 48],
            true,
        )
        .unwrap_err();
        assert!(
            matches!(&err, TlsError::HandshakeFailed(m) if m.contains("illegal_parameter")),
            "expected illegal_parameter, got {err:?}"
        );
    }

    #[test]
    fn test_verify_certificate_verify_ecdsa_p384_roundtrip() {
        let kp = hitls_crypto::ecdsa::EcdsaKeyPair::generate(EccCurveId::NistP384).unwrap();
        let pub_key = kp.public_key_bytes().unwrap();

        let transcript_hash = vec![0xBB; 48];
        let content = build_verify_content(&transcript_hash, true);
        let digest = compute_sha384(&content).unwrap();
        let signature = kp.sign(&digest).unwrap();

        let cert = make_cert_with_spki_p(
            vec![0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
            Some(vec![0x2b, 0x81, 0x04, 0x00, 0x22]),
            pub_key,
        );

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
    fn test_verify_certificate_verify_ecdsa_p521_roundtrip() {
        let kp = hitls_crypto::ecdsa::EcdsaKeyPair::generate(EccCurveId::NistP521).unwrap();
        let pub_key = kp.public_key_bytes().unwrap();

        let transcript_hash = vec![0xCC; 48];
        let content = build_verify_content(&transcript_hash, true);
        let digest = compute_sha512(&content).unwrap();
        let signature = kp.sign(&digest).unwrap();

        let cert = make_cert_with_spki_p(
            vec![0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
            Some(vec![0x2b, 0x81, 0x04, 0x00, 0x23]),
            pub_key,
        );

        verify_certificate_verify(
            &cert,
            SignatureScheme::ECDSA_SECP521R1_SHA512,
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

    #[test]
    fn test_verify_certificate_verify_ecdsa_p256_wrong_signature() {
        let kp = hitls_crypto::ecdsa::EcdsaKeyPair::generate(EccCurveId::NistP256).unwrap();
        let pub_key = kp.public_key_bytes().unwrap();

        let transcript_hash = vec![0xAA; 32];
        let content = build_verify_content(&transcript_hash, true);
        let digest = compute_sha256(&content).unwrap();
        let mut signature = kp.sign(&digest).unwrap();

        // Tamper with signature
        if let Some(last) = signature.last_mut() {
            *last ^= 0xFF;
        }

        let cert = make_cert_with_spki_p(
            vec![0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
            Some(vec![0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
            pub_key,
        );

        let result = verify_certificate_verify(
            &cert,
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            &signature,
            &transcript_hash,
            true,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_certificate_verify_ed25519_empty_signature() {
        let seed = vec![0x42; 32];
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(&seed).unwrap();
        let pub_key = kp.public_key().to_vec();

        let cert = make_cert_with_spki(vec![0x2b, 0x65, 0x70], pub_key);

        // Empty signature should produce an error, not a panic
        let result =
            verify_certificate_verify(&cert, SignatureScheme::ED25519, &[], &[0xAA; 32], true);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_certificate_verify_rsa_malformed_key() {
        // Non-DER garbage as RSA public_key → should fail with parse error
        let cert = make_cert_with_spki(
            vec![0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01], // RSA OID
            vec![0xDE, 0xAD, 0xBE, 0xEF],                               // garbage
        );

        let result = verify_certificate_verify(
            &cert,
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            &[0x00; 64],
            &[0xAA; 32],
            true,
        );
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("RSA") || err_msg.contains("parse"),
            "expected RSA parse error, got: {err_msg}"
        );
    }

    #[test]
    fn test_build_verify_content_deterministic() {
        let hash = vec![0xAA; 32];

        // Same inputs → identical output
        let content1 = build_verify_content(&hash, true);
        let content2 = build_verify_content(&hash, true);
        assert_eq!(content1, content2);

        // Different hash → different output
        let hash2 = vec![0xBB; 32];
        let content3 = build_verify_content(&hash2, true);
        assert_ne!(content1, content3);

        // Different is_server → different output
        let content4 = build_verify_content(&hash, false);
        assert_ne!(content1, content4);
    }

    #[test]
    fn test_verify_certificate_verify_ed25519_wrong_public_key() {
        // Generate keypair and sign
        let seed = vec![0x42; 32];
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(&seed).unwrap();

        let transcript_hash = vec![0xAA; 32];
        let content = build_verify_content(&transcript_hash, true);
        let signature = kp.sign(&content).unwrap();

        // Use a different keypair's public key for verification
        let other_seed = vec![0x99; 32];
        let other_kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(&other_seed).unwrap();
        let wrong_pub_key = other_kp.public_key().to_vec();

        let cert = make_cert_with_spki(vec![0x2b, 0x65, 0x70], wrong_pub_key);

        let result = verify_certificate_verify(
            &cert,
            SignatureScheme::ED25519,
            &signature,
            &transcript_hash,
            true,
        );
        assert!(result.is_err());
    }
}
