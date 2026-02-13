//! CMS EncryptedData (RFC 5652 section 6).
//!
//! Provides symmetric-key encryption and decryption of CMS EncryptedData
//! messages using a pre-shared key. This is the simplest CMS content type
//! — no key management (unlike EnvelopedData with RSA/KEK).

use hitls_types::PkiError;
use hitls_utils::asn1::{Decoder, Encoder};
use hitls_utils::oid::known;

use super::enveloped::{CmsEncryptionAlg, EncryptedContentInfo};
use super::{
    cerr, enc_explicit_ctx, enc_int, enc_octet, enc_oid, enc_seq, AlgorithmIdentifier,
    CmsContentType, CmsMessage,
};

// ── EncryptedData structure ─────────────────────────────────────────

/// CMS EncryptedData (RFC 5652 §6).
///
/// ```text
/// EncryptedData ::= SEQUENCE {
///   version               CMSVersion,
///   encryptedContentInfo  EncryptedContentInfo
/// }
/// ```
#[derive(Debug, Clone)]
pub struct EncryptedData {
    pub version: u32,
    pub encrypted_content_info: EncryptedContentInfo,
}

// ── Encryption / Decryption ─────────────────────────────────────────

impl CmsMessage {
    /// Encrypt data using a pre-shared symmetric key (EncryptedData).
    ///
    /// The key length must match the algorithm:
    /// - `Aes128Gcm`: 16 bytes
    /// - `Aes256Gcm`: 32 bytes
    pub fn encrypt_symmetric(
        data: &[u8],
        key: &[u8],
        alg: CmsEncryptionAlg,
    ) -> Result<Self, PkiError> {
        if key.len() != alg.key_len() {
            return Err(cerr(&format!(
                "key length {} does not match algorithm (expected {})",
                key.len(),
                alg.key_len()
            )));
        }

        // Generate random 12-byte nonce for GCM
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|e| cerr(&format!("getrandom: {e}")))?;

        // Encrypt content with AES-GCM
        let ciphertext = hitls_crypto::modes::gcm::gcm_encrypt(key, &nonce, &[], data)
            .map_err(PkiError::from)?;

        // Build content encryption algorithm identifier (OID + nonce param)
        let nonce_param = enc_octet(&nonce);
        let content_enc_alg = AlgorithmIdentifier {
            oid: alg.oid().to_der_value(),
            params: Some(nonce_param),
        };

        let eci = EncryptedContentInfo {
            content_type: known::pkcs7_data().to_der_value(),
            content_encryption_algorithm: content_enc_alg,
            encrypted_content: Some(ciphertext),
        };

        let ed = EncryptedData {
            version: 0,
            encrypted_content_info: eci,
        };

        let encoded = encode_encrypted_data_cms(&ed);

        Ok(CmsMessage {
            content_type: CmsContentType::EncryptedData,
            signed_data: None,
            enveloped_data: None,
            encrypted_data: Some(ed),
            digested_data: None,
            raw: encoded,
        })
    }

    /// Decrypt an EncryptedData message using the pre-shared symmetric key.
    pub fn decrypt_symmetric(&self, key: &[u8]) -> Result<Vec<u8>, PkiError> {
        let ed = self
            .encrypted_data
            .as_ref()
            .ok_or_else(|| cerr("not EncryptedData"))?;

        let eci = &ed.encrypted_content_info;
        let ciphertext = eci
            .encrypted_content
            .as_ref()
            .ok_or_else(|| cerr("no encrypted content"))?;

        // Extract nonce from algorithm params
        let params = eci
            .content_encryption_algorithm
            .params
            .as_ref()
            .ok_or_else(|| cerr("no content encryption params (nonce)"))?;
        let mut nonce_dec = Decoder::new(params);
        let nonce = nonce_dec
            .read_octet_string()
            .map_err(|e| cerr(&format!("nonce parse: {e}")))?;

        // Decrypt with AES-GCM
        hitls_crypto::modes::gcm::gcm_decrypt(key, nonce, &[], ciphertext).map_err(PkiError::from)
    }
}

// ── Encoding ────────────────────────────────────────────────────────

fn encode_algorithm_identifier(alg: &AlgorithmIdentifier) -> Vec<u8> {
    let mut inner = enc_oid(&alg.oid);
    if let Some(params) = &alg.params {
        inner.extend_from_slice(params);
    }
    enc_seq(&inner)
}

fn encode_encrypted_content_info(eci: &EncryptedContentInfo) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&enc_oid(&eci.content_type));
    inner.extend_from_slice(&encode_algorithm_identifier(
        &eci.content_encryption_algorithm,
    ));
    if let Some(content) = &eci.encrypted_content {
        // [0] IMPLICIT OCTET STRING
        let mut e = Encoder::new();
        e.write_tlv(0x80, content); // CONTEXT_SPECIFIC | PRIMITIVE | 0
        inner.extend_from_slice(&e.finish());
    }
    enc_seq(&inner)
}

fn encode_encrypted_data(ed: &EncryptedData) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&enc_int(&[ed.version as u8]));
    inner.extend_from_slice(&encode_encrypted_content_info(&ed.encrypted_content_info));
    enc_seq(&inner)
}

fn encode_encrypted_data_cms(ed: &EncryptedData) -> Vec<u8> {
    let ed_encoded = encode_encrypted_data(ed);
    let ctx0 = enc_explicit_ctx(0, &ed_encoded);
    let mut ci_inner = enc_oid(&known::pkcs7_encrypted_data().to_der_value());
    ci_inner.extend_from_slice(&ctx0);
    enc_seq(&ci_inner)
}

// ── Parsing ─────────────────────────────────────────────────────────

fn parse_algorithm_identifier(dec: &mut Decoder) -> Result<AlgorithmIdentifier, PkiError> {
    let mut seq = dec
        .read_sequence()
        .map_err(|e| cerr(&format!("AlgId: {e}")))?;
    let oid = seq
        .read_oid()
        .map_err(|e| cerr(&format!("alg OID: {e}")))?
        .to_vec();
    let params = if !seq.is_empty() {
        Some(seq.remaining().to_vec())
    } else {
        None
    };
    Ok(AlgorithmIdentifier { oid, params })
}

fn parse_encrypted_content_info(dec: &mut Decoder) -> Result<EncryptedContentInfo, PkiError> {
    let mut seq = dec
        .read_sequence()
        .map_err(|e| cerr(&format!("EncCI: {e}")))?;

    let content_type = seq
        .read_oid()
        .map_err(|e| cerr(&format!("EncCI type: {e}")))?
        .to_vec();

    let content_encryption_algorithm = parse_algorithm_identifier(&mut seq)?;

    // [0] IMPLICIT OCTET STRING OPTIONAL
    let encrypted_content = seq
        .try_read_context_specific(0, false)
        .map_err(|e| cerr(&format!("EncCI [0]: {e}")))?
        .map(|tlv| tlv.value.to_vec());

    Ok(EncryptedContentInfo {
        content_type,
        content_encryption_algorithm,
        encrypted_content,
    })
}

fn bytes_to_u32(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |acc, &b| acc.wrapping_shl(8) | b as u32)
}

pub(crate) fn parse_encrypted_data(data: &[u8]) -> Result<EncryptedData, PkiError> {
    let mut dec = Decoder::new(data);
    let mut ed = dec
        .read_sequence()
        .map_err(|e| cerr(&format!("EncryptedData: {e}")))?;

    let version = bytes_to_u32(
        ed.read_integer()
            .map_err(|e| cerr(&format!("ED ver: {e}")))?,
    );

    let encrypted_content_info = parse_encrypted_content_info(&mut ed)?;

    Ok(EncryptedData {
        version,
        encrypted_content_info,
    })
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cms_encrypted_data_roundtrip() {
        let key = [0x42u8; 16]; // AES-128
        let plaintext = b"Hello, CMS EncryptedData!";

        let cms =
            CmsMessage::encrypt_symmetric(plaintext, &key, CmsEncryptionAlg::Aes128Gcm).unwrap();
        assert_eq!(cms.content_type, CmsContentType::EncryptedData);
        assert!(cms.encrypted_data.is_some());

        let decrypted = cms.decrypt_symmetric(&key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cms_encrypted_data_aes256() {
        let key = [0xAA; 32]; // AES-256
        let plaintext = b"Testing AES-256-GCM EncryptedData symmetric encryption";

        let cms =
            CmsMessage::encrypt_symmetric(plaintext, &key, CmsEncryptionAlg::Aes256Gcm).unwrap();

        let ed = cms.encrypted_data.as_ref().unwrap();
        assert_eq!(ed.version, 0);

        let decrypted = cms.decrypt_symmetric(&key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cms_encrypted_data_wrong_key() {
        let key = [0x42u8; 16];
        let wrong_key = [0x99u8; 16];
        let plaintext = b"This should fail with wrong key";

        let cms =
            CmsMessage::encrypt_symmetric(plaintext, &key, CmsEncryptionAlg::Aes128Gcm).unwrap();

        let result = cms.decrypt_symmetric(&wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_cms_encrypted_data_parse_encode() {
        let key = [0xBB; 32];
        let plaintext = b"Parse-encode roundtrip for EncryptedData";

        let cms =
            CmsMessage::encrypt_symmetric(plaintext, &key, CmsEncryptionAlg::Aes256Gcm).unwrap();

        // Parse back from DER
        let parsed = CmsMessage::from_der(&cms.raw).unwrap();
        assert_eq!(parsed.content_type, CmsContentType::EncryptedData);
        assert!(parsed.encrypted_data.is_some());

        let ed = parsed.encrypted_data.as_ref().unwrap();
        assert_eq!(ed.version, 0);
        assert!(ed.encrypted_content_info.encrypted_content.is_some());

        // Decrypt from re-parsed message
        let decrypted = parsed.decrypt_symmetric(&key).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
