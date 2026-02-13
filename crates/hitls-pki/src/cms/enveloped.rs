//! CMS EnvelopedData (RFC 5652 section 6).
//!
//! Provides encryption and decryption of CMS EnvelopedData messages using
//! RSA OAEP key transport or AES key wrap for the content-encryption key.

use hitls_types::PkiError;
use hitls_utils::asn1::{tags, Decoder, Encoder};
use hitls_utils::oid::{known, Oid};

use super::{
    cerr, enc_explicit_ctx, enc_int, enc_octet, enc_oid, enc_seq, enc_set, enc_tlv,
    AlgorithmIdentifier, CmsContentType, CmsMessage,
};

// ── Types ────────────────────────────────────────────────────────────

/// Content encryption algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmsEncryptionAlg {
    /// AES-128-GCM (16-byte key).
    Aes128Gcm,
    /// AES-256-GCM (32-byte key).
    Aes256Gcm,
}

impl CmsEncryptionAlg {
    pub(crate) fn key_len(self) -> usize {
        match self {
            CmsEncryptionAlg::Aes128Gcm => 16,
            CmsEncryptionAlg::Aes256Gcm => 32,
        }
    }

    pub(crate) fn oid(self) -> Oid {
        match self {
            CmsEncryptionAlg::Aes128Gcm => known::aes128_gcm(),
            CmsEncryptionAlg::Aes256Gcm => known::aes256_gcm(),
        }
    }
}

/// Encrypted content info (RFC 5652 section 6.1).
#[derive(Debug, Clone)]
pub struct EncryptedContentInfo {
    /// Content type OID (usually id-data).
    pub content_type: Vec<u8>,
    /// Content encryption algorithm identifier.
    pub content_encryption_algorithm: AlgorithmIdentifier,
    /// Encrypted content bytes (ciphertext || tag for GCM).
    pub encrypted_content: Option<Vec<u8>>,
}

/// Key transport recipient info (RFC 5652 section 6.2.1).
#[derive(Debug, Clone)]
pub struct KeyTransRecipientInfo {
    pub version: u32,
    /// Recipient identifier (issuer + serial from cert).
    pub rid_issuer: Vec<u8>,
    pub rid_serial: Vec<u8>,
    /// Key encryption algorithm identifier.
    pub key_encryption_algorithm: AlgorithmIdentifier,
    /// Encrypted content-encryption key.
    pub encrypted_key: Vec<u8>,
}

/// KEK recipient info (RFC 5652 section 6.2.3).
#[derive(Debug, Clone)]
pub struct KekRecipientInfo {
    pub version: u32,
    /// KEK identifier (opaque octet string).
    pub kek_id: Vec<u8>,
    /// Key encryption algorithm identifier.
    pub key_encryption_algorithm: AlgorithmIdentifier,
    /// Wrapped content-encryption key.
    pub encrypted_key: Vec<u8>,
}

/// Recipient info (CHOICE).
#[derive(Debug, Clone)]
pub enum RecipientInfo {
    /// Key transport (RSA).
    KeyTransport(KeyTransRecipientInfo),
    /// Key encryption key (AES wrap).
    Kek(KekRecipientInfo),
}

/// CMS EnvelopedData structure.
#[derive(Debug, Clone)]
pub struct EnvelopedData {
    pub version: u32,
    pub recipient_infos: Vec<RecipientInfo>,
    pub encrypted_content_info: EncryptedContentInfo,
}

// ── Encryption ───────────────────────────────────────────────────────

impl CmsMessage {
    /// Encrypt data using RSA OAEP key transport.
    ///
    /// Generates a random content-encryption key (CEK), encrypts the data with
    /// AES-GCM, then wraps the CEK with the recipient's RSA public key using OAEP.
    pub fn encrypt_rsa(
        data: &[u8],
        recipient_cert_der: &[u8],
        alg: CmsEncryptionAlg,
    ) -> Result<Self, PkiError> {
        // Parse recipient certificate to get RSA public key
        let cert = crate::x509::Certificate::from_der(recipient_cert_der)
            .map_err(|e| cerr(&format!("cert parse: {e}")))?;

        // Extract RSA public key from SPKI
        let mut key_dec = Decoder::new(&cert.public_key.public_key);
        let mut key_seq = key_dec
            .read_sequence()
            .map_err(|e| cerr(&format!("RSA key seq: {e}")))?;
        let n = key_seq
            .read_integer()
            .map_err(|e| cerr(&format!("RSA n: {e}")))?;
        let e = key_seq
            .read_integer()
            .map_err(|e| cerr(&format!("RSA e: {e}")))?;

        let rsa_pub = hitls_crypto::rsa::RsaPublicKey::new(n, e).map_err(PkiError::from)?;

        // Generate random CEK
        let key_len = alg.key_len();
        let mut cek = vec![0u8; key_len];
        getrandom::getrandom(&mut cek).map_err(|e| cerr(&format!("getrandom CEK: {e}")))?;

        // Generate random nonce (12 bytes for GCM)
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|e| cerr(&format!("getrandom nonce: {e}")))?;

        // Encrypt content with AES-GCM (returns ciphertext || tag)
        let encrypted_content = hitls_crypto::modes::gcm::gcm_encrypt(&cek, &nonce, &[], data)
            .map_err(PkiError::from)?;

        // Encrypt CEK with RSA OAEP
        let encrypted_key = rsa_pub
            .encrypt(hitls_crypto::rsa::RsaPadding::Oaep, &cek)
            .map_err(PkiError::from)?;

        // Build recipient info
        let rid_issuer = super::extract_raw_issuer(recipient_cert_der)?;
        let ktri = KeyTransRecipientInfo {
            version: 0,
            rid_issuer,
            rid_serial: cert.serial_number.clone(),
            key_encryption_algorithm: AlgorithmIdentifier {
                oid: known::rsaes_oaep().to_der_value(),
                params: None,
            },
            encrypted_key,
        };

        // Build content encryption algorithm (OID + nonce as OCTET STRING param)
        let nonce_param = enc_octet(&nonce);
        let content_enc_alg = AlgorithmIdentifier {
            oid: alg.oid().to_der_value(),
            params: Some(nonce_param),
        };

        let eci = EncryptedContentInfo {
            content_type: known::pkcs7_data().to_der_value(),
            content_encryption_algorithm: content_enc_alg,
            encrypted_content: Some(encrypted_content),
        };

        let ed = EnvelopedData {
            version: 0,
            recipient_infos: vec![RecipientInfo::KeyTransport(ktri)],
            encrypted_content_info: eci,
        };

        let encoded = encode_enveloped_data_cms(&ed);

        Ok(CmsMessage {
            content_type: CmsContentType::EnvelopedData,
            signed_data: None,
            enveloped_data: Some(ed),
            encrypted_data: None,
            digested_data: None,
            raw: encoded,
        })
    }

    /// Encrypt data using AES key wrap for the CEK.
    ///
    /// Generates a random CEK, encrypts data with AES-GCM, then wraps the CEK
    /// with the provided key-encryption key using AES Key Wrap (RFC 3394).
    pub fn encrypt_kek(
        data: &[u8],
        kek: &[u8],
        kek_id: &[u8],
        alg: CmsEncryptionAlg,
    ) -> Result<Self, PkiError> {
        // Validate KEK length
        if kek.len() != 16 && kek.len() != 24 && kek.len() != 32 {
            return Err(cerr("KEK must be 16, 24, or 32 bytes"));
        }

        // Generate random CEK
        let key_len = alg.key_len();
        let mut cek = vec![0u8; key_len];
        getrandom::getrandom(&mut cek).map_err(|e| cerr(&format!("getrandom CEK: {e}")))?;

        // Generate random nonce (12 bytes for GCM)
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|e| cerr(&format!("getrandom nonce: {e}")))?;

        // Encrypt content with AES-GCM
        let encrypted_content = hitls_crypto::modes::gcm::gcm_encrypt(&cek, &nonce, &[], data)
            .map_err(PkiError::from)?;

        // Wrap CEK with AES key wrap
        let wrapped_key = hitls_crypto::modes::wrap::key_wrap(kek, &cek).map_err(PkiError::from)?;

        // Determine wrap algorithm OID based on KEK length
        let wrap_alg_oid = match kek.len() {
            16 => known::aes128_wrap().to_der_value(),
            // 24 bytes not in our OID list, use 256 wrap as fallback
            32 => known::aes256_wrap().to_der_value(),
            _ => known::aes256_wrap().to_der_value(),
        };

        let kekri = KekRecipientInfo {
            version: 4,
            kek_id: kek_id.to_vec(),
            key_encryption_algorithm: AlgorithmIdentifier {
                oid: wrap_alg_oid,
                params: None,
            },
            encrypted_key: wrapped_key,
        };

        let nonce_param = enc_octet(&nonce);
        let content_enc_alg = AlgorithmIdentifier {
            oid: alg.oid().to_der_value(),
            params: Some(nonce_param),
        };

        let eci = EncryptedContentInfo {
            content_type: known::pkcs7_data().to_der_value(),
            content_encryption_algorithm: content_enc_alg,
            encrypted_content: Some(encrypted_content),
        };

        let ed = EnvelopedData {
            version: 2,
            recipient_infos: vec![RecipientInfo::Kek(kekri)],
            encrypted_content_info: eci,
        };

        let encoded = encode_enveloped_data_cms(&ed);

        Ok(CmsMessage {
            content_type: CmsContentType::EnvelopedData,
            signed_data: None,
            enveloped_data: Some(ed),
            encrypted_data: None,
            digested_data: None,
            raw: encoded,
        })
    }

    /// Decrypt an EnvelopedData message using an RSA private key.
    ///
    /// Requires all RSA key components (n, d, e, p, q) as big-endian byte slices.
    pub fn decrypt_rsa(
        &self,
        n: &[u8],
        d: &[u8],
        e: &[u8],
        p: &[u8],
        q: &[u8],
    ) -> Result<Vec<u8>, PkiError> {
        let ed = self
            .enveloped_data
            .as_ref()
            .ok_or_else(|| cerr("not EnvelopedData"))?;

        // Find key transport recipient
        let ktri = ed
            .recipient_infos
            .iter()
            .find_map(|ri| match ri {
                RecipientInfo::KeyTransport(k) => Some(k),
                _ => None,
            })
            .ok_or_else(|| cerr("no KeyTransRecipientInfo found"))?;

        // Decrypt CEK using RSA OAEP
        let priv_key =
            hitls_crypto::rsa::RsaPrivateKey::new(n, d, e, p, q).map_err(PkiError::from)?;
        let cek = priv_key
            .decrypt(hitls_crypto::rsa::RsaPadding::Oaep, &ktri.encrypted_key)
            .map_err(PkiError::from)?;

        // Decrypt content
        decrypt_content(&ed.encrypted_content_info, &cek)
    }

    /// Decrypt an EnvelopedData message using a key-encryption key.
    pub fn decrypt_kek(&self, kek: &[u8]) -> Result<Vec<u8>, PkiError> {
        let ed = self
            .enveloped_data
            .as_ref()
            .ok_or_else(|| cerr("not EnvelopedData"))?;

        // Find KEK recipient
        let kekri = ed
            .recipient_infos
            .iter()
            .find_map(|ri| match ri {
                RecipientInfo::Kek(k) => Some(k),
                _ => None,
            })
            .ok_or_else(|| cerr("no KekRecipientInfo found"))?;

        // Unwrap CEK
        let cek = hitls_crypto::modes::wrap::key_unwrap(kek, &kekri.encrypted_key)
            .map_err(PkiError::from)?;

        // Decrypt content
        decrypt_content(&ed.encrypted_content_info, &cek)
    }
}

// ── Content decryption ───────────────────────────────────────────────

fn decrypt_content(eci: &EncryptedContentInfo, cek: &[u8]) -> Result<Vec<u8>, PkiError> {
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
    hitls_crypto::modes::gcm::gcm_decrypt(cek, nonce, &[], ciphertext).map_err(PkiError::from)
}

// ── Encoding ─────────────────────────────────────────────────────────

fn encode_algorithm_identifier(alg: &AlgorithmIdentifier) -> Vec<u8> {
    let mut inner = enc_oid(&alg.oid);
    if let Some(params) = &alg.params {
        inner.extend_from_slice(params);
    }
    enc_seq(&inner)
}

fn encode_key_trans_recipient_info(ktri: &KeyTransRecipientInfo) -> Vec<u8> {
    let mut inner = Vec::new();

    // version
    inner.extend_from_slice(&enc_int(&[ktri.version as u8]));

    // rid: IssuerAndSerialNumber SEQUENCE
    let mut ias_inner = Vec::new();
    ias_inner.extend_from_slice(&ktri.rid_issuer);
    ias_inner.extend_from_slice(&enc_int(&ktri.rid_serial));
    inner.extend_from_slice(&enc_seq(&ias_inner));

    // keyEncryptionAlgorithm
    inner.extend_from_slice(&encode_algorithm_identifier(&ktri.key_encryption_algorithm));

    // encryptedKey OCTET STRING
    inner.extend_from_slice(&enc_octet(&ktri.encrypted_key));

    enc_seq(&inner)
}

fn encode_kek_recipient_info(kekri: &KekRecipientInfo) -> Vec<u8> {
    let mut inner = Vec::new();

    // version
    inner.extend_from_slice(&enc_int(&[kekri.version as u8]));

    // kekid: KEKIdentifier SEQUENCE { keyIdentifier OCTET STRING }
    let kekid_inner = enc_octet(&kekri.kek_id);
    inner.extend_from_slice(&enc_seq(&kekid_inner));

    // keyEncryptionAlgorithm
    inner.extend_from_slice(&encode_algorithm_identifier(
        &kekri.key_encryption_algorithm,
    ));

    // encryptedKey OCTET STRING
    inner.extend_from_slice(&enc_octet(&kekri.encrypted_key));

    enc_seq(&inner)
}

fn encode_recipient_info(ri: &RecipientInfo) -> Vec<u8> {
    match ri {
        RecipientInfo::KeyTransport(ktri) => {
            // KeyTransRecipientInfo is the default CHOICE (no implicit tag)
            encode_key_trans_recipient_info(ktri)
        }
        RecipientInfo::Kek(kekri) => {
            // KEKRecipientInfo is [2] IMPLICIT
            let inner = encode_kek_recipient_info(kekri);
            // Re-tag: change SEQUENCE (0x30) to [2] CONSTRUCTED (0xA2)
            let mut result = inner;
            if !result.is_empty() {
                result[0] = tags::CONTEXT_SPECIFIC | tags::CONSTRUCTED | 2;
            }
            result
        }
    }
}

fn encode_encrypted_content_info(eci: &EncryptedContentInfo) -> Vec<u8> {
    let mut inner = Vec::new();

    // contentType OID
    inner.extend_from_slice(&enc_oid(&eci.content_type));

    // contentEncryptionAlgorithm AlgorithmIdentifier
    inner.extend_from_slice(&encode_algorithm_identifier(
        &eci.content_encryption_algorithm,
    ));

    // encryptedContent [0] IMPLICIT OCTET STRING OPTIONAL
    if let Some(content) = &eci.encrypted_content {
        inner.extend_from_slice(&enc_tlv(
            tags::CONTEXT_SPECIFIC, // [0] IMPLICIT (primitive OCTET STRING)
            content,
        ));
    }

    enc_seq(&inner)
}

fn encode_enveloped_data(ed: &EnvelopedData) -> Vec<u8> {
    let mut inner = Vec::new();

    // version
    inner.extend_from_slice(&enc_int(&[ed.version as u8]));

    // recipientInfos SET OF RecipientInfo
    let mut ri_inner = Vec::new();
    for ri in &ed.recipient_infos {
        ri_inner.extend_from_slice(&encode_recipient_info(ri));
    }
    inner.extend_from_slice(&enc_set(&ri_inner));

    // encryptedContentInfo
    inner.extend_from_slice(&encode_encrypted_content_info(&ed.encrypted_content_info));

    enc_seq(&inner)
}

pub(crate) fn encode_enveloped_data_cms(ed: &EnvelopedData) -> Vec<u8> {
    let ed_encoded = encode_enveloped_data(ed);
    let ctx0 = enc_explicit_ctx(0, &ed_encoded);
    let mut ci_inner = enc_oid(&known::pkcs7_enveloped_data().to_der_value());
    ci_inner.extend_from_slice(&ctx0);
    enc_seq(&ci_inner)
}

// ── Parsing ──────────────────────────────────────────────────────────

fn bytes_to_u32(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |acc, &b| acc.wrapping_shl(8) | b as u32)
}

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

fn parse_key_trans_recipient_info(dec: &mut Decoder) -> Result<KeyTransRecipientInfo, PkiError> {
    let mut seq = dec
        .read_sequence()
        .map_err(|e| cerr(&format!("KTRI: {e}")))?;

    let version = bytes_to_u32(
        seq.read_integer()
            .map_err(|e| cerr(&format!("KTRI ver: {e}")))?,
    );

    // rid: IssuerAndSerialNumber
    let mut ias = seq
        .read_sequence()
        .map_err(|e| cerr(&format!("KTRI IAS: {e}")))?;
    let issuer_tlv = ias
        .read_tlv()
        .map_err(|e| cerr(&format!("KTRI issuer: {e}")))?;
    let mut issuer_enc = Encoder::new();
    issuer_enc.write_tlv(0x30, issuer_tlv.value);
    let rid_issuer = issuer_enc.finish();
    let rid_serial = ias
        .read_integer()
        .map_err(|e| cerr(&format!("KTRI serial: {e}")))?
        .to_vec();

    let key_encryption_algorithm = parse_algorithm_identifier(&mut seq)?;

    let encrypted_key = seq
        .read_octet_string()
        .map_err(|e| cerr(&format!("KTRI encKey: {e}")))?
        .to_vec();

    Ok(KeyTransRecipientInfo {
        version,
        rid_issuer,
        rid_serial,
        key_encryption_algorithm,
        encrypted_key,
    })
}

fn parse_kek_recipient_info_from_bytes(data: &[u8]) -> Result<KekRecipientInfo, PkiError> {
    let mut dec = Decoder::new(data);

    let version = bytes_to_u32(
        dec.read_integer()
            .map_err(|e| cerr(&format!("KEKRI ver: {e}")))?,
    );

    // kekid: KEKIdentifier SEQUENCE { keyIdentifier OCTET STRING }
    let mut kekid_seq = dec
        .read_sequence()
        .map_err(|e| cerr(&format!("KEKId: {e}")))?;
    let kek_id = kekid_seq
        .read_octet_string()
        .map_err(|e| cerr(&format!("KEKId keyId: {e}")))?
        .to_vec();

    let key_encryption_algorithm = parse_algorithm_identifier(&mut dec)?;

    let encrypted_key = dec
        .read_octet_string()
        .map_err(|e| cerr(&format!("KEKRI encKey: {e}")))?
        .to_vec();

    Ok(KekRecipientInfo {
        version,
        kek_id,
        key_encryption_algorithm,
        encrypted_key,
    })
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

pub(crate) fn parse_enveloped_data(data: &[u8]) -> Result<EnvelopedData, PkiError> {
    let mut dec = Decoder::new(data);
    let mut ed = dec
        .read_sequence()
        .map_err(|e| cerr(&format!("EnvelopedData: {e}")))?;

    let version = bytes_to_u32(
        ed.read_integer()
            .map_err(|e| cerr(&format!("ED ver: {e}")))?,
    );

    // recipientInfos SET OF RecipientInfo
    let mut ri_set = ed
        .read_set()
        .map_err(|e| cerr(&format!("recipientInfos: {e}")))?;
    let mut recipient_infos = Vec::new();
    while !ri_set.is_empty() {
        // Peek at the tag to determine which CHOICE
        let tlv = ri_set
            .read_tlv()
            .map_err(|e| cerr(&format!("RI TLV: {e}")))?;

        let tag_byte = (tlv.tag.class as u8) << 6
            | if tlv.tag.constructed { 0x20 } else { 0 }
            | tlv.tag.number as u8;

        if tag_byte == 0x30 {
            // SEQUENCE → KeyTransRecipientInfo
            let full_data = {
                let mut enc = Encoder::new();
                enc.write_tlv(tag_byte, tlv.value);
                enc.finish()
            };
            let mut inner_dec = Decoder::new(&full_data);
            recipient_infos.push(RecipientInfo::KeyTransport(parse_key_trans_recipient_info(
                &mut inner_dec,
            )?));
        } else if tag_byte == 0xA2 {
            // [2] IMPLICIT → KEKRecipientInfo
            recipient_infos.push(RecipientInfo::Kek(parse_kek_recipient_info_from_bytes(
                tlv.value,
            )?));
        } else {
            return Err(cerr(&format!(
                "unknown RecipientInfo tag: 0x{tag_byte:02x}"
            )));
        }
    }

    let encrypted_content_info = parse_encrypted_content_info(&mut ed)?;

    Ok(EnvelopedData {
        version,
        recipient_infos,
        encrypted_content_info,
    })
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // RSA key generation is slow (~5-10s)
    fn test_cms_enveloped_rsa_roundtrip() {
        // Generate RSA key pair
        let rsa_key = hitls_crypto::rsa::RsaPrivateKey::generate(2048).unwrap();
        let pub_key = rsa_key.public_key();

        // Build a self-signed cert for the recipient
        let cert_der = make_test_rsa_cert(&rsa_key, &pub_key);

        let plaintext = b"Hello, CMS EnvelopedData with RSA!";

        // Encrypt
        let cms =
            CmsMessage::encrypt_rsa(plaintext, &cert_der, CmsEncryptionAlg::Aes128Gcm).unwrap();
        assert_eq!(cms.content_type, CmsContentType::EnvelopedData);
        assert!(cms.enveloped_data.is_some());

        // Decrypt
        let decrypted = cms
            .decrypt_rsa(
                &rsa_key.n_bytes(),
                &rsa_key.d_bytes(),
                &rsa_key.e_bytes(),
                &rsa_key.p_bytes(),
                &rsa_key.q_bytes(),
            )
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cms_enveloped_kek_roundtrip() {
        let kek = [0x42u8; 16]; // 128-bit KEK
        let kek_id = b"test-kek-id-001";
        let plaintext = b"Hello, CMS EnvelopedData with KEK wrap!";

        // Encrypt
        let cms =
            CmsMessage::encrypt_kek(plaintext, &kek, kek_id, CmsEncryptionAlg::Aes128Gcm).unwrap();
        assert_eq!(cms.content_type, CmsContentType::EnvelopedData);

        // Decrypt
        let decrypted = cms.decrypt_kek(&kek).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cms_enveloped_parse_encode() {
        let kek = [0xAA; 32]; // 256-bit KEK
        let kek_id = b"roundtrip-key";
        let plaintext = b"Parse-encode roundtrip test data";

        // Create an enveloped message
        let cms =
            CmsMessage::encrypt_kek(plaintext, &kek, kek_id, CmsEncryptionAlg::Aes256Gcm).unwrap();

        // Parse the DER encoding back
        let parsed = CmsMessage::from_der(&cms.raw).unwrap();
        assert_eq!(parsed.content_type, CmsContentType::EnvelopedData);
        let ed = parsed.enveloped_data.as_ref().unwrap();
        assert_eq!(ed.version, 2);
        assert_eq!(ed.recipient_infos.len(), 1);

        // Verify the KEK recipient info
        match &ed.recipient_infos[0] {
            RecipientInfo::Kek(kekri) => {
                assert_eq!(kekri.version, 4);
                assert_eq!(kekri.kek_id, kek_id);
            }
            _ => panic!("expected KekRecipientInfo"),
        }

        // Decrypt from re-parsed message
        let decrypted = parsed.decrypt_kek(&kek).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cms_enveloped_wrong_key() {
        let kek = [0x42u8; 16];
        let wrong_kek = [0x99u8; 16];
        let kek_id = b"wrong-key-test";
        let plaintext = b"This should fail with wrong key";

        let cms =
            CmsMessage::encrypt_kek(plaintext, &kek, kek_id, CmsEncryptionAlg::Aes128Gcm).unwrap();

        // Attempt decrypt with wrong key — should fail
        let result = cms.decrypt_kek(&wrong_kek);
        assert!(result.is_err());
    }

    #[test]
    fn test_cms_enveloped_aes256_gcm() {
        let kek = [0xBB; 32]; // 256-bit KEK
        let kek_id = b"aes256-test";
        let plaintext = b"Testing AES-256-GCM content encryption";

        // Encrypt with AES-256-GCM
        let cms =
            CmsMessage::encrypt_kek(plaintext, &kek, kek_id, CmsEncryptionAlg::Aes256Gcm).unwrap();

        // Verify algorithm
        let ed = cms.enveloped_data.as_ref().unwrap();
        let alg_oid =
            Oid::from_der_value(&ed.encrypted_content_info.content_encryption_algorithm.oid)
                .unwrap();
        assert_eq!(alg_oid, known::aes256_gcm());

        // Decrypt
        let decrypted = cms.decrypt_kek(&kek).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // ── Test helpers ──────────────────────────────────────────────────

    /// Build a minimal self-signed X.509 certificate with the given RSA key.
    fn make_test_rsa_cert(
        priv_key: &hitls_crypto::rsa::RsaPrivateKey,
        pub_key: &hitls_crypto::rsa::RsaPublicKey,
    ) -> Vec<u8> {
        // Encode the RSA public key as a BIT STRING inside SubjectPublicKeyInfo
        let n_bytes = pub_key.n_bytes();
        let e_bytes = pub_key.e_bytes();

        let mut rsa_key_inner = Vec::new();
        rsa_key_inner.extend_from_slice(&enc_int(&n_bytes));
        rsa_key_inner.extend_from_slice(&enc_int(&e_bytes));
        let rsa_key_seq = enc_seq(&rsa_key_inner);

        // AlgorithmIdentifier for rsaEncryption
        let mut alg_inner = enc_oid(&known::rsa_encryption().to_der_value());
        alg_inner.push(0x05);
        alg_inner.push(0x00); // NULL params
        let alg_seq = enc_seq(&alg_inner);

        // SubjectPublicKeyInfo
        let mut spki_inner = Vec::new();
        spki_inner.extend_from_slice(&alg_seq);
        // BIT STRING (no unused bits)
        let mut e = Encoder::new();
        e.write_bit_string(0, &rsa_key_seq);
        spki_inner.extend_from_slice(&e.finish());
        let spki = enc_seq(&spki_inner);

        // Issuer/Subject: CN=Test
        let mut cn_attr = enc_oid(&known::common_name().to_der_value());
        {
            let mut e = Encoder::new();
            e.write_utf8_string("Test");
            cn_attr.extend_from_slice(&e.finish());
        }
        let cn_set = enc_set(&enc_seq(&cn_attr));
        let name = enc_seq(&cn_set);

        // Validity (2020-01-01 to 2030-01-01)
        let mut validity_inner = Vec::new();
        {
            let mut e = Encoder::new();
            e.write_utc_time(1577836800); // 2020-01-01
            validity_inner.extend_from_slice(&e.finish());
        }
        {
            let mut e = Encoder::new();
            e.write_utc_time(1893456000); // 2030-01-01
            validity_inner.extend_from_slice(&e.finish());
        }
        let validity = enc_seq(&validity_inner);

        // Signature algorithm: sha256WithRSAEncryption
        let mut sig_alg_inner = enc_oid(&known::sha256_with_rsa_encryption().to_der_value());
        sig_alg_inner.push(0x05);
        sig_alg_inner.push(0x00);
        let sig_alg = enc_seq(&sig_alg_inner);

        // TBSCertificate
        let mut tbs_inner = Vec::new();
        // version [0] EXPLICIT INTEGER 2 (v3)
        tbs_inner.extend_from_slice(&enc_explicit_ctx(0, &enc_int(&[2])));
        // serialNumber
        tbs_inner.extend_from_slice(&enc_int(&[1]));
        // signature algorithm
        tbs_inner.extend_from_slice(&sig_alg);
        // issuer
        tbs_inner.extend_from_slice(&name);
        // validity
        tbs_inner.extend_from_slice(&validity);
        // subject
        tbs_inner.extend_from_slice(&name);
        // subjectPublicKeyInfo
        tbs_inner.extend_from_slice(&spki);

        let tbs = enc_seq(&tbs_inner);

        // Sign TBS with SHA-256 + RSA PKCS#1v15
        let tbs_digest = {
            let mut h = hitls_crypto::sha2::Sha256::new();
            h.update(&tbs).unwrap();
            h.finish().unwrap()
        };
        let sig = priv_key
            .sign(hitls_crypto::rsa::RsaPadding::Pkcs1v15Sign, &tbs_digest)
            .unwrap();

        // Certificate SEQUENCE
        let mut cert_inner = Vec::new();
        cert_inner.extend_from_slice(&tbs);
        cert_inner.extend_from_slice(&sig_alg);
        // signature BIT STRING
        let mut e = Encoder::new();
        e.write_bit_string(0, &sig);
        cert_inner.extend_from_slice(&e.finish());

        enc_seq(&cert_inner)
    }
}
