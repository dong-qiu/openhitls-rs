//! CMS (Cryptographic Message Syntax) / PKCS#7 — SignedData + EnvelopedData + EncryptedData + DigestedData (RFC 5652).

pub mod encrypted;
pub mod enveloped;

use hitls_types::PkiError;
use hitls_utils::asn1::{tags, Decoder, Encoder};
use hitls_utils::oid::{known, Oid};

/// CMS content type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmsContentType {
    Data,
    SignedData,
    EnvelopedData,
    DigestedData,
    EncryptedData,
    AuthenticatedData,
    Unknown,
}

/// Digest algorithm for CMS signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmsDigestAlg {
    Sha256,
    Sha384,
    Sha512,
}

/// Algorithm identifier (OID + optional params).
#[derive(Debug, Clone)]
pub struct AlgorithmIdentifier {
    pub oid: Vec<u8>,
    pub params: Option<Vec<u8>>,
}

/// Encapsulated content info.
#[derive(Debug, Clone)]
pub struct EncapContentInfo {
    pub content_type: Vec<u8>,
    pub content: Option<Vec<u8>>,
}

/// Signer identifier.
#[derive(Debug, Clone)]
pub enum SignerIdentifier {
    IssuerAndSerialNumber {
        issuer: Vec<u8>,
        serial_number: Vec<u8>,
    },
    SubjectKeyIdentifier(Vec<u8>),
}

/// Signer info.
#[derive(Debug, Clone)]
pub struct SignerInfo {
    pub version: u32,
    pub sid: SignerIdentifier,
    pub digest_algorithm: AlgorithmIdentifier,
    pub signed_attrs: Option<Vec<u8>>,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: Vec<u8>,
}

/// A CMS SignedData message.
#[derive(Debug, Clone)]
pub struct SignedData {
    pub version: u32,
    pub digest_algorithms: Vec<AlgorithmIdentifier>,
    pub encap_content_info: EncapContentInfo,
    pub certificates: Vec<Vec<u8>>,
    pub signer_infos: Vec<SignerInfo>,
}

/// A CMS DigestedData message (RFC 5652 §5).
#[derive(Debug, Clone)]
pub struct DigestedData {
    pub version: u32,
    pub digest_algorithm: AlgorithmIdentifier,
    pub encap_content_info: EncapContentInfo,
    pub digest: Vec<u8>,
}

/// A CMS message.
#[derive(Debug)]
pub struct CmsMessage {
    pub content_type: CmsContentType,
    pub signed_data: Option<SignedData>,
    pub enveloped_data: Option<enveloped::EnvelopedData>,
    pub encrypted_data: Option<encrypted::EncryptedData>,
    pub digested_data: Option<DigestedData>,
    pub raw: Vec<u8>,
}

// ── Encoder helpers ──────────────────────────────────────────────────

fn enc_seq(content: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.write_sequence(content);
    e.finish()
}

fn enc_set(content: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.write_set(content);
    e.finish()
}

fn enc_octet(content: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.write_octet_string(content);
    e.finish()
}

fn enc_oid(oid_bytes: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.write_oid(oid_bytes);
    e.finish()
}

fn enc_int(value: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.write_integer(value);
    e.finish()
}

fn enc_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.write_tlv(tag, value);
    e.finish()
}

fn enc_explicit_ctx(tag_num: u8, content: &[u8]) -> Vec<u8> {
    enc_tlv(
        tags::CONTEXT_SPECIFIC | tags::CONSTRUCTED | tag_num,
        content,
    )
}

fn cerr(msg: &str) -> PkiError {
    PkiError::CmsError(msg.into())
}

fn cms_oid_to_curve_id(oid: &Oid) -> Option<hitls_types::EccCurveId> {
    use hitls_types::EccCurveId;
    if *oid == known::secp224r1() {
        Some(EccCurveId::NistP224)
    } else if *oid == known::prime256v1() {
        Some(EccCurveId::NistP256)
    } else if *oid == known::secp384r1() {
        Some(EccCurveId::NistP384)
    } else if *oid == known::secp521r1() {
        Some(EccCurveId::NistP521)
    } else if *oid == known::brainpool_p256r1() {
        Some(EccCurveId::BrainpoolP256r1)
    } else if *oid == known::brainpool_p384r1() {
        Some(EccCurveId::BrainpoolP384r1)
    } else if *oid == known::brainpool_p512r1() {
        Some(EccCurveId::BrainpoolP512r1)
    } else {
        None
    }
}

fn bytes_to_u32(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |acc, &b| acc.wrapping_shl(8) | b as u32)
}

// ── Parsing ──────────────────────────────────────────────────────────

impl CmsMessage {
    /// Parse a CMS message from DER-encoded bytes.
    pub fn from_der(data: &[u8]) -> Result<Self, PkiError> {
        let mut dec = Decoder::new(data);
        let mut ci = dec
            .read_sequence()
            .map_err(|e| cerr(&format!("ContentInfo: {e}")))?;

        let ct_bytes = ci
            .read_oid()
            .map_err(|e| cerr(&format!("contentType: {e}")))?;
        let ct_oid = Oid::from_der_value(ct_bytes).map_err(|e| cerr(&format!("ct OID: {e}")))?;

        let content_type = oid_to_content_type(&ct_oid);

        if content_type == CmsContentType::SignedData {
            let ctx0 = ci
                .read_context_specific(0, true)
                .map_err(|e| cerr(&format!("[0]: {e}")))?;
            let sd = parse_signed_data(ctx0.value)?;
            Ok(CmsMessage {
                content_type,
                signed_data: Some(sd),
                enveloped_data: None,
                encrypted_data: None,
                digested_data: None,
                raw: data.to_vec(),
            })
        } else if content_type == CmsContentType::EnvelopedData {
            let ctx0 = ci
                .read_context_specific(0, true)
                .map_err(|e| cerr(&format!("[0]: {e}")))?;
            let ed = enveloped::parse_enveloped_data(ctx0.value)?;
            Ok(CmsMessage {
                content_type,
                signed_data: None,
                enveloped_data: Some(ed),
                encrypted_data: None,
                digested_data: None,
                raw: data.to_vec(),
            })
        } else if content_type == CmsContentType::EncryptedData {
            let ctx0 = ci
                .read_context_specific(0, true)
                .map_err(|e| cerr(&format!("[0]: {e}")))?;
            let ed = encrypted::parse_encrypted_data(ctx0.value)?;
            Ok(CmsMessage {
                content_type,
                signed_data: None,
                enveloped_data: None,
                encrypted_data: Some(ed),
                digested_data: None,
                raw: data.to_vec(),
            })
        } else if content_type == CmsContentType::DigestedData {
            let ctx0 = ci
                .read_context_specific(0, true)
                .map_err(|e| cerr(&format!("[0]: {e}")))?;
            let dd = parse_digested_data(ctx0.value)?;
            Ok(CmsMessage {
                content_type,
                signed_data: None,
                enveloped_data: None,
                encrypted_data: None,
                digested_data: Some(dd),
                raw: data.to_vec(),
            })
        } else {
            Ok(CmsMessage {
                content_type,
                signed_data: None,
                enveloped_data: None,
                encrypted_data: None,
                digested_data: None,
                raw: data.to_vec(),
            })
        }
    }

    /// Parse a CMS message from PEM.
    pub fn from_pem(pem: &str) -> Result<Self, PkiError> {
        let blocks = hitls_utils::pem::parse(pem).map_err(|e| cerr(&format!("PEM parse: {e}")))?;
        let block = blocks
            .iter()
            .find(|b| b.label == "CMS" || b.label == "PKCS7")
            .ok_or_else(|| cerr("no CMS/PKCS7 PEM block found"))?;
        Self::from_der(&block.data)
    }

    /// Verify the signature(s) in a SignedData message.
    ///
    /// For attached signatures, data is taken from encapContentInfo.
    /// For detached signatures, provide the original data.
    /// `certs` are additional certificates to search for signer certs.
    pub fn verify_signatures(
        &self,
        detached_data: Option<&[u8]>,
        extra_certs: &[crate::x509::Certificate],
    ) -> Result<bool, PkiError> {
        let sd = self
            .signed_data
            .as_ref()
            .ok_or_else(|| cerr("not SignedData"))?;

        let content_data = match (&sd.encap_content_info.content, detached_data) {
            (Some(data), _) => data.as_slice(),
            (None, Some(data)) => data,
            (None, None) => return Err(cerr("no content data for verification")),
        };

        // Collect all certs: embedded + extra
        let mut all_certs: Vec<crate::x509::Certificate> = Vec::new();
        for cert_der in &sd.certificates {
            if let Ok(c) = crate::x509::Certificate::from_der(cert_der) {
                all_certs.push(c);
            }
        }
        all_certs.extend_from_slice(extra_certs);

        for si in &sd.signer_infos {
            verify_signer_info(si, content_data, &all_certs)?;
        }

        Ok(true)
    }

    /// Create a CMS SignedData message (attached mode).
    pub fn sign(
        data: &[u8],
        signer_cert_der: &[u8],
        private_key_der: &[u8],
        digest_alg: CmsDigestAlg,
    ) -> Result<Self, PkiError> {
        let cert = crate::x509::Certificate::from_der(signer_cert_der)
            .map_err(|e| cerr(&format!("cert parse: {e}")))?;

        let digest = compute_digest(data, digest_alg)?;
        let digest_alg_id = digest_alg_identifier(digest_alg);

        // Build signedAttrs
        let signed_attrs_content = build_signed_attrs(&known::pkcs7_data().to_der_value(), &digest);
        // Re-encode with SET tag for signing
        let signed_attrs_for_signing = enc_set(&signed_attrs_content);

        // Hash the signedAttrs
        let attrs_digest = compute_digest(&signed_attrs_for_signing, digest_alg)?;

        // Determine signature algorithm and sign
        let sig_alg_oid = &cert.signature_algorithm;
        let (signature, sig_alg_id) =
            sign_digest(&attrs_digest, private_key_der, sig_alg_oid, &cert)?;

        // Build SignerInfo
        let si = SignerInfo {
            version: 1,
            sid: SignerIdentifier::IssuerAndSerialNumber {
                issuer: extract_raw_issuer(signer_cert_der)?,
                serial_number: cert.serial_number.clone(),
            },
            digest_algorithm: digest_alg_id.clone(),
            signed_attrs: Some(signed_attrs_content.clone()), // Store raw
            signature_algorithm: sig_alg_id,
            signature,
        };

        let sd = SignedData {
            version: 1,
            digest_algorithms: vec![digest_alg_id],
            encap_content_info: EncapContentInfo {
                content_type: known::pkcs7_data().to_der_value(),
                content: Some(data.to_vec()),
            },
            certificates: vec![signer_cert_der.to_vec()],
            signer_infos: vec![si],
        };

        let encoded = encode_signed_data_cms(&sd);

        Ok(CmsMessage {
            content_type: CmsContentType::SignedData,
            signed_data: Some(sd),
            enveloped_data: None,
            encrypted_data: None,
            digested_data: None,
            raw: encoded,
        })
    }

    /// Create a CMS SignedData message (detached mode — content not embedded).
    ///
    /// In detached mode, the `encapContentInfo.eContent` field is omitted.
    /// The verifier must supply the original data externally via
    /// `verify_signatures(Some(data), &[])`.
    pub fn sign_detached(
        data: &[u8],
        signer_cert_der: &[u8],
        private_key_der: &[u8],
        digest_alg: CmsDigestAlg,
    ) -> Result<Self, PkiError> {
        let cert = crate::x509::Certificate::from_der(signer_cert_der)
            .map_err(|e| cerr(&format!("cert parse: {e}")))?;

        let digest = compute_digest(data, digest_alg)?;
        let digest_alg_id = digest_alg_identifier(digest_alg);

        // Build signedAttrs
        let signed_attrs_content = build_signed_attrs(&known::pkcs7_data().to_der_value(), &digest);
        // Re-encode with SET tag for signing
        let signed_attrs_for_signing = enc_set(&signed_attrs_content);

        // Hash the signedAttrs
        let attrs_digest = compute_digest(&signed_attrs_for_signing, digest_alg)?;

        // Determine signature algorithm and sign
        let sig_alg_oid = &cert.signature_algorithm;
        let (signature, sig_alg_id) =
            sign_digest(&attrs_digest, private_key_der, sig_alg_oid, &cert)?;

        // Build SignerInfo
        let si = SignerInfo {
            version: 1,
            sid: SignerIdentifier::IssuerAndSerialNumber {
                issuer: extract_raw_issuer(signer_cert_der)?,
                serial_number: cert.serial_number.clone(),
            },
            digest_algorithm: digest_alg_id.clone(),
            signed_attrs: Some(signed_attrs_content.clone()),
            signature_algorithm: sig_alg_id,
            signature,
        };

        let sd = SignedData {
            version: 1,
            digest_algorithms: vec![digest_alg_id],
            encap_content_info: EncapContentInfo {
                content_type: known::pkcs7_data().to_der_value(),
                content: None, // detached — no embedded content
            },
            certificates: vec![signer_cert_der.to_vec()],
            signer_infos: vec![si],
        };

        let encoded = encode_signed_data_cms(&sd);

        Ok(CmsMessage {
            content_type: CmsContentType::SignedData,
            signed_data: Some(sd),
            enveloped_data: None,
            encrypted_data: None,
            digested_data: None,
            raw: encoded,
        })
    }
}

// ── SignedData parsing ───────────────────────────────────────────────

fn parse_signed_data(data: &[u8]) -> Result<SignedData, PkiError> {
    let mut dec = Decoder::new(data);
    let mut sd = dec
        .read_sequence()
        .map_err(|e| cerr(&format!("SignedData: {e}")))?;

    let version = bytes_to_u32(
        sd.read_integer()
            .map_err(|e| cerr(&format!("SD ver: {e}")))?,
    );

    // digestAlgorithms SET OF AlgorithmIdentifier
    let mut da_set = sd
        .read_set()
        .map_err(|e| cerr(&format!("digestAlgs: {e}")))?;
    let mut digest_algorithms = Vec::new();
    while !da_set.is_empty() {
        digest_algorithms.push(parse_algorithm_identifier(&mut da_set)?);
    }

    // encapContentInfo
    let encap = parse_encap_content_info(&mut sd)?;

    // [0] IMPLICIT certificates (optional)
    let mut certificates = Vec::new();
    if let Some(ctx0) = sd
        .try_read_context_specific(0, true)
        .map_err(|e| cerr(&format!("[0] certs: {e}")))?
    {
        let mut cert_dec = Decoder::new(ctx0.value);
        while !cert_dec.is_empty() {
            let tlv = cert_dec
                .read_tlv()
                .map_err(|e| cerr(&format!("cert TLV: {e}")))?;
            // Reconstruct the full TLV
            let mut enc = Encoder::new();
            enc.write_tlv(
                (tlv.tag.class as u8) << 6
                    | if tlv.tag.constructed { 0x20 } else { 0 }
                    | tlv.tag.number as u8,
                tlv.value,
            );
            let cert_der = enc.finish();
            certificates.push(cert_der);
        }
    }

    // [1] IMPLICIT crls (optional) — skip
    let _ = sd.try_read_context_specific(1, true);

    // signerInfos SET OF SignerInfo
    let mut si_set = sd
        .read_set()
        .map_err(|e| cerr(&format!("signerInfos: {e}")))?;
    let mut signer_infos = Vec::new();
    while !si_set.is_empty() {
        signer_infos.push(parse_signer_info(&mut si_set)?);
    }

    Ok(SignedData {
        version,
        digest_algorithms,
        encap_content_info: encap,
        certificates,
        signer_infos,
    })
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

fn parse_encap_content_info(dec: &mut Decoder) -> Result<EncapContentInfo, PkiError> {
    let mut seq = dec
        .read_sequence()
        .map_err(|e| cerr(&format!("EncapCI: {e}")))?;
    let content_type = seq
        .read_oid()
        .map_err(|e| cerr(&format!("EncapCI type: {e}")))?
        .to_vec();

    let content = if let Some(ctx0) = seq
        .try_read_context_specific(0, true)
        .map_err(|e| cerr(&format!("EncapCI [0]: {e}")))?
    {
        // content is EXPLICIT [0] OCTET STRING
        let mut ctx0_dec = Decoder::new(ctx0.value);
        let data = ctx0_dec
            .read_octet_string()
            .map_err(|e| cerr(&format!("EncapCI content: {e}")))?
            .to_vec();
        Some(data)
    } else {
        None
    };

    Ok(EncapContentInfo {
        content_type,
        content,
    })
}

fn parse_signer_info(dec: &mut Decoder) -> Result<SignerInfo, PkiError> {
    let mut seq = dec
        .read_sequence()
        .map_err(|e| cerr(&format!("SignerInfo: {e}")))?;

    let version = bytes_to_u32(
        seq.read_integer()
            .map_err(|e| cerr(&format!("SI ver: {e}")))?,
    );

    // sid: IssuerAndSerialNumber (v1) or SubjectKeyIdentifier [0] (v3)
    let sid = if version == 1 {
        let mut ias = seq
            .read_sequence()
            .map_err(|e| cerr(&format!("IAS: {e}")))?;
        // Issuer is a SEQUENCE (Name) — capture raw
        let issuer_tlv = ias.read_tlv().map_err(|e| cerr(&format!("issuer: {e}")))?;
        let mut issuer_enc = Encoder::new();
        issuer_enc.write_tlv(0x30, issuer_tlv.value);
        let issuer = issuer_enc.finish();
        let serial = ias
            .read_integer()
            .map_err(|e| cerr(&format!("serial: {e}")))?
            .to_vec();
        SignerIdentifier::IssuerAndSerialNumber {
            issuer,
            serial_number: serial,
        }
    } else {
        let ctx0 = seq
            .read_context_specific(0, false)
            .map_err(|e| cerr(&format!("SKI: {e}")))?;
        SignerIdentifier::SubjectKeyIdentifier(ctx0.value.to_vec())
    };

    let digest_algorithm = parse_algorithm_identifier(&mut seq)?;

    // [0] signedAttrs (optional)
    let signed_attrs = seq
        .try_read_context_specific(0, true)
        .map_err(|e| cerr(&format!("signedAttrs: {e}")))?
        .map(|ctx0| ctx0.value.to_vec());

    let signature_algorithm = parse_algorithm_identifier(&mut seq)?;

    let signature = seq
        .read_octet_string()
        .map_err(|e| cerr(&format!("sig: {e}")))?
        .to_vec();

    Ok(SignerInfo {
        version,
        sid,
        digest_algorithm,
        signed_attrs,
        signature_algorithm,
        signature,
    })
}

// ── Verification ─────────────────────────────────────────────────────

fn verify_signer_info(
    si: &SignerInfo,
    content_data: &[u8],
    certs: &[crate::x509::Certificate],
) -> Result<(), PkiError> {
    let digest_alg = oid_to_digest_alg(&si.digest_algorithm.oid)?;
    let content_digest = compute_digest(content_data, digest_alg)?;

    let data_to_verify = if let Some(attrs_content) = &si.signed_attrs {
        // Verify messageDigest attribute matches content digest
        verify_message_digest_attr(attrs_content, &content_digest)?;
        // Re-encode signedAttrs as SET (tag 0x31) for signature verification
        let set_encoded = enc_set(attrs_content);
        compute_digest(&set_encoded, digest_alg)?
    } else {
        content_digest
    };

    // Find signer cert
    let signer_cert = find_signer_cert(&si.sid, certs)?;

    // Verify signature using cert's public key
    verify_signature_with_cert(
        &data_to_verify,
        &si.signature,
        &si.signature_algorithm,
        signer_cert,
    )
}

fn verify_message_digest_attr(
    attrs_content: &[u8],
    expected_digest: &[u8],
) -> Result<(), PkiError> {
    // Parse attrs to find messageDigest
    let md_oid = known::pkcs9_message_digest().to_der_value();

    let mut dec = Decoder::new(attrs_content);
    while !dec.is_empty() {
        let mut attr_seq = dec
            .read_sequence()
            .map_err(|e| cerr(&format!("attr: {e}")))?;
        let attr_oid = attr_seq
            .read_oid()
            .map_err(|e| cerr(&format!("attr OID: {e}")))?;
        if attr_oid == md_oid.as_slice() {
            let mut vals = attr_seq
                .read_set()
                .map_err(|e| cerr(&format!("attr vals: {e}")))?;
            let digest = vals
                .read_octet_string()
                .map_err(|e| cerr(&format!("md val: {e}")))?;
            if digest != expected_digest {
                return Err(cerr("messageDigest mismatch"));
            }
            return Ok(());
        }
    }
    Err(cerr("messageDigest attribute not found"))
}

fn find_signer_cert<'a>(
    sid: &SignerIdentifier,
    certs: &'a [crate::x509::Certificate],
) -> Result<&'a crate::x509::Certificate, PkiError> {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber {
            issuer: _,
            serial_number,
        } => {
            for cert in certs {
                if cert.serial_number == *serial_number {
                    return Ok(cert);
                }
            }
            Err(cerr("signer cert not found by serial number"))
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            for cert in certs {
                if let Some(cert_ski) = cert.subject_key_identifier() {
                    if cert_ski == *ski {
                        return Ok(cert);
                    }
                }
            }
            Err(cerr("signer cert not found by SubjectKeyIdentifier"))
        }
    }
}

fn verify_signature_with_cert(
    digest: &[u8],
    signature: &[u8],
    sig_alg: &AlgorithmIdentifier,
    cert: &crate::x509::Certificate,
) -> Result<(), PkiError> {
    let sig_oid = Oid::from_der_value(&sig_alg.oid).map_err(|e| cerr(&format!("sig OID: {e}")))?;

    if sig_oid == known::sha256_with_rsa_encryption()
        || sig_oid == known::sha384_with_rsa_encryption()
        || sig_oid == known::sha512_with_rsa_encryption()
        || sig_oid == known::sha1_with_rsa_encryption()
        || sig_oid == known::rsa_encryption()
    {
        // RSA PKCS#1v15
        let mut key_dec = Decoder::new(&cert.public_key.public_key);
        let mut key_seq = key_dec
            .read_sequence()
            .map_err(|e| cerr(&format!("RSA key: {e}")))?;
        let n = key_seq
            .read_integer()
            .map_err(|e| cerr(&format!("RSA n: {e}")))?;
        let e = key_seq
            .read_integer()
            .map_err(|e| cerr(&format!("RSA e: {e}")))?;
        let rsa_pub = hitls_crypto::rsa::RsaPublicKey::new(n, e).map_err(PkiError::from)?;
        let ok = rsa_pub
            .verify(
                hitls_crypto::rsa::RsaPadding::Pkcs1v15Sign,
                digest,
                signature,
            )
            .map_err(PkiError::from)?;
        if ok {
            Ok(())
        } else {
            Err(cerr("RSA signature verification failed"))
        }
    } else if sig_oid == known::rsassa_pss() {
        // RSA-PSS
        let mut key_dec = Decoder::new(&cert.public_key.public_key);
        let mut key_seq = key_dec
            .read_sequence()
            .map_err(|e| cerr(&format!("RSA key: {e}")))?;
        let n = key_seq
            .read_integer()
            .map_err(|e| cerr(&format!("RSA n: {e}")))?;
        let e = key_seq
            .read_integer()
            .map_err(|e| cerr(&format!("RSA e: {e}")))?;
        let rsa_pub = hitls_crypto::rsa::RsaPublicKey::new(n, e).map_err(PkiError::from)?;
        let ok = rsa_pub
            .verify(hitls_crypto::rsa::RsaPadding::Pss, digest, signature)
            .map_err(PkiError::from)?;
        if ok {
            Ok(())
        } else {
            Err(cerr("RSA-PSS signature verification failed"))
        }
    } else if sig_oid == known::ecdsa_with_sha256()
        || sig_oid == known::ecdsa_with_sha384()
        || sig_oid == known::ecdsa_with_sha512()
    {
        // ECDSA
        let curve_oid_bytes = cert
            .public_key
            .algorithm_params
            .as_ref()
            .ok_or_else(|| cerr("missing EC curve in cert"))?;
        let curve_oid =
            Oid::from_der_value(curve_oid_bytes).map_err(|e| cerr(&format!("curve OID: {e}")))?;
        let curve_id = cms_oid_to_curve_id(&curve_oid)
            .ok_or_else(|| cerr(&format!("unsupported EC curve: {curve_oid}")))?;
        let verifier = hitls_crypto::ecdsa::EcdsaKeyPair::from_public_key(
            curve_id,
            &cert.public_key.public_key,
        )
        .map_err(PkiError::from)?;
        let ok = verifier.verify(digest, signature).map_err(PkiError::from)?;
        if ok {
            Ok(())
        } else {
            Err(cerr("ECDSA signature verification failed"))
        }
    } else if sig_oid == known::ed25519() {
        let kp =
            hitls_crypto::ed25519::Ed25519KeyPair::from_public_key(&cert.public_key.public_key)
                .map_err(|e| cerr(&format!("Ed25519 key: {e}")))?;
        let ok = kp
            .verify(digest, signature)
            .map_err(|e| cerr(&format!("Ed25519 verify: {e}")))?;
        if ok {
            Ok(())
        } else {
            Err(cerr("Ed25519 signature verification failed"))
        }
    } else if sig_oid == known::ed448() {
        let kp = hitls_crypto::ed448::Ed448KeyPair::from_public_key(&cert.public_key.public_key)
            .map_err(|e| cerr(&format!("Ed448 key: {e}")))?;
        let ok = kp
            .verify(digest, signature)
            .map_err(|e| cerr(&format!("Ed448 verify: {e}")))?;
        if ok {
            Ok(())
        } else {
            Err(cerr("Ed448 signature verification failed"))
        }
    } else {
        Err(cerr(&format!("unsupported sig alg: {sig_oid}")))
    }
}

// ── Signing ──────────────────────────────────────────────────────────

fn sign_digest(
    digest: &[u8],
    private_key_der: &[u8],
    cert_sig_alg_oid: &[u8],
    cert: &crate::x509::Certificate,
) -> Result<(Vec<u8>, AlgorithmIdentifier), PkiError> {
    let sig_oid =
        Oid::from_der_value(cert_sig_alg_oid).map_err(|e| cerr(&format!("sig OID: {e}")))?;

    if sig_oid == known::sha256_with_rsa_encryption()
        || sig_oid == known::sha384_with_rsa_encryption()
        || sig_oid == known::sha512_with_rsa_encryption()
    {
        // Parse RSA private key from PKCS#8 PrivateKeyInfo
        let rsa_key = parse_rsa_private_key(private_key_der)?;
        let signature = rsa_key
            .sign(hitls_crypto::rsa::RsaPadding::Pkcs1v15Sign, digest)
            .map_err(PkiError::from)?;
        Ok((
            signature,
            AlgorithmIdentifier {
                oid: cert_sig_alg_oid.to_vec(),
                params: Some(vec![0x05, 0x00]), // NULL
            },
        ))
    } else if sig_oid == known::ecdsa_with_sha256() || sig_oid == known::ecdsa_with_sha384() {
        let curve_oid_bytes = cert
            .public_key
            .algorithm_params
            .as_ref()
            .ok_or_else(|| cerr("missing EC curve"))?;
        let curve_oid =
            Oid::from_der_value(curve_oid_bytes).map_err(|e| cerr(&format!("curve: {e}")))?;
        let curve_id = cms_oid_to_curve_id(&curve_oid)
            .ok_or_else(|| cerr(&format!("unsupported curve: {curve_oid}")))?;

        let ec_key_bytes = parse_ec_private_key(private_key_der)?;
        let kp = hitls_crypto::ecdsa::EcdsaKeyPair::from_private_key(curve_id, &ec_key_bytes)
            .map_err(PkiError::from)?;
        let signature = kp.sign(digest).map_err(PkiError::from)?;
        Ok((
            signature,
            AlgorithmIdentifier {
                oid: cert_sig_alg_oid.to_vec(),
                params: None,
            },
        ))
    } else if sig_oid == known::ed25519() {
        let seed = parse_eddsa_private_key(private_key_der)?;
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(&seed)
            .map_err(|e| cerr(&format!("Ed25519 key: {e}")))?;
        let signature = kp
            .sign(digest)
            .map_err(|e| cerr(&format!("Ed25519 sign: {e}")))?
            .to_vec();
        Ok((
            signature,
            AlgorithmIdentifier {
                oid: cert_sig_alg_oid.to_vec(),
                params: None,
            },
        ))
    } else if sig_oid == known::ed448() {
        let seed = parse_eddsa_private_key(private_key_der)?;
        let kp = hitls_crypto::ed448::Ed448KeyPair::from_seed(&seed)
            .map_err(|e| cerr(&format!("Ed448 key: {e}")))?;
        let signature = kp
            .sign(digest)
            .map_err(|e| cerr(&format!("Ed448 sign: {e}")))?
            .to_vec();
        Ok((
            signature,
            AlgorithmIdentifier {
                oid: cert_sig_alg_oid.to_vec(),
                params: None,
            },
        ))
    } else {
        Err(cerr(&format!("unsupported sig alg for signing: {sig_oid}")))
    }
}

/// Parse EdDSA private key seed from PKCS#8 DER.
///
/// PKCS#8: SEQUENCE { version, algorithm SEQUENCE { OID }, privateKey OCTET STRING }
/// The privateKey is itself a DER-encoded OCTET STRING containing the seed.
fn parse_eddsa_private_key(pkcs8_der: &[u8]) -> Result<Vec<u8>, PkiError> {
    let mut dec = Decoder::new(pkcs8_der);
    let mut seq = dec
        .read_sequence()
        .map_err(|e| cerr(&format!("PKCS8: {e}")))?;
    let _version = seq
        .read_integer()
        .map_err(|e| cerr(&format!("PKCS8 ver: {e}")))?;
    let _alg = seq
        .read_sequence()
        .map_err(|e| cerr(&format!("PKCS8 alg: {e}")))?;
    let key_octet = seq
        .read_octet_string()
        .map_err(|e| cerr(&format!("PKCS8 key: {e}")))?;
    // The key_octet is another OCTET STRING wrapping the raw seed
    let mut inner_dec = Decoder::new(key_octet);
    let seed = inner_dec
        .read_octet_string()
        .map_err(|e| cerr(&format!("EdDSA seed: {e}")))?
        .to_vec();
    Ok(seed)
}

fn parse_rsa_private_key(pkcs8_der: &[u8]) -> Result<hitls_crypto::rsa::RsaPrivateKey, PkiError> {
    // PKCS#8 PrivateKeyInfo: SEQUENCE { version, algorithm, privateKey OCTET STRING }
    let mut dec = Decoder::new(pkcs8_der);
    let mut seq = dec
        .read_sequence()
        .map_err(|e| cerr(&format!("PKCS8: {e}")))?;
    let _version = seq
        .read_integer()
        .map_err(|e| cerr(&format!("PKCS8 ver: {e}")))?;
    let _alg = seq
        .read_sequence()
        .map_err(|e| cerr(&format!("PKCS8 alg: {e}")))?;
    let key_bytes = seq
        .read_octet_string()
        .map_err(|e| cerr(&format!("PKCS8 key: {e}")))?;

    // RSAPrivateKey: SEQUENCE { version, n, e, d, p, q, dp, dq, qinv }
    let mut key_dec = Decoder::new(key_bytes);
    let mut key_seq = key_dec
        .read_sequence()
        .map_err(|e| cerr(&format!("RSA key: {e}")))?;
    let _ver = key_seq
        .read_integer()
        .map_err(|e| cerr(&format!("key ver: {e}")))?;
    let n = key_seq
        .read_integer()
        .map_err(|e| cerr(&format!("n: {e}")))?
        .to_vec();
    let e = key_seq
        .read_integer()
        .map_err(|e| cerr(&format!("e: {e}")))?
        .to_vec();
    let d = key_seq
        .read_integer()
        .map_err(|e| cerr(&format!("d: {e}")))?
        .to_vec();
    let p = key_seq
        .read_integer()
        .map_err(|e| cerr(&format!("p: {e}")))?
        .to_vec();
    let q = key_seq
        .read_integer()
        .map_err(|e| cerr(&format!("q: {e}")))?
        .to_vec();

    hitls_crypto::rsa::RsaPrivateKey::new(&n, &d, &e, &p, &q).map_err(PkiError::from)
}

fn parse_ec_private_key(pkcs8_der: &[u8]) -> Result<Vec<u8>, PkiError> {
    let mut dec = Decoder::new(pkcs8_der);
    let mut seq = dec
        .read_sequence()
        .map_err(|e| cerr(&format!("PKCS8: {e}")))?;
    let _version = seq
        .read_integer()
        .map_err(|e| cerr(&format!("PKCS8 ver: {e}")))?;
    let _alg = seq
        .read_sequence()
        .map_err(|e| cerr(&format!("PKCS8 alg: {e}")))?;
    let key_bytes = seq
        .read_octet_string()
        .map_err(|e| cerr(&format!("PKCS8 key: {e}")))?;

    // ECPrivateKey: SEQUENCE { version, privateKey OCTET STRING, ... }
    let mut key_dec = Decoder::new(key_bytes);
    let mut key_seq = key_dec
        .read_sequence()
        .map_err(|e| cerr(&format!("EC key: {e}")))?;
    let _ver = key_seq
        .read_integer()
        .map_err(|e| cerr(&format!("EC ver: {e}")))?;
    let private_key = key_seq
        .read_octet_string()
        .map_err(|e| cerr(&format!("EC privkey: {e}")))?
        .to_vec();

    Ok(private_key)
}

// ── Encoding ─────────────────────────────────────────────────────────

fn encode_signed_data_cms(sd: &SignedData) -> Vec<u8> {
    let sd_encoded = encode_signed_data(sd);
    let ctx0 = enc_explicit_ctx(0, &sd_encoded);
    let mut ci_inner = enc_oid(&known::pkcs7_signed_data().to_der_value());
    ci_inner.extend_from_slice(&ctx0);
    enc_seq(&ci_inner)
}

fn encode_signed_data(sd: &SignedData) -> Vec<u8> {
    let mut inner = Vec::new();

    // version
    inner.extend_from_slice(&enc_int(&[sd.version as u8]));

    // digestAlgorithms SET
    let mut da_inner = Vec::new();
    for alg in &sd.digest_algorithms {
        da_inner.extend_from_slice(&encode_algorithm_identifier(alg));
    }
    inner.extend_from_slice(&enc_set(&da_inner));

    // encapContentInfo
    inner.extend_from_slice(&encode_encap_content_info(&sd.encap_content_info));

    // [0] certificates (optional)
    if !sd.certificates.is_empty() {
        let mut certs_inner = Vec::new();
        for cert in &sd.certificates {
            certs_inner.extend_from_slice(cert);
        }
        inner.extend_from_slice(&enc_explicit_ctx(0, &certs_inner));
    }

    // signerInfos SET
    let mut si_inner = Vec::new();
    for si in &sd.signer_infos {
        si_inner.extend_from_slice(&encode_signer_info(si));
    }
    inner.extend_from_slice(&enc_set(&si_inner));

    enc_seq(&inner)
}

fn encode_algorithm_identifier(alg: &AlgorithmIdentifier) -> Vec<u8> {
    let mut inner = enc_oid(&alg.oid);
    if let Some(params) = &alg.params {
        inner.extend_from_slice(params);
    }
    enc_seq(&inner)
}

fn encode_encap_content_info(eci: &EncapContentInfo) -> Vec<u8> {
    let mut inner = enc_oid(&eci.content_type);
    if let Some(content) = &eci.content {
        let octet = enc_octet(content);
        inner.extend_from_slice(&enc_explicit_ctx(0, &octet));
    }
    enc_seq(&inner)
}

fn encode_signer_info(si: &SignerInfo) -> Vec<u8> {
    let mut inner = Vec::new();

    inner.extend_from_slice(&enc_int(&[si.version as u8]));

    match &si.sid {
        SignerIdentifier::IssuerAndSerialNumber {
            issuer,
            serial_number,
        } => {
            let mut ias_inner = Vec::new();
            ias_inner.extend_from_slice(issuer);
            ias_inner.extend_from_slice(&enc_int(serial_number));
            inner.extend_from_slice(&enc_seq(&ias_inner));
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            inner.extend_from_slice(&enc_tlv(tags::CONTEXT_SPECIFIC, ski));
        }
    }

    inner.extend_from_slice(&encode_algorithm_identifier(&si.digest_algorithm));

    if let Some(attrs) = &si.signed_attrs {
        // signedAttrs [0] IMPLICIT SET OF Attribute
        inner.extend_from_slice(&enc_explicit_ctx(0, attrs));
    }

    inner.extend_from_slice(&encode_algorithm_identifier(&si.signature_algorithm));
    inner.extend_from_slice(&enc_octet(&si.signature));

    enc_seq(&inner)
}

fn build_signed_attrs(content_type_oid: &[u8], message_digest: &[u8]) -> Vec<u8> {
    let mut attrs = Vec::new();

    // contentType attribute
    let ct_val = enc_oid(content_type_oid);
    let mut ct_attr = enc_oid(&known::pkcs9_content_type().to_der_value());
    ct_attr.extend_from_slice(&enc_set(&ct_val));
    attrs.extend_from_slice(&enc_seq(&ct_attr));

    // messageDigest attribute
    let md_val = enc_octet(message_digest);
    let mut md_attr = enc_oid(&known::pkcs9_message_digest().to_der_value());
    md_attr.extend_from_slice(&enc_set(&md_val));
    attrs.extend_from_slice(&enc_seq(&md_attr));

    attrs
}

/// Extract the raw DER-encoded issuer Name from a certificate's raw DER.
fn extract_raw_issuer(cert_der: &[u8]) -> Result<Vec<u8>, PkiError> {
    let mut dec = Decoder::new(cert_der);
    let mut cert_seq = dec
        .read_sequence()
        .map_err(|e| cerr(&format!("cert: {e}")))?;
    let mut tbs = cert_seq
        .read_sequence()
        .map_err(|e| cerr(&format!("tbs: {e}")))?;

    // Skip [0] version (optional)
    let _ = tbs.read_context_specific(0, true);
    // Skip serialNumber
    let _ = tbs
        .read_integer()
        .map_err(|e| cerr(&format!("serial: {e}")))?;
    // Skip signature AlgorithmIdentifier
    let _ = tbs
        .read_sequence()
        .map_err(|e| cerr(&format!("sig alg: {e}")))?;

    // Read the issuer Name as raw TLV
    let issuer_tlv = tbs.read_tlv().map_err(|e| cerr(&format!("issuer: {e}")))?;
    let mut enc = Encoder::new();
    enc.write_tlv(0x30, issuer_tlv.value);
    Ok(enc.finish())
}

// ── DigestedData (RFC 5652 §5) ───────────────────────────────────────

/// Parse DigestedData from the inner SEQUENCE bytes.
///
/// DigestedData ::= SEQUENCE {
///   version          CMSVersion,
///   digestAlgorithm  DigestAlgorithmIdentifier,
///   encapContentInfo EncapsulatedContentInfo,
///   digest           Digest (OCTET STRING)
/// }
fn parse_digested_data(data: &[u8]) -> Result<DigestedData, PkiError> {
    let mut dec = Decoder::new(data);
    let mut dd = dec
        .read_sequence()
        .map_err(|e| cerr(&format!("DigestedData: {e}")))?;

    let version = bytes_to_u32(
        dd.read_integer()
            .map_err(|e| cerr(&format!("DD ver: {e}")))?,
    );

    let digest_algorithm = parse_algorithm_identifier(&mut dd)?;

    let encap = parse_encap_content_info(&mut dd)?;

    let digest = dd
        .read_octet_string()
        .map_err(|e| cerr(&format!("DD digest: {e}")))?
        .to_vec();

    Ok(DigestedData {
        version,
        digest_algorithm,
        encap_content_info: encap,
        digest,
    })
}

/// Encode a DigestedData as a full CMS ContentInfo.
fn encode_digested_data_cms(dd: &DigestedData) -> Vec<u8> {
    let mut inner = Vec::new();

    // version
    inner.extend_from_slice(&enc_int(&[dd.version as u8]));

    // digestAlgorithm
    inner.extend_from_slice(&encode_algorithm_identifier(&dd.digest_algorithm));

    // encapContentInfo
    inner.extend_from_slice(&encode_encap_content_info(&dd.encap_content_info));

    // digest OCTET STRING
    inner.extend_from_slice(&enc_octet(&dd.digest));

    let dd_seq = enc_seq(&inner);

    // Wrap in ContentInfo
    let ctx0 = enc_explicit_ctx(0, &dd_seq);
    let mut ci_inner = enc_oid(&known::pkcs7_digested_data().to_der_value());
    ci_inner.extend_from_slice(&ctx0);
    enc_seq(&ci_inner)
}

impl CmsMessage {
    /// Create a CMS DigestedData message.
    ///
    /// Computes the digest of the provided data and wraps it in a
    /// DigestedData structure (RFC 5652 §5).
    pub fn digest(data: &[u8], alg: CmsDigestAlg) -> Result<Self, PkiError> {
        let digest = compute_digest(data, alg)?;
        let alg_id = digest_alg_identifier(alg);

        let dd = DigestedData {
            version: 0,
            digest_algorithm: alg_id,
            encap_content_info: EncapContentInfo {
                content_type: known::pkcs7_data().to_der_value(),
                content: Some(data.to_vec()),
            },
            digest,
        };

        let encoded = encode_digested_data_cms(&dd);

        Ok(CmsMessage {
            content_type: CmsContentType::DigestedData,
            signed_data: None,
            enveloped_data: None,
            encrypted_data: None,
            digested_data: Some(dd),
            raw: encoded,
        })
    }

    /// Verify the digest in a DigestedData message.
    ///
    /// Re-computes the digest from the encapsulated content and compares
    /// it with the stored digest value.
    pub fn verify_digest(&self) -> Result<bool, PkiError> {
        let dd = self
            .digested_data
            .as_ref()
            .ok_or_else(|| cerr("not DigestedData"))?;

        let content = dd
            .encap_content_info
            .content
            .as_ref()
            .ok_or_else(|| cerr("no content in DigestedData"))?;

        let alg = oid_to_digest_alg(&dd.digest_algorithm.oid)?;
        let computed = compute_digest(content, alg)?;

        Ok(computed == dd.digest)
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

fn oid_to_content_type(oid: &Oid) -> CmsContentType {
    if *oid == known::pkcs7_data() {
        CmsContentType::Data
    } else if *oid == known::pkcs7_signed_data() {
        CmsContentType::SignedData
    } else if *oid == known::pkcs7_enveloped_data() {
        CmsContentType::EnvelopedData
    } else if *oid == known::pkcs7_digested_data() {
        CmsContentType::DigestedData
    } else if *oid == known::pkcs7_encrypted_data() {
        CmsContentType::EncryptedData
    } else {
        CmsContentType::Unknown
    }
}

fn oid_to_digest_alg(oid_bytes: &[u8]) -> Result<CmsDigestAlg, PkiError> {
    let oid = Oid::from_der_value(oid_bytes).map_err(|e| cerr(&format!("digest OID: {e}")))?;
    if oid == known::sha256() {
        Ok(CmsDigestAlg::Sha256)
    } else if oid == known::sha384() {
        Ok(CmsDigestAlg::Sha384)
    } else if oid == known::sha512() {
        Ok(CmsDigestAlg::Sha512)
    } else {
        Err(cerr(&format!("unsupported digest alg: {oid}")))
    }
}

fn digest_alg_identifier(alg: CmsDigestAlg) -> AlgorithmIdentifier {
    let oid = match alg {
        CmsDigestAlg::Sha256 => known::sha256().to_der_value(),
        CmsDigestAlg::Sha384 => known::sha384().to_der_value(),
        CmsDigestAlg::Sha512 => known::sha512().to_der_value(),
    };
    AlgorithmIdentifier {
        oid,
        params: Some(vec![0x05, 0x00]), // NULL
    }
}

fn compute_digest(data: &[u8], alg: CmsDigestAlg) -> Result<Vec<u8>, PkiError> {
    match alg {
        CmsDigestAlg::Sha256 => {
            let mut h = hitls_crypto::sha2::Sha256::new();
            h.update(data).map_err(PkiError::from)?;
            Ok(h.finish().map_err(PkiError::from)?.to_vec())
        }
        CmsDigestAlg::Sha384 => {
            let mut h = hitls_crypto::sha2::Sha384::new();
            h.update(data).map_err(PkiError::from)?;
            Ok(h.finish().map_err(PkiError::from)?.to_vec())
        }
        CmsDigestAlg::Sha512 => {
            let mut h = hitls_crypto::sha2::Sha512::new();
            h.update(data).map_err(PkiError::from)?;
            Ok(h.finish().map_err(PkiError::from)?.to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cms_content_type_detection() {
        let sd_oid = known::pkcs7_signed_data();
        assert_eq!(oid_to_content_type(&sd_oid), CmsContentType::SignedData);
        let data_oid = known::pkcs7_data();
        assert_eq!(oid_to_content_type(&data_oid), CmsContentType::Data);
    }

    #[test]
    fn test_cms_encode_decode_encap_content_info() {
        let eci = EncapContentInfo {
            content_type: known::pkcs7_data().to_der_value(),
            content: Some(b"Hello CMS".to_vec()),
        };
        let encoded = encode_encap_content_info(&eci);
        // Verify it's a valid SEQUENCE
        let mut dec = Decoder::new(&encoded);
        let mut seq = dec.read_sequence().unwrap();
        let oid = seq.read_oid().unwrap();
        assert_eq!(oid, known::pkcs7_data().to_der_value());
    }

    #[test]
    fn test_cms_algorithm_identifier_roundtrip() {
        let alg = AlgorithmIdentifier {
            oid: known::sha256().to_der_value(),
            params: Some(vec![0x05, 0x00]),
        };
        let encoded = encode_algorithm_identifier(&alg);
        let mut dec = Decoder::new(&encoded);
        let parsed = parse_algorithm_identifier(&mut dec).unwrap();
        assert_eq!(parsed.oid, alg.oid);
    }

    #[test]
    fn test_cms_build_signed_attrs() {
        let ct_oid = known::pkcs7_data().to_der_value();
        let digest = vec![0xAA; 32];
        let attrs = build_signed_attrs(&ct_oid, &digest);
        // Verify we can parse 2 attributes
        let mut dec = Decoder::new(&attrs);
        let mut attr1 = dec.read_sequence().unwrap();
        let oid1 = attr1.read_oid().unwrap();
        assert_eq!(oid1, known::pkcs9_content_type().to_der_value());
        let mut attr2 = dec.read_sequence().unwrap();
        let oid2 = attr2.read_oid().unwrap();
        assert_eq!(oid2, known::pkcs9_message_digest().to_der_value());
    }

    #[test]
    fn test_cms_digest_alg_lookup() {
        let sha256_oid = known::sha256().to_der_value();
        assert_eq!(
            oid_to_digest_alg(&sha256_oid).unwrap(),
            CmsDigestAlg::Sha256
        );
        let sha384_oid = known::sha384().to_der_value();
        assert_eq!(
            oid_to_digest_alg(&sha384_oid).unwrap(),
            CmsDigestAlg::Sha384
        );
    }

    #[test]
    fn test_cms_compute_digest() {
        let data = b"test data";
        let d = compute_digest(data, CmsDigestAlg::Sha256).unwrap();
        assert_eq!(d.len(), 32);
        let d2 = compute_digest(data, CmsDigestAlg::Sha384).unwrap();
        assert_eq!(d2.len(), 48);
    }

    #[test]
    fn test_cms_encode_signed_data_structure() {
        // Build a minimal SignedData and verify it encodes
        let sd = SignedData {
            version: 1,
            digest_algorithms: vec![digest_alg_identifier(CmsDigestAlg::Sha256)],
            encap_content_info: EncapContentInfo {
                content_type: known::pkcs7_data().to_der_value(),
                content: Some(b"hello".to_vec()),
            },
            certificates: vec![],
            signer_infos: vec![],
        };
        let encoded = encode_signed_data_cms(&sd);

        // Parse it back
        let msg = CmsMessage::from_der(&encoded).unwrap();
        assert_eq!(msg.content_type, CmsContentType::SignedData);
        let parsed_sd = msg.signed_data.unwrap();
        assert_eq!(parsed_sd.version, 1);
        assert_eq!(
            parsed_sd.encap_content_info.content.as_deref(),
            Some(b"hello".as_slice())
        );
    }

    #[test]
    fn test_cms_detached_content_type() {
        // SignedData with no embedded content
        let sd = SignedData {
            version: 1,
            digest_algorithms: vec![],
            encap_content_info: EncapContentInfo {
                content_type: known::pkcs7_data().to_der_value(),
                content: None,
            },
            certificates: vec![],
            signer_infos: vec![],
        };
        let encoded = encode_signed_data_cms(&sd);
        let msg = CmsMessage::from_der(&encoded).unwrap();
        let parsed = msg.signed_data.unwrap();
        assert!(parsed.encap_content_info.content.is_none());
    }

    #[test]
    fn test_cms_digested_data_create_and_verify() {
        let data = b"Hello, DigestedData!";
        let msg = CmsMessage::digest(data, CmsDigestAlg::Sha256).unwrap();
        assert_eq!(msg.content_type, CmsContentType::DigestedData);
        assert!(msg.digested_data.is_some());
        let dd = msg.digested_data.as_ref().unwrap();
        assert_eq!(dd.version, 0);
        assert_eq!(dd.digest.len(), 32);
        assert_eq!(
            dd.encap_content_info.content.as_deref(),
            Some(data.as_slice())
        );
        assert!(msg.verify_digest().unwrap());
    }

    #[test]
    fn test_cms_digested_data_roundtrip() {
        let data = b"Roundtrip test data for CMS DigestedData";
        let msg = CmsMessage::digest(data, CmsDigestAlg::Sha384).unwrap();
        let dd = msg.digested_data.as_ref().unwrap();
        assert_eq!(dd.digest.len(), 48); // SHA-384

        // Encode and re-parse
        let parsed = CmsMessage::from_der(&msg.raw).unwrap();
        assert_eq!(parsed.content_type, CmsContentType::DigestedData);
        let parsed_dd = parsed.digested_data.as_ref().unwrap();
        assert_eq!(parsed_dd.version, dd.version);
        assert_eq!(parsed_dd.digest, dd.digest);
        assert_eq!(
            parsed_dd.encap_content_info.content,
            dd.encap_content_info.content
        );
        assert!(parsed.verify_digest().unwrap());
    }

    #[test]
    fn test_cms_digested_data_sha512() {
        let data = b"SHA-512 digested data";
        let msg = CmsMessage::digest(data, CmsDigestAlg::Sha512).unwrap();
        let dd = msg.digested_data.as_ref().unwrap();
        assert_eq!(dd.digest.len(), 64);
        assert!(msg.verify_digest().unwrap());
    }

    #[test]
    fn test_cms_digested_data_tampered_fails() {
        let data = b"original data";
        let msg = CmsMessage::digest(data, CmsDigestAlg::Sha256).unwrap();

        // Re-parse and tamper the digest
        let mut parsed = CmsMessage::from_der(&msg.raw).unwrap();
        if let Some(dd) = parsed.digested_data.as_mut() {
            dd.digest[0] ^= 0xFF;
        }
        assert!(!parsed.verify_digest().unwrap());
    }

    #[test]
    fn test_cms_digested_data_tampered_content_fails() {
        let data = b"original data";
        let msg = CmsMessage::digest(data, CmsDigestAlg::Sha256).unwrap();

        let mut parsed = CmsMessage::from_der(&msg.raw).unwrap();
        if let Some(dd) = parsed.digested_data.as_mut() {
            dd.encap_content_info.content = Some(b"tampered data".to_vec());
        }
        assert!(!parsed.verify_digest().unwrap());
    }

    #[test]
    fn test_cms_digested_data_content_type_detection() {
        let dd_oid = known::pkcs7_digested_data();
        assert_eq!(oid_to_content_type(&dd_oid), CmsContentType::DigestedData);
    }

    #[test]
    fn test_cms_encode_signer_info() {
        let si = SignerInfo {
            version: 1,
            sid: SignerIdentifier::IssuerAndSerialNumber {
                issuer: enc_seq(&[]),
                serial_number: vec![0x01],
            },
            digest_algorithm: digest_alg_identifier(CmsDigestAlg::Sha256),
            signed_attrs: None,
            signature_algorithm: AlgorithmIdentifier {
                oid: known::sha256_with_rsa_encryption().to_der_value(),
                params: Some(vec![0x05, 0x00]),
            },
            signature: vec![0xAA; 64],
        };
        let encoded = encode_signer_info(&si);
        // Verify it's parseable as a SEQUENCE
        let mut dec = Decoder::new(&encoded);
        let _seq = dec.read_sequence().unwrap();
    }

    /// Helper: make a minimal Certificate with Ed25519 public key for CMS tests.
    fn make_ed25519_cert(pub_key: &[u8]) -> crate::x509::Certificate {
        crate::x509::Certificate {
            raw: Vec::new(),
            version: 3,
            serial_number: vec![0x01],
            issuer: crate::x509::DistinguishedName {
                entries: Vec::new(),
            },
            subject: crate::x509::DistinguishedName {
                entries: Vec::new(),
            },
            not_before: 0,
            not_after: 0,
            public_key: crate::x509::SubjectPublicKeyInfo {
                algorithm_oid: known::ed25519().to_der_value(),
                algorithm_params: None,
                public_key: pub_key.to_vec(),
            },
            extensions: Vec::new(),
            tbs_raw: Vec::new(),
            signature_algorithm: known::ed25519().to_der_value(),
            signature_params: None,
            signature_value: Vec::new(),
        }
    }

    /// Helper: make a minimal Certificate with Ed448 public key for CMS tests.
    fn make_ed448_cert(pub_key: &[u8]) -> crate::x509::Certificate {
        crate::x509::Certificate {
            raw: Vec::new(),
            version: 3,
            serial_number: vec![0x01],
            issuer: crate::x509::DistinguishedName {
                entries: Vec::new(),
            },
            subject: crate::x509::DistinguishedName {
                entries: Vec::new(),
            },
            not_before: 0,
            not_after: 0,
            public_key: crate::x509::SubjectPublicKeyInfo {
                algorithm_oid: known::ed448().to_der_value(),
                algorithm_params: None,
                public_key: pub_key.to_vec(),
            },
            extensions: Vec::new(),
            tbs_raw: Vec::new(),
            signature_algorithm: known::ed448().to_der_value(),
            signature_params: None,
            signature_value: Vec::new(),
        }
    }

    #[test]
    fn test_cms_ed25519_verify_roundtrip() {
        let seed = vec![0x42u8; 32];
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(&seed).unwrap();
        let pub_key = kp.public_key().to_vec();
        let cert = make_ed25519_cert(&pub_key);

        let message = b"CMS Ed25519 test message";
        let signature = kp.sign(message).unwrap().to_vec();

        let sig_alg = AlgorithmIdentifier {
            oid: known::ed25519().to_der_value(),
            params: None,
        };

        verify_signature_with_cert(message, &signature, &sig_alg, &cert).unwrap();
    }

    #[test]
    fn test_cms_ed25519_tampered_signature() {
        let seed = vec![0x42u8; 32];
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(&seed).unwrap();
        let pub_key = kp.public_key().to_vec();
        let cert = make_ed25519_cert(&pub_key);

        let message = b"CMS Ed25519 tamper test";
        let mut signature = kp.sign(message).unwrap().to_vec();
        signature[0] ^= 0xFF; // tamper

        let sig_alg = AlgorithmIdentifier {
            oid: known::ed25519().to_der_value(),
            params: None,
        };

        assert!(verify_signature_with_cert(message, &signature, &sig_alg, &cert).is_err());
    }

    #[test]
    fn test_cms_ed448_verify_roundtrip() {
        let seed = vec![0x42u8; 57];
        let kp = hitls_crypto::ed448::Ed448KeyPair::from_seed(&seed).unwrap();
        let pub_key = kp.public_key().to_vec();
        let cert = make_ed448_cert(&pub_key);

        let message = b"CMS Ed448 test message";
        let signature = kp.sign(message).unwrap().to_vec();

        let sig_alg = AlgorithmIdentifier {
            oid: known::ed448().to_der_value(),
            params: None,
        };

        verify_signature_with_cert(message, &signature, &sig_alg, &cert).unwrap();
    }

    // -----------------------------------------------------------------------
    // Phase 51: Real C test vector — CMS SignedData tests
    // -----------------------------------------------------------------------

    const CMS_CA_CERT: &str = include_str!("../../../../tests/vectors/cms/ca_cert.pem");
    const CMS_MSG: &[u8] = include_bytes!("../../../../tests/vectors/cms/msg.txt");

    const CMS_RSA_PKCS1_ATTACHED: &[u8] =
        include_bytes!("../../../../tests/vectors/cms/rsa_pkcs1_attached.cms");
    const CMS_RSA_PKCS1_DETACHED: &[u8] =
        include_bytes!("../../../../tests/vectors/cms/rsa_pkcs1_detached.cms");
    const CMS_RSA_PSS_ATTACHED: &[u8] =
        include_bytes!("../../../../tests/vectors/cms/rsa_pss_attached.cms");
    const CMS_P256_ATTACHED: &[u8] =
        include_bytes!("../../../../tests/vectors/cms/p256_attached.cms");
    const CMS_P256_DETACHED: &[u8] =
        include_bytes!("../../../../tests/vectors/cms/p256_detached.cms");
    const CMS_P384_ATTACHED: &[u8] =
        include_bytes!("../../../../tests/vectors/cms/p384_attached.cms");
    const CMS_P384_DETACHED: &[u8] =
        include_bytes!("../../../../tests/vectors/cms/p384_detached.cms");
    const CMS_P521_ATTACHED: &[u8] =
        include_bytes!("../../../../tests/vectors/cms/p521_attached.cms");

    // --- Parsing tests ---

    #[test]
    fn test_cms_parse_rsa_pkcs1_attached() {
        let msg = CmsMessage::from_der(CMS_RSA_PKCS1_ATTACHED).unwrap();
        assert_eq!(msg.content_type, CmsContentType::SignedData);
        let sd = msg.signed_data.as_ref().unwrap();
        assert!(sd.encap_content_info.content.is_some());
        assert!(!sd.signer_infos.is_empty());
        assert!(!sd.certificates.is_empty());
    }

    #[test]
    fn test_cms_parse_rsa_pss_attached() {
        let msg = CmsMessage::from_der(CMS_RSA_PSS_ATTACHED).unwrap();
        assert_eq!(msg.content_type, CmsContentType::SignedData);
        let sd = msg.signed_data.as_ref().unwrap();
        assert!(sd.encap_content_info.content.is_some());
    }

    #[test]
    fn test_cms_parse_p256_detached() {
        let msg = CmsMessage::from_der(CMS_P256_DETACHED).unwrap();
        assert_eq!(msg.content_type, CmsContentType::SignedData);
        let sd = msg.signed_data.as_ref().unwrap();
        // Detached: no embedded content
        assert!(sd.encap_content_info.content.is_none());
    }

    #[test]
    fn test_cms_parse_p384_attached() {
        let msg = CmsMessage::from_der(CMS_P384_ATTACHED).unwrap();
        assert_eq!(msg.content_type, CmsContentType::SignedData);
        let sd = msg.signed_data.as_ref().unwrap();
        assert!(sd.encap_content_info.content.is_some());
    }

    // --- Verification tests ---

    #[test]
    fn test_cms_verify_rsa_pkcs1_attached() {
        let msg = CmsMessage::from_der(CMS_RSA_PKCS1_ATTACHED).unwrap();
        let ca = crate::x509::Certificate::from_pem(CMS_CA_CERT).unwrap();
        let result = msg.verify_signatures(None, &[ca]);
        assert!(
            result.is_ok(),
            "RSA PKCS#1 attached verify failed: {result:?}"
        );
        assert!(result.unwrap());
    }

    #[test]
    fn test_cms_verify_p256_attached() {
        let msg = CmsMessage::from_der(CMS_P256_ATTACHED).unwrap();
        let ca = crate::x509::Certificate::from_pem(CMS_CA_CERT).unwrap();
        let result = msg.verify_signatures(None, &[ca]);
        assert!(result.is_ok(), "P-256 attached verify failed: {result:?}");
        assert!(result.unwrap());
    }

    #[test]
    fn test_cms_verify_p384_detached() {
        let msg = CmsMessage::from_der(CMS_P384_DETACHED).unwrap();
        let ca = crate::x509::Certificate::from_pem(CMS_CA_CERT).unwrap();
        let result = msg.verify_signatures(Some(CMS_MSG), &[ca]);
        assert!(result.is_ok(), "P-384 detached verify failed: {result:?}");
        assert!(result.unwrap());
    }

    #[test]
    fn test_cms_verify_p521_attached() {
        let msg = CmsMessage::from_der(CMS_P521_ATTACHED).unwrap();
        let ca = crate::x509::Certificate::from_pem(CMS_CA_CERT).unwrap();
        let result = msg.verify_signatures(None, &[ca]);
        assert!(result.is_ok(), "P-521 attached verify failed: {result:?}");
        assert!(result.unwrap());
    }

    #[test]
    fn test_cms_verify_rsa_pkcs1_detached() {
        let msg = CmsMessage::from_der(CMS_RSA_PKCS1_DETACHED).unwrap();
        let ca = crate::x509::Certificate::from_pem(CMS_CA_CERT).unwrap();
        let result = msg.verify_signatures(Some(CMS_MSG), &[ca]);
        assert!(
            result.is_ok(),
            "RSA PKCS#1 detached verify failed: {result:?}"
        );
        assert!(result.unwrap());
    }

    // --- Failure tests ---

    #[test]
    fn test_cms_verify_detached_wrong_content() {
        let msg = CmsMessage::from_der(CMS_P256_DETACHED).unwrap();
        let ca = crate::x509::Certificate::from_pem(CMS_CA_CERT).unwrap();
        let wrong_content = b"wrong content that was not signed";
        let result = msg.verify_signatures(Some(wrong_content), &[ca]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cms_verify_tampered_cms() {
        let mut tampered = CMS_RSA_PKCS1_ATTACHED.to_vec();
        // Flip a bit in the signature area (near the end)
        if let Some(b) = tampered.last_mut() {
            *b ^= 0xFF;
        }
        let msg = CmsMessage::from_der(&tampered);
        if let Ok(msg) = msg {
            let ca = crate::x509::Certificate::from_pem(CMS_CA_CERT).unwrap();
            let result = msg.verify_signatures(None, &[ca]);
            assert!(result.is_err());
        }
        // If parse fails, that's also a valid failure path
    }

    #[test]
    fn test_cms_parse_truncated() {
        let truncated = &CMS_RSA_PKCS1_ATTACHED[..50];
        let result = CmsMessage::from_der(truncated);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Phase 52: CMS SubjectKeyIdentifier signer lookup
    // -----------------------------------------------------------------------

    #[test]
    fn test_cms_ski_signer_lookup() {
        // Build a cert with a known SKI, then look it up by SKI
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let pub_key = kp.public_key().to_vec();
        let ski = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01];
        let mut cert = make_ed25519_cert(&pub_key);
        // Add SKI extension
        let mut enc = hitls_utils::asn1::Encoder::new();
        enc.write_octet_string(&ski);
        let ski_value = enc.finish();
        cert.extensions.push(crate::x509::X509Extension {
            oid: known::subject_key_identifier().to_der_value(),
            critical: false,
            value: ski_value,
        });

        let sid = SignerIdentifier::SubjectKeyIdentifier(ski.clone());
        let certs = vec![cert];
        let found = find_signer_cert(&sid, &certs);
        assert!(found.is_ok(), "should find cert by SKI");
    }

    #[test]
    fn test_cms_ski_signer_not_found() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let pub_key = kp.public_key().to_vec();
        let cert = make_ed25519_cert(&pub_key);
        // No SKI extension on cert

        let sid = SignerIdentifier::SubjectKeyIdentifier(vec![0x01, 0x02, 0x03]);
        let certs = vec![cert];
        let result = find_signer_cert(&sid, &certs);
        assert!(result.is_err(), "should not find cert by non-matching SKI");
    }

    #[test]
    fn test_cms_ski_vs_issuer_serial() {
        // Verify both lookup methods find the same cert
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let pub_key = kp.public_key().to_vec();
        let ski = vec![0xAA, 0xBB, 0xCC];
        let serial = vec![0x42];
        let mut cert = make_ed25519_cert(&pub_key);
        cert.serial_number = serial.clone();
        let mut enc = hitls_utils::asn1::Encoder::new();
        enc.write_octet_string(&ski);
        let ski_value = enc.finish();
        cert.extensions.push(crate::x509::X509Extension {
            oid: known::subject_key_identifier().to_der_value(),
            critical: false,
            value: ski_value,
        });

        let certs = vec![cert];

        // Lookup by SKI
        let sid_ski = SignerIdentifier::SubjectKeyIdentifier(ski);
        let found_ski = find_signer_cert(&sid_ski, &certs).unwrap();

        // Lookup by serial
        let sid_serial = SignerIdentifier::IssuerAndSerialNumber {
            issuer: Vec::new(),
            serial_number: serial,
        };
        let found_serial = find_signer_cert(&sid_serial, &certs).unwrap();

        // Both should find the same cert
        assert_eq!(found_ski.serial_number, found_serial.serial_number);
    }

    #[test]
    fn test_cms_ski_multiple_certs() {
        // Multiple certs, only one matches the SKI
        let kp1 = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let kp2 = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let mut cert1 = make_ed25519_cert(kp1.public_key());
        cert1.serial_number = vec![0x01];
        let mut cert2 = make_ed25519_cert(kp2.public_key());
        cert2.serial_number = vec![0x02];

        let target_ski = vec![0xFF, 0xEE, 0xDD];
        let mut enc = hitls_utils::asn1::Encoder::new();
        enc.write_octet_string(&target_ski);
        let ski_value = enc.finish();
        cert2.extensions.push(crate::x509::X509Extension {
            oid: known::subject_key_identifier().to_der_value(),
            critical: false,
            value: ski_value,
        });

        let certs = vec![cert1, cert2];
        let sid = SignerIdentifier::SubjectKeyIdentifier(target_ski);
        let found = find_signer_cert(&sid, &certs).unwrap();
        assert_eq!(found.serial_number, vec![0x02]);
    }

    // -----------------------------------------------------------------------
    // Phase 53: CMS NoAttr (no signed attributes) tests
    // -----------------------------------------------------------------------

    const NOATTR_CA_CERT: &str = include_str!("../../../../tests/vectors/cms/noattr/ca_cert.pem");
    const NOATTR_P256_ATTACHED: &[u8] =
        include_bytes!("../../../../tests/vectors/cms/noattr/p256_attached.cms");
    const NOATTR_P256_DETACHED: &[u8] =
        include_bytes!("../../../../tests/vectors/cms/noattr/p256_detached.cms");
    const NOATTR_P384_ATTACHED: &[u8] =
        include_bytes!("../../../../tests/vectors/cms/noattr/p384_attached.cms");
    const NOATTR_P384_DETACHED: &[u8] =
        include_bytes!("../../../../tests/vectors/cms/noattr/p384_detached.cms");
    const NOATTR_P521_ATTACHED: &[u8] =
        include_bytes!("../../../../tests/vectors/cms/noattr/p521_attached.cms");
    const NOATTR_P521_DETACHED: &[u8] =
        include_bytes!("../../../../tests/vectors/cms/noattr/p521_detached.cms");
    const NOATTR_RSA_PKCS1_ATTACHED: &[u8] =
        include_bytes!("../../../../tests/vectors/cms/noattr/rsa_pkcs1_attached.cms");
    const NOATTR_RSA_PKCS1_DETACHED: &[u8] =
        include_bytes!("../../../../tests/vectors/cms/noattr/rsa_pkcs1_detached.cms");
    const NOATTR_RSA_PSS_ATTACHED: &[u8] =
        include_bytes!("../../../../tests/vectors/cms/noattr/rsa_pss_attached.cms");
    const NOATTR_RSA_PSS_DETACHED: &[u8] =
        include_bytes!("../../../../tests/vectors/cms/noattr/rsa_pss_detached.cms");

    #[test]
    fn test_cms_noattr_p256_parse() {
        let msg = CmsMessage::from_der(NOATTR_P256_ATTACHED).unwrap();
        assert_eq!(msg.content_type, CmsContentType::SignedData);
        let sd = msg.signed_data.as_ref().unwrap();
        assert!(!sd.signer_infos.is_empty());
        // No signed attributes
        assert!(
            sd.signer_infos[0].signed_attrs.is_none(),
            "noattr CMS should have no signed attributes"
        );
    }

    #[test]
    fn test_cms_noattr_p256_verify() {
        let msg = CmsMessage::from_der(NOATTR_P256_ATTACHED).unwrap();
        let ca = crate::x509::Certificate::from_pem(NOATTR_CA_CERT).unwrap();
        let result = msg.verify_signatures(None, &[ca]);
        assert!(result.is_ok(), "noattr P-256 attached verify: {result:?}");
        assert!(result.unwrap());
    }

    #[test]
    fn test_cms_noattr_p256_detached_verify() {
        let msg = CmsMessage::from_der(NOATTR_P256_DETACHED).unwrap();
        let ca = crate::x509::Certificate::from_pem(NOATTR_CA_CERT).unwrap();
        let result = msg.verify_signatures(Some(CMS_MSG), &[ca]);
        assert!(result.is_ok(), "noattr P-256 detached verify: {result:?}");
        assert!(result.unwrap());
    }

    #[test]
    fn test_cms_noattr_p384_verify() {
        let msg = CmsMessage::from_der(NOATTR_P384_ATTACHED).unwrap();
        let ca = crate::x509::Certificate::from_pem(NOATTR_CA_CERT).unwrap();
        let result = msg.verify_signatures(None, &[ca]);
        assert!(result.is_ok(), "noattr P-384 attached verify: {result:?}");
        assert!(result.unwrap());
    }

    #[test]
    fn test_cms_noattr_p384_detached_verify() {
        let msg = CmsMessage::from_der(NOATTR_P384_DETACHED).unwrap();
        let ca = crate::x509::Certificate::from_pem(NOATTR_CA_CERT).unwrap();
        let result = msg.verify_signatures(Some(CMS_MSG), &[ca]);
        assert!(result.is_ok(), "noattr P-384 detached verify: {result:?}");
        assert!(result.unwrap());
    }

    #[test]
    fn test_cms_noattr_p521_verify() {
        let msg = CmsMessage::from_der(NOATTR_P521_ATTACHED).unwrap();
        let ca = crate::x509::Certificate::from_pem(NOATTR_CA_CERT).unwrap();
        let result = msg.verify_signatures(None, &[ca]);
        assert!(result.is_ok(), "noattr P-521 attached verify: {result:?}");
        assert!(result.unwrap());
    }

    #[test]
    fn test_cms_noattr_p521_detached_verify() {
        let msg = CmsMessage::from_der(NOATTR_P521_DETACHED).unwrap();
        let ca = crate::x509::Certificate::from_pem(NOATTR_CA_CERT).unwrap();
        let result = msg.verify_signatures(Some(CMS_MSG), &[ca]);
        assert!(result.is_ok(), "noattr P-521 detached verify: {result:?}");
        assert!(result.unwrap());
    }

    #[test]
    fn test_cms_noattr_rsa_pkcs1_verify() {
        let msg = CmsMessage::from_der(NOATTR_RSA_PKCS1_ATTACHED).unwrap();
        let ca = crate::x509::Certificate::from_pem(NOATTR_CA_CERT).unwrap();
        let result = msg.verify_signatures(None, &[ca]);
        assert!(
            result.is_ok(),
            "noattr RSA PKCS#1 attached verify: {result:?}"
        );
        assert!(result.unwrap());
    }

    #[test]
    fn test_cms_noattr_rsa_pkcs1_detached_verify() {
        let msg = CmsMessage::from_der(NOATTR_RSA_PKCS1_DETACHED).unwrap();
        let ca = crate::x509::Certificate::from_pem(NOATTR_CA_CERT).unwrap();
        let result = msg.verify_signatures(Some(CMS_MSG), &[ca]);
        assert!(
            result.is_ok(),
            "noattr RSA PKCS#1 detached verify: {result:?}"
        );
        assert!(result.unwrap());
    }

    #[test]
    fn test_cms_noattr_rsa_pss_verify() {
        let msg = CmsMessage::from_der(NOATTR_RSA_PSS_ATTACHED).unwrap();
        let ca = crate::x509::Certificate::from_pem(NOATTR_CA_CERT).unwrap();
        let result = msg.verify_signatures(None, &[ca]);
        assert!(result.is_ok(), "noattr RSA-PSS attached verify: {result:?}");
        assert!(result.unwrap());
    }

    #[test]
    fn test_cms_noattr_rsa_pss_detached_verify() {
        let msg = CmsMessage::from_der(NOATTR_RSA_PSS_DETACHED).unwrap();
        let ca = crate::x509::Certificate::from_pem(NOATTR_CA_CERT).unwrap();
        let result = msg.verify_signatures(Some(CMS_MSG), &[ca]);
        assert!(result.is_ok(), "noattr RSA-PSS detached verify: {result:?}");
        assert!(result.unwrap());
    }

    // -----------------------------------------------------------------------
    // Phase 53: CMS Chain cert tests
    // -----------------------------------------------------------------------

    const CHAIN_ROOT_CRT: &str = include_str!("../../../../tests/vectors/cms/chain/root_ca.crt");
    const CHAIN_MID_CRT: &str = include_str!("../../../../tests/vectors/cms/chain/mid_ca.crt");
    const CHAIN_DEVICE1_CRT: &str = include_str!("../../../../tests/vectors/cms/chain/device1.crt");
    const CHAIN_DEVICE2_CRT: &str = include_str!("../../../../tests/vectors/cms/chain/device2.crt");

    #[test]
    fn test_cms_chain_certs_parse() {
        // Verify all chain certs parse correctly
        let root = crate::x509::Certificate::from_pem(CHAIN_ROOT_CRT).unwrap();
        let mid = crate::x509::Certificate::from_pem(CHAIN_MID_CRT).unwrap();
        let dev1 = crate::x509::Certificate::from_pem(CHAIN_DEVICE1_CRT).unwrap();
        let dev2 = crate::x509::Certificate::from_pem(CHAIN_DEVICE2_CRT).unwrap();

        assert!(root.is_self_signed());
        assert!(root.is_ca());
        assert!(mid.is_ca());
        assert!(!dev1.is_self_signed());
        assert!(!dev2.is_self_signed());
    }

    #[test]
    fn test_cms_chain_verify() {
        // Verify 3-level chain: root → mid → device
        let root = crate::x509::Certificate::from_pem(CHAIN_ROOT_CRT).unwrap();
        let mid = crate::x509::Certificate::from_pem(CHAIN_MID_CRT).unwrap();
        let dev1 = crate::x509::Certificate::from_pem(CHAIN_DEVICE1_CRT).unwrap();

        let mut verifier = crate::x509::verify::CertificateVerifier::new();
        verifier.add_trusted_cert(root);
        // Use a time that's within the cert validity period
        verifier.set_verification_time(1_767_225_600); // Jan 1, 2026
        let chain = verifier.verify_cert(&dev1, &[mid]).unwrap();
        assert_eq!(chain.len(), 3);
    }

    // ── CMS Detached SignedData Tests ────────────────────────────────

    /// Helper: generate a self-signed Ed25519 cert DER + key PKCS#8 DER.
    fn gen_ed25519_cert_and_key() -> (Vec<u8>, Vec<u8>) {
        let seed = [0x55u8; 32];
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(&seed).unwrap();
        let sk = crate::x509::SigningKey::Ed25519(kp);
        let dn = crate::x509::DistinguishedName {
            entries: vec![("CN".to_string(), "CMS Detached Test".to_string())],
        };
        let cert =
            crate::x509::CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000)
                .unwrap();
        let key_der = crate::pkcs8::encode_ed25519_pkcs8_der(&seed);
        (cert.raw, key_der)
    }

    /// Helper: generate a self-signed ECDSA P-256 cert DER + key PKCS#8 DER.
    fn gen_ecdsa_p256_cert_and_key() -> (Vec<u8>, Vec<u8>) {
        let kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
        let private_key = kp.private_key_bytes();
        let sk = crate::x509::SigningKey::Ecdsa {
            curve_id: hitls_types::EccCurveId::NistP256,
            key_pair: kp,
        };
        let dn = crate::x509::DistinguishedName {
            entries: vec![("CN".to_string(), "CMS Detached ECDSA Test".to_string())],
        };
        let cert =
            crate::x509::CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000)
                .unwrap();
        let key_der =
            crate::pkcs8::encode_ec_pkcs8_der(hitls_types::EccCurveId::NistP256, &private_key);
        (cert.raw, key_der)
    }

    #[test]
    fn test_cms_sign_detached_roundtrip() {
        let (cert_der, key_der) = gen_ed25519_cert_and_key();
        let data = b"Detached signing test data";

        let cms =
            CmsMessage::sign_detached(data, &cert_der, &key_der, CmsDigestAlg::Sha256).unwrap();

        // Embedded content should be None in the in-memory struct
        let sd = cms.signed_data.as_ref().unwrap();
        assert!(sd.encap_content_info.content.is_none());

        // DER roundtrip then verify with original data
        let cms2 = CmsMessage::from_der(&cms.raw).unwrap();
        let ok = cms2.verify_signatures(Some(data), &[]).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_cms_sign_detached_wrong_data() {
        let (cert_der, key_der) = gen_ed25519_cert_and_key();
        let data = b"Original data";

        let cms =
            CmsMessage::sign_detached(data, &cert_der, &key_der, CmsDigestAlg::Sha256).unwrap();

        // DER roundtrip; verify with wrong data should fail
        let cms2 = CmsMessage::from_der(&cms.raw).unwrap();
        let result = cms2.verify_signatures(Some(b"Wrong data"), &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cms_sign_detached_no_content() {
        let (cert_der, key_der) = gen_ed25519_cert_and_key();
        let data = b"Some content";

        let cms =
            CmsMessage::sign_detached(data, &cert_der, &key_der, CmsDigestAlg::Sha256).unwrap();

        // DER roundtrip; verify without providing external data should fail
        let cms2 = CmsMessage::from_der(&cms.raw).unwrap();
        let result = cms2.verify_signatures(None, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cms_sign_detached_ecdsa() {
        let (cert_der, key_der) = gen_ecdsa_p256_cert_and_key();
        let data = b"ECDSA detached signing test";

        let cms =
            CmsMessage::sign_detached(data, &cert_der, &key_der, CmsDigestAlg::Sha256).unwrap();

        // DER roundtrip then verify
        let cms2 = CmsMessage::from_der(&cms.raw).unwrap();
        let ok = cms2.verify_signatures(Some(data), &[]).unwrap();
        assert!(ok);

        // Content should be None (detached)
        let sd = cms2.signed_data.as_ref().unwrap();
        assert!(sd.encap_content_info.content.is_none());
    }
}
