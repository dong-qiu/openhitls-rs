//! X.509 certificate, CRL, CSR, and OCSP management.

pub mod crl;
pub mod ocsp;
pub mod verify;

use hitls_types::{CryptoError, EccCurveId, PkiError};
use hitls_utils::asn1::{tags, Decoder, TagClass};
use hitls_utils::oid::known;
use hitls_utils::oid::Oid;

/// An X.509 certificate.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// DER-encoded certificate data.
    pub raw: Vec<u8>,
    /// Certificate version (typically 3, encoded as 2).
    pub version: u8,
    /// Serial number.
    pub serial_number: Vec<u8>,
    /// Issuer distinguished name.
    pub issuer: DistinguishedName,
    /// Subject distinguished name.
    pub subject: DistinguishedName,
    /// Not-before validity time (UNIX timestamp).
    pub not_before: i64,
    /// Not-after validity time (UNIX timestamp).
    pub not_after: i64,
    /// Subject public key info.
    pub public_key: SubjectPublicKeyInfo,
    /// Extensions.
    pub extensions: Vec<X509Extension>,
    /// Raw TBS certificate bytes (for signature verification).
    pub tbs_raw: Vec<u8>,
    /// Signature algorithm OID (outer signatureAlgorithm field).
    pub signature_algorithm: Vec<u8>,
    /// Signature algorithm parameters (outer).
    pub signature_params: Option<Vec<u8>>,
    /// Signature value bytes.
    pub signature_value: Vec<u8>,
}

/// A distinguished name (DN).
#[derive(Debug, Clone)]
pub struct DistinguishedName {
    pub entries: Vec<(String, String)>,
}

/// Subject public key info.
#[derive(Debug, Clone)]
pub struct SubjectPublicKeyInfo {
    pub algorithm_oid: Vec<u8>,
    pub algorithm_params: Option<Vec<u8>>,
    pub public_key: Vec<u8>,
}

/// An X.509 extension.
#[derive(Debug, Clone)]
pub struct X509Extension {
    pub oid: Vec<u8>,
    pub critical: bool,
    pub value: Vec<u8>,
}

/// A certificate signing request (CSR / PKCS#10).
#[derive(Debug, Clone)]
pub struct CertificateRequest {
    /// DER-encoded CSR data.
    pub raw: Vec<u8>,
    /// Version (always 0).
    pub version: u8,
    /// Subject distinguished name.
    pub subject: DistinguishedName,
    /// Subject public key info.
    pub public_key: SubjectPublicKeyInfo,
    /// Requested extensions (from extensionRequest attribute).
    pub attributes: Vec<X509Extension>,
    /// Raw TBS bytes for signature verification.
    pub tbs_raw: Vec<u8>,
    /// Signature algorithm OID bytes.
    pub signature_algorithm: Vec<u8>,
    /// Signature value bytes.
    pub signature_value: Vec<u8>,
}

// CRL types are defined in crl.rs and re-exported here.
pub use crl::{CertificateRevocationList, RevocationReason, RevokedCertificate};
// OCSP types are defined in ocsp.rs and re-exported here.
pub use ocsp::{
    OcspBasicResponse, OcspCertId, OcspCertStatus, OcspRequest, OcspResponse, OcspResponseStatus,
    OcspSingleResponse, ResponderId,
};

// ---------------------------------------------------------------------------
// Distinguished Name helpers
// ---------------------------------------------------------------------------

impl std::fmt::Display for DistinguishedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts: Vec<String> = self
            .entries
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        write!(f, "{}", parts.join(", "))
    }
}

impl DistinguishedName {
    /// Get the value for a given attribute short name (e.g., "CN").
    pub fn get(&self, attr: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k == attr)
            .map(|(_, v)| v.as_str())
    }
}

// ---------------------------------------------------------------------------
// Extension types
// ---------------------------------------------------------------------------

/// Parsed BasicConstraints extension (RFC 5280 §4.2.1.9).
#[derive(Debug, Clone)]
pub struct BasicConstraints {
    pub is_ca: bool,
    pub path_len_constraint: Option<u32>,
}

/// Parsed KeyUsage extension (RFC 5280 §4.2.1.3) as a bit-flag mask.
#[derive(Debug, Clone, Copy)]
pub struct KeyUsage(pub u16);

impl KeyUsage {
    // BIT STRING bit numbering: bit 0 = MSB of first byte (0x80).
    pub const DIGITAL_SIGNATURE: u16 = 0x0080;
    pub const NON_REPUDIATION: u16 = 0x0040;
    pub const KEY_ENCIPHERMENT: u16 = 0x0020;
    pub const DATA_ENCIPHERMENT: u16 = 0x0010;
    pub const KEY_AGREEMENT: u16 = 0x0008;
    pub const KEY_CERT_SIGN: u16 = 0x0004;
    pub const CRL_SIGN: u16 = 0x0002;
    pub const ENCIPHER_ONLY: u16 = 0x0001;
    pub const DECIPHER_ONLY: u16 = 0x8000;

    pub fn has(&self, flag: u16) -> bool {
        self.0 & flag != 0
    }
}

/// Parse BasicConstraints from the extension value bytes.
/// `SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }`
fn parse_basic_constraints(value: &[u8]) -> Result<BasicConstraints, PkiError> {
    let mut dec = Decoder::new(value)
        .read_sequence()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let mut is_ca = false;
    let mut path_len_constraint = None;
    if !dec.is_empty() {
        let tag = dec
            .peek_tag()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        if tag.class == TagClass::Universal && tag.number == tags::BOOLEAN as u32 {
            is_ca = dec
                .read_boolean()
                .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        }
    }
    if !dec.is_empty() {
        let bytes = dec
            .read_integer()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let mut val: u32 = 0;
        for &b in bytes {
            val = val.checked_shl(8).unwrap_or(u32::MAX) | b as u32;
        }
        path_len_constraint = Some(val);
    }
    Ok(BasicConstraints {
        is_ca,
        path_len_constraint,
    })
}

/// Parse KeyUsage from the extension value bytes.
/// `BIT STRING` — first byte is unused-bits count, remaining bytes are the mask.
fn parse_key_usage(value: &[u8]) -> Result<KeyUsage, PkiError> {
    let mut dec = Decoder::new(value);
    let (unused_bits, data) = dec
        .read_bit_string()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let mut mask: u16 = 0;
    if !data.is_empty() {
        mask |= data[0] as u16;
    }
    if data.len() > 1 {
        mask |= (data[1] as u16) << 8;
    }
    // Clear unused bits in the last byte
    if unused_bits > 0 && !data.is_empty() {
        let last_idx = data.len() - 1;
        if last_idx == 0 {
            mask &= !((1u16 << unused_bits) - 1);
        } else {
            let high = (data[last_idx] as u16) << (last_idx as u16 * 8);
            let cleared = high & !((1u16 << unused_bits) - 1);
            mask = (mask & !(0xFF << (last_idx * 8))) | cleared;
        }
    }
    Ok(KeyUsage(mask))
}

// ---------------------------------------------------------------------------
// Certificate extension convenience methods
// ---------------------------------------------------------------------------

impl Certificate {
    /// Parse the BasicConstraints extension, if present.
    pub fn basic_constraints(&self) -> Option<BasicConstraints> {
        let bc_oid = known::basic_constraints().to_der_value();
        self.extensions
            .iter()
            .find(|e| e.oid == bc_oid)
            .and_then(|e| parse_basic_constraints(&e.value).ok())
    }

    /// Parse the KeyUsage extension, if present.
    pub fn key_usage(&self) -> Option<KeyUsage> {
        let ku_oid = known::key_usage().to_der_value();
        self.extensions
            .iter()
            .find(|e| e.oid == ku_oid)
            .and_then(|e| parse_key_usage(&e.value).ok())
    }

    /// Returns true if this certificate is a CA (BasicConstraints present with isCA=true).
    pub fn is_ca(&self) -> bool {
        self.basic_constraints().is_some_and(|bc| bc.is_ca)
    }

    /// Returns true if this certificate is self-signed (issuer DN == subject DN).
    pub fn is_self_signed(&self) -> bool {
        self.issuer.entries == self.subject.entries
    }
}

impl PartialEq for DistinguishedName {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}

impl Eq for DistinguishedName {}

// ---------------------------------------------------------------------------
// AlgorithmIdentifier parsing
// ---------------------------------------------------------------------------

pub(crate) fn parse_algorithm_identifier(
    dec: &mut Decoder,
) -> Result<(Vec<u8>, Option<Vec<u8>>), PkiError> {
    let mut alg_dec = dec
        .read_sequence()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let oid = alg_dec
        .read_oid()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?
        .to_vec();
    let params = if !alg_dec.is_empty() {
        let tlv = alg_dec
            .read_tlv()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        // NULL (tag 0x05, empty) → None; otherwise store raw value
        if tlv.tag.number == 0x05 && tlv.value.is_empty() {
            None
        } else {
            Some(tlv.value.to_vec())
        }
    } else {
        None
    };
    Ok((oid, params))
}

// ---------------------------------------------------------------------------
// Name / DN parsing
// ---------------------------------------------------------------------------

pub(crate) fn parse_name(dec: &mut Decoder) -> Result<DistinguishedName, PkiError> {
    let mut name_dec = dec
        .read_sequence()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let mut entries = Vec::new();
    while !name_dec.is_empty() {
        let mut rdn_dec = name_dec
            .read_set()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        while !rdn_dec.is_empty() {
            let mut atav_dec = rdn_dec
                .read_sequence()
                .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
            let oid_bytes = atav_dec
                .read_oid()
                .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
            let oid =
                Oid::from_der_value(oid_bytes).map_err(|e| PkiError::Asn1Error(e.to_string()))?;
            let attr_name = known::oid_to_dn_short_name(&oid)
                .map(|s| s.to_string())
                .unwrap_or_else(|| oid.to_dot_string());
            let value = atav_dec
                .read_string()
                .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
            entries.push((attr_name, value));
        }
    }
    Ok(DistinguishedName { entries })
}

// ---------------------------------------------------------------------------
// Validity parsing
// ---------------------------------------------------------------------------

fn parse_validity(dec: &mut Decoder) -> Result<(i64, i64), PkiError> {
    let mut val_dec = dec
        .read_sequence()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let not_before = val_dec
        .read_time()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let not_after = val_dec
        .read_time()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    Ok((not_before, not_after))
}

// ---------------------------------------------------------------------------
// SubjectPublicKeyInfo parsing
// ---------------------------------------------------------------------------

fn parse_subject_public_key_info(dec: &mut Decoder) -> Result<SubjectPublicKeyInfo, PkiError> {
    let mut spki_dec = dec
        .read_sequence()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let (alg_oid, alg_params) = parse_algorithm_identifier(&mut spki_dec)?;
    let (_, pub_key_bytes) = spki_dec
        .read_bit_string()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    Ok(SubjectPublicKeyInfo {
        algorithm_oid: alg_oid,
        algorithm_params: alg_params,
        public_key: pub_key_bytes.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Extensions parsing
// ---------------------------------------------------------------------------

pub(crate) fn parse_extensions(ext_data: &[u8]) -> Result<Vec<X509Extension>, PkiError> {
    let mut ext_seq = Decoder::new(ext_data)
        .read_sequence()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let mut extensions = Vec::new();
    while !ext_seq.is_empty() {
        let mut ext_dec = ext_seq
            .read_sequence()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let oid = ext_dec
            .read_oid()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?
            .to_vec();
        // critical BOOLEAN DEFAULT FALSE
        let critical = if !ext_dec.is_empty() {
            let tag = ext_dec
                .peek_tag()
                .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
            if tag.class == TagClass::Universal && tag.number == tags::BOOLEAN as u32 {
                ext_dec
                    .read_boolean()
                    .map_err(|e| PkiError::Asn1Error(e.to_string()))?
            } else {
                false
            }
        } else {
            false
        };
        let value = ext_dec
            .read_octet_string()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?
            .to_vec();
        extensions.push(X509Extension {
            oid,
            critical,
            value,
        });
    }
    Ok(extensions)
}

// ---------------------------------------------------------------------------
// Certificate implementation
// ---------------------------------------------------------------------------

impl Certificate {
    /// Parse a certificate from DER-encoded bytes.
    pub fn from_der(data: &[u8]) -> Result<Self, PkiError> {
        let mut outer = Decoder::new(data)
            .read_sequence()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

        // Extract raw TBS bytes (tag + length + value) for signature
        // verification. Use remaining() before/after to capture the exact span.
        let remaining_before = outer.remaining();
        let tbs_tlv = outer
            .read_tlv()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let tbs_consumed = remaining_before.len() - outer.remaining().len();
        let tbs_raw = remaining_before[..tbs_consumed].to_vec();

        // Parse TBS certificate contents
        let mut tbs_dec = Decoder::new(tbs_tlv.value);

        // version [0] EXPLICIT INTEGER DEFAULT v1
        let version = {
            let v_tlv = tbs_dec
                .try_read_context_specific(0, true)
                .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
            if let Some(v_tlv) = v_tlv {
                let mut v_dec = Decoder::new(v_tlv.value);
                let ver_bytes = v_dec
                    .read_integer()
                    .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                ver_bytes.last().copied().unwrap_or(0) + 1
            } else {
                1 // default v1
            }
        };

        // serialNumber INTEGER
        let serial_number = tbs_dec
            .read_integer()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?
            .to_vec();

        // signature AlgorithmIdentifier (inner — must match outer)
        let (_inner_sig_oid, _inner_sig_params) = parse_algorithm_identifier(&mut tbs_dec)?;

        // issuer Name
        let issuer = parse_name(&mut tbs_dec)?;

        // validity Validity
        let (not_before, not_after) = parse_validity(&mut tbs_dec)?;

        // subject Name
        let subject = parse_name(&mut tbs_dec)?;

        // subjectPublicKeyInfo SubjectPublicKeyInfo
        let public_key = parse_subject_public_key_info(&mut tbs_dec)?;

        // issuerUniqueID [1] IMPLICIT BIT STRING OPTIONAL — skip
        let _ = tbs_dec
            .try_read_context_specific(1, false)
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

        // subjectUniqueID [2] IMPLICIT BIT STRING OPTIONAL — skip
        let _ = tbs_dec
            .try_read_context_specific(2, false)
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

        // extensions [3] EXPLICIT Extensions OPTIONAL
        let extensions = {
            let ext_tlv = tbs_dec
                .try_read_context_specific(3, true)
                .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
            if let Some(ext_tlv) = ext_tlv {
                parse_extensions(ext_tlv.value)?
            } else {
                Vec::new()
            }
        };

        // signatureAlgorithm AlgorithmIdentifier
        let (signature_algorithm, signature_params) = parse_algorithm_identifier(&mut outer)?;

        // signatureValue BIT STRING
        let (_, sig_bytes) = outer
            .read_bit_string()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

        Ok(Certificate {
            raw: data.to_vec(),
            version,
            serial_number,
            issuer,
            subject,
            not_before,
            not_after,
            public_key,
            extensions,
            tbs_raw,
            signature_algorithm,
            signature_params,
            signature_value: sig_bytes.to_vec(),
        })
    }

    /// Parse a certificate from PEM-encoded string.
    pub fn from_pem(pem: &str) -> Result<Self, PkiError> {
        let blocks =
            hitls_utils::pem::parse(pem).map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let cert_block = blocks
            .iter()
            .find(|b| b.label == "CERTIFICATE")
            .ok_or_else(|| PkiError::InvalidCert("no CERTIFICATE block found".into()))?;
        Self::from_der(&cert_block.data)
    }

    /// Encode this certificate to DER format.
    pub fn to_der(&self) -> Vec<u8> {
        self.raw.clone()
    }

    /// Verify the certificate signature against an issuer's public key.
    pub fn verify_signature(&self, issuer: &Certificate) -> Result<bool, PkiError> {
        let sig_oid = Oid::from_der_value(&self.signature_algorithm)
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

        if sig_oid == known::sha256_with_rsa_encryption() {
            verify_rsa(
                &self.tbs_raw,
                &self.signature_value,
                &issuer.public_key,
                HashAlg::Sha256,
            )
        } else if sig_oid == known::sha384_with_rsa_encryption() {
            verify_rsa(
                &self.tbs_raw,
                &self.signature_value,
                &issuer.public_key,
                HashAlg::Sha384,
            )
        } else if sig_oid == known::sha512_with_rsa_encryption() {
            verify_rsa(
                &self.tbs_raw,
                &self.signature_value,
                &issuer.public_key,
                HashAlg::Sha512,
            )
        } else if sig_oid == known::sha1_with_rsa_encryption() {
            verify_rsa(
                &self.tbs_raw,
                &self.signature_value,
                &issuer.public_key,
                HashAlg::Sha1,
            )
        } else if sig_oid == known::ecdsa_with_sha256() {
            verify_ecdsa(
                &self.tbs_raw,
                &self.signature_value,
                &issuer.public_key,
                HashAlg::Sha256,
            )
        } else if sig_oid == known::ecdsa_with_sha384() {
            verify_ecdsa(
                &self.tbs_raw,
                &self.signature_value,
                &issuer.public_key,
                HashAlg::Sha384,
            )
        } else if sig_oid == known::ecdsa_with_sha512() {
            verify_ecdsa(
                &self.tbs_raw,
                &self.signature_value,
                &issuer.public_key,
                HashAlg::Sha512,
            )
        } else if sig_oid == known::ed25519() {
            verify_ed25519(&self.tbs_raw, &self.signature_value, &issuer.public_key)
        } else {
            Err(PkiError::InvalidCert(format!(
                "unsupported signature algorithm: {}",
                sig_oid
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// Signature verification helpers
// ---------------------------------------------------------------------------

pub(crate) enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

pub(crate) fn compute_hash(data: &[u8], alg: &HashAlg) -> Result<Vec<u8>, CryptoError> {
    match alg {
        HashAlg::Sha1 => {
            let mut h = hitls_crypto::sha1::Sha1::new();
            h.update(data)?;
            Ok(h.finish()?.to_vec())
        }
        HashAlg::Sha256 => {
            let mut h = hitls_crypto::sha2::Sha256::new();
            h.update(data)?;
            Ok(h.finish()?.to_vec())
        }
        HashAlg::Sha384 => {
            let mut h = hitls_crypto::sha2::Sha384::new();
            h.update(data)?;
            Ok(h.finish()?.to_vec())
        }
        HashAlg::Sha512 => {
            let mut h = hitls_crypto::sha2::Sha512::new();
            h.update(data)?;
            Ok(h.finish()?.to_vec())
        }
    }
}

pub(crate) fn verify_rsa(
    tbs: &[u8],
    signature: &[u8],
    spki: &SubjectPublicKeyInfo,
    hash_alg: HashAlg,
) -> Result<bool, PkiError> {
    // RSA SPKI public_key is DER: SEQUENCE { modulus INTEGER, exponent INTEGER }
    let mut key_dec = Decoder::new(&spki.public_key);
    let mut seq = key_dec
        .read_sequence()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let n = seq
        .read_integer()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let e = seq
        .read_integer()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

    let rsa_pub = hitls_crypto::rsa::RsaPublicKey::new(n, e).map_err(PkiError::from)?;
    let digest = compute_hash(tbs, &hash_alg).map_err(PkiError::from)?;
    rsa_pub
        .verify(
            hitls_crypto::rsa::RsaPadding::Pkcs1v15Sign,
            &digest,
            signature,
        )
        .map_err(PkiError::from)
}

pub(crate) fn oid_to_curve_id(oid: &Oid) -> Result<EccCurveId, PkiError> {
    if *oid == known::secp224r1() {
        Ok(EccCurveId::NistP224)
    } else if *oid == known::prime256v1() {
        Ok(EccCurveId::NistP256)
    } else if *oid == known::secp384r1() {
        Ok(EccCurveId::NistP384)
    } else if *oid == known::secp521r1() {
        Ok(EccCurveId::NistP521)
    } else if *oid == known::brainpool_p256r1() {
        Ok(EccCurveId::BrainpoolP256r1)
    } else if *oid == known::brainpool_p384r1() {
        Ok(EccCurveId::BrainpoolP384r1)
    } else if *oid == known::brainpool_p512r1() {
        Ok(EccCurveId::BrainpoolP512r1)
    } else {
        Err(PkiError::InvalidCert(format!(
            "unsupported EC curve: {}",
            oid
        )))
    }
}

pub(crate) fn verify_ecdsa(
    tbs: &[u8],
    signature: &[u8],
    spki: &SubjectPublicKeyInfo,
    hash_alg: HashAlg,
) -> Result<bool, PkiError> {
    let curve_oid_bytes = spki
        .algorithm_params
        .as_ref()
        .ok_or_else(|| PkiError::InvalidCert("missing EC curve OID in algorithm params".into()))?;
    let curve_oid =
        Oid::from_der_value(curve_oid_bytes).map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let curve_id = oid_to_curve_id(&curve_oid)?;

    let verifier = hitls_crypto::ecdsa::EcdsaKeyPair::from_public_key(curve_id, &spki.public_key)
        .map_err(PkiError::from)?;

    let digest = compute_hash(tbs, &hash_alg).map_err(PkiError::from)?;
    verifier.verify(&digest, signature).map_err(PkiError::from)
}

pub(crate) fn verify_ed25519(
    tbs: &[u8],
    signature: &[u8],
    spki: &SubjectPublicKeyInfo,
) -> Result<bool, PkiError> {
    let verifier = hitls_crypto::ed25519::Ed25519KeyPair::from_public_key(&spki.public_key)
        .map_err(PkiError::from)?;
    // Ed25519 takes the raw message (not pre-hashed)
    verifier.verify(tbs, signature).map_err(PkiError::from)
}

// ---------------------------------------------------------------------------
// DER encoding helpers
// ---------------------------------------------------------------------------

use hitls_utils::asn1::Encoder;

/// Encode a DistinguishedName to DER (SEQUENCE of SET of SEQUENCE { OID, string }).
pub(crate) fn encode_distinguished_name(dn: &DistinguishedName) -> Vec<u8> {
    let mut rdns = Encoder::new();
    for (attr_name, value) in &dn.entries {
        let mut atav = Encoder::new();
        // Look up the OID for the attribute name
        let oid = known::dn_short_name_to_oid(attr_name).unwrap_or_else(|| Oid::new(&[2, 5, 4, 3])); // fallback to CN
        atav.write_oid(&oid.to_der_value());
        // Country name uses PrintableString per RFC 5280
        if attr_name == "C" {
            atav.write_printable_string(value);
        } else {
            atav.write_utf8_string(value);
        }
        let atav_der = atav.finish();
        let mut seq = Encoder::new();
        seq.write_sequence(&atav_der);
        let seq_der = seq.finish();
        let mut set = Encoder::new();
        set.write_set(&seq_der);
        rdns.write_raw(&set.finish());
    }
    let mut outer = Encoder::new();
    outer.write_sequence(&rdns.finish());
    outer.finish()
}

/// Encode an AlgorithmIdentifier to DER.
///
/// `params_tlv` should be a complete DER TLV (tag+length+value), or None.
/// When None, adds NULL for RSA algorithms, omits params for ECDSA/Ed25519.
pub(crate) fn encode_algorithm_identifier(oid: &[u8], params_tlv: Option<&[u8]>) -> Vec<u8> {
    let mut inner = Encoder::new();
    inner.write_oid(oid);
    if let Some(p) = params_tlv {
        inner.write_raw(p);
    }
    // If no params TLV is provided, nothing is written (absent).
    // Callers that need NULL should pass Some(&[0x05, 0x00]).
    let mut outer = Encoder::new();
    outer.write_sequence(&inner.finish());
    outer.finish()
}

/// NULL parameter bytes for AlgorithmIdentifier (DER: 0x05 0x00).
const ALG_PARAMS_NULL: &[u8] = &[0x05, 0x00];

/// Encode a SubjectPublicKeyInfo to DER.
pub(crate) fn encode_subject_public_key_info(spki: &SubjectPublicKeyInfo) -> Vec<u8> {
    // algorithm_params stores raw VALUE bytes from parse_algorithm_identifier;
    // for EC keys this is the raw OID value; for RSA it's None (→ NULL).
    let params_tlv = if let Some(ref p) = spki.algorithm_params {
        // Reconstruct full OID TLV from raw value bytes
        let mut enc = Encoder::new();
        enc.write_oid(p);
        Some(enc.finish())
    } else {
        // RSA and Ed25519: RSA needs NULL, Ed25519 needs absent
        let alg_oid = Oid::from_der_value(&spki.algorithm_oid).ok();
        if alg_oid.as_ref() == Some(&known::rsa_encryption()) {
            Some(ALG_PARAMS_NULL.to_vec())
        } else {
            None
        }
    };
    let alg_id = encode_algorithm_identifier(&spki.algorithm_oid, params_tlv.as_deref());
    let mut inner = Encoder::new();
    inner.write_raw(&alg_id);
    inner.write_bit_string(0, &spki.public_key);
    let mut outer = Encoder::new();
    outer.write_sequence(&inner.finish());
    outer.finish()
}

/// Encode extensions to DER (SEQUENCE of Extension).
pub(crate) fn encode_extensions(exts: &[X509Extension]) -> Vec<u8> {
    let mut seq_contents = Encoder::new();
    for ext in exts {
        let mut ext_inner = Encoder::new();
        ext_inner.write_oid(&ext.oid);
        if ext.critical {
            ext_inner.write_boolean(true);
        }
        ext_inner.write_octet_string(&ext.value);
        let mut ext_seq = Encoder::new();
        ext_seq.write_sequence(&ext_inner.finish());
        seq_contents.write_raw(&ext_seq.finish());
    }
    let mut outer = Encoder::new();
    outer.write_sequence(&seq_contents.finish());
    outer.finish()
}

/// Encode validity (notBefore, notAfter) to DER.
pub(crate) fn encode_validity(not_before: i64, not_after: i64) -> Vec<u8> {
    let mut inner = Encoder::new();
    inner.write_time(not_before);
    inner.write_time(not_after);
    let mut outer = Encoder::new();
    outer.write_sequence(&inner.finish());
    outer.finish()
}

// ---------------------------------------------------------------------------
// SigningKey — unified signing dispatch
// ---------------------------------------------------------------------------

/// A private key that can sign data. Supports RSA, ECDSA, and Ed25519.
pub enum SigningKey {
    /// RSA private key (signs with SHA-256 + PKCS#1 v1.5).
    Rsa(hitls_crypto::rsa::RsaPrivateKey),
    /// ECDSA private key (signs with SHA-256/384 depending on curve).
    Ecdsa {
        curve_id: EccCurveId,
        key_pair: hitls_crypto::ecdsa::EcdsaKeyPair,
    },
    /// Ed25519 private key (signs raw message).
    Ed25519(hitls_crypto::ed25519::Ed25519KeyPair),
}

impl SigningKey {
    /// Create a SigningKey from PKCS#8 DER bytes.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, PkiError> {
        use crate::pkcs8::{parse_pkcs8_der, Pkcs8PrivateKey};
        let key = parse_pkcs8_der(der).map_err(PkiError::from)?;
        match key {
            Pkcs8PrivateKey::Rsa(rsa) => Ok(SigningKey::Rsa(rsa)),
            Pkcs8PrivateKey::Ec { curve_id, key_pair } => {
                Ok(SigningKey::Ecdsa { curve_id, key_pair })
            }
            Pkcs8PrivateKey::Ed25519(ed) => Ok(SigningKey::Ed25519(ed)),
            _ => Err(PkiError::InvalidCert(
                "unsupported key type for signing".into(),
            )),
        }
    }

    /// Create a SigningKey from PKCS#8 PEM string.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, PkiError> {
        let blocks =
            hitls_utils::pem::parse(pem).map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let key_block = blocks
            .iter()
            .find(|b| b.label == "PRIVATE KEY")
            .ok_or_else(|| PkiError::InvalidCert("no PRIVATE KEY block found".into()))?;
        Self::from_pkcs8_der(&key_block.data)
    }

    /// Sign the given data (hash + sign for RSA/ECDSA, raw sign for Ed25519).
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, PkiError> {
        match self {
            SigningKey::Rsa(rsa) => {
                let digest = compute_hash(data, &HashAlg::Sha256).map_err(PkiError::from)?;
                rsa.sign(hitls_crypto::rsa::RsaPadding::Pkcs1v15Sign, &digest)
                    .map_err(PkiError::from)
            }
            SigningKey::Ecdsa { curve_id, key_pair } => {
                let hash_alg = match curve_id {
                    EccCurveId::NistP384 | EccCurveId::BrainpoolP384r1 => HashAlg::Sha384,
                    EccCurveId::NistP521 | EccCurveId::BrainpoolP512r1 => HashAlg::Sha512,
                    _ => HashAlg::Sha256,
                };
                let digest = compute_hash(data, &hash_alg).map_err(PkiError::from)?;
                key_pair.sign(&digest).map_err(PkiError::from)
            }
            SigningKey::Ed25519(ed) => {
                let sig = ed.sign(data).map_err(PkiError::from)?;
                Ok(sig.to_vec())
            }
        }
    }

    /// Get the signature algorithm OID bytes for this key type.
    pub fn algorithm_oid(&self) -> Vec<u8> {
        match self {
            SigningKey::Rsa(_) => known::sha256_with_rsa_encryption().to_der_value(),
            SigningKey::Ecdsa { curve_id, .. } => match curve_id {
                EccCurveId::NistP384 | EccCurveId::BrainpoolP384r1 => {
                    known::ecdsa_with_sha384().to_der_value()
                }
                EccCurveId::NistP521 | EccCurveId::BrainpoolP512r1 => {
                    known::ecdsa_with_sha512().to_der_value()
                }
                _ => known::ecdsa_with_sha256().to_der_value(),
            },
            SigningKey::Ed25519(_) => known::ed25519().to_der_value(),
        }
    }

    /// Get the signature algorithm parameters as full DER TLV.
    /// Returns Some(NULL TLV) for RSA, None (absent) for ECDSA/Ed25519.
    pub fn algorithm_params(&self) -> Option<Vec<u8>> {
        match self {
            SigningKey::Rsa(_) => Some(ALG_PARAMS_NULL.to_vec()),
            SigningKey::Ecdsa { .. } | SigningKey::Ed25519(_) => None,
        }
    }

    /// Extract the SubjectPublicKeyInfo for this key.
    pub fn public_key_info(&self) -> Result<SubjectPublicKeyInfo, PkiError> {
        match self {
            SigningKey::Rsa(rsa) => {
                let pub_key = rsa.public_key();
                // Encode public key as SEQUENCE { modulus INTEGER, exponent INTEGER }
                let mut inner = Encoder::new();
                inner.write_integer(&pub_key.n_bytes());
                inner.write_integer(&pub_key.e_bytes());
                let mut seq = Encoder::new();
                seq.write_sequence(&inner.finish());
                // RSA SPKI algorithm_params: None here means NULL will be added
                // by encode_subject_public_key_info (since it doesn't match OID pattern)
                Ok(SubjectPublicKeyInfo {
                    algorithm_oid: known::rsa_encryption().to_der_value(),
                    algorithm_params: None,
                    public_key: seq.finish(),
                })
            }
            SigningKey::Ecdsa { curve_id, key_pair } => {
                let pub_bytes = key_pair.public_key_bytes().map_err(PkiError::from)?;
                let curve_oid = curve_id_to_oid(*curve_id)?;
                // algorithm_params stores raw OID value bytes (without tag+length)
                // because parse_algorithm_identifier stores tlv.value
                Ok(SubjectPublicKeyInfo {
                    algorithm_oid: known::ec_public_key().to_der_value(),
                    algorithm_params: Some(curve_oid.to_der_value()),
                    public_key: pub_bytes,
                })
            }
            SigningKey::Ed25519(ed) => Ok(SubjectPublicKeyInfo {
                algorithm_oid: known::ed25519().to_der_value(),
                algorithm_params: None,
                public_key: ed.public_key().to_vec(),
            }),
        }
    }
}

/// Map an EccCurveId to its OID.
fn curve_id_to_oid(curve_id: EccCurveId) -> Result<Oid, PkiError> {
    match curve_id {
        EccCurveId::NistP224 => Ok(known::secp224r1()),
        EccCurveId::NistP256 => Ok(known::prime256v1()),
        EccCurveId::NistP384 => Ok(known::secp384r1()),
        EccCurveId::NistP521 => Ok(known::secp521r1()),
        EccCurveId::BrainpoolP256r1 => Ok(known::brainpool_p256r1()),
        EccCurveId::BrainpoolP384r1 => Ok(known::brainpool_p384r1()),
        EccCurveId::BrainpoolP512r1 => Ok(known::brainpool_p512r1()),
        _ => Err(PkiError::InvalidCert(format!(
            "unsupported curve: {:?}",
            curve_id
        ))),
    }
}

// ---------------------------------------------------------------------------
// CSR (PKCS#10) Parsing + Generation
// ---------------------------------------------------------------------------

impl CertificateRequest {
    /// Parse a CSR from DER-encoded bytes (RFC 2986).
    pub fn from_der(data: &[u8]) -> Result<Self, PkiError> {
        let mut outer = Decoder::new(data)
            .read_sequence()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

        // Extract raw TBS bytes for signature verification
        let remaining_before = outer.remaining();
        let tbs_tlv = outer
            .read_tlv()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let tbs_consumed = remaining_before.len() - outer.remaining().len();
        let tbs_raw = remaining_before[..tbs_consumed].to_vec();

        // Parse CertificationRequestInfo
        let mut tbs_dec = Decoder::new(tbs_tlv.value);

        // version INTEGER (must be 0)
        let version_bytes = tbs_dec
            .read_integer()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let version = version_bytes.last().copied().unwrap_or(0);

        // subject Name
        let subject = parse_name(&mut tbs_dec)?;

        // subjectPKInfo SubjectPublicKeyInfo
        let public_key = parse_subject_public_key_info(&mut tbs_dec)?;

        // attributes [0] IMPLICIT SET OF Attribute
        let attributes = {
            let attr_tlv = tbs_dec
                .try_read_context_specific(0, true)
                .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
            if let Some(attr_tlv) = attr_tlv {
                parse_csr_attributes(attr_tlv.value)?
            } else {
                Vec::new()
            }
        };

        // signatureAlgorithm AlgorithmIdentifier
        let (signature_algorithm, _sig_params) = parse_algorithm_identifier(&mut outer)?;

        // signatureValue BIT STRING
        let (_, sig_bytes) = outer
            .read_bit_string()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

        Ok(CertificateRequest {
            raw: data.to_vec(),
            version,
            subject,
            public_key,
            attributes,
            tbs_raw,
            signature_algorithm,
            signature_value: sig_bytes.to_vec(),
        })
    }

    /// Parse a CSR from PEM-encoded string.
    pub fn from_pem(pem: &str) -> Result<Self, PkiError> {
        let blocks =
            hitls_utils::pem::parse(pem).map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let csr_block = blocks
            .iter()
            .find(|b| b.label == "CERTIFICATE REQUEST")
            .ok_or_else(|| PkiError::InvalidCert("no CERTIFICATE REQUEST block found".into()))?;
        Self::from_der(&csr_block.data)
    }

    /// Verify the CSR's self-signature.
    pub fn verify_signature(&self) -> Result<bool, PkiError> {
        let sig_oid = Oid::from_der_value(&self.signature_algorithm)
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

        if sig_oid == known::sha256_with_rsa_encryption()
            || sig_oid == known::sha384_with_rsa_encryption()
            || sig_oid == known::sha512_with_rsa_encryption()
            || sig_oid == known::sha1_with_rsa_encryption()
        {
            let hash_alg = if sig_oid == known::sha384_with_rsa_encryption() {
                HashAlg::Sha384
            } else if sig_oid == known::sha512_with_rsa_encryption() {
                HashAlg::Sha512
            } else if sig_oid == known::sha1_with_rsa_encryption() {
                HashAlg::Sha1
            } else {
                HashAlg::Sha256
            };
            verify_rsa(
                &self.tbs_raw,
                &self.signature_value,
                &self.public_key,
                hash_alg,
            )
        } else if sig_oid == known::ecdsa_with_sha256()
            || sig_oid == known::ecdsa_with_sha384()
            || sig_oid == known::ecdsa_with_sha512()
        {
            let hash_alg = if sig_oid == known::ecdsa_with_sha384() {
                HashAlg::Sha384
            } else if sig_oid == known::ecdsa_with_sha512() {
                HashAlg::Sha512
            } else {
                HashAlg::Sha256
            };
            verify_ecdsa(
                &self.tbs_raw,
                &self.signature_value,
                &self.public_key,
                hash_alg,
            )
        } else if sig_oid == known::ed25519() {
            verify_ed25519(&self.tbs_raw, &self.signature_value, &self.public_key)
        } else {
            Err(PkiError::InvalidCert(format!(
                "unsupported CSR signature algorithm: {}",
                sig_oid
            )))
        }
    }
}

/// Parse CSR attributes — extract extensionRequest extensions.
fn parse_csr_attributes(data: &[u8]) -> Result<Vec<X509Extension>, PkiError> {
    let mut dec = Decoder::new(data);
    let mut extensions = Vec::new();
    while !dec.is_empty() {
        let mut attr_dec = dec
            .read_sequence()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let oid_bytes = attr_dec
            .read_oid()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let oid = Oid::from_der_value(oid_bytes).map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        if oid == known::extension_request() {
            // Values is SET OF Extensions
            let set_dec = attr_dec
                .read_set()
                .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
            if !set_dec.is_empty() {
                let ext_data = set_dec.remaining();
                extensions.extend(parse_extensions(ext_data)?);
            }
        }
    }
    Ok(extensions)
}

/// Builder for creating Certificate Signing Requests (CSRs).
pub struct CertificateRequestBuilder {
    subject: DistinguishedName,
    extensions: Vec<X509Extension>,
}

impl CertificateRequestBuilder {
    /// Create a new CSR builder with the given subject DN.
    pub fn new(subject: DistinguishedName) -> Self {
        Self {
            subject,
            extensions: Vec::new(),
        }
    }

    /// Add an extension to the CSR.
    pub fn add_extension(mut self, oid: Vec<u8>, critical: bool, value: Vec<u8>) -> Self {
        self.extensions.push(X509Extension {
            oid,
            critical,
            value,
        });
        self
    }

    /// Build the CSR, signing with the given key.
    pub fn build(self, signing_key: &SigningKey) -> Result<CertificateRequest, PkiError> {
        let spki = signing_key.public_key_info()?;

        // Build CertificationRequestInfo
        let mut cri = Encoder::new();
        cri.write_integer(&[0x00]); // version 0

        // subject Name
        let dn_der = encode_distinguished_name(&self.subject);
        cri.write_raw(&dn_der);

        // subjectPKInfo
        let spki_der = encode_subject_public_key_info(&spki);
        cri.write_raw(&spki_der);

        // attributes [0] IMPLICIT SET OF Attribute
        if !self.extensions.is_empty() {
            let ext_der = encode_extensions(&self.extensions);
            // Wrap in Attribute: SEQUENCE { OID extensionRequest, SET { extensions } }
            let mut attr_inner = Encoder::new();
            attr_inner.write_oid(&known::extension_request().to_der_value());
            let mut set_enc = Encoder::new();
            set_enc.write_raw(&ext_der); // extensions already wrapped in SEQUENCE
            let mut attr_set = Encoder::new();
            attr_set.write_set(&set_enc.finish());
            attr_inner.write_raw(&attr_set.finish());
            let mut attr_seq = Encoder::new();
            attr_seq.write_sequence(&attr_inner.finish());
            cri.write_context_specific(0, true, &attr_seq.finish());
        } else {
            cri.write_context_specific(0, true, &[]);
        }

        let mut tbs_seq = Encoder::new();
        tbs_seq.write_sequence(&cri.finish());
        let tbs_raw = tbs_seq.finish();

        // Sign the TBS
        let signature = signing_key.sign(&tbs_raw)?;

        // Build outer SEQUENCE
        let sig_alg_oid = signing_key.algorithm_oid();
        let sig_alg_params = signing_key.algorithm_params();
        let alg_id_der = encode_algorithm_identifier(&sig_alg_oid, sig_alg_params.as_deref());

        let mut outer = Encoder::new();
        outer.write_raw(&tbs_raw);
        outer.write_raw(&alg_id_der);
        outer.write_bit_string(0, &signature);
        let mut result = Encoder::new();
        result.write_sequence(&outer.finish());
        let raw = result.finish();

        Ok(CertificateRequest {
            raw: raw.clone(),
            version: 0,
            subject: self.subject,
            public_key: spki,
            attributes: self.extensions,
            tbs_raw,
            signature_algorithm: sig_alg_oid,
            signature_value: signature,
        })
    }

    /// Build the CSR and encode as PEM string.
    pub fn build_pem(self, signing_key: &SigningKey) -> Result<String, PkiError> {
        let csr = self.build(signing_key)?;
        Ok(hitls_utils::pem::encode("CERTIFICATE REQUEST", &csr.raw))
    }
}

// ---------------------------------------------------------------------------
// Certificate Builder
// ---------------------------------------------------------------------------

/// Builder for creating X.509 v3 certificates.
pub struct CertificateBuilder {
    serial_number: Vec<u8>,
    issuer: DistinguishedName,
    subject: DistinguishedName,
    not_before: i64,
    not_after: i64,
    subject_public_key: Option<SubjectPublicKeyInfo>,
    extensions: Vec<X509Extension>,
}

impl CertificateBuilder {
    /// Create a new certificate builder with default values.
    pub fn new() -> Self {
        Self {
            serial_number: vec![0x01],
            issuer: DistinguishedName {
                entries: Vec::new(),
            },
            subject: DistinguishedName {
                entries: Vec::new(),
            },
            not_before: 0,
            not_after: 0,
            subject_public_key: None,
            extensions: Vec::new(),
        }
    }

    /// Set the serial number.
    pub fn serial_number(mut self, serial: &[u8]) -> Self {
        self.serial_number = serial.to_vec();
        self
    }

    /// Set the issuer DN.
    pub fn issuer(mut self, dn: DistinguishedName) -> Self {
        self.issuer = dn;
        self
    }

    /// Set the subject DN.
    pub fn subject(mut self, dn: DistinguishedName) -> Self {
        self.subject = dn;
        self
    }

    /// Set the validity period.
    pub fn validity(mut self, not_before: i64, not_after: i64) -> Self {
        self.not_before = not_before;
        self.not_after = not_after;
        self
    }

    /// Set the subject public key.
    pub fn subject_public_key(mut self, spki: SubjectPublicKeyInfo) -> Self {
        self.subject_public_key = Some(spki);
        self
    }

    /// Add a raw extension.
    pub fn add_extension(mut self, oid: Vec<u8>, critical: bool, value: Vec<u8>) -> Self {
        self.extensions.push(X509Extension {
            oid,
            critical,
            value,
        });
        self
    }

    /// Add a BasicConstraints extension.
    pub fn add_basic_constraints(self, is_ca: bool, path_len: Option<u32>) -> Self {
        let mut inner = Encoder::new();
        if is_ca {
            inner.write_boolean(true);
        }
        if let Some(pl) = path_len {
            inner.write_integer(&pl.to_be_bytes());
        }
        let mut seq = Encoder::new();
        seq.write_sequence(&inner.finish());
        let value = seq.finish();
        self.add_extension(known::basic_constraints().to_der_value(), true, value)
    }

    /// Add a KeyUsage extension.
    pub fn add_key_usage(self, usage: u16) -> Self {
        // Encode as BIT STRING
        let mut bits = vec![(usage & 0xFF) as u8];
        if usage > 0xFF {
            bits.push((usage >> 8) as u8);
        }
        // Calculate unused bits in last byte
        let last = *bits.last().unwrap();
        let unused = if last == 0 {
            0
        } else {
            last.trailing_zeros() as u8
        };
        let mut enc = Encoder::new();
        enc.write_bit_string(unused, &bits);
        let value = enc.finish();
        self.add_extension(known::key_usage().to_der_value(), true, value)
    }

    /// Build the certificate, signing with the given key.
    pub fn build(self, signing_key: &SigningKey) -> Result<Certificate, PkiError> {
        let spki = self
            .subject_public_key
            .ok_or_else(|| PkiError::InvalidCert("subject public key not set".into()))?;

        let sig_alg_oid = signing_key.algorithm_oid();
        let sig_alg_params = signing_key.algorithm_params();

        // Build TBSCertificate
        let mut tbs = Encoder::new();

        // version [0] EXPLICIT INTEGER v3 (2)
        let mut ver_int = Encoder::new();
        ver_int.write_integer(&[0x02]);
        tbs.write_context_specific(0, true, &ver_int.finish());

        // serialNumber INTEGER
        tbs.write_integer(&self.serial_number);

        // signature AlgorithmIdentifier (inner)
        let alg_id = encode_algorithm_identifier(&sig_alg_oid, sig_alg_params.as_deref());
        tbs.write_raw(&alg_id);

        // issuer Name
        tbs.write_raw(&encode_distinguished_name(&self.issuer));

        // validity
        tbs.write_raw(&encode_validity(self.not_before, self.not_after));

        // subject Name
        tbs.write_raw(&encode_distinguished_name(&self.subject));

        // subjectPublicKeyInfo
        tbs.write_raw(&encode_subject_public_key_info(&spki));

        // extensions [3] EXPLICIT Extensions
        if !self.extensions.is_empty() {
            let ext_der = encode_extensions(&self.extensions);
            tbs.write_context_specific(3, true, &ext_der);
        }

        let mut tbs_seq = Encoder::new();
        tbs_seq.write_sequence(&tbs.finish());
        let tbs_raw = tbs_seq.finish();

        // Sign the TBS
        let signature = signing_key.sign(&tbs_raw)?;

        // Build outer Certificate SEQUENCE
        let mut outer = Encoder::new();
        outer.write_raw(&tbs_raw);
        outer.write_raw(&encode_algorithm_identifier(
            &sig_alg_oid,
            sig_alg_params.as_deref(),
        ));
        outer.write_bit_string(0, &signature);
        let mut result = Encoder::new();
        result.write_sequence(&outer.finish());
        let raw = result.finish();

        // Parse the generated cert to ensure correctness and fill all fields
        Certificate::from_der(&raw)
    }

    /// Build the certificate and encode as PEM string.
    pub fn build_pem(self, signing_key: &SigningKey) -> Result<String, PkiError> {
        let cert = self.build(signing_key)?;
        Ok(hitls_utils::pem::encode("CERTIFICATE", &cert.raw))
    }

    /// Create a self-signed certificate with sensible defaults (v3, CA=true).
    pub fn self_signed(
        subject: DistinguishedName,
        signing_key: &SigningKey,
        not_before: i64,
        not_after: i64,
    ) -> Result<Certificate, PkiError> {
        let spki = signing_key.public_key_info()?;
        // Generate a random serial number
        let mut serial = [0u8; 16];
        getrandom::getrandom(&mut serial)
            .map_err(|_| PkiError::InvalidCert("failed to generate random serial".into()))?;
        serial[0] &= 0x7F; // Ensure positive

        CertificateBuilder::new()
            .serial_number(&serial)
            .issuer(subject.clone())
            .subject(subject)
            .validity(not_before, not_after)
            .subject_public_key(spki)
            .add_basic_constraints(true, None)
            .add_key_usage(
                KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN,
            )
            .build(signing_key)
    }
}

impl Default for CertificateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Self-signed RSA 2048 test certificate (SHA-256, CN=Test RSA, O=OpenHiTLS, C=CN)
    const RSA_CERT_HEX: &str = "3082034b30820233a0030201020214581eeff0e59e83d8457fa83d599d4ff9048b45b5300d06092a864886f70d01010b050030343111300f06035504030c08546573742052534131123010060355040a0c094f70656e4869544c53310b300906035504061302434e3020170d3236303230373133313931355a180f32313236303131343133313931355a30343111300f06035504030c08546573742052534131123010060355040a0c094f70656e4869544c53310b300906035504061302434e30820122300d06092a864886f70d01010105000382010f003082010a02820101009565f148f55f7367afb865eb15285cfce9fd2208f35f5dba7ea24b426ad79ce82e5f88ae990feba39961921fa477f0411eb28739cf476577c5e0324aa95534a4dd7226fc133a5e435d81e433aa5928aef56e84c5eeb3a6073996c729d878ea1d6ef2a5da17c20a1a205a1ae8193a7fa8f56c6fb3feff398467c6cb4405b9e491fc9ecba5b2eca93f13ca94983b13f708f6dc428ce4fd9b893c57285b97d01ecb76f82c1bd2eef1867b8c4604d97616132da27d79a49698d9f47ff358079dd356b2f9d759ddbe5822b52520d0fa2a61a3c0b02991b2447ae944941a6df433c4f6bcf45d9d55dd45cbb8218df3777fde45fd2c9b3790bfbc4b6cb23e2e145b70990203010001a3533051301d0603551d0e041604145359b82d12f1ae48dc982fc1b49f8205d273dea4301f0603551d230418301680145359b82d12f1ae48dc982fc1b49f8205d273dea4300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003820101008d92384c0601ba663e8e064d4fcfa33aad19cc55ce393c2179b90f136c928a6f419594f66c661947376d60c7a8629e131018bd469bdb610995c32e6ae13a8c0b794c3a9fe6b9db59cf55dff1ba417daaf4f5acceb7e901665e136c6e9aff4450a59d0feb7503dbaf83f43862b002f827ab92b3aa5905dfd58b5e1f55ca1b56658c0dc79469c00bce331ea7805906e4018bcc7ddf8e53498e1f3eab7945eb277a0f139ff59656c6180538e767856d4725e59e39eac063088e814b5b3f879e31722f9c3a062782d68f555b4eed230dea309ac071f38e4261608943654aa4242af40e50a97d6c20208feb4dc1b45686fd60906ce1452d208ade0ee19f70b00b1ef4";

    // Self-signed ECDSA P-256 test certificate (SHA-256, CN=Test ECDSA, O=OpenHiTLS, C=CN)
    const ECDSA_CERT_HEX: &str = "308201c330820169a00302010202147f2de0bcdec04fc31b1442eaabb1561bc7e5ad55300a06082a8648ce3d04030230363113301106035504030c0a5465737420454344534131123010060355040a0c094f70656e4869544c53310b300906035504061302434e3020170d3236303230373133313931355a180f32313236303131343133313931355a30363113301106035504030c0a5465737420454344534131123010060355040a0c094f70656e4869544c53310b300906035504061302434e3059301306072a8648ce3d020106082a8648ce3d03010703420004e4adc7cbb9a8c374c4bf19fcebe5c3f89ae80ed3d01932ec3d45dd850423a5b20fb642a585279fe6afdff55f6dd9df2ba92af7ce3061666cda3d8e16dd87cbc1a3533051301d0603551d0e04160414910b89e4b9a3bedca4757d8f90894f291ce9caf6301f0603551d23041830168014910b89e4b9a3bedca4757d8f90894f291ce9caf6300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022100a29318671565968f3ffeb41e954f129fecd184cc9b2829e382a28cde1cc8df3f02203cbeb915ee07ba041c359f67a5505a0aa32af970ee2e0e4d0576c6883771f1c7";

    const RSA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDSzCCAjOgAwIBAgIUWB7v8OWeg9hFf6g9WZ1P+QSLRbUwDQYJKoZIhvcNAQEL
BQAwNDERMA8GA1UEAwwIVGVzdCBSU0ExEjAQBgNVBAoMCU9wZW5IaVRMUzELMAkG
A1UEBhMCQ04wIBcNMjYwMjA3MTMxOTE1WhgPMjEyNjAxMTQxMzE5MTVaMDQxETAP
BgNVBAMMCFRlc3QgUlNBMRIwEAYDVQQKDAlPcGVuSGlUTFMxCzAJBgNVBAYTAkNO
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlWXxSPVfc2evuGXrFShc
/On9IgjzX126fqJLQmrXnOguX4iumQ/ro5lhkh+kd/BBHrKHOc9HZXfF4DJKqVU0
pN1yJvwTOl5DXYHkM6pZKK71boTF7rOmBzmWxynYeOodbvKl2hfCChogWhroGTp/
qPVsb7P+/zmEZ8bLRAW55JH8nsulsuypPxPKlJg7E/cI9txCjOT9m4k8Vyhbl9Ae
y3b4LBvS7vGGe4xGBNl2FhMton15pJaY2fR/81gHndNWsvnXWd2+WCK1JSDQ+iph
o8CwKZGyRHrpRJQabfQzxPa89F2dVd1Fy7ghjfN3f95F/SybN5C/vEtssj4uFFtw
mQIDAQABo1MwUTAdBgNVHQ4EFgQUU1m4LRLxrkjcmC/BtJ+CBdJz3qQwHwYDVR0j
BBgwFoAUU1m4LRLxrkjcmC/BtJ+CBdJz3qQwDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAQEAjZI4TAYBumY+jgZNT8+jOq0ZzFXOOTwhebkPE2ySim9B
lZT2bGYZRzdtYMeoYp4TEBi9RpvbYQmVwy5q4TqMC3lMOp/mudtZz1Xf8bpBfar0
9azOt+kBZl4TbG6a/0RQpZ0P63UD26+D9DhisAL4J6uSs6pZBd/Vi14fVcobVmWM
DceUacALzjMep4BZBuQBi8x9345TSY4fPqt5Resneg8Tn/WWVsYYBTjnZ4VtRyXl
njnqwGMIjoFLWz+HnjFyL5w6BieC1o9VW07tIw3qMJrAcfOOQmFgiUNlSqQkKvQO
UKl9bCAgj+tNwbRWhv1gkGzhRS0git4O4Z9wsAse9A==
-----END CERTIFICATE-----
";

    #[test]
    fn test_parse_rsa_cert_der() {
        let data = hex(RSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        assert_eq!(cert.version, 3);
        assert_eq!(cert.subject.get("CN"), Some("Test RSA"));
        assert_eq!(cert.subject.get("O"), Some("OpenHiTLS"));
        assert_eq!(cert.subject.get("C"), Some("CN"));
        assert_eq!(cert.issuer.get("CN"), Some("Test RSA"));
        assert!(!cert.serial_number.is_empty());
        assert!(!cert.public_key.public_key.is_empty());
        // Should have extensions (SubjectKeyIdentifier, AuthorityKeyIdentifier, BasicConstraints)
        assert_eq!(cert.extensions.len(), 3);
    }

    #[test]
    fn test_parse_rsa_cert_pem() {
        let cert = Certificate::from_pem(RSA_CERT_PEM).unwrap();
        assert_eq!(cert.version, 3);
        assert_eq!(cert.subject.get("CN"), Some("Test RSA"));
    }

    #[test]
    fn test_parse_ecdsa_p256_cert() {
        let data = hex(ECDSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        assert_eq!(cert.version, 3);
        assert_eq!(cert.subject.get("CN"), Some("Test ECDSA"));
        assert_eq!(cert.subject.get("O"), Some("OpenHiTLS"));
        // EC public key should be 65 bytes (uncompressed point 0x04 || x || y)
        assert_eq!(cert.public_key.public_key.len(), 65);
        // Algorithm params should be P-256 curve OID
        let params = cert.public_key.algorithm_params.as_ref().unwrap();
        let curve_oid = Oid::from_der_value(params).unwrap();
        assert_eq!(curve_oid, known::prime256v1());
    }

    #[test]
    fn test_parse_cert_distinguished_name() {
        let data = hex(RSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        let dn_str = cert.subject.to_string();
        assert!(dn_str.contains("CN=Test RSA"));
        assert!(dn_str.contains("O=OpenHiTLS"));
        assert!(dn_str.contains("C=CN"));
    }

    #[test]
    fn test_parse_cert_extensions() {
        let data = hex(RSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        // Check for BasicConstraints extension (2.5.29.19)
        let bc_oid = known::basic_constraints().to_der_value();
        let bc = cert.extensions.iter().find(|e| e.oid == bc_oid);
        assert!(bc.is_some());
        assert!(bc.unwrap().critical); // CA cert BasicConstraints should be critical

        // Check for SubjectKeyIdentifier (2.5.29.14)
        let ski_oid = known::subject_key_identifier().to_der_value();
        let ski = cert.extensions.iter().find(|e| e.oid == ski_oid);
        assert!(ski.is_some());
    }

    #[test]
    fn test_parse_cert_validity_time() {
        let data = hex(RSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        // notBefore: 2026-02-07 13:19:15 UTC
        // Expected UNIX timestamp: 1770639555
        assert!(cert.not_before > 0);
        assert!(cert.not_after > cert.not_before);
        // The cert has 36500-day validity (~100 years)
        let diff_days = (cert.not_after - cert.not_before) / 86400;
        assert!(diff_days > 36000);
    }

    #[test]
    fn test_verify_self_signed_rsa() {
        let data = hex(RSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        // Self-signed: issuer == subject, verify with own public key
        let result = cert.verify_signature(&cert).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_self_signed_ecdsa() {
        let data = hex(ECDSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        let result = cert.verify_signature(&cert).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_wrong_issuer_fails() {
        let rsa_data = hex(RSA_CERT_HEX);
        let rsa_cert = Certificate::from_der(&rsa_data).unwrap();
        let ecdsa_data = hex(ECDSA_CERT_HEX);
        let ecdsa_cert = Certificate::from_der(&ecdsa_data).unwrap();
        // RSA cert verified with ECDSA cert's key should fail
        // (the algorithm OID mismatch or key parsing will cause an error)
        let result = rsa_cert.verify_signature(&ecdsa_cert);
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_to_der_roundtrip() {
        let data = hex(RSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        assert_eq!(cert.to_der(), data);
    }

    #[test]
    fn test_parse_cert_serial_number() {
        let data = hex(RSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        // Serial number should be non-empty
        assert!(!cert.serial_number.is_empty());
        // Serial number should match what OpenSSL generated
        assert!(cert.serial_number.len() <= 20); // RFC 5280 max 20 octets
    }

    #[test]
    fn test_signature_algorithm_oid() {
        let data = hex(RSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        let sig_oid = Oid::from_der_value(&cert.signature_algorithm).unwrap();
        // Should be sha256WithRSAEncryption
        assert_eq!(sig_oid, known::sha256_with_rsa_encryption());

        let ecdsa_data = hex(ECDSA_CERT_HEX);
        let ecdsa_cert = Certificate::from_der(&ecdsa_data).unwrap();
        let ecdsa_sig_oid = Oid::from_der_value(&ecdsa_cert.signature_algorithm).unwrap();
        // Should be ecdsaWithSHA256
        assert_eq!(ecdsa_sig_oid, known::ecdsa_with_sha256());
    }

    // -----------------------------------------------------------------------
    // Encoding roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_dn_roundtrip() {
        let dn = DistinguishedName {
            entries: vec![
                ("CN".to_string(), "Test".to_string()),
                ("O".to_string(), "OpenHiTLS".to_string()),
                ("C".to_string(), "CN".to_string()),
            ],
        };
        let encoded = encode_distinguished_name(&dn);
        let mut dec = hitls_utils::asn1::Decoder::new(&encoded);
        let parsed = parse_name(&mut dec).unwrap();
        assert_eq!(parsed.entries, dn.entries);
    }

    #[test]
    fn test_encode_algorithm_identifier_rsa() {
        let oid = known::sha256_with_rsa_encryption().to_der_value();
        let encoded = encode_algorithm_identifier(&oid, None);
        let mut dec = hitls_utils::asn1::Decoder::new(&encoded);
        let (parsed_oid, parsed_params) = parse_algorithm_identifier(&mut dec).unwrap();
        assert_eq!(parsed_oid, oid);
        assert!(parsed_params.is_none()); // NULL → None
    }

    #[test]
    fn test_encode_spki_roundtrip() {
        // Parse SPKI from an existing cert, encode it back, and reparse
        let data = hex(RSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        let encoded = encode_subject_public_key_info(&cert.public_key);
        let mut dec = hitls_utils::asn1::Decoder::new(&encoded);
        let parsed = parse_subject_public_key_info(&mut dec).unwrap();
        assert_eq!(parsed.algorithm_oid, cert.public_key.algorithm_oid);
        assert_eq!(parsed.public_key, cert.public_key.public_key);
    }

    #[test]
    fn test_encode_extensions_roundtrip() {
        let exts = vec![X509Extension {
            oid: known::basic_constraints().to_der_value(),
            critical: true,
            value: vec![0x30, 0x03, 0x01, 0x01, 0xFF], // isCA=true
        }];
        let encoded = encode_extensions(&exts);
        let parsed = parse_extensions(&encoded).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].oid, exts[0].oid);
        assert!(parsed[0].critical);
        assert_eq!(parsed[0].value, exts[0].value);
    }

    // -----------------------------------------------------------------------
    // SigningKey tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_signing_key_ed25519() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let data = b"hello world";
        let sig = sk.sign(data).unwrap();
        let spki = sk.public_key_info().unwrap();

        // Verify
        let result = verify_ed25519(data, &sig, &spki).unwrap();
        assert!(result);
    }

    #[test]
    fn test_signing_key_ecdsa_p256() {
        let kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
        let sk = SigningKey::Ecdsa {
            curve_id: hitls_types::EccCurveId::NistP256,
            key_pair: kp,
        };
        let data = b"test message";
        let sig = sk.sign(data).unwrap();
        let spki = sk.public_key_info().unwrap();

        let result = verify_ecdsa(data, &sig, &spki, HashAlg::Sha256).unwrap();
        assert!(result);
    }

    // -----------------------------------------------------------------------
    // CSR tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_csr_ed25519() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let subject = DistinguishedName {
            entries: vec![("CN".to_string(), "Test CSR".to_string())],
        };
        let csr = CertificateRequestBuilder::new(subject.clone())
            .build(&sk)
            .unwrap();
        assert_eq!(csr.version, 0);
        assert_eq!(csr.subject.entries, subject.entries);

        // Verify self-signature
        assert!(csr.verify_signature().unwrap());

        // Roundtrip: DER → parse → verify
        let parsed = CertificateRequest::from_der(&csr.raw).unwrap();
        assert_eq!(parsed.subject.entries, subject.entries);
        assert!(parsed.verify_signature().unwrap());
    }

    #[test]
    fn test_build_csr_ecdsa() {
        let kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
        let sk = SigningKey::Ecdsa {
            curve_id: hitls_types::EccCurveId::NistP256,
            key_pair: kp,
        };
        let subject = DistinguishedName {
            entries: vec![
                ("CN".to_string(), "ECDSA CSR".to_string()),
                ("O".to_string(), "Test Org".to_string()),
            ],
        };
        let csr = CertificateRequestBuilder::new(subject.clone())
            .build(&sk)
            .unwrap();
        assert!(csr.verify_signature().unwrap());

        let parsed = CertificateRequest::from_der(&csr.raw).unwrap();
        assert_eq!(parsed.subject.get("CN"), Some("ECDSA CSR"));
        assert!(parsed.verify_signature().unwrap());
    }

    #[test]
    fn test_build_csr_pem_roundtrip() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let subject = DistinguishedName {
            entries: vec![("CN".to_string(), "PEM Test".to_string())],
        };
        let pem = CertificateRequestBuilder::new(subject)
            .build_pem(&sk)
            .unwrap();
        assert!(pem.contains("-----BEGIN CERTIFICATE REQUEST-----"));
        let parsed = CertificateRequest::from_pem(&pem).unwrap();
        assert_eq!(parsed.subject.get("CN"), Some("PEM Test"));
        assert!(parsed.verify_signature().unwrap());
    }

    #[test]
    fn test_build_csr_with_extensions() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let subject = DistinguishedName {
            entries: vec![("CN".to_string(), "Ext CSR".to_string())],
        };
        let csr = CertificateRequestBuilder::new(subject)
            .add_extension(
                known::basic_constraints().to_der_value(),
                true,
                vec![0x30, 0x03, 0x01, 0x01, 0xFF],
            )
            .build(&sk)
            .unwrap();
        assert!(csr.verify_signature().unwrap());
        // Verify extension survived the roundtrip
        let parsed = CertificateRequest::from_der(&csr.raw).unwrap();
        assert!(parsed.verify_signature().unwrap());
    }

    // -----------------------------------------------------------------------
    // Certificate Builder tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_self_signed_ed25519() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let subject = DistinguishedName {
            entries: vec![
                ("CN".to_string(), "Test CA".to_string()),
                ("O".to_string(), "OpenHiTLS".to_string()),
            ],
        };
        let cert = CertificateBuilder::self_signed(
            subject.clone(),
            &sk,
            1_700_000_000, // 2023-11-14
            1_800_000_000, // 2027-01-15
        )
        .unwrap();

        assert_eq!(cert.version, 3);
        assert_eq!(cert.subject.get("CN"), Some("Test CA"));
        assert_eq!(cert.issuer.get("CN"), Some("Test CA"));
        assert!(cert.is_self_signed());
        assert!(cert.is_ca());
        assert!(cert.verify_signature(&cert).unwrap());
    }

    #[test]
    fn test_build_self_signed_ecdsa() {
        let kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
        let sk = SigningKey::Ecdsa {
            curve_id: hitls_types::EccCurveId::NistP256,
            key_pair: kp,
        };
        let subject = DistinguishedName {
            entries: vec![("CN".to_string(), "ECDSA CA".to_string())],
        };
        let cert =
            CertificateBuilder::self_signed(subject, &sk, 1_700_000_000, 1_800_000_000).unwrap();
        assert!(cert.is_self_signed());
        assert!(cert.verify_signature(&cert).unwrap());
    }

    #[test]
    fn test_build_cert_chain() {
        // Generate CA
        let ca_kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let ca_sk = SigningKey::Ed25519(ca_kp);
        let ca_dn = DistinguishedName {
            entries: vec![("CN".to_string(), "Root CA".to_string())],
        };
        let ca_cert =
            CertificateBuilder::self_signed(ca_dn, &ca_sk, 1_700_000_000, 1_800_000_000).unwrap();

        // Generate end-entity cert signed by CA
        let ee_kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let ee_sk = SigningKey::Ed25519(ee_kp);
        let ee_spki = ee_sk.public_key_info().unwrap();
        let ee_dn = DistinguishedName {
            entries: vec![("CN".to_string(), "server.example.com".to_string())],
        };
        let ee_cert = CertificateBuilder::new()
            .serial_number(&[0x02])
            .issuer(ca_cert.subject.clone())
            .subject(ee_dn.clone())
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(ee_spki)
            .build(&ca_sk)
            .unwrap();

        assert_eq!(ee_cert.subject.get("CN"), Some("server.example.com"));
        assert_eq!(ee_cert.issuer.get("CN"), Some("Root CA"));
        assert!(!ee_cert.is_self_signed());

        // Verify EE cert signature against CA
        assert!(ee_cert.verify_signature(&ca_cert).unwrap());
        // CA self-verify still works
        assert!(ca_cert.verify_signature(&ca_cert).unwrap());
    }

    #[test]
    fn test_build_cert_with_basic_constraints() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".to_string(), "CA".to_string())],
        };
        let spki = sk.public_key_info().unwrap();
        let cert = CertificateBuilder::new()
            .serial_number(&[0x01])
            .issuer(dn.clone())
            .subject(dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .add_basic_constraints(true, Some(1))
            .build(&sk)
            .unwrap();

        let bc = cert.basic_constraints().unwrap();
        assert!(bc.is_ca);
        assert_eq!(bc.path_len_constraint, Some(1));
    }

    #[test]
    fn test_build_cert_with_key_usage() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".to_string(), "KU Test".to_string())],
        };
        let spki = sk.public_key_info().unwrap();
        let cert = CertificateBuilder::new()
            .serial_number(&[0x01])
            .issuer(dn.clone())
            .subject(dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .add_key_usage(KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_CERT_SIGN)
            .build(&sk)
            .unwrap();

        let ku = cert.key_usage().unwrap();
        assert!(ku.has(KeyUsage::DIGITAL_SIGNATURE));
        assert!(ku.has(KeyUsage::KEY_CERT_SIGN));
        assert!(!ku.has(KeyUsage::KEY_ENCIPHERMENT));
    }

    #[test]
    fn test_cert_pem_roundtrip() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".to_string(), "PEM Cert".to_string())],
        };
        let pem = CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000).unwrap();
        let pem_str = hitls_utils::pem::encode("CERTIFICATE", &pem.raw);
        assert!(pem_str.contains("-----BEGIN CERTIFICATE-----"));
        let parsed = Certificate::from_pem(&pem_str).unwrap();
        assert_eq!(parsed.subject.get("CN"), Some("PEM Cert"));
        assert!(parsed.verify_signature(&parsed).unwrap());
    }

    #[test]
    fn test_build_from_csr() {
        // Build CSR
        let ee_kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let ee_sk = SigningKey::Ed25519(ee_kp);
        let csr = CertificateRequestBuilder::new(DistinguishedName {
            entries: vec![("CN".to_string(), "CSR Subject".to_string())],
        })
        .build(&ee_sk)
        .unwrap();
        assert!(csr.verify_signature().unwrap());

        // CA signs a cert using CSR's subject and public key
        let ca_kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let ca_sk = SigningKey::Ed25519(ca_kp);
        let ca_dn = DistinguishedName {
            entries: vec![("CN".to_string(), "Issuing CA".to_string())],
        };
        let cert = CertificateBuilder::new()
            .serial_number(&[0x42])
            .issuer(ca_dn)
            .subject(csr.subject.clone())
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(csr.public_key.clone())
            .build(&ca_sk)
            .unwrap();

        assert_eq!(cert.subject.get("CN"), Some("CSR Subject"));
        assert_eq!(cert.issuer.get("CN"), Some("Issuing CA"));
    }
}
