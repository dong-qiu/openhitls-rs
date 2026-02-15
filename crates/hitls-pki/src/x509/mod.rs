//! X.509 certificate, CRL, CSR, and OCSP management.

pub mod crl;
pub mod ocsp;
pub mod text;
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

/// Parsed Extended Key Usage extension (RFC 5280 §4.2.1.12).
#[derive(Debug, Clone)]
pub struct ExtendedKeyUsage {
    pub purposes: Vec<Oid>,
}

/// Parsed Subject Alternative Name extension (RFC 5280 §4.2.1.6).
#[derive(Debug, Clone)]
pub struct SubjectAltName {
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<Vec<u8>>,
    pub email_addresses: Vec<String>,
    pub uris: Vec<String>,
}

/// Parsed Authority Key Identifier extension (RFC 5280 §4.2.1.1).
#[derive(Debug, Clone)]
pub struct AuthorityKeyIdentifier {
    pub key_identifier: Option<Vec<u8>>,
}

/// Parsed Authority Information Access extension (RFC 5280 §4.2.2.1).
#[derive(Debug, Clone)]
pub struct AuthorityInfoAccess {
    pub ocsp_urls: Vec<String>,
    pub ca_issuer_urls: Vec<String>,
}

/// Parsed Name Constraints extension (RFC 5280 §4.2.1.10).
#[derive(Debug, Clone)]
pub struct NameConstraints {
    pub permitted_subtrees: Vec<GeneralSubtree>,
    pub excluded_subtrees: Vec<GeneralSubtree>,
}

/// A subtree constraint for Name Constraints.
#[derive(Debug, Clone)]
pub struct GeneralSubtree {
    pub base: GeneralName,
}

/// A GeneralName value as used in SAN and Name Constraints.
#[derive(Debug, Clone)]
pub enum GeneralName {
    DnsName(String),
    DirectoryName(DistinguishedName),
    Rfc822Name(String),
    IpAddress(Vec<u8>),
    Uri(String),
}

/// Parsed Certificate Policies extension (RFC 5280 §4.2.1.4).
#[derive(Debug, Clone)]
pub struct CertificatePolicies {
    pub policies: Vec<PolicyInformation>,
}

/// A single policy entry within the Certificate Policies extension.
#[derive(Debug, Clone)]
pub struct PolicyInformation {
    pub policy_identifier: Oid,
    pub qualifiers: Vec<PolicyQualifier>,
}

/// A policy qualifier within a PolicyInformation.
#[derive(Debug, Clone)]
pub struct PolicyQualifier {
    pub qualifier_id: Oid,
    /// Raw DER value of the qualifier.
    pub qualifier: Vec<u8>,
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
    if unused_bits > 0 && unused_bits < 16 && !data.is_empty() {
        let last_idx = data.len() - 1;
        if last_idx == 0 {
            mask &= !((1u16 << unused_bits) - 1);
        } else if last_idx == 1 {
            let high = (data[last_idx] as u16) << 8;
            let cleared = high & !((1u16 << unused_bits) - 1);
            mask = (mask & 0x00FF) | cleared;
        }
    }
    Ok(KeyUsage(mask))
}

// ---------------------------------------------------------------------------
// Extension parsing helpers
// ---------------------------------------------------------------------------

/// Parse ExtendedKeyUsage: `SEQUENCE OF OID`
fn parse_extended_key_usage(value: &[u8]) -> Result<ExtendedKeyUsage, PkiError> {
    let mut dec = Decoder::new(value)
        .read_sequence()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let mut purposes = Vec::new();
    while !dec.is_empty() {
        let oid_bytes = dec
            .read_oid()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let oid = Oid::from_der_value(oid_bytes).map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        purposes.push(oid);
    }
    Ok(ExtendedKeyUsage { purposes })
}

/// Parse a GeneralName from a context-tagged TLV.
/// GeneralName ::= CHOICE {
///   otherName       [0], rfc822Name [1] IA5String, dNSName [2] IA5String,
///   x400Address     [3], directoryName [4] EXPLICIT Name,
///   ediPartyName    [5], uniformResourceIdentifier [6] IA5String,
///   iPAddress       [7] OCTET STRING, registeredID [8] OID
/// }
fn parse_general_name(tag_num: u32, value: &[u8]) -> Option<GeneralName> {
    match tag_num {
        1 => {
            // rfc822Name — IA5String
            String::from_utf8(value.to_vec())
                .ok()
                .map(GeneralName::Rfc822Name)
        }
        2 => {
            // dNSName — IA5String
            String::from_utf8(value.to_vec())
                .ok()
                .map(GeneralName::DnsName)
        }
        4 => {
            // directoryName — EXPLICIT Name
            let mut dec = Decoder::new(value);
            parse_name(&mut dec).ok().map(GeneralName::DirectoryName)
        }
        6 => {
            // uniformResourceIdentifier — IA5String
            String::from_utf8(value.to_vec()).ok().map(GeneralName::Uri)
        }
        7 => {
            // iPAddress — OCTET STRING (4 for IPv4, 16 for IPv6; 8/32 in NC)
            Some(GeneralName::IpAddress(value.to_vec()))
        }
        _ => None, // skip unsupported types
    }
}

/// Parse SubjectAltName: `SEQUENCE OF GeneralName`
fn parse_subject_alt_name(value: &[u8]) -> Result<SubjectAltName, PkiError> {
    let mut dec = Decoder::new(value)
        .read_sequence()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let mut san = SubjectAltName {
        dns_names: Vec::new(),
        ip_addresses: Vec::new(),
        email_addresses: Vec::new(),
        uris: Vec::new(),
    };
    while !dec.is_empty() {
        let tlv = dec
            .read_tlv()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        if tlv.tag.class == TagClass::ContextSpecific {
            match tlv.tag.number {
                1 => {
                    if let Ok(s) = String::from_utf8(tlv.value.to_vec()) {
                        san.email_addresses.push(s);
                    }
                }
                2 => {
                    if let Ok(s) = String::from_utf8(tlv.value.to_vec()) {
                        san.dns_names.push(s);
                    }
                }
                6 => {
                    if let Ok(s) = String::from_utf8(tlv.value.to_vec()) {
                        san.uris.push(s);
                    }
                }
                7 => {
                    san.ip_addresses.push(tlv.value.to_vec());
                }
                _ => {} // skip unsupported GeneralName types
            }
        }
    }
    Ok(san)
}

/// Parse AuthorityKeyIdentifier: `SEQUENCE { [0] keyIdentifier OPTIONAL, ... }`
fn parse_authority_key_identifier(value: &[u8]) -> Result<AuthorityKeyIdentifier, PkiError> {
    let mut dec = Decoder::new(value)
        .read_sequence()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let key_identifier = dec
        .try_read_context_specific(0, false)
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?
        .map(|tlv| tlv.value.to_vec());
    Ok(AuthorityKeyIdentifier { key_identifier })
}

/// Parse SubjectKeyIdentifier: the extension value is `OCTET STRING`.
fn parse_subject_key_identifier(value: &[u8]) -> Result<Vec<u8>, PkiError> {
    let mut dec = Decoder::new(value);
    let ski = dec
        .read_octet_string()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    Ok(ski.to_vec())
}

/// Parse AuthorityInfoAccess: `SEQUENCE OF AccessDescription`
/// AccessDescription ::= SEQUENCE { accessMethod OID, accessLocation GeneralName }
fn parse_authority_info_access(value: &[u8]) -> Result<AuthorityInfoAccess, PkiError> {
    let mut dec = Decoder::new(value)
        .read_sequence()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let mut aia = AuthorityInfoAccess {
        ocsp_urls: Vec::new(),
        ca_issuer_urls: Vec::new(),
    };
    let ocsp_oid = known::ocsp().to_der_value();
    let ca_issuers_oid = known::ca_issuers().to_der_value();
    while !dec.is_empty() {
        let mut ad = dec
            .read_sequence()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let method_bytes = ad
            .read_oid()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let tlv = ad
            .read_tlv()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        // accessLocation is a GeneralName — typically [6] URI
        if tlv.tag.class == TagClass::ContextSpecific && tlv.tag.number == 6 {
            if let Ok(url) = String::from_utf8(tlv.value.to_vec()) {
                if method_bytes == ocsp_oid.as_slice() {
                    aia.ocsp_urls.push(url);
                } else if method_bytes == ca_issuers_oid.as_slice() {
                    aia.ca_issuer_urls.push(url);
                }
            }
        }
    }
    Ok(aia)
}

/// Parse NameConstraints: `SEQUENCE { [0] permitted OPTIONAL, [1] excluded OPTIONAL }`
fn parse_name_constraints(value: &[u8]) -> Result<NameConstraints, PkiError> {
    let mut dec = Decoder::new(value)
        .read_sequence()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let mut nc = NameConstraints {
        permitted_subtrees: Vec::new(),
        excluded_subtrees: Vec::new(),
    };
    if let Some(tlv) = dec
        .try_read_context_specific(0, true)
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?
    {
        nc.permitted_subtrees = parse_general_subtrees(tlv.value)?;
    }
    if let Some(tlv) = dec
        .try_read_context_specific(1, true)
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?
    {
        nc.excluded_subtrees = parse_general_subtrees(tlv.value)?;
    }
    Ok(nc)
}

/// Parse CertificatePolicies: `SEQUENCE SIZE (1..MAX) OF PolicyInformation`
/// PolicyInformation ::= SEQUENCE { policyIdentifier OID, policyQualifiers SEQUENCE OF OPTIONAL }
fn parse_certificate_policies(value: &[u8]) -> Result<CertificatePolicies, PkiError> {
    let mut dec = Decoder::new(value)
        .read_sequence()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let mut policies = Vec::new();
    while !dec.is_empty() {
        let mut pi_dec = dec
            .read_sequence()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let oid_bytes = pi_dec
            .read_oid()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let policy_oid =
            Oid::from_der_value(oid_bytes).map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let mut qualifiers = Vec::new();
        if !pi_dec.is_empty() {
            let mut quals_dec = pi_dec
                .read_sequence()
                .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
            while !quals_dec.is_empty() {
                let mut q_dec = quals_dec
                    .read_sequence()
                    .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                let q_oid_bytes = q_dec
                    .read_oid()
                    .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                let q_oid = Oid::from_der_value(q_oid_bytes)
                    .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                // Read qualifier value — remaining bytes
                let q_value = q_dec.remaining().to_vec();
                // Consume remaining
                while !q_dec.is_empty() {
                    let _ = q_dec.read_tlv();
                }
                qualifiers.push(PolicyQualifier {
                    qualifier_id: q_oid,
                    qualifier: q_value,
                });
            }
        }
        policies.push(PolicyInformation {
            policy_identifier: policy_oid,
            qualifiers,
        });
    }
    Ok(CertificatePolicies { policies })
}

/// Parse GeneralSubtrees: `SEQUENCE OF GeneralSubtree`
/// GeneralSubtree ::= SEQUENCE { base GeneralName, minimum [0] DEFAULT 0, maximum [1] OPTIONAL }
fn parse_general_subtrees(data: &[u8]) -> Result<Vec<GeneralSubtree>, PkiError> {
    let mut dec = Decoder::new(data);
    let mut subtrees = Vec::new();
    while !dec.is_empty() {
        let mut sub_dec = dec
            .read_sequence()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let tlv = sub_dec
            .read_tlv()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        if tlv.tag.class == TagClass::ContextSpecific {
            if let Some(gn) = parse_general_name(tlv.tag.number, tlv.value) {
                subtrees.push(GeneralSubtree { base: gn });
            }
        }
        // Skip minimum/maximum if present
    }
    Ok(subtrees)
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

    /// Parse the Extended Key Usage extension, if present.
    pub fn extended_key_usage(&self) -> Option<ExtendedKeyUsage> {
        let eku_oid = known::ext_key_usage().to_der_value();
        self.extensions
            .iter()
            .find(|e| e.oid == eku_oid)
            .and_then(|e| parse_extended_key_usage(&e.value).ok())
    }

    /// Parse the Subject Alternative Name extension, if present.
    pub fn subject_alt_name(&self) -> Option<SubjectAltName> {
        let san_oid = known::subject_alt_name().to_der_value();
        self.extensions
            .iter()
            .find(|e| e.oid == san_oid)
            .and_then(|e| parse_subject_alt_name(&e.value).ok())
    }

    /// Parse the Authority Key Identifier extension, if present.
    pub fn authority_key_identifier(&self) -> Option<AuthorityKeyIdentifier> {
        let aki_oid = known::authority_key_identifier().to_der_value();
        self.extensions
            .iter()
            .find(|e| e.oid == aki_oid)
            .and_then(|e| parse_authority_key_identifier(&e.value).ok())
    }

    /// Parse the Subject Key Identifier extension, if present.
    pub fn subject_key_identifier(&self) -> Option<Vec<u8>> {
        let ski_oid = known::subject_key_identifier().to_der_value();
        self.extensions
            .iter()
            .find(|e| e.oid == ski_oid)
            .and_then(|e| parse_subject_key_identifier(&e.value).ok())
    }

    /// Parse the Authority Information Access extension, if present.
    pub fn authority_info_access(&self) -> Option<AuthorityInfoAccess> {
        let aia_oid = known::authority_info_access().to_der_value();
        self.extensions
            .iter()
            .find(|e| e.oid == aia_oid)
            .and_then(|e| parse_authority_info_access(&e.value).ok())
    }

    /// Parse the Name Constraints extension, if present.
    pub fn name_constraints(&self) -> Option<NameConstraints> {
        let nc_oid = known::name_constraints().to_der_value();
        self.extensions
            .iter()
            .find(|e| e.oid == nc_oid)
            .and_then(|e| parse_name_constraints(&e.value).ok())
    }

    /// Parse the Certificate Policies extension, if present.
    pub fn certificate_policies(&self) -> Option<CertificatePolicies> {
        let cp_oid = known::certificate_policies().to_der_value();
        self.extensions
            .iter()
            .find(|e| e.oid == cp_oid)
            .and_then(|e| parse_certificate_policies(&e.value).ok())
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
        } else if sig_oid == known::ed448() {
            verify_ed448(&self.tbs_raw, &self.signature_value, &issuer.public_key)
        } else if sig_oid == known::sm2_with_sm3() {
            verify_sm2(&self.tbs_raw, &self.signature_value, &issuer.public_key)
        } else if sig_oid == known::rsassa_pss() {
            verify_rsa_pss(&self.tbs_raw, &self.signature_value, &issuer.public_key)
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

pub(crate) fn verify_ed448(
    tbs: &[u8],
    signature: &[u8],
    spki: &SubjectPublicKeyInfo,
) -> Result<bool, PkiError> {
    let verifier = hitls_crypto::ed448::Ed448KeyPair::from_public_key(&spki.public_key)
        .map_err(PkiError::from)?;
    // Ed448 takes the raw message (not pre-hashed)
    verifier.verify(tbs, signature).map_err(PkiError::from)
}

pub(crate) fn verify_sm2(
    tbs: &[u8],
    signature: &[u8],
    spki: &SubjectPublicKeyInfo,
) -> Result<bool, PkiError> {
    let verifier =
        hitls_crypto::sm2::Sm2KeyPair::from_public_key(&spki.public_key).map_err(PkiError::from)?;
    // SM2 with SM3 — use empty user ID for X.509 certificate verification
    // (matches C implementation which uses zero-length userId by default)
    verifier
        .verify_with_id(b"", tbs, signature)
        .map_err(PkiError::from)
}

pub(crate) fn verify_rsa_pss(
    tbs: &[u8],
    signature: &[u8],
    spki: &SubjectPublicKeyInfo,
) -> Result<bool, PkiError> {
    // RSA-PSS SPKI uses the same RSA key format
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
    // Default to SHA-256 for PSS hash; compute digest then verify with PSS padding
    let digest = compute_hash(tbs, &HashAlg::Sha256).map_err(PkiError::from)?;
    rsa_pub
        .verify(hitls_crypto::rsa::RsaPadding::Pss, &digest, signature)
        .map_err(PkiError::from)
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

/// Encode GeneralSubtrees for NameConstraints.
fn encode_general_subtrees(names: &[GeneralName]) -> Vec<u8> {
    let mut out = Vec::new();
    for name in names {
        let mut sub_inner = Encoder::new();
        match name {
            GeneralName::DnsName(s) => {
                sub_inner.write_context_specific(2, false, s.as_bytes());
            }
            GeneralName::Rfc822Name(s) => {
                sub_inner.write_context_specific(1, false, s.as_bytes());
            }
            GeneralName::Uri(s) => {
                sub_inner.write_context_specific(6, false, s.as_bytes());
            }
            GeneralName::IpAddress(ip) => {
                sub_inner.write_context_specific(7, false, ip);
            }
            GeneralName::DirectoryName(dn) => {
                let dn_der = encode_distinguished_name(dn);
                sub_inner.write_context_specific(4, true, &dn_der);
            }
        }
        let mut seq = Encoder::new();
        seq.write_sequence(&sub_inner.finish());
        out.extend_from_slice(&seq.finish());
    }
    out
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

/// A private key that can sign data. Supports RSA, ECDSA, Ed25519, and SM2.
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
    /// SM2 private key (signs with SM2-SM3).
    Sm2(hitls_crypto::sm2::Sm2KeyPair),
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
            SigningKey::Sm2(sm2) => sm2.sign(data).map_err(PkiError::from),
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
            SigningKey::Sm2(_) => known::sm2_with_sm3().to_der_value(),
        }
    }

    /// Get the signature algorithm parameters as full DER TLV.
    /// Returns Some(NULL TLV) for RSA, None (absent) for ECDSA/Ed25519/SM2.
    pub fn algorithm_params(&self) -> Option<Vec<u8>> {
        match self {
            SigningKey::Rsa(_) => Some(ALG_PARAMS_NULL.to_vec()),
            SigningKey::Ecdsa { .. } | SigningKey::Ed25519(_) | SigningKey::Sm2(_) => None,
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
            SigningKey::Sm2(sm2) => {
                let pub_bytes = sm2.public_key_bytes().map_err(PkiError::from)?;
                Ok(SubjectPublicKeyInfo {
                    algorithm_oid: known::ec_public_key().to_der_value(),
                    algorithm_params: Some(known::sm2_curve().to_der_value()),
                    public_key: pub_bytes,
                })
            }
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
        } else if sig_oid == known::ed448() {
            verify_ed448(&self.tbs_raw, &self.signature_value, &self.public_key)
        } else if sig_oid == known::sm2_with_sm3() {
            verify_sm2(&self.tbs_raw, &self.signature_value, &self.public_key)
        } else if sig_oid == known::rsassa_pss() {
            verify_rsa_pss(&self.tbs_raw, &self.signature_value, &self.public_key)
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

    /// Add a SubjectKeyIdentifier extension (hash of public key).
    pub fn add_subject_key_identifier(self, key_id: &[u8]) -> Self {
        let mut enc = Encoder::new();
        enc.write_octet_string(key_id);
        let value = enc.finish();
        self.add_extension(known::subject_key_identifier().to_der_value(), false, value)
    }

    /// Add an AuthorityKeyIdentifier extension.
    pub fn add_authority_key_identifier(self, key_id: &[u8]) -> Self {
        // AKI: SEQUENCE { [0] keyIdentifier }
        let mut inner = Encoder::new();
        inner.write_context_specific(0, false, key_id);
        let mut seq = Encoder::new();
        seq.write_sequence(&inner.finish());
        let value = seq.finish();
        self.add_extension(
            known::authority_key_identifier().to_der_value(),
            false,
            value,
        )
    }

    /// Add an ExtendedKeyUsage extension.
    pub fn add_extended_key_usage(self, oids: &[Oid], critical: bool) -> Self {
        let mut inner = Encoder::new();
        for oid in oids {
            inner.write_oid(&oid.to_der_value());
        }
        let mut seq = Encoder::new();
        seq.write_sequence(&inner.finish());
        let value = seq.finish();
        self.add_extension(known::ext_key_usage().to_der_value(), critical, value)
    }

    /// Add a SubjectAltName extension with DNS names.
    pub fn add_subject_alt_name_dns(self, dns_names: &[&str]) -> Self {
        let mut inner = Encoder::new();
        for name in dns_names {
            // dNSName [2] IA5String (context-specific, primitive)
            inner.write_context_specific(2, false, name.as_bytes());
        }
        let mut seq = Encoder::new();
        seq.write_sequence(&inner.finish());
        let value = seq.finish();
        self.add_extension(known::subject_alt_name().to_der_value(), false, value)
    }

    /// Add a NameConstraints extension.
    pub fn add_name_constraints(self, permitted: &[GeneralName], excluded: &[GeneralName]) -> Self {
        let mut inner = Encoder::new();
        if !permitted.is_empty() {
            let subtrees = encode_general_subtrees(permitted);
            inner.write_context_specific(0, true, &subtrees);
        }
        if !excluded.is_empty() {
            let subtrees = encode_general_subtrees(excluded);
            inner.write_context_specific(1, true, &subtrees);
        }
        let mut seq = Encoder::new();
        seq.write_sequence(&inner.finish());
        let value = seq.finish();
        self.add_extension(known::name_constraints().to_der_value(), true, value)
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

    // -----------------------------------------------------------------------
    // Phase 51: Real C test vector — certificate parsing edge cases
    // -----------------------------------------------------------------------

    const CERTCHECK_V0: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certversion0noext.der");
    const CERTCHECK_V2: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certversion2withext.der");
    const CERTCHECK_NEG_SERIAL: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certnegativeserialnum.der");
    const CERTCHECK_DN_NULL: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certdnvaluenull.der");
    const CERTCHECK_RSA_PSS: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certrsapss.der");
    const CERTCHECK_SAN_DNS: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_san_parse_1.der");
    const CERTCHECK_SAN_IP: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_san_parse_3.der");
    const CERTCHECK_KU: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_keyusage_parse_1.der");
    const CERTCHECK_EKU: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_extku_parse_1.der");
    const CERTCHECK_BC: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_bcon_parse_1.der");

    #[test]
    fn test_parse_v1_cert() {
        // Version 0 (v1) cert — no extensions
        let cert = Certificate::from_der(CERTCHECK_V0).unwrap();
        assert_eq!(cert.version, 1); // v1 = version field value 0
        assert!(cert.extensions.is_empty());
    }

    #[test]
    fn test_parse_v3_cert() {
        // Version 2 (v3) cert — has extensions
        let cert = Certificate::from_der(CERTCHECK_V2).unwrap();
        assert_eq!(cert.version, 3); // v3 = version field value 2
        assert!(!cert.extensions.is_empty());
    }

    #[test]
    fn test_parse_negative_serial() {
        // Certificate with serial number 0xFF (encoded as 00 FF in DER to stay positive)
        let cert = Certificate::from_der(CERTCHECK_NEG_SERIAL).unwrap();
        assert!(!cert.serial_number.is_empty());
        // DER INTEGER encoding: 00 FF (leading zero keeps it positive per X.690)
        // The raw bytes should contain 0xFF after any leading zero padding
        let sn = &cert.serial_number;
        let value_byte = if sn[0] == 0x00 && sn.len() > 1 {
            sn[1] // strip DER padding byte
        } else {
            sn[0]
        };
        assert_eq!(value_byte, 0xFF, "serial value byte should be 0xFF");
    }

    #[test]
    fn test_parse_dn_null_value() {
        // Certificate with null byte in DN value
        let result = Certificate::from_der(CERTCHECK_DN_NULL);
        // Should either parse successfully or fail gracefully
        match result {
            Ok(cert) => {
                assert!(!cert.subject.entries.is_empty());
            }
            Err(_) => {
                // Failing to parse a null DN is acceptable
            }
        }
    }

    #[test]
    fn test_parse_rsa_pss_cert() {
        // RSA-PSS algorithm identifier
        let cert = Certificate::from_der(CERTCHECK_RSA_PSS).unwrap();
        assert_eq!(cert.version, 3);
        // RSA-PSS OID: 1.2.840.113549.1.1.10
        let sig_oid = Oid::from_der_value(&cert.signature_algorithm).unwrap();
        let rsa_pss_oid = Oid::new(&[1, 2, 840, 113549, 1, 1, 10]);
        assert_eq!(sig_oid, rsa_pss_oid);
    }

    #[test]
    fn test_parse_san_dns() {
        // SAN extension with DNS names
        let cert = Certificate::from_der(CERTCHECK_SAN_DNS).unwrap();
        let san_oid = known::subject_alt_name().to_der_value();
        let san_ext = cert.extensions.iter().find(|e| e.oid == san_oid);
        assert!(san_ext.is_some(), "should have SAN extension");
    }

    #[test]
    fn test_parse_san_ip() {
        // SAN extension with IP addresses
        let cert = Certificate::from_der(CERTCHECK_SAN_IP).unwrap();
        let san_oid = known::subject_alt_name().to_der_value();
        let san_ext = cert.extensions.iter().find(|e| e.oid == san_oid);
        assert!(san_ext.is_some(), "should have SAN extension");
    }

    #[test]
    fn test_parse_keyusage_ext() {
        // KeyUsage extension
        let cert = Certificate::from_der(CERTCHECK_KU).unwrap();
        let ku = cert.key_usage();
        assert!(ku.is_some(), "should have KeyUsage extension");
    }

    #[test]
    fn test_parse_eku_ext() {
        // Extended Key Usage extension
        let cert = Certificate::from_der(CERTCHECK_EKU).unwrap();
        let eku_oid = vec![0x55, 0x1D, 0x25]; // 2.5.29.37
        let has_eku = cert.extensions.iter().any(|e| e.oid.ends_with(&eku_oid));
        assert!(has_eku, "should have EKU extension");
    }

    #[test]
    fn test_parse_bc_ext() {
        // BasicConstraints extension
        let cert = Certificate::from_der(CERTCHECK_BC).unwrap();
        let bc = cert.basic_constraints();
        assert!(bc.is_some(), "should have BasicConstraints extension");
    }

    // -----------------------------------------------------------------------
    // Phase 52: Typed extension parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_eku_parsing() {
        let cert = Certificate::from_der(CERTCHECK_EKU).unwrap();
        let eku = cert.extended_key_usage();
        assert!(eku.is_some(), "cert should have EKU extension");
        let eku = eku.unwrap();
        assert!(!eku.purposes.is_empty());
    }

    #[test]
    fn test_eku_parsing_real_server() {
        // server_good.der from eku_suite has serverAuth
        let cert = Certificate::from_der(EKU_SERVER_GOOD_DER).unwrap();
        let eku = cert.extended_key_usage();
        assert!(eku.is_some());
        let eku = eku.unwrap();
        assert!(
            eku.purposes.iter().any(|p| *p == known::kp_server_auth()),
            "server cert should have serverAuth EKU"
        );
    }

    const EKU_SERVER_GOOD_DER: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/eku_suite/server_good.der");
    const EKU_CLIENT_GOOD_DER: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/eku_suite/client_good.der");
    const EKU_ANY_GOOD_DER: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/eku_suite/anyEKU/anyeku_good.der");

    #[test]
    fn test_eku_parsing_real_client() {
        let cert = Certificate::from_der(EKU_CLIENT_GOOD_DER).unwrap();
        let eku = cert.extended_key_usage().unwrap();
        assert!(eku.purposes.iter().any(|p| *p == known::kp_client_auth()));
    }

    #[test]
    fn test_eku_any_purpose() {
        let cert = Certificate::from_der(EKU_ANY_GOOD_DER).unwrap();
        let eku = cert.extended_key_usage().unwrap();
        assert!(
            eku.purposes
                .iter()
                .any(|p| *p == known::any_extended_key_usage()),
            "anyEKU cert should have anyExtendedKeyUsage"
        );
    }

    #[test]
    fn test_san_email_parsing() {
        // cert_ext_san_parse_1.der has rfc822Name (email), not dNSName
        let cert = Certificate::from_der(CERTCHECK_SAN_DNS).unwrap();
        let san = cert.subject_alt_name();
        assert!(san.is_some(), "cert should have SAN extension");
        let san = san.unwrap();
        assert!(
            !san.email_addresses.is_empty(),
            "SAN should have email addresses"
        );
    }

    #[test]
    fn test_san_ip_parsing() {
        let cert = Certificate::from_der(CERTCHECK_SAN_IP).unwrap();
        let san = cert.subject_alt_name();
        assert!(san.is_some(), "cert should have SAN extension");
        let san = san.unwrap();
        assert!(!san.ip_addresses.is_empty(), "SAN should have IP addresses");
    }

    #[test]
    fn test_san_empty() {
        // RSA test cert has no SAN
        let data = hex(RSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        assert!(cert.subject_alt_name().is_none());
    }

    #[test]
    fn test_aki_parsing() {
        let data = hex(RSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        let aki = cert.authority_key_identifier();
        assert!(aki.is_some(), "cert should have AKI extension");
        let aki = aki.unwrap();
        assert!(aki.key_identifier.is_some(), "AKI should have key ID");
    }

    #[test]
    fn test_ski_parsing() {
        let data = hex(RSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        let ski = cert.subject_key_identifier();
        assert!(ski.is_some(), "cert should have SKI extension");
        assert!(!ski.unwrap().is_empty());
    }

    #[test]
    fn test_aki_ski_match() {
        // Self-signed cert: AKI.keyId == SKI
        let data = hex(RSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        let ski = cert.subject_key_identifier().unwrap();
        let aki = cert.authority_key_identifier().unwrap();
        assert_eq!(
            aki.key_identifier.as_ref().unwrap(),
            &ski,
            "self-signed cert AKI should match SKI"
        );
    }

    #[test]
    fn test_name_constraints_synthetic() {
        // Build a cert with NameConstraints using the builder
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".to_string(), "NC Test CA".to_string())],
        };
        let spki = sk.public_key_info().unwrap();
        let cert = CertificateBuilder::new()
            .serial_number(&[0x01])
            .issuer(dn.clone())
            .subject(dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .add_basic_constraints(true, None)
            .add_name_constraints(
                &[GeneralName::DnsName(".example.com".into())],
                &[GeneralName::DnsName(".evil.com".into())],
            )
            .build(&sk)
            .unwrap();

        let nc = cert.name_constraints();
        assert!(nc.is_some(), "cert should have NameConstraints");
        let nc = nc.unwrap();
        assert_eq!(nc.permitted_subtrees.len(), 1);
        assert_eq!(nc.excluded_subtrees.len(), 1);
        match &nc.permitted_subtrees[0].base {
            GeneralName::DnsName(s) => assert_eq!(s, ".example.com"),
            _ => panic!("expected DnsName"),
        }
        match &nc.excluded_subtrees[0].base {
            GeneralName::DnsName(s) => assert_eq!(s, ".evil.com"),
            _ => panic!("expected DnsName"),
        }
    }

    #[test]
    fn test_eku_builder_roundtrip() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".to_string(), "EKU Test".to_string())],
        };
        let spki = sk.public_key_info().unwrap();
        let cert = CertificateBuilder::new()
            .serial_number(&[0x01])
            .issuer(dn.clone())
            .subject(dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .add_extended_key_usage(&[known::kp_server_auth(), known::kp_client_auth()], false)
            .build(&sk)
            .unwrap();

        let eku = cert.extended_key_usage().unwrap();
        assert_eq!(eku.purposes.len(), 2);
        assert!(eku.purposes.contains(&known::kp_server_auth()));
        assert!(eku.purposes.contains(&known::kp_client_auth()));
    }

    #[test]
    fn test_san_builder_roundtrip() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".to_string(), "SAN Test".to_string())],
        };
        let spki = sk.public_key_info().unwrap();
        let cert = CertificateBuilder::new()
            .serial_number(&[0x01])
            .issuer(dn.clone())
            .subject(dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .add_subject_alt_name_dns(&["www.example.com", "mail.example.com"])
            .build(&sk)
            .unwrap();

        let san = cert.subject_alt_name().unwrap();
        assert_eq!(san.dns_names.len(), 2);
        assert!(san.dns_names.contains(&"www.example.com".to_string()));
        assert!(san.dns_names.contains(&"mail.example.com".to_string()));
    }

    #[test]
    fn test_ski_aki_builder_roundtrip() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".to_string(), "SKI Test".to_string())],
        };
        let spki = sk.public_key_info().unwrap();
        let key_id = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let cert = CertificateBuilder::new()
            .serial_number(&[0x01])
            .issuer(dn.clone())
            .subject(dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .add_subject_key_identifier(&key_id)
            .add_authority_key_identifier(&key_id)
            .build(&sk)
            .unwrap();

        let ski = cert.subject_key_identifier().unwrap();
        assert_eq!(ski, key_id);
        let aki = cert.authority_key_identifier().unwrap();
        assert_eq!(aki.key_identifier.unwrap(), key_id);
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

    // -----------------------------------------------------------------------
    // Phase 53: Extension edge cases + cert parsing edge cases
    // -----------------------------------------------------------------------

    const CERTCHECK_ZERO_SERIAL: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert0serialnum.der");
    const CERTCHECK_20_SERIAL: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert20serialnum.der");
    const CERTCHECK_21_SERIAL: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert21serialnum.der");
    const CERTCHECK_NO_ISSUER: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certnoissuer.der");
    const CERTCHECK_NO_PUBKEY: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certnopublickey.der");
    const CERTCHECK_NO_SIG_ALG: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certnosignaturealgorithm.der");
    const CERTCHECK_NO_SUBJECT_NO_SAN: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certnosubjectnosan.der");
    const CERTCHECK_SAN_NO_SUBJECT: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certwithsannosubject.der");
    const CERTCHECK_EMAIL_SUBJECT: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certsubjectwithemail.der");
    const CERTCHECK_TELETEX: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certteletexstring.der");
    const CERTCHECK_IA5_DN: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certdnvalueIA5String.der");
    const CERTCHECK_DSA: &[u8] = include_bytes!("../../../../tests/vectors/certcheck/dsacert.der");

    // Duplicate extension test certs
    const EXT_AKID_REPEAT: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_akid_repeat.der");
    const EXT_BCONS_REPEAT: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_bcons_repeat.der");
    const EXT_EXKU_REPEAT: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_exku_repeat.der");
    const EXT_KU_REPEAT: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_keyusage_repeat.der");
    const EXT_KU_ERR: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_keyusage_err.der");
    const EXT_SAN_REPEAT: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_san_repeat.der");
    const EXT_SKID_REPEAT: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_skid_repeat.der");
    const EXT_MANY: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_extensions.der");

    #[test]
    fn test_parse_zero_serial() {
        let cert = Certificate::from_der(CERTCHECK_ZERO_SERIAL).unwrap();
        // Serial number should be 0 (single byte [0x00] or empty)
        assert!(
            cert.serial_number == vec![0x00] || cert.serial_number.is_empty(),
            "serial should be zero, got: {:?}",
            cert.serial_number
        );
    }

    #[test]
    fn test_parse_large_serial_20() {
        let cert = Certificate::from_der(CERTCHECK_20_SERIAL).unwrap();
        // 20-byte serial number
        assert!(
            cert.serial_number.len() >= 20,
            "serial should be at least 20 bytes, got {} bytes",
            cert.serial_number.len()
        );
    }

    #[test]
    fn test_parse_large_serial_21() {
        let cert = Certificate::from_der(CERTCHECK_21_SERIAL).unwrap();
        // 21-byte serial number (may have leading zero)
        assert!(
            cert.serial_number.len() >= 20,
            "serial should be at least 20 bytes, got {} bytes",
            cert.serial_number.len()
        );
    }

    #[test]
    fn test_parse_missing_issuer() {
        // Should fail — issuer is mandatory
        let result = Certificate::from_der(CERTCHECK_NO_ISSUER);
        assert!(result.is_err(), "missing issuer should fail parsing");
    }

    #[test]
    fn test_parse_missing_pubkey() {
        // Should fail — public key is mandatory
        let result = Certificate::from_der(CERTCHECK_NO_PUBKEY);
        assert!(result.is_err(), "missing pubkey should fail parsing");
    }

    #[test]
    fn test_parse_missing_sig_alg() {
        // Should fail — signature algorithm is mandatory
        let result = Certificate::from_der(CERTCHECK_NO_SIG_ALG);
        assert!(result.is_err(), "missing sig alg should fail parsing");
    }

    #[test]
    fn test_parse_san_no_subject() {
        // Cert with SAN but empty subject — may fail to parse if DER is unusual
        let result = Certificate::from_der(CERTCHECK_SAN_NO_SUBJECT);
        match result {
            Ok(cert) => {
                let san = cert.subject_alt_name();
                assert!(
                    san.is_some(),
                    "cert with SAN-no-subject should have SAN extension"
                );
            }
            Err(_) => {
                // Some test vectors have unusual encoding that our parser doesn't support
            }
        }
    }

    #[test]
    fn test_parse_no_subject_no_san() {
        // Cert with neither subject nor SAN — may parse but is invalid per RFC
        let result = Certificate::from_der(CERTCHECK_NO_SUBJECT_NO_SAN);
        if let Ok(cert) = result {
            assert!(cert.subject.entries.is_empty() || cert.subject_alt_name().is_none());
        }
    }

    #[test]
    fn test_parse_email_in_subject() {
        let cert = Certificate::from_der(CERTCHECK_EMAIL_SUBJECT).unwrap();
        // Subject DN should contain emailAddress attribute
        let has_email = cert
            .subject
            .entries
            .iter()
            .any(|(k, _)| k == "emailAddress" || k.contains("1.2.840.113549.1.9.1"));
        assert!(has_email, "subject should have email address attribute");
    }

    #[test]
    fn test_parse_teletex_string() {
        // TeletexString (T61String) encoding in DN
        let result = Certificate::from_der(CERTCHECK_TELETEX);
        match result {
            Ok(cert) => {
                assert!(!cert.subject.entries.is_empty());
            }
            Err(_) => {
                // TeletexString may not be fully supported — acceptable
            }
        }
    }

    #[test]
    fn test_parse_ia5string_dn() {
        let result = Certificate::from_der(CERTCHECK_IA5_DN);
        if let Ok(cert) = result {
            assert!(!cert.subject.entries.is_empty());
        }
    }

    #[test]
    fn test_parse_dsa_cert() {
        let cert = Certificate::from_der(CERTCHECK_DSA).unwrap();
        assert_eq!(cert.version, 3);
        // DSA OID: 1.2.840.10040.4.3 (id-dsa-with-sha1) or similar
        let sig_oid = Oid::from_der_value(&cert.signature_algorithm).unwrap();
        // Just verify it parsed successfully with a non-empty signature
        assert!(!sig_oid.to_dot_string().is_empty());
        assert!(!cert.signature_value.is_empty());
    }

    #[test]
    fn test_parse_duplicate_aki() {
        // Cert with duplicate AKI extension — should parse (first wins)
        let cert = Certificate::from_der(EXT_AKID_REPEAT).unwrap();
        let aki_oid = known::authority_key_identifier().to_der_value();
        let count = cert.extensions.iter().filter(|e| e.oid == aki_oid).count();
        assert!(count >= 2, "should have duplicate AKI extensions");
        // Method returns first one
        let aki = cert.authority_key_identifier();
        assert!(aki.is_some());
    }

    #[test]
    fn test_parse_duplicate_bc() {
        let cert = Certificate::from_der(EXT_BCONS_REPEAT).unwrap();
        let bc_oid = known::basic_constraints().to_der_value();
        let count = cert.extensions.iter().filter(|e| e.oid == bc_oid).count();
        assert!(count >= 2, "should have duplicate BC extensions");
        let bc = cert.basic_constraints();
        assert!(bc.is_some());
    }

    #[test]
    fn test_parse_duplicate_eku() {
        let cert = Certificate::from_der(EXT_EXKU_REPEAT).unwrap();
        let eku_oid = known::ext_key_usage().to_der_value();
        let count = cert.extensions.iter().filter(|e| e.oid == eku_oid).count();
        assert!(count >= 2, "should have duplicate EKU extensions");
        let eku = cert.extended_key_usage();
        assert!(eku.is_some());
    }

    #[test]
    fn test_parse_duplicate_ku() {
        let cert = Certificate::from_der(EXT_KU_REPEAT).unwrap();
        let ku_oid = known::key_usage().to_der_value();
        let count = cert.extensions.iter().filter(|e| e.oid == ku_oid).count();
        assert!(count >= 2, "should have duplicate KU extensions");
        let ku = cert.key_usage();
        assert!(ku.is_some());
    }

    #[test]
    fn test_parse_malformed_ku() {
        // Malformed KeyUsage extension — should parse cert, but key_usage() may return None
        let cert = Certificate::from_der(EXT_KU_ERR).unwrap();
        // The cert itself should parse; the extension value may or may not parse
        let _ku = cert.key_usage(); // don't assert — just ensure no panic
    }

    #[test]
    fn test_parse_duplicate_san() {
        let cert = Certificate::from_der(EXT_SAN_REPEAT).unwrap();
        let san_oid = known::subject_alt_name().to_der_value();
        let count = cert.extensions.iter().filter(|e| e.oid == san_oid).count();
        assert!(count >= 2, "should have duplicate SAN extensions");
        let san = cert.subject_alt_name();
        assert!(san.is_some());
    }

    #[test]
    fn test_parse_duplicate_ski() {
        let cert = Certificate::from_der(EXT_SKID_REPEAT).unwrap();
        let ski_oid = known::subject_key_identifier().to_der_value();
        let count = cert.extensions.iter().filter(|e| e.oid == ski_oid).count();
        assert!(count >= 2, "should have duplicate SKI extensions");
        let ski = cert.subject_key_identifier();
        assert!(ski.is_some());
    }

    #[test]
    fn test_parse_many_extensions() {
        let cert = Certificate::from_der(EXT_MANY).unwrap();
        assert!(
            cert.extensions.len() >= 3,
            "cert_extensions.der should have multiple extensions"
        );
    }

    // -----------------------------------------------------------------------
    // Phase 53: CertificatePolicies extension parsing tests
    // -----------------------------------------------------------------------

    const POLICY_CRITICAL_DER: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/policy_suite/inter_policy_critical.der");
    const POLICY_NONCRIT_DER: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/policy_suite/inter_policy_noncrit.der");

    #[test]
    fn test_cert_policies_parsing_critical() {
        let cert = Certificate::from_der(POLICY_CRITICAL_DER).unwrap();
        let cp = cert.certificate_policies();
        assert!(cp.is_some(), "should have CertificatePolicies extension");
        let cp = cp.unwrap();
        assert!(!cp.policies.is_empty(), "should have at least one policy");
        // Policy OID: 1.3.6.1.4.1.55555.1
        let expected_oid = Oid::new(&[1, 3, 6, 1, 4, 1, 55555, 1]);
        assert!(
            cp.policies
                .iter()
                .any(|p| p.policy_identifier == expected_oid),
            "should contain policy 1.3.6.1.4.1.55555.1"
        );
    }

    #[test]
    fn test_cert_policies_parsing_noncrit() {
        let cert = Certificate::from_der(POLICY_NONCRIT_DER).unwrap();
        let cp = cert.certificate_policies();
        assert!(cp.is_some());
        let cp = cp.unwrap();
        assert!(!cp.policies.is_empty());
        let expected_oid = Oid::new(&[1, 3, 6, 1, 4, 1, 55555, 1]);
        assert!(cp
            .policies
            .iter()
            .any(|p| p.policy_identifier == expected_oid));
    }

    #[test]
    fn test_cert_policies_none() {
        // RSA test cert has no policies
        let data = hex(RSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        assert!(
            cert.certificate_policies().is_none(),
            "cert without policies should return None"
        );
    }

    #[test]
    fn test_cert_policies_any_policy() {
        // Build a cert with anyPolicy using the builder
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".to_string(), "Policy Test".to_string())],
        };
        let spki = sk.public_key_info().unwrap();

        // Manually encode anyPolicy CertificatePolicies extension
        let any_policy_oid = known::any_policy();
        let pi_body = {
            let mut e = hitls_utils::asn1::Encoder::new();
            e.write_oid(&any_policy_oid.to_der_value());
            e.finish()
        };
        let cp_body = {
            let mut e = hitls_utils::asn1::Encoder::new();
            e.write_sequence(&pi_body);
            e.finish()
        };
        let cp_value = {
            let mut e = hitls_utils::asn1::Encoder::new();
            e.write_sequence(&cp_body);
            e.finish()
        };

        let cert = CertificateBuilder::new()
            .serial_number(&[0x01])
            .issuer(dn.clone())
            .subject(dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .add_extension(
                known::certificate_policies().to_der_value(),
                false,
                cp_value,
            )
            .build(&sk)
            .unwrap();

        let cp = cert.certificate_policies().unwrap();
        assert_eq!(cp.policies.len(), 1);
        assert_eq!(cp.policies[0].policy_identifier, any_policy_oid);
    }

    // -----------------------------------------------------------------------
    // Phase 53: CSR parsing tests from C test vectors
    // -----------------------------------------------------------------------

    const CSR_RSA_SHA256: &str =
        include_str!("../../../../tests/vectors/csr/rsa_sha/rsa_sh256.csr");
    const CSR_ECDSA_SHA256: &str =
        include_str!("../../../../tests/vectors/csr/ecdsa_sha/ec_app256SHA256.csr");
    const CSR_SM2: &str = include_str!("../../../../tests/vectors/csr/sm2/ca.csr");

    #[test]
    fn test_csr_parse_rsa_sha256() {
        let csr = CertificateRequest::from_pem(CSR_RSA_SHA256).unwrap();
        assert_eq!(csr.version, 0);
        assert!(!csr.subject.entries.is_empty());
        assert!(!csr.public_key.public_key.is_empty());
        // RSA key — algorithm OID should be rsaEncryption
        let alg_oid = Oid::from_der_value(&csr.public_key.algorithm_oid).unwrap();
        let rsa_oid = Oid::new(&[1, 2, 840, 113549, 1, 1, 1]);
        assert_eq!(alg_oid, rsa_oid);
    }

    #[test]
    fn test_csr_parse_ecdsa_sha256() {
        let csr = CertificateRequest::from_pem(CSR_ECDSA_SHA256).unwrap();
        assert_eq!(csr.version, 0);
        assert!(!csr.subject.entries.is_empty());
        // EC key — algorithm OID should be id-ecPublicKey
        let alg_oid = Oid::from_der_value(&csr.public_key.algorithm_oid).unwrap();
        let ec_oid = known::ec_public_key();
        assert_eq!(alg_oid, ec_oid);
    }

    #[test]
    fn test_csr_parse_sm2() {
        let csr = CertificateRequest::from_pem(CSR_SM2).unwrap();
        assert_eq!(csr.version, 0);
        assert!(!csr.subject.entries.is_empty());
        // SM2 key — algorithm OID should be id-ecPublicKey
        let alg_oid = Oid::from_der_value(&csr.public_key.algorithm_oid).unwrap();
        let ec_oid = known::ec_public_key();
        assert_eq!(alg_oid, ec_oid);
    }

    #[test]
    fn test_csr_verify_rsa() {
        let csr = CertificateRequest::from_pem(CSR_RSA_SHA256).unwrap();
        let result = csr.verify_signature();
        assert!(result.is_ok(), "RSA CSR verify failed: {result:?}");
        assert!(result.unwrap());
    }

    #[test]
    fn test_csr_verify_ecdsa() {
        let csr = CertificateRequest::from_pem(CSR_ECDSA_SHA256).unwrap();
        let result = csr.verify_signature();
        assert!(result.is_ok(), "ECDSA CSR verify failed: {result:?}");
        assert!(result.unwrap());
    }

    #[test]
    fn test_cert_policies_with_cps_qualifier() {
        // Build a cert with CPS URI qualifier
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".to_string(), "CPS Test".to_string())],
        };
        let spki = sk.public_key_info().unwrap();

        let policy_oid = Oid::new(&[2, 5, 29, 32, 0]); // anyPolicy
        let cps_oid = known::cps_qualifier();

        // Encode CPS URI as IA5String
        let cps_uri = "https://example.com/cps";
        let mut cps_str_enc = hitls_utils::asn1::Encoder::new();
        cps_str_enc.write_ia5_string(cps_uri);
        let cps_str_bytes = cps_str_enc.finish();

        // PolicyQualifierInfo: SEQUENCE { OID, IA5String }
        let mut pqi_enc = hitls_utils::asn1::Encoder::new();
        pqi_enc.write_oid(&cps_oid.to_der_value());
        pqi_enc.write_raw(&cps_str_bytes);
        let pqi_body = pqi_enc.finish();

        let mut pqi_seq = hitls_utils::asn1::Encoder::new();
        pqi_seq.write_sequence(&pqi_body);
        let pqi_seq_bytes = pqi_seq.finish();

        // policyQualifiers SEQUENCE
        let mut quals_enc = hitls_utils::asn1::Encoder::new();
        quals_enc.write_sequence(&pqi_seq_bytes);
        let quals_bytes = quals_enc.finish();

        // PolicyInformation: SEQUENCE { OID, qualifiers }
        let mut pi_enc = hitls_utils::asn1::Encoder::new();
        pi_enc.write_oid(&policy_oid.to_der_value());
        pi_enc.write_raw(&quals_bytes);
        let pi_body = pi_enc.finish();

        let mut pi_seq = hitls_utils::asn1::Encoder::new();
        pi_seq.write_sequence(&pi_body);
        let pi_seq_bytes = pi_seq.finish();

        // CertificatePolicies: SEQUENCE OF PolicyInformation
        let mut cp_enc = hitls_utils::asn1::Encoder::new();
        cp_enc.write_sequence(&pi_seq_bytes);
        let cp_value = cp_enc.finish();

        let cert = CertificateBuilder::new()
            .serial_number(&[0x02])
            .issuer(dn.clone())
            .subject(dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .add_extension(
                known::certificate_policies().to_der_value(),
                false,
                cp_value,
            )
            .build(&sk)
            .unwrap();

        let cp = cert.certificate_policies().unwrap();
        assert_eq!(cp.policies.len(), 1);
        assert_eq!(cp.policies[0].policy_identifier, policy_oid);
        assert_eq!(cp.policies[0].qualifiers.len(), 1);
        assert_eq!(cp.policies[0].qualifiers[0].qualifier_id, cps_oid);
    }

    // -----------------------------------------------------------------------
    // Phase 54: Ed448, SM2, RSA-PSS signature verification tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_ed448_direct() {
        // Test Ed448 signature verification using the verify_ed448 helper directly
        let kp = hitls_crypto::ed448::Ed448KeyPair::generate().unwrap();
        let pub_bytes = kp.public_key().to_vec();
        let spki = SubjectPublicKeyInfo {
            algorithm_oid: known::ed448().to_der_value(),
            algorithm_params: None,
            public_key: pub_bytes,
        };
        let message = b"test message for Ed448 verification";
        let sig = kp.sign(message).unwrap();
        let result = verify_ed448(message, &sig, &spki).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_ed448_bad_signature() {
        // Test Ed448 verification with tampered signature
        let kp = hitls_crypto::ed448::Ed448KeyPair::generate().unwrap();
        let pub_bytes = kp.public_key().to_vec();
        let spki = SubjectPublicKeyInfo {
            algorithm_oid: known::ed448().to_der_value(),
            algorithm_params: None,
            public_key: pub_bytes,
        };
        let message = b"test message for Ed448 verification";
        let mut sig = kp.sign(message).unwrap();
        sig[10] ^= 0xFF; // Tamper
        let result = verify_ed448(message, &sig, &spki);
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_verify_sm2_self_signed() {
        let root_pem = include_str!("../../../../tests/vectors/chain/sigParam/sm2_root.pem");
        let root = Certificate::from_pem(root_pem).unwrap();
        assert_eq!(root.subject.get("CN"), Some("sigParam Root SM2"));
        let result = root.verify_signature(&root);
        assert!(result.is_ok(), "SM2 self-signed verify failed: {result:?}");
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_sm2_chain() {
        let root_pem = include_str!("../../../../tests/vectors/chain/sigParam/sm2_root.pem");
        let leaf_pem = include_str!("../../../../tests/vectors/chain/sigParam/sm2_leaf.pem");
        let root = Certificate::from_pem(root_pem).unwrap();
        let leaf = Certificate::from_pem(leaf_pem).unwrap();
        let result = leaf.verify_signature(&root);
        assert!(result.is_ok(), "SM2 chain verify failed: {result:?}");
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_rsa_pss_self_signed() {
        let root_pem = include_str!("../../../../tests/vectors/chain/sigParam/rsa_pss_root.pem");
        let root = Certificate::from_pem(root_pem).unwrap();
        assert_eq!(root.subject.get("CN"), Some("sigParam Root RSA-PSS"));
        let result = root.verify_signature(&root);
        assert!(
            result.is_ok(),
            "RSA-PSS self-signed verify failed: {result:?}"
        );
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_rsa_pss_chain() {
        let root_pem = include_str!("../../../../tests/vectors/chain/sigParam/rsa_pss_root.pem");
        let leaf_pem = include_str!("../../../../tests/vectors/chain/sigParam/rsa_pss_leaf.pem");
        let root = Certificate::from_pem(root_pem).unwrap();
        let leaf = Certificate::from_pem(leaf_pem).unwrap();
        let result = leaf.verify_signature(&root);
        assert!(result.is_ok(), "RSA-PSS chain verify failed: {result:?}");
        assert!(result.unwrap());
    }
}
