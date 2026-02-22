//! X.509 extension types, parsing functions, and certificate convenience methods.

use hitls_types::PkiError;
use hitls_utils::asn1::{Decoder, TagClass};
use hitls_utils::oid::{known, Oid};

use super::certificate::{parse_name, Certificate, DistinguishedName};

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

// ---------------------------------------------------------------------------
// Extension parsing functions
// ---------------------------------------------------------------------------

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
        if tag.class == TagClass::Universal && tag.number == hitls_utils::asn1::tags::BOOLEAN as u32
        {
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
}
