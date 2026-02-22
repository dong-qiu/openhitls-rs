//! Core X.509 types and DER/PEM parsing.

use hitls_types::PkiError;
use hitls_utils::asn1::{tags, Decoder, TagClass};
use hitls_utils::oid::{known, Oid};

use super::signing::{
    verify_ecdsa, verify_ed25519, verify_ed448, verify_rsa, verify_rsa_pss, verify_sm2, HashAlg,
};

// ---------------------------------------------------------------------------
// Core type definitions
// ---------------------------------------------------------------------------

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

pub(super) fn parse_subject_public_key_info(
    dec: &mut Decoder,
) -> Result<SubjectPublicKeyInfo, PkiError> {
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

    /// Returns true if this certificate is self-signed (issuer DN == subject DN).
    pub fn is_self_signed(&self) -> bool {
        self.issuer.entries == self.subject.entries
    }
}

// ---------------------------------------------------------------------------
// CSR (PKCS#10) Parsing
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
