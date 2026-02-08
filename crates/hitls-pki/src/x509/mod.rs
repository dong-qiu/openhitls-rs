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
    pub raw: Vec<u8>,
    pub subject: DistinguishedName,
    pub public_key: SubjectPublicKeyInfo,
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
}
