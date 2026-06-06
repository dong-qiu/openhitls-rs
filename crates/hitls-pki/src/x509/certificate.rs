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
///
/// # Examples
///
/// Parse a DER-encoded certificate:
///
/// ```
/// use hitls_pki::x509::Certificate;
///
/// // Minimal self-signed RSA certificate (DER-encoded)
/// let der = hitls_utils::hex::hex(
///     "3082034b30820233a0030201020214581eeff0e59e83d8457fa83d599d4ff9048b45b5\
///      300d06092a864886f70d01010b050030343111300f06035504030c08546573742052534131\
///      123010060355040a0c094f70656e4869544c53310b300906035504061302434e3020170d32\
///      36303230373133313931355a180f32313236303131343133313931355a30343111300f0603\
///      5504030c08546573742052534131123010060355040a0c094f70656e4869544c53310b3009\
///      06035504061302434e30820122300d06092a864886f70d01010105000382010f003082010a\
///      02820101009565f148f55f7367afb865eb15285cfce9fd2208f35f5dba7ea24b426ad79ce8\
///      2e5f88ae990feba39961921fa477f0411eb28739cf476577c5e0324aa95534a4dd7226fc13\
///      3a5e435d81e433aa5928aef56e84c5eeb3a6073996c729d878ea1d6ef2a5da17c20a1a205\
///      a1ae8193a7fa8f56c6fb3feff398467c6cb4405b9e491fc9ecba5b2eca93f13ca94983b13\
///      f708f6dc428ce4fd9b893c57285b97d01ecb76f82c1bd2eef1867b8c4604d97616132da27\
///      d79a49698d9f47ff358079dd356b2f9d759ddbe5822b52520d0fa2a61a3c0b02991b2447ae\
///      944941a6df433c4f6bcf45d9d55dd45cbb8218df3777fde45fd2c9b3790bfbc4b6cb23e2e1\
///      45b70990203010001a3533051301d0603551d0e041604145359b82d12f1ae48dc982fc1b49f\
///      8205d273dea4301f0603551d230418301680145359b82d12f1ae48dc982fc1b49f8205d273de\
///      a4300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003820101008d\
///      92384c0601ba663e8e064d4fcfa33aad19cc55ce393c2179b90f136c928a6f419594f66c6619\
///      47376d60c7a8629e131018bd469bdb610995c32e6ae13a8c0b794c3a9fe6b9db59cf55dff1ba\
///      417daaf4f5acceb7e901665e136c6e9aff4450a59d0feb7503dbaf83f43862b002f827ab92b3\
///      aa5905dfd58b5e1f55ca1b56658c0dc79469c00bce331ea7805906e4018bcc7ddf8e53498e1f\
///      3eab7945eb277a0f139ff59656c6180538e767856d4725e59e39eac063088e814b5b3f879e317\
///      22f9c3a062782d68f555b4eed230dea309ac071f38e4261608943654aa4242af40e50a97d6c20\
///      208feb4dc1b45686fd60906ce1452d208ade0ee19f70b00b1ef4"
/// );
/// let cert = Certificate::from_der(&der).unwrap();
/// assert_eq!(cert.version, 3);
/// assert_eq!(cert.subject.get("CN"), Some("Test RSA"));
/// ```
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
    /// Raw DER-encoded issuer Name (for OCSP CertID hashing).
    pub issuer_raw: Vec<u8>,
    /// Subject distinguished name.
    pub subject: DistinguishedName,
    /// Raw DER-encoded subject Name (for OCSP CertID hashing).
    pub subject_raw: Vec<u8>,
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
            if tag.class == TagClass::Universal && tag.number == u32::from(tags::BOOLEAN) {
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
                ver_bytes.last().copied().unwrap_or(0).saturating_add(1)
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

        // issuer Name — capture raw DER for OCSP CertID hashing
        let issuer_remaining = tbs_dec.remaining();
        let issuer = parse_name(&mut tbs_dec)?;
        let issuer_consumed = issuer_remaining.len() - tbs_dec.remaining().len();
        let issuer_raw = issuer_remaining[..issuer_consumed].to_vec();

        // validity Validity
        let (not_before, not_after) = parse_validity(&mut tbs_dec)?;

        // subject Name — capture raw DER for OCSP CertID hashing
        let subject_remaining = tbs_dec.remaining();
        let subject = parse_name(&mut tbs_dec)?;
        let subject_consumed = subject_remaining.len() - tbs_dec.remaining().len();
        let subject_raw = subject_remaining[..subject_consumed].to_vec();

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
            issuer_raw,
            subject,
            subject_raw,
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
        } else if cfg!(feature = "mldsa")
            && (sig_oid == known::ml_dsa_44()
                || sig_oid == known::ml_dsa_65()
                || sig_oid == known::ml_dsa_87())
        {
            #[cfg(feature = "mldsa")]
            {
                verify_mldsa_cert(
                    &sig_oid,
                    &self.tbs_raw,
                    &self.signature_value,
                    &issuer.public_key.public_key,
                )
            }
            #[cfg(not(feature = "mldsa"))]
            {
                Err(PkiError::InvalidCert(format!(
                    "unsupported signature algorithm: {}",
                    sig_oid
                )))
            }
        } else if cfg!(feature = "slhdsa") && slhdsa_param_for_oid(&sig_oid).is_some() {
            #[cfg(feature = "slhdsa")]
            {
                verify_slhdsa_cert(
                    &sig_oid,
                    &self.tbs_raw,
                    &self.signature_value,
                    &issuer.public_key.public_key,
                )
            }
            #[cfg(not(feature = "slhdsa"))]
            {
                Err(PkiError::InvalidCert(format!(
                    "unsupported signature algorithm: {}",
                    sig_oid
                )))
            }
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

/// Verify an X.509 certificate signature made with pure ML-DSA (FIPS 204).
///
/// The signature covers the TBSCertificate. ML-DSA hashes internally, so we
/// verify over the raw TBS — wrapped in the FIPS 204 §5.2 *pure*-mode prefix
/// `0x00 || len(ctx)=0x00 || M` (empty context), since `mldsa_verify` is the
/// internal variant (μ = H(tr || M)). `issuer_pubkey` is the issuer SPKI's raw
/// ML-DSA public key. Mirrors the I118 CMS ML-DSA verify convention.
#[cfg(feature = "mldsa")]
fn verify_mldsa_cert(
    sig_oid: &Oid,
    tbs: &[u8],
    signature: &[u8],
    issuer_pubkey: &[u8],
) -> Result<bool, PkiError> {
    let param_set = if *sig_oid == known::ml_dsa_44() {
        44u32
    } else if *sig_oid == known::ml_dsa_65() {
        65
    } else {
        87
    };
    let params = hitls_crypto::mldsa::get_params(param_set)
        .map_err(|e| PkiError::InvalidCert(format!("ML-DSA params: {e}")))?;
    let mut msg = Vec::with_capacity(2 + tbs.len());
    msg.push(0x00);
    msg.push(0x00);
    msg.extend_from_slice(tbs);
    hitls_crypto::mldsa::mldsa_verify(issuer_pubkey, &msg, signature, &params)
        .map_err(|e| PkiError::InvalidCert(format!("ML-DSA verify: {e}")))
}

/// Map an X.509 signature-algorithm OID to its SLH-DSA parameter set (NIST FIPS
/// 205 / CSOR `id-slh-dsa-*` = 2.16.840.1.101.3.4.3.{20..31}), or `None` if the
/// OID is not an SLH-DSA algorithm. Defined unconditionally so the dispatch's
/// `cfg!(feature = "slhdsa")` guard can reference it without the crypto feature.
fn slhdsa_param_for_oid(sig_oid: &Oid) -> Option<hitls_types::SlhDsaParamId> {
    use hitls_types::SlhDsaParamId as P;
    let m = [
        (known::slh_dsa_sha2_128s(), P::Sha2128s),
        (known::slh_dsa_sha2_128f(), P::Sha2128f),
        (known::slh_dsa_sha2_192s(), P::Sha2192s),
        (known::slh_dsa_sha2_192f(), P::Sha2192f),
        (known::slh_dsa_sha2_256s(), P::Sha2256s),
        (known::slh_dsa_sha2_256f(), P::Sha2256f),
        (known::slh_dsa_shake_128s(), P::Shake128s),
        (known::slh_dsa_shake_128f(), P::Shake128f),
        (known::slh_dsa_shake_192s(), P::Shake192s),
        (known::slh_dsa_shake_192f(), P::Shake192f),
        (known::slh_dsa_shake_256s(), P::Shake256s),
        (known::slh_dsa_shake_256f(), P::Shake256f),
    ];
    m.into_iter()
        .find(|(oid, _)| oid == sig_oid)
        .map(|(_, p)| p)
}

/// Verify an X.509 certificate signature made with pure SLH-DSA (FIPS 205).
///
/// SLH-DSA hashes the message internally, so we verify over the raw TBS wrapped
/// in the FIPS 205 §10.2 *pure*-mode prefix `0x00 || len(ctx)=0x00 || M` (empty
/// context — X.509 carries no SLH-DSA context). `issuer_pubkey` is the issuer
/// SPKI's raw SLH-DSA public key (`PK.seed || PK.root`). Mirrors the
/// [`verify_mldsa_cert`] convention.
#[cfg(feature = "slhdsa")]
fn verify_slhdsa_cert(
    sig_oid: &Oid,
    tbs: &[u8],
    signature: &[u8],
    issuer_pubkey: &[u8],
) -> Result<bool, PkiError> {
    let param = slhdsa_param_for_oid(sig_oid)
        .ok_or_else(|| PkiError::InvalidCert(format!("not an SLH-DSA OID: {sig_oid}")))?;
    let kp = hitls_crypto::slh_dsa::SlhDsaKeyPair::from_public_key(param, issuer_pubkey)
        .map_err(|e| PkiError::InvalidCert(format!("SLH-DSA pubkey: {e}")))?;
    let mut msg = Vec::with_capacity(2 + tbs.len());
    msg.push(0x00);
    msg.push(0x00);
    msg.extend_from_slice(tbs);
    kp.verify(&msg, signature)
        .map_err(|e| PkiError::InvalidCert(format!("SLH-DSA verify: {e}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_utils::asn1::Encoder;

    /// ML-DSA X.509 certificate-chain signature verification (FIPS 204).
    /// Loads the openHiTLS C `mldsa-v3` chain (root self-signed → inter → end,
    /// all ML-DSA-65) and verifies each issuer binding, plus a negative
    /// (end signed by inter, not root). Exercises the `verify_mldsa_cert` path.
    #[cfg(feature = "mldsa")]
    #[test]
    fn test_mldsa_cert_chain_verify() {
        fn load(rel: &str) -> Certificate {
            let path = format!(
                "{}/../../tests/vectors/c-asn1-fixtures/cert/chain/{}",
                env!("CARGO_MANIFEST_DIR"),
                rel
            );
            let bytes = std::fs::read(&path).unwrap();
            match std::str::from_utf8(&bytes) {
                Ok(s) if s.contains("-----BEGIN") => Certificate::from_pem(s).unwrap(),
                _ => Certificate::from_der(&bytes).unwrap(),
            }
        }
        let root = load("mldsa-v3/root.crt");
        let inter = load("mldsa-v3/inter.crt");
        let end = load("mldsa-v3/end.crt");
        assert!(root.verify_signature(&root).unwrap(), "root self-signed");
        assert!(inter.verify_signature(&root).unwrap(), "inter by root");
        assert!(end.verify_signature(&inter).unwrap(), "end by inter");
        // Wrong issuer → signature does not verify.
        assert!(!end.verify_signature(&root).unwrap(), "end not by root");
    }

    #[test]
    fn test_distinguished_name_display() {
        let dn = DistinguishedName {
            entries: vec![
                ("CN".to_string(), "Test".to_string()),
                ("O".to_string(), "Org".to_string()),
            ],
        };
        assert_eq!(format!("{dn}"), "CN=Test, O=Org");
    }

    #[test]
    fn test_distinguished_name_get() {
        let dn = DistinguishedName {
            entries: vec![
                ("CN".to_string(), "Test".to_string()),
                ("O".to_string(), "Org".to_string()),
            ],
        };
        assert_eq!(dn.get("CN"), Some("Test"));
        assert_eq!(dn.get("O"), Some("Org"));
        assert_eq!(dn.get("XX"), None);
    }

    #[test]
    fn test_parse_algorithm_identifier_rsa_null() {
        // Build SEQUENCE { OID(sha256WithRSAEncryption), NULL }
        let oid_bytes = known::sha256_with_rsa_encryption().to_der_value();
        let mut inner = Encoder::new();
        inner.write_oid(&oid_bytes);
        inner.write_null();
        let inner_der = inner.finish();
        let mut enc = Encoder::new();
        enc.write_sequence(&inner_der);
        let der = enc.finish();

        let mut dec = Decoder::new(&der);
        let (oid, params) = parse_algorithm_identifier(&mut dec).unwrap();
        assert_eq!(oid, oid_bytes);
        // NULL parameter is normalized to None
        assert!(params.is_none(), "NULL params should be normalized to None");
    }

    #[test]
    fn test_parse_algorithm_identifier_ec_params() {
        // Build SEQUENCE { OID(ecPublicKey), OID(prime256v1) }
        let alg_oid = known::ec_public_key().to_der_value();
        let curve_oid = known::prime256v1().to_der_value();
        let mut inner = Encoder::new();
        inner.write_oid(&alg_oid);
        inner.write_oid(&curve_oid);
        let inner_der = inner.finish();
        let mut enc = Encoder::new();
        enc.write_sequence(&inner_der);
        let der = enc.finish();

        let mut dec = Decoder::new(&der);
        let (oid, params) = parse_algorithm_identifier(&mut dec).unwrap();
        assert_eq!(oid, alg_oid);
        // The OID parameter should be present (not NULL)
        let params = params.expect("EC params should be Some");
        // The value should be the OID value bytes (prime256v1)
        assert_eq!(params, curve_oid);
    }

    #[test]
    fn test_certificate_roundtrip_self_signed() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = super::super::signing::SigningKey::Ed25519(kp);
        let subject = DistinguishedName {
            entries: vec![
                ("CN".to_string(), "Test CA".to_string()),
                ("O".to_string(), "OpenHiTLS".to_string()),
            ],
        };
        let cert = super::super::builder::CertificateBuilder::self_signed(
            subject.clone(),
            &sk,
            1_700_000_000,
            1_800_000_000,
        )
        .unwrap();

        // Re-parse from DER
        let parsed = Certificate::from_der(&cert.raw).unwrap();
        assert_eq!(parsed.version, 3);
        assert_eq!(parsed.subject.get("CN"), Some("Test CA"));
        assert_eq!(parsed.subject.get("O"), Some("OpenHiTLS"));
        assert!(parsed.is_self_signed());
        assert_eq!(parsed.issuer, parsed.subject);
    }

    #[test]
    fn test_certificate_pem_roundtrip() {
        use super::super::builder::CertificateBuilder;
        use super::super::signing::SigningKey;
        use hitls_utils::base64;

        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".into(), "PEM Test".into())],
        };
        let cert = CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000).unwrap();

        // DER → PEM → from_pem roundtrip
        let der = cert.to_der();
        let b64 = base64::encode(&der);
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            b64
        );
        let parsed = Certificate::from_pem(&pem).unwrap();
        assert_eq!(parsed.subject.get("CN"), Some("PEM Test"));
        assert_eq!(parsed.raw, cert.raw);
    }

    #[test]
    fn test_certificate_from_pem_missing_block() {
        // PEM parses fine, but only the PRIVATE KEY block is present;
        // `from_pem` searches for a CERTIFICATE label and returns
        // `InvalidCert` when none is found.
        let bad_pem = "-----BEGIN PRIVATE KEY-----\nMC4=\n-----END PRIVATE KEY-----\n";
        assert!(matches!(
            Certificate::from_pem(bad_pem).unwrap_err(),
            PkiError::InvalidCert(_)
        ));
    }

    #[test]
    fn test_certificate_from_der_truncated() {
        // Truncated DER should fail at ASN.1 decode (`PkiError::Asn1Error`).
        // The empty input has no outer SEQUENCE tag at all; the second
        // input has a SEQUENCE tag claiming 3 bytes of body but only 1
        // byte is provided.
        assert!(matches!(
            Certificate::from_der(&[]).unwrap_err(),
            PkiError::Asn1Error(_)
        ));
        assert!(matches!(
            Certificate::from_der(&[0x30, 0x03, 0x01]).unwrap_err(),
            PkiError::Asn1Error(_)
        ));
    }

    // ================================================================
    // Phase T85 — D28 coverage: certificate parser edge cases.
    // The original D28 audit flagged certificate.rs as 1.4 tests/100L
    // with several unparser-edge classes uncovered. These tests pin
    // negative-path contracts on inputs an attacker could construct.
    // ================================================================

    /// Wrong outermost tag (not SEQUENCE) must reject. ITU-T X.690 §8.1
    /// requires Certificate to be encoded as SEQUENCE; a SET (0x31) or any
    /// other tag at the outer position is malformed and must not parse.
    /// All three inputs trip the `PkiError::Asn1Error` arm in `from_der`'s
    /// outer-SEQUENCE map_err.
    #[test]
    fn test_certificate_from_der_wrong_outer_tag() {
        // type=SET (0x31), length=0
        assert!(matches!(
            Certificate::from_der(&[0x31, 0x00]).unwrap_err(),
            PkiError::Asn1Error(_)
        ));
        // type=OCTET STRING (0x04), length=2, value=ab
        assert!(matches!(
            Certificate::from_der(&[0x04, 0x02, 0xAB, 0xCD]).unwrap_err(),
            PkiError::Asn1Error(_)
        ));
        // type=INTEGER (0x02)
        assert!(matches!(
            Certificate::from_der(&[0x02, 0x01, 0x05]).unwrap_err(),
            PkiError::Asn1Error(_)
        ));
    }

    /// Empty SEQUENCE must reject — a Certificate has at minimum a TBSCertificate
    /// (itself a non-empty SEQUENCE), an AlgorithmIdentifier, and a signatureValue
    /// BIT STRING. An empty outer SEQUENCE has none of these.
    #[test]
    fn test_certificate_from_der_empty_outer_sequence_rejected() {
        // SEQUENCE of length 0 (well-formed ASN.1 but missing required body).
        // Fails at the first inner-decode step (TBSCertificate read) →
        // `PkiError::Asn1Error`.
        assert!(matches!(
            Certificate::from_der(&[0x30, 0x00]).unwrap_err(),
            PkiError::Asn1Error(_)
        ));
    }

    /// Length-prefix that overruns the buffer must reject without panicking.
    /// Defends against indefinite-length / oversized-length attacks where the
    /// outer length-prefix lies about the body size.
    #[test]
    fn test_certificate_from_der_length_overrun_rejected() {
        // SEQUENCE claiming 100 bytes but only providing 3 → ASN.1 decoder
        // refuses the truncated body → `PkiError::Asn1Error`.
        let buf = [0x30, 0x64, 0x01, 0x02, 0x03];
        assert!(matches!(
            Certificate::from_der(&buf).unwrap_err(),
            PkiError::Asn1Error(_)
        ));
    }

    /// PEM with the right BEGIN/END marker but base64 garbage inside must
    /// reject at parse time, not silently succeed with empty fields. The PEM
    /// parser surfaces the base64 decode failure as `PkiError::Asn1Error`
    /// (the `map_err` arm at `from_pem`'s top wraps every PEM-layer
    /// failure into the ASN.1 variant for uniformity).
    #[test]
    fn test_certificate_from_pem_garbage_body_rejected() {
        let bad = "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n";
        assert!(matches!(
            Certificate::from_pem(bad).unwrap_err(),
            PkiError::Asn1Error(_)
        ));
    }

    /// PEM input with no PEM blocks at all (just plain text) must reject —
    /// not be interpreted as a 0-byte DER encoding. The parse succeeds
    /// returning zero blocks; the no-CERTIFICATE-block branch in
    /// `from_pem` then surfaces `PkiError::InvalidCert`.
    #[test]
    fn test_certificate_from_pem_no_blocks_rejected() {
        assert!(matches!(
            Certificate::from_pem("").unwrap_err(),
            PkiError::InvalidCert(_)
        ));
        assert!(matches!(
            Certificate::from_pem("not a pem file at all").unwrap_err(),
            PkiError::InvalidCert(_)
        ));
    }

    /// Parser must accept a well-formed certificate at every roundtrip
    /// boundary: parse → re-emit raw DER → re-parse → equal serial / DN /
    /// validity. This pins the round-trip closure used by signature verify
    /// (`tbs_raw` and `signature_value` must round-trip exactly).
    #[test]
    fn test_certificate_round_trip_byte_equality() {
        use super::super::builder::CertificateBuilder;
        use super::super::signing::SigningKey;

        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".into(), "Roundtrip Test".into())],
        };
        let cert = CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000).unwrap();
        let der = cert.to_der();

        let cert2 = Certificate::from_der(&der).unwrap();
        // Parsed twice from the same bytes must produce structurally
        // identical view. We compare the public-API observable fields.
        assert_eq!(cert.serial_number, cert2.serial_number);
        assert_eq!(cert.issuer, cert2.issuer);
        assert_eq!(cert.subject, cert2.subject);
        assert_eq!(cert.not_before, cert2.not_before);
        assert_eq!(cert.not_after, cert2.not_after);
        assert_eq!(cert.signature_algorithm, cert2.signature_algorithm);
        assert_eq!(cert.signature_value, cert2.signature_value);
        // tbs_raw exact byte equality is critical: signature verification
        // re-hashes this slice. Drift here silently breaks chain validation.
        assert_eq!(cert.tbs_raw, cert2.tbs_raw);
    }

    #[test]
    fn test_certificate_verify_signature_self_signed_ed25519() {
        use super::super::builder::CertificateBuilder;
        use super::super::signing::SigningKey;

        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".into(), "Sig Test".into())],
        };
        let cert = CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000).unwrap();

        // Self-signed cert should verify against itself
        assert!(cert.verify_signature(&cert).unwrap());
    }

    #[test]
    fn test_certificate_verify_signature_rsa() {
        use super::super::builder::CertificateBuilder;
        use super::super::signing::SigningKey;

        let rsa_key = hitls_crypto::rsa::RsaPrivateKey::generate(2048).unwrap();
        let sk = SigningKey::Rsa(rsa_key);
        let dn = DistinguishedName {
            entries: vec![("CN".into(), "RSA CA".into())],
        };
        let cert = CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000).unwrap();
        assert!(cert.verify_signature(&cert).unwrap());
    }

    #[test]
    fn test_certificate_verify_signature_wrong_issuer() {
        use super::super::builder::CertificateBuilder;
        use super::super::signing::SigningKey;

        let kp1 = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk1 = SigningKey::Ed25519(kp1);
        let cert1 = CertificateBuilder::self_signed(
            DistinguishedName {
                entries: vec![("CN".into(), "CA 1".into())],
            },
            &sk1,
            1_700_000_000,
            1_800_000_000,
        )
        .unwrap();

        let kp2 = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk2 = SigningKey::Ed25519(kp2);
        let cert2 = CertificateBuilder::self_signed(
            DistinguishedName {
                entries: vec![("CN".into(), "CA 2".into())],
            },
            &sk2,
            1_700_000_000,
            1_800_000_000,
        )
        .unwrap();

        // cert1 verified against cert2's key should fail
        let result = cert1.verify_signature(&cert2);
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_certificate_is_ca() {
        use super::super::builder::CertificateBuilder;
        use super::super::signing::SigningKey;

        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".into(), "CA Test".into())],
        };
        // self_signed sets basicConstraints CA:true
        let ca_cert =
            CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000).unwrap();
        assert!(ca_cert.is_ca());
    }

    #[test]
    fn test_distinguished_name_equality() {
        let dn1 = DistinguishedName {
            entries: vec![("CN".into(), "Test".into()), ("O".into(), "Org".into())],
        };
        let dn2 = DistinguishedName {
            entries: vec![("CN".into(), "Test".into()), ("O".into(), "Org".into())],
        };
        let dn3 = DistinguishedName {
            entries: vec![("CN".into(), "Other".into())],
        };
        assert_eq!(dn1, dn2);
        assert_ne!(dn1, dn3);
    }
}
