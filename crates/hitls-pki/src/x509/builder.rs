//! DER encoding helpers, `CertificateRequestBuilder`, and `CertificateBuilder`.

use hitls_types::PkiError;
use hitls_utils::asn1::Encoder;
use hitls_utils::oid::{known, Oid};

use super::certificate::{
    Certificate, CertificateRequest, DistinguishedName, SubjectPublicKeyInfo, X509Extension,
};
use super::extensions::{GeneralName, KeyUsage};
use super::signing::{SigningKey, ALG_PARAMS_NULL};

// ---------------------------------------------------------------------------
// DER encoding helpers
// ---------------------------------------------------------------------------

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
// CertificateRequestBuilder
// ---------------------------------------------------------------------------

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
