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
    // For DSA, it's the full DER-encoded DSAParameters SEQUENCE.
    let alg_oid = Oid::from_der_value(&spki.algorithm_oid).ok();
    let is_dsa = alg_oid.as_ref() == Some(&known::dsa());
    let params_tlv = if let Some(ref p) = spki.algorithm_params {
        if is_dsa {
            // DSA params are already a complete DER SEQUENCE TLV
            Some(p.clone())
        } else {
            // EC keys: reconstruct full OID TLV from raw value bytes
            let mut enc = Encoder::new();
            enc.write_oid(p);
            Some(enc.finish())
        }
    } else {
        // RSA and Ed25519: RSA needs NULL, Ed25519 needs absent
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

/// Encode a single GeneralName as a context-specific tagged value.
fn encode_general_name(enc: &mut Encoder, name: &GeneralName) {
    match name {
        GeneralName::DnsName(s) => {
            enc.write_context_specific(2, false, s.as_bytes());
        }
        GeneralName::Rfc822Name(s) => {
            enc.write_context_specific(1, false, s.as_bytes());
        }
        GeneralName::Uri(s) => {
            enc.write_context_specific(6, false, s.as_bytes());
        }
        GeneralName::IpAddress(ip) => {
            enc.write_context_specific(7, false, ip);
        }
        GeneralName::DirectoryName(dn) => {
            let dn_der = encode_distinguished_name(dn);
            enc.write_context_specific(4, true, &dn_der);
        }
    }
}

/// Encode GeneralSubtrees for NameConstraints.
fn encode_general_subtrees(names: &[GeneralName]) -> Vec<u8> {
    let mut out = Vec::new();
    for name in names {
        let mut sub_inner = Encoder::new();
        encode_general_name(&mut sub_inner, name);
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

    /// Add a CRL Distribution Points extension (OID 2.5.29.31, non-critical).
    ///
    /// Each URI becomes a DistributionPoint with a single fullName URI.
    pub fn add_crl_distribution_points(self, uris: &[&str]) -> Self {
        // SEQUENCE OF DistributionPoint
        let mut dps = Encoder::new();
        for uri in uris {
            // DistributionPoint ::= SEQUENCE {
            //   distributionPoint [0] {
            //     fullName [0] { uniformResourceIdentifier [6] }
            //   }
            // }
            let mut gn = Encoder::new();
            gn.write_context_specific(6, false, uri.as_bytes());
            let mut full_name = Encoder::new();
            full_name.write_context_specific(0, true, &gn.finish());
            let mut dp_name = Encoder::new();
            dp_name.write_context_specific(0, true, &full_name.finish());
            let mut dp_seq = Encoder::new();
            dp_seq.write_sequence(&dp_name.finish());
            dps.write_raw(&dp_seq.finish());
        }
        let mut outer_seq = Encoder::new();
        outer_seq.write_sequence(&dps.finish());
        let value = outer_seq.finish();
        self.add_extension(
            known::crl_distribution_points().to_der_value(),
            false,
            value,
        )
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
// CRL Builder
// ---------------------------------------------------------------------------

use super::crl::{CertificateRevocationList, RevocationReason};

/// Builder for a single revoked-certificate entry within a CRL.
pub struct RevokedCertBuilder {
    serial_number: Vec<u8>,
    revocation_date: i64,
    extensions: Vec<X509Extension>,
}

impl RevokedCertBuilder {
    /// Create a new revoked-certificate entry.
    ///
    /// `serial_number` is the DER-encoded serial (big-endian, no leading zeros
    /// except the sign byte if needed). `revocation_date` is a UNIX timestamp.
    pub fn new(serial_number: &[u8], revocation_date: i64) -> Self {
        Self {
            serial_number: serial_number.to_vec(),
            revocation_date,
            extensions: Vec::new(),
        }
    }

    /// Set the CRLReason extension (OID 2.5.29.21).
    pub fn reason(self, reason: RevocationReason) -> Self {
        let mut enc = Encoder::new();
        enc.write_enumerated(reason as u8);
        let value = enc.finish();
        self.add_extension(known::crl_reason().to_der_value(), false, value)
    }

    /// Set the InvalidityDate extension (OID 2.5.29.24).
    pub fn invalidity_date(self, date: i64) -> Self {
        let mut enc = Encoder::new();
        enc.write_generalized_time(date);
        let value = enc.finish();
        self.add_extension(known::invalidity_date().to_der_value(), false, value)
    }

    /// Add a raw extension to this revoked-certificate entry.
    pub fn add_extension(mut self, oid: Vec<u8>, critical: bool, value: Vec<u8>) -> Self {
        self.extensions.push(X509Extension {
            oid,
            critical,
            value,
        });
        self
    }

    /// Encode the entry to DER (SEQUENCE { serial INTEGER, time Time, exts? }).
    fn encode(&self) -> Vec<u8> {
        let mut inner = Encoder::new();
        inner.write_integer(&self.serial_number);
        inner.write_time(self.revocation_date);
        if !self.extensions.is_empty() {
            let ext_der = encode_extensions(&self.extensions);
            inner.write_raw(&ext_der);
        }
        let mut seq = Encoder::new();
        seq.write_sequence(&inner.finish());
        seq.finish()
    }

    /// Whether this entry carries any extensions.
    fn has_extensions(&self) -> bool {
        !self.extensions.is_empty()
    }
}

/// Builder for X.509 Certificate Revocation Lists (RFC 5280 §5).
pub struct CrlBuilder {
    issuer: DistinguishedName,
    this_update: i64,
    next_update: Option<i64>,
    revoked_certs: Vec<RevokedCertBuilder>,
    extensions: Vec<X509Extension>,
}

impl CrlBuilder {
    /// Create a new CRL builder.
    pub fn new(issuer: DistinguishedName, this_update: i64) -> Self {
        Self {
            issuer,
            this_update,
            next_update: None,
            revoked_certs: Vec::new(),
            extensions: Vec::new(),
        }
    }

    /// Set the nextUpdate time.
    pub fn next_update(mut self, time: i64) -> Self {
        self.next_update = Some(time);
        self
    }

    /// Add a revoked certificate entry.
    pub fn add_revoked(mut self, entry: RevokedCertBuilder) -> Self {
        self.revoked_certs.push(entry);
        self
    }

    /// Add a CRL Number extension (OID 2.5.29.20, non-critical).
    pub fn add_crl_number(self, number: &[u8]) -> Self {
        let mut enc = Encoder::new();
        enc.write_integer(number);
        let value = enc.finish();
        self.add_extension(known::crl_number().to_der_value(), false, value)
    }

    /// Add an Authority Key Identifier extension (OID 2.5.29.35, non-critical).
    pub fn add_authority_key_identifier(self, key_id: &[u8]) -> Self {
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

    /// Add an Issuing Distribution Point extension (OID 2.5.29.28, critical).
    ///
    /// `full_names` specifies the distribution point URIs/names.
    pub fn add_issuing_distribution_point(self, full_names: &[GeneralName]) -> Self {
        let mut inner = Encoder::new();
        if !full_names.is_empty() {
            // distributionPoint [0] { fullName [0] SEQUENCE OF GeneralName }
            let mut gns = Encoder::new();
            for gn in full_names {
                encode_general_name(&mut gns, gn);
            }
            let mut full_name_ctx = Encoder::new();
            full_name_ctx.write_context_specific(0, true, &gns.finish());
            inner.write_context_specific(0, true, &full_name_ctx.finish());
        }
        let mut seq = Encoder::new();
        seq.write_sequence(&inner.finish());
        let value = seq.finish();
        self.add_extension(
            known::issuing_distribution_point().to_der_value(),
            true,
            value,
        )
    }

    /// Add a Delta CRL Indicator extension (OID 2.5.29.27, critical).
    ///
    /// `base_crl_number` is the CRL number of the base CRL (big-endian integer bytes).
    pub fn add_delta_crl_indicator(self, base_crl_number: &[u8]) -> Self {
        let mut enc = Encoder::new();
        enc.write_integer(base_crl_number);
        let value = enc.finish();
        self.add_extension(known::delta_crl_indicator().to_der_value(), true, value)
    }

    /// Add a raw extension to the CRL.
    pub fn add_extension(mut self, oid: Vec<u8>, critical: bool, value: Vec<u8>) -> Self {
        self.extensions.push(X509Extension {
            oid,
            critical,
            value,
        });
        self
    }

    /// Build the CRL, signing with the given key.
    pub fn build(self, signing_key: &SigningKey) -> Result<CertificateRevocationList, PkiError> {
        let sig_alg_oid = signing_key.algorithm_oid();
        let sig_alg_params = signing_key.algorithm_params();

        // Determine version: v2 (1) if any CRL-level or entry-level extensions
        let has_entry_exts = self.revoked_certs.iter().any(|e| e.has_extensions());
        let is_v2 = !self.extensions.is_empty() || has_entry_exts;

        // ---- TBSCertList (RFC 5280 §5.1) ----
        let mut tbs = Encoder::new();

        // version INTEGER OPTIONAL (v2 = 1)
        if is_v2 {
            tbs.write_integer(&[0x01]);
        }

        // signature AlgorithmIdentifier
        let alg_id = encode_algorithm_identifier(&sig_alg_oid, sig_alg_params.as_deref());
        tbs.write_raw(&alg_id);

        // issuer Name
        tbs.write_raw(&encode_distinguished_name(&self.issuer));

        // thisUpdate Time
        tbs.write_time(self.this_update);

        // nextUpdate Time OPTIONAL
        if let Some(nu) = self.next_update {
            tbs.write_time(nu);
        }

        // revokedCertificates SEQUENCE OF OPTIONAL
        if !self.revoked_certs.is_empty() {
            let mut entries = Encoder::new();
            for entry in &self.revoked_certs {
                entries.write_raw(&entry.encode());
            }
            let mut seq = Encoder::new();
            seq.write_sequence(&entries.finish());
            tbs.write_raw(&seq.finish());
        }

        // crlExtensions [0] EXPLICIT Extensions OPTIONAL
        if !self.extensions.is_empty() {
            let ext_der = encode_extensions(&self.extensions);
            tbs.write_context_specific(0, true, &ext_der);
        }

        let mut tbs_seq = Encoder::new();
        tbs_seq.write_sequence(&tbs.finish());
        let tbs_raw = tbs_seq.finish();

        // Sign the TBS
        let signature = signing_key.sign(&tbs_raw)?;

        // Build outer CertificateList SEQUENCE
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

        // Parse back to fill all fields consistently
        CertificateRevocationList::from_der(&raw)
    }

    /// Build the CRL and encode as PEM string.
    pub fn build_pem(self, signing_key: &SigningKey) -> Result<String, PkiError> {
        let crl = self.build(signing_key)?;
        Ok(crl.to_pem())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_utils::asn1::Decoder;

    // -----------------------------------------------------------------------
    // Helper: create a self-signed CA + signing key for CRL tests (RSA)
    // -----------------------------------------------------------------------
    fn make_rsa_ca() -> (Certificate, SigningKey) {
        let rsa_key = hitls_crypto::rsa::RsaPrivateKey::generate(2048).unwrap();
        let sk = SigningKey::Rsa(rsa_key);
        let dn = DistinguishedName {
            entries: vec![
                ("C".into(), "CN".into()),
                ("O".into(), "Test CA".into()),
                ("CN".into(), "CRL Test CA".into()),
            ],
        };
        let cert = CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000).unwrap();
        (cert, sk)
    }

    // -----------------------------------------------------------------------
    // CRL Builder tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_crl_builder_v1_empty() {
        let (cert, sk) = make_rsa_ca();
        let crl = CrlBuilder::new(cert.issuer.clone(), 1_700_000_000)
            .next_update(1_710_000_000)
            .build(&sk)
            .unwrap();
        assert_eq!(crl.version, 1);
        assert!(crl.revoked_certs.is_empty());
        assert!(crl.extensions.is_empty());
        assert!(crl.next_update.is_some());
    }

    #[test]
    fn test_crl_builder_v2_with_extensions() {
        let (cert, sk) = make_rsa_ca();
        let crl = CrlBuilder::new(cert.issuer.clone(), 1_700_000_000)
            .next_update(1_710_000_000)
            .add_crl_number(&[0x01])
            .add_authority_key_identifier(&[0xAA; 20])
            .build(&sk)
            .unwrap();
        assert_eq!(crl.version, 2);
        assert!(!crl.extensions.is_empty());
        let crl_num = crl.crl_number().unwrap();
        assert_eq!(crl_num, vec![0x01]);
    }

    #[test]
    fn test_crl_builder_with_revoked_certs() {
        let (cert, sk) = make_rsa_ca();
        let entry1 = RevokedCertBuilder::new(&[0x01], 1_700_100_000);
        let entry2 = RevokedCertBuilder::new(&[0x02], 1_700_200_000);
        let crl = CrlBuilder::new(cert.issuer.clone(), 1_700_000_000)
            .add_revoked(entry1)
            .add_revoked(entry2)
            .build(&sk)
            .unwrap();
        assert_eq!(crl.revoked_certs.len(), 2);
        assert_eq!(crl.revoked_certs[0].serial_number, vec![0x01]);
        assert_eq!(crl.revoked_certs[1].serial_number, vec![0x02]);
    }

    #[test]
    fn test_crl_builder_roundtrip_verify() {
        let (cert, sk) = make_rsa_ca();
        let entry =
            RevokedCertBuilder::new(&[0x42], 1_700_100_000).reason(RevocationReason::KeyCompromise);
        let crl = CrlBuilder::new(cert.issuer.clone(), 1_700_000_000)
            .next_update(1_710_000_000)
            .add_crl_number(&[0x01])
            .add_revoked(entry)
            .build(&sk)
            .unwrap();

        // Parse again from DER
        let crl2 = CertificateRevocationList::from_der(&crl.to_der()).unwrap();
        assert_eq!(crl2.version, crl.version);
        assert_eq!(crl2.revoked_certs.len(), 1);

        // Verify signature
        assert!(crl2.verify_signature(&cert).unwrap());
    }

    #[test]
    fn test_crl_builder_roundtrip_pem() {
        let (cert, sk) = make_rsa_ca();
        let pem = CrlBuilder::new(cert.issuer.clone(), 1_700_000_000)
            .next_update(1_710_000_000)
            .build_pem(&sk)
            .unwrap();
        assert!(pem.contains("-----BEGIN X509 CRL-----"));
        assert!(pem.contains("-----END X509 CRL-----"));

        let crl = CertificateRevocationList::from_pem(&pem).unwrap();
        assert!(crl.verify_signature(&cert).unwrap());
    }

    #[test]
    fn test_crl_builder_reason_roundtrip() {
        let (cert, sk) = make_rsa_ca();
        let entry =
            RevokedCertBuilder::new(&[0x10], 1_700_100_000).reason(RevocationReason::CaCompromise);
        let crl = CrlBuilder::new(cert.issuer.clone(), 1_700_000_000)
            .add_revoked(entry)
            .build(&sk)
            .unwrap();
        assert_eq!(crl.revoked_certs.len(), 1);
        assert_eq!(
            crl.revoked_certs[0].reason,
            Some(RevocationReason::CaCompromise)
        );
    }

    #[test]
    fn test_crl_builder_invalidity_date_roundtrip() {
        let (cert, sk) = make_rsa_ca();
        let inv_date = 1_699_000_000i64;
        let entry = RevokedCertBuilder::new(&[0x20], 1_700_100_000).invalidity_date(inv_date);
        let crl = CrlBuilder::new(cert.issuer.clone(), 1_700_000_000)
            .add_revoked(entry)
            .build(&sk)
            .unwrap();
        assert_eq!(crl.revoked_certs.len(), 1);
        assert_eq!(crl.revoked_certs[0].invalidity_date, Some(inv_date));
    }

    #[test]
    fn test_crl_builder_auto_upgrade_v2() {
        let (cert, sk) = make_rsa_ca();
        // Entry with extensions but no CRL-level extensions → should auto v2
        let entry =
            RevokedCertBuilder::new(&[0x30], 1_700_100_000).reason(RevocationReason::Superseded);
        let crl = CrlBuilder::new(cert.issuer.clone(), 1_700_000_000)
            .add_revoked(entry)
            .build(&sk)
            .unwrap();
        assert_eq!(crl.version, 2);
    }

    #[test]
    fn test_crl_builder_to_der_to_pem() {
        let (cert, sk) = make_rsa_ca();
        let crl = CrlBuilder::new(cert.issuer.clone(), 1_700_000_000)
            .build(&sk)
            .unwrap();

        let der = crl.to_der();
        assert!(!der.is_empty());
        assert_eq!(der[0], 0x30); // SEQUENCE tag

        let pem = crl.to_pem();
        assert!(pem.contains("-----BEGIN X509 CRL-----"));
        let crl2 = CertificateRevocationList::from_pem(&pem).unwrap();
        assert_eq!(crl2.raw, der);
    }

    #[test]
    fn test_crl_builder_ecdsa_signing() {
        use hitls_types::EccCurveId;
        let kp = hitls_crypto::ecdsa::EcdsaKeyPair::generate(EccCurveId::NistP256).unwrap();
        let sk = SigningKey::Ecdsa {
            curve_id: EccCurveId::NistP256,
            key_pair: kp,
        };
        let dn = DistinguishedName {
            entries: vec![("CN".into(), "ECDSA CRL CA".into())],
        };
        let cert = CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000).unwrap();

        let entry =
            RevokedCertBuilder::new(&[0x05], 1_700_100_000).reason(RevocationReason::KeyCompromise);
        let crl = CrlBuilder::new(cert.issuer.clone(), 1_700_000_000)
            .next_update(1_710_000_000)
            .add_crl_number(&[0x01])
            .add_revoked(entry)
            .build(&sk)
            .unwrap();

        assert_eq!(crl.version, 2);
        assert!(crl.verify_signature(&cert).unwrap());
    }

    // -----------------------------------------------------------------------
    // Original DER encoding tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_distinguished_name_cn() {
        let dn = DistinguishedName {
            entries: vec![("CN".to_string(), "Test".to_string())],
        };
        let der = encode_distinguished_name(&dn);
        // Must start with SEQUENCE tag
        assert_eq!(der[0], 0x30);
        // Must contain OID 2.5.4.3 (CN) — DER value bytes: 55 04 03
        assert!(
            der.windows(3).any(|w| w == [0x55, 0x04, 0x03]),
            "DER should contain CN OID (2.5.4.3)"
        );
        // Must contain UTF8String "Test"
        assert!(
            der.windows(4).any(|w| w == b"Test"),
            "DER should contain the value 'Test'"
        );
    }

    #[test]
    fn test_encode_algorithm_identifier_with_null() {
        let oid = known::sha256_with_rsa_encryption().to_der_value();
        let der = encode_algorithm_identifier(&oid, Some(&[0x05, 0x00]));
        // Outer SEQUENCE tag
        assert_eq!(der[0], 0x30);
        // Must contain NULL TLV (05 00)
        assert!(
            der.windows(2).any(|w| w == [0x05, 0x00]),
            "DER should contain NULL parameter"
        );
    }

    #[test]
    fn test_encode_algorithm_identifier_no_params() {
        let oid = known::ed25519().to_der_value();
        let der = encode_algorithm_identifier(&oid, None);
        // Outer SEQUENCE tag
        assert_eq!(der[0], 0x30);
        // Must NOT contain NULL TLV (05 00)
        assert!(
            !der.windows(2).any(|w| w == [0x05, 0x00]),
            "DER should not contain NULL when params is None"
        );
    }

    #[test]
    fn test_encode_validity_parseable() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        // 2025-01-01 00:00:00 UTC = 1735689600
        let not_before = 1_704_067_200i64;
        let not_after = 1_735_689_600i64;
        let der = encode_validity(not_before, not_after);
        // Must be a SEQUENCE
        assert_eq!(der[0], 0x30);
        // Parse it back: SEQUENCE { time, time }
        let mut dec = Decoder::new(&der);
        let mut seq = dec.read_sequence().expect("should parse as SEQUENCE");
        let t1 = seq.read_time().expect("should read notBefore");
        let t2 = seq.read_time().expect("should read notAfter");
        assert_eq!(t1, not_before);
        assert_eq!(t2, not_after);
    }

    #[test]
    fn test_encode_extensions_critical_flag() {
        let oid = known::basic_constraints().to_der_value();
        let value = vec![0x30, 0x00]; // empty SEQUENCE

        // Critical extension: should contain BOOLEAN TRUE (01 01 FF)
        let critical_ext = X509Extension {
            oid: oid.clone(),
            critical: true,
            value: value.clone(),
        };
        let der_crit = encode_extensions(&[critical_ext]);
        assert!(
            der_crit.windows(3).any(|w| w == [0x01, 0x01, 0xFF]),
            "Critical extension DER should contain BOOLEAN TRUE"
        );

        // Non-critical extension: should NOT contain BOOLEAN TRUE
        let non_critical_ext = X509Extension {
            oid,
            critical: false,
            value,
        };
        let der_non = encode_extensions(&[non_critical_ext]);
        assert!(
            !der_non.windows(3).any(|w| w == [0x01, 0x01, 0xFF]),
            "Non-critical extension DER should not contain BOOLEAN TRUE"
        );
    }

    // -----------------------------------------------------------------------
    // Phase I86: CRL/CDP builder roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_crl_builder_idp_roundtrip() {
        let (cert, sk) = make_rsa_ca();
        let crl = CrlBuilder::new(cert.issuer.clone(), 1_700_000_000)
            .next_update(1_710_000_000)
            .add_crl_number(&[0x01])
            .add_issuing_distribution_point(&[GeneralName::Uri(
                "http://crl.example.com/ca.crl".into(),
            )])
            .build(&sk)
            .unwrap();

        assert_eq!(crl.version, 2);
        let idp = crl.issuing_distribution_point();
        assert!(idp.is_some());
        let idp = idp.unwrap();
        assert_eq!(idp.full_names.len(), 1);
        match &idp.full_names[0] {
            GeneralName::Uri(u) => assert_eq!(u, "http://crl.example.com/ca.crl"),
            _ => panic!("expected URI"),
        }
        assert!(!idp.only_contains_user_certs);
        assert!(!idp.only_contains_ca_certs);
        assert!(!idp.indirect_crl);
    }

    #[test]
    fn test_crl_builder_delta_crl_roundtrip() {
        let (cert, sk) = make_rsa_ca();
        let crl = CrlBuilder::new(cert.issuer.clone(), 1_700_000_000)
            .next_update(1_710_000_000)
            .add_crl_number(&[0x05])
            .add_delta_crl_indicator(&[0x03])
            .build(&sk)
            .unwrap();

        assert_eq!(crl.version, 2);
        let dci = crl.delta_crl_indicator();
        assert!(dci.is_some());
        assert_eq!(dci.unwrap(), vec![0x03]);

        // Verify CRL number is also present
        let crl_num = crl.crl_number().unwrap();
        assert_eq!(crl_num, vec![0x05]);
    }

    #[test]
    fn test_cert_crl_distribution_points_roundtrip() {
        let (cert, sk) = make_rsa_ca();
        let spki = sk.public_key_info().unwrap();
        let dn = DistinguishedName {
            entries: vec![("CN".into(), "Test EE".into())],
        };
        let ee_cert = CertificateBuilder::new()
            .serial_number(&[0x42])
            .issuer(cert.issuer.clone())
            .subject(dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .add_crl_distribution_points(&[
                "http://crl.example.com/ca.crl",
                "http://crl2.example.com/ca.crl",
            ])
            .build(&sk)
            .unwrap();

        let cdp = ee_cert.crl_distribution_points();
        assert!(cdp.is_some());
        let cdp = cdp.unwrap();
        assert_eq!(cdp.points.len(), 2);
        match &cdp.points[0].full_names[0] {
            GeneralName::Uri(u) => assert_eq!(u, "http://crl.example.com/ca.crl"),
            _ => panic!("expected URI"),
        }
        match &cdp.points[1].full_names[0] {
            GeneralName::Uri(u) => assert_eq!(u, "http://crl2.example.com/ca.crl"),
            _ => panic!("expected URI"),
        }
    }

    #[test]
    fn test_cert_crl_distribution_points_none() {
        let (cert, sk) = make_rsa_ca();
        let spki = sk.public_key_info().unwrap();
        let dn = DistinguishedName {
            entries: vec![("CN".into(), "No CDP".into())],
        };
        let ee_cert = CertificateBuilder::new()
            .serial_number(&[0x43])
            .issuer(cert.issuer.clone())
            .subject(dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .build(&sk)
            .unwrap();

        assert!(ee_cert.crl_distribution_points().is_none());
    }

    #[test]
    fn test_revoked_entry_certificate_issuer() {
        use hitls_utils::asn1::Encoder;

        let (cert, sk) = make_rsa_ca();
        // Build a revoked entry with Certificate Issuer extension
        let mut gn_enc = Encoder::new();
        gn_enc.write_context_specific(6, false, b"http://ca.example.com");
        let mut seq_enc = Encoder::new();
        seq_enc.write_sequence(&gn_enc.finish());
        let ci_value = seq_enc.finish();
        let entry = RevokedCertBuilder::new(&[0x99], 1_700_100_000)
            .reason(RevocationReason::KeyCompromise)
            .add_extension(known::certificate_issuer().to_der_value(), true, ci_value);
        let crl = CrlBuilder::new(cert.issuer.clone(), 1_700_000_000)
            .add_revoked(entry)
            .build(&sk)
            .unwrap();

        assert_eq!(crl.revoked_certs.len(), 1);
        let re = &crl.revoked_certs[0];
        assert!(re.certificate_issuer.is_some());
        let ci = re.certificate_issuer.as_ref().unwrap();
        assert_eq!(ci.len(), 1);
        match &ci[0] {
            GeneralName::Uri(u) => assert_eq!(u, "http://ca.example.com"),
            _ => panic!("expected URI"),
        }
    }

    #[test]
    fn test_crl_issuing_distribution_point_roundtrip() {
        let (cert, sk) = make_rsa_ca();
        let crl = CrlBuilder::new(cert.issuer.clone(), 1_700_000_000)
            .next_update(1_710_000_000)
            .add_crl_number(&[0x02])
            .add_issuing_distribution_point(&[
                GeneralName::Uri("http://crl.example.com/ca.crl".into()),
                GeneralName::Uri("ldap://ldap.example.com/ca.crl".into()),
            ])
            .build(&sk)
            .unwrap();

        let idp = crl.issuing_distribution_point().unwrap();
        assert_eq!(idp.full_names.len(), 2);
        match &idp.full_names[0] {
            GeneralName::Uri(u) => assert_eq!(u, "http://crl.example.com/ca.crl"),
            _ => panic!("expected URI"),
        }
        match &idp.full_names[1] {
            GeneralName::Uri(u) => assert_eq!(u, "ldap://ldap.example.com/ca.crl"),
            _ => panic!("expected URI"),
        }
        // Verify signature
        assert!(crl.verify_signature(&cert).unwrap());
    }

    #[test]
    fn test_crl_delta_crl_indicator_roundtrip() {
        let (cert, sk) = make_rsa_ca();
        let crl = CrlBuilder::new(cert.issuer.clone(), 1_700_000_000)
            .add_crl_number(&[0x11])
            .add_delta_crl_indicator(&[0x10])
            .build(&sk)
            .unwrap();

        let dci = crl.delta_crl_indicator().unwrap();
        assert_eq!(dci, vec![0x10]);
        assert!(crl.verify_signature(&cert).unwrap());
    }
}
