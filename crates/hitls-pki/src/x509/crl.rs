//! X.509 Certificate Revocation List (CRL) parsing and verification (RFC 5280 §5).

use hitls_types::PkiError;
use hitls_utils::asn1::{tags, Decoder, TagClass};
use hitls_utils::oid::{known, Oid};

use super::{
    parse_algorithm_identifier, parse_extensions, parse_name, verify_ecdsa, verify_ed25519,
    verify_ed448, verify_rsa, verify_rsa_pss, verify_sm2, Certificate, DistinguishedName, HashAlg,
    SubjectPublicKeyInfo, X509Extension,
};

/// A certificate revocation list (CRL).
#[derive(Debug, Clone)]
pub struct CertificateRevocationList {
    /// DER-encoded CRL data.
    pub raw: Vec<u8>,
    /// CRL version (1 for v1, 2 for v2).
    pub version: u8,
    /// Signature algorithm OID (outer).
    pub signature_algorithm: Vec<u8>,
    /// Signature algorithm parameters.
    pub signature_params: Option<Vec<u8>>,
    /// CRL issuer distinguished name.
    pub issuer: DistinguishedName,
    /// thisUpdate time (UNIX timestamp).
    pub this_update: i64,
    /// nextUpdate time (UNIX timestamp, optional).
    pub next_update: Option<i64>,
    /// Revoked certificate entries.
    pub revoked_certs: Vec<RevokedCertificate>,
    /// CRL-level extensions (v2 only).
    pub extensions: Vec<X509Extension>,
    /// Raw TBS bytes (for signature verification).
    pub tbs_raw: Vec<u8>,
    /// Signature value bytes.
    pub signature_value: Vec<u8>,
}

/// A revoked certificate entry.
#[derive(Debug, Clone)]
pub struct RevokedCertificate {
    /// Certificate serial number.
    pub serial_number: Vec<u8>,
    /// Revocation date (UNIX timestamp).
    pub revocation_date: i64,
    /// Revocation reason (from CRLReason extension).
    pub reason: Option<RevocationReason>,
    /// Invalidity date (from InvalidityDate extension).
    pub invalidity_date: Option<i64>,
    /// Entry-level extensions.
    pub extensions: Vec<X509Extension>,
}

/// CRL revocation reason codes (RFC 5280 §5.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RevocationReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    // 7 is not used
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}

impl RevocationReason {
    /// Parse a reason code from an integer value.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Unspecified),
            1 => Some(Self::KeyCompromise),
            2 => Some(Self::CaCompromise),
            3 => Some(Self::AffiliationChanged),
            4 => Some(Self::Superseded),
            5 => Some(Self::CessationOfOperation),
            6 => Some(Self::CertificateHold),
            8 => Some(Self::RemoveFromCrl),
            9 => Some(Self::PrivilegeWithdrawn),
            10 => Some(Self::AaCompromise),
            _ => None,
        }
    }
}

impl CertificateRevocationList {
    /// Parse a CRL from DER-encoded bytes.
    pub fn from_der(data: &[u8]) -> Result<Self, PkiError> {
        let mut outer = Decoder::new(data)
            .read_sequence()
            .map_err(|e| PkiError::InvalidCrl(e.to_string()))?;

        // Extract raw TBS bytes for signature verification
        let remaining_before = outer.remaining();
        let tbs_tlv = outer
            .read_tlv()
            .map_err(|e| PkiError::InvalidCrl(e.to_string()))?;
        let tbs_consumed = remaining_before.len() - outer.remaining().len();
        let tbs_raw = remaining_before[..tbs_consumed].to_vec();

        // Parse TBS CertList
        let mut tbs_dec = Decoder::new(tbs_tlv.value);

        // version INTEGER OPTIONAL — If first element is INTEGER (tag 0x02),
        // it's the version. If it's SEQUENCE (tag 0x30), version is absent (default v1).
        // In TBSCertList: version comes before signature AlgorithmIdentifier (SEQUENCE).
        let version = {
            let tag = tbs_dec
                .peek_tag()
                .map_err(|e| PkiError::InvalidCrl(e.to_string()))?;
            if tag.class == TagClass::Universal && tag.number == tags::INTEGER as u32 {
                let ver_bytes = tbs_dec
                    .read_integer()
                    .map_err(|e| PkiError::InvalidCrl(e.to_string()))?;
                let v = ver_bytes.last().copied().unwrap_or(0);
                v + 1 // v1=0, v2=1
            } else {
                1 // default v1 (no version field present)
            }
        };

        // signature AlgorithmIdentifier
        let (_inner_sig_oid, _inner_sig_params) = parse_algorithm_identifier(&mut tbs_dec)?;

        // issuer Name
        let issuer = parse_name(&mut tbs_dec)?;

        // thisUpdate Time
        let this_update = tbs_dec
            .read_time()
            .map_err(|e| PkiError::InvalidCrl(e.to_string()))?;

        // nextUpdate Time OPTIONAL
        let next_update = if !tbs_dec.is_empty() {
            let tag = tbs_dec
                .peek_tag()
                .map_err(|e| PkiError::InvalidCrl(e.to_string()))?;
            if tag.class == TagClass::Universal
                && (tag.number == tags::UTC_TIME as u32
                    || tag.number == tags::GENERALIZED_TIME as u32)
            {
                // Try to read the time; if the TLV has zero-length value, treat as absent
                tbs_dec.read_time().ok()
            } else {
                None
            }
        } else {
            None
        };

        // revokedCertificates SEQUENCE OF SEQUENCE OPTIONAL
        let mut revoked_certs = Vec::new();
        if !tbs_dec.is_empty() {
            let tag = tbs_dec
                .peek_tag()
                .map_err(|e| PkiError::InvalidCrl(e.to_string()))?;
            if tag.class == TagClass::Universal && tag.number == 0x10 {
                let mut revoked_seq = tbs_dec
                    .read_sequence()
                    .map_err(|e| PkiError::InvalidCrl(e.to_string()))?;
                while !revoked_seq.is_empty() {
                    let entry = parse_revoked_entry(&mut revoked_seq)?;
                    revoked_certs.push(entry);
                }
            }
        }

        // crlExtensions [0] EXPLICIT Extensions OPTIONAL
        let extensions = if !tbs_dec.is_empty() {
            let ext_tlv = tbs_dec
                .try_read_context_specific(0, true)
                .map_err(|e| PkiError::InvalidCrl(e.to_string()))?;
            if let Some(ext_tlv) = ext_tlv {
                parse_extensions(ext_tlv.value)?
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // signatureAlgorithm AlgorithmIdentifier
        let (signature_algorithm, signature_params) = parse_algorithm_identifier(&mut outer)?;

        // signatureValue BIT STRING
        let (_, sig_bytes) = outer
            .read_bit_string()
            .map_err(|e| PkiError::InvalidCrl(e.to_string()))?;

        Ok(CertificateRevocationList {
            raw: data.to_vec(),
            version,
            signature_algorithm,
            signature_params,
            issuer,
            this_update,
            next_update,
            revoked_certs,
            extensions,
            tbs_raw,
            signature_value: sig_bytes.to_vec(),
        })
    }

    /// Parse a CRL from PEM-encoded string.
    pub fn from_pem(pem: &str) -> Result<Self, PkiError> {
        let blocks =
            hitls_utils::pem::parse(pem).map_err(|e| PkiError::InvalidCrl(e.to_string()))?;
        let crl_block = blocks
            .iter()
            .find(|b| b.label == "X509 CRL")
            .ok_or_else(|| PkiError::InvalidCrl("no X509 CRL block found".into()))?;
        Self::from_der(&crl_block.data)
    }

    /// Check if a certificate (by serial number) is revoked.
    /// Returns the revoked entry if found, None otherwise.
    pub fn is_revoked(&self, serial: &[u8]) -> Option<&RevokedCertificate> {
        // Strip leading zeros for comparison
        let serial_trimmed = strip_leading_zeros(serial);
        self.revoked_certs.iter().find(|entry| {
            let entry_trimmed = strip_leading_zeros(&entry.serial_number);
            entry_trimmed == serial_trimmed
        })
    }

    /// Verify the CRL's signature against the issuer certificate.
    pub fn verify_signature(&self, issuer: &Certificate) -> Result<bool, PkiError> {
        let sig_oid = Oid::from_der_value(&self.signature_algorithm)
            .map_err(|e| PkiError::InvalidCrl(e.to_string()))?;

        verify_signature_with_oid(
            &sig_oid,
            &self.tbs_raw,
            &self.signature_value,
            &issuer.public_key,
        )
    }

    /// Get the CRL number extension value, if present.
    pub fn crl_number(&self) -> Option<Vec<u8>> {
        let crl_num_oid = known::crl_number().to_der_value();
        self.extensions
            .iter()
            .find(|e| e.oid == crl_num_oid)
            .and_then(|e| {
                let mut dec = Decoder::new(&e.value);
                dec.read_integer().ok().map(|v| v.to_vec())
            })
    }
}

/// Verify a signature given the OID, TBS data, signature, and SPKI.
pub(crate) fn verify_signature_with_oid(
    sig_oid: &Oid,
    tbs: &[u8],
    signature: &[u8],
    spki: &SubjectPublicKeyInfo,
) -> Result<bool, PkiError> {
    if *sig_oid == known::sha256_with_rsa_encryption() {
        verify_rsa(tbs, signature, spki, HashAlg::Sha256)
    } else if *sig_oid == known::sha384_with_rsa_encryption() {
        verify_rsa(tbs, signature, spki, HashAlg::Sha384)
    } else if *sig_oid == known::sha512_with_rsa_encryption() {
        verify_rsa(tbs, signature, spki, HashAlg::Sha512)
    } else if *sig_oid == known::sha1_with_rsa_encryption() {
        verify_rsa(tbs, signature, spki, HashAlg::Sha1)
    } else if *sig_oid == known::ecdsa_with_sha256() {
        verify_ecdsa(tbs, signature, spki, HashAlg::Sha256)
    } else if *sig_oid == known::ecdsa_with_sha384() {
        verify_ecdsa(tbs, signature, spki, HashAlg::Sha384)
    } else if *sig_oid == known::ecdsa_with_sha512() {
        verify_ecdsa(tbs, signature, spki, HashAlg::Sha512)
    } else if *sig_oid == known::ed25519() {
        verify_ed25519(tbs, signature, spki)
    } else if *sig_oid == known::ed448() {
        verify_ed448(tbs, signature, spki)
    } else if *sig_oid == known::sm2_with_sm3() {
        verify_sm2(tbs, signature, spki)
    } else if *sig_oid == known::rsassa_pss() {
        verify_rsa_pss(tbs, signature, spki)
    } else {
        Err(PkiError::InvalidCrl(format!(
            "unsupported signature algorithm: {}",
            sig_oid
        )))
    }
}

/// Strip leading zero bytes from a byte slice.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

/// Parse a single revoked certificate entry from a SEQUENCE decoder.
fn parse_revoked_entry(dec: &mut Decoder) -> Result<RevokedCertificate, PkiError> {
    let mut entry_dec = dec
        .read_sequence()
        .map_err(|e| PkiError::InvalidCrl(e.to_string()))?;

    // userCertificate INTEGER (serial number)
    let serial_number = entry_dec
        .read_integer()
        .map_err(|e| PkiError::InvalidCrl(e.to_string()))?
        .to_vec();

    // revocationDate Time
    let revocation_date = entry_dec
        .read_time()
        .map_err(|e| PkiError::InvalidCrl(e.to_string()))?;

    // crlEntryExtensions Extensions OPTIONAL
    let mut reason = None;
    let mut invalidity_date = None;
    let mut extensions = Vec::new();

    if !entry_dec.is_empty() {
        // Entry extensions: SEQUENCE OF Extension
        let mut ext_seq = entry_dec
            .read_sequence()
            .map_err(|e| PkiError::InvalidCrl(e.to_string()))?;
        while !ext_seq.is_empty() {
            let mut ext_dec = ext_seq
                .read_sequence()
                .map_err(|e| PkiError::InvalidCrl(e.to_string()))?;
            let oid = ext_dec
                .read_oid()
                .map_err(|e| PkiError::InvalidCrl(e.to_string()))?
                .to_vec();
            // critical BOOLEAN DEFAULT FALSE
            let critical = if !ext_dec.is_empty() {
                let tag = ext_dec
                    .peek_tag()
                    .map_err(|e| PkiError::InvalidCrl(e.to_string()))?;
                if tag.class == TagClass::Universal && tag.number == tags::BOOLEAN as u32 {
                    ext_dec
                        .read_boolean()
                        .map_err(|e| PkiError::InvalidCrl(e.to_string()))?
                } else {
                    false
                }
            } else {
                false
            };
            let value = ext_dec
                .read_octet_string()
                .map_err(|e| PkiError::InvalidCrl(e.to_string()))?
                .to_vec();

            // Parse known entry extensions
            let oid_parsed =
                Oid::from_der_value(&oid).map_err(|e| PkiError::InvalidCrl(e.to_string()))?;

            if oid_parsed == known::crl_reason() {
                reason = parse_reason_code(&value).ok();
            } else if oid_parsed == known::invalidity_date() {
                invalidity_date = parse_invalidity_date(&value).ok();
            }

            extensions.push(X509Extension {
                oid,
                critical,
                value,
            });
        }
    }

    Ok(RevokedCertificate {
        serial_number,
        revocation_date,
        reason,
        invalidity_date,
        extensions,
    })
}

/// Parse a CRLReason extension value (ENUMERATED).
fn parse_reason_code(value: &[u8]) -> Result<RevocationReason, PkiError> {
    let mut dec = Decoder::new(value);
    let tlv = dec
        .read_tlv()
        .map_err(|e| PkiError::InvalidCrl(e.to_string()))?;
    // ENUMERATED tag = 0x0A
    if tlv.tag.number != 0x0A {
        return Err(PkiError::InvalidCrl(
            "expected ENUMERATED for reason code".into(),
        ));
    }
    let val = tlv.value.last().copied().unwrap_or(0);
    RevocationReason::from_u8(val)
        .ok_or_else(|| PkiError::InvalidCrl(format!("unknown reason code: {}", val)))
}

/// Parse an InvalidityDate extension value (GeneralizedTime or UTCTime).
fn parse_invalidity_date(value: &[u8]) -> Result<i64, PkiError> {
    let mut dec = Decoder::new(value);
    dec.read_time()
        .map_err(|e| PkiError::InvalidCrl(e.to_string()))
}

/// Parse multiple CRLs from a PEM string.
pub fn parse_crls_pem(pem: &str) -> Result<Vec<CertificateRevocationList>, PkiError> {
    let blocks = hitls_utils::pem::parse(pem).map_err(|e| PkiError::InvalidCrl(e.to_string()))?;
    let mut crls = Vec::new();
    for block in &blocks {
        if block.label == "X509 CRL" {
            crls.push(CertificateRevocationList::from_der(&block.data)?);
        }
    }
    Ok(crls)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real CRL from test data (PEM format, v1, RSA SHA-256, 2 revoked certs)
    const CRL_V1_PEM: &str = include_str!("../../../../tests/vectors/crl/crl_verify/crl/ca.crl");

    // CA certificate for verifying the CRL
    const CA_CERT_PEM: &str = include_str!("../../../../tests/vectors/crl/crl_verify/certs/ca.crt");

    // V2 CRL with extensions (PEM format)
    const CRL_V2_PEM: &str =
        include_str!("../../../../tests/vectors/crl/extension_crl/test_crl.pem");

    // CA cert for the v2 CRL
    const CRL_V2_CA_PEM: &str =
        include_str!("../../../../tests/vectors/crl/extension_crl/ca_cert.pem");

    // Empty CRL (no revoked certs) — PEM
    const EMPTY_CRL_PEM: &str =
        include_str!("../../../../tests/vectors/crl/crl_parse/crl/demoCA_rsa2048_v2_empty_crl.crl");

    // No next_update CRL — PEM
    const NO_NEXT_UPDATE_PEM: &str = include_str!(
        "../../../../tests/vectors/crl/crl_parse/crl/demoCA_rsa2048_v2_no_next_time.crl"
    );

    // Reason code test — key compromise (reason=1) — PEM
    const REASON_CODE_1_PEM: &str = include_str!(
        "../../../../tests/vectors/crl/crl_parse/crl/reason_code_test/demoCA_rsa2048_v2_reason_code_1.crl"
    );

    // Reason code test — CA compromise (reason=2) — PEM
    const REASON_CODE_2_PEM: &str = include_str!(
        "../../../../tests/vectors/crl/crl_parse/crl/reason_code_test/demoCA_rsa2048_v2_reason_code_2.crl"
    );

    // Invalidity date CRL — PEM
    const INVALIDITY_DATE_PEM: &str = include_str!(
        "../../../../tests/vectors/crl/crl_parse/crl/demoCA_rsa2048_v2_InvalidityData.crl"
    );

    #[test]
    fn test_parse_crl_v1_pem() {
        let crl = CertificateRevocationList::from_pem(CRL_V1_PEM).unwrap();
        assert_eq!(crl.version, 1);
        assert_eq!(crl.revoked_certs.len(), 2);
        assert!(crl.next_update.is_some());
        // Check issuer contains expected DN
        assert!(crl.issuer.get("CN").is_some());
    }

    #[test]
    fn test_parse_crl_v2_pem() {
        let crl = CertificateRevocationList::from_pem(CRL_V2_PEM).unwrap();
        assert_eq!(crl.version, 2);
        assert_eq!(crl.revoked_certs.len(), 1);
        assert!(crl.next_update.is_some());
        // v2 CRL should have extensions
        assert!(!crl.extensions.is_empty());
        // Should have a CRL number
        let crl_num = crl.crl_number();
        assert!(crl_num.is_some());
    }

    #[test]
    fn test_parse_crl_v2_empty() {
        let crl = CertificateRevocationList::from_pem(EMPTY_CRL_PEM).unwrap();
        assert_eq!(crl.revoked_certs.len(), 0);
    }

    #[test]
    fn test_parse_crl_no_next_update() {
        let crl = CertificateRevocationList::from_pem(NO_NEXT_UPDATE_PEM).unwrap();
        assert!(crl.next_update.is_none());
    }

    #[test]
    fn test_parse_crl_reason_codes() {
        // Reason code 1 = KeyCompromise
        let crl1 = CertificateRevocationList::from_pem(REASON_CODE_1_PEM).unwrap();
        assert!(!crl1.revoked_certs.is_empty());
        let entry = &crl1.revoked_certs[0];
        assert_eq!(entry.reason, Some(RevocationReason::KeyCompromise));

        // Reason code 2 = CaCompromise
        let crl2 = CertificateRevocationList::from_pem(REASON_CODE_2_PEM).unwrap();
        assert!(!crl2.revoked_certs.is_empty());
        let entry2 = &crl2.revoked_certs[0];
        assert_eq!(entry2.reason, Some(RevocationReason::CaCompromise));
    }

    #[test]
    fn test_parse_crl_invalidity_date() {
        let crl = CertificateRevocationList::from_pem(INVALIDITY_DATE_PEM).unwrap();
        assert!(!crl.revoked_certs.is_empty());
        let entry = &crl.revoked_certs[0];
        assert!(entry.invalidity_date.is_some());
    }

    #[test]
    fn test_verify_crl_signature() {
        let crl = CertificateRevocationList::from_pem(CRL_V1_PEM).unwrap();
        let ca = Certificate::from_pem(CA_CERT_PEM).unwrap();
        let result = crl.verify_signature(&ca).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_crl_v2_signature() {
        let crl = CertificateRevocationList::from_pem(CRL_V2_PEM).unwrap();
        let ca = Certificate::from_pem(CRL_V2_CA_PEM).unwrap();
        let result = crl.verify_signature(&ca).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_crl_signature_wrong_issuer() {
        let crl = CertificateRevocationList::from_pem(CRL_V2_PEM).unwrap();
        // Use a different CA cert — should fail
        let wrong_ca = Certificate::from_pem(CA_CERT_PEM).unwrap();
        let result = crl.verify_signature(&wrong_ca);
        // Either returns Ok(false) or Err — both indicate verification failure
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_is_revoked_found() {
        let crl = CertificateRevocationList::from_pem(CRL_V1_PEM).unwrap();
        // The first revoked cert's serial number should be found
        let serial = &crl.revoked_certs[0].serial_number;
        assert!(crl.is_revoked(serial).is_some());
    }

    #[test]
    fn test_is_revoked_not_found() {
        let crl = CertificateRevocationList::from_pem(CRL_V1_PEM).unwrap();
        // A random serial should not be found
        assert!(crl.is_revoked(&[0xFF, 0xFF, 0xFF]).is_none());
    }

    #[test]
    fn test_parse_crls_pem_multiple() {
        // Create a PEM string with two CRLs
        let combined = format!("{}\n{}", CRL_V1_PEM, CRL_V2_PEM);
        let crls = parse_crls_pem(&combined).unwrap();
        assert_eq!(crls.len(), 2);
    }

    #[test]
    fn test_crl_v2_reason_key_compromise() {
        let crl = CertificateRevocationList::from_pem(CRL_V2_PEM).unwrap();
        assert_eq!(crl.revoked_certs.len(), 1);
        let entry = &crl.revoked_certs[0];
        assert_eq!(entry.reason, Some(RevocationReason::KeyCompromise));
    }

    // -----------------------------------------------------------------------
    // P5: CRL C test vectors + edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_crl_ecdsa_v1_der() {
        let data = include_bytes!("../../../../tests/vectors/crl/ecdsa/crl_v1.der");
        let crl = CertificateRevocationList::from_der(data).unwrap();
        assert_eq!(crl.version, 1);
        assert!(!crl.issuer.entries.is_empty());
    }

    #[test]
    fn test_parse_crl_ecdsa_v2_der() {
        let data = include_bytes!("../../../../tests/vectors/crl/ecdsa/crl_v2.der");
        let crl = CertificateRevocationList::from_der(data).unwrap();
        assert_eq!(crl.version, 2);
        assert!(!crl.extensions.is_empty());
    }

    #[test]
    fn test_parse_crl_ecdsa_multiple_der() {
        let data = include_bytes!("../../../../tests/vectors/crl/ecdsa/crl_v2.mul.der");
        let crl = CertificateRevocationList::from_der(data).unwrap();
        assert!(!crl.revoked_certs.is_empty());
        assert_eq!(crl.version, 2);
    }

    #[test]
    fn test_parse_crl_rsa_v1_der() {
        let data = include_bytes!("../../../../tests/vectors/crl/rsa_der/crl_v1.der");
        let crl = CertificateRevocationList::from_der(data).unwrap();
        assert_eq!(crl.version, 1);
        assert!(!crl.issuer.entries.is_empty());
    }

    #[test]
    fn test_parse_crl_rsa_v2_der() {
        let data = include_bytes!("../../../../tests/vectors/crl/rsa_der/crl_v2.der");
        let crl = CertificateRevocationList::from_der(data).unwrap();
        assert_eq!(crl.version, 2);
        assert!(!crl.extensions.is_empty());
    }

    #[test]
    fn test_parse_crl_rsa_multiple_der() {
        let data = include_bytes!("../../../../tests/vectors/crl/rsa_der/crl_v2.mul.der");
        let crl = CertificateRevocationList::from_der(data).unwrap();
        assert!(!crl.revoked_certs.is_empty());
        assert_eq!(crl.version, 2);
    }

    #[test]
    fn test_crl_number_value() {
        // Parse the v2 CRL and check the actual CRL number
        let crl = CertificateRevocationList::from_pem(CRL_V2_PEM).unwrap();
        let crl_num = crl.crl_number().unwrap();
        assert!(!crl_num.is_empty());
        // CRL number should be a small positive integer
        assert!(crl_num.len() <= 8);
    }

    #[test]
    fn test_revocation_reason_from_u8_valid() {
        assert_eq!(
            RevocationReason::from_u8(0),
            Some(RevocationReason::Unspecified)
        );
        assert_eq!(
            RevocationReason::from_u8(1),
            Some(RevocationReason::KeyCompromise)
        );
        assert_eq!(
            RevocationReason::from_u8(5),
            Some(RevocationReason::CessationOfOperation)
        );
        assert_eq!(
            RevocationReason::from_u8(10),
            Some(RevocationReason::AaCompromise)
        );
    }

    #[test]
    fn test_revocation_reason_from_u8_invalid() {
        // 7 is not used
        assert_eq!(RevocationReason::from_u8(7), None);
        // 11+ are invalid
        assert_eq!(RevocationReason::from_u8(11), None);
        assert_eq!(RevocationReason::from_u8(255), None);
    }

    #[test]
    fn test_parse_crl_from_der_direct() {
        // Parse the v1 CRL from DER (convert PEM to DER first)
        let blocks = hitls_utils::pem::parse(CRL_V1_PEM).unwrap();
        let crl_block = blocks.iter().find(|b| b.label == "X509 CRL").unwrap();
        let crl = CertificateRevocationList::from_der(&crl_block.data).unwrap();
        assert_eq!(crl.version, 1);
        assert_eq!(crl.revoked_certs.len(), 2);
    }

    #[test]
    fn test_parse_crl_empty_from_pem() {
        // Empty CRL should have no revoked certs
        let crl = CertificateRevocationList::from_pem(EMPTY_CRL_PEM).unwrap();
        assert!(crl.revoked_certs.is_empty());
        // Empty CRL should still have issuer
        assert!(!crl.issuer.entries.is_empty());
    }

    #[test]
    fn test_crl_sig_alg_ecdsa() {
        let data = include_bytes!("../../../../tests/vectors/crl/ecdsa/crl_v2.der");
        let crl = CertificateRevocationList::from_der(data).unwrap();
        let sig_oid = Oid::from_der_value(&crl.signature_algorithm).unwrap();
        // ECDSA CRL should use an ecdsa-with-sha* OID
        assert!(
            sig_oid == known::ecdsa_with_sha256()
                || sig_oid == known::ecdsa_with_sha384()
                || sig_oid == known::ecdsa_with_sha512()
        );
    }

    #[test]
    fn test_crl_sig_alg_rsa() {
        let data = include_bytes!("../../../../tests/vectors/crl/rsa_der/crl_v2.der");
        let crl = CertificateRevocationList::from_der(data).unwrap();
        let sig_oid = Oid::from_der_value(&crl.signature_algorithm).unwrap();
        // RSA CRL should use sha*WithRSAEncryption OID
        assert!(
            sig_oid == known::sha256_with_rsa_encryption()
                || sig_oid == known::sha384_with_rsa_encryption()
                || sig_oid == known::sha512_with_rsa_encryption()
                || sig_oid == known::sha1_with_rsa_encryption()
        );
    }
}
