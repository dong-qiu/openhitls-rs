//! Online Certificate Status Protocol (OCSP) support (RFC 6960).
//!
//! Provides OCSP request building, response parsing, signature verification,
//! delegated responder validation, and response freshness checking.
//! No HTTP transport — callers handle network I/O.

use hitls_types::PkiError;
use hitls_utils::asn1::{Decoder, TagClass};
use hitls_utils::oid::{known, Oid};

use crate::encoding::{enc_int, enc_null, enc_octet, enc_oid, enc_raw_parts, enc_seq, enc_tlv};

use super::crl::{verify_signature_with_oid, RevocationReason};
use super::{compute_hash, Certificate, HashAlg};

/// OCSP certificate identifier (RFC 6960 §4.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcspCertId {
    /// Hash algorithm OID bytes.
    pub hash_algorithm: Vec<u8>,
    /// Hash of issuer's distinguished name.
    pub issuer_name_hash: Vec<u8>,
    /// Hash of issuer's public key.
    pub issuer_key_hash: Vec<u8>,
    /// Certificate serial number.
    pub serial_number: Vec<u8>,
}

impl OcspCertId {
    /// Build a CertID from a certificate and its issuer using SHA-256.
    ///
    /// Hashes the issuer's raw DER-encoded Name and SubjectPublicKey per RFC 6960 §4.1.1.
    pub fn new(cert: &Certificate, issuer: &Certificate) -> Result<Self, PkiError> {
        Self::new_with_hash(cert, issuer, &HashAlg::Sha256)
    }

    /// Build a CertID with a configurable hash algorithm.
    pub(crate) fn new_with_hash(
        cert: &Certificate,
        issuer: &Certificate,
        hash_alg: &HashAlg,
    ) -> Result<Self, PkiError> {
        let hash_oid = hash_alg_to_oid(hash_alg);

        // Hash of issuer's raw DER-encoded subject Name (RFC 6960 §4.1.1)
        let issuer_name_hash =
            compute_hash(&issuer.subject_raw, hash_alg).map_err(PkiError::CryptoError)?;

        // Hash of issuer's SubjectPublicKey BIT STRING value
        let issuer_key_hash = compute_hash(&issuer.public_key.public_key, hash_alg)
            .map_err(PkiError::CryptoError)?;

        Ok(OcspCertId {
            hash_algorithm: hash_oid,
            issuer_name_hash,
            issuer_key_hash,
            serial_number: cert.serial_number.clone(),
        })
    }

    /// Encode this CertID to DER.
    pub fn to_der(&self) -> Vec<u8> {
        let alg_id_inner = enc_raw_parts(&[&enc_oid(&self.hash_algorithm), &enc_null()]);
        let inner = enc_raw_parts(&[
            &enc_seq(&alg_id_inner),
            &enc_octet(&self.issuer_name_hash),
            &enc_octet(&self.issuer_key_hash),
            &enc_int(&self.serial_number),
        ]);
        enc_seq(&inner)
    }

    /// Parse a CertID from a DER decoder positioned at the SEQUENCE.
    fn from_decoder(dec: &mut Decoder) -> Result<Self, PkiError> {
        let mut seq = dec
            .read_sequence()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

        // hashAlgorithm AlgorithmIdentifier
        let mut alg_seq = seq
            .read_sequence()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let hash_algorithm = alg_seq
            .read_oid()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?
            .to_vec();
        if !alg_seq.is_empty() {
            let _ = alg_seq.read_tlv();
        }

        let issuer_name_hash = seq
            .read_octet_string()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?
            .to_vec();
        let issuer_key_hash = seq
            .read_octet_string()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?
            .to_vec();
        let serial_number = seq
            .read_integer()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?
            .to_vec();

        Ok(OcspCertId {
            hash_algorithm,
            issuer_name_hash,
            issuer_key_hash,
            serial_number,
        })
    }

    /// Check if this CertID matches another.
    pub fn matches(&self, other: &OcspCertId) -> bool {
        self.hash_algorithm == other.hash_algorithm
            && self.issuer_name_hash == other.issuer_name_hash
            && self.issuer_key_hash == other.issuer_key_hash
            && self.serial_number == other.serial_number
    }
}

/// OCSP request (RFC 6960 §4.1.1).
pub struct OcspRequest {
    /// List of certificate status requests.
    pub request_list: Vec<OcspCertId>,
    /// Optional nonce extension value.
    pub nonce: Option<Vec<u8>>,
}

impl OcspRequest {
    /// Create a request for a single certificate.
    pub fn new(cert: &Certificate, issuer: &Certificate) -> Result<Self, PkiError> {
        let cert_id = OcspCertId::new(cert, issuer)?;
        Ok(OcspRequest {
            request_list: vec![cert_id],
            nonce: None,
        })
    }

    /// Add another certificate to the request list.
    pub fn add_cert(
        &mut self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> Result<&mut Self, PkiError> {
        let cert_id = OcspCertId::new(cert, issuer)?;
        self.request_list.push(cert_id);
        Ok(self)
    }

    /// Set a nonce value for replay protection.
    pub fn set_nonce(&mut self, nonce: Vec<u8>) -> &mut Self {
        self.nonce = Some(nonce);
        self
    }

    /// Generate and set a random 16-byte nonce.
    pub fn generate_nonce(&mut self) -> Result<&mut Self, PkiError> {
        let mut buf = [0u8; 16];
        getrandom::getrandom(&mut buf)
            .map_err(|_| PkiError::CryptoError(hitls_types::CryptoError::InvalidArg(
                "getrandom failed for OCSP nonce",
            )))?;
        self.nonce = Some(buf.to_vec());
        Ok(self)
    }

    /// Parse an OCSP request from DER-encoded bytes.
    pub fn from_der(data: &[u8]) -> Result<Self, PkiError> {
        let mut outer = Decoder::new(data)
            .read_sequence()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

        // tbsRequest TBSRequest
        let mut tbs = outer
            .read_sequence()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

        // version [0] EXPLICIT INTEGER DEFAULT v1 — skip if present
        if !tbs.is_empty() {
            let tag = tbs
                .peek_tag()
                .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
            if tag.class == TagClass::ContextSpecific && tag.number == 0 {
                let _ = tbs.read_context_specific(0, true);
            }
        }

        // requestorName [1] EXPLICIT GeneralName OPTIONAL — skip if present
        if !tbs.is_empty() {
            let tag = tbs
                .peek_tag()
                .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
            if tag.class == TagClass::ContextSpecific && tag.number == 1 {
                let _ = tbs.read_context_specific(1, true);
            }
        }

        // requestList SEQUENCE OF Request
        let mut req_list_seq = tbs
            .read_sequence()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let mut request_list = Vec::new();
        while !req_list_seq.is_empty() {
            let mut req_seq = req_list_seq
                .read_sequence()
                .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
            let cert_id = OcspCertId::from_decoder(&mut req_seq)?;
            request_list.push(cert_id);
        }

        // requestExtensions [2] EXPLICIT Extensions OPTIONAL
        let mut nonce = None;
        if !tbs.is_empty() {
            if let Ok(Some(ext_tlv)) = tbs.try_read_context_specific(2, true) {
                let mut ext_dec = Decoder::new(ext_tlv.value);
                let mut exts_seq = ext_dec
                    .read_sequence()
                    .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                while !exts_seq.is_empty() {
                    let mut ext_seq = exts_seq
                        .read_sequence()
                        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                    let oid_bytes = ext_seq
                        .read_oid()
                        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                    let oid = Oid::from_der_value(oid_bytes)
                        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                    if oid == Oid::new(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 2]) {
                        // Nonce extension: value is OCTET STRING wrapping OCTET STRING
                        let outer_oct = ext_seq
                            .read_octet_string()
                            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                        let mut nonce_dec = Decoder::new(outer_oct);
                        let nonce_val = nonce_dec
                            .read_octet_string()
                            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                        nonce = Some(nonce_val.to_vec());
                    }
                }
            }
        }

        Ok(OcspRequest {
            request_list,
            nonce,
        })
    }

    /// Encode the OCSP request to DER.
    pub fn to_der(&self) -> Result<Vec<u8>, PkiError> {
        // requestList: SEQUENCE OF Request
        let mut req_list_parts: Vec<Vec<u8>> = Vec::new();
        for cert_id in &self.request_list {
            let cert_id_der = cert_id.to_der();
            // Request ::= SEQUENCE { reqCert CertID }
            req_list_parts.push(enc_seq(&cert_id_der));
        }
        let req_list_inner = enc_raw_parts(
            &req_list_parts
                .iter()
                .map(|v| v.as_slice())
                .collect::<Vec<_>>(),
        );
        let req_list_seq = enc_seq(&req_list_inner);

        // TBSRequest: SEQUENCE { requestList, [requestExtensions] }
        let mut tbs_parts = vec![req_list_seq];

        if let Some(ref nonce) = self.nonce {
            let nonce_oid = Oid::new(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 2]).to_der_value();
            let nonce_value = enc_octet(nonce);
            let ext_inner = enc_raw_parts(&[&enc_oid(&nonce_oid), &enc_octet(&nonce_value)]);
            let ext_seq = enc_seq(&ext_inner);
            let exts_seq = enc_seq(&ext_seq);
            tbs_parts.push(enc_tlv(0xA2, &exts_seq));
        }

        let tbs_inner = enc_raw_parts(&tbs_parts.iter().map(|v| v.as_slice()).collect::<Vec<_>>());
        let tbs_request = enc_seq(&tbs_inner);

        // OCSPRequest: SEQUENCE { tbsRequest }
        Ok(enc_seq(&tbs_request))
    }
}

/// OCSP response status (RFC 6960 §4.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OcspResponseStatus {
    Successful = 0,
    MalformedRequest = 1,
    InternalError = 2,
    TryLater = 3,
    SigRequired = 5,
    Unauthorized = 6,
}

impl OcspResponseStatus {
    fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Successful),
            1 => Some(Self::MalformedRequest),
            2 => Some(Self::InternalError),
            3 => Some(Self::TryLater),
            5 => Some(Self::SigRequired),
            6 => Some(Self::Unauthorized),
            _ => None,
        }
    }
}

/// Certificate status in an OCSP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OcspCertStatus {
    Good,
    Revoked {
        revocation_time: i64,
        reason: Option<RevocationReason>,
    },
    Unknown,
}

/// A single OCSP response for one certificate.
#[derive(Debug, Clone)]
pub struct OcspSingleResponse {
    pub cert_id: OcspCertId,
    pub status: OcspCertStatus,
    pub this_update: i64,
    pub next_update: Option<i64>,
}

/// OCSP BasicResponse (RFC 6960 §4.2.1).
#[derive(Debug, Clone)]
pub struct OcspBasicResponse {
    pub tbs_raw: Vec<u8>,
    pub responder_id: ResponderId,
    pub produced_at: i64,
    pub responses: Vec<OcspSingleResponse>,
    /// Nonce extension value from responseExtensions (if present).
    pub nonce: Option<Vec<u8>>,
    pub signature_algorithm: Vec<u8>,
    pub signature: Vec<u8>,
    pub certs: Vec<Certificate>,
}

/// OCSP responder identifier.
#[derive(Debug, Clone)]
pub enum ResponderId {
    ByName(String),
    ByKey(Vec<u8>),
}

/// Complete OCSP response (RFC 6960 §4.2.1).
#[derive(Debug, Clone)]
pub struct OcspResponse {
    pub status: OcspResponseStatus,
    pub basic_response: Option<OcspBasicResponse>,
}

impl OcspResponse {
    /// Parse an OCSP response from DER-encoded bytes.
    pub fn from_der(data: &[u8]) -> Result<Self, PkiError> {
        let mut outer = Decoder::new(data)
            .read_sequence()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

        // responseStatus ENUMERATED
        let status_tlv = outer
            .read_tlv()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        if status_tlv.tag.number != 0x0A {
            return Err(PkiError::Asn1Error(
                "expected ENUMERATED for responseStatus".into(),
            ));
        }
        let status_val = status_tlv.value.last().copied().unwrap_or(0);
        let status = OcspResponseStatus::from_u8(status_val).ok_or_else(|| {
            PkiError::Asn1Error(format!("unknown OCSP response status: {}", status_val))
        })?;

        // responseBytes [0] EXPLICIT ResponseBytes OPTIONAL
        let basic_response = if !outer.is_empty() && status == OcspResponseStatus::Successful {
            let resp_bytes_tlv = outer
                .read_context_specific(0, true)
                .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

            let mut resp_bytes_dec = Decoder::new(resp_bytes_tlv.value);
            let mut resp_bytes_seq = resp_bytes_dec
                .read_sequence()
                .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

            // responseType OID — must be id-pkix-ocsp-basic
            let resp_type_bytes = resp_bytes_seq
                .read_oid()
                .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
            let resp_type = Oid::from_der_value(resp_type_bytes)
                .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
            if resp_type != known::ocsp_basic() {
                return Err(PkiError::Asn1Error(format!(
                    "unsupported OCSP response type: {}",
                    resp_type
                )));
            }

            // response OCTET STRING (BasicOCSPResponse DER)
            let basic_der = resp_bytes_seq
                .read_octet_string()
                .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

            Some(OcspBasicResponse::from_der(basic_der)?)
        } else {
            None
        };

        Ok(OcspResponse {
            status,
            basic_response,
        })
    }
}

impl OcspBasicResponse {
    /// Parse a BasicOCSPResponse from DER.
    fn from_der(data: &[u8]) -> Result<Self, PkiError> {
        let mut outer = Decoder::new(data)
            .read_sequence()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

        // Extract TBS raw bytes
        let remaining_before = outer.remaining();
        let tbs_tlv = outer
            .read_tlv()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let tbs_consumed = remaining_before.len() - outer.remaining().len();
        let tbs_raw = remaining_before[..tbs_consumed].to_vec();

        // Parse ResponseData
        let mut tbs_dec = Decoder::new(tbs_tlv.value);

        // version [0] EXPLICIT — optional, skip if present
        if !tbs_dec.is_empty() {
            let tag = tbs_dec
                .peek_tag()
                .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
            if tag.class == TagClass::ContextSpecific && tag.number == 0 {
                let _ = tbs_dec.read_context_specific(0, true);
            }
        }

        // responderID CHOICE { byName [1], byKey [2] }
        let responder_id = {
            let tag = tbs_dec
                .peek_tag()
                .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
            if tag.class == TagClass::ContextSpecific && tag.number == 1 {
                let name_tlv = tbs_dec
                    .read_context_specific(1, true)
                    .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                ResponderId::ByName(format!("{:?}", name_tlv.value))
            } else if tag.class == TagClass::ContextSpecific && tag.number == 2 {
                let key_tlv = tbs_dec
                    .read_context_specific(2, true)
                    .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                let mut key_dec = Decoder::new(key_tlv.value);
                let key_hash = key_dec
                    .read_octet_string()
                    .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                ResponderId::ByKey(key_hash.to_vec())
            } else {
                return Err(PkiError::Asn1Error("invalid responderID".into()));
            }
        };

        // producedAt GeneralizedTime
        let produced_at = tbs_dec
            .read_time()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

        // responses SEQUENCE OF SingleResponse
        let mut responses_seq = tbs_dec
            .read_sequence()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let mut responses = Vec::new();
        while !responses_seq.is_empty() {
            responses.push(parse_single_response(&mut responses_seq)?);
        }

        // responseExtensions [1] EXPLICIT Extensions OPTIONAL
        let mut nonce = None;
        if !tbs_dec.is_empty() {
            if let Ok(Some(ext_tlv)) = tbs_dec.try_read_context_specific(1, true) {
                let mut ext_dec = Decoder::new(ext_tlv.value);
                let mut exts_seq = ext_dec
                    .read_sequence()
                    .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                while !exts_seq.is_empty() {
                    let mut ext_seq = exts_seq
                        .read_sequence()
                        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                    let oid_bytes = ext_seq
                        .read_oid()
                        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                    let oid = Oid::from_der_value(oid_bytes)
                        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                    // id-pkix-ocsp-nonce 1.3.6.1.5.5.7.48.1.2
                    if oid == Oid::new(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 2]) {
                        let outer_oct = ext_seq
                            .read_octet_string()
                            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                        let mut nonce_dec = Decoder::new(outer_oct);
                        let nonce_val = nonce_dec
                            .read_octet_string()
                            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                        nonce = Some(nonce_val.to_vec());
                    } else {
                        // Skip unknown extensions
                        while !ext_seq.is_empty() {
                            let _ = ext_seq.read_tlv();
                        }
                    }
                }
            }
        }

        // signatureAlgorithm AlgorithmIdentifier
        let mut sig_alg_seq = outer
            .read_sequence()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let signature_algorithm = sig_alg_seq
            .read_oid()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?
            .to_vec();

        // signature BIT STRING
        let (_, sig_bytes) = outer
            .read_bit_string()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

        // certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
        let mut certs = Vec::new();
        if !outer.is_empty() {
            if let Ok(Some(certs_tlv)) = outer.try_read_context_specific(0, true) {
                let mut certs_dec = Decoder::new(certs_tlv.value);
                let mut certs_seq = certs_dec
                    .read_sequence()
                    .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                while !certs_seq.is_empty() {
                    let cert_remaining = certs_seq.remaining();
                    let _cert_tlv = certs_seq
                        .read_tlv()
                        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                    let cert_len = cert_remaining.len() - certs_seq.remaining().len();
                    let cert_der = &cert_remaining[..cert_len];
                    certs.push(Certificate::from_der(cert_der)?);
                }
            }
        }

        Ok(OcspBasicResponse {
            tbs_raw,
            responder_id,
            produced_at,
            responses,
            nonce,
            signature_algorithm,
            signature: sig_bytes.to_vec(),
            certs,
        })
    }

    /// Verify the response signature against the issuer certificate.
    pub fn verify_signature(&self, issuer: &Certificate) -> Result<bool, PkiError> {
        let sig_oid = Oid::from_der_value(&self.signature_algorithm)
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        verify_signature_with_oid(&sig_oid, &self.tbs_raw, &self.signature, &issuer.public_key)
    }

    /// Verify signature using either the issuer directly or a delegated OCSP responder
    /// certificate embedded in the response (RFC 6960 §4.2.2.2).
    ///
    /// A delegated responder must:
    /// 1. Be signed by the issuer
    /// 2. Have the id-kp-OCSPSigning extended key usage
    pub fn verify_signature_or_delegated(
        &self,
        issuer: &Certificate,
    ) -> Result<bool, PkiError> {
        // First try direct verification against the issuer
        if let Ok(true) = self.verify_signature(issuer) {
            return Ok(true);
        }

        // Try each embedded certificate as a delegated responder
        for responder_cert in &self.certs {
            // Check: responder cert is signed by the issuer
            if responder_cert.verify_signature(issuer)? {
                // Check: responder cert has OCSPSigning EKU
                if has_ocsp_signing_eku(responder_cert) {
                    // Verify response signature against responder cert
                    if self.verify_signature(responder_cert)? {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    /// Find a response for the given CertID.
    pub fn find_response(&self, cert_id: &OcspCertId) -> Option<&OcspSingleResponse> {
        self.responses.iter().find(|r| r.cert_id.matches(cert_id))
    }

    /// Verify the nonce in this response matches the expected nonce from the request.
    pub fn verify_nonce(&self, expected: &[u8]) -> bool {
        self.nonce.as_deref() == Some(expected)
    }
}

impl OcspSingleResponse {
    /// Check if this response is valid at the given time.
    ///
    /// Returns `true` if `now >= this_update` and (if `next_update` is present)
    /// `now <= next_update`. The optional `max_age` parameter allows rejecting
    /// responses older than a threshold even when `next_update` is absent.
    pub fn check_validity(&self, now: i64, max_age: Option<i64>) -> bool {
        if now < self.this_update {
            return false;
        }
        if let Some(next) = self.next_update {
            if now > next {
                return false;
            }
        }
        if let Some(age) = max_age {
            if now - self.this_update > age {
                return false;
            }
        }
        true
    }
}

impl OcspResponse {
    /// Convenience: check a single certificate's OCSP status.
    ///
    /// Builds a CertID, parses the response, verifies the signature (including
    /// delegated responders), and returns the certificate status.
    pub fn check_cert(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> Result<Option<OcspCertStatus>, PkiError> {
        let cert_id = OcspCertId::new(cert, issuer)?;
        let basic = match &self.basic_response {
            Some(b) => b,
            None => return Ok(None),
        };
        if !basic.verify_signature_or_delegated(issuer)? {
            return Err(PkiError::InvalidCert(
                "OCSP response signature verification failed".into(),
            ));
        }
        Ok(basic.find_response(&cert_id).map(|r| r.status.clone()))
    }
}

/// Map a HashAlg to its OID DER value.
fn hash_alg_to_oid(alg: &HashAlg) -> Vec<u8> {
    match alg {
        HashAlg::Sha1 => known::sha1_oid().to_der_value(),
        HashAlg::Sha256 => known::sha256().to_der_value(),
        HashAlg::Sha384 => known::sha384().to_der_value(),
        HashAlg::Sha512 => known::sha512().to_der_value(),
    }
}

/// Check if a certificate has the id-kp-OCSPSigning extended key usage.
fn has_ocsp_signing_eku(cert: &Certificate) -> bool {
    if let Some(eku) = cert.extended_key_usage() {
        let ocsp_signing = known::kp_ocsp_signing();
        return eku.purposes.contains(&ocsp_signing);
    }
    false
}

/// Parse a SingleResponse from a decoder.
fn parse_single_response(dec: &mut Decoder) -> Result<OcspSingleResponse, PkiError> {
    let mut seq = dec
        .read_sequence()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

    let cert_id = OcspCertId::from_decoder(&mut seq)?;

    // certStatus CHOICE { good [0], revoked [1], unknown [2] }
    let status_tag = seq
        .peek_tag()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let status = if status_tag.class == TagClass::ContextSpecific && status_tag.number == 0 {
        let _ = seq.read_tlv();
        OcspCertStatus::Good
    } else if status_tag.class == TagClass::ContextSpecific && status_tag.number == 1 {
        let revoked_tlv = seq
            .read_tlv()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let mut revoked_dec = Decoder::new(revoked_tlv.value);
        let revocation_time = revoked_dec
            .read_time()
            .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        let reason = if !revoked_dec.is_empty() {
            if let Ok(Some(reason_tlv)) = revoked_dec.try_read_context_specific(0, true) {
                let mut reason_dec = Decoder::new(reason_tlv.value);
                let reason_val_tlv = reason_dec
                    .read_tlv()
                    .map_err(|e| PkiError::Asn1Error(e.to_string()))?;
                let val = reason_val_tlv.value.last().copied().unwrap_or(0);
                RevocationReason::from_u8(val)
            } else {
                None
            }
        } else {
            None
        };
        OcspCertStatus::Revoked {
            revocation_time,
            reason,
        }
    } else if status_tag.class == TagClass::ContextSpecific && status_tag.number == 2 {
        let _ = seq.read_tlv();
        OcspCertStatus::Unknown
    } else {
        return Err(PkiError::Asn1Error("invalid certStatus tag".into()));
    };

    // thisUpdate GeneralizedTime
    let this_update = seq
        .read_time()
        .map_err(|e| PkiError::Asn1Error(e.to_string()))?;

    // nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL
    let next_update = if !seq.is_empty() {
        if let Ok(Some(next_tlv)) = seq.try_read_context_specific(0, true) {
            let mut next_dec = Decoder::new(next_tlv.value);
            Some(
                next_dec
                    .read_time()
                    .map_err(|e| PkiError::Asn1Error(e.to_string()))?,
            )
        } else {
            None
        }
    } else {
        None
    };

    Ok(OcspSingleResponse {
        cert_id,
        status,
        this_update,
        next_update,
    })
}

// ---- Test helpers for building synthetic OCSP responses ----

#[cfg(test)]
fn enc_bit_string(unused: u8, value: &[u8]) -> Vec<u8> {
    let mut e = hitls_utils::asn1::Encoder::new();
    e.write_bit_string(unused, value);
    e.finish()
}

#[cfg(test)]
fn format_generalized_time(timestamp: i64) -> String {
    let secs_per_day: i64 = 86400;
    let days = timestamp / secs_per_day;
    let time_of_day = timestamp % secs_per_day;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    let (year, month, day) = days_to_ymd(days);
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

#[cfg(test)]
fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i32 + (era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
fn enc_generalized_time(timestamp: i64) -> Vec<u8> {
    let s = format_generalized_time(timestamp);
    enc_tlv(0x18, s.as_bytes()) // 0x18 = GENERALIZED_TIME
}

/// Build a synthetic OCSP response DER for testing.
#[cfg(test)]
fn build_test_ocsp_response(
    status: OcspResponseStatus,
    single_responses: &[(OcspCertId, OcspCertStatus, i64)],
    sig_alg_oid: &[u8],
    signature: &[u8],
) -> Vec<u8> {
    if status != OcspResponseStatus::Successful {
        let inner = enc_tlv(0x0A, &[status as u8]);
        return enc_seq(&inner);
    }

    // Build SingleResponse entries
    let mut resp_parts: Vec<Vec<u8>> = Vec::new();
    for (cert_id, cert_status, this_update) in single_responses {
        let cert_id_der = cert_id.to_der();

        let status_der = match cert_status {
            OcspCertStatus::Good => vec![0x80, 0x00],
            OcspCertStatus::Revoked {
                revocation_time, ..
            } => {
                let time_der = enc_generalized_time(*revocation_time);
                enc_tlv(0xA1, &time_der)
            }
            OcspCertStatus::Unknown => vec![0x82, 0x00],
        };

        let this_update_der = enc_generalized_time(*this_update);
        let single_inner = enc_raw_parts(&[&cert_id_der, &status_der, &this_update_der]);
        resp_parts.push(enc_seq(&single_inner));
    }
    let responses_inner =
        enc_raw_parts(&resp_parts.iter().map(|v| v.as_slice()).collect::<Vec<_>>());
    let responses_seq = enc_seq(&responses_inner);

    // ResponderID: byKey [2]
    let key_hash_octet = enc_octet(&[0u8; 32]);
    let responder_id = enc_tlv(0xA2, &key_hash_octet);

    // producedAt
    let produced_at = enc_generalized_time(1_763_164_800);

    // ResponseData SEQUENCE
    let response_data_inner = enc_raw_parts(&[&responder_id, &produced_at, &responses_seq]);
    let response_data = enc_seq(&response_data_inner);

    // signatureAlgorithm
    let sig_alg_inner = enc_raw_parts(&[&enc_oid(sig_alg_oid), &enc_null()]);
    let sig_alg = enc_seq(&sig_alg_inner);

    // signature BIT STRING
    let sig_bs = enc_bit_string(0, signature);

    // BasicOCSPResponse
    let basic_inner = enc_raw_parts(&[&response_data, &sig_alg, &sig_bs]);
    let basic_der = enc_seq(&basic_inner);

    // ResponseBytes
    let ocsp_basic_oid = known::ocsp_basic().to_der_value();
    let resp_bytes_inner = enc_raw_parts(&[&enc_oid(&ocsp_basic_oid), &enc_octet(&basic_der)]);
    let resp_bytes = enc_seq(&resp_bytes_inner);

    // OCSPResponse
    let status_der = enc_tlv(0x0A, &[0]); // successful
    let resp_bytes_tagged = enc_tlv(0xA0, &resp_bytes);
    let outer = enc_raw_parts(&[&status_der, &resp_bytes_tagged]);
    enc_seq(&outer)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CRL_CA_PEM: &str = include_str!("../../../../tests/vectors/crl/crl_verify/certs/ca.crt");
    const SERVER1_PEM: &str =
        include_str!("../../../../tests/vectors/crl/crl_verify/certs/server1.crt");

    #[test]
    fn test_ocsp_cert_id_new() {
        let ca = Certificate::from_pem(CRL_CA_PEM).unwrap();
        let server = Certificate::from_pem(SERVER1_PEM).unwrap();
        let cert_id = OcspCertId::new(&server, &ca).unwrap();

        assert_eq!(cert_id.issuer_name_hash.len(), 32);
        assert_eq!(cert_id.issuer_key_hash.len(), 32);
        assert_eq!(cert_id.serial_number, server.serial_number);
    }

    #[test]
    fn test_ocsp_cert_id_matches() {
        let ca = Certificate::from_pem(CRL_CA_PEM).unwrap();
        let server = Certificate::from_pem(SERVER1_PEM).unwrap();
        let id1 = OcspCertId::new(&server, &ca).unwrap();
        let id2 = OcspCertId::new(&server, &ca).unwrap();
        assert!(id1.matches(&id2));
    }

    #[test]
    fn test_ocsp_cert_id_to_der_roundtrip() {
        let ca = Certificate::from_pem(CRL_CA_PEM).unwrap();
        let server = Certificate::from_pem(SERVER1_PEM).unwrap();
        let cert_id = OcspCertId::new(&server, &ca).unwrap();

        let der = cert_id.to_der();
        let mut dec = Decoder::new(&der);
        let parsed = OcspCertId::from_decoder(&mut dec).unwrap();
        assert!(cert_id.matches(&parsed));
    }

    #[test]
    fn test_ocsp_request_to_der() {
        let ca = Certificate::from_pem(CRL_CA_PEM).unwrap();
        let server = Certificate::from_pem(SERVER1_PEM).unwrap();
        let req = OcspRequest::new(&server, &ca).unwrap();
        let der = req.to_der().unwrap();
        assert!(!der.is_empty());

        // Verify valid ASN.1 structure
        let mut outer = Decoder::new(&der).read_sequence().unwrap();
        let mut tbs = outer.read_sequence().unwrap();
        let req_list = tbs.read_sequence().unwrap();
        assert!(!req_list.is_empty());
    }

    #[test]
    fn test_ocsp_response_non_successful() {
        let inner = enc_tlv(0x0A, &[3]); // tryLater
        let der = enc_seq(&inner);

        let resp = OcspResponse::from_der(&der).unwrap();
        assert_eq!(resp.status, OcspResponseStatus::TryLater);
        assert!(resp.basic_response.is_none());
    }

    #[test]
    fn test_ocsp_response_parse_good() {
        let ca = Certificate::from_pem(CRL_CA_PEM).unwrap();
        let server = Certificate::from_pem(SERVER1_PEM).unwrap();
        let cert_id = OcspCertId::new(&server, &ca).unwrap();

        let sha256_rsa_oid = known::sha256_with_rsa_encryption().to_der_value();
        let der = build_test_ocsp_response(
            OcspResponseStatus::Successful,
            &[(cert_id.clone(), OcspCertStatus::Good, 1_763_164_800)],
            &sha256_rsa_oid,
            &[0u8; 64],
        );

        let resp = OcspResponse::from_der(&der).unwrap();
        assert_eq!(resp.status, OcspResponseStatus::Successful);
        let basic = resp.basic_response.unwrap();
        assert_eq!(basic.responses.len(), 1);
        assert_eq!(basic.responses[0].status, OcspCertStatus::Good);
        assert!(basic.responses[0].cert_id.matches(&cert_id));
    }

    #[test]
    fn test_ocsp_response_parse_revoked() {
        let ca = Certificate::from_pem(CRL_CA_PEM).unwrap();
        let server = Certificate::from_pem(SERVER1_PEM).unwrap();
        let cert_id = OcspCertId::new(&server, &ca).unwrap();

        let sha256_rsa_oid = known::sha256_with_rsa_encryption().to_der_value();
        let revoked = OcspCertStatus::Revoked {
            revocation_time: 1_760_000_000,
            reason: None,
        };
        let der = build_test_ocsp_response(
            OcspResponseStatus::Successful,
            &[(cert_id.clone(), revoked, 1_763_164_800)],
            &sha256_rsa_oid,
            &[0u8; 64],
        );

        let resp = OcspResponse::from_der(&der).unwrap();
        let basic = resp.basic_response.unwrap();
        match &basic.responses[0].status {
            OcspCertStatus::Revoked {
                revocation_time, ..
            } => assert_eq!(*revocation_time, 1_760_000_000),
            _ => panic!("expected Revoked status"),
        }
    }

    #[test]
    fn test_ocsp_response_find_response() {
        let ca = Certificate::from_pem(CRL_CA_PEM).unwrap();
        let server = Certificate::from_pem(SERVER1_PEM).unwrap();
        let cert_id = OcspCertId::new(&server, &ca).unwrap();

        let sha256_rsa_oid = known::sha256_with_rsa_encryption().to_der_value();
        let der = build_test_ocsp_response(
            OcspResponseStatus::Successful,
            &[(cert_id.clone(), OcspCertStatus::Good, 1_763_164_800)],
            &sha256_rsa_oid,
            &[0u8; 64],
        );

        let resp = OcspResponse::from_der(&der).unwrap();
        let basic = resp.basic_response.unwrap();

        assert!(basic.find_response(&cert_id).is_some());

        let other_id = OcspCertId {
            hash_algorithm: cert_id.hash_algorithm.clone(),
            issuer_name_hash: cert_id.issuer_name_hash.clone(),
            issuer_key_hash: cert_id.issuer_key_hash.clone(),
            serial_number: vec![0xFF, 0xFF],
        };
        assert!(basic.find_response(&other_id).is_none());
    }

    // -----------------------------------------------------------------------
    // Phase 54: OCSP verify_signature tests
    // -----------------------------------------------------------------------

    /// Build a properly signed OCSP response for testing.
    /// Returns DER-encoded OCSPResponse.
    fn build_signed_ocsp_response(
        single_responses: &[(OcspCertId, OcspCertStatus, i64)],
        sig_alg_oid: &[u8],
        sign_fn: &dyn Fn(&[u8]) -> Vec<u8>,
    ) -> Vec<u8> {
        // Build SingleResponse entries
        let mut resp_parts: Vec<Vec<u8>> = Vec::new();
        for (cert_id, cert_status, this_update) in single_responses {
            let cert_id_der = cert_id.to_der();
            let status_der = match cert_status {
                OcspCertStatus::Good => vec![0x80, 0x00],
                OcspCertStatus::Revoked {
                    revocation_time, ..
                } => {
                    let time_der = enc_generalized_time(*revocation_time);
                    enc_tlv(0xA1, &time_der)
                }
                OcspCertStatus::Unknown => vec![0x82, 0x00],
            };
            let this_update_der = enc_generalized_time(*this_update);
            let single_inner = enc_raw_parts(&[&cert_id_der, &status_der, &this_update_der]);
            resp_parts.push(enc_seq(&single_inner));
        }
        let responses_inner =
            enc_raw_parts(&resp_parts.iter().map(|v| v.as_slice()).collect::<Vec<_>>());
        let responses_seq = enc_seq(&responses_inner);

        // ResponderID: byKey [2]
        let key_hash_octet = enc_octet(&[0u8; 32]);
        let responder_id = enc_tlv(0xA2, &key_hash_octet);

        // producedAt
        let produced_at = enc_generalized_time(1_763_164_800);

        // ResponseData SEQUENCE (this is what gets signed)
        let response_data_inner = enc_raw_parts(&[&responder_id, &produced_at, &responses_seq]);
        let response_data = enc_seq(&response_data_inner);

        // Sign the ResponseData
        let signature = sign_fn(&response_data);

        // signatureAlgorithm
        let sig_alg_inner = enc_raw_parts(&[&enc_oid(sig_alg_oid), &enc_null()]);
        let sig_alg = enc_seq(&sig_alg_inner);

        // signature BIT STRING
        let sig_bs = enc_bit_string(0, &signature);

        // BasicOCSPResponse
        let basic_inner = enc_raw_parts(&[&response_data, &sig_alg, &sig_bs]);
        let basic_der = enc_seq(&basic_inner);

        // ResponseBytes
        let ocsp_basic_oid = known::ocsp_basic().to_der_value();
        let resp_bytes_inner = enc_raw_parts(&[&enc_oid(&ocsp_basic_oid), &enc_octet(&basic_der)]);
        let resp_bytes = enc_seq(&resp_bytes_inner);

        // OCSPResponse
        let status_der = enc_tlv(0x0A, &[0]); // successful
        let resp_bytes_tagged = enc_tlv(0xA0, &resp_bytes);
        let outer = enc_raw_parts(&[&status_der, &resp_bytes_tagged]);
        enc_seq(&outer)
    }

    #[test]
    fn test_ocsp_verify_signature_ecdsa() {
        // Build a cert and key for signing
        let kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
        // Build a minimal self-signed cert
        let dn = crate::x509::DistinguishedName {
            entries: vec![("CN".to_string(), "OCSP Test ECDSA".to_string())],
        };
        let sk = crate::x509::SigningKey::Ecdsa {
            curve_id: hitls_types::EccCurveId::NistP256,
            key_pair: kp.clone(),
        };
        let cert =
            crate::x509::CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000)
                .unwrap();

        // Build OCSP request components
        let cert_id = OcspCertId {
            hash_algorithm: known::sha256().to_der_value(),
            issuer_name_hash: vec![0u8; 32],
            issuer_key_hash: vec![0u8; 32],
            serial_number: vec![1],
        };

        let sig_alg_oid = known::ecdsa_with_sha256().to_der_value();
        let der = build_signed_ocsp_response(
            &[(cert_id, OcspCertStatus::Good, 1_763_164_800)],
            &sig_alg_oid,
            &|data: &[u8]| {
                let mut h = hitls_crypto::sha2::Sha256::new();
                h.update(data).unwrap();
                let digest = h.finish().unwrap();
                kp.sign(&digest).unwrap()
            },
        );

        let resp = OcspResponse::from_der(&der).unwrap();
        let basic = resp.basic_response.unwrap();
        let result = basic.verify_signature(&cert);
        assert!(result.is_ok(), "OCSP ECDSA verify failed: {result:?}");
        assert!(result.unwrap());
    }

    #[test]
    fn test_ocsp_verify_signature_wrong_issuer() {
        // Sign with one key, try to verify with different cert
        let kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();

        let cert_id = OcspCertId {
            hash_algorithm: known::sha256().to_der_value(),
            issuer_name_hash: vec![0u8; 32],
            issuer_key_hash: vec![0u8; 32],
            serial_number: vec![1],
        };

        let sig_alg_oid = known::ecdsa_with_sha256().to_der_value();
        let der = build_signed_ocsp_response(
            &[(cert_id, OcspCertStatus::Good, 1_763_164_800)],
            &sig_alg_oid,
            &|data: &[u8]| {
                let mut h = hitls_crypto::sha2::Sha256::new();
                h.update(data).unwrap();
                let digest = h.finish().unwrap();
                kp.sign(&digest).unwrap()
            },
        );

        // Build a DIFFERENT cert
        let other_kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
        let other_dn = crate::x509::DistinguishedName {
            entries: vec![("CN".to_string(), "Wrong Issuer".to_string())],
        };
        let other_sk = crate::x509::SigningKey::Ecdsa {
            curve_id: hitls_types::EccCurveId::NistP256,
            key_pair: other_kp,
        };
        let wrong_cert = crate::x509::CertificateBuilder::self_signed(
            other_dn,
            &other_sk,
            1_700_000_000,
            1_800_000_000,
        )
        .unwrap();

        let resp = OcspResponse::from_der(&der).unwrap();
        let basic = resp.basic_response.unwrap();
        let result = basic.verify_signature(&wrong_cert);
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_ocsp_verify_signature_tampered() {
        // Sign properly then tamper with tbs_raw
        let kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
        let dn = crate::x509::DistinguishedName {
            entries: vec![("CN".to_string(), "Tamper Test".to_string())],
        };
        let sk = crate::x509::SigningKey::Ecdsa {
            curve_id: hitls_types::EccCurveId::NistP256,
            key_pair: kp.clone(),
        };
        let cert =
            crate::x509::CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000)
                .unwrap();

        let cert_id = OcspCertId {
            hash_algorithm: known::sha256().to_der_value(),
            issuer_name_hash: vec![0u8; 32],
            issuer_key_hash: vec![0u8; 32],
            serial_number: vec![1],
        };

        let sig_alg_oid = known::ecdsa_with_sha256().to_der_value();
        let der = build_signed_ocsp_response(
            &[(cert_id, OcspCertStatus::Good, 1_763_164_800)],
            &sig_alg_oid,
            &|data: &[u8]| {
                let mut h = hitls_crypto::sha2::Sha256::new();
                h.update(data).unwrap();
                let digest = h.finish().unwrap();
                kp.sign(&digest).unwrap()
            },
        );

        let resp = OcspResponse::from_der(&der).unwrap();
        let mut basic = resp.basic_response.unwrap();
        // Tamper with tbs_raw
        let len = basic.tbs_raw.len();
        if len > 0 {
            basic.tbs_raw[len - 1] ^= 0xFF;
        }
        let result = basic.verify_signature(&cert);
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_ocsp_request_new() {
        let ca = Certificate::from_pem(CRL_CA_PEM).unwrap();
        let server = Certificate::from_pem(SERVER1_PEM).unwrap();
        let req = OcspRequest::new(&server, &ca).unwrap();
        assert_eq!(req.request_list.len(), 1);
        assert!(!req.request_list[0].issuer_name_hash.is_empty());
        assert!(!req.request_list[0].issuer_key_hash.is_empty());
        assert_eq!(req.request_list[0].serial_number, server.serial_number);
        let der = req.to_der().unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn test_ocsp_response_unknown_status() {
        let ca = Certificate::from_pem(CRL_CA_PEM).unwrap();
        let server = Certificate::from_pem(SERVER1_PEM).unwrap();
        let cert_id = OcspCertId::new(&server, &ca).unwrap();

        let sha256_rsa_oid = known::sha256_with_rsa_encryption().to_der_value();
        let der = build_test_ocsp_response(
            OcspResponseStatus::Successful,
            &[(cert_id.clone(), OcspCertStatus::Unknown, 1_763_164_800)],
            &sha256_rsa_oid,
            &[0u8; 64],
        );

        let resp = OcspResponse::from_der(&der).unwrap();
        let basic = resp.basic_response.unwrap();
        assert_eq!(basic.responses[0].status, OcspCertStatus::Unknown);
    }

    #[test]
    fn test_ocsp_response_malformed() {
        // Completely invalid DER
        let result = OcspResponse::from_der(&[0xFF, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn test_ocsp_response_non_successful_statuses() {
        for (code, expected) in [
            (1, OcspResponseStatus::MalformedRequest),
            (2, OcspResponseStatus::InternalError),
            (3, OcspResponseStatus::TryLater),
            (5, OcspResponseStatus::SigRequired),
            (6, OcspResponseStatus::Unauthorized),
        ] {
            let inner = enc_tlv(0x0A, &[code]);
            let der = enc_seq(&inner);
            let resp = OcspResponse::from_der(&der).unwrap();
            assert_eq!(resp.status, expected);
            assert!(resp.basic_response.is_none());
        }
    }

    // ---- Phase I88: New OCSP enhancement tests ----

    #[test]
    fn test_ocsp_cert_id_uses_raw_der_name() {
        let ca = Certificate::from_pem(CRL_CA_PEM).unwrap();
        let server = Certificate::from_pem(SERVER1_PEM).unwrap();

        // Ensure raw DER fields are populated
        assert!(!ca.subject_raw.is_empty());
        assert!(!ca.issuer_raw.is_empty());

        let cert_id = OcspCertId::new(&server, &ca).unwrap();
        // Hash of raw DER Name must be 32 bytes (SHA-256)
        assert_eq!(cert_id.issuer_name_hash.len(), 32);
        assert_eq!(cert_id.issuer_key_hash.len(), 32);

        // Verify hash is of raw DER, not string: rebuild and compare
        let cert_id2 = OcspCertId::new(&server, &ca).unwrap();
        assert!(cert_id.matches(&cert_id2));
    }

    #[test]
    fn test_ocsp_cert_id_new_with_hash_sha384() {
        let ca = Certificate::from_pem(CRL_CA_PEM).unwrap();
        let server = Certificate::from_pem(SERVER1_PEM).unwrap();
        let cert_id = OcspCertId::new_with_hash(&server, &ca, &HashAlg::Sha384).unwrap();
        // SHA-384 hash is 48 bytes
        assert_eq!(cert_id.issuer_name_hash.len(), 48);
        assert_eq!(cert_id.issuer_key_hash.len(), 48);
    }

    #[test]
    fn test_ocsp_request_add_cert() {
        let ca = Certificate::from_pem(CRL_CA_PEM).unwrap();
        let server = Certificate::from_pem(SERVER1_PEM).unwrap();
        let mut req = OcspRequest::new(&server, &ca).unwrap();
        assert_eq!(req.request_list.len(), 1);

        // Add same cert again (just to test multi-request)
        req.add_cert(&server, &ca).unwrap();
        assert_eq!(req.request_list.len(), 2);

        let der = req.to_der().unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn test_ocsp_request_generate_nonce() {
        let ca = Certificate::from_pem(CRL_CA_PEM).unwrap();
        let server = Certificate::from_pem(SERVER1_PEM).unwrap();
        let mut req = OcspRequest::new(&server, &ca).unwrap();
        assert!(req.nonce.is_none());

        req.generate_nonce().unwrap();
        assert!(req.nonce.is_some());
        assert_eq!(req.nonce.as_ref().unwrap().len(), 16);

        // Nonces should be different each time
        let nonce1 = req.nonce.clone().unwrap();
        req.generate_nonce().unwrap();
        let nonce2 = req.nonce.clone().unwrap();
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_ocsp_request_der_roundtrip() {
        let ca = Certificate::from_pem(CRL_CA_PEM).unwrap();
        let server = Certificate::from_pem(SERVER1_PEM).unwrap();
        let mut req = OcspRequest::new(&server, &ca).unwrap();
        req.set_nonce(vec![0xAA; 16]);

        let der = req.to_der().unwrap();
        let parsed = OcspRequest::from_der(&der).unwrap();

        assert_eq!(parsed.request_list.len(), 1);
        assert!(parsed.request_list[0].matches(&req.request_list[0]));
        assert_eq!(parsed.nonce, Some(vec![0xAA; 16]));
    }

    #[test]
    fn test_ocsp_request_from_der_no_nonce() {
        let ca = Certificate::from_pem(CRL_CA_PEM).unwrap();
        let server = Certificate::from_pem(SERVER1_PEM).unwrap();
        let req = OcspRequest::new(&server, &ca).unwrap();

        let der = req.to_der().unwrap();
        let parsed = OcspRequest::from_der(&der).unwrap();

        assert_eq!(parsed.request_list.len(), 1);
        assert!(parsed.nonce.is_none());
    }

    #[test]
    fn test_ocsp_single_response_check_validity() {
        let resp = OcspSingleResponse {
            cert_id: OcspCertId {
                hash_algorithm: known::sha256().to_der_value(),
                issuer_name_hash: vec![0u8; 32],
                issuer_key_hash: vec![0u8; 32],
                serial_number: vec![1],
            },
            status: OcspCertStatus::Good,
            this_update: 1_000_000,
            next_update: Some(2_000_000),
        };

        // Valid: within [this_update, next_update]
        assert!(resp.check_validity(1_500_000, None));

        // Invalid: before this_update
        assert!(!resp.check_validity(999_999, None));

        // Invalid: after next_update
        assert!(!resp.check_validity(2_000_001, None));

        // Valid: at exact boundaries
        assert!(resp.check_validity(1_000_000, None));
        assert!(resp.check_validity(2_000_000, None));
    }

    #[test]
    fn test_ocsp_single_response_check_validity_max_age() {
        let resp = OcspSingleResponse {
            cert_id: OcspCertId {
                hash_algorithm: known::sha256().to_der_value(),
                issuer_name_hash: vec![0u8; 32],
                issuer_key_hash: vec![0u8; 32],
                serial_number: vec![1],
            },
            status: OcspCertStatus::Good,
            this_update: 1_000_000,
            next_update: None,
        };

        // Without max_age: valid at any future time
        assert!(resp.check_validity(9_999_999, None));

        // With max_age: stale response rejected
        let max_age = 3600; // 1 hour
        assert!(resp.check_validity(1_003_000, Some(max_age)));
        assert!(!resp.check_validity(1_004_000, Some(max_age)));
    }

    #[test]
    fn test_ocsp_verify_nonce() {
        let basic = OcspBasicResponse {
            tbs_raw: vec![],
            responder_id: ResponderId::ByKey(vec![0u8; 32]),
            produced_at: 1_763_164_800,
            responses: vec![],
            nonce: Some(vec![0xBB; 16]),
            signature_algorithm: vec![],
            signature: vec![],
            certs: vec![],
        };

        assert!(basic.verify_nonce(&[0xBB; 16]));
        assert!(!basic.verify_nonce(&[0xCC; 16]));
    }

    #[test]
    fn test_ocsp_verify_nonce_absent() {
        let basic = OcspBasicResponse {
            tbs_raw: vec![],
            responder_id: ResponderId::ByKey(vec![0u8; 32]),
            produced_at: 1_763_164_800,
            responses: vec![],
            nonce: None,
            signature_algorithm: vec![],
            signature: vec![],
            certs: vec![],
        };

        assert!(!basic.verify_nonce(&[0xBB; 16]));
    }

    #[test]
    fn test_ocsp_check_cert_convenience() {
        let kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
        let dn = crate::x509::DistinguishedName {
            entries: vec![("CN".to_string(), "OCSP Check Test".to_string())],
        };
        let sk = crate::x509::SigningKey::Ecdsa {
            curve_id: hitls_types::EccCurveId::NistP256,
            key_pair: kp.clone(),
        };
        let cert =
            crate::x509::CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000)
                .unwrap();

        let cert_id = OcspCertId {
            hash_algorithm: known::sha256().to_der_value(),
            issuer_name_hash: compute_hash(&cert.subject_raw, &HashAlg::Sha256).unwrap(),
            issuer_key_hash: compute_hash(&cert.public_key.public_key, &HashAlg::Sha256).unwrap(),
            serial_number: cert.serial_number.clone(),
        };

        let sig_alg_oid = known::ecdsa_with_sha256().to_der_value();
        let der = build_signed_ocsp_response(
            &[(cert_id, OcspCertStatus::Good, 1_763_164_800)],
            &sig_alg_oid,
            &|data: &[u8]| {
                let mut h = hitls_crypto::sha2::Sha256::new();
                h.update(data).unwrap();
                let digest = h.finish().unwrap();
                kp.sign(&digest).unwrap()
            },
        );

        let resp = OcspResponse::from_der(&der).unwrap();
        let status = resp.check_cert(&cert, &cert).unwrap();
        assert_eq!(status, Some(OcspCertStatus::Good));
    }
}
