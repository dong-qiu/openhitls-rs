//! X.509 certificate, CRL, and CSR management.

use hitls_types::PkiError;

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

/// A certificate revocation list (CRL).
#[derive(Debug, Clone)]
pub struct CertificateRevocationList {
    pub raw: Vec<u8>,
    pub issuer: DistinguishedName,
    pub this_update: i64,
    pub next_update: Option<i64>,
    pub revoked_certs: Vec<RevokedCertificate>,
}

/// A revoked certificate entry.
#[derive(Debug, Clone)]
pub struct RevokedCertificate {
    pub serial_number: Vec<u8>,
    pub revocation_date: i64,
}

impl Certificate {
    /// Parse a certificate from DER-encoded bytes.
    pub fn from_der(_data: &[u8]) -> Result<Self, PkiError> {
        todo!("X.509 DER parsing")
    }

    /// Parse a certificate from PEM-encoded string.
    pub fn from_pem(_pem: &str) -> Result<Self, PkiError> {
        todo!("X.509 PEM parsing")
    }

    /// Encode this certificate to DER format.
    pub fn to_der(&self) -> Vec<u8> {
        self.raw.clone()
    }

    /// Verify the certificate signature against an issuer's public key.
    pub fn verify_signature(&self, _issuer: &Certificate) -> Result<bool, PkiError> {
        todo!("certificate signature verification")
    }
}
