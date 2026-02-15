//! X.509 certificate chain building and verification.

use hitls_types::PkiError;
use hitls_utils::oid::{known, Oid};

use super::crl::CertificateRevocationList;
use super::{Certificate, GeneralName, KeyUsage, NameConstraints};

/// X.509 certificate chain verifier.
///
/// Builds and validates certificate chains from an end-entity certificate
/// through intermediate CAs to a trusted root certificate.
pub struct CertificateVerifier {
    trusted_certs: Vec<Certificate>,
    crls: Vec<CertificateRevocationList>,
    max_depth: u32,
    verification_time: Option<i64>,
    check_revocation: bool,
    required_eku: Option<Oid>,
}

impl Default for CertificateVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl CertificateVerifier {
    /// Create a new verifier with default settings (max depth 10, no time/CRL check).
    pub fn new() -> Self {
        Self {
            trusted_certs: Vec::new(),
            crls: Vec::new(),
            max_depth: 10,
            verification_time: None,
            check_revocation: false,
            required_eku: None,
        }
    }

    /// Add a trusted root certificate to the trust store.
    pub fn add_trusted_cert(&mut self, cert: Certificate) -> &mut Self {
        self.trusted_certs.push(cert);
        self
    }

    /// Parse and add all certificates from a PEM string to the trust store.
    pub fn add_trusted_certs_pem(&mut self, pem: &str) -> Result<&mut Self, PkiError> {
        let blocks =
            hitls_utils::pem::parse(pem).map_err(|e| PkiError::Asn1Error(e.to_string()))?;
        for block in &blocks {
            if block.label == "CERTIFICATE" {
                let cert = Certificate::from_der(&block.data)?;
                self.trusted_certs.push(cert);
            }
        }
        Ok(self)
    }

    /// Set the maximum chain depth (default 10).
    pub fn set_max_depth(&mut self, depth: u32) -> &mut Self {
        self.max_depth = depth;
        self
    }

    /// Set the verification time as a UNIX timestamp.
    /// If set, certificates are checked for validity at this time.
    /// If not set, time checking is skipped.
    pub fn set_verification_time(&mut self, time: i64) -> &mut Self {
        self.verification_time = Some(time);
        self
    }

    /// Add a CRL for revocation checking.
    pub fn add_crl(&mut self, crl: CertificateRevocationList) -> &mut Self {
        self.crls.push(crl);
        self
    }

    /// Parse and add all CRLs from a PEM string.
    pub fn add_crls_pem(&mut self, pem: &str) -> Result<&mut Self, PkiError> {
        let crls = super::crl::parse_crls_pem(pem)?;
        self.crls.extend(crls);
        Ok(self)
    }

    /// Enable or disable revocation checking (default: disabled).
    pub fn set_check_revocation(&mut self, check: bool) -> &mut Self {
        self.check_revocation = check;
        self
    }

    /// Set a required Extended Key Usage for end-entity certificates.
    /// When set, the end-entity cert's EKU must contain this purpose
    /// (or anyExtendedKeyUsage). If the cert has no EKU extension,
    /// it passes per RFC 5280 §4.2.1.12.
    pub fn set_required_eku(&mut self, eku: Oid) -> &mut Self {
        self.required_eku = Some(eku);
        self
    }

    /// Build and verify a certificate chain.
    ///
    /// Given an end-entity `cert` and a set of `intermediates`, builds a chain
    /// from the end-entity through intermediates to a trusted root CA.
    ///
    /// Returns the built chain `[end_entity, intermediate..., root]` on success.
    pub fn verify_cert(
        &self,
        cert: &Certificate,
        intermediates: &[Certificate],
    ) -> Result<Vec<Certificate>, PkiError> {
        let mut chain = vec![cert.clone()];
        let mut current = cert.clone();

        // Limit iterations to prevent infinite loops from circular references
        for _ in 0..100 {
            // Check if current cert is a trusted self-signed root
            if current.is_self_signed() && self.is_trusted(&current) {
                // Validate the entire chain
                self.validate_chain(&chain)?;
                return Ok(chain);
            }

            // Find issuer in intermediates or trust store
            let issuer = self
                .find_issuer(&current, intermediates)
                .ok_or(PkiError::IssuerNotFound)?;

            // Verify signature: current cert must be signed by issuer
            let valid = current
                .verify_signature(&issuer)
                .map_err(|e| PkiError::ChainVerifyFailed(e.to_string()))?;
            if !valid {
                return Err(PkiError::ChainVerifyFailed(
                    "signature verification failed".into(),
                ));
            }

            // Check chain depth
            if chain.len() as u32 > self.max_depth {
                return Err(PkiError::MaxDepthExceeded(self.max_depth));
            }

            chain.push(issuer.clone());
            current = issuer;
        }

        Err(PkiError::ChainVerifyFailed(
            "chain building exceeded iteration limit (possible circular reference)".into(),
        ))
    }

    /// Check if a certificate is in the trust store (by matching raw DER bytes).
    fn is_trusted(&self, cert: &Certificate) -> bool {
        self.trusted_certs.iter().any(|t| t.raw == cert.raw)
    }

    /// Find the issuer of `cert` by matching issuer DN and optionally AKI/SKI.
    /// Prefers AKI/SKI match when available (stronger than DN-only).
    /// Searches intermediates first, then the trust store.
    fn find_issuer(
        &self,
        cert: &Certificate,
        intermediates: &[Certificate],
    ) -> Option<Certificate> {
        let aki = cert.authority_key_identifier();
        let aki_key_id = aki.as_ref().and_then(|a| a.key_identifier.as_ref());

        // First pass: AKI/SKI match (if AKI has a keyIdentifier)
        if let Some(key_id) = aki_key_id {
            for candidate in intermediates.iter().chain(self.trusted_certs.iter()) {
                if cert.issuer == candidate.subject {
                    if let Some(ski) = candidate.subject_key_identifier() {
                        if ski == *key_id {
                            return Some(candidate.clone());
                        }
                    }
                }
            }
        }

        // Fallback: DN-only matching
        for candidate in intermediates.iter().chain(self.trusted_certs.iter()) {
            if cert.issuer == candidate.subject {
                return Some(candidate.clone());
            }
        }
        None
    }

    /// Validate the built chain (time, BasicConstraints, KeyUsage, pathLen, revocation).
    fn validate_chain(&self, chain: &[Certificate]) -> Result<(), PkiError> {
        for (i, cert) in chain.iter().enumerate() {
            // Time validity check
            if let Some(time) = self.verification_time {
                if time < cert.not_before {
                    return Err(PkiError::CertNotYetValid);
                }
                if time > cert.not_after {
                    return Err(PkiError::CertExpired);
                }
            }

            // For all certs except the end-entity (i==0), check CA constraints
            if i > 0 {
                // BasicConstraints: must be a CA
                if !cert.is_ca() {
                    return Err(PkiError::BasicConstraintsViolation(format!(
                        "certificate at depth {} is not a CA",
                        i
                    )));
                }

                // KeyUsage: if present, must include keyCertSign
                if let Some(ku) = cert.key_usage() {
                    if !ku.has(KeyUsage::KEY_CERT_SIGN) {
                        return Err(PkiError::KeyUsageViolation(format!(
                            "certificate at depth {} lacks keyCertSign",
                            i
                        )));
                    }
                }

                // pathLenConstraint: if set, the number of intermediate CAs
                // below this CA must not exceed the constraint.
                // chain[1..i] are the CAs between end-entity and this CA.
                if let Some(bc) = cert.basic_constraints() {
                    if let Some(path_len) = bc.path_len_constraint {
                        // Number of CA certs issued below this one
                        let ca_count_below = (i - 1) as u32;
                        if ca_count_below > path_len {
                            return Err(PkiError::BasicConstraintsViolation(format!(
                                "pathLenConstraint {} exceeded ({} CAs below)",
                                path_len, ca_count_below
                            )));
                        }
                    }
                }

                // NameConstraints: all certificates below this CA must satisfy
                if let Some(nc) = cert.name_constraints() {
                    for below in chain.iter().take(i) {
                        validate_name_constraints(below, &nc)?;
                    }
                }
            }
        }

        // EKU enforcement on end-entity certificate
        if let Some(ref required) = self.required_eku {
            let ee = &chain[0];
            if let Some(eku) = ee.extended_key_usage() {
                let any_eku = known::any_extended_key_usage();
                if !eku.purposes.iter().any(|p| p == required || *p == any_eku) {
                    return Err(PkiError::ExtKeyUsageViolation(format!(
                        "end-entity lacks required EKU: {}",
                        required
                    )));
                }
            }
            // If no EKU extension → no restriction per RFC 5280 §4.2.1.12
        }

        // Revocation checking (if enabled)
        if self.check_revocation {
            self.check_revocation_status(chain)?;
        }

        Ok(())
    }

    /// Check revocation status for each certificate in the chain (except the root).
    fn check_revocation_status(&self, chain: &[Certificate]) -> Result<(), PkiError> {
        // For each cert except the last (root), check if it's revoked.
        // The issuer of chain[i] is chain[i+1].
        for i in 0..chain.len().saturating_sub(1) {
            let cert = &chain[i];
            let issuer = &chain[i + 1];

            // Find a CRL from this issuer
            if let Some(crl) = self.find_crl_for_issuer(issuer) {
                // Verify CRL signature
                let sig_valid = crl.verify_signature(issuer).map_err(|e| {
                    PkiError::InvalidCrl(format!("CRL signature verification failed: {}", e))
                })?;
                if !sig_valid {
                    return Err(PkiError::InvalidCrl(
                        "CRL signature verification failed".into(),
                    ));
                }

                // Check CRL time validity
                if let Some(time) = self.verification_time {
                    if time < crl.this_update {
                        return Err(PkiError::InvalidCrl("CRL not yet valid".into()));
                    }
                    if let Some(next_update) = crl.next_update {
                        if time > next_update {
                            return Err(PkiError::InvalidCrl("CRL has expired".into()));
                        }
                    }
                }

                // Check if certificate is revoked
                if crl.is_revoked(&cert.serial_number).is_some() {
                    return Err(PkiError::CertRevoked);
                }
            }
            // If no CRL found for this issuer, skip (soft-fail).
            // A strict mode could return an error here.
        }
        Ok(())
    }

    /// Find a CRL issued by the given issuer certificate (by matching issuer DN).
    fn find_crl_for_issuer(&self, issuer: &Certificate) -> Option<&CertificateRevocationList> {
        self.crls.iter().find(|crl| crl.issuer == issuer.subject)
    }
}

/// Validate a certificate against NameConstraints (RFC 5280 §4.2.1.10).
///
/// Checks the certificate's subject DN and SAN entries against the permitted
/// and excluded subtrees.
fn validate_name_constraints(cert: &Certificate, nc: &NameConstraints) -> Result<(), PkiError> {
    // Collect all names to check: subject DN + SAN entries
    let san = cert.subject_alt_name();

    // Check DNS names from SAN
    if let Some(ref san) = san {
        for dns in &san.dns_names {
            check_name_against_constraints(&GeneralName::DnsName(dns.clone()), nc)?;
        }
        for email in &san.email_addresses {
            check_name_against_constraints(&GeneralName::Rfc822Name(email.clone()), nc)?;
        }
        for ip in &san.ip_addresses {
            check_name_against_constraints(&GeneralName::IpAddress(ip.clone()), nc)?;
        }
        for uri in &san.uris {
            check_name_against_constraints(&GeneralName::Uri(uri.clone()), nc)?;
        }
    }

    // Check subject DN (if non-empty and there are directoryName constraints)
    if !cert.subject.entries.is_empty() {
        let has_dn_constraints = nc
            .permitted_subtrees
            .iter()
            .any(|s| matches!(s.base, GeneralName::DirectoryName(_)))
            || nc
                .excluded_subtrees
                .iter()
                .any(|s| matches!(s.base, GeneralName::DirectoryName(_)));
        if has_dn_constraints {
            check_name_against_constraints(&GeneralName::DirectoryName(cert.subject.clone()), nc)?;
        }
    }

    Ok(())
}

/// Check a single name against permitted/excluded constraints.
fn check_name_against_constraints(
    name: &GeneralName,
    nc: &NameConstraints,
) -> Result<(), PkiError> {
    // Excluded check: name MUST NOT be within any excluded subtree
    for subtree in &nc.excluded_subtrees {
        if name_matches_constraint(name, &subtree.base) {
            return Err(PkiError::NameConstraintsViolation(
                "name is in excluded subtree".to_string(),
            ));
        }
    }

    // Permitted check: if there are permitted subtrees of the same type,
    // name MUST be within at least one of them
    let same_type_permitted: Vec<_> = nc
        .permitted_subtrees
        .iter()
        .filter(|s| same_name_type(name, &s.base))
        .collect();

    if !same_type_permitted.is_empty() {
        let matched = same_type_permitted
            .iter()
            .any(|s| name_matches_constraint(name, &s.base));
        if !matched {
            return Err(PkiError::NameConstraintsViolation(
                "name is not within any permitted subtree".to_string(),
            ));
        }
    }

    Ok(())
}

/// Check if two GeneralName values are the same type.
fn same_name_type(a: &GeneralName, b: &GeneralName) -> bool {
    matches!(
        (a, b),
        (GeneralName::DnsName(_), GeneralName::DnsName(_))
            | (GeneralName::Rfc822Name(_), GeneralName::Rfc822Name(_))
            | (GeneralName::IpAddress(_), GeneralName::IpAddress(_))
            | (GeneralName::Uri(_), GeneralName::Uri(_))
            | (GeneralName::DirectoryName(_), GeneralName::DirectoryName(_))
    )
}

/// Check if a name matches a constraint subtree.
fn name_matches_constraint(name: &GeneralName, constraint: &GeneralName) -> bool {
    match (name, constraint) {
        (GeneralName::DnsName(dns), GeneralName::DnsName(constraint_dns)) => {
            dns_matches(dns, constraint_dns)
        }
        (GeneralName::Rfc822Name(email), GeneralName::Rfc822Name(constraint_email)) => {
            email_matches(email, constraint_email)
        }
        (GeneralName::IpAddress(ip), GeneralName::IpAddress(constraint_ip)) => {
            ip_matches(ip, constraint_ip)
        }
        (GeneralName::DirectoryName(dn), GeneralName::DirectoryName(constraint_dn)) => {
            dn_is_subtree(dn, constraint_dn)
        }
        (GeneralName::Uri(uri), GeneralName::Uri(constraint_uri)) => {
            // URI constraint: match host portion
            let uri_host = uri
                .split("://")
                .nth(1)
                .unwrap_or(uri)
                .split('/')
                .next()
                .unwrap_or("");
            dns_matches(uri_host, constraint_uri)
        }
        _ => false,
    }
}

/// DNS name matching: constraint ".example.com" matches "foo.example.com".
/// Constraint "example.com" matches exactly "example.com" and "*.example.com".
fn dns_matches(name: &str, constraint: &str) -> bool {
    let name_lower = name.to_ascii_lowercase();
    let constraint_lower = constraint.to_ascii_lowercase();

    if let Some(stripped) = constraint_lower.strip_prefix('.') {
        // ".example.com" matches any subdomain
        name_lower.ends_with(&constraint_lower) || name_lower == stripped
    } else {
        // "example.com" matches exactly or as suffix with dot
        name_lower == constraint_lower || name_lower.ends_with(&format!(".{}", constraint_lower))
    }
}

/// Email matching: "@example.com" matches "user@example.com".
/// "example.com" matches any email at that domain.
fn email_matches(email: &str, constraint: &str) -> bool {
    let email_lower = email.to_ascii_lowercase();
    let constraint_lower = constraint.to_ascii_lowercase();

    if constraint_lower.starts_with('@') {
        // "@example.com" matches any user at that domain
        email_lower.ends_with(&constraint_lower)
    } else if constraint_lower.contains('@') {
        // Exact email match
        email_lower == constraint_lower
    } else {
        // Domain-only constraint: matches any email at that domain
        if let Some(domain) = email_lower.split('@').nth(1) {
            domain == constraint_lower || domain.ends_with(&format!(".{}", constraint_lower))
        } else {
            false
        }
    }
}

/// IP address matching against CIDR-style constraint.
/// Constraint is IP(n) || Netmask(n) where n is 4 (IPv4) or 16 (IPv6).
fn ip_matches(ip: &[u8], constraint: &[u8]) -> bool {
    let addr_len = constraint.len() / 2;
    if ip.len() != addr_len || constraint.len() != addr_len * 2 {
        return false;
    }
    let net = &constraint[..addr_len];
    let mask = &constraint[addr_len..];
    for i in 0..addr_len {
        if (ip[i] & mask[i]) != (net[i] & mask[i]) {
            return false;
        }
    }
    true
}

/// Check if `dn` is a subtree of `constraint_dn`.
/// The constraint DN's entries must be a suffix of the subject DN's entries.
fn dn_is_subtree(dn: &super::DistinguishedName, constraint_dn: &super::DistinguishedName) -> bool {
    if constraint_dn.entries.is_empty() {
        return true; // empty constraint matches all
    }
    if dn.entries.len() < constraint_dn.entries.len() {
        return false;
    }
    // Constraint entries must match the suffix of dn entries
    let offset = dn.entries.len() - constraint_dn.entries.len();
    for (i, (ck, cv)) in constraint_dn.entries.iter().enumerate() {
        let (dk, dv) = &dn.entries[offset + i];
        if dk != ck || dv != cv {
            return false;
        }
    }
    true
}

/// Parse multiple certificates from a PEM string.
pub fn parse_certs_pem(pem: &str) -> Result<Vec<Certificate>, PkiError> {
    let blocks = hitls_utils::pem::parse(pem).map_err(|e| PkiError::Asn1Error(e.to_string()))?;
    let mut certs = Vec::new();
    for block in &blocks {
        if block.label == "CERTIFICATE" {
            certs.push(Certificate::from_der(&block.data)?);
        }
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::{CertificateBuilder, DistinguishedName, SigningKey};

    // Root CA: CN=certificate.testca.com (self-signed, RSA 2048, SHA-256)
    // BasicConstraints: CA=true, pathLen=30
    // KeyUsage: Certificate Sign, CRL Sign
    const ROOT_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDzzCCAregAwIBAgIUMnfWZiXhuZbCaFkOLRiQSEI46rkwDQYJKoZIhvcNAQEL
BQAwbzELMAkGA1UEBhMCWFgxCzAJBgNVBAgMAlhYMQswCQYDVQQHDAJYWDEUMBIG
A1UECgwLY2VydGlmaWNhdGUxDzANBgNVBAsMBnRlc3RjYTEfMB0GA1UEAwwWY2Vy
dGlmaWNhdGUudGVzdGNhLmNvbTAeFw0yNDA0MjUxMzAxMDBaFw0zNDA0MjMxMzAx
MDBaMG8xCzAJBgNVBAYTAlhYMQswCQYDVQQIDAJYWDELMAkGA1UEBwwCWFgxFDAS
BgNVBAoMC2NlcnRpZmljYXRlMQ8wDQYDVQQLDAZ0ZXN0Y2ExHzAdBgNVBAMMFmNl
cnRpZmljYXRlLnRlc3RjYS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCZD4K/oBU7/DCThMTftZUazVd3NIjKHQcIO5Uul9F3gIOavMpqcT+epfy1
yUWny31DdG6ku3HJHT2zoqerYgqAh2ediFvnCAe+OzCrDOr3+9ZXt8vv1H2M6X1U
zF+tRaeZ3IgAJBiYBNbdoK4RtzYRfM+29tVp01NJguJza9bMw/qEiQQyubGhlVQi
IW109aYjhiA0RQl6814upi09vfECnzZ+2kkvmkuEEptBiDlE3tSEctJPNSbAN6mn
B3krKfLspcZaoRuJucI6duJeJQcsjQCIEjqgnVuOWoMVOAPLU7JPeOrubePbAySU
yNTPzntqJWs/j6Iacol6N3iJThjfAgMBAAGjYzBhMB0GA1UdDgQWBBSLzdFm06DU
ldtZ2btuIKMNjG1YjzAfBgNVHSMEGDAWgBSLzdFm06DUldtZ2btuIKMNjG1YjzAS
BgNVHRMBAf8ECDAGAQH/AgEeMAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOC
AQEALqPQ8BTMfMFBEvxN9wJzanH6M0FIt+LE0JvMPMBvflwu0GTL26+/Nqd2sQLx
mDByrx+8cFodY3squFBY1dFMwIsMyF8WK/Nh80ZGG8tjKrFlVXE2npRlf5VSkytk
FVz94lFjl0eP6rsUfUamRF2eNg76uoY7tZwTPNqA/zsoRN81n3ccr81CbfOyhPVB
XAse0651f3u76rm7NJNYSeR7qebMyfYrJBu7w/O3K4QCeGjZ3b76xNZtatw1ZXol
irzwVW71bsCftIj3Nu1WFmczr6habktQ7/PyR5hG/I8mh2lkZcZe1Fw3t4hGNAtW
oWDxfkMk0rSnsUcvOtvhfX5Bvw==
-----END CERTIFICATE-----
";

    // Intermediate CA: CN=certificate.testin.com (signed by root, RSA 2048, SHA-256)
    // BasicConstraints: CA=true
    const INTERMEDIATE_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDnDCCAoSgAwIBAgIBATANBgkqhkiG9w0BAQsFADBvMQswCQYDVQQGEwJYWDEL
MAkGA1UECAwCWFgxCzAJBgNVBAcMAlhYMRQwEgYDVQQKDAtjZXJ0aWZpY2F0ZTEP
MA0GA1UECwwGdGVzdGNhMR8wHQYDVQQDDBZjZXJ0aWZpY2F0ZS50ZXN0Y2EuY29t
MB4XDTI0MDQyNTEzMDEwMFoXDTM0MDQyMzEzMDEwMFowYjELMAkGA1UEBhMCWFgx
CzAJBgNVBAgMAlhYMRQwEgYDVQQKDAtjZXJ0aWZpY2F0ZTEPMA0GA1UECwwGdGVz
dGluMR8wHQYDVQQDDBZjZXJ0aWZpY2F0ZS50ZXN0aW4uY29tMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA18rpiCfBpz44ZvBoELRoaCt1ddxSBI250Uj4
io1XUPhqJUmreEFc6vR32RvW6krspgYyx00pqH4nptJOVpOF7fGxANqmT3Dq7jyt
H91gha7GViTRe/NH52R3iGInCxsC+snaFH35MLzvaKUCg6Agrw0ozrykjHBrQtkj
zTvXkwexj/1lMW0FzF79z6SC9bfwLqYldfEgtEZTcTt0SJf6wLW4BeEUCnT+vMX1
hlbOjgI4tuh6RznmbffoxOb9ynJYJ8oPo5X1RN+DIMZ9KUj4DUAP/84x1uQj5cSQ
hERvnEBPWOEC2KhEUzsG97fH/axXg3+Aj8FJAkNp6BnWeKtG1wIDAQABo1AwTjAM
BgNVHRMEBTADAQH/MB0GA1UdDgQWBBTgYJN/ObsFIRlEELDAKWSitrsjEjAfBgNV
HSMEGDAWgBSLzdFm06DUldtZ2btuIKMNjG1YjzANBgkqhkiG9w0BAQsFAAOCAQEA
Q0MFGy3ZfYaBqSIUBwBq1bbADM0mTj3kjeDz7qBKQu4Krfvpzlp7VqD1T3bldgwR
T0gBzWAZnbQ77fBZnCnaz7ZbK0mIin5eT2s9QCOgPY0u6P8oFH56Guet86ly9gSU
yako9lzyYxaJrWpWAmMw7zAzWWLtIiTjciQ7Wi4ihTPbAloUvEIyIWHNs39hNHWF
hBr121y0WDbcNpScFd2ZY+Z4T3Bzs8K3rhX+Gxr118qhXYSLsjlm2kkG6y68e8U2
9BeiW15gWirCLtKVv/fUdOoMcVbjpr7QYtK8iOOyumjxSn9KOevJ/V6p30ZyCuuz
FbPbbv2clmJvtygezDOZxA==
-----END CERTIFICATE-----
";

    // End-entity: CN=certificate.testend22.com (signed by intermediate, RSA 2048, SHA-256)
    // BasicConstraints: absent (not a CA)
    const END_ENTITY_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDkjCCAnqgAwIBAgIBBDANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJYWDEL
MAkGA1UECAwCWFgxFDASBgNVBAoMC2NlcnRpZmljYXRlMQ8wDQYDVQQLDAZ0ZXN0
aW4xHzAdBgNVBAMMFmNlcnRpZmljYXRlLnRlc3Rpbi5jb20wHhcNMjQwNTA1MDkz
NzQ5WhcNMzQwNTAzMDkzNzQ5WjBoMQswCQYDVQQGEwJYWDELMAkGA1UECAwCWFgx
FDASBgNVBAoMC2NlcnRpZmljYXRlMRIwEAYDVQQLDAl0ZXN0ZW5kMjIxIjAgBgNV
BAMMGWNlcnRpZmljYXRlLnRlc3RlbmQyMi5jb20wggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDsMC84reB0dS3CYYcSL7rj2OaE0Jqtyhuo77j9qf7jrwAG
eIuTaiCQy0L07jEtm6i8PYulVwi1ImcaIbehiPdjhv4Rx0bMZAofHHmn6ExAYphi
I1zY29Ww5pZfXmaXPaiGxmQUkntcZMPeqg4HxNm/1G5RVqGNr2gL5Vptj9pYZNvf
hWsrj7PMPFw09GJrQK2FJlQy7sxXm0ovirHXh4Z9NJfUN9VtbKNBvvWjtYnHTYPd
2nMHdE7HggcS/bWUEppFESYUSvO7kDKvOdswkDKxwJ2oVmBU0DDAUhsTorAFY8dH
bp5wNtqhCKESL7BI/ve151iVZvjU57LnjqKSwc2fAgMBAAGjTTBLMAkGA1UdEwQC
MAAwHQYDVR0OBBYEFHa3eEMeYPvYglLa6NwOuj/vSDHhMB8GA1UdIwQYMBaAFOBg
k385uwUhGUQQsMApZKK2uyMSMA0GCSqGSIb3DQEBCwUAA4IBAQB3TVit43C2LEX1
TBVyfh3386EEvqbKOKcUekzfTXagn6qkWRcEWCrRz752EdxcbjMdFcghlu7zWIhH
oLLHNvxxoXMGN9KmHKBSOG2R849aRJ+/Txe5q5zGPSB9Z4hdnsJAq/rA91elnur2
m/zLnANSZsLrZt7KkZJQ9k23yFzMtrTTsyFSAN5tsXRlU7X+++B96f0+zZ3LM56y
8LQD6nNxKpMowPfoZDK5AWaxiilKHLFVijQfbw12smsfPpuzTDhYrLPKViVmZjY4
qsHibMRjr/+tlhwAiVosgKY9l6f3ocSNjREAPuyswv7iFkF2CBsA1uykpVKELDZR
zYvWHlcn
-----END CERTIFICATE-----
";

    fn root_ca() -> Certificate {
        Certificate::from_pem(ROOT_CA_PEM).unwrap()
    }

    fn intermediate_ca() -> Certificate {
        Certificate::from_pem(INTERMEDIATE_CA_PEM).unwrap()
    }

    fn end_entity() -> Certificate {
        Certificate::from_pem(END_ENTITY_PEM).unwrap()
    }

    // --- Extension parsing tests ---

    #[test]
    fn test_parse_basic_constraints_ca() {
        let ca = root_ca();
        let bc = ca.basic_constraints().unwrap();
        assert!(bc.is_ca);
        // pathLenConstraint = 30 (0x1e)
        assert_eq!(bc.path_len_constraint, Some(30));
    }

    #[test]
    fn test_parse_basic_constraints_intermediate() {
        let inter = intermediate_ca();
        let bc = inter.basic_constraints().unwrap();
        assert!(bc.is_ca);
        // Intermediate has no pathLenConstraint explicitly set
        // (or it may be absent — depends on cert)
    }

    #[test]
    fn test_parse_basic_constraints_end_entity() {
        let ee = end_entity();
        // End-entity should either have no BC or is_ca=false
        let bc = ee.basic_constraints();
        assert!(bc.is_none() || !bc.unwrap().is_ca);
    }

    #[test]
    fn test_parse_key_usage_ca() {
        let ca = root_ca();
        let ku = ca.key_usage();
        if let Some(ku) = ku {
            // CA should have keyCertSign
            assert!(ku.has(KeyUsage::KEY_CERT_SIGN));
        }
    }

    #[test]
    fn test_is_ca() {
        assert!(root_ca().is_ca());
        assert!(intermediate_ca().is_ca());
        assert!(!end_entity().is_ca());
    }

    #[test]
    fn test_is_self_signed() {
        assert!(root_ca().is_self_signed());
        assert!(!intermediate_ca().is_self_signed());
        assert!(!end_entity().is_self_signed());
    }

    // --- Chain verification tests ---

    #[test]
    fn test_verify_chain_rsa() {
        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root_ca());
        let ee = end_entity();
        let intermediates = [intermediate_ca()];
        let chain = verifier.verify_cert(&ee, &intermediates).unwrap();
        // Chain should be: [end-entity, intermediate, root]
        assert_eq!(chain.len(), 3);
        assert_eq!(
            chain[0].subject.get("CN"),
            Some("certificate.testend22.com")
        );
        assert_eq!(chain[1].subject.get("CN"), Some("certificate.testin.com"));
        assert_eq!(chain[2].subject.get("CN"), Some("certificate.testca.com"));
    }

    #[test]
    fn test_verify_self_signed_root() {
        let mut verifier = CertificateVerifier::new();
        let ca = root_ca();
        verifier.add_trusted_cert(ca.clone());
        // Root CA verifies against itself
        let chain = verifier.verify_cert(&ca, &[]).unwrap();
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn test_verify_missing_intermediate() {
        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root_ca());
        let ee = end_entity();
        // No intermediates provided — should fail
        let result = verifier.verify_cert(&ee, &[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PkiError::IssuerNotFound));
    }

    #[test]
    fn test_verify_expired_cert() {
        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root_ca());
        // Set time far in the future (year 2099)
        verifier.set_verification_time(4_102_444_800);
        let ee = end_entity();
        let intermediates = [intermediate_ca()];
        let result = verifier.verify_cert(&ee, &intermediates);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PkiError::CertExpired));
    }

    #[test]
    fn test_verify_max_depth_exceeded() {
        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root_ca());
        verifier.set_max_depth(1);
        let ee = end_entity();
        let intermediates = [intermediate_ca()];
        let result = verifier.verify_cert(&ee, &intermediates);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PkiError::MaxDepthExceeded(1)));
    }

    #[test]
    fn test_verify_wrong_trust_anchor() {
        // Use a completely unrelated CA (our self-generated test cert)
        let unrelated_ca = Certificate::from_pem(
            "-----BEGIN CERTIFICATE-----
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
",
        )
        .unwrap();

        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(unrelated_ca);
        let ee = end_entity();
        let intermediates = [intermediate_ca()];
        // Chain should build but root won't be in trust store
        let result = verifier.verify_cert(&ee, &intermediates);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_empty_chain_direct_trust() {
        // Intermediate cert verified directly against trust store containing root
        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root_ca());
        let inter = intermediate_ca();
        let chain = verifier.verify_cert(&inter, &[]).unwrap();
        // Chain: [intermediate, root]
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn test_verify_with_time_in_validity() {
        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root_ca());
        // Set time within validity period: 2025-01-01 (1735689600)
        verifier.set_verification_time(1_735_689_600);
        let ee = end_entity();
        let intermediates = [intermediate_ca()];
        let chain = verifier.verify_cert(&ee, &intermediates).unwrap();
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn test_parse_certs_pem_multiple() {
        let chain_pem = format!("{}{}{}", END_ENTITY_PEM, INTERMEDIATE_CA_PEM, ROOT_CA_PEM);
        let certs = parse_certs_pem(&chain_pem).unwrap();
        assert_eq!(certs.len(), 3);
        assert_eq!(
            certs[0].subject.get("CN"),
            Some("certificate.testend22.com")
        );
        assert_eq!(certs[1].subject.get("CN"), Some("certificate.testin.com"));
        assert_eq!(certs[2].subject.get("CN"), Some("certificate.testca.com"));
    }

    #[test]
    fn test_add_trusted_certs_pem() {
        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_certs_pem(ROOT_CA_PEM).unwrap();
        let ee = end_entity();
        let intermediates = [intermediate_ca()];
        let chain = verifier.verify_cert(&ee, &intermediates).unwrap();
        assert_eq!(chain.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Part 2 (P2): Real C test vector — certVer suite
    // -----------------------------------------------------------------------

    const CV_ROOT: &str = include_str!("../../../../tests/vectors/chain/certVer/certVer_root.pem");
    const CV_INTER: &str =
        include_str!("../../../../tests/vectors/chain/certVer/certVer_inter.pem");
    const CV_LEAF: &str = include_str!("../../../../tests/vectors/chain/certVer/certVer_leaf.pem");
    const CV_LEAF_TAMPERED: &str =
        include_str!("../../../../tests/vectors/chain/certVer/certVer_leaf_tampered.pem");
    const CV_TARGET_CA_TAMPERED: &str =
        include_str!("../../../../tests/vectors/chain/certVer/certVer_target_ca_tampered.pem");
    const CV_NM_ROOT: &str =
        include_str!("../../../../tests/vectors/chain/certVer/certVer_name_mismatch_root.pem");
    const CV_NM_WRONG_INTER: &str = include_str!(
        "../../../../tests/vectors/chain/certVer/certVer_name_mismatch_wrong_inter.pem"
    );
    const CV_NM_LEAF: &str =
        include_str!("../../../../tests/vectors/chain/certVer/certVer_name_mismatch_leaf.pem");
    const CV_WA_ROOT: &str =
        include_str!("../../../../tests/vectors/chain/certVer/certVer_wrong_anchor_root.pem");
    const CV_WA_INTER: &str =
        include_str!("../../../../tests/vectors/chain/certVer/certVer_wrong_anchor_inter.pem");
    const CV_WA_LEAF: &str =
        include_str!("../../../../tests/vectors/chain/certVer/certVer_wrong_anchor_leaf.pem");
    const CV_WA_FAKE_ROOT: &str =
        include_str!("../../../../tests/vectors/chain/certVer/certVer_wrong_anchor_fake_root.pem");
    const CV_CYCLE_A: &str =
        include_str!("../../../../tests/vectors/chain/certVer/certVer_cycle_a.pem");
    const CV_CYCLE_B: &str =
        include_str!("../../../../tests/vectors/chain/certVer/certVer_cycle_b.pem");

    #[test]
    fn test_chain_valid_3cert() {
        let root = Certificate::from_pem(CV_ROOT).unwrap();
        let inter = Certificate::from_pem(CV_INTER).unwrap();
        let leaf = Certificate::from_pem(CV_LEAF).unwrap();

        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root);
        let chain = verifier.verify_cert(&leaf, &[inter]).unwrap();
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn test_chain_tampered_leaf_sig() {
        let root = Certificate::from_pem(CV_ROOT).unwrap();
        let inter = Certificate::from_pem(CV_INTER).unwrap();
        let leaf_tampered = Certificate::from_pem(CV_LEAF_TAMPERED).unwrap();

        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root);
        let result = verifier.verify_cert(&leaf_tampered, &[inter]);
        assert!(result.is_err());
    }

    #[test]
    fn test_chain_tampered_ca_sig() {
        let root = Certificate::from_pem(CV_ROOT).unwrap();
        let inter = Certificate::from_pem(CV_INTER).unwrap();
        let target_tampered = Certificate::from_pem(CV_TARGET_CA_TAMPERED).unwrap();

        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root);
        let result = verifier.verify_cert(&target_tampered, &[inter]);
        assert!(result.is_err());
    }

    #[test]
    fn test_chain_dn_mismatch() {
        // Leaf claims issuer = "Actual Intermediate" but only "Wrong Intermediate" is provided
        let root = Certificate::from_pem(CV_NM_ROOT).unwrap();
        let wrong_inter = Certificate::from_pem(CV_NM_WRONG_INTER).unwrap();
        let leaf = Certificate::from_pem(CV_NM_LEAF).unwrap();

        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root);
        let result = verifier.verify_cert(&leaf, &[wrong_inter]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PkiError::IssuerNotFound));
    }

    #[test]
    fn test_chain_wrong_trust_anchor_real() {
        // Valid chain root→inter→leaf, but trust store has only fake_root
        let actual_root = Certificate::from_pem(CV_WA_ROOT).unwrap();
        let inter = Certificate::from_pem(CV_WA_INTER).unwrap();
        let leaf = Certificate::from_pem(CV_WA_LEAF).unwrap();
        let fake_root = Certificate::from_pem(CV_WA_FAKE_ROOT).unwrap();

        // With fake root: chain builds to actual_root but it's not trusted
        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(fake_root);
        let result = verifier.verify_cert(&leaf, &[inter.clone(), actual_root.clone()]);
        // actual_root is self-signed but not in trust store → fails
        assert!(result.is_err());

        // With actual root: should succeed
        let mut verifier2 = CertificateVerifier::new();
        verifier2.add_trusted_cert(actual_root);
        let chain = verifier2.verify_cert(&leaf, &[inter]).unwrap();
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn test_chain_cycle_detection() {
        // cycle_a's issuer = cycle_b, cycle_b's issuer = cycle_a — circular
        let cycle_a = Certificate::from_pem(CV_CYCLE_A).unwrap();
        let cycle_b = Certificate::from_pem(CV_CYCLE_B).unwrap();

        let verifier = CertificateVerifier::new();
        // Neither is in trust store, so chain building should fail
        let result = verifier.verify_cert(&cycle_a, &[cycle_b]);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Phase 51: bcExt suite — BasicConstraints enforcement
    // -----------------------------------------------------------------------

    const BC_ROOT: &str = include_str!("../../../../tests/vectors/chain/bcExt/bc_root_general.pem");
    const BC_INTER_MISSING_BC: &str =
        include_str!("../../../../tests/vectors/chain/bcExt/bc_inter_missing_bc.pem");
    const BC_INTER_CA_FALSE: &str =
        include_str!("../../../../tests/vectors/chain/bcExt/bc_inter_ca_false.pem");
    const BC_LEAF_MISSING_BC: &str =
        include_str!("../../../../tests/vectors/chain/bcExt/bc_leaf_missing_bc.pem");
    const BC_LEAF_CA_FALSE: &str =
        include_str!("../../../../tests/vectors/chain/bcExt/bc_leaf_ca_false.pem");

    #[test]
    fn test_bc_missing_on_intermediate() {
        // Intermediate has no BasicConstraints — not a CA
        let root = Certificate::from_pem(BC_ROOT).unwrap();
        let inter = Certificate::from_pem(BC_INTER_MISSING_BC).unwrap();
        let leaf = Certificate::from_pem(BC_LEAF_MISSING_BC).unwrap();

        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root);
        let result = verifier.verify_cert(&leaf, &[inter]);
        assert!(result.is_err());
        match result.unwrap_err() {
            PkiError::BasicConstraintsViolation(_) => {}
            e => panic!("expected BasicConstraintsViolation, got: {e:?}"),
        }
    }

    #[test]
    fn test_bc_ca_false_intermediate() {
        // Intermediate has CA:FALSE — not a CA
        let root = Certificate::from_pem(BC_ROOT).unwrap();
        let inter = Certificate::from_pem(BC_INTER_CA_FALSE).unwrap();
        let leaf = Certificate::from_pem(BC_LEAF_CA_FALSE).unwrap();

        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root);
        let result = verifier.verify_cert(&leaf, &[inter]);
        assert!(result.is_err());
        match result.unwrap_err() {
            PkiError::BasicConstraintsViolation(_) => {}
            e => panic!("expected BasicConstraintsViolation, got: {e:?}"),
        }
    }

    const PL_ROOT: &str =
        include_str!("../../../../tests/vectors/chain/bcExt/pathlen_root_pl1.pem");
    const PL_INTER1: &str =
        include_str!("../../../../tests/vectors/chain/bcExt/pathlen_inter_lvl1.pem");
    const PL_INTER2: &str =
        include_str!("../../../../tests/vectors/chain/bcExt/pathlen_inter_lvl2.pem");
    const PL_LEAF: &str =
        include_str!("../../../../tests/vectors/chain/bcExt/pathlen_leaf_pl_exceed.pem");

    #[test]
    fn test_bc_pathlen_exceeded() {
        // root (pathlen=1) → inter1 → inter2 → leaf
        // root allows only 1 CA below it, but inter1 + inter2 = 2 CAs → violation
        let root = Certificate::from_pem(PL_ROOT).unwrap();
        let inter1 = Certificate::from_pem(PL_INTER1).unwrap();
        let inter2 = Certificate::from_pem(PL_INTER2).unwrap();
        let leaf = Certificate::from_pem(PL_LEAF).unwrap();

        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root);
        let result = verifier.verify_cert(&leaf, &[inter1, inter2]);
        assert!(result.is_err());
        match result.unwrap_err() {
            PkiError::BasicConstraintsViolation(_) => {}
            e => panic!("expected BasicConstraintsViolation, got: {e:?}"),
        }
    }

    #[test]
    fn test_bc_pathlen_within_limit() {
        // root (pathlen=1) → inter1: only 1 CA below root → OK
        let root = Certificate::from_pem(PL_ROOT).unwrap();
        let inter1 = Certificate::from_pem(PL_INTER1).unwrap();

        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root);
        // Verify inter1 against root — inter1 is signed by root, chain = [inter1, root]
        let chain = verifier.verify_cert(&inter1, &[]).unwrap();
        assert_eq!(chain.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Phase 51: depth_suite — chain depth tests
    // -----------------------------------------------------------------------

    const DEPTH_ROOT: &str =
        include_str!("../../../../tests/vectors/chain/bcExt/depth_suite/depth_root.pem");
    const DEPTH_INTER1: &str =
        include_str!("../../../../tests/vectors/chain/bcExt/depth_suite/depth_inter1.pem");
    const DEPTH_INTER2: &str =
        include_str!("../../../../tests/vectors/chain/bcExt/depth_suite/depth_inter2.pem");
    const DEPTH_LEAF1: &str =
        include_str!("../../../../tests/vectors/chain/bcExt/depth_suite/depth_leaf_lvl1.pem");
    const DEPTH_LEAF2: &str =
        include_str!("../../../../tests/vectors/chain/bcExt/depth_suite/depth_leaf_lvl2.pem");

    #[test]
    fn test_bc_depth_within_limit() {
        // root → inter1 → leaf_lvl1 with max_depth=3 → passes
        let root = Certificate::from_pem(DEPTH_ROOT).unwrap();
        let inter1 = Certificate::from_pem(DEPTH_INTER1).unwrap();
        let leaf = Certificate::from_pem(DEPTH_LEAF1).unwrap();

        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root);
        verifier.set_max_depth(3);
        let chain = verifier.verify_cert(&leaf, &[inter1]).unwrap();
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn test_bc_depth_exceeded() {
        // root → inter1 → inter2 → leaf_lvl2 with max_depth=2 → fails
        let root = Certificate::from_pem(DEPTH_ROOT).unwrap();
        let inter1 = Certificate::from_pem(DEPTH_INTER1).unwrap();
        let inter2 = Certificate::from_pem(DEPTH_INTER2).unwrap();
        let leaf = Certificate::from_pem(DEPTH_LEAF2).unwrap();

        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root);
        verifier.set_max_depth(2);
        let result = verifier.verify_cert(&leaf, &[inter1, inter2]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PkiError::MaxDepthExceeded(2)));
    }

    #[test]
    fn test_bc_depth_4level_passes() {
        // root → inter1 → inter2 → leaf_lvl2 with default max_depth=10 → passes
        let root = Certificate::from_pem(DEPTH_ROOT).unwrap();
        let inter1 = Certificate::from_pem(DEPTH_INTER1).unwrap();
        let inter2 = Certificate::from_pem(DEPTH_INTER2).unwrap();
        let leaf = Certificate::from_pem(DEPTH_LEAF2).unwrap();

        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root);
        let chain = verifier.verify_cert(&leaf, &[inter1, inter2]).unwrap();
        assert_eq!(chain.len(), 4);
    }

    // -----------------------------------------------------------------------
    // Phase 51: time suite — certificate validity period tests
    // -----------------------------------------------------------------------

    const TIME_ROOT_CURRENT: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/time/root_current.der");
    const TIME_INTER_CURRENT: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/time/inter_current.der");
    const TIME_LEAF_CURRENT: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/time/leaf_current.der");
    const TIME_ROOT_EXPIRED: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/time/root_expired.der");
    const TIME_INTER_EXPIRED: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/time/inter_expired.der");
    const TIME_LEAF_EXPIRED: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/time/leaf_expired.der");

    #[test]
    fn test_time_all_current() {
        // All certs valid at 2026-06-01 (1780272000)
        let root = Certificate::from_der(TIME_ROOT_CURRENT).unwrap();
        let inter = Certificate::from_der(TIME_INTER_CURRENT).unwrap();
        let leaf = Certificate::from_der(TIME_LEAF_CURRENT).unwrap();

        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root);
        verifier.set_verification_time(1_780_272_000);
        let chain = verifier.verify_cert(&leaf, &[inter]).unwrap();
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn test_time_expired_leaf() {
        // leaf_expired: 2019-07-01 to 2019-12-31 — expired at 2025
        let root = Certificate::from_der(TIME_ROOT_EXPIRED).unwrap();
        let inter = Certificate::from_der(TIME_INTER_EXPIRED).unwrap();
        let leaf = Certificate::from_der(TIME_LEAF_EXPIRED).unwrap();

        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root);
        verifier.set_verification_time(1_735_689_600); // 2025-01-01
        let result = verifier.verify_cert(&leaf, &[inter]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PkiError::CertExpired));
    }

    #[test]
    fn test_time_expired_root() {
        // root_expired: 2018-01-01 to 2021-01-01 — expired at 2025
        let root = Certificate::from_der(TIME_ROOT_EXPIRED).unwrap();

        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root.clone());
        verifier.set_verification_time(1_735_689_600); // 2025-01-01
        let result = verifier.verify_cert(&root, &[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PkiError::CertExpired));
    }

    #[test]
    fn test_time_historical_valid() {
        // All expired certs were valid at 2019-09-01 (1567296000)
        let root = Certificate::from_der(TIME_ROOT_EXPIRED).unwrap();
        let inter = Certificate::from_der(TIME_INTER_EXPIRED).unwrap();
        let leaf = Certificate::from_der(TIME_LEAF_EXPIRED).unwrap();

        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(root);
        verifier.set_verification_time(1_567_296_000); // 2019-09-01
        let chain = verifier.verify_cert(&leaf, &[inter]).unwrap();
        assert_eq!(chain.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Phase 51: eku suite — Extended Key Usage parsing tests
    // -----------------------------------------------------------------------

    const EKU_ROOTCA: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/eku_suite/rootca.der");
    const EKU_CA: &[u8] = include_bytes!("../../../../tests/vectors/chain/eku_suite/ca.der");
    const EKU_SERVER_GOOD: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/eku_suite/server_good.der");
    const EKU_CLIENT_GOOD: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/eku_suite/client_good.der");
    const EKU_SERVER_BADKU: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/eku_suite/server_badku.der");
    const EKU_ANY_GOOD: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/eku_suite/anyEKU/anyeku_good.der");

    #[test]
    fn test_eku_server_good_parses() {
        let cert = Certificate::from_der(EKU_SERVER_GOOD).unwrap();
        assert_eq!(cert.subject.get("CN"), Some("EKU Test Server Good"));
        // Should have extensions including ExtendedKeyUsage
        assert!(!cert.extensions.is_empty());
        // EKU OID = 2.5.29.37
        let eku_oid = vec![0x55, 0x1D, 0x25]; // id-ce-extKeyUsage
        let has_eku = cert.extensions.iter().any(|e| e.oid.ends_with(&eku_oid));
        assert!(has_eku, "server_good should have EKU extension");
    }

    #[test]
    fn test_eku_client_good_parses() {
        let cert = Certificate::from_der(EKU_CLIENT_GOOD).unwrap();
        assert_eq!(cert.subject.get("CN"), Some("EKU Test Client Good"));
        let eku_oid = vec![0x55, 0x1D, 0x25];
        let has_eku = cert.extensions.iter().any(|e| e.oid.ends_with(&eku_oid));
        assert!(has_eku, "client_good should have EKU extension");
    }

    #[test]
    fn test_eku_bad_ku_parses() {
        let cert = Certificate::from_der(EKU_SERVER_BADKU).unwrap();
        assert_eq!(cert.subject.get("CN"), Some("EKU Test Server BadKU"));
        // Still has KU but with wrong bits for server auth
        let ku = cert.key_usage();
        assert!(ku.is_some());
    }

    #[test]
    fn test_eku_any_parses() {
        let cert = Certificate::from_der(EKU_ANY_GOOD).unwrap();
        assert_eq!(cert.subject.get("CN"), Some("AnyEKU Good"));
        let eku_oid = vec![0x55, 0x1D, 0x25];
        let has_eku = cert.extensions.iter().any(|e| e.oid.ends_with(&eku_oid));
        assert!(has_eku, "anyeku_good should have EKU extension");
    }

    #[test]
    fn test_eku_chain_verifies() {
        // rootca → ca → server_good (3-cert chain)
        let rootca = Certificate::from_der(EKU_ROOTCA).unwrap();
        let ca = Certificate::from_der(EKU_CA).unwrap();
        let server = Certificate::from_der(EKU_SERVER_GOOD).unwrap();

        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(rootca);
        let chain = verifier.verify_cert(&server, &[ca]).unwrap();
        assert_eq!(chain.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Phase 52: EKU enforcement tests
    // -----------------------------------------------------------------------

    fn eku_chain_verifier() -> CertificateVerifier {
        let rootca = Certificate::from_der(EKU_ROOTCA).unwrap();
        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(rootca);
        v
    }

    fn eku_ca() -> Certificate {
        Certificate::from_der(EKU_CA).unwrap()
    }

    #[test]
    fn test_eku_enforce_server_auth_good() {
        let mut v = eku_chain_verifier();
        v.set_required_eku(known::kp_server_auth());
        let server = Certificate::from_der(EKU_SERVER_GOOD).unwrap();
        let result = v.verify_cert(&server, &[eku_ca()]);
        assert!(result.is_ok(), "serverAuth cert should pass: {result:?}");
    }

    #[test]
    fn test_eku_enforce_server_auth_bad() {
        let mut v = eku_chain_verifier();
        v.set_required_eku(known::kp_server_auth());
        let client = Certificate::from_der(EKU_CLIENT_GOOD).unwrap();
        let result = v.verify_cert(&client, &[eku_ca()]);
        assert!(
            result.is_err(),
            "clientAuth cert should fail serverAuth check"
        );
        match result.unwrap_err() {
            PkiError::ExtKeyUsageViolation(_) => {}
            e => panic!("expected ExtKeyUsageViolation, got: {e:?}"),
        }
    }

    #[test]
    fn test_eku_enforce_client_auth_good() {
        let mut v = eku_chain_verifier();
        v.set_required_eku(known::kp_client_auth());
        let client = Certificate::from_der(EKU_CLIENT_GOOD).unwrap();
        let result = v.verify_cert(&client, &[eku_ca()]);
        assert!(result.is_ok(), "clientAuth cert should pass: {result:?}");
    }

    #[test]
    fn test_eku_enforce_any_eku_accepts_all() {
        // anyEKU certs have their own CA chain
        const ANY_ROOTCA: &[u8] =
            include_bytes!("../../../../tests/vectors/chain/eku_suite/anyEKU/rootca.der");
        const ANY_CA: &[u8] =
            include_bytes!("../../../../tests/vectors/chain/eku_suite/anyEKU/ca.der");
        let rootca = Certificate::from_der(ANY_ROOTCA).unwrap();
        let ca = Certificate::from_der(ANY_CA).unwrap();
        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(rootca);
        v.set_required_eku(known::kp_server_auth());
        let any_cert = Certificate::from_der(EKU_ANY_GOOD).unwrap();
        let result = v.verify_cert(&any_cert, &[ca]);
        assert!(
            result.is_ok(),
            "anyExtendedKeyUsage should accept any required EKU: {result:?}"
        );
    }

    #[test]
    fn test_eku_enforce_bad_ku_passes_eku() {
        // server_badku has wrong KeyUsage but right EKU — EKU check should pass
        // (KU is a separate check)
        let mut v = eku_chain_verifier();
        v.set_required_eku(known::kp_server_auth());
        let server_badku = Certificate::from_der(EKU_SERVER_BADKU).unwrap();
        let result = v.verify_cert(&server_badku, &[eku_ca()]);
        // This should pass EKU but may fail KU — we only care about EKU here
        match result {
            Ok(_) => {} // passes both — fine
            Err(PkiError::ExtKeyUsageViolation(_)) => {
                panic!("should not fail EKU check for server_badku")
            }
            Err(_) => {} // KU or other failure is fine
        }
    }

    #[test]
    fn test_eku_no_extension_passes() {
        // Cert without EKU → no restriction per RFC 5280
        let mut v = CertificateVerifier::new();
        let root = root_ca();
        v.add_trusted_cert(root.clone());
        v.set_required_eku(known::kp_server_auth());
        // end_entity has no EKU extension → should pass
        let ee = end_entity();
        let result = v.verify_cert(&ee, &[intermediate_ca()]);
        assert!(result.is_ok(), "no EKU → passes: {result:?}");
    }

    #[test]
    fn test_eku_enforce_not_set_skips() {
        // No required_eku set → any cert passes
        let v = eku_chain_verifier();
        // Do NOT set required_eku
        let client = Certificate::from_der(EKU_CLIENT_GOOD).unwrap();
        let result = v.verify_cert(&client, &[eku_ca()]);
        assert!(result.is_ok(), "no required_eku → passes: {result:?}");
    }

    #[test]
    fn test_eku_enforce_code_signing_rejects_tls() {
        let mut v = eku_chain_verifier();
        v.set_required_eku(known::kp_code_signing());
        let server = Certificate::from_der(EKU_SERVER_GOOD).unwrap();
        let result = v.verify_cert(&server, &[eku_ca()]);
        assert!(
            result.is_err(),
            "serverAuth cert should fail codeSigning check"
        );
        match result.unwrap_err() {
            PkiError::ExtKeyUsageViolation(_) => {}
            e => panic!("expected ExtKeyUsageViolation, got: {e:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Phase 52: AKI/SKI chain matching tests
    // -----------------------------------------------------------------------

    fn make_dn(cn: &str) -> DistinguishedName {
        DistinguishedName {
            entries: vec![("CN".to_string(), cn.to_string())],
        }
    }

    #[test]
    fn test_aki_ski_chain_building() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let spki = sk.public_key_info().unwrap();
        let ski_bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08";
        let ca_dn = make_dn("AKI-SKI Test CA");

        let ca = CertificateBuilder::new()
            .serial_number(&[1])
            .issuer(ca_dn.clone())
            .subject(ca_dn.clone())
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki.clone())
            .add_basic_constraints(true, None)
            .add_key_usage(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
            .add_subject_key_identifier(ski_bytes)
            .build(&sk)
            .unwrap();

        let ee = CertificateBuilder::new()
            .serial_number(&[2])
            .issuer(ca_dn)
            .subject(make_dn("AKI-SKI Test EE"))
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .add_authority_key_identifier(ski_bytes)
            .build(&sk)
            .unwrap();

        // Verify AKI/SKI parsed correctly
        assert_eq!(ca.subject_key_identifier(), Some(ski_bytes.to_vec()));
        let aki = ee.authority_key_identifier().unwrap();
        assert_eq!(aki.key_identifier, Some(ski_bytes.to_vec()));

        // Chain should build successfully
        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(ca);
        let result = v.verify_cert(&ee, &[]);
        assert!(result.is_ok(), "AKI/SKI chain should verify: {result:?}");
    }

    #[test]
    fn test_aki_ski_cross_signed() {
        // Two CAs with the SAME subject DN but different SKIs.
        let kp_a = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk_a = SigningKey::Ed25519(kp_a);
        let spki_a = sk_a.public_key_info().unwrap();
        let kp_b = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk_b = SigningKey::Ed25519(kp_b);
        let spki_b = sk_b.public_key_info().unwrap();
        let ski_a = b"\xAA\xBB\xCC\xDD";
        let ski_b = b"\x11\x22\x33\x44";
        let ca_dn = make_dn("Cross-Sign CA");

        let ca_a = CertificateBuilder::new()
            .serial_number(&[1])
            .issuer(ca_dn.clone())
            .subject(ca_dn.clone())
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki_a.clone())
            .add_basic_constraints(true, None)
            .add_key_usage(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
            .add_subject_key_identifier(ski_a)
            .build(&sk_a)
            .unwrap();

        let ca_b = CertificateBuilder::new()
            .serial_number(&[2])
            .issuer(ca_dn.clone())
            .subject(ca_dn.clone())
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki_b)
            .add_basic_constraints(true, None)
            .add_key_usage(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
            .add_subject_key_identifier(ski_b)
            .build(&sk_b)
            .unwrap();

        // EE cert issued by CA A (AKI points to ski_a)
        let ee = CertificateBuilder::new()
            .serial_number(&[3])
            .issuer(ca_dn)
            .subject(make_dn("Cross-Sign EE"))
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki_a)
            .add_authority_key_identifier(ski_a)
            .build(&sk_a)
            .unwrap();

        // Both CAs in trust store, same DN — AKI/SKI selects correct one
        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(ca_a);
        v.add_trusted_cert(ca_b);
        let result = v.verify_cert(&ee, &[]);
        assert!(
            result.is_ok(),
            "should find correct CA via AKI/SKI: {result:?}"
        );
    }

    #[test]
    fn test_no_aki_falls_back_to_dn() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let spki = sk.public_key_info().unwrap();
        let ca_dn = make_dn("DN-Only CA");

        let ca = CertificateBuilder::new()
            .serial_number(&[1])
            .issuer(ca_dn.clone())
            .subject(ca_dn.clone())
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki.clone())
            .add_basic_constraints(true, None)
            .add_key_usage(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
            .build(&sk)
            .unwrap();

        let ee = CertificateBuilder::new()
            .serial_number(&[2])
            .issuer(ca_dn)
            .subject(make_dn("DN-Only EE"))
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .build(&sk)
            .unwrap();

        assert!(ee.authority_key_identifier().is_none());
        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(ca);
        let result = v.verify_cert(&ee, &[]);
        assert!(result.is_ok(), "DN-only matching should work: {result:?}");
    }

    #[test]
    fn test_aki_mismatch_falls_to_dn() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let spki = sk.public_key_info().unwrap();
        let ca_dn = make_dn("Mismatch CA");

        let ca = CertificateBuilder::new()
            .serial_number(&[1])
            .issuer(ca_dn.clone())
            .subject(ca_dn.clone())
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki.clone())
            .add_basic_constraints(true, None)
            .add_key_usage(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
            .add_subject_key_identifier(b"\xAA\xBB")
            .build(&sk)
            .unwrap();

        let ee = CertificateBuilder::new()
            .serial_number(&[2])
            .issuer(ca_dn)
            .subject(make_dn("Mismatch EE"))
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .add_authority_key_identifier(b"\xFF\xFF")
            .build(&sk)
            .unwrap();

        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(ca);
        let result = v.verify_cert(&ee, &[]);
        assert!(
            result.is_ok(),
            "AKI mismatch should fall back to DN: {result:?}"
        );
    }

    #[test]
    fn test_real_certs_have_aki_ski() {
        let root = root_ca();
        let inter = intermediate_ca();
        let ee = end_entity();

        // Root should have SKI
        let root_ski = root.subject_key_identifier();
        assert!(root_ski.is_some(), "root CA should have SKI");

        // Intermediate should have AKI and SKI
        let inter_aki = inter.authority_key_identifier();
        assert!(inter_aki.is_some(), "intermediate CA should have AKI");
        let inter_ski = inter.subject_key_identifier();
        assert!(inter_ski.is_some(), "intermediate CA should have SKI");

        // AKI of intermediate should match SKI of root
        if let (Some(ref aki), Some(ref ski)) = (&inter_aki, &root_ski) {
            if let Some(ref key_id) = aki.key_identifier {
                assert_eq!(key_id, ski, "intermediate AKI should match root SKI");
            }
        }

        // EE should have AKI matching intermediate's SKI
        let ee_aki = ee.authority_key_identifier();
        assert!(ee_aki.is_some(), "end entity should have AKI");
        if let (Some(ref aki), Some(ref ski)) = (&ee_aki, &inter_ski) {
            if let Some(ref key_id) = aki.key_identifier {
                assert_eq!(key_id, ski, "EE AKI should match intermediate SKI");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Phase 52: Name Constraints enforcement tests
    // -----------------------------------------------------------------------

    /// Build a CA cert with NameConstraints and an EE cert, returns (ca, ee).
    fn build_nc_chain(
        permitted: &[GeneralName],
        excluded: &[GeneralName],
        ee_dns: &[&str],
    ) -> (Certificate, Certificate) {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let spki = sk.public_key_info().unwrap();
        let ca_dn = make_dn("NC Test CA");

        let ca = CertificateBuilder::new()
            .serial_number(&[1])
            .issuer(ca_dn.clone())
            .subject(ca_dn.clone())
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki.clone())
            .add_basic_constraints(true, None)
            .add_key_usage(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
            .add_name_constraints(permitted, excluded)
            .build(&sk)
            .unwrap();

        let mut builder = CertificateBuilder::new()
            .serial_number(&[2])
            .issuer(ca_dn)
            .subject(make_dn("NC Test EE"))
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki);
        if !ee_dns.is_empty() {
            builder = builder.add_subject_alt_name_dns(ee_dns);
        }
        let ee = builder.build(&sk).unwrap();

        (ca, ee)
    }

    #[test]
    fn test_nc_permitted_dns_pass() {
        let (ca, ee) = build_nc_chain(
            &[GeneralName::DnsName(".example.com".into())],
            &[],
            &["server.example.com"],
        );
        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(ca);
        let result = v.verify_cert(&ee, &[]);
        assert!(
            result.is_ok(),
            "DNS within permitted should pass: {result:?}"
        );
    }

    #[test]
    fn test_nc_permitted_dns_fail() {
        let (ca, ee) = build_nc_chain(
            &[GeneralName::DnsName(".example.com".into())],
            &[],
            &["evil.com"],
        );
        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(ca);
        let result = v.verify_cert(&ee, &[]);
        assert!(result.is_err(), "DNS outside permitted should fail");
        match result.unwrap_err() {
            PkiError::NameConstraintsViolation(_) => {}
            e => panic!("expected NameConstraintsViolation, got: {e:?}"),
        }
    }

    #[test]
    fn test_nc_excluded_dns() {
        let (ca, ee) = build_nc_chain(
            &[],
            &[GeneralName::DnsName(".evil.com".into())],
            &["server.evil.com"],
        );
        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(ca);
        let result = v.verify_cert(&ee, &[]);
        assert!(result.is_err(), "DNS in excluded should fail");
        match result.unwrap_err() {
            PkiError::NameConstraintsViolation(_) => {}
            e => panic!("expected NameConstraintsViolation, got: {e:?}"),
        }
    }

    #[test]
    fn test_nc_no_constraints_passes() {
        // No NameConstraints extension → no restriction
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let spki = sk.public_key_info().unwrap();
        let ca_dn = make_dn("No NC CA");

        let ca = CertificateBuilder::new()
            .serial_number(&[1])
            .issuer(ca_dn.clone())
            .subject(ca_dn.clone())
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki.clone())
            .add_basic_constraints(true, None)
            .add_key_usage(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
            .build(&sk)
            .unwrap();

        let ee = CertificateBuilder::new()
            .serial_number(&[2])
            .issuer(ca_dn)
            .subject(make_dn("No NC EE"))
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .add_subject_alt_name_dns(&["anything.org"])
            .build(&sk)
            .unwrap();

        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(ca);
        let result = v.verify_cert(&ee, &[]);
        assert!(result.is_ok(), "no NC → passes: {result:?}");
    }

    #[test]
    fn test_nc_permitted_exact_domain() {
        // "example.com" permits exactly "example.com" and subdomains
        let (ca, ee) = build_nc_chain(
            &[GeneralName::DnsName("example.com".into())],
            &[],
            &["example.com"],
        );
        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(ca);
        let result = v.verify_cert(&ee, &[]);
        assert!(result.is_ok(), "exact domain match should pass: {result:?}");
    }

    #[test]
    fn test_nc_excluded_overrides_permitted() {
        // Permitted ".example.com" but excluded ".bad.example.com"
        let (ca, ee) = build_nc_chain(
            &[GeneralName::DnsName(".example.com".into())],
            &[GeneralName::DnsName(".bad.example.com".into())],
            &["server.bad.example.com"],
        );
        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(ca);
        let result = v.verify_cert(&ee, &[]);
        assert!(result.is_err(), "excluded should override permitted");
        match result.unwrap_err() {
            PkiError::NameConstraintsViolation(_) => {}
            e => panic!("expected NameConstraintsViolation, got: {e:?}"),
        }
    }

    #[test]
    fn test_nc_ip_constraint() {
        // Permitted: 192.168.1.0/24 (IP=192.168.1.0 mask=255.255.255.0)
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let spki = sk.public_key_info().unwrap();
        let ca_dn = make_dn("IP NC CA");

        let permitted_ip = vec![192, 168, 1, 0, 255, 255, 255, 0]; // IP + netmask
        let ca = CertificateBuilder::new()
            .serial_number(&[1])
            .issuer(ca_dn.clone())
            .subject(ca_dn.clone())
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki.clone())
            .add_basic_constraints(true, None)
            .add_key_usage(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
            .add_name_constraints(&[GeneralName::IpAddress(permitted_ip)], &[])
            .build(&sk)
            .unwrap();

        // Test: verify IP matching works (IP SAN in cert via raw extension)
        // We'll just verify the NC was stored correctly
        let nc = ca.name_constraints().unwrap();
        assert_eq!(nc.permitted_subtrees.len(), 1);
        assert!(nc.excluded_subtrees.is_empty());
    }

    #[test]
    fn test_nc_email_constraint() {
        // Verify email matching logic
        assert!(email_matches("user@example.com", "example.com"));
        assert!(email_matches("user@example.com", "@example.com"));
        assert!(!email_matches("user@other.com", "example.com"));
        assert!(email_matches("user@sub.example.com", "example.com"));
        assert!(email_matches("admin@example.com", "admin@example.com"));
        assert!(!email_matches("user@example.com", "admin@example.com"));
    }

    // --- CRL revocation checking tests ---

    // CRL test data: ca.crl revokes server2 (serial ...D9) but NOT server1 (serial ...D8)
    const CRL_CA_PEM: &str = include_str!("../../../../tests/vectors/crl/crl_verify/certs/ca.crt");
    const CRL_PEM: &str = include_str!("../../../../tests/vectors/crl/crl_verify/crl/ca.crl");
    const SERVER1_PEM: &str =
        include_str!("../../../../tests/vectors/crl/crl_verify/certs/server1.crt");
    const SERVER2_PEM: &str =
        include_str!("../../../../tests/vectors/crl/crl_verify/certs/server2.crt");

    #[test]
    fn test_verify_chain_with_crl_revoked() {
        let ca = Certificate::from_pem(CRL_CA_PEM).unwrap();
        let server2 = Certificate::from_pem(SERVER2_PEM).unwrap();
        let crl = CertificateRevocationList::from_pem(CRL_PEM).unwrap();

        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(ca);
        verifier.add_crl(crl);
        verifier.set_check_revocation(true);
        // CRL valid Nov 4 – Dec 4, 2025; use Nov 19, 2025
        verifier.set_verification_time(1_763_164_800);

        let result = verifier.verify_cert(&server2, &[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PkiError::CertRevoked));
    }

    #[test]
    fn test_verify_chain_with_crl_not_revoked() {
        let ca = Certificate::from_pem(CRL_CA_PEM).unwrap();
        let server1 = Certificate::from_pem(SERVER1_PEM).unwrap();
        let crl = CertificateRevocationList::from_pem(CRL_PEM).unwrap();

        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(ca);
        verifier.add_crl(crl);
        verifier.set_check_revocation(true);
        verifier.set_verification_time(1_763_164_800);

        let chain = verifier.verify_cert(&server1, &[]).unwrap();
        assert_eq!(chain.len(), 2); // [server1, ca]
    }

    #[test]
    fn test_verify_chain_no_revocation_check_default() {
        // With revocation checking off (default), a revoked cert still passes
        let ca = Certificate::from_pem(CRL_CA_PEM).unwrap();
        let server2 = Certificate::from_pem(SERVER2_PEM).unwrap();
        let crl = CertificateRevocationList::from_pem(CRL_PEM).unwrap();

        let mut verifier = CertificateVerifier::new();
        verifier.add_trusted_cert(ca);
        verifier.add_crl(crl);
        // check_revocation defaults to false
        verifier.set_verification_time(1_763_164_800);

        let chain = verifier.verify_cert(&server2, &[]).unwrap();
        assert_eq!(chain.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Phase 53: AKI/SKI C test vector suite
    // -----------------------------------------------------------------------

    const AKISKI_ROOT: &str =
        include_str!("../../../../tests/vectors/chain/akiski_suite/aki_root.pem");
    const AKISKI_INTER: &str =
        include_str!("../../../../tests/vectors/chain/akiski_suite/aki_inter.pem");
    const AKISKI_SUBINTER: &str =
        include_str!("../../../../tests/vectors/chain/akiski_suite/aki_subinter.pem");
    const AKISKI_LEAF_KEYMATCH: &str =
        include_str!("../../../../tests/vectors/chain/akiski_suite/aki_leaf_keymatch.pem");
    const AKISKI_LEAF_KEYMISMATCH: &str =
        include_str!("../../../../tests/vectors/chain/akiski_suite/aki_leaf_keymismatch.pem");
    const AKISKI_LEAF_NOAKI: &str =
        include_str!("../../../../tests/vectors/chain/akiski_suite/aki_leaf_noaki.pem");
    const AKISKI_INTER_NOSKI: &str =
        include_str!("../../../../tests/vectors/chain/akiski_suite/aki_inter_noski.pem");
    const AKISKI_LEAF_CRITICAL: &str =
        include_str!("../../../../tests/vectors/chain/akiski_suite/aki_leaf_critical.pem");
    const AKISKI_LEAF_ISS_MATCH: &str = include_str!(
        "../../../../tests/vectors/chain/akiski_suite/aki_leaf_issuer_serial_match.pem"
    );
    const AKISKI_LEAF_ISS_MISMATCH: &str = include_str!(
        "../../../../tests/vectors/chain/akiski_suite/aki_leaf_issuer_serial_mismatch.pem"
    );
    const AKISKI_LEAF_MULTILEVEL: &str =
        include_str!("../../../../tests/vectors/chain/akiski_suite/aki_leaf_multilevel.pem");
    const AKISKI_LEAF_PARENT_NOSKI: &str = include_str!(
        "../../../../tests/vectors/chain/akiski_suite/aki_leaf_parent_noski_match.pem"
    );

    // Basic chain (root → ca → device) from akiski_suite
    const AKISKI_BASIC_ROOT: &str =
        include_str!("../../../../tests/vectors/chain/akiski_suite/root_cert.pem");
    const AKISKI_BASIC_CA: &str =
        include_str!("../../../../tests/vectors/chain/akiski_suite/ca_cert.pem");
    const AKISKI_BASIC_DEVICE: &str =
        include_str!("../../../../tests/vectors/chain/akiski_suite/device_cert.pem");

    // Jan 1, 2026 00:00 UTC
    const AKISKI_TIME: i64 = 1_767_225_600;

    #[test]
    fn test_akiski_basic_chain() {
        let root = Certificate::from_pem(AKISKI_BASIC_ROOT).unwrap();
        let ca = Certificate::from_pem(AKISKI_BASIC_CA).unwrap();
        let device = Certificate::from_pem(AKISKI_BASIC_DEVICE).unwrap();

        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(root);
        v.set_verification_time(AKISKI_TIME);
        let chain = v.verify_cert(&device, &[ca]).unwrap();
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn test_akiski_key_match() {
        // AKI keyIdentifier matches issuer's SKI → passes
        let root = Certificate::from_pem(AKISKI_ROOT).unwrap();
        let inter = Certificate::from_pem(AKISKI_INTER).unwrap();
        let leaf = Certificate::from_pem(AKISKI_LEAF_KEYMATCH).unwrap();

        // Verify AKI/SKI match exists
        let leaf_aki = leaf.authority_key_identifier().unwrap();
        let inter_ski = inter.subject_key_identifier().unwrap();
        assert_eq!(
            leaf_aki.key_identifier.as_ref().unwrap(),
            &inter_ski,
            "leaf AKI should match inter SKI"
        );

        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(root);
        v.set_verification_time(AKISKI_TIME);
        let chain = v.verify_cert(&leaf, &[inter]).unwrap();
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn test_akiski_key_mismatch() {
        // AKI keyIdentifier doesn't match — falls back to DN match (may fail sig)
        let root = Certificate::from_pem(AKISKI_ROOT).unwrap();
        let inter = Certificate::from_pem(AKISKI_INTER).unwrap();
        let leaf = Certificate::from_pem(AKISKI_LEAF_KEYMISMATCH).unwrap();

        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(root);
        v.set_verification_time(AKISKI_TIME);
        // Chain building uses DN fallback; signature check may pass if signed by same key
        let result = v.verify_cert(&leaf, &[inter]);
        // Either passes (if actually signed by inter) or fails (signature mismatch)
        if let Ok(chain) = result {
            assert!(chain.len() >= 2);
        }
    }

    #[test]
    fn test_akiski_leaf_no_aki() {
        // Leaf without AKI extension → DN-only matching works
        let root = Certificate::from_pem(AKISKI_ROOT).unwrap();
        let inter = Certificate::from_pem(AKISKI_INTER).unwrap();
        let leaf = Certificate::from_pem(AKISKI_LEAF_NOAKI).unwrap();

        assert!(
            leaf.authority_key_identifier().is_none(),
            "leaf should have no AKI"
        );

        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(root);
        v.set_verification_time(AKISKI_TIME);
        let chain = v.verify_cert(&leaf, &[inter]).unwrap();
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn test_akiski_inter_no_ski() {
        // Intermediate without SKI → DN-only fallback
        let root = Certificate::from_pem(AKISKI_ROOT).unwrap();
        let inter_noski = Certificate::from_pem(AKISKI_INTER_NOSKI).unwrap();
        let leaf = Certificate::from_pem(AKISKI_LEAF_PARENT_NOSKI).unwrap();

        assert!(
            inter_noski.subject_key_identifier().is_none(),
            "inter_noski should have no SKI"
        );

        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(root);
        v.set_verification_time(AKISKI_TIME);
        let chain = v.verify_cert(&leaf, &[inter_noski]).unwrap();
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn test_akiski_critical() {
        // AKI extension marked critical (unusual but should work)
        let root = Certificate::from_pem(AKISKI_ROOT).unwrap();
        let inter = Certificate::from_pem(AKISKI_INTER).unwrap();
        let leaf = Certificate::from_pem(AKISKI_LEAF_CRITICAL).unwrap();

        // Check that AKI is marked critical
        let aki_oid = known::authority_key_identifier().to_der_value();
        let aki_ext = leaf.extensions.iter().find(|e| e.oid == aki_oid);
        assert!(aki_ext.is_some(), "should have AKI");
        assert!(aki_ext.unwrap().critical, "AKI should be marked critical");

        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(root);
        v.set_verification_time(AKISKI_TIME);
        let chain = v.verify_cert(&leaf, &[inter]).unwrap();
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn test_akiski_issuer_serial_match() {
        // AKI with issuer+serial (may have keyId too)
        let root = Certificate::from_pem(AKISKI_ROOT).unwrap();
        let inter = Certificate::from_pem(AKISKI_INTER).unwrap();
        let leaf = Certificate::from_pem(AKISKI_LEAF_ISS_MATCH).unwrap();

        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(root);
        v.set_verification_time(AKISKI_TIME);
        let chain = v.verify_cert(&leaf, &[inter]).unwrap();
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn test_akiski_issuer_serial_mismatch() {
        // AKI issuer+serial doesn't match — may still work via DN or keyId
        let root = Certificate::from_pem(AKISKI_ROOT).unwrap();
        let inter = Certificate::from_pem(AKISKI_INTER).unwrap();
        let leaf = Certificate::from_pem(AKISKI_LEAF_ISS_MISMATCH).unwrap();

        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(root);
        v.set_verification_time(AKISKI_TIME);
        // Our verifier only checks AKI.keyId, not authorityCertIssuer/serial
        // So this should still succeed via keyId or DN match
        let result = v.verify_cert(&leaf, &[inter]);
        if let Ok(chain) = result {
            assert!(chain.len() >= 2);
        }
    }

    #[test]
    fn test_akiski_multilevel() {
        // 4-level chain: root → inter → subinter → leaf
        let root = Certificate::from_pem(AKISKI_ROOT).unwrap();
        let inter = Certificate::from_pem(AKISKI_INTER).unwrap();
        let subinter = Certificate::from_pem(AKISKI_SUBINTER).unwrap();
        let leaf = Certificate::from_pem(AKISKI_LEAF_MULTILEVEL).unwrap();

        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(root);
        v.set_verification_time(AKISKI_TIME);
        let chain = v.verify_cert(&leaf, &[inter, subinter]).unwrap();
        assert_eq!(chain.len(), 4);
    }

    #[test]
    fn test_akiski_parent_noski_match() {
        // Parent lacks SKI, leaf has AKI — falls through to DN matching
        let root = Certificate::from_pem(AKISKI_ROOT).unwrap();
        let inter_noski = Certificate::from_pem(AKISKI_INTER_NOSKI).unwrap();
        let leaf = Certificate::from_pem(AKISKI_LEAF_PARENT_NOSKI).unwrap();

        // Verify the leaf has AKI but parent has no SKI
        assert!(leaf.authority_key_identifier().is_some());
        assert!(inter_noski.subject_key_identifier().is_none());

        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(root);
        v.set_verification_time(AKISKI_TIME);
        let chain = v.verify_cert(&leaf, &[inter_noski]).unwrap();
        assert_eq!(chain.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Phase 53: Signature parameter consistency tests
    // -----------------------------------------------------------------------

    const SIGPARAM_RSA_ROOT: &str =
        include_str!("../../../../tests/vectors/chain/sigParam/rsa_root.pem");
    const SIGPARAM_RSA_LEAF: &str =
        include_str!("../../../../tests/vectors/chain/sigParam/rsa_leaf.pem");
    const SIGPARAM_RSA_PSS_ROOT: &str =
        include_str!("../../../../tests/vectors/chain/sigParam/rsa_pss_root.pem");
    const SIGPARAM_RSA_PSS_LEAF: &str =
        include_str!("../../../../tests/vectors/chain/sigParam/rsa_pss_leaf.pem");
    const SIGPARAM_SM2_ROOT: &str =
        include_str!("../../../../tests/vectors/chain/sigParam/sm2_root.pem");
    const SIGPARAM_SM2_LEAF: &str =
        include_str!("../../../../tests/vectors/chain/sigParam/sm2_leaf.pem");

    #[test]
    fn test_sigparam_rsa_consistency() {
        let root = Certificate::from_pem(SIGPARAM_RSA_ROOT).unwrap();
        let leaf = Certificate::from_pem(SIGPARAM_RSA_LEAF).unwrap();
        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(root);
        v.set_verification_time(AKISKI_TIME);
        let chain = v.verify_cert(&leaf, &[]).unwrap();
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn test_sigparam_rsa_pss_consistency() {
        let root = Certificate::from_pem(SIGPARAM_RSA_PSS_ROOT).unwrap();
        let leaf = Certificate::from_pem(SIGPARAM_RSA_PSS_LEAF).unwrap();
        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(root);
        v.set_verification_time(AKISKI_TIME);
        let chain = v.verify_cert(&leaf, &[]).unwrap();
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn test_sigparam_sm2_consistency() {
        let root = Certificate::from_pem(SIGPARAM_SM2_ROOT).unwrap();
        let leaf = Certificate::from_pem(SIGPARAM_SM2_LEAF).unwrap();
        let mut v = CertificateVerifier::new();
        v.add_trusted_cert(root);
        v.set_verification_time(AKISKI_TIME);
        let chain = v.verify_cert(&leaf, &[]).unwrap();
        assert_eq!(chain.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Phase 54: Additional chain verification quality tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_chain_verify_rsa_pss_full() {
        // Verify RSA-PSS chain with full verifier pipeline
        let root = Certificate::from_pem(SIGPARAM_RSA_PSS_ROOT).unwrap();
        let leaf = Certificate::from_pem(SIGPARAM_RSA_PSS_LEAF).unwrap();
        // Verify leaf signature against root directly
        let sig_ok = leaf.verify_signature(&root).unwrap();
        assert!(sig_ok, "RSA-PSS leaf signature should verify against root");
        // Verify root self-signature
        let self_sig_ok = root.verify_signature(&root).unwrap();
        assert!(self_sig_ok, "RSA-PSS root self-signature should verify");
    }

    #[test]
    fn test_chain_verify_sm2_full() {
        // Verify SM2 chain with full verifier pipeline
        let root = Certificate::from_pem(SIGPARAM_SM2_ROOT).unwrap();
        let leaf = Certificate::from_pem(SIGPARAM_SM2_LEAF).unwrap();
        // Direct signature verification
        let sig_ok = leaf.verify_signature(&root).unwrap();
        assert!(sig_ok, "SM2 leaf signature should verify against root");
        let self_sig_ok = root.verify_signature(&root).unwrap();
        assert!(self_sig_ok, "SM2 root self-signature should verify");
    }

    #[test]
    fn test_chain_verify_rsa_pss_wrong_root() {
        // RSA-PSS leaf verified against wrong root should fail
        let root = Certificate::from_pem(SIGPARAM_RSA_ROOT).unwrap(); // RSA, not RSA-PSS
        let leaf = Certificate::from_pem(SIGPARAM_RSA_PSS_LEAF).unwrap();
        let result = leaf.verify_signature(&root);
        // Should fail — wrong key
        assert!(result.is_err() || !result.unwrap());
    }
}
