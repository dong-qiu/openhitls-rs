//! X.509 certificate chain building and verification.

use hitls_types::PkiError;

use super::crl::CertificateRevocationList;
use super::{Certificate, KeyUsage};

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

    /// Find the issuer of `cert` by matching issuer DN to candidate subject DN.
    /// Searches intermediates first, then the trust store.
    fn find_issuer(
        &self,
        cert: &Certificate,
        intermediates: &[Certificate],
    ) -> Option<Certificate> {
        // Search intermediates first
        for candidate in intermediates {
            if cert.issuer == candidate.subject {
                return Some(candidate.clone());
            }
        }
        // Then search trust store
        for candidate in &self.trusted_certs {
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
            }
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

    // --- CRL revocation checking tests ---

    // CRL test data: ca.crl revokes server2 (serial ...D9) but NOT server1 (serial ...D8)
    const CRL_CA_PEM: &str = include_str!(
        "../../../../../openhitls/testcode/testdata/cert/test_for_crl/crl_verify/certs/ca.crt"
    );
    const CRL_PEM: &str = include_str!(
        "../../../../../openhitls/testcode/testdata/cert/test_for_crl/crl_verify/crl/ca.crl"
    );
    const SERVER1_PEM: &str = include_str!(
        "../../../../../openhitls/testcode/testdata/cert/test_for_crl/crl_verify/certs/server1.crt"
    );
    const SERVER2_PEM: &str = include_str!(
        "../../../../../openhitls/testcode/testdata/cert/test_for_crl/crl_verify/certs/server2.crt"
    );

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
}
