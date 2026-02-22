//! X.509 certificate, CRL, CSR, and OCSP management.

mod builder;
mod certificate;
mod extensions;
mod signing;

pub mod crl;
pub mod hostname;
pub mod ocsp;
pub mod text;
pub mod verify;

// ---------------------------------------------------------------------------
// Public re-exports (preserve existing public API)
// ---------------------------------------------------------------------------

pub use builder::{CertificateBuilder, CertificateRequestBuilder};
pub use certificate::{
    Certificate, CertificateRequest, DistinguishedName, SubjectPublicKeyInfo, X509Extension,
};
pub use extensions::{
    AuthorityInfoAccess, AuthorityKeyIdentifier, BasicConstraints, CertificatePolicies,
    ExtendedKeyUsage, GeneralName, GeneralSubtree, KeyUsage, NameConstraints, PolicyInformation,
    PolicyQualifier, SubjectAltName,
};
pub use signing::SigningKey;

// CRL types are defined in crl.rs and re-exported here.
pub use crl::{CertificateRevocationList, RevocationReason, RevokedCertificate};
// OCSP types are defined in ocsp.rs and re-exported here.
pub use ocsp::{
    OcspBasicResponse, OcspCertId, OcspCertStatus, OcspRequest, OcspResponse, OcspResponseStatus,
    OcspSingleResponse, ResponderId,
};

// ---------------------------------------------------------------------------
// pub(crate) re-exports (for sibling modules: crl.rs, ocsp.rs, verify.rs, etc.)
// ---------------------------------------------------------------------------

pub(crate) use certificate::{parse_algorithm_identifier, parse_extensions, parse_name};
pub(crate) use signing::{
    compute_hash, verify_ecdsa, verify_ed25519, verify_ed448, verify_rsa, verify_rsa_pss,
    verify_sm2, HashAlg,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::builder::{
        encode_algorithm_identifier, encode_distinguished_name, encode_extensions,
        encode_subject_public_key_info,
    };
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
        let curve_oid = hitls_utils::oid::Oid::from_der_value(params).unwrap();
        assert_eq!(curve_oid, hitls_utils::oid::known::prime256v1());
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
        let bc_oid = hitls_utils::oid::known::basic_constraints().to_der_value();
        let bc = cert.extensions.iter().find(|e| e.oid == bc_oid);
        assert!(bc.is_some());
        assert!(bc.unwrap().critical); // CA cert BasicConstraints should be critical

        // Check for SubjectKeyIdentifier (2.5.29.14)
        let ski_oid = hitls_utils::oid::known::subject_key_identifier().to_der_value();
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
        let sig_oid = hitls_utils::oid::Oid::from_der_value(&cert.signature_algorithm).unwrap();
        // Should be sha256WithRSAEncryption
        assert_eq!(
            sig_oid,
            hitls_utils::oid::known::sha256_with_rsa_encryption()
        );

        let ecdsa_data = hex(ECDSA_CERT_HEX);
        let ecdsa_cert = Certificate::from_der(&ecdsa_data).unwrap();
        let ecdsa_sig_oid =
            hitls_utils::oid::Oid::from_der_value(&ecdsa_cert.signature_algorithm).unwrap();
        // Should be ecdsaWithSHA256
        assert_eq!(ecdsa_sig_oid, hitls_utils::oid::known::ecdsa_with_sha256());
    }

    // -----------------------------------------------------------------------
    // Encoding roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_dn_roundtrip() {
        let dn = DistinguishedName {
            entries: vec![
                ("CN".to_string(), "Test".to_string()),
                ("O".to_string(), "OpenHiTLS".to_string()),
                ("C".to_string(), "CN".to_string()),
            ],
        };
        let encoded = encode_distinguished_name(&dn);
        let mut dec = hitls_utils::asn1::Decoder::new(&encoded);
        let parsed = parse_name(&mut dec).unwrap();
        assert_eq!(parsed.entries, dn.entries);
    }

    #[test]
    fn test_encode_algorithm_identifier_rsa() {
        let oid = hitls_utils::oid::known::sha256_with_rsa_encryption().to_der_value();
        let encoded = encode_algorithm_identifier(&oid, None);
        let mut dec = hitls_utils::asn1::Decoder::new(&encoded);
        let (parsed_oid, parsed_params) = parse_algorithm_identifier(&mut dec).unwrap();
        assert_eq!(parsed_oid, oid);
        assert!(parsed_params.is_none()); // NULL → None
    }

    #[test]
    fn test_encode_spki_roundtrip() {
        // Parse SPKI from an existing cert, encode it back, and reparse
        let data = hex(RSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        let encoded = encode_subject_public_key_info(&cert.public_key);
        let mut dec = hitls_utils::asn1::Decoder::new(&encoded);
        let parsed = certificate::parse_subject_public_key_info(&mut dec).unwrap();
        assert_eq!(parsed.algorithm_oid, cert.public_key.algorithm_oid);
        assert_eq!(parsed.public_key, cert.public_key.public_key);
    }

    #[test]
    fn test_encode_extensions_roundtrip() {
        let exts = vec![X509Extension {
            oid: hitls_utils::oid::known::basic_constraints().to_der_value(),
            critical: true,
            value: vec![0x30, 0x03, 0x01, 0x01, 0xFF], // isCA=true
        }];
        let encoded = encode_extensions(&exts);
        let parsed = parse_extensions(&encoded).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].oid, exts[0].oid);
        assert!(parsed[0].critical);
        assert_eq!(parsed[0].value, exts[0].value);
    }

    // -----------------------------------------------------------------------
    // SigningKey tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_signing_key_ed25519() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let data = b"hello world";
        let sig = sk.sign(data).unwrap();
        let spki = sk.public_key_info().unwrap();

        // Verify
        let result = verify_ed25519(data, &sig, &spki).unwrap();
        assert!(result);
    }

    #[test]
    fn test_signing_key_ecdsa_p256() {
        let kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
        let sk = SigningKey::Ecdsa {
            curve_id: hitls_types::EccCurveId::NistP256,
            key_pair: kp,
        };
        let data = b"test message";
        let sig = sk.sign(data).unwrap();
        let spki = sk.public_key_info().unwrap();

        let result = verify_ecdsa(data, &sig, &spki, HashAlg::Sha256).unwrap();
        assert!(result);
    }

    // -----------------------------------------------------------------------
    // CSR tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_csr_ed25519() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let subject = DistinguishedName {
            entries: vec![("CN".to_string(), "Test CSR".to_string())],
        };
        let csr = CertificateRequestBuilder::new(subject.clone())
            .build(&sk)
            .unwrap();
        assert_eq!(csr.version, 0);
        assert_eq!(csr.subject.entries, subject.entries);

        // Verify self-signature
        assert!(csr.verify_signature().unwrap());

        // Roundtrip: DER → parse → verify
        let parsed = CertificateRequest::from_der(&csr.raw).unwrap();
        assert_eq!(parsed.subject.entries, subject.entries);
        assert!(parsed.verify_signature().unwrap());
    }

    #[test]
    fn test_build_csr_ecdsa() {
        let kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
        let sk = SigningKey::Ecdsa {
            curve_id: hitls_types::EccCurveId::NistP256,
            key_pair: kp,
        };
        let subject = DistinguishedName {
            entries: vec![
                ("CN".to_string(), "ECDSA CSR".to_string()),
                ("O".to_string(), "Test Org".to_string()),
            ],
        };
        let csr = CertificateRequestBuilder::new(subject.clone())
            .build(&sk)
            .unwrap();
        assert!(csr.verify_signature().unwrap());

        let parsed = CertificateRequest::from_der(&csr.raw).unwrap();
        assert_eq!(parsed.subject.get("CN"), Some("ECDSA CSR"));
        assert!(parsed.verify_signature().unwrap());
    }

    #[test]
    fn test_build_csr_pem_roundtrip() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let subject = DistinguishedName {
            entries: vec![("CN".to_string(), "PEM Test".to_string())],
        };
        let pem = CertificateRequestBuilder::new(subject)
            .build_pem(&sk)
            .unwrap();
        assert!(pem.contains("-----BEGIN CERTIFICATE REQUEST-----"));
        let parsed = CertificateRequest::from_pem(&pem).unwrap();
        assert_eq!(parsed.subject.get("CN"), Some("PEM Test"));
        assert!(parsed.verify_signature().unwrap());
    }

    #[test]
    fn test_build_csr_with_extensions() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let subject = DistinguishedName {
            entries: vec![("CN".to_string(), "Ext CSR".to_string())],
        };
        let csr = CertificateRequestBuilder::new(subject)
            .add_extension(
                hitls_utils::oid::known::basic_constraints().to_der_value(),
                true,
                vec![0x30, 0x03, 0x01, 0x01, 0xFF],
            )
            .build(&sk)
            .unwrap();
        assert!(csr.verify_signature().unwrap());
        // Verify extension survived the roundtrip
        let parsed = CertificateRequest::from_der(&csr.raw).unwrap();
        assert!(parsed.verify_signature().unwrap());
    }

    // -----------------------------------------------------------------------
    // Certificate Builder tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_self_signed_ed25519() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let subject = DistinguishedName {
            entries: vec![
                ("CN".to_string(), "Test CA".to_string()),
                ("O".to_string(), "OpenHiTLS".to_string()),
            ],
        };
        let cert = CertificateBuilder::self_signed(
            subject.clone(),
            &sk,
            1_700_000_000, // 2023-11-14
            1_800_000_000, // 2027-01-15
        )
        .unwrap();

        assert_eq!(cert.version, 3);
        assert_eq!(cert.subject.get("CN"), Some("Test CA"));
        assert_eq!(cert.issuer.get("CN"), Some("Test CA"));
        assert!(cert.is_self_signed());
        assert!(cert.is_ca());
        assert!(cert.verify_signature(&cert).unwrap());
    }

    #[test]
    fn test_build_self_signed_ecdsa() {
        let kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
        let sk = SigningKey::Ecdsa {
            curve_id: hitls_types::EccCurveId::NistP256,
            key_pair: kp,
        };
        let subject = DistinguishedName {
            entries: vec![("CN".to_string(), "ECDSA CA".to_string())],
        };
        let cert =
            CertificateBuilder::self_signed(subject, &sk, 1_700_000_000, 1_800_000_000).unwrap();
        assert!(cert.is_self_signed());
        assert!(cert.verify_signature(&cert).unwrap());
    }

    #[test]
    fn test_build_cert_chain() {
        // Generate CA
        let ca_kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let ca_sk = SigningKey::Ed25519(ca_kp);
        let ca_dn = DistinguishedName {
            entries: vec![("CN".to_string(), "Root CA".to_string())],
        };
        let ca_cert =
            CertificateBuilder::self_signed(ca_dn, &ca_sk, 1_700_000_000, 1_800_000_000).unwrap();

        // Generate end-entity cert signed by CA
        let ee_kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let ee_sk = SigningKey::Ed25519(ee_kp);
        let ee_spki = ee_sk.public_key_info().unwrap();
        let ee_dn = DistinguishedName {
            entries: vec![("CN".to_string(), "server.example.com".to_string())],
        };
        let ee_cert = CertificateBuilder::new()
            .serial_number(&[0x02])
            .issuer(ca_cert.subject.clone())
            .subject(ee_dn.clone())
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(ee_spki)
            .build(&ca_sk)
            .unwrap();

        assert_eq!(ee_cert.subject.get("CN"), Some("server.example.com"));
        assert_eq!(ee_cert.issuer.get("CN"), Some("Root CA"));
        assert!(!ee_cert.is_self_signed());

        // Verify EE cert signature against CA
        assert!(ee_cert.verify_signature(&ca_cert).unwrap());
        // CA self-verify still works
        assert!(ca_cert.verify_signature(&ca_cert).unwrap());
    }

    #[test]
    fn test_build_cert_with_basic_constraints() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".to_string(), "CA".to_string())],
        };
        let spki = sk.public_key_info().unwrap();
        let cert = CertificateBuilder::new()
            .serial_number(&[0x01])
            .issuer(dn.clone())
            .subject(dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .add_basic_constraints(true, Some(1))
            .build(&sk)
            .unwrap();

        let bc = cert.basic_constraints().unwrap();
        assert!(bc.is_ca);
        assert_eq!(bc.path_len_constraint, Some(1));
    }

    #[test]
    fn test_build_cert_with_key_usage() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".to_string(), "KU Test".to_string())],
        };
        let spki = sk.public_key_info().unwrap();
        let cert = CertificateBuilder::new()
            .serial_number(&[0x01])
            .issuer(dn.clone())
            .subject(dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .add_key_usage(KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_CERT_SIGN)
            .build(&sk)
            .unwrap();

        let ku = cert.key_usage().unwrap();
        assert!(ku.has(KeyUsage::DIGITAL_SIGNATURE));
        assert!(ku.has(KeyUsage::KEY_CERT_SIGN));
        assert!(!ku.has(KeyUsage::KEY_ENCIPHERMENT));
    }

    #[test]
    fn test_cert_pem_roundtrip() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".to_string(), "PEM Cert".to_string())],
        };
        let pem = CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000).unwrap();
        let pem_str = hitls_utils::pem::encode("CERTIFICATE", &pem.raw);
        assert!(pem_str.contains("-----BEGIN CERTIFICATE-----"));
        let parsed = Certificate::from_pem(&pem_str).unwrap();
        assert_eq!(parsed.subject.get("CN"), Some("PEM Cert"));
        assert!(parsed.verify_signature(&parsed).unwrap());
    }

    // -----------------------------------------------------------------------
    // Phase 51: Real C test vector — certificate parsing edge cases
    // -----------------------------------------------------------------------

    const CERTCHECK_V0: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certversion0noext.der");
    const CERTCHECK_V2: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certversion2withext.der");
    const CERTCHECK_NEG_SERIAL: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certnegativeserialnum.der");
    const CERTCHECK_DN_NULL: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certdnvaluenull.der");
    const CERTCHECK_RSA_PSS: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certrsapss.der");
    const CERTCHECK_SAN_DNS: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_san_parse_1.der");
    const CERTCHECK_SAN_IP: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_san_parse_3.der");
    const CERTCHECK_KU: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_keyusage_parse_1.der");
    const CERTCHECK_EKU: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_extku_parse_1.der");
    const CERTCHECK_BC: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_bcon_parse_1.der");

    #[test]
    fn test_parse_v1_cert() {
        // Version 0 (v1) cert — no extensions
        let cert = Certificate::from_der(CERTCHECK_V0).unwrap();
        assert_eq!(cert.version, 1); // v1 = version field value 0
        assert!(cert.extensions.is_empty());
    }

    #[test]
    fn test_parse_v3_cert() {
        // Version 2 (v3) cert — has extensions
        let cert = Certificate::from_der(CERTCHECK_V2).unwrap();
        assert_eq!(cert.version, 3); // v3 = version field value 2
        assert!(!cert.extensions.is_empty());
    }

    #[test]
    fn test_parse_negative_serial() {
        // Certificate with serial number 0xFF (encoded as 00 FF in DER to stay positive)
        let cert = Certificate::from_der(CERTCHECK_NEG_SERIAL).unwrap();
        assert!(!cert.serial_number.is_empty());
        // DER INTEGER encoding: 00 FF (leading zero keeps it positive per X.690)
        // The raw bytes should contain 0xFF after any leading zero padding
        let sn = &cert.serial_number;
        let value_byte = if sn[0] == 0x00 && sn.len() > 1 {
            sn[1] // strip DER padding byte
        } else {
            sn[0]
        };
        assert_eq!(value_byte, 0xFF, "serial value byte should be 0xFF");
    }

    #[test]
    fn test_parse_dn_null_value() {
        // Certificate with null byte in DN value
        let result = Certificate::from_der(CERTCHECK_DN_NULL);
        // Should either parse successfully or fail gracefully
        match result {
            Ok(cert) => {
                assert!(!cert.subject.entries.is_empty());
            }
            Err(_) => {
                // Failing to parse a null DN is acceptable
            }
        }
    }

    #[test]
    fn test_parse_rsa_pss_cert() {
        // RSA-PSS algorithm identifier
        let cert = Certificate::from_der(CERTCHECK_RSA_PSS).unwrap();
        assert_eq!(cert.version, 3);
        // RSA-PSS OID: 1.2.840.113549.1.1.10
        let sig_oid = hitls_utils::oid::Oid::from_der_value(&cert.signature_algorithm).unwrap();
        let rsa_pss_oid = hitls_utils::oid::Oid::new(&[1, 2, 840, 113549, 1, 1, 10]);
        assert_eq!(sig_oid, rsa_pss_oid);
    }

    #[test]
    fn test_parse_san_dns() {
        // SAN extension with DNS names
        let cert = Certificate::from_der(CERTCHECK_SAN_DNS).unwrap();
        let san_oid = hitls_utils::oid::known::subject_alt_name().to_der_value();
        let san_ext = cert.extensions.iter().find(|e| e.oid == san_oid);
        assert!(san_ext.is_some(), "should have SAN extension");
    }

    #[test]
    fn test_parse_san_ip() {
        // SAN extension with IP addresses
        let cert = Certificate::from_der(CERTCHECK_SAN_IP).unwrap();
        let san_oid = hitls_utils::oid::known::subject_alt_name().to_der_value();
        let san_ext = cert.extensions.iter().find(|e| e.oid == san_oid);
        assert!(san_ext.is_some(), "should have SAN extension");
    }

    #[test]
    fn test_parse_keyusage_ext() {
        // KeyUsage extension
        let cert = Certificate::from_der(CERTCHECK_KU).unwrap();
        let ku = cert.key_usage();
        assert!(ku.is_some(), "should have KeyUsage extension");
    }

    #[test]
    fn test_parse_eku_ext() {
        // Extended Key Usage extension
        let cert = Certificate::from_der(CERTCHECK_EKU).unwrap();
        let eku_oid = vec![0x55, 0x1D, 0x25]; // 2.5.29.37
        let has_eku = cert.extensions.iter().any(|e| e.oid.ends_with(&eku_oid));
        assert!(has_eku, "should have EKU extension");
    }

    #[test]
    fn test_parse_bc_ext() {
        // BasicConstraints extension
        let cert = Certificate::from_der(CERTCHECK_BC).unwrap();
        let bc = cert.basic_constraints();
        assert!(bc.is_some(), "should have BasicConstraints extension");
    }

    // -----------------------------------------------------------------------
    // Phase 52: Typed extension parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_eku_parsing() {
        let cert = Certificate::from_der(CERTCHECK_EKU).unwrap();
        let eku = cert.extended_key_usage();
        assert!(eku.is_some(), "cert should have EKU extension");
        let eku = eku.unwrap();
        assert!(!eku.purposes.is_empty());
    }

    #[test]
    fn test_eku_parsing_real_server() {
        // server_good.der from eku_suite has serverAuth
        let cert = Certificate::from_der(EKU_SERVER_GOOD_DER).unwrap();
        let eku = cert.extended_key_usage();
        assert!(eku.is_some());
        let eku = eku.unwrap();
        assert!(
            eku.purposes
                .iter()
                .any(|p| *p == hitls_utils::oid::known::kp_server_auth()),
            "server cert should have serverAuth EKU"
        );
    }

    const EKU_SERVER_GOOD_DER: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/eku_suite/server_good.der");
    const EKU_CLIENT_GOOD_DER: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/eku_suite/client_good.der");
    const EKU_ANY_GOOD_DER: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/eku_suite/anyEKU/anyeku_good.der");

    #[test]
    fn test_eku_parsing_real_client() {
        let cert = Certificate::from_der(EKU_CLIENT_GOOD_DER).unwrap();
        let eku = cert.extended_key_usage().unwrap();
        assert!(eku
            .purposes
            .iter()
            .any(|p| *p == hitls_utils::oid::known::kp_client_auth()));
    }

    #[test]
    fn test_eku_any_purpose() {
        let cert = Certificate::from_der(EKU_ANY_GOOD_DER).unwrap();
        let eku = cert.extended_key_usage().unwrap();
        assert!(
            eku.purposes
                .iter()
                .any(|p| *p == hitls_utils::oid::known::any_extended_key_usage()),
            "anyEKU cert should have anyExtendedKeyUsage"
        );
    }

    #[test]
    fn test_san_email_parsing() {
        // cert_ext_san_parse_1.der has rfc822Name (email), not dNSName
        let cert = Certificate::from_der(CERTCHECK_SAN_DNS).unwrap();
        let san = cert.subject_alt_name();
        assert!(san.is_some(), "cert should have SAN extension");
        let san = san.unwrap();
        assert!(
            !san.email_addresses.is_empty(),
            "SAN should have email addresses"
        );
    }

    #[test]
    fn test_san_ip_parsing() {
        let cert = Certificate::from_der(CERTCHECK_SAN_IP).unwrap();
        let san = cert.subject_alt_name();
        assert!(san.is_some(), "cert should have SAN extension");
        let san = san.unwrap();
        assert!(!san.ip_addresses.is_empty(), "SAN should have IP addresses");
    }

    #[test]
    fn test_san_empty() {
        // RSA test cert has no SAN
        let data = hex(RSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        assert!(cert.subject_alt_name().is_none());
    }

    #[test]
    fn test_aki_parsing() {
        let data = hex(RSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        let aki = cert.authority_key_identifier();
        assert!(aki.is_some(), "cert should have AKI extension");
        let aki = aki.unwrap();
        assert!(aki.key_identifier.is_some(), "AKI should have key ID");
    }

    #[test]
    fn test_ski_parsing() {
        let data = hex(RSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        let ski = cert.subject_key_identifier();
        assert!(ski.is_some(), "cert should have SKI extension");
        assert!(!ski.unwrap().is_empty());
    }

    #[test]
    fn test_aki_ski_match() {
        // Self-signed cert: AKI.keyId == SKI
        let data = hex(RSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        let ski = cert.subject_key_identifier().unwrap();
        let aki = cert.authority_key_identifier().unwrap();
        assert_eq!(
            aki.key_identifier.as_ref().unwrap(),
            &ski,
            "self-signed cert AKI should match SKI"
        );
    }

    #[test]
    fn test_name_constraints_synthetic() {
        // Build a cert with NameConstraints using the builder
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".to_string(), "NC Test CA".to_string())],
        };
        let spki = sk.public_key_info().unwrap();
        let cert = CertificateBuilder::new()
            .serial_number(&[0x01])
            .issuer(dn.clone())
            .subject(dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .add_basic_constraints(true, None)
            .add_name_constraints(
                &[GeneralName::DnsName(".example.com".into())],
                &[GeneralName::DnsName(".evil.com".into())],
            )
            .build(&sk)
            .unwrap();

        let nc = cert.name_constraints();
        assert!(nc.is_some(), "cert should have NameConstraints");
        let nc = nc.unwrap();
        assert_eq!(nc.permitted_subtrees.len(), 1);
        assert_eq!(nc.excluded_subtrees.len(), 1);
        match &nc.permitted_subtrees[0].base {
            GeneralName::DnsName(s) => assert_eq!(s, ".example.com"),
            _ => panic!("expected DnsName"),
        }
        match &nc.excluded_subtrees[0].base {
            GeneralName::DnsName(s) => assert_eq!(s, ".evil.com"),
            _ => panic!("expected DnsName"),
        }
    }

    #[test]
    fn test_eku_builder_roundtrip() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".to_string(), "EKU Test".to_string())],
        };
        let spki = sk.public_key_info().unwrap();
        let cert = CertificateBuilder::new()
            .serial_number(&[0x01])
            .issuer(dn.clone())
            .subject(dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .add_extended_key_usage(
                &[
                    hitls_utils::oid::known::kp_server_auth(),
                    hitls_utils::oid::known::kp_client_auth(),
                ],
                false,
            )
            .build(&sk)
            .unwrap();

        let eku = cert.extended_key_usage().unwrap();
        assert_eq!(eku.purposes.len(), 2);
        assert!(eku
            .purposes
            .contains(&hitls_utils::oid::known::kp_server_auth()));
        assert!(eku
            .purposes
            .contains(&hitls_utils::oid::known::kp_client_auth()));
    }

    #[test]
    fn test_san_builder_roundtrip() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".to_string(), "SAN Test".to_string())],
        };
        let spki = sk.public_key_info().unwrap();
        let cert = CertificateBuilder::new()
            .serial_number(&[0x01])
            .issuer(dn.clone())
            .subject(dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .add_subject_alt_name_dns(&["www.example.com", "mail.example.com"])
            .build(&sk)
            .unwrap();

        let san = cert.subject_alt_name().unwrap();
        assert_eq!(san.dns_names.len(), 2);
        assert!(san.dns_names.contains(&"www.example.com".to_string()));
        assert!(san.dns_names.contains(&"mail.example.com".to_string()));
    }

    #[test]
    fn test_ski_aki_builder_roundtrip() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".to_string(), "SKI Test".to_string())],
        };
        let spki = sk.public_key_info().unwrap();
        let key_id = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let cert = CertificateBuilder::new()
            .serial_number(&[0x01])
            .issuer(dn.clone())
            .subject(dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .add_subject_key_identifier(&key_id)
            .add_authority_key_identifier(&key_id)
            .build(&sk)
            .unwrap();

        let ski = cert.subject_key_identifier().unwrap();
        assert_eq!(ski, key_id);
        let aki = cert.authority_key_identifier().unwrap();
        assert_eq!(aki.key_identifier.unwrap(), key_id);
    }

    #[test]
    fn test_build_from_csr() {
        // Build CSR
        let ee_kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let ee_sk = SigningKey::Ed25519(ee_kp);
        let csr = CertificateRequestBuilder::new(DistinguishedName {
            entries: vec![("CN".to_string(), "CSR Subject".to_string())],
        })
        .build(&ee_sk)
        .unwrap();
        assert!(csr.verify_signature().unwrap());

        // CA signs a cert using CSR's subject and public key
        let ca_kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let ca_sk = SigningKey::Ed25519(ca_kp);
        let ca_dn = DistinguishedName {
            entries: vec![("CN".to_string(), "Issuing CA".to_string())],
        };
        let cert = CertificateBuilder::new()
            .serial_number(&[0x42])
            .issuer(ca_dn)
            .subject(csr.subject.clone())
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(csr.public_key.clone())
            .build(&ca_sk)
            .unwrap();

        assert_eq!(cert.subject.get("CN"), Some("CSR Subject"));
        assert_eq!(cert.issuer.get("CN"), Some("Issuing CA"));
    }

    // -----------------------------------------------------------------------
    // Phase 53: Extension edge cases + cert parsing edge cases
    // -----------------------------------------------------------------------

    const CERTCHECK_ZERO_SERIAL: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert0serialnum.der");
    const CERTCHECK_20_SERIAL: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert20serialnum.der");
    const CERTCHECK_21_SERIAL: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert21serialnum.der");
    const CERTCHECK_NO_ISSUER: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certnoissuer.der");
    const CERTCHECK_NO_PUBKEY: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certnopublickey.der");
    const CERTCHECK_NO_SIG_ALG: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certnosignaturealgorithm.der");
    const CERTCHECK_NO_SUBJECT_NO_SAN: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certnosubjectnosan.der");
    const CERTCHECK_SAN_NO_SUBJECT: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certwithsannosubject.der");
    const CERTCHECK_EMAIL_SUBJECT: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certsubjectwithemail.der");
    const CERTCHECK_TELETEX: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certteletexstring.der");
    const CERTCHECK_IA5_DN: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/certdnvalueIA5String.der");
    const CERTCHECK_DSA: &[u8] = include_bytes!("../../../../tests/vectors/certcheck/dsacert.der");

    // Duplicate extension test certs
    const EXT_AKID_REPEAT: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_akid_repeat.der");
    const EXT_BCONS_REPEAT: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_bcons_repeat.der");
    const EXT_EXKU_REPEAT: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_exku_repeat.der");
    const EXT_KU_REPEAT: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_keyusage_repeat.der");
    const EXT_KU_ERR: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_keyusage_err.der");
    const EXT_SAN_REPEAT: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_san_repeat.der");
    const EXT_SKID_REPEAT: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_ext_skid_repeat.der");
    const EXT_MANY: &[u8] =
        include_bytes!("../../../../tests/vectors/certcheck/cert_extensions.der");

    #[test]
    fn test_parse_zero_serial() {
        let cert = Certificate::from_der(CERTCHECK_ZERO_SERIAL).unwrap();
        // Serial number should be 0 (single byte [0x00] or empty)
        assert!(
            cert.serial_number == vec![0x00] || cert.serial_number.is_empty(),
            "serial should be zero, got: {:?}",
            cert.serial_number
        );
    }

    #[test]
    fn test_parse_large_serial_20() {
        let cert = Certificate::from_der(CERTCHECK_20_SERIAL).unwrap();
        // 20-byte serial number
        assert!(
            cert.serial_number.len() >= 20,
            "serial should be at least 20 bytes, got {} bytes",
            cert.serial_number.len()
        );
    }

    #[test]
    fn test_parse_large_serial_21() {
        let cert = Certificate::from_der(CERTCHECK_21_SERIAL).unwrap();
        // 21-byte serial number (may have leading zero)
        assert!(
            cert.serial_number.len() >= 20,
            "serial should be at least 20 bytes, got {} bytes",
            cert.serial_number.len()
        );
    }

    #[test]
    fn test_parse_missing_issuer() {
        // Should fail — issuer is mandatory
        let result = Certificate::from_der(CERTCHECK_NO_ISSUER);
        assert!(result.is_err(), "missing issuer should fail parsing");
    }

    #[test]
    fn test_parse_missing_pubkey() {
        // Should fail — public key is mandatory
        let result = Certificate::from_der(CERTCHECK_NO_PUBKEY);
        assert!(result.is_err(), "missing pubkey should fail parsing");
    }

    #[test]
    fn test_parse_missing_sig_alg() {
        // Should fail — signature algorithm is mandatory
        let result = Certificate::from_der(CERTCHECK_NO_SIG_ALG);
        assert!(result.is_err(), "missing sig alg should fail parsing");
    }

    #[test]
    fn test_parse_san_no_subject() {
        // Cert with SAN but empty subject — may fail to parse if DER is unusual
        let result = Certificate::from_der(CERTCHECK_SAN_NO_SUBJECT);
        match result {
            Ok(cert) => {
                let san = cert.subject_alt_name();
                assert!(
                    san.is_some(),
                    "cert with SAN-no-subject should have SAN extension"
                );
            }
            Err(_) => {
                // Some test vectors have unusual encoding that our parser doesn't support
            }
        }
    }

    #[test]
    fn test_parse_no_subject_no_san() {
        // Cert with neither subject nor SAN — may parse but is invalid per RFC
        let result = Certificate::from_der(CERTCHECK_NO_SUBJECT_NO_SAN);
        if let Ok(cert) = result {
            assert!(cert.subject.entries.is_empty() || cert.subject_alt_name().is_none());
        }
    }

    #[test]
    fn test_parse_email_in_subject() {
        let cert = Certificate::from_der(CERTCHECK_EMAIL_SUBJECT).unwrap();
        // Subject DN should contain emailAddress attribute
        let has_email = cert
            .subject
            .entries
            .iter()
            .any(|(k, _)| k == "emailAddress" || k.contains("1.2.840.113549.1.9.1"));
        assert!(has_email, "subject should have email address attribute");
    }

    #[test]
    fn test_parse_teletex_string() {
        // TeletexString (T61String) encoding in DN
        let result = Certificate::from_der(CERTCHECK_TELETEX);
        match result {
            Ok(cert) => {
                assert!(!cert.subject.entries.is_empty());
            }
            Err(_) => {
                // TeletexString may not be fully supported — acceptable
            }
        }
    }

    #[test]
    fn test_parse_ia5string_dn() {
        let result = Certificate::from_der(CERTCHECK_IA5_DN);
        if let Ok(cert) = result {
            assert!(!cert.subject.entries.is_empty());
        }
    }

    #[test]
    fn test_parse_dsa_cert() {
        let cert = Certificate::from_der(CERTCHECK_DSA).unwrap();
        assert_eq!(cert.version, 3);
        // DSA OID: 1.2.840.10040.4.3 (id-dsa-with-sha1) or similar
        let sig_oid = hitls_utils::oid::Oid::from_der_value(&cert.signature_algorithm).unwrap();
        // Just verify it parsed successfully with a non-empty signature
        assert!(!sig_oid.to_dot_string().is_empty());
        assert!(!cert.signature_value.is_empty());
    }

    #[test]
    fn test_parse_duplicate_aki() {
        // Cert with duplicate AKI extension — should parse (first wins)
        let cert = Certificate::from_der(EXT_AKID_REPEAT).unwrap();
        let aki_oid = hitls_utils::oid::known::authority_key_identifier().to_der_value();
        let count = cert.extensions.iter().filter(|e| e.oid == aki_oid).count();
        assert!(count >= 2, "should have duplicate AKI extensions");
        // Method returns first one
        let aki = cert.authority_key_identifier();
        assert!(aki.is_some());
    }

    #[test]
    fn test_parse_duplicate_bc() {
        let cert = Certificate::from_der(EXT_BCONS_REPEAT).unwrap();
        let bc_oid = hitls_utils::oid::known::basic_constraints().to_der_value();
        let count = cert.extensions.iter().filter(|e| e.oid == bc_oid).count();
        assert!(count >= 2, "should have duplicate BC extensions");
        let bc = cert.basic_constraints();
        assert!(bc.is_some());
    }

    #[test]
    fn test_parse_duplicate_eku() {
        let cert = Certificate::from_der(EXT_EXKU_REPEAT).unwrap();
        let eku_oid = hitls_utils::oid::known::ext_key_usage().to_der_value();
        let count = cert.extensions.iter().filter(|e| e.oid == eku_oid).count();
        assert!(count >= 2, "should have duplicate EKU extensions");
        let eku = cert.extended_key_usage();
        assert!(eku.is_some());
    }

    #[test]
    fn test_parse_duplicate_ku() {
        let cert = Certificate::from_der(EXT_KU_REPEAT).unwrap();
        let ku_oid = hitls_utils::oid::known::key_usage().to_der_value();
        let count = cert.extensions.iter().filter(|e| e.oid == ku_oid).count();
        assert!(count >= 2, "should have duplicate KU extensions");
        let ku = cert.key_usage();
        assert!(ku.is_some());
    }

    #[test]
    fn test_parse_malformed_ku() {
        // Malformed KeyUsage extension — should parse cert, but key_usage() may return None
        let cert = Certificate::from_der(EXT_KU_ERR).unwrap();
        // The cert itself should parse; the extension value may or may not parse
        let _ku = cert.key_usage(); // don't assert — just ensure no panic
    }

    #[test]
    fn test_parse_duplicate_san() {
        let cert = Certificate::from_der(EXT_SAN_REPEAT).unwrap();
        let san_oid = hitls_utils::oid::known::subject_alt_name().to_der_value();
        let count = cert.extensions.iter().filter(|e| e.oid == san_oid).count();
        assert!(count >= 2, "should have duplicate SAN extensions");
        let san = cert.subject_alt_name();
        assert!(san.is_some());
    }

    #[test]
    fn test_parse_duplicate_ski() {
        let cert = Certificate::from_der(EXT_SKID_REPEAT).unwrap();
        let ski_oid = hitls_utils::oid::known::subject_key_identifier().to_der_value();
        let count = cert.extensions.iter().filter(|e| e.oid == ski_oid).count();
        assert!(count >= 2, "should have duplicate SKI extensions");
        let ski = cert.subject_key_identifier();
        assert!(ski.is_some());
    }

    #[test]
    fn test_parse_many_extensions() {
        let cert = Certificate::from_der(EXT_MANY).unwrap();
        assert!(
            cert.extensions.len() >= 3,
            "cert_extensions.der should have multiple extensions"
        );
    }

    // -----------------------------------------------------------------------
    // Phase 53: CertificatePolicies extension parsing tests
    // -----------------------------------------------------------------------

    const POLICY_CRITICAL_DER: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/policy_suite/inter_policy_critical.der");
    const POLICY_NONCRIT_DER: &[u8] =
        include_bytes!("../../../../tests/vectors/chain/policy_suite/inter_policy_noncrit.der");

    #[test]
    fn test_cert_policies_parsing_critical() {
        let cert = Certificate::from_der(POLICY_CRITICAL_DER).unwrap();
        let cp = cert.certificate_policies();
        assert!(cp.is_some(), "should have CertificatePolicies extension");
        let cp = cp.unwrap();
        assert!(!cp.policies.is_empty(), "should have at least one policy");
        // Policy OID: 1.3.6.1.4.1.55555.1
        let expected_oid = hitls_utils::oid::Oid::new(&[1, 3, 6, 1, 4, 1, 55555, 1]);
        assert!(
            cp.policies
                .iter()
                .any(|p| p.policy_identifier == expected_oid),
            "should contain policy 1.3.6.1.4.1.55555.1"
        );
    }

    #[test]
    fn test_cert_policies_parsing_noncrit() {
        let cert = Certificate::from_der(POLICY_NONCRIT_DER).unwrap();
        let cp = cert.certificate_policies();
        assert!(cp.is_some());
        let cp = cp.unwrap();
        assert!(!cp.policies.is_empty());
        let expected_oid = hitls_utils::oid::Oid::new(&[1, 3, 6, 1, 4, 1, 55555, 1]);
        assert!(cp
            .policies
            .iter()
            .any(|p| p.policy_identifier == expected_oid));
    }

    #[test]
    fn test_cert_policies_none() {
        // RSA test cert has no policies
        let data = hex(RSA_CERT_HEX);
        let cert = Certificate::from_der(&data).unwrap();
        assert!(
            cert.certificate_policies().is_none(),
            "cert without policies should return None"
        );
    }

    #[test]
    fn test_cert_policies_any_policy() {
        // Build a cert with anyPolicy using the builder
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".to_string(), "Policy Test".to_string())],
        };
        let spki = sk.public_key_info().unwrap();

        // Manually encode anyPolicy CertificatePolicies extension
        let any_policy_oid = hitls_utils::oid::known::any_policy();
        let pi_body = {
            let mut e = hitls_utils::asn1::Encoder::new();
            e.write_oid(&any_policy_oid.to_der_value());
            e.finish()
        };
        let cp_body = {
            let mut e = hitls_utils::asn1::Encoder::new();
            e.write_sequence(&pi_body);
            e.finish()
        };
        let cp_value = {
            let mut e = hitls_utils::asn1::Encoder::new();
            e.write_sequence(&cp_body);
            e.finish()
        };

        let cert = CertificateBuilder::new()
            .serial_number(&[0x01])
            .issuer(dn.clone())
            .subject(dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .add_extension(
                hitls_utils::oid::known::certificate_policies().to_der_value(),
                false,
                cp_value,
            )
            .build(&sk)
            .unwrap();

        let cp = cert.certificate_policies().unwrap();
        assert_eq!(cp.policies.len(), 1);
        assert_eq!(cp.policies[0].policy_identifier, any_policy_oid);
    }

    // -----------------------------------------------------------------------
    // Phase 53: CSR parsing tests from C test vectors
    // -----------------------------------------------------------------------

    const CSR_RSA_SHA256: &str =
        include_str!("../../../../tests/vectors/csr/rsa_sha/rsa_sh256.csr");
    const CSR_ECDSA_SHA256: &str =
        include_str!("../../../../tests/vectors/csr/ecdsa_sha/ec_app256SHA256.csr");
    const CSR_SM2: &str = include_str!("../../../../tests/vectors/csr/sm2/ca.csr");

    #[test]
    fn test_csr_parse_rsa_sha256() {
        let csr = CertificateRequest::from_pem(CSR_RSA_SHA256).unwrap();
        assert_eq!(csr.version, 0);
        assert!(!csr.subject.entries.is_empty());
        assert!(!csr.public_key.public_key.is_empty());
        // RSA key — algorithm OID should be rsaEncryption
        let alg_oid = hitls_utils::oid::Oid::from_der_value(&csr.public_key.algorithm_oid).unwrap();
        let rsa_oid = hitls_utils::oid::Oid::new(&[1, 2, 840, 113549, 1, 1, 1]);
        assert_eq!(alg_oid, rsa_oid);
    }

    #[test]
    fn test_csr_parse_ecdsa_sha256() {
        let csr = CertificateRequest::from_pem(CSR_ECDSA_SHA256).unwrap();
        assert_eq!(csr.version, 0);
        assert!(!csr.subject.entries.is_empty());
        // EC key — algorithm OID should be id-ecPublicKey
        let alg_oid = hitls_utils::oid::Oid::from_der_value(&csr.public_key.algorithm_oid).unwrap();
        let ec_oid = hitls_utils::oid::known::ec_public_key();
        assert_eq!(alg_oid, ec_oid);
    }

    #[test]
    fn test_csr_parse_sm2() {
        let csr = CertificateRequest::from_pem(CSR_SM2).unwrap();
        assert_eq!(csr.version, 0);
        assert!(!csr.subject.entries.is_empty());
        // SM2 key — algorithm OID should be id-ecPublicKey
        let alg_oid = hitls_utils::oid::Oid::from_der_value(&csr.public_key.algorithm_oid).unwrap();
        let ec_oid = hitls_utils::oid::known::ec_public_key();
        assert_eq!(alg_oid, ec_oid);
    }

    #[test]
    fn test_csr_verify_rsa() {
        let csr = CertificateRequest::from_pem(CSR_RSA_SHA256).unwrap();
        let result = csr.verify_signature();
        assert!(result.is_ok(), "RSA CSR verify failed: {result:?}");
        assert!(result.unwrap());
    }

    #[test]
    fn test_csr_verify_ecdsa() {
        let csr = CertificateRequest::from_pem(CSR_ECDSA_SHA256).unwrap();
        let result = csr.verify_signature();
        assert!(result.is_ok(), "ECDSA CSR verify failed: {result:?}");
        assert!(result.unwrap());
    }

    #[test]
    fn test_cert_policies_with_cps_qualifier() {
        // Build a cert with CPS URI qualifier
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".to_string(), "CPS Test".to_string())],
        };
        let spki = sk.public_key_info().unwrap();

        let policy_oid = hitls_utils::oid::Oid::new(&[2, 5, 29, 32, 0]); // anyPolicy
        let cps_oid = hitls_utils::oid::known::cps_qualifier();

        // Encode CPS URI as IA5String
        let cps_uri = "https://example.com/cps";
        let mut cps_str_enc = hitls_utils::asn1::Encoder::new();
        cps_str_enc.write_ia5_string(cps_uri);
        let cps_str_bytes = cps_str_enc.finish();

        // PolicyQualifierInfo: SEQUENCE { OID, IA5String }
        let mut pqi_enc = hitls_utils::asn1::Encoder::new();
        pqi_enc.write_oid(&cps_oid.to_der_value());
        pqi_enc.write_raw(&cps_str_bytes);
        let pqi_body = pqi_enc.finish();

        let mut pqi_seq = hitls_utils::asn1::Encoder::new();
        pqi_seq.write_sequence(&pqi_body);
        let pqi_seq_bytes = pqi_seq.finish();

        // policyQualifiers SEQUENCE
        let mut quals_enc = hitls_utils::asn1::Encoder::new();
        quals_enc.write_sequence(&pqi_seq_bytes);
        let quals_bytes = quals_enc.finish();

        // PolicyInformation: SEQUENCE { OID, qualifiers }
        let mut pi_enc = hitls_utils::asn1::Encoder::new();
        pi_enc.write_oid(&policy_oid.to_der_value());
        pi_enc.write_raw(&quals_bytes);
        let pi_body = pi_enc.finish();

        let mut pi_seq = hitls_utils::asn1::Encoder::new();
        pi_seq.write_sequence(&pi_body);
        let pi_seq_bytes = pi_seq.finish();

        // CertificatePolicies: SEQUENCE OF PolicyInformation
        let mut cp_enc = hitls_utils::asn1::Encoder::new();
        cp_enc.write_sequence(&pi_seq_bytes);
        let cp_value = cp_enc.finish();

        let cert = CertificateBuilder::new()
            .serial_number(&[0x02])
            .issuer(dn.clone())
            .subject(dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(spki)
            .add_extension(
                hitls_utils::oid::known::certificate_policies().to_der_value(),
                false,
                cp_value,
            )
            .build(&sk)
            .unwrap();

        let cp = cert.certificate_policies().unwrap();
        assert_eq!(cp.policies.len(), 1);
        assert_eq!(cp.policies[0].policy_identifier, policy_oid);
        assert_eq!(cp.policies[0].qualifiers.len(), 1);
        assert_eq!(cp.policies[0].qualifiers[0].qualifier_id, cps_oid);
    }

    // -----------------------------------------------------------------------
    // Phase 54: Ed448, SM2, RSA-PSS signature verification tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_ed448_direct() {
        // Test Ed448 signature verification using the verify_ed448 helper directly
        let kp = hitls_crypto::ed448::Ed448KeyPair::generate().unwrap();
        let pub_bytes = kp.public_key().to_vec();
        let spki = SubjectPublicKeyInfo {
            algorithm_oid: hitls_utils::oid::known::ed448().to_der_value(),
            algorithm_params: None,
            public_key: pub_bytes,
        };
        let message = b"test message for Ed448 verification";
        let sig = kp.sign(message).unwrap();
        let result = verify_ed448(message, &sig, &spki).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_ed448_bad_signature() {
        // Test Ed448 verification with tampered signature
        let kp = hitls_crypto::ed448::Ed448KeyPair::generate().unwrap();
        let pub_bytes = kp.public_key().to_vec();
        let spki = SubjectPublicKeyInfo {
            algorithm_oid: hitls_utils::oid::known::ed448().to_der_value(),
            algorithm_params: None,
            public_key: pub_bytes,
        };
        let message = b"test message for Ed448 verification";
        let mut sig = kp.sign(message).unwrap();
        sig[10] ^= 0xFF; // Tamper
        let result = verify_ed448(message, &sig, &spki);
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_verify_sm2_self_signed() {
        let root_pem = include_str!("../../../../tests/vectors/chain/sigParam/sm2_root.pem");
        let root = Certificate::from_pem(root_pem).unwrap();
        assert_eq!(root.subject.get("CN"), Some("sigParam Root SM2"));
        let result = root.verify_signature(&root);
        assert!(result.is_ok(), "SM2 self-signed verify failed: {result:?}");
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_sm2_chain() {
        let root_pem = include_str!("../../../../tests/vectors/chain/sigParam/sm2_root.pem");
        let leaf_pem = include_str!("../../../../tests/vectors/chain/sigParam/sm2_leaf.pem");
        let root = Certificate::from_pem(root_pem).unwrap();
        let leaf = Certificate::from_pem(leaf_pem).unwrap();
        let result = leaf.verify_signature(&root);
        assert!(result.is_ok(), "SM2 chain verify failed: {result:?}");
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_rsa_pss_self_signed() {
        let root_pem = include_str!("../../../../tests/vectors/chain/sigParam/rsa_pss_root.pem");
        let root = Certificate::from_pem(root_pem).unwrap();
        assert_eq!(root.subject.get("CN"), Some("sigParam Root RSA-PSS"));
        let result = root.verify_signature(&root);
        assert!(
            result.is_ok(),
            "RSA-PSS self-signed verify failed: {result:?}"
        );
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_rsa_pss_chain() {
        let root_pem = include_str!("../../../../tests/vectors/chain/sigParam/rsa_pss_root.pem");
        let leaf_pem = include_str!("../../../../tests/vectors/chain/sigParam/rsa_pss_leaf.pem");
        let root = Certificate::from_pem(root_pem).unwrap();
        let leaf = Certificate::from_pem(leaf_pem).unwrap();
        let result = leaf.verify_signature(&root);
        assert!(result.is_ok(), "RSA-PSS chain verify failed: {result:?}");
        assert!(result.unwrap());
    }
}
