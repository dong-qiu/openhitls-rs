//! Certificate chain verification command implementation.

use std::fs;

pub fn run(ca_file: &str, cert_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Load CA certificates
    let ca_pem =
        fs::read_to_string(ca_file).map_err(|e| format!("cannot read CA file '{ca_file}': {e}"))?;

    // Load certificate to verify
    let cert_pem = fs::read_to_string(cert_file)
        .map_err(|e| format!("cannot read certificate '{cert_file}': {e}"))?;

    let cert = hitls_pki::x509::Certificate::from_pem(&cert_pem)
        .map_err(|e| format!("failed to parse certificate: {e}"))?;

    // Build verifier with trusted CAs
    let mut verifier = hitls_pki::x509::verify::CertificateVerifier::new();
    verifier
        .add_trusted_certs_pem(&ca_pem)
        .map_err(|e| format!("failed to parse CA certificates: {e}"))?;

    // Verify
    let intermediates: Vec<hitls_pki::x509::Certificate> = vec![];
    match verifier.verify_cert(&cert, &intermediates) {
        Ok(chain) => {
            println!("{cert_file}: OK");
            println!("Chain depth: {}", chain.len());
            for (i, c) in chain.iter().enumerate() {
                println!("  [{i}] {}", c.subject);
            }
        }
        Err(e) => {
            eprintln!("{cert_file}: FAIL");
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_self_signed_cert_pem() -> String {
        let seed = [0x55u8; 32];
        let der = hitls_pki::pkcs8::encode_ed25519_pkcs8_der(&seed);
        let key_pem = hitls_utils::pem::encode("PRIVATE KEY", &der);
        let sk = hitls_pki::x509::SigningKey::from_pkcs8_pem(&key_pem).unwrap();
        let dn = hitls_pki::x509::DistinguishedName {
            entries: vec![("CN".to_string(), "Test CA".to_string())],
        };
        let cert =
            hitls_pki::x509::CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 9_999_999_999)
                .unwrap();
        hitls_utils::pem::encode("CERTIFICATE", &cert.raw)
    }

    #[test]
    fn test_run_success_self_signed() {
        // A self-signed cert IS its own CA — verification should succeed
        let cert_pem = make_self_signed_cert_pem();
        let tmp_ca = std::env::temp_dir().join("test_verify_ca.pem");
        let tmp_cert = std::env::temp_dir().join("test_verify_cert.pem");
        fs::write(&tmp_ca, &cert_pem).unwrap();
        fs::write(&tmp_cert, &cert_pem).unwrap();
        let result = run(tmp_ca.to_str().unwrap(), tmp_cert.to_str().unwrap());
        assert!(result.is_ok());
        let _ = fs::remove_file(&tmp_ca);
        let _ = fs::remove_file(&tmp_cert);
    }

    #[test]
    fn test_run_ca_file_not_found() {
        let result = run(
            "/nonexistent_verify_test/ca.pem",
            "/nonexistent_verify_test/cert.pem",
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cannot read CA file"));
    }

    #[test]
    fn test_run_cert_file_not_found() {
        let cert_pem = make_self_signed_cert_pem();
        let tmp_ca = std::env::temp_dir().join("test_verify_ca_only.pem");
        fs::write(&tmp_ca, &cert_pem).unwrap();
        let result = run(
            tmp_ca.to_str().unwrap(),
            "/nonexistent_verify_test/cert.pem",
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cannot read certificate"));
        let _ = fs::remove_file(&tmp_ca);
    }

    #[test]
    fn test_run_invalid_cert_pem() {
        let cert_pem = make_self_signed_cert_pem();
        let tmp_ca = std::env::temp_dir().join("test_verify_ca_valid.pem");
        let tmp_cert = std::env::temp_dir().join("test_verify_cert_invalid.pem");
        fs::write(&tmp_ca, &cert_pem).unwrap();
        fs::write(
            &tmp_cert,
            b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let result = run(tmp_ca.to_str().unwrap(), tmp_cert.to_str().unwrap());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("failed to parse certificate"));
        let _ = fs::remove_file(&tmp_ca);
        let _ = fs::remove_file(&tmp_cert);
    }
}
