//! CRL display command implementation.

use std::fs;

pub fn run(input: &str, text: bool) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(input)?;

    // Try PEM first, then DER
    let crl = if let Ok(pem_str) = std::str::from_utf8(&data) {
        if pem_str.contains("-----BEGIN X509 CRL-----") {
            let blocks =
                hitls_utils::pem::parse(pem_str).map_err(|e| format!("PEM parse failed: {e}"))?;
            let der = blocks.first().ok_or("no PEM block found")?;
            hitls_pki::x509::CertificateRevocationList::from_der(&der.data)
                .map_err(|e| format!("CRL parse failed: {e}"))?
        } else {
            hitls_pki::x509::CertificateRevocationList::from_der(&data)
                .map_err(|e| format!("CRL parse failed: {e}"))?
        }
    } else {
        hitls_pki::x509::CertificateRevocationList::from_der(&data)
            .map_err(|e| format!("CRL parse failed: {e}"))?
    };

    if text {
        print!("{}", crl.to_text());
    } else {
        println!("CRL file: {input}");
        println!("  Issuer: {}", crl.issuer);
        println!("  Revoked certificates: {}", crl.revoked_certs.len());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // PEM CRL from test vectors (empty revocation list, RSA 2048, v2)
    const EMPTY_CRL_PEM: &str =
        include_str!("../../../tests/vectors/crl/crl_parse/crl/demoCA_rsa2048_v2_empty_crl.crl");

    // PEM CRL with 2 revoked certs (used for non-empty revocation list test)
    const CRL_V1_PEM: &str = include_str!("../../../tests/vectors/crl/crl_verify/crl/ca.crl");

    #[test]
    fn test_run_pem_crl_empty_revoked() {
        let tmp = std::env::temp_dir().join("test_crl_empty.crl");
        fs::write(&tmp, EMPTY_CRL_PEM.as_bytes()).unwrap();
        let result = run(tmp.to_str().unwrap(), false);
        assert!(result.is_ok());
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_run_pem_crl_with_revoked() {
        let tmp = std::env::temp_dir().join("test_crl_v1.crl");
        fs::write(&tmp, CRL_V1_PEM.as_bytes()).unwrap();
        let result = run(tmp.to_str().unwrap(), false);
        assert!(result.is_ok());
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_run_text_mode() {
        let tmp = std::env::temp_dir().join("test_crl_text.crl");
        fs::write(&tmp, EMPTY_CRL_PEM.as_bytes()).unwrap();
        let result = run(tmp.to_str().unwrap(), true);
        assert!(result.is_ok());
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_run_der_crl() {
        // Parse PEM → extract DER → write as binary → verify DER path
        let blocks = hitls_utils::pem::parse(EMPTY_CRL_PEM).unwrap();
        let der = blocks.first().unwrap().data.clone();
        let tmp = std::env::temp_dir().join("test_crl_der.der");
        fs::write(&tmp, &der).unwrap();
        let result = run(tmp.to_str().unwrap(), false);
        assert!(result.is_ok());
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_run_nonexistent_file() {
        assert!(run("/nonexistent_crl_test/file.crl", false).is_err());
    }

    #[test]
    fn test_run_invalid_data() {
        let tmp = std::env::temp_dir().join("test_crl_invalid.crl");
        fs::write(&tmp, b"this is not a crl").unwrap();
        assert!(run(tmp.to_str().unwrap(), false).is_err());
        let _ = fs::remove_file(&tmp);
    }
}
