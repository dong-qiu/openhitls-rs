//! CSR (Certificate Signing Request) generation command.

use std::fs;
use std::io::Write;

use hitls_pki::x509::{CertificateRequestBuilder, DistinguishedName, SigningKey};

/// Parse a subject string like "/CN=Test/O=Org/C=US" into a DistinguishedName.
fn parse_subject(subj: &str) -> Result<DistinguishedName, Box<dyn std::error::Error>> {
    let mut entries = Vec::new();
    for part in subj.split('/') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| format!("invalid subject part: {part}"))?;
        entries.push((key.to_string(), value.to_string()));
    }
    if entries.is_empty() {
        return Err("empty subject".into());
    }
    Ok(DistinguishedName { entries })
}

pub fn run(
    _new: bool,
    key: Option<&str>,
    subj: Option<&str>,
    output: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_path = key.ok_or("--key is required for CSR generation")?;
    let subj_str = subj.ok_or("--subj is required (e.g. /CN=Test/O=Org)")?;

    // Read the private key
    let key_pem = fs::read_to_string(key_path)?;
    let signing_key =
        SigningKey::from_pkcs8_pem(&key_pem).map_err(|e| format!("failed to parse key: {e}"))?;

    // Parse subject
    let subject = parse_subject(subj_str)?;

    // Build CSR
    let pem = CertificateRequestBuilder::new(subject)
        .build_pem(&signing_key)
        .map_err(|e| format!("failed to build CSR: {e}"))?;

    // Output
    if let Some(out_path) = output {
        fs::write(out_path, &pem)?;
        eprintln!("CSR written to {out_path}");
    } else {
        std::io::stdout().write_all(pem.as_bytes())?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_ed25519_key_pem() -> String {
        let seed = [0x42u8; 32];
        let der = hitls_pki::pkcs8::encode_ed25519_pkcs8_der(&seed);
        hitls_utils::pem::encode("PRIVATE KEY", &der)
    }

    // -----------------------------------------------------------------------
    // parse_subject
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_subject_simple() {
        let dn = parse_subject("/CN=Test").unwrap();
        assert_eq!(dn.entries.len(), 1);
        assert_eq!(dn.entries[0], ("CN".to_string(), "Test".to_string()));
    }

    #[test]
    fn test_parse_subject_multiple_components() {
        let dn = parse_subject("/CN=Test/O=Org/C=US").unwrap();
        assert_eq!(dn.entries.len(), 3);
        assert_eq!(dn.entries[0], ("CN".to_string(), "Test".to_string()));
        assert_eq!(dn.entries[1], ("O".to_string(), "Org".to_string()));
        assert_eq!(dn.entries[2], ("C".to_string(), "US".to_string()));
    }

    #[test]
    fn test_parse_subject_no_leading_slash() {
        // Works without leading slash too (split on '/' yields empty first part → skipped)
        let dn = parse_subject("CN=Test/O=Org").unwrap();
        assert_eq!(dn.entries.len(), 2);
    }

    #[test]
    fn test_parse_subject_empty_string() {
        let result = parse_subject("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty subject"));
    }

    #[test]
    fn test_parse_subject_missing_equals() {
        let result = parse_subject("/CNTest");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid subject part"));
    }

    // -----------------------------------------------------------------------
    // run()
    // -----------------------------------------------------------------------

    #[test]
    fn test_run_csr_generation_stdout() {
        let key_pem = make_ed25519_key_pem();
        let tmp_key = std::env::temp_dir().join("test_req_key.pem");
        fs::write(&tmp_key, &key_pem).unwrap();
        let result = run(
            true,
            Some(tmp_key.to_str().unwrap()),
            Some("/CN=Test/O=Org"),
            None,
        );
        assert!(result.is_ok());
        let _ = fs::remove_file(&tmp_key);
    }

    #[test]
    fn test_run_csr_output_to_file() {
        let key_pem = make_ed25519_key_pem();
        let tmp_key = std::env::temp_dir().join("test_req_key2.pem");
        let tmp_out = std::env::temp_dir().join("test_req_out.csr");
        fs::write(&tmp_key, &key_pem).unwrap();
        let result = run(
            true,
            Some(tmp_key.to_str().unwrap()),
            Some("/CN=CSR Test"),
            Some(tmp_out.to_str().unwrap()),
        );
        assert!(result.is_ok());
        let csr_pem = fs::read_to_string(&tmp_out).unwrap();
        assert!(csr_pem.contains("CERTIFICATE REQUEST"));
        let _ = fs::remove_file(&tmp_key);
        let _ = fs::remove_file(&tmp_out);
    }

    #[test]
    fn test_run_no_key_error() {
        let result = run(true, None, Some("/CN=Test"), None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("--key is required"));
    }

    #[test]
    fn test_run_no_subject_error() {
        let key_pem = make_ed25519_key_pem();
        let tmp_key = std::env::temp_dir().join("test_req_nosubj.pem");
        fs::write(&tmp_key, &key_pem).unwrap();
        let result = run(true, Some(tmp_key.to_str().unwrap()), None, None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("--subj is required"));
        let _ = fs::remove_file(&tmp_key);
    }
}
