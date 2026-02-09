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
