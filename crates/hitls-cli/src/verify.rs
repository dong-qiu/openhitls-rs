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
