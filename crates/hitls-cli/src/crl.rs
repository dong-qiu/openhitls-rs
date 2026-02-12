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
