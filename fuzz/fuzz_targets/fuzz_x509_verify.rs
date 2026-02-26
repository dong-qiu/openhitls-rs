#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try parsing fuzz data as a DER-encoded X.509 certificate
    let cert = match hitls_pki::x509::Certificate::from_der(data) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Exercise self-signed signature verification (crypto verify path)
    let _ = cert.verify_signature(&cert);

    // Exercise chain verification with self as trust anchor
    let mut verifier = hitls_pki::x509::verify::CertificateVerifier::new();
    verifier.add_trusted_cert(cert.clone());
    let _ = verifier.verify_cert(&cert, &[]);
});
