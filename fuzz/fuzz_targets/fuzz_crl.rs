#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let crl = match hitls_pki::x509::CertificateRevocationList::from_der(data) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Exercise field access — must not panic
    let _ = crl.version;
    let _ = crl.issuer.to_string();
    let _ = crl.this_update;
    let _ = crl.next_update;
    let _ = crl.revoked_certs.len();
    let _ = crl.extensions.len();
    let _ = crl.signature_algorithm.len();

    // Check revocation for a dummy serial number
    let _ = crl.is_revoked(&[0x01]);

    // Check revocation for each listed serial
    for rc in &crl.revoked_certs {
        let _ = crl.is_revoked(&rc.serial_number);
    }

    // Exercise roundtrip encoding — must not panic
    let der = crl.to_der();
    let _ = hitls_pki::x509::CertificateRevocationList::from_der(&der);

    // Exercise PEM encoding
    let pem = crl.to_pem();
    let _ = hitls_pki::x509::CertificateRevocationList::from_pem(&pem);
});
