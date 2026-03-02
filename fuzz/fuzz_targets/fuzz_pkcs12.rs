#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try parsing with empty password
    if let Ok(p12) = hitls_pki::pkcs12::Pkcs12::from_der(data, "") {
        // Exercise field access — must not panic
        let _ = p12.private_key.as_ref().map(|k| k.len());
        let _ = p12.certificates.len();
        for cert_der in &p12.certificates {
            // Try parsing embedded certificates
            let _ = hitls_pki::x509::Certificate::from_der(cert_der);
        }
        if let Some(pk_der) = &p12.private_key {
            // Try parsing embedded PKCS#8 key
            let _ = hitls_pki::pkcs8::parse_pkcs8_der(pk_der);
        }
    }

    // Try parsing with a non-empty password
    let _ = hitls_pki::pkcs12::Pkcs12::from_der(data, "password");
});
