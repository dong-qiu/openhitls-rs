#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let cms = match hitls_pki::cms::CmsMessage::from_der(data) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Exercise content type inspection — must not panic
    let _ = cms.content_type;

    // Exercise signature verification (will fail for fuzzed data, but must not panic)
    let _ = cms.verify_signatures(None, &[]);
    let _ = cms.verify_signatures(Some(b"detached data"), &[]);

    // Access sub-structures if present
    if let Some(sd) = &cms.signed_data {
        let _ = sd.version;
        let _ = sd.digest_algorithms.len();
        let _ = sd.signer_infos.len();
        let _ = sd.certificates.len();
        for cert_der in &sd.certificates {
            let _ = hitls_pki::x509::Certificate::from_der(cert_der);
        }
    }
    if let Some(dd) = &cms.digested_data {
        let _ = dd.version;
        let _ = dd.digest.len();
    }
    if let Some(ad) = &cms.authenticated_data {
        let _ = ad.version;
        let _ = ad.mac.len();
    }
});
