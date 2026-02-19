//! TLS certificate verification orchestration.
//!
//! Shared certificate chain + hostname verification called by all client handshake paths.

use crate::config::TlsConfig;
use hitls_pki::x509::hostname::verify_hostname;
use hitls_pki::x509::verify::CertificateVerifier;
use hitls_pki::x509::Certificate;
use hitls_types::TlsError;

/// Information passed to the certificate verification callback.
#[derive(Debug)]
pub struct CertVerifyInfo {
    /// The result of chain verification (Ok or error message).
    pub chain_result: Result<(), String>,
    /// The result of hostname verification (Ok or error message).
    pub hostname_result: Result<(), String>,
    /// The server certificate chain (DER-encoded, leaf first).
    pub cert_chain: Vec<Vec<u8>>,
    /// The hostname that was checked (if any).
    pub hostname: Option<String>,
}

/// Verify the server certificate chain and hostname.
///
/// Called by TLS 1.2/1.3/DTLS/TLCP/DTLCP clients after receiving the server's
/// Certificate message.
///
/// 1. If `!config.verify_peer` → return Ok(()) immediately
/// 2. Parse DER certs → build CertificateVerifier → verify chain
/// 3. If `config.verify_hostname` && `config.server_name` is set → verify hostname
/// 4. If `config.cert_verify_callback` is set → call it (can override results)
/// 5. Otherwise, both chain and hostname must pass
pub fn verify_server_certificate(
    config: &TlsConfig,
    cert_chain_der: &[Vec<u8>],
) -> Result<(), TlsError> {
    if !config.verify_peer {
        return Ok(());
    }

    if cert_chain_der.is_empty() {
        return Err(TlsError::CertVerifyFailed("empty certificate chain".into()));
    }

    // Parse leaf certificate
    let leaf = Certificate::from_der(&cert_chain_der[0]).map_err(|e| {
        TlsError::CertVerifyFailed(format!("failed to parse leaf certificate: {e}"))
    })?;

    // Parse intermediate certificates
    let intermediates: Vec<Certificate> = cert_chain_der[1..]
        .iter()
        .filter_map(|der| Certificate::from_der(der).ok())
        .collect();

    // Chain verification
    let chain_result = if config.trusted_certs.is_empty() {
        Err("no trusted certificates configured".to_string())
    } else {
        let mut verifier = CertificateVerifier::new();
        for trusted_der in &config.trusted_certs {
            if let Ok(trusted) = Certificate::from_der(trusted_der) {
                verifier.add_trusted_cert(trusted);
            }
        }
        verifier
            .verify_cert(&leaf, &intermediates)
            .map(|_| ())
            .map_err(|e| e.to_string())
    };

    // Hostname verification
    let hostname_result = if config.verify_hostname {
        if let Some(ref server_name) = config.server_name {
            verify_hostname(&leaf, server_name).map_err(|e| e.to_string())
        } else {
            Ok(()) // No server_name set — skip hostname check
        }
    } else {
        Ok(())
    };

    // If a callback is set, let it decide
    if let Some(ref cb) = config.cert_verify_callback {
        let info = CertVerifyInfo {
            chain_result,
            hostname_result,
            cert_chain: cert_chain_der.to_vec(),
            hostname: config.server_name.clone(),
        };
        return cb(&info)
            .map_err(|reason| TlsError::CertVerifyFailed(format!("callback rejected: {reason}")));
    }

    // Default: both must pass
    if let Err(e) = chain_result {
        return Err(TlsError::CertVerifyFailed(format!("chain: {e}")));
    }
    if let Err(e) = hostname_result {
        return Err(TlsError::CertVerifyFailed(format!("hostname: {e}")));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CertVerifyCallback, TlsConfig};
    use crate::TlsRole;
    use std::sync::Arc;

    /// Helper: generate a self-signed Ed25519 certificate DER for "localhost".
    fn make_self_signed_cert_der(cn: &str) -> Vec<u8> {
        use hitls_pki::x509::{CertificateBuilder, DistinguishedName, SigningKey};
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".into(), cn.into())],
        };
        let cert = CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_900_000_000).unwrap();
        cert.raw
    }

    // -------------------------------------------------------
    // 1. verify_peer=false bypasses all checks
    // -------------------------------------------------------

    #[test]
    fn test_verify_skipped_when_verify_peer_false() {
        // Even an empty chain succeeds when verify_peer is false
        let config = TlsConfig::builder().verify_peer(false).build();
        assert!(verify_server_certificate(&config, &[]).is_ok());
    }

    #[test]
    fn test_verify_skipped_invalid_der_when_verify_peer_false() {
        let config = TlsConfig::builder().verify_peer(false).build();
        // Garbage DER should be accepted because verify_peer=false
        assert!(verify_server_certificate(&config, &[vec![0xFF, 0x00, 0x01]]).is_ok());
    }

    // -------------------------------------------------------
    // 2. Empty chain rejected
    // -------------------------------------------------------

    #[test]
    fn test_verify_empty_chain_rejected() {
        let config = TlsConfig::builder()
            .role(TlsRole::Client)
            .verify_peer(true)
            .build();
        let result = verify_server_certificate(&config, &[]);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("empty certificate chain"), "unexpected: {msg}");
    }

    // -------------------------------------------------------
    // 3. Invalid DER in leaf certificate
    // -------------------------------------------------------

    #[test]
    fn test_verify_invalid_der_rejected() {
        let config = TlsConfig::builder()
            .role(TlsRole::Client)
            .verify_peer(true)
            .build();
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let result = verify_server_certificate(&config, &[garbage]);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("failed to parse leaf certificate"),
            "unexpected: {msg}"
        );
    }

    // -------------------------------------------------------
    // 4. Chain fails when no trusted certs
    // -------------------------------------------------------

    #[test]
    fn test_verify_no_trusted_certs_fails_chain() {
        let cert_der = make_self_signed_cert_der("localhost");
        let config = TlsConfig::builder()
            .role(TlsRole::Client)
            .verify_peer(true)
            .verify_hostname(false)
            .build();
        // verify_peer=true, no trusted_certs → chain fails
        let result = verify_server_certificate(&config, &[cert_der]);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("no trusted certificates configured"),
            "unexpected: {msg}"
        );
    }

    // -------------------------------------------------------
    // 5. Hostname verification skipped when verify_hostname=false
    // -------------------------------------------------------

    #[test]
    fn test_verify_hostname_skipped_when_disabled() {
        let cert_der = make_self_signed_cert_der("localhost");
        // Use the cert itself as trusted → chain passes
        let config = TlsConfig::builder()
            .role(TlsRole::Client)
            .verify_peer(true)
            .verify_hostname(false)
            .trusted_cert(cert_der.clone())
            .build();
        // Chain passes (self-signed, trusted), hostname skipped → Ok
        let result = verify_server_certificate(&config, &[cert_der]);
        assert!(result.is_ok(), "expected Ok but got: {:?}", result.err());
    }

    // -------------------------------------------------------
    // 6. Hostname skipped when no server_name set
    // -------------------------------------------------------

    #[test]
    fn test_verify_hostname_skipped_when_no_server_name() {
        let cert_der = make_self_signed_cert_der("localhost");
        // verify_hostname=true but no server_name → hostname check is skipped
        let config = TlsConfig::builder()
            .role(TlsRole::Client)
            .verify_peer(true)
            .verify_hostname(true) // enabled, but no server_name
            .trusted_cert(cert_der.clone())
            .build();
        // No server_name → hostname_result = Ok(); chain passes → Ok
        let result = verify_server_certificate(&config, &[cert_der]);
        assert!(result.is_ok(), "expected Ok but got: {:?}", result.err());
    }

    // -------------------------------------------------------
    // 7. Callback overrides: accept despite chain failure
    // -------------------------------------------------------

    #[test]
    fn test_verify_callback_accepts_despite_chain_failure() {
        let cert_der = make_self_signed_cert_der("example.com");
        // Callback always returns Ok → accepts even without trusted certs
        let cb: CertVerifyCallback = Arc::new(|_info| Ok(()));
        let config = TlsConfig::builder()
            .role(TlsRole::Client)
            .verify_peer(true)
            .verify_hostname(false)
            .cert_verify_callback(cb)
            .build();
        // No trusted certs → chain would fail, but callback accepts
        assert!(verify_server_certificate(&config, &[cert_der]).is_ok());
    }

    // -------------------------------------------------------
    // 8. Callback overrides: reject despite valid chain
    // -------------------------------------------------------

    #[test]
    fn test_verify_callback_rejects_despite_valid_chain() {
        let cert_der = make_self_signed_cert_der("localhost");
        // Callback always rejects
        let cb: CertVerifyCallback = Arc::new(|_info| Err("policy violation".to_string()));
        let config = TlsConfig::builder()
            .role(TlsRole::Client)
            .verify_peer(true)
            .verify_hostname(false)
            .trusted_cert(cert_der.clone())
            .cert_verify_callback(cb)
            .build();
        let result = verify_server_certificate(&config, &[cert_der]);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("callback rejected"), "unexpected: {msg}");
        assert!(msg.contains("policy violation"), "unexpected: {msg}");
    }

    // -------------------------------------------------------
    // 9. Callback receives correct CertVerifyInfo fields
    // -------------------------------------------------------

    #[test]
    fn test_verify_callback_receives_correct_info() {
        use std::sync::Mutex;
        let cert_der = make_self_signed_cert_der("example.com");
        let received_hostname: Arc<Mutex<Option<Option<String>>>> = Arc::new(Mutex::new(None));
        let received_chain_len: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(None));
        let received_chain_err: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

        let rh = received_hostname.clone();
        let rcl = received_chain_len.clone();
        let rce = received_chain_err.clone();

        let cb: CertVerifyCallback = Arc::new(move |info| {
            *rh.lock().unwrap() = Some(info.hostname.clone());
            *rcl.lock().unwrap() = Some(info.cert_chain.len());
            *rce.lock().unwrap() = info.chain_result.is_err();
            Ok(()) // accept regardless
        });

        let config = TlsConfig::builder()
            .role(TlsRole::Client)
            .verify_peer(true)
            .verify_hostname(true)
            .server_name("example.com")
            .cert_verify_callback(cb)
            .build();

        let _ = verify_server_certificate(&config, &[cert_der]);

        // Callback should have been invoked with the correct info
        assert_eq!(
            *received_hostname.lock().unwrap(),
            Some(Some("example.com".to_string()))
        );
        assert_eq!(*received_chain_len.lock().unwrap(), Some(1));
        // No trusted certs → chain_result was Err
        assert!(*received_chain_err.lock().unwrap());
    }

    // -------------------------------------------------------
    // 10. Hostname mismatch fails when verify_hostname=true
    // -------------------------------------------------------

    #[test]
    fn test_verify_hostname_mismatch_fails() {
        let cert_der = make_self_signed_cert_der("localhost"); // CN=localhost
                                                               // Trust the cert, but check against "example.com" → hostname mismatch
        let config = TlsConfig::builder()
            .role(TlsRole::Client)
            .verify_peer(true)
            .verify_hostname(true)
            .server_name("example.com") // mismatch with CN=localhost
            .trusted_cert(cert_der.clone())
            .build();
        let result = verify_server_certificate(&config, &[cert_der]);
        assert!(result.is_err(), "expected hostname mismatch error");
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("hostname"), "unexpected: {msg}");
    }

    // -------------------------------------------------------
    // 11. CertVerifyInfo Debug impl works
    // -------------------------------------------------------

    #[test]
    fn test_cert_verify_info_debug() {
        let info = CertVerifyInfo {
            chain_result: Ok(()),
            hostname_result: Err("mismatch".to_string()),
            cert_chain: vec![vec![0x01, 0x02]],
            hostname: Some("example.com".to_string()),
        };
        let s = format!("{info:?}");
        assert!(s.contains("hostname_result"));
        assert!(s.contains("mismatch"));
    }

    // -------------------------------------------------------
    // 12. Callback not invoked when verify_peer=false
    // -------------------------------------------------------

    #[test]
    fn test_callback_not_invoked_when_verify_peer_false() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let invoked = Arc::new(AtomicBool::new(false));
        let inv = invoked.clone();
        let cb: CertVerifyCallback = Arc::new(move |_info| {
            inv.store(true, Ordering::Relaxed);
            Ok(())
        });

        let config = TlsConfig::builder()
            .verify_peer(false)
            .cert_verify_callback(cb)
            .build();

        // verify_peer=false → early return, callback never invoked
        let _ = verify_server_certificate(&config, &[vec![0x30, 0x00]]);
        assert!(
            !invoked.load(Ordering::Relaxed),
            "callback must not be invoked when verify_peer=false"
        );
    }

    // -------------------------------------------------------
    // 13. Hostname CN match succeeds
    // -------------------------------------------------------

    #[test]
    fn test_verify_hostname_cn_match_succeeds() {
        let cert_der = make_self_signed_cert_der("myhost.example.com");
        let config = TlsConfig::builder()
            .role(TlsRole::Client)
            .verify_peer(true)
            .verify_hostname(true)
            .server_name("myhost.example.com")
            .trusted_cert(cert_der.clone())
            .build();
        // CN matches server_name, chain trusted → Ok
        let result = verify_server_certificate(&config, &[cert_der]);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
    }

    // -------------------------------------------------------
    // 14. Multiple trusted certs — one matches
    // -------------------------------------------------------

    #[test]
    fn test_verify_multiple_trusted_certs() {
        let cert_a_der = make_self_signed_cert_der("server-a.example.com");
        let cert_b_der = make_self_signed_cert_der("server-b.example.com");

        // Trust both certs, present cert_b → should verify
        let config = TlsConfig::builder()
            .role(TlsRole::Client)
            .verify_peer(true)
            .verify_hostname(false)
            .trusted_cert(cert_a_der)
            .trusted_cert(cert_b_der.clone())
            .build();
        let result = verify_server_certificate(&config, &[cert_b_der]);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
    }

    // -------------------------------------------------------
    // 15. Wrong trusted cert fails chain
    // -------------------------------------------------------

    #[test]
    fn test_verify_wrong_trusted_cert_fails() {
        let cert_a_der = make_self_signed_cert_der("server-a.example.com");
        let cert_b_der = make_self_signed_cert_der("server-b.example.com");

        // Only trust cert_a, present cert_b → chain should fail
        let config = TlsConfig::builder()
            .role(TlsRole::Client)
            .verify_peer(true)
            .verify_hostname(false)
            .trusted_cert(cert_a_der)
            .build();
        let result = verify_server_certificate(&config, &[cert_b_der]);
        assert!(result.is_err(), "expected chain verification to fail");
    }

    // -------------------------------------------------------
    // 16. Callback receives hostname_result error on mismatch
    // -------------------------------------------------------

    #[test]
    fn test_callback_receives_hostname_error() {
        use std::sync::Mutex;
        let cert_der = make_self_signed_cert_der("localhost");
        let hostname_was_err: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
        let hwe = hostname_was_err.clone();

        let cb: CertVerifyCallback = Arc::new(move |info| {
            *hwe.lock().unwrap() = info.hostname_result.is_err();
            Ok(()) // accept anyway
        });

        let config = TlsConfig::builder()
            .role(TlsRole::Client)
            .verify_peer(true)
            .verify_hostname(true)
            .server_name("wrong-host.example.com")
            .trusted_cert(cert_der.clone())
            .cert_verify_callback(cb)
            .build();

        // Should succeed because callback accepts
        assert!(verify_server_certificate(&config, &[cert_der]).is_ok());
        // But callback should have seen hostname error
        assert!(*hostname_was_err.lock().unwrap());
    }
}
