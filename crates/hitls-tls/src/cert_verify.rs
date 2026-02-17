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
