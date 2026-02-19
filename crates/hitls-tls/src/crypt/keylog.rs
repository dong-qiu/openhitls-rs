//! NSS Key Log Format support (SSLKEYLOGFILE).
//!
//! Provides Wireshark-compatible key logging for TLS debugging.
//! Format: `<label> <client_random_hex> <secret_hex>`
//!
//! Labels:
//! - TLS 1.3: CLIENT_EARLY_TRAFFIC_SECRET, CLIENT_HANDSHAKE_TRAFFIC_SECRET,
//!   SERVER_HANDSHAKE_TRAFFIC_SECRET, CLIENT_TRAFFIC_SECRET_0,
//!   SERVER_TRAFFIC_SECRET_0, EXPORTER_SECRET
//! - TLS 1.2 / DTLS 1.2 / TLCP / DTLCP: CLIENT_RANDOM

use crate::config::TlsConfig;

/// Convert bytes to lowercase hex string.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Log a key material line in NSS key log format.
///
/// Calls the `key_log_callback` on `config` (if set) with a line:
/// `<label> <client_random_hex> <secret_hex>`
pub fn log_key(config: &TlsConfig, label: &str, client_random: &[u8; 32], secret: &[u8]) {
    if let Some(cb) = &config.key_log_callback {
        let line = format!("{} {} {}", label, to_hex(client_random), to_hex(secret));
        cb(&line);
    }
}

/// Log TLS 1.2 / DTLS 1.2 / TLCP / DTLCP master secret.
pub fn log_master_secret(config: &TlsConfig, client_random: &[u8; 32], master_secret: &[u8]) {
    log_key(config, "CLIENT_RANDOM", client_random, master_secret);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_to_hex() {
        assert_eq!(to_hex(&[0x01, 0xab, 0xff]), "01abff");
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn test_log_key_no_callback() {
        let config = TlsConfig::builder().build();
        // Should not panic
        log_key(&config, "CLIENT_RANDOM", &[0u8; 32], &[1, 2, 3]);
    }

    #[test]
    fn test_log_key_with_callback() {
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let lines_clone = lines.clone();
        let config = TlsConfig::builder()
            .key_log(Arc::new(move |line: &str| {
                lines_clone.lock().unwrap().push(line.to_string());
            }))
            .build();

        let client_random = [0x42u8; 32];
        let secret = [0xAB, 0xCD];
        log_key(&config, "CLIENT_RANDOM", &client_random, &secret);

        let logged = lines.lock().unwrap();
        assert_eq!(logged.len(), 1);
        let expected_cr_hex: String = "42".repeat(32);
        let expected = format!("CLIENT_RANDOM {} abcd", expected_cr_hex);
        assert_eq!(logged[0], expected);
    }

    #[test]
    fn test_log_master_secret() {
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let lines_clone = lines.clone();
        let config = TlsConfig::builder()
            .key_log(Arc::new(move |line: &str| {
                lines_clone.lock().unwrap().push(line.to_string());
            }))
            .build();

        log_master_secret(&config, &[0u8; 32], &[0xFF; 48]);
        let logged = lines.lock().unwrap();
        assert_eq!(logged.len(), 1);
        assert!(logged[0].starts_with("CLIENT_RANDOM "));
    }

    #[test]
    fn test_nss_format_compliance() {
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let lines_clone = lines.clone();
        let config = TlsConfig::builder()
            .key_log(Arc::new(move |line: &str| {
                lines_clone.lock().unwrap().push(line.to_string());
            }))
            .build();

        let cr = [0x01u8; 32];
        let secret = [0x02u8; 48];
        log_key(&config, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", &cr, &secret);

        let logged = lines.lock().unwrap();
        let parts: Vec<&str> = logged[0].split(' ').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
        assert_eq!(parts[1].len(), 64); // 32 bytes = 64 hex chars
        assert_eq!(parts[2].len(), 96); // 48 bytes = 96 hex chars
    }

    #[test]
    fn test_keylog_empty_secret() {
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let lines_clone = lines.clone();
        let config = TlsConfig::builder()
            .key_log(Arc::new(move |line: &str| {
                lines_clone.lock().unwrap().push(line.to_string());
            }))
            .build();

        log_key(&config, "TEST_LABEL", &[0xAA; 32], &[]);
        let logged = lines.lock().unwrap();
        let parts: Vec<&str> = logged[0].split(' ').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[2], ""); // empty secret → empty hex
    }

    #[test]
    fn test_keylog_multiple_calls_order() {
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let lines_clone = lines.clone();
        let config = TlsConfig::builder()
            .key_log(Arc::new(move |line: &str| {
                lines_clone.lock().unwrap().push(line.to_string());
            }))
            .build();

        log_key(&config, "LABEL_A", &[0x01; 32], &[0x10; 16]);
        log_key(&config, "LABEL_B", &[0x02; 32], &[0x20; 16]);
        log_key(&config, "LABEL_C", &[0x03; 32], &[0x30; 16]);

        let logged = lines.lock().unwrap();
        assert_eq!(logged.len(), 3);
        assert!(logged[0].starts_with("LABEL_A "));
        assert!(logged[1].starts_with("LABEL_B "));
        assert!(logged[2].starts_with("LABEL_C "));
    }

    #[test]
    fn test_to_hex_boundary_values() {
        assert_eq!(to_hex(&[0x00]), "00");
        assert_eq!(to_hex(&[0xFF]), "ff");
        assert_eq!(to_hex(&[0x00, 0xFF, 0x0A, 0xF0]), "00ff0af0");
        // Empty
        assert_eq!(to_hex(&[]), "");
        // Single byte
        assert_eq!(to_hex(&[0xAB]), "ab");
    }

    #[test]
    fn test_keylog_tls13_exporter_label() {
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let lines_clone = lines.clone();
        let config = TlsConfig::builder()
            .key_log(Arc::new(move |line: &str| {
                lines_clone.lock().unwrap().push(line.to_string());
            }))
            .build();

        log_key(&config, "EXPORTER_SECRET", &[0xBB; 32], &[0xCC; 32]);
        let logged = lines.lock().unwrap();
        assert!(logged[0].starts_with("EXPORTER_SECRET "));
        let parts: Vec<&str> = logged[0].split(' ').collect();
        assert_eq!(parts[2].len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_keylog_large_secret() {
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let lines_clone = lines.clone();
        let config = TlsConfig::builder()
            .key_log(Arc::new(move |line: &str| {
                lines_clone.lock().unwrap().push(line.to_string());
            }))
            .build();

        let large_secret = vec![0xDD; 256];
        log_key(&config, "LARGE_SECRET", &[0xEE; 32], &large_secret);
        let logged = lines.lock().unwrap();
        let parts: Vec<&str> = logged[0].split(' ').collect();
        assert_eq!(parts[2].len(), 512); // 256 bytes = 512 hex chars
    }
}
