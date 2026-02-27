//! Protocol attack scenario tests — downgrade, truncation, padding oracle resistance,
//! 0-RTT limits, renegotiation, and miscellaneous protocol abuse.
//!
//! Phase T163: D22 (High) — <10% protocol attack scenarios tested.

use hitls_integration_tests::*;

// ============================================================================
// Downgrade attacks
// ============================================================================

/// Client configured for TLS 1.3 only, server configured for TLS 1.2 only.
/// The handshake must fail cleanly — no fallback allowed.
#[test]
fn test_tls13_client_rejects_tls12_only_server() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::TlsClientConnection;
    use hitls_tls::connection12::Tls12ServerConnection;
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            let _ = conn.handshake();
        }
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let mut conn = TlsClientConnection::new(stream, client_config);
    assert!(
        conn.handshake().is_err(),
        "TLS 1.3-only client must reject TLS 1.2-only server"
    );
    server_handle.join().unwrap();
}

/// Server configured for TLS 1.3 only rejects TLS 1.2-only client.
#[test]
fn test_tls13_server_rejects_tls12_only_client() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::TlsServerConnection;
    use hitls_tls::connection12::Tls12ClientConnection;
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();
    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
            let mut conn = TlsServerConnection::new(stream, server_config);
            let _ = conn.handshake();
        }
    });

    let (cert2, key2) = make_ecdsa_server_identity();
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .certificate_chain(cert2)
        .private_key(key2)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    assert!(
        conn.handshake().is_err(),
        "TLS 1.2-only client must fail against TLS 1.3-only server"
    );
    server_handle.join().unwrap();
}

/// Client with min_version=TLS1.2 and server with max_version=TLS1.2 should succeed
/// (same version), proving version enforcement is granular.
#[test]
fn test_version_match_tls12_both_sides_succeeds() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_rsa_server_identity();
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];
    let suite = CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"version-ok").unwrap();
    let mut buf = [0u8; 64];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"version-ok");
    server_handle.join().unwrap();
}

// ============================================================================
// CBC padding oracle resistance
// ============================================================================

/// All invalid padding patterns must produce the same error type ("bad record MAC"),
/// not distinct errors for padding vs MAC failures — padding oracle resistance.
#[test]
fn test_cbc_invalid_padding_all_produce_same_error() {
    use hitls_tls::record::encryption12_cbc::{RecordDecryptor12Cbc, RecordEncryptor12Cbc};
    use hitls_tls::record::ContentType;

    let enc_key = vec![0x42u8; 16];
    let mac_key = vec![0xABu8; 32];

    // Encrypt a valid record first to get realistic ciphertext size
    let mut enc = RecordEncryptor12Cbc::new(enc_key.clone(), mac_key.clone(), 32);
    let valid_record = enc
        .encrypt_record(ContentType::ApplicationData, b"test payload data here")
        .unwrap();

    // Create records with different invalid content but correct structure
    // All should produce "bad record MAC" error, not distinct error types
    let mut error_messages = Vec::new();
    for tamper_byte in [0x00, 0x01, 0x0F, 0x10, 0x80, 0xFF] {
        let mut dec = RecordDecryptor12Cbc::new(enc_key.clone(), mac_key.clone(), 32);
        let mut record = valid_record.clone();
        // Tamper with last byte of ciphertext (affects padding byte after decrypt)
        let last = record.fragment.len() - 1;
        record.fragment[last] = tamper_byte;
        if let Err(e) = dec.decrypt_record(&record) {
            error_messages.push(e.to_string());
        }
    }

    // All errors should be the same type — "bad record MAC" (not "bad padding")
    assert!(
        !error_messages.is_empty(),
        "at least some tampered records must fail"
    );
    for msg in &error_messages {
        assert!(
            msg.contains("bad record MAC"),
            "expected 'bad record MAC' for all padding errors, got: {msg}"
        );
    }
}

/// MAC failure and padding failure both produce "bad record MAC" — indistinguishable.
#[test]
fn test_cbc_mac_vs_padding_failure_indistinguishable() {
    use hitls_tls::record::encryption12_cbc::{RecordDecryptor12Cbc, RecordEncryptor12Cbc};
    use hitls_tls::record::ContentType;

    let enc_key = vec![0x42u8; 16];
    let mac_key = vec![0xABu8; 32];

    // MAC failure: decrypt with wrong MAC key
    let mut enc1 = RecordEncryptor12Cbc::new(enc_key.clone(), mac_key.clone(), 32);
    let record1 = enc1
        .encrypt_record(ContentType::ApplicationData, b"payload")
        .unwrap();
    let mut dec_wrong_mac = RecordDecryptor12Cbc::new(enc_key.clone(), vec![0xCDu8; 32], 32);
    let mac_err = dec_wrong_mac.decrypt_record(&record1).unwrap_err();

    // Ciphertext tamper: same key but corrupted ciphertext (garbles both padding and MAC)
    let mut enc2 = RecordEncryptor12Cbc::new(enc_key.clone(), mac_key.clone(), 32);
    let mut record2 = enc2
        .encrypt_record(ContentType::ApplicationData, b"payload")
        .unwrap();
    record2.fragment[20] ^= 0xFF; // corrupt middle of ciphertext
    let mut dec_correct = RecordDecryptor12Cbc::new(enc_key, mac_key, 32);
    let tamper_err = dec_correct.decrypt_record(&record2).unwrap_err();

    // Both must produce identical error message
    assert_eq!(
        mac_err.to_string(),
        tamper_err.to_string(),
        "MAC failure and ciphertext tamper must produce identical errors"
    );
    assert!(mac_err.to_string().contains("bad record MAC"));
}

// ============================================================================
// Empty record DoS protection
// ============================================================================

/// Consecutive empty records beyond the limit must be rejected.
#[test]
fn test_empty_record_dos_limit_exceeded() {
    use hitls_tls::record::{ContentType, RecordLayer};

    let mut rl = RecordLayer::new();
    rl.empty_records_limit = 3;

    // First 3 empty records allowed
    for _ in 0..3 {
        rl.check_empty_record(ContentType::Handshake, 0).unwrap();
    }
    // 4th exceeds limit
    assert!(
        rl.check_empty_record(ContentType::Handshake, 0).is_err(),
        "4th empty record must be rejected when limit=3"
    );
}

/// Non-empty record resets the empty record counter, allowing more empty records.
#[test]
fn test_empty_record_counter_reset_on_data() {
    use hitls_tls::record::{ContentType, RecordLayer};

    let mut rl = RecordLayer::new();
    rl.empty_records_limit = 2;

    // Two empty records
    rl.check_empty_record(ContentType::Handshake, 0).unwrap();
    rl.check_empty_record(ContentType::Handshake, 0).unwrap();

    // Non-empty record resets counter
    rl.check_empty_record(ContentType::Handshake, 42).unwrap();
    assert_eq!(rl.empty_record_count, 0);

    // Two more empty records allowed again
    rl.check_empty_record(ContentType::Handshake, 0).unwrap();
    rl.check_empty_record(ContentType::Handshake, 0).unwrap();

    // 3rd consecutive empty record rejected
    assert!(rl.check_empty_record(ContentType::Handshake, 0).is_err());
}

// ============================================================================
// Cipher suite mismatch attacks
// ============================================================================

/// Client and server with completely disjoint cipher suites — handshake must fail.
#[test]
fn test_cipher_suite_mismatch_gcm_vs_cbc() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_rsa_server_identity();
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];

    // Server: only GCM-256
    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            let _ = conn.handshake();
        }
    });

    // Client: only CBC-128
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    assert!(
        conn.handshake().is_err(),
        "GCM-only server vs CBC-only client must fail"
    );
    server_handle.join().unwrap();
}

/// TLS 1.3 cipher suite mismatch — client offers only AES-256-GCM, server only AES-128-GCM.
#[test]
fn test_tls13_cipher_suite_mismatch() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .cipher_suites(&[CipherSuite::TLS_AES_128_GCM_SHA256])
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
            let mut conn = TlsServerConnection::new(stream, server_config);
            let _ = conn.handshake();
        }
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .cipher_suites(&[CipherSuite::TLS_AES_256_GCM_SHA384])
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let mut conn = TlsClientConnection::new(stream, client_config);
    assert!(
        conn.handshake().is_err(),
        "TLS 1.3 cipher suite mismatch must fail"
    );
    server_handle.join().unwrap();
}

// ============================================================================
// PSK key mismatch attack
// ============================================================================

/// Different PSK keys on client and server — handshake must fail (MAC verification).
#[test]
fn test_psk_key_mismatch_rejected() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let suite = CipherSuite::TLS_PSK_WITH_AES_256_GCM_SHA384;
    let sig_algs = [
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .psk(b"server-secret-psk-key-32-bytes!!".to_vec())
        .psk_identity_hint(b"hint".to_vec())
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            let _ = conn.handshake();
        }
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .psk(b"client-wrong-psk-key-32-bytes!!".to_vec())
        .psk_identity(b"client-id".to_vec())
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    assert!(
        conn.handshake().is_err(),
        "PSK key mismatch must cause handshake failure"
    );
    server_handle.join().unwrap();
}

// ============================================================================
// Record layer attacks
// ============================================================================

/// CBC sequence number tracking: records must be decrypted in order with
/// monotonically increasing sequence numbers.
#[test]
fn test_cbc_sequence_number_tracking() {
    use hitls_tls::record::encryption12_cbc::{RecordDecryptor12Cbc, RecordEncryptor12Cbc};
    use hitls_tls::record::ContentType;

    let enc_key = vec![0x42u8; 16];
    let mac_key = vec![0xABu8; 32];

    let mut enc = RecordEncryptor12Cbc::new(enc_key.clone(), mac_key.clone(), 32);
    let mut dec = RecordDecryptor12Cbc::new(enc_key, mac_key, 32);

    // Encrypt 3 records
    let r0 = enc
        .encrypt_record(ContentType::ApplicationData, b"msg0")
        .unwrap();
    let _r1 = enc
        .encrypt_record(ContentType::ApplicationData, b"msg1")
        .unwrap();
    let r2 = enc
        .encrypt_record(ContentType::ApplicationData, b"msg2")
        .unwrap();

    // Decrypt in order: must succeed
    assert_eq!(dec.decrypt_record(&r0).unwrap(), b"msg0");
    assert_eq!(dec.sequence_number(), 1);

    // Skip r1, try to decrypt r2 out of order — MAC mismatch because seq doesn't match
    let result = dec.decrypt_record(&r2);
    assert!(
        result.is_err(),
        "out-of-order record decryption must fail due to seq mismatch"
    );
}

/// Encrypt-Then-MAC also tracks sequence numbers and rejects replayed records.
#[test]
fn test_etm_sequence_number_tracking() {
    use hitls_tls::record::encryption12_cbc::{RecordDecryptor12EtM, RecordEncryptor12EtM};
    use hitls_tls::record::ContentType;

    let enc_key = vec![0x42u8; 16];
    let mac_key = vec![0xABu8; 32];

    let mut enc = RecordEncryptor12EtM::new(enc_key.clone(), mac_key.clone(), 32);
    let mut dec = RecordDecryptor12EtM::new(enc_key, mac_key, 32);

    let r0 = enc
        .encrypt_record(ContentType::ApplicationData, b"etm0")
        .unwrap();
    let _r1 = enc
        .encrypt_record(ContentType::ApplicationData, b"etm1")
        .unwrap();

    // Decrypt r0 correctly
    assert_eq!(dec.decrypt_record(&r0).unwrap(), b"etm0");
    assert_eq!(dec.sequence_number(), 1);

    // Try to replay r0 again — seq has advanced, MAC won't match
    let replay_result = dec.decrypt_record(&r0);
    assert!(
        replay_result.is_err(),
        "replayed EtM record must be rejected"
    );
}

// ============================================================================
// DTLS anti-replay window
// ============================================================================

/// DTLS anti-replay window rejects already-seen sequence numbers.
#[test]
fn test_dtls_anti_replay_rejects_duplicate() {
    use hitls_tls::record::anti_replay::AntiReplayWindow;

    let mut window = AntiReplayWindow::new();

    // Accept seq 0, 1, 2
    window.check_and_accept(0).unwrap();
    window.check_and_accept(1).unwrap();
    window.check_and_accept(2).unwrap();

    // Replay seq 1 — must be rejected
    assert!(
        window.check_and_accept(1).is_err(),
        "replayed DTLS seq must be rejected"
    );
    // Replay seq 0 — must be rejected
    assert!(
        window.check_and_accept(0).is_err(),
        "replayed DTLS seq 0 must be rejected"
    );

    // New seq 3 — accepted
    window.check_and_accept(3).unwrap();
}

/// DTLS anti-replay window handles large sequence number gaps correctly.
#[test]
fn test_dtls_anti_replay_large_gap() {
    use hitls_tls::record::anti_replay::AntiReplayWindow;

    let mut window = AntiReplayWindow::new();

    // Accept seq 0
    window.check_and_accept(0).unwrap();

    // Jump to seq 1000 (large gap)
    window.check_and_accept(1000).unwrap();

    // Seq 0 is now outside the window — should be rejected
    assert!(
        window.check_and_accept(0).is_err(),
        "seq 0 outside window after large gap must be rejected"
    );

    // Seq 999 is within the window (just before 1000)
    window.check_and_accept(999).unwrap();

    // Replay 999 — rejected
    assert!(window.check_and_accept(999).is_err());
}

// ============================================================================
// Fallback SCSV configuration
// ============================================================================

/// Verify that send_fallback_scsv configuration flag works correctly.
#[test]
fn test_fallback_scsv_config_propagation() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::TlsRole;

    // Default: fallback SCSV disabled
    let default_config = TlsConfig::builder().role(TlsRole::Client).build();
    assert!(
        !default_config.send_fallback_scsv,
        "fallback SCSV should be disabled by default"
    );

    // Explicitly enabled
    let enabled_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .send_fallback_scsv(true)
        .build();
    assert!(
        enabled_config.send_fallback_scsv,
        "fallback SCSV should be enabled when configured"
    );
}

/// Verify that allow_renegotiation configuration flag works correctly.
#[test]
fn test_renegotiation_config_propagation() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::TlsRole;

    // Default: renegotiation disabled
    let default_config = TlsConfig::builder().role(TlsRole::Server).build();
    assert!(
        !default_config.allow_renegotiation,
        "renegotiation should be disabled by default"
    );

    // Explicitly enabled
    let enabled_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .allow_renegotiation(true)
        .build();
    assert!(
        enabled_config.allow_renegotiation,
        "renegotiation should be enabled when configured"
    );
}
