//! Extension Negotiation E2E Tests (Phase T105)
//!
//! Tests ALPN, SNI, group negotiation/HRR, max fragment length,
//! record size limit, and combined extension negotiation over TCP loopback.

use hitls_integration_tests::*;
use hitls_tls::config::{MaxFragmentLength, TlsConfig};
use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
use hitls_tls::crypt::{NamedGroup, SignatureScheme};
use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

// =========================================================================
// ALPN tests
// =========================================================================

/// TLS 1.3: Client [h2, spdy], Server [grpc, mqtt] — no overlap → handshake OK, alpn = None.
#[test]
fn test_tls13_alpn_no_common_protocol() {
    let (cert_chain, server_key) = make_ed25519_server_identity();
    let (tx, rx) = mpsc::channel::<Option<Vec<u8>>>();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .alpn(&[b"grpc", b"mqtt"])
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let alpn = conn.alpn_protocol().map(|p| p.to_vec());
        tx.send(alpn).unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
        let _ = conn.shutdown();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .alpn(&[b"h2", b"spdy"])
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    let client_alpn = conn.alpn_protocol().map(|p| p.to_vec());
    assert_eq!(client_alpn, None, "client ALPN should be None (no overlap)");

    conn.write(b"ping").unwrap();
    let mut buf = [0u8; 32];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();

    server_handle.join().unwrap();
    let server_alpn = rx.recv().unwrap();
    assert_eq!(server_alpn, None, "server ALPN should be None (no overlap)");
}

/// TLS 1.2: Client [h2, http/1.1], Server [http/1.1, h2] → server preference: http/1.1.
#[test]
fn test_tls12_alpn_server_selects_first_match() {
    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let (tx, rx) = mpsc::channel::<Option<Vec<u8>>>();

    let suites = [CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .alpn(&[b"http/1.1", b"h2"])
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let alpn = conn.alpn_protocol().map(|p| p.to_vec());
        tx.send(alpn).unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
        let _ = conn.shutdown();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .alpn(&[b"h2", b"http/1.1"])
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    let client_alpn = conn.alpn_protocol().map(|p| p.to_vec());
    assert_eq!(
        client_alpn,
        Some(b"http/1.1".to_vec()),
        "server preference should win: http/1.1"
    );

    conn.write(b"ping").unwrap();
    let mut buf = [0u8; 32];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();

    server_handle.join().unwrap();
    let server_alpn = rx.recv().unwrap();
    assert_eq!(
        server_alpn,
        Some(b"http/1.1".to_vec()),
        "server ALPN should be http/1.1"
    );
}

/// TLS 1.2: Client [h2], Server [grpc] — no overlap → handshake OK, alpn = None.
#[test]
fn test_tls12_alpn_no_common_protocol() {
    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let (tx, rx) = mpsc::channel::<Option<Vec<u8>>>();

    let suites = [CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .alpn(&[b"grpc"])
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let alpn = conn.alpn_protocol().map(|p| p.to_vec());
        tx.send(alpn).unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
        let _ = conn.shutdown();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .alpn(&[b"h2"])
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    let client_alpn = conn.alpn_protocol().map(|p| p.to_vec());
    assert_eq!(client_alpn, None, "client ALPN should be None (no overlap)");

    conn.write(b"ping").unwrap();
    let mut buf = [0u8; 32];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();

    server_handle.join().unwrap();
    let server_alpn = rx.recv().unwrap();
    assert_eq!(server_alpn, None, "server ALPN should be None (no overlap)");
}

// =========================================================================
// SNI tests
// =========================================================================

/// TLS 1.3: Client sets server_name, verify it appears on both sides.
#[test]
fn test_tls13_sni_propagated_to_both_sides() {
    let (cert_chain, server_key) = make_ed25519_server_identity();
    let (tx, rx) = mpsc::channel::<Option<String>>();

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
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let sni = conn.server_name().map(|s| s.to_string());
        tx.send(sni).unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
        let _ = conn.shutdown();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .server_name("app.example.com")
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    let client_sni = conn.server_name().map(|s| s.to_string());
    assert_eq!(
        client_sni.as_deref(),
        Some("app.example.com"),
        "client server_name() should reflect configured SNI"
    );

    conn.write(b"ping").unwrap();
    let mut buf = [0u8; 32];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();

    server_handle.join().unwrap();
    let server_sni = rx.recv().unwrap();
    assert_eq!(
        server_sni.as_deref(),
        Some("app.example.com"),
        "server server_name() should see client's SNI"
    );
}

/// TLS 1.2: Client sets server_name, verify it appears on both sides.
#[test]
fn test_tls12_sni_visible_on_server() {
    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let (tx, rx) = mpsc::channel::<Option<String>>();

    let suites = [CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
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
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let sni = conn.server_name().map(|s| s.to_string());
        tx.send(sni).unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
        let _ = conn.shutdown();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .server_name("legacy.example.com")
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    let client_sni = conn.server_name().map(|s| s.to_string());
    assert_eq!(
        client_sni.as_deref(),
        Some("legacy.example.com"),
        "client server_name() should reflect configured SNI"
    );

    conn.write(b"ping").unwrap();
    let mut buf = [0u8; 32];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();

    server_handle.join().unwrap();
    let server_sni = rx.recv().unwrap();
    assert_eq!(
        server_sni.as_deref(),
        Some("legacy.example.com"),
        "server should see client SNI"
    );
}

// =========================================================================
// Group negotiation tests
// =========================================================================

/// TLS 1.3: Client [X25519, P256], Server [P256, X25519]. Client generates key_share for
/// X25519 (first in its list), server finds it in the key_share entries → X25519 selected.
#[test]
fn test_tls13_group_server_preference() {
    let (cert_chain, server_key) = make_ed25519_server_identity();
    let (tx, rx) = mpsc::channel::<Option<NamedGroup>>();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .supported_groups(&[NamedGroup::SECP256R1, NamedGroup::X25519])
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let group = conn.negotiated_group();
        tx.send(group).unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
        let _ = conn.shutdown();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .supported_groups(&[NamedGroup::X25519, NamedGroup::SECP256R1])
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    let client_group = conn.negotiated_group();
    // Client sends key_share for X25519 (first in its list); server uses it
    assert_eq!(
        client_group,
        Some(NamedGroup::X25519),
        "should negotiate X25519 (client's first key_share)"
    );

    conn.write(b"ping").unwrap();
    let mut buf = [0u8; 32];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();

    server_handle.join().unwrap();
    let server_group = rx.recv().unwrap();
    assert_eq!(server_group, Some(NamedGroup::X25519));
}

/// TLS 1.3: Client key_share for P256, but server wants X25519 only → HRR → success.
#[test]
fn test_tls13_group_mismatch_triggers_hrr() {
    let (cert_chain, server_key) = make_ed25519_server_identity();
    let (tx, rx) = mpsc::channel::<Option<NamedGroup>>();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .supported_groups(&[NamedGroup::X25519])
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let group = conn.negotiated_group();
        tx.send(group).unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
        let _ = conn.shutdown();
    });

    // Client: supported_groups has P256 first (generates key_share for it) + X25519
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .supported_groups(&[NamedGroup::SECP256R1, NamedGroup::X25519])
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    let client_group = conn.negotiated_group();
    assert_eq!(
        client_group,
        Some(NamedGroup::X25519),
        "HRR should force X25519"
    );

    conn.write(b"hrr-test").unwrap();
    let mut buf = [0u8; 32];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"hrr-test");

    let _ = conn.shutdown();
    server_handle.join().unwrap();
    let server_group = rx.recv().unwrap();
    assert_eq!(server_group, Some(NamedGroup::X25519));
}

/// TLS 1.3: Client [P256 only], Server [X448 only] → no common group → handshake failure.
#[test]
fn test_tls13_no_common_group_fails() {
    let (cert_chain, server_key) = make_ed25519_server_identity();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .supported_groups(&[NamedGroup::X448])
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        let _ = conn.handshake(); // expected to fail
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .supported_groups(&[NamedGroup::SECP256R1])
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    let result = conn.handshake();
    assert!(
        result.is_err(),
        "handshake should fail with no common group"
    );

    server_handle.join().unwrap();
}

// =========================================================================
// Fragment / Record Size Limit tests
// =========================================================================

/// TLS 1.2: Client sets MFL=2048, handshake + data exchange works.
#[test]
fn test_tls12_max_fragment_length_e2e() {
    let (cert_chain, server_key) = make_ecdsa_server_identity();

    let suites = [CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .max_fragment_length(MaxFragmentLength::Bits2048)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
        let _ = conn.shutdown();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .max_fragment_length(MaxFragmentLength::Bits2048)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    assert_eq!(conn.version(), Some(TlsVersion::Tls12));

    conn.write(b"mfl-test-data").unwrap();
    let mut buf = [0u8; 256];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"mfl-test-data");

    let _ = conn.shutdown();
    server_handle.join().unwrap();
}

/// TLS 1.3: Client RSL=2048, Server RSL=4096, handshake + data exchange.
#[test]
fn test_tls13_record_size_limit_e2e() {
    let (cert_chain, server_key) = make_ed25519_server_identity();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .record_size_limit(4096)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
        let _ = conn.shutdown();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .record_size_limit(2048)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    assert_eq!(conn.version(), Some(TlsVersion::Tls13));

    conn.write(b"rsl-tls13-test").unwrap();
    let mut buf = [0u8; 256];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"rsl-tls13-test");

    let _ = conn.shutdown();
    server_handle.join().unwrap();
}

// =========================================================================
// Combined tests
// =========================================================================

/// TLS 1.2: Client RSL=1024, Server RSL=2048, handshake + data exchange.
#[test]
fn test_tls12_record_size_limit_e2e() {
    let (cert_chain, server_key) = make_ecdsa_server_identity();

    let suites = [CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .record_size_limit(2048)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
        let _ = conn.shutdown();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .record_size_limit(1024)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    assert_eq!(conn.version(), Some(TlsVersion::Tls12));

    conn.write(b"rsl-tls12-test").unwrap();
    let mut buf = [0u8; 256];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"rsl-tls12-test");

    let _ = conn.shutdown();
    server_handle.join().unwrap();
}

/// TLS 1.3: ALPN [h2] + SNI "multi.example.com" + X25519, verify all in ConnectionInfo.
#[test]
fn test_tls13_multiple_extensions_combined() {
    let (cert_chain, server_key) = make_ed25519_server_identity();
    // Send back (alpn, sni, group) from server
    let (tx, rx) = mpsc::channel::<(Option<Vec<u8>>, Option<String>, Option<NamedGroup>)>();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .supported_groups(&[NamedGroup::X25519])
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .alpn(&[b"h2"])
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let alpn = conn.alpn_protocol().map(|p| p.to_vec());
        let sni = conn.server_name().map(|s| s.to_string());
        let group = conn.negotiated_group();
        tx.send((alpn, sni, group)).unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
        let _ = conn.shutdown();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .supported_groups(&[NamedGroup::X25519])
        .verify_peer(false)
        .alpn(&[b"h2"])
        .server_name("multi.example.com")
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    // Verify client-side ConnectionInfo
    let info = conn.connection_info().expect("should have connection info");
    assert_eq!(
        info.alpn_protocol,
        Some(b"h2".to_vec()),
        "client ConnectionInfo.alpn"
    );
    assert_eq!(
        info.server_name.as_deref(),
        Some("multi.example.com"),
        "client ConnectionInfo.server_name"
    );
    assert_eq!(
        info.negotiated_group,
        Some(NamedGroup::X25519),
        "client ConnectionInfo.negotiated_group"
    );

    conn.write(b"combined").unwrap();
    let mut buf = [0u8; 32];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"combined");

    let _ = conn.shutdown();
    server_handle.join().unwrap();

    // Verify server-side values
    let (server_alpn, server_sni, server_group) = rx.recv().unwrap();
    assert_eq!(server_alpn, Some(b"h2".to_vec()), "server ALPN");
    assert_eq!(
        server_sni.as_deref(),
        Some("multi.example.com"),
        "server SNI"
    );
    assert_eq!(server_group, Some(NamedGroup::X25519), "server group");
}
