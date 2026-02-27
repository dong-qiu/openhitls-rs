//! OpenSSL CLI interop tests (Phase T160).
//!
//! Verifies that hitls-rs can interoperate with OpenSSL's `s_client` and
//! `s_server` commands. These tests require OpenSSL 3.x CLI to be installed.
//!
//! All tests are marked `#[ignore]` because:
//! - They depend on the `openssl` binary being available in `$PATH`
//! - They spawn external processes and bind TCP ports
//! - They may be slow due to process startup overhead
//!
//! Run with: `cargo test -p hitls-integration-tests --ignored -- openssl`

use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

/// Check if `openssl` binary is available.
fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Find a free TCP port.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

// ============================================================
// Test 1: OpenSSL s_client → hitls-rs TLS 1.3 server
// ============================================================

#[test]
#[ignore]
fn test_openssl_s_client_tls13() {
    if !openssl_available() {
        eprintln!("openssl not found, skipping");
        return;
    }

    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::TlsServerConnection;
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};

    let (cert_chain, server_key) = hitls_integration_tests::make_ecdsa_server_identity();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // Spawn hitls-rs TLS 1.3 server in a thread
    let server_handle = thread::spawn(move || {
        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .cipher_suites(&[CipherSuite::TLS_AES_128_GCM_SHA256])
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();

        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();

        // Server handshake succeeded — that's the primary verification.
        // Try to read, but don't fail if s_client closes early.
        let mut buf = [0u8; 256];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();
    });

    // Give server a moment to start accepting
    thread::sleep(Duration::from_millis(50));

    // Run openssl s_client (with -brief for compact output)
    let output = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{}", addr.port()),
            "-tls1_3",
            "-brief",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run openssl s_client");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    // -brief outputs connection summary; check for protocol version
    assert!(
        combined.contains("TLSv1.3") || combined.contains("DONE") || output.status.success(),
        "s_client should complete TLS 1.3 handshake.\nstdout: {stdout}\nstderr: {stderr}\nexit: {}",
        output.status
    );

    server_handle.join().unwrap();
}

// ============================================================
// Test 2: hitls-rs TLS 1.2 client → OpenSSL s_server
//
// Known issue: TLS 1.2 handshake with OpenSSL s_server fails with
// "server Finished verify_data mismatch", indicating a difference in
// handshake transcript computation. This test captures the interop gap
// for future investigation.
// ============================================================

#[test]
#[ignore]
fn test_openssl_s_server_tls12() {
    if !openssl_available() {
        eprintln!("openssl not found, skipping");
        return;
    }

    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::Tls12ClientConnection;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};

    let port = free_port();

    // Generate self-signed ECDSA P-256 cert + key using openssl CLI
    let tmp_dir = std::env::temp_dir().join(format!("hitls_interop_{port}"));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let cert_path = tmp_dir.join("cert.pem");
    let key_path = tmp_dir.join("key.pem");

    let gen_status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-keyout",
        ])
        .arg(&key_path)
        .arg("-out")
        .arg(&cert_path)
        .args(["-nodes", "-days", "1", "-subj", "/CN=localhost", "-batch"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("Failed to generate cert with openssl");
    assert!(gen_status.success(), "openssl req -x509 failed");

    // Start openssl s_server with -www (required for proper handshake handling)
    // and -no_tls1_3 to force TLS 1.2 negotiation
    let mut s_server = Command::new("openssl")
        .args(["s_server", "-4", "-cert"])
        .arg(&cert_path)
        .arg("-key")
        .arg(&key_path)
        .args(["-port", &port.to_string(), "-www", "-no_tls1_3"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn openssl s_server");

    // Wait for s_server to start listening
    thread::sleep(Duration::from_secs(1));

    // Connect with hitls-rs TLS 1.2 client
    // Must specify supported_groups and signature_algorithms for OpenSSL compat
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
        .supported_groups(&[NamedGroup::SECP256R1])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_secs(5),
    )
    .expect("Failed to connect to s_server");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let mut conn = Tls12ClientConnection::new(stream, client_config);
    let handshake_result = conn.handshake();

    // Verify handshake succeeded
    assert!(
        handshake_result.is_ok(),
        "TLS 1.2 handshake with s_server should succeed: {:?}",
        handshake_result.err()
    );

    // Verify cipher suite was negotiated correctly
    let suite = conn.cipher_suite().unwrap();
    assert_eq!(
        suite,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        "Should negotiate ECDHE-ECDSA-AES128-GCM-SHA256"
    );

    let _ = conn.shutdown();

    // Kill s_server
    let _ = s_server.kill();
    let _ = s_server.wait();

    // Cleanup temp files
    let _ = std::fs::remove_dir_all(&tmp_dir);
}
