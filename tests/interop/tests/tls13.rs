//! TLS 1.3 handshake, data, cipher suites, ALPN, and EKM integration tests.

use hitls_integration_tests::*;

#[test]
fn test_tcp_tls13_loopback_ed25519() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::{TcpListener, TcpStream};
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

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"Hello from client!");

        conn.write(b"Hello from server!").unwrap();
        conn.shutdown().unwrap();
    });

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    assert_eq!(conn.version(), Some(TlsVersion::Tls13));

    conn.write(b"Hello from client!").unwrap();

    let mut buf = [0u8; 256];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"Hello from server!");

    conn.shutdown().unwrap();
    server_handle.join().unwrap();
}

#[test]
fn test_tcp_tls13_loopback_large_payload() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::{TcpListener, TcpStream};
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

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .build();

    let payload: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
    let payload_clone = payload.clone();

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

        // Read all 64 KB (may arrive across multiple TLS records)
        let mut received = Vec::new();
        while received.len() < 65536 {
            let mut buf = [0u8; 16384];
            let n = conn.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        assert_eq!(received, payload_clone);

        // Echo back in chunks
        let mut offset = 0;
        while offset < received.len() {
            let end = (offset + 16000).min(received.len());
            conn.write(&received[offset..end]).unwrap();
            offset = end;
        }
        conn.shutdown().unwrap();
    });

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    // Write in chunks (TLS max fragment = 16384)
    let mut offset = 0;
    while offset < payload.len() {
        let end = (offset + 16000).min(payload.len());
        conn.write(&payload[offset..end]).unwrap();
        offset = end;
    }

    let mut received = Vec::new();
    while received.len() < 65536 {
        let mut buf = [0u8; 16384];
        let n = conn.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }
    assert_eq!(received, payload);

    conn.shutdown().unwrap();
    server_handle.join().unwrap();
}

#[test]
fn test_tcp_tls13_loopback_multi_message() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::{TcpListener, TcpStream};
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

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();

        for _ in 0..5 {
            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
        }
        conn.shutdown().unwrap();
    });

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    for i in 0..5u32 {
        let msg = format!("Message #{}", i + 1);
        conn.write(msg.as_bytes()).unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], msg.as_bytes());
    }

    conn.shutdown().unwrap();
    server_handle.join().unwrap();
}

#[test]
fn test_tls13_post_hs_auth_in_memory() {
    use hitls_tls::config::{ServerPrivateKey, TlsConfig};
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();

    // Create client Ed25519 identity
    let client_kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
    let client_seed = client_kp.seed().to_vec();
    let client_sk = hitls_pki::x509::SigningKey::Ed25519(client_kp);
    let client_dn = hitls_pki::x509::DistinguishedName {
        entries: vec![("CN".into(), "post-hs-client".into())],
    };
    let client_cert = hitls_pki::x509::CertificateBuilder::self_signed(
        client_dn,
        &client_sk,
        1_700_000_000,
        1_800_000_000,
    )
    .unwrap();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .post_handshake_auth(true)
        .client_certificate_chain(vec![client_cert.raw])
        .client_private_key(ServerPrivateKey::Ed25519(client_seed))
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();

        // Request post-handshake client auth
        let certs = conn.request_client_auth().unwrap();
        assert!(!certs.is_empty(), "should receive client cert");

        conn.write(b"post-hs auth ok").unwrap();
        conn.shutdown().unwrap();
    });

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    let mut buf = [0u8; 256];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"post-hs auth ok");

    conn.shutdown().unwrap();
    server_handle.join().unwrap();
}

#[test]
fn test_tls13_post_hs_auth_not_offered() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::{TcpListener, TcpStream};
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

    // Client does NOT offer post_handshake_auth
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .post_handshake_auth(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();

        // Request post-handshake auth — client didn't offer it
        // Server should still send CertificateRequest, but client will error
        let result = conn.request_client_auth();
        // This should fail because client didn't offer post_handshake_auth
        assert!(
            result.is_err(),
            "should fail when client didn't offer post-hs auth"
        );
    });

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    // Client reads — should get CertificateRequest and fail
    let mut buf = [0u8; 256];
    let _ = conn.read(&mut buf);

    let _ = conn.shutdown();
    server_handle.join().unwrap();
}

#[test]
fn test_tcp_tls13_aes256_gcm() {
    use hitls_tls::CipherSuite;
    let suite = CipherSuite::TLS_AES_256_GCM_SHA384;
    let (cs, ss) = run_tls13_tcp_loopback(suite);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls13_chacha20_poly1305() {
    use hitls_tls::CipherSuite;
    let suite = CipherSuite::TLS_CHACHA20_POLY1305_SHA256;
    let (cs, ss) = run_tls13_tcp_loopback(suite);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls13_rsa_server_cert() {
    // TLS 1.3 handshake with an RSA server certificate (not Ed25519)
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_rsa_server_identity();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
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
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

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
    conn.write(b"ping").unwrap();
    let mut buf = [0u8; 32];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();
    server_handle.join().unwrap();
}

#[test]
fn test_tcp_tls13_aes128_ccm_8() {
    use hitls_tls::CipherSuite;
    let suite = CipherSuite::TLS_AES_128_CCM_8_SHA256;
    let (cs, ss) = run_tls13_tcp_loopback(suite);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

/// TLS 1.3 ALPN negotiation — client and server share "http/1.1" protocol.
#[test]
fn test_tls13_alpn_overlap_negotiated() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();
    let (tx, rx) = mpsc::channel::<Option<Vec<u8>>>();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .alpn(&[b"http/1.1"])
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
        let mut buf = [0u8; 8];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .alpn(&[b"h2", b"http/1.1"]) // prefers h2 but server only has http/1.1
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
    assert_eq!(
        client_alpn,
        Some(b"http/1.1".to_vec()),
        "ALPN should be http/1.1"
    );
    conn.write(b"ping").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();

    server_handle.join().unwrap();
    let server_alpn = rx.recv().unwrap();
    assert_eq!(
        server_alpn,
        Some(b"http/1.1".to_vec()),
        "Server ALPN should be http/1.1"
    );
}

/// TLS 1.3 ALPN — client offers protocols, server has none → no ALPN negotiated.
#[test]
fn test_tls13_alpn_client_only_no_server_alpn() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();

    // Server has NO ALPN configured
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
        let mut buf = [0u8; 8];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

    // Client offers ALPN, server ignores it
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
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
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    // Server didn't select any protocol
    assert_eq!(conn.alpn_protocol(), None, "no ALPN when server has none");
    conn.write(b"ping").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();
    server_handle.join().unwrap();
}

/// Five concurrent TLS 1.3 connections all succeed independently.
#[test]
fn test_concurrent_tls13_connections() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let sub_handles: Vec<_> = (0..5)
            .map(|_| {
                let (stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let cc = cert_chain.clone();
                let pk = server_key.clone();
                thread::spawn(move || {
                    let cfg = TlsConfig::builder()
                        .role(TlsRole::Server)
                        .min_version(TlsVersion::Tls13)
                        .max_version(TlsVersion::Tls13)
                        .certificate_chain(cc)
                        .private_key(pk)
                        .verify_peer(false)
                        .build();
                    let mut conn = TlsServerConnection::new(stream, cfg);
                    conn.handshake().unwrap();
                    let mut buf = [0u8; 64];
                    let n = conn.read(&mut buf).unwrap();
                    conn.write(&buf[..n]).unwrap();
                })
            })
            .collect();
        for h in sub_handles {
            h.join().unwrap();
        }
    });

    let client_handles: Vec<_> = (0..5_usize)
        .map(|i| {
            thread::spawn(move || {
                let cfg = TlsConfig::builder()
                    .role(TlsRole::Client)
                    .min_version(TlsVersion::Tls13)
                    .max_version(TlsVersion::Tls13)
                    .verify_peer(false)
                    .build();
                let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut conn = TlsClientConnection::new(stream, cfg);
                conn.handshake().unwrap();
                let msg = format!("tls13-client-{}", i);
                conn.write(msg.as_bytes()).unwrap();
                let mut buf = [0u8; 64];
                let n = conn.read(&mut buf).unwrap();
                assert_eq!(&buf[..n], msg.as_bytes());
                let _ = conn.shutdown();
            })
        })
        .collect();

    for h in client_handles {
        h.join().unwrap();
    }
    server_handle.join().unwrap();
}

/// TLS 1.3: 64 KB payload round-trip succeeds (tests record fragmentation).
#[test]
fn test_tls13_large_64kb_payload() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let payload: Vec<u8> = (0u8..=255).cycle().take(65536).collect();
    let payload_for_server = payload.clone();

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
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut received = Vec::new();
        while received.len() < 65536 {
            let mut buf = vec![0u8; 16384];
            let n = conn.read(&mut buf).unwrap();
            received.extend_from_slice(&buf[..n]);
        }
        tx.send(received).unwrap();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(&payload).unwrap();
    let _ = conn.shutdown();

    server_handle.join().unwrap();
    let received = rx.recv().unwrap();
    assert_eq!(
        received, payload_for_server,
        "64KB payload must arrive intact"
    );
}

/// TLS 1.3 ConnectionInfo — cipher_suite, negotiated_group, session_resumed.
#[test]
fn test_tls13_connection_info_fields() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::connection_info::ConnectionInfo;
    use hitls_tls::crypt::NamedGroup;
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();
    let suite = CipherSuite::TLS_AES_128_GCM_SHA256;
    let (tx, rx) = mpsc::channel::<ConnectionInfo>();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .cipher_suites(&[suite])
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
        let info = conn.connection_info().unwrap();
        tx.send(info).unwrap();
        let mut buf = [0u8; 8];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .cipher_suites(&[suite])
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

    let info = conn.connection_info().unwrap();
    assert_eq!(info.cipher_suite, suite);
    assert!(!info.session_resumed, "first connection is never resumed");
    assert!(
        info.negotiated_group.is_some(),
        "TLS 1.3 must negotiate a group"
    );
    let group = info.negotiated_group.unwrap();
    assert!(
        matches!(group, NamedGroup::X25519 | NamedGroup::SECP256R1),
        "expected X25519 or P-256, got {:?}",
        group
    );

    conn.write(b"info").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();

    server_handle.join().unwrap();
    let server_info = rx.recv().unwrap();
    assert_eq!(server_info.cipher_suite, suite);
    assert!(!server_info.session_resumed);
}

/// TLS 1.3: is_session_resumed() returns false on the first (full) handshake.
#[test]
fn test_tls13_first_connection_not_resumed() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
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
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        assert!(
            !conn.is_session_resumed(),
            "server: first connection not resumed"
        );
        let mut buf = [0u8; 8];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
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
    assert!(
        !conn.is_session_resumed(),
        "client: first connection not resumed"
    );
    conn.write(b"hello").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();
    server_handle.join().unwrap();
}

/// TLS 1.3: cipher suite negotiation when both sides share multiple suites.
#[test]
fn test_tls13_multi_suite_negotiation() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();
    // Server prefers AES-256-GCM first
    let server_suites = [
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_AES_128_GCM_SHA256,
    ];
    // Client prefers AES-128-GCM first, also supports AES-256-GCM
    let client_suites = [
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
    ];
    let (tx, rx) = mpsc::channel::<CipherSuite>();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .cipher_suites(&server_suites)
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
        tx.send(conn.cipher_suite().unwrap()).unwrap();
        let mut buf = [0u8; 8];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .cipher_suites(&client_suites)
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
    let client_suite = conn.cipher_suite().unwrap();
    conn.write(b"suite").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();

    server_handle.join().unwrap();
    let server_suite = rx.recv().unwrap();
    assert_eq!(
        client_suite, server_suite,
        "both sides must use same cipher suite"
    );
    assert!(
        matches!(
            client_suite,
            CipherSuite::TLS_AES_128_GCM_SHA256 | CipherSuite::TLS_AES_256_GCM_SHA384
        ),
        "negotiated suite must be from the common set"
    );
}

/// TLS 1.3: session_resumption(true) — first connection has session_resumed=false.
#[test]
fn test_tls13_session_take_after_handshake() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
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
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 8];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .session_resumption(true)
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
    assert!(
        !conn.is_session_resumed(),
        "first connection is never resumed"
    );
    conn.write(b"take").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();
    server_handle.join().unwrap();
}

/// TLS 1.3 handshake with certificate_authorities config succeeds.
/// Verifies the extension is sent without protocol errors.
#[test]
fn test_tls13_certificate_authorities_config_handshake() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
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
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        conn.write(b"ok").unwrap();
    });

    // Client sends certificate_authorities extension with two fake DER-encoded DNs
    let dn1 = vec![0x30, 0x07, 0x31, 0x05, 0x30, 0x03, 0x06, 0x01, 0x41]; // minimal SEQUENCE
    let dn2 = vec![0x30, 0x07, 0x31, 0x05, 0x30, 0x03, 0x06, 0x01, 0x42];
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_authorities(vec![dn1, dn2])
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
    conn.write(b"hi").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();

    server_handle.join().unwrap();
}

/// TLS 1.3 handshake succeeds when no certificate_authorities are configured.
#[test]
fn test_tls13_certificate_authorities_empty_config() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
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
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        conn.write(b"ok").unwrap();
    });

    // Empty certificate_authorities (equivalent to not setting it)
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_authorities(vec![])
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
    conn.write(b"hi").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();

    server_handle.join().unwrap();
}

/// TLS 1.3 export_keying_material: client and server derive the same material.
#[test]
fn test_tls13_export_keying_material_client_server_match() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();
    let (tx, rx) = mpsc::channel::<Vec<u8>>();

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
        let ekm = conn
            .export_keying_material(b"TESTING LABEL", Some(b"test context"), 32)
            .unwrap();
        tx.send(ekm).unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
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
    let client_ekm = conn
        .export_keying_material(b"TESTING LABEL", Some(b"test context"), 32)
        .unwrap();
    assert_eq!(client_ekm.len(), 32);

    conn.write(b"done").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();

    server_handle.join().unwrap();
    let server_ekm = rx.recv().unwrap();
    assert_eq!(
        client_ekm, server_ekm,
        "client and server must derive identical keying material"
    );
}

/// TLS 1.3 export_keying_material: different labels produce different material.
#[test]
fn test_tls13_export_keying_material_different_labels() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
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
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
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

    let ekm1 = conn.export_keying_material(b"LABEL ONE", None, 32).unwrap();
    let ekm2 = conn.export_keying_material(b"LABEL TWO", None, 32).unwrap();
    let ekm3 = conn
        .export_keying_material(b"LABEL ONE", Some(b"context"), 32)
        .unwrap();
    assert_ne!(
        ekm1, ekm2,
        "different labels must produce different material"
    );
    assert_ne!(ekm1, ekm3, "no-context vs with-context must differ");

    conn.write(b"done").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();

    server_handle.join().unwrap();
}

/// TLS 1.3 export_keying_material: returns error before handshake.
#[test]
fn test_tls13_export_keying_material_before_handshake() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::TlsClientConnection;
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    // Create an unconnected client — handshake() never called
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();

    let config = TlsConfig::builder()
        .role(hitls_tls::TlsRole::Client)
        .verify_peer(false)
        .build();
    let conn = TlsClientConnection::new(stream, config);

    let result = conn.export_keying_material(b"test", None, 32);
    assert!(
        result.is_err(),
        "export_keying_material must fail before handshake"
    );
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("not connected"),
        "error should say 'not connected', got: {msg}"
    );
}

/// TLS 1.3 export_early_keying_material: returns error when no PSK was used.
#[test]
fn test_tls13_export_early_keying_material_no_psk() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
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
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        // Server also fails without PSK
        let res = conn.export_early_keying_material(b"early", None, 32);
        assert!(res.is_err(), "server: early export must fail without PSK");
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
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

    // No PSK → early exporter master secret is empty → error
    let result = conn.export_early_keying_material(b"early", None, 32);
    assert!(result.is_err(), "early export must fail without PSK");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("no early exporter master secret"),
        "unexpected error: {msg}"
    );

    conn.write(b"done").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();

    server_handle.join().unwrap();
}

/// TLS 1.3 export_keying_material: various output lengths work correctly.
#[test]
fn test_tls13_export_keying_material_various_lengths() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
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
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
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

    for length in [16, 32, 48, 64] {
        let ekm = conn
            .export_keying_material(b"EXPORTER LABEL", Some(b"ctx"), length)
            .unwrap();
        assert_eq!(
            ekm.len(),
            length,
            "expected {length} bytes, got {}",
            ekm.len()
        );
    }

    conn.write(b"done").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();

    server_handle.join().unwrap();
}

/// TLS 1.3 export_keying_material: server-side export also works.
#[test]
fn test_tls13_export_keying_material_server_side() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();
    let (tx, rx) = mpsc::channel::<(Vec<u8>, Vec<u8>)>();

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
        let ekm_with_ctx = conn
            .export_keying_material(b"MY LABEL", Some(b"my context"), 48)
            .unwrap();
        let ekm_no_ctx = conn.export_keying_material(b"MY LABEL", None, 48).unwrap();
        tx.send((ekm_with_ctx, ekm_no_ctx)).unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
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
    let client_ekm_with_ctx = conn
        .export_keying_material(b"MY LABEL", Some(b"my context"), 48)
        .unwrap();
    let client_ekm_no_ctx = conn.export_keying_material(b"MY LABEL", None, 48).unwrap();

    conn.write(b"done").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();

    server_handle.join().unwrap();
    let (server_ekm_with_ctx, server_ekm_no_ctx) = rx.recv().unwrap();

    assert_eq!(
        client_ekm_with_ctx, server_ekm_with_ctx,
        "with-context EKM must match"
    );
    assert_eq!(
        client_ekm_no_ctx, server_ekm_no_ctx,
        "no-context EKM must match"
    );
    assert_ne!(
        client_ekm_with_ctx, client_ekm_no_ctx,
        "context vs no-context must differ"
    );
    assert_eq!(client_ekm_with_ctx.len(), 48);
    assert_eq!(client_ekm_no_ctx.len(), 48);
}

// =========================================================================
// TLS 1.3 key_update tests
// =========================================================================

/// TLS 1.3: server-initiated key update (request_response=true) + subsequent data exchange.
#[test]
fn test_tls13_key_update_server_initiated() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::{TcpListener, TcpStream};
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

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
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

        // Read initial data
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"before key update");
        conn.write(b"ack1").unwrap();

        // Server initiates key update requesting response
        conn.key_update(true).unwrap();

        // Data exchange after key update
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"after key update");
        conn.write(b"ack2").unwrap();

        // Wait for client "done" before dropping — key_update's complex
        // protocol flow makes bare TcpStream drop unreliable on Windows.
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"done");
    });

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    conn.write(b"before key update").unwrap();
    let mut buf = [0u8; 64];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"ack1");

    // Client processes key update during read/write
    conn.write(b"after key update").unwrap();
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"ack2");

    // Signal server that client has read all data
    conn.write(b"done").unwrap();
    let _ = conn.shutdown();
    server_handle.join().unwrap();
}

/// TLS 1.3: server-initiated key update (request_response=false) — no response expected.
#[test]
fn test_tls13_key_update_no_response() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::{TcpListener, TcpStream};
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

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
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

        // Server initiates key update without requesting response
        conn.key_update(false).unwrap();

        // Verify data still works
        conn.write(b"after update").unwrap();
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"client ok");
    });

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    let mut buf = [0u8; 64];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"after update");
    conn.write(b"client ok").unwrap();
    let _ = conn.shutdown();
    server_handle.join().unwrap();
}

/// TLS 1.3: key_update before connected returns error.
#[test]
fn test_tls13_key_update_before_connected() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::TlsServerConnection;
    use std::net::TcpListener;
    use std::time::Duration;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // Accept a connection but never handshake
    let server_handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let config = TlsConfig::builder()
            .role(hitls_tls::TlsRole::Server)
            .verify_peer(false)
            .build();
        let mut conn = TlsServerConnection::new(stream, config);
        // key_update before handshake should fail
        let result = conn.key_update(true);
        assert!(result.is_err(), "key_update must fail before handshake");
    });

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    drop(stream);
    server_handle.join().unwrap();
}

/// TLS 1.3: request_client_auth before connected returns error.
#[test]
fn test_tls13_post_hs_auth_before_connected() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::TlsServerConnection;
    use std::net::TcpListener;
    use std::time::Duration;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let config = TlsConfig::builder()
            .role(hitls_tls::TlsRole::Server)
            .verify_peer(false)
            .build();
        let mut conn = TlsServerConnection::new(stream, config);
        let result = conn.request_client_auth();
        assert!(
            result.is_err(),
            "request_client_auth must fail before connected"
        );
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("not connected"), "got: {msg}");
    });

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    drop(stream);
    server_handle.join().unwrap();
}

/// TLS 1.3: server accessor methods return correct values after handshake.
#[test]
fn test_tls13_server_accessors() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();
    let (tx, rx) = mpsc::channel();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .alpn(&[b"h2"])
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();

        // Collect accessor results
        let alpn = conn.alpn_protocol().map(|p| p.to_vec());
        let sni = conn.server_name().map(|s| s.to_string());
        let group = conn.negotiated_group();
        let certs = conn.peer_certificates().len();
        let resumed = conn.is_session_resumed();
        tx.send((alpn, sni, group, certs, resumed)).unwrap();

        let mut buf = [0u8; 16];
        let _ = conn.read(&mut buf);
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .alpn(&[b"h2"])
        .server_name("test.example.com")
        .verify_peer(false)
        .build();

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    conn.write(b"done").unwrap();
    let _ = conn.shutdown();
    server_handle.join().unwrap();

    let (alpn, sni, group, certs, resumed) = rx.recv().unwrap();
    assert_eq!(alpn, Some(b"h2".to_vec()), "ALPN negotiation");
    assert_eq!(sni.as_deref(), Some("test.example.com"), "SNI");
    assert!(group.is_some(), "negotiated_group should be set");
    assert_eq!(certs, 0, "no client cert expected");
    assert!(!resumed, "first connection should not be resumed");
}

/// TLS 1.3: server-side export_keying_material works after handshake.
#[test]
fn test_tls13_server_export_keying_material() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();
    let (tx, rx) = mpsc::channel();

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
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();

        let ekm = conn
            .export_keying_material(b"ROUNDTRIP TEST", Some(b"ctx"), 32)
            .unwrap();
        tx.send(ekm).unwrap();

        let mut buf = [0u8; 16];
        let _ = conn.read(&mut buf);
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .build();

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    let client_ekm = conn
        .export_keying_material(b"ROUNDTRIP TEST", Some(b"ctx"), 32)
        .unwrap();

    conn.write(b"done").unwrap();
    let _ = conn.shutdown();
    server_handle.join().unwrap();

    let server_ekm = rx.recv().unwrap();
    assert_eq!(client_ekm, server_ekm, "EKM must match on both sides");
    assert_eq!(client_ekm.len(), 32);
}

/// TLS 1.3: server shutdown sends close_notify.
#[test]
fn test_tls13_server_shutdown_close_notify() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::{TcpListener, TcpStream};
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

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();

        // Server initiates shutdown
        conn.shutdown().unwrap();
    });

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    // Client reads: should get 0 bytes (close_notify received)
    let mut buf = [0u8; 64];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(n, 0, "should get EOF after server shutdown");

    let _ = conn.shutdown();
    server_handle.join().unwrap();
}
