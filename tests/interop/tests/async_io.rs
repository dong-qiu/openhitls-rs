//! Async tokio TLS 1.3/1.2/TLCP/DTLS/DTLCP loopback integration tests.

use hitls_integration_tests::*;

#[tokio::test]
async fn test_async_tls13_loopback() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection_async::{AsyncTlsClientConnection, AsyncTlsServerConnection};
    use hitls_tls::{AsyncTlsConnection, TlsRole, TlsVersion};
    use tokio::net::TcpListener;

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

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut conn = AsyncTlsServerConnection::new(stream, server_config);
        conn.handshake().await.unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"async hello from client!");

        conn.write(b"async hello from server!").await.unwrap();
        conn.shutdown().await.unwrap();
    });

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut conn = AsyncTlsClientConnection::new(stream, client_config);
    conn.handshake().await.unwrap();

    assert_eq!(conn.version(), Some(TlsVersion::Tls13));

    conn.write(b"async hello from client!").await.unwrap();

    let mut buf = [0u8; 256];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"async hello from server!");

    conn.shutdown().await.unwrap();
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_async_tls12_loopback() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12_async::{AsyncTls12ClientConnection, AsyncTls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{AsyncTlsConnection, CipherSuite, TlsRole, TlsVersion};
    use tokio::net::TcpListener;

    let (cert_chain, server_key) = make_ecdsa_server_identity();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .supported_groups(&[NamedGroup::SECP256R1])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .supported_groups(&[NamedGroup::SECP256R1])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut conn = AsyncTls12ServerConnection::new(stream, server_config);
        conn.handshake().await.unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"async TLS 1.2 hello!");

        conn.write(b"async TLS 1.2 reply!").await.unwrap();
        conn.shutdown().await.unwrap();
    });

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut conn = AsyncTls12ClientConnection::new(stream, client_config);
    conn.handshake().await.unwrap();

    assert_eq!(conn.version(), Some(TlsVersion::Tls12));
    assert_eq!(
        conn.cipher_suite(),
        Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
    );

    conn.write(b"async TLS 1.2 hello!").await.unwrap();

    let mut buf = [0u8; 256];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"async TLS 1.2 reply!");

    conn.shutdown().await.unwrap();
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_async_tls13_large_payload() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection_async::{AsyncTlsClientConnection, AsyncTlsServerConnection};
    use hitls_tls::{AsyncTlsConnection, TlsRole, TlsVersion};
    use tokio::net::TcpListener;

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

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // 64KB payload — must be chunked since TLS max fragment is 16384
    let payload: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
    let payload_clone = payload.clone();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut conn = AsyncTlsServerConnection::new(stream, server_config);
        conn.handshake().await.unwrap();

        // Echo back everything
        let mut received = Vec::new();
        let mut buf = [0u8; 32768];
        while received.len() < payload_clone.len() {
            let n = conn.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        assert_eq!(received, payload_clone);

        // Send it back in chunks
        let mut offset = 0;
        while offset < received.len() {
            let end = std::cmp::min(offset + 16000, received.len());
            conn.write(&received[offset..end]).await.unwrap();
            offset = end;
        }
        conn.shutdown().await.unwrap();
    });

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut conn = AsyncTlsClientConnection::new(stream, client_config);
    conn.handshake().await.unwrap();

    // Send in chunks
    let mut offset = 0;
    while offset < payload.len() {
        let end = std::cmp::min(offset + 16000, payload.len());
        conn.write(&payload[offset..end]).await.unwrap();
        offset = end;
    }

    // Receive echo
    let mut received = Vec::new();
    let mut buf = [0u8; 32768];
    while received.len() < payload.len() {
        let n = conn.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }
    assert_eq!(received, payload);

    conn.shutdown().await.unwrap();
    server_handle.await.unwrap();
}

// -------------------------------------------------------
// TLCP async integration tests
// -------------------------------------------------------

#[tokio::test]
async fn test_async_tlcp_ecdhe_gcm_data_transfer() {
    use hitls_tls::config::{ServerPrivateKey, TlsConfig};
    use hitls_tls::connection_tlcp_async::{AsyncTlcpClientConnection, AsyncTlcpServerConnection};
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{AsyncTlsConnection, CipherSuite};
    use tokio::net::TcpListener;

    let (sign_privkey, sign_cert, enc_privkey, enc_cert) = make_sm2_tlcp_identity();

    let server_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::ECDHE_SM4_GCM_SM3])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .certificate_chain(vec![sign_cert])
        .private_key(ServerPrivateKey::Sm2 {
            private_key: sign_privkey,
        })
        .tlcp_enc_certificate_chain(vec![enc_cert])
        .tlcp_enc_private_key(ServerPrivateKey::Sm2 {
            private_key: enc_privkey,
        })
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::ECDHE_SM4_GCM_SM3])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut conn = AsyncTlcpServerConnection::new(stream, server_config);
        conn.handshake().await.unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"async TLCP hello!");

        conn.write(b"async TLCP reply!").await.unwrap();
        conn.shutdown().await.unwrap();
    });

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut conn = AsyncTlcpClientConnection::new(stream, client_config);
    conn.handshake().await.unwrap();

    assert_eq!(conn.cipher_suite(), Some(CipherSuite::ECDHE_SM4_GCM_SM3));

    conn.write(b"async TLCP hello!").await.unwrap();

    let mut buf = [0u8; 256];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"async TLCP reply!");

    conn.shutdown().await.unwrap();
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_async_tlcp_ecdhe_cbc_data_transfer() {
    use hitls_tls::config::{ServerPrivateKey, TlsConfig};
    use hitls_tls::connection_tlcp_async::{AsyncTlcpClientConnection, AsyncTlcpServerConnection};
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{AsyncTlsConnection, CipherSuite};
    use tokio::net::TcpListener;

    let (sign_privkey, sign_cert, enc_privkey, enc_cert) = make_sm2_tlcp_identity();

    let server_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::ECDHE_SM4_CBC_SM3])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .certificate_chain(vec![sign_cert])
        .private_key(ServerPrivateKey::Sm2 {
            private_key: sign_privkey,
        })
        .tlcp_enc_certificate_chain(vec![enc_cert])
        .tlcp_enc_private_key(ServerPrivateKey::Sm2 {
            private_key: enc_privkey,
        })
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::ECDHE_SM4_CBC_SM3])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut conn = AsyncTlcpServerConnection::new(stream, server_config);
        conn.handshake().await.unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"TLCP CBC async!");

        conn.write(b"TLCP CBC reply!").await.unwrap();
        conn.shutdown().await.unwrap();
    });

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut conn = AsyncTlcpClientConnection::new(stream, client_config);
    conn.handshake().await.unwrap();

    assert_eq!(conn.cipher_suite(), Some(CipherSuite::ECDHE_SM4_CBC_SM3));

    conn.write(b"TLCP CBC async!").await.unwrap();

    let mut buf = [0u8; 256];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"TLCP CBC reply!");

    conn.shutdown().await.unwrap();
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_async_tlcp_large_payload() {
    use hitls_tls::config::{ServerPrivateKey, TlsConfig};
    use hitls_tls::connection_tlcp_async::{AsyncTlcpClientConnection, AsyncTlcpServerConnection};
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{AsyncTlsConnection, CipherSuite};
    use tokio::net::TcpListener;

    let (sign_privkey, sign_cert, enc_privkey, enc_cert) = make_sm2_tlcp_identity();

    let server_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::ECDHE_SM4_GCM_SM3])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .certificate_chain(vec![sign_cert])
        .private_key(ServerPrivateKey::Sm2 {
            private_key: sign_privkey,
        })
        .tlcp_enc_certificate_chain(vec![enc_cert])
        .tlcp_enc_private_key(ServerPrivateKey::Sm2 {
            private_key: enc_privkey,
        })
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::ECDHE_SM4_GCM_SM3])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let payload: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
    let payload_clone = payload.clone();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut conn = AsyncTlcpServerConnection::new(stream, server_config);
        conn.handshake().await.unwrap();

        let mut received = Vec::new();
        let mut buf = [0u8; 32768];
        while received.len() < payload_clone.len() {
            let n = conn.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        assert_eq!(received, payload_clone);

        let mut offset = 0;
        while offset < received.len() {
            let end = std::cmp::min(offset + 16000, received.len());
            conn.write(&received[offset..end]).await.unwrap();
            offset = end;
        }
        conn.shutdown().await.unwrap();
    });

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut conn = AsyncTlcpClientConnection::new(stream, client_config);
    conn.handshake().await.unwrap();

    let mut offset = 0;
    while offset < payload.len() {
        let end = std::cmp::min(offset + 16000, payload.len());
        conn.write(&payload[offset..end]).await.unwrap();
        offset = end;
    }

    let mut received = Vec::new();
    let mut buf = [0u8; 32768];
    while received.len() < payload.len() {
        let n = conn.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }
    assert_eq!(received, payload);

    conn.shutdown().await.unwrap();
    server_handle.await.unwrap();
}

// -------------------------------------------------------
// DTLS 1.2 async integration tests
// -------------------------------------------------------

#[tokio::test]
async fn test_async_dtls12_handshake_data_transfer() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection_dtls12_async::{
        AsyncDtls12ClientConnection, AsyncDtls12ServerConnection,
    };
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{AsyncTlsConnection, CipherSuite};

    let (cert_chain, server_key) = make_ecdsa_server_identity();

    let server_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
        .supported_groups(&[NamedGroup::SECP256R1])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
        .supported_groups(&[NamedGroup::SECP256R1])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .verify_peer(false)
        .build();

    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);

    let mut client = AsyncDtls12ClientConnection::new(client_stream, client_config);
    let mut server = AsyncDtls12ServerConnection::new(server_stream, server_config, false);

    let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
    c_res.unwrap();
    s_res.unwrap();

    assert_eq!(
        client.cipher_suite(),
        Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
    );

    client.write(b"async DTLS hello!").await.unwrap();
    let mut buf = [0u8; 256];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"async DTLS hello!");

    server.write(b"async DTLS reply!").await.unwrap();
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"async DTLS reply!");
}

#[tokio::test]
async fn test_async_dtls12_multiple_messages() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection_dtls12_async::{
        AsyncDtls12ClientConnection, AsyncDtls12ServerConnection,
    };
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{AsyncTlsConnection, CipherSuite};

    let (cert_chain, server_key) = make_ecdsa_server_identity();

    let server_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
        .supported_groups(&[NamedGroup::SECP256R1])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
        .supported_groups(&[NamedGroup::SECP256R1])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .verify_peer(false)
        .build();

    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);

    let mut client = AsyncDtls12ClientConnection::new(client_stream, client_config);
    let mut server = AsyncDtls12ServerConnection::new(server_stream, server_config, false);

    let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
    c_res.unwrap();
    s_res.unwrap();

    // Exchange 20 messages bidirectionally
    for i in 0..20u32 {
        let msg = format!("DTLS-msg-{i}");
        client.write(msg.as_bytes()).await.unwrap();

        let mut buf = [0u8; 256];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg.as_bytes());

        // Echo back
        server.write(&buf[..n]).await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg.as_bytes());
    }
}

#[tokio::test]
async fn test_async_dtls12_large_payload() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection_dtls12_async::{
        AsyncDtls12ClientConnection, AsyncDtls12ServerConnection,
    };
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{AsyncTlsConnection, CipherSuite};

    let (cert_chain, server_key) = make_ecdsa_server_identity();

    let server_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
        .supported_groups(&[NamedGroup::SECP256R1])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
        .supported_groups(&[NamedGroup::SECP256R1])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .verify_peer(false)
        .build();

    let (client_stream, server_stream) = tokio::io::duplex(128 * 1024);

    let mut client = AsyncDtls12ClientConnection::new(client_stream, client_config);
    let mut server = AsyncDtls12ServerConnection::new(server_stream, server_config, false);

    let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
    c_res.unwrap();
    s_res.unwrap();

    // Send 8KB payload in chunks, then read back
    let payload: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();

    // Client sends in 2KB chunks
    let mut offset = 0;
    while offset < payload.len() {
        let end = std::cmp::min(offset + 2048, payload.len());
        client.write(&payload[offset..end]).await.unwrap();
        offset = end;
    }

    // Server receives and verifies
    let mut received = Vec::new();
    let mut buf = [0u8; 8192];
    while received.len() < payload.len() {
        let n = server.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }
    assert_eq!(received, payload);

    // Server echoes back
    server.write(&received).await.unwrap();
    let mut echo = Vec::new();
    while echo.len() < payload.len() {
        let n = client.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        echo.extend_from_slice(&buf[..n]);
    }
    assert_eq!(echo, payload);
}

// -------------------------------------------------------
// DTLCP async integration tests
// -------------------------------------------------------

#[tokio::test]
async fn test_async_dtlcp_ecdhe_gcm_data_transfer() {
    use hitls_tls::config::{ServerPrivateKey, TlsConfig};
    use hitls_tls::connection_dtlcp_async::{
        AsyncDtlcpClientConnection, AsyncDtlcpServerConnection,
    };
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{AsyncTlsConnection, CipherSuite};

    let (sign_privkey, sign_cert, enc_privkey, enc_cert) = make_sm2_tlcp_identity();

    let server_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::ECDHE_SM4_GCM_SM3])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .certificate_chain(vec![sign_cert])
        .private_key(ServerPrivateKey::Sm2 {
            private_key: sign_privkey,
        })
        .tlcp_enc_certificate_chain(vec![enc_cert])
        .tlcp_enc_private_key(ServerPrivateKey::Sm2 {
            private_key: enc_privkey,
        })
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::ECDHE_SM4_GCM_SM3])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .verify_peer(false)
        .build();

    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);

    let mut client = AsyncDtlcpClientConnection::new(client_stream, client_config);
    let mut server = AsyncDtlcpServerConnection::new(server_stream, server_config, false);

    let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
    c_res.unwrap();
    s_res.unwrap();

    assert_eq!(client.cipher_suite(), Some(CipherSuite::ECDHE_SM4_GCM_SM3));

    client.write(b"async DTLCP hello!").await.unwrap();
    let mut buf = [0u8; 256];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"async DTLCP hello!");

    server.write(b"async DTLCP reply!").await.unwrap();
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"async DTLCP reply!");
}

#[tokio::test]
async fn test_async_dtlcp_ecdhe_cbc_data_transfer() {
    use hitls_tls::config::{ServerPrivateKey, TlsConfig};
    use hitls_tls::connection_dtlcp_async::{
        AsyncDtlcpClientConnection, AsyncDtlcpServerConnection,
    };
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{AsyncTlsConnection, CipherSuite};

    let (sign_privkey, sign_cert, enc_privkey, enc_cert) = make_sm2_tlcp_identity();

    let server_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::ECDHE_SM4_CBC_SM3])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .certificate_chain(vec![sign_cert])
        .private_key(ServerPrivateKey::Sm2 {
            private_key: sign_privkey,
        })
        .tlcp_enc_certificate_chain(vec![enc_cert])
        .tlcp_enc_private_key(ServerPrivateKey::Sm2 {
            private_key: enc_privkey,
        })
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::ECDHE_SM4_CBC_SM3])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .verify_peer(false)
        .build();

    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);

    let mut client = AsyncDtlcpClientConnection::new(client_stream, client_config);
    let mut server = AsyncDtlcpServerConnection::new(server_stream, server_config, false);

    let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
    c_res.unwrap();
    s_res.unwrap();

    assert_eq!(client.cipher_suite(), Some(CipherSuite::ECDHE_SM4_CBC_SM3));

    client.write(b"DTLCP CBC async!").await.unwrap();
    let mut buf = [0u8; 256];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"DTLCP CBC async!");

    server.write(b"DTLCP CBC reply!").await.unwrap();
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"DTLCP CBC reply!");
}

#[tokio::test]
async fn test_async_dtlcp_multiple_messages() {
    use hitls_tls::config::{ServerPrivateKey, TlsConfig};
    use hitls_tls::connection_dtlcp_async::{
        AsyncDtlcpClientConnection, AsyncDtlcpServerConnection,
    };
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{AsyncTlsConnection, CipherSuite};

    let (sign_privkey, sign_cert, enc_privkey, enc_cert) = make_sm2_tlcp_identity();

    let server_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::ECDHE_SM4_GCM_SM3])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .certificate_chain(vec![sign_cert])
        .private_key(ServerPrivateKey::Sm2 {
            private_key: sign_privkey,
        })
        .tlcp_enc_certificate_chain(vec![enc_cert])
        .tlcp_enc_private_key(ServerPrivateKey::Sm2 {
            private_key: enc_privkey,
        })
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::ECDHE_SM4_GCM_SM3])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .verify_peer(false)
        .build();

    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);

    let mut client = AsyncDtlcpClientConnection::new(client_stream, client_config);
    let mut server = AsyncDtlcpServerConnection::new(server_stream, server_config, false);

    let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
    c_res.unwrap();
    s_res.unwrap();

    // Exchange 10 messages bidirectionally
    for i in 0..10u32 {
        let msg = format!("DTLCP-msg-{i}");
        client.write(msg.as_bytes()).await.unwrap();

        let mut buf = [0u8; 256];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg.as_bytes());

        server.write(&buf[..n]).await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg.as_bytes());
    }
}

// -------------------------------------------------------
// Cross-protocol concurrent async tests
// -------------------------------------------------------

#[tokio::test]
async fn test_async_concurrent_tls13_connections() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection_async::{AsyncTlsClientConnection, AsyncTlsServerConnection};
    use hitls_tls::{AsyncTlsConnection, TlsRole, TlsVersion};
    use tokio::net::TcpListener;

    let (cert_chain, server_key) = make_ed25519_server_identity();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let cert_clone = cert_chain.clone();
    let key_clone = server_key.clone();

    // Server accepts 10 connections
    let server_handle = tokio::spawn(async move {
        let mut handles = Vec::new();
        for _ in 0..10 {
            let (stream, _) = listener.accept().await.unwrap();
            let sc = TlsConfig::builder()
                .role(TlsRole::Server)
                .min_version(TlsVersion::Tls13)
                .max_version(TlsVersion::Tls13)
                .certificate_chain(cert_clone.clone())
                .private_key(key_clone.clone())
                .verify_peer(false)
                .build();
            handles.push(tokio::spawn(async move {
                let mut conn = AsyncTlsServerConnection::new(stream, sc);
                conn.handshake().await.unwrap();
                let mut buf = [0u8; 256];
                let n = conn.read(&mut buf).await.unwrap();
                conn.write(&buf[..n]).await.unwrap();
                conn.shutdown().await.unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    });

    // 10 clients connect in parallel
    let mut client_handles = Vec::new();
    for i in 0..10u32 {
        let cc = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .build();
        client_handles.push(tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut conn = AsyncTlsClientConnection::new(stream, cc);
            conn.handshake().await.unwrap();
            assert_eq!(conn.version(), Some(TlsVersion::Tls13));
            let msg = format!("concurrent-{i}");
            conn.write(msg.as_bytes()).await.unwrap();
            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
            conn.shutdown().await.unwrap();
        }));
    }

    for h in client_handles {
        h.await.unwrap();
    }
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_async_concurrent_tls12_connections() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12_async::{AsyncTls12ClientConnection, AsyncTls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{AsyncTlsConnection, CipherSuite, TlsRole, TlsVersion};
    use tokio::net::TcpListener;

    let (cert_chain, server_key) = make_ecdsa_server_identity();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let cert_clone = cert_chain.clone();
    let key_clone = server_key.clone();

    let server_handle = tokio::spawn(async move {
        let mut handles = Vec::new();
        for _ in 0..10 {
            let (stream, _) = listener.accept().await.unwrap();
            let sc = TlsConfig::builder()
                .role(TlsRole::Server)
                .min_version(TlsVersion::Tls12)
                .max_version(TlsVersion::Tls12)
                .certificate_chain(cert_clone.clone())
                .private_key(key_clone.clone())
                .supported_groups(&[NamedGroup::SECP256R1])
                .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
                .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
                .verify_peer(false)
                .build();
            handles.push(tokio::spawn(async move {
                let mut conn = AsyncTls12ServerConnection::new(stream, sc);
                conn.handshake().await.unwrap();
                let mut buf = [0u8; 256];
                let n = conn.read(&mut buf).await.unwrap();
                conn.write(&buf[..n]).await.unwrap();
                conn.shutdown().await.unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    });

    let mut client_handles = Vec::new();
    for i in 0..10u32 {
        let cc = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .verify_peer(false)
            .build();
        client_handles.push(tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut conn = AsyncTls12ClientConnection::new(stream, cc);
            conn.handshake().await.unwrap();
            assert_eq!(conn.version(), Some(TlsVersion::Tls12));
            let msg = format!("tls12-concurrent-{i}");
            conn.write(msg.as_bytes()).await.unwrap();
            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
            conn.shutdown().await.unwrap();
        }));
    }

    for h in client_handles {
        h.await.unwrap();
    }
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_async_mixed_protocol_concurrent() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12_async::{AsyncTls12ClientConnection, AsyncTls12ServerConnection};
    use hitls_tls::connection_async::{AsyncTlsClientConnection, AsyncTlsServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{AsyncTlsConnection, CipherSuite, TlsRole, TlsVersion};
    use tokio::net::TcpListener;

    // Separate listeners for TLS 1.3 and TLS 1.2
    let listener13 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr13 = listener13.local_addr().unwrap();

    let listener12 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr12 = listener12.local_addr().unwrap();

    let (ed_cert, ed_key) = make_ed25519_server_identity();
    let (ec_cert, ec_key) = make_ecdsa_server_identity();

    let ed_cert_c = ed_cert.clone();
    let ed_key_c = ed_key.clone();

    // TLS 1.3 server
    let server13 = tokio::spawn(async move {
        let mut handles = Vec::new();
        for _ in 0..5 {
            let (stream, _) = listener13.accept().await.unwrap();
            let sc = TlsConfig::builder()
                .role(TlsRole::Server)
                .min_version(TlsVersion::Tls13)
                .max_version(TlsVersion::Tls13)
                .certificate_chain(ed_cert_c.clone())
                .private_key(ed_key_c.clone())
                .verify_peer(false)
                .build();
            handles.push(tokio::spawn(async move {
                let mut conn = AsyncTlsServerConnection::new(stream, sc);
                conn.handshake().await.unwrap();
                let mut buf = [0u8; 256];
                let n = conn.read(&mut buf).await.unwrap();
                conn.write(&buf[..n]).await.unwrap();
                conn.shutdown().await.unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    });

    let ec_cert_c = ec_cert.clone();
    let ec_key_c = ec_key.clone();

    // TLS 1.2 server
    let server12 = tokio::spawn(async move {
        let mut handles = Vec::new();
        for _ in 0..5 {
            let (stream, _) = listener12.accept().await.unwrap();
            let sc = TlsConfig::builder()
                .role(TlsRole::Server)
                .min_version(TlsVersion::Tls12)
                .max_version(TlsVersion::Tls12)
                .certificate_chain(ec_cert_c.clone())
                .private_key(ec_key_c.clone())
                .supported_groups(&[NamedGroup::SECP256R1])
                .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
                .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
                .verify_peer(false)
                .build();
            handles.push(tokio::spawn(async move {
                let mut conn = AsyncTls12ServerConnection::new(stream, sc);
                conn.handshake().await.unwrap();
                let mut buf = [0u8; 256];
                let n = conn.read(&mut buf).await.unwrap();
                conn.write(&buf[..n]).await.unwrap();
                conn.shutdown().await.unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    });

    // Launch 5 TLS 1.3 + 5 TLS 1.2 clients concurrently
    let mut client_handles = Vec::new();

    for i in 0..5u32 {
        let cc = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .build();
        client_handles.push(tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(addr13).await.unwrap();
            let mut conn = AsyncTlsClientConnection::new(stream, cc);
            conn.handshake().await.unwrap();
            assert_eq!(conn.version(), Some(TlsVersion::Tls13));
            let msg = format!("mixed-tls13-{i}");
            conn.write(msg.as_bytes()).await.unwrap();
            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
            conn.shutdown().await.unwrap();
        }));
    }

    for i in 0..5u32 {
        let cc = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .verify_peer(false)
            .build();
        client_handles.push(tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(addr12).await.unwrap();
            let mut conn = AsyncTls12ClientConnection::new(stream, cc);
            conn.handshake().await.unwrap();
            assert_eq!(conn.version(), Some(TlsVersion::Tls12));
            let msg = format!("mixed-tls12-{i}");
            conn.write(msg.as_bytes()).await.unwrap();
            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
            conn.shutdown().await.unwrap();
        }));
    }

    for h in client_handles {
        h.await.unwrap();
    }
    server13.await.unwrap();
    server12.await.unwrap();
}

// -------------------------------------------------------
// Async cipher suite stress tests (Phase T170)
// -------------------------------------------------------

/// Iterate all TLS 1.3 cipher suites, performing async handshake + data transfer for each.
#[tokio::test]
async fn test_async_tls13_all_cipher_suites() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection_async::{AsyncTlsClientConnection, AsyncTlsServerConnection};
    use hitls_tls::{AsyncTlsConnection, CipherSuite, TlsRole, TlsVersion};
    use tokio::net::TcpListener;

    // Note: TLS_AES_128_CCM_SHA256 and TLS_AES_128_CCM_8_SHA256 are excluded
    // because Ed25519 certificate negotiation does not overlap with CCM suites
    // in async mode. The sync tests (tls13.rs) cover CCM suites separately.
    let suites = [
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
    ];

    for suite in suites {
        let (cert_chain, server_key) = make_ed25519_server_identity();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .cipher_suites(&[suite])
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .cipher_suites(&[suite])
            .verify_peer(false)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = AsyncTlsServerConnection::new(stream, server_config);
            conn.handshake().await.unwrap();
            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).await.unwrap();
            conn.write(&buf[..n]).await.unwrap();
            conn.shutdown().await.unwrap();
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut conn = AsyncTlsClientConnection::new(stream, client_config);
        conn.handshake().await.unwrap();
        assert_eq!(conn.version(), Some(TlsVersion::Tls13));
        assert_eq!(conn.cipher_suite(), Some(suite));

        let msg = format!("tls13-suite-{:04X}", suite.0);
        conn.write(msg.as_bytes()).await.unwrap();
        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg.as_bytes());

        conn.shutdown().await.unwrap();
        server_handle.await.unwrap();
    }
}

/// All ECDHE-ECDSA GCM suites via async TLS 1.2.
#[tokio::test]
async fn test_async_tls12_ecdhe_ecdsa_suite_matrix() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12_async::{AsyncTls12ClientConnection, AsyncTls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{AsyncTlsConnection, CipherSuite, TlsRole, TlsVersion};
    use tokio::net::TcpListener;

    let suites = [
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    ];

    for suite in suites {
        let (cert_chain, server_key) = make_ecdsa_server_identity();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .verify_peer(false)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = AsyncTls12ServerConnection::new(stream, server_config);
            conn.handshake().await.unwrap();
            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).await.unwrap();
            conn.write(&buf[..n]).await.unwrap();
            conn.shutdown().await.unwrap();
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut conn = AsyncTls12ClientConnection::new(stream, client_config);
        conn.handshake().await.unwrap();
        assert_eq!(conn.version(), Some(TlsVersion::Tls12));
        assert_eq!(conn.cipher_suite(), Some(suite));

        let msg = format!("ecdsa-suite-{:04X}", suite.0);
        conn.write(msg.as_bytes()).await.unwrap();
        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg.as_bytes());

        conn.shutdown().await.unwrap();
        server_handle.await.unwrap();
    }
}

/// All DHE-RSA GCM suites via async TLS 1.2.
#[tokio::test]
async fn test_async_tls12_dhe_rsa_suite_matrix() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12_async::{AsyncTls12ClientConnection, AsyncTls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{AsyncTlsConnection, CipherSuite, TlsRole, TlsVersion};
    use tokio::net::TcpListener;

    let suites = [
        CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];

    let sig_algs = [
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];

    for suite in suites {
        let (cert_chain, server_key) = make_rsa_server_identity();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::FFDHE2048])
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::FFDHE2048])
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = AsyncTls12ServerConnection::new(stream, server_config);
            conn.handshake().await.unwrap();
            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).await.unwrap();
            conn.write(&buf[..n]).await.unwrap();
            conn.shutdown().await.unwrap();
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut conn = AsyncTls12ClientConnection::new(stream, client_config);
        conn.handshake().await.unwrap();
        assert_eq!(conn.version(), Some(TlsVersion::Tls12));
        assert_eq!(conn.cipher_suite(), Some(suite));

        let msg = format!("dhe-rsa-suite-{:04X}", suite.0);
        conn.write(msg.as_bytes()).await.unwrap();
        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg.as_bytes());

        conn.shutdown().await.unwrap();
        server_handle.await.unwrap();
    }
}

/// All PSK GCM suites via async TLS 1.2.
#[tokio::test]
async fn test_async_tls12_psk_suite_matrix() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12_async::{AsyncTls12ClientConnection, AsyncTls12ServerConnection};
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{AsyncTlsConnection, CipherSuite, TlsRole, TlsVersion};
    use tokio::net::TcpListener;

    let suites = [
        CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_PSK_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
    ];

    let psk = b"integration-test-psk-32-bytes!!!".to_vec();
    let psk_identity = b"test-client".to_vec();
    let sig_algs = [
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];

    for suite in suites {
        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .psk(psk.clone())
            .psk_identity_hint(b"server-hint".to_vec())
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .psk(psk.clone())
            .psk_identity(psk_identity.clone())
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = AsyncTls12ServerConnection::new(stream, server_config);
            conn.handshake().await.unwrap();
            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).await.unwrap();
            conn.write(&buf[..n]).await.unwrap();
            conn.shutdown().await.unwrap();
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut conn = AsyncTls12ClientConnection::new(stream, client_config);
        conn.handshake().await.unwrap();
        assert_eq!(conn.version(), Some(TlsVersion::Tls12));
        assert_eq!(conn.cipher_suite(), Some(suite));

        let msg = format!("psk-suite-{:04X}", suite.0);
        conn.write(msg.as_bytes()).await.unwrap();
        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg.as_bytes());

        conn.shutdown().await.unwrap();
        server_handle.await.unwrap();
    }
}

/// Sequential connections with different cipher suites on same server port,
/// testing connection reuse / teardown correctness.
#[tokio::test]
async fn test_async_connection_reuse_different_suites() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12_async::{AsyncTls12ClientConnection, AsyncTls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{AsyncTlsConnection, CipherSuite, TlsRole, TlsVersion};
    use tokio::net::TcpListener;

    // Use different ECDHE-RSA suites sequentially on the same listener
    let suites = [
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];

    let sig_algs = [
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (cert_chain, server_key) = make_rsa_server_identity();
    let cert_clone = cert_chain.clone();
    let key_clone = server_key.clone();

    let server_handle = tokio::spawn(async move {
        for _ in &suites {
            let (stream, _) = listener.accept().await.unwrap();

            // Server accepts any of the suites
            let sc = TlsConfig::builder()
                .role(TlsRole::Server)
                .min_version(TlsVersion::Tls12)
                .max_version(TlsVersion::Tls12)
                .cipher_suites(&suites)
                .supported_groups(&[NamedGroup::SECP256R1])
                .signature_algorithms(&sig_algs)
                .certificate_chain(cert_clone.clone())
                .private_key(key_clone.clone())
                .verify_peer(false)
                .build();

            let mut conn = AsyncTls12ServerConnection::new(stream, sc);
            conn.handshake().await.unwrap();
            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).await.unwrap();
            conn.write(&buf[..n]).await.unwrap();
            conn.shutdown().await.unwrap();
        }
    });

    // Client connects sequentially with each specific suite
    for suite in suites {
        let cc = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .build();

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut conn = AsyncTls12ClientConnection::new(stream, cc);
        conn.handshake().await.unwrap();
        assert_eq!(conn.version(), Some(TlsVersion::Tls12));
        assert_eq!(conn.cipher_suite(), Some(suite));

        let msg = format!("reuse-{:04X}", suite.0);
        conn.write(msg.as_bytes()).await.unwrap();
        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg.as_bytes());

        conn.shutdown().await.unwrap();
    }

    server_handle.await.unwrap();
}
