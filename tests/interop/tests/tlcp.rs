//! TLCP and DTLCP handshake integration tests.

use hitls_integration_tests::*;

#[test]
fn test_tlcp_ecdhe_gcm() {
    use hitls_tls::connection_tlcp::tlcp_handshake_in_memory;
    use hitls_tls::CipherSuite;

    let (cc, sc) = make_tlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
    let (mut client, mut server) = tlcp_handshake_in_memory(cc, sc).unwrap();

    let rec = client.seal_app_data(b"TLCP ECDHE GCM test").unwrap();
    let pt = server.open_app_data(&rec).unwrap();
    assert_eq!(pt, b"TLCP ECDHE GCM test");

    let rec = server.seal_app_data(b"TLCP server reply").unwrap();
    let pt = client.open_app_data(&rec).unwrap();
    assert_eq!(pt, b"TLCP server reply");
}

#[test]
fn test_tlcp_ecdhe_cbc() {
    use hitls_tls::connection_tlcp::tlcp_handshake_in_memory;
    use hitls_tls::CipherSuite;

    let (cc, sc) = make_tlcp_configs(CipherSuite::ECDHE_SM4_CBC_SM3);
    let (mut client, mut server) = tlcp_handshake_in_memory(cc, sc).unwrap();

    let rec = client.seal_app_data(b"TLCP ECDHE CBC test").unwrap();
    let pt = server.open_app_data(&rec).unwrap();
    assert_eq!(pt, b"TLCP ECDHE CBC test");

    let rec = server.seal_app_data(b"CBC server reply").unwrap();
    let pt = client.open_app_data(&rec).unwrap();
    assert_eq!(pt, b"CBC server reply");
}

#[test]
fn test_tlcp_ecc_gcm() {
    use hitls_tls::connection_tlcp::tlcp_handshake_in_memory;
    use hitls_tls::CipherSuite;

    let (cc, sc) = make_tlcp_configs(CipherSuite::ECC_SM4_GCM_SM3);
    let (mut client, mut server) = tlcp_handshake_in_memory(cc, sc).unwrap();

    let rec = client.seal_app_data(b"ECC GCM test").unwrap();
    let pt = server.open_app_data(&rec).unwrap();
    assert_eq!(pt, b"ECC GCM test");
}

#[test]
fn test_tlcp_ecc_cbc() {
    use hitls_tls::connection_tlcp::tlcp_handshake_in_memory;
    use hitls_tls::CipherSuite;

    let (cc, sc) = make_tlcp_configs(CipherSuite::ECC_SM4_CBC_SM3);
    let (mut client, mut server) = tlcp_handshake_in_memory(cc, sc).unwrap();

    let rec = client.seal_app_data(b"ECC CBC test").unwrap();
    let pt = server.open_app_data(&rec).unwrap();
    assert_eq!(pt, b"ECC CBC test");
}

// -------------------------------------------------------
// DTLCP integration tests
// -------------------------------------------------------

#[test]
fn test_dtlcp_ecdhe_gcm() {
    use hitls_tls::connection_dtlcp::dtlcp_handshake_in_memory;
    use hitls_tls::CipherSuite;

    let (cc, sc) = make_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
    let (mut client, mut server) = dtlcp_handshake_in_memory(cc, sc, false).unwrap();

    let dg = client.seal_app_data(b"DTLCP ECDHE GCM").unwrap();
    let pt = server.open_app_data(&dg).unwrap();
    assert_eq!(pt, b"DTLCP ECDHE GCM");

    let dg = server.seal_app_data(b"DTLCP reply").unwrap();
    let pt = client.open_app_data(&dg).unwrap();
    assert_eq!(pt, b"DTLCP reply");
}

#[test]
fn test_dtlcp_ecdhe_cbc() {
    use hitls_tls::connection_dtlcp::dtlcp_handshake_in_memory;
    use hitls_tls::CipherSuite;

    let (cc, sc) = make_dtlcp_configs(CipherSuite::ECDHE_SM4_CBC_SM3);
    let (mut client, mut server) = dtlcp_handshake_in_memory(cc, sc, false).unwrap();

    let dg = client.seal_app_data(b"DTLCP ECDHE CBC").unwrap();
    let pt = server.open_app_data(&dg).unwrap();
    assert_eq!(pt, b"DTLCP ECDHE CBC");
}

#[test]
fn test_dtlcp_with_cookie() {
    use hitls_tls::connection_dtlcp::dtlcp_handshake_in_memory;
    use hitls_tls::{CipherSuite, TlsVersion};

    let (cc, sc) = make_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
    let (client, server) = dtlcp_handshake_in_memory(cc, sc, true).unwrap();
    assert_eq!(client.version(), Some(TlsVersion::Dtlcp));
    assert_eq!(server.version(), Some(TlsVersion::Dtlcp));
}

// -------------------------------------------------------
// TLCP/DTLCP double-certificate validation error tests
// -------------------------------------------------------

#[test]
fn test_tlcp_handshake_fails_without_enc_cert() {
    use hitls_tls::config::{ServerPrivateKey, TlsConfig};
    use hitls_tls::connection_tlcp::tlcp_handshake_in_memory;
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::CipherSuite;

    let (sign_privkey, sign_cert, _enc_privkey, _enc_cert) = make_sm2_tlcp_identity();

    let client_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::ECDHE_SM4_GCM_SM3])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .verify_peer(false)
        .build();

    let server_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::ECDHE_SM4_GCM_SM3])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .certificate_chain(vec![sign_cert])
        .private_key(ServerPrivateKey::Sm2 {
            private_key: sign_privkey,
        })
        // NO enc cert
        .verify_peer(false)
        .build();

    let result = tlcp_handshake_in_memory(client_config, server_config);
    assert!(result.is_err());
    let msg = format!("{}", result.err().unwrap());
    assert!(
        msg.contains("no TLCP encryption certificate"),
        "expected 'no TLCP encryption certificate', got: {msg}"
    );
}

#[test]
fn test_tlcp_handshake_fails_without_signing_key() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection_tlcp::tlcp_handshake_in_memory;
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::CipherSuite;

    let (_sign_privkey, sign_cert, _enc_privkey, enc_cert) = make_sm2_tlcp_identity();

    let client_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::ECDHE_SM4_GCM_SM3])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .verify_peer(false)
        .build();

    let server_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::ECDHE_SM4_GCM_SM3])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .certificate_chain(vec![sign_cert])
        // NO private_key
        .tlcp_enc_certificate_chain(vec![enc_cert])
        .verify_peer(false)
        .build();

    let result = tlcp_handshake_in_memory(client_config, server_config);
    assert!(result.is_err());
    let msg = format!("{}", result.err().unwrap());
    assert!(
        msg.contains("no signing private key"),
        "expected 'no signing private key', got: {msg}"
    );
}

#[test]
fn test_dtlcp_handshake_fails_without_enc_cert() {
    use hitls_tls::config::{ServerPrivateKey, TlsConfig};
    use hitls_tls::connection_dtlcp::dtlcp_handshake_in_memory;
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::CipherSuite;

    let (sign_privkey, sign_cert, _enc_privkey, _enc_cert) = make_sm2_tlcp_identity();

    let client_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::ECDHE_SM4_GCM_SM3])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .verify_peer(false)
        .build();

    let server_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::ECDHE_SM4_GCM_SM3])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .certificate_chain(vec![sign_cert])
        .private_key(ServerPrivateKey::Sm2 {
            private_key: sign_privkey,
        })
        // NO enc cert
        .verify_peer(false)
        .build();

    let result = dtlcp_handshake_in_memory(client_config, server_config, false);
    assert!(result.is_err());
    let msg = format!("{}", result.err().unwrap());
    assert!(
        msg.contains("no TLCP encryption certificate"),
        "expected 'no TLCP encryption certificate', got: {msg}"
    );
}

#[test]
fn test_dtlcp_handshake_fails_without_signing_key() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection_dtlcp::dtlcp_handshake_in_memory;
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::CipherSuite;

    let (_sign_privkey, sign_cert, _enc_privkey, enc_cert) = make_sm2_tlcp_identity();

    let client_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::ECDHE_SM4_GCM_SM3])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .verify_peer(false)
        .build();

    let server_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::ECDHE_SM4_GCM_SM3])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .certificate_chain(vec![sign_cert])
        // NO private_key
        .tlcp_enc_certificate_chain(vec![enc_cert])
        .verify_peer(false)
        .build();

    let result = dtlcp_handshake_in_memory(client_config, server_config, false);
    assert!(result.is_err());
    let msg = format!("{}", result.err().unwrap());
    assert!(
        msg.contains("no signing private key"),
        "expected 'no signing private key', got: {msg}"
    );
}
