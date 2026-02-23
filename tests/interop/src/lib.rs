//! Integration test helpers for openHiTLS-rs.
//!
//! Provides shared helper functions used by the integration test files
//! under `tests/`. Each `tests/*.rs` file imports these via
//! `use hitls_integration_tests::*;`.

pub use hitls_utils::hex::hex;

pub fn make_ed25519_server_identity() -> (Vec<Vec<u8>>, hitls_tls::config::ServerPrivateKey) {
    use hitls_pki::x509::{CertificateBuilder, DistinguishedName, SigningKey};
    let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
    let seed = kp.seed().to_vec();
    let sk = SigningKey::Ed25519(kp);
    let dn = DistinguishedName {
        entries: vec![("CN".into(), "localhost".into())],
    };
    let cert = CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000).unwrap();
    (
        vec![cert.raw],
        hitls_tls::config::ServerPrivateKey::Ed25519(seed),
    )
}

/// Generate an ECDSA P-256 server identity.
pub fn make_ecdsa_server_identity() -> (Vec<Vec<u8>>, hitls_tls::config::ServerPrivateKey) {
    use hitls_pki::x509::{CertificateBuilder, DistinguishedName, SigningKey};
    use hitls_types::EccCurveId;
    let kp = hitls_crypto::ecdsa::EcdsaKeyPair::generate(EccCurveId::NistP256).unwrap();
    let priv_bytes = kp.private_key_bytes();
    let sk = SigningKey::Ecdsa {
        curve_id: EccCurveId::NistP256,
        key_pair: kp,
    };
    let dn = DistinguishedName {
        entries: vec![("CN".into(), "localhost".into())],
    };
    let cert = CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000).unwrap();
    (
        vec![cert.raw],
        hitls_tls::config::ServerPrivateKey::Ecdsa {
            curve_id: EccCurveId::NistP256,
            private_key: priv_bytes,
        },
    )
}

/// Generate an RSA 2048 server identity.
pub fn make_rsa_server_identity() -> (Vec<Vec<u8>>, hitls_tls::config::ServerPrivateKey) {
    use hitls_pki::x509::{CertificateBuilder, DistinguishedName, SigningKey};
    let rsa = hitls_crypto::rsa::RsaPrivateKey::generate(2048).unwrap();
    let (n, d, e) = (rsa.n_bytes(), rsa.d_bytes(), rsa.e_bytes());
    let (p, q) = (rsa.p_bytes(), rsa.q_bytes());
    let sk = SigningKey::Rsa(rsa);
    let dn = DistinguishedName {
        entries: vec![("CN".into(), "localhost".into())],
    };
    let cert = CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000).unwrap();
    (
        vec![cert.raw],
        hitls_tls::config::ServerPrivateKey::Rsa { n, d, e, p, q },
    )
}

pub fn make_dtls12_configs() -> (hitls_tls::config::TlsConfig, hitls_tls::config::TlsConfig) {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::CipherSuite;

    let (cert_chain, server_key) = make_ecdsa_server_identity();

    let client_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
        .supported_groups(&[NamedGroup::SECP256R1])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .verify_peer(false)
        .build();

    let server_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
        .supported_groups(&[NamedGroup::SECP256R1])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    (client_config, server_config)
}

pub fn make_sm2_tlcp_identity() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    use hitls_crypto::sm2::Sm2KeyPair;
    use hitls_pki::x509::{
        CertificateBuilder, DistinguishedName, SigningKey, SubjectPublicKeyInfo,
    };
    use hitls_utils::oid::known;

    let sign_kp = Sm2KeyPair::generate().unwrap();
    let sign_pubkey = sign_kp.public_key_bytes().unwrap();
    let sign_privkey = sign_kp.private_key_bytes().unwrap();

    let enc_kp = Sm2KeyPair::generate().unwrap();
    let enc_pubkey = enc_kp.public_key_bytes().unwrap();
    let enc_privkey = enc_kp.private_key_bytes().unwrap();

    let sign_spki = SubjectPublicKeyInfo {
        algorithm_oid: known::ec_public_key().to_der_value(),
        algorithm_params: Some(known::sm2_curve().to_der_value()),
        public_key: sign_pubkey,
    };
    let sign_sk = SigningKey::Sm2(sign_kp);
    let sign_dn = DistinguishedName {
        entries: vec![("CN".into(), "TLCP Sign".into())],
    };
    let sign_cert = CertificateBuilder::new()
        .serial_number(&[0x01])
        .issuer(sign_dn.clone())
        .subject(sign_dn)
        .validity(1_700_000_000, 1_800_000_000)
        .subject_public_key(sign_spki)
        .build(&sign_sk)
        .unwrap();

    let enc_spki = SubjectPublicKeyInfo {
        algorithm_oid: known::ec_public_key().to_der_value(),
        algorithm_params: Some(known::sm2_curve().to_der_value()),
        public_key: enc_pubkey,
    };
    let enc_sk = SigningKey::Sm2(enc_kp);
    let enc_dn = DistinguishedName {
        entries: vec![("CN".into(), "TLCP Enc".into())],
    };
    let enc_cert = CertificateBuilder::new()
        .serial_number(&[0x02])
        .issuer(enc_dn.clone())
        .subject(enc_dn)
        .validity(1_700_000_000, 1_800_000_000)
        .subject_public_key(enc_spki)
        .build(&enc_sk)
        .unwrap();

    (sign_privkey, sign_cert.raw, enc_privkey, enc_cert.raw)
}

pub fn make_tlcp_configs(
    suite: hitls_tls::CipherSuite,
) -> (hitls_tls::config::TlsConfig, hitls_tls::config::TlsConfig) {
    use hitls_tls::config::{ServerPrivateKey, TlsConfig};
    use hitls_tls::crypt::SignatureScheme;

    let (sign_privkey, sign_cert, enc_privkey, enc_cert) = make_sm2_tlcp_identity();

    let client_config = TlsConfig::builder()
        .cipher_suites(&[suite])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .verify_peer(false)
        .build();

    let server_config = TlsConfig::builder()
        .cipher_suites(&[suite])
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

    (client_config, server_config)
}

pub fn make_dtlcp_configs(
    suite: hitls_tls::CipherSuite,
) -> (hitls_tls::config::TlsConfig, hitls_tls::config::TlsConfig) {
    use hitls_tls::config::{ServerPrivateKey, TlsConfig};
    use hitls_tls::crypt::SignatureScheme;

    let (sign_privkey, sign_cert, enc_privkey, enc_cert) = make_sm2_tlcp_identity();

    let client_config = TlsConfig::builder()
        .cipher_suites(&[suite])
        .signature_algorithms(&[SignatureScheme::SM2_SM3])
        .verify_peer(false)
        .build();

    let server_config = TlsConfig::builder()
        .cipher_suites(&[suite])
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

    (client_config, server_config)
}

pub fn run_tls12_tcp_loopback(
    client_config: hitls_tls::config::TlsConfig,
    server_config: hitls_tls::config::TlsConfig,
) -> (hitls_tls::CipherSuite, hitls_tls::CipherSuite) {
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::TlsConnection;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let (tx, rx) = mpsc::channel();
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
        let suite = conn.cipher_suite().unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
        let _ = conn.shutdown();
        tx.send(suite).unwrap();
    });

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    let client_suite = conn.cipher_suite().unwrap();
    conn.write(b"ping").unwrap();
    let mut buf = [0u8; 32];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();

    server_handle.join().unwrap();
    let server_suite = rx.recv().unwrap();
    (client_suite, server_suite)
}

pub fn make_psk_configs(
    suite: hitls_tls::CipherSuite,
    groups: &[hitls_tls::crypt::NamedGroup],
) -> (hitls_tls::config::TlsConfig, hitls_tls::config::TlsConfig) {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{TlsRole, TlsVersion};

    let psk = b"integration-test-psk-32-bytes!!!".to_vec();
    let psk_identity = b"test-client".to_vec();
    let sig_algs = [
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .psk(psk.clone())
        .psk_identity(psk_identity)
        .build();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .psk(psk)
        .psk_identity_hint(b"server-hint".to_vec())
        .build();

    (client_config, server_config)
}

pub fn make_anon_configs(
    suite: hitls_tls::CipherSuite,
    groups: &[hitls_tls::crypt::NamedGroup],
) -> (hitls_tls::config::TlsConfig, hitls_tls::config::TlsConfig) {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::{TlsRole, TlsVersion};

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(groups)
        .verify_peer(false)
        .build();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(groups)
        .verify_peer(false)
        .build();

    (client_config, server_config)
}

pub fn run_tls13_tcp_loopback(
    suite: hitls_tls::CipherSuite,
) -> (hitls_tls::CipherSuite, hitls_tls::CipherSuite) {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();
    let (tx, rx) = mpsc::channel();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .cipher_suites(&[suite])
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

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
        let s = conn.cipher_suite().unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
        let _ = conn.shutdown();
        tx.send(s).unwrap();
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
    let client_suite = conn.cipher_suite().unwrap();
    conn.write(b"ping").unwrap();
    let mut buf = [0u8; 32];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();

    server_handle.join().unwrap();
    let server_suite = rx.recv().unwrap();
    (client_suite, server_suite)
}
