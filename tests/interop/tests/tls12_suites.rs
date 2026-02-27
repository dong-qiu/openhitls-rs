//! TLS 1.2 CCM/PSK/anonymous cipher suites, GREASE, and Heartbeat integration tests.

use hitls_integration_tests::*;

// -------------------------------------------------------
// 40–43. ECDHE_ECDSA CCM cipher suites (RFC 7251)
// -------------------------------------------------------

#[test]
fn test_tcp_tls12_ecdhe_ecdsa_aes128_ccm() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM;
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

    let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_ecdhe_ecdsa_aes256_ccm() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM;
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

    let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_ecdhe_ecdsa_aes128_ccm_8() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
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

    let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_ecdhe_ecdsa_aes256_ccm_8() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8;
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

    let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

// -------------------------------------------------------
// 44–47. DHE_RSA CCM cipher suites (RFC 6655)
// -------------------------------------------------------

#[test]
fn test_tcp_tls12_dhe_rsa_aes128_ccm() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

    let suite = CipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM;
    let (cert_chain, server_key) = make_rsa_server_identity();
    let sig_algs = [
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];

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

    let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_dhe_rsa_aes256_ccm() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

    let suite = CipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM;
    let (cert_chain, server_key) = make_rsa_server_identity();
    let sig_algs = [
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];

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

    let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_dhe_rsa_aes128_ccm_8() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

    let suite = CipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM_8;
    let (cert_chain, server_key) = make_rsa_server_identity();
    let sig_algs = [
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];

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

    let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_dhe_rsa_aes256_ccm_8() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

    let suite = CipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM_8;
    let (cert_chain, server_key) = make_rsa_server_identity();
    let sig_algs = [
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];

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

    let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

// -------------------------------------------------------
// 48–52. PSK cipher suites (RFC 4279, RFC 5487)
// -------------------------------------------------------

#[test]
fn test_tcp_tls12_psk_aes128_gcm() {
    use hitls_tls::CipherSuite;
    let suite = CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256;
    let (cc, sc) = make_psk_configs(suite, &[]);
    let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_psk_aes128_ccm() {
    use hitls_tls::CipherSuite;
    let suite = CipherSuite::TLS_PSK_WITH_AES_128_CCM;
    let (cc, sc) = make_psk_configs(suite, &[]);
    let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_dhe_psk_aes128_gcm() {
    use hitls_tls::crypt::NamedGroup;
    use hitls_tls::CipherSuite;
    let suite = CipherSuite::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256;
    let (cc, sc) = make_psk_configs(suite, &[NamedGroup::FFDHE2048]);
    let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_ecdhe_psk_aes128_gcm() {
    use hitls_tls::crypt::NamedGroup;
    use hitls_tls::CipherSuite;
    let suite = CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256;
    let (cc, sc) = make_psk_configs(suite, &[NamedGroup::SECP256R1]);
    let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_psk_chacha20() {
    use hitls_tls::CipherSuite;
    let suite = CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256;
    let (cc, sc) = make_psk_configs(suite, &[]);
    let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

// -------------------------------------------------------
// 53–56. DH_ANON / ECDH_ANON cipher suites (RFC 5246/4492)
// -------------------------------------------------------

#[test]
fn test_tcp_tls12_dh_anon_aes128_gcm() {
    use hitls_tls::crypt::NamedGroup;
    use hitls_tls::CipherSuite;
    let suite = CipherSuite::TLS_DH_ANON_WITH_AES_128_GCM_SHA256;
    let (cc, sc) = make_anon_configs(suite, &[NamedGroup::FFDHE2048]);
    let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_dh_anon_aes128_cbc() {
    use hitls_tls::crypt::NamedGroup;
    use hitls_tls::CipherSuite;
    let suite = CipherSuite::TLS_DH_ANON_WITH_AES_128_CBC_SHA256;
    let (cc, sc) = make_anon_configs(suite, &[NamedGroup::FFDHE2048]);
    let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_ecdh_anon_aes128_cbc() {
    use hitls_tls::crypt::NamedGroup;
    use hitls_tls::CipherSuite;
    let suite = CipherSuite::TLS_ECDH_ANON_WITH_AES_128_CBC_SHA;
    let (cc, sc) = make_anon_configs(suite, &[NamedGroup::SECP256R1]);
    let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_ecdh_anon_aes256_cbc() {
    use hitls_tls::crypt::NamedGroup;
    use hitls_tls::CipherSuite;
    let suite = CipherSuite::TLS_ECDH_ANON_WITH_AES_256_CBC_SHA;
    let (cc, sc) = make_anon_configs(suite, &[NamedGroup::SECP256R1]);
    let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

// -------------------------------------------------------
// DHE_DSS cipher suites (Phase T161)
// -------------------------------------------------------

#[test]
fn test_tcp_tls12_dhe_dss_aes128_gcm() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

    let suite = CipherSuite::TLS_DHE_DSS_WITH_AES_128_GCM_SHA256;
    let (cert_chain, server_key) = make_dsa_server_identity();
    let sig_algs = [SignatureScheme::DSA_SHA256];

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

    let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_dhe_dss_aes256_gcm() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

    let suite = CipherSuite::TLS_DHE_DSS_WITH_AES_256_GCM_SHA384;
    let (cert_chain, server_key) = make_dsa_server_identity();
    let sig_algs = [SignatureScheme::DSA_SHA256, SignatureScheme::DSA_SHA384];

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

    let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_dhe_dss_aes128_cbc_sha() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

    let suite = CipherSuite::TLS_DHE_DSS_WITH_AES_128_CBC_SHA;
    let (cert_chain, server_key) = make_dsa_server_identity();
    let sig_algs = [SignatureScheme::DSA_SHA256];

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

    let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_dhe_dss_aes256_cbc_sha() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

    let suite = CipherSuite::TLS_DHE_DSS_WITH_AES_256_CBC_SHA;
    let (cert_chain, server_key) = make_dsa_server_identity();
    let sig_algs = [SignatureScheme::DSA_SHA256];

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

    let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_dhe_dss_aes128_cbc_sha256() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

    let suite = CipherSuite::TLS_DHE_DSS_WITH_AES_128_CBC_SHA256;
    let (cert_chain, server_key) = make_dsa_server_identity();
    let sig_algs = [SignatureScheme::DSA_SHA256];

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

    let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_dhe_dss_aes256_cbc_sha256() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

    let suite = CipherSuite::TLS_DHE_DSS_WITH_AES_256_CBC_SHA256;
    let (cert_chain, server_key) = make_dsa_server_identity();
    let sig_algs = [SignatureScheme::DSA_SHA256];

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

    let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

// -------------------------------------------------------
// RSA static key exchange cipher suites (Phase T161)
// -------------------------------------------------------

#[test]
fn test_tcp_tls12_rsa_aes128_cbc_sha() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

    let suite = CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA;
    let (cert_chain, server_key) = make_rsa_server_identity();
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
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .build();

    let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_rsa_aes256_cbc_sha() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

    let suite = CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA;
    let (cert_chain, server_key) = make_rsa_server_identity();
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
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .build();

    let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_rsa_aes128_cbc_sha256() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

    let suite = CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256;
    let (cert_chain, server_key) = make_rsa_server_identity();
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
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .build();

    let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_rsa_aes256_gcm_sha384() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

    let suite = CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384;
    let (cert_chain, server_key) = make_rsa_server_identity();
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
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .build();

    let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_rsa_aes128_ccm() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

    let suite = CipherSuite::TLS_RSA_WITH_AES_128_CCM;
    let (cert_chain, server_key) = make_rsa_server_identity();
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
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .build();

    let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

// -------------------------------------------------------
// RSA_PSK cipher suites (Phase T161)
// -------------------------------------------------------

#[test]
fn test_tcp_tls12_rsa_psk_aes128_gcm() {
    use hitls_tls::CipherSuite;
    let suite = CipherSuite::TLS_RSA_PSK_WITH_AES_128_GCM_SHA256;
    let (cc, sc) = make_rsa_psk_configs(suite);
    let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_rsa_psk_aes256_gcm() {
    use hitls_tls::CipherSuite;
    let suite = CipherSuite::TLS_RSA_PSK_WITH_AES_256_GCM_SHA384;
    let (cc, sc) = make_rsa_psk_configs(suite);
    let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_rsa_psk_aes128_cbc_sha() {
    use hitls_tls::CipherSuite;
    let suite = CipherSuite::TLS_RSA_PSK_WITH_AES_128_CBC_SHA;
    let (cc, sc) = make_rsa_psk_configs(suite);
    let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_rsa_psk_aes256_cbc_sha() {
    use hitls_tls::CipherSuite;
    let suite = CipherSuite::TLS_RSA_PSK_WITH_AES_256_CBC_SHA;
    let (cc, sc) = make_rsa_psk_configs(suite);
    let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_rsa_psk_aes128_cbc_sha256() {
    use hitls_tls::CipherSuite;
    let suite = CipherSuite::TLS_RSA_PSK_WITH_AES_128_CBC_SHA256;
    let (cc, sc) = make_rsa_psk_configs(suite);
    let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_rsa_psk_aes256_cbc_sha384() {
    use hitls_tls::CipherSuite;
    let suite = CipherSuite::TLS_RSA_PSK_WITH_AES_256_CBC_SHA384;
    let (cc, sc) = make_rsa_psk_configs(suite);
    let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

#[test]
fn test_tcp_tls12_rsa_psk_chacha20_poly1305() {
    use hitls_tls::CipherSuite;
    let suite = CipherSuite::TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256;
    let (cc, sc) = make_rsa_psk_configs(suite);
    let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
    assert_eq!(cs, suite);
    assert_eq!(ss, suite);
}

// -------------------------------------------------------
// GREASE — TLS 1.2 (RFC 8701)
// -------------------------------------------------------

/// TLS 1.2: GREASE enabled on client -- server ignores GREASE values, handshake succeeds.
#[test]
fn test_tls12_grease_enabled_handshake() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    let groups = [hitls_tls::crypt::NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

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
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

    // Client with GREASE enabled
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .grease(true)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"grease-tls12").unwrap();
    let mut buf = [0u8; 32];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"grease-tls12");
    server_handle.join().unwrap();
}

// -------------------------------------------------------
// Heartbeat — TLS 1.2 (RFC 6520)
// -------------------------------------------------------

/// TLS 1.2: Client with heartbeat_mode=2, handshake succeeds.
#[test]
fn test_tls12_heartbeat_mode_handshake() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    let groups = [hitls_tls::crypt::NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

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
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

    // Client with heartbeat_mode=2 (peer_not_allowed_to_send)
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .heartbeat_mode(2)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"heartbeat-tls12").unwrap();
    let mut buf = [0u8; 32];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"heartbeat-tls12");
    server_handle.join().unwrap();
}
