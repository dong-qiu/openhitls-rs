//! TLS signature-algorithm / named-group handshake matrix — T183 (#60).
//!
//! Migrated from `openhitls/testcode/sdv/testcase/tls/ciphersuite/`
//! `test_suite_sdv_hlt_group_signature.{c,data}` (31 SDV rows / 8 TC families).
//!
//! Each test below runs a TLS 1.2 or 1.3 handshake over TCP loopback with a
//! specific `(NamedGroup, SignatureScheme, server_cert_kind)` triple and
//! asserts the handshake completes. The C reference uses the `HLT` harness
//! to spawn the openhitls TLS endpoints; the Rust side reuses the existing
//! `tests/interop` thread-pair pattern (server thread + client `handshake`).
//!
//! ## Migration map (C TC → Rust test)
//!
//! | C TC family | C rows | Rust tests | Notes |
//! |-------------|-------:|-----------:|-------|
//! | `SDV_TLS_13_GROUP` | 1 (loop) | 6 | One Rust test per NIST/X25519/FFDHE group |
//! | `SDV_TLS_12_GROUP` | 7 | 4 | Brainpool 3 rows unmigratable (Rust does not implement them) |
//! | `SDV_TLS_ECDSA_SIGNATURE` (TLS 1.2) | 5 | 3 | SHA-1 / SHA-224 legacy schemes are unsupported by the Rust verifier |
//! | `SDV_TLS_RSA_SIGNATURE` (TLS 1.2) | 8 | 6 | Same SHA-1 / SHA-224 limitation; PKCS#1 + PSS-RSAE migrated |
//! | `SDV_TLS_RSAPSS_SIGNATURE` (TLS 1.2 & 1.3) | 3 | 0 | `rsa_pss_pss_*` requires PSS-OID `id-RSASSA-PSS` certs (RFC 8446 §4.2.3); the Rust handshake refuses them with `illegal_parameter`. See `SignatureScheme::RSA_PSS_PSS_*` doc-comment in `crates/hitls-tls/src/crypt/mod.rs`. |
//! | `SDV_TLS13_RSA_SIGNATURE` | 3 | 3 | RSA-PSS-RSAE SHA-256/384/512 |
//! | `SDV_TLS13_ECDSA_SIGNATURE` | 3 | 3 | ECDSA P-256/P-384/P-521 |
//! | `SDV_TLS13_EDDSA_SIGNATURE` | 1 | 1 | Ed25519 |
//! | **Total** | **31** | **26** | 5 rows documented as unmigratable above |
//!
//! ## Why this is an interop test, not a crypto KAT
//!
//! Issue #60 was filed with a description suggesting byte-exact signature
//! KAT comparison, but the C source uses the `HLT_*` helpers to drive a
//! full TLS handshake — the actual coverage is "given this `(group, sig,
//! cert)` triple, can a Rust hitls-tls client + server negotiate?" The KAT
//! pretence is misleading: there is no signature-bytes assertion in the C
//! tests, only `CONNECT(...) == SUCCESS`. We mirror that semantics here.

use hitls_integration_tests::{
    make_ecdsa_server_identity, make_ed25519_server_identity, make_rsa_server_identity,
};
use hitls_tls::config::TlsConfig;
use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
use hitls_tls::crypt::{NamedGroup, SignatureScheme};
use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
use hitls_types::EccCurveId;
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
enum CertKind {
    /// `make_rsa_server_identity()` — RSA 2048, sha256 self-sig.
    Rsa,
    /// `make_ecdsa_server_identity()` — P-256, sha256 self-sig.
    Ecdsa,
    /// Curve-parameterized ECDSA self-signed cert (sha384 for P-384, sha512 for P-521).
    EcdsaCurve(EccCurveId),
    /// `make_ed25519_server_identity()` — Ed25519 self-sig.
    Ed25519,
}

fn make_ecdsa_identity_for_curve(
    curve_id: EccCurveId,
) -> (Vec<Vec<u8>>, hitls_tls::config::ServerPrivateKey) {
    use hitls_pki::x509::{CertificateBuilder, DistinguishedName, SigningKey};
    let kp = hitls_crypto::ecdsa::EcdsaKeyPair::generate(curve_id).unwrap();
    let priv_bytes = kp.private_key_bytes();
    let sk = SigningKey::Ecdsa {
        curve_id,
        key_pair: kp,
    };
    let dn = DistinguishedName {
        entries: vec![("CN".into(), "localhost".into())],
    };
    let cert = CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000).unwrap();
    (
        vec![cert.raw],
        hitls_tls::config::ServerPrivateKey::Ecdsa {
            curve_id,
            private_key: priv_bytes,
        },
    )
}

fn make_identity(kind: CertKind) -> (Vec<Vec<u8>>, hitls_tls::config::ServerPrivateKey) {
    match kind {
        CertKind::Rsa => make_rsa_server_identity(),
        CertKind::Ecdsa => make_ecdsa_server_identity(),
        CertKind::EcdsaCurve(curve) => make_ecdsa_identity_for_curve(curve),
        CertKind::Ed25519 => make_ed25519_server_identity(),
    }
}

/// TLS 1.2 cipher suite for `(cert_kind, sig_scheme)` — TLS 1.2 suite encodes
/// kex + cert sig algorithm, so it must match the server cert (and the AEAD
/// hash must match the sig scheme's hash where possible). Returns `None` for
/// combinations that have no TLS 1.2 cipher suite (e.g. Ed25519).
fn tls12_cipher_suites(cert_kind: CertKind, sig: SignatureScheme) -> &'static [CipherSuite] {
    match cert_kind {
        CertKind::Rsa => match sig {
            SignatureScheme::RSA_PKCS1_SHA384
            | SignatureScheme::RSA_PSS_RSAE_SHA384
            | SignatureScheme::RSA_PKCS1_SHA512
            | SignatureScheme::RSA_PSS_RSAE_SHA512 => {
                &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384]
            }
            _ => &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
        },
        CertKind::Ecdsa | CertKind::EcdsaCurve(_) => match sig {
            SignatureScheme::ECDSA_SECP384R1_SHA384 | SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                &[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384]
            }
            _ => &[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
        },
        CertKind::Ed25519 => &[],
    }
}

/// Run a TLS 1.3 handshake with the given `(group, signature, cert)` triple
/// and assert it completes. Returns the negotiated group from the server
/// side, which the caller may use for an extra sanity check.
fn handshake_tls13(
    cert_kind: CertKind,
    group: NamedGroup,
    sig: SignatureScheme,
) -> Option<NamedGroup> {
    let (cert_chain, server_key) = make_identity(cert_kind);
    let (tx, rx) = mpsc::channel::<Option<NamedGroup>>();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .supported_groups(&[group])
        .signature_algorithms(&[sig])
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
        conn.handshake().expect("server TLS 1.3 handshake");
        tx.send(conn.negotiated_group()).unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .supported_groups(&[group])
        .signature_algorithms(&[sig])
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
    conn.handshake().expect("client TLS 1.3 handshake");
    conn.write(b"ping").unwrap();
    let mut buf = [0u8; 32];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"ping");

    let negotiated = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    server_handle.join().unwrap();
    negotiated
}

/// Run a TLS 1.2 handshake with the given `(group, signature, cert)` triple
/// and assert it completes.
fn handshake_tls12(cert_kind: CertKind, group: NamedGroup, sig: SignatureScheme) {
    let (cert_chain, server_key) = make_identity(cert_kind);
    let suites = tls12_cipher_suites(cert_kind, sig);
    let (tx, rx) = mpsc::channel::<()>();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .supported_groups(&[group])
        .signature_algorithms(&[sig])
        .cipher_suites(suites)
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
        conn.handshake().expect("server TLS 1.2 handshake");
        tx.send(()).unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .supported_groups(&[group])
        .signature_algorithms(&[sig])
        .cipher_suites(suites)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().expect("client TLS 1.2 handshake");
    conn.write(b"ping").unwrap();
    let mut buf = [0u8; 32];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"ping");

    rx.recv_timeout(Duration::from_secs(5)).unwrap();
    server_handle.join().unwrap();
}

// ---------------------------------------------------------------------------
// SDV_TLS_13_GROUP — TLS 1.3 group matrix (RSA cert + RSA-PSS-RSAE-SHA256)
// ---------------------------------------------------------------------------

#[test]
fn sdv_tls13_group_secp256r1() {
    let g = handshake_tls13(
        CertKind::Rsa,
        NamedGroup::SECP256R1,
        SignatureScheme::RSA_PSS_RSAE_SHA256,
    );
    assert_eq!(g, Some(NamedGroup::SECP256R1));
}

#[test]
fn sdv_tls13_group_secp384r1() {
    let g = handshake_tls13(
        CertKind::Rsa,
        NamedGroup::SECP384R1,
        SignatureScheme::RSA_PSS_RSAE_SHA256,
    );
    assert_eq!(g, Some(NamedGroup::SECP384R1));
}

#[test]
fn sdv_tls13_group_secp521r1() {
    let g = handshake_tls13(
        CertKind::Rsa,
        NamedGroup::SECP521R1,
        SignatureScheme::RSA_PSS_RSAE_SHA256,
    );
    assert_eq!(g, Some(NamedGroup::SECP521R1));
}

#[test]
fn sdv_tls13_group_x25519() {
    let g = handshake_tls13(
        CertKind::Rsa,
        NamedGroup::X25519,
        SignatureScheme::RSA_PSS_RSAE_SHA256,
    );
    assert_eq!(g, Some(NamedGroup::X25519));
}

#[test]
fn sdv_tls13_group_ffdhe2048() {
    let g = handshake_tls13(
        CertKind::Rsa,
        NamedGroup::FFDHE2048,
        SignatureScheme::RSA_PSS_RSAE_SHA256,
    );
    assert_eq!(g, Some(NamedGroup::FFDHE2048));
}

#[test]
fn sdv_tls13_group_ffdhe3072() {
    let g = handshake_tls13(
        CertKind::Rsa,
        NamedGroup::FFDHE3072,
        SignatureScheme::RSA_PSS_RSAE_SHA256,
    );
    assert_eq!(g, Some(NamedGroup::FFDHE3072));
}

// ---------------------------------------------------------------------------
// SDV_TLS_12_GROUP — TLS 1.2 group matrix (NIST + X25519; Brainpool skipped)
// ---------------------------------------------------------------------------

#[test]
fn sdv_tls12_group_secp256r1() {
    handshake_tls12(
        CertKind::Rsa,
        NamedGroup::SECP256R1,
        SignatureScheme::RSA_PKCS1_SHA256,
    );
}

#[test]
fn sdv_tls12_group_secp384r1() {
    handshake_tls12(
        CertKind::Rsa,
        NamedGroup::SECP384R1,
        SignatureScheme::RSA_PKCS1_SHA256,
    );
}

#[test]
fn sdv_tls12_group_secp521r1() {
    handshake_tls12(
        CertKind::Rsa,
        NamedGroup::SECP521R1,
        SignatureScheme::RSA_PKCS1_SHA256,
    );
}

#[test]
fn sdv_tls12_group_x25519() {
    handshake_tls12(
        CertKind::Rsa,
        NamedGroup::X25519,
        SignatureScheme::RSA_PKCS1_SHA256,
    );
}

// ---------------------------------------------------------------------------
// SDV_TLS_ECDSA_SIGNATURE (TLS 1.2) — ECDSA scheme matrix
// ---------------------------------------------------------------------------

#[test]
fn sdv_tls12_ecdsa_secp256r1_sha256() {
    handshake_tls12(
        CertKind::Ecdsa,
        NamedGroup::SECP256R1,
        SignatureScheme::ECDSA_SECP256R1_SHA256,
    );
}

#[test]
fn sdv_tls12_ecdsa_secp384r1_sha384() {
    handshake_tls12(
        CertKind::EcdsaCurve(EccCurveId::NistP384),
        NamedGroup::SECP384R1,
        SignatureScheme::ECDSA_SECP384R1_SHA384,
    );
}

#[test]
fn sdv_tls12_ecdsa_secp521r1_sha512() {
    handshake_tls12(
        CertKind::EcdsaCurve(EccCurveId::NistP521),
        NamedGroup::SECP521R1,
        SignatureScheme::ECDSA_SECP521R1_SHA512,
    );
}

// ---------------------------------------------------------------------------
// SDV_TLS_RSA_SIGNATURE (TLS 1.2) — RSA scheme matrix
// ---------------------------------------------------------------------------

#[test]
fn sdv_tls12_rsa_pkcs1_sha256() {
    handshake_tls12(
        CertKind::Rsa,
        NamedGroup::SECP256R1,
        SignatureScheme::RSA_PKCS1_SHA256,
    );
}

#[test]
fn sdv_tls12_rsa_pkcs1_sha384() {
    handshake_tls12(
        CertKind::Rsa,
        NamedGroup::SECP256R1,
        SignatureScheme::RSA_PKCS1_SHA384,
    );
}

#[test]
fn sdv_tls12_rsa_pkcs1_sha512() {
    handshake_tls12(
        CertKind::Rsa,
        NamedGroup::SECP256R1,
        SignatureScheme::RSA_PKCS1_SHA512,
    );
}

#[test]
fn sdv_tls12_rsa_pss_rsae_sha256() {
    handshake_tls12(
        CertKind::Rsa,
        NamedGroup::SECP256R1,
        SignatureScheme::RSA_PSS_RSAE_SHA256,
    );
}

#[test]
fn sdv_tls12_rsa_pss_rsae_sha384() {
    handshake_tls12(
        CertKind::Rsa,
        NamedGroup::SECP256R1,
        SignatureScheme::RSA_PSS_RSAE_SHA384,
    );
}

#[test]
fn sdv_tls12_rsa_pss_rsae_sha512() {
    handshake_tls12(
        CertKind::Rsa,
        NamedGroup::SECP256R1,
        SignatureScheme::RSA_PSS_RSAE_SHA512,
    );
}

// ---------------------------------------------------------------------------
// SDV_TLS13_RSA_SIGNATURE — RSA-PSS-RSAE matrix (TLS 1.3)
// ---------------------------------------------------------------------------

#[test]
fn sdv_tls13_rsa_pss_rsae_sha256() {
    handshake_tls13(
        CertKind::Rsa,
        NamedGroup::SECP256R1,
        SignatureScheme::RSA_PSS_RSAE_SHA256,
    );
}

#[test]
fn sdv_tls13_rsa_pss_rsae_sha384() {
    handshake_tls13(
        CertKind::Rsa,
        NamedGroup::SECP256R1,
        SignatureScheme::RSA_PSS_RSAE_SHA384,
    );
}

#[test]
fn sdv_tls13_rsa_pss_rsae_sha512() {
    handshake_tls13(
        CertKind::Rsa,
        NamedGroup::SECP256R1,
        SignatureScheme::RSA_PSS_RSAE_SHA512,
    );
}

// ---------------------------------------------------------------------------
// SDV_TLS13_ECDSA_SIGNATURE — ECDSA curve × hash matrix (TLS 1.3)
//
// The C TC takes a `cert` argument so it can swap the server certificate
// per row: `ECDSA` (P-256), `ECDSA-384`, `ECDSA-512`. RFC 8446 §4.2.3 ties
// `ecdsa_secp{256,384,521}r1_sha{256,384,512}` to the corresponding cert
// curve, so each row gets a self-signed cert on that curve.
// ---------------------------------------------------------------------------

#[test]
fn sdv_tls13_ecdsa_secp256r1_sha256() {
    handshake_tls13(
        CertKind::Ecdsa,
        NamedGroup::SECP256R1,
        SignatureScheme::ECDSA_SECP256R1_SHA256,
    );
}

#[test]
fn sdv_tls13_ecdsa_secp384r1_sha384() {
    handshake_tls13(
        CertKind::EcdsaCurve(EccCurveId::NistP384),
        NamedGroup::SECP384R1,
        SignatureScheme::ECDSA_SECP384R1_SHA384,
    );
}

#[test]
fn sdv_tls13_ecdsa_secp521r1_sha512() {
    handshake_tls13(
        CertKind::EcdsaCurve(EccCurveId::NistP521),
        NamedGroup::SECP521R1,
        SignatureScheme::ECDSA_SECP521R1_SHA512,
    );
}

// ---------------------------------------------------------------------------
// SDV_TLS13_EDDSA_SIGNATURE — Ed25519 over X25519 (TLS 1.3)
// ---------------------------------------------------------------------------

#[test]
fn sdv_tls13_ed25519_x25519() {
    handshake_tls13(
        CertKind::Ed25519,
        NamedGroup::X25519,
        SignatureScheme::ED25519,
    );
}
