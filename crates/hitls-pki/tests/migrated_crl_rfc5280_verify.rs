//! C → Rust migration of CRL verify-side rows from
//! `test_suite_sdv_x509_crl_rfc5280.{c,data}` that were not emitted by
//! `xtask migrate-c-tests` because their row shapes (multi-arg CA + middleCRL +
//! intermediateCRL + targetCert + flags + crlVerResult + expResult) did not
//! match the existing emitter kinds in `xtask/src/x509.rs`.
//!
//! Scope: rows that exercise `CertificateVerifier` revocation-status checking
//! against a trust store + CRL set. Only rows using `VFY_FLAG_CRL_ALL` (or the
//! equivalent `set_check_revocation(true)`) are migrated — the `CRL_DEV`
//! variant has no Rust analogue and is deferred.
//!
//! The migration is paired with the RFC 5280 §6.3.3(f) product fix
//! ("CRL issuer cert must have cRLSign KU asserted") that this PR ships in
//! `verify.rs::check_revocation_status`; `tc_line176_*` is the trophy test
//! for that fix.

#![cfg(feature = "x509")]

use hitls_pki::x509::verify::CertificateVerifier;
use hitls_pki::x509::{Certificate, CertificateRevocationList, KeyUsage};
use hitls_types::PkiError;

fn load_cert(rel: &str) -> Certificate {
    let path = format!(
        "{}/../../tests/vectors/c-asn1-fixtures/{}",
        env!("CARGO_MANIFEST_DIR"),
        rel
    );
    let bytes = std::fs::read(&path).unwrap();
    match std::str::from_utf8(&bytes) {
        Ok(s) if s.contains("-----BEGIN") => Certificate::from_pem(s).unwrap(),
        _ => Certificate::from_der(&bytes).unwrap(),
    }
}

fn load_crl(rel: &str) -> CertificateRevocationList {
    let path = format!(
        "{}/../../tests/vectors/c-asn1-fixtures/{}",
        env!("CARGO_MANIFEST_DIR"),
        rel
    );
    let bytes = std::fs::read(&path).unwrap();
    match std::str::from_utf8(&bytes) {
        Ok(s) if s.contains("-----BEGIN") => CertificateRevocationList::from_pem(s).unwrap(),
        _ => CertificateRevocationList::from_der(&bytes).unwrap(),
    }
}

// ---------------------------------------------------------------------------
// FILE_VERIFY_FUNC_TC002 — two-tier chain (root CA + intermediate CA) with
// CRL coverage at one or both tiers.
// ---------------------------------------------------------------------------

/// SDV_X509_CRL_FILE_VERIFY_FUNC_TC002 (line 170): two-tier chain with a fresh
/// `root_updated.crl` and a healthy `intermediate.crl`, `VFY_FLAG_CRL_ALL`.
/// device1 is not revoked by either CRL → verify succeeds (chain length 3).
#[test]
fn tc_line170_x509_crl_verify_two_tier_no_revocation() {
    let ca = load_cert("cert/test_for_crl/crl_verify/certs/ca.crt");
    let intermediate =
        load_cert("cert/test_for_crl/crl_verify/intermediate/certs/intermediate.crt");
    let device1 = load_cert("cert/test_for_crl/crl_verify/intermediate/certs/device1.crt");
    let root_updated_crl = load_crl("cert/test_for_crl/crl_verify/crl/root_updated.crl");
    let intermediate_crl =
        load_crl("cert/test_for_crl/crl_verify/intermediate/crl/intermediate.crl");

    let mut verifier = CertificateVerifier::new();
    verifier.add_trusted_cert(ca);
    verifier.add_crl(root_updated_crl);
    verifier.add_crl(intermediate_crl);
    verifier.set_check_revocation(true);

    let chain = verifier
        .verify_cert(&device1, std::slice::from_ref(&intermediate))
        .expect("chain should validate cleanly when device1 is not on either CRL");
    assert_eq!(
        chain.len(),
        3,
        "chain should be [device1, intermediate, root]"
    );
}

// SDV_X509_CRL_FILE_VERIFY_FUNC_TC002 (line 176): the intermediate CA in the
// chain has its `cRLSign` KeyUsage bit cleared. The C fixture
// `intermediate_no_crlsign.crt` was hand-edited to flip the KU bit without
// re-signing, so its tbsCert no longer matches its signature — Rust's chain
// validator catches the cert-level signature mismatch *before* the revocation
// step is reached, and the test panics with `ChainVerifyFailed`. Migrating
// the row verbatim therefore does not exercise the §6.3.3(f) cRLSign rule;
// the synthetic `verify_revocation_*_crl_sign_*` tests below cover the rule
// instead, using freshly-signed certs.

/// Synthetic positive: an issuer cert with `cRLSign` asserted in its KeyUsage
/// extension is accepted as a CRL signer (RFC 5280 §6.3.3(f) — the rule
/// permits the usage).
#[test]
fn verify_revocation_accepts_issuer_with_crl_sign_keyusage() {
    let (ca, ca_chain, crl, target) = synth_chain(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN);

    let mut verifier = CertificateVerifier::new();
    verifier.add_trusted_cert(ca);
    verifier.add_crl(crl);
    verifier.set_check_revocation(true);

    verifier
        .verify_cert(&target, &ca_chain)
        .expect("CA with cRLSign — revocation check should pass when target is not revoked");
}

/// Synthetic negative: an issuer cert with KeyUsage present but missing the
/// `cRLSign` bit MUST NOT be accepted as a CRL signer (RFC 5280 §6.3.3(f)).
/// This is the trophy test for the product fix in this PR.
#[test]
fn verify_revocation_rejects_issuer_without_crl_sign_keyusage() {
    let (ca, ca_chain, crl, target) = synth_chain(KeyUsage::KEY_CERT_SIGN);

    // Sanity: the synthetic CA has KeyUsage present but cRLSign missing.
    let ku = ca
        .key_usage()
        .expect("synthetic CA should carry a KeyUsage extension");
    assert!(
        !ku.has(KeyUsage::CRL_SIGN),
        "synthetic CA should NOT assert cRLSign"
    );

    let mut verifier = CertificateVerifier::new();
    verifier.add_trusted_cert(ca);
    verifier.add_crl(crl);
    verifier.set_check_revocation(true);

    let err = verifier
        .verify_cert(&target, &ca_chain)
        .expect_err("CA lacks cRLSign — RFC 5280 §6.3.3(f) requires rejection");
    match err {
        PkiError::KeyUsageViolation(msg) => assert!(
            msg.contains("cRLSign"),
            "expected message to mention cRLSign, got: {msg}"
        ),
        other => panic!("expected PkiError::KeyUsageViolation, got: {other:?}"),
    }
}

/// Build a self-signed CA with the requested KeyUsage bits, a leaf cert signed
/// by that CA, and an empty CRL signed by the same CA. The leaf is not
/// revoked — the revocation walk's only failure mode under test is the
/// `cRLSign` KeyUsage check.
fn synth_chain(
    ca_key_usage: u16,
) -> (
    Certificate,
    Vec<Certificate>,
    CertificateRevocationList,
    Certificate,
) {
    use hitls_pki::x509::{CertificateBuilder, CrlBuilder, DistinguishedName, SigningKey};

    let ca_kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
    let ca_sk = SigningKey::Ed25519(ca_kp);
    let ca_dn = DistinguishedName {
        entries: vec![("CN".to_string(), "Test CA RFC 5280 6.3.3(f)".to_string())],
    };
    let ca_spki = ca_sk.public_key_info().unwrap();
    let ca = CertificateBuilder::new()
        .serial_number(&[0x01])
        .issuer(ca_dn.clone())
        .subject(ca_dn.clone())
        .validity(1_700_000_000, 1_800_000_000)
        .subject_public_key(ca_spki)
        .add_basic_constraints(true, None)
        .add_key_usage(ca_key_usage)
        .build(&ca_sk)
        .unwrap();

    let leaf_kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
    let leaf_sk = SigningKey::Ed25519(leaf_kp);
    let leaf_spki = leaf_sk.public_key_info().unwrap();
    let leaf_dn = DistinguishedName {
        entries: vec![("CN".to_string(), "Test Leaf".to_string())],
    };
    let leaf = CertificateBuilder::new()
        .serial_number(&[0x02])
        .issuer(ca_dn.clone())
        .subject(leaf_dn)
        .validity(1_700_000_000, 1_800_000_000)
        .subject_public_key(leaf_spki)
        .add_key_usage(KeyUsage::DIGITAL_SIGNATURE)
        .build(&ca_sk)
        .unwrap();

    let crl = CrlBuilder::new(ca_dn, 1_700_000_000)
        .next_update(1_800_000_000)
        .build(&ca_sk)
        .unwrap();

    (ca, Vec::new(), crl, leaf)
}

// ---------------------------------------------------------------------------
// FILE_VERIFY_FUNC_TC004 — single-tier SM2 chain (one CA, one CRL) used to
// exercise the SM2 signature-verification path under `check_revocation(true)`.
// ---------------------------------------------------------------------------

/// SDV_X509_CRL_FILE_VERIFY_FUNC_TC004 (line 191): SM2 root + SM2 CRL +
/// server2 (not revoked) + `VFY_FLAG_CRL_ALL`. Verify succeeds.
#[test]
fn tc_line191_x509_crl_verify_sm2_server_not_revoked() {
    let root = load_cert("cert/test_for_crl/sm2/sm2_without_userid/crl_verify/certs/root.crt");
    let server2 =
        load_cert("cert/test_for_crl/sm2/sm2_without_userid/crl_verify/certs/server2.crt");
    let root_crl = load_crl("cert/test_for_crl/sm2/sm2_without_userid/crl_verify/crl/root.crl");

    let mut verifier = CertificateVerifier::new();
    verifier.add_trusted_cert(root);
    verifier.add_crl(root_crl);
    verifier.set_check_revocation(true);

    let chain = verifier
        .verify_cert(&server2, &[])
        .expect("SM2 chain should validate cleanly when server2 is not on the CRL");
    assert_eq!(chain.len(), 2, "chain should be [server2, root]");
}

/// SDV_X509_CRL_FILE_VERIFY_FUNC_TC004 (line 194): SM2 root + SM2 CRL +
/// server1 (revoked) + `VFY_FLAG_CRL_ALL`. Expect `CertRevoked`.
#[test]
fn tc_line194_x509_crl_verify_sm2_server_revoked() {
    let root = load_cert("cert/test_for_crl/sm2/sm2_without_userid/crl_verify/certs/root.crt");
    let server1 =
        load_cert("cert/test_for_crl/sm2/sm2_without_userid/crl_verify/certs/server1.crt");
    let root_crl = load_crl("cert/test_for_crl/sm2/sm2_without_userid/crl_verify/crl/root.crl");

    let mut verifier = CertificateVerifier::new();
    verifier.add_trusted_cert(root);
    verifier.add_crl(root_crl);
    verifier.set_check_revocation(true);

    let err = verifier
        .verify_cert(&server1, &[])
        .expect_err("server1 should be on the CRL");
    assert!(
        matches!(err, PkiError::CertRevoked),
        "expected PkiError::CertRevoked, got: {err:?}"
    );
}

/// SDV_X509_CRL_FILE_VERIFY_FUNC_TC004 (line 200): same SM2 chain as r194 but
/// `set_check_revocation(false)` (mirrors the C `flags = 0` row). The CRL is
/// ignored entirely → verify succeeds even though server1 IS on the CRL.
#[test]
fn tc_line200_x509_crl_verify_sm2_check_revocation_disabled() {
    let root = load_cert("cert/test_for_crl/sm2/sm2_without_userid/crl_verify/certs/root.crt");
    let server1 =
        load_cert("cert/test_for_crl/sm2/sm2_without_userid/crl_verify/certs/server1.crt");
    let root_crl = load_crl("cert/test_for_crl/sm2/sm2_without_userid/crl_verify/crl/root.crl");

    let mut verifier = CertificateVerifier::new();
    verifier.add_trusted_cert(root);
    verifier.add_crl(root_crl);
    verifier.set_check_revocation(false);

    let chain = verifier
        .verify_cert(&server1, &[])
        .expect("with revocation check off, chain should validate");
    assert_eq!(chain.len(), 2);
}

/// SDV_X509_CRL_FILE_VERIFY_FUNC_TC004 (line 203): SM2 root + SM2 CRL with
/// extensions + revoked server + `VFY_FLAG_CRL_ALL`. The CRL carries an
/// extensionRequest attribute (the only difference from r194 is the CRL
/// fixture); revocation lookup still fires → `CertRevoked`.
#[test]
fn tc_line203_x509_crl_verify_sm2_extension_crl_revoked() {
    let root = load_cert("cert/test_for_crl/sm2/sm2_without_userid/extension_crl/root.crt");
    let server = load_cert("cert/test_for_crl/sm2/sm2_without_userid/extension_crl/server.crt");
    let root_crl = load_crl("cert/test_for_crl/sm2/sm2_without_userid/extension_crl/root.crl");

    let mut verifier = CertificateVerifier::new();
    verifier.add_trusted_cert(root);
    verifier.add_crl(root_crl);
    verifier.set_check_revocation(true);

    let err = verifier
        .verify_cert(&server, &[])
        .expect_err("server should be on the extension_crl");
    assert!(
        matches!(err, PkiError::CertRevoked),
        "expected PkiError::CertRevoked, got: {err:?}"
    );
}
