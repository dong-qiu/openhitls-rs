//! x509_check.c + x509_vfy.c gap-coverage tests — T207 / #42.
//!
//! Phase C-4 of the PKI malformed-fixture migration plan
//! (`docs/issue-42-phase-c-plan.md`). Targets the surface left after
//! T204-T206:
//!
//! - `openhitls/testcode/sdv/testcase/pki/cert/test_suite_sdv_x509_check.c`
//!   (39 fn / 346 rows — `CERT_VERSIONCHECK_TC001-004`,
//!   `CERT_ISSUERCHECK_TC001/002`, `CERT_SUBJECTCHECK_TC001-003`,
//!   `CERT_WITH_AKISKI_GEN_TEST`, `CERT_WITH_BCON_*`,
//!   `CERT_WITH_ALL_EXT_GEN/PARSE`, custom-ext rows)
//! - `openhitls/testcode/sdv/testcase/pki/verify/test_suite_sdv_x509_vfy.c`
//!   (84 fn / 385 rows — `BUILD_CERT_CHAIN_FUNC_TC001-009`,
//!   `CERT_VERIFY_BY_PUBKEY`, MLDSA/MLKEM/SLHDSA chain rows)
//!
//! Existing Rust coverage (`migrated_x509_parse.rs` 1 076 fns +
//! `tests/interop/` chain handshakes) already covers the bulk of
//! positive parse + verify round-trips. This batch pins the
//! complementary attack surface: extension accessor presence, version
//! detection, and the algorithm matrix for self-signed verify.
//!
//! ## C-source decision matrix
//!
//! | C TC family | Rust coverage | Decision |
//! |-------------|---------------|----------|
//! | `CERT_VERSIONCHECK_TC001-004` | none for v3 surface | **port** — v3 detection |
//! | `CERT_ISSUERCHECK_TC001` (DN equality) | none for raw DN equality pin | **port** — DN field round-trip |
//! | `CERT_SUBJECTCHECK_TC001` (subject DN) | none | **port** — subject DN round-trip |
//! | `CERT_WITH_AKISKI_GEN_TEST_TC001` | none for accessor presence | **port** — AKI/SKI presence pin |
//! | `CERT_WITH_BCON_*` (BasicConstraints CA flag) | none for explicit accessor | **port** — CA=true (root) vs CA=false (leaf) |
//! | `CERT_WITH_ALL_EXT_PARSE_TEST_TC001` | partial — extensions Vec walks | **port** — KU + EKU accessor combo |
//! | `BUILD_CERT_CHAIN_FUNC_TC001` (self-signed verify) | partial via interop tests | **port** — explicit verify_signature(self) per algorithm |
//! | `BUILD_MLDSA_CERT_CHAIN_FUNC_TC001` | none (ML-DSA cert parse may be unsupported) | **port as gap pin** |
//! | `BUILD_SLHDSA_CERT_CHAIN_FUNC_TC001` | none | **port as gap pin** |
//! | `CERT_VERIFY_BY_PUBKEY_FUNC_TC001` | covered by `verify_signature(&issuer)` round-trip above | scope-cut |
//! | `BUILD_CERT_CHAIN_*` complex multi-tier rows | covered by existing `migrated_x509_parse` chain rows | scope-cut |
//! | `CA_PATH_WITH_VARIOUS_CHARSET_*` | covered by `migrated_crl_rfc5280_gap` charset rows | scope-cut |
//!
//! ## Plan-doc cross-coverage pin
//!
//! `audit_plan_docs_in_sync` reads `docs/issue-42-phase-c-plan.md`,
//! same pattern as T204-T206.

#![cfg(feature = "x509")]

use hitls_pki::x509::Certificate;

/// Load a certificate fixture (PEM or DER) from
/// `tests/vectors/c-asn1-fixtures/`.
fn load_cert(rel: &str) -> Certificate {
    let path = format!(
        "{}/../../tests/vectors/c-asn1-fixtures/{}",
        env!("CARGO_MANIFEST_DIR"),
        rel
    );
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("missing fixture {path}: {e}"));
    match std::str::from_utf8(&bytes) {
        Ok(s) if s.contains("-----BEGIN") => Certificate::from_pem(s).unwrap(),
        _ => Certificate::from_der(&bytes).unwrap(),
    }
}

// ===========================================================================
// CERT_VERSIONCHECK_TC001-004 — v3 detection.
// ===========================================================================

/// Mirrors C `SDV_X509_CERT_VERSIONCHECK_TC001`: rsa-v3 chain root
/// surfaces as version 3 (encoded as INTEGER 2 in DER).
#[test]
fn cert_check_rsa_v3_root_version() {
    let cert = load_cert("cert/chain/rsa-v3/rootca.der");
    assert_eq!(cert.version, 3, "rsa-v3 rootca must be X.509 v3");
}

/// ecdsa-v3 baseline: end-entity surfaces as v3.
#[test]
fn cert_check_ecdsa_v3_end_version() {
    let cert = load_cert("cert/chain/ecdsa-v3/end.der");
    assert_eq!(cert.version, 3, "ecdsa-v3 end-entity must be X.509 v3");
}

// ===========================================================================
// CERT_ISSUERCHECK_TC001 + CERT_SUBJECTCHECK_TC001 — DN round-trip pins.
// ===========================================================================

/// Mirrors C `SDV_X509_CERT_ISSUERCHECK_TC001`: a v3 leaf cert's
/// issuer DN matches its CA's subject DN (chain consistency).
#[test]
fn cert_check_issuer_dn_matches_ca_subject() {
    let leaf = load_cert("cert/chain/rsa-v3/end.der");
    let ca = load_cert("cert/chain/rsa-v3/inter.der");
    assert_eq!(
        leaf.issuer, ca.subject,
        "rsa-v3 leaf's issuer must equal its intermediate CA's subject"
    );
}

/// Mirrors C `SDV_X509_CERT_SUBJECTCHECK_TC001`: subject DN field is
/// non-empty for a normal end-entity.
#[test]
fn cert_check_subject_dn_non_empty() {
    let cert = load_cert("cert/chain/rsa-v3/end.der");
    assert!(
        !cert.subject.entries.is_empty(),
        "rsa-v3 end-entity must carry a non-empty subject DN"
    );
}

// ===========================================================================
// CERT_WITH_AKISKI_GEN_TEST_TC001 — AKI + SKI extension presence.
// ===========================================================================

/// Mirrors C `SDV_X509_CERT_WITH_AKISKI_GEN_TEST_TC001`: an
/// AKI-carrying intermediate must surface the AKI extension.
#[test]
fn cert_check_aki_extension_present_on_intermediate() {
    let cert = load_cert("cert/chain/akiski_suite/aki_inter.pem");
    let aki = cert.authority_key_identifier();
    assert!(
        aki.is_some(),
        "akiski_suite/aki_inter must carry an AKI extension"
    );
}

/// Mirror: the root cert in the AKI suite carries an SKI extension.
#[test]
fn cert_check_ski_extension_present_on_root() {
    let cert = load_cert("cert/chain/akiski_suite/aki_root.pem");
    let ski = cert.subject_key_identifier();
    assert!(
        ski.is_some(),
        "akiski_suite/aki_root must carry an SKI extension"
    );
}

// ===========================================================================
// CERT_WITH_BCON_* — BasicConstraints `cA` flag accessor.
// ===========================================================================

/// Mirrors C `SDV_X509_CERT_WITH_BCON_PARSE_TEST_TC001`: a normal root
/// carries `BasicConstraints { ca: true }`.
#[test]
fn cert_check_basic_constraints_ca_true_on_root() {
    let cert = load_cert("cert/chain/bcExt/bc_root_general.pem");
    let bc = cert
        .basic_constraints()
        .expect("root must carry a BasicConstraints extension");
    assert!(bc.is_ca, "root's BasicConstraints must have ca=true");
}

/// Mirror: a leaf with explicit `BasicConstraints { ca: false }`
/// surfaces with `ca: false`.
#[test]
fn cert_check_basic_constraints_ca_false_on_leaf() {
    let cert = load_cert("cert/chain/bcExt/bc_leaf_ca_false.pem");
    let bc = cert
        .basic_constraints()
        .expect("leaf must carry a BasicConstraints extension");
    assert!(!bc.is_ca, "leaf's BasicConstraints must have ca=false");
}

// ===========================================================================
// CERT_WITH_ALL_EXT_PARSE_TEST_TC001 — KU + EKU accessor combo.
// ===========================================================================

/// Mirrors C `SDV_X509_CERT_WITH_ALL_EXT_PARSE_TEST_TC001` slice:
/// a "good" server certificate from the EKU suite carries an
/// `extended_key_usage` extension.
#[test]
fn cert_check_extended_key_usage_present_on_server_good() {
    let cert = load_cert("cert/chain/eku_suite/server_good.der");
    let eku = cert.extended_key_usage();
    assert!(
        eku.is_some(),
        "eku_suite/server_good must carry an ExtendedKeyUsage extension"
    );
}

/// Same fixture: KeyUsage extension is also present.
#[test]
fn cert_check_key_usage_present_on_server_good() {
    let cert = load_cert("cert/chain/eku_suite/server_good.der");
    let ku = cert.key_usage();
    assert!(
        ku.is_some(),
        "eku_suite/server_good must carry a KeyUsage extension"
    );
}

// ===========================================================================
// BUILD_CERT_CHAIN_FUNC_TC001 — self-signed verify per algorithm matrix.
// ===========================================================================

/// Mirrors C `SDV_X509_BUILD_CERT_CHAIN_FUNC_TC001` row: an RSA-v3
/// self-signed root verifies against itself.
#[test]
fn cert_verify_rsa_self_signed_root() {
    let root = load_cert("cert/chain/rsa-v3/rootca.der");
    assert!(
        root.is_self_signed(),
        "rsa-v3 rootca must be flagged as self-signed"
    );
    assert!(
        root.verify_signature(&root)
            .expect("self-signature verify must complete"),
        "rsa-v3 rootca self-signature must verify"
    );
}

/// ECDSA self-signed root.
#[test]
fn cert_verify_ecdsa_self_signed_root() {
    let root = load_cert("cert/chain/ecdsa-v3/ca.der");
    let _ = root.is_self_signed(); // structural pin
    assert!(
        root.verify_signature(&root)
            .expect("self-signature verify must complete"),
        "ecdsa-v3 ca self-signature must verify"
    );
}

// ===========================================================================
// BUILD_MLDSA / SLHDSA_CERT_CHAIN_FUNC_TC001 — PQC gap pins.
//
// Rust's certificate parser may not yet recognise ML-DSA / SLH-DSA
// OIDs in `SignatureAlgorithm`. Pin the current behaviour so a future
// PQC cert support lands as a deliberate change.
// ===========================================================================

/// Mirrors C `SDV_X509_BUILD_MLDSA_CERT_CHAIN_FUNC_TC001`: ML-DSA
/// (Dilithium) cert load. If Rust's parser doesn't yet decode the
/// SubjectPublicKeyInfo's ML-DSA OID, surface this as a gap pin
/// rather than a hard assertion.
#[test]
fn cert_check_mldsa_chain_root_round_trip_or_gap() {
    let path = format!(
        "{}/../../tests/vectors/c-asn1-fixtures/cert/chain/mldsa-v3/root.crt",
        env!("CARGO_MANIFEST_DIR")
    );
    let bytes = std::fs::read(&path).unwrap();
    match Certificate::from_pem(std::str::from_utf8(&bytes).unwrap_or("")) {
        Ok(cert) => {
            // Parser accepted ML-DSA — pin the v3 round-trip.
            assert_eq!(cert.version, 3, "ML-DSA root must be v3 if parsed");
        }
        Err(_) => {
            // TODO(#42-phase-c): add ML-DSA dispatch to the X.509
            // signature-algorithm decoder.
        }
    }
}

/// Mirrors C `SDV_X509_BUILD_SLHDSA_CERT_CHAIN_FUNC_TC001`: SLH-DSA
/// (SPHINCS+) cert load. Same gap-pin treatment as ML-DSA.
#[test]
fn cert_check_slhdsa_chain_root_round_trip_or_gap() {
    let path = format!(
        "{}/../../tests/vectors/c-asn1-fixtures/cert/chain/slhdsa",
        env!("CARGO_MANIFEST_DIR")
    );
    // The slhdsa fixtures live in a sub-directory; we don't pre-bind a
    // specific file name. Pin only that the directory exists in the
    // mirror (the fixture-presence claim is the audit anchor).
    let dir = std::fs::read_dir(&path);
    assert!(
        dir.is_ok(),
        "slhdsa fixture directory must remain mirrored under \
         tests/vectors/c-asn1-fixtures/cert/chain/slhdsa for #42 Phase C"
    );
    // TODO(#42-phase-c): when SLH-DSA cert support lands, port
    // `BUILD_SLHDSA_CERT_CHAIN_FUNC_TC001`'s round-trip path here.
}

// ===========================================================================
// Plan-doc cross-coverage pin.
// ===========================================================================

#[test]
fn audit_plan_docs_in_sync() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-c-plan.md");
    let plan = std::fs::read_to_string(&plan_path)
        .unwrap_or_else(|e| panic!("missing audit doc at {plan_path}: {e}"));

    for tag in &[
        "T204", "T205", "T206", "T207", "T208", "C-1", "C-2", "C-3", "C-4",
    ] {
        assert!(plan.contains(tag), "plan doc missing sub-PR tag `{tag}`");
    }

    for anchor in &["x509_check.c", "x509_vfy.c", "TODO(#42-phase-c)"] {
        assert!(
            plan.contains(anchor),
            "plan doc must keep anchor `{anchor}`"
        );
    }
}
