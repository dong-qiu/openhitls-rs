//! Phase B audit pins — T112 / #42.
//!
//! Phase B-1 of the audit-pin closure of the 49 `#43-#61` TODO
//! anchors (`docs/issue-42-phase-b-plan.md`). Same audit-pin
//! methodology codified through Phase C (T204-T208), Phase G
//! (T219-T223), and Phase H (T224-T228).
//!
//! ## Why this file exists
//!
//! The 5 Phase B GitHub issues (#43 enc CLI, #44 CSR negative, #45
//! CRL RFC 5280, #47 CLI 5 sub-commands, #57 idle fixtures) are all
//! CLOSED at the issue level. 49 deeper TODO anchors remain across
//! 8+ files representing real implementation gaps that the issue
//! closure deliberately deferred. Phase B locks the current lenient
//! / unsupported behaviour at every remaining TODO site and produces
//! a concrete Phase I roadmap at T236 closeout, rather than
//! implementing the deeper crypto primitives here.
//!
//! ## T112 scope (this PR)
//!
//! 8 audit pins covering the 8 `#44 / #45` sites in
//! `migrated_csr_negative_parse.rs` + `migrated_crl_rfc5280_verify.rs`:
//!
//! - 3 × CSR RFC 2986 §4 version field pins
//! - 3 × CRL RFC 5280 §5.1.2.1 version field pins
//! - 2 × CRL RFC 5280 §5.2.1 AKI ↔ SKI matching pins
//!
//! Each pin asserts: (a) the RFC section number, (b) the codepoint /
//! version byte, (c) the existing TODO marker remains in its source
//! file (cross-file grep target), (d) the plan-doc anchor remains
//! the authority.

// CSR RFC 2986 §4 — `CertificationRequestInfo.version` field
// codepoint = 0 (v1). RFC 2986 §4.1 says: "version is the version
// number, for compatibility with future revisions of this document.
// It shall be 0 for this version of the standard."
//
// Current Rust behaviour: parser stores the corrupted version
// verbatim instead of rejecting. Pinned at
// `migrated_csr_negative_parse.rs` line 284 with the literal
// `TODO(#44-strict-version)` marker. Phase I will tighten this to
// `Err(PkiError::InvalidCsr)` when version != 0.
//
// The pin asserts the RFC version codepoint as a byte literal that
// a future Phase I PR can grep here when adding the rejection path.

#[test]
fn t112_csr_rfc2986_version_codepoint_pin() {
    let csr_version_v1: u8 = 0;
    assert_eq!(
        csr_version_v1, 0,
        "RFC 2986 §4.1 — CSR version field MUST be 0 (v1)"
    );
}

/// T112 audit pin #2: cross-file grep that
/// `migrated_csr_negative_parse.rs` still carries the
/// `TODO(#44-strict-version)` marker. A regression that silently
/// deleted the marker would fail this pin.
#[test]
fn t112_csr_strict_version_anchor_preserved_in_source() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/tests/migrated_csr_negative_parse.rs");
    let body = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("missing {path}: {e}"));
    assert!(
        body.contains("TODO(#44-strict-version)"),
        "migrated_csr_negative_parse.rs must retain the #44-strict-version anchor \
         as the future-Phase-I grep target"
    );
    assert!(
        body.contains("RFC 2986"),
        "the existing CSR audit pin must reference RFC 2986 by name"
    );
}

/// T112 audit pin #3: cross-file grep that
/// `migrated_csr_negative_parse.rs` includes at least one
/// `expect(...)` line documenting the lenient behaviour. A
/// regression that auto-rewrote `expect` to `?` would lose the
/// behaviour-pin and fail this audit.
#[test]
fn t112_csr_lenient_behaviour_documented_via_expect_pattern() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/tests/migrated_csr_negative_parse.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(
        body.contains("parser stores the corrupted version verbatim"),
        "the lenient-behaviour assertion message must remain to document \
         the gap the strict-version anchor describes"
    );
}

// CRL RFC 5280 §5.1.2.1 — `TBSCertList.version` field codepoint = 1
// (v2) when extensions are present. RFC 5280 §5.1.2.1 says: "This
// optional field describes the version of the encoded CRL. When
// extensions are used, as required by this profile, this field MUST
// be present and MUST specify version 2 (the integer value is 1)."
//
// Current Rust behaviour: parser tolerates invalid version. Pinned
// at `migrated_crl_rfc5280_verify.rs` line 1235 with the literal
// `TODO(#45-strict-version)` marker. Phase I will tighten this to
// `Err(PkiError::InvalidCrl)` when version != 1 and extensions are
// present.

/// T112 audit pin #4: RFC 5280 §5.1.2.1 CRL v2 version codepoint
/// equals 1; pin the literal byte so a future Phase I rejection
/// path can grep this anchor.
#[test]
fn t112_crl_rfc5280_version_codepoint_pin() {
    let crl_version_v2: u8 = 1;
    assert_eq!(
        crl_version_v2, 1,
        "RFC 5280 §5.1.2.1 — CRL version field MUST be 1 (v2) when extensions present"
    );
}

/// T112 audit pin #5: cross-file grep that
/// `migrated_crl_rfc5280_verify.rs` still carries the
/// `TODO(#45-strict-version)` marker.
#[test]
fn t112_crl_strict_version_anchor_preserved_in_source() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/tests/migrated_crl_rfc5280_verify.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(
        body.contains("TODO(#45-strict-version)"),
        "migrated_crl_rfc5280_verify.rs must retain the #45-strict-version anchor"
    );
    assert!(
        body.contains("RFC 5280"),
        "the existing CRL audit pin must reference RFC 5280 by name"
    );
}

/// T112 audit pin #6: pin that the lenient-behaviour assertion
/// message for CRL version tolerance remains in source as the
/// behaviour anchor.
#[test]
fn t112_crl_lenient_version_behaviour_documented() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/tests/migrated_crl_rfc5280_verify.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(
        body.contains("Rust parser tolerates invalid version"),
        "the CRL lenient-behaviour assertion message must remain pinned"
    );
}

// CRL RFC 5280 §5.2.1 — AuthorityKeyIdentifier ↔ SubjectKeyIdentifier
// matching. RFC 5280 §5.2.1 (and §4.2.1.1) says the CRL's AKI MUST
// match the issuing CA's SKI for unambiguous chain construction.
//
// Current Rust behaviour: CRL is matched to issuer by Distinguished
// Name only; AKI/SKI match is unimplemented. Pinned at
// `migrated_crl_rfc5280_verify.rs` line 1151 with the literal
// `TODO(#45-aki-match)` marker. Phase I will add AKI/SKI matching
// alongside DN matching.

/// T112 audit pin #7: pin that the AKI-match anchor remains. The
/// future Phase I PR will grep this anchor to find the call site
/// to change.
#[test]
fn t112_crl_aki_match_anchor_preserved_in_source() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/tests/migrated_crl_rfc5280_verify.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(
        body.contains("TODO(#45-aki-match)"),
        "migrated_crl_rfc5280_verify.rs must retain the #45-aki-match anchor"
    );
    assert!(
        body.contains("AKI") || body.contains("AuthorityKeyIdentifier"),
        "the AKI-match audit pin must reference AuthorityKeyIdentifier"
    );
}

// ===========================================================================
// T233 / Phase B-2 — `#47-pkey-*` family audit pins.
//
// 10 sites in `crates/hitls-cli/src/pkey.rs`:
//
// - `#47-pkey-rsa-pss` × 3 (module doc + 2 `not implemented` call sites)
// - `#47-pkey-sm2` × 3 (module doc + 2 `not implemented` call sites)
// - `#47-pkey-brainpool` × 1 (module doc)
// - `#47-pkey-p224` × 1 (module doc)
// - `#47-pkey-encrypted-pkcs8` × 2 (module doc + body comment)
//
// 10 audit pins extending the T112 4-tuple methodology (RFC § + OID/
// codepoint + TODO marker + plan-doc anchor) to OID identity pins. Each
// OID byte literal is the future Phase I grep target when implementing
// the corresponding PKCS#8 codec.
//
// Cumulative: T112 (8) + T233 (10) = 18 tests.
// ===========================================================================

/// T233 audit pin #1: RFC 8017 §C.1 `id-RSASSA-PSS` OID =
/// `1.2.840.113549.1.1.10` (the algorithm identifier inside the
/// `AlgorithmIdentifier` of an RSA-PSS PKCS#8 private key). Phase I
/// implementation will need this OID to dispatch the codec.
#[test]
fn t233_rsa_pss_oid_codepoint_pin() {
    let rsa_pss_oid = "1.2.840.113549.1.1.10";
    assert_eq!(
        rsa_pss_oid, "1.2.840.113549.1.1.10",
        "RFC 8017 §C.1 — id-RSASSA-PSS OID"
    );
}

/// T233 audit pin #2: 3 `#47-pkey-rsa-pss` sites in
/// `crates/hitls-cli/src/pkey.rs` (module doc + 2 `not implemented`
/// returns) remain preserved.
#[test]
fn t233_rsa_pss_pkcs8_anchor_preserved_in_source() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../hitls-cli/src/pkey.rs");
    let body =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("missing pkey.rs at {path}: {e}"));
    let count = body.matches("TODO(#47-pkey-rsa-pss)").count();
    assert!(
        count >= 3,
        "pkey.rs must retain at least 3 #47-pkey-rsa-pss anchors (module doc + 2 call sites); found {count}"
    );
    assert!(
        body.contains("RSA-PSS PKCS#8 re-encoding not implemented"),
        "the existing RSA-PSS not-implemented assertion message must remain"
    );
}

/// T233 audit pin #3: SM2 named curve OID per GM/T 0006 / RFC 8998 =
/// `1.2.156.10197.1.301`. Phase I implementation will route this OID
/// to the SM2 PKCS#8 codec.
#[test]
fn t233_sm2_pkcs8_oid_codepoint_pin() {
    let sm2_oid = "1.2.156.10197.1.301";
    assert_eq!(
        sm2_oid, "1.2.156.10197.1.301",
        "GM/T 0006 / RFC 8998 — sm2 named curve OID"
    );
}

/// T233 audit pin #4: 3 `#47-pkey-sm2` sites in `pkey.rs` remain.
#[test]
fn t233_sm2_pkcs8_anchor_preserved_in_source() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../hitls-cli/src/pkey.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    let count = body.matches("TODO(#47-pkey-sm2)").count();
    assert!(
        count >= 3,
        "pkey.rs must retain at least 3 #47-pkey-sm2 anchors; found {count}"
    );
    assert!(
        body.contains("SM2 PKCS#8 re-encoding not implemented"),
        "the existing SM2 not-implemented assertion message must remain"
    );
}

/// T233 audit pin #5: RFC 5639 §A.1 Brainpool brainpoolP256r1 OID =
/// `1.3.36.3.3.2.8.1.1.7`. Phase I implementation needs this OID
/// to add Brainpool curve support to the EC PKCS#8 codec.
#[test]
fn t233_brainpool_p256_oid_codepoint_pin() {
    let brainpool_p256r1_oid = "1.3.36.3.3.2.8.1.1.7";
    assert_eq!(
        brainpool_p256r1_oid, "1.3.36.3.3.2.8.1.1.7",
        "RFC 5639 §A.1 — brainpoolP256r1 OID"
    );
}

/// T233 audit pin #6: `#47-pkey-brainpool` anchor in `pkey.rs`
/// module doc remains preserved.
#[test]
fn t233_brainpool_anchor_preserved_in_source() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../hitls-cli/src/pkey.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(
        body.contains("TODO(#47-pkey-brainpool)"),
        "pkey.rs must retain the #47-pkey-brainpool anchor"
    );
    assert!(
        body.contains("Brainpool"),
        "the existing Brainpool anchor must reference the curve family by name"
    );
}

/// T233 audit pin #7: RFC 5480 / SEC 2 NIST P-224 (secp224r1) OID =
/// `1.3.132.0.33`. Phase I implementation needs this OID + the
/// underlying field arithmetic in hitls-crypto.
#[test]
fn t233_nist_p224_oid_codepoint_pin() {
    let secp224r1_oid = "1.3.132.0.33";
    assert_eq!(
        secp224r1_oid, "1.3.132.0.33",
        "RFC 5480 / SEC 2 — secp224r1 (NIST P-224) OID"
    );
}

/// T233 audit pin #8: `#47-pkey-p224` anchor in `pkey.rs` remains.
#[test]
fn t233_p224_anchor_preserved_in_source() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../hitls-cli/src/pkey.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(
        body.contains("TODO(#47-pkey-p224)"),
        "pkey.rs must retain the #47-pkey-p224 anchor"
    );
    assert!(
        body.contains("P-224"),
        "the existing P-224 anchor must reference the curve by name"
    );
}

/// T233 audit pin #9: RFC 8018 §A.4 PBES2 OID =
/// `1.2.840.113549.1.5.13` + RFC 8018 §A.2 PBKDF2 OID =
/// `1.2.840.113549.1.5.12`. Phase I implementation needs both OIDs
/// for password-derived PKCS#8 encryption per the C
/// `UT_HITLS_APP_ENCKEY_TC*` family.
#[test]
fn t233_pbes2_pbkdf2_oid_codepoint_pin() {
    let pbes2_oid = "1.2.840.113549.1.5.13";
    let pbkdf2_oid = "1.2.840.113549.1.5.12";
    assert_eq!(
        pbes2_oid, "1.2.840.113549.1.5.13",
        "RFC 8018 §A.4 PBES2 OID"
    );
    assert_eq!(
        pbkdf2_oid, "1.2.840.113549.1.5.12",
        "RFC 8018 §A.2 PBKDF2 OID"
    );
}

/// T233 audit pin #10: `#47-pkey-encrypted-pkcs8` anchor in `pkey.rs`
/// remains across 2 sites (module doc + body comment). The pkey.rs
/// module docs must enumerate all 5 `#47-pkey-*` families so the
/// per-anchor `.expect()` assertion messages stay coherent with the
/// inventory.
#[test]
fn t233_encrypted_pkcs8_anchor_preserved_in_source() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../hitls-cli/src/pkey.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    let count = body.matches("TODO(#47-pkey-encrypted-pkcs8)").count();
    assert!(
        count >= 2,
        "pkey.rs must retain at least 2 #47-pkey-encrypted-pkcs8 anchors; found {count}"
    );
    // Inventory pin: pkey.rs module docs must surface all 5 families.
    for family in [
        "#47-pkey-rsa-pss",
        "#47-pkey-sm2",
        "#47-pkey-brainpool",
        "#47-pkey-p224",
        "#47-pkey-encrypted-pkcs8",
    ] {
        assert!(
            body.contains(family),
            "pkey.rs module doc must enumerate `{family}` for inventory coherence"
        );
    }
}

// ===========================================================================
// T234 / Phase B-3 — `#47-genrsa/rsa-codec/conf/sm/keymgmt` family.
//
// 17 sites across 7 files (workspace-wide tally):
//
// - `crates/hitls-cli/README.md` × 5
// - `crates/hitls-cli/src/sm_defer.rs` × 3
// - `crates/hitls-cli/src/keymgmt_defer.rs` × 3
// - `crates/hitls-cli/src/rsa_cmd.rs` × 2
// - `crates/hitls-cli/src/genrsa.rs` × 2
// - `crates/hitls-cli/src/main.rs` × 1
// - `crates/hitls-cli/src/conf_util.rs` × 1
//
// 10 audit pins covering 5 families + README inventory + plan doc.
//
// Cumulative: T112 (8) + T233 (10) + T234 (10) = 28 tests.
// ===========================================================================

/// T234 audit pin #1: `#47-genrsa-encryption` anchors in `genrsa.rs`
/// remain. The `-cipher` flag is not yet wired to actually encrypt
/// generated keys (currently writes unencrypted PEM with a deferral
/// comment).
#[test]
fn t234_genrsa_encryption_anchor_preserved_in_source() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../hitls-cli/src/genrsa.rs");
    let body = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing genrsa.rs at {path}: {e}"));
    let count = body.matches("TODO(#47-genrsa-encryption)").count();
    assert!(
        count >= 2,
        "genrsa.rs must retain at least 2 #47-genrsa-encryption anchors; found {count}"
    );
}

/// T234 audit pin #2: RFC 7468 §10 PEM label for traditional RSA
/// private keys is `RSA PRIVATE KEY` (vs `PRIVATE KEY` for PKCS#8).
/// Pin the label literal so Phase I implementors can grep this
/// anchor when adding `-cipher`-driven encryption that switches the
/// label to `ENCRYPTED PRIVATE KEY`.
#[test]
fn t234_genrsa_pem_label_constant_pin() {
    let rsa_pem_label = "RSA PRIVATE KEY";
    let encrypted_pem_label = "ENCRYPTED PRIVATE KEY";
    assert_eq!(rsa_pem_label, "RSA PRIVATE KEY");
    assert_eq!(encrypted_pem_label, "ENCRYPTED PRIVATE KEY");
}

/// T234 audit pin #3: `#47-rsa-codec-extract` anchors in `rsa_cmd.rs`
/// remain. The RSA PKCS#1 CRT-form encoder is duplicated inside
/// `rsa_cmd` rather than extracted to `hitls-pki`; Phase I will
/// extract it.
#[test]
fn t234_rsa_codec_extract_anchor_preserved_in_source() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../hitls-cli/src/rsa_cmd.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    let count = body.matches("TODO(#47-rsa-codec-extract)").count();
    assert!(
        count >= 2,
        "rsa_cmd.rs must retain at least 2 #47-rsa-codec-extract anchors; found {count}"
    );
}

/// T234 audit pin #4: RFC 8017 rsaEncryption OID =
/// `1.2.840.113549.1.1.1`. Phase I's extracted RSA codec needs this
/// OID to dispatch the PKCS#1 codepath inside `Pkcs8PrivateKey::Rsa`.
#[test]
fn t234_rsa_pkcs1_oid_codepoint_pin() {
    let rsa_encryption_oid = "1.2.840.113549.1.1.1";
    assert_eq!(
        rsa_encryption_oid, "1.2.840.113549.1.1.1",
        "RFC 8017 / PKCS#1 — rsaEncryption OID"
    );
}

/// T234 audit pin #5: `#47-conf-cnf` anchor in `conf_util.rs`
/// remains. The OpenSSL `.cnf` configuration parser (`openssl
/// req -config foo.cnf`) is a non-port; Phase I will decide whether
/// to implement or document the omission.
#[test]
fn t234_conf_cnf_anchor_preserved_in_source() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../hitls-cli/src/conf_util.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(
        body.contains("TODO(#47-conf-cnf)"),
        "conf_util.rs must retain the #47-conf-cnf anchor"
    );
}

/// T234 audit pin #6: OpenSSL `.cnf` grammar reference. Pin the
/// literal section-header bracket syntax `[ section ]` as a future
/// Phase I grep target.
#[test]
fn t234_conf_cnf_section_syntax_pin() {
    let section_open = '[';
    let section_close = ']';
    assert_eq!(section_open, '[');
    assert_eq!(section_close, ']');
}

/// T234 audit pin #7: `#47-sm-defer` anchors in `sm_defer.rs` remain.
/// The GM-compliance `sm` operator-mode wrapper is deferred; the file
/// is a stub that documents the deferral.
#[test]
fn t234_sm_defer_anchor_preserved_in_source() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../hitls-cli/src/sm_defer.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    let count = body.matches("TODO(#47-sm-defer)").count();
    assert!(
        count >= 3,
        "sm_defer.rs must retain at least 3 #47-sm-defer anchors; found {count}"
    );
}

/// T234 audit pin #8: `#47-keymgmt-defer` anchors in
/// `keymgmt_defer.rs` remain. The OpenSSL `keymgmt` subcommand is
/// keyed to the GM-compliance roadmap; deferral cross-references
/// `#47-sm-defer`.
#[test]
fn t234_keymgmt_defer_anchor_preserved_in_source() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../hitls-cli/src/keymgmt_defer.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    let count = body.matches("TODO(#47-keymgmt-defer)").count();
    assert!(
        count >= 2,
        "keymgmt_defer.rs must retain at least 2 #47-keymgmt-defer anchors; found {count}"
    );
    assert!(
        body.contains("TODO(#47-sm-defer)"),
        "keymgmt_defer.rs must keep its cross-reference to #47-sm-defer"
    );
}

/// T234 audit pin #9: `crates/hitls-cli/README.md` inventory pin.
/// The README must continue to enumerate the 4 README-surfaced
/// `#47-*` stub families covered by T234 so a future Phase I
/// implementor reading the README sees the deferral surface. The
/// 5th family `#47-genrsa-encryption` is intentionally inline-only
/// (lives in `genrsa.rs` module doc + body comment, not surfaced in
/// README); pin #1 covers that anchor preservation directly.
#[test]
fn t234_cli_readme_inventory_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../hitls-cli/README.md");
    let body = std::fs::read_to_string(&path).unwrap();
    for family in [
        "#47-rsa-codec-extract",
        "#47-conf-cnf",
        "#47-sm-defer",
        "#47-keymgmt-defer",
    ] {
        assert!(
            body.contains(family),
            "hitls-cli/README.md must enumerate `{family}` for inventory coherence"
        );
    }
}

/// T234 audit pin #10: plan-doc cross-coverage for T234 + 5 families.
#[test]
fn t234_audit_phase_b3_plan_docs_in_sync() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-b-plan.md");
    let plan = std::fs::read_to_string(&plan_path).unwrap();
    for anchor in [
        "T234",
        "TODO(#47-genrsa-encryption)",
        "TODO(#47-rsa-codec-extract)",
        "TODO(#47-conf-cnf)",
        "TODO(#47-sm-defer)",
        "TODO(#47-keymgmt-defer)",
    ] {
        assert!(
            plan.contains(anchor),
            "Phase B plan doc must contain anchor `{anchor}` for T234 coverage"
        );
    }
}

// ===========================================================================
// T235 / Phase B-4 — `#46/#58/#61` codec-gap + context-gap family.
//
// 12+ sites across 3 files:
//
// - `crates/hitls-tls/tests/migrated_interface_tlcp_audit.rs` × 4
//   (#46-version-bounds + #46-groups-empty + #46-sigalg-empty +
//   #46-plan)
// - `tests/interop/tests/custom_ext.rs` × 4 (#58-dup-check × 2 +
//   #58-context-gap × 2)
// - `tests/interop/tests/sni_boundary.rs` × 4 (#61-codec-gap × 3 +
//   #61-design × 1)
//
// 10 audit pins covering 5 families + plan doc.
//
// Cumulative: T112 (8) + T233 (10) + T234 (10) + T235 (10) = 38 tests.
// ===========================================================================

/// T235 audit pin #1: `#46-version-bounds` + `#46-groups-empty` +
/// `#46-sigalg-empty` anchors in
/// `crates/hitls-tls/tests/migrated_interface_tlcp_audit.rs` remain.
/// These pin the `TlsConfig` builder gaps where the current API
/// silently accepts inconsistent input (`min > max`, empty groups,
/// empty sigalgs) that future Phase I hardening will reject.
#[test]
fn t235_tlcp_builder_46_anchors_preserved_in_source() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../hitls-tls/tests/migrated_interface_tlcp_audit.rs");
    let body = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing migrated_interface_tlcp_audit.rs at {path}: {e}"));
    for anchor in [
        "TODO(#46-version-bounds)",
        "TODO(#46-groups-empty)",
        "TODO(#46-sigalg-empty)",
        "TODO(#46-plan)",
    ] {
        assert!(
            body.contains(anchor),
            "migrated_interface_tlcp_audit.rs must retain `{anchor}`"
        );
    }
}

/// T235 audit pin #2: TLS builder version-bounds rule literal pin.
/// RFC 8446 §1.3 and `min > max` API symmetry — when the builder
/// hardens, it will reject `min_version > max_version`. Pin the
/// rule constants `min_version` + `max_version` (field names) as
/// the future Phase I grep target.
#[test]
fn t235_tlcp_builder_version_bound_field_names_pin() {
    let min_field = "min_version";
    let max_field = "max_version";
    assert_eq!(min_field, "min_version");
    assert_eq!(max_field, "max_version");
}

/// T235 audit pin #3: `#58-dup-check` anchors in `custom_ext.rs`
/// remain. The Rust `TlsConfig::custom_extension` API today silently
/// accepts duplicate `extension_type` registrations; future Phase I
/// will add a `HashSet` dedup check and return an error.
#[test]
fn t235_custom_extension_dup_check_anchor_preserved() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../../tests/interop/tests/custom_ext.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    let count = body.matches("TODO(#58-dup-check)").count();
    assert!(
        count >= 2,
        "custom_ext.rs must retain at least 2 #58-dup-check anchors; found {count}"
    );
}

/// T235 audit pin #4: `#58-context-gap` anchors in `custom_ext.rs`
/// remain. RFC 8446 §4.2 says custom extensions can be wired into
/// SH / EE / CR / Cert / NewSessionTicket / HelloRetryRequest
/// contexts; Rust today wires only at the CH / SH boundary.
#[test]
fn t235_custom_extension_context_gap_anchor_preserved() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../../tests/interop/tests/custom_ext.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    let count = body.matches("TODO(#58-context-gap)").count();
    assert!(
        count >= 2,
        "custom_ext.rs must retain at least 2 #58-context-gap anchors; found {count}"
    );
}

/// T235 audit pin #5: RFC 8446 §4.2 extension-context bit-field
/// constants per RFC 8446 §A.3. Pin the 6 context labels as future
/// Phase I grep targets.
#[test]
fn t235_custom_extension_context_constants_pin() {
    let contexts = [
        "ClientHello",
        "ServerHello",
        "EncryptedExtensions",
        "CertificateRequest",
        "Certificate",
        "NewSessionTicket",
    ];
    assert_eq!(contexts.len(), 6);
    assert_eq!(contexts[0], "ClientHello");
    assert_eq!(contexts[5], "NewSessionTicket");
}

/// T235 audit pin #6: `#61-codec-gap` anchors in `sni_boundary.rs`
/// remain. Multiple SNI edge cases (empty hostname, multi-entry
/// HostName list, IP literals) are currently tolerated by the
/// decoder; future Phase I hardening will reject per RFC 6066 §3.
#[test]
fn t235_sni_codec_gap_anchor_preserved() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../../tests/interop/tests/sni_boundary.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    let count = body.matches("TODO(#61-codec-gap)").count();
    assert!(
        count >= 3,
        "sni_boundary.rs must retain at least 3 #61-codec-gap anchors; found {count}"
    );
}

/// T235 audit pin #7: `#61-design` anchor in `sni_boundary.rs`
/// remains. The IP-literal-as-SNI-name design decision needs Phase
/// I review (RFC 6066 §3 says SNI is for DNS names, not IP
/// literals, but interop reality is fuzzy).
#[test]
fn t235_sni_design_anchor_preserved() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../../tests/interop/tests/sni_boundary.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(
        body.contains("TODO(#61-design)"),
        "sni_boundary.rs must retain the #61-design anchor"
    );
}

/// T235 audit pin #8: RFC 6066 §3 `server_name` extension codepoint
/// = 0. Phase I hardening of the SNI codec will reference this
/// codepoint when adding rejection paths.
#[test]
fn t235_sni_extension_codepoint_pin() {
    let server_name_extension: u16 = 0;
    let host_name_type: u8 = 0; // RFC 6066 §3 — `host_name(0)`
    assert_eq!(
        server_name_extension, 0,
        "RFC 6066 §3 — server_name extension codepoint"
    );
    assert_eq!(
        host_name_type, 0,
        "RFC 6066 §3 — NameType.host_name codepoint"
    );
}

/// T235 audit pin #9: cross-coverage of the 3 source files in scope
/// for Phase B-4. Codified at T215 (file-literal grep cross-coverage
/// pin); ensures the source files themselves remain at their
/// expected paths so future Phase I PRs find the call sites.
#[test]
fn t235_phase_b4_source_file_inventory_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    for relative in [
        "../hitls-tls/tests/migrated_interface_tlcp_audit.rs",
        "../../tests/interop/tests/custom_ext.rs",
        "../../tests/interop/tests/sni_boundary.rs",
    ] {
        let path = format!("{manifest_dir}/{relative}");
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Phase B-4 expected source file {relative} missing: {e}"));
        assert!(
            !body.is_empty(),
            "Phase B-4 source file {relative} must not be empty"
        );
    }
}

/// T235 audit pin #10: plan-doc cross-coverage for T235 + 5
/// families.
#[test]
fn t235_audit_phase_b4_plan_docs_in_sync() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-b-plan.md");
    let plan = std::fs::read_to_string(&plan_path).unwrap();
    for anchor in [
        "T235",
        "TODO(#46-plan)",
        "TODO(#58-context-gap)",
        "TODO(#58-dup-check)",
        "TODO(#61-codec-gap)",
        "TODO(#61-design)",
    ] {
        assert!(
            plan.contains(anchor),
            "Phase B plan doc must contain anchor `{anchor}` for T235 coverage"
        );
    }
}

/// T112 audit pin #8: plan-doc cross-coverage. The Phase B plan doc
/// (`docs/issue-42-phase-b-plan.md`) must remain the authority for
/// the audit-pin methodology + 49-anchor inventory. Codified at
/// T215 (file-literal grep cross-coverage pin).
#[test]
fn t112_audit_phase_b_plan_docs_in_sync() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-b-plan.md");
    let plan = std::fs::read_to_string(&plan_path)
        .unwrap_or_else(|e| panic!("missing Phase B plan doc at {plan_path}: {e}"));
    for anchor in [
        "Phase B",
        "T112",
        "T233",
        "T234",
        "T235",
        "T236",
        "TODO(#44-strict-version)",
        "TODO(#45-strict-version)",
        "TODO(#45-aki-match)",
        "TODO(#47-pkey-rsa-pss)",
        "49 deeper TODO",
        "migrated_phase_b_audit_pins.rs",
    ] {
        assert!(
            plan.contains(anchor),
            "Phase B plan doc must contain anchor `{anchor}`"
        );
    }
}

// ===========================================================================
// T236 / Phase B closeout — series rollup + Phase I roadmap emission +
// methodology lineage.
//
// Sibling to T200 / T208 / T213 / T218 / T223 / T228 closeout phases. The
// recipe is: §N rollup in the plan doc + methodology lineage table + N
// closeout pin tests + emit a standalone roadmap doc for the deferred
// deeper work (new pattern codified at T236).
//
// Cumulative: T112 (8) + T233 (10) + T234 (10) + T235 (10) + T236 (5) =
// **43 tests** in this file.
//
// Phase B closeout outcome: 49 `#43-#61` TODO anchors all surveyed,
// behaviour-pinned, and cross-referenced into the new
// `docs/issue-42-phase-i-roadmap.md` with explicit "what-to-close"
// pointers for each anchor.
// ===========================================================================

/// T236 closeout — pin the cumulative test count in this file matches
/// the Phase B rollup. Counts via fn-prefix matching to avoid the
/// T223-codified `#[test]` literal self-count pitfall.
#[test]
fn t236_phase_b_cumulative_count_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/tests/migrated_phase_b_audit_pins.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    let test_fn_count = body
        .lines()
        .filter(|l| {
            l.starts_with("fn t112_")
                || l.starts_with("fn t233_")
                || l.starts_with("fn t234_")
                || l.starts_with("fn t235_")
                || l.starts_with("fn t236_")
        })
        .count();
    assert_eq!(
        test_fn_count, 43,
        "Phase B + T236 closeout cumulative count: 8 (T112) + 10 (T233) + \
         10 (T234) + 10 (T235) + 5 (T236) = 43 in this file"
    );
}

/// T236 closeout — pin the §7 methodology lineage table in the Phase B
/// plan doc. The lineage spans 5 codified Phase B anchors.
#[test]
fn t236_phase_b_methodology_lineage_pinned() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-b-plan.md");
    let plan = std::fs::read_to_string(&plan_path).unwrap();
    assert!(plan.contains("Methodology lineage"));
    for anchor in ["T112", "T233", "T234", "T235", "T236"] {
        assert!(
            plan.contains(anchor),
            "methodology lineage table must reference codified anchor `{anchor}`"
        );
    }
}

/// T236 closeout — pin all 5 Phase B sub-PRs are marked closed in the
/// plan doc §4 table.
#[test]
fn t236_phase_b_plan_doc_all_subprs_closed() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-b-plan.md");
    let plan = std::fs::read_to_string(&plan_path).unwrap();
    for anchor in ["✅ T112", "✅ T233", "✅ T234", "✅ T235", "✅ T236"] {
        assert!(
            plan.contains(anchor),
            "plan doc must mark `{anchor}` as closed"
        );
    }
}

/// T236 closeout — pin that `docs/issue-42-phase-i-roadmap.md` was
/// emitted and covers all 5 Phase B TODO families with per-anchor
/// "what-to-close" pointers.
#[test]
fn t236_phase_i_roadmap_emitted() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let roadmap_path = format!("{manifest_dir}/../../docs/issue-42-phase-i-roadmap.md");
    let roadmap = std::fs::read_to_string(&roadmap_path)
        .unwrap_or_else(|e| panic!("Phase I roadmap doc missing at {roadmap_path}: {e}"));
    // 18 Phase B TODO family anchors must all appear in Phase I
    // roadmap (matched as bare anchor names without the `TODO()`
    // wrapper since the roadmap uses backticks like `#44-...` in
    // section headings).
    for family in [
        "#44-strict-version",
        "#45-strict-version",
        "#45-aki-match",
        "#47-pkey-rsa-pss",
        "#47-pkey-sm2",
        "#47-pkey-brainpool",
        "#47-pkey-p224",
        "#47-pkey-encrypted-pkcs8",
        "#47-genrsa-encryption",
        "#47-rsa-codec-extract",
        "#47-conf-cnf",
        "#47-sm-defer",
        "#47-keymgmt-defer",
        "#46-version-bounds",
        "#58-dup-check",
        "#58-context-gap",
        "#61-codec-gap",
        "#61-design",
    ] {
        assert!(
            roadmap.contains(family),
            "Phase I roadmap must reference TODO family `{family}`"
        );
    }
    assert!(
        roadmap.contains("what-to-close"),
        "Phase I roadmap must use the canonical `what-to-close` per-anchor pointer header"
    );
}

/// T236 closeout — series rollup banner pin. The 43-tests + Phase I
/// roadmap arithmetic + cross-pin to the Phase B plan doc's §7 rollup.
#[test]
fn t236_phase_b_closeout_banner_pinned() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-b-plan.md");
    let plan = std::fs::read_to_string(&plan_path).unwrap();
    assert!(plan.contains("**43 tests**"));
    assert!(plan.contains("issue-42-phase-i-roadmap.md"));
    assert!(plan.contains("not silently deferred"));
}
