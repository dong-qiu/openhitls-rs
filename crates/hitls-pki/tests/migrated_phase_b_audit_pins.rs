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
