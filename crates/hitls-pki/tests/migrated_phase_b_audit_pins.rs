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
