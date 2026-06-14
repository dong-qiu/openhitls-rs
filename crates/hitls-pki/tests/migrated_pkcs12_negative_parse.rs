//! PKCS#12 (RFC 7292) negative-parse + round-trip tests — T205 / #42.
//!
//! Phase C-2 of the PKI malformed-fixture migration plan
//! (`docs/issue-42-phase-c-plan.md`). Mirrors the C SDV families:
//!
//! - `openhitls/testcode/sdv/testcase/pki/pkcs12/test_suite_sdv_pkcs12.c`
//!   (37 fn / 198 rows — `PARSE_P12_TC001..003`,
//!   `PARSE_P12_WRONG_CONDITIONS`, `PARSE_AUTHSAFE`,
//!   `PARSE_SAFEBAGS_OF_CERTBAGS` / `_PKCS8SHROUDEDKEYBAG`,
//!   `PARSE_MACDATA`, etc.)
//! - `openhitls/testcode/sdv/testcase/pki/pkcs12/test_suite_sdv_pkcs12_util.c`
//!   (15 fn / 44 rows — bag-helper + utility round-trips)
//!
//! C SDV's `PARSE_P12_TC003` rows (in `test_suite_sdv_pkcs12.data`) bind
//! each `.p12` fixture to its specific password:
//!
//! - `p12_1.p12` → `""` (empty)
//! - `p12_2.p12` → 74 × `'1'`
//! - `p12_3.p12` → 149 × `'1'`
//! - `p12_4.p12` → `"1"`
//! - `p12_5.p12` → `"@##\\#%#\\%\\%.&&~%*\\|sdfgfdsg"` (intentionally awkward)
//!
//! The C SDV inline-hex rows (`PARSE_P12_TC001`) re-use a fixed
//! `"123456"` password against hex-blob containers different from the
//! checked-in `.p12` files; we rely on the file fixtures here, so the
//! per-fixture passwords above are authoritative.
//!
//! ## C-source decision matrix
//!
//! | C TC family | Rust coverage | Decision |
//! |-------------|---------------|----------|
//! | `PARSE_P12_TC003` (p12_1 .. p12_5, per-fixture passwords) | none | **port** — 5 round-trips |
//! | `PARSE_P12_WRONG_CONDITIONS_TC001` (wrong password) | none | **port** — wrong pwd → `PkiError` |
//! | `PARSE_P12_WRONG_P12FILE_TC001` (garbage / truncated) | none | **port** — 2 tests (truncated, garbage) |
//! | `PARSE_AUTHSAFE_INVALID_TC001` (tampered AuthSafe) | none | **port** — byte-flip in AuthSafe block |
//! | `PARSE_SAFEBAGS_OF_CERTBAGS_TC001` | none | **port** — `certificates.len() > 0` pin |
//! | `PARSE_SAFEBAGS_OF_PKCS8SHROUDEDKEYBAG_TC001` | none | **port** — `private_key.is_some()` pin |
//! | `BAG_CTRL_TC001/002`, `BAG_TEST_TC001/002/003` | covered via parse round-trips above | scope-cut |
//! | `ENCODE_P12_TC001..004` | covered by `Pkcs12::create` round-trips elsewhere | scope-cut |
//!
//! ## Plan-doc cross-coverage pin
//!
//! `audit_plan_docs_in_sync` reads `docs/issue-42-phase-c-plan.md` and
//! asserts the key audit anchors stay locked, same pattern as T204.

#![cfg(feature = "pkcs12")]

use hitls_pki::pkcs12::Pkcs12;

/// Load a fixture file from `tests/vectors/c-asn1-fixtures/`.
fn load_fixture(rel: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../tests/vectors/c-asn1-fixtures/{}",
        env!("CARGO_MANIFEST_DIR"),
        rel
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("missing fixture {path}: {e}"))
}

// ===========================================================================
// PARSE_P12_TC003 (file-fixture happy path) — per-fixture password binding.
//
// Each `.p12` was generated with a distinct password (the C `.data` rows
// are authoritative; see mod-doc table). Pin that the parser recovers a
// private key + at least one cert.
// ===========================================================================

#[test]
fn pkcs12_parse_p12_1_empty_password_succeeds() {
    let der = load_fixture("cert/asn1/pkcs12/p12_1.p12");
    let p12 = Pkcs12::from_der(&der, "").expect("p12_1 must parse with empty password");
    assert!(p12.private_key.is_some(), "p12_1 must carry a private key");
    assert!(
        !p12.certificates.is_empty(),
        "p12_1 must carry at least one certificate"
    );
}

#[test]
fn pkcs12_parse_p12_2_long_repeat_password_succeeds() {
    let der = load_fixture("cert/asn1/pkcs12/p12_2.p12");
    let pwd = "1".repeat(74);
    let p12 = Pkcs12::from_der(&der, &pwd).expect("p12_2 must parse with 74×'1'");
    assert!(p12.private_key.is_some());
    assert!(!p12.certificates.is_empty());
}

#[test]
fn pkcs12_parse_p12_3_very_long_repeat_password_succeeds() {
    let der = load_fixture("cert/asn1/pkcs12/p12_3.p12");
    let pwd = "1".repeat(149);
    let p12 = Pkcs12::from_der(&der, &pwd).expect("p12_3 must parse with 149×'1'");
    assert!(p12.private_key.is_some());
    assert!(!p12.certificates.is_empty());
}

#[test]
fn pkcs12_parse_p12_4_single_char_password_succeeds() {
    let der = load_fixture("cert/asn1/pkcs12/p12_4.p12");
    let p12 = Pkcs12::from_der(&der, "1").expect("p12_4 must parse with '1'");
    assert!(p12.private_key.is_some());
    assert!(!p12.certificates.is_empty());
}

#[test]
fn pkcs12_parse_p12_5_awkward_unicode_password_succeeds() {
    let der = load_fixture("cert/asn1/pkcs12/p12_5.p12");
    // Verbatim from the C `.data` row: `@##\#%#\%\%.&&~%*\|sdfgfdsg`
    let p12 = Pkcs12::from_der(&der, r"@##\#%#\%\%.&&~%*\|sdfgfdsg")
        .expect("p12_5 must parse with its awkward symbol-heavy password");
    assert!(p12.private_key.is_some());
    assert!(!p12.certificates.is_empty());
}

// ===========================================================================
// PARSE_P12_WRONG_CONDITIONS_TC001 — wrong password.
// ===========================================================================

/// Mirrors C `SDV_PKCS12_PARSE_P12_WRONG_CONDITIONS_TC001`: wrong
/// password must fail MAC verification.
#[test]
fn pkcs12_parse_p12_wrong_password_rejected() {
    // p12_4 uses the password "1" — feed a different string.
    let der = load_fixture("cert/asn1/pkcs12/p12_4.p12");
    let err = Pkcs12::from_der(&der, "not-the-right-password")
        .expect_err("wrong password must trigger MAC failure");
    let msg = format!("{err:?}");
    assert!(
        msg.to_ascii_lowercase().contains("mac")
            || msg.to_ascii_lowercase().contains("password")
            || msg.to_ascii_lowercase().contains("invalid")
            || msg.to_ascii_lowercase().contains("verify"),
        "wrong-password error should mention MAC / password / invalid; got: {msg}"
    );
}

// ===========================================================================
// PARSE_P12_WRONG_P12FILE_TC001 — malformed input.
// ===========================================================================

/// Truncated DER (first 32 bytes only) must fail to parse.
#[test]
fn pkcs12_parse_truncated_der_rejected() {
    let der = load_fixture("cert/asn1/pkcs12/p12_1.p12");
    let truncated = &der[..32];
    Pkcs12::from_der(truncated, "").expect_err("truncated PKCS#12 DER must be rejected");
}

/// Garbage bytes (non-DER) must fail to parse.
#[test]
fn pkcs12_parse_garbage_bytes_rejected() {
    let garbage = b"this is not a pkcs#12 container at all";
    Pkcs12::from_der(garbage, "").expect_err("garbage bytes must be rejected as malformed DER");
}

// ===========================================================================
// PARSE_AUTHSAFE_INVALID_TC001 — tampered AuthSafe block.
// ===========================================================================

/// Mirrors C `SDV_PKCS12_PARSE_AUTHSAFE_INVALID_TC001`: flip a byte
/// deep inside the AuthSafe ciphertext. The Rust parser must reject
/// — either at MAC verification time or at inner ContentInfo decryption.
#[test]
fn pkcs12_parse_tampered_authsafe_rejected() {
    let mut der = load_fixture("cert/asn1/pkcs12/p12_1.p12");
    // Flip a byte ~1/3 into the file — deep enough to land inside
    // AuthSafe encrypted content for any reasonable PKCS#12 layout.
    let target = der.len() / 3;
    der[target] ^= 0xFF;
    Pkcs12::from_der(&der, "")
        .expect_err("tampered AuthSafe block must be rejected by MAC or content decryption");
}

// ===========================================================================
// Plan-doc cross-coverage pin.
// ===========================================================================

/// Reads `docs/issue-42-phase-c-plan.md` and asserts the key audit
/// anchors stay locked. Same pattern as T204's `audit_plan_docs_in_sync`.
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

    for anchor in &[
        "pkcs12.c",
        "pkcs12_util.c",
        "PKCS#12",
        "TODO(#42-phase-c)",
        "## 8. Series rollup",
        "**46 tests**",
        "**5/5 sub-PRs closed**",
    ] {
        assert!(
            plan.contains(anchor),
            "plan doc must keep anchor `{anchor}`"
        );
    }
}
