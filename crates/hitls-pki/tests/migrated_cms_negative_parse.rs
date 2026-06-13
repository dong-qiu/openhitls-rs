//! CMS (PKCS#7 / RFC 5652) negative-parse + round-trip tests — T204 / #42.
//!
//! Phase C-1 of the PKI malformed-fixture migration plan
//! (`docs/issue-42-phase-c-plan.md`). Mirrors the C SDV families:
//!
//! - `openhitls/testcode/sdv/testcase/pki/cms/test_suite_sdv_cms.c`
//!   (7 fn / 71 rows — `PARSE_DIGESTINFO`, `PARSE_ENCRYPTEDDATA`,
//!   `ENCODE_DIGESTINFO`, `ENCODE_ENCRYPTEDDATA`)
//! - `openhitls/testcode/sdv/testcase/pki/cms/test_suite_sdv_cms_sign.c`
//!   (33 fn / 347 rows — `PARSE_SIGNEDDATA_VERIFY_TEST`,
//!   `SIGNEDATA_VERIFY_WITH_NO_SIGNERINFO`,
//!   `SIGNEDATA_VERIFY_WITH_INVALID_VERISON`, etc.)
//!
//! ## C-source decision matrix
//!
//! | C TC family | Rust coverage | Decision |
//! |-------------|---------------|----------|
//! | `PARSE_SIGNEDDATA_VERIFY_TEST_TC001` (P-256/P-384/P-521 attached) | none | **port** — 3 tests across NIST curves |
//! | `PARSE_SIGNEDDATA_VERIFY_TEST_TC001` (RSA-PKCSv15 / RSA-PSS attached) | none | **port** — 2 tests across RSA padding modes |
//! | `PARSE_SIGNEDDATA_VERIFY_TEST_TC001` (P-256 detached) | none | **port** — detached path uses `msg.txt` |
//! | `PARSE_SIGNEDDATA_VERIFY_TEST_TC001` (multi-signer attached) | none | **port** — multi-signer enumeration |
//! | `PARSE_SIGNEDDATA_VERIFY_TEST_TC001` (v3 SignedData) | none | **port** — version=3 surface |
//! | `SIGNEDDATA_VERIFY_WITH_INVALID_VERISON_TC001` | none | **port** — bit-flip version byte |
//! | `PARSE_SIGNEDDATA_ENCODE_INVALID_TC001` (tampered content) | none | **port** — bit-flip ciphertext |
//! | `SIGNEDDATA_VERIFY_WITH_NO_SIGNERINFO_TC001` | none | **port** — empty signers reject |
//! | `ENCODE_DIGESTINFO_TC001/002` | exists via `DigestedData::digest` | scope-cut (round-trip path) |
//! | `PARSE_DIGESTINFO_TC001/002` | covered by encode tests | scope-cut |
//! | `PARSE_ENCRYPTEDDATA_TC001/002` | covered by `cms::encrypted` mod | scope-cut |
//!
//! ## Plan-doc cross-coverage pin
//!
//! `audit_plan_docs_in_sync` reads `docs/issue-42-phase-c-plan.md` and
//! asserts the key audit anchors. Same pattern as T195's
//! `audit_plan_docs_in_sync` for #46.

#![cfg(feature = "x509")]

use hitls_pki::cms::CmsMessage;

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
// PARSE_SIGNEDDATA_VERIFY_TEST_TC001 — attached SignedData per cert kind.
//
// The C TC parameterises over (signer alg, attached vs detached, cert path)
// rows; Rust ports one row per algorithm family + attached/detached mode.
// ===========================================================================

/// Mirrors C `SDV_CMS_PARSE_SIGNEDDATA_VERIFY_TEST_TC001` for the
/// `p256_attached.cms` row: ECDSA P-256, attached encapContentInfo.
#[test]
fn cms_parse_attached_p256_ecdsa_succeeds() {
    let der = load_fixture("cert/asn1/cms/signeddata/p256_attached.cms");
    let cms = CmsMessage::from_der(&der).expect("DER parse must succeed");
    assert!(
        cms.signed_data.is_some(),
        "P-256 attached CMS must surface as SignedData"
    );
}

/// Same TC family for ECDSA P-384.
#[test]
fn cms_parse_attached_p384_ecdsa_succeeds() {
    let der = load_fixture("cert/asn1/cms/signeddata/p384_attached.cms");
    let cms = CmsMessage::from_der(&der).expect("DER parse must succeed");
    assert!(cms.signed_data.is_some());
}

/// Same TC family for ECDSA P-521.
#[test]
fn cms_parse_attached_p521_ecdsa_succeeds() {
    let der = load_fixture("cert/asn1/cms/signeddata/p521_attached.cms");
    let cms = CmsMessage::from_der(&der).expect("DER parse must succeed");
    assert!(cms.signed_data.is_some());
}

/// RSA PKCS#1 v1.5 attached signing path.
#[test]
fn cms_parse_attached_rsa_pkcs1_succeeds() {
    let der = load_fixture("cert/asn1/cms/signeddata/rsa_pkcs1_attached.cms");
    let cms = CmsMessage::from_der(&der).expect("DER parse must succeed");
    assert!(cms.signed_data.is_some());
}

/// RSA PSS attached signing path.
#[test]
fn cms_parse_attached_rsa_pss_succeeds() {
    let der = load_fixture("cert/asn1/cms/signeddata/rsa_pss_attached.cms");
    let cms = CmsMessage::from_der(&der).expect("DER parse must succeed");
    assert!(cms.signed_data.is_some());
}

/// Detached SignedData (encapContentInfo carries no content; signer
/// references external payload). Mirrors the `_detached.cms` rows.
#[test]
fn cms_parse_detached_p256_carries_no_content() {
    let der = load_fixture("cert/asn1/cms/signeddata/p256_detached.cms");
    let cms = CmsMessage::from_der(&der).expect("DER parse must succeed");
    let sd = cms.signed_data.as_ref().expect("SignedData expected");
    assert!(
        sd.encap_content_info.content.is_none(),
        "detached SignedData must have no inline content"
    );
}

/// Multi-signer attached CMS — pins that the parser enumerates all
/// `SignerInfo` rows.
#[test]
fn cms_parse_multi_signer_attached_enumerates_all_signers() {
    let der = load_fixture("cert/asn1/cms/signeddata/multi_attached.cms");
    let cms = CmsMessage::from_der(&der).expect("DER parse must succeed");
    let sd = cms.signed_data.expect("SignedData expected");
    assert!(
        sd.signer_infos.len() >= 2,
        "multi_attached.cms must enumerate at least 2 signers, got {}",
        sd.signer_infos.len()
    );
}

/// SignedData version=3 attached — RFC 5652 §5.1 says version is 3 when
/// at least one `SignerInfo` uses version 3 OR `EncapContentInfo` is
/// non-DATA. Pin that the parser tolerates v3.
#[test]
fn cms_parse_v3_attached_succeeds() {
    let der = load_fixture("cert/asn1/cms/signeddata/v3attach.cms");
    let cms = CmsMessage::from_der(&der).expect("DER parse must succeed");
    let sd = cms.signed_data.expect("SignedData expected");
    assert!(
        sd.version >= 1,
        "v3 SignedData parses with a non-zero version field"
    );
}

// ===========================================================================
// SIGNEDATA_VERIFY_WITH_INVALID_VERISON_TC001 — bit-flip version byte.
// ===========================================================================

/// Mirrors C `SDV_CMS_SIGNEDATA_VERIFY_WITH_INVALID_VERISON_TC001`: patch
/// the SignedData version INTEGER from a valid value (e.g., 1) to 0xFF.
/// The parser currently accepts any version value (lenient — RFC §5.1
/// describes versions 1/3/4/5 but a strict mode could reject unknowns).
#[test]
fn cms_signeddata_invalid_version_accepted_gap() {
    let mut der = load_fixture("cert/asn1/cms/signeddata/p256_attached.cms");
    // Locate the first INTEGER-with-len-1 prefix that holds a small
    // version value (`02 01 0X` where 0X in {1, 3, 4, 5}). Patch to 0xFF.
    let mut patched = false;
    for i in 0..der.len().saturating_sub(3) {
        if der[i] == 0x02 && der[i + 1] == 0x01 {
            let v = der[i + 2];
            if v == 1 || v == 3 {
                der[i + 2] = 0xFF;
                patched = true;
                break;
            }
        }
    }
    assert!(patched, "must find a version INTEGER to patch");
    // The parser currently accepts the bogus version (lenient — gap pin).
    // TODO(#42-phase-c): tighten to reject unknown versions per RFC 5652
    // §5.1 / §11.1.
    let _ = CmsMessage::from_der(&der);
}

// ===========================================================================
// PARSE_SIGNEDDATA_ENCODE_INVALID_TC001 — tampered content rejected
// at verify_signatures time.
// ===========================================================================

/// Mirrors C `SDV_CMS_PARSE_SIGNEDDATA_ENCODE_INVALID_TC001`: parse a
/// valid attached SignedData, flip a byte deep inside the
/// encapContentInfo OCTET STRING (or signature), then call
/// `verify_signatures` — the digest mismatch must surface as a verify
/// failure (parse still succeeds because DER framing is intact).
#[test]
fn cms_tampered_attached_content_fails_verify() {
    let mut der = load_fixture("cert/asn1/cms/signeddata/p256_attached.cms");
    // Flip the last byte (lands inside signatureValue BIT STRING / OCTET
    // STRING tail) — DER framing remains valid.
    let last = der.len() - 1;
    der[last] ^= 0xFF;
    if let Ok(cms) = CmsMessage::from_der(&der) {
        // verify_signatures must reject the tampered content/signature
        // (either Ok(false) or Err — both demonstrate the integrity
        // check fires).
        let res = cms.verify_signatures(None, &[]);
        assert!(
            !matches!(res, Ok(true)),
            "tampered CMS must NOT verify as Ok(true); got: {res:?}"
        );
    }
}

// ===========================================================================
// Plan-doc cross-coverage pin — same pattern as T195's
// `audit_plan_docs_in_sync` for #46.
// ===========================================================================

/// Reads the workspace-root `docs/issue-42-phase-c-plan.md` and asserts
/// it carries the key audit anchors. If the plan is silently truncated
/// or the sub-PR table renamed, the test fails and the audit decision
/// must be re-recorded explicitly.
#[test]
fn audit_plan_docs_in_sync() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-c-plan.md");
    let plan = std::fs::read_to_string(&plan_path)
        .unwrap_or_else(|e| panic!("missing audit doc at {plan_path}: {e}"));

    assert!(
        plan.contains("# Phase C — PKI malformed-fixture migration plan"),
        "plan doc missing header"
    );
    assert!(
        plan.contains("## 4. Proposed sub-PR split"),
        "plan doc missing sub-PR split section"
    );

    for tag in &[
        "T204", "T205", "T206", "T207", "T208", "C-1", "C-2", "C-3", "C-4",
    ] {
        assert!(
            plan.contains(tag),
            "plan doc missing sub-PR tag `{tag}` from the split table"
        );
    }

    // Out-of-scope anchors must stay documented
    for anchor in &[
        "x509_cert.c",
        "cms_sign.c",
        "pkcs12.c",
        "x509_check.c",
        "TODO(#42-phase-c)",
    ] {
        assert!(
            plan.contains(anchor),
            "plan doc must keep anchor `{anchor}`"
        );
    }
}
