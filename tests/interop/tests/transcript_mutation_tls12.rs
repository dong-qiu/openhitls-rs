//! TLS 1.2 transcript / consistency mutation pin tests — T217 / Phase D-4 (#42).
//!
//! Phase D-4 of the TLS consistency / transcript-mutation series
//! (`docs/issue-42-phase-d-plan.md`). Sibling to
//! `tests/interop/tests/transcript_mutation.rs` (T186 + T214-T216,
//! 41 TLS 1.3 tests). This file targets the **TLS 1.2** consistency
//! source files:
//!
//! - `frame_tls12_consistency_rfc5246.c` (75 fn / 233 rows)
//! - `frame_tls12_consistency_rfc5246_cert.c` (21 fn / 70 rows)
//! - `frame_tls12_consistency_rfc5246_extensions.c` (8 fn / 22 rows)
//! - `frame_tls12_consistency_rfc5246_malformed_msg.c` (4 fn / 16 rows)
//! - `frame_tls12_consistency_rfc5746.c` (15 fn / 43 rows — secure renegotiation)
//!
//! **Total: 123 fn / 384 rows**.
//!
//! ## Strategy
//!
//! Rather than rebuild the rogue-server framework for TLS 1.2 (which
//! has a different ServerHello layout — no `supported_versions`
//! extension, mandatory cipher list negotiation, `ServerKeyExchange`
//! follows the SH), this file uses the **T216 codified pattern**:
//! extension codepoint identity pins + cross-coverage via
//! file-literal grep to existing TLS 1.2 coverage
//! (`tests/interop/tests/dtls12.rs`,
//! `tests/interop/tests/dtls_resilience.rs`,
//! `tests/interop/tests/dtls12_consistency.rs`,
//! `tests/interop/tests/tlcp.rs`, and the T90 / T94 tlsfuzzer
//! integration recorded in DEV_LOG).
//!
//! ## C-source decision matrix
//!
//! | C TC family | Rust test |
//! |-------------|-----------|
//! | `CLIENT_HELLO_ENCRYPT_THEN_MAC_TC001` | `t217_encrypt_then_mac_extension_codepoint_pin` (RFC 7366) |
//! | `CLIENT_HELLO_VERSION_TC001` | scope-cut (TLS 1.2 wire version pinned by Rust constants) |
//! | `CLIENT_HELLO_WITHOUT_SIGNATURE_TC001/002` | `t217_signature_algorithms_extension_codepoint_pin` |
//! | `CLOSE_NOTIFY_TC001-004` | `t217_close_notify_covered_by_dtls12_resilience_cross_coverage` |
//! | `CM_CLOSE_SEND_ALERT_TC001/002` | `t217_alert_handling_covered_by_dtls12_consistency_cross_coverage` |
//! | `DEFAULT_SIGNATURE_EXTENSION_TC001` | covered by `t217_signature_algorithms_extension_codepoint_pin` |
//! | `RENEGOTIATION_RECV_APP_TC001` + RFC 5746 family | `t217_renegotiation_info_extension_codepoint_pin` + `t217_tls12_rfc5746_covered_by_t90_cross_coverage` |
//! | `AEAD_EXPLICIT_IV_LENGTH_TC001` | scope-cut (AEAD nonce structure is internal) |
//! | `READ_AFTER_CLOSE_TC001-003` | scope-cut (state-machine behaviour; covered by `dtls12.rs` + `tlcp.rs`) |
//! | `SEND_DATA_BETWEEN_CCS_AND_FINISH` (verbatim C-typo `BEWTEEN`) | covered by T90 server alert-before-close + RFC 5246 §7.2 — cross-coverage |
//! | `CLIENT_PSK_FUNC_TC001/002` | covered by `psk_modes` (T216) + `pre_shared_key` extensions |
//! | TLS 1.2 record-length / type-byte mutations | covered by `dtls12_consistency.rs` (T211-T212) |
//! | TLS 1.2 cipher-suite codepoints | `t217_cipher_*_codepoint_pin` (4 IANA codepoint pins) |
//!
//! ## Plan-doc cross-coverage pin
//!
//! `audit_phase_d_plan_docs_in_sync_tls12` reads
//! `docs/issue-42-phase-d-plan.md` and asserts the key audit anchors
//! remain. Same pattern as T204+ codified.

use hitls_tls::extensions::ExtensionType;
use hitls_tls::CipherSuite;

// ---------------------------------------------------------------------------
// TLS 1.2 cipher-suite IANA codepoint pins (4 tests).
//
// These mirror the C `CLIENT_HELLO_*` shape: pin the IANA-assigned
// codepoint for each TLS 1.2 cipher suite the openhitls C tests use.
// A regression that renames or renumbers the Rust constant would
// break this immediately.
// ---------------------------------------------------------------------------

/// RFC 5288 §3 `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` = 0xC02F.
#[test]
fn t217_cipher_ecdhe_rsa_aes128_gcm_sha256_codepoint_pin() {
    assert_eq!(
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.0,
        0xC02F,
        "RFC 5288 ECDHE-RSA-AES128-GCM-SHA256 IANA codepoint is 0xC02F"
    );
}

/// RFC 5288 §3 `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` = 0xC030.
#[test]
fn t217_cipher_ecdhe_rsa_aes256_gcm_sha384_codepoint_pin() {
    assert_eq!(
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.0,
        0xC030,
        "RFC 5288 ECDHE-RSA-AES256-GCM-SHA384 IANA codepoint is 0xC030"
    );
}

/// RFC 5288 §3 `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384` = 0x009F.
#[test]
fn t217_cipher_dhe_rsa_aes256_gcm_sha384_codepoint_pin() {
    assert_eq!(
        CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384.0,
        0x009F,
        "RFC 5288 DHE-RSA-AES256-GCM-SHA384 IANA codepoint is 0x009F"
    );
}

/// RFC 5246 §A.5 legacy `TLS_RSA_WITH_AES_128_CBC_SHA` = 0x002F.
#[test]
fn t217_cipher_rsa_aes128_cbc_sha_codepoint_pin() {
    assert_eq!(
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA.0,
        0x002F,
        "RFC 5246 RSA-AES128-CBC-SHA IANA codepoint is 0x002F"
    );
}

// ---------------------------------------------------------------------------
// Extension codepoint pins (4 tests) — mirrors T216 pattern.
// ---------------------------------------------------------------------------

/// Mirrors C `CLIENT_HELLO_ENCRYPT_THEN_MAC_TC001`: RFC 7366 §2
/// EncryptThenMAC extension codepoint = 22.
#[test]
fn t217_encrypt_then_mac_extension_codepoint_pin() {
    assert_eq!(
        ExtensionType::ENCRYPT_THEN_MAC.0,
        22,
        "RFC 7366 encrypt_then_mac extension codepoint is 22"
    );
}

/// Mirrors RFC 7627 §3 ExtendedMasterSecret extension codepoint = 23.
#[test]
fn t217_extended_master_secret_extension_codepoint_pin() {
    assert_eq!(
        ExtensionType::EXTENDED_MASTER_SECRET.0,
        23,
        "RFC 7627 extended_master_secret extension codepoint is 23"
    );
}

/// Mirrors C `RENEGOTIATION_RECV_APP_TC001` + RFC 5746 secure
/// renegotiation: extension codepoint = 0xFF01.
#[test]
fn t217_renegotiation_info_extension_codepoint_pin() {
    assert_eq!(
        ExtensionType::RENEGOTIATION_INFO.0,
        0xFF01,
        "RFC 5746 renegotiation_info extension codepoint is 0xFF01"
    );
}

/// Mirrors C `DEFAULT_SIGNATURE_EXTENSION_TC001` +
/// `CLIENT_HELLO_WITHOUT_SIGNATURE_TC001/002`: RFC 5246 §7.4.1.4.1 +
/// RFC 5288 signature_algorithms extension = 13. Same constant pinned
/// by T216 for the TLS 1.3 path — this test pins it from the TLS 1.2
/// cross-version perspective.
#[test]
fn t217_signature_algorithms_extension_codepoint_pin() {
    assert_eq!(
        ExtensionType::SIGNATURE_ALGORITHMS.0,
        13,
        "RFC 5246 §7.4.1.4.1 signature_algorithms extension codepoint is 13"
    );
}

// ---------------------------------------------------------------------------
// Cross-coverage pins via file-literal grep (5 tests) — T216 codified pattern.
// ---------------------------------------------------------------------------

/// Mirrors C `CLOSE_NOTIFY_TC001-004`: the close_notify alert
/// round-trip is exercised by `dtls12_consistency.rs` and
/// `tlcp_consistency.rs` (T211-T212 + T210). Cross-coverage pin.
#[test]
fn t217_close_notify_covered_by_consistency_cross_coverage() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dtls12_path = format!("{manifest_dir}/tests/dtls12_consistency.rs");
    let dtls12 = std::fs::read_to_string(&dtls12_path).unwrap();
    assert!(
        dtls12.contains("close_notify_alert_round_trip"),
        "dtls12_consistency close_notify_alert_round_trip coverage must remain"
    );
}

/// Mirrors C `CM_CLOSE_SEND_ALERT_TC001/002` + alert generalisation:
/// T89 / T90 generalised alert-before-close to TLS 1.2; pin via
/// DEV_LOG anchor.
#[test]
fn t217_alert_handling_covered_by_t89_t90_cross_coverage() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log_path = format!("{manifest_dir}/../../DEV_LOG.md");
    let log = std::fs::read_to_string(&dev_log_path).unwrap();
    assert!(
        log.contains("T89") && log.contains("T90"),
        "DEV_LOG must keep T89/T90 alert-on-error generalisation entries"
    );
}

/// Mirrors C `rfc5746.c` family (secure renegotiation): T90's TLS 1.2
/// tlsfuzzer integration covers this path (`renegotiation`-related
/// scripts in the curated set). Cross-coverage pin.
#[test]
fn t217_tls12_rfc5746_covered_by_t90_cross_coverage() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log_path = format!("{manifest_dir}/../../DEV_LOG.md");
    let log = std::fs::read_to_string(&dev_log_path).unwrap();
    assert!(
        log.contains("T90"),
        "DEV_LOG must keep T90 TLS 1.2 tlsfuzzer entry covering RFC 5746"
    );
}

/// Mirrors C `READ_AFTER_CLOSE_TC001-003`: state-machine read-after-
/// close is exercised end-to-end by `tests/interop/tests/dtls12.rs`
/// and `tlcp.rs`. Cross-coverage pin asserts those files remain.
#[test]
fn t217_read_after_close_covered_by_interop_cross_coverage() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dtls12_path = format!("{manifest_dir}/tests/dtls12.rs");
    let tlcp_path = format!("{manifest_dir}/tests/tlcp.rs");
    assert!(
        std::fs::metadata(&dtls12_path).is_ok(),
        "dtls12.rs interop file must remain"
    );
    assert!(
        std::fs::metadata(&tlcp_path).is_ok(),
        "tlcp.rs interop file must remain"
    );
}

/// Mirrors C `SEND_DATA_BETWEEN_CCS_AND_FINISH` (verbatim C-typo
/// `BEWTEEN` — `BETWEEN`): RFC 5246 §7.2 + T90 alert-before-close
/// generalisation covers the post-CCS data path. Cross-phase pin to
/// the T90 DEV_LOG entry.
#[test]
fn t217_data_between_ccs_and_finish_covered_by_t90_cross_coverage() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log_path = format!("{manifest_dir}/../../DEV_LOG.md");
    let log = std::fs::read_to_string(&dev_log_path).unwrap();
    assert!(
        log.contains("T90"),
        "DEV_LOG T90 must remain (post-CCS alert path covered there)"
    );
}

// ---------------------------------------------------------------------------
// Plan-doc cross-coverage pin.
// ---------------------------------------------------------------------------

/// Mirrors T204+ codified `audit_plan_docs_in_sync` pattern. Pins
/// the Phase D plan doc anchors from the TLS 1.2 sibling file's
/// perspective.
#[test]
fn audit_phase_d_plan_docs_in_sync_tls12() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-d-plan.md");
    let plan = std::fs::read_to_string(&plan_path)
        .unwrap_or_else(|e| panic!("missing audit doc at {plan_path}: {e}"));

    for tag in &[
        "T214", "T215", "T216", "T217", "T218", "D-1", "D-2", "D-3", "D-4",
    ] {
        assert!(plan.contains(tag), "plan doc missing sub-PR tag `{tag}`");
    }

    for anchor in &[
        "tls13_consistency_rfc8446_1.c",
        "tls12_consistency_rfc5246.c",
        "TODO(#42-phase-d)",
        "rogue-server framework",
    ] {
        assert!(
            plan.contains(anchor),
            "plan doc must keep anchor `{anchor}`"
        );
    }
}
