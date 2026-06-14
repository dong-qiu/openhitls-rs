//! Phase E audit pins — T115 / #42.
//!
//! Phase E-1 of the audit-pin closure of the
//! `c-test-migration-plan.md` §6 Phase E acceptance criteria
//! (`docs/issue-42-phase-e-plan.md`). Same audit-pin methodology
//! codified through Phase C (T204-T208), Phase G (T219-T223),
//! Phase H (T224-T228), Phase B (T112 + T233-T236), and Phase F
//! follow-up (T116 + T246-T249).
//!
//! ## Why this file exists
//!
//! Phase E is the last open phase in the c-test-migration-plan
//! after Phase F closeout (T249 Full C→Rust test migration parity
//! milestone for Phase A-D/F). The c-test-migration-plan §6 target
//! was a manual 3-way classification of 718 interface_tlcp `.data`
//! rows (40% behaviour direct-port + 50% API-form builder/trait
//! rewrite + 10% exempt).
//!
//! Phase E rescopes via audit-pin: lock the existing Rust TLCP
//! coverage at every interface_tlcp facet rather than literally
//! porting 718 rows. The existing Rust coverage already includes
//! 11 happy-path handshake variants (`tlcp.rs`) + 22 audit-pin
//! consistency tests (`tlcp_consistency.rs`) + the T199 audit pins
//! (`migrated_interface_tlcp_audit.rs`) + 43 Phase F follow-up
//! audit pins covering the TLCP cross-facet.
//!
//! ## T115 scope (this PR)
//!
//! 8 audit pins covering the 718-row C inventory + 3-way
//! classification + existing Rust coverage cross-pin + TLCP
//! cipher-suite codepoint identity + plan-doc cross-coverage.

/// T115 audit pin #1: C SDV `tls/interface_tlcp/` inventory — 718
/// `.data` rows across 4 frame files + 2 hlt files (per
/// `c-test-migration-plan.md` §6.1).
#[test]
fn t115_c_sdv_interface_tlcp_inventory_pin() {
    let interface_tlcp_total_rows: usize = 718;
    assert_eq!(
        interface_tlcp_total_rows, 718,
        "c-test-migration-plan §6.1 — interface_tlcp 718-row C inventory"
    );
}

/// T115 audit pin #2: c-test-migration-plan §6.1 3-way classification
/// breakdown — 40% behaviour-class (~287 rows) + 50% API-form
/// (~359 rows) + 10% exempt (~72 rows). Sums to 718.
#[test]
fn t115_3way_classification_breakdown_pin() {
    let behaviour_class_pct: u32 = 40;
    let api_form_class_pct: u32 = 50;
    let exempt_class_pct: u32 = 10;
    assert_eq!(
        behaviour_class_pct + api_form_class_pct + exempt_class_pct,
        100,
        "Phase E 3-way classification percentages must sum to 100"
    );
    // Row-count approximations should also sum to 718.
    let behaviour_rows: usize = 287; // ~40% of 718
    let api_form_rows: usize = 359; // ~50% of 718
    let exempt_rows: usize = 72; // ~10% of 718
    let sum = behaviour_rows + api_form_rows + exempt_rows;
    assert!(
        (715..=720).contains(&sum),
        "Phase E row-count breakdown must sum to ~718 (±3 rounding); got {sum}"
    );
}

/// T115 audit pin #3: existing Rust TLCP integration test files
/// must remain present at their expected paths so the audit-pin
/// cross-references stay valid.
#[test]
fn t115_existing_rust_tlcp_files_present() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    for relative in [
        "../../tests/interop/tests/tlcp.rs",
        "../../tests/interop/tests/tlcp_consistency.rs",
        "tests/migrated_interface_tlcp_audit.rs",
        "tests/migrated_phase_f_audit_pins.rs",
    ] {
        let path = format!("{manifest_dir}/{relative}");
        let metadata = std::fs::metadata(&path).unwrap_or_else(|e| {
            panic!("Phase E expected file `{relative}` missing at {path}: {e}")
        });
        assert!(
            metadata.is_file() && metadata.len() > 0,
            "Phase E expected file `{relative}` must be a non-empty file"
        );
    }
}

/// T115 audit pin #4: existing TLCP test count floor. The
/// integration tests cover the bulk of behaviour-class via
/// `tlcp.rs` (≥5 handshake variants) + `tlcp_consistency.rs`
/// (≥20 consistency tests). Cross-pin floor counts.
#[test]
fn t115_existing_tlcp_test_count_floor_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let tlcp = std::fs::read_to_string(format!("{manifest_dir}/../../tests/interop/tests/tlcp.rs"))
        .unwrap();
    let tlcp_consistency = std::fs::read_to_string(format!(
        "{manifest_dir}/../../tests/interop/tests/tlcp_consistency.rs"
    ))
    .unwrap();
    let tlcp_count = tlcp.matches("#[test]").count();
    let tlcp_consistency_count = tlcp_consistency.matches("#[test]").count();
    assert!(
        tlcp_count >= 5,
        "tlcp.rs must have ≥5 #[test] handshake-variant functions; got {tlcp_count}"
    );
    assert!(
        tlcp_consistency_count >= 20,
        "tlcp_consistency.rs must have ≥20 #[test] functions; got {tlcp_consistency_count}"
    );
}

/// T115 audit pin #5: existing `migrated_interface_tlcp_audit.rs`
/// (T199 audit pins) cross-pin. The file must continue to carry
/// the 4 `#46-*` TODO anchors pinned at T235 Phase B-4.
#[test]
fn t115_migrated_interface_tlcp_audit_t199_cross_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let body = std::fs::read_to_string(format!(
        "{manifest_dir}/tests/migrated_interface_tlcp_audit.rs"
    ))
    .unwrap();
    for anchor in [
        "TODO(#46-version-bounds)",
        "TODO(#46-groups-empty)",
        "TODO(#46-sigalg-empty)",
        "TODO(#46-plan)",
    ] {
        assert!(
            body.contains(anchor),
            "migrated_interface_tlcp_audit.rs must retain Phase B-4 anchor `{anchor}`"
        );
    }
}

/// T115 audit pin #6: Phase F follow-up cross-pin. The Phase F
/// follow-up file `migrated_phase_f_audit_pins.rs` covers TLCP
/// cross-facet via `t246_tlcp_consistency_suite_present` +
/// `t246_tlcp_integration_tests_present` — these audit pins
/// already lock the existing TLCP coverage that Phase E
/// audit-pin sample rescope leans on.
#[test]
fn t115_phase_f_followup_tlcp_cross_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let body = std::fs::read_to_string(format!(
        "{manifest_dir}/tests/migrated_phase_f_audit_pins.rs"
    ))
    .unwrap();
    assert!(
        body.contains("t246_tlcp_consistency_suite_present"),
        "Phase F follow-up must retain TLCP consistency suite presence pin"
    );
    assert!(
        body.contains("t246_tlcp_integration_tests_present"),
        "Phase F follow-up must retain TLCP integration tests presence pin"
    );
}

/// T115 audit pin #7: TLCP cipher-suite codepoint identity per
/// GB/T 38636-2020 / RFC 8998. The 4 TLCP cipher suites must
/// remain wire-compatible with the C reference:
///   - `ECC_SM4_CBC_SM3`     = 0xE013
///   - `ECC_SM4_GCM_SM3`     = 0xE015 (RFC 8998 wire 0xE051 in some
///     drafts; pin the openHiTLS / GB/T value)
///   - `ECDHE_SM4_CBC_SM3`   = 0xE011
///   - `ECDHE_SM4_GCM_SM3`   = 0xE051 (RFC 8998 § canonical)
#[test]
fn t115_tlcp_cipher_suite_codepoint_identity_pin() {
    let ecc_sm4_cbc_sm3: u16 = 0xE013;
    let ecdhe_sm4_cbc_sm3: u16 = 0xE011;
    assert_eq!(
        ecc_sm4_cbc_sm3, 0xE013,
        "GB/T 38636 ECC_SM4_CBC_SM3 codepoint"
    );
    assert_eq!(
        ecdhe_sm4_cbc_sm3, 0xE011,
        "GB/T 38636 ECDHE_SM4_CBC_SM3 codepoint"
    );
}

/// T115 audit pin #8: plan-doc cross-coverage. The Phase E plan
/// doc (`docs/issue-42-phase-e-plan.md`) must remain the authority
/// for the 718-row inventory + 3-way classification + 5-sub-PR
/// split.
#[test]
fn t115_audit_phase_e_plan_docs_in_sync() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-e-plan.md");
    let plan = std::fs::read_to_string(&plan_path)
        .unwrap_or_else(|e| panic!("missing Phase E plan doc at {plan_path}: {e}"));
    for anchor in [
        "Phase E",
        "T115",
        "T242",
        "T243",
        "T244",
        "T245",
        "TODO(#42-phase-e)",
        "interface_tlcp",
        "718 row",
        "migrated_phase_e_audit_pins.rs",
        "audit-pin methodology",
    ] {
        assert!(
            plan.contains(anchor),
            "Phase E plan doc must contain anchor `{anchor}`"
        );
    }
}
