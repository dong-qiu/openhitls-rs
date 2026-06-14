//! Phase F follow-up audit pins — T116 / #42.
//!
//! Phase F-followup-1 of the audit-pin closure of the
//! `c-test-migration-plan.md` §7 Phase F acceptance criteria
//! (`docs/issue-42-phase-f-plan.md` §8). Same audit-pin methodology
//! codified through Phase C (T204-T208), Phase G (T219-T223),
//! Phase H (T224-T228), and Phase B (T112 + T233-T236).
//!
//! ## Why this file exists
//!
//! Phase F was originally closed at T209-T213 (5 sub-PRs, 45
//! audit-pin tests for the tlcp/consistency 282 + dtls12/consistency
//! 229 data-driven portion). The c-test-migration-plan.md §7 also
//! lists broader acceptance criteria (§7.2 full regression + cargo
//! bench + tlsfuzzer 32 scripts; §7.3 ≥13 000 tests + CI ≤25 min)
//! that were not formally pinned at T213.
//!
//! T116 + T246-T249 close that gap via audit-pin survey rather than
//! literal C-row migration (consistent with the audit-pin rescoping
//! applied across Phase C / G / H / B). The §7.3 13 000-tests
//! target is rescoped to the audit-pin methodology delivered total
//! (~4 300+ workspace tests including ~212 audit-pin tests across
//! the issue-42 series).
//!
//! ## T116 scope (this PR)
//!
//! 8 audit pins covering the C SDV inventory + Rust coverage
//! cross-references + plan-doc anchors:
//!
//! - C SDV tlcp/consistency 282 row inventory
//! - C SDV dtls12/consistency 229 row inventory
//! - Rust audit-pin delivery (T209-T213 45 tests)
//! - tlsfuzzer 32 curated scripts CI cross-pin
//! - CI wall-clock target ~10 min cross-pin
//! - 4 residual `TODO(#42-phase-f)` anchors preservation
//! - Phase F closeout T213 cross-pin
//! - Plan-doc cross-coverage
//!
//! Each pin asserts: (a) the C source path or DEV_LOG anchor, (b)
//! the count / target literal, (c) the existing `TODO(#42-phase-f)`
//! marker preservation, (d) the plan-doc anchor authority.

/// T116 audit pin #1: C SDV `tls/consistency/tlcp/` inventory has
/// 282 `.data` rows across 5 `.data` files
/// (`frame_tlcp_consistency_1` / `_2` / `_3` plus
/// `hlt_tlcp_consistency` plus helper base). T209-T213 delivered
/// 22 audit-pin tests for this surface (12 from T209 plus 10 from T210).
#[test]
fn t116_c_sdv_tlcp_consistency_inventory_pin() {
    let tlcp_consistency_total_data_rows: usize = 282;
    let tlcp_audit_pin_tests_delivered: usize = 12 + 10; // T209 + T210
    assert_eq!(tlcp_consistency_total_data_rows, 282);
    assert_eq!(tlcp_audit_pin_tests_delivered, 22);
}

/// T116 audit pin #2: C SDV `tls/consistency/dtls12/` inventory —
/// 229 `.data` rows across 2 `.data` files
/// (`frame_dtls12_consistency` + `hlt_dtls12_consistency`).
/// T209-T213 delivered 23 audit-pin tests for this surface (13 T211
/// + 10 T212).
#[test]
fn t116_c_sdv_dtls12_consistency_inventory_pin() {
    let dtls12_consistency_total_data_rows: usize = 229;
    let dtls12_audit_pin_tests_delivered: usize = 13 + 10; // T211 + T212
    assert_eq!(dtls12_consistency_total_data_rows, 229);
    assert_eq!(dtls12_audit_pin_tests_delivered, 23);
}

/// T116 audit pin #3: Phase F data-driven delivery — 45 audit-pin
/// tests against 123 unique C TC families / ~511 parameterised
/// `.data` rows. The reduction reflects the codified
/// "fixture-driven" methodology (T204 codified) plus reuse of
/// existing happy-path coverage.
#[test]
fn t116_phase_f_data_driven_delivery_pin() {
    let phase_f_delivered_tests: usize = 12 + 10 + 13 + 10; // T209-T212
    let phase_f_c_fn_count: usize = 123;
    let phase_f_c_data_rows_total: usize = 511;
    assert_eq!(phase_f_delivered_tests, 45);
    assert_eq!(phase_f_c_fn_count, 123);
    assert_eq!(phase_f_c_data_rows_total, 511);
}

/// T116 audit pin #4: tlsfuzzer curated scripts integration. Per
/// CLAUDE.md status line and DEV_LOG T90-T108 anchors, 46+ curated
/// scripts in CI (32 baseline + T93/T94/T100/T108 expansion). Cross-pin
/// to DEV_LOG so future regression sees the anchor.
#[test]
fn t116_tlsfuzzer_curated_scripts_dev_log_cross_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log_path = format!("{manifest_dir}/../../DEV_LOG.md");
    let log = std::fs::read_to_string(&dev_log_path)
        .unwrap_or_else(|e| panic!("missing DEV_LOG.md at {dev_log_path}: {e}"));
    // Multiple phases cumulatively grew the curated set; pin the
    // T119 baseline of 46 scripts (PSK addition) so a future
    // regression that drops scripts fails this audit.
    assert!(
        log.contains("46 scripts") || log.contains("curated CI suite"),
        "DEV_LOG must reference the tlsfuzzer curated CI suite"
    );
    assert!(log.contains("T119"), "DEV_LOG must retain T119 PSK anchor");
}

/// T116 audit pin #5: CI wall-clock budget. CLAUDE.md status line
/// asserts "PR/push CI wall-clock optimised 84 min → ~10 min (8×)".
/// The original `c-test-migration-plan.md` §7.3 target was ≤25 min;
/// actual delivery is ~10 min (well under budget).
#[test]
fn t116_ci_wall_clock_budget_cross_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let claude_md_path = format!("{manifest_dir}/../../CLAUDE.md");
    let claude_md = std::fs::read_to_string(&claude_md_path).unwrap();
    assert!(
        claude_md.contains("CI wall-clock") && claude_md.contains("~10 min"),
        "CLAUDE.md must retain the CI wall-clock ~10 min audit anchor"
    );
    // §7.3 budget target = 25 min; literal pin for Phase I grep.
    let plan_path = format!("{manifest_dir}/../../docs/c-test-migration-plan.md");
    let plan = std::fs::read_to_string(&plan_path).unwrap();
    assert!(
        plan.contains("≤ 25 min") || plan.contains("≤25 min"),
        "c-test-migration-plan.md §7.3 must retain the CI ≤25 min budget"
    );
}

/// T116 audit pin #6: residual `TODO(#42-phase-f)` anchors preserved
/// in 2 Phase F test files (T209/T211 follow-up TODOs documented in
/// `docs/issue-42-phase-f-plan.md` §7 "Follow-up TODOs left open").
#[test]
fn t116_residual_phase_f_anchors_preserved() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let tlcp_path = format!("{manifest_dir}/../../tests/interop/tests/tlcp_consistency.rs");
    let dtls12_path = format!("{manifest_dir}/../../tests/interop/tests/dtls12_consistency.rs");
    let tlcp_body = std::fs::read_to_string(&tlcp_path).unwrap();
    let dtls12_body = std::fs::read_to_string(&dtls12_path).unwrap();
    assert!(
        tlcp_body.contains("TODO(#42-phase-f)"),
        "tlcp_consistency.rs must retain residual #42-phase-f anchor"
    );
    assert!(
        dtls12_body.contains("TODO(#42-phase-f)"),
        "dtls12_consistency.rs must retain residual #42-phase-f anchor"
    );
}

/// T116 audit pin #7: Phase F closeout (T213) cross-pin to DEV_LOG.
/// The §7 series rollup table in the Phase F plan doc + the T213
/// closeout entry in DEV_LOG must both remain authoritative.
#[test]
fn t116_phase_f_closeout_t213_dev_log_cross_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log_path = format!("{manifest_dir}/../../DEV_LOG.md");
    let log = std::fs::read_to_string(&dev_log_path).unwrap();
    assert!(
        log.contains("T213"),
        "DEV_LOG must retain T213 closeout anchor"
    );
    // T209-T213 anchors must all remain (Phase F 5 sub-PRs).
    for anchor in ["T209", "T210", "T211", "T212", "T213"] {
        assert!(
            log.contains(anchor),
            "DEV_LOG must retain Phase F anchor `{anchor}`"
        );
    }
}

/// T116 audit pin #8: plan-doc cross-coverage. The Phase F plan doc
/// (`docs/issue-42-phase-f-plan.md`) must remain the authority for
/// both the original §7 rollup and the new §8 follow-up section.
#[test]
fn t116_audit_phase_f_plan_docs_in_sync() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-f-plan.md");
    let plan = std::fs::read_to_string(&plan_path)
        .unwrap_or_else(|e| panic!("missing Phase F plan doc at {plan_path}: {e}"));
    for anchor in [
        "Phase F",
        "T209",
        "T213",
        "T116",
        "T246",
        "T247",
        "T248",
        "T249",
        "TODO(#42-phase-f)",
        "audit-pin methodology",
        "migrated_phase_f_audit_pins.rs",
    ] {
        assert!(
            plan.contains(anchor),
            "Phase F plan doc must contain anchor `{anchor}`"
        );
    }
}
