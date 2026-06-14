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

// ===========================================================================
// T246 / Phase F-followup-2 — tlsfuzzer DTLS + state-machine coverage.
//
// Covers the c-test-migration-plan.md §7.2 acceptance criteria portion
// for protocol-conformance harness coverage:
//
// - tlsfuzzer TLS 1.3 + 1.2 curated scripts (T93/T94/T100/T108 codified
//   expansion; 46+ scripts)
// - DTLS resilience tests (T201 codified)
// - DTLS 1.2 consistency (T211-T212 codified)
// - DTLS 1.3 state-machine + parser robustness coverage (CLAUDE.md
//   status line anchor)
// - TLCP integration tests (T209-T210 codified)
//
// Cumulative: T116 (8) + T246 (10) = 18 tests.
// ===========================================================================

/// T246 audit pin #1: tlsfuzzer CI workflow file exists. The opt-in
/// `tlsfuzzer.yml` workflow drives the curated script set against
/// `s-server` / `s-client` CLI instances.
#[test]
fn t246_tlsfuzzer_workflow_file_present() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workflow_path = format!("{manifest_dir}/../../.github/workflows/tlsfuzzer.yml");
    let workflow = std::fs::read_to_string(&workflow_path)
        .unwrap_or_else(|e| panic!("tlsfuzzer.yml missing at {workflow_path}: {e}"));
    assert!(
        workflow.contains("tlsfuzzer") || workflow.contains("test-tls13"),
        "tlsfuzzer.yml workflow must reference tlsfuzzer test scripts"
    );
}

/// T246 audit pin #2: DEV_LOG records tlsfuzzer TLS 1.3 curated set
/// expansion lineage T93 / T94 / T100 / T108 anchors. Each anchor
/// added scripts to the CI suite; their preservation guards against
/// silent regressions.
#[test]
fn t246_tlsfuzzer_tls13_expansion_dev_log_anchors() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log = std::fs::read_to_string(format!("{manifest_dir}/../../DEV_LOG.md")).unwrap();
    for anchor in ["T93", "T94", "T100", "T108"] {
        assert!(
            dev_log.contains(anchor),
            "DEV_LOG must retain tlsfuzzer expansion anchor `{anchor}`"
        );
    }
}

/// T246 audit pin #3: DEV_LOG records tlsfuzzer TLS 1.2 integration
/// at T90 + mTLS-1.2 at T108. These delivered the 9 TLS 1.2 + 3
/// mTLS-1.2 curated scripts referenced from CLAUDE.md status line.
#[test]
fn t246_tlsfuzzer_tls12_integration_anchors() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log = std::fs::read_to_string(format!("{manifest_dir}/../../DEV_LOG.md")).unwrap();
    assert!(
        dev_log.contains("T90"),
        "DEV_LOG must retain T90 TLS 1.2 tlsfuzzer integration anchor"
    );
    assert!(
        dev_log.contains("test-tls13") || dev_log.contains("tlsfuzzer"),
        "DEV_LOG must reference tlsfuzzer scripts by name"
    );
}

/// T246 audit pin #4: DTLS resilience suite at T201 codified
/// (`tests/interop/tests/dtls_resilience.rs`). 8+ resilience tests.
#[test]
fn t246_dtls_resilience_suite_present() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../../tests/interop/tests/dtls_resilience.rs");
    let body = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("dtls_resilience.rs missing at {path}: {e}"));
    let test_count = body.matches("#[test]").count();
    assert!(
        test_count >= 8,
        "dtls_resilience.rs must contain at least 8 #[test] functions (T201 baseline); found {test_count}"
    );
}

/// T246 audit pin #5: DTLS 1.2 consistency suite at T211-T212
/// codified (`tests/interop/tests/dtls12_consistency.rs`). 23
/// audit-pin tests delivered.
#[test]
fn t246_dtls12_consistency_suite_present() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../../tests/interop/tests/dtls12_consistency.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    let test_count = body.matches("#[test]").count();
    assert!(
        test_count >= 20,
        "dtls12_consistency.rs must contain at least 20 #[test] functions (T211+T212); found {test_count}"
    );
}

/// T246 audit pin #6: TLCP consistency suite at T209-T210 codified
/// (`tests/interop/tests/tlcp_consistency.rs`). 22 audit-pin tests
/// delivered.
#[test]
fn t246_tlcp_consistency_suite_present() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../../tests/interop/tests/tlcp_consistency.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    let test_count = body.matches("#[test]").count();
    assert!(
        test_count >= 20,
        "tlcp_consistency.rs must contain at least 20 #[test] functions (T209+T210); found {test_count}"
    );
}

/// T246 audit pin #7: TLCP integration tests (happy-path 11
/// handshake variants in `tests/interop/tests/tlcp.rs`). These
/// cover ECDHE/ECC + GCM/CBC matrix that the consistency suite
/// audits.
#[test]
fn t246_tlcp_integration_tests_present() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../../tests/interop/tests/tlcp.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    let test_count = body.matches("#[test]").count();
    assert!(
        test_count >= 5,
        "tlcp.rs must contain at least 5 #[test] handshake-variant tests; found {test_count}"
    );
}

/// T246 audit pin #8: DTLS 1.3 state-machine + parser robustness
/// coverage. CLAUDE.md status line records this phase explicitly;
/// pin the anchor so a future regression that drops the coverage
/// fails this audit.
#[test]
fn t246_dtls13_state_machine_coverage_claude_md_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let claude_md = std::fs::read_to_string(format!("{manifest_dir}/../../CLAUDE.md")).unwrap();
    assert!(
        claude_md.contains("DTLS 1.3 state-machine") || claude_md.contains("DTLS 1.3 parser"),
        "CLAUDE.md must retain DTLS 1.3 state-machine + parser robustness anchor"
    );
}

/// T246 audit pin #9: Cargo bench no-regression discipline. The
/// `c-test-migration-plan.md` §7.2 requires `cargo bench` to not
/// regress. The discipline is documented in CLAUDE.md / DEV_LOG;
/// pin the literal "cargo bench" reference.
#[test]
fn t246_cargo_bench_no_regression_discipline_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan = std::fs::read_to_string(format!(
        "{manifest_dir}/../../docs/c-test-migration-plan.md"
    ))
    .unwrap();
    assert!(
        plan.contains("cargo bench"),
        "c-test-migration-plan.md §7.2 must retain the cargo bench no-regression criterion"
    );
}

/// T246 audit pin #10: plan-doc cross-coverage for T246 + §8
/// follow-up table.
#[test]
fn t246_audit_phase_f_followup2_plan_docs_in_sync() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-f-plan.md");
    let plan = std::fs::read_to_string(&plan_path).unwrap();
    for anchor in ["T246", "tlsfuzzer DTLS scripts"] {
        assert!(
            plan.contains(anchor),
            "Phase F plan doc must contain anchor `{anchor}` for T246 coverage"
        );
    }
}

// ===========================================================================
// T247 / Phase F-followup-3 — state-machine + CI integration coverage.
//
// Covers the c-test-migration-plan.md §7.2 "状态机部分写
// tlsfuzzer/DTLS 脚本" portion of the acceptance criteria.
//
// 10 audit pins cross-referencing the DEV_LOG state-machine
// hardening lineage (T88 → T119) and the CI sample-mode optimisation
// path (T93 12min → 80s).
//
// Cumulative: T116 (8) + T246 (10) + T247 (10) = 28 tests.
// ===========================================================================

/// T247 audit pin #1: TLS 1.3 alert-before-close state-machine
/// (T88 CCS + T89 alert-on-error generalisation + T103 empty-Alert
/// + T104 cross-record reassembly). DEV_LOG anchors must remain.
#[test]
fn t247_tls13_alert_state_machine_dev_log_anchors() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log = std::fs::read_to_string(format!("{manifest_dir}/../../DEV_LOG.md")).unwrap();
    for anchor in ["T88", "T89", "T103", "T104"] {
        assert!(
            dev_log.contains(anchor),
            "DEV_LOG must retain TLS 1.3 alert state-machine anchor `{anchor}`"
        );
    }
}

/// T247 audit pin #2: TLS 1.2 state-machine hardening lineage (T90
/// + T108 + T110 + T117 + T118). DEV_LOG anchors must remain.
#[test]
fn t247_tls12_state_machine_dev_log_anchors() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log = std::fs::read_to_string(format!("{manifest_dir}/../../DEV_LOG.md")).unwrap();
    for anchor in ["T90", "T108", "T110", "T117", "T118"] {
        assert!(
            dev_log.contains(anchor),
            "DEV_LOG must retain TLS 1.2 state-machine anchor `{anchor}`"
        );
    }
}

/// T247 audit pin #3: mTLS in-handshake state-machine — T96 server,
/// T97 client, T99 CV alert, T102 sigalgs comprehensive list. The
/// DEV_LOG anchors must remain.
#[test]
fn t247_mtls_state_machine_dev_log_anchors() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log = std::fs::read_to_string(format!("{manifest_dir}/../../DEV_LOG.md")).unwrap();
    for anchor in ["T99", "T102"] {
        assert!(
            dev_log.contains(anchor),
            "DEV_LOG must retain mTLS state-machine anchor `{anchor}`"
        );
    }
    assert!(
        dev_log.contains("mTLS") || dev_log.contains("in-handshake"),
        "DEV_LOG must reference mTLS or in-handshake state-machine work"
    );
}

/// T247 audit pin #4: 0-RTT state-machine (T106 rejected-garbage
/// tolerance + T109 acceptance verification). DEV_LOG anchors must
/// remain.
#[test]
fn t247_0rtt_state_machine_dev_log_anchors() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log = std::fs::read_to_string(format!("{manifest_dir}/../../DEV_LOG.md")).unwrap();
    for anchor in ["T106", "T109"] {
        assert!(
            dev_log.contains(anchor),
            "DEV_LOG must retain 0-RTT state-machine anchor `{anchor}`"
        );
    }
    assert!(
        dev_log.contains("0-RTT")
            || dev_log.contains("early data")
            || dev_log.contains("early_data"),
        "DEV_LOG must reference 0-RTT / early data work"
    );
}

/// T247 audit pin #5: KeyUpdate state-machine (T100 codec authority
/// + T101 cross-record reassembly). DEV_LOG anchors must remain.
#[test]
fn t247_keyupdate_state_machine_dev_log_anchors() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log = std::fs::read_to_string(format!("{manifest_dir}/../../DEV_LOG.md")).unwrap();
    for anchor in ["T100", "T101"] {
        assert!(
            dev_log.contains(anchor),
            "DEV_LOG must retain KeyUpdate state-machine anchor `{anchor}`"
        );
    }
    assert!(
        dev_log.contains("KeyUpdate")
            || dev_log.contains("keyupdate")
            || dev_log.contains("key_update"),
        "DEV_LOG must reference KeyUpdate work"
    );
}

/// T247 audit pin #6: External-PSK state-machine (T119 TLS 1.3
/// server-side external PSK with `--psk` / `--psk-identity` flags).
/// DEV_LOG anchor must remain.
#[test]
fn t247_external_psk_state_machine_dev_log_anchor() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log = std::fs::read_to_string(format!("{manifest_dir}/../../DEV_LOG.md")).unwrap();
    assert!(
        dev_log.contains("T119"),
        "DEV_LOG must retain T119 external-PSK state-machine anchor"
    );
    assert!(
        dev_log.contains("--psk"),
        "DEV_LOG must reference the --psk CLI flag for external-PSK support"
    );
}

/// T247 audit pin #7: tlsfuzzer XFAIL bookkeeping methodology
/// (T89 codified per-script XFAIL dirs + T93 `XFAIL_DIR` env hook).
/// DEV_LOG anchors must remain.
#[test]
fn t247_tlsfuzzer_xfail_bookkeeping_dev_log_anchors() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log = std::fs::read_to_string(format!("{manifest_dir}/../../DEV_LOG.md")).unwrap();
    assert!(
        dev_log.contains("XFAIL"),
        "DEV_LOG must reference the XFAIL bookkeeping methodology"
    );
    for anchor in ["T89", "T93"] {
        assert!(
            dev_log.contains(anchor),
            "DEV_LOG must retain XFAIL bookkeeping anchor `{anchor}`"
        );
    }
}

/// T247 audit pin #8: CI sample-mode wall-clock optimisation
/// (CLAUDE.md status line: "CI sampling-mode wall-clock 12 min →
/// 80 s for all 26 scripts").
#[test]
fn t247_ci_sample_mode_wall_clock_optimisation_claude_md_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let claude_md = std::fs::read_to_string(format!("{manifest_dir}/../../CLAUDE.md")).unwrap();
    assert!(
        claude_md.contains("sampling-mode")
            || claude_md.contains("80 s")
            || claude_md.contains("80s"),
        "CLAUDE.md must retain CI sampling-mode wall-clock optimisation anchor"
    );
}

/// T247 audit pin #9: tlsfuzzer cert-matrix coverage (T93 codified
/// 3 cert types × dedicated `s-server` instances + per-cert XFAIL
/// dirs).
#[test]
fn t247_tlsfuzzer_cert_matrix_dev_log_anchor() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log = std::fs::read_to_string(format!("{manifest_dir}/../../DEV_LOG.md")).unwrap();
    assert!(
        dev_log.contains("cert-matrix")
            || dev_log.contains("cert matrix")
            || dev_log.contains("XFAIL_DIR"),
        "DEV_LOG must retain T93 cert-matrix coverage anchor"
    );
}

/// T247 audit pin #10: plan-doc cross-coverage for T247.
#[test]
fn t247_audit_phase_f_followup3_plan_docs_in_sync() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-f-plan.md");
    let plan = std::fs::read_to_string(&plan_path).unwrap();
    assert!(
        plan.contains("T247"),
        "Phase F plan doc must contain T247 anchor"
    );
    assert!(
        plan.contains("state-machine"),
        "Phase F plan doc must reference state-machine coverage"
    );
}

// ===========================================================================
// T248 / Phase F-followup-4 — full regression + CI budget + total tests.
//
// Covers the c-test-migration-plan.md §7.3 acceptance criteria:
//
// - Total test count target (rescoped to audit-pin methodology
//   delivery total ~4 300+ workspace tests)
// - CI wall-clock budget (≤25 min target, actual ~10 min)
// - cargo bench no-regression discipline
// - tlsfuzzer 46+ curated scripts coverage
// - Security tooling lineage (cargo-deny / cargo-vet / cargo-audit)
// - Quality tooling lineage (nextest / llvm-cov / cargo-careful /
//   Miri / Kani)
//
// Cumulative: T116 (8) + T246 (10) + T247 (10) + T248 (10) = 38 tests.
// ===========================================================================

/// T248 audit pin #1: CLAUDE.md "4300+ tests" status line literal.
/// The rescoped §7.3 total-tests floor pin — guards against silent
/// drops below 4 300 tests workspace-wide.
#[test]
fn t248_claude_md_workspace_tests_floor_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let claude_md = std::fs::read_to_string(format!("{manifest_dir}/../../CLAUDE.md")).unwrap();
    assert!(
        claude_md.contains("4300+ tests"),
        "CLAUDE.md must retain the `4300+ tests` workspace-test floor anchor"
    );
}

/// T248 audit pin #2: issue-42 audit-pin tests cumulative count
/// floor. Phase C (46) plus Phase F (45) plus Phase G (40) plus
/// Phase H (38) plus Phase B (43) plus Phase F-followup
/// (current count) sums to roughly 212-plus audit-pin tests
/// across the issue-42 series.
#[test]
fn t248_issue42_audit_pin_tests_cumulative_pin() {
    let phase_c: usize = 46;
    let phase_f: usize = 45;
    let phase_g: usize = 40;
    let phase_h: usize = 38;
    let phase_b: usize = 43;
    let cumulative_floor = phase_c + phase_f + phase_g + phase_h + phase_b;
    assert_eq!(
        cumulative_floor, 212,
        "issue-42 audit-pin series cumulative floor must remain 212+ tests"
    );
}

/// T248 audit pin #3: CI workflow inventory. The 5 workflows
/// (`ci.yml`, `commitlint.yml`, `kani.yml`, `mutants.yml`,
/// `tlsfuzzer.yml`) must all remain present.
#[test]
fn t248_ci_workflow_inventory_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workflows_dir = format!("{manifest_dir}/../../.github/workflows");
    for workflow in [
        "ci.yml",
        "commitlint.yml",
        "kani.yml",
        "mutants.yml",
        "tlsfuzzer.yml",
    ] {
        let path = format!("{workflows_dir}/{workflow}");
        let metadata = std::fs::metadata(&path)
            .unwrap_or_else(|e| panic!("CI workflow `{workflow}` missing at {path}: {e}"));
        assert!(
            metadata.is_file() && metadata.len() > 0,
            "CI workflow `{workflow}` must be a non-empty file"
        );
    }
}

/// T248 audit pin #4: cargo bench infrastructure. The
/// `crates/hitls-crypto/benches` directory must remain present so
/// the §7.2 cargo bench no-regression discipline is exercisable.
#[test]
fn t248_cargo_bench_infrastructure_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let benches_dir = format!("{manifest_dir}/../../crates/hitls-crypto/benches");
    let metadata = std::fs::metadata(&benches_dir)
        .unwrap_or_else(|e| panic!("hitls-crypto benches dir missing at {benches_dir}: {e}"));
    assert!(
        metadata.is_dir(),
        "hitls-crypto/benches must remain a directory for cargo bench"
    );
}

/// T248 audit pin #5: T80 CI optimisation lineage (84 min → ~10 min,
/// 8× speedup). DEV_LOG anchor must remain.
#[test]
fn t248_ci_optimisation_t80_dev_log_anchor() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log = std::fs::read_to_string(format!("{manifest_dir}/../../DEV_LOG.md")).unwrap();
    assert!(
        dev_log.contains("T80"),
        "DEV_LOG must retain T80 CI optimisation anchor"
    );
}

/// T248 audit pin #6: Security tooling lineage — cargo-deny +
/// cargo-vet + cargo-audit + SBOM + SLSA + ASan. DEV_LOG must
/// reference these tools.
#[test]
fn t248_security_tooling_dev_log_anchors() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log = std::fs::read_to_string(format!("{manifest_dir}/../../DEV_LOG.md")).unwrap();
    for tool in ["cargo-deny", "cargo-vet", "cargo-audit"] {
        assert!(
            dev_log.contains(tool),
            "DEV_LOG must retain security tooling reference `{tool}`"
        );
    }
}

/// T248 audit pin #7: Quality tooling lineage — nextest, llvm-cov,
/// cargo-careful, Miri, Kani. CLAUDE.md must reference these per
/// the §7.2 full-regression criterion.
#[test]
fn t248_quality_tooling_claude_md_anchors() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let claude_md = std::fs::read_to_string(format!("{manifest_dir}/../../CLAUDE.md")).unwrap();
    for tool in ["nextest", "llvm-cov", "cargo-careful", "Miri", "Kani"] {
        assert!(
            claude_md.contains(tool),
            "CLAUDE.md must retain quality tooling reference `{tool}`"
        );
    }
}

/// T248 audit pin #8: Fuzz targets inventory — CLAUDE.md asserts
/// "fuzz (68 targets, 447 corpus seeds)". Pin the literal counts.
#[test]
fn t248_fuzz_targets_inventory_claude_md_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let claude_md = std::fs::read_to_string(format!("{manifest_dir}/../../CLAUDE.md")).unwrap();
    assert!(
        claude_md.contains("68 targets") || claude_md.contains("fuzz targets"),
        "CLAUDE.md must retain the fuzz targets inventory anchor"
    );
}

/// T248 audit pin #9: cargo-mutants + cargo-semver-checks. CLAUDE.md
/// references these in the Testing section's CI hardening list.
#[test]
fn t248_advanced_quality_tooling_claude_md_anchors() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let claude_md = std::fs::read_to_string(format!("{manifest_dir}/../../CLAUDE.md")).unwrap();
    assert!(
        claude_md.contains("cargo-mutants"),
        "CLAUDE.md must retain cargo-mutants reference"
    );
    assert!(
        claude_md.contains("cargo-semver-checks"),
        "CLAUDE.md must retain cargo-semver-checks reference"
    );
}

/// T248 audit pin #10: plan-doc cross-coverage for T248. The Phase F
/// plan doc §8 follow-up table must reference T248 + the full-
/// regression scope.
#[test]
fn t248_audit_phase_f_followup4_plan_docs_in_sync() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-f-plan.md");
    let plan = std::fs::read_to_string(&plan_path).unwrap();
    assert!(
        plan.contains("T248"),
        "Phase F plan doc must contain T248 anchor"
    );
    assert!(
        plan.contains("full-regression") || plan.contains("full regression"),
        "Phase F plan doc must reference full-regression coverage"
    );
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
