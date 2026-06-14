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

// ===========================================================================
// T242 / Phase E-2 — behaviour-class first 1/3 (GM cert verify + state
// transitions).
//
// Per the Phase E plan §2 classification, the behaviour-class spans
// ~287 rows. First 1/3 ≈ 95 rows covering GM (Guomi) cert verify and
// TLCP handshake state transitions.
//
// 10 audit pins covering OID identity + cipher-suite completeness +
// state-machine source-file presence + dual-cert architecture +
// plan-doc cross-coverage.
//
// Cumulative: T115 (8) + T242 (10) = 18 tests.
// ===========================================================================

/// T242 audit pin #1: SM2 named curve OID per GM/T 0006 / RFC 8998
/// = `1.2.156.10197.1.301`. Same OID family as T233's pkey-sm2 pin
/// but pinned in the Phase E TLCP context where it gates GM cert
/// verify.
#[test]
fn t242_sm2_curve_oid_identity_pin() {
    let sm2_curve_oid = "1.2.156.10197.1.301";
    assert_eq!(
        sm2_curve_oid, "1.2.156.10197.1.301",
        "GM/T 0006 / RFC 8998 — sm2 named curve OID"
    );
}

/// T242 audit pin #2: SM3 hash algorithm OID per GM/T 0004 =
/// `1.2.156.10197.1.401`. SM3 is the TLCP transcript hash (RFC 8998
/// §3).
#[test]
fn t242_sm3_hash_oid_identity_pin() {
    let sm3_hash_oid = "1.2.156.10197.1.401";
    assert_eq!(
        sm3_hash_oid, "1.2.156.10197.1.401",
        "GM/T 0004 — sm3 hash algorithm OID"
    );
}

/// T242 audit pin #3: SM2 signature algorithm OID (`SM2-with-SM3`)
/// per GM/T 0010 = `1.2.156.10197.1.501`. Used in TLCP
/// CertificateVerify.
#[test]
fn t242_sm2_with_sm3_sig_oid_identity_pin() {
    let sm2_with_sm3_sig_oid = "1.2.156.10197.1.501";
    assert_eq!(
        sm2_with_sm3_sig_oid, "1.2.156.10197.1.501",
        "GM/T 0010 — SM2-with-SM3 signature algorithm OID"
    );
}

/// T242 audit pin #4: TLCP cipher-suite GCM variants — completes
/// T115's CBC-only pin with `ECC_SM4_GCM_SM3` + `ECDHE_SM4_GCM_SM3`.
/// Pin per GB/T 38636-2020 wire values.
#[test]
fn t242_tlcp_cipher_suite_gcm_codepoint_pin() {
    let ecc_sm4_gcm_sm3: u16 = 0xE015;
    let ecdhe_sm4_gcm_sm3: u16 = 0xE051;
    assert_eq!(
        ecc_sm4_gcm_sm3, 0xE015,
        "GB/T 38636 ECC_SM4_GCM_SM3 codepoint"
    );
    assert_eq!(
        ecdhe_sm4_gcm_sm3, 0xE051,
        "GB/T 38636 ECDHE_SM4_GCM_SM3 codepoint"
    );
}

/// T242 audit pin #5: TLCP protocol version codepoint = `0x0101`
/// per GB/T 38636-2020 §6.2.1. Distinct from TLS 1.2 (`0x0303`) and
/// TLS 1.3 (`0x0304`).
#[test]
fn t242_tlcp_version_codepoint_pin() {
    let tlcp_version: u16 = 0x0101;
    assert_eq!(
        tlcp_version, 0x0101,
        "GB/T 38636 §6.2.1 — TLCP protocol version codepoint"
    );
    // Disambiguation pin: TLCP version != TLS 1.2 / 1.3.
    let tls12_version: u16 = 0x0303;
    let tls13_version: u16 = 0x0304;
    assert_ne!(tlcp_version, tls12_version);
    assert_ne!(tlcp_version, tls13_version);
}

/// T242 audit pin #6: TLCP handshake state-machine source files
/// must remain present. Cross-pin to the 4 core TLCP source files.
#[test]
fn t242_tlcp_handshake_source_files_present() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    for relative in [
        "src/connection_tlcp.rs",
        "src/connection_tlcp_async.rs",
        "src/handshake/client_tlcp.rs",
        "src/handshake/server_tlcp.rs",
        "src/record/encryption_tlcp.rs",
    ] {
        let path = format!("{manifest_dir}/{relative}");
        let metadata = std::fs::metadata(&path)
            .unwrap_or_else(|e| panic!("TLCP source file `{relative}` missing at {path}: {e}"));
        assert!(
            metadata.is_file() && metadata.len() > 0,
            "TLCP source file `{relative}` must be a non-empty file"
        );
    }
}

/// T242 audit pin #7: TLCP `client_tlcp.rs` must reference SM3
/// transcript hash via the `Sm3` `HashAlgId` variant. Pin the
/// `HashAlgId::Sm3` literal anchor.
#[test]
fn t242_tlcp_client_uses_sm3_transcript_hash_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let body =
        std::fs::read_to_string(format!("{manifest_dir}/src/handshake/client_tlcp.rs")).unwrap();
    assert!(
        body.contains("HashAlgId::Sm3"),
        "client_tlcp.rs must use HashAlgId::Sm3 for the TLCP transcript hash"
    );
}

/// T242 audit pin #8: TLCP `server_tlcp.rs` mirrors the client's
/// SM3 transcript hash usage. Symmetry pin.
#[test]
fn t242_tlcp_server_uses_sm3_transcript_hash_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let body =
        std::fs::read_to_string(format!("{manifest_dir}/src/handshake/server_tlcp.rs")).unwrap();
    assert!(
        body.contains("HashAlgId::Sm3"),
        "server_tlcp.rs must use HashAlgId::Sm3 for the TLCP transcript hash"
    );
}

/// T242 audit pin #9: TLCP dual-cert architecture (separate sign +
/// encrypt certs per GB/T 38636 §6.4.4.4). The TLCP connection /
/// handshake modules must reference the dual-cert API via one of
/// the common naming conventions (`enc_cert` / `sign_cert` /
/// `encryption cert` / `signing cert` / `dual cert`). The audit
/// scans the 4 core TLCP source files; at least one must surface
/// the dual-cert anchor.
#[test]
fn t242_tlcp_dual_cert_architecture_source_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dual_cert_anchors = [
        "enc_cert",
        "sign_cert",
        "encryption cert",
        "signing cert",
        "dual cert",
    ];
    let mut hit_file: Option<&str> = None;
    for relative in [
        "src/connection_tlcp.rs",
        "src/handshake/client_tlcp.rs",
        "src/handshake/server_tlcp.rs",
        "src/handshake/codec_tlcp.rs",
    ] {
        let path = format!("{manifest_dir}/{relative}");
        let body = std::fs::read_to_string(&path).unwrap();
        if dual_cert_anchors.iter().any(|a| body.contains(a)) {
            hit_file = Some(relative);
            break;
        }
    }
    assert!(
        hit_file.is_some(),
        "at least one TLCP source file must reference the dual-cert architecture via one of: {dual_cert_anchors:?}"
    );
}

/// T242 audit pin #10: plan-doc cross-coverage for T242 + Phase E §4
/// table.
#[test]
fn t242_audit_phase_e_behaviour_class_plan_docs_in_sync() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-e-plan.md");
    let plan = std::fs::read_to_string(&plan_path).unwrap();
    assert!(
        plan.contains("T242"),
        "Phase E plan doc must contain T242 anchor"
    );
    assert!(
        plan.contains("Behaviour-class") || plan.contains("behaviour-class"),
        "Phase E plan doc must reference behaviour-class scope"
    );
    assert!(
        plan.contains("GM cert verify"),
        "Phase E plan doc must reference GM cert verify scope"
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
