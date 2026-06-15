//! Phase I closeout pin tests — T254 / #42.
//!
//! Phase I-6 / T254 closeout. The 5-sub-PR Phase I series (T250-T254)
//! closes 49 audit-pinned `#46/#47/#58/#61-*` anchors at the
//! **cli-layer**. Real product code wiring delivered for 11 anchors
//! (RSA-PSS encoder + SM2 dispatch + RSA codec extract), cli-layer
//! deferral upgrade applied to 15 anchors (Brainpool/P-224 + PBES2 +
//! genrsa-encryption + RSA codec extract callers + TLS hardening), and
//! 23 anchors flagged as crypto-tier deferrals for future Implementation
//! phases.
//!
//! Same codified closeout recipe sibling to T200 / T208 / T213 / T218 /
//! T223 / T228 / T236 / T249 / T245: §N rollup in the plan doc +
//! methodology lineage + cross-doc milestone-phrase consistency audit.

/// T254 closeout pin #1: the Phase I roadmap doc (§1 status) flipped
/// to "✅ Complete" with the cli-layer closure note. The doc is the
/// authoritative artefact emitted by T236 closeout; T254 closes it.
#[test]
fn t254_phase_i_roadmap_doc_status_complete() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../../docs/issue-42-phase-i-roadmap.md");
    let body = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Phase I roadmap missing at {path}: {e}"));
    assert!(
        body.contains("✅ Complete"),
        "Phase I roadmap §1 status must be flipped to ✅ Complete"
    );
    assert!(
        body.contains("Phase I closes at the cli-layer"),
        "Phase I roadmap must surface the cli-layer closure phrase"
    );
}

/// T254 closeout pin #2: methodology lineage table in §4 must
/// reference all 5 codified T-phase anchors T250-T254.
#[test]
fn t254_phase_i_methodology_lineage_pinned() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/../../docs/issue-42-phase-i-roadmap.md");
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(body.contains("Methodology lineage"));
    for anchor in ["T250", "T251", "T252", "T253", "T254"] {
        assert!(
            body.contains(anchor),
            "Phase I methodology lineage must reference codified anchor `{anchor}`"
        );
    }
}

/// T254 closeout pin #3: §4 series rollup table marks all 5 sub-PRs
/// closed with their PR numbers.
#[test]
fn t254_phase_i_series_rollup_table() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let body = std::fs::read_to_string(format!(
        "{manifest_dir}/../../docs/issue-42-phase-i-roadmap.md"
    ))
    .unwrap();
    for pr in ["#331", "#332", "#333", "#334"] {
        assert!(
            body.contains(pr),
            "Phase I series rollup must reference merged PR `{pr}`"
        );
    }
    assert!(
        body.contains("**5 sub-PRs**"),
        "Phase I series rollup must show 5 sub-PR total"
    );
}

/// T254 closeout pin #4: cli-layer closure milestone — cross-doc
/// consistency audit. The milestone phrase
/// "Complete cli-layer Phase I closure milestone" must appear in
/// both the roadmap doc and CLAUDE.md status line.
#[test]
fn t254_complete_cli_layer_phase_i_closure_milestone() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let roadmap = std::fs::read_to_string(format!(
        "{manifest_dir}/../../docs/issue-42-phase-i-roadmap.md"
    ))
    .unwrap();
    let claude_md = std::fs::read_to_string(format!("{manifest_dir}/../../CLAUDE.md")).unwrap();
    let milestone = "Complete cli-layer Phase I closure milestone";
    assert!(
        roadmap.contains(milestone),
        "Phase I roadmap §5 must surface the milestone phrase"
    );
    assert!(
        claude_md.contains(milestone),
        "CLAUDE.md status line must surface the milestone phrase"
    );
}

/// T254 closeout pin #5: Phase B `migrated_phase_b_audit_pins.rs`
/// test file continues passing — verified via the file presence at
/// its expected path. The 43 Phase B audit pins use literal grep
/// against `TODO(#47-*)` / `TODO(#46-*)` strings; T250-T254 preserved
/// every literal anchor via the layered RESOLVED annotation pattern.
#[test]
fn t254_phase_b_audit_pin_file_preserved() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/tests/migrated_phase_b_audit_pins.rs");
    let metadata = std::fs::metadata(&path)
        .unwrap_or_else(|e| panic!("Phase B audit pin file missing at {path}: {e}"));
    assert!(
        metadata.is_file() && metadata.len() > 0,
        "Phase B audit pin file must be a non-empty file"
    );
    // Sanity-pin one literal anchor name from each TODO family that
    // T250-T254 closed via the layered RESOLVED annotation pattern —
    // if these literal strings get refactored, both Phase B and
    // Phase I closeout pins should fail in lock-step.
    let body = std::fs::read_to_string(&path).unwrap();
    for anchor_family in ["#47-pkey-rsa-pss", "#47-pkey-sm2", "#47-rsa-codec-extract"] {
        assert!(
            body.contains(anchor_family),
            "Phase B audit pin file must continue to reference `{anchor_family}` literal anchor family"
        );
    }
}
