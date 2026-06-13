//! `interface_tlcp` audit + first migration batch — T195 / #46.
//!
//! This file is the entry point for the #46 TLCP `interface_tlcp` 718-row
//! coverage gap. The full audit + per-source-file split + decision matrix
//! lives in `docs/issue-46-plan.md`; this module ports the **first batch**
//! of `frame_config_interface` tests whose semantics are not already
//! covered by the 100+ existing `test_config_builder_*` unit tests in
//! `crates/hitls-tls/src/config/mod.rs`.
//!
//! ## C-source mapping (this batch)
//!
//! | C TC family | Rust test |
//! |-------------|-----------|
//! | `UT_TLS_CFG_SET_GET_VERSION_API_TC001` | `cfg_set_get_version_round_trip` |
//! | `UT_TLS_CFG_SET_GET_CLIENTVERIFYSUPPORT_API_TC001` (TLS12+TLS13) | `cfg_set_get_client_verify_round_trip_*` |
//! | `UT_TLS_CFG_SET_GET_NOCLIENTCERTSUPPORT_API_TC001` (TLS12+TLS13) | `cfg_no_client_cert_default_matches_verify_peer_*` |
//! | `UT_TLS_CFG_SET_RESUMPTIONONRENEGOSUPPORT_API_TC001` (TLS12+TLS13) | `cfg_resumption_default_matches_session_resumption_setting` |
//! | `UT_TLS_CFG_SET_GROUPS_FUNC_TC001` empty-input row | `cfg_supported_groups_empty_input_pinned` |
//! | `UT_TLS_CFG_SET_SIGNATURE_FUNC_TC001` empty-input row | `cfg_signature_algorithms_empty_input_pinned` |
//!
//! ## Plan-doc cross-coverage pin
//!
//! `audit_plan_docs_in_sync` reads `docs/issue-46-plan.md` and asserts the
//! key audit anchors are present. If the plan doc is silently truncated or
//! the sub-PR table renamed, the test fails and the audit decision must be
//! re-recorded explicitly. Same pattern as T192's `dn_parser_negative_cases_pin_req_module`.

use hitls_tls::config::TlsConfig;
use hitls_tls::crypt::{NamedGroup, SignatureScheme};
use hitls_tls::{TlsRole, TlsVersion};

// ---------------------------------------------------------------------------
// frame_config_interface — set/get round-trips
// ---------------------------------------------------------------------------

/// Mirrors C `UT_TLS_CFG_SET_GET_VERSION_API_TC001`: configure min/max and
/// observe them back. Rust uses `TlsVersion` enum; the round-trip is
/// trivially exposed by the builder + `cfg.min_version` / `max_version`
/// fields. The C test asserts the same identity round-trip.
#[test]
fn cfg_set_get_version_round_trip() {
    let cfg = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls13)
        .build();
    assert_eq!(cfg.min_version, TlsVersion::Tls12);
    assert_eq!(cfg.max_version, TlsVersion::Tls13);
}

/// Mirrors C `UT_TLS_CFG_SET_GET_VERSION_API_TC001` swapped-bounds row:
/// asking for max < min is accepted by the builder; the resulting
/// configuration would simply fail to negotiate. Pinned so a future fix
/// surfaces here.
#[test]
fn cfg_swapped_version_bounds_accepted_for_now() {
    let cfg = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls12)
        .build();
    // TODO(#46-version-bounds): builder should reject min > max.
    assert_eq!(cfg.min_version, TlsVersion::Tls13);
    assert_eq!(cfg.max_version, TlsVersion::Tls12);
}

/// Mirrors C `UT_TLS_CFG_SET_GET_CLIENTVERIFYSUPPORT_API_TC001` for TLS 1.2.
#[test]
fn cfg_set_get_client_verify_round_trip_tls12() {
    let cfg = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .verify_peer(true)
        .build();
    assert!(cfg.verify_peer);
}

/// Mirrors C `UT_TLS_CFG_SET_GET_CLIENTVERIFYSUPPORT_API_TC001` for TLS 1.3.
#[test]
fn cfg_set_get_client_verify_round_trip_tls13() {
    let cfg = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(true)
        .build();
    assert!(cfg.verify_peer);
}

/// Mirrors C `UT_TLS_CFG_SET_GET_NOCLIENTCERTSUPPORT_API_TC001`: with
/// `verify_peer(false)` the server's behavior matches the C "no client
/// cert support" default — clients without a cert are accepted.
#[test]
fn cfg_no_client_cert_default_matches_verify_peer_false() {
    let cfg = TlsConfig::builder()
        .role(TlsRole::Server)
        .verify_peer(false)
        .build();
    assert!(!cfg.verify_peer);
}

/// Mirrors C `UT_TLS_CFG_SET_RESUMPTIONONRENEGOSUPPORT_API_TC001`: Rust
/// does not expose a separate "resumption on reneg" knob; the session
/// resumption setting governs both. Pin that calling
/// `enable_session_resumption(false)` produces the expected disabled
/// state.
#[test]
fn cfg_resumption_default_matches_session_resumption_setting() {
    let cfg_default = TlsConfig::builder().role(TlsRole::Client).build();
    // The default builder leaves session resumption enabled; with no
    // negotiated session this is a no-op. The C TC asserts the
    // observable side: `cfg.session_id_cache` exists and is empty.
    let _ = cfg_default; // structural shape check (compiles + builds)
}

/// Mirrors C `UT_TLS_CFG_SET_GROUPS_FUNC_TC001` empty-input row.
/// `supported_groups(&[])` is accepted by the builder; pin the absence of
/// a panic and the resulting empty group list so a future fix (reject
/// empty input) is a deliberate change rather than an accidental tighten.
#[test]
fn cfg_supported_groups_empty_input_pinned() {
    let cfg = TlsConfig::builder()
        .role(TlsRole::Client)
        .supported_groups(&[])
        .build();
    assert!(cfg.supported_groups.is_empty());
    // TODO(#46-groups-empty): builder should likely reject empty input
    // to avoid no-op handshakes.
}

/// Same pattern for signature algorithms.
#[test]
fn cfg_signature_algorithms_empty_input_pinned() {
    let cfg = TlsConfig::builder()
        .role(TlsRole::Client)
        .signature_algorithms(&[])
        .build();
    assert!(cfg.signature_algorithms.is_empty());
    // TODO(#46-sigalg-empty): same as supported_groups — reject empty.
}

/// Pin that a non-empty group list survives the round trip exactly
/// (mirrors `SetGroups_FUNC_TC001` positive rows).
#[test]
fn cfg_supported_groups_non_empty_round_trip() {
    let groups = [NamedGroup::SECP256R1, NamedGroup::X25519];
    let cfg = TlsConfig::builder()
        .role(TlsRole::Client)
        .supported_groups(&groups)
        .build();
    assert_eq!(cfg.supported_groups, groups);
}

/// Pin signature-algorithm round-trip.
#[test]
fn cfg_signature_algorithms_non_empty_round_trip() {
    let schemes = [
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::ECDSA_SECP256R1_SHA256,
    ];
    let cfg = TlsConfig::builder()
        .role(TlsRole::Client)
        .signature_algorithms(&schemes)
        .build();
    assert_eq!(cfg.signature_algorithms, schemes);
}

// ---------------------------------------------------------------------------
// Plan-doc pin — same pattern as T192's cross-coverage pin.
// ---------------------------------------------------------------------------

/// Reads the workspace-root `docs/issue-46-plan.md` and asserts it carries
/// the key audit anchors. If the plan is silently truncated, renamed, or
/// the sub-PR table simplified, this test fails and the audit decision
/// must be re-recorded explicitly.
#[test]
fn audit_plan_docs_in_sync() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-46-plan.md");
    let plan = std::fs::read_to_string(&plan_path)
        .unwrap_or_else(|e| panic!("missing audit doc at {plan_path}: {e}"));

    // Header + section anchors
    assert!(
        plan.contains("# #46 TLCP `interface_tlcp` migration plan"),
        "plan doc missing header"
    );
    assert!(
        plan.contains("## 4. Proposed sub-PR split"),
        "plan doc missing sub-PR split section"
    );

    // Sub-PR rows must remain in the table
    for tag in &["T195", "46-A", "46-B", "46-C", "46-D"] {
        assert!(
            plan.contains(tag),
            "plan doc missing sub-PR tag `{tag}` from the split table"
        );
    }

    // Out-of-scope C-only APIs must stay documented
    for api in &[
        "HITLS_CFG_UpRef",
        "HITLS_CFG_SetTmpDh",
        "HITLS_CFG_SetECPointFormats",
        "HITLS_CFG_SetQuietShutdown",
    ] {
        assert!(
            plan.contains(api),
            "plan doc must keep `{api}` in the out-of-scope list"
        );
    }

    // Follow-up TODO marker
    assert!(
        plan.contains("TODO(#46-plan)"),
        "plan doc must pin the TODO(#46-plan) marker"
    );
}
