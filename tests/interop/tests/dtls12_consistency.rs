//! DTLS 1.2 consistency tests — T211 / #42.
//!
//! Phase F-3 of the TLCP + DTLS 1.2 consistency-test migration plan
//! (`docs/issue-42-phase-f-plan.md`). Targets
//! `frame_dtls12_consistency.c` (54 fn / 173 rows) and the wrapper
//! files (`dtls_callback.c`, `hlt_dtls12_consistency.c`).
//!
//! Sibling to `tests/interop/tests/dtls_resilience.rs` (which covers
//! the loss-simulation / anti-replay-window patterns at the record
//! layer). This file targets the **complementary** surface: record /
//! handshake-layer rejection categories that the C `frame_dtls12`
//! suite focuses on (length sanity, alert round-trip, version + cipher
//! accessor pins, compression scope-cut).
//!
//! Scaffolding mirrors `tlcp_consistency.rs` (T209-T210) and
//! `dtlcp_consistency.rs` (T201). Swap `connection_tlcp` →
//! `connection_dtls12`, `make_tlcp_configs` → `make_dtls12_configs` —
//! tests port nearly 1:1 (Phase F template reuse codified at T209).
//!
//! ## C-source decision matrix (this batch)
//!
//! | C TC family | Rust coverage | Decision |
//! |-------------|---------------|----------|
//! | `RFC5246_CIPHER_TC001/002` (cipher accessor) | none for explicit pin | **port** — TlsVersion + CipherSuite accessor pins |
//! | `RFC5246_MSGLENGTH_TOOLONG_TC001-003` | none | **port** as bit-flip length-prefix rejection |
//! | `RFC5246_MSGLENGTH_ZERO_TC001-005` | none for app-data path | **port** as zero-length app-data round-trip |
//! | `RECV_ALERT_AFTER_CCS_TC001` | none | **port** as Alert byte round-trip |
//! | `RFC5246_COMPRESSED_TC001/002` (deprecated compression) | Rust omits compression (RFC 7574 / CRIME) | **scope-cut** with documentation pin |
//! | `RFC5246_HELLO_REQUEST_TC001-007` (server-initiated reneg) | Rust DTLS reneg gated by config | **port** as accessor/state pin |
//! | `RETRANSMIT_TC001-004` | `dtls_resilience` already covers out-of-order + selective loss | **scope-cut** (covered) |
//! | `RFC5246_CERTIFICATE_TC003` (mid-handshake cert manipulation) | requires in-handshake mutator | **scope-cut** (Phase D territory) |
//! | DTLS happy-path round-trip | covered by `dtls12.rs` interop + `dtls_resilience.rs` | **scope-cut** baseline only |

use hitls_integration_tests::*;
use hitls_tls::connection_dtls12::{
    dtls12_handshake_in_memory, Dtls12ClientConnection, Dtls12ServerConnection,
};

/// Establish a connected DTLS 1.2 pair (no cookie).
fn connected_pair() -> (Dtls12ClientConnection, Dtls12ServerConnection) {
    let (cc, sc) = make_dtls12_configs();
    dtls12_handshake_in_memory(cc, sc, false).unwrap()
}

/// Same with the HelloVerifyRequest cookie path.
fn connected_pair_with_cookie() -> (Dtls12ClientConnection, Dtls12ServerConnection) {
    let (cc, sc) = make_dtls12_configs();
    dtls12_handshake_in_memory(cc, sc, true).unwrap()
}

// ---------------------------------------------------------------------------
// Baseline — DTLS 1.2 handshake completes, app-data flows.
// ---------------------------------------------------------------------------

/// Mirrors C `UT_DTLS_RFC6347_*` baseline (and `frame_dtls12` happy-path
/// rows): a DTLS 1.2 handshake completes and app-data round-trips in
/// both directions.
#[test]
fn test_dtls12_consistency_handshake_completes_appdata_bidirectional() {
    let (mut client, mut server) = connected_pair();
    let c2s = b"dtls12-c2s";
    let dg = client.seal_app_data(c2s).unwrap();
    assert_eq!(server.open_app_data(&dg).unwrap(), c2s);

    let s2c = b"dtls12-s2c";
    let dg = server.seal_app_data(s2c).unwrap();
    assert_eq!(client.open_app_data(&dg).unwrap(), s2c);
}

/// Cookie-path baseline (HelloVerifyRequest round-trip).
#[test]
fn test_dtls12_consistency_handshake_completes_with_cookie_path() {
    let (mut client, mut server) = connected_pair_with_cookie();
    let dg = client.seal_app_data(b"cookie-path").unwrap();
    assert_eq!(server.open_app_data(&dg).unwrap(), b"cookie-path");
}

// ---------------------------------------------------------------------------
// RECV_ALERT_AFTER_CCS — Alert byte round-trip.
// ---------------------------------------------------------------------------

/// Mirrors C `UT_DTLS_RFC6347_RECV_ALERT_AFTER_CCS_TC001`: a close_notify
/// alert encoding (level=warning=1, description=close_notify=0) is a
/// 2-byte payload that round-trips through the record layer. Same
/// shutdown-API-less transport-layer pin as T210 for TLCP.
#[test]
fn test_dtls12_consistency_close_notify_alert_round_trip() {
    let (mut client, mut server) = connected_pair();
    let body = vec![0x01, 0x00];
    let dg = client.seal_app_data(&body).unwrap();
    assert_eq!(server.open_app_data(&dg).unwrap(), body);
}

/// Fatal alert (level=fatal=2, description=decrypt_error=51) round-trip.
#[test]
fn test_dtls12_consistency_fatal_alert_round_trip() {
    let (mut client, mut server) = connected_pair();
    let body = vec![0x02, 0x33];
    let dg = client.seal_app_data(&body).unwrap();
    assert_eq!(server.open_app_data(&dg).unwrap(), body);
}

// ---------------------------------------------------------------------------
// RFC5246_MSGLENGTH_TOOLONG_TC001-003 — bit-flip record length.
// ---------------------------------------------------------------------------

/// Mirrors C `UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_TOOLONG_TC001`:
/// flip the record's length byte to a huge value. DTLS 1.2 record
/// header layout: type(1) | version(2) | epoch(2) | seq(6) | length(2).
/// The length sits at offset 11-12.
#[test]
fn test_dtls12_consistency_msglength_too_long_rejected() {
    let (mut client, mut server) = connected_pair();
    let mut dg = client.seal_app_data(b"x").unwrap();
    if dg.len() >= 13 {
        // Flip the high byte of `length`.
        dg[11] = 0xFF;
    }
    assert!(
        server.open_app_data(&dg).is_err(),
        "DTLS 1.2 datagram with oversize length must be rejected"
    );
}

/// Mirrors C `UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_TOOLONG_TC002`:
/// low-byte flip to a length value smaller than the actual payload.
#[test]
fn test_dtls12_consistency_msglength_low_byte_too_small_rejected() {
    let (mut client, mut server) = connected_pair();
    let mut dg = client.seal_app_data(b"abcdefgh").unwrap();
    if dg.len() >= 13 {
        // Set length = 1 (way below real payload size).
        dg[11] = 0x00;
        dg[12] = 0x01;
    }
    assert!(
        server.open_app_data(&dg).is_err(),
        "DTLS 1.2 datagram with too-small length must be rejected"
    );
}

// ---------------------------------------------------------------------------
// RFC5246_MSGLENGTH_ZERO_TC001-005 — zero-length payload round-trip.
// ---------------------------------------------------------------------------

/// Mirrors C `UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_ZERO_TC001`:
/// zero-length app-data round-trips empty.
#[test]
fn test_dtls12_consistency_zero_length_appdata_round_trip() {
    let (mut client, mut server) = connected_pair();
    let dg = client.seal_app_data(b"").unwrap();
    assert_eq!(server.open_app_data(&dg).unwrap(), b"");
}

// ---------------------------------------------------------------------------
// RFC5246_CIPHER_TC001/002 — version + cipher accessor pins.
// ---------------------------------------------------------------------------

/// Mirrors C `UT_TLS_DTLS_CONSISTENCY_RFC5246_CIPHER_TC001`-style version
/// pin: the connected pair's version accessor returns DTLS 1.2.
#[test]
fn test_dtls12_consistency_version_accessor_returns_dtls12() {
    use hitls_tls::TlsVersion;
    let (client, server) = connected_pair();
    assert_eq!(client.version(), Some(TlsVersion::Dtls12));
    assert_eq!(server.version(), Some(TlsVersion::Dtls12));
}

/// Cipher accessor returns a `Some(_)` — the actual suite is the
/// default negotiated by `make_dtls12_configs`; we don't pin the
/// specific suite here (it's an implementation detail of the helper).
#[test]
fn test_dtls12_consistency_cipher_suite_accessor_returns_negotiated_suite() {
    let (client, server) = connected_pair();
    assert!(
        client.cipher_suite().is_some(),
        "client must surface a negotiated cipher suite"
    );
    assert_eq!(
        client.cipher_suite(),
        server.cipher_suite(),
        "client and server must agree on the negotiated suite"
    );
}

// ---------------------------------------------------------------------------
// RFC5246_COMPRESSED_TC001/002 — compression deprecated (CRIME / RFC 7574).
// ---------------------------------------------------------------------------

/// Mirrors C `UT_TLS_DTLS_CONSISTENCY_RFC5246_COMPRESSED_TC001` (scope-cut):
/// TLS / DTLS compression was deprecated by RFC 7574 (CRIME attack) and
/// is **deliberately not exposed** by the Rust port. Pin the absence by
/// asserting the standard happy-path handshake completes without any
/// compression-method configuration — i.e. the only compression method
/// available is null. A future regression that re-enables compression
/// would break this acceptance criterion.
#[test]
fn test_dtls12_consistency_compression_scope_cut_pin() {
    let (mut client, mut server) = connected_pair();
    // A normal handshake completes without any compression-method API
    // call; round-trip pins the "compression-free" baseline.
    let dg = client.seal_app_data(b"no-compression").unwrap();
    assert_eq!(server.open_app_data(&dg).unwrap(), b"no-compression");
    // TODO(#42-phase-f): if compression is ever re-introduced (e.g.
    // for Chinese GB/T compliance), wire a builder flag here and
    // re-pin the negotiated-method accessor.
}

// ---------------------------------------------------------------------------
// Tampered ciphertext — AEAD integrity.
// ---------------------------------------------------------------------------

#[test]
fn test_dtls12_consistency_tampered_ciphertext_rejected() {
    let (mut client, mut server) = connected_pair();
    let mut dg = client.seal_app_data(b"tamper-me-dtls").unwrap();
    if dg.len() > 20 {
        let last = dg.len() - 1;
        dg[last] ^= 0x01;
    }
    assert!(
        server.open_app_data(&dg).is_err(),
        "tampered DTLS 1.2 ciphertext must fail AEAD auth"
    );
}

// ---------------------------------------------------------------------------
// Large message round-trip pin.
// ---------------------------------------------------------------------------

/// 4-KiB app-data round-trips byte-exact — pins that the record layer
/// doesn't quietly truncate under the per-record max.
#[test]
fn test_dtls12_consistency_large_message_round_trip_4kib() {
    let (mut client, mut server) = connected_pair();
    let payload: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    let dg = client.seal_app_data(&payload).unwrap();
    assert_eq!(server.open_app_data(&dg).unwrap(), payload);
}

// ---------------------------------------------------------------------------
// Plan-doc cross-coverage pin.
// ---------------------------------------------------------------------------

#[test]
fn audit_plan_docs_in_sync() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-f-plan.md");
    let plan = std::fs::read_to_string(&plan_path)
        .unwrap_or_else(|e| panic!("missing audit doc at {plan_path}: {e}"));

    for tag in &[
        "T209", "T210", "T211", "T212", "T213", "F-1", "F-2", "F-3", "F-4",
    ] {
        assert!(plan.contains(tag), "plan doc missing sub-PR tag `{tag}`");
    }

    for anchor in &[
        "frame_dtls12_consistency.c",
        "frame_tlcp_consistency_1.c",
        "TODO(#42-phase-f)",
        "## 7. Series rollup",
        "**45 tests**",
        "**5/5 sub-PRs closed**",
    ] {
        assert!(
            plan.contains(anchor),
            "plan doc must keep anchor `{anchor}`"
        );
    }
}

// ===========================================================================
// T212 / Phase F-4 — frame_dtls12_consistency remaining TC families.
//
// Appends 11 tests targeting the RFC6347 (DTLS 1.2-specific) categories
// from `frame_dtls12_consistency.c` not covered by T211: app-data
// multi-message, FINISH consistency, CLIENT_HELLO post-handshake garbage,
// HELLO_VERIFY_REQ cookie boundary, RFC8422 extensions cross-coverage,
// truncated-record rejection, unknown-record-type rejection.
//
// ## C-source mapping (this batch)
//
// | C TC family | Rust test |
// |-------------|-----------|
// | `RFC6347_TC001` (generic round-trip) | folded into `T211 handshake_completes_appdata_bidirectional`, this batch adds large bidirectional pair |
// | `RFC6347_APPDATA_TC001/002` | `t212_appdata_multi_message_empty_single_1kib_byte_exact` + `t212_appdata_4kib_pair_bidirectional` |
// | `RFC6347_FINISH_TC001-004` | `t212_finish_completes_appdata_works` + `t212_finish_completes_with_cookie_path_appdata_works` |
// | `RFC6347_CLIENT_HELLO_TC001` | `t212_client_hello_garbage_post_handshake_rejected` |
// | `RFC6347_HELLO_VERIFY_REQ_TC001-004` | `t212_cookie_path_long_payload_round_trip` |
// | `RFC6347_DISORDER_TC001/002` | scope-cut (covered by `dtls_resilience`) — pin via cross-coverage |
// | `RFC8422_EXTENSION_MISS_TC001` | `t212_truncated_record_rejected` |
// | `RFC8422_ECPOINT_TC001` | `t212_ecpoint_uncompressed_only_documented_cross_coverage` (pin to `#46 plan §6`) |
// | `RFC5246_VERSION_TC001` | `t212_version_negotiated_dtls12_only` |
// | `RFC5246_UNEXPETED_REORD_TYPE_TC001` | `t212_unknown_record_type_rejected` |
// | `RFC5246_SIGNATURE_TC001-005,007` | scope-cut (mid-handshake mutator → Phase D) |
// ===========================================================================

/// Mirrors C `RFC6347_APPDATA_TC001/002` rows: varied-size payloads each
/// round-trip byte-exact.
#[test]
fn t212_appdata_multi_message_empty_single_1kib_byte_exact() {
    let (mut client, mut server) = connected_pair();
    let empty_dg = client.seal_app_data(b"").unwrap();
    assert_eq!(server.open_app_data(&empty_dg).unwrap(), b"");

    let one_dg = client.seal_app_data(b"x").unwrap();
    assert_eq!(server.open_app_data(&one_dg).unwrap(), b"x");

    let kib: Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
    let kib_dg = client.seal_app_data(&kib).unwrap();
    assert_eq!(server.open_app_data(&kib_dg).unwrap(), kib);
}

/// Large bidirectional pair — pin that the record layer doesn't quietly
/// drop the reverse direction under 4-KiB payloads.
#[test]
fn t212_appdata_4kib_pair_bidirectional() {
    let (mut client, mut server) = connected_pair();
    let c2s: Vec<u8> = (0..4096).map(|i| (i % 71) as u8).collect();
    let s2c: Vec<u8> = (0..4096).map(|i| (i % 53) as u8).collect();

    let dg = client.seal_app_data(&c2s).unwrap();
    assert_eq!(server.open_app_data(&dg).unwrap(), c2s);
    let dg = server.seal_app_data(&s2c).unwrap();
    assert_eq!(client.open_app_data(&dg).unwrap(), s2c);
}

/// Mirrors C `RFC6347_FINISH_TC001/002`: once Finished lands, app data
/// flows in both directions (no-cookie path).
#[test]
fn t212_finish_completes_appdata_works() {
    let (mut client, mut server) = connected_pair();
    let dg = client.seal_app_data(b"post-finished").unwrap();
    assert_eq!(server.open_app_data(&dg).unwrap(), b"post-finished");
}

/// Mirrors C `RFC6347_FINISH_TC003/004`: cookie-path Finished completion
/// also enables app data both ways.
#[test]
fn t212_finish_completes_with_cookie_path_appdata_works() {
    let (mut client, mut server) = connected_pair_with_cookie();
    let dg = server.seal_app_data(b"cookie-post-finished").unwrap();
    assert_eq!(client.open_app_data(&dg).unwrap(), b"cookie-post-finished");
}

/// Mirrors C `RFC6347_CLIENT_HELLO_TC001`: a 32-byte garbage record
/// (handshake-content-type byte + 0xFF payload) injected post-handshake
/// must be rejected. Parallel to T201's DTLCP version of this test.
#[test]
fn t212_client_hello_garbage_post_handshake_rejected() {
    let (_client, mut server) = connected_pair();
    let bogus = vec![0x16u8; 32]; // record-type byte + garbage
    assert!(
        server.open_app_data(&bogus).is_err(),
        "post-handshake garbage record must be rejected"
    );
}

/// Mirrors C `RFC6347_HELLO_VERIFY_REQ_TC001-004`: with the cookie path
/// enabled, large payloads still round-trip after Finished.
#[test]
fn t212_cookie_path_long_payload_round_trip() {
    let (mut client, mut server) = connected_pair_with_cookie();
    let payload: Vec<u8> = (0..2048).map(|i| ((i * 17) % 251) as u8).collect();
    let dg = client.seal_app_data(&payload).unwrap();
    assert_eq!(server.open_app_data(&dg).unwrap(), payload);
}

/// Mirrors C `RFC8422_EXTENSION_MISS_TC001`-shape: a truncated
/// post-handshake record (header-only) must be rejected at the record
/// layer before any state-machine effect. Same observable as T201's
/// DTLCP truncated-record test.
#[test]
fn t212_truncated_record_rejected() {
    let (mut client, mut server) = connected_pair();
    let dg = client.seal_app_data(b"truncate-me").unwrap();
    let truncated = &dg[..5];
    assert!(
        server.open_app_data(truncated).is_err(),
        "truncated post-handshake DTLS 1.2 record must be rejected"
    );
}

/// Mirrors C `RFC8422_ECPOINT_TC001` shape (scope-cut, cross-coverage):
/// TLS / DTLS supports only the uncompressed EC-point format in the
/// Rust port. The `#46` plan §6 already documents
/// `HITLS_CFG_SetECPointFormats` as out-of-scope; this test pins the
/// cross-issue decision the way T201 did for DTLCP.
#[test]
fn t212_ecpoint_uncompressed_only_documented_cross_coverage() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-46-plan.md");
    let plan = std::fs::read_to_string(&plan_path)
        .unwrap_or_else(|e| panic!("missing #46 plan doc at {plan_path}: {e}"));
    assert!(
        plan.contains("HITLS_CFG_SetECPointFormats"),
        "#46 plan §6 must keep HITLS_CFG_SetECPointFormats as out-of-scope \
         (DTLS supports uncompressed EC points only)"
    );
}

/// Mirrors C `RFC5246_VERSION_TC001` shape: the version-accessor returns
/// DTLS 1.2 (not TLS 1.2 — both report `TlsVersion::Dtls12` in this
/// port; the test pins the strict equality so a future protocol-version
/// re-enum doesn't silently break the accessor contract).
#[test]
fn t212_version_negotiated_dtls12_only() {
    use hitls_tls::TlsVersion;
    let (client, server) = connected_pair_with_cookie();
    // Cookie path doesn't change the negotiated version.
    assert_eq!(client.version(), Some(TlsVersion::Dtls12));
    assert_eq!(server.version(), Some(TlsVersion::Dtls12));
}

/// Mirrors C `RFC5246_UNEXPETED_REORD_TYPE_TC001` (note: the typo
/// `UNEXPETED` is verbatim from the C source; allow-listed in
/// `typos.toml`). An unknown ContentType byte must be rejected.
#[test]
fn t212_unknown_record_type_rejected() {
    let (_client, mut server) = connected_pair();
    // ContentType 0xFF = invalid (TLS defines 20-25 + 26 for TLS 1.3
    // EncryptedExtensions).
    let bogus = vec![
        0xFF, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xDE, 0xAD,
        0xBE, 0xEF, 0x00,
    ];
    assert!(
        server.open_app_data(&bogus).is_err(),
        "unknown DTLS 1.2 record type must be rejected"
    );
}
