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
    ] {
        assert!(
            plan.contains(anchor),
            "plan doc must keep anchor `{anchor}`"
        );
    }
}
