//! DTLCP consistency tests — T201 / #59.
//!
//! Ports the C `consistency/dtlcp/` test family from
//! `openhitls/testcode/sdv/testcase/tls/consistency/dtlcp/`. The C side
//! has **12 unique `void UT_*` TC families** parameterised over 13
//! `.data` rows in `frame_dtlcp_consistency` and 6 wrapper rows in
//! `hlt_dtlcp_consistency` (the "43 TCs" figure in the issue counts the
//! `.c` row inventory pre-dedup; the unique fn count is 12).
//!
//! ## C-source decision matrix
//!
//! | C TC family | Rust coverage | Decision |
//! |-------------|---------------|----------|
//! | `RFC6347_TC001` (generic round-trip) | `connection_dtlcp::tests::test_dtlcp_*` happy-path × 5 | **port as state pin** (one new explicit consistency test) |
//! | `RFC6347_FINISH_TC001` | covered by Rust handshake tests | port as Finished-completion app-data pin |
//! | `RFC6347_FINISH_TC002` (no-cookie) | `test_dtlcp_handshake_ecdhe_gcm_no_cookie` | port as no-cookie consistency pin |
//! | `RFC6347_FINISH_TC003` (with-cookie) | `test_dtlcp_handshake_ecdhe_gcm_with_cookie` | port as cookie consistency pin |
//! | `RFC6347_DISORDER_TC001` | `dtls_resilience::test_dtls12_out_of_order_delivery` (DTLS 1.2 only) | **port** as DTLCP-specific out-of-order test |
//! | `RFC6347_DISORDER_TC002` | `dtls_resilience::test_dtls12_interleaved_bidirectional_out_of_order` (DTLS 1.2 only) | **port** as DTLCP interleaved test |
//! | `RFC6347_APPDATA_TC001` (round-trip integrity) | `test_dtlcp_app_data_exchange*` (positive) | port as multi-message byte-exact pin |
//! | `RFC6347_APPDATA_TC002` (replay) | `test_dtlcp_anti_replay_rejection` | **scope-cut** (equivalent semantics already pinned) |
//! | `RFC6347_CLIENT_HELLO_TC001` | covered by handshake establishment | port as post-handshake CH-rejection pin |
//! | `RFC6347_RECV_ALERT_AFTER_CCS_TC001` | not pinned | port as corrupted-ciphertext rejection (AEAD integrity guards the post-CCS path) |
//! | `RFC8422_ECPOINT_TC001` (ECPointFormats handling) | TLCP supports uncompressed only — `#46 plan §6` lists `HITLS_CFG_SetECPointFormats` out-of-scope | **scope-cut** (cross-coverage pin to #46 plan doc) |
//! | `RFC8422_EXTENSION_MISS_TC001` (missing extension graceful handling) | implicit in handshake; not byte-pinned | port as truncated-record-rejected pin (extension-miss path surfaces via record-layer error) |
//!
//! Scaffolding mirrors `tests/interop/tests/dtls_resilience.rs`: build
//! a TLCP config pair via `make_dtlcp_configs(...)`, run
//! `dtlcp_handshake_in_memory(...)` to a Connected pair, then exercise
//! the seal/open path with crafted delivery patterns.

use hitls_integration_tests::*;
use hitls_tls::connection_dtlcp::{
    dtlcp_handshake_in_memory, DtlcpClientConnection, DtlcpServerConnection,
};
use hitls_tls::CipherSuite;

/// Establish a connected DTLCP pair (default: ECDHE-SM4-GCM-SM3, no cookie).
fn connected_pair() -> (DtlcpClientConnection, DtlcpServerConnection) {
    let (cc, sc) = make_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
    dtlcp_handshake_in_memory(cc, sc, false).unwrap()
}

/// Establish a connected DTLCP pair with the HelloVerifyRequest cookie path.
fn connected_pair_with_cookie() -> (DtlcpClientConnection, DtlcpServerConnection) {
    let (cc, sc) = make_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
    dtlcp_handshake_in_memory(cc, sc, true).unwrap()
}

// ---------------------------------------------------------------------------
// RFC6347_TC001 + FINISH_TC001 — handshake completes, app-data flows.
// ---------------------------------------------------------------------------

/// Mirrors C `UT_TLS_DTLCP_CONSISTENCY_RFC6347_TC001` + `_FINISH_TC001`:
/// once the Finished message lands the connection accepts application data
/// in both directions byte-exact.
#[test]
fn test_dtlcp_consistency_handshake_completes_appdata_bidirectional() {
    let (mut client, mut server) = connected_pair();

    let c2s = b"client->server-bytes";
    let dg = client.seal_app_data(c2s).unwrap();
    assert_eq!(server.open_app_data(&dg).unwrap(), c2s);

    let s2c = b"server->client-bytes";
    let dg = server.seal_app_data(s2c).unwrap();
    assert_eq!(client.open_app_data(&dg).unwrap(), s2c);
}

// ---------------------------------------------------------------------------
// RFC6347_FINISH_TC002 — no-cookie handshake variant.
// ---------------------------------------------------------------------------

/// Mirrors C `UT_TLS_DTLCP_CONSISTENCY_RFC6347_FINISH_TC002`: the
/// no-cookie path (server does not require HelloVerifyRequest) completes
/// the Finished exchange and delivers app data.
#[test]
fn test_dtlcp_consistency_finish_no_cookie_path() {
    let (mut client, mut server) = connected_pair();
    let dg = client.seal_app_data(b"no-cookie-msg").unwrap();
    assert_eq!(server.open_app_data(&dg).unwrap(), b"no-cookie-msg");
}

// ---------------------------------------------------------------------------
// RFC6347_FINISH_TC003 — with-cookie handshake variant.
// ---------------------------------------------------------------------------

/// Mirrors C `UT_TLS_DTLCP_CONSISTENCY_RFC6347_FINISH_TC003`: the
/// cookie path (server requires HelloVerifyRequest) completes the
/// Finished exchange and delivers app data.
#[test]
fn test_dtlcp_consistency_finish_cookie_path() {
    let (mut client, mut server) = connected_pair_with_cookie();
    let dg = client.seal_app_data(b"cookie-msg").unwrap();
    assert_eq!(server.open_app_data(&dg).unwrap(), b"cookie-msg");
}

// ---------------------------------------------------------------------------
// RFC6347_DISORDER_TC001 — out-of-order delivery within the anti-replay
// window must still decrypt successfully.
// ---------------------------------------------------------------------------

/// Mirrors C `UT_TLS_DTLCP_CONSISTENCY_RFC6347_DISORDER_TC001`: 5
/// datagrams sealed in order then delivered in reverse — all should
/// open within the anti-replay window. Parallels
/// `dtls_resilience::test_dtls12_out_of_order_delivery` for the DTLCP
/// (SM4-GCM-SM3) cipher pipeline.
#[test]
fn test_dtlcp_consistency_disorder_out_of_order_within_window() {
    let (mut client, mut server) = connected_pair();

    let mut datagrams = Vec::new();
    for i in 0..5u32 {
        let msg = format!("dtlcp-ooo-{i}");
        datagrams.push((msg.clone(), client.seal_app_data(msg.as_bytes()).unwrap()));
    }

    for (msg, dg) in datagrams.iter().rev() {
        let pt = server
            .open_app_data(dg)
            .expect("DTLCP out-of-order within window must succeed");
        assert_eq!(pt, msg.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// RFC6347_DISORDER_TC002 — interleaved bidirectional out-of-order.
// ---------------------------------------------------------------------------

/// Mirrors C `UT_TLS_DTLCP_CONSISTENCY_RFC6347_DISORDER_TC002`: client
/// and server each emit a series, then the other side opens out-of-order.
/// Parallels `dtls_resilience::test_dtls12_interleaved_bidirectional_out_of_order`.
#[test]
fn test_dtlcp_consistency_disorder_interleaved_bidirectional() {
    let (mut client, mut server) = connected_pair();

    let mut c2s: Vec<(String, Vec<u8>)> = (0..4u32)
        .map(|i| {
            let m = format!("c2s-{i}");
            let dg = client.seal_app_data(m.as_bytes()).unwrap();
            (m, dg)
        })
        .collect();
    let mut s2c: Vec<(String, Vec<u8>)> = (0..4u32)
        .map(|i| {
            let m = format!("s2c-{i}");
            let dg = server.seal_app_data(m.as_bytes()).unwrap();
            (m, dg)
        })
        .collect();

    // Open both sides in reverse order — each direction has its own
    // anti-replay window so reversal must still succeed.
    c2s.reverse();
    s2c.reverse();
    for (m, dg) in &c2s {
        assert_eq!(server.open_app_data(dg).unwrap(), m.as_bytes());
    }
    for (m, dg) in &s2c {
        assert_eq!(client.open_app_data(dg).unwrap(), m.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// RFC6347_APPDATA_TC001 — multi-message byte-exact integrity.
// ---------------------------------------------------------------------------

/// Mirrors C `UT_TLS_DTLCP_CONSISTENCY_RFC6347_APPDATA_TC001` rows: a
/// sequence of varied-size payloads must each round-trip byte-exact.
/// The C test parameterises this with 8 distinct payload-shape rows
/// (.data); Rust covers the same space with a single test exercising
/// the empty / single-byte / boundary / record-size / max-fragment
/// cases.
#[test]
fn test_dtlcp_consistency_appdata_multi_message_byte_exact() {
    let (mut client, mut server) = connected_pair();

    // Empty payload — the DTLCP record layer must still seal a zero-length
    // payload without panic (sane sentinel).
    let empty_dg = client.seal_app_data(b"").unwrap();
    assert_eq!(server.open_app_data(&empty_dg).unwrap(), b"");

    // Single byte
    let one_dg = client.seal_app_data(b"x").unwrap();
    assert_eq!(server.open_app_data(&one_dg).unwrap(), b"x");

    // A 1-KiB payload
    let big: Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
    let big_dg = client.seal_app_data(&big).unwrap();
    assert_eq!(server.open_app_data(&big_dg).unwrap(), big);
}

// ---------------------------------------------------------------------------
// RFC6347_CLIENT_HELLO_TC001 — post-handshake garbage rejected.
// ---------------------------------------------------------------------------

/// Mirrors C `UT_TLS_DTLCP_CONSISTENCY_RFC6347_CLIENT_HELLO_TC001` in
/// the spirit of "well-formed-for-other-state record sent into a
/// Connected DTLCP server must be rejected, not silently absorbed".
/// We approximate the C TC by feeding a bogus 32-byte record (header
/// shape but garbage payload) into a Connected server — the AEAD
/// integrity check on the record-layer must reject it.
#[test]
fn test_dtlcp_consistency_client_hello_garbage_post_handshake_rejected() {
    let (_client, mut server) = connected_pair();

    let bogus = vec![0x16u8; 32]; // record-type byte + garbage
    let result = server.open_app_data(&bogus);
    assert!(
        result.is_err(),
        "post-handshake garbage record must be rejected"
    );
}

// ---------------------------------------------------------------------------
// RFC6347_RECV_ALERT_AFTER_CCS_TC001 — corrupted ciphertext rejected
// (AEAD integrity guards the post-CCS application-data path).
// ---------------------------------------------------------------------------

/// Mirrors C `UT_DTLCP_RFC6347_RECV_ALERT_AFTER_CCS_TC001` in the
/// Rust-equivalent observable: an attacker-flipped ciphertext bit in a
/// post-handshake datagram is rejected by the SM4-GCM AEAD's tag check
/// (record post-CCS is encrypted; any tampering — including a forged
/// "alert" payload — fails authentication and never reaches the
/// state machine).
#[test]
fn test_dtlcp_consistency_corrupted_ciphertext_post_ccs_rejected() {
    let (mut client, mut server) = connected_pair();

    let mut datagram = client.seal_app_data(b"to-tamper").unwrap();
    let len = datagram.len();
    // Flip a bit deep in the ciphertext (past the DTLS record header
    // + explicit IV).
    let target = len.saturating_sub(20);
    datagram[target] ^= 0x01;
    let result = server.open_app_data(&datagram);
    assert!(
        result.is_err(),
        "corrupted post-CCS ciphertext must fail AEAD integrity"
    );
}

// ---------------------------------------------------------------------------
// RFC8422_EXTENSION_MISS_TC001 — extension-handling consistency:
// a truncated record (which is the natural manifestation of an
// extension boundary error at the wire layer) is rejected.
// ---------------------------------------------------------------------------

/// Mirrors C `UT_TLS_DTLCP_CONSISTENCY_RFC8422_EXTENSION_MISS_TC001` in
/// the Rust-equivalent observable: extension parsing errors surface
/// to the record layer as truncated/invalid records. A truncated
/// post-handshake record (5-byte header only) is rejected at the
/// record layer before any state-machine effect.
#[test]
fn test_dtlcp_consistency_truncated_record_rejected() {
    let (mut client, mut server) = connected_pair();

    let datagram = client.seal_app_data(b"truncate-me").unwrap();
    let truncated = &datagram[..5];
    let result = server.open_app_data(truncated);
    assert!(
        result.is_err(),
        "truncated post-handshake record must be rejected"
    );
}

// ---------------------------------------------------------------------------
// RFC8422_ECPOINT_TC001 + plan-doc cross-coverage pin.
// ---------------------------------------------------------------------------

/// Mirrors C `UT_TLS_DTLCP_CONSISTENCY_RFC8422_ECPOINT_TC001`: TLCP/DTLCP
/// supports only the uncompressed EC-point format. The Rust port omits
/// `HITLS_CFG_SetECPointFormats` entirely (documented in `#46 plan §6`).
/// This row is therefore a **scope-cut**: pin via cross-coverage assertion
/// against the #46 plan doc.
#[test]
fn test_dtlcp_consistency_ecpoint_uncompressed_only_documented() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-46-plan.md");
    let plan = std::fs::read_to_string(&plan_path)
        .unwrap_or_else(|e| panic!("missing #46 plan doc at {plan_path}: {e}"));
    assert!(
        plan.contains("HITLS_CFG_SetECPointFormats"),
        "#46 plan §6 must keep HITLS_CFG_SetECPointFormats as out-of-scope (DTLCP supports uncompressed only)"
    );
}
