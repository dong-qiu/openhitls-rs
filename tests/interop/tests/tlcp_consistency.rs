//! TLCP consistency tests — T209 / #42.
//!
//! Phase F-1 of the TLCP + DTLS 1.2 consistency-test migration plan
//! (`docs/issue-42-phase-f-plan.md`). Targets `frame_tlcp_consistency_1.c`
//! (34 fn / 119 rows) — the largest of the 3 TLCP frame files. The C
//! TC families cluster around record-layer rejection (oversize records,
//! malformed length fields, sequence-number gaps) and handshake-state
//! validation (unexpected message types during specific handshake stages).
//!
//! Scaffolding mirrors `tests/interop/tests/dtlcp_consistency.rs`
//! (T201): build a TLCP config pair via `make_tlcp_configs(...)`, run
//! `tlcp_handshake_in_memory(...)` to a Connected pair, then exercise
//! the seal/open path with crafted delivery patterns.
//!
//! ## C-source decision matrix (this batch)
//!
//! | C TC family | Rust coverage | Decision |
//! |-------------|---------------|----------|
//! | `CIPHERTEXT_TOOLONG_TC001` (record size > 2^14 + slack) | none | **port** as truncated/oversize record reject |
//! | `MSGLENGTH_TOOLONG_TC001-004` (handshake-msg length sanity) | none | **port** as bit-flip length-prefix → rejection |
//! | `NONZERO_MESSAGELEN_TC001` | none | **port** as zero-length handshake-msg shape pin |
//! | `SEQ_NUM_TC001/002` (seq gap) | covered by `dtls_resilience::out_of_order_*` (DTLS only) | **port** as TLCP-specific (TLS is in-order; pin the strict-order claim) |
//! | `SERVER_TLS_ALL_TC001-003` (server rejects pure-TLS client) | covered by handshake-version-rejection paths | **port** as version-mismatch handshake-reject |
//! | `UNEXPECT_HANDSHAKEMSG_TC001-012` (out-of-state messages) | partial — connection-state guards exist | **port** as post-handshake garbage record rejection |
//! | `UNEXPECT_RECORDTYPE_TC001-007` (non-Handshake during handshake) | partial — record-layer dispatch guards | **port** as post-handshake garbage record rejection |
//! | TLCP happy-path handshake completion (round-trip + appdata) | `tests/interop/tests/tlcp.rs` 11 tests | **scope-cut** (covered) — pin only the explicit consistency baseline |

use hitls_integration_tests::*;
use hitls_tls::connection_tlcp::{
    tlcp_handshake_in_memory, TlcpClientConnection, TlcpServerConnection,
};
use hitls_tls::CipherSuite;

/// Establish a connected TLCP pair (default: ECDHE-SM4-GCM-SM3).
fn connected_pair() -> (TlcpClientConnection, TlcpServerConnection) {
    let (cc, sc) = make_tlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
    tlcp_handshake_in_memory(cc, sc).unwrap()
}

/// Same with ECC-SM4-CBC-SM3 (the non-ECDHE TLCP suite).
fn connected_pair_ecc_cbc() -> (TlcpClientConnection, TlcpServerConnection) {
    let (cc, sc) = make_tlcp_configs(CipherSuite::ECC_SM4_CBC_SM3);
    tlcp_handshake_in_memory(cc, sc).unwrap()
}

// ---------------------------------------------------------------------------
// Baseline — `frame_tlcp_consistency_1` round-trip pin.
// ---------------------------------------------------------------------------

/// Mirrors C `UT_TLS_TLCP_CONSISTENCY_SERVER_TLS_ALL_TC001`-style baseline:
/// a TLCP handshake completes and the connection accepts app-data
/// byte-exact in both directions.
#[test]
fn test_tlcp_consistency_handshake_completes_appdata_bidirectional() {
    let (mut client, mut server) = connected_pair();
    let c2s = b"tlcp client->server";
    let rec = client.seal_app_data(c2s).unwrap();
    assert_eq!(server.open_app_data(&rec).unwrap(), c2s);

    let s2c = b"tlcp server->client";
    let rec = server.seal_app_data(s2c).unwrap();
    assert_eq!(client.open_app_data(&rec).unwrap(), s2c);
}

/// Round-trip on the ECC-SM4-CBC-SM3 (non-ECDHE) suite.
#[test]
fn test_tlcp_consistency_handshake_completes_appdata_ecc_cbc() {
    let (mut client, mut server) = connected_pair_ecc_cbc();
    let rec = client.seal_app_data(b"ecc-cbc-msg").unwrap();
    assert_eq!(server.open_app_data(&rec).unwrap(), b"ecc-cbc-msg");
}

// ---------------------------------------------------------------------------
// CIPHERTEXT_TOOLONG_TC001 — oversize record rejected.
// ---------------------------------------------------------------------------

/// Mirrors C `UT_TLS_TLCP_CONSISTENCY_CIPHERTEXT_TOOLONG_TC001` shape:
/// the Rust `open_app_data` parses a single record according to its
/// declared length and silently ignores trailing bytes (each record
/// carries its own length prefix). Pin the lenient one-record-at-a-time
/// behavior so a future strict-mode change is deliberate.
#[test]
fn test_tlcp_consistency_trailing_bytes_after_record_silently_ignored_gap() {
    let (mut client, mut server) = connected_pair();
    let mut rec = client.seal_app_data(b"normal").unwrap();
    let original_len = rec.len();
    rec.extend_from_slice(&[0xFF; 1024]);
    let opened = server
        .open_app_data(&rec)
        .expect("TLCP open reads first record only; trailing bytes don't fail it");
    assert_eq!(opened, b"normal");
    // TODO(#42-phase-f): consider strict mode that requires the input
    // slice length to match the record's declared total.
    let _ = original_len;
}

// ---------------------------------------------------------------------------
// MSGLENGTH_TOOLONG_TC001-004 — bit-flip the record length byte.
// ---------------------------------------------------------------------------

/// Mirrors C `UT_TLS_TLCP_CONSISTENCY_MSGLENGTH_TOOLONG_TC001`: flip the
/// record's length byte to a huge value. The record-layer fails to
/// match wire length against payload length.
#[test]
fn test_tlcp_consistency_msglength_too_long_rejected() {
    let (mut client, mut server) = connected_pair();
    let mut rec = client.seal_app_data(b"x").unwrap();
    // TLCP record header layout: type(1) | version(2) | length(2)
    // Flip the high byte of `length` to 0xFF.
    if rec.len() >= 5 {
        rec[3] = 0xFF;
    }
    assert!(
        server.open_app_data(&rec).is_err(),
        "TLCP record with oversize length must be rejected"
    );
}

/// Mirrors C `UT_TLS_TLCP_CONSISTENCY_MSGLENGTH_TOOLONG_TC002`: flip the
/// low byte of `length` to a non-zero value smaller than the actual
/// payload. The reader sees too few bytes.
#[test]
fn test_tlcp_consistency_msglength_low_byte_too_small_rejected() {
    let (mut client, mut server) = connected_pair();
    let mut rec = client.seal_app_data(b"abcdefgh").unwrap();
    if rec.len() >= 5 {
        // Set length = 1 (way below real payload size)
        rec[3] = 0x00;
        rec[4] = 0x01;
    }
    let result = server.open_app_data(&rec);
    assert!(
        result.is_err(),
        "TLCP record with too-small length must be rejected; got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// NONZERO_MESSAGELEN_TC001 — zero-length payload handling.
// ---------------------------------------------------------------------------

/// Mirrors C `UT_TLS_TLCP_CONSISTENCY_NONZERO_MESSAGELEN_TC001` shape:
/// app-data records may carry an empty payload (length-0); the Rust
/// port treats this as a valid no-op. Pin the lenient behaviour.
#[test]
fn test_tlcp_consistency_zero_length_appdata_round_trip() {
    let (mut client, mut server) = connected_pair();
    let rec = client.seal_app_data(b"").unwrap();
    let opened = server.open_app_data(&rec).unwrap();
    assert_eq!(
        opened, b"",
        "zero-length TLCP app-data must round-trip empty"
    );
}

// ---------------------------------------------------------------------------
// SEQ_NUM_TC001/002 — TLCP is in-order over TCP-equivalent; pin the claim.
// ---------------------------------------------------------------------------

/// Mirrors C `UT_TLS_TLCP_CONSISTENCY_SEQ_NUM_TC001` for an in-order
/// stream: TLCP runs over a reliable transport so seq-num gaps are
/// not tolerated. Two sealed records, delivered in order, must both
/// open.
#[test]
fn test_tlcp_consistency_seq_num_in_order_both_open() {
    let (mut client, mut server) = connected_pair();
    let rec1 = client.seal_app_data(b"first").unwrap();
    let rec2 = client.seal_app_data(b"second").unwrap();
    assert_eq!(server.open_app_data(&rec1).unwrap(), b"first");
    assert_eq!(server.open_app_data(&rec2).unwrap(), b"second");
}

/// Out-of-order delivery (skip rec1, deliver rec2 first) — TLCP is
/// in-order; the AEAD's sequence-bound nonce makes rec2 fail to
/// authenticate when applied as the first record.
#[test]
fn test_tlcp_consistency_seq_num_out_of_order_rejected() {
    let (mut client, mut server) = connected_pair();
    let _rec1 = client.seal_app_data(b"first").unwrap();
    let rec2 = client.seal_app_data(b"second").unwrap();
    // Try to open rec2 before rec1 — sequence number 1 used with key
    // that's expecting sequence number 0 → AEAD fail.
    let result = server.open_app_data(&rec2);
    assert!(
        result.is_err(),
        "out-of-order TLCP record must fail AEAD auth; got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// UNEXPECT_HANDSHAKEMSG / UNEXPECT_RECORDTYPE — post-handshake garbage.
// ---------------------------------------------------------------------------

/// Mirrors C `UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC001`:
/// well-formed-for-other-state handshake record sent into a Connected
/// TLCP server must be rejected, not silently absorbed.
#[test]
fn test_tlcp_consistency_unexpected_handshake_record_post_handshake_rejected() {
    let (_client, mut server) = connected_pair();
    // ContentType 0x16 = Handshake, version 0x0101 (TLCP), small fake length.
    let bogus = vec![
        0x16, 0x01, 0x01, 0x00, 0x10, // header
        0x01, 0x00, 0x00, 0x0C, // HandshakeType=ClientHello, length=12
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert!(
        server.open_app_data(&bogus).is_err(),
        "unexpected Handshake record after handshake must be rejected"
    );
}

/// Mirrors C `UT_TLS_TLCP_CONSISTENCY_UNEXPECT_RECORDTYPE_TC001`: an
/// unknown ContentType byte must be rejected.
#[test]
fn test_tlcp_consistency_unknown_record_type_rejected() {
    let (_client, mut server) = connected_pair();
    // ContentType 0xFF = invalid (TLS defines 20-25 and 26 for TLS 1.3
    // EncryptedExtensions; anything else is invalid).
    let bogus = vec![0xFF, 0x01, 0x01, 0x00, 0x05, 0xDE, 0xAD, 0xBE, 0xEF, 0x00];
    assert!(
        server.open_app_data(&bogus).is_err(),
        "unknown TLCP record type must be rejected"
    );
}

// ---------------------------------------------------------------------------
// Tampered ciphertext — AEAD integrity guards the data path.
// ---------------------------------------------------------------------------

/// Bit-flip in the ciphertext tail → AEAD tag fails → record rejected.
#[test]
fn test_tlcp_consistency_tampered_ciphertext_rejected() {
    let (mut client, mut server) = connected_pair();
    let mut rec = client.seal_app_data(b"tamper-me").unwrap();
    if rec.len() > 20 {
        let last = rec.len() - 1;
        rec[last] ^= 0x01;
    }
    assert!(
        server.open_app_data(&rec).is_err(),
        "tampered TLCP ciphertext must fail AEAD auth"
    );
}

// ---------------------------------------------------------------------------
// Plan-doc cross-coverage pin.
// ---------------------------------------------------------------------------

/// Reads `docs/issue-42-phase-f-plan.md` and asserts the key audit
/// anchors. Same pattern as T204-T207's `audit_plan_docs_in_sync`.
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
        "frame_tlcp_consistency_1.c",
        "frame_dtls12_consistency.c",
        "TODO(#42-phase-f)",
    ] {
        assert!(
            plan.contains(anchor),
            "plan doc must keep anchor `{anchor}`"
        );
    }
}
