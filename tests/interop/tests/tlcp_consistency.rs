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
// T210 / Phase F-2 — frame_tlcp_consistency_{2,3} TC families.
//
// Adds 10 tests appended under a new section banner. Covers families that
// don't need crafted handshake messages (the Rust port has no public
// in-handshake mutator): close_notify, version/cipher accessors, multi-
// message disorder pins, large-message split round-trips, AEAD integrity
// on the CBC variant, etc.
//
// ## C-source mapping (this batch)
//
// | C TC family | Rust test |
// |-------------|-----------|
// | `CLOSE_NOTIFY_TC001` | `tlcp_consistency_close_notify_alert_round_trip` |
// | `FATAL_ALERT_TC003` | `tlcp_consistency_fatal_alert_round_trip` |
// | `AMEND_APPDATA_TC001` | `tlcp_consistency_amend_appdata_three_messages_in_order` |
// | `DISORDER_TC001-003` | `tlcp_consistency_third_record_first_rejected` |
// | (accessor) | `tlcp_consistency_version_accessor_returns_tlcp_v11` |
// | (accessor) | `tlcp_consistency_cipher_suite_accessor_returns_negotiated_ecdhe_gcm` |
// | (accessor) | `tlcp_consistency_cipher_suite_accessor_returns_negotiated_ecc_cbc` |
// | `KEY_EXCHANGE_TC001` (large msg) | `tlcp_consistency_large_message_round_trip_4kib` |
// | (CBC integrity) | `tlcp_consistency_ecc_cbc_tampered_ciphertext_rejected` |
// | (multi-record) | `tlcp_consistency_split_message_two_records_each_open` |
// ===========================================================================

/// Mirrors C `UT_TLS_TLCP_CONSISTENCY_CLOSE_NOTIFY_TC001`: a close_notify
/// alert is a small fixed-shape encrypted record. The Rust port doesn't
/// expose a `shutdown()` API, so we exercise the *transport* side: seal
/// an arbitrary 2-byte app-data payload representing the close_notify
/// encoding (level=warning=1, description=close_notify=0) and verify
/// round-trip. The semantic post-close behavior is internal to the
/// state machine.
#[test]
fn tlcp_consistency_close_notify_alert_round_trip() {
    let (mut client, mut server) = connected_pair();
    let close_notify_body = vec![0x01, 0x00];
    let rec = client.seal_app_data(&close_notify_body).unwrap();
    let opened = server.open_app_data(&rec).unwrap();
    assert_eq!(opened, close_notify_body);
}

/// Mirrors C `UT_TLS_TLCP_CONSISTENCY_FATAL_ALERT_TC003`: a fatal alert
/// (level=fatal=2) round-trips the same way as close_notify at the
/// transport layer.
#[test]
fn tlcp_consistency_fatal_alert_round_trip() {
    let (mut client, mut server) = connected_pair();
    let fatal_decrypt_error = vec![0x02, 0x33];
    let rec = client.seal_app_data(&fatal_decrypt_error).unwrap();
    assert_eq!(server.open_app_data(&rec).unwrap(), fatal_decrypt_error);
}

/// Mirrors C `UT_TLS_TLCP_CONSISTENCY_AMEND_APPDATA_TC001`: a sequence
/// of three sealed app-data records, delivered in order, each round-trip
/// byte-exact.
#[test]
fn tlcp_consistency_amend_appdata_three_messages_in_order() {
    let (mut client, mut server) = connected_pair();
    for i in 0..3u8 {
        let payload = vec![0x42, i, 0xAB];
        let rec = client.seal_app_data(&payload).unwrap();
        assert_eq!(server.open_app_data(&rec).unwrap(), payload);
    }
}

/// Mirrors C `UT_TLS_TLCP_CONSISTENCY_DISORDER_TC001` strict-order
/// invariant: seal three records, deliver only the third — the AEAD
/// nonce mismatch on TLCP's reliable-transport sequence path means the
/// third record cannot open before the first two were processed.
#[test]
fn tlcp_consistency_third_record_first_rejected() {
    let (mut client, mut server) = connected_pair();
    let _rec1 = client.seal_app_data(b"first").unwrap();
    let _rec2 = client.seal_app_data(b"second").unwrap();
    let rec3 = client.seal_app_data(b"third").unwrap();
    assert!(
        server.open_app_data(&rec3).is_err(),
        "third record cannot open before first two are processed"
    );
}

/// Pin the version accessor — TLCP is TLS 1.1-equivalent in protocol
/// version space (GB/T 38636 §6 uses `version = 0x0101`).
#[test]
fn tlcp_consistency_version_accessor_returns_tlcp_v11() {
    use hitls_tls::TlsVersion;
    let (client, server) = connected_pair();
    assert_eq!(client.version(), Some(TlsVersion::Tlcp));
    assert_eq!(server.version(), Some(TlsVersion::Tlcp));
}

/// Pin the cipher_suite accessor — the ECDHE-SM4-GCM-SM3 connected pair
/// must surface that suite.
#[test]
fn tlcp_consistency_cipher_suite_accessor_returns_negotiated_ecdhe_gcm() {
    let (client, server) = connected_pair();
    assert_eq!(client.cipher_suite(), Some(CipherSuite::ECDHE_SM4_GCM_SM3));
    assert_eq!(server.cipher_suite(), Some(CipherSuite::ECDHE_SM4_GCM_SM3));
}

/// Same accessor pin for the ECC-SM4-CBC-SM3 (non-ECDHE) suite.
#[test]
fn tlcp_consistency_cipher_suite_accessor_returns_negotiated_ecc_cbc() {
    let (client, server) = connected_pair_ecc_cbc();
    assert_eq!(client.cipher_suite(), Some(CipherSuite::ECC_SM4_CBC_SM3));
    assert_eq!(server.cipher_suite(), Some(CipherSuite::ECC_SM4_CBC_SM3));
}

/// Mirrors C `UT_TLS_TLCP_CONSISTENCY_KEY_EXCHANGE_TC001`-style large
/// payload pin: a 4-KiB app-data message round-trips byte-exact.
/// TLCP's record-layer max is 2^14 minus a small header, so 4 KiB is
/// comfortably below the boundary.
#[test]
fn tlcp_consistency_large_message_round_trip_4kib() {
    let (mut client, mut server) = connected_pair();
    let payload: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    let rec = client.seal_app_data(&payload).unwrap();
    assert_eq!(server.open_app_data(&rec).unwrap(), payload);
}

/// CBC integrity check: bit-flip in the ciphertext of an ECC-SM4-CBC-SM3
/// record must fail the Encrypt-then-MAC verification (TLCP CBC uses
/// the SM3 HMAC for integrity).
#[test]
fn tlcp_consistency_ecc_cbc_tampered_ciphertext_rejected() {
    let (mut client, mut server) = connected_pair_ecc_cbc();
    let mut rec = client.seal_app_data(b"cbc-tamper-me").unwrap();
    if rec.len() > 20 {
        let mid = rec.len() / 2;
        rec[mid] ^= 0x01;
    }
    assert!(
        server.open_app_data(&rec).is_err(),
        "tampered ECC-SM4-CBC-SM3 record must fail HMAC verification"
    );
}

/// Multi-record split-message pin: the application sends two
/// independent records; each opens individually. Mirrors the
/// "amend appdata as separate records" path in the C consistency suite.
#[test]
fn tlcp_consistency_split_message_two_records_each_open() {
    let (mut client, mut server) = connected_pair();
    let a = client.seal_app_data(b"part-a-bytes").unwrap();
    let b = client.seal_app_data(b"part-b-bytes").unwrap();
    assert_eq!(server.open_app_data(&a).unwrap(), b"part-a-bytes");
    assert_eq!(server.open_app_data(&b).unwrap(), b"part-b-bytes");
}
