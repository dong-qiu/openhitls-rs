// Phase M-4 (T280) — DTLS 1.3 (RFC 9147) record-format wire pins.
//
// WP-C of docs/issue-42-residual-closure-plan.md scopes M-4 as "DTLS 1.3 UDP
// rogue server". A *full* UDP rogue server (M-1/M-2/M-3 style over UDP with
// flight reassembly + retransmission) is disproportionate here for two reasons:
//
//   1. **No C migration source.** The openHiTLS C SDV has DTLS *1.2* and DTLCP
//      consistency suites but **no DTLS 1.3** suite — there are no C
//      `MODIFIED_*` rows to reproduce against a DTLS 1.3 wire alert.
//   2. **The record layer is already unit-tested** (13 tests across
//      `record/dtls13.rs` + `record/encryption_dtls13.rs`).
//
// Per the plan's scope-cut guidance ("先 wire-format pin (参照 T227)"), M-4
// instead pins the RFC 9147 §4 DTLSPlaintext record format at the *integration*
// level via the public record codec — the exact substrate a future full UDP
// rogue server would compose. The full UDP driver remains deferred (no C data).

use hitls_tls::record::dtls13::{
    build_aad_dtls13, parse_dtls13_record, serialize_dtls13_record, Dtls13EpochState, Dtls13Record,
    EPOCH_HANDSHAKE, EPOCH_INITIAL,
};
use hitls_tls::record::ContentType;

fn sample_record() -> Dtls13Record {
    Dtls13Record {
        content_type: ContentType::Handshake,
        epoch: EPOCH_HANDSHAKE,
        sequence_number: 0x01_02_03_04_05,
        fragment: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee],
    }
}

/// RFC 9147 §4: serialize → parse round-trips all DTLSPlaintext fields.
#[test]
fn m280_dtls13_record_serialize_parse_roundtrip() {
    let rec = sample_record();
    let wire = serialize_dtls13_record(&rec);
    let (parsed, consumed) = parse_dtls13_record(&wire).expect("parse");
    assert_eq!(consumed, wire.len());
    assert_eq!(parsed.content_type as u8, rec.content_type as u8);
    assert_eq!(parsed.epoch, rec.epoch);
    assert_eq!(parsed.sequence_number, rec.sequence_number);
    assert_eq!(parsed.fragment, rec.fragment);
}

/// RFC 9147 §4: the 13-byte DTLSPlaintext header layout —
/// content_type(1) || version(2) || epoch(2) || sequence(6) || length(2).
#[test]
fn m280_dtls13_record_header_layout() {
    let rec = sample_record();
    let wire = serialize_dtls13_record(&rec);
    assert_eq!(wire.len(), 13 + rec.fragment.len());
    assert_eq!(wire[0], rec.content_type as u8); // content_type
    assert_eq!(u16::from_be_bytes([wire[3], wire[4]]), rec.epoch); // epoch
                                                                   // 6-byte sequence number (big-endian, low 48 bits)
    let seq = u64::from_be_bytes([0, 0, wire[5], wire[6], wire[7], wire[8], wire[9], wire[10]]);
    assert_eq!(seq, rec.sequence_number);
    assert_eq!(
        u16::from_be_bytes([wire[11], wire[12]]) as usize,
        rec.fragment.len()
    ); // length
}

/// RFC 9147 §4: the AEAD AAD equals the 13-byte record header (with the
/// plaintext length), i.e. `build_aad_dtls13` == `serialize(..)[..13]`.
#[test]
fn m280_dtls13_aad_equals_record_header() {
    let rec = sample_record();
    let wire = serialize_dtls13_record(&rec);
    let aad = build_aad_dtls13(
        rec.content_type,
        rec.epoch,
        rec.sequence_number,
        rec.fragment.len() as u16,
    );
    assert_eq!(&aad[..], &wire[..13]);
}

/// A truncated record header (< 13 bytes) must be rejected.
#[test]
fn m280_dtls13_record_truncated_header_rejected() {
    assert!(parse_dtls13_record(&[22, 0xfe, 0xfc, 0x00]).is_err());
}

/// A record claiming more body than is present must be rejected.
#[test]
fn m280_dtls13_record_short_body_rejected() {
    let mut wire = serialize_dtls13_record(&sample_record());
    // Bump the declared length beyond the actual fragment.
    wire[11] = 0xff;
    wire[12] = 0xff;
    assert!(parse_dtls13_record(&wire).is_err());
}

/// An unknown content type must be rejected.
#[test]
fn m280_dtls13_record_unknown_content_type_rejected() {
    let mut wire = serialize_dtls13_record(&sample_record());
    wire[0] = 0x99; // not 20/21/22/23
    assert!(parse_dtls13_record(&wire).is_err());
}

/// RFC 9147 §4.2.2: the per-epoch sequence counter increments and resets to 0
/// when the epoch advances.
#[test]
fn m280_dtls13_epoch_seq_increment_and_reset() {
    let mut state = Dtls13EpochState::new(EPOCH_INITIAL);
    assert_eq!(state.epoch(), 0);
    assert_eq!(state.next_write_seq().unwrap(), 0);
    assert_eq!(state.next_write_seq().unwrap(), 1);
    state.set_epoch(EPOCH_HANDSHAKE);
    assert_eq!(state.epoch(), EPOCH_HANDSHAKE);
    assert_eq!(state.next_write_seq().unwrap(), 0); // reset on epoch change
}

/// Phase M-4 audit pin: the residual closure plan records WP-C / DTLS 1.3.
#[test]
fn m280_audit_plan_records_dtls13() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-residual-closure-plan.md");
    let plan = std::fs::read_to_string(&plan_path).expect("residual closure plan doc");
    assert!(plan.contains("DTLS"));
}
