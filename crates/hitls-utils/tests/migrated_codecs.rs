// Phase J-5 — codecs / bsl Base64 + PEM primitive migration.
//
// Source: openHiTLS C SDV codecs/decode/test_suite_sdv_decode.{data,c}
//         + bsl/base64/test_suite_sdv_base64.* + bsl/pem/test_suite_sdv_pem.*.
//
// The C `codecs` suite is the EAL **decoder-provider framework**
// (`CRYPT_DECODE_ProviderNewCtx(..., "provider=default, inFormat=PEM,
// outFormat=ASN1")`): its rows are `(void)`-bodied / provider-CRUD with the
// data-file path args ignored (`(void)pemPath; (void)asn1Path;`). The Rust port
// has no "provider" concept — the decode capability (PEM → DER, Base64) lives
// natively in `hitls_utils::{pem, base64}`. So the provider-framework rows route
// to API-surface (architecturally N/A); the underlying Base64 / PEM *codec*
// behaviour is what this file migrates.
//
// The C `bsl/base64` + `bsl/pem` suites carry **empty data rows** (the vectors
// are inline in the `.c`). The standard those codecs implement is RFC 4648, so
// this file migrates the RFC 4648 §10 canonical Base64 vectors (an independent
// third-party KAT, byte-exact) against `hitls_utils::base64`, plus a PEM
// round-trip against `hitls_utils::pem`. This is the byte-exact codec layer the
// C bsl/codecs Base64+PEM tests exercise. (The remaining bsl families — SAL
// file/socket/time/atomic/dl, uio, list, hash table, err, log — are C system /
// memory-model layers replaced by the Rust std library; see Phase J closeout.)

use hitls_utils::base64;
use hitls_utils::pem;

/// RFC 4648 §10 canonical Base64 test vectors: `(plaintext, base64)`.
const RFC4648_VECTORS: &[(&str, &str)] = &[
    ("", ""),
    ("f", "Zg=="),
    ("fo", "Zm8="),
    ("foo", "Zm9v"),
    ("foob", "Zm9vYg=="),
    ("fooba", "Zm9vYmE="),
    ("foobar", "Zm9vYmFy"),
];

/// Base64 encode matches the RFC 4648 §10 vectors byte-exact.
#[test]
fn tc_base64_encode_rfc4648() {
    for (plain, b64) in RFC4648_VECTORS {
        assert_eq!(
            base64::encode(plain.as_bytes()),
            *b64,
            "encode({plain:?}) must equal {b64:?}"
        );
    }
}

/// Base64 decode matches the RFC 4648 §10 vectors byte-exact.
#[test]
fn tc_base64_decode_rfc4648() {
    for (plain, b64) in RFC4648_VECTORS {
        assert_eq!(
            base64::decode(b64).unwrap(),
            plain.as_bytes(),
            "decode({b64:?}) must equal {plain:?}"
        );
    }
}

/// Encode → decode round-trips for a range of byte lengths (exercises all three
/// Base64 padding cases: 0, 1, 2 trailing `=`).
#[test]
fn tc_base64_roundtrip_all_pad_lengths() {
    for len in 0..=24usize {
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + 1) as u8).collect();
        let encoded = base64::encode(&data);
        assert_eq!(
            base64::decode(&encoded).unwrap(),
            data,
            "round-trip len={len}"
        );
    }
}

/// Malformed Base64 (invalid alphabet character) is rejected.
#[test]
fn tc_base64_decode_invalid_char_rejected() {
    assert!(base64::decode("Zm9v*g==").is_err());
}

/// PEM encode → parse round-trip: the label and the decoded DER bytes survive
/// (this is the PEM → ASN.1/DER decode the C codecs provider framework performs
/// natively in the Rust port).
#[test]
fn tc_pem_encode_parse_roundtrip() {
    // A minimal DER SEQUENCE { INTEGER 1 } as stand-in payload.
    let der: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];
    let pem_text = pem::encode("CERTIFICATE", der);
    assert!(pem_text.starts_with("-----BEGIN CERTIFICATE-----"));

    let blocks = pem::parse(&pem_text).unwrap();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].label, "CERTIFICATE");
    assert_eq!(blocks[0].data, der);
}

/// PEM parse recovers multiple concatenated blocks in order.
#[test]
fn tc_pem_parse_multiple_blocks() {
    let a: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x0a];
    let b: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x0b];
    let text = format!(
        "{}{}",
        pem::encode("CERTIFICATE", a),
        pem::encode("PRIVATE KEY", b)
    );

    let blocks = pem::parse(&text).unwrap();
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].label, "CERTIFICATE");
    assert_eq!(blocks[0].data, a);
    assert_eq!(blocks[1].label, "PRIVATE KEY");
    assert_eq!(blocks[1].data, b);
}
