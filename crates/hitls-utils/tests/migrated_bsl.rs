// Phase J closeout — bsl (ASN.1 + OID) primitive coverage.
//
// Source: openHiTLS C SDV bsl/asn1/test_suite_sdv_asn1.* +
//         bsl/obj/test_suite_sdv_obj.*.
//
// Most of the C `bsl` suite is a system / memory-model layer with no Rust
// counterpart (architecturally N/A, see docs/c-test-na-list.md Phase-J note):
//   - SAL (file / socket / time / atomic / dl), uio, list, hash table, err,
//     log — replaced by the Rust std library.
//   - obj (OID) FUNC rows are `(void)`-bodied with inline data.
// The bsl codec primitives (ASN.1, OID) are natively implemented in
// `hitls_utils::{asn1, oid}`. This file migrates the two data-driven bsl checks
// that DO carry a reproducible vector: the ASN.1 max-depth nested-SEQUENCE
// decode (`bsl/asn1` `DECODE_TEMPLATE_DEPTH_MAX_SUCCESS` inline DER) and an OID
// DER round-trip (`bsl/obj`).

use hitls_utils::asn1::Decoder;
use hitls_utils::oid::Oid;

/// `bsl/asn1` `DECODE_TEMPLATE_DEPTH_MAX_SUCCESS_TC001` inline DER:
/// `300D300B3009300730053003020101` = six nested SEQUENCE tags wrapping
/// `INTEGER 1`. Decoding all six levels must succeed and recover the integer.
#[test]
fn tc_bsl_asn1_nested_sequence_max_depth_decode() {
    let der: &[u8] = &[
        0x30, 0x0d, 0x30, 0x0b, 0x30, 0x09, 0x30, 0x07, 0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01,
    ];
    let mut dec = Decoder::new(der);
    // Descend six nested SEQUENCE tags.
    let mut inner = dec.read_sequence().unwrap();
    for _ in 0..5 {
        inner = inner.read_sequence().unwrap();
    }
    // Innermost element is INTEGER 1.
    assert_eq!(inner.read_integer().unwrap(), &[0x01]);
}

/// A truncated nested-SEQUENCE DER must fail to decode (negative path).
#[test]
fn tc_bsl_asn1_truncated_sequence_rejected() {
    // Outer SEQUENCE claims length 13 but only 3 content bytes follow.
    let der: &[u8] = &[0x30, 0x0d, 0x30, 0x0b, 0x30];
    let mut dec = Decoder::new(der);
    let inner = dec.read_sequence();
    let bad = match inner {
        Err(_) => true,
        Ok(mut d) => d
            .read_sequence()
            .and_then(|mut x| x.read_sequence())
            .is_err(),
    };
    assert!(bad, "truncated nested SEQUENCE must not decode cleanly");
}

/// `bsl/obj`: OID DER round-trip for rsaEncryption (1.2.840.113549.1.1.1).
/// `to_der_value` must equal the canonical DER content and `from_der_value`
/// must recover the same arc sequence + dotted string.
#[test]
fn tc_bsl_oid_rsa_encryption_der_roundtrip() {
    let canonical: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    let oid = Oid::new(&[1, 2, 840, 113549, 1, 1, 1]);
    assert_eq!(oid.to_der_value(), canonical);
    assert_eq!(oid.to_dot_string(), "1.2.840.113549.1.1.1");

    let decoded = Oid::from_der_value(canonical).unwrap();
    assert_eq!(decoded.arcs(), &[1, 2, 840, 113549, 1, 1, 1]);
    assert_eq!(decoded.to_dot_string(), "1.2.840.113549.1.1.1");
}

/// `bsl/obj`: building an OID from arcs and serialising must reproduce the
/// canonical DER (the inverse of the decode above), covering the multi-byte
/// base-128 arc encoding (840, 113549).
#[test]
fn tc_bsl_oid_from_arcs_encodes_canonical() {
    let oid = Oid::new(&[1, 2, 840, 113549, 1, 1, 1]);
    assert_eq!(
        oid.to_der_value(),
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]
    );
}
