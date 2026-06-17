// crypto/encode — ECDSA/DSA signature DER codec migration.
//
// Source: openHiTLS C SDV crypto/encode/test_suite_sdv_encode.{c,data}
//   - SDV_ENCODE_SIGN_BN_FUNC_TC001(r, s, expect): CRYPT_EAL_EncodeSign(r, s)
//     == expect, byte-exact (the `SEQUENCE { INTEGER r, INTEGER s }` DER form;
//     includes the RFC 6979 appendix-A.1.3 vector).
//   - SDV_DECODE_SIGN_BN_FUNC_TC001(encode, expectR, expectS, ret):
//     CRYPT_EAL_DecodeSign(encode) -> (r, s) on success, else `ret` error.
//
// Migrated against the new public `hitls_crypto::ecdsa::{encode_signature,
// decode_signature}` (thin wrappers over the codec the ECDSA sign/verify path
// already used internally). Exact C error codes are not reproduced (different
// error enums), so negative rows assert `is_err()`.
//
// One intentional strictness difference is pinned: the C `DecodeSign` tolerates
// trailing bytes after the outer SEQUENCE (row `300602010002010001` -> SUCCESS),
// whereas the Rust decoder rejects them (`decode_signature` is strict — a safer
// posture for a signature parser). That row is migrated as a *rejection*.

#![cfg(feature = "ecdsa")]

use hitls_bignum::BigNum;
use hitls_crypto::ecdsa::{decode_signature, encode_signature};
use hitls_utils::hex::hex;

fn bn(h: &str) -> BigNum {
    BigNum::from_bytes_be(&hex(h))
}

/// SDV_ENCODE_SIGN_BN_FUNC_TC001 — byte-exact `(r, s) -> DER`.
#[test]
fn tc_encode_sign_bn_byte_exact() {
    // (r, s, expected DER)
    let cases: &[(&str, &str, &str)] = &[
        // RFC 6979 appendix-A.1.3 (r, s each 21 bytes, leading 0x01 is value).
        (
            "0113a63990598a3828c407c0f4d2438d990df99a7f",
            "01313a2e03f5412ddb296a22e2c455335545672d9f",
            "302e02150113a63990598a3828c407c0f4d2438d990df99a7f0215\
             01313a2e03f5412ddb296a22e2c455335545672d9f",
        ),
        // s has its high bit set -> canonical DER adds a 0x00 sign pad.
        (
            "0123456789abcdef",
            "fedcba0987654321",
            "301502080123456789abcdef020900fedcba0987654321",
        ),
        // Both 32-byte all-ones -> both get a 0x00 sign pad.
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "3046022100ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             022100ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
    ];
    for (r, s, expect) in cases {
        let der = encode_signature(&bn(r), &bn(s)).unwrap();
        assert_eq!(der, hex(expect), "EncodeSign({r}, {s})");
    }
}

/// SDV_DECODE_SIGN_BN_FUNC_TC001 (CRYPT_SUCCESS rows) — `DER -> (r, s)`.
#[test]
fn tc_decode_sign_bn_success() {
    // (der, expectR, expectS) — compared as BigNum (normalises leading zeros).
    let cases: &[(&str, &str, &str)] = &[
        (
            "302e02150113a63990598a3828c407c0f4d2438d990df99a7f0215\
             01313a2e03f5412ddb296a22e2c455335545672d9f",
            "0113a63990598a3828c407c0f4d2438d990df99a7f",
            "01313a2e03f5412ddb296a22e2c455335545672d9f",
        ),
        // r = s = 0.
        ("3006020100020100", "00", "00"),
        (
            "3046022100ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             022100ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
    ];
    for (der, er, es) in cases {
        let (r, s) = decode_signature(&hex(der)).unwrap();
        assert_eq!(r, bn(er), "DecodeSign r: {der}");
        assert_eq!(s, bn(es), "DecodeSign s: {der}");
    }
}

/// SDV_DECODE_SIGN_BN_FUNC_TC001 (error rows) — malformed DER must be rejected.
#[test]
fn tc_decode_sign_bn_rejected() {
    let bad: &[&str] = &[
        "300702010102020000", // BSL_ASN1_ERR_DECODE_INT (non-minimal INTEGER)
        "30070201f102020000", // BSL_ASN1_ERR_DECODE_INT (negative INTEGER)
        "ff",                 // BSL_ASN1_ERR_TAG_EXPECTED (not a SEQUENCE)
        "3008020100020200f1", // BSL_ASN1_ERR_DECODE_LEN (length mismatch)
        "3003020101",         // BSL_ASN1_ERR_DECODE_LEN (only one INTEGER)
        "30050200020101",     // CRYPT_DECODE_ASN1_BUFF_LEN_ZERO (zero-len r)
        "30050201010200",     // CRYPT_DECODE_ASN1_BUFF_LEN_ZERO (zero-len s)
        // C tolerates the trailing 0x01 after the SEQUENCE; the Rust decoder is
        // strict and rejects trailing bytes (safer for a signature parser).
        "300602010002010001",
    ];
    for der in bad {
        assert!(
            decode_signature(&hex(der)).is_err(),
            "DecodeSign must reject malformed DER: {der}"
        );
    }
}

/// SDV_ENCODE_DECODE_SIGN_COMBO_TC001 — `encode` then `decode` round-trips.
#[test]
fn tc_encode_decode_sign_roundtrip() {
    let cases: &[(&str, &str)] = &[
        (
            "0113a63990598a3828c407c0f4d2438d990df99a7f",
            "01313a2e03f5412ddb296a22e2c455335545672d9f",
        ),
        ("0123456789abcdef", "fedcba0987654321"),
    ];
    for (r, s) in cases {
        let der = encode_signature(&bn(r), &bn(s)).unwrap();
        let (r2, s2) = decode_signature(&der).unwrap();
        assert_eq!(r2, bn(r), "round-trip r");
        assert_eq!(s2, bn(s), "round-trip s");
    }
}
