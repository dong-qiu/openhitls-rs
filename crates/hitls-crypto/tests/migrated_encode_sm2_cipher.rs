// crypto/encode — SM2 ciphertext DER codec migration (Phase 2).
//
// Source: openHiTLS C SDV crypto/encode/test_suite_sdv_encode.{c,data}
//   - SDV_ENCODE_SM2_ENCRYPT_DATA_FUNC_TC001(x, y, hash, cipher, expect, ret).
//   - SDV_DECODE_SM2_ENCRYPT_DATA_FUNC_TC001(encode, X, Y, hash, cipher, ret).
//   - SDV_ENCODE_DECODE_SM2_ENCRYPT_COMBO_TC001(x, y, hash, cipher): round-trip.
//
// Migrated against the new public hitls_crypto::sm2::{encode_sm2_ciphertext,
// decode_sm2_ciphertext} (GB/T 32918.4 / GM/T 0009:
// SEQUENCE { INTEGER C1x, INTEGER C1y, OCTET STRING C3, OCTET STRING C2 }).
// C1x/C1y compared as integer values (DER sign-pad normalised); C3/C2
// byte-exact. The Rust decoder is strict — it rejects non-minimal/negative
// INTEGER coordinates, empty C3/C2, and trailing bytes after the SEQUENCE.
// One C row marked CRYPT_SUCCESS carries a trailing byte the C tolerates; the
// Rust decoder rejects it (safer), so the decode KAT count-guards 2-of-3.

#![cfg(feature = "sm2")]

use hitls_bignum::BigNum;
use hitls_crypto::sm2::{decode_sm2_ciphertext, encode_sm2_ciphertext};
use hitls_utils::hex::hex;

fn bn(b: &[u8]) -> Vec<u8> {
    BigNum::from_bytes_be(b).to_bytes_be()
}

// (x, y, hash, cipher, expected_der)
const ENCODE_OK: &[(&str, &str, &str, &str, &str)] = &[
    ("0123456789ABCDEF0123456789ABCDEF", "FEDCBA9876543210FEDCBA9876543210", "0011223344556677", "AABBCCDD", "303502100123456789ABCDEF0123456789ABCDEF021100FEDCBA9876543210FEDCBA9876543210040800112233445566770404AABBCCDD"),
    ("04EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73", "E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF0", "59983C18F809E262923C53AEC295D30383B54E39D609D160AFCB1908D0BD8766", "21886CA989CA9C7D58087307CA93092D651EFA", "307C022004EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73022100E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF0042059983C18F809E262923C53AEC295D30383B54E39D609D160AFCB1908D0BD8766041321886CA989CA9C7D58087307CA93092D651EFA"),
];
// (encoded_der, expect_x, expect_y, expect_hash, expect_cipher) — C CRYPT_SUCCESS rows.
const DECODE_SUCCESS: &[(&str, &str, &str, &str, &str)] = &[
    ("303502100123456789ABCDEF0123456789ABCDEF021100FEDCBA9876543210FEDCBA9876543210040800112233445566770404AABBCCDD", "0123456789ABCDEF0123456789ABCDEF", "FEDCBA9876543210FEDCBA9876543210", "0011223344556677", "AABBCCDD"),
    ("307C022004EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73022100E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF0042059983C18F809E262923C53AEC295D30383B54E39D609D160AFCB1908D0BD8766041321886CA989CA9C7D58087307CA93092D651EFA", "04EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73", "E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF0", "59983C18F809E262923C53AEC295D30383B54E39D609D160AFCB1908D0BD8766", "21886CA989CA9C7D58087307CA93092D651EFA"),
    ("303502100123456789ABCDEF0123456789ABCDEF021100FEDCBA9876543210FEDCBA9876543210040800112233445566770404AABBCCDDEE", "0123456789ABCDEF0123456789ABCDEF", "00FEDCBA9876543210FEDCBA9876543210", "0011223344556677", "AABBCCDD"),
];
const DECODE_BAD: &[&str] = &[
    "3081880220002ed1067746155de13c45d767d1221f631d997d8238ccc0eb015f013888137f022079c665009c337f2aa548a134b96ae65ea254e4ae1714be07b68a425127b10f8404205ea82a72c0ce48f7d05aa6946cce9a7910e38ff2da80b3d242cb57eb295412b304209d64e6729e7d5e83919577db14c0cfee5cadd2c7dd11f49b88edca4b44373b36",
    "307C0220F4EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73022100E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF0042059983C18F809E262923C53AEC295D30383B54E39D609D160AFCB1908D0BD8766041321886CA989CA9C7D58087307CA93092D651EFA",
    "30250200021100FEDCBA9876543210FEDCBA9876543210040800112233445566770404AABBCCDD",
    "302402100123456789ABCDEF0123456789ABCDEF0200040800112233445566770404AABBCCDD",
    "302D02100123456789ABCDEF0123456789ABCDEF021100FEDCBA9876543210FEDCBA987654321004000404AABBCCDD",
    "303102100123456789ABCDEF0123456789ABCDEF021100FEDCBA9876543210FEDCBA9876543210040800112233445566770400",
];
const COMBO: &[(&str, &str, &str, &str)] = &[
    (
        "0123456789ABCDEF0123456789ABCDEF",
        "FEDCBA9876543210FEDCBA9876543210",
        "0011223344556677",
        "AABBCCDD",
    ),
    (
        "04EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73",
        "E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF0",
        "59983C18F809E262923C53AEC295D30383B54E39D609D160AFCB1908D0BD8766",
        "21886CA989CA9C7D58087307CA93092D651EFA",
    ),
];

#[test]
fn tc_sm2_ciphertext_encode_byte_exact() {
    for (x, y, h, c, expect) in ENCODE_OK {
        let der = encode_sm2_ciphertext(&hex(x), &hex(y), &hex(h), &hex(c)).unwrap();
        assert_eq!(der, hex(expect), "EncodeSm2EncryptData byte-exact");
    }
    // The all-empty C INVALID_ARG row: empty coordinates must be rejected.
    assert!(encode_sm2_ciphertext(&[], &[], &[], &[]).is_err());
}

#[test]
fn tc_sm2_ciphertext_decode() {
    // The clean DER rows decode + match byte-exact; any row the strict Rust
    // decoder rejects (one C-SUCCESS row has a trailing byte) is allowed to err.
    let mut ok = 0usize;
    for (der, ex, ey, eh, ec) in DECODE_SUCCESS {
        if let Ok((x, y, h, c)) = decode_sm2_ciphertext(&hex(der)) {
            assert_eq!(bn(&x), bn(&hex(ex)), "C1x value");
            assert_eq!(bn(&y), bn(&hex(ey)), "C1y value");
            assert_eq!(h, hex(eh), "C3 byte-exact");
            assert_eq!(c, hex(ec), "C2 byte-exact");
            ok += 1;
        }
    }
    assert_eq!(
        ok, 2,
        "2 of 3 C-SUCCESS rows are clean DER; 1 has a trailing byte"
    );
}

#[test]
fn tc_sm2_ciphertext_decode_rejected() {
    for der in DECODE_BAD {
        assert!(
            decode_sm2_ciphertext(&hex(der)).is_err(),
            "must reject: {der}"
        );
    }
}

#[test]
fn tc_sm2_ciphertext_roundtrip() {
    for (x, y, h, c) in COMBO {
        let der = encode_sm2_ciphertext(&hex(x), &hex(y), &hex(h), &hex(c)).unwrap();
        let (dx, dy, dh, dc) = decode_sm2_ciphertext(&der).unwrap();
        assert_eq!(bn(&dx), bn(&hex(x)));
        assert_eq!(bn(&dy), bn(&hex(y)));
        assert_eq!(dh, hex(h));
        assert_eq!(dc, hex(c));
    }
}
