//! Shared ASN.1 encoding helpers for the PKI crate.
//!
//! These functions wrap `hitls_utils::asn1::Encoder` to produce DER-encoded
//! ASN.1 primitives. They are used across x509, pkcs8, pkcs12, and cms modules.

use hitls_utils::asn1::{tags, Encoder};

/// Encode a SEQUENCE containing `content`.
pub(crate) fn enc_seq(content: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.write_sequence(content);
    e.finish()
}

/// Encode a SET containing `content`.
pub(crate) fn enc_set(content: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.write_set(content);
    e.finish()
}

/// Encode an OCTET STRING.
pub(crate) fn enc_octet(content: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.write_octet_string(content);
    e.finish()
}

/// Encode an OID from its DER value bytes.
pub(crate) fn enc_oid(oid_bytes: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.write_oid(oid_bytes);
    e.finish()
}

/// Encode an INTEGER from big-endian bytes.
pub(crate) fn enc_int(value: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.write_integer(value);
    e.finish()
}

/// Encode a NULL value.
pub(crate) fn enc_null() -> Vec<u8> {
    let mut e = Encoder::new();
    e.write_null();
    e.finish()
}

/// Encode a raw TLV (Tag-Length-Value).
pub(crate) fn enc_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.write_tlv(tag, value);
    e.finish()
}

/// Encode an EXPLICIT context-specific tagged value.
pub(crate) fn enc_explicit_ctx(tag_num: u8, content: &[u8]) -> Vec<u8> {
    enc_tlv(
        tags::CONTEXT_SPECIFIC | tags::CONSTRUCTED | tag_num,
        content,
    )
}

/// Concatenate multiple raw byte slices into a single DER fragment.
pub(crate) fn enc_raw_parts(parts: &[&[u8]]) -> Vec<u8> {
    let mut e = Encoder::new();
    for p in parts {
        e.write_raw(p);
    }
    e.finish()
}

/// Decode big-endian bytes into a `u32`.
pub(crate) fn bytes_to_u32(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |acc, &b| acc.wrapping_shl(8) | b as u32)
}
