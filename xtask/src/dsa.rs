//! Emitter for openHiTLS C `test_suite_sdv_eal_dsa.data`.
//!
//! Real KAT families (both share the row shape
//! `md : P : Q : G : Msg : X : Y : K : R : S : provider` and, in Rust, are
//! treated identically — `DsaKeyPair::sign`/`verify` both operate on a
//! digest, so the `_FUNC` vs `_DATA_FUNC` C distinction collapses):
//!
//! * `DSA_SIGN_VERIFY_FUNC_TC001`      — C signs the raw message
//! * `DSA_SIGN_VERIFY_DATA_FUNC_TC001` — C hashes first, then signs the digest
//!
//! The C test pins the signing nonce `K` via a stubbed RNG so it can byte-
//! compare against the NIST `(R, S)`. Two tests are emitted per row: a
//! **verify** (the NIST `(R, S)` DER-encoded as `SEQUENCE { INTEGER, INTEGER }`
//! at generation time, checked with `DsaKeyPair::verify`) and a
//! **deterministic sign** (`DsaKeyPair::sign_with_nonce(MD(Msg), K) ==
//! DER(R, S)`). The sign test is gated behind the non-default `kat-nonce`
//! feature, since `sign_with_nonce` is a test-only entry point (a caller-chosen
//! DSA nonce leaks the private key).
//!
//! Everything else (key-pair / P-Q / G generation, key-bit getters, ctx
//! duplication, key-pair checks) is API-surface and routed to `ApiSurface`.

use std::collections::BTreeSet;
use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::{format_byte_slice, TestCase};

pub fn emit_dsa_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();
    let mut used: BTreeSet<&'static str> = BTreeSet::new();

    for case in cases {
        match classify(&case.tc_name) {
            Kind::SignVerify => {
                emit_sign_verify(&mut body, case, &mut stats, &mut used);
                emit_sign(&mut body, case, &mut stats, &mut used);
            }
            Kind::ApiSurface => stats.skipped_api += 1,
            Kind::Unknown => stats.skipped_unknown += 1,
        }
    }

    let mut out = String::new();
    write_header(&mut out, &used);
    out.push_str(&body);
    write_footer(&mut out, &stats, cases.len());
    (out, stats)
}

#[derive(Debug, Clone, Copy)]
enum Kind {
    SignVerify,
    ApiSurface,
    Unknown,
}

fn classify(tc: &str) -> Kind {
    if tc.contains("DSA_SIGN_VERIFY_DATA_FUNC_TC001") || tc.contains("DSA_SIGN_VERIFY_FUNC_TC001") {
        return Kind::SignVerify;
    }
    if tc.contains("_KEY_PAIR_GEN")
        || tc.contains("_GEN_PQ_")
        || tc.contains("_GEN_G_")
        || tc.contains("_GEN_FUNC_")
        || tc.contains("_VERIFY_PQ_")
        || tc.contains("_GET_KEY_BITS_")
        || tc.contains("_GET_SEC_BITS_")
        || tc.contains("_KEY_PAIR_CHECK_")
        || tc.contains("_DUP_CTX_")
    {
        return Kind::ApiSurface;
    }
    Kind::Unknown
}

/// Skip provider-flag duplicates: the rightmost arg is `0` (default provider)
/// or `1` (EAL provider framework); the rest of the row is byte-identical.
/// Rust has no provider concept, so emitting both would just duplicate tests.
fn skip_if_provider_dup(case: &TestCase) -> bool {
    matches!(case.args.last().and_then(|a| a.as_symbol()), Some("1"))
}

/// Map a `CRYPT_MD_*` symbol to the hitls-crypto digest type that hashes the
/// message before signing/verifying.
fn md_to_hash(symbol: &str) -> Option<&'static str> {
    match symbol {
        "CRYPT_MD_SHA1" => Some("Sha1"),
        "CRYPT_MD_SHA224" => Some("Sha224"),
        "CRYPT_MD_SHA256" => Some("Sha256"),
        "CRYPT_MD_SHA384" => Some("Sha384"),
        "CRYPT_MD_SHA512" => Some("Sha512"),
        _ => None,
    }
}

fn emit_sign_verify(
    out: &mut String,
    case: &TestCase,
    stats: &mut EmitStats,
    used: &mut BTreeSet<&'static str>,
) {
    if skip_if_provider_dup(case) {
        stats.skipped_api += 1;
        return;
    }
    // Shape: md : P : Q : G : Msg : X : Y : K : R : S : provider
    if case.args.len() < 11 {
        stats.skipped_unknown += 1;
        return;
    }
    let Some(md) = case.args[0].as_symbol() else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(hash) = md_to_hash(md) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let (Some(p), Some(q), Some(g), Some(msg), Some(y), Some(r), Some(s)) = (
        case.args[1].as_hex(),
        case.args[2].as_hex(),
        case.args[3].as_hex(),
        case.args[4].as_hex(),
        case.args[6].as_hex(),
        case.args[8].as_hex(),
        case.args[9].as_hex(),
    ) else {
        stats.skipped_unknown += 1;
        return;
    };
    let sig = der_encode_sig(r, s);
    used.insert(hash);

    let fn_name = format!("tc_line{}_dsa_verify", case.line);
    write_doc(out, case);
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn {fn_name}() {{").unwrap();
    writeln!(out, "    let p: &[u8] = {};", format_byte_slice(p)).unwrap();
    writeln!(out, "    let q: &[u8] = {};", format_byte_slice(q)).unwrap();
    writeln!(out, "    let g: &[u8] = {};", format_byte_slice(g)).unwrap();
    writeln!(out, "    let msg: &[u8] = {};", format_byte_slice(msg)).unwrap();
    writeln!(out, "    let pubk: &[u8] = {};", format_byte_slice(y)).unwrap();
    writeln!(out, "    let sig: &[u8] = {};", format_byte_slice(&sig)).unwrap();
    writeln!(out, "    let params = DsaParams::new(p, q, g).unwrap();").unwrap();
    writeln!(
        out,
        "    let kp = DsaKeyPair::from_public_key(params, pubk).unwrap();"
    )
    .unwrap();
    writeln!(out, "    let digest = {hash}::digest(msg).unwrap();").unwrap();
    writeln!(out, "    assert!(kp.verify(&digest, sig).unwrap());").unwrap();
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

/// Deterministic DSA **sign** KAT from the same row: sign `MD(Msg)` with the
/// nonce `K` and check the DER `(r, s)` matches the vector's `(R, S)`. The C
/// pins `K` via a stubbed RNG; the Rust port draws it randomly, so this uses
/// the test-only `sign_with_nonce` (behind the `kat-nonce` feature).
fn emit_sign(
    out: &mut String,
    case: &TestCase,
    stats: &mut EmitStats,
    used: &mut BTreeSet<&'static str>,
) {
    if skip_if_provider_dup(case) || case.args.len() < 11 {
        return;
    }
    let Some(md) = case.args[0].as_symbol() else {
        return;
    };
    let Some(hash) = md_to_hash(md) else {
        return;
    };
    // md : P : Q : G : Msg : X : Y : K : R : S
    let (Some(p), Some(q), Some(g), Some(msg), Some(x), Some(k), Some(r), Some(s)) = (
        case.args[1].as_hex(),
        case.args[2].as_hex(),
        case.args[3].as_hex(),
        case.args[4].as_hex(),
        case.args[5].as_hex(),
        case.args[7].as_hex(),
        case.args[8].as_hex(),
        case.args[9].as_hex(),
    ) else {
        return;
    };
    if x.is_empty() || k.is_empty() {
        return;
    }
    let sig = der_encode_sig(r, s);
    used.insert(hash);

    let fn_name = format!("tc_line{}_dsa_sign", case.line);
    write_doc(out, case);
    writeln!(out, "#[cfg(feature = \"kat-nonce\")]").unwrap();
    writeln!(out, "#[allow(deprecated)]").unwrap();
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn {fn_name}() {{").unwrap();
    writeln!(out, "    let p: &[u8] = {};", format_byte_slice(p)).unwrap();
    writeln!(out, "    let q: &[u8] = {};", format_byte_slice(q)).unwrap();
    writeln!(out, "    let g: &[u8] = {};", format_byte_slice(g)).unwrap();
    writeln!(out, "    let msg: &[u8] = {};", format_byte_slice(msg)).unwrap();
    writeln!(out, "    let prv: &[u8] = {};", format_byte_slice(x)).unwrap();
    writeln!(out, "    let k: &[u8] = {};", format_byte_slice(k)).unwrap();
    writeln!(
        out,
        "    let expected: &[u8] = {};",
        format_byte_slice(&sig)
    )
    .unwrap();
    writeln!(out, "    let params = DsaParams::new(p, q, g).unwrap();").unwrap();
    writeln!(
        out,
        "    let kp = DsaKeyPair::from_private_key(params, prv).unwrap();"
    )
    .unwrap();
    writeln!(out, "    let digest = {hash}::digest(msg).unwrap();").unwrap();
    writeln!(
        out,
        "    assert_eq!(kp.sign_with_nonce(&digest, k).unwrap(), expected);"
    )
    .unwrap();
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

/// DER-encode a DSA signature as `SEQUENCE { INTEGER r, INTEGER s }` — the
/// format `DsaKeyPair::verify` decodes. Done at generation time so the
/// emitted test carries a ready byte literal and needs no runtime helper.
fn der_encode_sig(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut content = der_int(r);
    content.extend(der_int(s));
    let mut out = vec![0x30];
    der_len(&mut out, content.len());
    out.extend(content);
    out
}

/// Encode a non-negative big-endian integer as a DER `INTEGER` TLV.
fn der_int(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes;
    while v.len() > 1 && v[0] == 0 {
        v = &v[1..];
    }
    let mut content: Vec<u8> = if v.is_empty() { vec![0] } else { v.to_vec() };
    // A leading bit of 1 would be read as a negative integer — pad with 0x00.
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    let mut out = vec![0x02];
    der_len(&mut out, content.len());
    out.extend(content);
    out
}

/// Append a DER length (definite form) to `out`.
fn der_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    }
}

fn write_header(out: &mut String, used: &BTreeSet<&'static str>) {
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo dsa`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_eal_dsa.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\n",
    );
    out.push_str("#![cfg(all(feature = \"dsa\", feature = \"sha1\", feature = \"sha2\"))]\n\n");
    out.push_str("use hitls_crypto::dsa::{DsaKeyPair, DsaParams};\n");
    let sha2: Vec<&str> = ["Sha224", "Sha256", "Sha384", "Sha512"]
        .into_iter()
        .filter(|h| used.contains(h))
        .collect();
    if used.contains("Sha1") {
        out.push_str("use hitls_crypto::sha1::Sha1;\n");
    }
    if !sha2.is_empty() {
        writeln!(out, "use hitls_crypto::sha2::{{{}}};", sha2.join(", ")).unwrap();
    }
    out.push('\n');
}

fn write_footer(out: &mut String, stats: &EmitStats, total: usize) {
    writeln!(
        out,
        "\n// Generation summary: {emitted} emitted / {api} API-surface skipped \
         / {unk} unknown / {unsupported} unsupported alg / {total} total C cases.",
        emitted = stats.emitted,
        api = stats.skipped_api,
        unk = stats.skipped_unknown,
        unsupported = stats.skipped_unsupported_alg,
        total = total,
    )
    .unwrap();
}

fn write_doc(out: &mut String, case: &TestCase) {
    if let Some(desc) = &case.description {
        writeln!(out, "/// {desc}").unwrap();
    }
    writeln!(
        out,
        "/// C source: {} (line {}, DSA verify KAT)",
        case.tc_name, case.line
    )
    .unwrap();
}
