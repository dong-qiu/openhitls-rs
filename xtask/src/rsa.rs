//! Emitter for openHiTLS C `test_suite_sdv_eal_rsa_sign_verify.data` — RSA
//! signature *verify* KATs (public-key only, so no private-key / nonce hook).
//!
//! * `RSA_VERIFY_PKCSV15_FUNC_TC001` (`mdId : n : e : msg : sign : expect :
//!   isProvider`) — PKCS#1 v1.5 verify: `RsaPublicKey::new(n, e).verify(
//!   Pkcs1v15Sign, MD(msg), sign)`.
//! * `RSA_VERIFY_PSS_FUNC_TC001` (`mdId : n : e : salt : msg : sign : expect :
//!   isProvider`) — PSS verify (the `salt` is a sign-side input, unused here):
//!   `RsaPublicKey::new(n, e).verify_pss(MD(msg), sign, alg)`.
//!
//! `expect == 0` (CRYPT_SUCCESS) means the signature must verify; any other
//! value means it must not. PSS is limited to SHA-256/384/512 (the Rust
//! `verify_pss` / MGF1 hashes); PSS-SHA-1/224 rows are `unsupported`. The
//! sign / encrypt / decrypt families need a private key built from `(n, d)`
//! (the Rust `RsaPrivateKey::new` wants CRT params the vectors omit) — a
//! follow-up `from_nd` constructor; routed to `ApiSurface` here.

use std::collections::BTreeSet;
use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::{format_byte_slice, TestCase};

pub fn emit_rsa_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();
    let mut used: BTreeSet<&'static str> = BTreeSet::new();

    for case in cases {
        if case.tc_name.contains("RSA_VERIFY_PKCSV15_FUNC_TC001") {
            emit_verify_pkcs15(&mut body, case, &mut stats, &mut used);
        } else if case.tc_name.contains("RSA_VERIFY_PSS_FUNC_TC001") {
            emit_verify_pss(&mut body, case, &mut stats, &mut used);
        } else {
            stats.skipped_api += 1;
        }
    }

    let mut out = String::new();
    write_header(&mut out, &used);
    out.push_str(&body);
    write_footer(&mut out, &stats, cases.len());
    (out, stats)
}

fn skip_if_provider_dup(case: &TestCase) -> bool {
    matches!(case.args.last().and_then(|a| a.as_symbol()), Some("1"))
}

/// Map a `CRYPT_MD_*` symbol to the hitls-crypto digest type (for `MD(msg)`).
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

/// Map a `CRYPT_MD_*` symbol to the `RsaHashAlg` variant accepted by
/// `verify_pss` (SHA-256/384/512 only — MGF1 has no SHA-1 and there is no
/// SHA-224 variant).
fn md_to_pss_alg(symbol: &str) -> Option<&'static str> {
    match symbol {
        "CRYPT_MD_SHA256" => Some("Sha256"),
        "CRYPT_MD_SHA384" => Some("Sha384"),
        "CRYPT_MD_SHA512" => Some("Sha512"),
        _ => None,
    }
}

/// `expect == 0` (CRYPT_SUCCESS) → the signature must verify.
fn expect_pass(case: &TestCase, idx: usize) -> Option<bool> {
    case.args
        .get(idx)
        .and_then(|a| a.as_symbol())
        .and_then(|s| s.parse::<i64>().ok())
        .map(|v| v == 0)
}

fn emit_verify_pkcs15(
    out: &mut String,
    case: &TestCase,
    stats: &mut EmitStats,
    used: &mut BTreeSet<&'static str>,
) {
    if skip_if_provider_dup(case) {
        stats.skipped_api += 1;
        return;
    }
    // mdId : n : e : msg : sign : expect : isProvider
    if case.args.len() < 6 {
        stats.skipped_unknown += 1;
        return;
    }
    let Some(hash) = case.args[0].as_symbol().and_then(md_to_hash) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let (Some(n), Some(e), Some(msg), Some(sign)) = (
        case.args[1].as_hex(),
        case.args[2].as_hex(),
        case.args[3].as_hex(),
        case.args[4].as_hex(),
    ) else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(pass) = expect_pass(case, 5) else {
        stats.skipped_unknown += 1;
        return;
    };
    used.insert(hash);

    write_doc(out, case, "RSA PKCS#1 v1.5 verify");
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn tc_line{}_rsa_pkcs15_verify() {{", case.line).unwrap();
    emit_key_inputs(out, n, e, msg, sign);
    writeln!(out, "    let digest = {hash}::digest(msg).unwrap();").unwrap();
    writeln!(out, "    let pk = RsaPublicKey::new(n, e).unwrap();").unwrap();
    writeln!(
        out,
        "    let ok = pk.verify(RsaPadding::Pkcs1v15Sign, &digest, sign).unwrap_or(false);"
    )
    .unwrap();
    if pass {
        writeln!(out, "    assert!(ok);").unwrap();
    } else {
        writeln!(out, "    assert!(!ok);").unwrap();
    }
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

fn emit_verify_pss(
    out: &mut String,
    case: &TestCase,
    stats: &mut EmitStats,
    used: &mut BTreeSet<&'static str>,
) {
    if skip_if_provider_dup(case) {
        stats.skipped_api += 1;
        return;
    }
    // mdId : n : e : salt : msg : sign : expect : isProvider
    if case.args.len() < 7 {
        stats.skipped_unknown += 1;
        return;
    }
    let Some(md) = case.args[0].as_symbol() else {
        stats.skipped_unknown += 1;
        return;
    };
    let (Some(hash), Some(alg)) = (md_to_hash(md), md_to_pss_alg(md)) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    // mdId : n : e : salt : msg : sign : expect : isProvider
    let (Some(n), Some(e), Some(salt), Some(msg), Some(sign)) = (
        case.args[1].as_hex(),
        case.args[2].as_hex(),
        case.args[3].as_hex(),
        case.args[4].as_hex(),
        case.args[5].as_hex(),
    ) else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(pass) = expect_pass(case, 6) else {
        stats.skipped_unknown += 1;
        return;
    };
    let salt_len = salt.len();
    used.insert(hash);
    used.insert("pss");

    write_doc(out, case, "RSA PSS verify");
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn tc_line{}_rsa_pss_verify() {{", case.line).unwrap();
    emit_key_inputs(out, n, e, msg, sign);
    writeln!(out, "    let digest = {hash}::digest(msg).unwrap();").unwrap();
    writeln!(out, "    let pk = RsaPublicKey::new(n, e).unwrap();").unwrap();
    writeln!(
        out,
        "    let ok = pk.verify_pss_with_salt(&digest, sign, RsaHashAlg::{alg}, {salt_len}).unwrap_or(false);"
    )
    .unwrap();
    if pass {
        writeln!(out, "    assert!(ok);").unwrap();
    } else {
        writeln!(out, "    assert!(!ok);").unwrap();
    }
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

fn emit_key_inputs(out: &mut String, n: &[u8], e: &[u8], msg: &[u8], sign: &[u8]) {
    writeln!(out, "    let n: &[u8] = {};", format_byte_slice(n)).unwrap();
    writeln!(out, "    let e: &[u8] = {};", format_byte_slice(e)).unwrap();
    writeln!(out, "    let msg: &[u8] = {};", format_byte_slice(msg)).unwrap();
    writeln!(out, "    let sign: &[u8] = {};", format_byte_slice(sign)).unwrap();
}

fn write_header(out: &mut String, used: &BTreeSet<&'static str>) {
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo rsa`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_eal_rsa_sign_verify.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\n",
    );
    out.push_str("#![cfg(all(feature = \"rsa\", feature = \"sha1\", feature = \"sha2\"))]\n\n");
    if used.contains("pss") {
        out.push_str("use hitls_crypto::rsa::{RsaHashAlg, RsaPadding, RsaPublicKey};\n");
    } else {
        out.push_str("use hitls_crypto::rsa::{RsaPadding, RsaPublicKey};\n");
    }
    if used.contains("Sha1") {
        out.push_str("use hitls_crypto::sha1::Sha1;\n");
    }
    let sha2: Vec<&str> = ["Sha224", "Sha256", "Sha384", "Sha512"]
        .into_iter()
        .filter(|h| used.contains(h))
        .collect();
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

fn write_doc(out: &mut String, case: &TestCase, kind: &str) {
    if let Some(desc) = &case.description {
        writeln!(out, "/// {desc}").unwrap();
    }
    writeln!(
        out,
        "/// C source: {} (line {}, {kind} KAT)",
        case.tc_name, case.line
    )
    .unwrap();
}
