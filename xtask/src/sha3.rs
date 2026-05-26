//! Emitter for openHiTLS C `test_suite_sdv_eal_md_sha3.data` — SHA-3 / SHAKE.
//!
//! Migrates the deterministic hash / XOF KAT families:
//!
//! * `SDV_CRYPT_EAL_SHA3_FUNC_TC003` (`algId : in : digest`) — fixed-length
//!   SHA3-224/256/384/512 hash.
//! * `SDV_CRYPTO_SHA3_COPY_CTX_FUNC_TC001` (`algId : msg : hash`) — same hash
//!   KAT (the C exercises ctx-copy; in Rust it is a plain one-shot digest).
//! * `SDV_CRYPT_EAL_SHA3_FUNC_TC005` (`algId : in : digest : isProvider`) —
//!   SHAKE128/256 squeezed to the KAT digest's own length.
//! * `SDV_CRYPT_EAL_SHA3_FUNC_TC006` (`algId : in : outLen : digest :
//!   isProvider`) — SHAKE128/256 variable-length XOF squeeze of `outLen` bytes.
//!
//! `TC001` (algId-only property test) and the `_API_` rows are API-surface.

use std::collections::BTreeSet;
use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::{format_byte_slice, TestCase};

pub fn emit_sha3_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();
    let mut used: BTreeSet<&'static str> = BTreeSet::new();

    for case in cases {
        match classify(&case.tc_name) {
            Kind::Hash => emit_hash(&mut body, case, &mut stats, &mut used),
            Kind::ShakeDefault => emit_shake(&mut body, case, &mut stats, &mut used, false),
            Kind::ShakeVariable => emit_shake(&mut body, case, &mut stats, &mut used, true),
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
    Hash,
    ShakeDefault,
    ShakeVariable,
    ApiSurface,
    Unknown,
}

fn classify(tc: &str) -> Kind {
    if tc.contains("SHA3_FUNC_TC003") || tc.contains("SHA3_COPY_CTX_FUNC_TC001") {
        return Kind::Hash;
    }
    if tc.contains("SHA3_FUNC_TC005") {
        return Kind::ShakeDefault;
    }
    if tc.contains("SHA3_FUNC_TC006") {
        return Kind::ShakeVariable;
    }
    if tc.contains("SHA3_FUNC_TC001")
        || tc.contains("SHA3_FUNC_TC002")
        || tc.contains("SHA3_FUNC_TC004")
        || tc.contains("SHA3_FUNC_TC007")
        || tc.contains("_API_")
        || tc.contains("DEFAULT_PROVIDER")
    {
        return Kind::ApiSurface;
    }
    Kind::Unknown
}

fn skip_if_provider_dup(case: &TestCase) -> bool {
    matches!(case.args.last().and_then(|a| a.as_symbol()), Some("1"))
}

/// Map a `CRYPT_MD_SHA3_*` symbol to the Rust fixed-length digest type.
fn hash_type(symbol: &str) -> Option<&'static str> {
    match symbol {
        "CRYPT_MD_SHA3_224" => Some("Sha3_224"),
        "CRYPT_MD_SHA3_256" => Some("Sha3_256"),
        "CRYPT_MD_SHA3_384" => Some("Sha3_384"),
        "CRYPT_MD_SHA3_512" => Some("Sha3_512"),
        _ => None,
    }
}

/// Map a `CRYPT_MD_SHAKE*` symbol to the Rust XOF type.
fn shake_type(symbol: &str) -> Option<&'static str> {
    match symbol {
        "CRYPT_MD_SHAKE128" => Some("Shake128"),
        "CRYPT_MD_SHAKE256" => Some("Shake256"),
        _ => None,
    }
}

fn emit_hash(
    out: &mut String,
    case: &TestCase,
    stats: &mut EmitStats,
    used: &mut BTreeSet<&'static str>,
) {
    // Shape: algId : in : digest
    if case.args.len() < 3 {
        stats.skipped_unknown += 1;
        return;
    }
    let Some(ty) = case.args[0].as_symbol().and_then(hash_type) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let (Some(input), Some(digest)) = (case.args[1].as_hex(), case.args[2].as_hex()) else {
        stats.skipped_unknown += 1;
        return;
    };
    used.insert(ty);

    let fn_name = format!("tc_line{}_{}_hash", case.line, ty.to_lowercase());
    write_doc(out, case, ty);
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn {fn_name}() {{").unwrap();
    writeln!(out, "    let input: &[u8] = {};", format_byte_slice(input)).unwrap();
    writeln!(
        out,
        "    let expected: &[u8] = {};",
        format_byte_slice(digest)
    )
    .unwrap();
    writeln!(out, "    let out = {ty}::digest(input).unwrap();").unwrap();
    writeln!(out, "    assert_eq!(&out[..], expected);").unwrap();
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

fn emit_shake(
    out: &mut String,
    case: &TestCase,
    stats: &mut EmitStats,
    used: &mut BTreeSet<&'static str>,
    variable: bool,
) {
    if skip_if_provider_dup(case) {
        stats.skipped_api += 1;
        return;
    }
    let Some(ty) = case
        .args
        .first()
        .and_then(|a| a.as_symbol())
        .and_then(shake_type)
    else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    // TC005: algId : in : digest : isProvider
    // TC006: algId : in : outLen : digest : isProvider
    let (input, digest) = if variable {
        if case.args.len() < 4 {
            stats.skipped_unknown += 1;
            return;
        }
        (case.args[1].as_hex(), case.args[3].as_hex())
    } else {
        if case.args.len() < 3 {
            stats.skipped_unknown += 1;
            return;
        }
        (case.args[1].as_hex(), case.args[2].as_hex())
    };
    let (Some(input), Some(digest)) = (input, digest) else {
        stats.skipped_unknown += 1;
        return;
    };
    // The squeeze length is always the KAT digest's own byte length (for TC006
    // `outLen` equals `digest.len()` by construction).
    let out_len = digest.len();
    used.insert(ty);

    let fn_name = format!("tc_line{}_{}_xof", case.line, ty.to_lowercase());
    write_doc(out, case, ty);
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn {fn_name}() {{").unwrap();
    writeln!(out, "    let input: &[u8] = {};", format_byte_slice(input)).unwrap();
    writeln!(
        out,
        "    let expected: &[u8] = {};",
        format_byte_slice(digest)
    )
    .unwrap();
    writeln!(out, "    let mut xof = {ty}::new();").unwrap();
    writeln!(out, "    xof.update(input).unwrap();").unwrap();
    writeln!(out, "    let out = xof.squeeze({out_len}).unwrap();").unwrap();
    writeln!(out, "    assert_eq!(out, expected);").unwrap();
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

fn write_header(out: &mut String, used: &BTreeSet<&'static str>) {
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo sha3`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_eal_md_sha3.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\n",
    );
    out.push_str("#![cfg(feature = \"sha3\")]\n\n");
    let types: Vec<&str> = [
        "Sha3_224", "Sha3_256", "Sha3_384", "Sha3_512", "Shake128", "Shake256",
    ]
    .into_iter()
    .filter(|t| used.contains(t))
    .collect();
    writeln!(out, "use hitls_crypto::sha3::{{{}}};", types.join(", ")).unwrap();
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

fn write_doc(out: &mut String, case: &TestCase, ty: &str) {
    if let Some(desc) = &case.description {
        writeln!(out, "/// {desc}").unwrap();
    }
    writeln!(
        out,
        "/// C source: {} (line {}, {ty} KAT)",
        case.tc_name, case.line
    )
    .unwrap();
}
