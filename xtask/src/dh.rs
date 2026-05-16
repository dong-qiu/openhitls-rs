//! Emitter for openHiTLS C `test_suite_sdv_eal_dh.data`.
//!
//! Real KAT families (row shape `p : g : q : prv1 : pub1 : prv2 : pub2 :
//! share : provider`, matching the C signature
//! `SDV_CRYPTO_DH_FUNC_TC00x(Hex *p, Hex *g, Hex *q, Hex *prv1, Hex *pub1,
//! Hex *prv2, Hex *pub2, Hex *share, int isProvider)`):
//!
//! * `DH_FUNC_TC001` — positive: both parties compute the shared secret and
//!   it equals `share`.
//! * `DH_FUNC_TC006` — negative ("fail vector, Z changed"): `share` is a
//!   deliberately corrupted value, so the real computation must NOT match.
//!
//! The `q` subgroup order is unused — `DhParams::new` takes only `(p, g)`,
//! which is all `compute_shared_secret` (a plain `g^x mod p`) needs.
//!
//! Key-generation / named-group / ctx-duplication families (`TC002`–`TC005`,
//! `GET_KEY_BITS`, `DUP_CTX`) are API-surface and routed to `ApiSurface` —
//! Rust DH key generation draws the private exponent from the system RNG,
//! so a generation KAT is not reproducible.

use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::{format_byte_slice, TestCase};

pub fn emit_dh_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();

    for case in cases {
        match classify(&case.tc_name) {
            Kind::Positive => emit_exchange(&mut body, case, &mut stats, false),
            Kind::Negative => emit_exchange(&mut body, case, &mut stats, true),
            Kind::ApiSurface => stats.skipped_api += 1,
            Kind::Unknown => stats.skipped_unknown += 1,
        }
    }

    let mut out = String::new();
    write_header(&mut out);
    out.push_str(&body);
    write_footer(&mut out, &stats, cases.len());
    (out, stats)
}

#[derive(Debug, Clone, Copy)]
enum Kind {
    Positive,
    Negative,
    ApiSurface,
    Unknown,
}

fn classify(tc: &str) -> Kind {
    if tc.contains("DH_FUNC_TC001") {
        return Kind::Positive;
    }
    if tc.contains("DH_FUNC_TC006") {
        return Kind::Negative;
    }
    if tc.contains("DH_FUNC_TC002")
        || tc.contains("DH_FUNC_TC003")
        || tc.contains("DH_FUNC_TC004")
        || tc.contains("DH_FUNC_TC005")
        || tc.contains("_GET_KEY_BITS_")
        || tc.contains("_DUP_CTX_")
    {
        return Kind::ApiSurface;
    }
    Kind::Unknown
}

/// Skip provider-flag duplicates: the rightmost arg is `0` (default provider)
/// or `1` (EAL provider framework); the rest of the row is byte-identical.
fn skip_if_provider_dup(case: &TestCase) -> bool {
    matches!(case.args.last().and_then(|a| a.as_symbol()), Some("1"))
}

fn emit_exchange(out: &mut String, case: &TestCase, stats: &mut EmitStats, negative: bool) {
    if skip_if_provider_dup(case) {
        stats.skipped_api += 1;
        return;
    }
    // Shape: p : g : q : prv1 : pub1 : prv2 : pub2 : share : provider
    if case.args.len() < 9 {
        stats.skipped_unknown += 1;
        return;
    }
    let (Some(p), Some(g), Some(prv1), Some(pub1), Some(prv2), Some(pub2), Some(share)) = (
        case.args[0].as_hex(),
        case.args[1].as_hex(),
        case.args[3].as_hex(),
        case.args[4].as_hex(),
        case.args[5].as_hex(),
        case.args[6].as_hex(),
        case.args[7].as_hex(),
    ) else {
        stats.skipped_unknown += 1;
        return;
    };

    let kind = if negative {
        "DH key-exchange fail vector"
    } else {
        "DH key-exchange KAT"
    };
    let suffix = if negative { "_fail" } else { "" };
    let fn_name = format!("tc_line{}_dh_exchange{}", case.line, suffix);
    write_doc(out, case, kind);
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn {fn_name}() {{").unwrap();
    writeln!(out, "    let p: &[u8] = {};", format_byte_slice(p)).unwrap();
    writeln!(out, "    let g: &[u8] = {};", format_byte_slice(g)).unwrap();
    writeln!(out, "    let prv1: &[u8] = {};", format_byte_slice(prv1)).unwrap();
    writeln!(out, "    let pub1: &[u8] = {};", format_byte_slice(pub1)).unwrap();
    writeln!(out, "    let prv2: &[u8] = {};", format_byte_slice(prv2)).unwrap();
    writeln!(out, "    let pub2: &[u8] = {};", format_byte_slice(pub2)).unwrap();
    writeln!(out, "    let share: &[u8] = {};", format_byte_slice(share)).unwrap();
    writeln!(out, "    let params = DhParams::new(p, g).unwrap();").unwrap();
    // Both parties derive the shared secret: party 1 = prv1 x pub2,
    // party 2 = prv2 x pub1. A keying/compute error yields `None`.
    writeln!(
        out,
        "    let d1 = DhKeyPair::from_private_key(&params, prv1)\n\
         \x20       .and_then(|kp| kp.compute_shared_secret(&params, pub2))\n\
         \x20       .ok();"
    )
    .unwrap();
    writeln!(
        out,
        "    let d2 = DhKeyPair::from_private_key(&params, prv2)\n\
         \x20       .and_then(|kp| kp.compute_shared_secret(&params, pub1))\n\
         \x20       .ok();"
    )
    .unwrap();
    if negative {
        // Fail vector: a key field is corrupted, so it is NOT the case that
        // both directions cleanly reproduce `share` (mirrors the C assert
        // `ret1 != OK || cmp1 || ret2 != OK || cmp2`).
        writeln!(
            out,
            "    let ok1 = d1.as_deref() == Some(share);\n\
             \x20   let ok2 = d2.as_deref() == Some(share);\n\
             \x20   assert!(!(ok1 && ok2));"
        )
        .unwrap();
    } else {
        // Positive KAT: both directions reproduce `share` exactly.
        writeln!(out, "    assert_eq!(d1.as_deref(), Some(share));").unwrap();
        writeln!(out, "    assert_eq!(d2.as_deref(), Some(share));").unwrap();
    }
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

fn write_header(out: &mut String) {
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo dh`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_eal_dh.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\n",
    );
    out.push_str("#![cfg(feature = \"dh\")]\n\n");
    out.push_str("use hitls_crypto::dh::{DhKeyPair, DhParams};\n\n");
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
        "/// C source: {} (line {}, {})",
        case.tc_name, case.line, kind
    )
    .unwrap();
}
