//! Emitter for openHiTLS C `test_suite_sdv_mldsa.data` — ML-DSA (FIPS 204).
//!
//! Migrates the pure-verify KAT family `MLDSA_FUNC_VERIFYDATA_TC001`
//! (`type : pubKey : msg : sign : res`). The C case sets
//! `CRYPT_CTRL_SET_MLDSA_ENCODE_FLAG = 0` and no context, then calls
//! `CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, msg, …)` — i.e. it verifies the
//! *raw* message under the FIPS 204 *internal* interface (μ = H(tr ‖ M)). Rust
//! `mldsa::mldsa_verify(pk, message, sig, params)` is exactly that internal
//! variant, so the message is passed through unmodified (no §5.2
//! `0x00‖len(ctx)‖ctx‖M` prefix — that is the *pure* interface, used by
//! X.509/CMS, not here).
//!
//! `res == 1` means C expects `CRYPT_SUCCESS` (verify true); any other value
//! means C expects `ret != CRYPT_SUCCESS`, so the migrated test asserts the
//! verify did **not** return `Ok(true)` (an `Err` or `Ok(false)` both satisfy
//! the C `ASSERT_NE`).
//!
//! `SIGNDATA_TC001` (`type : seed : prvKey : msg : sign`) is also migrated: the
//! C injects `seed` as the FIPS 204 hedging `rnd` (`ρ' = H(K ‖ rnd ‖ μ)`), and
//! the test reproduces it via the test-only `MlDsaKeyPair::sign_with_rnd`
//! (behind the non-default `kat-nonce` feature). The context / external-mu /
//! prehash sign+verify variants and keygen / API-surface cases are not emitted.

use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::{format_byte_slice, TestCase};

pub fn emit_mldsa_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();

    for case in cases {
        match classify(&case.tc_name) {
            Kind::VerifyData => emit_verify(&mut body, case, &mut stats),
            Kind::SignData => emit_sign(&mut body, case, &mut stats),
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
    VerifyData,
    SignData,
    ApiSurface,
    Unknown,
}

fn classify(tc: &str) -> Kind {
    if tc.contains("MLDSA_FUNC_VERIFYDATA_TC001") {
        return Kind::VerifyData;
    }
    if tc.contains("MLDSA_FUNC_SIGNDATA_TC001") {
        return Kind::SignData;
    }
    // Context/external-mu/prehash sign+verify variants, keygen and EAL CRUD are
    // all API-surface for this mechanical pass.
    if tc.contains("MLDSA_FUNC_SIGNDATA")
        || tc.contains("MLDSA_FUNC_SIGN_")
        || tc.contains("MLDSA_FUNC_VERIFYDATA_TC002")
        || tc.contains("MLDSA_FUNC_VERIFY_TC001")
        || tc.contains("MLDSA_FUNC_KEYGEN")
        || tc.contains("_API_")
        || tc.contains("_FUNC_KEY")
    {
        return Kind::ApiSurface;
    }
    Kind::Unknown
}

/// Map the C `CRYPT_MLDSA_TYPE_MLDSA_*` symbol to the Rust parameter-set id.
fn type_to_param(symbol: &str) -> Option<u32> {
    match symbol {
        "CRYPT_MLDSA_TYPE_MLDSA_44" => Some(44),
        "CRYPT_MLDSA_TYPE_MLDSA_65" => Some(65),
        "CRYPT_MLDSA_TYPE_MLDSA_87" => Some(87),
        _ => None,
    }
}

fn emit_verify(out: &mut String, case: &TestCase, stats: &mut EmitStats) {
    // Shape: type : pubKey : msg : sign : res
    if case.args.len() < 5 {
        stats.skipped_unknown += 1;
        return;
    }
    let Some(param) = case.args[0].as_symbol().and_then(type_to_param) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let (Some(pk), Some(msg), Some(sig)) = (
        case.args[1].as_hex(),
        case.args[2].as_hex(),
        case.args[3].as_hex(),
    ) else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(res) = case.args[4].as_symbol().and_then(|s| s.parse::<i64>().ok()) else {
        stats.skipped_unknown += 1;
        return;
    };
    let expect_ok = res == 1;

    let fn_name = format!("tc_line{}_mldsa{}_verify", case.line, param);
    write_doc(out, case, param);
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn {fn_name}() {{").unwrap();
    writeln!(out, "    let pk: &[u8] = {};", format_byte_slice(pk)).unwrap();
    writeln!(out, "    let msg: &[u8] = {};", format_byte_slice(msg)).unwrap();
    writeln!(out, "    let sig: &[u8] = {};", format_byte_slice(sig)).unwrap();
    writeln!(out, "    let params = get_params({param}).unwrap();").unwrap();
    writeln!(
        out,
        "    let verified = mldsa_verify(pk, msg, sig, &params).unwrap_or(false);"
    )
    .unwrap();
    if expect_ok {
        writeln!(out, "    assert!(verified);").unwrap();
    } else {
        writeln!(out, "    assert!(!verified);").unwrap();
    }
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

/// Deterministic ML-DSA **sign** KAT (`SIGNDATA_TC001`:
/// `type : seed : prvKey : msg : sign`). The C injects `seed` as the FIPS 204
/// hedging randomness `rnd` via a stubbed RNG (`ρ' = H(K ‖ rnd ‖ μ)`), with
/// `ENCODE_FLAG=0` → the internal interface (μ = H(tr ‖ M) on the raw msg). The
/// migrated test reproduces it with the test-only `sign_with_rnd` (behind the
/// `kat-nonce` feature): `from_private_key(type, prvKey).sign_with_rnd(msg,
/// seed) == sign`.
fn emit_sign(out: &mut String, case: &TestCase, stats: &mut EmitStats) {
    // Shape: type : seed : prvKey : msg : sign
    if case.args.len() < 5 {
        stats.skipped_unknown += 1;
        return;
    }
    let Some(param) = case.args[0].as_symbol().and_then(type_to_param) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let (Some(seed), Some(prv), Some(msg), Some(sign)) = (
        case.args[1].as_hex(),
        case.args[2].as_hex(),
        case.args[3].as_hex(),
        case.args[4].as_hex(),
    ) else {
        stats.skipped_unknown += 1;
        return;
    };

    let fn_name = format!("tc_line{}_mldsa{}_sign", case.line, param);
    write_doc(out, case, param);
    writeln!(out, "#[cfg(feature = \"kat-nonce\")]").unwrap();
    writeln!(out, "#[allow(deprecated)]").unwrap();
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn {fn_name}() {{").unwrap();
    writeln!(out, "    let seed: &[u8] = {};", format_byte_slice(seed)).unwrap();
    writeln!(out, "    let prv: &[u8] = {};", format_byte_slice(prv)).unwrap();
    writeln!(out, "    let msg: &[u8] = {};", format_byte_slice(msg)).unwrap();
    writeln!(
        out,
        "    let expected: &[u8] = {};",
        format_byte_slice(sign)
    )
    .unwrap();
    writeln!(
        out,
        "    let kp = MlDsaKeyPair::from_private_key({param}, prv).unwrap();"
    )
    .unwrap();
    writeln!(
        out,
        "    assert_eq!(kp.sign_with_rnd(msg, seed).unwrap(), expected);"
    )
    .unwrap();
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

fn write_header(out: &mut String) {
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo mldsa`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_mldsa.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\n",
    );
    out.push_str("#![cfg(feature = \"mldsa\")]\n\n");
    out.push_str("use hitls_crypto::mldsa::{get_params, mldsa_verify};\n");
    // `MlDsaKeyPair` is used only by the kat-nonce sign tests; gate the import
    // so a build without `kat-nonce` has no unused import under `-D warnings`.
    out.push_str("#[cfg(feature = \"kat-nonce\")]\n");
    out.push_str("use hitls_crypto::mldsa::MlDsaKeyPair;\n\n");
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

fn write_doc(out: &mut String, case: &TestCase, param: u32) {
    if let Some(desc) = &case.description {
        writeln!(out, "/// {desc}").unwrap();
    }
    writeln!(
        out,
        "/// C source: {} (line {}, ML-DSA-{param} internal verify KAT)",
        case.tc_name, case.line
    )
    .unwrap();
}
