//! Emitter for the three openHiTLS C SM2 SDV files (`sm2_sign`,
//! `sm2_crypt`, `sm2_exchange`), all consumed into one `migrated_sm2.rs`.
//!
//! Migrated KAT families:
//!
//! * `SM2_VERIFY_FUNC_TC001` / `TC002` — positive verify. Row shape
//!   `pubKey : userId : msg : sign : provider` (`TC002` prepends an extra
//!   `pubKeyTmp` that the C test overwrites — only the final `pubKey` is
//!   used). `sign` is already DER `SEQUENCE { INTEGER r, INTEGER s }`.
//! * `SM2_VERIFY_FUNC_TC003` — negative verify (corrupted key/msg/sig); the
//!   signature must NOT verify.
//! * `SM2_DEC_FUNC_TC001` — positive decrypt: `prvKey : plain : cipher`.
//! * `SM2_DEC_FUNC_TC002` — negative decrypt: `prvKey : cipher` (corrupted
//!   ciphertext); decryption must fail.
//!
//! The *sign* and *encrypt* families pin the nonce `k` via a stubbed RNG;
//! Rust's `Sm2KeyPair::sign` / `encrypt` draw `k` from the system RNG with
//! no injection hook, so those sides are not reproducible — routed to
//! `ApiSurface`. SM2 key exchange (`sm2_exchange`) has no public Rust API,
//! so the whole file routes to `skipped_unsupported_alg`.

use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::{format_byte_slice, TestCase};

pub fn emit_sm2_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();

    for case in cases {
        match classify(&case.tc_name) {
            Kind::VerifyPos => emit_verify(&mut body, case, &mut stats, false),
            Kind::VerifyNeg => emit_verify(&mut body, case, &mut stats, true),
            Kind::DecryptPos => emit_decrypt(&mut body, case, &mut stats, false),
            Kind::DecryptNeg => emit_decrypt(&mut body, case, &mut stats, true),
            Kind::Unsupported => stats.skipped_unsupported_alg += 1,
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
    VerifyPos,
    VerifyNeg,
    DecryptPos,
    DecryptNeg,
    Unsupported,
    ApiSurface,
    Unknown,
}

fn classify(tc: &str) -> Kind {
    if tc.contains("SM2_VERIFY_FUNC_TC003") {
        return Kind::VerifyNeg;
    }
    if tc.contains("SM2_VERIFY_FUNC_TC001") || tc.contains("SM2_VERIFY_FUNC_TC002") {
        return Kind::VerifyPos;
    }
    if tc.contains("SM2_DEC_FUNC_TC002") {
        return Kind::DecryptNeg;
    }
    if tc.contains("SM2_DEC_FUNC_TC001") {
        return Kind::DecryptPos;
    }
    // SM2 key exchange has no public Rust API.
    if tc.contains("SM2_EXCHANGE_FUNC") || tc.contains("SM2_EXCHANGE_CHECK") {
        return Kind::Unsupported;
    }
    // Sign / encrypt families pin `k` (not reproducible in Rust), plus all
    // the `_API_` / key-pair-check / compare / decode workflow families.
    if tc.contains("SM2_") {
        return Kind::ApiSurface;
    }
    Kind::Unknown
}

/// Skip provider-flag duplicates: the rightmost arg is `0` (default) or `1`
/// (EAL provider framework); the rest of the row is byte-identical.
fn skip_if_provider_dup(case: &TestCase) -> bool {
    matches!(case.args.last().and_then(|a| a.as_symbol()), Some("1"))
}

fn emit_verify(out: &mut String, case: &TestCase, stats: &mut EmitStats, negative: bool) {
    if skip_if_provider_dup(case) {
        stats.skipped_api += 1;
        return;
    }
    // TC002 prepends a `pubKeyTmp` arg the C test overwrites; the live
    // public key is then at index 1. TC001/TC003 start at index 0.
    let base = if case.tc_name.contains("TC002") { 1 } else { 0 };
    if case.args.len() < base + 4 {
        stats.skipped_unknown += 1;
        return;
    }
    let (Some(pubk), Some(userid), Some(msg), Some(sign)) = (
        case.args[base].as_hex(),
        case.args[base + 1].as_hex(),
        case.args[base + 2].as_hex(),
        case.args[base + 3].as_hex(),
    ) else {
        stats.skipped_unknown += 1;
        return;
    };

    let kind = if negative {
        "SM2 verify negative KAT"
    } else {
        "SM2 verify KAT"
    };
    let suffix = if negative { "_fail" } else { "" };
    write_doc(out, case, kind);
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn tc_line{}_sm2_verify{suffix}() {{", case.line).unwrap();
    writeln!(out, "    let pubk: &[u8] = {};", format_byte_slice(pubk)).unwrap();
    writeln!(
        out,
        "    let userid: &[u8] = {};",
        format_byte_slice(userid)
    )
    .unwrap();
    writeln!(out, "    let msg: &[u8] = {};", format_byte_slice(msg)).unwrap();
    writeln!(out, "    let sign: &[u8] = {};", format_byte_slice(sign)).unwrap();
    if negative {
        // A corrupted key/message/signature must not verify. A keying or
        // signature-decode error also satisfies the negative.
        writeln!(
            out,
            "    let outcome = Sm2KeyPair::from_public_key(pubk)\n\
             \x20       .and_then(|kp| kp.verify_with_id(userid, msg, sign));"
        )
        .unwrap();
        writeln!(out, "    assert!(!matches!(outcome, Ok(true)));").unwrap();
    } else {
        writeln!(
            out,
            "    let kp = Sm2KeyPair::from_public_key(pubk).unwrap();"
        )
        .unwrap();
        writeln!(
            out,
            "    assert!(kp.verify_with_id(userid, msg, sign).unwrap());"
        )
        .unwrap();
    }
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

fn emit_decrypt(out: &mut String, case: &TestCase, stats: &mut EmitStats, negative: bool) {
    if skip_if_provider_dup(case) {
        stats.skipped_api += 1;
        return;
    }
    // Positive: prvKey : plain : cipher : provider.
    // Negative: prvKey : cipher : provider.
    let need = if negative { 3 } else { 4 };
    if case.args.len() < need {
        stats.skipped_unknown += 1;
        return;
    }
    let prv = case.args[0].as_hex();
    let (cipher, plain) = if negative {
        (case.args[1].as_hex(), None)
    } else {
        (case.args[2].as_hex(), case.args[1].as_hex())
    };
    let (Some(prv), Some(cipher)) = (prv, cipher) else {
        stats.skipped_unknown += 1;
        return;
    };
    if !negative && plain.is_none() {
        stats.skipped_unknown += 1;
        return;
    }

    let kind = if negative {
        "SM2 decrypt negative KAT"
    } else {
        "SM2 decrypt KAT"
    };
    let suffix = if negative { "_fail" } else { "" };
    write_doc(out, case, kind);
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn tc_line{}_sm2_decrypt{suffix}() {{", case.line).unwrap();
    writeln!(out, "    let prv: &[u8] = {};", format_byte_slice(prv)).unwrap();
    writeln!(
        out,
        "    let cipher: &[u8] = {};",
        format_byte_slice(cipher)
    )
    .unwrap();
    if negative {
        // Corrupted ciphertext: decryption (the C3 hash check) must fail.
        writeln!(
            out,
            "    let outcome = Sm2KeyPair::from_private_key(prv)\n\
             \x20       .and_then(|kp| kp.decrypt(cipher));"
        )
        .unwrap();
        writeln!(out, "    assert!(outcome.is_err());").unwrap();
    } else {
        writeln!(
            out,
            "    let expected: &[u8] = {};",
            format_byte_slice(plain.unwrap())
        )
        .unwrap();
        writeln!(
            out,
            "    let kp = Sm2KeyPair::from_private_key(prv).unwrap();"
        )
        .unwrap();
        writeln!(
            out,
            "    assert_eq!(kp.decrypt(cipher).unwrap().as_slice(), expected);"
        )
        .unwrap();
    }
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

fn write_header(out: &mut String) {
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo sm2`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_eal_sm2_*.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\n",
    );
    out.push_str("#![cfg(feature = \"sm2\")]\n\n");
    out.push_str("use hitls_crypto::sm2::Sm2KeyPair;\n\n");
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
