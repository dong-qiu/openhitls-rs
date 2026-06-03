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
//! * `SM2_SIGN_FUNC_TC001` / `TC002` — deterministic sign. Row shape
//!   `prvKey : userId : k : msg : sign : provider` (`TC002` prepends a
//!   `prvKeyTmp` the C overwrites). The C pins the nonce `k`; the migrated test
//!   uses the test-only `Sm2KeyPair::sign_with_id_nonce` (behind the non-default
//!   `kat-nonce` feature) and checks the DER `(r, s)` matches `sign`.
//!
//! The *encrypt* family pins `k` with no nonce hook (encrypt is not migrated —
//! routed to `ApiSurface`).
//!
//! * `SM2_EXCHANGE_FUNC_TC001` — SM2 key exchange (GB/T 32918.3-2016 §6.1):
//!   `prvKey : pubKey : r : R : shareKey : userId1 : userId2 : server : provider`.
//!   I154 added `Sm2KeyPair::exchange_with_nonce`; the C `server` flag maps
//!   to `is_initiator` (the C SDV uses `server == 1` to mean "this side is
//!   party A / initiator"). The migrated test asserts the derived key
//!   matches `shareKey` byte-exactly.

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
            Kind::SignPos => emit_sign(&mut body, case, &mut stats),
            Kind::DecryptPos => emit_decrypt(&mut body, case, &mut stats, false),
            Kind::DecryptNeg => emit_decrypt(&mut body, case, &mut stats, true),
            Kind::ExchangePos => emit_exchange(&mut body, case, &mut stats),
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
    SignPos,
    DecryptPos,
    DecryptNeg,
    ExchangePos,
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
    if tc.contains("SM2_SIGN_FUNC_TC001") || tc.contains("SM2_SIGN_FUNC_TC002") {
        return Kind::SignPos;
    }
    if tc.contains("SM2_DEC_FUNC_TC002") {
        return Kind::DecryptNeg;
    }
    if tc.contains("SM2_DEC_FUNC_TC001") {
        return Kind::DecryptPos;
    }
    // SM2 key exchange: TC001 = positive KAT (migrated via I154's
    // `exchange_with_nonce`). TC002 / TC003 / TC004 / CHECK_TC are
    // workflow / negative-validity tests — `_API_` style — and stay
    // ApiSurface.
    if tc.contains("SM2_EXCHANGE_FUNC_TC001") {
        return Kind::ExchangePos;
    }
    if tc.contains("SM2_EXCHANGE_FUNC") || tc.contains("SM2_EXCHANGE_CHECK") {
        return Kind::ApiSurface;
    }
    // Encrypt KATs pin `k` (encrypt has no nonce hook), plus all the `_API_` /
    // key-pair-check / compare / decode workflow families.
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

/// Deterministic SM2 **sign** KAT (`SM2_SIGN_FUNC_TC001`:
/// `prvKey : userId : k : msg : sign : isProvider`). The C pins the nonce `k`;
/// the Rust port draws it randomly, so this uses the test-only
/// `sign_with_id_nonce` (behind the `kat-nonce` feature): `from_private_key(prv)
/// .sign_with_id_nonce(userId, msg, k) == sign`.
fn emit_sign(out: &mut String, case: &TestCase, stats: &mut EmitStats) {
    if skip_if_provider_dup(case) {
        stats.skipped_api += 1;
        return;
    }
    // TC002 prepends a `prvKeyTmp` arg the C overwrites; live fields start at
    // index 1. TC001 starts at index 0.
    let base = if case.tc_name.contains("TC002") { 1 } else { 0 };
    if case.args.len() < base + 5 {
        stats.skipped_unknown += 1;
        return;
    }
    let (Some(prv), Some(userid), Some(k), Some(msg), Some(sign)) = (
        case.args[base].as_hex(),
        case.args[base + 1].as_hex(),
        case.args[base + 2].as_hex(),
        case.args[base + 3].as_hex(),
        case.args[base + 4].as_hex(),
    ) else {
        stats.skipped_unknown += 1;
        return;
    };
    write_doc(out, case, "SM2 deterministic sign KAT");
    writeln!(out, "#[cfg(feature = \"kat-nonce\")]").unwrap();
    writeln!(out, "#[allow(deprecated)]").unwrap();
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn tc_line{}_sm2_sign() {{", case.line).unwrap();
    writeln!(out, "    let prv: &[u8] = {};", format_byte_slice(prv)).unwrap();
    writeln!(
        out,
        "    let userid: &[u8] = {};",
        format_byte_slice(userid)
    )
    .unwrap();
    writeln!(out, "    let k: &[u8] = {};", format_byte_slice(k)).unwrap();
    writeln!(out, "    let msg: &[u8] = {};", format_byte_slice(msg)).unwrap();
    writeln!(
        out,
        "    let expected: &[u8] = {};",
        format_byte_slice(sign)
    )
    .unwrap();
    writeln!(
        out,
        "    let kp = Sm2KeyPair::from_private_key(prv).unwrap();"
    )
    .unwrap();
    writeln!(
        out,
        "    assert_eq!(kp.sign_with_id_nonce(userid, msg, k).unwrap(), expected);"
    )
    .unwrap();
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

/// SM2 key-exchange row shape (`EXCHANGE_FUNC_TC001`):
/// `prvKey : pubKey : r : R : shareKey : userId1 : userId2 : server : provider`.
fn emit_exchange(out: &mut String, case: &TestCase, stats: &mut EmitStats) {
    if skip_if_provider_dup(case) {
        stats.skipped_api += 1;
        return;
    }
    if case.args.len() < 9 {
        stats.skipped_unknown += 1;
        return;
    }
    let (
        Some(prv),
        Some(peer_pub),
        Some(my_r),
        Some(peer_r),
        Some(share),
        Some(id_my),
        Some(id_peer),
        Some(server),
    ) = (
        case.args[0].as_hex(),
        case.args[1].as_hex(),
        case.args[2].as_hex(),
        case.args[3].as_hex(),
        case.args[4].as_hex(),
        case.args[5].as_hex(),
        case.args[6].as_hex(),
        case.args[7].as_symbol(),
    )
    else {
        stats.skipped_unknown += 1;
        return;
    };
    // C `server == 1` → this side is party A / initiator. `server == 0` →
    // this side is party B / responder.
    let is_initiator = match server {
        "1" => "true",
        "0" => "false",
        _ => {
            stats.skipped_unknown += 1;
            return;
        }
    };

    write_doc(out, case, "SM2 key exchange KAT (GB/T 32918.3-2016 §6.1)");
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn tc_line{}_sm2_exchange() {{", case.line).unwrap();
    writeln!(out, "    let prv: &[u8] = {};", format_byte_slice(prv)).unwrap();
    writeln!(
        out,
        "    let peer_pub: &[u8] = {};",
        format_byte_slice(peer_pub)
    )
    .unwrap();
    writeln!(out, "    let my_r: &[u8] = {};", format_byte_slice(my_r)).unwrap();
    writeln!(
        out,
        "    let peer_r: &[u8] = {};",
        format_byte_slice(peer_r)
    )
    .unwrap();
    writeln!(
        out,
        "    let expected: &[u8] = {};",
        format_byte_slice(share)
    )
    .unwrap();
    writeln!(out, "    let id_my: &[u8] = {};", format_byte_slice(id_my)).unwrap();
    writeln!(
        out,
        "    let id_peer: &[u8] = {};",
        format_byte_slice(id_peer)
    )
    .unwrap();
    writeln!(
        out,
        "    let kp = Sm2KeyPair::from_private_key(prv).unwrap();"
    )
    .unwrap();
    writeln!(
        out,
        "    let key = kp\n\
         \x20       .exchange_with_nonce(my_r, peer_pub, peer_r, id_my, id_peer, \
         {is_initiator}, expected.len())\n\
         \x20       .unwrap();"
    )
    .unwrap();
    writeln!(out, "    assert_eq!(key.as_slice(), expected);").unwrap();
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
