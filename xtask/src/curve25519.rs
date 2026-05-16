//! Emitter for openHiTLS C `test_suite_sdv_eal_curve25519.data`.
//!
//! Real KAT families:
//!
//! * `ED25519_SIGN_FUNC_TC001`        — `prv : msg : expected_sig : provider`
//! * `ED25519_VERIFY_FUNC_TC001`      — `pub : msg : sig : provider`
//! * `ED25519_SIGN_VERIFY_FUNC_TC001` — `prv : pub : msg : expected_sig : provider`
//! * `X25519_EXCH_FUNC_TC002`         — `pub : prv : expected_shared : provider`
//!   (matches C signature `SDV_CRYPTO_X25519_EXCH_FUNC_TC002(Hex *pubkey, Hex *prvkey, Hex *share, int isProvider)`)
//!
//! Everything else is API-surface (CRYPT_EAL_PkeyCtx CRUD, key-bit getters,
//! provider-only sanity sweeps); routed to `ApiSurface`.

use std::collections::BTreeSet;
use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::{format_byte_slice, Arg, TestCase};

pub fn emit_curve25519_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();
    let mut used: BTreeSet<&'static str> = BTreeSet::new();

    for case in cases {
        match classify(&case.tc_name) {
            Kind::Ed25519Sign => emit_ed25519_sign(&mut body, case, &mut stats, &mut used),
            Kind::Ed25519Verify => emit_ed25519_verify(&mut body, case, &mut stats, &mut used),
            Kind::Ed25519SignVerify => {
                emit_ed25519_sign_verify(&mut body, case, &mut stats, &mut used)
            }
            Kind::X25519Exch => emit_x25519_exch(&mut body, case, &mut stats, &mut used),
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
    Ed25519Sign,
    Ed25519Verify,
    Ed25519SignVerify,
    X25519Exch,
    ApiSurface,
    Unknown,
}

fn classify(tc: &str) -> Kind {
    // Real one-shot KAT families first (most specific).
    if tc.contains("ED25519_SIGN_VERIFY_FUNC_TC001") {
        return Kind::Ed25519SignVerify;
    }
    if tc.contains("ED25519_SIGN_FUNC_TC001") {
        return Kind::Ed25519Sign;
    }
    if tc.contains("ED25519_VERIFY_FUNC_TC001") {
        return Kind::Ed25519Verify;
    }
    if tc.contains("X25519_EXCH_FUNC_TC002") {
        return Kind::X25519Exch;
    }
    // X25519_EXCH_FUNC_TC001 is a 1-arg provider-flag sanity sweep; no KAT.
    if tc.contains("_API_TC")
        || tc.contains("_EXCH_FUNC_TC001")
        || tc.contains("_CMP_FUNC_TC")
        || tc.contains("_GET_KEY_BITS_FUNC_TC")
        || tc.contains("_GET_SECURITY_BITS_FUNC_TC")
        || tc.contains("_KEY_PAIR_CHECK_FUNC_TC")
        || tc.contains("_PRV_KEY_CHECK_FUNC_TC")
        || tc.contains("_DUP_CTX_API_TC")
    {
        return Kind::ApiSurface;
    }
    Kind::Unknown
}

/// Skip provider-flag duplicates: the rightmost arg is `0` (default
/// provider) or `1` (EAL provider framework); the rest of the row is
/// byte-identical. Rust has no provider concept, so emitting both would
/// just duplicate tests.
fn skip_if_provider_dup(case: &TestCase) -> bool {
    matches!(
        case.args.last(),
        Some(Arg::Symbol(s)) if s == "1"
    )
}

fn emit_ed25519_sign(
    out: &mut String,
    case: &TestCase,
    stats: &mut EmitStats,
    used: &mut BTreeSet<&'static str>,
) {
    if skip_if_provider_dup(case) {
        stats.skipped_api += 1;
        return;
    }
    // Shape: prv : msg : expected_sig : provider
    if case.args.len() < 4 {
        stats.skipped_unknown += 1;
        return;
    }
    let Some(prv) = case.args[0].as_hex() else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(msg) = case.args[1].as_hex() else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(expected) = case.args[2].as_hex() else {
        stats.skipped_unknown += 1;
        return;
    };
    if prv.len() != 32 || expected.len() != 64 {
        stats.skipped_unknown += 1;
        return;
    }
    used.insert("ed25519");

    let fn_name = format!("tc_line{}_ed25519_sign", case.line);
    write_doc(out, case, "ed25519 sign KAT");
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn {fn_name}() {{").unwrap();
    writeln!(out, "    let seed: &[u8] = {};", format_byte_slice(prv)).unwrap();
    writeln!(out, "    let msg: &[u8] = {};", format_byte_slice(msg)).unwrap();
    writeln!(
        out,
        "    let expected: &[u8] = {};",
        format_byte_slice(expected)
    )
    .unwrap();
    writeln!(
        out,
        "    let kp = Ed25519KeyPair::from_seed(seed).unwrap();"
    )
    .unwrap();
    writeln!(out, "    let sig = kp.sign(msg).unwrap();").unwrap();
    writeln!(out, "    assert_eq!(sig.as_ref(), expected);").unwrap();
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

fn emit_ed25519_verify(
    out: &mut String,
    case: &TestCase,
    stats: &mut EmitStats,
    used: &mut BTreeSet<&'static str>,
) {
    if skip_if_provider_dup(case) {
        stats.skipped_api += 1;
        return;
    }
    // Shape: pub : msg : sig : provider
    if case.args.len() < 4 {
        stats.skipped_unknown += 1;
        return;
    }
    let Some(pubk) = case.args[0].as_hex() else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(msg) = case.args[1].as_hex() else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(sig) = case.args[2].as_hex() else {
        stats.skipped_unknown += 1;
        return;
    };
    if pubk.len() != 32 || sig.len() != 64 {
        stats.skipped_unknown += 1;
        return;
    }
    used.insert("ed25519");

    let fn_name = format!("tc_line{}_ed25519_verify", case.line);
    write_doc(out, case, "ed25519 verify KAT");
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn {fn_name}() {{").unwrap();
    writeln!(out, "    let pub_key: &[u8] = {};", format_byte_slice(pubk)).unwrap();
    writeln!(out, "    let msg: &[u8] = {};", format_byte_slice(msg)).unwrap();
    writeln!(out, "    let sig: &[u8] = {};", format_byte_slice(sig)).unwrap();
    writeln!(
        out,
        "    let kp = Ed25519KeyPair::from_public_key(pub_key).unwrap();"
    )
    .unwrap();
    writeln!(out, "    assert!(kp.verify(msg, sig).unwrap());").unwrap();
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

fn emit_ed25519_sign_verify(
    out: &mut String,
    case: &TestCase,
    stats: &mut EmitStats,
    used: &mut BTreeSet<&'static str>,
) {
    if skip_if_provider_dup(case) {
        stats.skipped_api += 1;
        return;
    }
    // Shape: prv : pub : msg : expected_sig : provider
    if case.args.len() < 5 {
        stats.skipped_unknown += 1;
        return;
    }
    let Some(prv) = case.args[0].as_hex() else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(pubk) = case.args[1].as_hex() else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(msg) = case.args[2].as_hex() else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(expected) = case.args[3].as_hex() else {
        stats.skipped_unknown += 1;
        return;
    };
    if prv.len() != 32 || pubk.len() != 32 || expected.len() != 64 {
        stats.skipped_unknown += 1;
        return;
    }
    used.insert("ed25519");

    let fn_name = format!("tc_line{}_ed25519_sign_verify", case.line);
    write_doc(out, case, "ed25519 round-trip KAT");
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn {fn_name}() {{").unwrap();
    writeln!(out, "    let seed: &[u8] = {};", format_byte_slice(prv)).unwrap();
    writeln!(out, "    let pub_key: &[u8] = {};", format_byte_slice(pubk)).unwrap();
    writeln!(out, "    let msg: &[u8] = {};", format_byte_slice(msg)).unwrap();
    writeln!(
        out,
        "    let expected: &[u8] = {};",
        format_byte_slice(expected)
    )
    .unwrap();
    writeln!(
        out,
        "    let signer = Ed25519KeyPair::from_seed(seed).unwrap();"
    )
    .unwrap();
    writeln!(
        out,
        "    assert_eq!(signer.public_key().as_slice(), pub_key);"
    )
    .unwrap();
    writeln!(out, "    let sig = signer.sign(msg).unwrap();").unwrap();
    writeln!(out, "    assert_eq!(sig.as_ref(), expected);").unwrap();
    writeln!(
        out,
        "    let verifier = Ed25519KeyPair::from_public_key(pub_key).unwrap();"
    )
    .unwrap();
    writeln!(out, "    assert!(verifier.verify(msg, expected).unwrap());").unwrap();
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

fn emit_x25519_exch(
    out: &mut String,
    case: &TestCase,
    stats: &mut EmitStats,
    used: &mut BTreeSet<&'static str>,
) {
    if skip_if_provider_dup(case) {
        stats.skipped_api += 1;
        return;
    }
    // Shape: pub : prv : expected_shared : provider
    if case.args.len() < 4 {
        stats.skipped_unknown += 1;
        return;
    }
    let Some(pubk) = case.args[0].as_hex() else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(prv) = case.args[1].as_hex() else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(expected) = case.args[2].as_hex() else {
        stats.skipped_unknown += 1;
        return;
    };
    if prv.len() != 32 || pubk.len() != 32 || expected.len() != 32 {
        stats.skipped_unknown += 1;
        return;
    }
    used.insert("x25519");

    let fn_name = format!("tc_line{}_x25519_exchange", case.line);
    write_doc(out, case, "x25519 ECDH KAT");
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn {fn_name}() {{").unwrap();
    writeln!(out, "    let prv: &[u8] = {};", format_byte_slice(prv)).unwrap();
    writeln!(out, "    let pubk: &[u8] = {};", format_byte_slice(pubk)).unwrap();
    writeln!(
        out,
        "    let expected: &[u8] = {};",
        format_byte_slice(expected)
    )
    .unwrap();
    writeln!(
        out,
        "    let prv_key = X25519PrivateKey::new(prv).unwrap();"
    )
    .unwrap();
    writeln!(
        out,
        "    let pub_key = X25519PublicKey::new(pubk).unwrap();"
    )
    .unwrap();
    writeln!(
        out,
        "    let shared = prv_key.diffie_hellman(&pub_key).unwrap();"
    )
    .unwrap();
    writeln!(out, "    assert_eq!(shared.as_slice(), expected);").unwrap();
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

fn write_header(out: &mut String, used: &BTreeSet<&'static str>) {
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo curve25519`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_eal_curve25519.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\n",
    );
    out.push_str("#![cfg(any(feature = \"ed25519\", feature = \"x25519\"))]\n\n");
    let mut imports = Vec::new();
    if used.contains("ed25519") {
        imports.push("#[cfg(feature = \"ed25519\")]\nuse hitls_crypto::ed25519::Ed25519KeyPair;");
    }
    if used.contains("x25519") {
        imports.push(
            "#[cfg(feature = \"x25519\")]\nuse hitls_crypto::x25519::{X25519PrivateKey, X25519PublicKey};",
        );
    }
    for line in imports {
        writeln!(out, "{line}").unwrap();
    }
    if !used.is_empty() {
        out.push('\n');
    }
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
    // The classifier already gates feature-cfg via the file header, but
    // individual tests still need the gate for `cargo test
    // --no-default-features --features ed25519` to compile cleanly when
    // x25519 tests would reference an absent symbol (and vice versa).
    if kind.starts_with("ed25519") {
        writeln!(out, "#[cfg(feature = \"ed25519\")]").unwrap();
    } else if kind.starts_with("x25519") {
        writeln!(out, "#[cfg(feature = \"x25519\")]").unwrap();
    }
}
