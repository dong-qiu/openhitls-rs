//! Emitter for the openHiTLS C RSA SDV vectors —
//! `test_suite_sdv_eal_rsa_sign_verify.data` (sign + verify) and
//! `test_suite_sdv_eal_rsa_encrypt_decrypt.data` (decrypt).
//!
//! * `RSA_VERIFY_PKCSV15_FUNC_TC001` (`mdId : n : e : msg : sign : expect :
//!   isProvider`) — PKCS#1 v1.5 verify: `RsaPublicKey::new(n, e).verify(
//!   Pkcs1v15Sign, MD(msg), sign)`.
//! * `RSA_VERIFY_PSS_FUNC_TC001` (`mdId : n : e : salt : msg : sign : expect :
//!   isProvider`) — PSS verify (the `salt` is a sign-side input, unused here):
//!   `RsaPublicKey::new(n, e).verify_pss(MD(msg), sign, alg)`.
//! * `RSA_SIGN_PKCSV15_FUNC_TC002` (`mdId : n : d : msg : sign : isProvider`) —
//!   deterministic PKCS#1 v1.5 sign: `from_nd(n, d).sign(Pkcs1v15Sign,
//!   MD(msg)) == sign` (`kat-nonce`-gated, since `from_nd` is).
//! * `RSA_CRYPT_FUNC_TC001` (`keyLen : padMode : hashId : n : e : d :
//!   plaintext : ciphertext : isProvider`) — deterministic decrypt:
//!   `from_nd(n, d).decrypt(Pkcs1v15Encrypt, ciphertext) == plaintext`
//!   (PKCS#1 v1.5 only; see below).
//!
//! `expect == 0` (CRYPT_SUCCESS) means the signature must verify; any other
//! value means it must not. PSS is limited to SHA-256/384/512 (the Rust
//! `verify_pss` / MGF1 hashes); PSS-SHA-1/224 rows are `unsupported`. Decrypt
//! migrates PKCS#1 v1.5 only — the Rust OAEP is hardcoded to SHA-256 + empty
//! label, but every C OAEP vector uses SHA-1, so OAEP rows are `unsupported`;
//! raw `NO_PAD` rows route to `ApiSurface`. RSA *encrypt* (randomised padding)
//! and PSS *sign* (random salt) stay `ApiSurface` pending nonce hooks.

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
        } else if case.tc_name.contains("RSA_SIGN_PKCSV15_FUNC_TC002") {
            emit_sign_pkcs15(&mut body, case, &mut stats, &mut used);
        } else if case.tc_name.contains("RSA_CRYPT_FUNC_TC001") {
            emit_decrypt(&mut body, case, &mut stats, &mut used);
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

/// Map a `CRYPT_MD_*` symbol to the `RsaHashAlg` variant accepted by
/// `decrypt_oaep` (SHA-1/256/384/512 — there is no SHA-224 variant).
fn md_to_oaep_alg(symbol: &str) -> Option<&'static str> {
    match symbol {
        "CRYPT_MD_SHA1" => Some("Sha1"),
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

/// Deterministic RSA PKCS#1 v1.5 **sign** KAT (`RSA_SIGN_PKCSV15_FUNC_TC002`:
/// `mdId : n : d : msg : sign`). PKCS#1 v1.5 signing has no randomness, so the
/// signature is fully determined by `(n, d, MD(msg))`. The C vector publishes
/// only `(n, d)` (no CRT params), so the test uses the test-only
/// `RsaPrivateKey::from_nd` (behind the `kat-nonce` feature): `from_nd(n, d)
/// .sign(Pkcs1v15Sign, MD(msg)) == sign`.
fn emit_sign_pkcs15(
    out: &mut String,
    case: &TestCase,
    stats: &mut EmitStats,
    used: &mut BTreeSet<&'static str>,
) {
    if skip_if_provider_dup(case) {
        stats.skipped_api += 1;
        return;
    }
    // mdId : n : d : msg : sign : isProvider
    if case.args.len() < 5 {
        stats.skipped_unknown += 1;
        return;
    }
    let Some(hash) = case.args[0].as_symbol().and_then(md_to_hash) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let (Some(n), Some(d), Some(msg), Some(sign)) = (
        case.args[1].as_hex(),
        case.args[2].as_hex(),
        case.args[3].as_hex(),
        case.args[4].as_hex(),
    ) else {
        stats.skipped_unknown += 1;
        return;
    };
    used.insert(hash);
    used.insert("privkey");

    write_doc(out, case, "RSA PKCS#1 v1.5 deterministic sign");
    writeln!(out, "#[cfg(feature = \"kat-nonce\")]").unwrap();
    writeln!(out, "#[allow(deprecated)]").unwrap();
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn tc_line{}_rsa_pkcs15_sign() {{", case.line).unwrap();
    writeln!(out, "    let n: &[u8] = {};", format_byte_slice(n)).unwrap();
    writeln!(out, "    let d: &[u8] = {};", format_byte_slice(d)).unwrap();
    writeln!(out, "    let msg: &[u8] = {};", format_byte_slice(msg)).unwrap();
    writeln!(
        out,
        "    let expected: &[u8] = {};",
        format_byte_slice(sign)
    )
    .unwrap();
    writeln!(out, "    let digest = {hash}::digest(msg).unwrap();").unwrap();
    writeln!(out, "    let sk = RsaPrivateKey::from_nd(n, d).unwrap();").unwrap();
    writeln!(
        out,
        "    assert_eq!(sk.sign(RsaPadding::Pkcs1v15Sign, &digest).unwrap(), expected);"
    )
    .unwrap();
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

/// Deterministic RSA **decrypt** KAT (`RSA_CRYPT_FUNC_TC001`:
/// `keyLen : padMode : hashId : n : e : d : plaintext : ciphertext :
/// isProvider`). Decryption is deterministic, so `decrypt(padding,
/// ciphertext) == plaintext`. Two padding modes are migrated, both using the
/// test-only `RsaPrivateKey::from_nd` (the C vectors publish only `(n, d)`):
/// **PKCS#1 v1.5** (`decrypt(Pkcs1v15Encrypt, ct)`, no hash) and **OAEP**
/// (`decrypt_oaep(ct, RsaHashAlg::{hash})`, hash from the row's `hashId` —
/// every C OAEP vector is SHA-1). Raw `NO_PAD` rows route to API-surface
/// (plain `c^d mod n`, already exercised by the sign KATs + the existing
/// `decrypt(None, …)` unit test).
fn emit_decrypt(
    out: &mut String,
    case: &TestCase,
    stats: &mut EmitStats,
    used: &mut BTreeSet<&'static str>,
) {
    if skip_if_provider_dup(case) {
        stats.skipped_api += 1;
        return;
    }
    // keyLen : padMode : hashId : n : e : d : plaintext : ciphertext : isProvider
    if case.args.len() < 8 {
        stats.skipped_unknown += 1;
        return;
    }
    let Some(pad_mode) = case.args[1].as_symbol() else {
        stats.skipped_unknown += 1;
        return;
    };
    let (Some(n), Some(d), Some(pt), Some(ct)) = (
        case.args[3].as_hex(),
        case.args[5].as_hex(),
        case.args[6].as_hex(),
        case.args[7].as_hex(),
    ) else {
        stats.skipped_unknown += 1;
        return;
    };

    // Decrypt expression + a short fn-name suffix, by padding mode.
    let (decrypt_expr, suffix) = match pad_mode {
        "CRYPT_CTRL_SET_RSA_RSAES_PKCSV15" => (
            "sk.decrypt(RsaPadding::Pkcs1v15Encrypt, ct)".to_string(),
            "pkcs15",
        ),
        "CRYPT_CTRL_SET_RSA_RSAES_OAEP" => {
            let Some(alg) = case.args[2].as_symbol().and_then(md_to_oaep_alg) else {
                stats.skipped_unsupported_alg += 1;
                return;
            };
            used.insert("oaep");
            (format!("sk.decrypt_oaep(ct, RsaHashAlg::{alg})"), "oaep")
        }
        // Raw NO_PAD (and any other ctrl) → API-surface.
        _ => {
            stats.skipped_api += 1;
            return;
        }
    };
    used.insert("privkey");

    write_doc(out, case, "RSA deterministic decrypt");
    writeln!(out, "#[cfg(feature = \"kat-nonce\")]").unwrap();
    writeln!(out, "#[allow(deprecated)]").unwrap();
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn tc_line{}_rsa_{suffix}_decrypt() {{", case.line).unwrap();
    writeln!(out, "    let n: &[u8] = {};", format_byte_slice(n)).unwrap();
    writeln!(out, "    let d: &[u8] = {};", format_byte_slice(d)).unwrap();
    writeln!(out, "    let ct: &[u8] = {};", format_byte_slice(ct)).unwrap();
    writeln!(out, "    let expected: &[u8] = {};", format_byte_slice(pt)).unwrap();
    writeln!(out, "    let sk = RsaPrivateKey::from_nd(n, d).unwrap();").unwrap();
    writeln!(out, "    assert_eq!({decrypt_expr}.unwrap(), expected);").unwrap();
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
    if used.contains("pss") || used.contains("oaep") {
        out.push_str("use hitls_crypto::rsa::{RsaHashAlg, RsaPadding, RsaPublicKey};\n");
    } else {
        out.push_str("use hitls_crypto::rsa::{RsaPadding, RsaPublicKey};\n");
    }
    if used.contains("privkey") {
        // `RsaPrivateKey` is used only by the kat-nonce sign tests; gate the
        // import so a build without `kat-nonce` has no unused import.
        out.push_str("#[cfg(feature = \"kat-nonce\")]\n");
        out.push_str("use hitls_crypto::rsa::RsaPrivateKey;\n");
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
