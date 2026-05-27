//! Emitter for openHiTLS C `test_suite_sdv_eal_ecdsa.data` +
//! `test_suite_sdv_eal_ecdh.data` — ECDSA verify + ECDH key exchange.
//!
//! * `SDV_CRYPTO_ECDSA_SIGN_VERIFY_FUNC_TC001`
//!   (`eccId : mdId : prvKey : msg : signR : signS : rand : pubKeyX : pubKeyY :
//!   pointFormat : isProvider`) — the C signs (with an injected nonce to match
//!   the published `(R,S)`) then verifies. Sign is not reproducible without a
//!   nonce hook, so the *verify* side is migrated: build the public key from
//!   the row's `(pubKeyX, pubKeyY)`, DER-encode `(R,S)`, and check
//!   `EcdsaKeyPair::from_public_key(curve, 0x04‖X‖Y).verify(MD(msg), sig)`.
//! * `SDV_CRYPTO_ECDH_EXCH_FUNC_TC001`
//!   (`eccId : prvKey : pubKeyX : pubKeyY : pointFormat : shareKey :
//!   isProvider`) — deterministic key exchange: local private key × peer
//!   public point → shared secret, checked against `shareKey`.
//!
//! Everything else (key-pair / pub / prv generation + checks, ctx CRUD, point
//! mul/add property tests, ECDSA sign-side, the `_API_` rows) is API-surface.

use std::collections::BTreeSet;
use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::{format_byte_slice, TestCase};

pub fn emit_ecc_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();
    let mut used: BTreeSet<&'static str> = BTreeSet::new();

    for case in cases {
        if case.tc_name.contains("ECDSA_SIGN_VERIFY_FUNC_TC001") {
            emit_ecdsa_verify(&mut body, case, &mut stats, &mut used);
        } else if case.tc_name.contains("ECDH_EXCH_FUNC_TC001") {
            emit_ecdh(&mut body, case, &mut stats, &mut used);
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

/// Map the C `CRYPT_ECC_*` curve symbol to the Rust `EccCurveId` variant.
fn curve(symbol: &str) -> Option<&'static str> {
    match symbol {
        "CRYPT_ECC_NISTP192" => Some("NistP192"),
        "CRYPT_ECC_NISTP224" => Some("NistP224"),
        "CRYPT_ECC_NISTP256" => Some("NistP256"),
        "CRYPT_ECC_NISTP384" => Some("NistP384"),
        "CRYPT_ECC_NISTP521" => Some("NistP521"),
        "CRYPT_ECC_BRAINPOOLP256R1" => Some("BrainpoolP256r1"),
        "CRYPT_ECC_BRAINPOOLP384R1" => Some("BrainpoolP384r1"),
        "CRYPT_ECC_BRAINPOOLP512R1" => Some("BrainpoolP512r1"),
        "CRYPT_ECC_SM2" => Some("Sm2Prime256"),
        _ => None,
    }
}

/// Map a `CRYPT_MD_*` symbol to the hitls-crypto digest type.
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

/// Build the uncompressed SEC1 public-key encoding `0x04 ‖ X ‖ Y`.
fn uncompressed_point(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(1 + x.len() + y.len());
    p.push(0x04);
    p.extend_from_slice(x);
    p.extend_from_slice(y);
    p
}

fn emit_ecdsa_verify(
    out: &mut String,
    case: &TestCase,
    stats: &mut EmitStats,
    used: &mut BTreeSet<&'static str>,
) {
    if skip_if_provider_dup(case) {
        stats.skipped_api += 1;
        return;
    }
    // eccId : mdId : prv : msg : R : S : rand : pubX : pubY : fmt : isProvider
    if case.args.len() < 9 {
        stats.skipped_unknown += 1;
        return;
    }
    let (Some(curve_ty), Some(md)) = (
        case.args[0].as_symbol().and_then(curve),
        case.args[1].as_symbol(),
    ) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let Some(hash) = md_to_hash(md) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let (Some(msg), Some(r), Some(s), Some(px), Some(py)) = (
        case.args[3].as_hex(),
        case.args[4].as_hex(),
        case.args[5].as_hex(),
        case.args[7].as_hex(),
        case.args[8].as_hex(),
    ) else {
        stats.skipped_unknown += 1;
        return;
    };
    let pubkey = uncompressed_point(px, py);
    let sig = der_encode_sig(r, s);
    used.insert("ecdsa");
    used.insert(hash);

    let fn_name = format!(
        "tc_line{}_ecdsa_{}_verify",
        case.line,
        curve_ty.to_lowercase()
    );
    write_doc(out, case, "ECDSA verify");
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn {fn_name}() {{").unwrap();
    writeln!(
        out,
        "    let pubkey: &[u8] = {};",
        format_byte_slice(&pubkey)
    )
    .unwrap();
    writeln!(out, "    let msg: &[u8] = {};", format_byte_slice(msg)).unwrap();
    writeln!(out, "    let sig: &[u8] = {};", format_byte_slice(&sig)).unwrap();
    writeln!(
        out,
        "    let kp = EcdsaKeyPair::from_public_key(EccCurveId::{curve_ty}, pubkey).unwrap();"
    )
    .unwrap();
    writeln!(out, "    let digest = {hash}::digest(msg).unwrap();").unwrap();
    writeln!(out, "    assert!(kp.verify(&digest, sig).unwrap());").unwrap();
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

fn emit_ecdh(
    out: &mut String,
    case: &TestCase,
    stats: &mut EmitStats,
    used: &mut BTreeSet<&'static str>,
) {
    if skip_if_provider_dup(case) {
        stats.skipped_api += 1;
        return;
    }
    // eccId : prv : pubX : pubY : fmt : shareKey : isProvider
    if case.args.len() < 6 {
        stats.skipped_unknown += 1;
        return;
    }
    let Some(curve_ty) = case.args[0].as_symbol().and_then(curve) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let (Some(prv), Some(px), Some(py), Some(share)) = (
        case.args[1].as_hex(),
        case.args[2].as_hex(),
        case.args[3].as_hex(),
        case.args[5].as_hex(),
    ) else {
        stats.skipped_unknown += 1;
        return;
    };
    let peer_pub = uncompressed_point(px, py);
    used.insert("ecdh");

    let fn_name = format!("tc_line{}_ecdh_{}", case.line, curve_ty.to_lowercase());
    write_doc(out, case, "ECDH key exchange");
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn {fn_name}() {{").unwrap();
    writeln!(out, "    let prv: &[u8] = {};", format_byte_slice(prv)).unwrap();
    writeln!(
        out,
        "    let peer_pub: &[u8] = {};",
        format_byte_slice(&peer_pub)
    )
    .unwrap();
    writeln!(
        out,
        "    let expected: &[u8] = {};",
        format_byte_slice(share)
    )
    .unwrap();
    writeln!(
        out,
        "    let kp = EcdhKeyPair::from_private_key(EccCurveId::{curve_ty}, prv).unwrap();"
    )
    .unwrap();
    writeln!(
        out,
        "    assert_eq!(kp.compute_shared_secret(peer_pub).unwrap(), expected);"
    )
    .unwrap();
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

/// DER-encode an ECDSA signature as `SEQUENCE { INTEGER r, INTEGER s }` — the
/// form `EcdsaKeyPair::verify` decodes. (Shared shape with the DSA emitter.)
fn der_encode_sig(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut content = der_int(r);
    content.extend(der_int(s));
    let mut out = vec![0x30];
    der_len(&mut out, content.len());
    out.extend(content);
    out
}

fn der_int(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes;
    while v.len() > 1 && v[0] == 0 {
        v = &v[1..];
    }
    let mut content: Vec<u8> = if v.is_empty() { vec![0] } else { v.to_vec() };
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    let mut out = vec![0x02];
    der_len(&mut out, content.len());
    out.extend(content);
    out
}

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
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo ecc`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_eal_ecdsa.data\n\
         // + test_suite_sdv_eal_ecdh.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\n",
    );
    // Gate the file on every feature it touches. ECDSA verify hashes the
    // message, so the sha1/sha2 digest features must be required too —
    // otherwise a narrow build like `--features ecdsa,ecdh` (no digests, as the
    // cargo-careful CI step uses) would fail to compile the `use sha*` imports.
    let mut features = vec![];
    if used.contains("ecdsa") {
        features.push("feature = \"ecdsa\"");
    }
    if used.contains("ecdh") {
        features.push("feature = \"ecdh\"");
    }
    if used.contains("Sha1") {
        features.push("feature = \"sha1\"");
    }
    if ["Sha224", "Sha256", "Sha384", "Sha512"]
        .iter()
        .any(|h| used.contains(h))
    {
        features.push("feature = \"sha2\"");
    }
    writeln!(out, "#![cfg(all({}))]\n", features.join(", ")).unwrap();
    if used.contains("ecdsa") {
        out.push_str("use hitls_crypto::ecdsa::EcdsaKeyPair;\n");
    }
    if used.contains("ecdh") {
        out.push_str("use hitls_crypto::ecdh::EcdhKeyPair;\n");
    }
    out.push_str("use hitls_types::EccCurveId;\n");
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
