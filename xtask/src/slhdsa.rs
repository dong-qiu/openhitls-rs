use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::{format_byte_slice, TestCase};

// ---------------------------------------------------------------------------
// SLH-DSA (FIPS 205) KAT migration — `test_suite_sdv_eal_slh_dsa1.data`.
//
// Scope (T153): VERIFY_KAT_TC001 only. The C row publishes the full secret
// key seed‖prf‖pk.seed‖pk.root, the message, an optional `context` byte
// string (FIPS 205 §10.2 pure-mode), the signature, and the expected C
// status. The Rust `SlhDsaKeyPair::verify(message, signature)` is the
// *low-level* SLH-DSA verify (does not wrap context); the caller has to
// pre-prepend the FIPS-205 §10.2.2 `M' = 0x00 || OCTET_TO_INT(|ctx|, 1) ||
// ctx || M` prefix. Existing `crates/hitls-crypto/src/slh_dsa/mod.rs`
// `assert_verify_kat` helper already does that — the emitter mirrors it.
//
// `addrand` (col 4) is sign-side hedging randomness — irrelevant for
// verify, ignored here.
//
// C test fn (test_suite_sdv_eal_slh_dsa1.c):
//   void SDV_CRYPTO_SLH_DSA_VERIFY_KAT_TC001(int id, Hex *key, Hex *addrand,
//       Hex *msg, Hex *context, Hex *sig, int result);
// Per row, `keyLen = N` and the `key` column is `seed(N) || prf(N) ||
// pk.seed(N) || pk.root(N)` — the public key is the last `2N` bytes.
//
// The C status values:
//   CRYPT_SUCCESS                          → verify must succeed (Ok(true)).
//   CRYPT_SLHDSA_ERR_INVALID_SIG_LEN       → verify rejects (Ok(false) per
//                                            Rust's `sig.len() != p.sig_bytes`
//                                            branch).
//   CRYPT_SLHDSA_ERR_HYPERTREE_VERIFY_FAIL → verify rejects (Ok(false)).
// All non-SUCCESS rows are negative KATs (`verify == Ok(false)`).
//
// VERIFY_PREHASHED_KAT_TC001 (1 row) is the pre-hash flavour (FIPS 205
// §10.2.3) — Rust does not expose a pre-hash verify entry point, so it
// routes to API-surface.
// ---------------------------------------------------------------------------

fn alg_enum(sym: &str) -> Option<(&'static str, &'static str, usize)> {
    // (Rust variant, short tag, N = security parameter in bytes)
    match sym {
        "CRYPT_SLH_DSA_SHA2_128S" => Some(("Sha2128s", "sha2_128s", 16)),
        "CRYPT_SLH_DSA_SHAKE_128S" => Some(("Shake128s", "shake_128s", 16)),
        "CRYPT_SLH_DSA_SHA2_128F" => Some(("Sha2128f", "sha2_128f", 16)),
        "CRYPT_SLH_DSA_SHAKE_128F" => Some(("Shake128f", "shake_128f", 16)),
        "CRYPT_SLH_DSA_SHA2_192S" => Some(("Sha2192s", "sha2_192s", 24)),
        "CRYPT_SLH_DSA_SHAKE_192S" => Some(("Shake192s", "shake_192s", 24)),
        "CRYPT_SLH_DSA_SHA2_192F" => Some(("Sha2192f", "sha2_192f", 24)),
        "CRYPT_SLH_DSA_SHAKE_192F" => Some(("Shake192f", "shake_192f", 24)),
        "CRYPT_SLH_DSA_SHA2_256S" => Some(("Sha2256s", "sha2_256s", 32)),
        "CRYPT_SLH_DSA_SHAKE_256S" => Some(("Shake256s", "shake_256s", 32)),
        "CRYPT_SLH_DSA_SHA2_256F" => Some(("Sha2256f", "sha2_256f", 32)),
        "CRYPT_SLH_DSA_SHAKE_256F" => Some(("Shake256f", "shake_256f", 32)),
        _ => None,
    }
}

fn write_doc(out: &mut String, case: &TestCase, kind: &str) {
    if let Some(desc) = &case.description {
        writeln!(out, "/// {desc}").unwrap();
    }
    writeln!(
        out,
        "/// C source: {} (line {}, {kind})",
        case.tc_name, case.line
    )
    .unwrap();
}

fn write_footer(out: &mut String, stats: &EmitStats, total: usize) {
    writeln!(
        out,
        "\n// Generation summary: {emitted} emitted / {api} API-surface skipped (N/A in Rust) \
         / {unk} unknown / {unsupported} unsupported alg / {total} total C cases.",
        emitted = stats.emitted,
        api = stats.skipped_api,
        unk = stats.skipped_unknown,
        unsupported = stats.skipped_unsupported_alg,
        total = total,
    )
    .unwrap();
}

fn emit_sign_kat(body: &mut String, stats: &mut EmitStats, case: &TestCase) {
    // Row: (isProvider, algId, key, addrand, msg, context, sig) — 7 fields.
    let (
        Some(is_provider),
        Some(alg_sym),
        Some(key),
        Some(addrand),
        Some(msg),
        Some(ctx),
        Some(sig),
    ) = (
        case.args.first().and_then(|a| a.as_symbol()),
        case.args.get(1).and_then(|a| a.as_symbol()),
        case.args.get(2).and_then(|a| a.as_hex()),
        case.args.get(3).and_then(|a| a.as_hex()),
        case.args.get(4).and_then(|a| a.as_hex()),
        case.args.get(5).and_then(|a| a.as_hex()),
        case.args.get(6).and_then(|a| a.as_hex()),
    )
    else {
        stats.skipped_unknown += 1;
        return;
    };
    if is_provider == "1" {
        // Provider-flag duplicate of the isProvider=0 row.
        stats.skipped_api += 1;
        return;
    }
    let Some((alg_var, alg_tag, n)) = alg_enum(alg_sym) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    if key.len() != 4 * n {
        stats.skipped_unknown += 1;
        return;
    }

    write_doc(body, case, "SLH-DSA sign KAT (FIPS 205 §10.2 pure mode)");
    writeln!(body, "#[test]").unwrap();
    writeln!(body, "#[allow(deprecated)]").unwrap();
    writeln!(body, "fn tc_line{}_slhdsa_sign_{alg_tag}() {{", case.line).unwrap();
    writeln!(body, "    let key: &[u8] = {};", format_byte_slice(key)).unwrap();
    writeln!(
        body,
        "    let addrand: &[u8] = {};",
        format_byte_slice(addrand)
    )
    .unwrap();
    writeln!(body, "    let msg: &[u8] = {};", format_byte_slice(msg)).unwrap();
    writeln!(body, "    let ctx: &[u8] = {};", format_byte_slice(ctx)).unwrap();
    writeln!(
        body,
        "    let expected_sig: &[u8] = {};",
        format_byte_slice(sig)
    )
    .unwrap();
    writeln!(
        body,
        "    let kp = SlhDsaKeyPair::from_private_key(SlhDsaParamId::{alg_var}, key).unwrap();"
    )
    .unwrap();
    writeln!(
        body,
        "    let mut m = Vec::with_capacity(2 + ctx.len() + msg.len());"
    )
    .unwrap();
    writeln!(body, "    m.push(0x00);").unwrap();
    writeln!(body, "    m.push(ctx.len() as u8);").unwrap();
    writeln!(body, "    m.extend_from_slice(ctx);").unwrap();
    writeln!(body, "    m.extend_from_slice(msg);").unwrap();
    writeln!(
        body,
        "    let sig = kp.sign_with_addrand(&m, addrand).unwrap();"
    )
    .unwrap();
    writeln!(body, "    assert_eq!(sig.as_slice(), expected_sig);").unwrap();
    writeln!(body, "}}\n").unwrap();
    stats.emitted += 1;
}

fn emit_genkey_kat(body: &mut String, stats: &mut EmitStats, case: &TestCase) {
    // Row: (algId, key_3n, expected_pk_2n) — 3 fields.
    // key = sk_seed(N) || sk_prf(N) || pk_seed(N); expected = pk_seed(N) || pk_root(N).
    let (Some(alg_sym), Some(key), Some(expected_pk)) = (
        case.args.first().and_then(|a| a.as_symbol()),
        case.args.get(1).and_then(|a| a.as_hex()),
        case.args.get(2).and_then(|a| a.as_hex()),
    ) else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some((alg_var, alg_tag, n)) = alg_enum(alg_sym) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    if key.len() != 3 * n || expected_pk.len() != 2 * n {
        stats.skipped_unknown += 1;
        return;
    }

    write_doc(body, case, "SLH-DSA keygen KAT (deterministic seeds)");
    writeln!(body, "#[test]").unwrap();
    writeln!(body, "#[allow(deprecated)]").unwrap();
    writeln!(body, "fn tc_line{}_slhdsa_genkey_{alg_tag}() {{", case.line).unwrap();
    writeln!(
        body,
        "    let sk_seed: &[u8] = {};",
        format_byte_slice(&key[..n])
    )
    .unwrap();
    writeln!(
        body,
        "    let sk_prf: &[u8] = {};",
        format_byte_slice(&key[n..2 * n])
    )
    .unwrap();
    writeln!(
        body,
        "    let pk_seed: &[u8] = {};",
        format_byte_slice(&key[2 * n..3 * n])
    )
    .unwrap();
    writeln!(
        body,
        "    let expected_pk: &[u8] = {};",
        format_byte_slice(expected_pk)
    )
    .unwrap();
    writeln!(
        body,
        "    let kp = SlhDsaKeyPair::from_seeds(SlhDsaParamId::{alg_var}, sk_seed, sk_prf, pk_seed).unwrap();"
    )
    .unwrap();
    writeln!(body, "    assert_eq!(kp.public_key(), expected_pk);").unwrap();
    writeln!(body, "}}\n").unwrap();
    stats.emitted += 1;
}

pub fn emit_slhdsa_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();

    for case in cases {
        if case.tc_name.contains("SIGN_KAT_TC001") {
            emit_sign_kat(&mut body, &mut stats, case);
            continue;
        }
        if case.tc_name.contains("GENKEY_KAT_TC001") {
            emit_genkey_kat(&mut body, &mut stats, case);
            continue;
        }
        if !case.tc_name.contains("VERIFY_KAT_TC001") {
            stats.skipped_api += 1;
            continue;
        }
        // The row is `(algId, key, addrand, msg, context, sig, expected)` —
        // 7 fields after the TC name. `expected` is a symbolic C status
        // macro; addrand is ignored (sign-side only).
        let (
            Some(alg_sym),
            Some(key),
            Some(_addrand),
            Some(msg),
            Some(ctx),
            Some(sig),
            Some(expected),
        ) = (
            case.args.first().and_then(|a| a.as_symbol()),
            case.args.get(1).and_then(|a| a.as_hex()),
            case.args.get(2).and_then(|a| a.as_hex()),
            case.args.get(3).and_then(|a| a.as_hex()),
            case.args.get(4).and_then(|a| a.as_hex()),
            case.args.get(5).and_then(|a| a.as_hex()),
            case.args.get(6).and_then(|a| a.as_symbol()),
        )
        else {
            stats.skipped_unknown += 1;
            continue;
        };
        let Some((alg_var, alg_tag, n)) = alg_enum(alg_sym) else {
            stats.skipped_unsupported_alg += 1;
            continue;
        };
        // Public key = key[2N..4N] (pk.seed || pk.root).
        if key.len() < 4 * n {
            stats.skipped_unknown += 1;
            continue;
        }
        let pk = &key[2 * n..4 * n];
        let expect_success = expected == "CRYPT_SUCCESS";
        let kind_tag = if expect_success { "ok" } else { "rej" };

        write_doc(
            &mut body,
            case,
            "SLH-DSA verify KAT (FIPS 205 §10.2 pure mode)",
        );
        writeln!(body, "#[test]").unwrap();
        writeln!(
            body,
            "fn tc_line{}_slhdsa_verify_{alg_tag}_{kind_tag}() {{",
            case.line
        )
        .unwrap();
        writeln!(body, "    let pk: &[u8] = {};", format_byte_slice(pk)).unwrap();
        writeln!(body, "    let msg: &[u8] = {};", format_byte_slice(msg)).unwrap();
        writeln!(body, "    let ctx: &[u8] = {};", format_byte_slice(ctx)).unwrap();
        writeln!(body, "    let sig: &[u8] = {};", format_byte_slice(sig)).unwrap();
        writeln!(
            body,
            "    let kp = SlhDsaKeyPair::from_public_key(SlhDsaParamId::{alg_var}, pk).unwrap();"
        )
        .unwrap();
        writeln!(
            body,
            "    let mut m = Vec::with_capacity(2 + ctx.len() + msg.len());"
        )
        .unwrap();
        writeln!(body, "    m.push(0x00);").unwrap();
        writeln!(body, "    m.push(ctx.len() as u8);").unwrap();
        writeln!(body, "    m.extend_from_slice(ctx);").unwrap();
        writeln!(body, "    m.extend_from_slice(msg);").unwrap();
        writeln!(body, "    let result = kp.verify(&m, sig);").unwrap();
        if expect_success {
            writeln!(
                body,
                "    assert!(matches!(result, Ok(true)), \"expected verify success, got {{:?}}\", result);"
            )
            .unwrap();
        } else {
            writeln!(
                body,
                "    assert!(!matches!(result, Ok(true)), \"expected verify failure ({expected}), got verify=Ok(true)\");"
            )
            .unwrap();
        }
        writeln!(body, "}}\n").unwrap();
        stats.emitted += 1;
    }

    let mut out = String::new();
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo slhdsa`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_eal_slh_dsa1.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\
         #![cfg(feature = \"slh-dsa\")]\n\n\
         use hitls_crypto::slh_dsa::SlhDsaKeyPair;\n\
         use hitls_types::SlhDsaParamId;\n\n",
    );
    out.push_str(&body);
    write_footer(&mut out, &stats, cases.len());
    (out, stats)
}
