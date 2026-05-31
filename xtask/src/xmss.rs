use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::{format_byte_slice, TestCase};

// ---------------------------------------------------------------------------
// XMSS / XMSS-MT (RFC 8391) KAT migration — `test_suite_sdv_eal_xmss.data`.
//
// Scope (T155): VERIFY_KAT_TC001 only. Each row carries an XMSS or XMSS-MT
// public key (`PK.seed || PK.root`, `2*n` bytes), a message, a signature,
// and an expected C status. We dispatch on the algId prefix
// (`CRYPT_XMSS_*` → single-tree `XmssKeyPair`; `CRYPT_XMSSMT_*` →
// multi-tree `XmssMtKeyPair`) and call the new (default-feature) public
// `from_public_key(param, pk_seed_root)` constructor + the existing
// `verify(msg, sig)`. SIGN_KAT (28 rows) + GENKEY_KAT (14 rows) are
// deferred to T156+ (need a `kat-nonce`-gated `from_private_key` +
// `sign_at_index` + `from_seeds` similar to the SLH-DSA T154 hooks).
//
// C test fn (test_suite_sdv_eal_xmss.c):
//   void SDV_CRYPTO_XMSS_VERIFY_KAT_TC001(int id, Hex *key, Hex *msg,
//       Hex *sig, int result);
// `key` is the raw 2*n public key `PK.seed || PK.root`. C status values:
//   CRYPT_SUCCESS                        → Ok(true).
//   CRYPT_XMSS_ERR_INVALID_SIG_LEN       → Ok(false) per the Rust
//                                          `signature.len() != p.sig_bytes`
//                                          length-check branch.
//   CRYPT_XMSS_ERR_MERKLETREE_ROOT_MISMATCH → Ok(false) per the inner
//                                          verify failing the root check.
// ---------------------------------------------------------------------------

/// Single-tree XMSS algorithm map: (Rust variant, short tag).
fn xmss_enum(sym: &str) -> Option<(&'static str, &'static str)> {
    match sym {
        "CRYPT_XMSS_SHA2_10_256" => Some(("Sha2_10_256", "sha2_10_256")),
        "CRYPT_XMSS_SHA2_10_512" => Some(("Sha2_10_512", "sha2_10_512")),
        "CRYPT_XMSS_SHA2_10_192" => Some(("Sha2_10_192", "sha2_10_192")),
        "CRYPT_XMSS_SHAKE_10_256" => Some(("Shake128_10_256", "shake128_10_256")),
        "CRYPT_XMSS_SHAKE256_10_256" => Some(("Shake256_10_256", "shake256_10_256")),
        "CRYPT_XMSS_SHAKE256_10_192" => Some(("Shake256_10_192", "shake256_10_192")),
        _ => None,
    }
}

/// Multi-tree XMSS-MT algorithm map: (Rust variant, short tag).
fn xmssmt_enum(sym: &str) -> Option<(&'static str, &'static str)> {
    match sym {
        "CRYPT_XMSSMT_SHA2_20_2_256" => Some(("Sha2_20_2_256", "sha2_20_2_256")),
        "CRYPT_XMSSMT_SHA2_20_2_512" => Some(("Sha2_20_2_512", "sha2_20_2_512")),
        "CRYPT_XMSSMT_SHA2_20_2_192" => Some(("Sha2_20_2_192", "sha2_20_2_192")),
        "CRYPT_XMSSMT_SHAKE_20_2_256" => Some(("Shake128_20_2_256", "shake128_20_2_256")),
        "CRYPT_XMSSMT_SHAKE_20_2_512" => Some(("Shake256_20_2_512", "shake256_20_2_512")),
        "CRYPT_XMSSMT_SHAKE256_20_2_256" => Some(("Shake256_20_2_256", "shake256_20_2_256")),
        "CRYPT_XMSSMT_SHAKE256_20_2_192" => Some(("Shake256_20_2_192", "shake256_20_2_192")),
        _ => None,
    }
}

// Note: the C uses `CRYPT_XMSSMT_SHAKE_20_2_512` to mean SHAKE256 (the
// Shake128 family stops at 256-bit hash output per RFC 8391 §5.2), so we
// map it to `XmssMtParamId::Shake256_20_2_512`.

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

pub fn emit_xmss_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();

    for case in cases {
        if !case.tc_name.contains("VERIFY_KAT_TC001") {
            // SIGN_KAT / GENKEY_KAT / API* / GETSET / NEW route to API-surface
            // in T155; T156+ will add `kat-nonce`-gated hooks for them.
            stats.skipped_api += 1;
            continue;
        }
        // Row: (algId, key, msg, sig, result) — 5 fields.
        let (Some(alg_sym), Some(key), Some(msg), Some(sig), Some(expected)) = (
            case.args.first().and_then(|a| a.as_symbol()),
            case.args.get(1).and_then(|a| a.as_hex()),
            case.args.get(2).and_then(|a| a.as_hex()),
            case.args.get(3).and_then(|a| a.as_hex()),
            case.args.get(4).and_then(|a| a.as_symbol()),
        ) else {
            stats.skipped_unknown += 1;
            continue;
        };

        // Dispatch on the algId prefix (XMSS vs XMSSMT).
        let (kp_type, param_type, alg_var, alg_tag) = if let Some((v, t)) = xmss_enum(alg_sym) {
            ("XmssKeyPair", "XmssParamId", v, t)
        } else if let Some((v, t)) = xmssmt_enum(alg_sym) {
            ("XmssMtKeyPair", "XmssMtParamId", v, t)
        } else {
            stats.skipped_unsupported_alg += 1;
            continue;
        };

        let expect_success = expected == "CRYPT_SUCCESS";
        let kind_tag = if expect_success { "ok" } else { "rej" };

        write_doc(&mut body, case, "XMSS verify KAT (RFC 8391)");
        writeln!(body, "#[test]").unwrap();
        writeln!(
            body,
            "fn tc_line{}_xmss_verify_{alg_tag}_{kind_tag}() {{",
            case.line
        )
        .unwrap();
        writeln!(body, "    let pk: &[u8] = {};", format_byte_slice(key)).unwrap();
        writeln!(body, "    let msg: &[u8] = {};", format_byte_slice(msg)).unwrap();
        writeln!(body, "    let sig: &[u8] = {};", format_byte_slice(sig)).unwrap();
        writeln!(
            body,
            "    let kp = {kp_type}::from_public_key({param_type}::{alg_var}, pk).unwrap();"
        )
        .unwrap();
        writeln!(body, "    let result = kp.verify(msg, sig);").unwrap();
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
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo xmss`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_eal_xmss.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\
         #![cfg(feature = \"xmss\")]\n\n\
         use hitls_crypto::xmss::{XmssKeyPair, XmssMtKeyPair};\n\
         use hitls_types::{XmssMtParamId, XmssParamId};\n\n",
    );
    out.push_str(&body);
    write_footer(&mut out, &stats, cases.len());
    (out, stats)
}
