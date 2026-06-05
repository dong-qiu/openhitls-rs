use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::{format_byte_slice, TestCase};

// ---------------------------------------------------------------------------
// PQC KEM decapsulation KAT migration (FrodoKEM).
//
// C `ENCAPS_DECAPS_FUNC_TC001` rows publish (algId, seed, testEk, testDk,
// testCt, testSs). The decapsulation direction is deterministic: load the
// vector's `testDk` and check `decapsulate(testCt) == testSs`. Unblocked by
// the I145 FrodoKEM pack/unpack fix (MSB-first, reference-compatible) +
// `FrodoKemKeyPair::from_decapsulation_key`.
//
// McEliece (added in I160 / T161): the C reference sk layout is
// `delta(32) || c(8) || g[0..t] (2t LE) || controlbits || s(n_bytes)`;
// I160 realigned the Rust sk codec to match (previously Rust embedded an
// extra alpha(2*Q) block + had controlbits/s in the wrong order +
// stored t+1 g-coeffs). T161 routes the `MCELIECE_ENCAPS_DECAPS_FUNC_TC001`
// rows through `McElieceKeyPair::from_decapsulation_key` for byte-exact
// reference KAT.
// ---------------------------------------------------------------------------

fn frodo_param(symbol: &str) -> Option<&'static str> {
    match symbol {
        "CRYPT_KEM_TYPE_FRODOKEM_640_SHAKE" => Some("FrodoKem640Shake"),
        "CRYPT_KEM_TYPE_FRODOKEM_976_SHAKE" => Some("FrodoKem976Shake"),
        "CRYPT_KEM_TYPE_FRODOKEM_1344_SHAKE" => Some("FrodoKem1344Shake"),
        "CRYPT_KEM_TYPE_FRODOKEM_640_AES" => Some("FrodoKem640Aes"),
        "CRYPT_KEM_TYPE_FRODOKEM_976_AES" => Some("FrodoKem976Aes"),
        "CRYPT_KEM_TYPE_FRODOKEM_1344_AES" => Some("FrodoKem1344Aes"),
        // eFrodoKEM (openHiTLS-specific extension, salt_len=0 + halved
        // seed_se_len). I162 surfaces these to the emitter — the Rust
        // params + encapsulate / decapsulate paths already handle
        // `salt_len = 0` cleanly (the salt buffer just zero-allocs at
        // length 0; SHAKE absorbs no salt bytes).
        "CRYPT_KEM_TYPE_eFRODOKEM_640_SHAKE" => Some("EFrodoKem640Shake"),
        "CRYPT_KEM_TYPE_eFRODOKEM_976_SHAKE" => Some("EFrodoKem976Shake"),
        "CRYPT_KEM_TYPE_eFRODOKEM_1344_SHAKE" => Some("EFrodoKem1344Shake"),
        "CRYPT_KEM_TYPE_eFRODOKEM_640_AES" => Some("EFrodoKem640Aes"),
        "CRYPT_KEM_TYPE_eFRODOKEM_976_AES" => Some("EFrodoKem976Aes"),
        "CRYPT_KEM_TYPE_eFRODOKEM_1344_AES" => Some("EFrodoKem1344Aes"),
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

fn mceliece_param(symbol: &str) -> Option<&'static str> {
    match symbol {
        "CRYPT_KEM_TYPE_MCELIECE_6688128" => Some("McEliece6688128"),
        "CRYPT_KEM_TYPE_MCELIECE_6688128_F" => Some("McEliece6688128F"),
        "CRYPT_KEM_TYPE_MCELIECE_6688128_PC" => Some("McEliece6688128Pc"),
        "CRYPT_KEM_TYPE_MCELIECE_6688128_PCF" => Some("McEliece6688128Pcf"),
        "CRYPT_KEM_TYPE_MCELIECE_6960119" => Some("McEliece6960119"),
        "CRYPT_KEM_TYPE_MCELIECE_6960119_F" => Some("McEliece6960119F"),
        "CRYPT_KEM_TYPE_MCELIECE_6960119_PC" => Some("McEliece6960119Pc"),
        "CRYPT_KEM_TYPE_MCELIECE_6960119_PCF" => Some("McEliece6960119Pcf"),
        "CRYPT_KEM_TYPE_MCELIECE_8192128" => Some("McEliece8192128"),
        "CRYPT_KEM_TYPE_MCELIECE_8192128_F" => Some("McEliece8192128F"),
        "CRYPT_KEM_TYPE_MCELIECE_8192128_PC" => Some("McEliece8192128Pc"),
        "CRYPT_KEM_TYPE_MCELIECE_8192128_PCF" => Some("McEliece8192128Pcf"),
        _ => None,
    }
}

pub fn emit_mceliece_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();

    for case in cases {
        if !case.tc_name.contains("_ENCAPS_DECAPS_FUNC_TC001") {
            stats.skipped_api += 1;
            continue;
        }
        // Layout: (param, seed, testEk, testDk, testCt, testSs). Header
        // rows (no quoted hex) fall through to `skipped_unknown`.
        let (Some(param_sym), Some(dk), Some(ct), Some(ss)) = (
            case.args.first().and_then(|a| a.as_symbol()),
            case.args.get(3).and_then(|a| a.as_hex()),
            case.args.get(4).and_then(|a| a.as_hex()),
            case.args.get(5).and_then(|a| a.as_hex()),
        ) else {
            stats.skipped_unknown += 1;
            continue;
        };
        let Some(variant) = mceliece_param(param_sym) else {
            stats.skipped_unsupported_alg += 1;
            continue;
        };
        write_doc(&mut body, case, "McEliece decapsulation KAT");
        writeln!(body, "#[test]").unwrap();
        writeln!(
            body,
            "fn tc_line{}_mceliece_{}_decaps() {{",
            case.line,
            variant.to_lowercase()
        )
        .unwrap();
        writeln!(body, "    let dk: &[u8] = {};", format_byte_slice(dk)).unwrap();
        writeln!(body, "    let ct: &[u8] = {};", format_byte_slice(ct)).unwrap();
        writeln!(
            body,
            "    let expected_ss: &[u8] = {};",
            format_byte_slice(ss)
        )
        .unwrap();
        writeln!(
            body,
            "    let kp = McElieceKeyPair::from_decapsulation_key(McElieceParamId::{variant}, dk).unwrap();"
        )
        .unwrap();
        writeln!(body, "    let ss = kp.decapsulate(ct).unwrap();").unwrap();
        writeln!(body, "    assert_eq!(ss.as_slice(), expected_ss);").unwrap();
        writeln!(body, "}}\n").unwrap();
        stats.emitted += 1;
    }

    let mut out = String::new();
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo mceliece`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_mceliece.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\
         #![cfg(feature = \"mceliece\")]\n\n\
         use hitls_crypto::mceliece::McElieceKeyPair;\n\
         use hitls_types::McElieceParamId;\n\n",
    );
    out.push_str(&body);
    write_footer(&mut out, &stats, cases.len());
    (out, stats)
}

pub fn emit_frodokem_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();

    for case in cases {
        if !case.tc_name.contains("_ENCAPS_DECAPS_FUNC_TC001") {
            stats.skipped_api += 1;
            continue;
        }
        // Layout: (param, seed, testEk, testDk, testCt, testSs).
        let (Some(param_sym), Some(dk), Some(ct), Some(ss)) = (
            case.args.first().and_then(|a| a.as_symbol()),
            case.args.get(3).and_then(|a| a.as_hex()),
            case.args.get(4).and_then(|a| a.as_hex()),
            case.args.get(5).and_then(|a| a.as_hex()),
        ) else {
            stats.skipped_unknown += 1;
            continue;
        };
        let Some(variant) = frodo_param(param_sym) else {
            stats.skipped_unsupported_alg += 1;
            continue;
        };
        write_doc(&mut body, case, "FrodoKEM decapsulation KAT");
        writeln!(body, "#[test]").unwrap();
        writeln!(
            body,
            "fn tc_line{}_frodokem_{}_decaps() {{",
            case.line,
            variant.to_lowercase()
        )
        .unwrap();
        writeln!(body, "    let dk: &[u8] = {};", format_byte_slice(dk)).unwrap();
        writeln!(body, "    let ct: &[u8] = {};", format_byte_slice(ct)).unwrap();
        writeln!(
            body,
            "    let expected_ss: &[u8] = {};",
            format_byte_slice(ss)
        )
        .unwrap();
        writeln!(
            body,
            "    let kp = FrodoKemKeyPair::from_decapsulation_key(FrodoKemParamId::{variant}, dk).unwrap();"
        )
        .unwrap();
        writeln!(body, "    let ss = kp.decapsulate(ct).unwrap();").unwrap();
        writeln!(body, "    assert_eq!(ss.as_slice(), expected_ss);").unwrap();
        writeln!(body, "}}\n").unwrap();
        stats.emitted += 1;
    }

    let mut out = String::new();
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo frodokem`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_frodokem.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\
         #![cfg(feature = \"frodokem\")]\n\n\
         use hitls_crypto::frodokem::FrodoKemKeyPair;\n\
         use hitls_types::FrodoKemParamId;\n\n",
    );
    out.push_str(&body);
    write_footer(&mut out, &stats, cases.len());
    (out, stats)
}
