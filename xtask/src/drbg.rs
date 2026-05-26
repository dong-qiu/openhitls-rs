//! Emitter for openHiTLS C `test_suite_sdv_drbg.data` — DRBG NIST vectors.
//!
//! Migrates `SDV_PRIMARY_DRBG_VECTOR_FUN_TC001` (`algId : entropyLen :
//! result`). The C test fixes the seed inputs in code (not in the row):
//! entropy = `entropyLen` bytes of `0xff`, nonce = 20 bytes of `0xff`,
//! personalization = `{00,01,02,03,04,05}`. It instantiates the DRBG and
//! generates 32 bytes, comparing against `result`.
//!
//! SP 800-90A instantiate builds `seed_material = entropy ‖ nonce ‖ pers` for
//! Hash- and HMAC-DRBG; the Rust `HashDrbg::new` / `HmacDrbg::new` consume
//! exactly that (`Hash_df` / HMAC `Update`). CTR-DRBG-no-df uses
//! `seed_material = entropy XOR pers` (no df, no nonce; entropy = seedlen).
//!
//! Migrated variants (the Rust port has a matching deterministic constructor):
//! Hash-DRBG SHA-256/384/512, HMAC-DRBG SHA-256, CTR-DRBG AES-256 (no df).
//!
//! Not migrated (routed to `unsupported`):
//! * Hash SHA-1/SHA-224/SM3, HMAC SHA-1/224/384/512 — no such Rust variant
//!   (`HashDrbgType` is 256/384/512; `HmacDrbg` is SHA-256-only).
//! * CTR AES-128/192 (±df), SM4-CTR-df — `CtrDrbg`/`Sm4CtrDrbg` are AES-256 /
//!   no-df only.
//! * CTR AES-256-df — `CtrDrbg::with_df` output diverges from the NIST vector
//!   (the Hash/HMAC/CTR-no-df cores all match, isolating the gap to
//!   `block_cipher_df`); tracked by the divergence anchor in `ctr_drbg.rs`.

use std::collections::BTreeSet;
use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::{format_byte_slice, TestCase};

/// Which Rust DRBG constructor a migratable `algId` maps to.
#[derive(Clone, Copy)]
enum Drbg {
    Hash(&'static str),
    Hmac,
    CtrNoDf,
}

fn migratable(alg: &str) -> Option<Drbg> {
    match alg {
        "BSL_CID_RAND_SHA256" => Some(Drbg::Hash("Sha256")),
        "BSL_CID_RAND_SHA384" => Some(Drbg::Hash("Sha384")),
        "BSL_CID_RAND_SHA512" => Some(Drbg::Hash("Sha512")),
        "BSL_CID_RAND_HMAC_SHA256" => Some(Drbg::Hmac),
        "BSL_CID_RAND_AES256_CTR" => Some(Drbg::CtrNoDf),
        _ => None,
    }
}

pub fn emit_drbg_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();
    let mut used: BTreeSet<&'static str> = BTreeSet::new();

    for case in cases {
        if !case.tc_name.contains("PRIMARY_DRBG_VECTOR_FUN_TC001") {
            stats.skipped_api += 1;
            continue;
        }
        emit_vector(&mut body, case, &mut stats, &mut used);
    }

    let mut out = String::new();
    write_header(&mut out, &used);
    out.push_str(&body);
    write_footer(&mut out, &stats, cases.len());
    (out, stats)
}

fn emit_vector(
    out: &mut String,
    case: &TestCase,
    stats: &mut EmitStats,
    used: &mut BTreeSet<&'static str>,
) {
    // Shape: algId : entropyLen : result
    if case.args.len() < 3 {
        stats.skipped_unknown += 1;
        return;
    }
    let Some(alg) = case.args[0].as_symbol() else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(kind) = migratable(alg) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let Some(ent_len) = case.args[1]
        .as_symbol()
        .and_then(|s| s.parse::<usize>().ok())
    else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(result) = case.args[2].as_hex() else {
        stats.skipped_unknown += 1;
        return;
    };

    let fn_name = format!("tc_line{}_{}_vector", case.line, alg.to_lowercase());
    write_doc(out, case);
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn {fn_name}() {{").unwrap();
    writeln!(
        out,
        "    let expected: &[u8] = {};",
        format_byte_slice(result)
    )
    .unwrap();
    match kind {
        Drbg::Hash(ty) => {
            used.insert("hash");
            // seed_material = entropy(ent_len) ‖ nonce(20) ‖ pers, all 0xff but pers.
            writeln!(out, "    let mut seed = vec![0xffu8; {} + 20];", ent_len).unwrap();
            writeln!(out, "    seed.extend_from_slice(&PERS);").unwrap();
            writeln!(
                out,
                "    let mut d = HashDrbg::new(HashDrbgType::{ty}, &seed).unwrap();"
            )
            .unwrap();
        }
        Drbg::Hmac => {
            used.insert("hmac");
            writeln!(out, "    let mut seed = vec![0xffu8; {} + 20];", ent_len).unwrap();
            writeln!(out, "    seed.extend_from_slice(&PERS);").unwrap();
            writeln!(out, "    let mut d = HmacDrbg::new(&seed).unwrap();").unwrap();
        }
        Drbg::CtrNoDf => {
            used.insert("ctr");
            // No-df: seed_material = entropy(seedlen=48) XOR (pers padded to 48).
            writeln!(out, "    let mut seed = vec![0xffu8; 48];").unwrap();
            writeln!(out, "    for (i, p) in PERS.iter().enumerate() {{").unwrap();
            writeln!(out, "        seed[i] ^= *p;").unwrap();
            writeln!(out, "    }}").unwrap();
            writeln!(out, "    let mut d = CtrDrbg::new(&seed).unwrap();").unwrap();
        }
    }
    writeln!(out, "    let mut got = [0u8; 32];").unwrap();
    writeln!(out, "    d.generate(&mut got, None).unwrap();").unwrap();
    writeln!(out, "    assert_eq!(&got[..], expected);").unwrap();
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

fn write_header(out: &mut String, used: &BTreeSet<&'static str>) {
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo drbg`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_drbg.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\n",
    );
    out.push_str("#![cfg(feature = \"drbg\")]\n\n");
    if used.contains("hash") {
        out.push_str("use hitls_crypto::drbg::hash_drbg::HashDrbgType;\n");
        out.push_str("use hitls_crypto::drbg::HashDrbg;\n");
    }
    if used.contains("hmac") {
        out.push_str("use hitls_crypto::drbg::HmacDrbg;\n");
    }
    if used.contains("ctr") {
        out.push_str("use hitls_crypto::drbg::CtrDrbg;\n");
    }
    out.push_str("\n/// Personalization string fixed by the C SDV harness.\n");
    out.push_str("const PERS: [u8; 6] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];\n\n");
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

fn write_doc(out: &mut String, case: &TestCase) {
    if let Some(desc) = &case.description {
        writeln!(out, "/// {desc}").unwrap();
    }
    writeln!(
        out,
        "/// C source: {} (line {}, DRBG NIST vector: instantiate(0xff entropy/nonce, \
         pers=00..05) + generate(32))",
        case.tc_name, case.line
    )
    .unwrap();
}
