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
//! Hash-DRBG SHA-1/SHA-224/SHA-256/SHA-384/SHA-512/SM3, HMAC-DRBG
//! SHA-1/SHA-224/SHA-256/SHA-384/SHA-512, CTR-DRBG AES-128/192/256 (no df
//! and with df), SM4-CTR-DRBG (no df and with df). CTR-DRBG-df uses
//! `seed_material = Block_Cipher_df(entropy ‖ nonce ‖ pers)`.

use std::collections::BTreeSet;
use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::{format_byte_slice, TestCase};

/// Which Rust DRBG constructor a migratable `algId` maps to.
#[derive(Clone, Copy)]
enum Drbg {
    /// Hash-DRBG with the given `HashDrbgType` variant name.
    Hash(&'static str),
    /// HMAC-DRBG with the given `HmacDrbgType` variant name.
    Hmac(&'static str),
    /// CTR-DRBG-no-df with the given `CtrDrbgType` variant + active seed length.
    CtrNoDf { ty: &'static str, seed_len: usize },
    /// CTR-DRBG-df with the given `CtrDrbgType` variant name.
    CtrDf(&'static str),
    /// SM4-CTR-DRBG, no derivation function (seedLen = 32).
    Sm4CtrNoDf,
    /// SM4-CTR-DRBG, with derivation function.
    Sm4CtrDf,
}

fn migratable(alg: &str) -> Option<Drbg> {
    match alg {
        // Hash-DRBG
        "BSL_CID_RAND_SHA1" => Some(Drbg::Hash("Sha1")),
        "BSL_CID_RAND_SHA224" => Some(Drbg::Hash("Sha224")),
        "BSL_CID_RAND_SHA256" => Some(Drbg::Hash("Sha256")),
        "BSL_CID_RAND_SHA384" => Some(Drbg::Hash("Sha384")),
        "BSL_CID_RAND_SHA512" => Some(Drbg::Hash("Sha512")),
        "BSL_CID_RAND_SM3" => Some(Drbg::Hash("Sm3")),
        // HMAC-DRBG
        "BSL_CID_RAND_HMAC_SHA1" => Some(Drbg::Hmac("Sha1")),
        "BSL_CID_RAND_HMAC_SHA224" => Some(Drbg::Hmac("Sha224")),
        "BSL_CID_RAND_HMAC_SHA256" => Some(Drbg::Hmac("Sha256")),
        "BSL_CID_RAND_HMAC_SHA384" => Some(Drbg::Hmac("Sha384")),
        "BSL_CID_RAND_HMAC_SHA512" => Some(Drbg::Hmac("Sha512")),
        // CTR-DRBG no-df (seed_len = key_len + 16).
        "BSL_CID_RAND_AES128_CTR" => Some(Drbg::CtrNoDf {
            ty: "Aes128",
            seed_len: 32,
        }),
        "BSL_CID_RAND_AES192_CTR" => Some(Drbg::CtrNoDf {
            ty: "Aes192",
            seed_len: 40,
        }),
        "BSL_CID_RAND_AES256_CTR" => Some(Drbg::CtrNoDf {
            ty: "Aes256",
            seed_len: 48,
        }),
        // CTR-DRBG with-df.
        "BSL_CID_RAND_AES128_CTR_DF" => Some(Drbg::CtrDf("Aes128")),
        "BSL_CID_RAND_AES192_CTR_DF" => Some(Drbg::CtrDf("Aes192")),
        "BSL_CID_RAND_AES256_CTR_DF" => Some(Drbg::CtrDf("Aes256")),
        // SM4-CTR-DRBG.
        "BSL_CID_RAND_SM4_CTR" => Some(Drbg::Sm4CtrNoDf),
        "BSL_CID_RAND_SM4_CTR_DF" => Some(Drbg::Sm4CtrDf),
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
        Drbg::Hmac(ty) => {
            used.insert("hmac");
            writeln!(out, "    let mut seed = vec![0xffu8; {} + 20];", ent_len).unwrap();
            writeln!(out, "    seed.extend_from_slice(&PERS);").unwrap();
            writeln!(
                out,
                "    let mut d = HmacDrbg::with(HmacDrbgType::{ty}, &seed).unwrap();"
            )
            .unwrap();
        }
        Drbg::CtrNoDf { ty, seed_len } => {
            used.insert("ctr");
            // No-df: seed_material = entropy(seedlen) XOR (pers padded to seedlen).
            writeln!(out, "    let mut seed = vec![0xffu8; {seed_len}];").unwrap();
            writeln!(out, "    for (i, p) in PERS.iter().enumerate() {{").unwrap();
            writeln!(out, "        seed[i] ^= *p;").unwrap();
            writeln!(out, "    }}").unwrap();
            writeln!(
                out,
                "    let mut d = CtrDrbg::with(CtrDrbgType::{ty}, &seed).unwrap();"
            )
            .unwrap();
        }
        Drbg::CtrDf(ty) => {
            used.insert("ctr");
            // With df: Block_Cipher_df(entropy(ent_len) ‖ nonce(20) ‖ pers).
            writeln!(out, "    let entropy = vec![0xffu8; {}];", ent_len).unwrap();
            writeln!(out, "    let nonce = [0xffu8; 20];").unwrap();
            writeln!(
                out,
                "    let mut d = CtrDrbg::with_df_typed(CtrDrbgType::{ty}, \
                 &entropy, &nonce, &PERS).unwrap();"
            )
            .unwrap();
        }
        Drbg::Sm4CtrNoDf => {
            used.insert("sm4");
            writeln!(out, "    let mut seed = vec![0xffu8; 32];").unwrap();
            writeln!(out, "    for (i, p) in PERS.iter().enumerate() {{").unwrap();
            writeln!(out, "        seed[i] ^= *p;").unwrap();
            writeln!(out, "    }}").unwrap();
            writeln!(out, "    let mut d = Sm4CtrDrbg::new(&seed).unwrap();").unwrap();
        }
        Drbg::Sm4CtrDf => {
            used.insert("sm4");
            writeln!(out, "    let entropy = vec![0xffu8; {}];", ent_len).unwrap();
            writeln!(out, "    let nonce = [0xffu8; 20];").unwrap();
            writeln!(
                out,
                "    let mut d = Sm4CtrDrbg::with_df(&entropy, &nonce, &PERS).unwrap();"
            )
            .unwrap();
        }
    }
    writeln!(out, "    let mut got = [0u8; 32];").unwrap();
    // openHiTLS C SDV invokes `CRYPT_EAL_RandbytesEx(output, 32)`, which is
    // the chunked entry point: `DRBG_GenerateBytes` splits the request into
    // chunks of `ctx->maxRequest`, calling the spec'd single-generate (with
    // its own post-Update) per chunk. SM4-CTR-DRBG sets `maxRequest = 16`
    // (GM/T 0105-2021 quirk; AES-CTR-DRBG uses 65536). To byte-match the
    // C vector we must mirror that chunking here.
    match kind {
        Drbg::Sm4CtrNoDf | Drbg::Sm4CtrDf => {
            writeln!(out, "    d.generate(&mut got[..16], None).unwrap();").unwrap();
            writeln!(out, "    d.generate(&mut got[16..], None).unwrap();").unwrap();
        }
        _ => {
            writeln!(out, "    d.generate(&mut got, None).unwrap();").unwrap();
        }
    }
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
    // SM4 rows additionally need the `sm4` feature on hitls-crypto.
    if used.contains("sm4") {
        out.push_str("#![cfg(all(feature = \"drbg\", feature = \"sm4\"))]\n\n");
    } else {
        out.push_str("#![cfg(feature = \"drbg\")]\n\n");
    }
    if used.contains("hash") {
        out.push_str("use hitls_crypto::drbg::{HashDrbg, HashDrbgType};\n");
    }
    if used.contains("hmac") {
        out.push_str("use hitls_crypto::drbg::{HmacDrbg, HmacDrbgType};\n");
    }
    if used.contains("ctr") {
        out.push_str("use hitls_crypto::drbg::{CtrDrbg, CtrDrbgType};\n");
    }
    if used.contains("sm4") {
        out.push_str("use hitls_crypto::drbg::Sm4CtrDrbg;\n");
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
