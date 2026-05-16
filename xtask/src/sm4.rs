//! Emitter for openHiTLS C `test_suite_sdv_eal_sm4.data`.
//!
//! Raw-KAT families (the C tests drive the EAL streaming cipher: `Init` +
//! single `Update` [+ `Final`]):
//!
//! * `SM4_ENCRYPT_FUNC_TC003` — `isProvider : id : key : plain : cipher : iv`,
//!   encrypt direction (`Init(enc=true)` + `Update(plain)` == `cipher`).
//! * `SM4_ENCRYPT_FUNC_TC004` — same shape, decrypt direction
//!   (`Init(enc=false)` + `Update(cipher)` == `plain`).
//! * `SM4_ENCRYPT_FUNC_TC012` — `id : key : iv : in : out : enc`, direction
//!   chosen by the trailing `enc` flag.
//!
//! The `.data` covers eight cipher modes (ECB/CBC/CTR/CFB/OFB/GCM/HCTR/XTS).
//! Only the subset with a clean, no-padding Rust API is migrated:
//!
//! * **ECB** — `Sm4Key::encrypt_block` / `decrypt_block`, applied per 16-byte
//!   block (KAT vectors are block-aligned).
//! * **GCM (encrypt)** — `sm4_gcm_encrypt`; the `.data` cipher field carries
//!   only the ciphertext (no tag), so the test compares the ciphertext
//!   prefix and GCM *decrypt* is skipped (it needs the tag to authenticate).
//!
//! CBC is skipped — `sm4_cbc_encrypt` hardcodes PKCS#7 padding, so it cannot
//! reproduce a raw block-aligned KAT. CTR/CFB/OFB/HCTR/XTS have no public
//! SM4 entry point. All of these route to `skipped_unsupported_alg`.

use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::{format_byte_slice, TestCase};

pub fn emit_sm4_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();
    let mut used_gcm = false;

    for case in cases {
        match classify(&case.tc_name) {
            Kind::Encrypt => emit_kat(&mut body, case, &mut stats, &mut used_gcm, Family::Tc003),
            Kind::Decrypt => emit_kat(&mut body, case, &mut stats, &mut used_gcm, Family::Tc004),
            Kind::EncFlag => emit_kat(&mut body, case, &mut stats, &mut used_gcm, Family::Tc012),
            Kind::ApiSurface => stats.skipped_api += 1,
            Kind::Unknown => stats.skipped_unknown += 1,
        }
    }

    let mut out = String::new();
    write_header(&mut out, used_gcm);
    out.push_str(&body);
    write_footer(&mut out, &stats, cases.len());
    (out, stats)
}

#[derive(Debug, Clone, Copy)]
enum Kind {
    Encrypt,
    Decrypt,
    EncFlag,
    ApiSurface,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
enum Family {
    Tc003,
    Tc004,
    Tc012,
}

fn classify(tc: &str) -> Kind {
    if tc.contains("SM4_ENCRYPT_FUNC_TC003") {
        return Kind::Encrypt;
    }
    if tc.contains("SM4_ENCRYPT_FUNC_TC004") {
        return Kind::Decrypt;
    }
    if tc.contains("SM4_ENCRYPT_FUNC_TC012") {
        return Kind::EncFlag;
    }
    // Every other SM4 family is a workflow/lifecycle test (padding-mode
    // probes, multi-update streaming, reinit, ctx duplication, …) with no
    // 1:1 mapping to a stateless one-shot Rust call.
    if tc.contains("SM4_") {
        return Kind::ApiSurface;
    }
    Kind::Unknown
}

/// One normalised KAT row: cipher mode, key, IV, the input fed to the
/// operation, the expected output, and whether it encrypts.
struct Row<'a> {
    mode: &'a str,
    key: &'a [u8],
    iv: &'a [u8],
    input: &'a [u8],
    output: &'a [u8],
    encrypt: bool,
}

/// Extract a [`Row`] from a case according to its C family shape. Returns
/// `None` (and the caller counts it unknown) if the args do not fit.
fn extract<'a>(case: &'a TestCase, family: Family) -> Option<Row<'a>> {
    match family {
        // isProvider : id : key : plain : cipher : iv
        Family::Tc003 | Family::Tc004 => {
            if case.args.len() < 6 {
                return None;
            }
            let mode = case.args[1].as_symbol()?;
            let key = case.args[2].as_hex()?;
            let plain = case.args[3].as_hex()?;
            let cipher = case.args[4].as_hex()?;
            let iv = case.args[5].as_hex()?;
            let encrypt = matches!(family, Family::Tc003);
            let (input, output) = if encrypt {
                (plain, cipher)
            } else {
                (cipher, plain)
            };
            Some(Row {
                mode,
                key,
                iv,
                input,
                output,
                encrypt,
            })
        }
        // id : key : iv : in : out : enc
        Family::Tc012 => {
            if case.args.len() < 6 {
                return None;
            }
            let mode = case.args[0].as_symbol()?;
            let key = case.args[1].as_hex()?;
            let iv = case.args[2].as_hex()?;
            let input = case.args[3].as_hex()?;
            let output = case.args[4].as_hex()?;
            let encrypt = matches!(case.args[5].as_symbol(), Some("true"));
            Some(Row {
                mode,
                key,
                iv,
                input,
                output,
                encrypt,
            })
        }
    }
}

/// Skip provider-flag duplicates. TC003/TC004 carry `isProvider` as the
/// FIRST arg (`0` default / `1` EAL provider framework); TC012 has none.
fn skip_if_provider_dup(case: &TestCase, family: Family) -> bool {
    match family {
        Family::Tc003 | Family::Tc004 => {
            matches!(case.args.first().and_then(|a| a.as_symbol()), Some("1"))
        }
        Family::Tc012 => false,
    }
}

fn emit_kat(
    out: &mut String,
    case: &TestCase,
    stats: &mut EmitStats,
    used_gcm: &mut bool,
    family: Family,
) {
    if skip_if_provider_dup(case, family) {
        stats.skipped_api += 1;
        return;
    }
    let Some(row) = extract(case, family) else {
        stats.skipped_unknown += 1;
        return;
    };

    match row.mode {
        "CRYPT_CIPHER_SM4_ECB" => {
            // ECB processes whole 16-byte blocks; a non-aligned KAT input
            // would be a padding/streaming case, not a raw block KAT.
            if row.input.is_empty() || row.input.len() % 16 != 0 {
                stats.skipped_unknown += 1;
                return;
            }
            emit_ecb(out, case, &row);
            stats.emitted += 1;
        }
        "CRYPT_CIPHER_SM4_GCM" if row.encrypt => {
            // The cipher field is the ciphertext only (no tag), so compare
            // the ciphertext prefix of `sm4_gcm_encrypt`'s `ct || tag`.
            if row.output.len() != row.input.len() {
                stats.skipped_unknown += 1;
                return;
            }
            emit_gcm_encrypt(out, case, &row);
            *used_gcm = true;
            stats.emitted += 1;
        }
        // GCM decrypt needs the tag (absent from the `.data`); CBC hardcodes
        // PKCS#7 padding; CTR/CFB/OFB/HCTR/XTS have no public SM4 entry.
        _ => stats.skipped_unsupported_alg += 1,
    }
}

fn emit_ecb(out: &mut String, case: &TestCase, row: &Row) {
    let dir = if row.encrypt { "encrypt" } else { "decrypt" };
    let op = if row.encrypt {
        "encrypt_block"
    } else {
        "decrypt_block"
    };
    write_doc(out, case, &format!("SM4-ECB {dir} KAT"));
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn tc_line{}_sm4_ecb_{dir}() {{", case.line).unwrap();
    writeln!(out, "    let key: &[u8] = {};", format_byte_slice(row.key)).unwrap();
    writeln!(
        out,
        "    let input: &[u8] = {};",
        format_byte_slice(row.input)
    )
    .unwrap();
    writeln!(
        out,
        "    let expected: &[u8] = {};",
        format_byte_slice(row.output)
    )
    .unwrap();
    writeln!(out, "    let sm4 = Sm4Key::new(key).unwrap();").unwrap();
    writeln!(out, "    let mut buf = input.to_vec();").unwrap();
    writeln!(out, "    for block in buf.chunks_mut(16) {{").unwrap();
    writeln!(out, "        sm4.{op}(block).unwrap();").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "    assert_eq!(buf.as_slice(), expected);").unwrap();
    writeln!(out, "}}\n").unwrap();
}

fn emit_gcm_encrypt(out: &mut String, case: &TestCase, row: &Row) {
    write_doc(out, case, "SM4-GCM encrypt KAT");
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn tc_line{}_sm4_gcm_encrypt() {{", case.line).unwrap();
    writeln!(out, "    let key: &[u8] = {};", format_byte_slice(row.key)).unwrap();
    writeln!(out, "    let iv: &[u8] = {};", format_byte_slice(row.iv)).unwrap();
    writeln!(
        out,
        "    let input: &[u8] = {};",
        format_byte_slice(row.input)
    )
    .unwrap();
    writeln!(
        out,
        "    let expected: &[u8] = {};",
        format_byte_slice(row.output)
    )
    .unwrap();
    // `sm4_gcm_encrypt` returns `ciphertext || 16-byte tag`; the KAT vector
    // carries only the ciphertext, so compare the leading `input.len()`.
    writeln!(
        out,
        "    let out = sm4_gcm_encrypt(key, iv, &[], input).unwrap();"
    )
    .unwrap();
    writeln!(out, "    assert_eq!(&out[..input.len()], expected);").unwrap();
    writeln!(out, "}}\n").unwrap();
}

fn write_header(out: &mut String, used_gcm: bool) {
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo sm4`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_eal_sm4.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\n",
    );
    out.push_str("#![cfg(all(feature = \"sm4\", feature = \"modes\"))]\n\n");
    out.push_str("use hitls_crypto::sm4::Sm4Key;\n");
    if used_gcm {
        out.push_str("use hitls_crypto::modes::gcm::sm4_gcm_encrypt;\n");
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
        "/// C source: {} (line {}, {})",
        case.tc_name, case.line, kind
    )
    .unwrap();
}
