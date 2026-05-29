use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::{format_byte_slice, TestCase};

// ---------------------------------------------------------------------------
// AEAD / MAC KAT migration (AES-GCM / GMAC / ChaCha20-Poly1305 / SipHash).
//
// Layouts confirmed against the C test-function signatures:
//   GCM    : (algId, key, iv, aad, pt, ct, tag)   — both directions
//   GMAC   : (algId, key, iv, msg, mac)            — Gmac over msg as AAD
//   ChaCha : (key, iv, aad, data, cipher, tag)     — both directions
//            (TC005 variant: (key, iv, aad, tag) — AAD-only / empty plaintext)
//   SipHash: (algId, key, data, mac)               — 64-bit only
//
// CBC-MAC is intentionally NOT migrated here: a pre-emit probe showed the
// Rust `CbcMacSm4` output diverges from the C SM4 CBC-MAC vectors (neither the
// as-is single block nor an appended zero block matches), so it needs a
// dedicated investigation — see docs/c-test-na-list.md.
// ---------------------------------------------------------------------------

fn aes_bits(key: &[u8]) -> Option<u32> {
    match key.len() {
        16 => Some(128),
        24 => Some(192),
        32 => Some(256),
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

// ---------------------------------------------------------------------------
// AES-GCM — (algId, key, iv, aad, pt, ct, tag); both directions.
// ---------------------------------------------------------------------------

pub fn emit_gcm_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();

    for case in cases {
        // KAT family: GCM_FUNC_TC001 / TC002 carry the 7-arg vector.
        if !(case.tc_name.contains("_FUNC_TC001") || case.tc_name.contains("_FUNC_TC002")) {
            stats.skipped_api += 1;
            continue;
        }
        let (Some(alg), Some(key), Some(iv), Some(aad), Some(pt), Some(ct), Some(tag)) = (
            case.args.first().and_then(|a| a.as_symbol()),
            case.args.get(1).and_then(|a| a.as_hex()),
            case.args.get(2).and_then(|a| a.as_hex()),
            case.args.get(3).and_then(|a| a.as_hex()),
            case.args.get(4).and_then(|a| a.as_hex()),
            case.args.get(5).and_then(|a| a.as_hex()),
            case.args.get(6).and_then(|a| a.as_hex()),
        ) else {
            stats.skipped_unknown += 1;
            continue;
        };
        // Only AES-GCM (key length distinguishes 128/192/256).
        let Some(bits) = (if alg.contains("AES") {
            aes_bits(key)
        } else {
            None
        }) else {
            stats.skipped_unsupported_alg += 1;
            continue;
        };
        let mut ct_tag = ct.to_vec();
        ct_tag.extend_from_slice(tag);

        write_doc(&mut body, case, "AES-GCM encrypt KAT");
        writeln!(body, "#[test]").unwrap();
        writeln!(body, "fn tc_line{}_gcm_aes{bits}_encrypt() {{", case.line).unwrap();
        writeln!(body, "    let key: &[u8] = {};", format_byte_slice(key)).unwrap();
        writeln!(body, "    let iv: &[u8] = {};", format_byte_slice(iv)).unwrap();
        writeln!(body, "    let aad: &[u8] = {};", format_byte_slice(aad)).unwrap();
        writeln!(body, "    let pt: &[u8] = {};", format_byte_slice(pt)).unwrap();
        writeln!(
            body,
            "    let ct_tag: &[u8] = {};",
            format_byte_slice(&ct_tag)
        )
        .unwrap();
        writeln!(
            body,
            "    let actual = gcm_encrypt(key, iv, aad, pt).unwrap();"
        )
        .unwrap();
        writeln!(body, "    assert_eq!(actual.as_slice(), ct_tag);").unwrap();
        writeln!(body, "}}\n").unwrap();
        stats.emitted += 1;

        write_doc(&mut body, case, "AES-GCM decrypt KAT");
        writeln!(body, "#[test]").unwrap();
        writeln!(body, "fn tc_line{}_gcm_aes{bits}_decrypt() {{", case.line).unwrap();
        writeln!(body, "    let key: &[u8] = {};", format_byte_slice(key)).unwrap();
        writeln!(body, "    let iv: &[u8] = {};", format_byte_slice(iv)).unwrap();
        writeln!(body, "    let aad: &[u8] = {};", format_byte_slice(aad)).unwrap();
        writeln!(body, "    let pt: &[u8] = {};", format_byte_slice(pt)).unwrap();
        writeln!(
            body,
            "    let ct_tag: &[u8] = {};",
            format_byte_slice(&ct_tag)
        )
        .unwrap();
        writeln!(
            body,
            "    let actual = gcm_decrypt(key, iv, aad, ct_tag).unwrap();"
        )
        .unwrap();
        writeln!(body, "    assert_eq!(actual.as_slice(), pt);").unwrap();
        writeln!(body, "}}\n").unwrap();
        stats.emitted += 1;
    }

    let mut out = String::new();
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo gcm`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_gcm.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\
         #![cfg(all(feature = \"modes\", feature = \"aes\"))]\n\n\
         use hitls_crypto::modes::gcm::{gcm_decrypt, gcm_encrypt};\n\n",
    );
    out.push_str(&body);
    write_footer(&mut out, &stats, cases.len());
    (out, stats)
}

// ---------------------------------------------------------------------------
// GMAC — (algId, key, iv, msg, mac).
// ---------------------------------------------------------------------------

pub fn emit_gmac_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();

    for case in cases {
        // KAT family: SDV_CRYPTO_EAL_GMAC_FUNC_TC001 (5 args). The STATE /
        // ADDR_NOT_ALIGN / SAMEADDR families are C memory-layout tests.
        if case.tc_name.contains("_STATE_")
            || case.tc_name.contains("_ADDR_NOT_ALIGN_")
            || case.tc_name.contains("_SAMEADDR_")
            || !case.tc_name.contains("_FUNC_TC001")
        {
            stats.skipped_api += 1;
            continue;
        }
        let (Some(alg), Some(key), Some(iv), Some(msg), Some(mac)) = (
            case.args.first().and_then(|a| a.as_symbol()),
            case.args.get(1).and_then(|a| a.as_hex()),
            case.args.get(2).and_then(|a| a.as_hex()),
            case.args.get(3).and_then(|a| a.as_hex()),
            case.args.get(4).and_then(|a| a.as_hex()),
        ) else {
            stats.skipped_unknown += 1;
            continue;
        };
        let Some(bits) = (if alg.contains("AES") {
            aes_bits(key)
        } else {
            None
        }) else {
            stats.skipped_unsupported_alg += 1;
            continue;
        };
        write_doc(&mut body, case, "GMAC KAT");
        writeln!(body, "#[test]").unwrap();
        writeln!(body, "fn tc_line{}_gmac_aes{bits}() {{", case.line).unwrap();
        writeln!(body, "    let key: &[u8] = {};", format_byte_slice(key)).unwrap();
        writeln!(body, "    let iv: &[u8] = {};", format_byte_slice(iv)).unwrap();
        writeln!(body, "    let msg: &[u8] = {};", format_byte_slice(msg)).unwrap();
        writeln!(
            body,
            "    let expected: &[u8] = {};",
            format_byte_slice(mac)
        )
        .unwrap();
        writeln!(body, "    let mut gmac = Gmac::new(key, iv).unwrap();").unwrap();
        writeln!(body, "    gmac.update(msg).unwrap();").unwrap();
        writeln!(body, "    let mut out = [0u8; 16];").unwrap();
        writeln!(body, "    gmac.finish(&mut out).unwrap();").unwrap();
        writeln!(body, "    assert_eq!(&out[..expected.len()], expected);").unwrap();
        writeln!(body, "}}\n").unwrap();
        stats.emitted += 1;
    }

    let mut out = String::new();
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo gmac`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_eal_gmac.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\
         #![cfg(feature = \"gmac\")]\n\n\
         use hitls_crypto::gmac::Gmac;\n\n",
    );
    out.push_str(&body);
    write_footer(&mut out, &stats, cases.len());
    (out, stats)
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 — (key, iv, aad, data, cipher, tag); both directions.
// TC005 variant is AAD-only: (key, iv, aad, tag) — empty plaintext.
// ---------------------------------------------------------------------------

pub fn emit_chachapoly_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();

    for case in cases {
        // TC008 is a round-trip consistency test (no fixed vector); TC009 is a
        // tamper/negative-auth test (ciphertext correct, tag deliberately
        // corrupted so authenticated decrypt MUST reject) — neither maps to a
        // positive byte-exact KAT, so both route to API-surface.
        if !case.tc_name.contains("_FUNC_TC")
            || case.tc_name.contains("_FUNC_TC008")
            || case.tc_name.contains("_FUNC_TC009")
        {
            stats.skipped_api += 1;
            continue;
        }
        // All-hex arg vector; shape: 6 = full (key,iv,aad,pt,ct,tag),
        // 4 = AAD-only (key,iv,aad,tag), 8 = split-update
        // (key,iv,aad,pt1,pt2,pt3,ct,tag) — the 3 chunks fold into one pt.
        let hexes: Option<Vec<&[u8]>> = case.args.iter().map(|a| a.as_hex()).collect();
        let Some(hexes) = hexes else {
            stats.skipped_unknown += 1;
            continue;
        };
        if hexes.len() < 4 {
            stats.skipped_unknown += 1;
            continue;
        }
        let key = hexes[0];
        let iv = hexes[1];
        let aad = hexes[2];
        let (pt, ct, tag): (Vec<u8>, &[u8], &[u8]) = match hexes.len() {
            4 => (Vec::new(), &[], hexes[3]),
            6 => (hexes[3].to_vec(), hexes[4], hexes[5]),
            8 => ([hexes[3], hexes[4], hexes[5]].concat(), hexes[6], hexes[7]),
            _ => {
                stats.skipped_unknown += 1;
                continue;
            }
        };
        if iv.len() != 12 {
            stats.skipped_unsupported_alg += 1;
            continue;
        }
        let pt: &[u8] = &pt;
        let mut ct_tag = ct.to_vec();
        ct_tag.extend_from_slice(tag);

        write_doc(&mut body, case, "ChaCha20-Poly1305 encrypt KAT");
        writeln!(body, "#[test]").unwrap();
        writeln!(body, "fn tc_line{}_chachapoly_encrypt() {{", case.line).unwrap();
        writeln!(body, "    let key: &[u8] = {};", format_byte_slice(key)).unwrap();
        writeln!(body, "    let nonce: &[u8] = {};", format_byte_slice(iv)).unwrap();
        writeln!(body, "    let aad: &[u8] = {};", format_byte_slice(aad)).unwrap();
        writeln!(body, "    let pt: &[u8] = {};", format_byte_slice(pt)).unwrap();
        writeln!(
            body,
            "    let ct_tag: &[u8] = {};",
            format_byte_slice(&ct_tag)
        )
        .unwrap();
        writeln!(body, "    let aead = ChaCha20Poly1305::new(key).unwrap();").unwrap();
        writeln!(
            body,
            "    let actual = aead.encrypt(nonce, aad, pt).unwrap();"
        )
        .unwrap();
        writeln!(body, "    assert_eq!(actual.as_slice(), ct_tag);").unwrap();
        writeln!(body, "}}\n").unwrap();
        stats.emitted += 1;

        write_doc(&mut body, case, "ChaCha20-Poly1305 decrypt KAT");
        writeln!(body, "#[test]").unwrap();
        writeln!(body, "fn tc_line{}_chachapoly_decrypt() {{", case.line).unwrap();
        writeln!(body, "    let key: &[u8] = {};", format_byte_slice(key)).unwrap();
        writeln!(body, "    let nonce: &[u8] = {};", format_byte_slice(iv)).unwrap();
        writeln!(body, "    let aad: &[u8] = {};", format_byte_slice(aad)).unwrap();
        writeln!(body, "    let pt: &[u8] = {};", format_byte_slice(pt)).unwrap();
        writeln!(
            body,
            "    let ct_tag: &[u8] = {};",
            format_byte_slice(&ct_tag)
        )
        .unwrap();
        writeln!(body, "    let aead = ChaCha20Poly1305::new(key).unwrap();").unwrap();
        writeln!(
            body,
            "    let actual = aead.decrypt(nonce, aad, ct_tag).unwrap();"
        )
        .unwrap();
        writeln!(body, "    assert_eq!(actual.as_slice(), pt);").unwrap();
        writeln!(body, "}}\n").unwrap();
        stats.emitted += 1;
    }

    let mut out = String::new();
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo chacha-poly`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_eal_chachapoly.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\
         #![cfg(feature = \"chacha20\")]\n\n\
         use hitls_crypto::chacha20::ChaCha20Poly1305;\n\n",
    );
    out.push_str(&body);
    write_footer(&mut out, &stats, cases.len());
    (out, stats)
}

// ---------------------------------------------------------------------------
// SipHash — (algId, key, data, mac). 64-bit only; 128-bit unsupported.
// The KAT vectors live in the ADDR_NOT_ALIGN / SAMEADDR families (the only
// ones carrying a mac); the C memory-layout intent is irrelevant in Rust —
// the (key, data, mac) triple is a valid SipHash KAT.
// ---------------------------------------------------------------------------

pub fn emit_siphash_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();

    for case in cases {
        // Rows that carry a mac: ADDR_NOT_ALIGN_FUNC_TC001 / SAMEADDR_FUNC_TC001
        // (4 args). FUN_TC005 (3 args, no mac) and API rows → API-surface.
        if case.args.len() != 4 || case.tc_name.contains("_API_TC") {
            stats.skipped_api += 1;
            continue;
        }
        let (Some(alg), Some(key), Some(data), Some(mac)) = (
            case.args.first().and_then(|a| a.as_symbol()),
            case.args.get(1).and_then(|a| a.as_hex()),
            case.args.get(2).and_then(|a| a.as_hex()),
            case.args.get(3).and_then(|a| a.as_hex()),
        ) else {
            stats.skipped_unknown += 1;
            continue;
        };
        // Rust SipHash returns a u64 (SipHash-2-4-64); 128-bit is unsupported.
        if !alg.contains("SIPHASH64") {
            stats.skipped_unsupported_alg += 1;
            continue;
        }
        write_doc(&mut body, case, "SipHash-64 KAT");
        writeln!(body, "#[test]").unwrap();
        writeln!(body, "fn tc_line{}_siphash64() {{", case.line).unwrap();
        writeln!(body, "    let key: &[u8] = {};", format_byte_slice(key)).unwrap();
        writeln!(body, "    let data: &[u8] = {};", format_byte_slice(data)).unwrap();
        writeln!(
            body,
            "    let expected: &[u8] = {};",
            format_byte_slice(mac)
        )
        .unwrap();
        writeln!(body, "    let mac = SipHash::hash(key, data).unwrap();").unwrap();
        writeln!(
            body,
            "    assert_eq!(mac.to_le_bytes().as_slice(), expected);"
        )
        .unwrap();
        writeln!(body, "}}\n").unwrap();
        stats.emitted += 1;
    }

    let mut out = String::new();
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo siphash`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_eal_mac_siphash.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\
         #![cfg(feature = \"siphash\")]\n\n\
         use hitls_crypto::siphash::SipHash;\n\n",
    );
    out.push_str(&body);
    write_footer(&mut out, &stats, cases.len());
    (out, stats)
}

// ---------------------------------------------------------------------------
// CBC-MAC (SM4) — FUN_TC004 (algId, padType, key, data, vecMac).
//
// Unblocked by the I144 `CbcMacSm4` fix (the Rust port double-encrypted the
// final block for block-aligned input). Only the SM4 + ZEROS-padding rows map
// to the Rust `CbcMacSm4` (which is SM4-only and zero-pads). The
// ADDR_NOT_ALIGN / SAMEADDR / FUN_TC006 families are C memory-layout / update-
// count tests → API-surface.
// ---------------------------------------------------------------------------

pub fn emit_cbc_mac_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();

    for case in cases {
        if case.tc_name.contains("_ADDR_NOT_ALIGN_")
            || case.tc_name.contains("_SAMEADDR_")
            || !case.tc_name.contains("_FUN_TC004")
        {
            stats.skipped_api += 1;
            continue;
        }
        let (Some(alg), Some(pad), Some(key), Some(data), Some(mac)) = (
            case.args.first().and_then(|a| a.as_symbol()),
            case.args.get(1).and_then(|a| a.as_symbol()),
            case.args.get(2).and_then(|a| a.as_hex()),
            case.args.get(3).and_then(|a| a.as_hex()),
            case.args.get(4).and_then(|a| a.as_hex()),
        ) else {
            stats.skipped_unknown += 1;
            continue;
        };
        // Rust CbcMacSm4 is SM4-only and zero-pads the final partial block.
        if !alg.contains("SM4") || !pad.contains("ZEROS") {
            stats.skipped_unsupported_alg += 1;
            continue;
        }
        write_doc(&mut body, case, "SM4 CBC-MAC (ZEROS padding) KAT");
        writeln!(body, "#[test]").unwrap();
        writeln!(body, "fn tc_line{}_cbc_mac_sm4() {{", case.line).unwrap();
        writeln!(body, "    let key: &[u8] = {};", format_byte_slice(key)).unwrap();
        writeln!(body, "    let data: &[u8] = {};", format_byte_slice(data)).unwrap();
        writeln!(
            body,
            "    let expected: &[u8] = {};",
            format_byte_slice(mac)
        )
        .unwrap();
        writeln!(body, "    let mut mac = CbcMacSm4::new(key).unwrap();").unwrap();
        writeln!(body, "    mac.update(data).unwrap();").unwrap();
        writeln!(body, "    let mut out = [0u8; 16];").unwrap();
        writeln!(body, "    mac.finish(&mut out).unwrap();").unwrap();
        writeln!(body, "    assert_eq!(&out[..expected.len()], expected);").unwrap();
        writeln!(body, "}}\n").unwrap();
        stats.emitted += 1;
    }

    let mut out = String::new();
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo cbc-mac`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_eal_mac_cbc_mac.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\
         #![cfg(feature = \"cbc-mac\")]\n\n\
         use hitls_crypto::cbc_mac::CbcMacSm4;\n\n",
    );
    out.push_str(&body);
    write_footer(&mut out, &stats, cases.len());
    (out, stats)
}
