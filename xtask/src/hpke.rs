use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::{format_byte_slice, TestCase};

// ---------------------------------------------------------------------------
// HPKE (RFC 9180) KAT migration — `test_suite_sdv_eal_hpke.data`.
//
// Scope (T149): SHARED_SECRET_TC001 only. The row already publishes the
// derived `sharedSecret`, so the migration drives the **key schedule + AEAD**
// directly via the new `kat-nonce`-gated `HpkeCtx::from_shared_secret`
// constructor (added to `hitls_crypto::hpke`), bypassing the KEM. This avoids
// needing a sender-side `ikmE` injection hook (RFC 9180 Encap is randomised
// over `ikmE`); that hook plus `kem_derive_key_pair` exposure is the
// follow-up needed for AEAD_TC001 / EXPORT_SECRET_TC001 / KEM_TC001 — those
// route to API-surface here.
//
// C test fn (test_suite_sdv_eal_hpke.c):
//   void SDV_CRYPT_EAL_HPKE_SHARED_SECRET_TC001(
//       int mode, int kemId, int kdfId, int aeadId,
//       Hex *info, Hex *psk, Hex *pskId, Hex *sharedSecret,
//       int seq, Hex *pt, Hex *aad, Hex *ct);
//
// The C body:
//   ctxS = GenHpkeCtxWithSharedSecret(SENDER, mode, suite, info, psk, pskId, sharedSecret);
//   ctxR = GenHpkeCtxWithSharedSecret(RECIPIENT, mode, suite, info, psk, pskId, sharedSecret);
//   HpkeSetSeq(ctxS, seq); HpkeSeal(ctxS, aad, pt) -> ct; assert_eq ct
//   HpkeSetSeq(ctxR, seq); HpkeOpen(ctxR, aad, ct) -> pt; assert_eq pt
// ---------------------------------------------------------------------------

fn mode_byte(sym: &str) -> Option<u8> {
    match sym {
        "CRYPT_HPKE_MODE_BASE" => Some(0x00),
        "CRYPT_HPKE_MODE_PSK" => Some(0x01),
        "CRYPT_HPKE_MODE_AUTH" => Some(0x02),
        "CRYPT_HPKE_MODE_AUTH_PSK" => Some(0x03),
        _ => None,
    }
}

fn mode_tag(sym: &str) -> &'static str {
    match sym {
        "CRYPT_HPKE_MODE_BASE" => "base",
        "CRYPT_HPKE_MODE_PSK" => "psk",
        "CRYPT_HPKE_MODE_AUTH" => "auth",
        "CRYPT_HPKE_MODE_AUTH_PSK" => "auth_psk",
        _ => "unknown",
    }
}

fn kem_enum(sym: &str) -> Option<(&'static str, &'static str)> {
    match sym {
        "CRYPT_KEM_DHKEM_X25519_HKDF_SHA256" => Some(("DhkemX25519HkdfSha256", "x25519")),
        "CRYPT_KEM_DHKEM_P256_HKDF_SHA256" => Some(("DhkemP256HkdfSha256", "p256")),
        "CRYPT_KEM_DHKEM_P384_HKDF_SHA384" => Some(("DhkemP384HkdfSha384", "p384")),
        "CRYPT_KEM_DHKEM_P521_HKDF_SHA512" => Some(("DhkemP521HkdfSha512", "p521")),
        _ => None,
    }
}

fn kdf_enum(sym: &str) -> Option<(&'static str, &'static str)> {
    match sym {
        "CRYPT_KDF_HKDF_SHA256" => Some(("HkdfSha256", "sha256")),
        "CRYPT_KDF_HKDF_SHA384" => Some(("HkdfSha384", "sha384")),
        "CRYPT_KDF_HKDF_SHA512" => Some(("HkdfSha512", "sha512")),
        _ => None,
    }
}

fn aead_enum(sym: &str) -> Option<(&'static str, &'static str)> {
    match sym {
        "CRYPT_AEAD_AES_128_GCM" => Some(("Aes128Gcm", "aes128gcm")),
        "CRYPT_AEAD_AES_256_GCM" => Some(("Aes256Gcm", "aes256gcm")),
        "CRYPT_AEAD_CHACHA20_POLY1305" => Some(("ChaCha20Poly1305", "chacha20poly1305")),
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

pub fn emit_hpke_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();

    for case in cases {
        // Migration scope: SHARED_SECRET_TC001 (key schedule + AEAD seal/open
        // from a pre-derived shared_secret). Everything else (AEAD_TC001 /
        // EXPORT_SECRET_TC001 / KEM_TC001 / SHARED_SECRET_TC002 / API /
        // RANDOMLY) routes to API-surface here; follow-up Phase A work in
        // T150+ will add `kem_encap_with_ikm_e` / `kem_derive_key_pair`
        // public hooks for those.
        if !case.tc_name.contains("SHARED_SECRET_TC001") {
            stats.skipped_api += 1;
            continue;
        }
        let (
            Some(mode_sym),
            Some(kem_sym),
            Some(kdf_sym),
            Some(aead_sym),
            Some(info),
            Some(psk),
            Some(psk_id),
            Some(shared_secret),
            Some(seq),
            Some(pt),
            Some(aad),
            Some(ct),
        ) = (
            case.args.first().and_then(|a| a.as_symbol()),
            case.args.get(1).and_then(|a| a.as_symbol()),
            case.args.get(2).and_then(|a| a.as_symbol()),
            case.args.get(3).and_then(|a| a.as_symbol()),
            case.args.get(4).and_then(|a| a.as_hex()),
            case.args.get(5).and_then(|a| a.as_hex()),
            case.args.get(6).and_then(|a| a.as_hex()),
            case.args.get(7).and_then(|a| a.as_hex()),
            case.args.get(8).and_then(|a| a.as_symbol()),
            case.args.get(9).and_then(|a| a.as_hex()),
            case.args.get(10).and_then(|a| a.as_hex()),
            case.args.get(11).and_then(|a| a.as_hex()),
        )
        else {
            stats.skipped_unknown += 1;
            continue;
        };
        let Some(mode_b) = mode_byte(mode_sym) else {
            stats.skipped_unsupported_alg += 1;
            continue;
        };
        let Some((kem_var, kem_tag)) = kem_enum(kem_sym) else {
            stats.skipped_unsupported_alg += 1;
            continue;
        };
        let Some((kdf_var, kdf_tag)) = kdf_enum(kdf_sym) else {
            stats.skipped_unsupported_alg += 1;
            continue;
        };
        let Some((aead_var, aead_tag)) = aead_enum(aead_sym) else {
            stats.skipped_unsupported_alg += 1;
            continue;
        };
        let Ok(seq_u64) = seq.parse::<u64>() else {
            stats.skipped_unknown += 1;
            continue;
        };
        let m_tag = mode_tag(mode_sym);

        write_doc(&mut body, case, "HPKE shared-secret KAT (seal + open)");
        writeln!(body, "#[test]").unwrap();
        writeln!(body, "#[allow(deprecated)]").unwrap();
        writeln!(
            body,
            "fn tc_line{}_hpke_ss_{m_tag}_{kem_tag}_{kdf_tag}_{aead_tag}() {{",
            case.line
        )
        .unwrap();
        writeln!(
            body,
            "    let suite = CipherSuite {{ kem: HpkeKem::{kem_var}, kdf: HpkeKdf::{kdf_var}, aead: HpkeAead::{aead_var} }};"
        )
        .unwrap();
        writeln!(body, "    let info: &[u8] = {};", format_byte_slice(info)).unwrap();
        writeln!(body, "    let psk: &[u8] = {};", format_byte_slice(psk)).unwrap();
        writeln!(
            body,
            "    let psk_id: &[u8] = {};",
            format_byte_slice(psk_id)
        )
        .unwrap();
        writeln!(
            body,
            "    let shared_secret: &[u8] = {};",
            format_byte_slice(shared_secret)
        )
        .unwrap();
        writeln!(body, "    let pt: &[u8] = {};", format_byte_slice(pt)).unwrap();
        writeln!(body, "    let aad: &[u8] = {};", format_byte_slice(aad)).unwrap();
        writeln!(
            body,
            "    let expected_ct: &[u8] = {};",
            format_byte_slice(ct)
        )
        .unwrap();
        writeln!(
            body,
            "    let mut ctx_s = HpkeCtx::from_shared_secret(suite, 0x{:02x}, shared_secret, info, psk, psk_id).unwrap();",
            mode_b
        )
        .unwrap();
        writeln!(body, "    ctx_s.set_seq({seq_u64});").unwrap();
        writeln!(body, "    let ct = ctx_s.seal(aad, pt).unwrap();").unwrap();
        writeln!(body, "    assert_eq!(ct.as_slice(), expected_ct);").unwrap();
        writeln!(
            body,
            "    let mut ctx_r = HpkeCtx::from_shared_secret(suite, 0x{:02x}, shared_secret, info, psk, psk_id).unwrap();",
            mode_b
        )
        .unwrap();
        writeln!(body, "    ctx_r.set_seq({seq_u64});").unwrap();
        writeln!(
            body,
            "    let pt_rec = ctx_r.open(aad, expected_ct).unwrap();"
        )
        .unwrap();
        writeln!(body, "    assert_eq!(pt_rec.as_slice(), pt);").unwrap();
        writeln!(body, "}}\n").unwrap();
        stats.emitted += 1;
    }

    let mut out = String::new();
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo hpke`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_eal_hpke.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\
         #![cfg(all(feature = \"hpke\", feature = \"kat-nonce\"))]\n\n\
         use hitls_crypto::hpke::{CipherSuite, HpkeAead, HpkeCtx, HpkeKdf, HpkeKem};\n\n",
    );
    out.push_str(&body);
    write_footer(&mut out, &stats, cases.len());
    (out, stats)
}
