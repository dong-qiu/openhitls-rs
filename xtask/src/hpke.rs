use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::{format_byte_slice, TestCase};

// ---------------------------------------------------------------------------
// HPKE (RFC 9180) KAT migration — `test_suite_sdv_eal_hpke.data`.
//
// Scope:
// - T149 / T150: SHARED_SECRET_TC001 / TC002. Rows publish the derived
//   `sharedSecret`, so the migration uses `HpkeCtx::from_shared_secret` to
//   drive the **key schedule + AEAD seal/open / export** directly,
//   bypassing the KEM.
// - T151: AEAD_TC001 (seal/open) + EXPORT_SECRET_TC001 (export). Rows
//   publish `ikmE` / `ikmR` / `ikmS` (the ephemeral / recipient / sender-
//   auth seeds). The migration calls the new `kat-nonce`-gated
//   `hitls_crypto::hpke::derive_key_pair` + `HpkeCtx::setup_sender_kat` +
//   `HpkeCtx::setup_recipient_kat` to inject the seeds and reproduce the
//   key schedule + AEAD. `ikmS` is empty for BASE / PSK modes — the
//   emitter still derives `(sk_s, pk_s)` (no-op for BASE / PSK because
//   `setup_sender_kat` / `setup_recipient_kat` ignore those args under
//   non-AUTH modes).
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

// Per-row emitter for SHARED_SECRET_TC002. C test fn:
//   void SDV_CRYPT_EAL_HPKE_SHARED_SECRET_TC002(
//       int mode, int kemId, int kdfId, int aeadId,
//       Hex *info, Hex *psk, Hex *pskId, Hex *sharedSecret,
//       Hex *exporterContext, int L, Hex *exportedValue);
// The C body builds both sender + recipient ctxs from the shared_secret and
// asserts `ExportSecret(ctx, exporterContext, L) == exportedValue` against
// both. The Rust `HpkeCtx::export` is `&self` (read-only), so a single ctx
// is functionally identical to two — we emit one ctx per row.
fn emit_shared_secret_tc002(body: &mut String, stats: &mut EmitStats, case: &TestCase) {
    let (
        Some(mode_sym),
        Some(kem_sym),
        Some(kdf_sym),
        Some(aead_sym),
        Some(info),
        Some(psk),
        Some(psk_id),
        Some(shared_secret),
        Some(exporter_context),
        Some(l),
        Some(exported_value),
    ) = (
        case.args.first().and_then(|a| a.as_symbol()),
        case.args.get(1).and_then(|a| a.as_symbol()),
        case.args.get(2).and_then(|a| a.as_symbol()),
        case.args.get(3).and_then(|a| a.as_symbol()),
        case.args.get(4).and_then(|a| a.as_hex()),
        case.args.get(5).and_then(|a| a.as_hex()),
        case.args.get(6).and_then(|a| a.as_hex()),
        case.args.get(7).and_then(|a| a.as_hex()),
        case.args.get(8).and_then(|a| a.as_hex()),
        case.args.get(9).and_then(|a| a.as_symbol()),
        case.args.get(10).and_then(|a| a.as_hex()),
    )
    else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(mode_b) = mode_byte(mode_sym) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let Some((kem_var, kem_tag)) = kem_enum(kem_sym) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let Some((kdf_var, kdf_tag)) = kdf_enum(kdf_sym) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let Some((aead_var, aead_tag)) = aead_enum(aead_sym) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let Ok(l_usize) = l.parse::<usize>() else {
        stats.skipped_unknown += 1;
        return;
    };
    let m_tag = mode_tag(mode_sym);

    write_doc(body, case, "HPKE shared-secret export KAT");
    writeln!(body, "#[test]").unwrap();
    writeln!(body, "#[allow(deprecated)]").unwrap();
    writeln!(
        body,
        "fn tc_line{}_hpke_export_{m_tag}_{kem_tag}_{kdf_tag}_{aead_tag}() {{",
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
    writeln!(
        body,
        "    let exporter_context: &[u8] = {};",
        format_byte_slice(exporter_context)
    )
    .unwrap();
    writeln!(
        body,
        "    let expected: &[u8] = {};",
        format_byte_slice(exported_value)
    )
    .unwrap();
    writeln!(
        body,
        "    let ctx = HpkeCtx::from_shared_secret(suite, 0x{:02x}, shared_secret, info, psk, psk_id).unwrap();",
        mode_b
    )
    .unwrap();
    writeln!(
        body,
        "    let exported = ctx.export(exporter_context, {l_usize}).unwrap();"
    )
    .unwrap();
    writeln!(body, "    assert_eq!(exported.as_slice(), expected);").unwrap();
    writeln!(body, "}}\n").unwrap();
    stats.emitted += 1;
}

// Helper: emit the suite + ikm + derive_key_pair block shared by AEAD_TC001
// and EXPORT_SECRET_TC001. After this preamble, `suite`, `info`, `psk`,
// `psk_id`, `ikm_e`, `sk_r`, `pk_r`, `sk_s`, `pk_s` are all in scope.
#[allow(clippy::too_many_arguments)]
fn emit_kat_derive_block(
    body: &mut String,
    kem_var: &str,
    kdf_var: &str,
    aead_var: &str,
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
    ikm_e: &[u8],
    ikm_r: &[u8],
    ikm_s: &[u8],
) {
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
    writeln!(body, "    let ikm_e: &[u8] = {};", format_byte_slice(ikm_e)).unwrap();
    writeln!(body, "    let ikm_r: &[u8] = {};", format_byte_slice(ikm_r)).unwrap();
    writeln!(body, "    let ikm_s: &[u8] = {};", format_byte_slice(ikm_s)).unwrap();
    writeln!(
        body,
        "    let (sk_r, pk_r) = derive_key_pair(suite.kem, ikm_r).unwrap();"
    )
    .unwrap();
    writeln!(
        body,
        "    let (sk_s, pk_s) = derive_key_pair(suite.kem, ikm_s).unwrap();"
    )
    .unwrap();
}

// Helper: emit setup_sender_kat / setup_recipient_kat lines. `mut_kw` is
// "mut " or "" — AEAD tests need mut for set_seq/seal/open; EXPORT tests
// only call &self::export.
fn emit_kat_setup_ctxs(body: &mut String, mode_b: u8, mut_kw: &str) {
    writeln!(
        body,
        "    let ({mut_kw}ctx_s, enc) = HpkeCtx::setup_sender_kat(suite, 0x{mode_b:02x}, &pk_r, &sk_s, info, psk, psk_id, ikm_e).unwrap();"
    )
    .unwrap();
    writeln!(
        body,
        "    let {mut_kw}ctx_r = HpkeCtx::setup_recipient_kat(suite, 0x{mode_b:02x}, &sk_r, &pk_s, &enc, info, psk, psk_id).unwrap();"
    )
    .unwrap();
}

// Per-row emitter for AEAD_TC001. C test fn:
//   void SDV_CRYPT_EAL_HPKE_AEAD_TC001(
//       int mode, int kemId, int kdfId, int aeadId,
//       Hex *info, Hex *psk, Hex *pskId,
//       Hex *ikmE, Hex *ikmR, Hex *ikmS,
//       int seq, Hex *pt, Hex *aad, Hex *ct);
// Each row asserts both `seal(aad, pt) == ct` (sender) and
// `open(aad, ct) == pt` (recipient).
#[allow(clippy::too_many_lines)]
fn emit_aead_tc001(body: &mut String, stats: &mut EmitStats, case: &TestCase) {
    let (
        Some(mode_sym),
        Some(kem_sym),
        Some(kdf_sym),
        Some(aead_sym),
        Some(info),
        Some(psk),
        Some(psk_id),
        Some(ikm_e),
        Some(ikm_r),
        Some(ikm_s),
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
        case.args.get(8).and_then(|a| a.as_hex()),
        case.args.get(9).and_then(|a| a.as_hex()),
        case.args.get(10).and_then(|a| a.as_symbol()),
        case.args.get(11).and_then(|a| a.as_hex()),
        case.args.get(12).and_then(|a| a.as_hex()),
        case.args.get(13).and_then(|a| a.as_hex()),
    )
    else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(mode_b) = mode_byte(mode_sym) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let Some((kem_var, kem_tag)) = kem_enum(kem_sym) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let Some((kdf_var, kdf_tag)) = kdf_enum(kdf_sym) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let Some((aead_var, aead_tag)) = aead_enum(aead_sym) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let Ok(seq_u64) = seq.parse::<u64>() else {
        stats.skipped_unknown += 1;
        return;
    };
    let m_tag = mode_tag(mode_sym);

    write_doc(
        body,
        case,
        "HPKE AEAD KAT (seal + open with ikmE injection)",
    );
    writeln!(body, "#[test]").unwrap();
    writeln!(body, "#[allow(deprecated)]").unwrap();
    writeln!(
        body,
        "fn tc_line{}_hpke_aead_{m_tag}_{kem_tag}_{kdf_tag}_{aead_tag}() {{",
        case.line
    )
    .unwrap();
    emit_kat_derive_block(
        body, kem_var, kdf_var, aead_var, info, psk, psk_id, ikm_e, ikm_r, ikm_s,
    );
    emit_kat_setup_ctxs(body, mode_b, "mut ");
    writeln!(body, "    let pt: &[u8] = {};", format_byte_slice(pt)).unwrap();
    writeln!(body, "    let aad: &[u8] = {};", format_byte_slice(aad)).unwrap();
    writeln!(
        body,
        "    let expected_ct: &[u8] = {};",
        format_byte_slice(ct)
    )
    .unwrap();
    writeln!(body, "    ctx_s.set_seq({seq_u64});").unwrap();
    writeln!(body, "    let ct = ctx_s.seal(aad, pt).unwrap();").unwrap();
    writeln!(body, "    assert_eq!(ct.as_slice(), expected_ct);").unwrap();
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

// Per-row emitter for EXPORT_SECRET_TC001. C test fn:
//   void SDV_CRYPT_EAL_HPKE_EXPORT_SECRET_TC001(
//       int mode, int kemId, int kdfId, int aeadId,
//       Hex *info, Hex *psk, Hex *pskId,
//       Hex *ikmE, Hex *ikmR, Hex *ikmS,
//       Hex *exporterContext, int L, Hex *exportedValue);
// Both sender + recipient ctxs export the same value (the export label is
// independent of role). We assert against the sender-side context only.
fn emit_export_secret_tc001(body: &mut String, stats: &mut EmitStats, case: &TestCase) {
    let (
        Some(mode_sym),
        Some(kem_sym),
        Some(kdf_sym),
        Some(aead_sym),
        Some(info),
        Some(psk),
        Some(psk_id),
        Some(ikm_e),
        Some(ikm_r),
        Some(ikm_s),
        Some(exporter_context),
        Some(l),
        Some(exported_value),
    ) = (
        case.args.first().and_then(|a| a.as_symbol()),
        case.args.get(1).and_then(|a| a.as_symbol()),
        case.args.get(2).and_then(|a| a.as_symbol()),
        case.args.get(3).and_then(|a| a.as_symbol()),
        case.args.get(4).and_then(|a| a.as_hex()),
        case.args.get(5).and_then(|a| a.as_hex()),
        case.args.get(6).and_then(|a| a.as_hex()),
        case.args.get(7).and_then(|a| a.as_hex()),
        case.args.get(8).and_then(|a| a.as_hex()),
        case.args.get(9).and_then(|a| a.as_hex()),
        case.args.get(10).and_then(|a| a.as_hex()),
        case.args.get(11).and_then(|a| a.as_symbol()),
        case.args.get(12).and_then(|a| a.as_hex()),
    )
    else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(mode_b) = mode_byte(mode_sym) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let Some((kem_var, kem_tag)) = kem_enum(kem_sym) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let Some((kdf_var, kdf_tag)) = kdf_enum(kdf_sym) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let Some((aead_var, aead_tag)) = aead_enum(aead_sym) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let Ok(l_usize) = l.parse::<usize>() else {
        stats.skipped_unknown += 1;
        return;
    };
    let m_tag = mode_tag(mode_sym);

    write_doc(body, case, "HPKE export-secret KAT with ikmE injection");
    writeln!(body, "#[test]").unwrap();
    writeln!(body, "#[allow(deprecated)]").unwrap();
    writeln!(
        body,
        "fn tc_line{}_hpke_exp_{m_tag}_{kem_tag}_{kdf_tag}_{aead_tag}() {{",
        case.line
    )
    .unwrap();
    emit_kat_derive_block(
        body, kem_var, kdf_var, aead_var, info, psk, psk_id, ikm_e, ikm_r, ikm_s,
    );
    emit_kat_setup_ctxs(body, mode_b, "");
    writeln!(
        body,
        "    let exporter_context: &[u8] = {};",
        format_byte_slice(exporter_context)
    )
    .unwrap();
    writeln!(
        body,
        "    let expected: &[u8] = {};",
        format_byte_slice(exported_value)
    )
    .unwrap();
    writeln!(
        body,
        "    let exported_s = ctx_s.export(exporter_context, {l_usize}).unwrap();"
    )
    .unwrap();
    writeln!(body, "    assert_eq!(exported_s.as_slice(), expected);").unwrap();
    writeln!(
        body,
        "    let exported_r = ctx_r.export(exporter_context, {l_usize}).unwrap();"
    )
    .unwrap();
    writeln!(body, "    assert_eq!(exported_r.as_slice(), expected);").unwrap();
    writeln!(body, "}}\n").unwrap();
    stats.emitted += 1;
}

pub fn emit_hpke_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();

    for case in cases {
        // Migration scope (T149/T150/T151):
        //   * SHARED_SECRET_TC001 (seal/open) — uses `from_shared_secret`.
        //   * SHARED_SECRET_TC002 (export) — uses `from_shared_secret`.
        //   * AEAD_TC001 (seal/open) — uses `setup_sender_kat` + `setup_recipient_kat`.
        //   * EXPORT_SECRET_TC001 (export) — uses `setup_sender_kat` (sender ctx).
        // Remaining (KEM_TC001 / ABNORMAL / RANDOMLY / GENERATE_KEY_PAIR /
        // SHARED_SECRET_RANDOMLY) route to API-surface — KEM_TC001 still
        // pending its own emitter shape (derive+encap+decap byte-exact).
        if case.tc_name.contains("AEAD_TC001") {
            emit_aead_tc001(&mut body, &mut stats, case);
            continue;
        }
        if case.tc_name.contains("EXPORT_SECRET_TC001") {
            emit_export_secret_tc001(&mut body, &mut stats, case);
            continue;
        }
        if case.tc_name.contains("SHARED_SECRET_TC002") {
            emit_shared_secret_tc002(&mut body, &mut stats, case);
            continue;
        }
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
         #[allow(deprecated)]\n\
         use hitls_crypto::hpke::{derive_key_pair, CipherSuite, HpkeAead, HpkeCtx, HpkeKdf, HpkeKem};\n\n",
    );
    out.push_str(&body);
    write_footer(&mut out, &stats, cases.len());
    (out, stats)
}
