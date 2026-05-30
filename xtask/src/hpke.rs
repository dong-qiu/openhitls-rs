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

// KEM_TC001 rows use raw RFC 9180 IANA codepoints (decimal integers in the
// `.data` file) rather than the `CRYPT_*` macro names. Map each integer to
// the Rust enum variant + short tag used in test names.

fn int_mode(sym: &str) -> Option<(u8, &'static str)> {
    match sym {
        "0" => Some((0x00, "base")),
        "1" => Some((0x01, "psk")),
        "2" => Some((0x02, "auth")),
        "3" => Some((0x03, "auth_psk")),
        _ => None,
    }
}

fn int_kem(sym: &str) -> Option<(&'static str, &'static str)> {
    match sym {
        "16" => Some(("DhkemP256HkdfSha256", "p256")),
        "17" => Some(("DhkemP384HkdfSha384", "p384")),
        "18" => Some(("DhkemP521HkdfSha512", "p521")),
        "32" => Some(("DhkemX25519HkdfSha256", "x25519")),
        _ => None,
    }
}

fn int_kdf_tag(sym: &str) -> Option<&'static str> {
    match sym {
        "1" => Some("sha256"),
        "2" => Some("sha384"),
        "3" => Some("sha512"),
        _ => None,
    }
}

fn int_aead_tag(sym: &str) -> Option<&'static str> {
    match sym {
        "1" => Some("aes128gcm"),
        "2" => Some("aes256gcm"),
        "3" => Some("chacha20poly1305"),
        _ => None,
    }
}

/// Curve byte length of the secret key for each HPKE KEM. NIST P-256 / P-384 /
/// P-521 are mod-N scalars; the C SDV `.data` file strips leading zeros in
/// the hex encoding of `skEm` / `skRm` / `skSm` for a handful of rows (~3
/// out of 24 in `KEM_TC001`), while `derive_key_pair` returns the
/// full-length, zero-padded scalar. We left-pad the row's expected `sk_*`
/// values up to the curve byte length so the byte-exact assertion succeeds.
/// X25519 secret keys are always 32 bytes (no leading-zero semantics),
/// so this is a no-op for `DhkemX25519HkdfSha256`.
fn kem_sk_len(kem_id_sym: &str) -> Option<usize> {
    match kem_id_sym {
        "16" => Some(32), // DhkemP256HkdfSha256
        "17" => Some(48), // DhkemP384HkdfSha384
        "18" => Some(66), // DhkemP521HkdfSha512
        "32" => Some(32), // DhkemX25519HkdfSha256
        _ => None,
    }
}

fn pad_left_to(bytes: &[u8], n: usize) -> Vec<u8> {
    if bytes.len() >= n {
        bytes.to_vec()
    } else {
        let mut out = vec![0u8; n - bytes.len()];
        out.extend_from_slice(bytes);
        out
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

// Per-row emitter for KEM_TC001. C test fn:
//   void SDV_CRYPT_EAL_HPKE_KEM_TC001(int mode, int kemId, int kdfId, int aeadId,
//       Hex *info, Hex *psk, Hex *pskId,
//       Hex *ikmE, Hex *pkEm, Hex *skEm,
//       Hex *ikmR, Hex *pkRm, Hex *skRm,
//       Hex *ikmS, Hex *pkSm, Hex *skSm,
//       Hex *enc, Hex *sharedSecret,
//       Hex *keyScheduleContext, Hex *secret, Hex *key, Hex *baseNonce, Hex *exporterSecret);
//
// The row publishes BOTH the deterministic ephemeral / recipient / sender-auth
// key pairs AND the resulting `(enc, sharedSecret)` from Encap/Decap. The
// migration asserts:
//   * DeriveKeyPair(ikm_e) -> (sk_e, pk_e) == (skEm, pkEm)
//   * DeriveKeyPair(ikm_r) -> (sk_r, pk_r) == (skRm, pkRm)
//   * For AUTH/AUTH_PSK: DeriveKeyPair(ikm_s) -> (sk_s, pk_s) == (skSm, pkSm)
//   * Sender-side Encap (or AuthEncap) -> (shared_secret, enc) ==
//     (sharedSecret, enc)
//   * Recipient-side Decap (or AuthDecap) -> shared_secret == sharedSecret
//
// The 5 trailing intermediate values (keyScheduleContext / secret / key /
// baseNonce / exporterSecret) come from the HPKE Key Schedule, not the KEM,
// and are already implicitly verified by the SHARED_SECRET_TC001 / TC002
// tests — we skip them here.
#[allow(clippy::too_many_lines)]
fn emit_kem_tc001(body: &mut String, stats: &mut EmitStats, case: &TestCase) {
    let (
        Some(mode_sym),
        Some(kem_sym),
        Some(kdf_sym),
        Some(aead_sym),
        Some(_info),
        Some(_psk),
        Some(_psk_id),
        Some(ikm_e),
        Some(pk_em),
        Some(sk_em),
        Some(ikm_r),
        Some(pk_rm),
        Some(sk_rm),
        Some(ikm_s),
        Some(pk_sm),
        Some(sk_sm),
        Some(enc),
        Some(shared_secret),
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
        case.args.get(11).and_then(|a| a.as_hex()),
        case.args.get(12).and_then(|a| a.as_hex()),
        case.args.get(13).and_then(|a| a.as_hex()),
        case.args.get(14).and_then(|a| a.as_hex()),
        case.args.get(15).and_then(|a| a.as_hex()),
        case.args.get(16).and_then(|a| a.as_hex()),
        case.args.get(17).and_then(|a| a.as_hex()),
    )
    else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some((mode_b, m_tag)) = int_mode(mode_sym) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let Some((kem_var, kem_tag)) = int_kem(kem_sym) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let Some(kdf_tag) = int_kdf_tag(kdf_sym) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let Some(aead_tag) = int_aead_tag(aead_sym) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let Some(sk_len) = kem_sk_len(kem_sym) else {
        stats.skipped_unsupported_alg += 1;
        return;
    };
    let is_auth = mode_b == 0x02 || mode_b == 0x03;
    // C SDV `.data` strips leading zeros from `sk*m` hex (NIST P-256/P-384/P-521
    // scalar with high bit clear); left-pad to the curve byte length to
    // match the fixed-length output of `derive_key_pair`.
    let sk_em_p = pad_left_to(sk_em, sk_len);
    let sk_rm_p = pad_left_to(sk_rm, sk_len);
    let sk_sm_p = if is_auth {
        pad_left_to(sk_sm, sk_len)
    } else {
        Vec::new()
    };

    write_doc(body, case, "HPKE KEM derive+encap+decap KAT");
    writeln!(body, "#[test]").unwrap();
    writeln!(body, "#[allow(deprecated)]").unwrap();
    writeln!(
        body,
        "fn tc_line{}_hpke_kem_{m_tag}_{kem_tag}_{kdf_tag}_{aead_tag}() {{",
        case.line
    )
    .unwrap();
    writeln!(body, "    let kem = HpkeKem::{kem_var};").unwrap();
    writeln!(body, "    let ikm_e: &[u8] = {};", format_byte_slice(ikm_e)).unwrap();
    writeln!(
        body,
        "    let expected_pk_e: &[u8] = {};",
        format_byte_slice(pk_em)
    )
    .unwrap();
    writeln!(
        body,
        "    let expected_sk_e: &[u8] = {};",
        format_byte_slice(&sk_em_p)
    )
    .unwrap();
    writeln!(body, "    let ikm_r: &[u8] = {};", format_byte_slice(ikm_r)).unwrap();
    writeln!(
        body,
        "    let expected_pk_r: &[u8] = {};",
        format_byte_slice(pk_rm)
    )
    .unwrap();
    writeln!(
        body,
        "    let expected_sk_r: &[u8] = {};",
        format_byte_slice(&sk_rm_p)
    )
    .unwrap();
    writeln!(
        body,
        "    let expected_enc: &[u8] = {};",
        format_byte_slice(enc)
    )
    .unwrap();
    writeln!(
        body,
        "    let expected_shared_secret: &[u8] = {};",
        format_byte_slice(shared_secret)
    )
    .unwrap();
    writeln!(
        body,
        "    let (sk_e, pk_e) = derive_key_pair(kem, ikm_e).unwrap();"
    )
    .unwrap();
    writeln!(body, "    assert_eq!(pk_e.as_slice(), expected_pk_e);").unwrap();
    writeln!(body, "    assert_eq!(sk_e.as_slice(), expected_sk_e);").unwrap();
    writeln!(
        body,
        "    let (sk_r, pk_r) = derive_key_pair(kem, ikm_r).unwrap();"
    )
    .unwrap();
    writeln!(body, "    assert_eq!(pk_r.as_slice(), expected_pk_r);").unwrap();
    writeln!(body, "    assert_eq!(sk_r.as_slice(), expected_sk_r);").unwrap();
    if is_auth {
        writeln!(body, "    let ikm_s: &[u8] = {};", format_byte_slice(ikm_s)).unwrap();
        writeln!(
            body,
            "    let expected_pk_s: &[u8] = {};",
            format_byte_slice(pk_sm)
        )
        .unwrap();
        writeln!(
            body,
            "    let expected_sk_s: &[u8] = {};",
            format_byte_slice(&sk_sm_p)
        )
        .unwrap();
        writeln!(
            body,
            "    let (sk_s, pk_s) = derive_key_pair(kem, ikm_s).unwrap();"
        )
        .unwrap();
        writeln!(body, "    assert_eq!(pk_s.as_slice(), expected_pk_s);").unwrap();
        writeln!(body, "    assert_eq!(sk_s.as_slice(), expected_sk_s);").unwrap();
        writeln!(
            body,
            "    let (shared_secret_s, enc) = kem_auth_encap_kat(kem, &pk_r, &sk_s, ikm_e).unwrap();"
        )
        .unwrap();
        writeln!(body, "    assert_eq!(enc.as_slice(), expected_enc);").unwrap();
        writeln!(
            body,
            "    assert_eq!(shared_secret_s.as_slice(), expected_shared_secret);"
        )
        .unwrap();
        writeln!(
            body,
            "    let shared_secret_r = kem_auth_decap_kat(kem, &enc, &sk_r, &pk_s).unwrap();"
        )
        .unwrap();
    } else {
        writeln!(
            body,
            "    let (shared_secret_s, enc) = kem_encap_kat(kem, &pk_r, ikm_e).unwrap();"
        )
        .unwrap();
        writeln!(body, "    assert_eq!(enc.as_slice(), expected_enc);").unwrap();
        writeln!(
            body,
            "    assert_eq!(shared_secret_s.as_slice(), expected_shared_secret);"
        )
        .unwrap();
        writeln!(
            body,
            "    let shared_secret_r = kem_decap_kat(kem, &enc, &sk_r).unwrap();"
        )
        .unwrap();
    }
    writeln!(
        body,
        "    assert_eq!(shared_secret_r.as_slice(), expected_shared_secret);"
    )
    .unwrap();
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
        if case.tc_name.contains("KEM_TC001") {
            emit_kem_tc001(&mut body, &mut stats, case);
            continue;
        }
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
         use hitls_crypto::hpke::{derive_key_pair, kem_auth_decap_kat, kem_auth_encap_kat, kem_decap_kat, kem_encap_kat, CipherSuite, HpkeAead, HpkeCtx, HpkeKdf, HpkeKem};\n\n",
    );
    out.push_str(&body);
    write_footer(&mut out, &stats, cases.len());
    (out, stats)
}
