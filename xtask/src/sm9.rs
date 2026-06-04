use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::{format_byte_slice, TestCase};

// ---------------------------------------------------------------------------
// SM9 (GB/T 38635) identity-based PKC KAT migration.
//
// Source files (all under `crypto/sm9/`):
//   * `test_suite_sdv_eal_sm9_sign.data` — sign + ctx-CRUD families
//   * `test_suite_sdv_eal_sm9_crypt.data` — encrypt + ctx-CRUD families
//   * `test_suite_sdv_eal_sm9_exchange.data` — SM9 key exchange (Rust has
//     no key-exchange API → API-surface)
//
// The SM9 `.data` files are largely **API tests**: each TC has a header row
// (arg-name list) followed by a data row. The migration scope (T158):
//
//   * SIGN_API_TC001 / TC002 — round-trip sign + verify (the C tests use
//     `assert(sign_then_verify == SUCCESS)`; no byte-exact KAT, but they
//     exercise the full sign→verify path with a fixed master key).
//   * CRYPT_API_TC001 / TC002 — round-trip encrypt + decrypt to a single
//     user ID.
//   * CRYPT_API_TC003 — round-trip encrypt + decrypt across two user IDs
//     (encrypt to B, decrypt with B's user key).
//   * CHECK_KEYPAIR_FUNC_TC001 — derive two user keys from the same master,
//     assert successful derivation for both.
//   * CHECK_PRVKEY_FUNC_TC001 — derive a single user key, assert sign +
//     verify round-trip succeeds with a sample message (validates that the
//     derived private key is functional).
//   * KEYEX_API_TC001 (added in T159) — round-trip GB/T 38635 §4.4 key
//     agreement: both sides call `Sm9MasterKey::compute_share_key` and
//     assert SK_A == SK_B, plus 63-byte (`SK_Long`) and 15-byte (`SK_Short`)
//     klen variants per the C SDV. The Rust API was added in I158.
//     KEYEX_API_TC002 stays API-surface — it drills NULL-pointer rejection
//     on the EAL `ComputeShareKey` wrapper, which Rust's borrow checker
//     forbids at compile time, so there's no runtime check to migrate.
//
// Header rows (where every arg is a bare identifier rather than a quoted
// hex literal) are detected by `args.first().and_then(|a| a.as_hex())`
// returning `None` and routed to API-surface; everything else not in the
// list above is also API-surface (the EAL ctx CRUD families have no Rust
// counterpart).
//
// All emitted tests require the new `kat-nonce`-gated
// `Sm9MasterKey::from_master_secret(key_type, ks_bytes_32)` constructor
// to bypass `generate()`'s randomness.
// ---------------------------------------------------------------------------

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

/// SIGN_API row: `(masterKey, userId, message)`. Round-trip sign + verify
/// + negative case (verify with a different message must fail).
fn emit_sign_api(body: &mut String, stats: &mut EmitStats, case: &TestCase, suffix: &str) {
    let (Some(master_key), Some(user_id), Some(msg)) = (
        case.args.first().and_then(|a| a.as_hex()),
        case.args.get(1).and_then(|a| a.as_hex()),
        case.args.get(2).and_then(|a| a.as_hex()),
    ) else {
        stats.skipped_api += 1;
        return;
    };
    write_doc(body, case, "SM9 sign+verify round-trip");
    writeln!(body, "#[test]").unwrap();
    writeln!(body, "#[allow(deprecated)]").unwrap();
    writeln!(body, "fn tc_line{}_sm9_sign_{suffix}() {{", case.line).unwrap();
    writeln!(
        body,
        "    let master_key: &[u8] = {};",
        format_byte_slice(master_key)
    )
    .unwrap();
    writeln!(
        body,
        "    let user_id: &[u8] = {};",
        format_byte_slice(user_id)
    )
    .unwrap();
    writeln!(body, "    let msg: &[u8] = {};", format_byte_slice(msg)).unwrap();
    writeln!(
        body,
        "    let master = Sm9MasterKey::from_master_secret(Sm9KeyType::Sign, master_key).unwrap();"
    )
    .unwrap();
    writeln!(
        body,
        "    let user = master.extract_user_key(user_id).unwrap();"
    )
    .unwrap();
    writeln!(
        body,
        "    let sig = user.sign(msg, master.master_public_key()).unwrap();"
    )
    .unwrap();
    writeln!(
        body,
        "    assert!(master.verify(user_id, msg, &sig).unwrap(), \"valid signature must verify\");"
    )
    .unwrap();
    writeln!(body, "    let wrong_msg = b\"Wrong Message\";").unwrap();
    writeln!(
        body,
        "    assert!(!master.verify(user_id, wrong_msg, &sig).unwrap(), \"wrong-message verify must fail\");"
    )
    .unwrap();
    writeln!(body, "}}\n").unwrap();
    stats.emitted += 1;
}

/// CRYPT_API_TC001/TC002 row: `(masterKey, userId, plaintext)`. Round-trip
/// encrypt + decrypt to the same user.
fn emit_crypt_api_self(body: &mut String, stats: &mut EmitStats, case: &TestCase, suffix: &str) {
    let (Some(master_key), Some(user_id), Some(pt)) = (
        case.args.first().and_then(|a| a.as_hex()),
        case.args.get(1).and_then(|a| a.as_hex()),
        case.args.get(2).and_then(|a| a.as_hex()),
    ) else {
        stats.skipped_api += 1;
        return;
    };
    write_doc(body, case, "SM9 encrypt+decrypt round-trip (same user)");
    writeln!(body, "#[test]").unwrap();
    writeln!(body, "#[allow(deprecated)]").unwrap();
    writeln!(body, "fn tc_line{}_sm9_crypt_self_{suffix}() {{", case.line).unwrap();
    writeln!(
        body,
        "    let master_key: &[u8] = {};",
        format_byte_slice(master_key)
    )
    .unwrap();
    writeln!(
        body,
        "    let user_id: &[u8] = {};",
        format_byte_slice(user_id)
    )
    .unwrap();
    writeln!(body, "    let pt: &[u8] = {};", format_byte_slice(pt)).unwrap();
    writeln!(
        body,
        "    let master = Sm9MasterKey::from_master_secret(Sm9KeyType::Encrypt, master_key).unwrap();"
    )
    .unwrap();
    writeln!(
        body,
        "    let user = master.extract_user_key(user_id).unwrap();"
    )
    .unwrap();
    writeln!(body, "    let ct = master.encrypt(user_id, pt).unwrap();").unwrap();
    writeln!(body, "    let decrypted = user.decrypt(&ct).unwrap();").unwrap();
    writeln!(body, "    assert_eq!(decrypted.as_slice(), pt);").unwrap();
    writeln!(body, "}}\n").unwrap();
    stats.emitted += 1;
}

/// CRYPT_API_TC003 row: `(masterKey, userIdA, userIdB, plaintext)`. Encrypt
/// to user B, decrypt with B's key; verify A's key cannot decrypt B's ct.
fn emit_crypt_api_cross(body: &mut String, stats: &mut EmitStats, case: &TestCase) {
    let (Some(master_key), Some(user_a), Some(user_b), Some(pt)) = (
        case.args.first().and_then(|a| a.as_hex()),
        case.args.get(1).and_then(|a| a.as_hex()),
        case.args.get(2).and_then(|a| a.as_hex()),
        case.args.get(3).and_then(|a| a.as_hex()),
    ) else {
        stats.skipped_api += 1;
        return;
    };
    write_doc(body, case, "SM9 encrypt+decrypt round-trip (cross-user)");
    writeln!(body, "#[test]").unwrap();
    writeln!(body, "#[allow(deprecated)]").unwrap();
    writeln!(body, "fn tc_line{}_sm9_crypt_cross() {{", case.line).unwrap();
    writeln!(
        body,
        "    let master_key: &[u8] = {};",
        format_byte_slice(master_key)
    )
    .unwrap();
    writeln!(
        body,
        "    let user_a: &[u8] = {};",
        format_byte_slice(user_a)
    )
    .unwrap();
    writeln!(
        body,
        "    let user_b: &[u8] = {};",
        format_byte_slice(user_b)
    )
    .unwrap();
    writeln!(body, "    let pt: &[u8] = {};", format_byte_slice(pt)).unwrap();
    writeln!(
        body,
        "    let master = Sm9MasterKey::from_master_secret(Sm9KeyType::Encrypt, master_key).unwrap();"
    )
    .unwrap();
    writeln!(
        body,
        "    let user_a_key = master.extract_user_key(user_a).unwrap();"
    )
    .unwrap();
    writeln!(
        body,
        "    let user_b_key = master.extract_user_key(user_b).unwrap();"
    )
    .unwrap();
    writeln!(body, "    let ct = master.encrypt(user_b, pt).unwrap();").unwrap();
    writeln!(
        body,
        "    let decrypted_b = user_b_key.decrypt(&ct).unwrap();"
    )
    .unwrap();
    writeln!(body, "    assert_eq!(decrypted_b.as_slice(), pt);").unwrap();
    writeln!(
        body,
        "    assert!(user_a_key.decrypt(&ct).is_err(), \"user A must not decrypt ciphertext addressed to user B\");"
    )
    .unwrap();
    writeln!(body, "}}\n").unwrap();
    stats.emitted += 1;
}

/// CHECK_KEYPAIR_FUNC_TC001 row: `(masterKey, userId1, userId2)`. Derive
/// two user keys from the same master + assert both can sign successfully.
fn emit_check_keypair(body: &mut String, stats: &mut EmitStats, case: &TestCase) {
    let (Some(master_key), Some(user_id1), Some(user_id2)) = (
        case.args.first().and_then(|a| a.as_hex()),
        case.args.get(1).and_then(|a| a.as_hex()),
        case.args.get(2).and_then(|a| a.as_hex()),
    ) else {
        stats.skipped_api += 1;
        return;
    };
    write_doc(
        body,
        case,
        "SM9 check-keypair (dual-user extract round-trip)",
    );
    writeln!(body, "#[test]").unwrap();
    writeln!(body, "#[allow(deprecated)]").unwrap();
    writeln!(body, "fn tc_line{}_sm9_check_keypair() {{", case.line).unwrap();
    writeln!(
        body,
        "    let master_key: &[u8] = {};",
        format_byte_slice(master_key)
    )
    .unwrap();
    writeln!(
        body,
        "    let user_id1: &[u8] = {};",
        format_byte_slice(user_id1)
    )
    .unwrap();
    writeln!(
        body,
        "    let user_id2: &[u8] = {};",
        format_byte_slice(user_id2)
    )
    .unwrap();
    writeln!(
        body,
        "    let master = Sm9MasterKey::from_master_secret(Sm9KeyType::Sign, master_key).unwrap();"
    )
    .unwrap();
    writeln!(
        body,
        "    let user1 = master.extract_user_key(user_id1).unwrap();"
    )
    .unwrap();
    writeln!(
        body,
        "    let user2 = master.extract_user_key(user_id2).unwrap();"
    )
    .unwrap();
    writeln!(body, "    let msg = b\"keypair check\";").unwrap();
    writeln!(
        body,
        "    let sig1 = user1.sign(msg, master.master_public_key()).unwrap();"
    )
    .unwrap();
    writeln!(
        body,
        "    let sig2 = user2.sign(msg, master.master_public_key()).unwrap();"
    )
    .unwrap();
    writeln!(
        body,
        "    assert!(master.verify(user_id1, msg, &sig1).unwrap());"
    )
    .unwrap();
    writeln!(
        body,
        "    assert!(master.verify(user_id2, msg, &sig2).unwrap());"
    )
    .unwrap();
    // Cross-verify: user1's sig must not verify against user2's identity.
    writeln!(
        body,
        "    assert!(!master.verify(user_id2, msg, &sig1).unwrap(), \"cross-identity verify must fail\");"
    )
    .unwrap();
    writeln!(body, "}}\n").unwrap();
    stats.emitted += 1;
}

/// CHECK_PRVKEY_FUNC_TC001 row: `(masterKey, userId)`. Derive a user key,
/// validate that it's functional by signing + verifying a sample message.
fn emit_check_prvkey(body: &mut String, stats: &mut EmitStats, case: &TestCase) {
    let (Some(master_key), Some(user_id)) = (
        case.args.first().and_then(|a| a.as_hex()),
        case.args.get(1).and_then(|a| a.as_hex()),
    ) else {
        stats.skipped_api += 1;
        return;
    };
    write_doc(body, case, "SM9 check-prvkey (derive + sign round-trip)");
    writeln!(body, "#[test]").unwrap();
    writeln!(body, "#[allow(deprecated)]").unwrap();
    writeln!(body, "fn tc_line{}_sm9_check_prvkey() {{", case.line).unwrap();
    writeln!(
        body,
        "    let master_key: &[u8] = {};",
        format_byte_slice(master_key)
    )
    .unwrap();
    writeln!(
        body,
        "    let user_id: &[u8] = {};",
        format_byte_slice(user_id)
    )
    .unwrap();
    writeln!(
        body,
        "    let master = Sm9MasterKey::from_master_secret(Sm9KeyType::Sign, master_key).unwrap();"
    )
    .unwrap();
    writeln!(
        body,
        "    let user = master.extract_user_key(user_id).unwrap();"
    )
    .unwrap();
    writeln!(body, "    let msg = b\"prvkey check\";").unwrap();
    writeln!(
        body,
        "    let sig = user.sign(msg, master.master_public_key()).unwrap();"
    )
    .unwrap();
    writeln!(
        body,
        "    assert!(master.verify(user_id, msg, &sig).unwrap(), \"derived private key must produce a valid signature\");"
    )
    .unwrap();
    writeln!(body, "}}\n").unwrap();
    stats.emitted += 1;
}

/// KEYEX_API_TC001 row: `(masterKey, userIdA, userIdB)`. GB/T 38635 §4.4
/// key agreement round-trip: derive both user keys, run
/// `Sm9MasterKey::compute_share_key` from each side, assert the shared
/// secrets agree at the default 32-byte klen plus the SDV-mandated
/// `SK_Long` (63 bytes — crosses an SM3 block boundary) and `SK_Short`
/// (15 bytes — tail-only path) klen variants.
fn emit_keyex_api(body: &mut String, stats: &mut EmitStats, case: &TestCase) {
    let (Some(master_key), Some(user_a), Some(user_b)) = (
        case.args.first().and_then(|a| a.as_hex()),
        case.args.get(1).and_then(|a| a.as_hex()),
        case.args.get(2).and_then(|a| a.as_hex()),
    ) else {
        stats.skipped_api += 1;
        return;
    };
    write_doc(body, case, "SM9 key exchange round-trip (GB/T 38635 §4.4)");
    writeln!(body, "#[test]").unwrap();
    writeln!(body, "#[allow(deprecated)]").unwrap();
    writeln!(body, "fn tc_line{}_sm9_keyex_roundtrip() {{", case.line).unwrap();
    writeln!(
        body,
        "    let master_key: &[u8] = {};",
        format_byte_slice(master_key)
    )
    .unwrap();
    writeln!(
        body,
        "    let user_a: &[u8] = {};",
        format_byte_slice(user_a)
    )
    .unwrap();
    writeln!(
        body,
        "    let user_b: &[u8] = {};",
        format_byte_slice(user_b)
    )
    .unwrap();
    writeln!(
        body,
        "    let master = Sm9MasterKey::from_master_secret(Sm9KeyType::Encrypt, master_key).unwrap();"
    )
    .unwrap();
    writeln!(
        body,
        "    let key_a = master.extract_user_key(user_a).unwrap();"
    )
    .unwrap();
    writeln!(
        body,
        "    let key_b = master.extract_user_key(user_b).unwrap();"
    )
    .unwrap();
    // Default klen — `SM9_SHARED_KEY_LEN` in the C SDV is 32 (one SM3 block).
    writeln!(body, "    for klen in [32usize, 63, 15] {{").unwrap();
    writeln!(
        body,
        "        let sk_a = master.compute_share_key(&key_a, &key_b, klen).unwrap();"
    )
    .unwrap();
    writeln!(
        body,
        "        let sk_b = master.compute_share_key(&key_b, &key_a, klen).unwrap();"
    )
    .unwrap();
    writeln!(body, "        assert_eq!(sk_a.len(), klen);").unwrap();
    writeln!(
        body,
        "        assert_eq!(sk_a, sk_b, \"SK_A and SK_B must agree at klen={{klen}}\");"
    )
    .unwrap();
    writeln!(body, "    }}").unwrap();
    writeln!(body, "}}\n").unwrap();
    stats.emitted += 1;
}

pub fn emit_sm9_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();

    for case in cases {
        // Header rows (e.g. `SDV_X:masterKey:userId:message` — bare
        // identifiers, no quoted hex) parse as all-`Arg::Symbol` and have
        // no usable byte data; route to API-surface.
        let first_is_hex = case.args.first().and_then(|a| a.as_hex()).is_some();
        if !first_is_hex {
            stats.skipped_api += 1;
            continue;
        }
        let name = &case.tc_name;
        if name.contains("SIGN_API_TC001") {
            emit_sign_api(&mut body, &mut stats, case, "tc001");
        } else if name.contains("SIGN_API_TC002") {
            emit_sign_api(&mut body, &mut stats, case, "tc002");
        } else if name.contains("CRYPT_API_TC001") {
            emit_crypt_api_self(&mut body, &mut stats, case, "tc001");
        } else if name.contains("CRYPT_API_TC002") {
            emit_crypt_api_self(&mut body, &mut stats, case, "tc002");
        } else if name.contains("CRYPT_API_TC003") {
            emit_crypt_api_cross(&mut body, &mut stats, case);
        } else if name.contains("CHECK_KEYPAIR_FUNC_TC001") {
            emit_check_keypair(&mut body, &mut stats, case);
        } else if name.contains("CHECK_PRVKEY_FUNC_TC001") {
            emit_check_prvkey(&mut body, &mut stats, case);
        } else if name.contains("KEYEX_API_TC001") {
            emit_keyex_api(&mut body, &mut stats, case);
        } else {
            // Other API_TC + KEYEX_API_TC002 (NULL-param rejection — Rust's
            // borrow checker forbids NULL refs at compile time, no runtime
            // analog to migrate) + BUFFER_SIZE / NULL_PARAM / FREE / DUP /
            // CMP / GET_* / SET_* / MULTI_OP — all EAL ctx CRUD with no
            // Rust counterpart.
            stats.skipped_api += 1;
        }
    }

    let mut out = String::new();
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo sm9`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV\n\
         // test_suite_sdv_eal_sm9_sign.data + ..._crypt.data + ..._exchange.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\
         #![cfg(all(feature = \"sm9\", feature = \"kat-nonce\"))]\n\n\
         use hitls_crypto::sm9::{Sm9KeyType, Sm9MasterKey};\n\n",
    );
    out.push_str(&body);
    write_footer(&mut out, &stats, cases.len());
    (out, stats)
}
