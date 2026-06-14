# Phase G — Encrypted-mutation key-schedule rogue server

**Status**: Planning + first batch (T219).
**Tracking issue**: [#42](https://github.com/dong-qiu/openhitls-rs/issues/42)
**Predecessor**: Phase D's `TODO(#48-encrypted-mutation)` markers
(13 instances).

This document is the audit + per-sub-PR split for Phase G — the
final infrastructure unlock that **Phase D explicitly deferred**.

## 1. Why this phase

Phase D (T214-T218) shipped 55 audit-pin tests against
`tls/consistency/tls{12,13}` and noted in 13 places that
**encrypted post-SH messages** (Certificate / CertVerify / Finished /
EncryptedExtensions) require simulating the full TLS 1.3 key
schedule on the rogue-server side. Without that, the rogue-server
framework can only mutate plaintext records (record header +
ServerHello fields), which is what T186 + T214-T217 cover.

Phase G **closes the encrypted-mutation gap** by building the key
schedule + AEAD infrastructure inside the rogue-server framework,
then porting the C `MODIFIED_*_TC` families that depend on
encrypted state.

## 2. C-source inventory

Encrypted-mutation TCs live in:

- `tls/consistency/tls13/test_suite_sdv_frame_tls13_consistency_rfc8446_cert.c`
  (37 fn — CertVerify, Certificate, abnormal cert sig)
- `tls/consistency/tls13/test_suite_sdv_frame_tls13_consistency_rfc8446_1.c`
  (rows like `RECVAPP_AFTER_CERT_FUNC_TC001` that need post-Finished
  state)
- `tls/consistency/tls13/test_suite_sdv_frame_tls13_consistency_rfc8446_pha.c`
  (4 fn / 10 rows — post-handshake authentication)
- `tls/consistency/tls13/test_suite_sdv_frame_tls13_consistency_rfc8446_extensions_2.c`
  (CERTICATE_VERIFY_FAIL + EncryptedExtensions abnormal cases)

**Estimated encrypted-mutation target**: ~50-60 unique TC families.

## 3. Existing Rust infrastructure (already public)

- `hitls_tls::crypt::key_schedule::KeySchedule` — full TLS 1.3 key
  schedule (RFC 8446 §7.1):
  - `new(params)` / `derive_early_secret` /
    `derive_handshake_secret(dhe_shared_secret)` /
    `derive_handshake_traffic_secrets(transcript_hash)`
  - `compute_finished_verify_data(base_key, transcript_hash)` /
    `derive_finished_key(base_key)`
- `hitls_tls::crypt::traffic_keys::TrafficKeys::derive(params,
  traffic_secret)` — derives AEAD key + IV from traffic secret
- `hitls_tls::crypt::aead::TlsAead` trait + `AesGcmAead` impl —
  RFC 8446 §5.2 record-layer AEAD
- `hitls_tls::handshake::key_exchange::KeyExchange::compute_shared_secret(peer_public)`
  — ECDH shared secret derivation
- `hitls_tls::crypt::hkdf::{hkdf_extract, hkdf_expand_label,
  derive_secret}` — pure HKDF helpers

**Critical decision**: No new product code is required. Phase G
composes existing public APIs into a key-schedule rogue server
inside the test file, just as T186 composed
`decode_client_hello` + `encode_server_hello` + `KeyExchange` for
the plaintext rogue server.

## 4. Sub-PR split (5 sub-PRs + closeout)

| # | T-phase | Source family | Estimate tests | Approach |
|---|---------|---------------|---------------:|----------|
| ✅ plan + G-1 | ✅ T219 | this doc + key schedule infrastructure + baseline encrypted-EE tests | ~5 (this PR) | new `transcript_mutation_encrypted.rs` |
| G-2 | T220 | `MODIFIED_CERT_VERIFY` family + abnormal cert sig | ~10 | extends `transcript_mutation_encrypted.rs` |
| G-3 | T221 | `MODIFIED_FINISHED` family (verify_data mutations) | ~10 | extends `transcript_mutation_encrypted.rs` |
| G-4 | T222 | EncryptedExtensions abnormal + post-handshake auth (PHA) | ~10 | extends `transcript_mutation_encrypted.rs` |
| **closeout** | T223 | series rollup + 13 `TODO(#48-encrypted-mutation)` markers closed | — | series summary |

`TODO(#42-phase-g)` — pinned in this doc and in each Phase G
sub-PR's audit pin. Each sub-PR removes its row from the planned
table once merged.

## 5. First batch — this PR (T219)

Lands `tests/interop/tests/transcript_mutation_encrypted.rs` with:

- Module-level docs explaining the encrypted-rogue-server approach
- Key-schedule helper functions composing existing
  `KeySchedule` + `TrafficKeys` + `TlsAead` public APIs
- Transcript-hash bookkeeping helpers (CH + SH running hash)
- `encrypt_handshake_record(plaintext, server_handshake_keys, seq)` —
  produces TLS 1.3 application_data record carrying encrypted
  handshake message
- 5 baseline tests:
  1. `g_key_schedule_derives_distinct_client_server_secrets` —
     HKDF-Extract/Expand chain produces RFC 8446 §7.1 outputs
  2. `g_encrypted_extensions_round_trip_baseline` — emit valid
     encrypted EE record; client accepts (handshake continues to
     CertVerify failure, the assertion is "didn't fail at EE
     decryption")
  3. `g_encrypted_extensions_tampered_tag_byte_rejected` — flip
     last AEAD tag byte → client rejects with `decrypt_error`
  4. `g_encrypted_extensions_tampered_ciphertext_byte_rejected` —
     flip middle ciphertext byte → AEAD decrypt fail
  5. `g_audit_phase_g_plan_docs_in_sync` — cross-file plan-doc pin

## 6. Out-of-scope (documented)

- **Full Finished MAC computation against transcript hash up to
  certificate** — T221's territory. T219 derives the keys but
  doesn't emit a Finished record.
- **Certificate / CertVerify mid-handshake mutation** — T220/T221.
- **DTLS 1.3 record encryption** — Rust DTLS 1.3 uses a different
  AEAD framing per RFC 9147 §4. Out of scope for Phase G; track as
  Phase H follow-up if needed.
- **0-RTT early data encryption** — RFC 8446 §4.2.10; out of scope.
- **Key update encryption** — RFC 8446 §4.6.3; out of scope.

## 7. Acceptance criteria

- [ ] 5 sub-PR series merged with ~35-40 audit-pin tests
- [ ] `tests/interop/tests/` has new
      `transcript_mutation_encrypted.rs`
- [ ] All 13 `TODO(#48-encrypted-mutation)` markers across
      `transcript_mutation.rs` are addressed (either resolved by
      a Phase G test or explicitly downgraded to a smaller follow-up)
- [ ] DEV_LOG **T219-T223** entries; PROMPT_LOG entries
- [ ] `audit_phase_g_plan_docs_in_sync` cross-file pin in every
      Phase G test file asserts this plan doc remains authoritative
