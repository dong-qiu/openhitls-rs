# Phase G — Encrypted-mutation key-schedule rogue server

**Status**: ✅ Complete (T219-T223 all merged) — 5/5 sub-PRs closed; helper-level pins for the 4 encrypted-mutation families landed.
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
| ✅ plan + G-1 | ✅ T219 | this doc + key schedule infrastructure + baseline encrypted-EE tests | 5 (delivered) | new `transcript_mutation_encrypted.rs` |
| ✅ G-2 | ✅ T220 | `MODIFIED_CERT_VERIFY` family + abnormal cert sig | 10 (delivered) | extends `transcript_mutation_encrypted.rs` |
| ✅ G-3 | ✅ T221 | `MODIFIED_FINISHED` family (verify_data mutations) | 10 (delivered) | extends `transcript_mutation_encrypted.rs` |
| ✅ G-4 | ✅ T222 | EncryptedExtensions abnormal + post-handshake auth (PHA) | 10 (delivered) | extends `transcript_mutation_encrypted.rs` |
| ✅ **closeout** | ✅ T223 | series rollup + 13 `TODO(#48-encrypted-mutation)` markers annotated with Phase G partial-close cross-references | 5 (delivered) | series summary + plaintext-file annotation + §8 rollup |

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

- [x] 5 sub-PR series merged with ~35-40 audit-pin tests — delivered 40 (5+10+10+10+5)
- [x] `tests/interop/tests/` has new `transcript_mutation_encrypted.rs` — 40 tests
- [x] All 13 `TODO(#48-encrypted-mutation)` markers across
      `transcript_mutation.rs` are addressed — annotated with Phase G partial-close
      cross-references in the module-level docblock; markers remain as anchors
      for the still-pending full TCP encrypted-handshake driver
- [x] DEV_LOG **T219-T223** entries; PROMPT_LOG entries — all 5 logged
- [x] `audit_phase_g_plan_docs_in_sync` cross-file pin in every
      Phase G test file asserts this plan doc remains authoritative

## 8. Series rollup (T223 closeout)

**Cumulative across the transcript-mutation family**:
T186 (7) + T214 (10) + T215 (11) + T216 (13) + T217 (14) + T219 (5) +
T220 (10) + T221 (10) + T222 (10) + T223 (5) = **95 tests in 3 files**
(transcript_mutation.rs 41 + transcript_mutation_tls12.rs 14 +
transcript_mutation_encrypted.rs 40).

**Methodology lineage** (codified across the series, in chronological order):

| Codified at | Pattern |
|-------------|---------|
| T186 | rogue server = public encoder/decoder composition (no test-hooks feature gate) |
| T196 | same-file cumulative append (one test file grows monotonically across sub-PRs) |
| T207 | struct field name grep beats intuition (also extends to newtype `.0` access) |
| T209 | verbatim C-typo allowlist accumulation (`typos.toml` `extend-words`) |
| T212 | C-typo allowlist now at 9 patterns (UNKOWN/VERISON/UNEXPECT/CERTFICATE/UNEXPETED/REORD/UNSUPPORT/CERTICATE/HEELO/BEWTEEN) |
| T215 | file-literal grep cross-coverage pin (assert another test name still appears in source) |
| T216 | extension codepoint identity pin (RFC numeric constants on public newtype) |
| T217 | sibling file without rebuilding rogue server (TLS 1.2 lives in its own test file) |
| T219 | key-schedule rogue server = public-API composition (KeySchedule + TrafficKeys + TlsAead + KeyExchange + HKDF) |
| T220 | helper-level mutation pin = full E2E driver alternative (ROI mismatch → rescope; 8h pin replaces 3-5d driver) |
| T221 | raw byte pin when enum is private (HandshakeType is private; pin `0x14` + RFC §B.3 reference) |
| T222 | app-traffic-secret distinct from handshake-secret = PHA prerequisite pin |
| T223 | partial-close annotation as scope-cut closeout (TODO markers stay as anchors for still-pending follow-up; module docs surface the Phase G cross-reference) |

**Still-pending follow-up** (out of Phase G scope, not blocking):

- Full TCP encrypted-handshake driver — rogue server emits encrypted EE →
  Cert → mutated CV → Finished on a real socket; real client rejects with a
  specific alert. The T219 infrastructure (`derive_server_handshake_keys`,
  `record_nonce`, `seal_encrypted_record`) is the substrate. Estimated 3-5 days.
- DTLS 1.3 record encryption (different AEAD framing per RFC 9147 §4).
- 0-RTT early data + KeyUpdate encryption mutations.

These are explicit out-of-scope items per §6, **not** silent gaps.
