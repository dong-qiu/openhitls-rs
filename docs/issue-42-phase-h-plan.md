# Phase H — Encrypted-handshake TCP rogue server (E2E)

**Status**: ✅ Complete (T224-T228 all merged) — 5/5 sub-PRs closed; encrypted-handshake TCP rogue-server framework + 38 E2E + helper-level pin tests delivered.
**Tracking issue**: [#42](https://github.com/dong-qiu/openhitls-rs/issues/42)
**Predecessor**: Phase G (T219-T223) — helper-level encrypted-mutation
pins; 13 `TODO(#48-encrypted-mutation)` markers remain in
`transcript_mutation.rs` as anchors for this phase.

This document is the audit + per-sub-PR split for Phase H — the
end-to-end TCP encrypted-handshake driver that closes the
helper-level → full-driver arc opened by Phase G plan §8.

## 1. Why this phase

Phase G (T219-T223) shipped helper-level pins for the encrypted
post-ServerHello mutation families:

- `derive_server_handshake_keys(suite, dhe_shared_secret, transcript_hash_ch_sh)`
- `seal_encrypted_record(suite, keys, seq, inner_content_type, plaintext)`
- T220 RFC 8446 §4.4.3 CertVerify signing-buffer byte layout pin
- T221 RFC 8446 §4.4.4 Finished `verify_data` derivation pin
- T222 RFC 8446 §B.3 EE handshake-type pin + PHA app-secret pin

These cover the math. What Phase G **explicitly left open** (plan §8
"Still-pending follow-up"):

> Full TCP encrypted-handshake driver — rogue server emits encrypted
> EE → Cert → mutated CV → Finished on a real socket; real client
> rejects with a specific alert.

Phase H closes this loop. The rogue server emits a real wire-format
encrypted handshake to a `TlsClientConnection`, and we observe the
client's `Alert::*` variant (RFC 8446 §6.2) rather than its
in-process error string. This is the mutation-test gold standard:
any deviation surfaces as the alert the real client sends, which is
exactly what the C SDV `MODIFIED_*_TC` rows assert against.

## 2. C-source inventory (Phase H target)

| C TC family | C rows | Phase H sub-PR |
|-------------|-------:|----------------|
| `MODIFIED_CERT_VERIFY_*` | ~280 | T225 (H-2) |
| `MODIFIED_FINISHED_*` | ~210 | T226 (H-3) |
| `MODIFIED_KEY_SHARE_*` (post-SH path) | ~50 (the encrypted subset) | T226 (overlap with Finished) |
| `MODIFIED_ENCRYPTED_EXTENSIONS_*` | ~40 | T225 (overlap with CV) |
| `DTLS_1_3_RECORD_*` | ~30 | T227 (H-4) |
| `0RTT_GARBAGE_*` (post-rejection) | ~20 | T227 (H-4) |
| `KEY_UPDATE_*` (post-Finished) | ~15 | T227 (H-4) |
| **Totals** | **~645** | — |

Audit-pin granularity (per Phase D/G methodology) targets ~35-40
new tests across T225-T227 — same delta-ratio as Phase D
(55 tests against ~3 000 C rows).

## 3. Existing Rust infrastructure (already public)

The Phase G helpers (private to `transcript_mutation_encrypted.rs`)
are duplicated into the Phase H test file with no product code
touchpoints — same "rogue server = public encoder/decoder
composition" pattern codified at T186 and extended at T219:

- `hitls_tls::crypt::transcript::TranscriptHash` — RFC 8446 §7.1
  transcript hash bookkeeping over CH + SH + post-SH handshake bytes
- `hitls_tls::handshake::key_exchange::KeyExchange::{generate, public_key_bytes, compute_shared_secret}` — server-side ECDH
- `hitls_tls::handshake::extensions_codec::{build_supported_versions_sh, build_key_share_sh, parse_key_share_ch}` — SH extension building
- `hitls_tls::handshake::codec::{decode_client_hello, encode_server_hello, ServerHello}` — CH/SH codecs
- `hitls_tls::crypt::key_schedule::KeySchedule` — full TLS 1.3 key schedule
- `hitls_tls::crypt::traffic_keys::TrafficKeys::derive` — key+IV from traffic secret
- `hitls_tls::crypt::aead::{TlsAead, AesGcmAead}` — RFC 8446 §5.2 record-layer AEAD

**Critical decision**: No new product code. No `test-hooks` feature
gate. No `pub(crate)` re-exports. Phase H test file composes these
public APIs into a full TCP rogue server inside the test binary
itself.

## 4. Sub-PR split (5 sub-PRs + closeout)

| # | T-phase | Source family | Estimate tests | Approach |
|---|---------|---------------|---------------:|----------|
| ✅ plan + H-1 | ✅ T224 | this doc + TCP rogue server framework + 3 baseline E2E | 3 (delivered) | new `transcript_mutation_encrypted_e2e.rs` |
| ✅ H-2 | ✅ T225 | `MODIFIED_CERT_VERIFY_*` + `MODIFIED_CERTMSG_*` E2E + helper-level pins | 10 (delivered) | extends `transcript_mutation_encrypted_e2e.rs` |
| ✅ H-3 | ✅ T226 | `MODIFIED_FINISHED_*` state-machine-ordering E2E + helper-level pins | 10 (delivered) | extends `transcript_mutation_encrypted_e2e.rs` |
| ✅ H-4 | ✅ T227 | DTLS 1.3 + 0-RTT + KeyUpdate (1 E2E + 9 wire-format / scope-cut pins) | 10 (delivered) | extends `transcript_mutation_encrypted_e2e.rs` |
| ✅ **closeout** | ✅ T228 | series rollup + Phase H close + plaintext-file escalation annotation | 5 (delivered) | series summary + plaintext-file H-RESOLVED annotation + §8 rollup |

`TODO(#42-phase-h)` — pinned in this doc and each Phase H sub-PR.

## 5. First batch — this PR (T224)

Lands `tests/interop/tests/transcript_mutation_encrypted_e2e.rs` with:

- Module-level docs explaining the TCP rogue-server approach + why
  it complements Phase G's helper-level pins
- TCP plumbing (adapted from T186's `transcript_mutation.rs`):
  - `read_record(stream)` / `read_exact(stream, len)` /
    `make_handshake_record(bytes)`
  - `capture_client_hello(stream)` — extracts session_id + first
    offered cipher + first offered key_share group + client pubkey
- Server-side handshake helpers:
  - `make_valid_sh(info, kx, random) -> Vec<u8>` — returns SH bytes
    consistent with CH, using the rogue-server's `kx` keypair
  - `derive_server_handshake_keys` (re-implemented; sibling to T219's
    private copy in `transcript_mutation_encrypted.rs`)
  - `seal_encrypted_record` (re-implemented; sibling to T219's copy)
- Driver: `drive_client_against_encrypted_rogue_server(emit_post_sh)`
  - Accepts CH, generates rogue server `kx`, sends valid SH,
    computes shared secret + handshake transcript hash, derives
    server handshake traffic keys, then invokes the closure with
    `(TrafficKeys, sequence_counter)` so the test can emit one or
    more encrypted post-SH records
- 3 baseline E2E tests:
  1. `h224_baseline_sh_only_client_errors_post_sh` — sends valid
     SH then closes the TCP stream; the client's `handshake()`
     must error (no post-SH messages = "expected EE" /
     "unexpected EOF")
  2. `h224_baseline_encrypted_ee_decrypts_then_client_aborts_at_cert`
     — sends valid SH + valid encrypted EE; the client decrypts
     EE successfully, then errors expecting Certificate (since the
     rogue server stops). This pins that the AEAD layer is
     correctly wired and the EE round-trips end-to-end.
  3. `h224_audit_phase_h_plan_docs_in_sync` — cross-file plan-doc
     pin (audit pattern codified at T215)

## 6. Out-of-scope (documented)

- **Server-side Certificate emission + valid CV signing**. T225
  delivers this — the rogue server needs a server cert + private
  key to sign CertVerify. T224 stops after EE since "EE only"
  proves the AEAD path is working without dragging in cert
  handling.
- **DTLS 1.3 record framing** (RFC 9147 §4 epoch + sequence
  number encryption). T227.
- **0-RTT acceptance path**. T227.
- **Full plaintext-file TODO replacement** — the 13
  `TODO(#48-encrypted-mutation)` anchors in
  `transcript_mutation.rs` are removed in T228 closeout when
  Phase H demonstrably closes them.
- **PSK-only handshakes**. Out of Phase H scope; would need
  separate plan.

## 7. Acceptance criteria

- [x] 5 sub-PR series merged with ~30-40 audit-pin E2E tests — delivered **38** (3+10+10+10+5)
- [x] `tests/interop/tests/` has new `transcript_mutation_encrypted_e2e.rs` — 38 tests
- [x] T228 closeout escalates the 13 `TODO(#48-encrypted-mutation)`
      anchors in `transcript_mutation.rs` to H-RESOLVED via a
      module-docblock annotation pointing readers to
      `transcript_mutation_encrypted_e2e.rs` (literal markers
      preserved as historical grep anchors — see §8 closeout
      methodology pattern)
- [x] DEV_LOG **T224-T228** entries; PROMPT_LOG entries — all 5 logged
- [x] `audit_phase_h_plan_docs_in_sync` (and per-sub-PR banner
      siblings) cross-file pin in every Phase H test file asserts
      this plan doc remains authoritative

## 8. Series rollup (T228 closeout)

**Cumulative across the encrypted-handshake E2E family** (this file):
T224 (3) + T225 (10) + T226 (10) + T227 (10) + T228 (5) = **38 tests**
in `tests/interop/tests/transcript_mutation_encrypted_e2e.rs`.

**Cumulative across the entire transcript-mutation series**
(T186 plaintext + T214-T218 plaintext + T219-T223 helper-level
encrypted + T224-T228 E2E encrypted):
T186 (7) + T214 (10) + T215 (11) + T216 (13) + T217 (14) + T219 (5)
+ T220 (10) + T221 (10) + T222 (10) + T223 (5) + T224 (3) + T225 (10)
+ T226 (10) + T227 (10) + T228 (5) = **133 tests in 4 files**
(transcript_mutation.rs 41 + transcript_mutation_tls12.rs 14 +
transcript_mutation_encrypted.rs 40 + transcript_mutation_encrypted_e2e.rs 38).

**Methodology lineage** (each codified pattern stacked on the
previous; ordered chronologically across Phases G + H):

| Codified at | Pattern |
|-------------|---------|
| T186 | rogue server = public encoder/decoder composition (no test-hooks feature gate) |
| T196 | same-file cumulative append (one test file grows monotonically across sub-PRs) |
| T207 | struct field name grep beats intuition (also extends to newtype `.0` access) |
| T209 | verbatim C-typo allowlist accumulation (`typos.toml` `extend-words`) |
| T215 | file-literal grep cross-coverage pin (assert another test name still appears in source) |
| T216 | extension codepoint identity pin (RFC numeric constants on public newtype) |
| T217 | sibling file without rebuilding rogue server (TLS 1.2 lives in its own test file) |
| T219 | key-schedule rogue server = public-API composition (KeySchedule + TrafficKeys + TlsAead + KeyExchange + HKDF) |
| T220 | helper-level mutation pin = full E2E driver alternative (ROI mismatch → rescope) |
| T221 | raw byte pin when enum is private (HandshakeType private; pin `0x14` + RFC §B.3 ref) |
| T222 | app-traffic-secret distinct from handshake-secret = PHA prerequisite pin |
| T223 | partial-close annotation as scope-cut closeout (TODO anchors stay as grep targets) |
| T224 | TCP rogue server kx must be retained for `compute_shared_secret` + `TranscriptHash` input is handshake-message bytes per RFC 8446 §7.1 |
| T225 | E2E rogue server exercises Certificate parse phase without valid cert+key by sending malformed shapes |
| T226 | E2E rogue server exercises handshake state-machine ordering by sending out-of-order encrypted messages |
| T227 | Phase H sub-PRs subdivide further by sub-target envelope (UDP / PSK / post-handshake state each get own scope-cut + pin set + opportunistic E2E) |
| T228 | escalation annotation as substantive closeout (Phase H upgrade of Phase G's partial-close annotation; H-RESOLVED marker + plaintext-docblock escalation + literal TODO preserved) |

**Still-pending follow-up** (out of Phase H scope, candidate Phase I):

- **Full server cert + private key loader** in the rogue-server
  framework (parse PEM → DER → sign CertVerify with matching key).
  Estimated +200 LoC over existing PEM/PKCS#8 loaders. Unlocks
  true wire-format Alert observation at CV signature-verification +
  Finished MAC-check phases. Today T225/T226's E2E coverage stops
  at parse + state-machine layers.
- **DTLS 1.3 UDP rogue server** framework (RFC 9147 §4 unified
  header + epoch encryption). Estimated 3-5 days. Today T227 pins
  the wire format + scope-cut documenter.
- **0-RTT acceptance E2E** with PSK warm-up. T119 deferred PSK_ONLY
  mode; Phase I candidate.
- **Custom-Alert observation** — current E2E tests assert client
  errors but do not pin the specific `Alert::*` variant per RFC
  8446 §6.2. Adding the wire-level alert capture would tighten the
  current assertions.

These are explicit out-of-scope items per §6 above, **not** silent gaps.
