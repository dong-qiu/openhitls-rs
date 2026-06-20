# TLS / DTLS / TLCP Test-Coverage Contract

**Status: living document.** Makes the TLS-family test strategy *explicit and
auditable*, so the deliberate sampling posture is not misread as exhaustive
1:1 C→Rust migration.

## 1. The dual-track decision (why TLS is sampled, not 1:1)

The C→Rust test migration follows a **pragmatic dual-track** policy (decided
2026-06-15, recorded in `docs/c-test-na-list.md` and the Phase plans):

| Track | Applies to | Posture |
|---|---|---|
| **Byte-exact KAT** | crypto / bignum / codecs / key formats | Full 1:1 against independent C/NIST/RFC vectors (can't false-pass). |
| **Audit-pin + E2E + fuzzer sampling** | **TLS / DTLS / TLCP / DTLCP state machines** | *Sampled*, not row-for-row. |

**Rationale.** The C SDV `tls/` suite (~74 `.data` files, ~3,172 rows across
`ciphersuite` + `consistency/{tls13,tls12,tlcp,dtls12,dtlcp}`) is overwhelmingly
a **parameterised matrix**: `(cipher suite) × (handshake state) × (extension)`.
Migrating it row-for-row would re-encode combinations the Rust integration +
E2E + fuzzer layers already exercise end-to-end. Instead we pin the **delta** —
the specific RFC semantics a C row asserts that the Rust suites did not already
cover — and lean on a protocol fuzzer for breadth. This is a coverage *strategy*
choice, **not** an omission.

## 2. The layers, and exactly what each guarantees

### 2.1 Protocol-conformance fuzzer — `tlsfuzzer` (breadth)
- **What**: the upstream `tlsfuzzer` suite (pinned commits) driven against live
  `s-server`/`s-client` listeners; CI workflow `.github/workflows/tlsfuzzer.yml`;
  harness in `tests/tlsfuzzer/` (`run.sh`, per-listener `xfail*` dirs).
- **Covers**: RFC 8446 (TLS 1.3) + RFC 5246 (TLS 1.2) wire conformance —
  malformed records, alert mapping (RFC 8446 §6), CCS rules (§5), Finished
  framing (§4.4.4), KeyUpdate, sig_algs, cert-matrix, mTLS, external PSK,
  0-RTT-reject tolerance, record limits.
- **Scale**: a curated, CI-sampled set (~46 scripts across RSA/ECDSA-P256/P384/
  P521/Ed25519 cert listeners + mTLS 1.3/1.2 + PSK), with per-script `XFAIL`
  bookkeeping (0 FAIL / 0 XPASS at CI sampling). Monthly full `-n 9999` sweep
  (86 scripts × 13 listeners). **This is the breadth layer** — it is the closest
  analogue to the C parameterised matrices and is where "did we handle this wire
  edge case" is answered. See `docs/tlsfuzzer.md`.

### 2.2 Rogue-server / transcript-mutation E2E — wire-`Alert::*` (adversarial depth)
- **Files**: `tests/interop/tests/transcript_mutation*.rs`
  (`transcript_mutation` 41, `_encrypted` 41, `_encrypted_e2e` 49,
  `_tls12` 14 = **145 tests**).
- **Covers**: the C `MODIFIED_*` gold standard — a rogue server emits a
  mutated EE / Certificate / CertificateVerify / Finished, and a real
  `TlsClientConnection` is asserted to emit the **specific** fatal `Alert`
  variant on the wire (`bad_record_mac` / `decrypt_error(51)` / `decode_error`),
  decrypted at the record layer. This is the "client rejects with the *right*
  alert", not merely "client errored somehow".

### 2.3 Consistency / interface audit-pins (the migrated delta)
- **Files**: `crates/hitls-tls/tests/migrated_{phase_e,phase_f}_audit_pins.rs`
  (52 + 52), `migrated_interface_tlcp_audit.rs` (67), `migrated_kdf_tls12.rs`
  (6); `tests/interop/tests/{tlcp,dtls12,dtlcp}_consistency.rs` (22 + 23 + 10),
  `dtls_resilience.rs` (8), `dtls13_record_wire.rs` (8).
- **Covers**: the **delta** semantics from the C `frame_*` / `*_consistency`
  suites — record-format wire pins (RFC 9147 §4 DTLS 1.3), TLCP/DTLS state
  assertions, TLS 1.2 PRF KAT — that the broader suites did not already pin.
  Mapped per-row in `docs/issue-42-phase-{e,f}-plan.md` + `docs/tlcp-test-mapping.md`.

### 2.4 Integration / interop (end-to-end correctness)
- **Files**: `tests/interop/tests/{tls13,tls12,tlcp,dtls12,openssl_interop,
  tls13_callbacks}.rs` (32 + 34 + … incl. OpenSSL differential).
- **Covers**: full handshakes (sync + async), resumption, mTLS, OpenSSL
  interop — the "does a real connection complete and agree" layer.

### 2.5 Property + targeted unit
- `proptest!` in `crates/hitls-tls/src/record/anti_replay.rs` +
  `handshake/codec.rs` (state-machine / parser robustness); per-module unit
  tests throughout `crates/hitls-tls/src`.

## 3. Known coverage (measured 2026-06-19)

`hitls-tls` line coverage = **90.1%**. The uncovered ~10% is structural and
concentrated in **lower-risk glue / async paths**, not the core handshake:

| File | Line% | Note |
|---|--:|---|
| `connection12_async.rs` | **75.7%** | _(was 59.7%; closed by T295)_ async TLS 1.2 cipher matrix + multi-record fragmentation + renegotiation roundtrip now covered. |
| `connection12/server.rs` | 68.0%+ | TLS 1.2 server state-machine branches. T296 added RFC 5705 EKM success (both PRF arms) + post-handshake `read()` buffering (lib-only +9 lines). Remaining gaps = deep `read()` error returns (need a raw-record-injection harness — keyed `RecordLayer` is a private field). |
| `connection12/client.rs` | 70.6%+ | TLS 1.2 client state-machine branches. T296 added EKM success + partial/multi-record `read()` (lib-only +14 lines). |
| `connection/server.rs` | 75.0% | TLS 1.3 server branches. |
| `crypt/mod.rs` | 79.9% | cipher-suite dispatch arms not all exercised. |

(CLI `s_client`/`s_server`, which *drive* TLS, are covered by subprocess
integration tests and so do not show in instrumented line coverage.)

## 4. The contract (what a reader may rely on)

1. **TLS wire conformance** (alerts, record rules, malformed inputs) → answered
   by **tlsfuzzer** (§2.1), not by 1:1 C row migration.
2. **Adversarial server behaviour** (mutated handshake → specific alert) →
   pinned by **transcript-mutation E2E** (§2.2).
3. **C `frame_*` / `*_consistency` delta semantics** → pinned by the
   **audit-pin** files (§2.3), mapped per-row in the Phase E/F docs.
4. **Anything labelled "audit-pin" or "sampled" is *intentionally* not row-for-row.**
   Absence of a per-C-row Rust test for a TLS combination is **by design** when
   that combination is exercised by §2.1/§2.4 — it is not a migration gap.
5. **Genuine gaps** (vs. design choices) are only the measured §3 items —
   these are coverage to *grow*, tracked here. (The async-TLS-1.2 gap that
   topped this list was closed by T295: 59.7% → 75.7%; the TLS 1.2
   state-machine branch files are the next-lowest.)

## 5. Related documents
- `docs/c-test-na-list.md` — the N/A exemption list + the dual-track rationale.
- `docs/tlsfuzzer.md` — tlsfuzzer harness + contributor walkthrough.
- `docs/issue-42-phase-e-plan.md`, `docs/issue-42-phase-f-plan.md` — per-row
  audit-pin mapping (TLCP / DTLS consistency).
- `docs/tlcp-test-mapping.md` — TLCP C-test → Rust mapping.
- `docs/dtls-s-server-plan.md` — DTLS server harness plan.
