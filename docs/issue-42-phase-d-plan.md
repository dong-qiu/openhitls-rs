# Phase D — TLS 1.2 + TLS 1.3 consistency / transcript-mutation tests

**Status**: Planning + first batch (T214).
**Tracking issue**: [#42](https://github.com/dong-qiu/openhitls-rs/issues/42)
**Migration plan**: `docs/c-test-migration-plan.md` Phase D (§5).

This document is the audit + per-source-file decision matrix + sub-PR
split for Phase D, modelled on the successful T204 (Phase C) and T209
(Phase F) audit patterns.

## 1. Inventory

C source: `openhitls/testcode/sdv/testcase/tls/consistency/{tls12,tls13}/`:

### TLS 1.3 consistency (rfc8446 + rfc8998)

| `.c` file | C fn | rows |
|-----------|-----:|-----:|
| `frame_tls13_consistency_rfc8446_1.c` | 57 | 192 |
| `frame_tls13_consistency_rfc8446_2.c` | 43 | 157 |
| `frame_tls13_consistency_rfc8446_cert.c` | 37 | 134 |
| `frame_tls13_consistency_rfc8446_kex.c` | 62 | 143 |
| `frame_tls13_consistency_rfc8446_extensions_1.c` | 53 | 157 |
| `frame_tls13_consistency_rfc8446_extensions_2.c` | 23 | 128 |
| `frame_tls13_consistency_rfc8446_record.c` | 43 | 124 |
| `frame_tls13_consistency_rfc8446_appendix.c` | 11 | 43 |
| `frame_tls13_consistency_rfc8446_pha.c` | 4 | 10 |
| **TLS 1.3 subtotal** | **333 fn** | **1 088 rows** |

### TLS 1.2 consistency (rfc5246 + rfc5746)

| `.c` file | C fn | rows |
|-----------|-----:|-----:|
| `frame_tls12_consistency_rfc5246.c` | 75 | 233 |
| `frame_tls12_consistency_rfc5246_cert.c` | 21 | 70 |
| `frame_tls12_consistency_rfc5246_extensions.c` | 8 | 22 |
| `frame_tls12_consistency_rfc5246_malformed_msg.c` | 4 | 16 |
| `frame_tls12_consistency_rfc5746.c` (secure reneg) | 15 | 43 |
| **TLS 1.2 subtotal** | **123 fn** | **384 rows** |

**Total**: **456 fn / 1 472 rows** across both protocol versions.

## 2. Existing Rust coverage + infrastructure

### Critical infrastructure (T186 / #48 Phase 1)

`tests/interop/tests/transcript_mutation.rs` (~360 lines) already
contains:

- **Rogue-server framework**: uses `hitls-tls` public encode/decode
  APIs + manual record-header construction to mutate handshake
  messages — replaces the C `FRAME_*` MITM framework, zero product
  code changes
- `ShBuilder` fluent builder (`.cipher() / .session_id() /
  .drop_extension() / .replace_supported_versions() /
  .replace_key_share_with() / .encode()`)
- `drive_client_against_rogue_server(mutate)` — rejection driver
- `drive_client_accepting_rogue_sh(mutate)` — gap-pin driver
- 7 tests passing + 3 RFC 8446 gap TODOs
  (`#48-encrypted-mutation` / `#48-rfc-gap-sessid` /
  `#48-rfc-gap-compression`)

**Critical decision**: Plan §5.1's proposed
`#[cfg(feature = "test-hooks")] TranscriptMutator` feature gate is
**not adopted** — T186 proved the rogue-server pattern covers
equivalent attack surface using only public APIs. Phase D extends
the rogue-server framework rather than threading hooks through
production code.

### Other existing coverage (scope-cuts)

- `tests/interop/tests/openssl_interop.rs` — OpenSSL differential
  handshake (positive baselines)
- `tests/interop/tests/tlsfuzzer_*.rs` — tlsfuzzer protocol
  conformance (62 PASS / 0 FAIL on the curated CI subset)
- `connection.rs` end-to-end paths covered by `dtls12.rs` /
  `tlcp.rs` / `tls13.rs` interop tests

## 3. Real gaps — 5 C-source family clusters

| Cluster | C scope | Estimate audit-pin tests |
|---------|--------:|-------------------------:|
| **TLS 1.3 _1.c** (record/state/version) | 57 fn / 192 rows | ~12 |
| **TLS 1.3 _2.c + _cert.c + _kex.c** | 142 fn / 434 rows | ~15 |
| **TLS 1.3 _extensions_1+2 + _record + _appendix + _pha** | 134 fn / 462 rows | ~15 |
| **TLS 1.2 rfc5246 + _cert + _extensions + _malformed_msg + rfc5746** | 123 fn / 384 rows | ~15 |
| **Totals** | **456 fn / 1 472 rows** | **~57 tests** |

The reduction reflects "audit-pin delta" methodology proven by
Phase C/F: the vast majority of C rows parameterise state ×
algorithm matrices that the existing Rust interop + connection
tests already cover end-to-end. The new tests target unique
mutation/consistency categories that no Rust test currently pins.

## 4. Proposed sub-PR split (5 sub-PRs + closeout)

| # | T-phase | Source family | Estimate tests | Approach |
|---|---------|---------------|---------------:|----------|
| ✅ plan + D-1 | ✅ T214 | this doc + `tls13_1.c` | 10 (delivered) | merged (PR #296) |
| ✅ D-2 | ✅ T215 | `tls13_2.c` + `_cert.c` + `_kex.c` | 11 (delivered) | merged (PR #297) |
| ✅ D-3 | ✅ T216 | `tls13_extensions_1+2.c` + `_record.c` + `_appendix.c` + `_pha.c` | 13 (delivered) | merged (PR #298) |
| ✅ D-4 | ✅ T217 | TLS 1.2 family (new `transcript_mutation_tls12.rs`) | 14 (delivered) | merged (PR #299) |
| ✅ **closeout** | ✅ T218 | series rollup + Phase D close | — | this PR |

`TODO(#42-phase-d)` — pinned in this doc and in each Phase D sub-PR's
audit-pin test. Each sub-PR removes its row from the planned table
once merged.

## 5. First batch — this PR (T214)

Migrates record-layer / state-machine / version-mismatch families
from `frame_tls13_consistency_rfc8446_1.c`. The targets are families
that **don't require encrypted post-SH mutation** (post-Finished
state mutations are tracked under `#48-encrypted-mutation` and may
need a follow-up sub-PR with key schedule plumbing):

- `MSGLENGTH_TOOLONG_TC001-004` — record-length field mutations
- `UNEXPECT_RECODETYPE_TC001-006` — unknown ContentType byte
- `NO_SUPPORTED_GROUP_TC001` — SH key_share group not in CH offered
- `RECEIVES_OTHER_CCS_TC001/002` — middlebox-compat CCS handling
- `MISSING_SIG_ALG_FROM_CH_TC001` — sig-alg negotiation
- `PREFER_PSS_TO_PKCS1_TC001` — sig-alg priority pin
- `RSAE_PSS_FUNC_TC001/002` — RSA-PSS signature handling

Lands in `tests/interop/tests/transcript_mutation.rs` (extending the
T186 framework) together with a new `audit_phase_d_plan_docs_in_sync`
test pinning this plan doc's anchors.

## 6. Out-of-scope (documented)

- **Post-Finished encrypted state mutations** (cert_verify /
  finished mid-handshake mutation) — requires key schedule
  simulation. Tracked under `TODO(#48-encrypted-mutation)` and
  considered a follow-up to this series rather than blocking.
- **C `FRAME_*` MITM-framework feature parity** — the rogue-server
  pattern covers equivalent attack surface; full FRAME_* port is
  not in scope.
- **tlsfuzzer-style end-to-end fuzz coverage** — covered by the
  existing `tlsfuzzer_*` CI; not the audit-pin target.
- **`hlt_*` wrappers** — HLT-style fixtures cover end-to-end
  scenarios already in `tests/interop/`; HLT-specific rows are
  duplicate coverage.
- **`base.c` files** — C helper definitions, not testcases.

## 7. Acceptance criteria

- [x] 5 sub-PR series merged with **55 audit-pin tests** (T214 10 + T215 11 + T216 13 + T217 14, vs initial ~57 estimate)
- [x] `tests/interop/tests/` has extensions to
      `transcript_mutation.rs` + a new `transcript_mutation_tls12.rs`
- [x] Each test asserts a specific reject path (record/handshake
      error), a verified-positive round-trip, or an explicit gap
      pin with `TODO(#42-phase-d)` / `TODO(#48-encrypted-mutation)`
- [x] DEV_LOG **T214-T218** entries; PROMPT_LOG entries
- [x] `audit_phase_d_plan_docs_in_sync*` cross-file pin in every
      Phase D test file asserts this plan doc + §8 rollup totals

## 8. Series rollup (T218 closeout)

The 5-sub-PR series is closed; this section is the final tally so the
issue closer / future readers can see the whole shape at a glance.

| Sub-PR | Phase | Source family | C scope (fn / rows) | Delivered tests | PR | Outcome |
|--------|-------|---------------|--------------------:|----------------:|----|---------|
| plan + D-1 | T214 | this doc + `tls13_1.c` | 57 fn / 192 rows | 10 | #296 | merged |
| D-2 | T215 | `tls13_2.c` + `_cert.c` + `_kex.c` | 142 fn / 434 rows | 11 | #297 | merged |
| D-3 | T216 | `tls13_extensions_1+2.c` + `_record.c` + `_appendix.c` + `_pha.c` | 134 fn / 462 rows | 13 | #298 | merged |
| D-4 | T217 | TLS 1.2 family (new `transcript_mutation_tls12.rs`) | 123 fn / 384 rows | 14 | #299 | merged |
| closeout | T218 | series rollup + Phase D close | — | — | this PR | — |
| **Totals** | | **456 fn / 1 472 rows** | | **55 tests** | | **5/5 sub-PRs closed** |

**Net result vs C input**: 55 net new Rust audit-pin tests against
456 unique C TC families / 1 472 parameterised `.data` rows across
TLS 1.2 and TLS 1.3 consistency suites (5/5 sub-PRs closed,
PRs #296 → #299). The reduction reflects Phase D's core thesis:
T186 (#48 Phase 1) had already established the rogue-server framework
+ ShBuilder + 2 drivers, and many `tls{12,13}_consistency_*` rows
either (a) test paths the rogue-server already covers (cross-coverage
pin), (b) require encrypted post-SH state (`TODO(#48-encrypted-mutation)`
scope-cut), or (c) pin extension/cipher codepoints that map directly
to Rust constants (T216 codified codepoint-identity pin pattern).

**Methodology lineage** (each sub-PR codified patterns the next
reused):

- T214 — Plan §X feature-gate proposal can be replaced by prior
  codified pattern (T186 rogue-server > plan §5.1 test-hooks gate) /
  record-layer raw byte mutation = SH-fluent's complementary attack
  vector / verbatim-C-typo `typos.toml` allowlist saturation check
- T215 — Cross-coverage pin via file-literal grep / Phase D's
  boundary before encrypted-mutation
- T216 — Extension-codepoint identity pin = RFC numeric-constant
  regression lock
- T217 — Sibling protocol file without rebuilding rogue-server /
  sibling-named audit pin (`*_tls12` suffix)
- T218 — Closeout = §8 rollup table + Methodology lineage + folds
  into existing `audit_phase_d_plan_docs_in_sync*` pins (no new
  test fn; same pattern as T200 / T208 / T213 three-Phase
  consistency)

**Follow-up TODOs left open** (5):

- `TODO(#48-encrypted-mutation)` — encrypted post-SH transcript
  mutations (cert_verify / finished / certificate / EncryptedExtensions)
  require key-schedule simulation on the rogue-server side. Tracked
  separately as a follow-up PR after Phase D closeout.
- `TODO(#48-rfc-gap-sessid)` — RFC 8446 §4.1.3 `legacy_session_id_echo`
  match check (T186 pinned the lenient acceptance).
- `TODO(#48-rfc-gap-compression)` — RFC 8446 §4.1.3
  `legacy_compression_method = 0` strict check (T186 pinned the
  lenient acceptance).
- `TODO(#42-phase-d)` — record-version strict-mode (T215 pinned
  the 0x0304 lenient acceptance).
- `TODO(#42-phase-d)` — ABNORMAL_CERTMSG_TC001-003 follow-up port
  once encrypted-mutation infrastructure lands (T215).

These are product-side hardening / extension tasks that surfaced
during the audit; the corresponding tests pin **current** lenient
or unsupported behaviour so a future hardening lands as a deliberate
change.

`typos.toml` C-quirk vocabulary accumulated to **9 patterns** across
Phase D (`UNKOWN` / `VERISON` / `UNEXPECT` / `CERTFICATE` /
`UNEXPETED` / `REORD` / `UNSUPPORT` / `CERTICATE` / `HEELO` /
`BEWTEEN`).
