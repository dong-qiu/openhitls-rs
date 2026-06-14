# Phase F — TLCP + DTLS 1.2 consistency tests migration plan

**Status**: Planning + first batch (T209).
**Tracking issue**: [#42](https://github.com/dong-qiu/openhitls-rs/issues/42)
**Migration plan**: `docs/c-test-migration-plan.md` Phase F (§7).

This document is the audit + per-source-file decision matrix + sub-PR split
for Phase F, modelled on the successful T204 (Phase C) and T195 (#46) audit
patterns.

## 1. Inventory

C source: `openhitls/testcode/sdv/testcase/tls/consistency/{tlcp,dtls12}/`:

### TLCP consistency (3 frame files + 1 hlt + 1 base)

| `.c` file | C fn | rows |
|-----------|-----:|-----:|
| `frame_tlcp_consistency_1.c` | 34 | 119 |
| `frame_tlcp_consistency_2.c` | 6 | 16 |
| `frame_tlcp_consistency_3.c` | 29 | 98 |
| `frame_tlcp_consistency.base.c` (helpers) | 0 | — |
| `hlt_tlcp_consistency.c` (HLT wrappers) | 0 | 49 |
| **TLCP subtotal** | **69 fn** | **282 rows** |

### DTLS 1.2 consistency (1 frame + 1 callback + 1 hlt + 1 base)

| `.c` file | C fn | rows |
|-----------|-----:|-----:|
| `frame_dtls12_consistency.c` | 54 | 173 |
| `frame_dtls12_consistency.base.c` (helpers) | 0 | — |
| `dtls_callback.c` | 0 | 46 |
| `hlt_dtls12_consistency.c` (HLT wrappers) | 0 | 10 |
| **DTLS 1.2 subtotal** | **54 fn** | **229 rows** |

**Total**: **123 fn / 511 rows** across both protocols.

## 2. Existing Rust coverage

### TLCP
- `tests/interop/tests/tlcp.rs` (11 happy-path tests: ECDHE/ECC + GCM/CBC)
- `crates/hitls-tls/src/connection_tlcp.rs::tests` (unit-level)
- No `tlcp_consistency.rs` file yet (this series creates it)

### DTLS 1.2
- `tests/interop/tests/dtls12.rs` (~10 happy-path)
- `tests/interop/tests/dtls_resilience.rs` (8 resilience tests T201 template)
- `crates/hitls-tls/src/connection_dtls12.rs::tests` (unit-level)
- No `dtls12_consistency.rs` file yet

### Shared template (proven by T201)
- `tests/interop/tests/dtlcp_consistency.rs` (10 tests, ports the **12** unique
  DTLCP TC families using `dtlcp_handshake_in_memory(...)` + crafted record
  delivery patterns)

## 3. Sub-PR split (5 sub-PRs + closeout)

Each sub-PR pulls ~10-15 tests of audit-pin coverage; reduction vs raw C
count reflects "fixture-driven" methodology (T204 codified) plus reuse of
existing happy-path coverage.

| # | T-phase | Source family | Estimate tests | Approach |
|---|---------|---------------|---------------:|----------|
| ✅ plan + F-1 | ✅ T209 | this doc + `frame_tlcp_consistency_1.c` (RFC-layer rejection + record-layer) | ~12 (this PR) | merged (this PR) |
| F-2 | T210 | `frame_tlcp_consistency_2.c` + `_3.c` (cert / resume / close_notify) | ~12 | extends `tlcp_consistency.rs` |
| F-3 | T211 | `frame_dtls12_consistency.c` first batch (anti-replay / cookie / record) | ~12 | new `dtls12_consistency.rs` (sibling to `dtls_resilience.rs`) |
| F-4 | T212 | `frame_dtls12_consistency.c` remainder (handshake reassembly / epoch / disorder) | ~12 | extends `dtls12_consistency.rs` |
| **closeout** | T213 | series rollup + Phase F close | — | series summary |

`TODO(#42-phase-f)` — pinned in this doc and in each Phase F sub-PR's
`*_consistency.rs` audit pin. Each sub-PR removes its row from the planned
table once merged.

## 4. First batch — this PR (T209)

Migrates the **record-layer + handshake-validation** families from
`frame_tlcp_consistency_1.c` (the largest of the 3 TLCP frame files):

- `CIPHERTEXT_TOOLONG_TC001` — record-size enforcement
- `MSGLENGTH_TOOLONG_TC001-004` — handshake-msg length sanity
- `NONZERO_MESSAGELEN_TC001` — non-zero length in message-with-empty-body
- `SEQ_NUM_TC001/002` — sequence-number gap handling
- `SERVER_TLS_ALL_TC001-003` — TLS version negotiation rejection (TLCP
  servers must reject TLS clients)
- `UNEXPECT_HANDSHAKEMSG_TC001-012` — out-of-state handshake messages
- `UNEXPECT_RECORDTYPE_TC001-007` — non-handshake records during handshake

Lands in `tests/interop/tests/tlcp_consistency.rs` (new file) together with
an `audit_plan_docs_in_sync` test that pins this plan doc's anchors.

## 5. Out-of-scope (documented)

- **TLCP happy-path handshake variants** (ECDHE/ECC + GCM/CBC) — already
  covered by `tests/interop/tests/tlcp.rs` (11 tests).
- **DTLS 1.2 anti-replay window** — already covered by `dtls_resilience.rs`
  (T201 template) + `connection_dtls12::tests`.
- **`hlt_*` wrappers** — HLT-style fixtures that drive real handshakes; the
  Rust port covers their semantics via `tests/interop/*.rs` end-to-end suites.
- **`dtls_callback.c`** — C BSL callback registration shim; the Rust port
  passes callbacks via `TlsConfig::builder()` setters, so this is a
  builder-pattern change with no test-side analogue.
- **`base.c` files** — C helper definitions; not testcases.

## 6. Acceptance criteria

- [ ] 5 sub-PR series merged with ~48 audit-pin tests
- [ ] `tests/interop/tests/` has new `tlcp_consistency.rs` +
      `dtls12_consistency.rs` files
- [ ] Each test asserts a specific reject path (record/handshake-layer
      error) or a verified-positive round-trip
- [ ] DEV_LOG **T209-T213** entries; PROMPT_LOG entries
- [ ] `audit_plan_docs_in_sync` cross-file pin in every Phase F test file
      asserts this plan doc remains authoritative
