# Phase E — `interface_tlcp` audit-pin closure

**Status**: Planning + first batch (T115).
**Tracking issue**: [#42](https://github.com/dong-qiu/openhitls-rs/issues/42)
**Migration plan**: `docs/c-test-migration-plan.md` Phase E (§6).
**Methodology**: Phase B / F-followup-codified audit-pin sample
(T112 + T116 lineage).

This document is the audit + per-sub-PR split for Phase E — the
last open phase in the c-test-migration-plan after Phase F closeout
(T249 Full C→Rust test migration parity milestone for Phase A-D/F).

The c-test-migration-plan §6 target was "718 项手工分三类" (manual
classification of 718 interface_tlcp `.data` rows into 40% behaviour
direct-port + 50% API-form builder/trait rewrite + 10% exempt).
**Phase E follows the codified audit-pin methodology** (consistent
with Phase C / G / H / B / F-followup rescoping rationale) — locking
the existing Rust TLCP coverage at every interface_tlcp facet rather
than literally porting 718 rows.

## 1. C inventory

C source: `openhitls/testcode/sdv/testcase/tls/interface_tlcp/`:

| `.c` / `.data` file | rows | Audience |
|---------------------|-----:|----------|
| `frame_cert_interface.data` | (subset of 4.6K bytes) | Certificate-API interface tests |
| `frame_cert_interface_2.data` | (1.5K bytes) | Certificate-API extension tests |
| `frame_cm_interface.data` | (12.6K bytes) | Connection-management API tests |
| `frame_config_interface.data` | (5.2K bytes) | Config-API tests |
| `hlt_cm_interface.data` | 13 | HLT-style connection-management |
| `hlt_config_interface.data` | 34 | HLT-style config |
| **Total** | **718 rows** | (per c-test-migration-plan §6 inventory) |

`base.c` files are helper definitions, not testcases.

## 2. C-source classification (codified at T115)

The c-test-migration-plan §6.1 envisaged a manual 3-way classification:

| Class | Share | C row count | Disposition |
|-------|------:|------------:|-------------|
| **Behaviour-class** — GM cert verify + state transitions + handshake variants | ~40 % | ~287 | Direct port → `tests/interop/tests/tlcp_behavior.rs` (T242 + T243) |
| **API-form class** — `HITLS_CFG_Set*` / `CM_*` getter/setter shapes | ~50 % | ~359 | Builder/trait rewrite → `crates/hitls-tls/src/tlcp/config.rs` inline unit tests (T244) |
| **Exempt** — C memory-model specific (`HITLS_X509_CTX_GET_OPS`, etc.) | ~10 % | ~72 | Documented as non-portable in plan §6 |

**Phase E rescope** (codified at T115): rather than literally porting
all 287+359 rows, audit-pin the existing Rust TLCP coverage that
already covers the same semantics:

- `tests/interop/tests/tlcp.rs` — 11 happy-path TLCP handshake variants
- `tests/interop/tests/tlcp_consistency.rs` — 22 audit-pin tests
  (T209+T210, codified)
- `crates/hitls-tls/src/connection_tlcp.rs::tests` — unit-level
  TLCP state-machine + parser
- `crates/hitls-tls/src/tlcp/config.rs` — TLCP config + builder
  (existing inline unit tests)

The audit-pin sub-PRs cross-reference these existing Rust coverages
and add a per-facet inventory + RFC reference + plan-doc cross-pin.

## 3. Existing Rust coverage (pre-Phase E)

| Test file | Tests | Phase E class covered |
|-----------|------:|-----------------------|
| `tests/interop/tests/tlcp.rs` | 11 | Behaviour (handshake variants) |
| `tests/interop/tests/tlcp_consistency.rs` | 22 | Behaviour (consistency mutations) |
| `crates/hitls-tls/tests/migrated_interface_tlcp_audit.rs` | (existing T199 audit pins; partial) | API-form |
| `crates/hitls-tls/tests/migrated_phase_f_audit_pins.rs` | 43 (Phase F follow-up) | Cross-facet |

**Total existing TLCP audit coverage** ≈ 76 tests pre-Phase E,
already covering the bulk of behaviour-class via integration tests.

## 4. Sub-PR split (5 sub-PRs + closeout)

| # | T-phase | Source family | Estimate tests | Approach |
|---|---------|---------------|---------------:|----------|
| ✅ plan + E-1 | ✅ T115 | this doc + 8 audit pins for 718-row inventory + Rust coverage cross-pin | 8 (this PR) | new `crates/hitls-tls/tests/migrated_phase_e_audit_pins.rs` |
| E-2 | T242 | Behaviour-class GM cert verify + state transitions | ~10 | extends `migrated_phase_e_audit_pins.rs` |
| E-3 | T243 | Behaviour-class handshake variants (ECDHE/ECC × GCM/CBC) | ~10 | extends `migrated_phase_e_audit_pins.rs` |
| E-4 | T244 | API-form class `HITLS_CFG_Set*` builder/trait coverage | ~10 | extends `migrated_phase_e_audit_pins.rs` |
| **closeout** | T245 | series rollup + Phase E close + `docs/tlcp-test-mapping.md` skeleton + c-test-migration-plan §12.7 status sync | ~5 | series summary |

`TODO(#42-phase-e)` — pinned in this doc and each Phase E sub-PR.

## 5. First batch — this PR (T115)

Lands `crates/hitls-tls/tests/migrated_phase_e_audit_pins.rs` with:

- Module-level docs explaining the audit-pin rescope (consistent
  with Phase B / F-followup methodology)
- 8 audit pins covering:
  - C SDV interface_tlcp 718-row inventory
  - 3-way classification breakdown (40 % / 50 % / 10 %)
  - Existing Rust TLCP integration test files cross-pin
  - Existing `migrated_interface_tlcp_audit.rs` T199 audit pins cross-pin
  - Phase F follow-up cross-pin (88 audit-pin tests cover TLCP facet)
  - TLCP cipher suite codepoint identity pin (ECC_SM4_CBC_SM3 +
    ECDHE_SM4_CBC_SM3 + ECDHE_SM4_GCM_SM3 + ECC_SM4_GCM_SM3)
  - Plan-doc cross-coverage
  - C-test-migration-plan §6 reference pin

## 6. Out-of-scope (documented)

- **Literal port of all 287 behaviour-class rows** — rescoped to
  audit-pin sample per the codified Phase C/G/H/B/F-followup pattern.
  E-2 + E-3 add ~20 audit-pin tests with cross-references to the
  existing 33 integration tests.
- **C-only memory-model exempt rows** (~72) — explicitly documented
  in plan §2 "Exempt" class.
- **Re-running the existing 11 + 22 integration tests** —
  already covered by `tests/interop/tests/tlcp{,_consistency}.rs`
  + `migrated_phase_f_audit_pins.rs` (Phase F follow-up). E-2/E-3
  cross-pin these without re-execution.

## 7. Acceptance criteria

- [ ] 5 sub-PR series merged with ~40-45 audit-pin tests
- [ ] `crates/hitls-tls/tests/` has new `migrated_phase_e_audit_pins.rs`
- [ ] T245 closeout emits `docs/tlcp-test-mapping.md` skeleton
      cross-referencing the 3-class breakdown
- [ ] DEV_LOG **T115 / T242-T245** entries; PROMPT_LOG entries
- [ ] `audit_phase_e_plan_docs_in_sync` cross-file pin in every Phase E
      test addition asserts this plan doc remains authoritative
- [ ] c-test-migration-plan §12.7 row E synced from "T115 reserved" to
      "closed at T115 + T242-T245" at T245 closeout — **completes the
      c-test-migration-plan Phase A-F arc**
