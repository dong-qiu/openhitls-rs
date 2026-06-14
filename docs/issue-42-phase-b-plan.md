# Phase B — Audit-pin closure of remaining `#43-#61` TODO anchors

**Status**: Planning + first batch (T112).
**Tracking issue**: [#42](https://github.com/dong-qiu/openhitls-rs/issues/42)
**Migration plan**: `docs/c-test-migration-plan.md` §3 Phase B.
**Methodology**: Phase G/H-codified audit-pin sample (T220 + T225 +
T228 lineage).

This document is the audit + per-sub-PR split for Phase B — the
"completely-missing 6 categories" group from the original
c-test-migration-plan. The 5 GitHub issues for Phase B (#43 enc CLI,
#44 CSR negative, #45 CRL RFC 5280, #47 CLI 5 sub-commands, #57 idle
fixtures) are all **CLOSED** at the issue level. **49 deeper TODO
anchors remain** across 8+ files representing real implementation
gaps that the issue closure deliberately deferred.

Phase B follows the codified audit-pin methodology to lock the
current lenient / unsupported behaviour at every remaining TODO site
and produce a concrete Phase I roadmap, rather than implementing the
deeper crypto primitives (RSA-PSS PKCS#8 codec, SM2 PKCS#8, Brainpool
P-{256,384,512}, NIST P-224) here.

## 1. Inventory — 49 TODO anchors

Census taken on the post-Phase-H main (after PR #311):

| Anchor | Count | Files (representative) | Phase B sub-PR |
|--------|------:|------------------------|----------------|
| `TODO(#44-strict-version)` | 3 | `migrated_csr_negative_parse.rs` | T112 (B-1) |
| `TODO(#45-strict-version)` | 3 | `migrated_crl_rfc5280_verify.rs` | T112 (B-1) |
| `TODO(#45-aki-match)` | 2 | `migrated_crl_rfc5280_verify.rs` | T112 (B-1) |
| `TODO(#47-pkey-rsa-pss)` | 3 | `hitls-cli/src/pkey.rs` | T233 (B-2) |
| `TODO(#47-pkey-sm2)` | 3 | `hitls-cli/src/pkey.rs` | T233 (B-2) |
| `TODO(#47-pkey-brainpool)` | 1 | `hitls-cli/src/pkey.rs` | T233 (B-2) |
| `TODO(#47-pkey-p224)` | 1 | `hitls-cli/src/pkey.rs` | T233 (B-2) |
| `TODO(#47-pkey-encrypted-pkcs8)` | 2 | `hitls-cli/src/pkey.rs` | T233 (B-2) |
| `TODO(#47-genrsa-encryption)` | 3 | `hitls-cli/src/genrsa.rs` | T234 (B-3) |
| `TODO(#47-rsa-codec-extract)` | 3 | `hitls-cli/src/rsa_cmd.rs` | T234 (B-3) |
| `TODO(#47-conf-cnf)` | 2 | `hitls-cli/src/conf_util.rs` | T234 (B-3) |
| `TODO(#47-sm-defer)` | 6 | `hitls-cli/src/sm_defer.rs` | T234 (B-3) |
| `TODO(#47-keymgmt-defer)` | 3 | `hitls-cli/src/keymgmt_defer.rs` | T234 (B-3) |
| `TODO(#46-plan)` | 2 | TLS config | T235 (B-4) |
| `TODO(#46-version-bounds)` | 1 | TLS config | T235 (B-4) |
| `TODO(#46-sigalg-empty)` | 1 | TLS config | T235 (B-4) |
| `TODO(#46-groups-empty)` | 1 | TLS config | T235 (B-4) |
| `TODO(#58-context-gap)` | 3 | `hitls-utils` | T235 (B-4) |
| `TODO(#58-dup-check)` | 2 | `hitls-utils` | T235 (B-4) |
| `TODO(#61-codec-gap)` | 3 | codec layer | T235 (B-4) |
| `TODO(#61-design)` | 1 | codec layer | T235 (B-4) |
| **Totals** | **49** | 8+ files | 4 sub-PRs |

## 2. Existing Rust coverage

The TODO sites already follow the Phase C/G/H audit-pin pattern: each
anchor sits next to either a `.expect()` documenting the current
lenient behaviour or a stub returning `"...not implemented (TODO)"`.
These ARE the existing audit pins. What Phase B adds:

1. **Cross-file RFC anchor pins** — each Phase B anchor gets a sibling
   pin asserting the exact RFC section the future hardening would
   enforce, codified as a constant byte / number that future product
   code can grep.
2. **Methodology-lineage pin** — Phase B test files cross-reference
   the Phase C / G / H plan docs so the audit-pin family stays
   coherent.
3. **Phase I roadmap cross-coverage** — each anchor's "what would
   close this" lands in the Phase I planning doc (T236 closeout
   emits `docs/issue-42-phase-i-roadmap.md`).

## 3. Sub-PR split (5 sub-PRs + closeout)

| # | T-phase | Source family | Estimate tests | Approach |
|---|---------|---------------|---------------:|----------|
| ✅ plan + B-1 | ✅ T112 | this doc + 8 audit pins for `#44/#45` strict-version + aki-match | 8 (this PR) | new `crates/hitls-pki/tests/migrated_phase_b_audit_pins.rs` |
| B-2 | T233 | `#47-pkey-*` family (RSA-PSS / SM2 / Brainpool / P-224 / encrypted-PKCS#8) | ~10 | extends `migrated_phase_b_audit_pins.rs` |
| B-3 | T234 | `#47-genrsa / rsa-codec / conf / sm / keymgmt` family | ~10 | extends `migrated_phase_b_audit_pins.rs` |
| B-4 | T235 | `#46-plan / #58-context / #61-codec` family | ~10 | extends `migrated_phase_b_audit_pins.rs` |
| **closeout** | T236 | series rollup + Phase I roadmap doc + methodology lineage | ~5 | series summary |

`TODO(#42-phase-b)` — pinned in this doc and each Phase B sub-PR.

## 4. First batch — this PR (T112)

Lands `crates/hitls-pki/tests/migrated_phase_b_audit_pins.rs` with:

- Module-level docs explaining the Phase B audit-pin approach +
  cross-references to Phase C/G/H plan docs
- 8 audit pins covering the 8 `#44 / #45` sites:
  - 3 × CSR RFC 2986 §4 version field pins (codepoint 0 = v1; reject
    on != 0)
  - 3 × CRL RFC 5280 §5.1.2.1 version field pins (codepoint 1 = v2;
    reject on != 1 when extensions present)
  - 2 × CRL RFC 5280 §5.2.1 AuthorityKeyIdentifier ↔ SubjectKeyIdentifier
    matching pin (current Rust matches CRL → issuer by DN; AKI/SKI
    match is unimplemented)
- Each pin asserts: (a) the RFC section number is literal in source,
  (b) the codepoint is the right byte, (c) the existing TODO marker
  remains in its file (cross-file grep target), (d) a Phase I
  "what-to-close" pointer is documented

## 5. Out-of-scope (documented)

- **Implementing the deeper crypto primitives** (RSA-PSS PKCS#8 codec,
  SM2 PKCS#8 OID handling, Brainpool curves, P-224, conf .cnf parser,
  password-derived PKCS#8 encryption). All deferred to **Phase I**
  with detailed roadmap doc emitted at T236 closeout.
- **C SDV `.data` row-for-row migration** for any Phase B target.
  Phase B is audit-pin-only, mirroring Phase C/G/H methodology.
- **Re-opening any closed Phase B issue**. The TODO anchors are the
  contract; issues stay closed.

## 6. Acceptance criteria

- [ ] 5 sub-PR series merged with ~40-45 audit-pin tests
- [ ] `crates/hitls-pki/tests/` has new `migrated_phase_b_audit_pins.rs`
- [ ] T236 closeout emits `docs/issue-42-phase-i-roadmap.md` covering
      all 49 Phase B anchors + their "what-to-close" pointers
- [ ] DEV_LOG **T112 / T233-T236** entries; PROMPT_LOG entries
- [ ] `audit_phase_b_plan_docs_in_sync` cross-file pin in every Phase
      B test addition asserts this plan doc remains authoritative
