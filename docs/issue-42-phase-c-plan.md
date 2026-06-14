# Phase C — PKI malformed-fixture migration plan

**Status**: Planning + first batch (T204).
**Tracking issue**: [#42](https://github.com/dong-qiu/openhitls-rs/issues/42)
**Migration plan**: `docs/c-test-migration-plan.md` Phase C (§4).

This document is the audit + per-source-file decision matrix + sub-PR split
for Phase C, modelled on the successful T195 audit pattern from the #46
series.

## 1. Inventory

C source: `openhitls/testcode/sdv/testcase/pki/` (12 `.c` files /
**459 fn / 7 415 `.data` rows**):

| `.c` file | C fn | rows | Audience |
|-----------|-----:|-----:|----------|
| `x509_cert.c` | 45 | 3 434 | X.509 parse + ext decoding |
| `x509.c` | 34 | 708 | X.509 generic codec |
| `common.c` | 71 | 866 | DN / OID / utility codecs |
| `x509_crl_rfc5280.c` | 18 | 317 | CRL strict-compliance |
| `x509_csr.c` | 31 | 251 | CSR (PKCS#10) |
| `x509_vfy.c` | 84 | 385 | Cert chain verify |
| **`x509_crl.c`** | 45 | 448 | CRL extensions / IDP / DCI |
| **`x509_check.c`** | 39 | 346 | Cert chain check |
| **`cms.c`** | 7 | 71 | CMS encoded/digest |
| **`cms_sign.c`** | 33 | 347 | CMS SignedData |
| **`pkcs12.c`** | 37 | 198 | PKCS#12 PFX |
| **`pkcs12_util.c`** | 15 | 44 | PKCS#12 utility |

## 2. Existing Rust coverage

| Test file | Tests | C family covered |
|-----------|------:|------------------|
| `migrated_x509_parse.rs` | 1 076 | `x509_cert` + `x509` + `common` (main body) |
| `migrated_crl_rfc5280_verify.rs` | 32 | `x509_crl_rfc5280` (T187 + T202) ✅ |
| `migrated_crl_rfc5280_gap.rs` | 9 | `x509_crl_rfc5280` gap rows |
| `migrated_csr_negative_parse.rs` | 13 | `x509_csr` (T188 + T203) ✅ |

**Total existing Phase C coverage ≈ 1 130 tests.**

## 3. Real gaps — 5 C-source families with ~0 Rust coverage

| Family | C scope | Estimate audit-pin tests |
|--------|--------:|-------------------------:|
| **CMS** (`cms.c` + `cms_sign.c`) | 40 fn / 418 rows | ~12 |
| **PKCS#12** (`pkcs12.c` + `pkcs12_util.c`) | 52 fn / 242 rows | ~12 |
| **x509_crl non-RFC5280** (`x509_crl.c`) | 45 fn / 448 rows | ~10 |
| **x509_check** (`x509_check.c`) | 39 fn / 346 rows | ~10 |
| **x509_vfy remainder** (`x509_vfy.c`) | 84 fn / 385 rows | ~8 |
| **Totals** | **260 fn / 1 839 rows** | **~52 tests** |

The reduction reflects the methodology proven by the #46 series: many C
rows parameterise state × cipher × cert-shape matrices that Rust's
existing `migrated_x509_parse.rs` (1 076 fns) + `tests/interop/`
end-to-end tests already cover. The new tests target the **delta** —
unique categories C asserts that no Rust test currently pins.

## 4. Proposed sub-PR split (5 sub-PRs + closeout)

| # | T-phase | Source family | Estimate tests | Approach |
|---|---------|---------------|---------------:|----------|
| ✅ plan + C-1 | ✅ T204 | this doc + `cms.c` + `cms_sign.c` first batch | 11 (delivered) | merged (PR #286) |
| ✅ C-2 | ✅ T205 | `pkcs12.c` + `pkcs12_util.c` | 10 (delivered) | merged (PR #287) |
| ✅ C-3 | ✅ T206 | `x509_crl.c` non-RFC5280 | 10 (delivered) | merged (PR #288) |
| ✅ C-4 | ✅ T207 | `x509_check.c` + `x509_vfy.c` | 15 (delivered) | merged (PR #289) |
| ✅ **closeout** | ✅ T208 | series rollup + Phase C close | — | this PR |

`TODO(#42-phase-c)` — pinned in this doc and in each Phase C sub-PR's
`migrated_*.rs` audit pin. Each sub-PR removes its row from the planned
table once merged.

## 5. First batch — this PR (T204)

Migrates a focused set of CMS-family rows that exercise the
`CmsMessage::from_der` + `verify_signatures` round-trip path using the
existing fixtures already mirrored under
`tests/vectors/c-asn1-fixtures/cert/asn1/cms/signeddata/`. Each test
references its C TC ID in the doc comment per #42 acceptance criterion.

Lands in `crates/hitls-pki/tests/migrated_cms_negative_parse.rs`
together with an `audit_plan_docs_in_sync` test that pins this plan
doc's anchors (same pattern as the #46 series).

## 6. Out-of-scope (documented)

- **`x509_cert.c` / `x509.c` / `common.c` POSITIVE round-trips** — already
  covered by `migrated_x509_parse.rs` (1 076 fns). Re-migrating would
  produce duplicate coverage at no gain.
- **`x509_crl_rfc5280.c` strict-version + dates** — closed by T187/T202.
- **`x509_csr.c` negative-parse categories** — closed by T188/T203.
- **C-only API surfaces** (`HITLS_X509_CMS_Sign{StreamUpdate,Finish}`,
  PKCS#12 raw `BSL_PKCS12_Init`/`Ctrl` knobs) that the Rust port
  deliberately omits — would need new product APIs.

## 7. Acceptance criteria

- [x] 5 sub-PR series merged with **46 audit-pin tests** (T204 11 + T205 10 + T206 10 + T207 15)
- [x] `crates/hitls-pki/tests/` has new `migrated_cms_negative_parse.rs` +
      `migrated_pkcs12_negative_parse.rs` +
      `migrated_x509_crl_extensions.rs` + `migrated_x509_check_vfy.rs`
- [x] Each test asserts a specific `PkiError::*` variant, a
      verified-positive round-trip, or an explicit gap pin with
      `TODO(#42-phase-c)`
- [x] DEV_LOG **T204-T208** entries; PROMPT_LOG entries
- [x] `audit_plan_docs_in_sync` cross-file pin in every Phase C test
      file asserts this plan doc + §8 rollup totals

## 8. Series rollup (T208 closeout)

The 5-sub-PR series is closed; this section is the final tally so the
issue closer / future readers can see the whole shape at a glance.

| Sub-PR | Phase | Source family | C scope (fn / rows) | Delivered tests | PR | Outcome |
|--------|-------|---------------|--------------------:|----------------:|----|---------|
| plan + C-1 | T204 | this doc + `cms.c` + `cms_sign.c` | 40 fn / 418 rows | 11 | #286 | merged |
| C-2 | T205 | `pkcs12.c` + `pkcs12_util.c` | 52 fn / 242 rows | 10 | #287 | merged |
| C-3 | T206 | `x509_crl.c` non-RFC5280 | 45 fn / 448 rows | 10 | #288 | merged |
| C-4 | T207 | `x509_check.c` + `x509_vfy.c` | 123 fn / 731 rows | 15 | #289 | merged |
| closeout | T208 | series rollup + Phase C close | — | — | this PR | — |
| **Totals** | | **260 fn / 1 839 rows** | | **46 tests** | | **5/5 sub-PRs closed** |

**Net result vs C input**: 46 net new Rust tests against 260 unique C
TC families / 1 839 parameterised `.data` rows in the 5 source files
this series targets. The reduction reflects Phase C's core thesis
(plan §2 + §3): much of the C surface is parameterised cipher × cert
× chain matrices that `migrated_x509_parse.rs` (1 076 fns) and the
existing interop chain tests already cover. The 46 audit-pin tests
are the **delta** — semantics C asserts that no Rust test currently
pins.

**Methodology lineage** (each sub-PR codified patterns the next
reused):

- T204 — fixture-driven (not mutation-driven) / per-algorithm-family
  enumeration / sub-PR series opener = plan doc + first batch +
  cross-file pin
- T205 — per-fixture password binding / `.data` row quoted-string
  byte counting / fixture-without-TC-row → drop
- T206 — unsupported-algorithm gap pin / algorithm-matrix fixture
  reuse / extension parse = tolerated pin (negative claim)
- T207 — struct field name grep beats intuition / PQC try-parse vs
  `expect_err` / fixture-presence audit pin
- T208 — closeout = §8 rollup table + Methodology lineage + 0 new
  test fns (fold into existing `audit_plan_docs_in_sync`)

**Follow-up TODOs left open** (3, all `TODO(#42-phase-c)`):

- CMS SignedData strict-version (T204) — reject unknown version
  values per RFC 5652 §5.1 / §11.1
- CRL DSA-SHA-256 dispatch (T206) — add OID `2.16.840.1.101.3.4.3.2`
  to the CRL signature-algorithm dispatch if DSA verification
  becomes a target
- PQC cert chain (T207) — ML-DSA / SLH-DSA SubjectPublicKeyInfo
  decode + cert chain build paths

These are product-side hardening / extension tasks that surfaced
during the audit; the corresponding tests pin **current** lenient or
unsupported behaviour so a future hardening lands as a deliberate
change (test fails, gets updated to the new assertion).
