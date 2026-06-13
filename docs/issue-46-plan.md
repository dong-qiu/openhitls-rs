# #46 TLCP `interface_tlcp` migration plan

**Status**: Planning + first batch (T195).
**Target**: Port the C `interface_tlcp/` test gap into the Rust workspace.
**Total scope**: ~80 unique TC functions × ~9 `.data` rows each = **718
parameterised test rows** across 4 source files.

This document is the audit + per-category coverage map + sub-PR split for
the #46 issue, modelled on the successful T191/T192 audit pattern from the
#47 series.

## 1. Inventory

C source: `openhitls/testcode/sdv/testcase/tls/interface_tlcp/`

| File | TC functions | `.data` rows | Audience |
|------|-------------:|-------------:|----------|
| `test_suite_sdv_frame_config_interface.{c,data}` | 28 | 151 | `HITLS_CFG_*` config setters/getters |
| `test_suite_sdv_frame_cert_interface.{c,data}` | 25 | 118 | `HITLS_X509_*` cert manager (low-level) |
| `test_suite_sdv_frame_cert_interface_2.{c,data}` | 6 | 34 | `HITLS_X509_*` cert manager (extras) |
| `test_suite_sdv_frame_cm_interface.{c,data}` | 92 | 364 | `HITLS_CFG_SetCert*` / `HITLS_*_GetVerify*` (cert-manager wrapper) |
| `test_suite_sdv_hlt_config_interface.{c,data}` | 0 | 34 | HLT-style handshake against configured TLS link |
| `test_suite_sdv_hlt_cert_interface.{c,data}` | 0 | 4 | HLT-style cert chain handshake |
| `test_suite_sdv_hlt_cm_interface.{c,data}` | 0 | 13 | HLT-style cert-mgr handshake |
| **Total** | **151** | **718** | |

The `hlt_*` files declare no `void UT_*` cases of their own; they are
parameterised wrappers around shared `HLT_TlsHandshake` scaffolding that the
`.data` rows drive (`HITLS_VERSION_TLCP_DTLCP11` / various cert combos).

## 2. Coverage already present in the Rust workspace

A substantial fraction of the C `HITLS_CFG_*` setter/getter round-trips is
already covered at unit-test level in
`crates/hitls-tls/src/config/mod.rs::tests` (**100+ `test_config_builder_*`
tests**) — version range, ALPN, cipher suites, session resumption, PSK,
EMS/ETM, OCSP, SCT, record size limit, fallback SCSV, etc.

The TLCP handshake happy-path is covered by
`tests/interop/tests/tlcp.rs` (11 tests, ECDHE/ECC GCM/CBC + DTLCP cookie).

The C `interface_tlcp/` tests are therefore a **gap audit** rather than an
unconditional migration target: we identify rows whose semantics are NOT
already enforced by Rust unit tests + interop, and port those.

## 3. Per-TC-family coverage map (sample — frame_config_interface)

| C TC family | C row count | Rust coverage | Decision |
|-------------|------------:|---------------|----------|
| `UT_TLS_CFG_UPREF_FUNC_TC001` | 1 | N/A — Rust uses `Arc<TlsConfig>` (no UpRef API) | **scope cut** (C API gap) |
| `UT_TLS_CFG_SET_RESUMPTIONONRENEGOSUPPORT_API_TC001` | 2 (TLS12 + TLS13) | Partial: builder lacks set/get for "ResumptionOnReneg" | **port** as builder fields |
| `UT_TLS_CFG_SET_GET_NOCLIENTCERTSUPPORT_API_TC001` | 2 (TLS12 + TLS13) | Covered by `verify_peer(false)` semantics | **scope cut** (equivalent) |
| `UT_TLS_CFG_SET_GET_CLIENTVERIFYSUPPORT_API_TC001` | 2 (TLS12 + TLS13) | Covered by `verify_peer(true)` semantics | **scope cut** (equivalent) |
| `UT_TLS_CFG_SET_TMPDH_API_TC001` | 5 (security-bits × levels) | N/A — Rust uses FFDHE groups (no static TmpDh) | **scope cut** (C API gap) |
| `UT_TLS_CFG_SET_TMPDHCB_API_TC001` | 5 | N/A — same as above | **scope cut** |
| `UT_TLS_CFG_SETTMPDH_FUNC_TC001` | 1 | N/A | **scope cut** |
| `UT_TLS_CFG_SET_CLIENTHELLOCB_API_TC001` | 2 | Partial — Rust has SNI cb but not generic CH cb | **scope cut** (deferred) |
| `UT_TLS_CFG_SET_COOKIEGENERATECB_API_TC001` | 1 | N/A — Rust DTLS cookie path is internal | **scope cut** (internal API) |
| `UT_TLS_CFG_SET_COOKIEVERIFYCB_API_TC001` | 1 | N/A | **scope cut** |
| `UT_TLS_CFG_SET_GET_VERSION_API_TC001` | 1 | Covered by `test_config_builder_version_range` | **scope cut** (equivalent) |
| `UT_TLS_CFG_SET_GET_VERSIONSUPPORT_API_TC001` | 1 | Covered | **scope cut** |
| `UT_TLS_CFG_SET_GROUPS_FUNC_TC001` | 8 | Partial — `supported_groups` builder exists, no NULL rejection | **port negative rows** |
| `UT_TLS_CFG_SET_SIGNATURE_FUNC_TC001` | 8 | Covered by `signature_algorithms` builder + cipher-suite tests | **scope cut** |
| `UT_TLS_CFG_SET_ECPOINTFORMATS_FUNC_TC001` | 4 | N/A — Rust uses uncompressed only | **scope cut** (C API gap) |
| `UT_TLS_CFG_SET_POSTHANDSHAKEAUTHSUPPORT_API_TC001` | 4 | Covered by T98 PHA tests + builder | **scope cut** |
| `UT_TLS_CFG_SET_GET_RENEGOTIATIONSUPPORT_FUNC_TC001` | 6 | Partial — `secure_renegotiation` builder, no set/get round-trip pin | **port** if novel |
| `UT_TLS_CFG_GET_*_API_TC001` (cipher metadata getters) | 9 | Partial — `CipherSuite::from_str` etc. exists | **port** the metadata-getter family if novel |
| `UT_TLS_CFG_SET_GET_HELLO_VERIFY_REQ_API_TC001` | 2 | N/A — Rust DTLS HelloVerifyRequest is internal | **scope cut** |
| `UT_TLS_CFG_SET_GET_QUIETSHUTDOWN_API_TC001` | 1 | N/A — no `quiet_shutdown` builder | **scope cut** (C API gap) |
| `UT_TLS_CFG_SET_GET_DHAUTOSUPPORT_FUNC_TC001` | 4 | N/A — same as TmpDh | **scope cut** |
| `UT_TLS_CFG_SET_GET_CIPHERSERVERPREFERENCE_API_TC001` | 1 | Covered (default behavior) | **scope cut** |

**Pre-audit estimate**:
- ~20 / 28 `frame_config_interface` TC families are either already covered
  by Rust unit tests, or test C-only APIs (TmpDh, ECPointFormats,
  HelloVerifyReq, QuietShutdown, UpRef) that the Rust port deliberately
  omits.
- ~8 families are novel-worth-porting candidates (set/get round-trips for
  ResumptionOnReneg, Groups NULL rejection, RenegoSupport gate, etc.).

The same audit pattern will apply to the other 3 source files. Detailed
per-family coverage maps will be produced as each sub-PR opens; the table
above is the worked example for `frame_config_interface`.

## 4. Proposed sub-PR split

Following the #47 6-PR series methodology (heterogeneous decision per
sub-PR, README + tests-pin documentation):

| # | T-phase | Source file | Approx. novel test count | Approach |
|---|---------|-------------|-------------------------:|----------|
| ✅ plan | ✅ T195 | (this doc) + 5–8 representative frame_config negatives | 11 (delivered) | merged (PR #275) |
| ✅ 46-A | ✅ T196 | `frame_config_interface` remainder (cipher metadata + reneg round-trip) | 10 (delivered) | merged (PR #276) |
| ✅ 46-B | ✅ T197 | `frame_cert_interface` + `frame_cert_interface_2` | 11 (delivered) | merged (PR #277) |
| ✅ 46-C | ✅ T198 | `frame_cm_interface` (largest, 92 fns) | 25 (delivered) | merged (PR #278) |
| ✅ 46-D | ✅ T199 | `hlt_config_interface` + `hlt_cert_interface` + `hlt_cm_interface` | 10 (delivered) | this PR |
| **closeout** | T200 | rollup table + #46 close | — | series summary |

Per-source-file totals will likely land at **~70 net new tests** across
4–5 sub-PRs (vs. C's 718 rows). The reduction reflects that the C tests
heavily parameterise version × security-level × cipher matrices that are
already covered by Rust's TLS protocol/handshake tests.

`TODO(#46-plan)` — pinned in this doc and in
`crates/hitls-tls/tests/migrated_interface_tlcp_audit.rs`. Each sub-PR
removes its row from the planned table once merged.

## 5. First batch — this PR (T195)

Migrates a focused set of `frame_config_interface` negative-validation
tests that demonstrate the pattern and are not currently covered by
`crates/hitls-tls/src/config/mod.rs::tests`. Each is a small unit test
that exercises the Rust `TlsConfig::builder` API for behavior the C TCs
explicitly assert.

These land in
`crates/hitls-tls/tests/migrated_interface_tlcp_audit.rs` (new file)
together with a `audit_plan_docs_in_sync` test that pins the plan doc's
existence + the proposed sub-PR table.

## 6. Out-of-scope (documented)

The following C-only APIs the Rust workspace deliberately does not expose
— migrating their TC families would require new product APIs and is
explicitly **not** in scope for #46:

- `HITLS_CFG_UpRef` (Rust uses `Arc<TlsConfig>`)
- `HITLS_CFG_SetTmpDh` / `SetTmpDhCb` (Rust uses FFDHE groups directly)
- `HITLS_CFG_SetECPointFormats` (Rust supports uncompressed only)
- `HITLS_CFG_SetHelloVerifyReq` (Rust DTLS cookie is internal)
- `HITLS_CFG_SetQuietShutdown`
- `HITLS_CFG_SetClientHelloCb` (generic CH callback — deferred)
- `HITLS_CFG_SetCookieGenCb` / `SetCookieVerifyCb` (internal DTLS path)
- `HITLS_CFG_SetDhAutoSupport` (related to TmpDh)
