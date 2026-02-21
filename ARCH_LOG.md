# openHiTLS-rs — Architecture Refactoring Log

> This log records the execution history of the refactoring plan defined in [ARCH_REPORT.md](ARCH_REPORT.md).
> For the original architecture analysis and the full 10-phase plan (Phase R102–R111), see ARCH_REPORT.md §7.

---

## Phase R102: PKI Encoding Consolidation

### Date: 2026-02-21

### Commit: `32cb3d1`

### Goal

Eliminate duplicated ASN.1 encoding helpers and OID mapping functions scattered across the `hitls-pki` crate. These identical functions were copy-pasted into `cms/mod.rs`, `pkcs12/mod.rs`, `x509/ocsp.rs`, and other modules during the original C→Rust migration.

### Problem

| Function | Copies | Files |
|----------|--------|-------|
| `enc_seq` | 3 | cms/mod.rs, pkcs12/mod.rs, x509/ocsp.rs |
| `enc_set` | 2 | cms/mod.rs, pkcs12/mod.rs |
| `enc_octet` | 3 | cms/mod.rs, pkcs12/mod.rs, x509/ocsp.rs |
| `enc_oid` | 3 | cms/mod.rs, pkcs12/mod.rs, x509/ocsp.rs |
| `enc_int` | 3 | cms/mod.rs, pkcs12/mod.rs, x509/ocsp.rs |
| `enc_null` | 2 | pkcs12/mod.rs, x509/ocsp.rs |
| `enc_tlv` | 3 | cms/mod.rs, pkcs12/mod.rs, x509/ocsp.rs |
| `enc_explicit_ctx` | 2 | cms/mod.rs, pkcs12/mod.rs |
| `bytes_to_u32` | 5 | cms/mod.rs, cms/enveloped.rs, cms/encrypted.rs, pkcs12/mod.rs, pkcs8/encrypted.rs |
| `oid_to_curve_id` | 3 | pkcs8/mod.rs, x509/mod.rs, cms/mod.rs |
| `parse_algorithm_identifier` | 3 identical | cms/mod.rs, cms/enveloped.rs, cms/encrypted.rs |

Total: **32 duplicate function definitions** across 7 files.

### Solution

Created two shared `pub(crate)` modules at the crate root, available to all feature-gated submodules:

**1. `crates/hitls-pki/src/encoding.rs`** — 11 ASN.1 encoding helpers

| Function | Wraps |
|----------|-------|
| `enc_seq(content)` | `Encoder::write_sequence` |
| `enc_set(content)` | `Encoder::write_set` |
| `enc_octet(content)` | `Encoder::write_octet_string` |
| `enc_oid(oid_bytes)` | `Encoder::write_oid` |
| `enc_int(value)` | `Encoder::write_integer` |
| `enc_null()` | `Encoder::write_null` |
| `enc_tlv(tag, value)` | `Encoder::write_tlv` |
| `enc_explicit_ctx(tag_num, content)` | `enc_tlv` with CONTEXT_SPECIFIC \| CONSTRUCTED |
| `enc_raw_parts(parts)` | `Encoder::write_raw` for each part |
| `bytes_to_u32(bytes)` | Big-endian bytes → u32 conversion |

**2. `crates/hitls-pki/src/oid_mapping.rs`** — Unified OID-to-algorithm mapping

| Function | Return Type | Curves Supported |
|----------|-------------|-----------------|
| `oid_to_curve_id(oid)` | `Option<EccCurveId>` | secp224r1, prime256v1, secp384r1, secp521r1, brainpoolP256r1/384r1/512r1 |

Returns `Option` — callers wrap in their own error types (`CryptoError`, `PkiError`, etc.).

**3. Additional consolidation**: Made `cms::parse_algorithm_identifier` `pub(crate)` so `enveloped.rs` and `encrypted.rs` import it from `super` instead of maintaining identical copies.

### Files Modified

| File | Action |
|------|--------|
| `crates/hitls-pki/src/encoding.rs` | **NEW** — 79 lines, 11 shared helpers |
| `crates/hitls-pki/src/oid_mapping.rs` | **NEW** — 27 lines, unified OID mapping |
| `crates/hitls-pki/src/lib.rs` | Added 2 non-feature-gated module declarations |
| `crates/hitls-pki/src/cms/mod.rs` | Removed 10 local functions, added imports, `parse_algorithm_identifier` → `pub(crate)` |
| `crates/hitls-pki/src/cms/enveloped.rs` | Removed `bytes_to_u32` + `parse_algorithm_identifier`, updated imports |
| `crates/hitls-pki/src/cms/encrypted.rs` | Removed `bytes_to_u32` + `parse_algorithm_identifier`, updated imports |
| `crates/hitls-pki/src/pkcs12/mod.rs` | Removed 9 local `enc_*` + `bytes_to_u32`, removed unused `Encoder`/`tags` imports |
| `crates/hitls-pki/src/x509/ocsp.rs` | Removed 7 local `enc_*`, removed unused `Encoder` import |
| `crates/hitls-pki/src/pkcs8/mod.rs` | Removed `oid_to_curve_id`, uses `oid_mapping::oid_to_curve_id` with `.ok_or()` |
| `crates/hitls-pki/src/pkcs8/encrypted.rs` | Removed `bytes_to_u32`, added import |
| `crates/hitls-pki/src/x509/mod.rs` | `oid_to_curve_id` → thin wrapper over `oid_mapping::oid_to_curve_id` |

### Not Changed (by design)

- **`x509/mod.rs::parse_algorithm_identifier`** — Returns `(Vec<u8>, Option<Vec<u8>>)` with distinct NULL-handling semantics (reads TLV, maps NULL tag to `None`). Different interface from CMS version. Used by 6+ call sites in x509 and crl. Not consolidatable without API change.
- **`cms/mod.rs::cerr`** — CMS-specific error helper, already shared via `use super::cerr` by enveloped.rs and encrypted.rs.
- **`x509/ocsp.rs::enc_bit_string`** — Test-only (`#[cfg(test)]`), not worth sharing.
- **`x509/ocsp.rs::enc_generalized_time`** — Test-only (`#[cfg(test)]`), OCSP-specific.

### Impact

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| Duplicate function definitions | 32 | 0 | −32 |
| Lines (across 11 files) | 416 | 141 | −275 |
| Shared modules | 0 | 2 | +2 |
| `oid_to_curve_id` implementations | 3 independent | 1 canonical + 1 thin wrapper | −2 |
| `parse_algorithm_identifier` copies | 4 (3 identical) | 2 (different types) | −2 |

### Build Status

- `cargo test -p hitls-pki --all-features`: **349 passed**, 0 failed, 1 ignored
- `cargo test --workspace --all-features`: all passed, 0 failed
- `RUSTFLAGS="-D warnings" cargo clippy -p hitls-pki --all-features --all-targets`: **0 warnings**
- Public API: **zero changes** — all modifications are `pub(crate)` internal

---

## Refactoring Queue

The following phases are defined in [ARCH_REPORT.md](ARCH_REPORT.md) §7 and have not yet been started:

| Phase | Title | Priority | Status |
|-------|-------|----------|--------|
| Phase R102 | PKI Encoding Consolidation | Critical | **Done** |
| Phase R103 | Record Layer Enum Dispatch | High | Pending |
| Phase R104 | Connection File Decomposition | High | Pending |
| Phase R105 | Hash Digest Enum Dispatch | Medium | Pending |
| Phase R106 | Sync/Async Unification via Macros | Medium | Pending |
| Phase R107 | X.509 Module Decomposition | Medium | Pending |
| Phase R108 | Integration Test Modularization | Medium | Pending |
| Phase R109 | Test Helper Consolidation | Low | Pending |
| Phase R110 | Parameter Struct Refactoring | Low | Pending |
| Phase R111 | DRBG State Machine Unification | Low | Pending |

**Recommended execution order**: R103 → R104 → R105 → R107 → R108 → R109 → R110 → R111 → R106
