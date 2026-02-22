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

## Phase R103: Record Layer Enum Dispatch

### Date: 2026-02-22

### Goal

Replace `Option<T>` field proliferation in `RecordLayer` with type-safe enum dispatch. The struct had 8–10 `Option` fields (only 2 active at any time), leading to verbose dispatch chains, manual variant clearing, and multi-field state checks.

### Problem

| Pattern | Before |
|---------|--------|
| `Option<T>` encryptor/decryptor fields | 8 (10 with TLCP feature) |
| `seal_record()` dispatch | 5-way `if/else` chain |
| `open_record()` dispatch | 5 separate `if-let-Some` blocks |
| `is_encrypting()`/`is_decrypting()` | 5-field `\|\|` chains |
| `activate_*` methods clearing others | 10 methods, each clears 1–3 competing variants |
| `deactivate_*` methods | Each lists all 5+ variants to clear |

### Solution

Defined two enum types that unify all encryption/decryption variants:

**1. `RecordEncryptorVariant`** — 5 variants (4 + TLCP feature-gated)

```rust
enum RecordEncryptorVariant {
    Tls13(RecordEncryptor),        // TLS 1.3 AEAD (with padding callback)
    Tls12Aead(RecordEncryptor12),  // TLS 1.2 GCM/CCM
    Tls12Cbc(RecordEncryptor12Cbc),// TLS 1.2 CBC
    Tls12EtM(RecordEncryptor12EtM),// TLS 1.2 Encrypt-Then-MAC (RFC 7366)
    #[cfg(feature = "tlcp")]
    Tlcp(TlcpEncryptor),           // TLCP (itself an enum: Cbc | Gcm)
}
```

All variants share `encrypt_record(content_type, plaintext) -> Result<Record, TlsError>`.

**2. `RecordDecryptorVariant`** — same 5 variants with unified `decrypt_record()`:

- TLS 1.3: extracts inner content type from encrypted ApplicationData records
- TLS 1.2/TLCP: preserves original content type, skips ChangeCipherSpec

**3. Simplified `RecordLayer` struct**:

```rust
pub struct RecordLayer {
    pub max_fragment_size: usize,
    pub empty_record_count: u32,
    pub empty_records_limit: u32,
    encryptor: Option<RecordEncryptorVariant>,  // was 5 Option fields
    decryptor: Option<RecordDecryptorVariant>,  // was 5 Option fields
}
```

### Files Modified

| File | Action |
|------|--------|
| `crates/hitls-tls/src/record/mod.rs` | **ONLY FILE** — added 2 enums + impl blocks, simplified struct (8→2 fields) + all methods |

### Not Changed (by design)

- **DTLS encryption** (`encryption_dtls12.rs`, `encryption_dtlcp.rs`) — DTLS types are NOT part of `RecordLayer`; managed separately in `connection_dtls12.rs` and `connection_dtlcp.rs` with different method signatures (explicit epoch/seq params).
- **Individual encryption type files** (`encryption.rs`, `encryption12.rs`, `encryption12_cbc.rs`, `encryption_tlcp.rs`) — unchanged, the enum wraps existing types as-is.
- **Connection files** (`connection.rs`, `connection12.rs`, `connection_async.rs`, etc.) — unchanged, all use `RecordLayer`'s public API which retains identical method signatures.

### Impact

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| `Option<T>` fields in RecordLayer | 8 (10 with TLCP) | 2 | −6 (−8) |
| `seal_record()` dispatch branches | 5 if/else | 1 enum match | −4 |
| `open_record()` dispatch blocks | 5 if-let-Some | 1 enum match | −4 |
| `is_encrypting()`/`is_decrypting()` | 5-field `\|\|` chain each | `.is_some()` | −10 checks |
| `activate_*` variant-clearing lines | ~20 | 0 | −20 |
| `deactivate_*` body lines | ~10 per method | 1 per method | −8 |
| Lines in mod.rs (non-test) | ~467 | ~390 | ~−77 |

### Build Status

- `cargo test -p hitls-tls --all-features`: **1164 passed**, 0 failed, 0 ignored
- `cargo test --workspace --all-features`: **2585 passed**, 0 failed, 40 ignored
- `RUSTFLAGS="-D warnings" cargo clippy -p hitls-tls --all-features --all-targets`: **0 warnings**
- Public API: **zero changes** — all method signatures unchanged, no callers modified

---

## Phase R104: Connection File Decomposition

### Date: 2026-02-22

### Goal

Decompose the two largest files in `hitls-tls` — `connection.rs` (7,324 lines) and `connection12.rs` (7,004 lines) — into directory modules with focused subfiles. Both files contained client struct + server struct + large test suites in a single flat file (tests accounted for 69–76% of content).

### Problem

| File | Total Lines | Implementation | Tests | % Tests |
|------|-------------|---------------|-------|---------|
| `connection.rs` | 7,324 | ~1,700 | ~5,600 | 76% |
| `connection12.rs` | 7,004 | ~2,200 | ~4,800 | 69% |

### Solution

Converted each flat file into a directory module (`mod.rs` + `client.rs` + `server.rs` + `tests.rs`):

**`connection/` directory**:
- `mod.rs` (19 lines) — `ConnectionState` enum, module declarations, re-exports
- `client.rs` (894 lines) — `TlsClientConnection<S>` struct + impl + `Drop` + `TlsConnection` trait impl
- `server.rs` (829 lines) — `TlsServerConnection<S>` struct + impl + `Drop` + `TlsConnection` trait impl
- `tests.rs` (5,603 lines) — all unit tests, with explicit imports replacing `use super::*;` dependencies

**`connection12/` directory**:
- `mod.rs` (23 lines) — `ConnectionState` enum (with `Renegotiating` variant), module declarations, re-exports
- `client.rs` (1,147 lines) — `Tls12ClientConnection<S>` struct + impl
- `server.rs` (1,048 lines) — `Tls12ServerConnection<S>` struct + impl
- `tests.rs` (4,779 lines) — all unit tests with explicit imports

Key implementation details:
- `ConnectionState` enum visibility changed to `pub(crate)` (was module-private)
- Test-accessed struct fields marked `pub(super)`: `state`, `cipher_params`, `client_app_secret`, `server_app_secret`, `early_exporter_master_secret`, `early_data_queue`, `key_update_recv_count`, `record_layer`, `session`, `sent_close_notify`, `received_close_notify`
- One private method `handle_post_hs_cert_request` marked `pub(super)` for test access
- Tests dedented by 4 spaces (removed `mod tests { }` wrapper indentation)
- `lib.rs` unchanged — Rust resolves `mod connection;` to `connection/mod.rs` automatically

### Files Modified

| File | Action |
|------|--------|
| `crates/hitls-tls/src/connection.rs` | **DELETED** — replaced by directory |
| `crates/hitls-tls/src/connection/mod.rs` | **NEW** — 19 lines |
| `crates/hitls-tls/src/connection/client.rs` | **NEW** — 894 lines |
| `crates/hitls-tls/src/connection/server.rs` | **NEW** — 829 lines |
| `crates/hitls-tls/src/connection/tests.rs` | **NEW** — 5,603 lines |
| `crates/hitls-tls/src/connection12.rs` | **DELETED** — replaced by directory |
| `crates/hitls-tls/src/connection12/mod.rs` | **NEW** — 23 lines |
| `crates/hitls-tls/src/connection12/client.rs` | **NEW** — 1,147 lines |
| `crates/hitls-tls/src/connection12/server.rs` | **NEW** — 1,048 lines |
| `crates/hitls-tls/src/connection12/tests.rs` | **NEW** — 4,779 lines |
| `crates/hitls-tls/src/lib.rs` | **NO CHANGE** |

### Not Changed (by design)

- `connection_async.rs` (2,129 lines) — Phase R106 will address async code
- `connection12_async.rs` (2,480 lines) — same rationale
- `connection_tlcp.rs` (780 lines) — small enough
- `connection_dtls12.rs` (1,151 lines) — small enough
- `connection_dtlcp.rs` (838 lines) — small enough

### Impact

| Metric | Before | After |
|--------|--------|-------|
| `connection.rs` | 7,324 lines (1 file) | 4 files: mod.rs (19) + client.rs (894) + server.rs (829) + tests.rs (5,603) |
| `connection12.rs` | 7,004 lines (1 file) | 4 files: mod.rs (23) + client.rs (1,147) + server.rs (1,048) + tests.rs (4,779) |
| Largest implementation file | 7,324 lines | 1,147 lines (connection12/client.rs) |
| Total lines | 14,328 | 14,342 (+14 for module headers/imports) |

### Build Status

- `cargo test -p hitls-tls --all-features`: **1164 passed**, 0 failed, 0 ignored
- `cargo test --workspace --all-features`: **2585 passed**, 0 failed, 40 ignored
- `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-features --all-targets`: **0 warnings**
- `cargo fmt --all -- --check`: **clean**
- Public API: **zero changes** — all types re-exported from module root

---

## Phase R105: Hash Digest Enum Dispatch

### Date: 2026-02-22

### Commit: `aa0fd49`

### Goal

Replace `HashFactory = Box<dyn Fn() -> Box<dyn Digest> + Send + Sync>` with stack-allocated enum dispatch, eliminating double heap allocation (boxed closure + boxed trait object) per hash operation in HKDF, PRF, transcript hash, key schedule, and key export code paths.

### Problem

| Pattern | Impact |
|---------|--------|
| `HashFactory` closure | 1 heap alloc per factory creation |
| `factory()` call | 1 heap alloc per `Box<dyn Digest>` |
| HKDF inner loop | 2–3 `factory()` calls per HMAC |
| Key derivation | Multiple HMAC calls per operation |
| Only 4 concrete types used | Sha256, Sha384, Sha1, Sm3 |

### Solution

**1. `HashAlgId`** — lightweight `Copy` enum identifying the hash algorithm:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgId {
    Sha256, Sha384, Sha1,
    #[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
    Sm3,
}
```

**2. `DigestVariant`** — concrete enum wrapping hash implementations:

```rust
pub enum DigestVariant {
    Sha256(Sha256), Sha384(Sha384), Sha1(Sha1),
    #[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
    Sm3(Sm3),
}
```

`DigestVariant` implements the `Digest` trait by delegating to the inner variant. Construction is stack-allocated via `DigestVariant::new(alg)`. Static size lookup via `DigestVariant::output_size_for(alg)`.

**3. `hash_alg_id()` methods** added to `CipherSuiteParams`, `Tls12CipherSuiteParams`, `TlcpCipherSuiteParams`. Also `mac_hash_alg_id()` on `Tls12CipherSuiteParams`.

**4. Migration pattern** applied across all files:
- `factory: &Factory` → `alg: HashAlgId`
- `factory()` / `(*factory)()` → `DigestVariant::new(alg)`
- `TranscriptHash::new(closure)` → `TranscriptHash::new(HashAlgId::Variant)`
- `hash_factory: HashFactory` (stored field) → `hash_alg: HashAlgId`

### Files Modified

| File | Action |
|------|--------|
| `crates/hitls-tls/src/crypt/mod.rs` | Added `HashAlgId`, `DigestVariant`, `hash_alg_id()` methods; removed `HashFactory`, `hash_factory()`, `mac_hash_factory()` |
| `crates/hitls-tls/src/crypt/hkdf.rs` | `&Factory` → `HashAlgId` in 6 functions |
| `crates/hitls-tls/src/crypt/prf.rs` | `&Factory` → `HashAlgId` in 2 functions |
| `crates/hitls-tls/src/crypt/transcript.rs` | Stored closure → `HashAlgId` field |
| `crates/hitls-tls/src/crypt/key_schedule.rs` | Stored `HashFactory` → `HashAlgId` field |
| `crates/hitls-tls/src/crypt/key_schedule12.rs` | `&Factory` → `HashAlgId` in 5 functions |
| `crates/hitls-tls/src/crypt/traffic_keys.rs` | Uses `params.hash_alg_id()` |
| `crates/hitls-tls/src/crypt/export.rs` | `&Factory` → `HashAlgId` in 3 functions |
| `crates/hitls-tls/src/handshake/client*.rs` (5) | Updated TranscriptHash, key derivation, PSK binder callers |
| `crates/hitls-tls/src/handshake/server*.rs` (5) | Updated TranscriptHash, encrypt/decrypt_ticket, key derivation callers |
| `crates/hitls-tls/src/connection/*.rs` (5) | Updated post-HS hashers, export callers |
| `crates/hitls-tls/src/connection_async.rs` | Updated post-HS hashers, export callers |

Total: **24 files**, +633 / −621 lines.

### Not Changed (by design)

- **`hitls-crypto`** crate — No changes. The `Digest` trait and concrete hash structs remain as-is.
- **`hitls-crypto/src/hmac/mod.rs`** — Not touched. The hitls-crypto `Hmac` struct keeps its own factory-based API.
- Any crate outside `hitls-tls`.

### Impact

| Metric | Before | After |
|--------|--------|-------|
| Heap allocs per hash operation | 2 (closure + trait object) | 0 (stack enum) |
| `HashFactory` type | 1 boxed closure type | Removed |
| `hash_factory()` methods | 4 methods returning `Box<dyn Fn>` | Removed |
| `HashAlgId` | N/A | New `Copy` enum |
| `DigestVariant` | N/A | New stack-allocated `Digest` impl |
| Function signatures | `factory: &Factory` | `alg: HashAlgId` (Copy, no ref needed) |

### Build Status

- `cargo test -p hitls-tls --all-features`: **1164 passed**, 0 failed, 0 ignored
- `cargo test --workspace --all-features`: **2585 passed**, 0 failed, 40 ignored
- `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-features --all-targets`: **0 warnings**
- `cargo fmt --all -- --check`: **clean**
- Public API: `HashAlgId` and `DigestVariant` added as new pub types; `HashFactory` removed (was internal)

---

## Phase R106: Sync/Async Unification via Body Macros

**Prompt**: Implement Phase R106 — Sync/Async Unification via Body Macros

**Scope**: Eliminate ~2,900 lines of sync/async code duplication using `macro_rules!` body macros with `maybe_await!` pattern.

**Work performed**:
1. Created `macros.rs` with `maybe_await!` (sync/is_async mode), 18 I/O body macros, 4 accessor macros
2. Refactored TLS 1.3 client: sync (893→197 lines) and async portion of `connection_async.rs`
3. Refactored TLS 1.3 server: sync (828→369 lines) and async portion of `connection_async.rs`
4. Refactored TLS 1.2 client: sync (1,149→1,025 lines) and async portion of `connection12_async.rs`
5. Refactored TLS 1.2 server: sync (1,050→927 lines) and async portion of `connection12_async.rs`
6. Removed 2 duplicate `ConnectionState` enum definitions from async files
7. TLS 1.2 complex methods (do_handshake, renegotiation) kept as-is due to structural differences

**Files modified**: 8 files (1 new + 7 modified), +1,511 / −2,871 lines (net −1,360)

**Result**:
- All 2585 workspace tests pass, 0 clippy warnings, formatting clean.
- Zero public API changes.

---

## Phase R107: X.509 Module Decomposition

### Date: 2026-02-22

### Goal

Split the monolithic `crates/hitls-pki/src/x509/mod.rs` (3,425 lines, 13 logical groups) into 4 focused submodules, improving navigability and reviewability while maintaining zero sibling module impact.

### Problem

The `x509/mod.rs` file contained all X.509 functionality in a single file: core type definitions, extension structs and parsing, DN helpers, ASN.1 parsing helpers, certificate parsing/verification, signature verification, DER encoding, SigningKey abstraction, CSR handling, CertificateBuilder, and 1,443 lines of tests.

### Solution

Created 4 new submodules with a clear dependency graph (no cycles):

| File | Lines | Contents |
|------|-------|----------|
| `x509/signing.rs` | 330 | `HashAlg`, `compute_hash`, 6 `verify_*` functions, `SigningKey` enum + impl, `curve_id_to_oid`, `ALG_PARAMS_NULL` |
| `x509/certificate.rs` | 628 | 5 core type structs, DN helpers, 5 ASN.1 parsing helpers, Certificate/CSR parsing & verification |
| `x509/extensions.rs` | 519 | 12 extension type structs, 11 parsing functions, 10 Certificate convenience methods |
| `x509/builder.rs` | 526 | 6 DER encoding helpers, `CertificateRequestBuilder`, `CertificateBuilder` + Default |
| `x509/mod.rs` | 1,516 | Module declarations, pub + pub(crate) re-exports, 1,443 lines of tests |

Dependency graph: `signing.rs` → no sibling deps; `certificate.rs` → `signing`; `extensions.rs` → `certificate`; `builder.rs` → all three.

All `pub(crate)` items used by sibling modules (`crl.rs`, `ocsp.rs`, `verify.rs`, `text.rs`, `hostname.rs`) are re-exported from mod.rs, requiring zero import changes in those files.

### Files Modified

| File | Action |
|------|--------|
| `crates/hitls-pki/src/x509/signing.rs` | **NEW** — 330 lines |
| `crates/hitls-pki/src/x509/certificate.rs` | **NEW** — 628 lines |
| `crates/hitls-pki/src/x509/extensions.rs` | **NEW** — 519 lines |
| `crates/hitls-pki/src/x509/builder.rs` | **NEW** — 526 lines |
| `crates/hitls-pki/src/x509/mod.rs` | Modified — 3,425 → 1,516 lines |

### Impact

| Metric | Before | After |
|--------|--------|-------|
| Largest file (x509/mod.rs) | 3,425 lines | 1,516 lines |
| Total files in x509/ | 6 | 10 |
| Sibling module changes | — | 0 |
| Public API changes | — | 0 |

### Build Status
- `cargo test -p hitls-pki --all-features`: 349 passed, 0 failed, 1 ignored
- `cargo test --workspace --all-features`: 2585 passed, 0 failed, 40 ignored
- `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-features --all-targets`: 0 warnings
- `cargo fmt --all -- --check`: clean

---

## Refactoring Queue

The following phases are defined in [ARCH_REPORT.md](ARCH_REPORT.md) §7 and have not yet been started:

| Phase | Title | Priority | Status |
|-------|-------|----------|--------|
| Phase R102 | PKI Encoding Consolidation | Critical | **Done** |
| Phase R103 | Record Layer Enum Dispatch | High | **Done** |
| Phase R104 | Connection File Decomposition | High | **Done** |
| Phase R105 | Hash Digest Enum Dispatch | Medium | **Done** |
| Phase R106 | Sync/Async Unification via Macros | Medium | **Done** |
| Phase R107 | X.509 Module Decomposition | Medium | **Done** |
| Phase R108 | Integration Test Modularization | Medium | Pending |
| Phase R109 | Test Helper Consolidation | Low | Pending |
| Phase R110 | Parameter Struct Refactoring | Low | Pending |
| Phase R111 | DRBG State Machine Unification | Low | Pending |

**Recommended execution order**: R107 → R108 → R109 → R110 → R111 → R106
