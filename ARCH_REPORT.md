# Architecture Analysis Report — openHiTLS-rs

> Generated: 2026-02-20 | Branch: `refactoring` | Commit: `33eae3a`

---

## 1. Executive Summary

openHiTLS-rs is a 121,589-line pure Rust rewrite of the C-based openHiTLS library, organized as a Cargo workspace with 8 crates. The codebase has achieved 100% C-to-Rust feature parity with 2,544 tests passing, zero clippy warnings, and comprehensive algorithm coverage spanning classical, modern, and post-quantum cryptography.

**Architecture Verdict**: The codebase has a clean layered dependency hierarchy with no circular dependencies and strong security practices (zeroize, constant-time, minimal unsafe). However, rapid feature-parity development has introduced significant structural debt: code duplication across protocol variants (~6,000+ lines of sync/async mirroring), PKI encoding helper proliferation (24 duplicated functions), oversized monolithic files (7,324-line connection.rs), and double-indirection dynamic dispatch in cryptographic hot paths. A targeted refactoring effort can reduce total code volume by an estimated 8-12% while improving maintainability and performance.

---

## 2. Codebase Metrics

### 2.1 Overall Statistics

| Metric | Value |
|--------|-------|
| Total Rust source files | 228 |
| Total lines of code | 121,589 |
| Workspace crates | 8 + integration test crate |
| External dependencies | 11 unique |
| Feature flags | 50+ |
| Test count | 2,544 (40 ignored) |
| Fuzz targets | 10 |
| Benchmark groups | 8 |
| Unsafe blocks | 16 (confined to 3 files) |
| Dynamic dispatch sites | 129 `Box<dyn ...>` |
| Suppressed warnings | 47 `#[allow(...)]` |

### 2.2 Per-Crate Size Distribution

| Crate | Files | Lines | % of Total | Tests |
|-------|-------|-------|------------|-------|
| hitls-tls | 55 | 60,950 | 50.1% | 1,156 |
| hitls-crypto | 120 | 36,066 | 29.7% | 619 + 15 Wycheproof |
| hitls-pki | 13 | 14,487 | 11.9% | 349 |
| hitls-cli | 17 | 3,618 | 3.0% | 117 |
| hitls-bignum | 8 | 1,934 | 1.6% | 49 |
| hitls-utils | 8 | 1,864 | 1.5% | 53 |
| hitls-auth | 4 | 1,577 | 1.3% | 33 |
| hitls-types | 3 | 1,093 | 0.9% | — |
| tests/interop | 1 | 7,675 | — | 125 |

### 2.3 Top 15 Largest Files

| File | Lines | Concern |
|------|-------|---------|
| `hitls-tls/src/connection.rs` | 7,324 | TLS 1.3 sync connection |
| `hitls-tls/src/connection12.rs` | 7,004 | TLS 1.2 sync connection |
| `tests/interop/src/lib.rs` | 7,675 | All integration tests |
| `hitls-pki/src/x509/mod.rs` | 3,441 | X.509 certificate core |
| `hitls-tls/src/handshake/server12.rs` | 2,668 | TLS 1.2 server state machine |
| `hitls-pki/src/cms/mod.rs` | 2,555 | CMS SignedData/AuthData |
| `hitls-tls/src/connection12_async.rs` | 2,480 | TLS 1.2 async connection |
| `hitls-tls/src/handshake/extensions_codec.rs` | 2,454 | Extension codec (all versions) |
| `hitls-tls/src/config/mod.rs` | 2,191 | Config builder + callbacks |
| `hitls-tls/src/handshake/client12.rs` | 2,175 | TLS 1.2 client state machine |
| `hitls-pki/src/x509/verify.rs` | 2,138 | Certificate chain verification |
| `hitls-tls/src/connection_async.rs` | 1,954 | TLS 1.3 async connection |
| `hitls-tls/src/crypt/mod.rs` | 1,889 | Crypto params & enums |
| `hitls-tls/src/connection_dtls12_async.rs` | 1,755 | DTLS 1.2 async connection |
| `hitls-tls/src/handshake/codec12.rs` | 1,726 | TLS 1.2 handshake codec |

---

## 3. Workspace Architecture

### 3.1 Dependency Graph

```
                    hitls-types (foundation)
                   /     |      \
                  /      |       \
           hitls-utils  hitls-bignum
                |  \      |
                |   \     |
              hitls-crypto (feature-gated, optional deps on bignum/utils)
               /    |     \
              /     |      \
        hitls-pki hitls-tls hitls-auth
              \     |      /
               \    |     /
               hitls-cli (facade)
                    |
             tests/interop (all crates)
```

**Layers**:
1. **Foundation**: `hitls-types` (algorithm IDs, error enums) — 0 internal deps
2. **Utilities**: `hitls-utils` (ASN.1, Base64, PEM, OID), `hitls-bignum` (big integer math)
3. **Cryptography**: `hitls-crypto` (48 algorithm modules, 36 feature flags)
4. **Protocol**: `hitls-tls` (5 TLS protocol variants), `hitls-pki` (X.509/CMS/PKCS)
5. **Application**: `hitls-auth` (OTP/SPAKE2+/PrivacyPass), `hitls-cli` (14 commands)

**Key Properties**:
- No circular dependencies
- Clean unidirectional flow: foundation → utilities → crypto → protocol → application
- Optional crate dependencies in `hitls-crypto` (bignum/utils only pulled when needed)
- Feature flags propagate through dependency chain (e.g., `hitls-tls/tlcp` enables `hitls-crypto/sm2,sm3,sm4`)

### 3.2 External Dependencies

| Dependency | Version | Used By | Purpose |
|------------|---------|---------|---------|
| thiserror | 2 | hitls-types | Error derive macros |
| zeroize | 1.8 | bignum, crypto, tls, pki, auth | Secret material cleanup |
| subtle | 2.5–2.6 | bignum, crypto, tls, auth | Constant-time operations |
| getrandom | 0.2 | bignum, crypto, tls, pki, auth, cli | Secure RNG |
| log | 0.4 | tls | Logging framework |
| flate2 | 1.0 | tls (optional) | Certificate compression |
| tokio | 1.0 | tls (optional), tests | Async runtime |
| clap | 4.0 | cli | CLI argument parsing |
| criterion | 0.5 | crypto (dev) | Benchmarks |
| serde | 1.0 | crypto (dev) | Test vector deserialization |
| serde_json | 1.0 | crypto (dev) | Wycheproof JSON parsing |

**Notable**: `subtle` version mismatch — hitls-auth uses 2.5, all others use 2.6.

---

## 4. Per-Crate Architecture Analysis

### 4.1 hitls-crypto (36,066 lines, 120 files)

**Module Categories** (9 categories, 44 modules):

| Category | Modules | Lines | Key Patterns |
|----------|---------|-------|--------------|
| Hash | SHA-1/2/3, MD5, SM3 | ~2,800 | `Digest` trait: `update()`, `finish()`, `reset()` |
| Symmetric | AES, SM4, ChaCha20 | ~2,400 | `BlockCipher` trait + hardware dispatch (AES-NI/NEON) |
| Modes | CBC/CTR/GCM/CCM/XTS/HCTR/Wrap | ~2,600 | Generic `<C: BlockCipher>` bounds |
| MAC | HMAC/CMAC/GMAC/CBC-MAC/SipHash | ~1,100 | `Mac` trait; HMAC uses `Box<dyn Fn() -> Box<dyn Digest>>` factory |
| Asymmetric | RSA/ECC/ECDSA/ECDH/DSA/Ed25519/Ed448/X25519/X448 | ~6,500 | `Signer`/`Verifier`/`KeyAgreement` traits |
| PQC | ML-KEM/ML-DSA/SLH-DSA/XMSS/FrodoKEM/McEliece/HybridKEM | ~8,000 | `Kem` trait; NTT-based polynomial arithmetic |
| Pairing | SM9 | ~2,300 | Field tower: Fp → Fp2 → Fp4 → Fp12 |
| KDF/DRBG | HKDF/PBKDF2/Scrypt/CTR-DRBG/HMAC-DRBG/Hash-DRBG | ~2,600 | `Kdf` trait; 4 independent DRBG implementations |
| FIPS/Entropy | FIPS state machine, KAT, PCT, health testing | ~1,700 | State machine: PreOperational → SelfTesting → Operational |

**Core Traits** (`provider.rs`, 145 lines — 11 traits):
- `Digest`, `HashAlgorithm` (hashing)
- `BlockCipher`, `Aead` (symmetric)
- `Mac` (message authentication)
- `Kdf`, `KeyAgreement` (key derivation/exchange)
- `Signer`, `Verifier` (asymmetric signatures)
- `Kem` (key encapsulation)
- `NoiseSource` (entropy)

**Feature Flag Architecture**: 36 features with dependency chains. Default: `aes`, `sha2`, `rsa`, `ecdsa`, `hmac`. The `fips` meta-feature enables 10 features required for FIPS compliance.

**Unsafe Code**: 16 blocks confined to `aes/aes_ni.rs` (8), `aes/aes_neon.rs` (6), `mceliece/benes.rs` (2). All for hardware intrinsics or type reinterpretation.

### 4.2 hitls-tls (60,950 lines, 55 files)

**Architecture Overview**: Supports 5 protocol variants (TLS 1.3, TLS 1.2, DTLS 1.2, TLCP, DTLCP) with 10 sync + 5 async connection types. The crate represents 50% of total codebase.

**Major Subsystems**:

| Subsystem | Files | Lines | Design |
|-----------|-------|-------|--------|
| Connection layer | 10 | ~28,000 | Concrete types per protocol × sync/async |
| Handshake | 18 | ~21,400 | State machine per protocol × client/server |
| Record layer | 9 | ~5,900 | Polymorphic encryptor/decryptor |
| Crypto params | 10 | ~5,600 | AEAD, key schedule, PRF, HKDF, transcript |
| Config | 1 | 2,191 | Builder pattern with 10+ callback types |
| Extensions | 1 | 369 | 15+ standard extensions + custom framework |
| Session | 1 | 809 | `SessionCache` trait + in-memory impl |
| Alert | 1 | 368 | RFC-compliant alert codes |

**State Machine Design**:
- Each protocol variant × role (client/server) has its own state enum
- TLS 1.3 client: Idle → WaitServerHello → WaitEncryptedExtensions → WaitCertCertReq → WaitCertVerify → WaitFinished → Connected
- TLS 1.2 adds renegotiation states
- DTLS adds retransmission and cookie exchange states

**Record Layer Polymorphism** (design concern):
```rust
pub struct RecordLayer {
    encryptor: Option<RecordEncryptor>,           // TLS 1.3
    encryptor12: Option<RecordEncryptor12>,       // TLS 1.2 AEAD
    encryptor12_cbc: Option<RecordEncryptor12Cbc>,// TLS 1.2 CBC
    encryptor12_etm: Option<RecordEncryptor12EtM>,// TLS 1.2 EtM
    encryptor_tlcp: Option<TlcpEncryptor>,        // TLCP
    // ... plus matching decryptor fields
}
```
Uses "one active slot" pattern with `Option<T>` fields — at most one pair is `Some` at any time. This results in a wide struct where most fields are `None`.

**Callback Architecture**: 10 callback types configured via `TlsConfigBuilder`:
- PSK, SNI, certificate verify, key log, session ticket
- Client hello observer, protocol message observer, security callback
- Custom extension add/parse, record padding

### 4.3 hitls-pki (14,487 lines, 13 files)

**Module Breakdown**:

| Module | Lines | Responsibility |
|--------|-------|---------------|
| x509/mod.rs | 3,441 | Certificate parsing, building, signing, extension methods |
| x509/verify.rs | 2,138 | Chain building, pathLen, KeyUsage, revocation checks |
| x509/ocsp.rs | 1,071 | OCSP request/response parsing |
| x509/text.rs | 606 | Human-readable certificate display |
| x509/hostname.rs | 381 | RFC 6125/9525 hostname verification |
| x509/crl.rs | 712 | CRL parsing and validation |
| cms/mod.rs | 2,555 | CMS message types (SignedData, AuthenticatedData, DigestedData) |
| cms/enveloped.rs | 1,068 | EnvelopedData (RSA-OAEP + AES-GCM) |
| cms/encrypted.rs | 379 | EncryptedData (AES-CBC) |
| pkcs8/mod.rs | 860 | Private key parsing/encoding (7 key types) |
| pkcs8/encrypted.rs | 315 | Encrypted PKCS#8 (PBES2) |
| pkcs12/mod.rs | 947 | PKCS#12 container parsing |

**Parsing Pattern**: All modules use `hitls_utils::asn1::Decoder` for DER parsing and `Encoder` for DER construction. OID-based dispatch for algorithm selection.

**Key Abstractions**:
- `Certificate` struct with lazy extension accessors (`.basic_constraints()`, `.key_usage()`, etc.)
- `CertificateVerifier` for chain validation with configurable trust anchors
- `SigningKey` enum for unified signing across algorithms
- `Pkcs8PrivateKey` enum for multi-algorithm key container

### 4.4 hitls-types (1,093 lines, 3 files)

Foundation crate providing:
- `HashAlgId`, `MacAlgId`, `CipherAlgId`, `PkeyAlgId`, `EccCurveId` — type-safe algorithm selection enums
- `CryptoError`, `TlsError`, `PkiError`, `CmvpError` — thiserror-based error hierarchies
- Zero dependencies beyond `thiserror`; `#![forbid(unsafe_code)]`

### 4.5 hitls-utils (1,864 lines, 8 files)

Utility crate providing:
- **ASN.1**: Zero-copy `Decoder<'a>` (borrowed) + builder `Encoder` (owned)
- **OID**: `Oid` struct with 40+ well-known OID constants
- **Base64**: `encode()`/`decode()`
- **PEM**: `PemBlock` parsing/encoding
- Feature-gated: `asn1`, `base64`, `pem`, `oid` (all default)

### 4.6 hitls-bignum (1,934 lines, 8 files)

Big number arithmetic with:
- Little-endian `Vec<Limb>` (u64) representation
- Montgomery multiplication context
- Miller-Rabin primality testing
- `#[derive(Zeroize)]` + `#[zeroize(drop)]` on all types
- Constant-time comparison via `subtle`

### 4.7 hitls-auth (1,577 lines, 4 files)

Authentication protocols:
- **HOTP/TOTP** (RFC 4226/6238): Time-based and counter-based OTP
- **SPAKE2+** (RFC 9382): Password-authenticated key exchange on P-256
- **Privacy Pass** (RFC 9578 Type 2): RSA blind signature-based tokens

### 4.8 hitls-cli (3,618 lines, 17 files)

CLI facade with 16 commands (dgst, enc, genpkey, x509, verify, pkey, crl, req, s-client, s-server, list, rand, pkeyutl, speed, pkcs12, mac). Each command is an independent module with `pub fn run(...)` entry point. Uses `clap` with derive macros.

---

## 5. Cross-Cutting Architectural Patterns

### 5.1 Error Handling

```
CryptoError (hitls-types) ──── used by: crypto, bignum, utils
TlsError (hitls-types)    ──── used by: tls
PkiError (hitls-types)    ──── used by: pki
CmvpError (hitls-types)   ──── used by: crypto/fips

hitls-cli uses Box<dyn std::error::Error> (generic)
```

All errors derive from `thiserror`. Cross-crate error conversion uses `impl From<CryptoError> for TlsError` etc. The CLI crate's use of `Box<dyn std::error::Error>` loses type information — acceptable for a CLI tool.

### 5.2 Security Discipline

| Practice | Implementation | Coverage |
|----------|---------------|----------|
| Zeroize on drop | `#[derive(Zeroize)]` + `#[zeroize(drop)]` | 58 types across crypto, bignum, tls, auth |
| Constant-time comparison | `subtle::ConstantTimeEq` | 18 call sites (MAC verify, signature verify, SPAKE2+) |
| No unsafe | `#![forbid(unsafe_code)]` | types, utils, auth, tls, pki (5 of 8 crates) |
| Minimal unsafe | 16 blocks in 3 files | AES-NI, AES-NEON, McEliece Benes network |
| Secure RNG | `getrandom` crate only | All key generation and nonce creation |

### 5.3 Feature Flag Architecture

The feature flag system enables fine-grained algorithm selection:

```
hitls-crypto features (36):
├── Symmetric: aes*, sm4, chacha20
├── Hash: md5, sha1, sha2*, sha3, sm3
├── MAC: hmac*, cmac→aes, cbc-mac→sm4, gmac→aes+modes, siphash
├── Asymmetric: rsa*→bignum, dsa→bignum+utils, ecc→bignum, ecdsa*→ecc+utils,
│               ecdh→ecc, dh→bignum, ed25519→sha2+bignum, ed448→sha3+bignum,
│               x25519, x448, sm2→ecc+sm3+utils, sm9→ecc+sm3
├── PQC: mlkem→sha3, mldsa→sha3, slh-dsa→sha2+sha3+hmac, xmss→sha2+sha3,
│         frodokem→sha3+aes, mceliece→sha3, hybridkem→x25519+mlkem+sha2
├── KDF: hkdf→hmac, pbkdf2→hmac, scrypt→pbkdf2, hpke→hkdf+x25519+sha2+aes+modes
├── DRBG: drbg→hmac+sha2+aes
├── Compliance: fips→sha2+hmac+aes+modes+drbg+rsa+ecdsa+ed25519+hkdf+entropy
└── Other: modes→aes, entropy→sha2, hazmat

(* = default feature)
```

hitls-tls features propagate crypto requirements:
- `tlcp` → `hitls-crypto/{sm2,sm3,sm4}`
- `sm_tls13` → `hitls-crypto/{sm3,sm4}`
- `async` → `tokio`
- `cert-compression` → `flate2`

### 5.4 Test Infrastructure

| Layer | Location | Count | Pattern |
|-------|----------|-------|---------|
| Unit tests | Inline `#[cfg(test)]` per module | ~2,400 | Standard Rust pattern |
| Integration tests | `tests/interop/src/lib.rs` (monolithic) | 125 | Cross-crate TCP loopback |
| Test vectors | `tests/vectors/` (148 files) | ~15 | NIST, Wycheproof, GM/T |
| Fuzz targets | `fuzz/fuzz_targets/` | 10 | cargo-fuzz (parsing focus) |
| Benchmarks | `crates/hitls-crypto/benches/` | 8 groups | Criterion.rs |

---

## 6. Architectural Issues & Technical Debt

### Issue 1: PKI Encoding Helper Duplication (Critical)

**Impact**: 24 duplicated functions across 3 files in hitls-pki

The following helper functions are independently reimplemented in `pkcs12/mod.rs`, `x509/ocsp.rs`, and `cms/mod.rs`:

| Function | Copies | Combined LOC |
|----------|--------|-------------|
| `enc_seq()` | 3 | ~18 |
| `enc_set()` | 2 | ~12 |
| `enc_octet()` | 3 | ~18 |
| `enc_oid()` | 3 | ~18 |
| `enc_int()` | 3 | ~18 |
| `enc_null()` | 2 | ~12 |
| `enc_tlv()` | 3 | ~18 |
| `enc_explicit_ctx()` | 2 | ~12 |
| `bytes_to_u32()` | 5 | ~15 |
| `oid_to_curve_id()` | 3 | ~60 |

**Root Cause**: Each PKI module was developed independently without a shared encoding utility layer.

### Issue 2: Sync/Async Connection Duplication (High)

**Impact**: ~6,189 lines of near-duplicate code

| Sync File | Lines | Async Mirror | Lines | Delta |
|-----------|-------|-------------|-------|-------|
| `connection.rs` | 7,324 | `connection_async.rs` | 1,954 | +async/.await |
| `connection12.rs` | 7,004 | `connection12_async.rs` | 2,480 | +async/.await |
| `connection_dtls12.rs` | 1,151 | `connection_dtls12_async.rs` | 1,755 | +async/.await |

The async variants largely replicate sync logic with `async`/`.await` additions. No shared abstraction exists between sync and async implementations.

### Issue 3: Protocol Variant Proliferation (High)

**Impact**: Parallel implementations across 5 protocol variants

Record encryption (6 files, ~4,274 lines):
- `encryption.rs` (TLS 1.3) — 590 lines
- `encryption12.rs` (TLS 1.2 AEAD) — 1,352 lines
- `encryption12_cbc.rs` (TLS 1.2 CBC) — 745 lines
- `encryption_dtls12.rs` (DTLS 1.2) — 291 lines
- `encryption_tlcp.rs` (TLCP) — 629 lines
- `encryption_dtlcp.rs` (DTLCP) — 667 lines

Handshake state machines (10 files, ~12,778 lines):
- TLS 1.3 client/server: 3,543 lines
- TLS 1.2 client/server: 4,843 lines
- DTLS 1.2 client/server: 2,057 lines
- TLCP client/server: 1,016 lines
- DTLCP client/server: 1,319 lines

Handshake codecs (4 files, ~6,111 lines):
- `codec.rs` (TLS 1.3) — 1,382 lines
- `codec12.rs` (TLS 1.2) — 1,726 lines
- `codec_dtls.rs` (DTLS) — 589 lines
- `codec_tlcp.rs` (TLCP) — 413 lines
- `extensions_codec.rs` (shared) — 2,454 lines (already unified)

Shared patterns across variants: certificate handling, key exchange flow, message construction, error handling. Many differ only in wire format details, optional fields, and validation rules.

### Issue 4: Oversized Files (Medium)

7 files exceed 2,000 lines — these are difficult to navigate, review, and test:

| File | Lines | Suggestion |
|------|-------|-----------|
| `connection.rs` | 7,324 | Split into connection lifecycle, I/O, handshake orchestration |
| `connection12.rs` | 7,004 | Same as above |
| `x509/mod.rs` | 3,441 | Split parsing, building, signing, extensions into submodules |
| `handshake/server12.rs` | 2,668 | Extract certificate handling, key exchange into helpers |
| `cms/mod.rs` | 2,555 | Split by CMS content type |
| `extensions_codec.rs` | 2,454 | Split into per-extension codecs |
| `config/mod.rs` | 2,191 | Extract callback types and validation |

### Issue 5: Dynamic Dispatch in Hot Paths (Medium)

**Impact**: Double indirection in cryptographic operations

```rust
// HMAC factory pattern — double Box allocation on every reset
pub struct Hmac {
    inner: Box<dyn Digest>,
    outer: Box<dyn Digest>,
    factory: Box<dyn Fn() -> Box<dyn Digest>>,  // allocates on reset
}

// TLS PRF/key derivation uses this pattern repeatedly
pub fn create_hash_factory(hash_alg: HashAlgId) -> Box<dyn Fn() -> Box<dyn Digest>>
```

The `Box<dyn Fn() -> Box<dyn Digest>>` factory creates a new heap allocation for every HMAC reset during key derivation. In a TLS handshake, key schedule computation calls this pattern dozens of times.

### Issue 6: RecordLayer Struct Width (Medium)

The `RecordLayer` struct holds 10+ `Option<T>` fields for different encryptor/decryptor variants, but only one pair is active at any time:

```rust
pub struct RecordLayer {
    encryptor: Option<RecordEncryptor>,
    decryptor: Option<RecordDecryptor>,
    encryptor12: Option<RecordEncryptor12>,
    decryptor12: Option<RecordDecryptor12>,
    encryptor12_cbc: Option<RecordEncryptor12Cbc>,
    decryptor12_cbc: Option<RecordDecryptor12Cbc>,
    encryptor12_etm: Option<RecordEncryptor12EtM>,
    decryptor12_etm: Option<RecordDecryptor12EtM>,
    encryptor_tlcp: Option<TlcpEncryptor>,
    decryptor_tlcp: Option<TlcpDecryptor>,
}
```

This wastes memory (many None fields) and requires runtime checks to determine which variant is active. An enum-based approach would be more idiomatic and memory-efficient.

### Issue 7: Monolithic Integration Test File (Medium)

`tests/interop/src/lib.rs` is a single 7,675-line file containing all 125 integration tests. This makes it difficult to run subsets, locate tests, and maintain.

### Issue 8: Test Helper Duplication (Low)

`fn hex(s: &str) -> Vec<u8>` is independently defined 43 times across the codebase. `fn to_hex(bytes: &[u8]) -> String` appears 10 times. While test-only, this adds maintenance burden.

### Issue 9: DRBG Implementation Redundancy (Low)

Four DRBG variants (CTR-DRBG, SM4-CTR-DRBG, HMAC-DRBG, Hash-DRBG) share a common state machine pattern (instantiate → generate → reseed) but are implemented independently (~1,534 lines total). A shared state machine abstraction could reduce duplication.

### Issue 10: Suppressed Warnings (Low)

47 `#[allow(...)]` attributes, including:
- 13 `dead_code` — may indicate unused code from protocol variant structs
- 8 `too_many_arguments` — functions that should take parameter structs
- 6 `type_complexity` — complex callback types that could be type-aliased

---

## 7. Refactoring Plan

### Phase R1: PKI Encoding Consolidation (Priority: Critical)

**Goal**: Eliminate 24 duplicated ASN.1 encoding helpers and 5 duplicated utility functions

**Changes**:

1. **Create `hitls-pki/src/encoding.rs`** — shared encoding helper module
   - Move `enc_seq()`, `enc_set()`, `enc_octet()`, `enc_oid()`, `enc_int()`, `enc_null()`, `enc_tlv()`, `enc_explicit_ctx()` into this module
   - Add `bytes_to_u32()` utility
   - Export as `pub(crate) mod encoding`

2. **Create `hitls-pki/src/oid_mapping.rs`** — unified OID-to-algorithm mapping
   - Consolidate 3 `oid_to_curve_id()` implementations
   - Core function returns `Option<EccCurveId>`, callers wrap in their error types
   - Add `oid_to_hash_alg()`, `oid_to_sig_alg()` if similar duplication exists

3. **Update all PKI modules** to use shared helpers:
   - `pkcs12/mod.rs`: Replace local `enc_*` functions with `use crate::encoding::*`
   - `x509/ocsp.rs`: Same
   - `cms/mod.rs`, `cms/enveloped.rs`, `cms/encrypted.rs`: Same
   - `pkcs8/encrypted.rs`: Replace local `bytes_to_u32()`

**Estimated Impact**: ~200 lines removed, 0 API changes, 0 behavior changes

**Risk**: Low — internal refactoring only, no public API changes

### Phase R2: Record Layer Enum Dispatch (Priority: High)

**Goal**: Replace `Option<T>` field proliferation with type-safe enum dispatch

**Changes**:

1. **Define `RecordEncryptorVariant` enum**:
   ```rust
   pub(crate) enum RecordEncryptorVariant {
       Tls13(RecordEncryptor),
       Tls12Aead(RecordEncryptor12),
       Tls12Cbc(RecordEncryptor12Cbc),
       Tls12EtM(RecordEncryptor12EtM),
       Tlcp(TlcpEncryptor),
       Dtls12(DtlsRecordEncryptor12),
       Dtlcp(DtlcpRecordEncryptor),
   }
   ```

2. **Simplify `RecordLayer`**:
   ```rust
   pub struct RecordLayer {
       encryptor: Option<RecordEncryptorVariant>,
       decryptor: Option<RecordDecryptorVariant>,
   }
   ```

3. **Implement shared `encrypt`/`decrypt` dispatch** on the enum variants

**Estimated Impact**: ~300 lines reduced, memory per connection reduced, cleaner control flow

**Risk**: Medium — requires updating all record layer callers

### Phase R3: Connection File Decomposition (Priority: High)

**Goal**: Split the two largest files (7,324 + 7,004 lines) into manageable modules

**Changes for `connection.rs`** (TLS 1.3):
1. `connection/tls13/mod.rs` — `TlsClientConnection`, `TlsServerConnection` structs + constructors
2. `connection/tls13/handshake.rs` — Handshake orchestration logic
3. `connection/tls13/io.rs` — `read()`, `write()`, `shutdown()` implementations
4. `connection/tls13/state.rs` — Connection state transitions
5. `connection/tls13/cert.rs` — Certificate processing and verification

**Same pattern for `connection12.rs`** (TLS 1.2):
1. `connection/tls12/mod.rs`, `handshake.rs`, `io.rs`, `state.rs`, `cert.rs`

**Estimated Impact**: 0 lines removed but improved navigability. Each file under 2,000 lines.

**Risk**: Low — pure structural reorganization, no logic changes

### Phase R4: Hash Digest Enum Dispatch (Priority: Medium)

**Goal**: Replace `Box<dyn Digest>` + factory closure with enum dispatch for known hash algorithms

**Changes**:

1. **Define `DigestEnum`**:
   ```rust
   pub(crate) enum DigestEnum {
       Sha256(Sha256),
       Sha384(Sha384),
       Sha512(Sha512),
       Sm3(Sm3),
       // ... other hash algorithms
   }
   ```

2. **Implement `Digest` trait on `DigestEnum`** with match dispatch

3. **Replace `Box<dyn Fn() -> Box<dyn Digest>>`** with `HashAlgId` + `DigestEnum::new(alg)`:
   ```rust
   pub struct Hmac {
       inner: DigestEnum,
       outer: DigestEnum,
       hash_alg: HashAlgId,  // for reset/clone
       key_block: Vec<u8>,
   }
   ```

4. **Update HMAC, TLS PRF, HKDF, transcript hash** to use enum dispatch

**Estimated Impact**: Eliminates heap allocation per hash operation in hot paths. ~100 lines changed.

**Risk**: Medium — touches core crypto infrastructure. Requires careful testing.

### Phase R5: Sync/Async Unification via Macros (Priority: Medium)

**Goal**: Reduce ~6,189 lines of sync/async duplication

**Approach**: Use a declarative macro to generate both sync and async variants from a single implementation.

**Changes**:

1. **Create `connection/macros.rs`** with a `define_connection!` macro:
   ```rust
   macro_rules! define_connection {
       (sync, $name:ident, $transport:ty, ...) => { /* sync impl */ };
       (async, $name:ident, $transport:ty, ...) => { /* async impl */ };
   }
   ```

2. **Extract shared connection logic** into a `ConnectionCore<T>` struct that handles state, config, record layer, and handshake — parameterized by transport type

3. **Thin sync/async wrappers** call into `ConnectionCore` methods

**Estimated Impact**: ~3,000-4,000 lines removed

**Risk**: High — significant structural change. Macro complexity. Must maintain feature parity. Consider as a multi-iteration effort.

### Phase R6: X.509 Module Decomposition (Priority: Medium)

**Goal**: Split `x509/mod.rs` (3,441 lines) into focused submodules

**Changes**:
1. `x509/certificate.rs` — `Certificate` struct, DER/PEM parsing, accessor methods
2. `x509/builder.rs` — `CertificateBuilder`, `CertificateRequestBuilder`
3. `x509/signing.rs` — `SigningKey` enum, `verify_signature()` implementations
4. `x509/extensions.rs` — Extension parsing helpers, extension type definitions
5. `x509/mod.rs` — Re-exports only

**Estimated Impact**: Improved navigability. Each file under 1,000 lines.

**Risk**: Low — pure structural reorganization

### Phase R7: Integration Test Modularization (Priority: Medium)

**Goal**: Split monolithic 7,675-line test file into focused test modules

**Changes**:
1. `tests/interop/src/lib.rs` — Only shared test helpers and re-exports
2. `tests/interop/tests/tls13.rs` — TLS 1.3 handshake and connection tests
3. `tests/interop/tests/tls12.rs` — TLS 1.2 handshake and connection tests
4. `tests/interop/tests/dtls12.rs` — DTLS 1.2 tests
5. `tests/interop/tests/tlcp.rs` — TLCP/DTLCP tests
6. `tests/interop/tests/pki.rs` — PKI/X.509 chain tests
7. `tests/interop/tests/crypto.rs` — Cross-crate crypto tests
8. `tests/interop/tests/extensions.rs` — Extension and callback tests
9. `tests/interop/tests/async_io.rs` — Async connection tests

**Estimated Impact**: Better test organization, ability to run targeted test subsets

**Risk**: Low — test-only change

### Phase R8: Test Helper Consolidation (Priority: Low)

**Goal**: Eliminate 53 duplicated `hex()`/`to_hex()` test helpers

**Changes**:
1. **Add `hitls-utils/src/hex.rs`** with `pub fn hex(s: &str) -> Vec<u8>` and `pub fn to_hex(bytes: &[u8]) -> String`
2. **Update all test modules** to use `hitls_utils::hex::*` (or a `#[cfg(test)]` re-export)
3. Alternatively, create a `hitls-test-utils` workspace crate for shared test infrastructure

**Estimated Impact**: ~200 lines removed across 53 call sites

**Risk**: Low — test-only change

### Phase R9: Parameter Struct Refactoring (Priority: Low)

**Goal**: Address 8 `too_many_arguments` suppressions

**Changes**: For each function with 7+ parameters, introduce a parameter struct:
```rust
// Before:
fn process_handshake(config: &TlsConfig, state: &mut State,
    record: &Record, transcript: &mut Transcript,
    key_schedule: &mut KeySchedule, extensions: &Extensions,
    cert_chain: &[Certificate], session: &mut Session) -> Result<()>

// After:
struct HandshakeContext<'a> {
    config: &'a TlsConfig,
    state: &'a mut State,
    transcript: &'a mut Transcript,
    key_schedule: &'a mut KeySchedule,
    // ...
}
fn process_handshake(ctx: &mut HandshakeContext, record: &Record) -> Result<()>
```

**Estimated Impact**: Improved readability. Remove `#[allow(clippy::too_many_arguments)]`.

**Risk**: Low — localized changes

### Phase R10: DRBG State Machine Unification (Priority: Low)

**Goal**: Extract shared DRBG lifecycle (instantiate/generate/reseed) into a common abstraction

**Changes**:
1. **Define `DrbgCore` trait**:
   ```rust
   trait DrbgCore {
       fn instantiate(&mut self, entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Result<()>;
       fn generate_internal(&mut self, output: &mut [u8], additional: &[u8]) -> Result<()>;
       fn reseed_internal(&mut self, entropy: &[u8], additional: &[u8]) -> Result<()>;
   }
   ```

2. **Implement `Drbg<C: DrbgCore>`** wrapper with shared lifecycle management (reseed counter, prediction resistance, health checks)

3. **Implement `DrbgCore` for each variant**: CtrDrbgCore, HmacDrbgCore, HashDrbgCore, Sm4CtrDrbgCore

**Estimated Impact**: ~300 lines reduced, unified DRBG behavior guarantees

**Risk**: Medium — touches security-critical code. Requires thorough testing.

---

## 8. Refactoring Priority Summary

| Phase | Priority | Risk | Est. Lines Saved | Dependencies |
|-------|----------|------|-------------------|-------------|
| R1: PKI Encoding Consolidation | Critical | Low | ~200 | None |
| R2: Record Layer Enum Dispatch | High | Medium | ~300 | None |
| R3: Connection File Decomposition | High | Low | 0 (structural) | None |
| R4: Hash Digest Enum Dispatch | Medium | Medium | ~100 | None |
| R5: Sync/Async Unification | Medium | High | ~3,000-4,000 | R3 |
| R6: X.509 Module Decomposition | Medium | Low | 0 (structural) | R1 |
| R7: Integration Test Modularization | Medium | Low | 0 (structural) | None |
| R8: Test Helper Consolidation | Low | Low | ~200 | None |
| R9: Parameter Struct Refactoring | Low | Low | ~50 | None |
| R10: DRBG State Machine Unification | Low | Medium | ~300 | None |

**Recommended Execution Order**: R1 → R3 → R2 → R6 → R7 → R4 → R8 → R9 → R10 → R5

R5 (Sync/Async Unification) is placed last due to its high complexity and risk — it should be attempted only after the foundational refactorings (R1-R4) stabilize the codebase.

---

## 9. Architecture Strengths (Preserve During Refactoring)

These aspects of the current architecture are well-designed and should be preserved:

1. **Clean dependency hierarchy** — No circular deps, clear layering
2. **Feature flag granularity** — Enables minimal builds for embedded/constrained targets
3. **Security discipline** — Zeroize, constant-time, minimal unsafe, forbid(unsafe) where appropriate
4. **Comprehensive algorithm coverage** — 48+ crypto algorithms, 5 TLS protocol variants
5. **Test vector infrastructure** — NIST, Wycheproof, GM/T standard vectors
6. **Production-ready TLS** — 91 cipher suites, 10 callbacks, session management, GREASE
7. **Shared extension codec** — `extensions_codec.rs` already unified across protocol versions
8. **Trait-based provider abstraction** — 11 core traits in `provider.rs` enable algorithm pluggability
9. **Hardware acceleration** — AES-NI/NEON with transparent software fallback
10. **Zero clippy warnings** — Enforced with `-D warnings`

---

## Appendix A: File Tree (Complete)

```
crates/
├── hitls-types/src/
│   ├── lib.rs (8)
│   ├── algorithm.rs (583)
│   └── error.rs (502)
├── hitls-utils/src/
│   ├── lib.rs (14)
│   ├── asn1/mod.rs (51), decoder.rs (461), encoder.rs (296), tag.rs (128)
│   ├── base64/mod.rs (171)
│   ├── pem/mod.rs (140)
│   └── oid/mod.rs (603)
├── hitls-bignum/src/
│   ├── lib.rs (12)
│   ├── bignum.rs (324), ops.rs (756), montgomery.rs (316)
│   ├── gcd.rs (157), ct.rs (136), prime.rs (101), rand.rs (132)
├── hitls-crypto/src/
│   ├── lib.rs, provider.rs (145), hash/mod.rs (23)
│   ├── aes/ (1,441), sm4/ (307), chacha20/ (633)
│   ├── modes/ (2,639) — cbc, ecb, cfb, ofb, ctr, gcm, ccm, xts, hctr, wrap
│   ├── sha1/ (265), sha2/ (879), sha3/ (701), md5/ (327), sm3/ (342)
│   ├── hmac/ (316), cmac/ (308), gmac/ (211), cbc_mac/ (~300), siphash/ (282)
│   ├── rsa/ (1,582), ecc/ (1,129), ecdsa/ (415), ecdh/ (245), dsa/ (366)
│   ├── curve25519/ (823), x25519/ (268), ed25519/ (432)
│   ├── curve448/ (1,314), x448/ (291), ed448/ (622)
│   ├── sm2/ (535), sm9/ (2,322), paillier/ (281), elgamal/ (330)
│   ├── mlkem/ (1,114), mldsa/ (1,590), slh_dsa/ (1,571), xmss/ (1,046)
│   ├── mceliece/ (2,332), frodokem/ (1,325), hybridkem/ (192)
│   ├── hkdf/ (185), pbkdf2/ (114), scrypt/ (258), hpke/ (592)
│   ├── drbg/ (1,534), dh/ (449)
│   ├── entropy/ (1,005), fips/ (734)
├── hitls-tls/src/
│   ├── lib.rs (419), cert_verify.rs (480), connection_info.rs (141)
│   ├── config/mod.rs (2,191)
│   ├── connection.rs (7,324), connection12.rs (7,004)
│   ├── connection_async.rs (1,954), connection12_async.rs (2,480)
│   ├── connection_dtls12.rs (1,151), connection_dtls12_async.rs (1,755)
│   ├── connection_tlcp.rs (1,004), connection_dtlcp.rs (1,024)
│   ├── alert/mod.rs (368)
│   ├── extensions/mod.rs (369)
│   ├── session/mod.rs (809)
│   ├── crypt/mod.rs (1,889), aead.rs (539), key_schedule.rs (730)
│   ├── crypt/key_schedule12.rs (734), prf.rs, hkdf.rs, transcript.rs, etc.
│   ├── record/mod.rs (1,103), encryption.rs (590), encryption12.rs (1,352)
│   ├── record/encryption12_cbc.rs (745), encryption_tlcp.rs (629)
│   ├── record/encryption_dtlcp.rs (667), encryption_dtls12.rs (291)
│   ├── handshake/client.rs (1,610), server.rs (1,933)
│   ├── handshake/client12.rs (2,175), server12.rs (2,668)
│   ├── handshake/client_dtls12.rs (971), server_dtls12.rs (1,086)
│   ├── handshake/client_tlcp.rs (538), server_tlcp.rs (478)
│   ├── handshake/client_dtlcp.rs (670), server_dtlcp.rs (649)
│   ├── handshake/codec.rs (1,382), codec12.rs (1,726)
│   ├── handshake/codec_dtls.rs (589), codec_tlcp.rs (413)
│   ├── handshake/extensions_codec.rs (2,454)
│   ├── handshake/key_exchange.rs (389), signing.rs (427), verify.rs (492)
│   ├── handshake/fragment.rs (348), retransmit.rs (222)
├── hitls-pki/src/
│   ├── lib.rs (14)
│   ├── x509/mod.rs (3,441), verify.rs (2,138), ocsp.rs (1,071)
│   ├── x509/hostname.rs (381), crl.rs (712), text.rs (606)
│   ├── pkcs8/mod.rs (860), encrypted.rs (315)
│   ├── pkcs12/mod.rs (947)
│   ├── cms/mod.rs (2,555), enveloped.rs (1,068), encrypted.rs (379)
├── hitls-auth/src/
│   ├── lib.rs (13)
│   ├── otp/mod.rs (289), spake2plus/mod.rs (707), privpass/mod.rs (568)
├── hitls-cli/src/
│   ├── main.rs (363)
│   ├── dgst.rs (213), enc.rs (267), genpkey.rs (282), pkeyutl.rs (392)
│   ├── s_client.rs (253), s_server.rs (295), x509cmd.rs (215)
│   ├── pkcs12.rs (297), mac.rs (205), req.rs (176), verify.rs (126)
│   ├── crl.rs (99), pkey.rs (86), speed.rs (141), list.rs (161), rand_cmd.rs (47)
tests/
├── interop/src/lib.rs (7,675)
├── vectors/ (148 files across 8 directories)
fuzz/
├── fuzz_targets/ (10 targets)
├── corpus/ (66 seed files)
benches/
├── crypto_bench.rs (39)
```
