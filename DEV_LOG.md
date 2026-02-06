# openHiTLS Rust Migration — Development Log

## Phase 0: Project Scaffolding (Session 2026-02-06)

### Goals
- Initialize Rust workspace with all crate skeletons
- Set up CI/CD pipeline
- Configure linting, formatting, and testing infrastructure
- Create development log and documentation

### Completed Steps

#### 1. Workspace Root (`Cargo.toml`)
- Created workspace with 8 member crates
- Shared package metadata: version 0.1.0, edition 2021, Rust 1.75+, MulanPSL-2.0 license
- Workspace-level dependency declarations for consistency
- Release profile optimized: LTO, single codegen unit, abort on panic

#### 2. `hitls-types` — Common Types and Error Codes
**Files created:**
- `src/lib.rs` — Module root with `#![forbid(unsafe_code)]`
- `src/algorithm.rs` — Rust enums mapped from C `crypt_algid.h`:
  - `HashAlgId` (13 variants), `MacAlgId` (21 variants), `CipherAlgId` (37 variants)
  - `PkeyAlgId` (18 variants), `EccCurveId` (9 curves), `DhParamId` (13 groups)
  - `MlKemParamId`, `MlDsaParamId`, `SlhDsaParamId`, `FrodoKemParamId`
  - `McElieceParamId`, `HybridKemParamId`, `RandAlgId` (19 DRBG variants)
  - `KdfAlgId`, `PointFormat`
- `src/error.rs` — Error types using `thiserror`:
  - `CryptoError` — 30+ variants covering all crypto subsystems
  - `TlsError` — TLS protocol errors with `std::io::Error` support
  - `PkiError` — PKI/certificate errors

**Design decisions:**
- Used `thiserror` instead of manual `Display`/`Error` impls — more maintainable
- Each algorithm category has its own enum, rather than one giant `AlgId` — better type safety
- Preserved all algorithm variants from C even if not yet implemented

#### 3. `hitls-utils` — Utility Functions
**Files created:**
- `src/asn1/` — ASN.1 DER encoder/decoder:
  - `mod.rs` — `Tag`, `TagClass`, `Tlv` types, tag constants
  - `tag.rs` — Tag parsing/encoding with roundtrip tests
  - `decoder.rs` — Streaming `Decoder` with `read_tlv()`, `read_integer()`, `read_sequence()`, etc.
  - `encoder.rs` — `Encoder` builder with `write_integer()`, `write_sequence()`, etc.
- `src/base64/mod.rs` — RFC 4648 Base64 encode/decode with all standard test vectors passing
- `src/pem/mod.rs` — PEM parser/generator with multi-block support
- `src/oid/mod.rs` — OID type with DER serialization + well-known OID constants (RSA, EC, SM2, AES, etc.)

**Design decisions:**
- Self-implemented ASN.1, Base64, PEM (no external crate) for full control
- OID uses `Vec<u32>` arc representation with efficient DER encoding

#### 4. `hitls-bignum` — Big Number Arithmetic
**Files created:**
- `src/bignum.rs` — `BigNum` type: little-endian u64 limbs, `Zeroize` on drop, byte conversion
- `src/ops.rs` — Add, sub, mul, div_rem, mod_exp (square-and-multiply), cmp_abs
- `src/montgomery.rs` — `MontgomeryCtx` with N' computation via Newton's method
- `src/prime.rs` — Miller-Rabin primality test with small prime witnesses

**Design decisions:**
- u64 limbs for 64-bit platforms, DoubleLimb = u128 for multiplication
- All BigNums zeroized on drop (via `zeroize` crate)
- Placeholder division uses binary long division (will be optimized later)

#### 5. `hitls-crypto` — Cryptographic Algorithms
**Files created:**
- `src/lib.rs` — Module root with feature-gated submodule declarations
- `src/provider.rs` — Core trait definitions:
  - `Digest`, `HashAlgorithm` — Hash interface
  - `BlockCipher`, `Aead` — Symmetric cipher interfaces
  - `Mac` — MAC interface
  - `Kdf` — Key derivation interface
  - `Signer`, `Verifier` — Digital signature interfaces
  - `Kem`, `KeyAgreement` — Key exchange interfaces
- 38 algorithm submodule stubs (hash, cipher, MAC, asymmetric, PQC, KDF)

**Feature flags configured:**
- Default: aes, sha2, rsa, ecdsa, hmac
- Algorithm groups: pqc (mlkem + mldsa), tlcp (sm2 + sm3 + sm4)
- Hazmat flag for low-level API exposure

#### 6. `hitls-tls` — TLS Protocol
**Files created:**
- `src/lib.rs` — `TlsVersion`, `CipherSuite`, `TlsRole`, `TlsConnection` trait
- `src/config/mod.rs` — `TlsConfig` with builder pattern
- `src/record/mod.rs` — Record layer with parsing/serialization
- `src/handshake/mod.rs` — Handshake state machine enum + message types
- `src/alert/mod.rs` — Alert types (RFC 8446 Section 6 complete)
- `src/session/mod.rs` — `TlsSession`, `SessionCache` trait
- `src/extensions/mod.rs` — TLS extension type constants
- `src/crypt/mod.rs` — Named groups, signature schemes for TLS

#### 7. `hitls-pki` — PKI Certificate Management
**Files created:**
- `src/x509/mod.rs` — `Certificate`, `CertificateRequest`, `CertificateRevocationList` types
- `src/pkcs12/mod.rs` — `Pkcs12` container
- `src/cms/mod.rs` — CMS/PKCS#7 message types

#### 8. `hitls-auth` — Authentication Protocols
**Files created:**
- `src/otp/mod.rs` — HOTP/TOTP (RFC 4226/6238) scaffolding
- `src/spake2plus/mod.rs` — SPAKE2+ (RFC 9382) scaffolding
- `src/privpass/mod.rs` — Privacy Pass token types

#### 9. `hitls-cli` — Command-Line Tool
**Files created:**
- `src/main.rs` — CLI with `clap` derive: dgst, enc, genpkey, pkey, req, x509, verify, crl, s_client, s_server

#### 10. Infrastructure
- `.github/workflows/ci.yml` — CI pipeline: fmt, clippy, test (multi-OS + multi-Rust), audit, miri, bench
- `.gitignore`, `rustfmt.toml`, `clippy.toml`
- `tests/vectors/README.md` — Test vector directory structure
- `benches/crypto_bench.rs` — BigNum benchmark scaffold

### Build Status
- `cargo check --all-features`: **PASS** (warnings only — unused variables in todo!() stubs)
- `cargo test --all-features`: **PASS** — 24 tests pass (13 bignum + 11 utils)
- hitls-types: 0 warnings
- hitls-utils: 0 errors, 11 tests pass (ASN.1 tag, Base64, OID, PEM)
- hitls-bignum: 0 errors, 13 tests pass (add, sub, mul, div, prime, Montgomery)
- hitls-crypto: compiles with all features, placeholder warnings expected
- hitls-tls, hitls-pki, hitls-auth, hitls-cli: compile cleanly

### Architecture Summary

```
openhitls-rs/
├── Cargo.toml                     # Workspace (8 members)
├── crates/
│   ├── hitls-types/    (~300 LOC)  # Types, errors, algorithm IDs
│   ├── hitls-utils/    (~500 LOC)  # ASN.1, Base64, PEM, OID
│   ├── hitls-bignum/   (~600 LOC)  # Big number arithmetic
│   ├── hitls-crypto/   (~1500 LOC) # 38 algorithm modules + provider traits
│   ├── hitls-tls/      (~400 LOC)  # TLS protocol skeleton
│   ├── hitls-pki/      (~200 LOC)  # PKI/certificate types
│   ├── hitls-auth/     (~150 LOC)  # Auth protocol stubs
│   └── hitls-cli/      (~150 LOC)  # CLI tool with clap
├── tests/vectors/                  # Test vector directory
├── benches/                        # Benchmarks
└── .github/workflows/ci.yml       # CI pipeline
```

### Next Steps (Phase 1)
- Verify the workspace compiles successfully with `cargo check`
- Fix any compilation issues
- Implement ASN.1 decoder tests with real certificate data
- Begin implementing SHA-256 algorithm
