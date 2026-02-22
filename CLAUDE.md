# CLAUDE.md — Project Guide for Claude Code

This file provides context for Claude Code when working on the openHiTLS-rs codebase.

## Project Overview

openHiTLS-rs is a pure Rust rewrite of [openHiTLS](https://gitee.com/openhitls/openhitls) (C implementation), providing production-grade cryptographic primitives and TLS protocol support.

- **Language**: Rust (MSRV 1.75, edition 2021)
- **License**: MulanPSL-2.0
- **Status**: Phase 92 complete + Phase T102 — 0-RTT early data + replay protection tests (2585 tests)

## Workspace Structure

```
openhitls-rs/
├── crates/
│   ├── hitls-types/     # Shared types: algorithm IDs, error enums
│   ├── hitls-utils/     # ASN.1, Base64, PEM, OID utilities
│   ├── hitls-bignum/    # Big number arithmetic (Montgomery, Miller-Rabin)
│   ├── hitls-crypto/    # Cryptographic algorithms (feature-gated): AES, SM4, ChaCha20, SHA-2/3, SM3, HMAC, RSA, ECC, Ed25519/448, X25519/448, DH, DSA, SM2, SM9, PQC (ML-KEM/ML-DSA/SLH-DSA/XMSS/FrodoKEM/McEliece), DRBG, FIPS/CMVP, entropy health, hardware AES (619 tests + 15 Wycheproof, 31 ignored)
│   ├── hitls-tls/       # TLS 1.3/1.2 (91 cipher suites), DTLS 1.2, TLCP, DTLCP; 10 connection types (5 sync + 5 async via tokio); 15 TLS extensions; 10 callbacks; session cache, hostname verification, renegotiation, GREASE, custom extensions, NSS key logging (1164 tests)
│   ├── hitls-pki/       # X.509, PKCS#8 (incl. Encrypted PBES2), PKCS#12, CMS (SignedData/EnvelopedData/EncryptedData/DigestedData/AuthenticatedData), hostname verification (349 tests, 1 ignored)
│   ├── hitls-auth/      # HOTP/TOTP, SPAKE2+, Privacy Pass (33 tests)
│   └── hitls-cli/       # CLI tool: dgst, genpkey, x509, verify, enc, pkey, crl, req, s-client, s-server, list, rand, pkeyutl, speed, pkcs12, mac (117 tests, 5 ignored)
├── tests/interop/       # Integration tests (125 cross-crate tests, 3 ignored)
├── tests/vectors/       # Standard test vectors (NIST, Wycheproof, GM/T)
├── fuzz/                # Fuzz targets (cargo-fuzz, 10 targets)
└── benches/             # Criterion benchmarks
```

## Build & Test Commands

```bash
# Build
cargo build --workspace --all-features

# Run all tests (2585 tests, 40 ignored)
cargo test --workspace --all-features

# Run tests for a specific crate
cargo test -p hitls-crypto --all-features   # 652 tests (31 ignored) + 15 Wycheproof
cargo test -p hitls-tls --all-features      # 1164 tests

cargo test -p hitls-pki --all-features      # 349 tests (1 ignored)
cargo test -p hitls-bignum                  # 49 tests
cargo test -p hitls-utils                   # 53 tests
cargo test -p hitls-auth --all-features     # 33 tests
cargo test -p hitls-cli --all-features      # 117 tests (5 ignored)
cargo test -p hitls-integration-tests       # 125 tests (3 ignored)

# Lint (must pass with zero warnings)
RUSTFLAGS="-D warnings" cargo clippy --workspace --all-features --all-targets

# Format check
cargo fmt --all -- --check
```

## Code Style & Conventions

### Formatting
- `rustfmt.toml`: max_width=100, use_field_init_shorthand, use_try_shorthand
- `clippy.toml`: cognitive-complexity-threshold=30
- Always run `cargo fmt` before committing
- **Sync before task**: Before starting any implementation task, always pull the latest remote main branch first (`git pull origin main`) to ensure the local codebase is up to date

### Error Handling
- Use `hitls_types::CryptoError` for all crypto errors (thiserror-based)
- Return `Result<T, CryptoError>` from all public APIs
- Never panic in library code; use `Result` instead

### Security Patterns
- **Zeroize on drop**: All secret material (keys, intermediate states) must implement `Zeroize` via `#[derive(Zeroize)]` and `#[zeroize(drop)]`
- **Constant-time comparisons**: Use `subtle::ConstantTimeEq` for cryptographic comparisons, never `==`
- **No unsafe code** in `hitls-types`, `hitls-utils`, and most crates. Only `hitls-bignum` and `hitls-crypto` may use unsafe (for SIMD, etc.)
- **Random generation**: Use `getrandom` crate, never `rand`

### Feature Flags
- `hitls-crypto` uses feature flags for algorithm selection
- Default features: `aes`, `sha2`, `rsa`, `ecdsa`, `hmac`
- Each algorithm module is gated by `#[cfg(feature = "...")]` in `lib.rs`
- Feature dependencies are declared in `Cargo.toml` (e.g., `hkdf = ["hmac"]`)

### API Patterns
- **SHA-256**: `Sha256::new()`, `.update(data)?`, `.finish()? -> [u8; 32]` (returns array, not `finish(&mut [u8])`)
- **HMAC**: `Hmac::new(factory, key)?`, `.update(data)?`, `.finish(&mut out)?` (writes to buffer)
- **HMAC Digest trait**: `finish(&mut self, out: &mut [u8])` pattern (different from SHA-256 direct API)
- **BigNum**: `BigNum::from_bytes_be()`, `.to_bytes_be()`, `.mod_exp()`, `.mod_inv()`, `.gcd()` — all return `Result`
- **X25519**: `X25519PrivateKey::new(bytes)` applies clamping; `.diffie_hellman(&pub_key)? -> Vec<u8>`

### Test Conventions
- Use standard test vectors from RFCs/NIST where available
- Slow tests (prime generation, keygen) are marked `#[ignore]`
- Hex helper functions: `fn hex(s: &str) -> Vec<u8>` and `fn to_hex(bytes: &[u8]) -> String`
- Tests live in `#[cfg(test)] mod tests` within each module file

### Post-Task Documentation Updates
After completing each implementation task (phase/feature), **always** update the following files:
- `DEV_LOG.md` — Add a new phase entry with summary, files modified, implementation details, test counts, and build status
- `TEST_LOG.md` — Add a new Phase T entry with test details and per-crate counts (for testing phases)
- `PROMPT_LOG.md` — Record the prompt and result for the phase
- `CLAUDE.md` — Update status line, test counts, and workspace structure annotations
- `README.md` — Update test counts in Building & Testing section; update protocol/algorithm tables if new features added

## C Reference Code

The original C implementation is at `/Users/dongqiu/Dev/code/openhitls/`:
- Crypto algorithms: `crypto/` directory
- Algorithm IDs: `include/crypto/crypt_algid.h`
- Error codes: `include/crypto/crypt_errno.h`
- TLS protocol: `tls/` directory (~63K lines)
- PKI/X.509: `pki/` directory (~18K lines)

## Migration Roadmap

Phase 0–92 complete + Phase T73–T102 (2585 tests, 40 ignored). **100% C→Rust feature parity achieved.**

### Completed Phases (Summary)

Implementation Phase 0–92 cover all crypto algorithms (48 modules), TLS 1.3/1.2 (91 cipher suites), DTLS 1.2, TLCP, DTLCP, PKI/X.509/CMS, FIPS/CMVP, entropy health testing, CLI (14 commands), and async I/O. Phase T73–T102 provide comprehensive unit test coverage across all modules.

Key milestones:
- Phase 21–39: TLS 1.3/1.2/DTLS/TLCP completeness, ECC curves, DRBG, PKI, cipher suites, extensions
- Phase 40–44: Async I/O, hardware AES, Wycheproof/fuzz/audit, feature completeness
- Phase 45–49: DH groups, FIPS/CMVP, entropy health, Ed448/X448/Curve448
- Phase 50–61: Test coverage expansion (PKI vectors, unit tests, edge cases)
- Phase 62–67: CCM/CCM_8/PSK cipher suites, DHE_DSS, DH_ANON/ECDH_ANON
- Phase 68–80: Renegotiation, hostname verification, session cache, async DTLS, GREASE, Heartbeat
- Phase 82–86: TLS callbacks (10 types), Trusted CA Keys/USE_SRTP/STATUS_REQUEST_V2, CMS AuthenticatedData
- Phase 88–92: Encrypted PKCS#8, TicketKeyCallback/SecurityCallback, SM4-CTR-DRBG, CMS ML-DSA
- Phase T73–T102: CLI unit tests, async connection tests, cipher suite integration, codec/state machine edge cases, ECC point/AES soft/SM9 field arithmetic/McEliece vector, 0-RTT early data tests
- Phase R102–R105: Architecture refactoring — PKI encoding consolidation, record layer enum dispatch, connection file decomposition, hash digest enum dispatch

See `DEV_LOG.md` for detailed phase tables, `TEST_LOG.md` for testing history, `PROMPT_LOG.md` for prompt/response log, and `ARCH_LOG.md` for refactoring execution log.
