# CLAUDE.md — Project Guide for Claude Code

This file provides context for Claude Code when working on the openHiTLS-rs codebase.

## Project Overview

openHiTLS-rs is a pure Rust rewrite of [openHiTLS](https://gitee.com/openhitls/openhitls) (C implementation), providing production-grade cryptographic primitives and TLS protocol support.

- **Language**: Rust (MSRV 1.75, edition 2021)
- **License**: MulanPSL-2.0
- **Status**: Phase 12 complete — core crypto + X.509 parsing done, TLS in progress

## Workspace Structure

```
openhitls-rs/
├── crates/
│   ├── hitls-types/     # Shared types: algorithm IDs, error enums
│   ├── hitls-utils/     # ASN.1, Base64, PEM, OID utilities
│   ├── hitls-bignum/    # Big number arithmetic (Montgomery, Miller-Rabin)
│   ├── hitls-crypto/    # All cryptographic algorithms (feature-gated)
│   ├── hitls-tls/       # TLS 1.2/1.3, DTLS, TLCP (skeleton)
│   ├── hitls-pki/       # X.509, PKCS#12, CMS (skeleton)
│   ├── hitls-auth/      # OTP, SPAKE2+, Privacy Pass (skeleton)
│   └── hitls-cli/       # Command-line tool (skeleton)
├── tests/vectors/       # Standard test vectors
└── benches/             # Performance benchmarks
```

## Build & Test Commands

```bash
# Build
cargo build --workspace --all-features

# Run all tests (310 tests, 3 ignored for slow keygen)
cargo test --workspace --all-features

# Run tests for a specific crate
cargo test -p hitls-crypto --all-features
cargo test -p hitls-bignum
cargo test -p hitls-utils

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

## C Reference Code

The original C implementation is at `/Users/dongqiu/Dev/code/openhitls/`:
- Crypto algorithms: `crypto/` directory
- Algorithm IDs: `include/crypto/crypt_algid.h`
- Error codes: `include/crypto/crypt_errno.h`
- TLS protocol: `tls/` directory (~63K lines)
- PKI/X.509: `pki/` directory (~18K lines)

## Migration Roadmap

Phases 0-12 complete. Remaining critical path:
- Phase 13: X.509 Verification + Chain Building
- Phase 14-17: TLS 1.3 (Key Schedule, Record Layer, Handshake)

See `DEV_LOG.md` for detailed implementation history and `PROMPT_LOG.md` for prompt/response log.
