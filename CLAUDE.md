# CLAUDE.md — Project Guide for Claude Code

This file provides context for Claude Code when working on the openHiTLS-rs codebase.

## Project Overview

openHiTLS-rs is a pure Rust rewrite of [openHiTLS](https://gitee.com/openhitls/openhitls) (C implementation), providing production-grade cryptographic primitives and TLS protocol support.

- **Language**: Rust (MSRV 1.75, edition 2021)
- **License**: MulanPSL-2.0
- **Status**: P5 complete — PKI Signature Coverage + OCSP/CRL Testing + CMS Error Paths

## Workspace Structure

```
openhitls-rs/
├── crates/
│   ├── hitls-types/     # Shared types: algorithm IDs, error enums
│   ├── hitls-utils/     # ASN.1, Base64, PEM, OID utilities
│   ├── hitls-bignum/    # Big number arithmetic (Montgomery, Miller-Rabin)
│   ├── hitls-crypto/    # All cryptographic algorithms (feature-gated); hardware AES acceleration (ARMv8/x86-64); ECC: P-192, P-224, P-256, P-384, P-521, Brainpool P-256r1/P-384r1/P-512r1; Curve448: Ed448, X448; DRBG: HMAC/CTR/Hash; SM4-CCM; HCTR mode; FIPS/CMVP (KAT, PCT, integrity); Entropy health testing (NIST SP 800-90B, RCT+APT); Wycheproof test vectors (476 tests + 15 Wycheproof)
│   ├── hitls-tls/       # TLS 1.3 key schedule, record encryption, client & server handshake, PSK/session tickets, 0-RTT early data, post-handshake client auth, hybrid KEM (X25519MLKEM768), async I/O (tokio), TLS 1.3 SM4-GCM/CCM (RFC 8998), TLS 1.2 handshake (ECDHE/RSA/DHE_RSA/PSK/DHE_PSK/RSA_PSK/ECDHE_PSK key exchange, GCM/CBC/ChaCha20, ALPN, SNI, session resumption, session ticket (RFC 5077), EMS (RFC 7627), ETM (RFC 7366), renegotiation indication (RFC 5746), mTLS, Bleichenbacher protection, OCSP stapling CertificateStatus), DTLS 1.2 (RFC 6347), TLCP (GM/T 0024), DTLCP (DTLS+TLCP), custom extensions framework, NSS key logging, Record Size Limit (RFC 8449), Fallback SCSV (RFC 7507), OCSP stapling, SCT, Ed448/X448 signing + key exchange, TLS 1.2 PRF (558 tests)
│   ├── hitls-pki/       # X.509 (parse, verify [RSA/ECDSA/Ed25519/Ed448/SM2/RSA-PSS], chain, CRL, OCSP, CSR generation, Certificate generation, to_text output, SigningKey abstraction, EKU/SAN/AKI/SKI/AIA/NameConstraints/CertificatePolicies enforcement), PKCS#12 (RFC 7292), CMS SignedData (Ed25519/Ed448, SKI signer lookup, RSA-PSS, noattr) + EnvelopedData + EncryptedData + DigestedData (RFC 5652), PKCS#8 (RFC 5958) (313 tests, 1 ignored)
│   ├── hitls-auth/      # HOTP/TOTP (RFC 4226/6238), SPAKE2+ (RFC 9382, P-256), Privacy Pass (RFC 9578, RSA blind sigs) (24 tests)
│   └── hitls-cli/       # Command-line tool (dgst, genpkey, x509, verify, enc, pkey, crl, req, s-client, s-server, list, rand, pkeyutl, speed, pkcs12, mac)
├── tests/interop/       # Integration tests (23 cross-crate tests, 3 ignored)
├── tests/vectors/       # Standard test vectors (Wycheproof JSON)
├── fuzz/                # Fuzz targets (cargo-fuzz, 10 targets)
└── benches/             # Performance benchmarks
```

## Build & Test Commands

```bash
# Build
cargo build --workspace --all-features

# Run all tests (1550 tests, 37 ignored)
cargo test --workspace --all-features

# Run tests for a specific crate
cargo test -p hitls-crypto --all-features   # 476 tests (28 ignored) + 15 Wycheproof
cargo test -p hitls-tls --all-features      # 558 tests
cargo test -p hitls-pki --all-features      # 313 tests (1 ignored)
cargo test -p hitls-bignum                  # 46 tests
cargo test -p hitls-utils                   # 35 tests
cargo test -p hitls-auth --all-features     # 24 tests
cargo test -p hitls-cli --all-features      # 32 tests (5 ignored)
cargo test -p hitls-integration-tests       # 23 tests (3 ignored)

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

Phases 0-49 + P1-P5 complete (1550 tests, 37 ignored).

### Completed
- Phase 40: Async I/O (tokio) + Hardware AES Acceleration (ARMv8/x86-64) + Criterion Benchmarks -- DONE
- Phase 41: DTLCP + Custom Extensions + Key Logging -- DONE
- Phase 42: Wycheproof (5000+ vectors) + Fuzzing (10 targets) + Security Audit -- DONE
- Phase 43: Feature Completeness (PKI text output, TLS 1.3 SM4-GCM/CCM, CMS EnvelopedData, Privacy Pass, CLI commands) -- DONE
- Phase 44: Remaining Features (NistP192, HCTR mode, CMS EncryptedData) -- DONE
- Phase 45: Complete DH Groups + TLS FFDHE Expansion (all 13 DH groups, FFDHE6144/8192 in TLS) -- DONE
- Phase 46: FIPS/CMVP Compliance Framework (KAT self-tests, FIPS state machine, PCT, integrity check, feature-gated) -- DONE
- Phase 47: CLI Enhancements + CMS DigestedData (pkcs12/mac CLI commands, CMS DigestedData RFC 5652 §5) -- DONE
- Phase 48: Entropy Health Testing (NIST SP 800-90B RCT+APT, entropy pool, conditioning, noise source trait, DRBG/FIPS integration) -- DONE
- Phase 49: Ed448 / X448 / Curve448 (GF(2^448-2^224-1) field, Edwards a=1 d=-39081 curve, RFC 8032 Ed448 sign/verify with SHAKE256+dom4, RFC 7748 X448 DH, TLS integration) -- DONE
- P1: Test Coverage + CMS Ed25519/Ed448 + enc CLI + TLS 1.2 OCSP/SCT (alert/session/record tests, CMS EdDSA signing/verification, multi-cipher enc CLI, TLS 1.2 CertificateStatus message) -- DONE
- P2: C Test Vectors Porting + CMS Real File Tests + PKCS#12 Interop (52 new PKI tests: chain verification with real certs, CMS real file parsing/verification, PKCS#12 interop, cert parsing edge cases) -- DONE
- P3: X.509 Extension Parsing + EKU/SAN/AKI/SKI Enforcement + CMS SKI Lookup (39 new PKI tests: typed extension parsing for EKU/SAN/AKI/SKI/AIA/NameConstraints, EKU enforcement in chain verifier, AKI/SKI issuer matching, CMS SKI signer lookup, Name Constraints enforcement) -- DONE
- P4: C Test Vectors Round 2 + CertificatePolicies + CMS Chain/NoAttr Tests (56 new PKI tests: AKI/SKI chain matching suite, extension edge cases, cert parsing edge cases, CertificatePolicies extension, CMS noattr verification, CMS RSA-PSS support, sig param consistency, CSR parse/verify from C vectors) -- DONE
- P5: PKI Signature Coverage + OCSP/CRL Testing + CMS Error Paths (41 new PKI tests: Ed448/SM2/RSA-PSS verify in cert/CRL/OCSP, OCSP verify_signature tests, CRL DER test vectors from C, CMS EnvelopedData error paths, text/PKCS#12/chain test quality) -- DONE

See `DEV_LOG.md` for detailed implementation history and `PROMPT_LOG.md` for prompt/response log.
