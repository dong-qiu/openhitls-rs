# CLAUDE.md — Project Guide for Claude Code

This file provides context for Claude Code when working on the openHiTLS-rs codebase.

## Project Overview

openHiTLS-rs is a pure Rust rewrite of [openHiTLS](https://gitee.com/openhitls/openhitls) (C implementation), providing production-grade cryptographic primitives and TLS protocol support.

- **Language**: Rust (MSRV 1.75, edition 2021)
- **License**: MulanPSL-2.0
- **Status**: Phase 71 complete — Server-side session cache + session expiration + cipher preference

## Workspace Structure

```
openhitls-rs/
├── crates/
│   ├── hitls-types/     # Shared types: algorithm IDs, error enums
│   ├── hitls-utils/     # ASN.1, Base64, PEM, OID utilities
│   ├── hitls-bignum/    # Big number arithmetic (Montgomery, Miller-Rabin)
│   ├── hitls-crypto/    # All cryptographic algorithms (feature-gated); hardware AES acceleration (ARMv8/x86-64); ECC: P-192, P-224, P-256, P-384, P-521, Brainpool P-256r1/P-384r1/P-512r1; Curve448: Ed448, X448; DRBG: HMAC/CTR/Hash; SM4-CCM; HCTR mode; FIPS/CMVP (KAT, PCT, integrity); Entropy health testing (NIST SP 800-90B, RCT+APT); Wycheproof test vectors (593 tests + 15 Wycheproof)
│   ├── hitls-tls/       # TLS 1.3 key schedule, record encryption, client & server handshake, PSK/session tickets, 0-RTT early data, post-handshake client auth, hybrid KEM (X25519MLKEM768), async I/O (tokio), TLS 1.3 SM4-GCM/CCM (RFC 8998) + AES_128_CCM_8_SHA256, RFC 5705/8446 key material export, TLS 1.2 handshake (ECDHE/RSA/DHE_RSA/DHE_DSS/DH_ANON/ECDH_ANON/PSK/DHE_PSK/RSA_PSK/ECDHE_PSK key exchange, GCM/CBC/ChaCha20/CCM/CCM_8, ALPN, SNI, session resumption, session ticket (RFC 5077), EMS (RFC 7627), ETM (RFC 7366), renegotiation (RFC 5746), mTLS, Bleichenbacher protection, AES-CCM (RFC 6655/7251), AES-CCM_8 (8-byte tag), PSK+CCM, PSK CBC-SHA256/SHA384 (RFC 5487), ECDHE_PSK GCM (draft-ietf-tls-ecdhe-psk-aead), DHE_DSS (RFC 5246), DH_ANON/ECDH_ANON (RFC 5246/4492), OCSP stapling CertificateStatus), hostname verification (RFC 6125), cert chain validation (CertificateVerifier), CertVerifyCallback + SniCallback, ConnectionInfo APIs, graceful shutdown (close_notify tracking), server-side session cache (Arc<Mutex<dyn SessionCache>>), session TTL expiration, cipher_server_preference config, DTLS 1.2 (RFC 6347), TLCP (GM/T 0024), DTLCP (DTLS+TLCP), custom extensions framework, NSS key logging, Record Size Limit (RFC 8449), Fallback SCSV (RFC 7507), OCSP stapling, SCT, Ed448/X448 signing + key exchange, TLS 1.2 PRF (697 tests)
│   ├── hitls-pki/       # X.509 (parse, verify [RSA/ECDSA/Ed25519/Ed448/SM2/RSA-PSS], chain, CRL, OCSP, CSR generation, Certificate generation, to_text output, SigningKey abstraction, EKU/SAN/AKI/SKI/AIA/NameConstraints/CertificatePolicies enforcement, hostname verification (RFC 6125)), PKCS#12 (RFC 7292), CMS SignedData (Ed25519/Ed448, SKI signer lookup, RSA-PSS, noattr, detached mode) + EnvelopedData + EncryptedData + DigestedData (RFC 5652), PKCS#8 (RFC 5958, Ed448/X448), SPKI public key parsing (336 tests, 1 ignored)
│   ├── hitls-auth/      # HOTP/TOTP (RFC 4226/6238), SPAKE2+ (RFC 9382, P-256), Privacy Pass (RFC 9578, RSA blind sigs) (33 tests)
│   └── hitls-cli/       # Command-line tool (dgst, genpkey, x509, verify, enc, pkey, crl, req, s-client, s-server, list, rand, pkeyutl, speed, pkcs12, mac)
├── tests/interop/       # Integration tests (39 cross-crate tests, 3 ignored)
├── tests/vectors/       # Standard test vectors (Wycheproof JSON)
├── fuzz/                # Fuzz targets (cargo-fuzz, 10 targets)
└── benches/             # Performance benchmarks
```

## Build & Test Commands

```bash
# Build
cargo build --workspace --all-features

# Run all tests (1880 tests, 40 ignored)
cargo test --workspace --all-features

# Run tests for a specific crate
cargo test -p hitls-crypto --all-features   # 593 tests (31 ignored) + 15 Wycheproof
cargo test -p hitls-tls --all-features      # 697 tests
cargo test -p hitls-pki --all-features      # 336 tests (1 ignored)
cargo test -p hitls-bignum                  # 48 tests
cargo test -p hitls-utils                   # 53 tests
cargo test -p hitls-auth --all-features     # 33 tests
cargo test -p hitls-cli --all-features      # 40 tests (5 ignored)
cargo test -p hitls-integration-tests       # 39 tests (3 ignored)

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

### Post-Task Documentation Updates
After completing each implementation task (phase/feature), **always** update the following files:
- `DEV_LOG.md` — Add a new phase entry with summary, files modified, implementation details, test counts, and build status
- `PROMPT_LOG.md` — Record the prompt and result for the phase
- `CLAUDE.md` — Update status line, test counts, hitls-tls feature list, and completed phases list
- `README.md` — Update feature list, test counts, and any new module descriptions as needed

## C Reference Code

The original C implementation is at `/Users/dongqiu/Dev/code/openhitls/`:
- Crypto algorithms: `crypto/` directory
- Algorithm IDs: `include/crypto/crypt_algid.h`
- Error codes: `include/crypto/crypt_errno.h`
- TLS protocol: `tls/` directory (~63K lines)
- PKI/X.509: `pki/` directory (~18K lines)

## Migration Roadmap

Phases 0-71 complete (1880 tests, 40 ignored).

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
- Phase 50: Test Coverage + CMS Ed25519/Ed448 + enc CLI + TLS 1.2 OCSP/SCT (alert/session/record tests, CMS EdDSA signing/verification, multi-cipher enc CLI, TLS 1.2 CertificateStatus message) -- DONE
- Phase 51: C Test Vectors Porting + CMS Real File Tests + PKCS#12 Interop (52 new PKI tests: chain verification with real certs, CMS real file parsing/verification, PKCS#12 interop, cert parsing edge cases) -- DONE
- Phase 52: X.509 Extension Parsing + EKU/SAN/AKI/SKI Enforcement + CMS SKI Lookup (39 new PKI tests: typed extension parsing for EKU/SAN/AKI/SKI/AIA/NameConstraints, EKU enforcement in chain verifier, AKI/SKI issuer matching, CMS SKI signer lookup, Name Constraints enforcement) -- DONE
- Phase 53: C Test Vectors Round 2 + CertificatePolicies + CMS Chain/NoAttr Tests (56 new PKI tests: AKI/SKI chain matching suite, extension edge cases, cert parsing edge cases, CertificatePolicies extension, CMS noattr verification, CMS RSA-PSS support, sig param consistency, CSR parse/verify from C vectors) -- DONE
- Phase 54: PKI Signature Coverage + OCSP/CRL Testing + CMS Error Paths (41 new PKI tests: Ed448/SM2/RSA-PSS verify in cert/CRL/OCSP, OCSP verify_signature tests, CRL DER test vectors from C, CMS EnvelopedData error paths, text/PKCS#12/chain test quality) -- DONE
- Phase 55: TLS RFC 5705 Key Export + CMS Detached Sign + pkeyutl Completeness (24 new tests: TLS 1.3/1.2 export_keying_material RFC 5705/8446 §7.5, CMS detached SignedData, PKCS#8 Ed448/X448, SPKI parsing, pkeyutl derive X25519/X448/ECDH + sign/verify ECDSA/Ed448/RSA-PSS) -- DONE
- Phase 56: Integration Test Expansion + TLCP Public API + Code Quality (30 new tests: ML-KEM panic→Result fix, TLCP public handshake-in-memory API, 5 DTLS 1.2 integration tests, 4 TLCP integration tests, 3 DTLCP integration tests, 4 mTLS integration tests, 12 TLS 1.3 server unit tests) -- DONE
- Phase 57: Unit Test Coverage Expansion (40 new tests: X25519 RFC 7748 §5.2 iterated vectors, HKDF from_prk/error paths, SM3/SM4 incremental+1M iteration vectors, Base64 negative tests, PEM negative tests, anti-replay window edge cases, TLS 1.2 client12 wrong-state/KX/ticket tests, DTLS 1.2 client HVR/wrong-state tests, DTLS 1.2 server cookie retry/wrong-cookie tests) -- DONE
- Phase 58: Unit Test Coverage Expansion (36 new tests: Ed25519 RFC 8032 vectors + error paths, ECDSA negative cases, ASN.1 decoder negative tests, HMAC RFC 2202/4231 vectors, ChaCha20-Poly1305 edge cases, TLS 1.3 client wrong-state tests, TLS 1.2 server wrong-state tests) -- DONE
- Phase 59: Unit Test Coverage Expansion (35 new tests: CFB/OFB/ECB/XTS cipher mode edge cases, ML-KEM failure/implicit rejection, ML-DSA corruption/wrong key, DRBG reseed divergence, SipHash key validation, GMAC/CMAC NIST vectors + error paths, SHA-1 reset/million-a, scrypt/PBKDF2 validation, TLS transcript hash SHA-384/replace_with_message_hash) -- DONE
- Phase 60: Unit Test Coverage Expansion (36 new tests: CTR invalid nonce/key + AES-256 NIST vector, CCM nonce/tag validation + tampered tag, AES Key Wrap short/non-aligned/corrupted + RFC 3394 §4.6, GCM invalid key + AES-256 NIST Case 14 + empty-pt-with-AAD, DSA wrong key/public-only/different digest, HPKE tampered ct/wrong AAD/PSK roundtrip/empty PSK rejection, HybridKEM cross-key/ct-length/multiple-encap, SM3 reset-reuse/block-boundary, Entropy zero-len/large/multiple-small/disabled-health/pool-min-capacity/partial-pop/RCT-reset, Privacy Pass wrong-challenge/empty-key/wire-roundtrip) -- DONE
- Phase 61: Unit Test Coverage Expansion (34 new tests: RSA cross-padding/OAEP-length/cross-key, ECDH zero/large/format/self-DH, SM2 public-only sign/decrypt + corrupted sig, ElGamal truncated/tampered ct, Paillier invalid-ct/triple-homomorphic, ECC scalar-mul-zero/point-add-negate, MD5 reset/boundary, SM4 consecutive-roundtrip/all-FF, SHA-256 reset/SHA-384 incremental/SHA-512 boundary, SHA-3 reset/SHAKE multi-squeeze, AES invalid-block-length, BigNum div-by-one/sqr-mul-consistency, HOTP empty-secret/1-digit/TOTP-boundary, SPAKE2+ setup-before-generate/empty-password/invalid-share) -- DONE
- Phase 62: TLS 1.2 CCM Cipher Suites (8 new tests: 6 AES-CCM suites per RFC 6655/7251 — TLS_RSA_WITH_AES_128/256_CCM, TLS_DHE_RSA_WITH_AES_128/256_CCM, TLS_ECDHE_ECDSA_WITH_AES_128/256_CCM, AesCcmAead adapter, 3 AEAD + 5 record layer tests) -- DONE
- Phase 63: CCM_8 + PSK+CCM Cipher Suites (RFC 6655, TLS 1.3 AES_128_CCM_8_SHA256 0x1305, 2 TLS 1.2 CCM_8 suites, 4 TLS 1.2 PSK+CCM suites, AesCcm8Aead adapter) -- DONE
- Phase 64: PSK CBC-SHA256/SHA384 + ECDHE_PSK GCM Cipher Suites (RFC 5487 + draft-ietf-tls-ecdhe-psk-aead, 8 new suites: PSK/DHE_PSK/RSA_PSK CBC-SHA256/SHA384, ECDHE_PSK GCM-SHA256/SHA384) -- DONE
- Phase 65: PSK CCM completion + CCM_8 authentication cipher suites (10 new suites: PSK AES_128_CCM/AES_128+256_CCM_8, DHE_PSK AES_128+256_CCM_8, ECDHE_PSK AES_128_CCM_8_SHA256, DHE_RSA AES_128+256_CCM_8, ECDHE_ECDSA AES_128+256_CCM_8, +11 tests) -- DONE
- Phase 66: DHE_DSS cipher suites (6 new suites: DHE_DSS_WITH_AES_128/256_CBC_SHA, DHE_DSS_WITH_AES_128/256_CBC_SHA256, DHE_DSS_WITH_AES_128_GCM_SHA256/AES_256_GCM_SHA384, AuthAlg::Dsa, DSA_SHA256/SHA384 signature schemes, ServerPrivateKey::Dsa, +8 tests) -- DONE
- Phase 67: DH_ANON + ECDH_ANON cipher suites (8 new suites: DH_ANON_WITH_AES_128/256_CBC_SHA, DH_ANON_WITH_AES_128/256_CBC_SHA256, DH_ANON_WITH_AES_128_GCM_SHA256/AES_256_GCM_SHA384, ECDH_ANON_WITH_AES_128/256_CBC_SHA, KeyExchangeAlg::DheAnon/EcdheAnon, AuthAlg::Anon, unsigned ServerKeyExchange codec, anonymous handshake flow, +10 tests) -- DONE
- Phase 68: TLS 1.2 renegotiation (RFC 5746) (HelloRequest message type + codec, NoRenegotiation alert, allow_renegotiation config, reset_for_renegotiation() for client/server, RFC 5746 renegotiation_info with verify_data validation, re-handshake over encrypted connection, server renegotiation_info in initial ServerHello fix, sync + async paths, +10 tests) -- DONE
- Phase 69: Connection info APIs + graceful shutdown + ALPN completion (ConnectionInfo struct with peer certs/ALPN/SNI/named group/verify_data, TLS 1.3 ALPN client+server, TLS 1.2 client ALPN parsing, close_notify tracking, graceful shutdown, public getters on all 8 connection types, sync + async paths, +8 tests) -- DONE
- Phase 70: Hostname verification + cert chain validation + SNI callback (RFC 6125 hostname verification (SAN/CN matching, wildcards, IP addresses), cert chain validation via CertificateVerifier (trusted_certs), CertVerifyCallback for custom verification override, SniCallback for server-side certificate selection by hostname, verify_hostname config (default: true), wired into all 5 client handshake paths (TLS 1.2/1.3/DTLS/TLCP/DTLCP), +15 tests) -- DONE
- Phase 71: Server-side session cache + session expiration + cipher preference (Arc<Mutex<dyn SessionCache>> in TlsConfig, auto-store after full handshake, auto-lookup on ClientHello, InMemorySessionCache TTL expiration (default 2h), cleanup(), cipher_server_preference config (default: true, toggle client preference), wired into sync+async TLS 1.2 server + renegotiation paths, TLS 1.3 cipher preference, +13 tests) -- DONE

See `DEV_LOG.md` for detailed implementation history and `PROMPT_LOG.md` for prompt/response log.
