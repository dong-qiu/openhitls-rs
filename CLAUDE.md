# CLAUDE.md — Project Guide for Claude Code

This file provides context for Claude Code when working on the openHiTLS-rs codebase.

## Project Overview

openHiTLS-rs is a pure Rust rewrite of [openHiTLS](https://gitee.com/openhitls/openhitls) (C implementation), providing production-grade cryptographic primitives and TLS protocol support.

- **Language**: Rust (MSRV 1.75, edition 2021)
- **License**: MulanPSL-2.0
- **Status**: Phase 0–160 + Phase P152–P157 complete (3331 tests, 19 ignored)

## Workspace Structure

```
openhitls-rs/
├── crates/
│   ├── hitls-types/     # Shared types: algorithm IDs, error enums
│   ├── hitls-utils/     # Hex, ASN.1, Base64, PEM, OID utilities
│   ├── hitls-bignum/    # Big number arithmetic (CIOS Montgomery, Miller-Rabin) (80 tests)
│   ├── hitls-crypto/    # Cryptographic algorithms (feature-gated): AES, SM4, ChaCha20, SHA-2/3, SM3, HMAC, RSA, ECC, Ed25519/448, X25519/448, DH, DSA, SM2, SM9, PQC (ML-KEM/ML-DSA/SLH-DSA/XMSS/FrodoKEM/McEliece), DRBG, FIPS/CMVP, entropy health, hardware AES/SHA-2/GHASH/ChaCha20, P-256 fast path, SM2 fast path, ML-KEM NEON NTT, ML-DSA NEON NTT, SM4 T-table (1105 tests + 15 Wycheproof, 2 ignored)
│   ├── hitls-tls/       # TLS 1.3/1.2 (91 cipher suites), DTLS 1.2, TLCP, DTLCP; 10 connection types (5 sync + 5 async via tokio); 15 TLS extensions; 10 callbacks; session cache, hostname verification, renegotiation, GREASE, custom extensions, NSS key logging, middlebox compat (1290 tests)
│   ├── hitls-pki/       # X.509, PKCS#8 (incl. Encrypted PBES2), PKCS#12, CMS (SignedData/EnvelopedData/EncryptedData/DigestedData/AuthenticatedData), hostname verification (390 tests)
│   ├── hitls-auth/      # HOTP/TOTP, SPAKE2+, Privacy Pass (33 tests)
│   └── hitls-cli/       # CLI tool: dgst, genpkey, x509, verify, enc, pkey, crl, req, s-client, s-server, list, rand, pkeyutl, speed, pkcs12, mac (117 tests, 5 ignored)
├── tests/interop/       # Integration tests (174 cross-crate tests) — 14 test files + helper lib
├── tests/vectors/       # Standard test vectors (NIST, Wycheproof, GM/T)
├── fuzz/                # Fuzz targets (cargo-fuzz, 14 targets)
└── benches/             # Criterion benchmarks
```

## Build & Test Commands

```bash
# Build
cargo build --workspace --all-features

# Run all tests (3331 tests, 19 ignored)
cargo test --workspace --all-features

# Run tests for a specific crate
cargo test -p hitls-crypto --all-features   # 1105 tests (2 ignored) + 15 Wycheproof
cargo test -p hitls-tls --all-features      # 1326 tests

cargo test -p hitls-pki --all-features      # 395 tests
cargo test -p hitls-bignum                  # 80 tests
cargo test -p hitls-utils                   # 66 tests
cargo test -p hitls-auth --all-features     # 33 tests
cargo test -p hitls-cli --all-features      # 117 tests (5 ignored)
cargo test -p hitls-integration-tests       # 174 tests (2 ignored)

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
- Hex helpers: `use hitls_utils::hex::{hex, to_hex};` — shared across all crates
- Tests live in `#[cfg(test)] mod tests` within each module file

### Post-Task Documentation Updates
After completing each implementation task (phase/feature), **always** update the following files:
- `DEV_LOG.md` — Add a new phase entry with summary, files modified, implementation details, test counts, and build status (all phase types: N, TN, RN, PN). **After adding the entry, refresh the Phase Index tables at the top of the file**: recalculate the `#` column (sequential row number) for the affected category table (Implementation/Testing/Refactoring/Performance) to ensure numbering is contiguous.
- `PROMPT_LOG.md` — Record the prompt and result for the phase
- `CLAUDE.md` — Update status line, test counts, workspace structure annotations, and phase number references to match DEV_LOG.md
- `README.md` — Update test counts in Building & Testing section; update protocol/algorithm tables if new features added

### Phase Numbering Rules
- **No sub-phases**: All phases use integer IDs (e.g., Phase 43, not Phase 43a/43b). If a task has multiple parts, use a single Phase entry with `### Part A / Part B` subsections inside.
- **Four categories**: Implementation (plain number, e.g., 43), Testing (T-prefix, e.g., T96), Refactoring (R-prefix, e.g., R100), Performance (P-prefix, e.g., P137).
- **Sequential within category**: New phases append to the end of their category with the next available number.
- **Global consistency**: When DEV_LOG.md phase numbering changes, synchronize all references in `CLAUDE.md`, `README.md`, and `PROMPT_LOG.md` to match.

## C Reference Code

The original C implementation is at `/Users/dongqiu/Dev/code/openhitls/`:
- Crypto algorithms: `crypto/` directory
- Algorithm IDs: `include/crypto/crypt_algid.h`
- Error codes: `include/crypto/crypt_errno.h`
- TLS protocol: `tls/` directory (~63K lines)
- PKI/X.509: `pki/` directory (~18K lines)

## Migration Roadmap

Phase 0–160 + Phase P152–P157 complete (3331 tests, 19 ignored). **100% C→Rust feature parity achieved. Architecture refactoring complete. Performance optimization and quality improvement complete.**

### Completed Phases (Summary)

Phase 0–94 cover implementation of all crypto algorithms (48 modules), TLS 1.3/1.2 (91 cipher suites), DTLS 1.2, TLCP, DTLCP, PKI/X.509/CMS, FIPS/CMVP, entropy health testing, CLI (14 commands), and async I/O. Phase 136–140 add TLS 1.3 middlebox compatibility and hardware acceleration (SHA-2 SHA-NI, GHASH CLMUL/PMULL, P-256 specialized field arithmetic, ChaCha20 SIMD). Phases T72–T135, T141–T151 provide comprehensive unit test coverage, architecture refactoring, and semantic fuzz expansion across all modules.

Key milestones:
- Phase 20–38: TLS 1.3/1.2/DTLS/TLCP completeness, ECC curves, DRBG, PKI, cipher suites, extensions
- Phase 39–43: Async I/O, hardware AES, Wycheproof/fuzz/audit, feature completeness
- Phase 43–47: DH groups, FIPS/CMVP, entropy health, Ed448/X448/Curve448
- Phase 49–60: Test coverage expansion (PKI vectors, unit tests, edge cases)
- Phase 61–66: CCM/CCM_8/PSK cipher suites, DHE_DSS, DH_ANON/ECDH_ANON
- Phase 67–80: Renegotiation, hostname verification, session cache, async DTLS, GREASE, Heartbeat
- Phase 85–87: TLS callbacks (10 types), Trusted CA Keys/USE_SRTP/STATUS_REQUEST_V2, CMS AuthenticatedData
- Phase 94: Encrypted PKCS#8, TicketKeyCallback/SecurityCallback, SM4-CTR-DRBG, CMS ML-DSA
- Phase 136–140: TLS 1.3 middlebox compatibility (RFC 8446 §D.4), SHA-2 hardware acceleration (ARMv8 SHA-NI / x86-64 SHA-NI), GHASH/CLMUL hardware acceleration (ARMv8 PMULL / x86-64 PCLMULQDQ), P-256 specialized field arithmetic (4×u64 Montgomery, w=4 fixed-window scalar mul, Shamir's trick), ChaCha20 SIMD optimization (ARMv8 NEON / x86-64 SSE2)
- Phase T72–T135, T141–T150: CLI unit tests, async connection tests, cipher suite integration, codec/state machine edge cases, ECC point/AES soft/SM9 field arithmetic/McEliece vector, 0-RTT early data tests, async TLS 1.2 deep coverage, async TLCP + DTLCP connection types & tests, extension negotiation E2E tests, DTLS loss simulation & resilience tests, TLCP double certificate validation tests, SM9 tower field unit tests, SLH-DSA internal module unit tests, McEliece + FrodoKEM + XMSS internal module tests, proptest property-based tests + coverage CI, TLCP SM3 cryptographic path coverage, TLS 1.3 key schedule & HKDF robustness tests, record layer encryption edge cases & AEAD failure modes, TLS 1.2 CBC padding security + DTLS parsing + TLS 1.3 inner plaintext edge cases, DTLS fragmentation/retransmission + CertificateVerify edge cases, DTLS codec edge cases + anti-replay boundaries + entropy conditioning, X.509 extension parsing + WOTS+ base conversion + ASN.1 tag edge cases, PKI encoding helpers + X.509 signing dispatch + certificate builder encoding, X.509 certificate parsing + SM9 G2 point arithmetic + SM9 pairing helpers, SM9 hash functions + SM9 algorithm helpers + SM9 curve parameters, McEliece keygen helpers + McEliece encoding + McEliece decoding, XMSS tree operations + XMSS WOTS+ deepening + SLH-DSA FORS deepening, McEliece GF(2^13) + Benes network + binary matrix deepening, FrodoKEM matrix ops + SLH-DSA hypertree + McEliece polynomial deepening, McEliece + FrodoKEM + XMSS parameter set validation deepening, XMSS hash abstraction + XMSS address scheme + ML-KEM NTT deepening, BigNum constant-time + primality testing + core type deepening, SLH-DSA params + hash abstraction + address scheme deepening, FrodoKEM PKE + SM9 G1 point + SM9 Fp field deepening, ML-DSA NTT + SM4-CTR-DRBG + BigNum random deepening, DH group params + entropy pool + SHA-1 deepening, ML-KEM poly + SM9 Fp12 + encrypted PKCS#8 deepening, ML-DSA poly + X.509 extensions + X.509 text deepening, XTS mode + Edwards curve + GMAC deepening, scrypt + CFB mode + X448 deepening
- Phase R100–R109: Architecture refactoring — PKI encoding consolidation, record layer enum dispatch, connection file decomposition, hash digest enum dispatch, sync/async unification via body macros, X.509 module decomposition, integration test modularization, test helper consolidation, parameter struct refactoring, DRBG state machine unification
- Phase R142, R146: Dev profile optimization — per-crate opt-level overrides (hitls-bignum=2, hitls-crypto=2), un-ignored 44→6 tests
- Phase T151: Semantic fuzz target expansion — AEAD decrypt fuzzing, X.509 verification path fuzzing, deep TLS handshake decoder fuzzing (10→13 fuzz targets, 66→79 corpus files)
- Phase P152: P-256 deep optimization — dedicated mont_sqr (10 vs 16 multiplies), P-256 specialized Montgomery reduction (P[0]=-1, P[2]=0), precomputed comb base table (64×16 affine points, OnceLock + batch inversion), mixed Jacobian-affine addition. ECDSA sign 21× speedup, verify 14× speedup.
- Phase P153: ML-KEM NEON NTT optimization — 8-wide Montgomery multiply (`vqdmulhq_s16` + `vhsubq_s16` trick), NEON forward/inverse NTT (stages len≥8 fully vectorized), NEON Barrett reduction (widening multiply + shift-narrow), NEON poly utilities (add/sub/to_mont/reduce), batch SHAKE-128 squeeze (504-byte blocks vs 3-byte). ML-KEM-768 encaps 2.0× speedup, decaps 2.6× speedup.
- Phase P154: BigNum CIOS Montgomery — CIOS fused multiply+reduce (single (n+2)-limb accumulator vs 2n-limb intermediate), pre-allocated flat limb table for exponentiation, optimized sqr_limbs with cross-product symmetry, single conditional subtraction. DH-2048 1.25× speedup (174→218 ops/s), RSA-2048 sign 1.11× speedup (719→800 ops/s). Gap narrowed from 7× to 5.6× vs C.
- Phase P155: SM4 T-table lookup optimization — compile-time T-tables (XBOX_0–3/KBOX_0–3) fusing S-box + L/L' transform into u32 lookups, 4-way unrolled rounds, precomputed decrypt keys. SM4-CBC 2.37× speedup (50.8→120.2 MB/s, parity with C), SM4-GCM 3.09× speedup (47.6→146.9 MB/s, 1.68× faster than C).
- Phase P156: ML-DSA NEON NTT vectorization — 4-wide i32 NEON intrinsics (`vqdmulhq_s32` + `vhsubq_s32` Montgomery trick), forward/inverse NTT (len≥4 vectorized, len=2 half-register, len=1 scalar), Barrett reduction, pointwise multiply, poly utilities. NTT 2.31× speedup, INTT 2.54× speedup. End-to-end ML-DSA improvement modest (~2–5%) due to SHAKE-128 sampling dominance.
- Phase P157: SM2 specialized field arithmetic — 4×u64 Montgomery field elements (SM2 prime P[0]=-1 trick), precomputed comb base table (64×16 affine points, OnceLock + batch inversion), w=4 fixed-window scalar mul, mixed Jacobian-affine addition, a=-3 optimized doubling. SM2 sign 25.3× speedup (1.43ms→56.6µs), verify 21.1× speedup (1.75ms→83.2µs), encrypt 18.7× speedup, decrypt 20.2× speedup.
- Phase T152–T160: Quality improvement roadmap — TLS connection unit tests (+15), TLS 1.2 handshake edge cases (+15), HW↔SW cross-validation (+8), proptest expansion to 5/9 crates (+15), side-channel timing tests (+6), concurrency stress tests (+10), feature flag smoke tests (+4), zeroize runtime verification (+4), DTLS fuzz + OpenSSL interop (+1 fuzz target, +2 tests). Total: +80 tests, 13→14 fuzz targets, defense model B→B+.

See `DEV_LOG.md` for detailed phase tables (including test, refactoring, and performance phases) and `PROMPT_LOG.md` for prompt/response log.
