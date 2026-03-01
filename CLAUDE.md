# CLAUDE.md — Project Guide for Claude Code

This file provides context for Claude Code when working on the openHiTLS-rs codebase.

## Project Overview

openHiTLS-rs is a pure Rust rewrite of [openHiTLS](https://gitee.com/openhitls/openhitls) (C implementation), providing production-grade cryptographic primitives and TLS protocol support.

- **Language**: Rust (MSRV 1.75, edition 2021)
- **License**: MulanPSL-2.0
- **Status**: Phases I1–I82, T1–T63, R1–R12, P1–P45 complete (3534 tests, 21 ignored)

## Workspace Structure

```
openhitls-rs/
├── crates/
│   ├── hitls-types/     # Shared types: algorithm IDs, error enums
│   ├── hitls-utils/     # Hex, ASN.1, Base64, PEM, OID utilities
│   ├── hitls-bignum/    # Big number arithmetic (CIOS Montgomery, Miller-Rabin) (80 tests)
│   ├── hitls-crypto/    # Cryptographic algorithms (feature-gated): AES, SM4, ChaCha20, SHA-2/3, SM3, HMAC, RSA, ECC, Ed25519/448, X25519/448, DH, DSA, SM2, SM9, PQC (ML-KEM/ML-DSA/SLH-DSA/XMSS/FrodoKEM/McEliece), HybridKEM (12 variants), DRBG, FIPS/CMVP, entropy health, hardware AES/SHA-2/GHASH/ChaCha20, P-256 fast path, SM2 fast path, ML-KEM NEON NTT, ML-DSA NEON NTT, SM4 T-table, SHA-512 HW accel, Ed25519 precomputed table, Keccak SHA-3 HW accel, P-256 scalar field (1182 tests, 14 ignored)
│   ├── hitls-tls/       # TLS 1.3/1.2 (91 cipher suites), DTLS 1.2, TLCP, DTLCP; 10 connection types (5 sync + 5 async via tokio); 15 TLS extensions; 10 callbacks; session cache, hostname verification, renegotiation, GREASE, custom extensions, NSS key logging, middlebox compat (1384 tests)
│   ├── hitls-pki/       # X.509, PKCS#8 (incl. Encrypted PBES2), PKCS#12, CMS (SignedData/EnvelopedData/EncryptedData/DigestedData/AuthenticatedData), CRL builder, hostname verification (405 tests)
│   ├── hitls-auth/      # HOTP/TOTP, SPAKE2+, Privacy Pass (33 tests)
│   └── hitls-cli/       # CLI tool: dgst, genpkey, x509, verify, enc, pkey, crl, req, s-client, s-server, list, rand, pkeyutl, speed, pkcs12, mac (117 tests, 5 ignored)
├── tests/interop/       # Integration tests (241 cross-crate tests) — 14 test files + helper lib
├── tests/vectors/       # Standard test vectors (NIST, Wycheproof, GM/T)
├── fuzz/                # Fuzz targets (cargo-fuzz, 40 targets)
└── benches/             # Criterion benchmarks
```

## Build & Test Commands

```bash
# Build
cargo build --workspace --all-features

# Run all tests (3534 tests, 21 ignored)
cargo test --workspace --all-features

# Run tests for a specific crate
cargo test -p hitls-crypto --all-features   # 1182 tests (14 ignored)
cargo test -p hitls-tls --all-features      # 1384 tests

cargo test -p hitls-pki --all-features      # 405 tests
cargo test -p hitls-bignum                  # 80 tests
cargo test -p hitls-utils                   # 66 tests
cargo test -p hitls-auth --all-features     # 33 tests
cargo test -p hitls-cli --all-features      # 117 tests (5 ignored)
cargo test -p hitls-integration-tests       # 241 tests (2 ignored)

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
- **No sub-phases**: All phases use integer IDs (e.g., Phase I44, not Phase I44a/I44b). If a task has multiple parts, use a single Phase entry with `### Part A / Part B` subsections inside.
- **Four categories**: Implementation (I-prefix, e.g., I43), Testing (T-prefix, e.g., T6), Refactoring (R-prefix, e.g., R1), Performance (P-prefix, e.g., P1).
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

Phases I1–I82, T1–T63, R1–R12, P1–P45 complete (3534 tests, 21 ignored). **100% C→Rust feature parity achieved. Architecture refactoring complete. Performance optimization and quality improvement complete.**

### Completed Phases (Summary)

Phase I1–I79 cover implementation of all crypto algorithms (48 modules), TLS 1.3/1.2 (91 cipher suites), DTLS 1.2, TLCP, DTLCP, PKI/X.509/CMS, FIPS/CMVP, entropy health testing, CLI (14 commands), and async I/O. Phase I80, P1–P4 add TLS 1.3 middlebox compatibility and hardware acceleration (SHA-2 SHA-NI, GHASH CLMUL/PMULL, P-256 specialized field arithmetic, ChaCha20 SIMD). Phase I81 generalizes HybridKEM to all 12 variants (X25519/P-256/P-384/P-521 × ML-KEM-512/768/1024). Phase T1–T44 provide comprehensive unit test coverage, architecture refactoring, and semantic fuzz expansion across all modules.

Key milestones:
- Phase I21–I39: TLS 1.3/1.2/DTLS/TLCP completeness, ECC curves, DRBG, PKI, cipher suites, extensions
- Phase I40–I43: Async I/O, hardware AES, Wycheproof/fuzz/audit, feature completeness
- Phase I44–I48: DH groups, FIPS/CMVP, entropy health, Ed448/X448/Curve448
- Phase I49–I60: Test coverage expansion (PKI vectors, unit tests, edge cases)
- Phase I61–I66: CCM/CCM_8/PSK cipher suites, DHE_DSS, DH_ANON/ECDH_ANON
- Phase I67–I75: Renegotiation, hostname verification, session cache, async DTLS, GREASE, Heartbeat
- Phase I76–I78: TLS callbacks (10 types), Trusted CA Keys/USE_SRTP/STATUS_REQUEST_V2, CMS AuthenticatedData
- Phase I79: Encrypted PKCS#8, TicketKeyCallback/SecurityCallback, SM4-CTR-DRBG, CMS ML-DSA
- Phase I80, P1–P4: TLS 1.3 middlebox compatibility (RFC 8446 §D.4), SHA-2 hardware acceleration (ARMv8 SHA-NI / x86-64 SHA-NI), GHASH/CLMUL hardware acceleration (ARMv8 PMULL / x86-64 PCLMULQDQ), P-256 specialized field arithmetic (4×u64 Montgomery, w=4 fixed-window scalar mul, Shamir's trick), ChaCha20 SIMD optimization (ARMv8 NEON / x86-64 SSE2)
- Phase I81: HybridKEM generalization — all 12 variants (X25519/P-256/P-384/P-521 × ML-KEM-512/768/1024), `from_public_key()` encapsulate-only constructor, C reference byte ordering, `param_id()` accessor
- Phase I82: CRL Builder — `CrlBuilder` + `RevokedCertBuilder` (auto v1/v2, CRL Number, AKI, CRLReason, InvalidityDate), `to_der()`/`to_pem()` on `CertificateRevocationList`, RSA/ECDSA signing (+10 tests)
- Phase T1–T43: CLI unit tests, async connection tests, cipher suite integration, codec/state machine edge cases, ECC point/AES soft/SM9 field arithmetic/McEliece vector, 0-RTT early data tests, async TLS 1.2 deep coverage, async TLCP + DTLCP connection types & tests, extension negotiation E2E tests, DTLS loss simulation & resilience tests, TLCP double certificate validation tests, SM9 tower field unit tests, SLH-DSA internal module unit tests, McEliece + FrodoKEM + XMSS internal module tests, proptest property-based tests + coverage CI, TLCP SM3 cryptographic path coverage, TLS 1.3 key schedule & HKDF robustness tests, record layer encryption edge cases & AEAD failure modes, TLS 1.2 CBC padding security + DTLS parsing + TLS 1.3 inner plaintext edge cases, DTLS fragmentation/retransmission + CertificateVerify edge cases, DTLS codec edge cases + anti-replay boundaries + entropy conditioning, X.509 extension parsing + WOTS+ base conversion + ASN.1 tag edge cases, PKI encoding helpers + X.509 signing dispatch + certificate builder encoding, X.509 certificate parsing + SM9 G2 point arithmetic + SM9 pairing helpers, SM9 hash functions + SM9 algorithm helpers + SM9 curve parameters, McEliece keygen helpers + McEliece encoding + McEliece decoding, XMSS tree operations + XMSS WOTS+ deepening + SLH-DSA FORS deepening, McEliece GF(2^13) + Benes network + binary matrix deepening, FrodoKEM matrix ops + SLH-DSA hypertree + McEliece polynomial deepening, McEliece + FrodoKEM + XMSS parameter set validation deepening, XMSS hash abstraction + XMSS address scheme + ML-KEM NTT deepening, BigNum constant-time + primality testing + core type deepening, SLH-DSA params + hash abstraction + address scheme deepening, FrodoKEM PKE + SM9 G1 point + SM9 Fp field deepening, ML-DSA NTT + SM4-CTR-DRBG + BigNum random deepening, DH group params + entropy pool + SHA-1 deepening, ML-KEM poly + SM9 Fp12 + encrypted PKCS#8 deepening, ML-DSA poly + X.509 extensions + X.509 text deepening, XTS mode + Edwards curve + GMAC deepening, scrypt + CFB mode + X448 deepening
- Phase R1–R10: Architecture refactoring — PKI encoding consolidation, record layer enum dispatch, connection file decomposition, hash digest enum dispatch, sync/async unification via body macros, X.509 module decomposition, integration test modularization, test helper consolidation, parameter struct refactoring, DRBG state machine unification
- Phase R11, R12: Dev profile optimization — per-crate opt-level overrides (hitls-bignum=2, hitls-crypto=2), un-ignored 44→6 tests
- Phase T44: Semantic fuzz target expansion — AEAD decrypt fuzzing, X.509 verification path fuzzing, deep TLS handshake decoder fuzzing (10→13 fuzz targets, 66→79 corpus files)
- Phase P5: P-256 deep optimization — dedicated mont_sqr (10 vs 16 multiplies), P-256 specialized Montgomery reduction (P[0]=-1, P[2]=0), precomputed comb base table (64×16 affine points, OnceLock + batch inversion), mixed Jacobian-affine addition. ECDSA sign 21× speedup, verify 14× speedup.
- Phase P6: ML-KEM NEON NTT optimization — 8-wide Montgomery multiply (`vqdmulhq_s16` + `vhsubq_s16` trick), NEON forward/inverse NTT (stages len≥8 fully vectorized), NEON Barrett reduction (widening multiply + shift-narrow), NEON poly utilities (add/sub/to_mont/reduce), batch SHAKE-128 squeeze (504-byte blocks vs 3-byte). ML-KEM-768 encaps 2.0× speedup, decaps 2.6× speedup.
- Phase P7: BigNum CIOS Montgomery — CIOS fused multiply+reduce (single (n+2)-limb accumulator vs 2n-limb intermediate), pre-allocated flat limb table for exponentiation, optimized sqr_limbs with cross-product symmetry, single conditional subtraction. DH-2048 1.25× speedup (174→218 ops/s), RSA-2048 sign 1.11× speedup (719→800 ops/s). Gap narrowed from 7× to 5.6× vs C.
- Phase P8: SM4 T-table lookup optimization — compile-time T-tables (XBOX_0–3/KBOX_0–3) fusing S-box + L/L' transform into u32 lookups, 4-way unrolled rounds, precomputed decrypt keys. SM4-CBC 2.37× speedup (50.8→120.2 MB/s, parity with C), SM4-GCM 3.09× speedup (47.6→146.9 MB/s, 1.68× faster than C).
- Phase P9: ML-DSA NEON NTT vectorization — 4-wide i32 NEON intrinsics (`vqdmulhq_s32` + `vhsubq_s32` Montgomery trick), forward/inverse NTT (len≥4 vectorized, len=2 half-register, len=1 scalar), Barrett reduction, pointwise multiply, poly utilities. NTT 2.31× speedup, INTT 2.54× speedup. End-to-end ML-DSA improvement modest (~2–5%) due to SHAKE-128 sampling dominance.
- Phase P10: SM2 specialized field arithmetic — 4×u64 Montgomery field elements (SM2 prime P[0]=-1 trick), precomputed comb base table (64×16 affine points, OnceLock + batch inversion), w=4 fixed-window scalar mul, mixed Jacobian-affine addition, a=-3 optimized doubling. SM2 sign 25.3× speedup (1.43ms→56.6µs), verify 21.1× speedup (1.75ms→83.2µs), encrypt 18.7× speedup, decrypt 20.2× speedup.
- Phase P11: SHA-512 ARMv8.2 hardware acceleration — SHA-512 Crypto Extension intrinsics (`vsha512hq_u64`/`vsha512h2q_u64`/`vsha512su0q_u64`/`vsha512su1q_u64`), 5-register rotation pattern, K+W halves swap, runtime detection (`sha3` feature). SHA-512 2.4× speedup (662→1578 MB/s), SHA-384 3.9× speedup (411→1597 MB/s). Rust now 1.8× faster than C.
- Phase P12: Ed25519 precomputed base table — comb method (64 groups × 16 Niels points), NielsPoint form (Y+X, Y-X, 2d·T) for 7M mixed addition, OnceLock-cached table, constant-time lookup. Ed25519 sign 3.1× speedup (29.7→9.5 µs), verify 1.5× speedup (61.9→40.9 µs). Rust now 1.6× faster than C for sign, at parity for verify.
- Phase P13: ML-DSA batch squeeze — replace per-byte/per-3-byte SHAKE squeeze with 504-byte (SHAKE-128) / 136-byte (SHAKE-256) batch operations in rejection sampling (`rej_ntt_poly`, `rej_bounded_poly`, `sample_in_ball`).
- Phase P14: Keccak heap elimination — `KeccakState.buf` from `Vec<u8>` to `[u8; 200]` stack array, zero heap allocations in SHA-3/SHAKE sponge operations, `Copy` derive on `KeccakState`.
- Phase P15: BigNum mont_exp squaring — dedicated `sqr_limbs` (cross-product symmetry, ~33% fewer multiplies) replacing generic `cios_mul(a,a)` for squaring steps in modular exponentiation.
- Phase P16: SM3 compression optimization — precomputed `T_J_ROTATED[64]` const table, split compression loop (rounds 0–15 XOR, 16–63 majority/choice), eliminated `wp[64]` array, inlined `p0`/`p1`.
- Phase P17: P-256 scalar field — new `P256ScalarElement` (4×u64 Montgomery mod curve order n), compile-time N0/R2/ONE constants, schoolbook mul/sqr with generic 4-limb reduction, Fermat inversion with addition chain + 4-bit window. Integrated into ECDSA sign for P-256 fast path.
- Phase P18: Keccak ARMv8 SHA-3 HW acceleration — EOR3 (3-input XOR) for theta column parities, RAX1 (rotate+XOR) for theta d, BCAX (bit-clear+XOR) for chi step. Runtime `sha3` feature detection with software fallback. Cfg-gated by `has_sha3_keccak_intrinsics` (Rust ≥ 1.79).
- Phase P19: SHAKE `squeeze_into` zero-allocation — `squeeze_into(&mut [u8])` for Shake128/Shake256, stack buffers in ML-KEM/ML-DSA/FrodoKEM rejection sampling loops, squeeze state machine fix for incremental rate-sized calls.
- Phase P20: CTR-DRBG AES/SM4 key caching — cached `AesKey`/`Sm4Key` in DRBG structs, eliminates per-block key expansion (67→1 expansions per 1KB output), `block_cipher_df` key reuse.
- Phase P21: AES-GCM/CBC monomorphization — `&dyn BlockCipher` → `<C: BlockCipher>` in `gcm_crypt_generic`, `cbc_encrypt_with`, `cbc_decrypt_with`. Eliminates vtable indirect calls, enables inlining.
- Phase P22: Miller-Rabin Montgomery optimization — single `MontgomeryCtx` for all witnesses (8→1 R²), `mont_exp_mont()` for Montgomery-form result, `mont_sqr` in inner loop. 2–3× Miller-Rabin speedup for 2048-bit primes.
- Phase P23: GCM/CCM per-record key schedule + GHASH table caching — AesGcmAead/Sm4GcmAead store pre-expanded cipher + precomputed GhashTable, AesCcmAead/Sm4CcmAead store pre-expanded cipher. Eliminates per-record AES key expansion + GHASH table build.
- Phase P24: TLS 1.2 CBC per-record AES key caching — 4 CBC record structs store pre-expanded `AesKey` instead of raw key bytes. Eliminates per-record AES key expansion in encrypt/decrypt.
- Phase P25: CBC generic path stack arrays — `Vec<u8>` → `[u8; 16]` for `prev` and `ct_copy` temporaries in `cbc_encrypt_with`/`cbc_decrypt_with`. Eliminates per-block heap allocation in decrypt.
- Phase P26: HMAC reset + TLS 1.2 CBC HMAC caching — Removed `Box<dyn Fn>` factory from `Hmac`, uses `Digest::reset()` for zero-alloc reset, stack arrays for all buffers. TLS 1.2 CBC record structs cache `Hmac` instance, eliminating per-record HMAC construction.
- Phase P27: CCM zero-allocation tag + CBC-MAC — Tag buffers `vec![0u8; tag_len]` → `[u8; 16]` stack, AAD encoding Vec → block-by-block XOR with stack header, plaintext padding `to_vec()` → inline partial-block processing.
- Phase P28: ChaCha20-Poly1305 padding stack arrays — `vec![0u8; N]` padding → `const ZEROS: [u8; 15]` static array slice in `compute_tag()`.
- Phase P29: PBKDF2 inner loop stack arrays — `vec![0u8; 32]` → `[0u8; 32]` stack for u/t/u_next, in-place `finish()` eliminates per-iteration allocation. For 80K iterations: 80K→0 heap allocations.
- Phase P30: HKDF expand stack arrays + HMAC reuse — `t_prev`/`t` Vec → `[u8; 32]` stack, default salt Vec → stack, reuse single `Hmac` with `reset()` across all expand iterations.
- Phase P31: TLS PRF stack arrays — label_seed and ai_seed concatenation Vec → `[u8; 128]`/`[u8; 192]` stack buffers, eliminated per-iteration concatenation allocation.
- Phase P32: TLS HKDF stack arrays — `hmac_hash`/`hkdf_extract`/`hkdf_expand` all Vec replaced with `[u8; 128]`/`[u8; 64]` stack arrays. Eliminated ~6 Vec per HMAC call and ~4N Vec per expand (N iterations).
- Phase P33: Key schedule + export stack arrays — `empty_hash()`/`zero_psk`/`zero_ikm` in key schedule and `empty_hash`/`ctx_hash` in export replaced with `[0u8; 64]` stack arrays. 5 allocations eliminated per TLS 1.3 handshake.
- Phase P34: Handshake hash output stack arrays — `vec![0u8; hash_len]` → `[0u8; 64]` in macros.rs (cr_hash/cv_hash/fin_hash), connection/server.rs (fin_hash_buf/cv_hash), handshake/server.rs (binder hash), handshake/client.rs (binder/eems/ch hash). 10 allocations eliminated across handshake paths.
- Phase P35: RSA padding stack arrays — OAEP seed `vec![0u8; 32]` → `[0u8; 32]`, PSS salt `vec![0u8; salt_len]` → `[0u8; 64]` stack (with Vec fallback for >64), PKCS1v15 `fill_nonzero_random` eliminated `vec![0u8; buf.len()]` (only 1 byte was ever used).
- Phase P36: HKDF label stack encoding — inlined `encode_hkdf_label` into `hkdf_expand_label` with `[0u8; 128]` stack buffer, eliminated per-call Vec allocation for HkdfLabel encoding. Vec fallback for >128 bytes.
- Phase P37: TLCP/DTLCP record stack arrays — MAC functions return `[u8; 32]` instead of `Vec<u8>`, padding functions return `([u8; 16], usize)` instead of `Vec<u8>`. Eliminates per-record heap allocations in CBC encrypt/decrypt.
- Phase P38: TLCP/DTLCP CBC HMAC caching — cached `Hmac` instances in encryptor/decryptor structs, `reset()` reuse per record instead of `Hmac::new(|| Box::new(...))` per record. Eliminates 3 box allocations per record.
- Phase P39: CBC decrypt truncate-in-place — `decrypted[..content_len].to_vec()` → `decrypted.truncate(content_len)` in all 4 CBC decrypt paths (TLS 1.2 MtE/EtM, TLCP, DTLCP). Eliminates one heap allocation per CBC record decryption.
- Phase P40: HMAC hash stack return — `hmac_hash()` returns `([u8; 64], usize)` instead of `Vec<u8>`. Eliminates per-call heap allocation in PRF iterations and HKDF operations.
- Phase P41: RSA OAEP/PSS in-place XOR — `.collect()` XOR patterns → `iter_mut().zip()` in-place. Eliminates 5 Vec allocations per RSA encrypt/decrypt/sign/verify.
- Phase P42: TLS 1.2 key schedule seed stack arrays — `Vec::with_capacity(64)` → `[0u8; 64]` for seed (always 2×32-byte randoms). Eliminates 3 heap allocations per TLS 1.2/TLCP handshake.
- Phase P43: ML-DSA hint encoding stack array — `vec![0u8; omega+k]` → `[0u8; 96]` in `encode_sig`. Eliminates per-sign heap allocation.
- Phase P44: SM2/SM9 in-place XOR — reuse KDF output `t` for XOR (SM2) and `k1.to_vec()` + in-place XOR (SM9) instead of `.collect()`. Eliminates 2 Vec allocations per SM2 encrypt/decrypt, 2 per SM9 encrypt/decrypt.
- Phase P45: ML-DSA signing loop heap elimination — `sample_mask_poly` `squeeze_into` with `[0u8; 640]` stack buffer, `hash_h_into`/`hash_h2_into` to caller stack arrays, `pack_w1_into`/`pack_z_into` zero-copy packing, pre-allocated `hash_input` Vec (1 alloc vs ~14/iter), `decode_sk` returns `[u8; 64]` for tr.
- Phase T45–T53: Quality improvement roadmap — TLS connection unit tests (+15), TLS 1.2 handshake edge cases (+15), HW↔SW cross-validation (+8), proptest expansion to 5/9 crates (+15), side-channel timing tests (+6), concurrency stress tests (+10), feature flag smoke tests (+4), zeroize runtime verification (+4), DTLS fuzz + OpenSSL interop (+1 fuzz target, +2 tests). Total: +80 tests, 13→14 fuzz targets, defense model B→B+.
- Phase T59–T62: Test optimization & deep defense — RSA OAEP/PKCS1v15 constant-time fix (timing side-channel elimination), CBC/GCM buffer zeroize on error, RSA timing tests (+2 ignored), unit tests (+2), crypto semantic fuzz targets (+6: RSA/ECDSA/HKDF/SM2/CCM/TLS PRF), TLS 1.3/1.2 state machine fuzz (+2), corpus enrichment (+40 seeds), cargo-deny supply-chain policy, CI hardening (miri blocking, feature combos, cargo-deny job), subtle version unification. Total: +4 tests, 18→26 fuzz targets, 118→158 corpus, defense model B+→A-.
- Phase T63: PQC fuzz + signature sign fuzz — ML-KEM encap/decap, ML-DSA sign/verify, SLH-DSA sign/verify (fast variants), RSA sign (PKCS1v15/PSS), ECDSA sign (P-256/P-384/P-521), Ed25519 full coverage, SM2 sign/encrypt/decrypt, DSA sign (small params). Total: +8 fuzz targets (26→34), +80 corpus seeds (158→238), PQC coverage 0→3/6, sign-path coverage 0→5/7.

See `DEV_LOG.md` for detailed phase tables (including test, refactoring, and performance phases) and `PROMPT_LOG.md` for prompt/response log.
