# openHiTLS-rs — Quality Assurance Report

> Quality safety net analysis and testing optimization roadmap.
> Related docs: [DEV_LOG.md](DEV_LOG.md) | [README.md](README.md)

---

## 1. Current Quality Safety Net

### 1.1 Defense Layers (7-Layer Model)

| Layer | Mechanism | Coverage | Rating | Notes |
|:-----:|-----------|----------|:------:|-------|
| **L1** | Static Analysis | clippy zero-warning + rustfmt + MSRV 1.75 dual-version CI + workspace lints | **A+** | Full workspace, all features, all targets; centralized `[workspace.lints]` (T74-A) |
| **L2** | Unit Tests | 3,965 tests (25 ignored), 100% pass rate | **A** | 3,940+ test fns + 92 async + 15 Wycheproof suites; all high-risk files directly tested |
| **L3** | Integration Tests | 261 cross-crate tests (TCP loopback + DTLS resilience + OpenSSL interop) | **A** | 14 test files; 5 protocol variants × sync/async; OpenSSL s_client/s_server interop |
| **L4** | Fuzz Testing | 65 fuzz targets + 429 seed corpus files | **A** | 10 parse + 34 crypto semantic + 8 PQC/sign-path + 13 additional; +fuzz-smoke on PR/push |
| **L5** | Property-Based Testing | ~87 proptest blocks across 6 crates | **A** | hitls-crypto + hitls-utils + hitls-tls + hitls-pki + hitls-bignum + hitls-auth; comprehensive algorithm coverage |
| **L6** | Standard Vectors | 15 Wycheproof suites + 7 FIPS KATs + 11 RFC vector sets + 10+ GB/T | **A** | 5,000+ vectors; all major algorithms covered |
| **L7** | Concurrency & Side-Channel | 48 concurrency-aware tests; 9 timing tests | **B** | Statistical timing analysis (Welch's t-test); multi-threaded stress tests; +3 AEAD ct_verify tests (T74-G) |

### 1.2 CI/CD Pipeline

```
GitHub Actions (.github/workflows/ci.yml) — 20 jobs, dependency graph: fmt/clippy → test/coverage/miri/ignored
├── Format Check       cargo fmt --all -- --check
├── Clippy Lint        cargo clippy --all-targets --all-features -- -D warnings
├── Test Matrix        Ubuntu + macOS + Windows × Rust stable + MSRV 1.75 (6 jobs)
│   └── Uses cargo-nextest for parallel execution + retry (T74-C)
├── Feature Testing    Individual + combo feature flags (59 combos)
├── Security Audit     rustsec/audit-check@v2
├── UB Detection       Miri on hitls-bignum + hitls-utils + hitls-crypto (benes + mlkem::ntt + mldsa::ntt + modes::gcm + sha2 + sha3 + chacha20 + sm3 + sm4 + p256 + p384 + p521)
├── Supply Chain       cargo-deny check (advisories + licenses + bans + sources)
├── Fuzz Build         cargo fuzz check (nightly) — 65 targets
├── Fuzz Smoke         Every PR/push: 10s per target smoke test (T68-A)
├── Cross-compile      aarch64-unknown-linux-gnu + i686-unknown-linux-gnu
├── Documentation      cargo doc --workspace --all-features -D warnings
├── Ignored Tests      Timing + zeroize + slow keygen (weekly + on-demand)
├── Bench Verify       cargo bench --no-run
├── Bench Compare      PR-only: Criterion base vs head with critcmp (T74-D)
├── Semver Check       PR-only: cargo-semver-checks on 7 library crates (T74-B)
├── Careful            cargo-careful UB detection on hitls-bignum + hitls-crypto (T74-F)
├── Coverage           cargo-llvm-cov → Codecov JSON + branch coverage (8 components)
├── Scheduled Fuzz     Weekly: all 65 targets × 60s each (Monday 03:00 UTC)
├── Scheduled Mutants  Weekly: cargo-mutants on hitls-bignum + hitls-utils (T74-E)
└── Dependabot         Weekly cargo + github-actions + fuzz dependency updates (T74-H)
```

### 1.3 Per-Crate Test Distribution

| Crate | Tests | Ignored | % of Total | Focus |
|-------|------:|--------:|:----------:|-------|
| hitls-crypto | 1,464 | 17 | 36.7% | 48 algorithm modules + HW accel + P-256/384/521 fast path + proptest + HW↔SW cross-validation + timing + ct_verify + zeroize + DRBG + GCM + FIPS PCT/KAT + HPKE + KAT golden-values |
| hitls-tls | 1,434 | 0 | 35.9% | TLS 1.3/1.2/DTLS/TLCP/DTLCP handshake, record, extensions, callbacks, middlebox compat, connection state guards, security levels, CRL, PHA |
| hitls-pki | 426 | 0 | 10.7% | X.509, PKCS#8/12, CMS (5 content types), CRL builder+extensions, encoding helpers, proptest roundtrips |
| hitls-integration | 261 | 2 | 6.5% | Cross-crate TCP loopback, error scenarios, concurrency stress, DTLS resilience, OpenSSL interop, TLS 1.3/1.2 key_update + session resumption + HPKE + XMSS-MT + CRL |
| hitls-cli | 161 | 5 | 4.0% | 16 CLI commands, speed benchmarks, s_client/s_server edge cases, hex/cipher/port edge cases, prime/kdf |
| hitls-bignum | 95 | 1 | 2.4% | Montgomery, Miller-Rabin, prime generation, modular arithmetic, constant-time, random generation, hex/dec string, proptest |
| hitls-utils | 68 | 0 | 1.7% | ASN.1, Base64, PEM, OID, proptest roundtrips |
| hitls-auth | 47 | 0 | 1.2% | HOTP/TOTP, SPAKE2+, Privacy Pass (edge cases + proptest) |
| hitls-types | 26 | 0 | 0.7% | Enum definitions, error types |
| **Total** | **3,990** | **25** | **100%** | |

### 1.4 Standard Compliance Coverage

| Source | Algorithms | Vector Count |
|--------|------------|:------------:|
| **Wycheproof** (Google) | AES-GCM/CCM/CBC, ChaCha20, ECDSA P-256/384/521, ECDH, Ed25519, X25519, RSA PKCS#1/PSS, HKDF, HMAC | 5,000+ |
| **RFC test vectors** | Ed25519/Ed448 (RFC 8032), X25519/X448 (RFC 7748), HKDF (RFC 5869), HMAC (RFC 4231/2202), ChaCha20 (RFC 8439), AES Key Wrap (RFC 3394), Scrypt (RFC 7914) | 50+ |
| **FIPS/NIST** | SHA-256 (FIPS 180-4), AES (FIPS 197), GCM (SP 800-38D), HMAC-DRBG (SP 800-90A), Entropy (SP 800-90B) | 7 KATs |
| **GB/T** (Chinese) | SM3 (GB/T 32905), SM4 (GB/T 32907) | 10+ |

### 1.5 Security Mechanisms

| Mechanism | Implementation | Test Coverage |
|-----------|---------------|:-------------:|
| Zeroize on drop | All secret types (keys, intermediate states) | Compile-time (derive) + 4 runtime drop verification tests (Phase T52) |
| Constant-time comparison | `subtle::ConstantTimeEq` in all crypto comparisons | 9 statistical timing tests (Welch's t-test, Phase T49 + T74-G ct_verify) |
| Unsafe code confinement | ~44 blocks: AES-NI (8), AES-NEON (6), SHA-2 HW (8), GHASH HW (22), ChaCha20 SIMD (15), McEliece (2) | NIST/RFC vectors + 8 HW↔SW cross-validation tests (Phase T47) |
| Random generation | `getrandom` crate, never `rand` | Indirect |

### 1.6 Test Type Distribution

| Category | Count | % | Description |
|----------|------:|--:|-------------|
| Error handling | ~370 | 10.1% | invalid/reject/wrong/error/fail paths |
| Roundtrip | ~350 | 9.5% | encrypt↔decrypt, sign↔verify, encode↔decode |
| Edge case | ~325 | 8.9% | empty/zero/boundary/single-byte/partial block |
| Standard vectors | ~106 | 2.9% | RFC/NIST/Wycheproof/KAT/GB/T test vectors |
| Async | 92 | 2.5% | tokio::test async connection + handshake |
| State machine | ~600 | 16.4% | handshake/connected/not-connected state transitions |
| Property-based | ~87 | 2.2% | proptest blocks (6 crates: crypto + utils + tls + pki + bignum + auth; comprehensive algorithm + codec coverage) |
| Concurrency | 48 | 1.2% | Arc/Mutex/thread::spawn/tokio::spawn stress tests |
| Timing/side-channel | 9 | 0.2% | Welch's t-test statistical timing analysis (6 timing.rs + 3 ct_verify.rs) |
| HW↔SW cross-validation | 8 | 0.2% | Software/hardware path differential tests |
| Zeroize verification | 4 | 0.1% | Drop-based memory zeroing verification |
| Other (deterministic, helper, etc.) | ~1,729 | 47.2% | Specific algorithm/module unit tests |

**Key observations**: Error-handling tests (~370) outnumber roundtrip tests (~350), indicating good negative-path coverage. Property-based testing now spans 6/9 crates with ~87 proptest blocks. Concurrency and timing tests have been significantly expanded. Fuzz coverage expanded from 14 → 65 targets with PQC and signature-path coverage. Phase T67 added `CryptoError::InvalidArg(&'static str)` with ~30 descriptive context strings and eliminated 16 `.unwrap()` panic risks in crypto library code. Phase T69–T73 expanded Miri coverage to NTT + GCM + SHA-2/3 + SM3/SM4 + P-256/384/521, feature flag isolation to 59 combos, and proptests to ~87 blocks across 6 crates. Phase T74 added quality infrastructure: workspace lint centralization, cargo-nextest, cargo-semver-checks, Criterion bench-compare, cargo-mutants, cargo-careful, and 3 new constant-time verification tests (ct_verify.rs).

### 1.7 High-Risk Zero Direct Unit Test Files — **SIGNIFICANTLY REDUCED** (Phase T45–T46)

Phase T45 added 15 state guard + I/O edge case tests and Phase T46 added 15 TLS 1.2 handshake + post-HS auth tests, directly covering the previously untested connection code:

| File | Lines | Risk | Coverage Mechanism |
|------|------:|:----:|-------------------|
| `hitls-tls/src/macros.rs` | 1,417 | **Low** | Phase T45: 15 state guard tests (write/read before handshake, key_update limits, shutdown states) |
| `hitls-tls/src/connection12/client.rs` | 1,025 | **Low** | Phase T46: 15 handshake edge case tests (EKM, session resumption, verify_data, MFL) |
| `hitls-tls/src/connection12/server.rs` | 927 | **Low** | Phase T46: server handshake tests (no shared cipher, cert request optional) |
| `hitls-tls/src/connection/server.rs` | 369 | **Low** | Phase T45: state guard tests + Phase T46: post-HS cert auth tests |
| `hitls-tls/src/connection/client.rs` | 197 | **Low** | Phase T45: connection_info, peer_certificates, negotiated_alpn tests |
| `hitls-crypto/src/provider.rs` | 144 | **Low** | Phase T65: +3 dedicated tests (HashAlgorithm default impl, Digest output_size/block_size, reset cycle) |

These files now have **33 dedicated unit tests** via Phase T45–T46 + T65, covering state transitions, error paths, and edge cases. Risk reduced from Critical → Low. `provider.rs` now has 3 direct tests via T65.

---

## 2. Identified Deficiencies

### 2.1 Deficiency Map

```
Severity         ID   Description                                  Impact
────────────     ──   ──────────────────────────────────────────   ──────────────────────────
CLOSED           D1   0-RTT replay protection: +8 tests             Resolved (Phase T9)
CLOSED           D2   Async TLCP/DTLCP: zero tests                   Resolved (Phase T11: +15)
CLOSED           D3   Extension negotiation: +14 e2e tests           Resolved (Phase T12: +14)
MOSTLY CLOSED    D4   DTLS loss/resilience: +30 tests                Resolved (Phase T13/T24/T25)
MOSTLY CLOSED    D5   TLCP double certificate: +25 tests             Resolved (Phase T14/T20)
CLOSED           D6   Property-based testing: +20 proptest           Resolved (Phase T18)
CLOSED           D7   Code coverage metrics in CI                    Resolved (Phase T18 tarpaulin → T65 llvm-cov + branch)
PARTIALLY CLOSED D8   Cross-implementation interop (Phase T53)      OpenSSL s_client/s_server tests; TLS 1.2 verify_data gap found
CLOSED           D9   Fuzz targets: parse-only                      Resolved (Phase T44/T59–T63: 40 targets, full crypto semantic + PQC coverage)
MOSTLY CLOSED    D10  Crypto files without unit tests                Resolved (Phase T15–T17/T25/T65)
──────── Phase T43 深度分析 → Phase T45–T65 Quality Improvement ────────
CLOSED           D11  Semantic/state-machine fuzz (Phase T44/T59–T63) 40 targets (10 parse + 22 semantic + 8 PQC/sign); 286 corpus files
PARTIALLY CLOSED D12  Side-channel timing tests (Phase T49)         6 timing tests added (Welch's t-test); more algorithms needed
CLOSED           D13  TLS connection code unit tests (Phase T45/T46) +30 state guard + handshake edge case tests
MOSTLY CLOSED    D14  Proptest scope expanded (Phase T48)           5/9 crates covered (was 2/9)
PARTIALLY CLOSED D15  Concurrency stress tests (Phase T50)          +10 multi-threaded stress tests (48 total)
CLOSED           D16  HW↔SW cross-validation (Phase T47)           +8 differential tests across all HW-accel modules
CLOSED           D17  Zeroize runtime verification (Phase T52)      +4 drop-based memory zeroing tests
CLOSED           D18  Feature flag smoke tests (Phase T51)          +4 smoke tests for feature subsets
──────── Phase T66–T67 CI Hardening + Code Quality ────────
CLOSED           D19  CI pipeline hardening (Phase T66)             Job dependency graph, Windows CI, cross-compile, cargo doc, Dependabot
CLOSED           D20  Panic-free crypto library (Phase T67)         16 .unwrap()→? in hash/ed25519/ed448/rsa; InvalidArg context strings
──────── Phase T68 Deep Analysis → Quality Safety Net Enhancement ────────
CLOSED           D21  Fuzz-smoke on PR/push (Phase T68-A)           +fuzz-smoke job, 10s per target on every PR
CLOSED           D22  Feature flag combos expanded (Phase T68-A)   9→24 combos in CI, +concurrency block
MOSTLY CLOSED    D23  +6 fuzz targets (Phase T68-B)                AES/ChaCha20/CMAC/ECDH/Scrypt/McEliece; 6/12 remaining
CLOSED           D24  Record layer zeroize on error (Phase T68-D)  CBC MtE/EtM + TLCP + DTLCP decrypt paths; +3 tests
CLOSED           D25  Proptest PQC/RSA/ECDSA/ECDH (Phase T68-C)   +9 proptest blocks across 5 modules
CLOSED           D26  Benchmarks lack regression detection          T74-D: Criterion bench-compare CI job (PR-only, base vs head with critcmp)
MOSTLY CLOSED    D27  Miri covers only 3/21 unsafe modules          T69–T73: +NTT + GCM + SHA-2/3 + SM3/SM4 + P-256/384/521; remaining: HW accel SIMD (untestable by Miri)
OPEN             D28  hitls-tls/hitls-auth/PKI low test density     1.1 tests/KLOC (tls), 1.2 tests/100L (cert parsing)
──────── Phase T69 Quality Safety Net P0 Enhancement ────────
CLOSED           D29  Feature flag isolation (Phase T69)            15→27 hitls-crypto single features + dtls12 + pki + auth; `aes,gcm`→`aes,modes` fix
CLOSED           D30  Miri NTT + GCM expansion (Phase T69)         +mlkem::ntt + mldsa::ntt (skip NEON) + modes::gcm; D→C+
CLOSED           D31  Proptest +6 modules (Phase T69)              DH/DSA/Ed448/SM2/SM9/SLH-DSA; 37→47 blocks; B→B+
──────── Phase T74 Quality Infrastructure + Deep Testing Audit ────────
CLOSED           D32  No semver-checks CI (Phase T74-B)            cargo-semver-checks on 7 library crates (PR-only)
CLOSED           D33  No mutation testing (Phase T74-E)            Weekly cargo-mutants on hitls-bignum + hitls-utils
OPEN             D34  Mutex .lock().unwrap() in TLS production     ~48 occurrences; poisoned mutex → panic risk
OPEN             D35  panic!() in library code (SLH-DSA params)    2 occurrences in hitls-crypto production code
```

### 2.2 D1 — 0-RTT Replay Protection ~~(Critical)~~ — **CLOSED** (Phase T9)

**Resolved**: Phase T9 added 8 tests covering:
- Early data extension codec (ClientHello/EncryptedExtensions/NewSessionTicket wire format)
- Client offering logic (no-PSK guard, zero max_early_data guard)
- Async 0-RTT accepted flow (session resumption → queue → verify early data received)
- Async 0-RTT rejected flow (server rejects → 1-RTT fallback works)
- Queue API accumulation and pre-handshake state

Remaining uncovered areas (lower risk, tracked for future phases):
- PSK `obfuscated_ticket_age` validation
- Binder verification for replay prevention
- `EndOfEarlyData` message codec roundtrip

### 2.3 D2 — Async/Sync Test Coverage Asymmetry ~~(Critical)~~ — **CLOSED** (Phase T11)

**Resolved**: Phase T10 added 10 async TLS 1.2 tests. Phase T11 created async connection types for TLCP and DTLCP and added 15 tests (8 TLCP + 7 DTLCP). All 5 protocol variants now have async tests.

| Connection Type | Sync Tests | Async Tests | Gap |
|-----------------|:----------:|:-----------:|:---:|
| TLS 1.3 | 61 | 25 | -36 |
| TLS 1.2 | 53 | 28 | -25 |
| DTLS 1.2 | 20 | 8 | -12 |
| TLCP | 15 | **8** | -7 |
| DTLCP | 6 | **7** | +1 |

Remaining async gaps are coverage depth (fewer test scenarios than sync), not missing connection types.

### 2.4 D3 — Extension Negotiation ~~(High)~~ — **CLOSED** (Phase T12)

Phase T12 added 14 E2E tests covering all identified gaps:
- ALPN no-common-protocol (TLS 1.3 + 1.2), server preference order (TLS 1.2)
- SNI accessor verification on both client and server (TLS 1.3 + 1.2)
- Group negotiation: server preference, HRR trigger, no-common-group failure
- Max fragment length (TLS 1.2), record size limit (TLS 1.3 + 1.2)
- Combined ALPN + SNI + group verification via ConnectionInfo
- Codec: duplicate extension type, zero-length extension parsing

### 2.5 D4 — DTLS Loss/Retransmission ~~(High)~~ — **MOSTLY CLOSED** (Phase T13/T24/T25)

**Resolved across 3 phases** with 30 total DTLS-specific tests:

- **Phase T13** (+10): Post-handshake adverse delivery — out-of-order, selective loss, stale records, corrupted ciphertext, truncated/empty datagrams, wrong epoch, interleaved bidirectional
- **Phase T23** (+10): Fragmentation reassembly (multi-message, old message, out-of-order, overlapping fragments) + retransmission timer (backoff, reset cycles, timeout cap, Flight clone)
- **Phase T24** (+10): Codec edge cases (all handshake types, fragment offset, TLS↔DTLS roundtrip, HVR empty/max cookie) + anti-replay window boundaries (uninitialized, near u64::MAX, shift by WINDOW_SIZE, reset/reuse)

**Remaining** (requires handshake driver refactoring, out of scope for test phase):
- Handshake-level loss simulation (e.g., ClientHello lost → timeout retransmission)
- Out-of-order handshake flight delivery (Finished before Certificate)

### 2.6 D5 — TLCP Double Certificate ~~(High)~~ — **MOSTLY CLOSED** (Phase T14/T20)

**Resolved across 2 phases** with 25 total TLCP-specific tests:

- **Phase T14** (+10): Missing encryption certificate, missing signing key, wrong key type — unit + integration for both TLCP and DTLCP
- **Phase T19** (+15): SM3 transcript hash correctness (empty hash, incremental, hash_len), SM3-PRF determinism and cross-validation, TLCP key schedule (master secret, CBC/GCM key blocks), verify_data SM3 client/server, EMS → key block pipeline, seed order sensitivity, full SM3 verify pipeline

**Remaining gap** (low risk):
- Encryption cert used in ClientKeyExchange SM2 encryption: covered by existing happy-path tests but no dedicated edge-case test

### 2.7 D6 — ~~No Property-Based Testing~~ (Medium) — **CLOSED** (Phase T18)

**Resolved**: Phase T18 added 20 proptest property-based tests:

- **Crypto roundtrips** (6): AES-128/256 block, SM4 block, GCM AEAD, CBC, ChaCha20-Poly1305
- **Hash determinism** (3): SHA-256 determinism, SHA-256 incremental equivalence, HMAC-SHA-256 determinism
- **Signature roundtrip** (1): Ed25519 sign/verify for arbitrary messages
- **DH commutativity** (1): X25519 `dh(a, pub(b)) == dh(b, pub(a))`
- **KDF determinism** (1): HKDF-expand determinism
- **Codec roundtrips** (8): Base64, hex, ASN.1 integer/octet string/boolean/UTF8 string/sequence

### 2.8 D7 — ~~No Code Coverage Metrics~~ (Medium) — **CLOSED** (Phase T18 → T65 upgrade)

**Resolved**: Phase T18 added initial coverage CI (cargo-tarpaulin). **Phase T65** upgraded to `cargo-llvm-cov` with branch coverage:

```yaml
coverage:
  runs-on: ubuntu-latest
  steps:
    - uses: taiki-e/install-action@cargo-llvm-cov
    - cargo llvm-cov --workspace --all-features --branch --codecov
        --output-path coverage/codecov.json
        --ignore-filename-regex "tests/vectors/"
    - Upload to Codecov (codecov/codecov-action@v4)
```

**Key improvements (T65)**: `--branch` enables branch coverage visibility, `--codecov` outputs native Codecov JSON (replaces Cobertura XML), `taiki-e/install-action` provides pre-compiled binary (~5-10× faster than `cargo install`).

### 2.9 D8 — Cross-Implementation Interop ~~(Medium)~~ — **PARTIALLY CLOSED** (Phase T53)

**Phase T53** added OpenSSL CLI interop tests (`tests/interop/tests/openssl_interop.rs`):

| Test | Protocol | Result |
|------|----------|--------|
| `test_openssl_s_client_tls13` | OpenSSL s_client → hitls-rs TLS 1.3 server | **PASS** — full handshake + TLSv1.3 negotiation verified |
| `test_openssl_s_server_tls12` | hitls-rs client → OpenSSL s_server TLS 1.2 | **Known gap** — `verify_data` mismatch in handshake transcript |

**Key finding**: TLS 1.3 interop with OpenSSL works correctly. TLS 1.2 has a `verify_data` mismatch indicating a difference in handshake transcript computation — documented for future investigation.

**Remaining gaps**:
- Post-quantum algorithms (ML-KEM/ML-DSA/SLH-DSA) have no cross-implementation verification
- TLS 1.2 verify_data mismatch needs root cause analysis
- No BoringSSL/GnuTLS interop testing

### 2.10 D9 — ~~Fuzz Targets Parse-Only~~ (Low-Medium) — **CLOSED** (Phase T44 + T59–T63)

**Resolved**: Fuzz targets expanded from 10 parse-only to 40 comprehensive targets:

| Category | Count | Examples |
|----------|:-----:|---------|
| Parse-only | 10 | ASN.1, PEM, X.509, TLS record/handshake, CMS, PKCS#8/12 |
| Crypto semantic | 6 | RSA/ECDSA/HKDF/SM2/CCM/TLS PRF (Phase T59–T60) |
| TLS state machine | 2 | TLS 1.3 + TLS 1.2 state machine fuzz (Phase T61) |
| DTLS codec | 1 | DTLS record/handshake/state machine (Phase T53) |
| AEAD + X.509 + deep handshake | 3 | GCM/ChaCha20 decrypt, X.509 verify, all 10 handshake decoders (Phase T44) |
| PQC | 3 | ML-KEM encap/decap, ML-DSA sign/verify, SLH-DSA sign/verify (Phase T63) |
| Signature sign-path | 5 | RSA PKCS1v15/PSS, ECDSA P-256/384/521, Ed25519, SM2, DSA (Phase T63) |
| Crypto roundtrip (T68) | 6 | AES block, ChaCha20-Poly1305, CMAC, ECDH, Scrypt, McEliece (Phase T68) |
| **Total** | **46** | **322 corpus seed files** |

### 2.11 D10 — ~~30~~ ~14 Crypto Files Without Direct Unit Tests ~~(Low)~~ — **MOSTLY CLOSED** (Phase T15–T17/125)

**Resolved across 4 phases** with 50 total internal module tests:

- **Phase T15** (+15): SM9 tower fields — Fp2 (add/sub/mul/frobenius/serialization), Fp4 (add/mul_by_v/frobenius/serialization), Fp12 (mul/frobenius/serialization/inverse)
- **Phase T16** (+15): SLH-DSA internals — address fields, WOTS+ chain/checksum, FORS tree/sign, hypertree sign/verify, hash PRF/H_msg
- **Phase T17** (+15): McEliece poly/matrix/syndrome, FrodoKEM matrix/pack/PKE, XMSS tree/WOTS/address
- **Phase T25** (+5): SLH-DSA WOTS+ base_b (2-bit/1-bit extraction, empty, all-zeros/all-FF checksum)

**Remaining** (~14 files with indirect coverage only):

| Category | Files | Lines | Status |
|----------|------:|------:|--------|
| SM9 (remaining) | 4 | ~600 | Indirect via roundtrip tests |
| McEliece (remaining) | 5 | ~1,100 | Indirect via keygen/encap/decap |
| XMSS (remaining) | 3 | ~400 | Indirect via sign/verify |
| FrodoKEM (remaining) | 1 | ~250 | Indirect via encap/decap |
| Provider traits | 1 | 144 | Phase T65: +3 direct tests (HashAlgorithm/Digest trait coverage) |

These modules have indirect coverage through top-level roundtrip tests and are lower risk. `provider.rs` now has 3 dedicated unit tests (Phase T65).

### 2.12 D11 — Semantic/State-Machine Fuzz — **CLOSED** (Phase T44 + T53 + T59–T63)

Fuzz coverage expanded across 6 phases from 10 parse-only to 46 comprehensive targets:

| Phase | Targets Added | Focus |
|-------|:------------:|-------|
| T44 | +3 | AEAD decrypt (GCM + ChaCha20), X.509 verification path, deep handshake decoders (10 message types) |
| T53 | +1 | DTLS state machine (8 codec paths: record parsing, handshake, ClientHello, HVR, TLS↔DTLS) |
| T59–T60 | +6 | Crypto semantic: RSA encrypt/decrypt, ECDSA sign/verify, HKDF derive, SM2 encrypt/sign, CCM encrypt/decrypt, TLS PRF |
| T61 | +2 | TLS 1.3 + TLS 1.2 state machine fuzz (arbitrary message sequences) |
| T63 | +8 | PQC (ML-KEM/ML-DSA/SLH-DSA) + signature sign-path (RSA/ECDSA/Ed25519/SM2/DSA) |
| T68 | +6 | Crypto roundtrip: AES block, ChaCha20-Poly1305, CMAC, ECDH, Scrypt, McEliece |

**Corpus**: 322 seed corpus files (79 original + 6 DTLS + 40 T59–T62 + 33 T61 + 80 T63 + 48 T65–T66 + 36 T68).

**Remaining gaps** (low priority):
- Full TLS connection state machine fuzzing (arbitrary message sequences against live connection with crypto state)
- Ed448/X448 specific fuzzing

**Impact**: All major crypto primitives and protocol paths now have fuzz coverage. L4 defense rating upgraded from B− to A−.

### 2.13 D12 — Side-Channel/Timing Test Infrastructure ~~(Critical)~~ — **PARTIALLY CLOSED** (Phase T49)

**Phase T49** added 6 statistical timing tests using Welch's t-test analysis (`crates/hitls-crypto/tests/timing.rs`):

| Test | Module | What's Timed |
|------|--------|-------------|
| `test_hmac_verify_constant_time` | hmac | HMAC comparison: valid vs invalid tag (same length) |
| `test_aes_gcm_tag_verify_constant_time` | modes/gcm | GCM tag comparison: valid vs corrupted |
| `test_ecdsa_verify_constant_time` | ecc/ecdsa | P-256 signature verify: valid vs invalid |
| `test_rsa_pkcs1_decrypt_constant_time` | rsa | RSA PKCS#1 v1.5 unpad: valid vs invalid padding |
| `test_x25519_dh_constant_time` | x25519 | X25519 DH: different private keys, same public key |
| `test_bignum_ct_eq_constant_time` | hitls-bignum/ct | BigNum equality: same vs different values |

**Approach**: Each test runs 10,000 iterations per class, measures timing distributions, and uses Welch's t-test with |t| > 4.5 threshold. Tests are `#[ignore]` (timing-sensitive, environment-dependent).

**Remaining gaps**:
- No CI integration (timing tests are environment-sensitive)
- No verification that branch-free code remains branch-free after compiler optimization
- Additional algorithms could be covered (e.g., AES key schedule, ECDSA k-nonce generation)

### 2.14 D13 — TLS Connection Code Unit Tests ~~(Critical)~~ — **CLOSED** (Phase T45 + T46)

**Phase T45** added 15 state guard + I/O edge case tests and **Phase T46** added 15 TLS 1.2 handshake + post-HS auth edge case tests:

**Phase T45 tests** (state guards, appended to `connection/tests.rs`):
- Write/read before handshake → error, key_update before connected → error
- Shutdown before connected → error, double handshake → error
- Write after shutdown → error, read after close_notify detection
- KeyUpdate recv count: increment, reset on app data, limit 128
- Connection info, peer certificates, negotiated ALPN accessors
- Record size enforcement, empty write behavior

**Phase T46 tests** (TLS 1.2 + post-HS auth):
- TLS 1.2 EKM (with/without context, before connected)
- Session resumption abbreviated handshake, session cache auto-lookup
- Verify data storage, max fragment length negotiation
- Post-HS cert request: context mismatch, empty cert, bad sig, bad finished, success
- Wrong message type handling, no shared cipher, optional cert request

**Impact**: Risk reduced from Critical → Low. 3,938 lines now covered by 30 dedicated unit tests + existing integration tests.

### 2.15 D14 — Proptest Scope ~~Too Narrow~~ Expanded ~~(High)~~ — **MOSTLY CLOSED** (Phase T48)

**Phase T48** expanded proptest from 2/9 to 5/9 crates:

| Crate | proptest Blocks | Status |
|-------|:---------------:|:------:|
| hitls-crypto | 10 | Covered (AES/SM4/GCM/CBC/ChaCha20/SHA-256/HMAC/Ed25519/X25519/HKDF) |
| hitls-utils | 3 | Covered (Base64/hex/ASN.1) |
| hitls-tls | **5** | **NEW** — ClientHello, ServerHello, CertificateVerify, handshake header, record layer roundtrips |
| hitls-pki | **5** | **NEW** — X.509 DER, PKCS#8 DER, ASN.1 INTEGER, GeneralName, Extension roundtrips |
| hitls-bignum | **5** | **NEW** — mod_add commutative, mod_mul commutative/associative, add identity, mod_inv correctness |
| hitls-auth | 0 | Low priority (simple counter logic) |
| hitls-cli | 0 | Low priority (CLI wrapper) |
| hitls-types | 0 | Not applicable (enum definitions) |

**Impact**: Complex codec and certificate parsing logic in hitls-tls and hitls-pki now has property-based coverage for encode↔decode roundtrips. Algebraic invariants verified for hitls-bignum modular arithmetic.

### 2.16 D15 — Concurrency Testing ~~Minimal~~ Expanded ~~(High)~~ — **PARTIALLY CLOSED** (Phase T50)

**Phase T50** added 10 multi-threaded stress tests (`tests/interop/tests/concurrency.rs`):

| Test | Description |
|------|-------------|
| `test_session_cache_concurrent_insert_lookup` | 10 threads × 100 insert+lookup ops |
| `test_session_cache_concurrent_eviction` | Insert beyond capacity from multiple threads |
| `test_session_cache_concurrent_remove` | Concurrent insert + remove consistency |
| `test_drbg_concurrent_generate` | 10 threads sharing one DRBG, 1000 bytes each |
| `test_drbg_concurrent_reseed_generate` | Concurrent reseed + generate, no panic |
| `test_concurrent_tls13_handshakes` | 10 parallel TLS 1.3 handshakes |
| `test_concurrent_tls12_handshakes` | 10 parallel TLS 1.2 handshakes |
| `test_concurrent_tls13_data_transfer` | 5 connections transferring data in parallel |
| `test_concurrent_key_generation` | 10 threads generating ECDSA P-256 key pairs |
| `test_concurrent_hash_operations` | 20 threads hashing with SHA-256 |

**Total concurrency tests**: 48 (was 38). Now covers session cache stress, DRBG thread-safety, parallel handshakes, and concurrent crypto operations.

**Remaining gaps** (lower priority):
- Race condition tests for connection shutdown/renegotiation
- Lock contention profiling under high thread counts

### 2.17 D16 — Hardware↔Software Cross-Validation ~~(High)~~ — **CLOSED** (Phase T47)

**Phase T47** added 8 differential tests comparing HW-accelerated and SW fallback paths:

| Test | HW Path | SW Path | Description |
|------|---------|---------|-------------|
| `test_aes128_soft_vs_hw_encrypt` | AesImpl::Ni/Neon | AesImpl::Soft | AES-128 encrypt random blocks |
| `test_aes256_soft_vs_hw_encrypt` | AesImpl::Ni/Neon | AesImpl::Soft | AES-256 encrypt, same strategy |
| `test_sha256_soft_vs_hw` | sha256_x86/arm | sha256 soft | SHA-256 hash of 0/1/64/1000 byte inputs |
| `test_ghash_soft_vs_hw` | ghash_x86/arm | ghash soft | GHASH multiply + accumulate |
| `test_chacha20_soft_vs_hw` | chacha20_neon | chacha20 soft | ChaCha20 keystream 256 bytes |
| `test_gcm_soft_vs_hw_roundtrip` | HW AES+GHASH | SW AES+GHASH | Full GCM encrypt→decrypt |
| `test_p256_scalar_mul_generic_vs_fast` | fast path | generic ECC | P-256 point multiplication |
| `test_mlkem_ntt_soft_vs_neon` | ntt_neon | ntt soft | ML-KEM NTT forward+inverse |

Tests are `#[cfg(target_arch = "...")]` guarded — they run on platforms where HW is available, skipped otherwise.

### 2.18 D17 — Zeroize Runtime Verification ~~(Medium)~~ — **CLOSED** (Phase T52)

**Phase T52** added 4 drop-based memory zeroing verification tests (`crates/hitls-crypto/tests/zeroize_verify.rs`):

| Test | Type | Description |
|------|------|-------------|
| `test_aes_key_zeroed_on_drop` | AES key | Verify non-zero key material before drop, structural verification after |
| `test_hmac_key_zeroed_on_drop` | HMAC key | Create HMAC, use it, drop, verify structural zeroize via derive |
| `test_ecdsa_private_key_zeroed_on_drop` | ECDSA privkey | P-256 key pair drop verification |
| `test_x25519_private_key_zeroed_on_drop` | X25519 privkey | X25519 secret key drop verification |

Tests are `#[ignore]` (best-effort verification via drop behavior). Verified that `#[zeroize(drop)]` is correctly applied on inner key types (SoftAesKey, HmacState, etc.).

**Note**: Stack-allocated temporaries inside crypto functions remain unverified — would require Miri shadow memory analysis.

### 2.19 D18 — Feature Flag Combinations ~~Untested~~ ~~(Medium)~~ — **CLOSED** (Phase T51)

**Phase T51** added 4 feature flag smoke tests (`crates/hitls-crypto/tests/feature_smoke.rs`):

| Test | Feature Guard | Description |
|------|--------------|-------------|
| `test_default_aes_sha2_hmac` | `cfg(all(feature="aes", feature="sha2", feature="hmac"))` | AES-128-CBC encrypt + SHA-256 hash + HMAC |
| `test_sm_algorithms` | `cfg(all(feature="sm2", feature="sm3", feature="sm4"))` | SM4-CBC encrypt + SM3 hash + SM2 sign |
| `test_pqc_algorithms` | `cfg(feature="pqc")` | ML-KEM-768 encaps + ML-DSA-65 sign |
| `test_minimal_no_default` | always | Verify `CryptoError` and basic types available |

**CI matrix recommendation** — now implemented in CI (Phase T66):
- `--no-default-features` — verify base compiles (in test job)
- `--features "aes,sha2"` / `--features "rsa,ecdsa"` / `--features "sm2,sm4"` — combo tests
- `--features "pqc"` — post-quantum algorithms only
- `--features "tls13"` / `--features "tls12"` / `--features "tlcp"` — protocol features

### 2.20 D19 — CI Pipeline Hardening — **CLOSED** (Phase T66 + T67)

**Phase T66** restructured CI with job dependency graph and added new jobs:

| Improvement | Before | After |
|------------|--------|-------|
| Job dependencies | None (all parallel) | `needs: [fmt, clippy]` for test/coverage/miri/ignored |
| OS matrix | Ubuntu + macOS (4 jobs) | Ubuntu + macOS + **Windows** (6 jobs) |
| Cross-compile | None | aarch64-unknown-linux-gnu + **i686-unknown-linux-gnu** |
| Documentation | None | `cargo doc --workspace -D warnings` |
| Ignored tests | Not run in CI | Dedicated job runs timing/zeroize/slow keygen |
| Fuzz artifacts | Not uploaded | `actions/upload-artifact@v4` on crash |
| Dependabot | None | Weekly cargo + github-actions dependency updates |
| Scheduled fuzz | None | Weekly: all 40 targets × 60s × 2 jobs |

**Impact**: CI now catches documentation warnings, Windows-specific issues, 32-bit compilation failures, and automatically updates dependencies. Test matrix expanded from 4→6 jobs.

### 2.21 D20 — Panic-Free Crypto Library Code — **CLOSED** (Phase T67)

**Phase T67** eliminated all 16 `.unwrap()` calls on fallible crypto operations in library (non-test) code:

| Module | Functions Changed | Unwraps Eliminated |
|--------|------------------|:------------------:|
| `rsa/pss.rs` | `pss_encode`, `pss_verify_unpad_with_salt` | 4 (hasher.update/finish) |
| `rsa/mod.rs` | `mgf1_sha256` → `Result<Vec<u8>>` | 3 (update×2, finish) |
| `rsa/oaep.rs` | `l_hash` → `Result<[u8; H_LEN]>` | 2 (update, finish) |
| `ed25519/mod.rs` | `sha512`, `reduce_scalar_wide`, `scalar_muladd` → `Result` | 4 |
| `ed448/mod.rs` | `shake256_114`, `reduce_scalar_wide_114`, `scalar_muladd` → `Result` | 3 |

Additionally, `CryptoError::InvalidArg` changed from unit variant to `InvalidArg(&'static str)`, with ~30 high-value sites receiving descriptive context strings (key length, nonce length, parameter range, buffer size).

**Impact**: Zero `.unwrap()` on fallible crypto ops in library code — panic risk eliminated. Error messages now include diagnostic context for faster debugging.

### 2.22 D21 — ~~Fuzz Only Runs Weekly, Not on PR/Push~~ — **CLOSED** (Phase T68-A)

**Resolved**: Phase T68-A added `fuzz-smoke` job to CI pipeline, triggered on every push and PR. Runs each of the 46 fuzz targets for 10 seconds (30s timeout), catching immediate crashes and regressions without full campaign cost.

**Files**: `.github/workflows/ci.yml`

### 2.23 D22 — ~~Feature Flag Combos Incomplete~~ — **CLOSED** (Phase T68-A)

**Resolved**: Phase T68-A expanded `test-features` CI job from 9 → 24 combinations:
- +10 single-feature flags: `dh`, `dsa`, `ed25519`, `ed448`, `sm3`, `sm4`, `chacha20`, `cmac`, `scrypt`, `entropy`
- +2 cross-feature combos: `aes,gcm`, `pqc,ecdsa`
- +2 no-default crate tests: `hitls-tls --no-default-features`, `hitls-pki --no-default-features`
- Added concurrency block for CI deduplication

**Files**: `.github/workflows/ci.yml`

### 2.24 D23 — ~~12~~ 6 Crypto Algorithms Lack Fuzz Targets — **MOSTLY CLOSED** (Phase T68-B)

**Resolved**: Phase T68-B added 6 fuzz targets (+36 corpus seeds), bringing total to 46 targets / 322 corpus:
- `fuzz_aes_block` — AES-128/192/256 block encrypt→decrypt roundtrip
- `fuzz_chacha20` — ChaCha20-Poly1305 AEAD encrypt→decrypt + tamper detection
- `fuzz_cmac` — CMAC one-shot vs incremental consistency
- `fuzz_ecdh` — ECDH P-256/384/521 commutativity verification
- `fuzz_scrypt` — Scrypt determinism with bounded parameters
- `fuzz_mceliece` — McEliece-6688128 encaps→decaps roundtrip + tamper

**Remaining** (6 algorithms still without dedicated fuzz): XMSS, SM9, X25519 (covered by proptest), HMAC (covered by existing fuzz_hmac), DH, PBKDF2 (covered by fuzz_pbkdf2).

**Files**: `fuzz/fuzz_targets/fuzz_{aes_block,chacha20,cmac,ecdh,scrypt,mceliece}.rs`

### 2.25 D24 — ~~Record Layer Decrypt No Zeroize on Error~~ — **CLOSED** (Phase T68-D)

**Resolved**: Phase T68-D added `decrypted.zeroize()` before all error returns in CBC decrypt paths:
- `encryption12_cbc.rs` MtE: 3 error paths (bad MAC/padding, plaintext too large, seq overflow)
- `encryption12_cbc.rs` EtM: 5 error paths (empty data, invalid padding, bad padding bytes, plaintext too large, seq overflow)
- `encryption_tlcp.rs` TLCP CBC: 3 error paths (bad MAC, plaintext too large, seq overflow)
- `encryption_dtlcp.rs` DTLCP CBC: 2 error paths (bad MAC, plaintext too large)
- +3 unit tests verifying error paths exercise correctly

**Files**: `crates/hitls-tls/src/record/encryption12_cbc.rs`, `encryption_tlcp.rs`, `encryption_dtlcp.rs`

### 2.26 D25 — ~~Proptest No PQC/RSA/ECDSA/ECDH Coverage~~ — **CLOSED** (Phase T68-C)

**Resolved**: Phase T68-C added 9 proptest blocks across 5 modules:
- **ML-KEM** (2): roundtrip encaps→decaps, tampered ct → implicit rejection (3 cases)
- **ML-DSA** (2): sign→verify roundtrip, tampered sig → rejection (3 cases)
- **RSA** (2): PSS sign→verify roundtrip, tampered sig → rejection (3 cases, static 1024-bit key)
- **ECDSA** (2): P-256 sign→verify roundtrip, different key → rejection (10 cases)
- **ECDH** (1): P-256 commutativity dh(a,pub(b)) == dh(b,pub(a)) (10 cases)

Total proptest blocks: 28 → 37 across 5 crates.

**Files**: `crates/hitls-crypto/src/{mlkem,mldsa,rsa,ecdsa,ecdh}/mod.rs`

### 2.27 D26 — ~~Benchmarks Lack Regression Detection~~ — **CLOSED** (Phase T74-D)

**Resolved**: Phase T74-D added `bench-compare` CI job (PR-only trigger):
- Checks out base branch, runs `cargo bench -- --save-baseline base`
- Checks out head branch, runs `cargo bench -- --save-baseline head`
- Compares with `critcmp base head` to detect regressions

Benchmarks exist for:
- AES-128/256, SM4, ChaCha20 (symmetric)
- SHA-256/384/512, SM3 (hash)
- HMAC-SHA-256, HMAC-SM3 (MAC)
- RSA-2048, ECDSA P-256, Ed25519, SM2, X25519 (asymmetric)
- ML-KEM-768, ML-DSA-65 (PQC)
- DH-2048, HKDF (key exchange / KDF)

**Remaining** (lower priority): Missing bench functions for Ed448, X448, SM9, DSA, P-384, P-521, SLH-DSA, FrodoKEM, XMSS, Scrypt, SHA-3, PBKDF2.

### 2.28 D27 — Miri Covers Only 3/21 Unsafe Modules — **MOSTLY CLOSED** (Phase T69–T73)

**Current state**: Miri runs on 14 targets:
1. `hitls-bignum` — All tests (Montgomery arithmetic, constant-time operations)
2. `hitls-utils` — All tests (ASN.1, Base64, PEM, hex)
3. `hitls-crypto::mceliece::benes` — Benes network permutation (unsafe pointer arithmetic)
4. `hitls-crypto::mlkem::ntt` — ML-KEM NTT (skip NEON, T69)
5. `hitls-crypto::mldsa::ntt` — ML-DSA NTT (skip NEON, T69)
6. `hitls-crypto::modes::gcm` — GCM encrypt/decrypt (T69)
7. `hitls-crypto::sha2` — SHA-256/384/512 software path (T70)
8. `hitls-crypto::sha3` — SHA-3/SHAKE software path (T70)
9. `hitls-crypto::chacha20` — ChaCha20 software path (T70)
10. `hitls-crypto::sm3` — SM3 hash (T71)
11. `hitls-crypto::sm4` — SM4 cipher (T71)
12. `hitls-crypto::ecc::p256` — P-256 field arithmetic (T72)
13. `hitls-crypto::ecc::p384` — P-384 field arithmetic (T72)
14. `hitls-crypto::ecc::p521` — P-521 field arithmetic (T72)

**Unsafe modules NOT covered by Miri** (18 modules):

| Module | Unsafe Blocks | Reason Not Covered |
|--------|:------------:|-------------------|
| AES-NI (x86-64) | 8 | SIMD intrinsics — Miri cannot execute x86 intrinsics |
| AES-NEON (aarch64) | 6 | ARM NEON intrinsics — same limitation |
| SHA-2 HW (x86/ARM) | 8 | SHA extension intrinsics |
| GHASH HW (x86/ARM) | 22 | CLMUL/PMULL intrinsics |
| ChaCha20 SIMD (NEON/SSE2) | 15 | SIMD intrinsics |
| ML-KEM NEON NTT | ~12 | ARM NEON intrinsics |
| ML-DSA NEON NTT | ~8 | ARM NEON intrinsics |
| SHA-512 HW (ARM) | ~6 | SHA-512 Crypto Extension |
| Keccak SHA-3 HW (ARM) | ~4 | SHA-3 Extension (EOR3/RAX1/BCAX) |

**Note**: Most of these modules use hardware SIMD intrinsics that Miri fundamentally cannot execute (no SIMD emulation). Miri expansion is limited to:
- Software fallback paths (already covered by HW↔SW cross-validation tests)
- McEliece additional unsafe blocks beyond `benes`
- Any future unsafe code in non-SIMD paths

**Impact**: Low actionability — this is a known Miri limitation rather than a testing gap. The HW↔SW cross-validation tests (Phase T47) provide equivalent functional coverage.

### 2.29 D28 — Low Test Density in TLS/Auth/PKI Modules — **OPEN**

**Test density analysis** (tests per thousand lines of code):

| Crate | Lines | Tests | Tests/KLOC | Assessment |
|-------|------:|------:|:----------:|:----------:|
| hitls-bignum | 4,200 | 80 | 19.0 | Excellent |
| hitls-utils | 4,800 | 66 | 13.8 | Good |
| hitls-auth | 2,841 | 33 | 11.6 | Good overall, but gaps |
| hitls-crypto | 72,000 | 1,233 | 17.1 | Excellent |
| hitls-pki | 18,200 | 405 | 22.3 | Excellent |
| hitls-cli | 8,500 | 152 | 17.9 | Good |
| **hitls-tls** | **132,000** | **1,411** | **10.7** | **Lowest density** |

**Specific low-density areas**:

| File/Area | Lines | Tests | Tests/100L | Gap |
|-----------|------:|------:|:----------:|-----|
| hitls-tls async connection files (6 files) | 6,361 | 0 direct | 0 | Covered only by integration tests |
| hitls-auth SPAKE2+ | ~800 | 8 | 1.0 | Counter overflow, invalid message untested |
| hitls-pki certificate.rs | 730 | 5 | 0.7 | Parser edge cases |
| hitls-pki builder.rs | 1,037 | 15 | 1.4 | Complex builder paths |

**Proposed fix (Phase T68-D partial)**: Add targeted unit tests for highest-risk low-density areas, particularly async connection error paths and SPAKE2+ edge cases.

### 2.32 D32 — ~~No Semver-Checks CI~~ — **CLOSED** (Phase T74-B)

**Resolved**: Phase T74-B added `semver` CI job (PR-only trigger) using `cargo-semver-checks-action@v2` on 7 library crates: hitls-types, hitls-utils, hitls-bignum, hitls-crypto, hitls-tls, hitls-pki, hitls-auth. Detects breaking API changes at PR time before merge.

### 2.33 D33 — ~~No Mutation Testing~~ — **CLOSED** (Phase T74-E)

**Resolved**: Phase T74-E added weekly `cargo-mutants` workflow (`.github/workflows/mutants.yml`) targeting hitls-bignum and hitls-utils (highest test-density crates). Uploads mutation results as artifacts. `mutants.toml` excludes benches/fuzz/vectors/unsafe/SIMD code.

### 2.34 D34 — Mutex `.lock().unwrap()` in TLS Production Code — **OPEN**

**Deep testing audit finding**: ~48 `Mutex::lock().unwrap()` occurrences in TLS production code.

| File | Count | Risk |
|------|:-----:|:----:|
| `crypt/keylog.rs` | 14 | Low (keylog is best-effort) |
| `session/mod.rs` | 12 | Medium (session cache corruption → panic) |
| `cert_verify.rs` | 12 | Medium (cert verify failure → panic) |
| `connection12/server.rs` | 2 | Medium (handshake state → panic) |
| `connection12_async.rs` | 2 | Medium (async handshake → panic) |
| `connection_dtls12.rs` | 2 | Low-Medium |
| `handshake/client_dtls12.rs` | 2 | Low-Medium |
| `handshake/server_dtls12.rs` | 1 | Low-Medium |
| `connection_dtls12_async.rs` | 1 | Low-Medium |

**Risk**: If any thread panics while holding a Mutex, subsequent `.lock().unwrap()` calls on that Mutex will panic (poisoned mutex). This can cascade into process termination.

**Proposed fix**: Replace `.lock().unwrap()` with `.lock().unwrap_or_else(|e| e.into_inner())` (ignore poisoning) or propagate as `Result`. Priority: session/cert_verify paths first.

### 2.35 D35 — `panic!()` in Library Code (SLH-DSA params) — **OPEN**

**Deep testing audit finding**: 2 `panic!()` occurrences in hitls-crypto production code:

| File | Location | Context |
|------|----------|---------|
| `slh_dsa/params.rs` | Line ~262 | Unreachable parameter branch in match arm |
| `dh/mod.rs` | 1 occurrence | Error path |

**Risk**: Violates the project convention "never panic in library code; use `Result` instead". While the SLH-DSA branch is theoretically unreachable (all valid parameter sets are covered), a future addition could trigger it without compiler warning.

**Proposed fix**: Replace `panic!()` with `return Err(CryptoError::InvalidArg("unsupported SLH-DSA parameter set"))`.

---

## 3. Deep Testing Audit (2026-03-04)

### 3.1 Automated Test Results

| Check | Result | Details |
|-------|:------:|---------|
| Full test suite | **PASS** | 3,965 passed, 0 failed, 25 ignored |
| Clippy (`-D warnings`) | **PASS** | 0 warnings across all workspace, all features, all targets |
| Format (`cargo fmt`) | **PASS** | All files formatted correctly |
| No-default-features build | **PASS** | All crates compile without defaults |
| Documentation (`cargo doc`) | **PASS** | 0 warnings with `-D warnings` |
| Feature isolation (12 crypto) | **PASS** | Each crypto feature compiles and tests independently |
| TLS/PKI/Auth isolation | **PASS** | Protocol feature subsets all pass |
| Ignored tests (release) | **PASS** | Timing, zeroize, slow keygen tests pass in release mode |
| Benchmark compilation | **PASS** | All Criterion benchmarks compile |

### 3.2 Code Quality Findings

**No FIXME/HACK/XXX markers found** — codebase is clean of technical debt markers.

**Production `unwrap()` patterns** (excluding test modules):

| Crate | Approx Count | Risk Assessment |
|-------|:------------:|:---------------:|
| hitls-crypto | ~112 | Mostly safe (array conversions, known-length slices, `try_into().unwrap()` on fixed sizes) |
| hitls-tls | ~48 (Mutex) | **Medium** — poisoned mutex → panic cascade risk |
| hitls-bignum | ~10 | Low (arithmetic invariants, documented preconditions) |
| hitls-utils | ~2 | Low |
| hitls-pki | ~1 | Low |
| hitls-auth | 0 | Clean |
| hitls-types | 0 | Clean |

**Production `panic!()` in library code**: 2 occurrences (hitls-crypto: `slh_dsa/params.rs`, `dh/mod.rs`)

### 3.3 Risk Assessment Summary

| Finding | Severity | Status | Recommendation |
|---------|:--------:|:------:|----------------|
| All tests pass (3,965/0/25) | — | Green | Maintain |
| Clippy/fmt/doc clean | — | Green | Maintain |
| Feature isolation all pass | — | Green | Maintain |
| 48 Mutex `.lock().unwrap()` in TLS | Medium | D34 Open | Replace with poison-tolerant pattern |
| 2 `panic!()` in crypto library | Low | D35 Open | Replace with `Result::Err` |
| ~112 `unwrap()` in hitls-crypto | Low | Accepted | Most are safe (fixed-size conversions) |

### 3.4 Overall Quality Score

| Dimension | Score | Notes |
|-----------|:-----:|-------|
| Static analysis | 10/10 | Zero warnings, workspace lints, MSRV CI |
| Unit test coverage | 9.5/10 | 3,990 total, all pass, comprehensive edge cases |
| Fuzz coverage | 9/10 | 65 targets, 429 corpus seeds, smoke on PR |
| Property testing | 9/10 | ~87 proptest blocks across 6/9 crates |
| CI/CD automation | 9.5/10 | 20 jobs, nextest, semver, bench, careful, mutants |
| Standard vectors | 10/10 | Wycheproof + RFC + FIPS + GB/T |
| Side-channel defense | 8/10 | 9 timing tests, subtle ConstantTimeEq, ct_verify |
| Code quality (panic-free) | 8.5/10 | 2 library panic!, ~48 Mutex unwrap |
| **Overall** | **~9.2/10** | **Production-grade quality posture** |

---

## 4. Testing Optimization Roadmap

### 4.1 Phase Plan Overview

```
Phase              Tests    Deficiency   Focus                                       Status
─────────────────  ───────  ──────────   ──────────────────────────────────────────  ──────
Phase T9          +8      D1           0-RTT early data + replay protection        ✅
Phase T10         +10      D2           Async TLS 1.2 deep coverage                 ✅
Phase T11         +15      D2           Async TLCP + DTLCP connection tests         ✅
Phase T12         +14      D3           Extension negotiation e2e tests             ✅
Phase T13         +10      D4           DTLS loss simulation + retransmission       ✅
Phase T14         +10      D5           TLCP double certificate validation          ✅
Phase T15         +15      D10          SM9 tower fields (fp2/fp4/fp12)             ✅
Phase T16         +15      D10          SLH-DSA internal modules                    ✅
Phase T17         +15      D10          McEliece + FrodoKEM + XMSS internals        ✅
Phase T18         +20      D6/D7        Infra: proptest + coverage CI               ✅
Phase T19         +15      D5           TLCP SM3 cryptographic path coverage        ✅
Phase T20         +15      —            TLS 1.3 key schedule & HKDF robustness      ✅
Phase T21         +15      —            Record layer encryption & AEAD failures     ✅
Phase T22         +15      D4           TLS 1.2 CBC padding + DTLS parsing          ✅
Phase T23         +15      D4           DTLS fragmentation + retransmission         ✅
Phase T24         +15      D4           DTLS codec + anti-replay boundaries         ✅
Phase T25         +15      D10          X.509 extensions + WOTS+ + ASN.1 tags       ✅
Phase T26         +15      —            PKI encoding + signing dispatch + builder   ✅
Phase T27         +15      —            X.509 cert parsing + SM9 G2 + pairing       ✅
Phase T28         +13      —            SM9 hash + algorithm helpers + curve params ✅
Phase T29         +15      —            McEliece keygen + encoding + decoding       ✅
Phase T30         +10      —            XMSS tree + WOTS+ deepening + FORS          ✅
Phase T31         +15      —            McEliece GF + Benes + matrix deepening      ✅
Phase T32         +12      —            FrodoKEM matrix + SLH-DSA hypertree + poly  ✅
Phase T33         +15      —            McEliece + FrodoKEM + XMSS params deepening ✅
Phase T34         +15      —            XMSS hash + address + ML-KEM NTT deepening  ✅
Phase T35         +15      —            BigNum CT + primality + core type deepening  ✅
Phase T36         +15      —            SLH-DSA params + hash abstraction + address  ✅
Phase T37         +15      —            FrodoKEM PKE + SM9 G1 + SM9 Fp deepening     ✅
Phase T38         +15      —            ML-DSA NTT + SM4-CTR-DRBG + BigNum random    ✅
Phase T39         +15      —            DH group params + entropy pool + SHA-1        ✅
Phase T40         +15      —            ML-KEM poly + SM9 Fp12 + encrypted PKCS#8     ✅
Phase T41         +15      —            ML-DSA poly + X.509 extensions + PKI text     ✅
Phase T42         +15      —            XTS mode + Edwards curve + GMAC deepening     ✅
Phase T43         +15      —            scrypt + CFB mode + X448 deepening            ✅
Phase T44         +3 fuzz  D11          Semantic fuzz: AEAD + X.509 + handshake deep  ✅
──────── Quality Improvement Roadmap (Phase T45–T53) ────────
Phase T45         +15      D13          TLS connection state guards + I/O edge cases  ✅
Phase T46         +15      D13          TLS 1.2 handshake + post-HS auth edge cases   ✅
Phase T47         +8       D16          HW↔SW cross-validation differential tests     ✅
Phase T48         +15      D14          Proptest expansion (tls + pki + bignum)        ✅
Phase T49         +6       D12          Side-channel timing test infrastructure        ✅
Phase T50         +10      D15          Concurrency stress tests                       ✅
Phase T51         +4       D18          Feature flag combination smoke tests           ✅
Phase T52         +4       D17          Zeroize runtime verification                   ✅
Phase T53         +2+1fuzz D8/D11       OpenSSL interop + DTLS state machine fuzz     ✅
──────── Deep Defense & Coverage Enhancement (Phase T59–T65) ────────
Phase T59         +2       D12          RSA OAEP/PKCS1v15 constant-time fix + tests    ✅
Phase T60         +6 fuzz  D9/D11       Crypto semantic fuzz (RSA/ECDSA/HKDF/SM2/CCM/PRF) ✅
Phase T61         +2 fuzz  D11          TLS 1.3/1.2 state machine fuzz                 ✅
Phase T62         infra    —            cargo-deny + CI hardening + subtle unification ✅
Phase T63         +8 fuzz  D9/D11       PQC fuzz + signature sign-path fuzz            ✅
Phase T65         +66      D7/D10       Test coverage enhancement + CI llvm-cov        ✅
──────── CI Hardening + Code Quality (Phase T66–T67) ────────
Phase T66         +66      D19          CI hardening + HMAC fix + test expansion        ✅
Phase T67         0        D19/D20      Dependabot + Windows CI + unwrap→? + InvalidArg ✅
──────── Quality Safety Net Enhancement (Phase T68) ────────
Phase T68-A       CI       D21/D22      Fuzz-smoke on PR + feature flag expansion       ✅
Phase T68-B       +6 fuzz  D23          Fuzz: AES/ChaCha20/CMAC/ECDH/Scrypt/McEliece   ✅
Phase T68-C       +9 prop  D25          Proptest: ML-KEM/ML-DSA/RSA/ECDSA/ECDH          ✅
Phase T68-D       +3 test  D24          Record zeroize + deny.toml + panic audit         ✅
──────── Quality Safety Net P0–P4 (Phase T69–T73) ────────
Phase T69         +53      D27/D29–D31  Miri NTT+GCM, feature isolation, +10 proptests   ✅
Phase T70         +6 fuzz  —            SHA-2/3/SM3/SM4/DH/ECC fuzz + 8 proptests         ✅
Phase T71         +8 fuzz  —            X448/XMSS/HybridKEM/HPKE/SM9/DSA/ML-DSA/SLH-DSA  ✅
Phase T72         +11+5    —            Auth edge cases + 3 proptests + 3 fuzz + 3 Miri   ✅
Phase T73         +35      —            KAT golden-values + security hardening + 2 fuzz   ✅
──────── Quality Infrastructure (Phase T74) ────────
Phase T74-A       infra    —            Workspace lints centralization                     ✅
Phase T74-B       CI       D32          cargo-semver-checks on 7 library crates (PR-only)  ✅
Phase T74-C       CI       —            cargo-nextest parallel test execution              ✅
Phase T74-D       CI       D26          Criterion bench-compare with critcmp (PR-only)     ✅
Phase T74-E       CI       D33          cargo-mutants weekly mutation testing               ✅
Phase T74-F       CI       —            cargo-careful UB detection (nightly)                ✅
Phase T74-G       +3 test  —            dudect-style ct_verify tests (CCM/ChaCha20/GCM)    ✅
Phase T74-H       CI       —            Dependabot fuzz dir + open-pull-requests-limit      ✅
```

**Result**: 2,585 → 3,990 tests (+1,405), 65 fuzz targets (429 corpus), ~87 proptest blocks. All planned deficiencies addressed. D26/D32/D33 closed. Residual: D28 (low test density), D34 (Mutex unwrap), D35 (SLH-DSA panic). Defense model rating: **A**.

### 4.2 Phase T9 — 0-RTT Early Data + Replay Protection (~8 tests) ✅

**Deficiency**: D1 (Critical)

| # | Test | Description |
|:-:|------|-------------|
| 1 | test_early_data_queue_and_accept | Queue early data, verify accepted after handshake |
| 2 | test_early_data_rejected_by_server | Server rejects 0-RTT, client falls back to 1-RTT |
| 3 | test_early_data_encryption_roundtrip | Early data encrypted with 0-RTT key, decrypted correctly |
| 4 | test_end_of_early_data_message | EndOfEarlyData message codec roundtrip |
| 5 | test_early_data_without_psk | 0-RTT without PSK should fail |
| 6 | test_early_data_binder_verification | PSK binder must be valid for early data acceptance |
| 7 | test_export_early_keying_material_with_data | Early exporter works when early data is sent |
| 8 | test_early_data_max_size_enforcement | Respect max_early_data_size configuration |

### 4.3 Phase T10 — Async TLS 1.2 Deep Coverage (+10 tests) ✅

**Deficiency**: D2 (async TLS 1.2 now has 28 tests; D2 fully closed in Phase T11)
**Bug found**: Session ticket encryption key must be 32 bytes (AES-256-GCM), not 48.

| # | Test | Status |
|:-:|------|:------:|
| 1 | test_async_tls12_alpn_negotiation | ✅ |
| 2 | test_async_tls12_server_name_sni | ✅ |
| 3 | test_async_tls12_aes256_gcm | ✅ |
| 4 | test_async_tls12_x25519_key_exchange | ✅ |
| 5 | test_async_tls12_session_resumption_via_ticket | ✅ |
| 6 | test_async_tls12_server_shutdown | ✅ |
| 7 | test_async_tls12_peer_certificates_populated | ✅ |
| 8 | test_async_tls12_empty_write | ✅ |
| 9 | test_async_tls12_bidirectional_server_first | ✅ |
| 10 | test_async_tls12_write_after_shutdown | ✅ |

### 4.4 Phase T11 — Async TLCP + DTLCP Connection Tests (+15 tests) ✅

**Deficiency**: D2 (Critical) — **CLOSED**
**Files created**: `connection_tlcp_async.rs`, `connection_dtlcp_async.rs`

| # | Test | Status |
|:-:|------|:------:|
| 1 | test_async_tlcp_read_before_handshake | ✅ |
| 2 | test_async_tlcp_full_handshake_and_data | ✅ |
| 3 | test_async_tlcp_gcm_handshake | ✅ |
| 4 | test_async_tlcp_ecc_handshake | ✅ |
| 5 | test_async_tlcp_shutdown | ✅ |
| 6 | test_async_tlcp_connection_info | ✅ |
| 7 | test_async_tlcp_large_payload | ✅ |
| 8 | test_async_tlcp_multi_message | ✅ |
| 9 | test_async_dtlcp_read_before_handshake | ✅ |
| 10 | test_async_dtlcp_full_handshake_and_data | ✅ |
| 11 | test_async_dtlcp_with_cookie | ✅ |
| 12 | test_async_dtlcp_shutdown | ✅ |
| 13 | test_async_dtlcp_connection_info | ✅ |
| 14 | test_async_dtlcp_bidirectional | ✅ |
| 15 | test_async_dtlcp_large_payload | ✅ |

### 4.5 Phase T12 — Extension Negotiation E2E Tests (+14 tests) ✅

**Deficiency**: D3 (High) — **CLOSED**

| # | Test | Description | Status |
|:-:|------|-------------|--------|
| 1 | test_tls13_alpn_no_common_protocol | TLS 1.3 ALPN no overlap → None | ✅ |
| 2 | test_tls12_alpn_server_selects_first_match | TLS 1.2 server preference wins | ✅ |
| 3 | test_tls12_alpn_no_common_protocol | TLS 1.2 ALPN no overlap → None | ✅ |
| 4 | test_tls13_sni_propagated_to_both_sides | TLS 1.3 SNI on both sides | ✅ |
| 5 | test_tls12_sni_visible_on_server | TLS 1.2 SNI on both sides | ✅ |
| 6 | test_tls13_group_server_preference | X25519 from key_share | ✅ |
| 7 | test_tls13_group_mismatch_triggers_hrr | HRR P256→X25519 | ✅ |
| 8 | test_tls13_no_common_group_fails | P256 vs X448 → failure | ✅ |
| 9 | test_tls12_max_fragment_length_e2e | MFL=2048 works | ✅ |
| 10 | test_tls13_record_size_limit_e2e | RSL 2048/4096 works | ✅ |
| 11 | test_tls12_record_size_limit_e2e | RSL 1024/2048 works | ✅ |
| 12 | test_tls13_multiple_extensions_combined | ALPN+SNI+group via ConnectionInfo | ✅ |
| 13 | test_duplicate_extension_type_both_returned | Codec: both returned | ✅ |
| 14 | test_zero_length_extension_parses_ok | Codec: PADDING(0) OK | ✅ |

### 4.6 Phase T13 — DTLS Loss Simulation + Retransmission (+10 tests) ✅

**Deficiency**: D4 (High) — partially addressed (further addressed by Phase T23/124)

| # | Test | Description |
|:-:|------|-------------|
| 1 | test_dtls12_out_of_order_delivery | 5 msgs delivered in reverse |
| 2 | test_dtls12_selective_loss_within_window | 10 msgs, deliver even only |
| 3 | test_dtls12_stale_beyond_anti_replay_window | 100 msgs, deliver #1-#99, then #0 rejected |
| 4 | test_dtls12_corrupted_ciphertext_rejected | Flip bit → AEAD failure |
| 5 | test_dtls12_truncated_record_rejected | Truncate to 10 bytes |
| 6 | test_dtls12_empty_datagram_rejected | Empty datagram → error |
| 7 | test_dtls12_wrong_epoch_record | Epoch 1→0 → AEAD nonce mismatch |
| 8 | test_dtls12_interleaved_bidirectional_out_of_order | Both sides seal 5, deliver scrambled |
| 9 | test_dtls12_seal_app_data_not_connected | Not connected → error |
| 10 | test_dtls12_open_app_data_not_connected | Not connected → error |

### 4.7 Phase T14 — TLCP Double Certificate Validation (+10 tests) ✅

**Deficiency**: D5 (High) — partially closed (further addressed by T12)

| # | Test | Description |
|:-:|------|-------------|
| 1 | test_tlcp_server_missing_enc_certificate | Missing enc cert → error |
| 2 | test_tlcp_server_missing_signing_key | Missing signing key → error |
| 3 | test_tlcp_server_wrong_signing_key_type | Ed25519 key → error |
| 4 | test_dtlcp_server_missing_enc_certificate | DTLCP: missing enc cert |
| 5 | test_dtlcp_server_missing_signing_key | DTLCP: missing signing key |
| 6 | test_dtlcp_server_wrong_signing_key_type | DTLCP: wrong key type |
| 7 | test_tlcp_handshake_fails_without_enc_cert | Full-stack TLCP: no enc cert |
| 8 | test_tlcp_handshake_fails_without_signing_key | Full-stack TLCP: no signing key |
| 9 | test_dtlcp_handshake_fails_without_enc_cert | Full-stack DTLCP: no enc cert |
| 10 | test_dtlcp_handshake_fails_without_signing_key | Full-stack DTLCP: no signing key |

### 4.8 Phase T15 — SM9 Tower Fields (+15 tests) ✅

**Deficiency**: D10

| # | Test | Description |
|:-:|------|-------------|
| 1-5 | fp2 tests | add/sub identity, mul conjugate, frobenius, serialization, mul_by_u |
| 6-10 | fp4 tests | add identity, mul_by_v, frobenius, serialization, neg_double_neg |
| 11-15 | fp12 tests | mul identity, frobenius p/p2/p3, serialization, inverse |

### 4.9 Phase T16 — SLH-DSA Internal Modules (+15 tests) ✅

**Deficiency**: D10

| Module | Tests | Description |
|--------|:-----:|-------------|
| address.rs | 3 | Set/get layer/tree/keypair/chain address fields |
| wots.rs | 3 | WOTS+ chain, pk_from_sig roundtrip, checksum |
| fors.rs | 3 | FORS tree leaf, sign/verify subset, root computation |
| hypertree.rs | 3 | Hypertree sign/verify, layer traversal, root |
| hash.rs | 3 | PRF, H_msg, F/T_l functions with test vectors |

### 4.10 Phase T17 — McEliece + FrodoKEM + XMSS Internals (+15 tests) ✅

**Deficiency**: D10

| Module | Tests | Description |
|--------|:-----:|-------------|
| McEliece poly/matrix | 5 | Polynomial GCD, systematic matrix, syndrome decode |
| FrodoKEM matrix/pke | 5 | Matrix sample, pack/unpack, PKE encrypt/decrypt |
| XMSS tree/WOTS | 5 | Merkle tree build, WOTS chain, address manipulation |

### 4.11 Phase T18 — Infrastructure: proptest + Coverage CI (+20 tests) ✅

**Deficiency**: D6, D7 — **BOTH CLOSED**

| Task | Description | Status |
|------|-------------|:------:|
| proptest dependency | dev-dependency for hitls-crypto and hitls-utils | ✅ |
| Crypto property tests (6) | AES/SM4/GCM/CBC/ChaCha20 roundtrips | ✅ |
| Hash/signature tests (5) | SHA-256 determinism/incremental, HMAC, Ed25519, X25519 DH | ✅ |
| KDF/codec tests (9) | HKDF, Base64, hex, ASN.1 integer/octet/bool/UTF8/sequence | ✅ |
| Coverage CI job | `cargo-tarpaulin` → Cobertura XML | ✅ |

### 4.12 Phase T19–T35, T36–T43 — Deep Edge-Case Coverage (+495 tests) ✅

Continued hardening beyond the original roadmap:

| Phase | Tests | Focus |
|-------|:-----:|-------|
| T19 | +15 | TLCP SM3 transcript hash, PRF, key schedule, verify_data (closes D5 SM3 gap) |
| T20 | +15 | TLS 1.3 key schedule SHA-384 pipeline, stage enforcement, SM4-GCM-SM3 |
| T21 | +15 | Record layer AEAD encryption edge cases, failure modes, epoch transitions |
| T22 | +15 | TLS 1.2 CBC padding oracle, DTLS record parsing, TLS 1.3 inner plaintext |
| T23 | +15 | DTLS fragmentation/reassembly, retransmission timer, CertificateVerify (extends D4) |
| T24 | +15 | DTLS codec all types, anti-replay window boundaries, entropy conditioning (extends D4) |
| T25 | +15 | X.509 extension parsing, SLH-DSA WOTS+ base conversion, ASN.1 tag long-form (extends D10) |
| T26 | +15 | PKI shared encoding helpers, X.509 signing hash dispatch, certificate builder DER encoding |
| T27 | +15 | X.509 certificate parsing, SM9 G2 point arithmetic, SM9 pairing helpers |
| T28 | +13 | SM9 hash functions H1/H2/KDF, SM9 algorithm sign/verify/encrypt/decrypt, BN256 curve parameters |
| T29 | +15 | McEliece keygen helpers (bitrev/SHAKE256/PRG), encoding (error vector), decoding (Berlekamp-Massey) |
| T30 | +10 | XMSS tree operations (compute_root/sign/verify), WOTS+ deepening, SLH-DSA FORS deepening |
| T31 | +15 | McEliece GF(2^13) field algebra, Benes network permutation/sort, binary matrix Gaussian elimination |
| T32 | +12 | FrodoKEM matrix ops, SLH-DSA hypertree, McEliece polynomial deepening |
| T33 | +15 | McEliece + FrodoKEM + XMSS parameter set validation deepening |
| T34 | +15 | XMSS hash abstraction + XMSS address scheme + ML-KEM NTT deepening |
| T35 | +15 | BigNum constant-time + primality testing + core type deepening |
| T36 | +15 | SLH-DSA params + hash abstraction + address scheme deepening |
| T37 | +15 | FrodoKEM PKE + SM9 G1 point + SM9 Fp field deepening |
| T38 | +15 | ML-DSA NTT + SM4-CTR-DRBG + BigNum random deepening |
| T39 | +15 | DH group params + entropy pool + SHA-1 deepening |
| T40 | +15 | ML-KEM poly + SM9 Fp12 + encrypted PKCS#8 deepening |
| T41 | +15 | ML-DSA poly + X.509 extensions + X.509 text deepening |
| T42 | +15 | XTS mode + Edwards curve + GMAC deepening |
| T43 | +15 | scrypt + CFB mode + X448 deepening |

---

## 5. Coverage Targets — Final Status

| Metric | Original (T8) | Target (T18) | **Actual (T74)** | Trend |
|--------|:---------------:|:-------------:|:------------------:|:-----:|
| Total tests | 2,634 | ~2,750+ | **3,990** (25 ignored) | +51% |
| Fuzz targets | 10 | 13 | **65** | +400% |
| Fuzz corpus | 66 | ~79 | **429** | +443% |
| Critical deficiencies | 2 | 0 | **0** | Resolved |
| High deficiencies | 3 | 0 | **0** | Resolved |
| Crypto files with tests | 75% | 90%+ | **~97%** | Exceeded |
| TLS files with tests | 100% | 100% | **100%** | Maintained |
| PKI files with tests | ~85% | ~85% | **100%** | Exceeded |
| Property-based testing | No | Yes | **~87 blocks (6/9 crates)** | Exceeded |
| Code coverage in CI | No | Yes | **llvm-cov + branch (8 components)** | Exceeded |
| Timing tests | 0 | — | **9** (Welch's t-test) | Strong |
| HW↔SW cross-validation | 0 | — | **8** differential tests | Strong |
| Concurrency stress tests | 38 | — | **48** | Good |
| Feature flag CI combos | — | — | **59** | Excellent |
| Miri targets | 3 | — | **14** | Good |
| Supply-chain policy | No | — | **Yes** (cargo-deny + semver-checks) | Strong |
| CI OS coverage | 2 | — | **3** (+ Windows) | Good |
| Mutation testing | No | — | **Yes** (weekly cargo-mutants) | New |
| Bench regression | No | — | **Yes** (critcmp base vs head) | New |
| UB detection (careful) | No | — | **Yes** (nightly cargo-careful) | New |
| Fuzz on PR/push | No | — | **Yes** (10s smoke per target) | Strong |

All original targets met or exceeded. Defense model rating: **A**. Quality Infrastructure (T74) added semver-checks, nextest, bench-compare, mutation testing, cargo-careful, and constant-time verification.

---

## 6. Priority Improvement Roadmap

### 6.1 Overview — Post-T67 Status + Phase T68 Gaps

```
Priority   Deficiency   Status            Phase       Result
────────   ──────────   ────────────────  ──────────  ──────────────────────────────
──────── Completed (Phase T45–T67) ────────
P0         D13          CLOSED            T45/T46     +30 connection unit tests
P0         D11          CLOSED            T44/T53–T63 40 fuzz targets (10 parse + 30 semantic/PQC/sign)
P0         D9           CLOSED            T44/T59–T63 Parse-only → comprehensive crypto+protocol fuzz
P0         D7           CLOSED            T18/T65     cargo-llvm-cov + branch coverage in CI
P1         D12          PARTIALLY CLOSED  T49         6 timing tests (Welch's t-test)
P1         D16          CLOSED            T47         8 HW↔SW differential tests
P1         D14          MOSTLY CLOSED     T48         Proptest in 5/9 crates (was 2/9)
P2         D15          PARTIALLY CLOSED  T50         +10 stress tests (48 total)
P2         D8           PARTIALLY CLOSED  T53         OpenSSL interop (TLS 1.3 ✅, TLS 1.2 known gap)
P2         D18          CLOSED            T51         4 feature smoke tests
P2         D19          CLOSED            T66/T67     CI hardening: Windows, cross-compile, doc check, Dependabot
P2         D20          CLOSED            T67         16 unwrap→? + InvalidArg(&'static str) context
P3         D17          CLOSED            T52         4 zeroize drop verification tests
P3         D4r          OPEN              —           Requires handshake driver refactoring
──────── New Gaps (Phase T68 Analysis) ────────
P0         D21          CLOSED            T68-A       Fuzz-smoke on PR/push (10s per target)
P0         D22          CLOSED            T68-A       Feature flag combos expanded (9→24)
P0         D23          MOSTLY CLOSED     T68-B       +6 fuzz targets (46 total, 6 remaining algorithms)
P0         D26          OPEN              —           Benchmarks: no regression detection
P1         D25          CLOSED            T68-C       +9 proptest blocks (37 total across 5 crates)
P1         D27          OPEN              —           Miri: only 3/21 unsafe modules (HW intrinsic limitation)
P1         D28          OPEN              —           Test density: tls 10.7/KLOC, auth 11.6/KLOC
P2         D24          CLOSED            T68-D       Record layer zeroize on error (+3 tests)
```

### 6.2 Completed Actions (Phase T45–T67)

All P0, P1, P2, and P3 actions have been addressed:

| Priority | Deficiency | Action | Phase | Result |
|----------|-----------|--------|-------|--------|
| P0 | D13 | TLS connection unit tests | T45/T46 | +30 tests (state guards + handshake edge cases) |
| P0 | D11 | Semantic + protocol fuzz | T44/T53/T59–T63 | 40 fuzz targets + 286 corpus (full crypto + PQC + sign-path) |
| P0 | D9 | Fuzz comprehensiveness | T44/T59–T63 | Parse-only → semantic + state-machine + PQC coverage |
| P0 | D7 | Coverage infrastructure | T18/T65 | cargo-llvm-cov + branch coverage (replaces tarpaulin) |
| P1 | D12 | Timing test infrastructure | T49 | 6 Welch's t-test timing tests |
| P1 | D16 | HW↔SW cross-validation | T47 | 8 differential tests across all HW modules |
| P1 | D14 | Proptest expansion | T48 | 5/9 crates now have proptest coverage |
| P2 | D15 | Concurrency stress | T50 | +10 multi-threaded stress tests (48 total) |
| P2 | D8 | OpenSSL interop | T53 | TLS 1.3 pass; TLS 1.2 verify_data gap found |
| P2 | D18 | Feature flag testing | T51 | 4 feature subset smoke tests |
| P2 | D19 | CI pipeline hardening | T66/T67 | Windows CI, cross-compile, cargo doc, Dependabot, job deps |
| P2 | D20 | Panic-free crypto library | T67 | 16 .unwrap()→?, InvalidArg(&'static str) with ~30 context strings |
| P3 | D17 | Zeroize verification | T52 | 4 drop-based zeroing tests |
| — | D10 | Crypto file coverage | T65 | +30 crypto tests (provider, matrix, DRBG, GCM, PCT, KAT, DSA, ElGamal) |
| — | — | TLS connection coverage | T65 | +17 TLS 1.3/1.2 integration tests (key_update, session resumption, accessors) |
| — | — | CLI command coverage | T65/T66 | +35 CLI tests (s_client, s_server, speed, hex, cipher, port edge cases) |
| — | — | HMAC API fix | T66 | `Hmac::reset()` fallible, proper error propagation in 6 callers |

### 6.3 Remaining Gaps (Future Work)

| Priority | Deficiency | Status | Phase | Description |
|----------|-----------|--------|-------|-------------|
| **P0** | **D21** | CLOSED | T68-A | Fuzz-smoke on PR/push (10s per target) |
| **P0** | **D22** | CLOSED | T68-A | Feature flag combos: 9 → 24 in CI + concurrency |
| **P0** | **D23** | MOSTLY CLOSED | T68-B | +6 fuzz targets (46 total); 6 algorithms remaining |
| **P0** | **D26** | OPEN | — | Benchmarks: no regression detection (build-only in CI) |
| **P1** | **D25** | CLOSED | T68-C | +9 proptest blocks (37 total across 5 crates) |
| **P1** | **D27** | OPEN | — | Miri: only 3/21 unsafe modules (HW intrinsic limitation) |
| **P1** | **D28** | OPEN | — | Test density gaps in TLS async, auth SPAKE2+, PKI cert parsing |
| **P2** | **D24** | CLOSED | T68-D | Record layer zeroize on error + 3 unit tests |
| Low | D4r | OPEN | — | Handshake-level DTLS loss simulation (requires handshake driver refactoring) |
| Low | D8 | PARTIALLY CLOSED | — | TLS 1.2 verify_data mismatch root cause analysis |
| Low | D12 | PARTIALLY CLOSED | — | Additional timing tests (AES key schedule, ECDSA k-nonce) + CI integration |
| Low | D15 | PARTIALLY CLOSED | — | Race condition tests for connection shutdown/renegotiation |
| Wish | D14 | MOSTLY CLOSED | — | Proptest for hitls-auth, hitls-cli (7/9 crates) |
| Wish | — | — | — | BoringSSL/GnuTLS cross-implementation interop |

### 6.4 Quantified Gap Summary — Post-T67

| Metric | Before (T43) | After (T53) | After (T65) | **After (T67)** | *Projected (T68)* |
|--------|:-------------:|:------------:|:------------:|:---------------:|:-----------------:|
| Total tests | 3,184 | 3,264 | 3,600 | **3,666** | *~3,669 (+3)* |
| Fuzz targets | 13 | 14 | 40 | **40** | *46 (+6)* |
| Fuzz corpus | 79 | 85 | 238 | **286** | *~322 (+36)* |
| Proptest blocks | 20 | ~28 | ~28 | **~28** | *~37 (+9)* |
| Proptest crates | 2/9 | 5/9 | 5/9 | **5/9** | *5/9* |
| Concurrency tests | 38 | 48 | 48 | **48** | *48* |
| Timing tests | 0 | 6 | 6 | **6** | *6* |
| HW↔SW cross-validation | 0 | 8 | 8 | **8** | *8* |
| TLS connection unit tests | 0 | 30 | 33 | **33** | *33* |
| Feature flag CI combos | — | — | 9 | **9** | *~25 (+16)* |
| Feature flag smoke tests | 0 | 4 | 4 | **4** | *4* |
| Zeroize verification | 0 | 4 | 4 | **4** | *4* |
| Cross-impl interop | 0 | 2 | 2 | **2** | *2* |
| Supply-chain policy | No | No | Yes | **Yes** | *Yes (yanked=deny)* |
| CI branch coverage | No | No | Yes | **Yes** | *Yes* |
| CI OS coverage | 2 | 2 | 2 | **3** | *3* |
| Dependabot | No | No | No | **Yes** | *Yes* |
| Crypto unwrap panics | 16 | 16 | 16 | **0** | *0* |
| InvalidArg diagnostics | 0 | 0 | 0 | **~30** | *~30* |
| Record zeroize on error | — | — | — | **No** | *Yes* |
| Fuzz on PR/push | — | — | — | **No** | *Yes (10s smoke)* |
| Deficiencies OPEN | 8 | 2 partial | 0 | **0 (D1–D20)** | *3 remaining (D26–D28)* |
| Defense model rating (avg) | **B** | **B+** | **A−** | **A−** | *A* |

### 6.5 Phase T68 Implementation Plan

Phase T68 addresses deficiencies D21–D28 across 4 sub-phases. This is a roadmap — actual implementation will be separate commits.

#### Phase T68-A: CI Pipeline Hardening (D21, D22)

1. **Fuzz-smoke on PR/push** (D21): Add a `fuzz-smoke` job triggered on `push` and `pull_request`:
   - Runs each of the 40+ fuzz targets for 10 seconds
   - Catches immediate crashes and deserialization regressions
   - Uses `cargo +nightly fuzz run <target> -- -max_total_time=10`
   - Estimated CI time: ~7 minutes (40 targets × 10s)

2. **Feature flag expansion** (D22): Expand `test-features` matrix from 9 → ~25 combos:
   - Single-feature: `dh`, `dsa`, `ed25519`, `ed448`, `sm3`, `sm4`, `chacha20`, `entropy`, `fips`, `hazmat`
   - Cross-feature: `aes,gcm`, `pqc,ecdsa`
   - No-default: `--no-default-features` for hitls-tls, hitls-pki
   - All tests: `--all-features` (already present)

3. **CI concurrency**: Add `concurrency:` config to prevent duplicate workflow runs on force-push.

4. **deny.toml**: Change `yanked = "warn"` → `yanked = "deny"` to block yanked dependency usage.

**Files**: `.github/workflows/ci.yml`, `deny.toml`

#### Phase T68-B: Fuzz Target Expansion (+6 targets, +36 corpus) (D23)

| # | Target | Algorithm | Strategy | Corpus Seeds |
|:-:|--------|-----------|----------|:------------:|
| 1 | `fuzz_aes.rs` | AES block encrypt/decrypt | Roundtrip (128/192/256), tamper detection | 6 |
| 2 | `fuzz_chacha20.rs` | ChaCha20 stream cipher | Keystream generation, encrypt/decrypt roundtrip | 6 |
| 3 | `fuzz_cmac.rs` | CMAC tag generation | Incremental vs one-shot equivalence, tag verification | 6 |
| 4 | `fuzz_ecdh.rs` | ECDH key agreement | P-256/384/521 commutativity check | 6 |
| 5 | `fuzz_scrypt.rs` | Scrypt KDF | Bounded parameters (N≤1024), determinism | 6 |
| 6 | `fuzz_mceliece.rs` | McEliece encaps/decaps | Roundtrip with smallest params, tampered ct rejection | 6 |

**Pattern**: Follows existing `fuzz_ecdsa_sign.rs` structure — deserialize parameters from fuzzer input, construct valid crypto operation, verify roundtrip/property.

**Files**: `fuzz/fuzz_targets/fuzz_{aes,chacha20,cmac,ecdh,scrypt,mceliece}.rs`, `fuzz/corpus/` directories

#### Phase T68-C: Proptest Expansion (+9 property blocks) (D25)

| # | Algorithm | Property | Location |
|:-:|-----------|----------|----------|
| 1 | ML-KEM-768 | keygen → encaps → decaps roundtrip | `mlkem/mod.rs` |
| 2 | ML-KEM-768 | Tampered ciphertext → implicit rejection (different shared secret) | `mlkem/mod.rs` |
| 3 | ML-DSA-65 | sign → verify roundtrip for arbitrary messages | `mldsa/mod.rs` |
| 4 | ML-DSA-65 | Tampered signature → rejection | `mldsa/mod.rs` |
| 5 | RSA-2048 | sign_pss → verify_pss roundtrip | `rsa/mod.rs` |
| 6 | RSA-2048 | Tampered signature → rejection | `rsa/mod.rs` |
| 7 | ECDSA P-256 | sign → verify roundtrip | `ecc/ecdsa.rs` |
| 8 | ECDSA P-256 | Different key → rejection | `ecc/ecdsa.rs` |
| 9 | ECDH P-256 | Commutativity: dh(a, pub(b)) == dh(b, pub(a)) | `ecdh/mod.rs` |

**Note**: PQC proptests (ML-KEM/ML-DSA) will use small case counts (`proptest!(ProptestConfig::with_cases(5), ...)`) due to slow keygen (~10ms per iteration).

#### Phase T68-D: Security Hardening (+3 tests) (D24)

1. **Record layer zeroize on error** (D24):
   - Add `use zeroize::Zeroize;` to `encryption12_cbc.rs`, `encryption_tlcp.rs`, `encryption_dtlcp.rs`
   - Insert `decrypted.zeroize()` before all error returns in CBC decrypt paths
   - Affected: MtE padding validation failure, MtE MAC mismatch, EtM MAC failure, TLCP/DTLCP equivalents

2. **deny.toml hardening**: `yanked = "warn"` → `yanked = "deny"`

3. **CLI panic audit**: Replace 6 `panic!()` in `s_server.rs` signature dispatch with proper error returns

4. **+3 unit tests**: CBC decrypt error paths verify that decrypted buffer is zeroized on MAC/padding failure

**Files**: `crates/hitls-tls/src/record/encryption12_cbc.rs`, `encryption_tlcp.rs`, `encryption_dtlcp.rs`, `crates/hitls-cli/src/commands/s_server.rs`

---

## 7. Strengths Summary

The current safety net has significant strengths across multiple dimensions:

### 7.1 Static & Compile-Time Guarantees
1. **Zero-warning policy**: `RUSTFLAGS="-D warnings" cargo clippy` enforced across entire workspace, all features, all targets
2. **Centralized workspace lints**: `[workspace.lints.clippy]` with 11 shared lint allows (T74-A)
3. **Rust type system**: Strong typing prevents entire categories of bugs (buffer overflow, use-after-free, null deref)
4. **100% Zeroize compliance**: All secret material types use `#[derive(Zeroize)]` + `#[zeroize(drop)]`
5. **Unsafe confinement**: 44 unsafe blocks restricted to hardware acceleration (6 files) + McEliece binary ops (1 file)

### 7.2 Test Coverage Breadth
6. **3,990 test functions** (3,965 pass + 25 ignored) with 100% pass rate
7. **Error-first culture**: ~370 error-handling tests (invalid input, wrong state, rejected parameters) outnumber roundtrip tests (~350)
8. **Edge case density**: ~325 boundary/empty/partial tests catch off-by-one and corner cases
9. **State machine coverage**: ~600 tests exercise handshake/connection/not-connected transitions
10. **Async parity**: 92 async tests across all 5 protocol variants (TLS 1.3/1.2/DTLS/TLCP/DTLCP)

### 7.3 Standard Compliance
11. **Wycheproof**: 15 test suites covering 5,000+ vectors (AES-GCM/CCM/CBC, ChaCha20, ECDSA, ECDH, Ed25519, X25519, RSA, HKDF, HMAC)
12. **RFC vectors**: Ed25519/Ed448 (RFC 8032), X25519/X448 (RFC 7748), HKDF (RFC 5869), HMAC (RFC 4231/2202), ChaCha20 (RFC 8439), AES Key Wrap (RFC 3394), Scrypt (RFC 7914)
13. **FIPS KATs**: SHA-256, AES, GCM, HMAC-DRBG — 7 known-answer tests for FIPS 140-3 readiness
14. **GB/T vectors**: SM3 (GB/T 32905), SM4 (GB/T 32907) — Chinese national standard compliance
15. **Frozen golden-value KATs**: ML-KEM-768 + ML-DSA-65 deterministic test vectors (Phase T73)

### 7.4 Infrastructure & Automation
16. **CI/CD pipeline**: GitHub Actions with 20 jobs: format + lint + test matrix (Ubuntu + macOS + Windows × stable + MSRV 1.75, nextest parallel execution) + feature combos (59 combinations) + security audit + Miri (14 targets) + fuzz build + fuzz smoke (PR/push) + cross-compile (aarch64 + i686) + doc check + ignored tests + bench compare (PR-only critcmp) + semver-checks (PR-only) + cargo-careful (nightly UB) + coverage (llvm-cov + branch, 8 components) + cargo-deny + mutation testing (weekly) + Dependabot
17. **Property-based testing**: ~87 proptest blocks across 6 crates (hitls-crypto + hitls-utils + hitls-tls + hitls-pki + hitls-bignum + hitls-auth)
18. **Code coverage tracking**: cargo-llvm-cov → Codecov JSON with branch coverage in CI (8 components)
19. **Miri validation**: Undefined behavior detection on 14 targets (hitls-bignum + hitls-utils + hitls-crypto modules)
20. **Deterministic testing**: Fixed seeds/keys for reproducible results across platforms
21. **Comprehensive wrong-state tests**: Every TLS state machine transition has invalid-state rejection tests
22. **Side-channel verification**: 9 statistical timing tests (Welch's t-test) for constant-time operations (timing.rs + ct_verify.rs)
23. **HW↔SW cross-validation**: 8 differential tests comparing hardware-accelerated and software fallback paths
24. **OpenSSL interop**: TLS 1.3 handshake verified against OpenSSL s_client
25. **Panic-free crypto library**: Zero `.unwrap()` on fallible crypto ops in library code — all propagated via `?` operator
26. **Diagnostic error context**: `CryptoError::InvalidArg(&'static str)` with ~30 descriptive messages for key/nonce/parameter validation failures
27. **Automated dependency updates**: Dependabot for cargo + GitHub Actions + fuzz (weekly), with MSRV-aware review
28. **Cross-platform CI**: Ubuntu + macOS + Windows test matrix + aarch64/i686 cross-compile checks
29. **Semver-checks**: cargo-semver-checks on 7 library crates for API breakage detection (PR-only)
30. **Mutation testing**: Weekly cargo-mutants on hitls-bignum + hitls-utils for test quality verification
31. **Benchmark regression detection**: Criterion base vs head comparison with critcmp (PR-only)
32. **Parallel test execution**: cargo-nextest with retry support (2 retries in CI profile)
