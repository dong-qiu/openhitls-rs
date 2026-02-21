# openHiTLS-rs — Quality Assurance Report

> Quality safety net analysis and testing optimization roadmap.
> Related docs: [TEST_LOG.md](TEST_LOG.md) | [DEV_LOG.md](DEV_LOG.md) | [README.md](README.md)

---

## 1. Current Quality Safety Net

### 1.1 Defense Layers (5-Layer Model)

| Layer | Mechanism | Coverage | Status |
|:-----:|-----------|----------|:------:|
| **L1** | Static Analysis | clippy zero-warning + rustfmt + MSRV 1.75 dual-version CI | Complete |
| **L2** | Unit Tests | 2,585 tests (40 ignored), 100% pass rate | Coverage uneven |
| **L3** | Integration Tests | 125 cross-crate TCP loopback tests | Scenarios insufficient |
| **L4** | Fuzz Testing | 10 fuzz targets + 66 seed corpus files | Parse-only |
| **L5** | Security Audit | rustsec/audit-check + Miri (bignum/utils) | Scope limited |

### 1.2 CI/CD Pipeline

```
GitHub Actions (.github/workflows/ci.yml)
├── Format Check     cargo fmt --all -- --check
├── Lint             cargo clippy --all-targets --all-features -- -D warnings
├── Test Matrix      Ubuntu + macOS × Rust stable + MSRV 1.75
├── Feature Testing  Individual feature flags (aes, sha2, rsa, sm2, pqc)
├── Security Audit   rustsec/audit-check@v2
├── UB Detection     Miri on hitls-bignum + hitls-utils
├── Fuzz Build       cargo fuzz build (nightly)
└── Bench Verify     cargo bench --no-run
```

### 1.3 Per-Crate Test Distribution

| Crate | Tests | Ignored | % of Total | Focus |
|-------|------:|--------:|:----------:|-------|
| hitls-tls | 1,164 | 0 | 45.0% | TLS 1.3/1.2/DTLS/TLCP/DTLCP handshake, record, extensions, callbacks |
| hitls-crypto | 652 | 31 | 25.3% | 48 algorithm modules + hardware acceleration |
| hitls-pki | 349 | 1 | 13.5% | X.509, PKCS#8/12, CMS (5 content types) |
| hitls-integration | 125 | 3 | 4.9% | Cross-crate TCP loopback, error scenarios, concurrency |
| hitls-cli | 117 | 5 | 4.5% | 14 CLI commands |
| hitls-utils | 53 | 0 | 2.1% | ASN.1, Base64, PEM, OID |
| hitls-bignum | 49 | 0 | 1.9% | Montgomery, Miller-Rabin, modular arithmetic |
| hitls-auth | 33 | 0 | 1.3% | HOTP/TOTP, SPAKE2+, Privacy Pass |
| hitls-types | 26 | 0 | 1.0% | Enum definitions, error types |
| Wycheproof | 15 | 0 | 0.6% | 5,000+ vectors across 15 test groups |
| Doc-tests | 2 | 0 | 0.1% | API documentation examples |
| **Total** | **2,585** | **40** | **100%** | |

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
| Zeroize on drop | All secret types (keys, intermediate states) | Compile-time (derive) |
| Constant-time comparison | `subtle::ConstantTimeEq` in all crypto comparisons | Structural (no timing tests) |
| Unsafe code confinement | 21 blocks: AES-NI (8), NEON (6), McEliece (2), lib.rs stubs (5) | All with NIST vectors |
| Random generation | `getrandom` crate, never `rand` | Indirect |

---

## 2. Identified Deficiencies

### 2.1 Deficiency Map

```
Severity   ID   Description                              Impact
────────   ──   ──────────────────────────────────────   ──────────────────────────
CLOSED     D1   0-RTT replay protection: +8 tests         Resolved (Phase T102)
Critical   D2   Async TLS 1.2/TLCP/DTLCP: zero tests     Functional regression risk
High       D3   Extension negotiation: no e2e tests       Protocol compliance risk
High       D4   DTLS loss/retransmission: no tests        Core DTLS feature unverified
High       D5   TLCP double certificate: untested         GM compliance risk
Medium     D6   No property-based testing framework       Input space coverage gap
Medium     D7   No code coverage metrics in CI            Cannot quantify quality
Medium     D8   No cross-implementation interop           Compatibility risk
Low-Med    D9   Fuzz targets: parse-only                  Deep bugs missed
Low        D10  30 crypto files without unit tests        Indirect coverage only
```

### 2.2 D1 — 0-RTT Replay Protection ~~(Critical)~~ — **CLOSED** (Phase T102)

**Resolved**: Phase T102 added 8 tests covering:
- Early data extension codec (ClientHello/EncryptedExtensions/NewSessionTicket wire format)
- Client offering logic (no-PSK guard, zero max_early_data guard)
- Async 0-RTT accepted flow (session resumption → queue → verify early data received)
- Async 0-RTT rejected flow (server rejects → 1-RTT fallback works)
- Queue API accumulation and pre-handshake state

Remaining uncovered areas (lower risk, tracked for future phases):
- PSK `obfuscated_ticket_age` validation
- Binder verification for replay prevention
- `EndOfEarlyData` message codec roundtrip

### 2.3 D2 — Async/Sync Test Coverage Asymmetry (Critical)

Async paths use independent code files but have severely uneven test coverage:

| Connection Type | Sync Tests | Async Tests | Gap |
|-----------------|:----------:|:-----------:|:---:|
| TLS 1.3 | 61 | 25 | -36 |
| TLS 1.2 | 53 | **0** | -53 |
| DTLS 1.2 | 20 | 8 | -12 |
| TLCP | 15 | **0** | -15 |
| DTLCP | 6 | **0** | -6 |

TLS 1.2 async, TLCP async, and DTLCP async have **zero tests**. These connection types may contain undiscovered bugs.

### 2.4 D3 — Extension Negotiation (High)

The extensions module has 14 tests covering only the custom extension framework. **Standard extension negotiation flows (client proposes → server selects/rejects)** lack dedicated tests:

- ALPN negotiation failure path (server supports none of client's protocols)
- SNI mismatch behavior
- `supported_groups` / `key_share` matching logic
- `max_fragment_length` vs `record_size_limit` conflict
- Duplicate extension detection
- Server returning extensions not proposed by client

### 2.5 D4 — DTLS Loss/Retransmission (High)

DTLS 1.2's core value is handling unreliable UDP transport, but all tests use **reliable in-memory transport**:

- No packet loss simulation (e.g., ClientHello lost → timeout retransmission)
- No out-of-order delivery tests (Finished arriving before Certificate)
- Retransmission backoff algorithm (`retransmit.rs`) has no integration-level verification
- Epoch transition with old-epoch records untested

### 2.6 D5 — TLCP Double Certificate (High)

TLCP's core differentiator is the **dual certificate mechanism** (signing cert + encryption cert):

- No validation that both certificates are present and correct type
- Signing cert used in ServerKeyExchange signature verification: no dedicated test
- Encryption cert used in ClientKeyExchange SM2 encryption: no dedicated test
- SM3 transcript hash and SM3-PRF correctness: no dedicated test

### 2.7 D6 — No Property-Based Testing (Medium)

The project relies on hand-written edge case tests and RFC vectors. No `proptest` or `quickcheck` usage. For a crypto library, property-based testing would catch input-space gaps:

- `decrypt(encrypt(x)) == x` for arbitrary x
- `verify(msg, sign(msg))` for arbitrary msg
- ASN.1 `encode(decode(bytes))` roundtrip symmetry

### 2.8 D7 — No Code Coverage Metrics (Medium)

CI pipeline has no `cargo-tarpaulin` or `llvm-cov` integration. Coverage is measured by file-level "has tests / no tests", but cannot determine:

- Function-level coverage
- Branch coverage (especially error branches)
- Actual indirect coverage of the 30 untested crypto files

### 2.9 D8 — No Cross-Implementation Interop (Medium)

No tests compare results against OpenSSL/BoringSSL/GnuTLS:

- Post-quantum algorithms (ML-KEM/ML-DSA/SLH-DSA) have no published standard test vectors yet, relying only on roundtrip verification
- TLS handshakes only interoperate with self — cannot detect protocol compatibility issues

### 2.10 D9 — Fuzz Targets Parse-Only (Low-Medium)

All 10 fuzz targets cover **parsing** (ASN.1, PEM, X.509, TLS record/handshake, CMS, PKCS#8/12). Missing:

- State machine fuzzing (arbitrary message sequences driving TLS state machine)
- Cryptographic fuzzing (arbitrary ciphertext → decrypt, verify no panic)
- Protocol fuzzing (mutated handshake message content → verify correct rejection)

### 2.11 D10 — 30 Crypto Files Without Unit Tests (Low)

After Phase T101, 30 `hitls-crypto` implementation files lack direct unit tests:

| Category | Files | Lines |
|----------|------:|------:|
| SLH-DSA (FIPS 205) | 6 | 1,224 |
| Classic McEliece | 7 | 1,686 |
| XMSS (RFC 8391) | 5 | 752 |
| FrodoKEM | 3 | 743 |
| SM9 (remaining) | 7 | 1,121 |
| Provider traits | 1 | 144 |

These modules have indirect coverage through top-level roundtrip tests (e.g., `test_slhdsa_sign_verify_roundtrip`), but internal functions lack boundary/negative tests.

---

## 3. Testing Optimization Roadmap

### 3.1 Phase Plan Overview

```
Phase              Est. Tests   Deficiency   Focus
─────────────────  ──────────   ──────────   ──────────────────────────────────
Phase T102        ~8      D1           0-RTT early data + replay protection ✅
Phase T103       ~20      D2           Async TLS 1.2 connection tests
Phase T104       ~15      D2           Async TLCP + DTLCP connection tests
Phase T105       ~12      D3           Extension negotiation e2e tests
Phase T106       ~10      D4           DTLS loss simulation + retransmission
Phase T107        ~8      D5           TLCP double certificate validation
Phase T108       ~15      D10          SM9 tower fields (fp2/fp4/fp12)
Phase T109       ~20      D10          SLH-DSA internal modules
Phase T110       ~15      D10          McEliece + FrodoKEM + XMSS internals
Phase T111        —       D6/D7        Infra: proptest + coverage CI
```

**Target**: 2,585 → 2,700+ tests, close all Critical/High deficiencies.

### 3.2 Phase T102 — 0-RTT Early Data + Replay Protection (~8 tests) ✅

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

### 3.3 Phase T103 — Async TLS 1.2 Connection Tests (~20 tests)

**Deficiency**: D2 (Critical)

| # | Test | Description |
|:-:|------|-------------|
| 1 | test_async_tls12_read_before_handshake | Read before handshake returns error |
| 2 | test_async_tls12_write_before_handshake | Write before handshake returns error |
| 3 | test_async_tls12_full_handshake_data | Full ECDHE handshake + bidirectional data |
| 4 | test_async_tls12_version_check | Verify negotiated version is TLS 1.2 |
| 5 | test_async_tls12_cipher_suite_check | Verify negotiated cipher suite |
| 6 | test_async_tls12_shutdown | Graceful close_notify shutdown |
| 7 | test_async_tls12_large_payload | 32KB payload transfer |
| 8 | test_async_tls12_multi_message | Multiple sequential messages |
| 9 | test_async_tls12_session_take | Take session after handshake |
| 10 | test_async_tls12_connection_info | ConnectionInfo fields populated |
| 11 | test_async_tls12_alpn | ALPN negotiation |
| 12 | test_async_tls12_session_resumed | Session resumption via ticket |
| 13 | test_async_tls12_rsa_handshake | RSA key exchange handshake |
| 14 | test_async_tls12_cbc_cipher | CBC cipher suite roundtrip |
| 15 | test_async_tls12_chacha20_cipher | ChaCha20-Poly1305 cipher suite |
| 16 | test_async_tls12_mtls | Mutual TLS with client certificate |
| 17 | test_async_tls12_renegotiation | Server-initiated renegotiation |
| 18 | test_async_tls12_export_keying_material | RFC 5705 key export |
| 19 | test_async_tls12_max_fragment | Max fragment length negotiation |
| 20 | test_async_tls12_server_name | SNI verification |

### 3.4 Phase T104 — Async TLCP + DTLCP Connection Tests (~15 tests)

**Deficiency**: D2 (Critical)

| # | Test | Description |
|:-:|------|-------------|
| 1 | test_async_tlcp_read_before_handshake | Error on premature read |
| 2 | test_async_tlcp_full_handshake_data | ECDHE_SM4_CBC_SM3 handshake + data |
| 3 | test_async_tlcp_gcm_handshake | SM4-GCM cipher suite |
| 4 | test_async_tlcp_ecc_handshake | ECC key exchange |
| 5 | test_async_tlcp_shutdown | Graceful shutdown |
| 6 | test_async_tlcp_connection_info | ConnectionInfo fields |
| 7 | test_async_tlcp_large_payload | 32KB payload |
| 8 | test_async_dtlcp_read_before_handshake | Error on premature read |
| 9 | test_async_dtlcp_full_handshake_data | DTLCP ECDHE handshake + data |
| 10 | test_async_dtlcp_gcm_handshake | DTLCP GCM cipher suite |
| 11 | test_async_dtlcp_shutdown | Graceful shutdown |
| 12 | test_async_dtlcp_connection_info | ConnectionInfo fields |
| 13 | test_async_dtlcp_bidirectional | Bidirectional data exchange |
| 14 | test_async_tlcp_multi_message | Multiple sequential messages |
| 15 | test_async_dtlcp_large_payload | 32KB payload |

### 3.5 Phase T105 — Extension Negotiation E2E Tests (~12 tests)

**Deficiency**: D3 (High)

| # | Test | Description |
|:-:|------|-------------|
| 1 | test_alpn_no_common_protocol | ALPN mismatch → handshake failure |
| 2 | test_alpn_server_selects_preferred | Server selects first matching protocol |
| 3 | test_sni_mismatch_rejection | SNI hostname mismatch → alert |
| 4 | test_supported_groups_no_common | No common group → HRR or failure |
| 5 | test_key_share_group_mismatch | Key share group not in supported_groups |
| 6 | test_sig_algs_client_server_match | Signature algorithm negotiation |
| 7 | test_max_fragment_length_negotiation | MFL client/server agreement |
| 8 | test_record_size_limit_enforcement | RSL overrides default record size |
| 9 | test_duplicate_extension_rejected | Duplicate extension → decode error |
| 10 | test_server_unsolicited_extension | Server sends unrequested extension |
| 11 | test_session_ticket_extension_flow | Ticket extension in CH/SH/NST |
| 12 | test_early_data_extension_codec | Early data extension roundtrip |

### 3.6 Phase T106 — DTLS Loss Simulation + Retransmission (~10 tests)

**Deficiency**: D4 (High)

| # | Test | Description |
|:-:|------|-------------|
| 1 | test_dtls_flight1_timeout_retransmit | ClientHello retransmission on timeout |
| 2 | test_dtls_flight2_timeout_retransmit | ServerHello retransmission on timeout |
| 3 | test_dtls_backoff_calculation | Exponential backoff doubling verified |
| 4 | test_dtls_max_retransmit_reached | Max retransmission limit → error |
| 5 | test_dtls_out_of_order_handshake | Messages arriving out of sequence |
| 6 | test_dtls_duplicate_handshake_ignored | Duplicate handshake message filtered |
| 7 | test_dtls_epoch_transition_ccs | Epoch 0→1 on ChangeCipherSpec |
| 8 | test_dtls_old_epoch_record_rejected | Post-CCS epoch-0 record rejected |
| 9 | test_dtls_fragment_reassembly_partial | Partial fragment arrival → buffered |
| 10 | test_dtls_cookie_replay_rejected | Replayed cookie from old HVR rejected |

### 3.7 Phase T107 — TLCP Double Certificate Validation (~8 tests)

**Deficiency**: D5 (High)

| # | Test | Description |
|:-:|------|-------------|
| 1 | test_tlcp_dual_cert_both_present | Both signing + encryption certs present |
| 2 | test_tlcp_signing_cert_verification | Signing cert used in SKE signature |
| 3 | test_tlcp_encryption_cert_sm2_encrypt | Encryption cert used in CKE SM2 encrypt |
| 4 | test_tlcp_missing_encryption_cert | Missing encryption cert → error |
| 5 | test_tlcp_missing_signing_cert | Missing signing cert → error |
| 6 | test_tlcp_sm3_transcript_hash | SM3 transcript hash correctness |
| 7 | test_tlcp_sm3_prf_master_secret | SM3-based PRF for master secret |
| 8 | test_tlcp_cert_issuer_mismatch | Signing/encryption cert issuer mismatch |

### 3.8 Phase T108 — SM9 Tower Fields (~15 tests)

**Deficiency**: D10

| # | Test | Description |
|:-:|------|-------------|
| 1-5 | fp2 tests | add/sub identity, mul conjugate, frobenius, serialization, mul_by_u |
| 6-10 | fp4 tests | add identity, mul_by_v, frobenius, serialization, neg_double_neg |
| 11-15 | fp12 tests | mul identity, frobenius p/p2/p3, serialization, inverse |

### 3.9 Phase T109 — SLH-DSA Internal Modules (~20 tests)

**Deficiency**: D10

| Module | Tests | Description |
|--------|:-----:|-------------|
| address.rs | 4 | Set/get layer/tree/keypair/chain address fields |
| wots.rs | 4 | WOTS+ chain, pk_from_sig roundtrip, checksum |
| fors.rs | 4 | FORS tree leaf, sign/verify subset, root computation |
| hypertree.rs | 4 | Hypertree sign/verify, layer traversal, root |
| hash.rs | 4 | PRF, H_msg, F/T_l functions with test vectors |

### 3.10 Phase T110 — McEliece + FrodoKEM + XMSS Internals (~15 tests)

**Deficiency**: D10

| Module | Tests | Description |
|--------|:-----:|-------------|
| McEliece poly/matrix | 5 | Polynomial GCD, systematic matrix, syndrome decode |
| FrodoKEM matrix/pke | 5 | Matrix sample, pack/unpack, PKE encrypt/decrypt |
| XMSS tree/WOTS | 5 | Merkle tree build, WOTS chain, address manipulation |

### 3.11 Phase T111 — Infrastructure: proptest + Coverage CI

**Deficiency**: D6, D7

| Task | Description |
|------|-------------|
| Add `proptest` dependency | dev-dependency for hitls-crypto and hitls-tls |
| Crypto property tests | `decrypt(encrypt(x)) == x` for AES-GCM, ChaCha20, RSA |
| Codec property tests | `decode(encode(x)) == x` for ASN.1, TLS records |
| Coverage CI job | `cargo-tarpaulin` or `llvm-cov` with threshold gate |
| Coverage badge | Add to README.md |

---

## 4. Coverage Targets

| Metric | Current | After Phase T107 | After Phase T111 |
|--------|:-------:|:--------------:|:---------------:|
| Total tests | 2,585 | ~2,660 | ~2,750+ |
| Critical deficiencies (D1-D2) | 2 | 0 | 0 |
| High deficiencies (D3-D5) | 3 | 0 | 0 |
| Crypto files with tests | 75% | 75% | 90%+ |
| TLS files with tests | 100% | 100% | 100% |
| Async connection type coverage | 40% | 100% | 100% |
| Extension negotiation coverage | ~20% | 80%+ | 80%+ |
| DTLS loss scenario coverage | 0% | 70%+ | 70%+ |
| Property-based testing | No | No | Yes |
| Code coverage in CI | No | No | Yes |

---

## 5. Strengths Summary

Despite the identified gaps, the current safety net has significant strengths:

1. **Multi-layer defense**: Unit + Integration + Fuzz + Benchmark + CI/CD
2. **Zero-warning policy**: Clippy enforced across entire workspace
3. **Standard compliance**: 15 Wycheproof suites (5,000+ vectors) + 7 FIPS KATs + 11 RFC vector sets
4. **100% Zeroize compliance**: All secret material types properly zeroized on drop
5. **Constant-time operations**: `subtle::ConstantTimeEq` in all cryptographic comparisons
6. **Unsafe confinement**: 21 unsafe blocks confined to hardware acceleration, all tested with NIST vectors
7. **Miri validation**: Undefined behavior detection on bignum and utils crates
8. **Security audit automation**: rustsec/audit-check in CI pipeline
9. **Deterministic testing**: Fixed seeds/keys for reproducible results
10. **Comprehensive wrong-state tests**: Every TLS state machine transition has invalid-state tests
