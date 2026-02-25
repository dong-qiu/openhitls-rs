# openHiTLS-rs — Quality Assurance Report

> Quality safety net analysis and testing optimization roadmap.
> Related docs: [TEST_LOG.md](TEST_LOG.md) | [DEV_LOG.md](DEV_LOG.md) | [README.md](README.md)

---

## 1. Current Quality Safety Net

### 1.1 Defense Layers (5-Layer Model)

| Layer | Mechanism | Coverage | Status |
|:-----:|-----------|----------|:------:|
| **L1** | Static Analysis | clippy zero-warning + rustfmt + MSRV 1.75 dual-version CI | Complete |
| **L2** | Unit Tests | 3,169 tests (7 ignored), 100% pass rate | Comprehensive |
| **L3** | Integration Tests | 149 cross-crate tests (TCP loopback + DTLS resilience) | Good |
| **L4** | Fuzz Testing | 10 fuzz targets + 66 seed corpus files | Parse-only |
| **L5** | Security Audit | rustsec/audit-check + Miri (bignum/utils) + cargo-tarpaulin coverage | Good |

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
├── Bench Verify     cargo bench --no-run
└── Coverage         cargo-tarpaulin → Cobertura XML (added Phase T111)
```

### 1.3 Per-Crate Test Distribution

| Crate | Tests | Ignored | % of Total | Focus |
|-------|------:|--------:|:----------:|-------|
| hitls-tls | 1,290 | 0 | 41.9% | TLS 1.3/1.2/DTLS/TLCP/DTLCP handshake, record, extensions, callbacks, middlebox compat |
| hitls-crypto | 1,009 | 2 | 31.9% | 48 algorithm modules + hardware acceleration (AES/SHA-2/GHASH/ChaCha20) + P-256 fast path + proptest |
| hitls-pki | 390 | 0 | 12.4% | X.509, PKCS#8/12, CMS (5 content types), encoding helpers |
| hitls-integration | 152 | 0 | 4.9% | Cross-crate TCP loopback, error scenarios, concurrency, DTLS resilience |
| hitls-cli | 117 | 5 | 3.8% | 14 CLI commands |
| hitls-utils | 66 | 0 | 2.1% | ASN.1, Base64, PEM, OID, proptest roundtrips |
| hitls-bignum | 69 | 0 | 2.2% | Montgomery, Miller-Rabin, modular arithmetic, constant-time, random generation |
| hitls-auth | 33 | 0 | 1.1% | HOTP/TOTP, SPAKE2+, Privacy Pass |
| hitls-types | 26 | 0 | 0.8% | Enum definitions, error types |
| Wycheproof | 15 | 0 | 0.5% | 5,000+ vectors across 15 test groups |
| Doc-tests | 2 | 0 | 0.1% | API documentation examples |
| **Total** | **3,169** | **7** | **100%** | |

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
| Unsafe code confinement | ~67 blocks: AES-NI (8), AES-NEON (6), SHA-2 HW (8), GHASH HW (10), ChaCha20 SIMD (6), McEliece (2), lib.rs stubs (5), test SIMD calls (~22) | All with NIST/RFC vectors |
| Random generation | `getrandom` crate, never `rand` | Indirect |

---

## 2. Identified Deficiencies

### 2.1 Deficiency Map

```
Severity         ID   Description                              Impact
────────────     ──   ──────────────────────────────────────   ──────────────────────────
CLOSED           D1   0-RTT replay protection: +8 tests         Resolved (Phase T102)
CLOSED           D2   Async TLCP/DTLCP: zero tests               Resolved (Phase T104: +15)
CLOSED           D3   Extension negotiation: +14 e2e tests       Resolved (Phase T105: +14)
MOSTLY CLOSED    D4   DTLS loss/resilience: +30 tests            Resolved (Phase T106/T116/T117)
MOSTLY CLOSED    D5   TLCP double certificate: +25 tests         Resolved (Phase T107/T112)
CLOSED           D6   Property-based testing: +20 proptest       Resolved (Phase T111)
CLOSED           D7   Code coverage metrics in CI                Resolved (Phase T111: tarpaulin)
Medium           D8   No cross-implementation interop           Compatibility risk
Low-Med          D9   Fuzz targets: parse-only                  Deep bugs missed
MOSTLY CLOSED    D10  Crypto files without unit tests            Resolved (Phase T108–T110/T118)
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

### 2.3 D2 — Async/Sync Test Coverage Asymmetry ~~(Critical)~~ — **CLOSED** (Phase T104)

**Resolved**: Phase T103 added 10 async TLS 1.2 tests. Phase T104 created async connection types for TLCP and DTLCP and added 15 tests (8 TLCP + 7 DTLCP). All 5 protocol variants now have async tests.

| Connection Type | Sync Tests | Async Tests | Gap |
|-----------------|:----------:|:-----------:|:---:|
| TLS 1.3 | 61 | 25 | -36 |
| TLS 1.2 | 53 | 28 | -25 |
| DTLS 1.2 | 20 | 8 | -12 |
| TLCP | 15 | **8** | -7 |
| DTLCP | 6 | **7** | +1 |

Remaining async gaps are coverage depth (fewer test scenarios than sync), not missing connection types.

### 2.4 D3 — Extension Negotiation ~~(High)~~ — **CLOSED** (Phase T105)

Phase T105 added 14 E2E tests covering all identified gaps:
- ALPN no-common-protocol (TLS 1.3 + 1.2), server preference order (TLS 1.2)
- SNI accessor verification on both client and server (TLS 1.3 + 1.2)
- Group negotiation: server preference, HRR trigger, no-common-group failure
- Max fragment length (TLS 1.2), record size limit (TLS 1.3 + 1.2)
- Combined ALPN + SNI + group verification via ConnectionInfo
- Codec: duplicate extension type, zero-length extension parsing

### 2.5 D4 — DTLS Loss/Retransmission ~~(High)~~ — **MOSTLY CLOSED** (Phase T106/T116/T117)

**Resolved across 3 phases** with 30 total DTLS-specific tests:

- **Phase T106** (+10): Post-handshake adverse delivery — out-of-order, selective loss, stale records, corrupted ciphertext, truncated/empty datagrams, wrong epoch, interleaved bidirectional
- **Phase T116** (+10): Fragmentation reassembly (multi-message, old message, out-of-order, overlapping fragments) + retransmission timer (backoff, reset cycles, timeout cap, Flight clone)
- **Phase T117** (+10): Codec edge cases (all handshake types, fragment offset, TLS↔DTLS roundtrip, HVR empty/max cookie) + anti-replay window boundaries (uninitialized, near u64::MAX, shift by WINDOW_SIZE, reset/reuse)

**Remaining** (requires handshake driver refactoring, out of scope for test phase):
- Handshake-level loss simulation (e.g., ClientHello lost → timeout retransmission)
- Out-of-order handshake flight delivery (Finished before Certificate)

### 2.6 D5 — TLCP Double Certificate ~~(High)~~ — **MOSTLY CLOSED** (Phase T107/T112)

**Resolved across 2 phases** with 25 total TLCP-specific tests:

- **Phase T107** (+10): Missing encryption certificate, missing signing key, wrong key type — unit + integration for both TLCP and DTLCP
- **Phase T112** (+15): SM3 transcript hash correctness (empty hash, incremental, hash_len), SM3-PRF determinism and cross-validation, TLCP key schedule (master secret, CBC/GCM key blocks), verify_data SM3 client/server, EMS → key block pipeline, seed order sensitivity, full SM3 verify pipeline

**Remaining gap** (low risk):
- Encryption cert used in ClientKeyExchange SM2 encryption: covered by existing happy-path tests but no dedicated edge-case test

### 2.7 D6 — ~~No Property-Based Testing~~ (Medium) — **CLOSED** (Phase T111)

**Resolved**: Phase T111 added 20 proptest property-based tests:

- **Crypto roundtrips** (6): AES-128/256 block, SM4 block, GCM AEAD, CBC, ChaCha20-Poly1305
- **Hash determinism** (3): SHA-256 determinism, SHA-256 incremental equivalence, HMAC-SHA-256 determinism
- **Signature roundtrip** (1): Ed25519 sign/verify for arbitrary messages
- **DH commutativity** (1): X25519 `dh(a, pub(b)) == dh(b, pub(a))`
- **KDF determinism** (1): HKDF-expand determinism
- **Codec roundtrips** (8): Base64, hex, ASN.1 integer/octet string/boolean/UTF8 string/sequence

### 2.8 D7 — ~~No Code Coverage Metrics~~ (Medium) — **CLOSED** (Phase T111)

**Resolved**: Phase T111 added a `cargo-tarpaulin` coverage CI job:

```yaml
coverage:
  runs-on: ubuntu-latest
  steps:
    - cargo install cargo-tarpaulin --locked
    - cargo tarpaulin --workspace --all-features --out xml --output-dir coverage/ --timeout 900
    - Upload cobertura.xml artifact
```

### 2.9 D8 — No Cross-Implementation Interop (Medium)

No tests compare results against OpenSSL/BoringSSL/GnuTLS:

- Post-quantum algorithms (ML-KEM/ML-DSA/SLH-DSA) have no published standard test vectors yet, relying only on roundtrip verification
- TLS handshakes only interoperate with self — cannot detect protocol compatibility issues

### 2.10 D9 — Fuzz Targets Parse-Only (Low-Medium)

All 10 fuzz targets cover **parsing** (ASN.1, PEM, X.509, TLS record/handshake, CMS, PKCS#8/12). Missing:

- State machine fuzzing (arbitrary message sequences driving TLS state machine)
- Cryptographic fuzzing (arbitrary ciphertext → decrypt, verify no panic)
- Protocol fuzzing (mutated handshake message content → verify correct rejection)

### 2.11 D10 — ~~30~~ ~14 Crypto Files Without Direct Unit Tests ~~(Low)~~ — **MOSTLY CLOSED** (Phase T108–T110/T118)

**Resolved across 4 phases** with 50 total internal module tests:

- **Phase T108** (+15): SM9 tower fields — Fp2 (add/sub/mul/frobenius/serialization), Fp4 (add/mul_by_v/frobenius/serialization), Fp12 (mul/frobenius/serialization/inverse)
- **Phase T109** (+15): SLH-DSA internals — address fields, WOTS+ chain/checksum, FORS tree/sign, hypertree sign/verify, hash PRF/H_msg
- **Phase T110** (+15): McEliece poly/matrix/syndrome, FrodoKEM matrix/pack/PKE, XMSS tree/WOTS/address
- **Phase T118** (+5): SLH-DSA WOTS+ base_b (2-bit/1-bit extraction, empty, all-zeros/all-FF checksum)

**Remaining** (~14 files with indirect coverage only):

| Category | Files | Lines | Status |
|----------|------:|------:|--------|
| SM9 (remaining) | 4 | ~600 | Indirect via roundtrip tests |
| McEliece (remaining) | 5 | ~1,100 | Indirect via keygen/encap/decap |
| XMSS (remaining) | 3 | ~400 | Indirect via sign/verify |
| FrodoKEM (remaining) | 1 | ~250 | Indirect via encap/decap |
| Provider traits | 1 | 144 | Compile-time coverage |

These modules have indirect coverage through top-level roundtrip tests and are lower risk.

---

## 3. Testing Optimization Roadmap

### 3.1 Phase Plan Overview

```
Phase              Tests    Deficiency   Focus                                       Status
─────────────────  ───────  ──────────   ──────────────────────────────────────────  ──────
Phase T102          +8      D1           0-RTT early data + replay protection        ✅
Phase T103         +10      D2           Async TLS 1.2 deep coverage                 ✅
Phase T104         +15      D2           Async TLCP + DTLCP connection tests         ✅
Phase T105         +14      D3           Extension negotiation e2e tests             ✅
Phase T106         +10      D4           DTLS loss simulation + retransmission       ✅
Phase T107         +10      D5           TLCP double certificate validation          ✅
Phase T108         +15      D10          SM9 tower fields (fp2/fp4/fp12)             ✅
Phase T109         +15      D10          SLH-DSA internal modules                    ✅
Phase T110         +15      D10          McEliece + FrodoKEM + XMSS internals        ✅
Phase T111         +20      D6/D7        Infra: proptest + coverage CI               ✅
Phase T112         +15      D5           TLCP SM3 cryptographic path coverage        ✅
Phase T113         +15      —            TLS 1.3 key schedule & HKDF robustness      ✅
Phase T114         +15      —            Record layer encryption & AEAD failures     ✅
Phase T115         +15      D4           TLS 1.2 CBC padding + DTLS parsing          ✅
Phase T116         +15      D4           DTLS fragmentation + retransmission         ✅
Phase T117         +15      D4           DTLS codec + anti-replay boundaries         ✅
Phase T118         +15      D10          X.509 extensions + WOTS+ + ASN.1 tags       ✅
Phase T119         +15      —            PKI encoding + signing dispatch + builder   ✅
Phase T120         +15      —            X.509 cert parsing + SM9 G2 + pairing       ✅
Phase T121         +13      —            SM9 hash + algorithm helpers + curve params ✅
Phase T122         +15      —            McEliece keygen + encoding + decoding       ✅
Phase T123         +10      —            XMSS tree + WOTS+ deepening + FORS          ✅
Phase T124         +15      —            McEliece GF + Benes + matrix deepening      ✅
Phase T125         +12      —            FrodoKEM matrix + SLH-DSA hypertree + poly  ✅
Phase T126         +15      —            McEliece + FrodoKEM + XMSS params deepening ✅
Phase T127         +15      —            XMSS hash + address + ML-KEM NTT deepening  ✅
Phase T128         +15      —            BigNum CT + primality + core type deepening  ✅
Phase T129         +15      —            SLH-DSA params + hash abstraction + address  ✅
Phase T130         +15      —            ML-DSA NTT + PKI text + X.509 cert parsing   ✅
Phase T131         +15      —            ML-DSA signing + XMSS keygen + FrodoKEM enc  ✅
Phase T132         +15      —            ML-KEM indcpa + McEliece field + BigNum shift ✅
Phase T133         +15      —            ML-DSA packing + X.509 builder + PKI CSR      ✅
Phase T134         +15      —            ML-DSA poly + X.509 extensions + PKI text     ✅
```

**Result**: 2,585 → 3,169 tests (+584), all planned deficiencies addressed.

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

### 3.3 Phase T103 — Async TLS 1.2 Deep Coverage (+10 tests) ✅

**Deficiency**: D2 (async TLS 1.2 now has 28 tests; D2 fully closed in Phase T104)
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

### 3.4 Phase T104 — Async TLCP + DTLCP Connection Tests (+15 tests) ✅

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

### 3.5 Phase T105 — Extension Negotiation E2E Tests (+14 tests) ✅

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

### 3.6 Phase T106 — DTLS Loss Simulation + Retransmission (+10 tests) ✅

**Deficiency**: D4 (High) — partially addressed (further addressed by T116/T117)

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

### 3.7 Phase T107 — TLCP Double Certificate Validation (+10 tests) ✅

**Deficiency**: D5 (High) — partially closed (further addressed by T112)

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

### 3.8 Phase T108 — SM9 Tower Fields (+15 tests) ✅

**Deficiency**: D10

| # | Test | Description |
|:-:|------|-------------|
| 1-5 | fp2 tests | add/sub identity, mul conjugate, frobenius, serialization, mul_by_u |
| 6-10 | fp4 tests | add identity, mul_by_v, frobenius, serialization, neg_double_neg |
| 11-15 | fp12 tests | mul identity, frobenius p/p2/p3, serialization, inverse |

### 3.9 Phase T109 — SLH-DSA Internal Modules (+15 tests) ✅

**Deficiency**: D10

| Module | Tests | Description |
|--------|:-----:|-------------|
| address.rs | 3 | Set/get layer/tree/keypair/chain address fields |
| wots.rs | 3 | WOTS+ chain, pk_from_sig roundtrip, checksum |
| fors.rs | 3 | FORS tree leaf, sign/verify subset, root computation |
| hypertree.rs | 3 | Hypertree sign/verify, layer traversal, root |
| hash.rs | 3 | PRF, H_msg, F/T_l functions with test vectors |

### 3.10 Phase T110 — McEliece + FrodoKEM + XMSS Internals (+15 tests) ✅

**Deficiency**: D10

| Module | Tests | Description |
|--------|:-----:|-------------|
| McEliece poly/matrix | 5 | Polynomial GCD, systematic matrix, syndrome decode |
| FrodoKEM matrix/pke | 5 | Matrix sample, pack/unpack, PKE encrypt/decrypt |
| XMSS tree/WOTS | 5 | Merkle tree build, WOTS chain, address manipulation |

### 3.11 Phase T111 — Infrastructure: proptest + Coverage CI (+20 tests) ✅

**Deficiency**: D6, D7 — **BOTH CLOSED**

| Task | Description | Status |
|------|-------------|:------:|
| proptest dependency | dev-dependency for hitls-crypto and hitls-utils | ✅ |
| Crypto property tests (6) | AES/SM4/GCM/CBC/ChaCha20 roundtrips | ✅ |
| Hash/signature tests (5) | SHA-256 determinism/incremental, HMAC, Ed25519, X25519 DH | ✅ |
| KDF/codec tests (9) | HKDF, Base64, hex, ASN.1 integer/octet/bool/UTF8/sequence | ✅ |
| Coverage CI job | `cargo-tarpaulin` → Cobertura XML | ✅ |

### 3.12 Phase T112–T119 — Deep Edge-Case Coverage (+120 tests) ✅

Phases T112–T119 continued hardening beyond the original roadmap:

| Phase | Tests | Focus |
|-------|:-----:|-------|
| T112 | +15 | TLCP SM3 transcript hash, PRF, key schedule, verify_data (closes D5 SM3 gap) |
| T113 | +15 | TLS 1.3 key schedule SHA-384 pipeline, stage enforcement, SM4-GCM-SM3 |
| T114 | +15 | Record layer AEAD encryption edge cases, failure modes, epoch transitions |
| T115 | +15 | TLS 1.2 CBC padding oracle, DTLS record parsing, TLS 1.3 inner plaintext |
| T116 | +15 | DTLS fragmentation/reassembly, retransmission timer, CertificateVerify (extends D4) |
| T117 | +15 | DTLS codec all types, anti-replay window boundaries, entropy conditioning (extends D4) |
| T118 | +15 | X.509 extension parsing, SLH-DSA WOTS+ base conversion, ASN.1 tag long-form (extends D10) |
| T119 | +15 | PKI shared encoding helpers, X.509 signing hash dispatch, certificate builder DER encoding |
| T120 | +15 | X.509 certificate parsing, SM9 G2 point arithmetic, SM9 pairing helpers |
| T121 | +13 | SM9 hash functions H1/H2/KDF, SM9 algorithm sign/verify/encrypt/decrypt, BN256 curve parameters |
| T122 | +15 | McEliece keygen helpers (bitrev/SHAKE256/PRG), encoding (error vector), decoding (Berlekamp-Massey) |
| T123 | +10 | XMSS tree operations (compute_root/sign/verify), WOTS+ deepening, SLH-DSA FORS deepening |
| T124 | +15 | McEliece GF(2^13) field algebra, Benes network permutation/sort, binary matrix Gaussian elimination |

---

## 4. Coverage Targets — Final Status

| Metric | Original (T106) | Target (T111) | **Actual (T135)** |
|--------|:---------------:|:-------------:|:-----------------:|
| Total tests | 2,634 | ~2,750+ | **3,169** |
| Critical deficiencies (D1-D2) | 0 | 0 | **0** |
| High deficiencies (D3-D5) | 2 partial | 0 | **0** (D4/D5 mostly closed) |
| Crypto files with tests | 75% | 90%+ | **~90%** |
| TLS files with tests | 100% | 100% | **100%** |
| PKI files with tests | ~85% | ~85% | **100%** (T118/T119) |
| Async connection type coverage | 100% | 100% | **100%** |
| Extension negotiation coverage | 80%+ | 80%+ | **95%+** |
| DTLS loss scenario coverage | 70%+ | 70%+ | **90%+** (T106/T116/T117) |
| Property-based testing | No | Yes | **Yes** (20 proptest) |
| Code coverage in CI | No | Yes | **Yes** (tarpaulin) |

All original targets met or exceeded.

---

## 5. Remaining Gaps (Low Priority)

| ID | Description | Risk | Effort |
|----|-------------|:----:|:------:|
| D8 | No cross-implementation interop (OpenSSL/BoringSSL) | Medium | High |
| D9 | Fuzz targets parse-only (no state machine / crypto fuzzing) | Low-Med | Medium |
| D4r | Handshake-level DTLS loss simulation (requires driver refactoring) | Low | High |
| D10r | ~14 crypto files with indirect-only coverage | Low | Low |

---

## 6. Strengths Summary

The current safety net has significant strengths:

1. **Multi-layer defense**: Unit + Integration + Fuzz + Benchmark + CI/CD + Coverage
2. **Zero-warning policy**: Clippy enforced across entire workspace
3. **Standard compliance**: 15 Wycheproof suites (5,000+ vectors) + 7 FIPS KATs + 11 RFC vector sets
4. **100% Zeroize compliance**: All secret material types properly zeroized on drop
5. **Constant-time operations**: `subtle::ConstantTimeEq` in all cryptographic comparisons
6. **Unsafe confinement**: 21 unsafe blocks confined to hardware acceleration, all tested with NIST vectors
7. **Miri validation**: Undefined behavior detection on bignum and utils crates
8. **Security audit automation**: rustsec/audit-check in CI pipeline
9. **Property-based testing**: 20 proptest tests covering crypto roundtrips, codec symmetry, DH commutativity
10. **Code coverage tracking**: cargo-tarpaulin integrated in CI pipeline
11. **Deterministic testing**: Fixed seeds/keys for reproducible results
12. **Comprehensive wrong-state tests**: Every TLS state machine transition has invalid-state tests
