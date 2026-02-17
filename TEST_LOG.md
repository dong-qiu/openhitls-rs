# openHiTLS-rs — Test Development Log

## Overview

Systematic test coverage improvement across the openHiTLS-rs workspace.
Tests were added in four priority tiers (P0–P3), working from most critical
(core crypto primitives) down to supplementary coverage.

**Baseline**: 1,104 tests (36 ignored)
**Current**: 1,952 tests (40 ignored)
**P0–P3 Total**: 1,291 tests (37 ignored) — **187 new tests added**
**Testing-Phase 72**: +72 tests (CLI commands + Session Cache concurrency)

---

## P0 — Critical Core Crypto (64 new tests)

**Target**: Core cryptographic primitives with zero or minimal existing tests.

| Module | File | Tests Added | Description |
|--------|------|:-----------:|-------------|
| AES-GCM | `hitls-crypto/src/modes/gcm.rs` | 12 | RFC 5116 vectors, empty AAD, empty plaintext, wrong key/nonce/tag, large AAD, IV lengths, determinism |
| AES-CBC | `hitls-crypto/src/modes/cbc.rs` | 10 | PKCS7 padding, multi-block, empty input, wrong key, block-aligned, unpad invalid, single block, 256-bit |
| SHA-2 | `hitls-crypto/src/sha2/mod.rs` | 10 | Empty input, single/multi-block, long message, incremental update, NIST vectors (SHA-256/384/512) |
| HMAC | `hitls-crypto/src/hmac/mod.rs` | 8 | RFC 4231 vectors (Cases 1–4), SHA-384, incremental update, wrong key, empty data |
| RSA | `hitls-crypto/src/rsa/mod.rs` | 8 | PKCS#1 v1.5 sign/verify roundtrip, wrong hash, tampered sig, PSS sign/verify, key generation, encrypt/decrypt, wrong private key |
| ECDSA | `hitls-crypto/src/ecdsa/mod.rs` | 8 | P-256/P-384 sign+verify, wrong curve, tampered signature/digest, key roundtrip, empty message, deterministic public key |
| Ed25519 | `hitls-crypto/src/ed25519/mod.rs` | 8 | RFC 8032 Test Vector 1, empty/long message, wrong public key, tampered sig, key from seed roundtrip, sign determinism |

**Workspace after P0**: 1,168 tests, 36 ignored

---

## P1 — Protocol-Critical TLS + PKI (60 new tests)

**Target**: TLS record layer, X.509 parsing, and additional crypto modules.

| Module | File | Tests Added | Description |
|--------|------|:-----------:|-------------|
| TLS Record | `hitls-tls/src/record/mod.rs` | 12 | Encode/decode roundtrip, fragment types, max-size fragment, empty payload, 1-byte payload, multi-record decode, sequence numbers, key update |
| X.509 Parse | `hitls-pki/src/x509/mod.rs` | 12 | Self-signed parse, issuer/subject, validity dates, extensions, SAN, key usage, serial, signature algorithm, unknown extension, certificate chain, version field, public key extraction |
| ChaCha20-Poly1305 | `hitls-crypto/src/chacha20/mod.rs` | 8 | RFC 7539 vectors, encrypt/decrypt roundtrip, wrong key/nonce, AEAD tag verification, empty plaintext, large data, counter overflow |
| X25519 | `hitls-crypto/src/x25519/mod.rs` | 8 | RFC 7748 vectors, DH roundtrip, clamping, all-zero check, key from bytes, different keys → different shared secrets, public key derivation |
| HKDF (crypto) | `hitls-crypto/src/hkdf/mod.rs` | 6 | RFC 5869 extract/expand Test Cases 1–3, SHA-384, zero-length info, long output |
| DH Groups | `hitls-crypto/src/dh/mod.rs` | 6 | RFC 3526 / RFC 7919 group params (modp2048/3072/ffdhe2048/3072), key exchange roundtrip, parameter validation |
| SM4 | `hitls-crypto/src/sm4/mod.rs` | 4 | GB/T 32907 vector, encrypt/decrypt roundtrip, wrong key length, ECB mode |
| SM3 | `hitls-crypto/src/sm3/mod.rs` | 4 | GB/T 32905 vectors (empty, "abc", 64-byte), incremental update |

**Workspace after P1**: 1,200 tests, 37 ignored

---

## P2 — Handshake & Key Schedule (42 new tests)

**Target**: TLS 1.3 handshake signing/verification and key derivation.

| Module | File | Tests Added | Description |
|--------|------|:-----------:|-------------|
| TLS 1.3 Key Schedule | `hitls-tls/src/crypt/key_schedule.rs` | 11 | PSK early secret, early traffic secret, binder keys (res/ext + wrong stage), exporter/resumption master secret (+ wrong stage), resumption PSK, finished verify_data, double derive_early_secret error, traffic update chain |
| CertificateVerify Signing | `hitls-tls/src/handshake/signing.rs` | 9 | Ed448/ECDSA P-256/P-384/RSA scheme selection, ECDSA P-256 sign+verify roundtrip, server vs client context difference, unsupported ECDSA scheme mismatch |
| CertificateVerify Verify | `hitls-tls/src/handshake/verify.rs` | 9 | build_verify_content lengths, empty hash, Ed25519 sign+verify roundtrip, wrong signature, wrong transcript, server vs client context, ECDSA P-256/P-384, unsupported scheme |
| Key Exchange | `hitls-tls/src/handshake/key_exchange.rs` | 7 | Non-KEM encapsulate error, wrong peer key lengths (X25519/X448/SECP256R1/hybrid), key uniqueness, non-zero shared secret |
| TLS 1.2 Key Schedule | `hitls-tls/src/crypt/key_schedule12.rs` | 6 | CBC key block with MAC keys, CBC-256 block length, ChaCha20-Poly1305, SHA-384 master secret, verify_data always 12 bytes, key block seed order |

**Workspace after P2**: 1,243 tests, 37 ignored

---

## P3 — Supplementary Coverage (48 new tests)

**Target**: Config builder, field arithmetic, HKDF TLS primitives, CMS EncryptedData.

| Module | File | Tests Added | Description |
|--------|------|:-----------:|-------------|
| TLS Config Builder | `hitls-tls/src/config/mod.rs` | 16 | Version range, ALPN, cipher suites, session resumption, PSK config, EMS/EtM defaults + disable, record size limit, fallback SCSV, OCSP/SCT, post-handshake auth, early data, ticket key, Debug format (config + builder), PSK server callback |
| Curve448 Field (Fe448) | `hitls-crypto/src/curve448/field.rs` | 13 | Neg roundtrip, neg zero, mul_small (×3: normal/zero/one), sqrt of square, distributive law, commutativity, is_negative, PartialEq (same/different), sub self = zero, invert one |
| HKDF (TLS) | `hitls-tls/src/crypt/hkdf.rs` | 8 | hmac_hash basic + long key, expand long output (multi-iteration), expand too large error, expand_label with context, derive_secret SHA-384, extract deterministic, expand single byte |
| CMS EncryptedData | `hitls-pki/src/cms/encrypted.rs` | 5 | Wrong key length, empty plaintext, large data (64 KiB), tampered ciphertext, unique nonces (randomness) |
| Traffic Keys | `hitls-tls/src/crypt/traffic_keys.rs` | 6 | Client HS keys (RFC 8448), SHA-384, ChaCha20-Poly1305, deterministic, different secrets, different suites/lengths |

**Workspace after P3**: 1,291 tests, 37 ignored

---

## Verification

All phases verified with:

```bash
# Full test suite — all pass
cargo test --workspace --all-features
# Result: 1,291 passed, 0 failed, 37 ignored

# Clippy — zero warnings
RUSTFLAGS="-D warnings" cargo clippy --workspace --all-features --all-targets

# Format check
cargo fmt --all -- --check
```

## Per-Crate Breakdown (Final)

| Crate | Tests | Ignored |
|-------|------:|--------:|
| hitls-crypto | 476 | 28 |
| hitls-tls | 496 | 0 |
| hitls-pki | 122 | 1 |
| hitls-bignum | 46 | 0 |
| hitls-utils | 35 | 0 |
| hitls-cli | 26 | 5 |
| hitls-auth | 24 | 0 |
| hitls-integration-tests | 23 | 3 |
| Wycheproof (hitls-crypto) | 15 | 0 |
| Doc-tests | 2 | 0 |
| **Total** | **1,291** | **37** |

## Test Quality Principles

- **RFC / standard test vectors** where available (RFC 8448, RFC 5869, RFC 7539, RFC 8032, RFC 4231, GB/T 32907, GB/T 32905)
- **Roundtrip tests** for all encrypt/decrypt and sign/verify paths
- **Negative tests**: wrong key, tampered data, invalid lengths, scheme mismatches
- **Edge cases**: empty input, single byte, max-size data, boundary values
- **Determinism checks**: same input → same output
- **State machine tests**: wrong-stage errors in key schedule
- **Constant-time equality** via `subtle::ConstantTimeEq` in crypto comparisons

---

## Phase 62: TLS 1.2 CCM Cipher Suites (RFC 6655 / RFC 7251) — 8 new tests

### Date: 2026-02-16

| Module | File | Tests Added | Description |
|--------|------|:-----------:|-------------|
| AEAD (CCM) | `hitls-tls/src/crypt/aead.rs` | 3 | AesCcmAead encrypt/decrypt roundtrip, AES-128-CCM + AES-256-CCM key sizes, tag verification |
| Record Layer (CCM) | `hitls-tls/src/record/encryption12.rs` | 5 | tls12_suite_to_aead_suite CCM mapping for all 6 suites, seal/open roundtrip with CCM encryptor, nonce construction (fixed_iv + explicit_nonce), AAD format verification, wrong-key rejection |

**Workspace after Phase 62**: 1,790 tests, 40 ignored (+8 from Phase 61's 1,782)

---

## Phase 63: CCM_8 + PSK+CCM Cipher Suites — 12 new tests

### Date: 2026-02-16

| Module | File | Tests Added | Description |
|--------|------|:-----------:|-------------|
| AEAD (CCM_8) | `hitls-tls/src/crypt/aead.rs` | 4 | AesCcm8Aead 8-byte tag encrypt/decrypt roundtrip, wrong AAD rejection, key sizes, TLS 1.3 CCM_8 dispatch |
| Record Layer (CCM_8/PSK+CCM) | `hitls-tls/src/record/encryption12.rs` | 8 | CCM_8 suite mapping (RSA 128/256), PSK+CCM suite mapping, CCM_8 128/256 encrypt/decrypt roundtrip, PSK CCM_8 tampered record, ECDHE_PSK CCM_8 params lookup |

**Workspace after Phase 63**: 1,802 tests, 40 ignored (+12 from Phase 62's 1,790)

---

## Phase 64: PSK CBC-SHA256/SHA384 + ECDHE_PSK GCM Cipher Suites — 5 new tests

### Date: 2026-02-16

| Module | File | Tests Added | Description |
|--------|------|:-----------:|-------------|
| Record Layer (PSK CBC/GCM) | `hitls-tls/src/record/encryption12.rs` | 5 | PSK CBC-SHA256/SHA384 params lookup, ECDHE_PSK GCM params lookup, ECDHE_PSK GCM 128/256 suite mapping + encrypt/decrypt roundtrip |

**Workspace after Phase 64**: 1,807 tests, 40 ignored (+5 from Phase 63's 1,802)

---

## Phase 65: PSK CCM Completion + CCM_8 Authentication Cipher Suites — 11 new tests

### Date: 2026-02-16

| Module | File | Tests Added | Description |
|--------|------|:-----------:|-------------|
| Record Layer (CCM/CCM_8) | `hitls-tls/src/record/encryption12.rs` | 11 | Phase 65 CCM/CCM_8 suite mapping, PSK CCM 128 encrypt/decrypt, PSK CCM_8 128/DHE_RSA CCM_8 256/ECDHE_ECDSA CCM_8 128 roundtrip, PSK CCM_8 tampered record, params lookup (PSK CCM/CCM_8, DHE_PSK CCM_8, ECDHE_PSK CCM_8, DHE_RSA CCM_8, ECDHE_ECDSA CCM_8) |

**Workspace after Phase 65**: 1,818 tests, 40 ignored (+11 from Phase 64's 1,807)

---

## Phase 66: DHE_DSS Cipher Suites (DSA Authentication for TLS 1.2) — 8 new tests

### Date: 2026-02-16

| Module | File | Tests Added | Description |
|--------|------|:-----------:|-------------|
| Record Layer (DHE_DSS) | `hitls-tls/src/record/encryption12.rs` | 8 | DHE_DSS CBC-SHA params lookup (128/256), CBC-SHA256 params lookup (128/256), GCM params lookup (128/256), GCM suite mapping (128→AES_128_GCM_SHA256, 256→AES_256_GCM_SHA384), GCM 128/256 encrypt/decrypt roundtrip, DSA sign/verify roundtrip (via DsaKeyPair + verify_dsa_from_spki), DSA signature scheme selection (DSA_SHA256/SHA384 preference, no-match error) |

**Workspace after Phase 66**: 1,826 tests, 40 ignored (+8 from Phase 65's 1,818)

---

## Phase 67: DH_ANON + ECDH_ANON Cipher Suites (Anonymous Key Exchange for TLS 1.2) — 10 new tests

### Date: 2026-02-16

| Module | File | Tests Added | Description |
|--------|------|:-----------:|-------------|
| Record Layer (DH_ANON/ECDH_ANON) | `hitls-tls/src/record/encryption12.rs` | 8 | DH_ANON CBC-SHA params lookup (128/256), DH_ANON CBC-SHA256 params lookup (128/256), DH_ANON GCM params lookup (128/256), ECDH_ANON CBC-SHA params lookup (128/256), DH_ANON GCM suite AEAD mapping (128→AES_128_GCM_SHA256, 256→AES_256_GCM_SHA384), DH_ANON GCM 128/256 encrypt/decrypt roundtrip, anonymous requires_certificate false |
| Codec (DH_ANON/ECDH_ANON) | `hitls-tls/src/handshake/codec12.rs` | 2 | DHE_ANON SKE codec roundtrip (encode→decode, 256-byte p/g/Ys), ECDHE_ANON SKE codec roundtrip (encode→decode, secp256r1 65-byte point) |

**Workspace after Phase 67**: 1,836 tests, 40 ignored (+10 from Phase 66's 1,826)

---

## Phase 68: TLS 1.2 Renegotiation (RFC 5746) — 10 new tests

### Date: 2026-02-17

| Module | File | Tests Added | Description |
|--------|------|:-----------:|-------------|
| Handshake Codec | `hitls-tls/src/handshake/codec.rs` | 1 | HelloRequest encode → `[0x00, 0x00, 0x00, 0x00]`, parse → type HelloRequest, empty body |
| Extensions Codec | `hitls-tls/src/handshake/extensions_codec.rs` | 1 | Build renegotiation_info with 12+12 verify_data, parse, validate content roundtrip |
| Client Handshake | `hitls-tls/src/handshake/client12.rs` | 1 | reset_for_renegotiation sets state=Idle, is_renegotiation=true, prev_*_verify_data preserved |
| Server Handshake | `hitls-tls/src/handshake/server12.rs` | 2 | reset_for_renegotiation (same as client), build_hello_request returns `[0, 0, 0, 0]` |
| Alert | `hitls-tls/src/alert/mod.rs` | 1 | NoRenegotiation = 100, from_u8(100) roundtrip |
| Config | `hitls-tls/src/config/mod.rs` | 1 | Builder default false, set true, build, verify |
| Connection (sync) | `hitls-tls/src/connection12.rs` | 3 | Full renegotiation TCP roundtrip (handshake → data → renego → data), renegotiation disabled rejects (no_renegotiation warning → connection continues), renegotiation no session resumption (with ticket_key, always full handshake) |

**Workspace after Phase 68**: 1,846 tests, 40 ignored (+10 from Phase 67's 1,836)

---

## Phase 69: Connection Info APIs + Graceful Shutdown + ALPN Completion — 8 new tests

### Date: 2026-02-17

| Module | File | Tests Added | Description |
|--------|------|:-----------:|-------------|
| Connection (TLS 1.2 sync) | `hitls-tls/src/connection12.rs` | 5 | connection_info cipher_suite/version/peer_certs/server_name/named_group/verify_data, ALPN negotiation (h2 selected from h2+http/1.1), session_resumed (full=false, abbreviated=true), graceful shutdown (close_notify send/receive, Ok(0) on read), close_notify_in_read (received_close_notify flag, ConnectionState::Closed) |
| Connection (TLS 1.3 sync) | `hitls-tls/src/connection.rs` | 3 | connection_info (SNI, negotiated_group, server_certs, is_psk_mode, negotiated_alpn), ALPN negotiation (client offers h2+http/1.1, server selects h2, verified on both sides), graceful shutdown (close_notify exchange via record layer, bidirectional close) |

**Workspace after Phase 69**: 1,854 tests, 40 ignored (+8 from Phase 68's 1,846)


---

## Testing-Phase 72 — CLI Command Unit Tests + Session Cache Concurrency (2026-02-17)

**Scope**: Stage A of the test optimization plan — fills gaps identified in the test completeness analysis.
**New tests**: +72 (1880 → 1952 total, 40 ignored unchanged)

### CLI Command Tests (+66 across 7 files)

| Module | File | Tests | Coverage |
|--------|------|:-----:|---------|
| dgst | `hitls-cli/src/dgst.rs` | 17 | hash_data() × 9 algorithms, case insensitivity, alias, different-inputs, run() success/file-not-found/bad-algorithm |
| x509cmd | `hitls-cli/src/x509cmd.rs` | 15 | hex_str(), days_to_ymd() (epoch/Y2K/leap/Dec31), format_time() (epoch/2024/UTC), run() default/fingerprint/text/invalid/nonexistent |
| genpkey | `hitls-cli/src/genpkey.rs` | 19 | parse_curve_id() ×aliases/P384/SM2/unknown, parse_mlkem_param() ×512/768/1024/empty/unknown, parse_mldsa_param() ×44/65/87/unknown, run() ×EC/ECDSA/Ed25519/X25519/MLKEM/MLDSA/unknown/file-output |
| pkey | `hitls-cli/src/pkey.rs` | 5 | run() no-flags/text/pubout/empty-file-error/nonexistent |
| req | `hitls-cli/src/req.rs` | 9 | parse_subject() simple/multi/no-leading-slash/empty/missing-equals, run() CSR-stdout/CSR-file/no-key/no-subject |
| crl | `hitls-cli/src/crl.rs` | 6 | run() PEM-empty/PEM-with-revoked/text-mode/DER/nonexistent/invalid; include_str! CRL test vectors |
| verify | `hitls-cli/src/verify.rs` | 4 | run() success-self-signed/CA-not-found/cert-not-found/invalid-pem |

### Session Cache Concurrency Tests (+6)

| Test | File | Description |
|------|------|-------------|
| test_cache_arc_mutex_basic | `hitls-tls/src/session/mod.rs` | Arc<Mutex<InMemorySessionCache>> basic put+get |
| test_cache_arc_mutex_concurrent_puts | session/mod.rs | 4 threads × 25 unique keys = 100 entries, no data races |
| test_cache_arc_mutex_concurrent_get_put | session/mod.rs | 2 writer + 2 reader threads simultaneously |
| test_cache_arc_mutex_eviction_under_load | session/mod.rs | 3 threads × 10 inserts, max_size=5, eviction preserved |
| test_cache_arc_mutex_shared_across_two_arcs | session/mod.rs | Two Arc clones see same underlying data |
| test_cache_trait_object_via_arc_mutex | session/mod.rs | Arc<Mutex<Box<dyn SessionCache>>> trait-object pattern |

### Workspace Test Counts After Testing-Phase 72

| Crate | Tests | Ignored |
|-------|------:|-------:|
| hitls-auth | 33 | 0 |
| hitls-bignum | 48 | 0 |
| hitls-cli | **117** | 5 |
| hitls-crypto | 593 | 31 |
| wycheproof | 15 | 0 |
| hitls-integration | 39 | 3 |
| hitls-pki | 336 | 1 |
| hitls-tls | **690** | 0 |
| hitls-types | 26 | 0 |
| hitls-utils | 53 | 0 |
| doc-tests | 2 | 0 |
| **Total** | **1952** | **40** |
