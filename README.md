# openHiTLS-rs

A production-grade cryptographic and TLS library written in pure Rust, rewritten from [openHiTLS](https://gitee.com/openhitls/openhitls) (C implementation).

> **Status: Phase 50 Complete — Test Coverage + CMS Ed25519/Ed448 + enc CLI + TLS 1.2 OCSP/SCT**
>
> 1397 tests passing (24 auth + 46 bignum + 504 crypto + 15 wycheproof + 126 pki + 558 tls + 26 types + 35 utils + 37 cli + 26 integration; 37 ignored). 5000+ Wycheproof edge-case vectors, 10 fuzz targets, security audit (constant-time, zeroize, unsafe code review). Full coverage: hash (SHA-2, SHA-3/SHAKE, SM3, SHA-1, MD5), HMAC/CMAC/GMAC/SipHash, symmetric (AES, SM4, ChaCha20), modes (ECB, CBC, CTR, GCM, CFB, OFB, CCM, XTS, Key Wrap), ChaCha20-Poly1305, KDFs (HKDF, PBKDF2, scrypt), DRBGs (HMAC-DRBG, CTR-DRBG, Hash-DRBG), entropy health testing (NIST SP 800-90B RCT+APT, entropy pool, conditioning, pluggable noise sources), RSA (PKCS#1v1.5, OAEP, PSS), ECC (P-224, P-256, P-384, P-521, Brainpool P-256r1/P-384r1/P-512r1), ECDSA, ECDH, Ed25519, X25519, Ed448 (RFC 8032), X448 (RFC 7748), Curve448 (Goldilocks), DH, DSA, SM2, SM9 (IBE with BN256 pairing), PQC (ML-KEM, ML-DSA, SLH-DSA, XMSS, FrodoKEM, Classic McEliece), HPKE, HybridKEM, Paillier, ElGamal, X.509 (parse/verify/chain/CSR generation/certificate generation/to_text), PKCS#8 (parse/encode), PKCS#12, CMS SignedData (Ed25519/Ed448) + EnvelopedData + EncryptedData + DigestedData, TLS 1.3 (key schedule + record + client/server handshake + PSK/session tickets + 0-RTT early data + post-handshake client auth + certificate compression + X25519MLKEM768 hybrid KEM + SM4-GCM/CCM (RFC 8998)), TLS 1.2 handshake (47 cipher suites: ECDHE/RSA/DHE_RSA/PSK/DHE_PSK/RSA_PSK/ECDHE_PSK key exchange, GCM/CBC/ChaCha20, Bleichenbacher protection, ALPN, SNI, session resumption, session ticket, EMS, ETM, renegotiation indication, mTLS, OCSP stapling CertificateStatus), DTLS 1.2 (record layer + handshake + fragmentation + retransmission + cookie exchange + anti-replay), TLCP (GM/T 0024, 4 cipher suites, double certificate, ECDHE + ECC key exchange), DTLCP (DTLS + TLCP, 4 cipher suites, cookie exchange, anti-replay), custom extensions framework, NSS key logging (SSLKEYLOGFILE), Record Size Limit (RFC 8449), Fallback SCSV (RFC 7507), OCSP stapling, SCT (RFC 6962), async I/O (tokio), hardware AES (AES-NI + ARMv8 NEON), FIPS/CMVP (KAT, PCT, integrity, entropy health tests), TLS 1.2 PRF, HOTP/TOTP, SPAKE2+, Privacy Pass (RFC 9578), and CLI tool (dgst, genpkey, x509, verify, enc, pkey, crl, req, s-client, s-server, list, rand, pkeyutl, speed, pkcs12, mac).

## Goals

- **Memory safety** — Leveraging Rust's ownership system to eliminate buffer overflows, use-after-free, and other memory bugs common in C cryptographic code
- **Type safety** — Strong typing for algorithm IDs, error handling (`Result<T, E>`), and protocol states
- **Secure by default** — Automatic secret zeroization on drop, constant-time operations via `subtle`, `#![forbid(unsafe_code)]` where possible
- **Modular** — Fine-grained feature flags for algorithm selection, minimizing binary size
- **Comprehensive** — Full coverage of classical, national (GM/T), and post-quantum cryptographic algorithms

## Workspace Structure

```
openhitls-rs/
├── crates/
│   ├── hitls-types/     # Shared types: algorithm IDs, error types, constants
│   ├── hitls-utils/     # Utilities: ASN.1, Base64, PEM, OID (35 tests)
│   ├── hitls-bignum/    # Big number: Montgomery, Miller-Rabin, GCD (46 tests)
│   ├── hitls-crypto/    # Crypto: AES, SM4, ChaCha20, GCM, SHA-2, SHA-3, HMAC, CMAC, RSA, ECC (P-224/P-256/P-384/P-521/Brainpool), ECDSA, ECDH, Ed25519, X25519, Ed448, X448, Curve448, DH, DSA, SM2, SM9, DRBG (HMAC/CTR/Hash), Entropy (SP 800-90B health tests), ML-KEM, ML-DSA, SLH-DSA, XMSS, FrodoKEM, McEliece, HPKE, HybridKEM, Paillier, ElGamal, SM4-CCM (504 tests + 15 Wycheproof)
│   ├── hitls-tls/       # TLS 1.3/1.2/DTLS 1.2/TLCP/DTLCP, async I/O (tokio), custom extensions, NSS key logging, 47+ cipher suites, hybrid KEM (X25519MLKEM768), TLS 1.3 SM4-GCM/CCM (RFC 8998), Record Size Limit, Fallback SCSV, OCSP stapling, SCT (558 tests)
│   ├── hitls-pki/       # X.509 (parse, verify, chain, CRL, OCSP, CSR generation, certificate generation, to_text), PKCS#8 (RFC 5958), PKCS#12 (RFC 7292), CMS SignedData (Ed25519/Ed448) + EnvelopedData (RFC 5652) (126 tests, 1 ignored)
│   ├── hitls-auth/      # HOTP/TOTP (RFC 4226/6238), SPAKE2+ (RFC 9382), Privacy Pass (RFC 9578, RSA blind sigs) (24 tests)
│   └── hitls-cli/       # Command-line tool (dgst, genpkey, x509, verify, enc, pkey, crl, req, s-client, s-server, list, rand, pkeyutl, speed, pkcs12, mac)
├── tests/interop/       # Integration tests: 23 cross-crate tests including TCP loopback (3 ignored)
├── tests/vectors/       # Standard test vectors (NIST CAVP, Wycheproof JSON, GM/T)
├── fuzz/                # Fuzz targets (cargo-fuzz, 10 libfuzzer targets)
└── benches/             # Performance benchmarks
```

## Supported Algorithms

### Hash

| Algorithm | Feature Flag | Status | Tests |
|-----------|-------------|--------|-------|
| SHA-256 / SHA-224 | `sha2` (default) | **Done** | FIPS 180-4 / RFC 6234 |
| SHA-512 / SHA-384 | `sha2` (default) | **Done** | FIPS 180-4 / RFC 6234 |
| SM3 | `sm3` | **Done** | GB/T 32905-2012 |
| SHA-1 | `sha1` | **Done** | RFC 3174 |
| MD5 | `md5` | **Done** | RFC 1321 |
| SHA3-224/256/384/512 | `sha3` | **Done** | FIPS 202 |
| SHAKE128/256 | `sha3` | **Done** | FIPS 202 |

### Symmetric Ciphers & Modes

| Algorithm | Feature Flag | Status | Tests |
|-----------|-------------|--------|-------|
| AES-128 / AES-192 / AES-256 | `aes` (default) | **Done** | FIPS 197 |
| SM4 | `sm4` | **Done** | GB/T 32907-2016 |
| ECB mode | `modes` | **Done** | NIST SP 800-38A |
| CBC mode (PKCS#7) | `modes` | **Done** | NIST SP 800-38A |
| CTR mode | `modes` | **Done** | NIST SP 800-38A |
| GCM mode (AEAD) | `modes` | **Done** | NIST SP 800-38D |
| ChaCha20-Poly1305 (AEAD) | `chacha20` | **Done** | RFC 8439 |
| CFB mode | `modes` | **Done** | NIST SP 800-38A |
| OFB mode | `modes` | **Done** | NIST SP 800-38A |
| CCM mode (AEAD) | `modes` | **Done** | NIST SP 800-38C |
| XTS mode | `modes` | **Done** | NIST SP 800-38E |
| AES Key Wrap | `modes` | **Done** | RFC 3394 |

### MAC

| Algorithm | Feature Flag | Status | Tests |
|-----------|-------------|--------|-------|
| HMAC-SHA-256 | `hmac` (default) | **Done** | RFC 4231 |
| CMAC-AES | `cmac` | **Done** | RFC 4493 / NIST SP 800-38B |
| GMAC | `gmac` | **Done** | NIST SP 800-38D |
| SipHash-2-4 | `siphash` | **Done** | Aumasson & Bernstein |

### Asymmetric / Public Key

| Algorithm | Feature Flag | Status |
|-----------|-------------|--------|
| RSA (PKCS#1 v1.5, PSS, OAEP) | `rsa` (default) | **Done** |
| ECDSA (P-224, P-256, P-384, P-521, Brainpool) | `ecdsa` (default) | **Done** |
| ECDH (P-224, P-256, P-384, P-521, Brainpool) | `ecdh` | **Done** |
| ECC core (P-224, P-256, P-384, P-521, Brainpool P-256r1/P-384r1/P-512r1) | `ecc` | **Done** |
| Ed25519 (RFC 8032) | `ed25519` | **Done** |
| X25519 (RFC 7748) | `x25519` | **Done** |
| Ed448 (RFC 8032) | `ed448` | **Done** |
| X448 (RFC 7748) | `x448` | **Done** |
| DH (ffdhe2048, ffdhe3072) | `dh` | **Done** |
| DSA (FIPS 186-4) | `dsa` | **Done** |
| SM2 (Sign, Verify, Encrypt, Decrypt) | `sm2` | **Done** |
| SM9 (IBE: Sign/Verify/Encrypt/Decrypt) | `sm9` | **Done** |
| Paillier (Homomorphic) | `paillier` | **Done** |
| ElGamal | `elgamal` | **Done** |

### Post-Quantum

| Algorithm | Feature Flag | Status |
|-----------|-------------|--------|
| ML-KEM (Kyber) 512/768/1024 | `mlkem` | **Done** |
| ML-DSA (Dilithium) 44/65/87 | `mldsa` | **Done** |
| SLH-DSA (SPHINCS+) FIPS 205 | `slh-dsa` | **Done** |
| XMSS (RFC 8391) | `xmss` | **Done** |
| FrodoKEM (640/976/1344 × SHAKE/AES) | `frodokem` | **Done** |
| Classic McEliece (6688128/6960119/8192128) | `mceliece` | **Done** |
| Hybrid KEM (X25519+ML-KEM-768) | `hybridkem` | **Done** |

### KDF & DRBG

| Algorithm | Feature Flag | Status | Tests |
|-----------|-------------|--------|-------|
| HKDF | `hkdf` | **Done** | RFC 5869 |
| PBKDF2 | `pbkdf2` | **Done** | Verified with OpenSSL |
| scrypt | `scrypt` | **Done** | RFC 7914 |
| HMAC-DRBG (SP 800-90A) | `drbg` | **Done** | NIST SP 800-90A |
| CTR-DRBG (SP 800-90A) | `drbg` | **Done** | NIST SP 800-90A §10.2 |
| Hash-DRBG (SP 800-90A) | `drbg` | **Done** | NIST SP 800-90A §10.1.1 |
| HPKE (RFC 9180) | `hpke` | **Done** | RFC 9180 A.1 |

### Big Number Arithmetic (`hitls-bignum`)

| Component | Status | Tests |
|-----------|--------|-------|
| Basic ops (add, sub, mul, div, mod) | **Done** | Knuth Algorithm D |
| Montgomery multiplication & exponentiation | **Done** | Fermat's theorem, RSA example |
| Miller-Rabin primality test | **Done** | Small + large primes |
| GCD & modular inverse | **Done** | Extended Euclidean |
| Constant-time operations | **Done** | ct_eq, ct_select |
| Cryptographic random generation | **Done** | random_bits, random_range |
| Padded big-endian export (`to_bytes_be_padded`) | **Done** | RSA output formatting |

### Protocols

| Protocol | Crate | Status |
|----------|-------|--------|
| TLS 1.3 | `hitls-tls` | **Done** — Key Schedule + Record + Client & Server Handshake + HRR + KeyUpdate + PSK/0-RTT + Certificate Compression + X25519MLKEM768 Hybrid KEM + SM4-GCM/CCM (RFC 8998) |
| TLS 1.2 PRF | `hitls-tls` | **Done** — PRF (RFC 5246 section 5) |
| TLS 1.2 | `hitls-tls` | **Done** — 47 cipher suites (ECDHE/RSA/DHE_RSA/PSK/DHE_PSK/RSA_PSK/ECDHE_PSK key exchange, GCM/CBC/ChaCha20, Bleichenbacher protection), ALPN, SNI, session resumption, session ticket (RFC 5077), EMS (RFC 7627), ETM (RFC 7366), renegotiation indication (RFC 5746), mTLS, PSK (RFC 4279/5489) |
| DTLS 1.2 | `hitls-tls` | **Done** — Record layer + Handshake + Fragmentation/Reassembly + Cookie Exchange + Anti-Replay + Retransmission |
| TLCP (GM/T 0024) | `hitls-tls` | **Done** — 4 cipher suites (ECDHE/ECC × SM4-CBC/GCM), double certificate, ECDHE + ECC key exchange |
| DTLCP (DTLS + TLCP) | `hitls-tls` | **Done** — DTLS 1.2 record layer + TLCP handshake/crypto (SM2/SM3/SM4), 4 cipher suites, cookie exchange, anti-replay |
| Custom Extensions | `hitls-tls` | **Done** — Callback-based framework for user-defined TLS extensions (CH, SH, EE contexts) |
| Key Logging | `hitls-tls` | **Done** — NSS key log format (SSLKEYLOGFILE) callback for TLS 1.3/1.2/DTLS 1.2/TLCP/DTLCP |
| Record Size Limit | `hitls-tls` | **Done** — RFC 8449: TLS 1.3 (CH + EncryptedExtensions, -1 for content type) and TLS 1.2 (CH + SH echo), 64..16385 range validation |
| Fallback SCSV | `hitls-tls` | **Done** — RFC 7507: Client appends 0x5600, server detects and rejects with inappropriate_fallback alert |
| OCSP Stapling | `hitls-tls` | **Done** — RFC 6066 section 8: TLS 1.3 full (status_request in CH, OCSP response in Certificate entry), TLS 1.2 CH offering |
| SCT | `hitls-tls` | **Done** — RFC 6962: TLS 1.3 full (signed_certificate_timestamp in CH, SCT list in Certificate entry), TLS 1.2 CH offering |
| X.509 Certificates | `hitls-pki` | **Done** (parse + verify + chain + CSR generation + certificate generation) |
| CRL | `hitls-pki` | **Done** (parse + validate + revocation checking) |
| PKCS#8 (RFC 5958) | `hitls-pki` | **Done** (parse + encode) |
| PKCS#12 (RFC 7292) | `hitls-pki` | **Done** (parse + create) |
| CMS SignedData (RFC 5652) | `hitls-pki` | **Done** (parse + verify + sign) |
| CMS EnvelopedData (RFC 5652) | `hitls-pki` | **Done** (RSA key transport + AES key wrap) |
| HOTP (RFC 4226) | `hitls-auth` | **Done** |
| TOTP (RFC 6238) | `hitls-auth` | **Done** |
| SPAKE2+ (RFC 9382, P-256) | `hitls-auth` | **Done** |
| Privacy Pass (RFC 9578 Type 2) | `hitls-auth` | **Done** (RSA blind signatures) |

## Building

```bash
# Build with default features
cargo build

# Build with all features
cargo build --all-features

# Build with specific algorithms only
cargo build -p hitls-crypto --no-default-features --features "aes,sha2,gcm"
```

## Testing

```bash
# Run all tests (1397 tests, 37 ignored)
cargo test --workspace --all-features

# Run tests for a specific crate
cargo test -p hitls-crypto --all-features   # 504 tests (28 ignored) + 15 Wycheproof
cargo test -p hitls-tls --all-features      # 558 tests
cargo test -p hitls-pki --all-features      # 126 tests (1 ignored)
cargo test -p hitls-bignum                  # 46 tests
cargo test -p hitls-utils                   # 35 tests
cargo test -p hitls-auth --all-features     # 24 tests
cargo test -p hitls-cli --all-features      # 37 tests (5 ignored)
cargo test -p hitls-integration-tests       # 26 tests (3 ignored)

# Lint
RUSTFLAGS="-D warnings" cargo clippy --workspace --all-features --all-targets

# Format check
cargo fmt --all -- --check
```

## Feature Flags

Select only the algorithms you need to minimize binary size:

```toml
[dependencies]
hitls-crypto = { version = "0.1", default-features = false, features = ["aes", "sha2", "gcm"] }
```

Convenience feature groups:

| Feature | Includes |
|---------|----------|
| `default` | `aes`, `sha2`, `rsa`, `ecdsa`, `hmac` |
| `pqc` | `mlkem`, `mldsa` |
| `sm2` | `ecc`, `sm3`, `hitls-utils` |
| `tlcp` | `sm2`, `sm3`, `sm4` (via `hitls-tls`) |

## Design Principles

- **Trait-based providers** — All algorithms implement common traits (`Digest`, `Aead`, `Signer`, `Verifier`, etc.) for static dispatch with zero-cost abstraction
- **Zeroize on drop** — All secret material (keys, intermediate states) is automatically zeroed when dropped
- **Constant-time operations** — Cryptographic comparisons and branching use the `subtle` crate to prevent timing side-channels
- **Strong error types** — `CryptoError`, `TlsError`, `PkiError` with `thiserror` for clear, actionable error messages
- **Builder pattern** — TLS configuration uses builder pattern for ergonomic and safe construction

## Roadmap

### Completed (Phase 0–50)

All 48+ cryptographic algorithm modules including Ed448/X448/Curve448, X.509 (parse/verify/chain/CRL/OCSP/CSR/cert generation/to_text), PKCS#8, PKCS#12, CMS SignedData (Ed25519/Ed448) + EnvelopedData, TLS 1.3 (full spec: PSK/0-RTT/KeyUpdate/HRR/post-HS auth/cert compression/X25519MLKEM768 hybrid KEM/SM4-GCM/CCM (RFC 8998)), TLS 1.2 (47 suites: ECDHE/RSA/DHE_RSA/PSK/DHE_PSK/RSA_PSK/ECDHE_PSK key exchange, GCM/CBC/ChaCha20, Bleichenbacher protection, ALPN, SNI, session resumption, session ticket (RFC 5077), EMS (RFC 7627), ETM (RFC 7366), renegotiation indication (RFC 5746), mTLS, PSK (RFC 4279/5489), OCSP stapling CertificateStatus), DTLS 1.2 (RFC 6347), TLCP (GM/T 0024, 4 suites), DTLCP (DTLS+TLCP, 4 suites), custom extensions framework, NSS key logging, async I/O (tokio), hardware AES (AES-NI + ARMv8 NEON), TLS extensions (Record Size Limit RFC 8449, Fallback SCSV RFC 7507, OCSP stapling, SCT RFC 6962), TLS 1.2 PRF, auth protocols (HOTP/TOTP/SPAKE2+/Privacy Pass RFC 9578), PQC (ML-KEM/ML-DSA/SLH-DSA/XMSS/FrodoKEM/McEliece), ECC curves (P-224/P-521/Brainpool), DRBGs (HMAC/CTR/Hash), CLI tool (14 commands), TCP loopback integration tests, 5000+ Wycheproof edge-case vectors, 10 fuzz targets, and security audit. 1397 tests passing (37 ignored) across 10 crates.

### Completed Migration Phases (Phase 21–39)

The original C implementation ([openHiTLS](https://gitee.com/openhitls/openhitls)) contains ~460K lines covering 48 crypto modules, TLS protocol variants, and full PKI infrastructure. The Rust port covers ~98% of core features with all crypto algorithms, TLS 1.3/1.2 (ECDHE/RSA/DHE_RSA/PSK/DHE_PSK/RSA_PSK/ECDHE_PSK + post-quantum hybrid KEM + SM4-GCM/CCM), DTLS 1.2, TLCP, DTLCP, TLS extensions, CMS EnvelopedData, Privacy Pass, and 14 CLI commands fully implemented. Below are the detailed phase tables for completed work.

#### Phase 21: TLS 1.3 Completeness

| Feature | RFC | Status |
|---------|-----|--------|
| PSK / Session Tickets | RFC 8446 §4.6.1 | **Done** |
| HelloRetryRequest (HRR) | RFC 8446 §4.1.4 | **Done** |
| 0-RTT Early Data | RFC 8446 §4.2.10 | **Done** |
| Post-Handshake Client Auth | RFC 8446 §4.6.2 | **Done** |
| KeyUpdate | RFC 8446 §4.6.3 | **Done** |
| Certificate Compression | RFC 8879 | **Done** (zlib, feature-gated) |

#### Phase 22: ECC Curve Additions

| Curve | Standard | Status |
|-------|----------|--------|
| P-521 (secp521r1) | FIPS 186-4 | **Done** |
| Brainpool P-256r1 | RFC 5639 | **Done** |
| Brainpool P-384r1 | RFC 5639 | **Done** |
| Brainpool P-512r1 | RFC 5639 | **Done** |
| P-224 (secp224r1) | FIPS 186-4 | **Done** |

#### Phase 23: DRBG Variants & PKCS#8

| Component | Standard | Status |
|-----------|----------|--------|
| CTR-DRBG (AES-256) | NIST SP 800-90A §10.2 | **Done** |
| Hash-DRBG (SHA-256/384/512) | NIST SP 800-90A §10.1.1 | **Done** |
| PKCS#8 Key Parsing | RFC 5958 | **Done** (RSA, EC, Ed25519, X25519, DSA) |

#### Phase 24: CRL & OCSP

| Feature | Standard | Status |
|---------|----------|--------|
| CRL Parsing | RFC 5280 §5 | **Done** |
| CRL Validation | RFC 5280 §6.3 | **Done** |
| Revocation Checking | RFC 5280 | **Done** |
| OCSP (basic) | RFC 6960 | **Done** |

#### Phase 25: CSR Generation, Certificate Generation, TLS 1.2 PRF

| Feature | Standard | Status |
|---------|----------|--------|
| CSR Parsing (PKCS#10) | RFC 2986 | **Done** |
| CSR Generation (CertificateRequestBuilder) | RFC 2986 | **Done** |
| X.509 Certificate Generation (CertificateBuilder) | RFC 5280 | **Done** |
| Self-Signed Certificate Generation | RFC 5280 | **Done** |
| SigningKey Abstraction (RSA/ECDSA/Ed25519) | — | **Done** |
| TLS 1.2 PRF | RFC 5246 §5 | **Done** |
| CLI `req` Command | — | **Done** |

#### Phase 26: TLS 1.2

| Feature | Standard | Status |
|---------|----------|--------|
| TLS 1.2 Handshake | RFC 5246 | **Done** (47 cipher suites: ECDHE/RSA/DHE_RSA/PSK/DHE_PSK/RSA_PSK/ECDHE_PSK, GCM/CBC/ChaCha20) |
| TLS 1.2 Cipher Suites (50+) | RFC 5246 | **Done** (47 suites: 14 ECDHE + 6 RSA + 7 DHE_RSA + 20 PSK) |
| Session Resumption (ID-based) | RFC 5246 §7.4.1.2 | **Done** |
| Client Certificate Auth (mTLS) | RFC 5246 §7.4.4 | **Done** |
| Renegotiation Indication | RFC 5746 | **Done** (Phase 35) |
| TLS 1.2 Record Protocol | RFC 5246 §6 | **Done** (GCM with explicit nonce) |

#### Phase 27: DTLS 1.2

| Feature | Standard | Status |
|---------|----------|--------|
| DTLS 1.2 Record Layer (13-byte header, epoch, 48-bit seq) | RFC 6347 | **Done** |
| Epoch-Aware AEAD Encryption/Decryption | RFC 6347 §4.1 | **Done** |
| DTLS Handshake Header (12-byte, message_seq, fragmentation) | RFC 6347 §4.2.2 | **Done** |
| HelloVerifyRequest Cookie Exchange | RFC 6347 §4.2.1 | **Done** |
| Message Fragmentation/Reassembly (MTU-aware) | RFC 6347 §4.2.3 | **Done** |
| Anti-Replay Sliding Window (64-bit bitmap) | RFC 6347 §4.1.2.6 | **Done** |
| Retransmission Timers (exponential backoff) | RFC 6347 §4.2.4 | **Done** |
| DTLS Client Handshake State Machine | RFC 6347 | **Done** |
| DTLS Server Handshake State Machine | RFC 6347 | **Done** |
| DTLS Connection Types + In-Memory Transport | RFC 6347 | **Done** |

#### Phase 28: TLCP (GM/T 0024)

| Feature | Standard | Status |
|---------|----------|--------|
| TLCP Handshake (ECDHE + ECC key exchange) | GM/T 0024 / GB/T 38636-2020 | **Done** |
| 4 Cipher Suites (ECDHE_SM4_CBC_SM3, ECC_SM4_CBC_SM3, ECDHE_SM4_GCM_SM3, ECC_SM4_GCM_SM3) | GM/T 0024 | **Done** |
| Double Certificate (signing + encryption) | GM/T 0024 | **Done** |
| CBC MAC-then-encrypt (HMAC-SM3 + SM4-CBC) | GM/T 0024 | **Done** |
| GCM AEAD (SM4-GCM) | GM/T 0024 | **Done** |
| SM3-based PRF | GM/T 0024 | **Done** |

#### Phase 29: TLS 1.2 CBC + ChaCha20-Poly1305 + ALPN + SNI

| Feature | Standard | Status |
|---------|----------|--------|
| 8 ECDHE-CBC cipher suites (AES-128/256, SHA/SHA256/SHA384) | RFC 5246 | **Done** |
| 2 ECDHE-ChaCha20-Poly1305 cipher suites | RFC 7905 | **Done** |
| CBC MAC-then-encrypt record protection | RFC 5246 §6.2.3.1 | **Done** |
| Constant-time padding oracle mitigation | RFC 5246 | **Done** |
| ALPN extension (Application-Layer Protocol Negotiation) | RFC 7301 | **Done** |
| SNI server-side parsing (Server Name Indication) | RFC 6066 | **Done** |

#### Phase 30: TLS 1.2 Session Resumption + Client Certificate Auth (mTLS)

| Feature | Standard | Status |
|---------|----------|--------|
| CertificateRequest12 + CertificateVerify12 codec | RFC 5246 §7.4.4/§7.4.8 | **Done** |
| Server-side mTLS (CertificateRequest, verify client cert) | RFC 5246 | **Done** |
| Client-side mTLS (respond to CertReq, CertVerify) | RFC 5246 | **Done** |
| Session ID-based resumption (abbreviated handshake) | RFC 5246 §7.4.1.2 | **Done** |
| Server-side session caching (InMemorySessionCache) | RFC 5246 | **Done** |
| Client-side session resumption (cached session_id) | RFC 5246 | **Done** |
| Abbreviated handshake (1-RTT, server CCS+Finished first) | RFC 5246 | **Done** |

#### Phase 31: s_client CLI + Network I/O

| Feature | Description | Status |
|---------|-------------|--------|
| s_client CLI command | TLS client with --tls, --insecure, --http, --CAfile, --alpn, --quiet | **Done** |
| TLS 1.3 over TCP | TlsClientConnection over TcpStream | **Done** |
| TLS 1.2 over TCP | Tls12ClientConnection over TcpStream | **Done** |
| TCP connect timeout | 10-second connect + read/write timeout | **Done** |
| HTTP GET mode | --http flag sends GET / and prints response | **Done** |
| CA file loading | --CAfile loads PEM CA cert for verification | **Done** |

#### Phase 32: s_server CLI + Key Conversion

| Feature | Description | Status |
|---------|-------------|--------|
| s_server CLI command | TLS server with --tls, --port, --cert, --key, --quiet | **Done** |
| PKCS#8 → ServerPrivateKey | Convert RSA/ECDSA/Ed25519 keys for TLS server | **Done** |
| TLS 1.3 echo server | TlsServerConnection over TcpStream | **Done** |
| TLS 1.2 echo server | Tls12ServerConnection over TcpStream | **Done** |
| RsaPrivateKey byte getters | d_bytes(), p_bytes(), q_bytes() | **Done** |

#### Phase 33: TCP Loopback Integration Tests (TLS 1.3/1.2 over real TCP sockets)

| Feature | Description | Status |
|---------|-------------|--------|
| TLS 1.3 Ed25519 TCP loopback | Bidirectional exchange over real TcpStream | **Done** |
| TLS 1.2 ECDSA P-256 TCP loopback | ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 | **Done** |
| TLS 1.3 large payload (64 KB) | Multi-record chunked writes over TCP | **Done** |
| TLS 1.2 RSA TCP loopback | ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ignored — slow keygen) | **Done** |
| TLS 1.3 multi-message echo | 5 round trips over TCP | **Done** |

#### Phase 34: TLS 1.2 Session Ticket (RFC 5077)

| Feature | Standard | Status |
|---------|----------|--------|
| SessionTicket extension (type 35, ClientHello + ServerHello codec) | RFC 5077 §3.2 | **Done** |
| Ticket encryption (AES-256-GCM, session state serialization) | RFC 5077 §4 | **Done** |
| NewSessionTicket message (HandshakeType 4, lifetime_hint + ticket) | RFC 5077 §3.3 | **Done** |
| Server ticket issuance + ticket-based resumption | RFC 5077 §3.1 | **Done** |
| Client ticket sending + NewSessionTicket processing | RFC 5077 §3.4 | **Done** |
| Connection-level ticket flow + take_session() | RFC 5077 | **Done** |

#### Phase 35: TLS 1.2 Extended Master Secret + Encrypt-Then-MAC + Renegotiation Indication

| Feature | Standard | Status |
|---------|----------|--------|
| Extended Master Secret (EMS) | RFC 7627 | **Done** |
| Encrypt-Then-MAC (ETM) | RFC 7366 | **Done** |
| Secure Renegotiation Indication | RFC 5746 | **Done** |
| Config flags (enable_extended_master_secret, enable_encrypt_then_mac) | — | **Done** |
| TCP loopback EMS+ETM over CBC integration test | — | **Done** |

#### Phase 36: TLS 1.2 RSA + DHE Key Exchange (13 New Cipher Suites)

| Feature | Standard | Status |
|---------|----------|--------|
| RSA static key exchange (no ServerKeyExchange) | RFC 5246 | **Done** |
| DHE_RSA key exchange (DH ServerKeyExchange) | RFC 5246 | **Done** |
| Bleichenbacher protection for RSA key exchange | — | **Done** |
| 6 RSA suites (AES-128/256 GCM + CBC) | RFC 5246 | **Done** |
| 7 DHE_RSA suites (AES-128/256 GCM + CBC + ChaCha20) | RFC 5246/7905 | **Done** |
| ECDHE_RSA suites tested with real RSA certificates | RFC 5246 | **Done** |

#### Phase 37: TLS 1.2 PSK Cipher Suites (RFC 4279/5489)

| Feature | Standard | Status |
|---------|----------|--------|
| PSK key exchange (5 suites: AES-128/256-GCM, AES-128/256-CBC-SHA, ChaCha20-Poly1305) | RFC 4279 | **Done** |
| DHE_PSK key exchange (5 suites: same AEAD/CBC variants) | RFC 4279 | **Done** |
| RSA_PSK key exchange (5 suites: same AEAD/CBC variants, server RSA cert) | RFC 4279 | **Done** |
| ECDHE_PSK key exchange (5 suites: same AEAD/CBC variants) | RFC 5489 | **Done** |
| PSK configuration (psk, psk_identity, psk_identity_hint, psk_server_callback) | RFC 4279 | **Done** |
| `build_psk_pms()` helper (RFC 4279 PMS format) | RFC 4279 | **Done** |
| `KeyExchangeAlg::Psk`, `DhePsk`, `RsaPsk`, `EcdhePsk` variants | — | **Done** |
| Conditional Certificate/CertificateRequest for PSK modes | RFC 4279 | **Done** |

#### Phase 38: TLS 1.3 Post-Quantum Hybrid KEM (X25519MLKEM768)

| Feature | Standard | Status |
|---------|----------|--------|
| X25519MLKEM768 key exchange (NamedGroup 0x6399) | draft-ietf-tls-ecdhe-mlkem | **Done** |
| Wire format: ML-KEM first, X25519 second | draft-ietf-tls-ecdhe-mlkem | **Done** |
| Client key_share: mlkem_ek(1184) + x25519_pk(32) = 1216 bytes | — | **Done** |
| Server key_share: mlkem_ct(1088) + x25519_eph_pk(32) = 1120 bytes | — | **Done** |
| Shared secret: mlkem_ss(32) + x25519_ss(32) = 64 bytes (raw concat) | — | **Done** |
| Server-side KEM encapsulation (not DH) for hybrid groups | — | **Done** |
| HRR fallback: client offers hybrid+X25519, server can HRR to X25519 | RFC 8446 §4.1.4 | **Done** |
| `MlKem768::from_encapsulation_key()` constructor | FIPS 203 | **Done** |
| `NamedGroup::is_kem()` helper | — | **Done** |
| E2E hybrid handshake + HRR fallback tests | — | **Done** |

#### Phase 39: TLS Extensions Completeness (Record Size Limit, Fallback SCSV, OCSP Stapling, SCT)

| Feature | Standard | Status |
|---------|----------|--------|
| Record Size Limit (TLS 1.3) | RFC 8449 | **Done** — CH + EncryptedExtensions, -1 for content type, 64..16385 range validation |
| Record Size Limit (TLS 1.2) | RFC 8449 | **Done** — CH + SH echo, no content type adjustment |
| Fallback SCSV | RFC 7507 | **Done** — Client appends 0x5600, server detects + inappropriate_fallback alert |
| OCSP Stapling (TLS 1.3) | RFC 6066 section 8 | **Done** — status_request in CH, OCSP response in leaf Certificate entry extensions |
| OCSP Stapling (TLS 1.2) | RFC 6066 section 8 | **Done** — CH offering + CertificateStatus message (type 22) |
| SCT (TLS 1.3) | RFC 6962 | **Done** — signed_certificate_timestamp in CH, SCT list in leaf Certificate entry extensions |
| SCT (TLS 1.2) | RFC 6962 | **Done** — CH offering |
| Record layer integration | RFC 8449 | **Done** — RSL applied via existing max_fragment_size |

### Completed Migration Phases (Phase 40–44)

Based on systematic gap analysis between the C implementation (~460K lines) and the Rust port, the following phases have been completed.

#### Phase 40: Async I/O + Performance Optimization — DONE

| Feature | Platform | Status |
|---------|----------|--------|
| Async TLS (tokio) | All | **Done** |
| AES-NI acceleration | x86-64 | **Done** |
| ARM NEON acceleration | AArch64 | **Done** |
| Criterion benchmarks | All | **Done** |

#### Phase 41: DTLCP + Custom Extensions + Key Logging — DONE

| Feature | Standard | Status |
|---------|----------|--------|
| DTLCP (DTLS over TLCP) | GM/T 0024 | **Done** — 4 cipher suites, cookie exchange, anti-replay |
| Custom Extensions Framework | — | **Done** — Callback-based, CH/SH/EE contexts |
| Key Log callback (SSLKEYLOGFILE) | — | **Done** — NSS format, TLS 1.3/1.2/DTLS/TLCP/DTLCP |

#### Phase 42: Testing & Quality Assurance — DONE

| Feature | Description | Status |
|---------|-------------|--------|
| Wycheproof test vectors | 15 test functions, 5000+ edge-case vectors (AES-GCM, ChaCha20, ECDSA P-256/P-384/P-521, ECDH, Ed25519, X25519, RSA PKCS#1v1.5, RSA-PSS, HKDF, HMAC, AES-CCM, AES-CBC) | **Done** |
| Fuzz targets | 10 libfuzzer targets (ASN.1, Base64, PEM, X.509, CRL, PKCS#8, PKCS#12, CMS, TLS record, TLS handshake) | **Done** |
| Security audit | Constant-time audit (fixed Ed25519 verify + Fe25519 PartialEq), zeroize audit (fixed Paillier + ElGamal), unsafe code review (3 files, all correct, added SAFETY comments) | **Done** |
| SECURITY.md | Security policy, algorithm status, known limitations, disclosure process | **Done** |
| CI enhancements | Fuzz build check (nightly) + Miri + Benchmark check | **Done** |

#### Phase 43: Feature Completeness — DONE

| Feature | Description | Status |
|---------|-------------|--------|
| PKI Text Output | `to_text()` for Certificate, CRL, CSR (OpenSSL-compatible format) | **Done** |
| TLS 1.3 SM4-GCM/CCM | `TLS_SM4_GCM_SM3` (0x00C6), `TLS_SM4_CCM_SM3` (0x00C7), RFC 8998 | **Done** |
| SM4-CCM crypto | BlockCipher trait generalization for SM4+AES in CCM mode | **Done** |
| CMS EnvelopedData | RFC 5652 §6: RSA OAEP key transport + AES Key Wrap | **Done** |
| Privacy Pass | RFC 9578 Type 2: RSA blind signatures (Issuer, Client, verify_token) | **Done** |
| CLI: list, rand, pkeyutl, speed | 4 new subcommands (14 total CLI commands) | **Done** |

### Completed Migration Phases (Phase 45)

#### Phase 45: Complete DH Groups + TLS FFDHE Expansion

All 13 DH groups from RFC 2409, RFC 3526, and RFC 7919 now fully implemented with prime constants, TLS FFDHE6144/8192 negotiation, and key exchange tests.

| Feature | Standard | Status | Notes |
|---------|----------|--------|-------|
| RFC 2409 DH groups (768-bit, 1024-bit) | RFC 2409 §6 | **Done** | Legacy MODP Group 1 & 2 |
| RFC 3526 DH groups (1536/2048/3072/4096/6144/8192-bit) | RFC 3526 §2-7 | **Done** | Classic MODP groups |
| RFC 7919 FFDHE groups (4096/6144/8192-bit) | RFC 7919 §3 | **Done** | Complete FFDHE family (all 5 groups) |
| TLS NamedGroup FFDHE6144/8192 | RFC 7919 | **Done** | `NamedGroup::FFDHE6144` (0x0103) / `FFDHE8192` (0x0104) |
| Expand TLS DHE negotiation | RFC 7919 | **Done** | `is_ffdhe_group()` + `named_group_to_dh_param_id()` support all 5 FFDHE groups |
| Tests for all 13 DH groups | — | **Done** | Prime size validation + key exchange roundtrip (6 ignored for slow large groups) |

### Completed Migration Phase 46

#### Phase 46: FIPS/CMVP Compliance Framework — DONE

**Priority: High** — Critical for deployment in regulated environments (financial, government, healthcare). The C implementation provides a full CMVP self-test infrastructure (`crypt_eal_cmvp.h`).

| Feature | Standard | Status | Notes |
|---------|----------|--------|-------|
| FIPS state machine | FIPS 140-3 | **Done** | `FipsModule`: PreOperational → SelfTesting → Operational → Error |
| KAT: SHA-256 | FIPS 140-3 §10.3.3 | **Done** | NIST CAVP SHAVS vector |
| KAT: HMAC-SHA256 | FIPS 140-3 §10.3.3 | **Done** | RFC 4231 Test Case 1 |
| KAT: AES-128-GCM | FIPS 140-3 §10.3.3 | **Done** | NIST SP 800-38D vector (encrypt + decrypt) |
| KAT: HMAC-DRBG | FIPS 140-3 §10.3.3 | **Done** | NIST SP 800-90A vector (instantiate/reseed/generate) |
| KAT: HKDF-SHA256 | FIPS 140-3 §10.3.3 | **Done** | RFC 5869 Appendix A Test Case 1 |
| KAT: ECDSA P-256 | FIPS 140-3 §10.3.3 | **Done** | Sign-verify roundtrip with generated key |
| Integrity check | FIPS 140-3 §10.3.1 | **Done** | HMAC-SHA256 library file integrity with constant-time comparison |
| PCT: ECDSA P-256 | FIPS 140-3 §10.3.5 | **Done** | Generate → sign → verify roundtrip |
| PCT: Ed25519 | FIPS 140-3 §10.3.5 | **Done** | Generate → sign → verify roundtrip |
| PCT: RSA-2048 PSS | FIPS 140-3 §10.3.5 | **Done** | Generate → sign(PSS) → verify roundtrip |
| CMVP error types | — | **Done** | `CmvpError` enum: IntegrityError, KatFailure, RandomnessError, PairwiseTestError, InvalidState, ParamCheckError |
| Feature gate (`fips`) | — | **Done** | All CMVP code gated with `#[cfg(feature = "fips")]`, pulls in required algorithm features |

**Scope**: `hitls-crypto/src/fips/` (mod.rs, kat.rs, pct.rs, integrity.rs), `hitls-types/src/error.rs`

### Completed Migration Phase 47

#### Phase 47: CLI Enhancements + CMS DigestedData — DONE

**Priority: Medium** — Practical tool completeness for PKCS#12 operations and CMS coverage.

| Feature | Standard | Status | Notes |
|---------|----------|--------|-------|
| CLI `pkcs12` subcommand | RFC 7292 | **Done** | Parse/create P12, extract cert/key (--info/--nokeys/--nocerts/--export) |
| CLI `mac` subcommand | — | **Done** | HMAC (SHA-1/256/384/512/SM3) + CMAC (AES-128/256), hex key input |
| CMS DigestedData | RFC 5652 §5 | **Done** | Parse + create + verify; SHA-256/384/512; 6 tests |

**Scope**: `hitls-cli/src/pkcs12.rs`, `hitls-cli/src/mac.rs`, `hitls-pki/src/cms/mod.rs`

### Completed Migration Phase 48

#### Phase 48: Entropy Health Testing (NIST SP 800-90B) — DONE

**Priority: Medium** — Security hardening for DRBG entropy quality validation and FIPS 140-3 compliance.

| Feature | Standard | Status | Notes |
|---------|----------|--------|-------|
| Repetition Count Test (RCT) | NIST SP 800-90B §4.4.1 | **Done** | Detects stuck noise sources |
| Adaptive Proportion Test (APT) | NIST SP 800-90B §4.4.2 | **Done** | Detects biased noise sources |
| Entropy Pool | — | **Done** | Circular buffer with secure zeroization |
| Hash Conditioning Function | NIST SP 800-90B §3.1.5 | **Done** | SHA-256 derivation function |
| Noise Source Trait | — | **Done** | Pluggable `NoiseSource` trait + system source |
| DRBG Integration | — | **Done** | `from_system_entropy()` uses health-tested entropy |
| FIPS KAT | FIPS 140-3 | **Done** | Entropy health test in FIPS self-test suite |

**Scope**: `hitls-crypto/src/entropy/` (mod.rs, health.rs, pool.rs, conditioning.rs), `hitls-crypto/src/drbg/`, `hitls-crypto/src/fips/kat.rs`

### Completed Migration Phase 49

#### Phase 49: Ed448 / X448 / Curve448 — DONE

**Priority: Medium** — Completes the RFC 8032/7748 Curve448 family alongside existing Curve25519 primitives. Enables Ed448 signatures and X448 key exchange in TLS.

| Feature | Standard | Status | Notes |
|---------|----------|--------|-------|
| Fe448 field arithmetic | GF(2^448-2^224-1) | **Done** | 16x28-bit limbs, Goldilocks reduction, constant-time |
| GeExtended448 Edwards point ops | Edwards a=1, d=-39081 | **Done** | Extended coordinates, scalar mul, basepoint |
| Ed448 sign/verify | RFC 8032 §5.2 | **Done** | SHAKE256 + dom4 prefix, context support, Ed448ph |
| X448 key exchange | RFC 7748 §5 | **Done** | Montgomery ladder, clamping, RFC test vectors |
| TLS integration | RFC 8446 | **Done** | SignatureScheme::ED448 (0x0808), X448 key exchange, ServerPrivateKey::Ed448 |
| PkeyAlgId::Ed448/X448 | — | **Done** | Algorithm ID enum variants |

**Scope**: `hitls-crypto/src/curve448/` (mod.rs, field.rs, edwards.rs), `hitls-crypto/src/ed448/mod.rs`, `hitls-crypto/src/x448/mod.rs`, `hitls-tls/` (key_exchange, signing, verify, config)

### Completed Migration Phase 50

#### Phase 50: Test Coverage + CMS Ed25519/Ed448 + enc CLI + TLS 1.2 OCSP/SCT — DONE

**Priority: P1** — Closes test coverage gaps, CMS EdDSA stub, enc CLI limitation, and TLS 1.2 OCSP/SCT implementation.

| Feature | Description | Status | Notes |
|---------|-------------|--------|-------|
| Alert module tests | 8 tests for AlertLevel/AlertDescription enums, from_u8 conversion | **Done** | `alert/mod.rs` |
| Session module tests | 21 tests for InMemorySessionCache, encode/decode, ticket encrypt/decrypt | **Done** | `session/mod.rs` |
| Record module tests | 23 tests for RecordLayer state, parse/serialize, seal/open, content type hiding | **Done** | `record/mod.rs` |
| CMS Ed25519/Ed448 | Verify + sign with Ed25519/Ed448 in CMS SignedData | **Done** | Replaced "not yet supported" stubs |
| enc CLI expansion | 4 ciphers: aes-256-gcm, aes-128-gcm, chacha20-poly1305, sm4-gcm | **Done** | `--cipher` flag |
| TLS 1.2 CertificateStatus | RFC 6066 §8: CertificateStatus (type 22) after Certificate | **Done** | Server sends when client requests + config has staple |
| TLS 1.2 OCSP client | Client parses CertificateStatus between Certificate and SKE | **Done** | Optional message handling |

**Scope**: `hitls-tls/src/alert/mod.rs`, `hitls-tls/src/session/mod.rs`, `hitls-tls/src/record/mod.rs`, `hitls-pki/src/cms/mod.rs`, `hitls-cli/src/enc.rs`, `hitls-tls/src/handshake/codec12.rs`, `hitls-tls/src/handshake/server12.rs`, `hitls-tls/src/connection12.rs`

#### Other Identified Gaps (Low Priority / Deferred)

| Category | Item | Priority | Notes |
|----------|------|----------|-------|
| Crypto | SM4 CTR-DRBG variant | Low | CTR-DRBG currently supports AES only |
| Crypto | eFrodoKEM variants | Low | Ephemeral FrodoKEM optimization |
| Crypto | CBC-MAC-SM4 (standalone) | Low | Available within CMAC, not standalone |
| Crypto | Multi-buffer SHA-256 | Low | Performance optimization, not a functional gap |
| Architecture | EAL Provider Framework | Low | Rust trait dispatch is more idiomatic than C plugin model |
| CLI | genrsa, rsa, prime, keymgmt, provider, sm | Low | Functionality covered by existing commands (genpkey, pkey, etc.) |

### Coverage Summary (vs. C Implementation)

| Component | C (lines) | Rust (lines) | Feature Coverage | Remaining Gaps |
|-----------|-----------|--------------|------------------|----------------|
| Crypto Algorithms | ~132K | ~26K | **100%** (all 48 modules + SM4-CCM + hardware AES + all 13 DH groups + FIPS/CMVP + entropy health testing + Ed448/X448/Curve448) | — |
| TLS Protocol | ~52K | ~14K | **100%** (TLS 1.3 + 1.2 + DTLS 1.2 + TLCP + DTLCP + X25519MLKEM768 + SM4-GCM/CCM + RSL/SCSV/OCSP/SCT + async I/O + key logging + custom extensions + all 5 FFDHE groups) | — |
| PKI / X.509 | ~17K | ~4K | **100%** (parse/verify/chain/CRL/OCSP/CSR/cert gen/to_text/PKCS#8/PKCS#12/CMS SignedData+EnvelopedData+EncryptedData+DigestedData) | — |
| Base Support Layer | ~12K | ~2K | **95%** (ASN.1/Base64/PEM/OID/errors) | — |
| CLI Tools | ~8K | ~2.2K | **100%** (dgst/genpkey/x509/verify/enc/pkey/crl/req/s-client/s-server/list/rand/pkeyutl/speed/pkcs12/mac) | — |
| FIPS/CMVP | ~5K | ~0.6K | **90%** (state machine, 7 KATs incl. entropy, 3 PCTs, integrity check, feature-gated) | Conditional algorithm disabling |
| Test Infrastructure | ~20K | ~3.5K | **95%** (1397 tests + 5000+ Wycheproof vectors + 10 fuzz targets + security audit) | SDV compliance tests |
| **Total** | **~460K** | **~52K** | **~99%** (production-ready for modern TLS deployments) | Low-priority items only |

## Minimum Supported Rust Version

**MSRV: 1.75**

## License

Licensed under the [Mulan Permissive Software License, Version 2](http://license.coscl.org.cn/MulanPSL2).

## Acknowledgments

This project is a Rust rewrite of [openHiTLS](https://gitee.com/openhitls/openhitls), an open-source cryptographic and TLS library originally written in C.
