# openHiTLS-rs

A production-grade cryptographic and TLS library written in pure Rust, rewritten from [openHiTLS](https://gitee.com/openhitls/openhitls) (C implementation).

> **Status: Phase 32 Complete — s_server CLI + Key Conversion**
>
> 842 tests passing (20 auth + 46 bignum + 330 crypto + 98 pki + 291 tls + 35 utils + 8 cli + 14 integration; 24 ignored). Full coverage: hash (SHA-2, SHA-3/SHAKE, SM3, SHA-1, MD5), HMAC/CMAC/GMAC/SipHash, symmetric (AES, SM4, ChaCha20), modes (ECB, CBC, CTR, GCM, CFB, OFB, CCM, XTS, Key Wrap), ChaCha20-Poly1305, KDFs (HKDF, PBKDF2, scrypt), DRBGs (HMAC-DRBG, CTR-DRBG, Hash-DRBG), RSA (PKCS#1v1.5, OAEP, PSS), ECC (P-224, P-256, P-384, P-521, Brainpool P-256r1/P-384r1/P-512r1), ECDSA, ECDH, Ed25519, X25519, DH, DSA, SM2, SM9 (IBE with BN256 pairing), PQC (ML-KEM, ML-DSA, SLH-DSA, XMSS, FrodoKEM, Classic McEliece), HPKE, HybridKEM, Paillier, ElGamal, X.509 (parse/verify/chain/CSR generation/certificate generation), PKCS#8 (parse/encode), PKCS#12, CMS SignedData, TLS 1.3 (key schedule + record + client/server handshake + PSK/session tickets + 0-RTT early data + post-handshake client auth + certificate compression), TLS 1.2 handshake (14 cipher suites: ECDHE-GCM/CBC/ChaCha20, ALPN, SNI, session resumption, mTLS), DTLS 1.2 (record layer + handshake + fragmentation + retransmission + cookie exchange + anti-replay), TLCP (GM/T 0024, 4 cipher suites, double certificate, ECDHE + ECC key exchange), TLS 1.2 PRF, HOTP/TOTP, SPAKE2+, and CLI tool (s-client + s-server).

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
│   ├── hitls-crypto/    # Crypto: AES, SM4, ChaCha20, GCM, SHA-2, SHA-3, HMAC, CMAC, RSA, ECC (P-224/P-256/P-384/P-521/Brainpool), ECDSA, ECDH, Ed25519, X25519, DH, DSA, SM2, SM9, DRBG (HMAC/CTR/Hash), ML-KEM, ML-DSA, SLH-DSA, XMSS, FrodoKEM, McEliece, HPKE, HybridKEM, Paillier, ElGamal (326 tests)
│   ├── hitls-tls/       # TLS 1.3 key schedule, record encryption, client & server handshake, PSK/session tickets, 0-RTT early data, post-handshake client auth, TLS 1.2 handshake (14 suites: ECDHE-GCM/CBC/ChaCha20, ALPN, SNI, session resumption, mTLS), DTLS 1.2 (RFC 6347), TLCP (GM/T 0024), TLS 1.2 PRF (291 tests)
│   ├── hitls-pki/       # X.509 (parse, verify, chain, CRL, OCSP, CSR generation, certificate generation), PKCS#8 (RFC 5958), PKCS#12 (RFC 7292), CMS SignedData (RFC 5652) (98 tests)
│   ├── hitls-auth/      # HOTP/TOTP (RFC 4226/6238), SPAKE2+ (RFC 9382), Privacy Pass (20 tests)
│   └── hitls-cli/       # Command-line tool (dgst, genpkey, x509, verify, enc, pkey, crl, req, s-client, s-server)
├── tests/interop/       # Integration tests: cross-crate roundtrip validation (14 tests)
├── tests/vectors/       # Standard test vectors (NIST CAVP, Wycheproof, GM/T)
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
| TLS 1.3 | `hitls-tls` | **Done** — Key Schedule + Record + Client & Server Handshake + HRR + KeyUpdate + PSK/0-RTT + Certificate Compression |
| TLS 1.2 PRF | `hitls-tls` | **Done** — PRF (RFC 5246 section 5) |
| TLS 1.2 | `hitls-tls` | **Done** — 14 cipher suites (ECDHE-GCM/CBC/ChaCha20), ALPN, SNI, session resumption, mTLS |
| DTLS 1.2 | `hitls-tls` | **Done** — Record layer + Handshake + Fragmentation/Reassembly + Cookie Exchange + Anti-Replay + Retransmission |
| TLCP (GM/T 0024) | `hitls-tls` | **Done** — 4 cipher suites (ECDHE/ECC × SM4-CBC/GCM), double certificate, ECDHE + ECC key exchange |
| X.509 Certificates | `hitls-pki` | **Done** (parse + verify + chain + CSR generation + certificate generation) |
| CRL | `hitls-pki` | **Done** (parse + validate + revocation checking) |
| PKCS#8 (RFC 5958) | `hitls-pki` | **Done** (parse + encode) |
| PKCS#12 (RFC 7292) | `hitls-pki` | **Done** (parse + create) |
| CMS SignedData (RFC 5652) | `hitls-pki` | **Done** (parse + verify + sign) |
| HOTP (RFC 4226) | `hitls-auth` | **Done** |
| TOTP (RFC 6238) | `hitls-auth` | **Done** |
| SPAKE2+ (RFC 9382, P-256) | `hitls-auth` | **Done** |

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
# Run all tests (806 tests, 19 ignored)
cargo test --workspace --all-features

# Run tests for a specific crate
cargo test -p hitls-crypto --all-features   # 330 tests (19 ignored)
cargo test -p hitls-tls --all-features      # 263 tests
cargo test -p hitls-pki --all-features      # 98 tests
cargo test -p hitls-bignum                  # 46 tests
cargo test -p hitls-utils                   # 35 tests
cargo test -p hitls-auth --all-features     # 20 tests
cargo test -p hitls-integration-tests       # 14 tests

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

### Completed (Phase 0-28)

All cryptographic primitives, X.509 (including CSR generation and certificate generation), PKCS#8, PKCS#12, CMS, CRL/OCSP, TLS 1.3 (including PSK/session tickets + 0-RTT early data + post-handshake client auth + certificate compression), TLS 1.2 handshake (14 cipher suites: ECDHE-GCM/CBC/ChaCha20, ALPN, SNI), DTLS 1.2 (RFC 6347: record layer, handshake, fragmentation/reassembly, cookie exchange, anti-replay, retransmission), TLCP (GM/T 0024: 4 cipher suites, double certificate, ECDHE + ECC key exchange, SM4-CBC/GCM), TLS 1.2 PRF, auth protocols, PQC, ECC curve additions (P-224, P-521, Brainpool), DRBG variants (HMAC, CTR, Hash), and CLI tool implemented. 806 tests passing across 9 crates.

### Remaining Migration Work

The original C implementation ([openHiTLS](https://gitee.com/openhitls/openhitls)) contains ~460K lines covering 48 crypto modules, 6 TLS protocol versions, and full PKI infrastructure. The Rust port currently covers ~72% of features by TLS 1.3-focused deployments. The following phases outline the remaining work to reach full parity.

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
| TLS 1.2 Handshake | RFC 5246 | **Done** (14 cipher suites: ECDHE-GCM/CBC/ChaCha20) |
| TLS 1.2 Cipher Suites (50+) | RFC 5246 | **Partial** (14 suites: 4 GCM + 8 CBC + 2 ChaCha20) |
| Session Resumption (ID-based) | RFC 5246 §7.4.1.2 | **Done** |
| Client Certificate Auth (mTLS) | RFC 5246 §7.4.4 | **Done** |
| Renegotiation | RFC 5746 | Not implemented |
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

#### Phase 32: Hardware Acceleration & Production Hardening

| Feature | Description | Status |
|---------|-------------|--------|
| AES-NI | x86-64 AES hardware instructions | Not implemented |
| ARM NEON | ECC scalar multiplication | Not implemented |
| AVX-512 Poly1305 | x86-64 SIMD for Poly1305 | Not implemented |
| CPU Capability Detection | Runtime feature detection | Not implemented |
| Provider/Engine System | Pluggable algorithm dispatch | Basic only |
| Wycheproof Test Vectors | Comprehensive edge-case tests | Partial |
| Fuzzing Harnesses | libfuzzer/AFL targets | Not implemented |

### Coverage Summary (vs. C Implementation)

| Component | C (lines) | Rust (lines) | Feature Coverage |
|-----------|-----------|--------------|------------------|
| Crypto Algorithms | ~132K | ~24K | ~90% |
| TLS Protocol | ~52K | ~9K | ~60% (TLS 1.3 + TLS 1.2 + DTLS 1.2 + TLCP) |
| PKI / X.509 | ~17K | ~3.3K | ~60% |
| Total | ~460K | ~33K | ~76% (TLS 1.3 deployments) |

## Minimum Supported Rust Version

**MSRV: 1.75**

## License

Licensed under the [Mulan Permissive Software License, Version 2](http://license.coscl.org.cn/MulanPSL2).

## Acknowledgments

This project is a Rust rewrite of [openHiTLS](https://gitee.com/openhitls/openhitls), an open-source cryptographic and TLS library originally written in C.
