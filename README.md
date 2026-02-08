# openHiTLS-rs

A production-grade cryptographic and TLS library written in pure Rust, rewritten from [openHiTLS](https://gitee.com/openhitls/openhitls) (C implementation).

> **Status: Phase 21 Step 4 Complete — TLS 1.3 0-RTT Early Data**
>
> 529 tests passing (20 auth + 46 bignum + 278 crypto + 47 pki + 102 tls + 26 utils + 10 integration). Full coverage: hash (SHA-2, SHA-3/SHAKE, SM3, SHA-1, MD5), HMAC/CMAC/GMAC/SipHash, symmetric (AES, SM4, ChaCha20), modes (ECB, CBC, CTR, GCM, CFB, OFB, CCM, XTS, Key Wrap), ChaCha20-Poly1305, KDFs (HKDF, PBKDF2, scrypt), RSA (PKCS#1v1.5, OAEP, PSS), ECC (P-256, P-384), ECDSA, ECDH, Ed25519, X25519, DH, DSA, SM2, SM9 (IBE with BN256 pairing), HMAC-DRBG, PQC (ML-KEM, ML-DSA, SLH-DSA, XMSS, FrodoKEM, Classic McEliece), HPKE, HybridKEM, Paillier, ElGamal, X.509 (parse/verify/chain), PKCS#12, CMS SignedData, TLS 1.3 (key schedule + record + client/server handshake + PSK/session tickets + 0-RTT early data), HOTP/TOTP, SPAKE2+, and CLI tool.

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
│   ├── hitls-utils/     # Utilities: ASN.1, Base64, PEM, OID (26 tests)
│   ├── hitls-bignum/    # Big number: Montgomery, Miller-Rabin, GCD (46 tests)
│   ├── hitls-crypto/    # Crypto: AES, SM4, ChaCha20, GCM, SHA-2, SHA-3, HMAC, CMAC, RSA, ECDSA, ECDH, Ed25519, X25519, DH, DSA, SM2, SM9, DRBG, ML-KEM, ML-DSA, SLH-DSA, XMSS, FrodoKEM, McEliece, HPKE, HybridKEM, Paillier, ElGamal (278 tests)
│   ├── hitls-tls/       # TLS 1.3 key schedule, record encryption, client & server handshake, PSK/session tickets, 0-RTT early data (102 tests)
│   ├── hitls-pki/       # X.509 (parse, verify, chain build), PKCS#12 (RFC 7292), CMS SignedData (RFC 5652) (47 tests)
│   ├── hitls-auth/      # HOTP/TOTP (RFC 4226/6238), SPAKE2+ (RFC 9382), Privacy Pass (20 tests)
│   └── hitls-cli/       # Command-line tool (dgst, genpkey, x509, verify, enc, pkey, crl)
├── tests/interop/       # Integration tests: cross-crate roundtrip validation (10 tests)
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
| ECDSA (P-256, P-384) | `ecdsa` (default) | **Done** |
| ECDH (P-256, P-384) | `ecdh` | **Done** |
| ECC core (Jacobian, Weierstrass) | `ecc` | **Done** |
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
| TLS 1.3 | `hitls-tls` | **Done** — Key Schedule + Record + Client & Server Handshake + PSK/Session Tickets + 0-RTT Early Data (no HRR yet) |
| TLS 1.2 | `hitls-tls` | Planned (Phase 25) |
| DTLS 1.2 | `hitls-tls` | Planned (Phase 26) |
| TLCP (GM/T 0024) | `hitls-tls` | Planned (Phase 27) |
| X.509 Certificates | `hitls-pki` | **Done** (parse + verify + chain) |
| CRL | `hitls-pki` | Planned (Phase 24) |
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
# Run all tests (529 tests, 18 ignored)
cargo test --workspace --all-features

# Run tests for a specific crate
cargo test -p hitls-crypto --all-features   # 278 tests (18 ignored)
cargo test -p hitls-tls --all-features      # 102 tests
cargo test -p hitls-pki --all-features      # 47 tests
cargo test -p hitls-bignum                  # 46 tests
cargo test -p hitls-utils                   # 26 tests
cargo test -p hitls-auth --all-features     # 20 tests
cargo test -p hitls-integration-tests       # 10 tests

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

### Completed (Phase 0-20)

All cryptographic primitives, X.509, PKCS#12, CMS, TLS 1.3 (including PSK/session tickets + 0-RTT early data), auth protocols, PQC, and CLI tool implemented. 529 tests passing across 9 crates.

### Remaining Migration Work

The original C implementation ([openHiTLS](https://gitee.com/openhitls/openhitls)) contains ~460K lines covering 48 crypto modules, 6 TLS protocol versions, and full PKI infrastructure. The Rust port currently covers ~70% of features by TLS 1.3-focused deployments. The following phases outline the remaining work to reach full parity.

#### Phase 21: TLS 1.3 Completeness

| Feature | RFC | Status |
|---------|-----|--------|
| PSK / Session Tickets | RFC 8446 §4.6.1 | **Done** |
| HelloRetryRequest (HRR) | RFC 8446 §4.1.4 | Not implemented |
| 0-RTT Early Data | RFC 8446 §4.2.10 | **Done** |
| Post-Handshake Client Auth | RFC 8446 §4.6.2 | Not implemented |
| KeyUpdate | RFC 8446 §4.6.3 | Stub only |
| Certificate Compression | RFC 8879 | Not implemented |

#### Phase 22: ECC Curve Additions

| Curve | Standard | Status |
|-------|----------|--------|
| P-521 (secp521r1) | FIPS 186-4 | Not implemented |
| Brainpool P-256r1 | RFC 5639 | Not implemented |
| Brainpool P-384r1 | RFC 5639 | Not implemented |
| Brainpool P-512r1 | RFC 5639 | Not implemented |
| P-224 (secp224r1) | FIPS 186-4 | Not implemented |

#### Phase 23: DRBG Variants & Cipher Modes

| Component | Standard | Status |
|-----------|----------|--------|
| CTR-DRBG (AES-based) | NIST SP 800-90A | Not implemented (only HMAC-DRBG done) |
| Hash-DRBG | NIST SP 800-90A | Not implemented |
| PKCS#8 Key Parsing | RFC 5958 | Not implemented |

#### Phase 24: CRL & OCSP

| Feature | Standard | Status |
|---------|----------|--------|
| CRL Parsing | RFC 5280 §5 | Not implemented |
| CRL Validation | RFC 5280 §6.3 | Not implemented |
| Revocation Checking | RFC 5280 | Not implemented |
| OCSP (basic) | RFC 6960 | Not implemented |

#### Phase 25: TLS 1.2

| Feature | Standard | Status |
|---------|----------|--------|
| TLS 1.2 Handshake | RFC 5246 | Not implemented |
| TLS 1.2 Cipher Suites (50+) | RFC 5246 | Not implemented |
| Session Resumption (ID-based) | RFC 5246 §7.4.1.2 | Not implemented |
| Renegotiation | RFC 5746 | Not implemented |
| TLS 1.2 Record Protocol | RFC 5246 §6 | Not implemented |

#### Phase 26: DTLS

| Feature | Standard | Status |
|---------|----------|--------|
| DTLS 1.2 Record Layer | RFC 6347 | Not implemented |
| Message Fragmentation/Reassembly | RFC 6347 §4.2.3 | Not implemented |
| Retransmission Timers | RFC 6347 §4.2.4 | Not implemented |
| Cookie Exchange | RFC 6347 §4.2.1 | Not implemented |

#### Phase 27: TLCP (GM/T 0024)

| Feature | Standard | Status |
|---------|----------|--------|
| TLCP Handshake | GM/T 0024 | Not implemented |
| SM2/SM3/SM4 Cipher Suites | GM/T 0024 | Not implemented |
| Double Certificate | GM/T 0024 | Not implemented |

#### Phase 28: Hardware Acceleration & Production Hardening

| Feature | Description | Status |
|---------|-------------|--------|
| AES-NI | x86-64 AES hardware instructions | Not implemented |
| ARM NEON | ECC scalar multiplication | Not implemented |
| AVX-512 Poly1305 | x86-64 SIMD for Poly1305 | Not implemented |
| CPU Capability Detection | Runtime feature detection | Not implemented |
| Network I/O Layer | Async/sync socket abstraction | Not implemented |
| Provider/Engine System | Pluggable algorithm dispatch | Basic only |
| Wycheproof Test Vectors | Comprehensive edge-case tests | Partial |
| Fuzzing Harnesses | libfuzzer/AFL targets | Not implemented |

### Coverage Summary (vs. C Implementation)

| Component | C (lines) | Rust (lines) | Feature Coverage |
|-----------|-----------|--------------|------------------|
| Crypto Algorithms | ~132K | ~24K | ~90% |
| TLS Protocol | ~52K | ~3.5K | ~30% (TLS 1.3 only) |
| PKI / X.509 | ~17K | ~3.3K | ~60% |
| Total | ~460K | ~27K | ~70% (TLS 1.3 deployments) |

## Minimum Supported Rust Version

**MSRV: 1.75**

## License

Licensed under the [Mulan Permissive Software License, Version 2](http://license.coscl.org.cn/MulanPSL2).

## Acknowledgments

This project is a Rust rewrite of [openHiTLS](https://gitee.com/openhitls/openhitls), an open-source cryptographic and TLS library originally written in C.
