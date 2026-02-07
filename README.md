# openHiTLS-rs

A production-grade cryptographic and TLS library written in pure Rust, rewritten from [openHiTLS](https://gitee.com/openhitls/openhitls) (C implementation).

> **Status: Active Development (Phase 18 Complete)**
>
> Core cryptographic primitives implemented: hash functions (SHA-2, SHA-3/SHAKE, SM3, SHA-1, MD5), HMAC/CMAC/GMAC/SipHash, symmetric ciphers (AES, SM4, ChaCha20), block cipher modes (ECB, CBC, CTR, GCM, CFB, OFB, CCM, XTS), AES Key Wrap (RFC 3394), ChaCha20-Poly1305 AEAD, KDFs (HKDF, PBKDF2, scrypt), RSA (PKCS#1 v1.5, OAEP, PSS), ECC (P-256, P-384, point_add/point_negate), ECDSA, ECDH, Ed25519, X25519, DH (ffdhe2048/3072), DSA, SM2 (sign/verify/encrypt/decrypt), HMAC-DRBG, ML-KEM (FIPS 203), ML-DSA (FIPS 204), HPKE (RFC 9180), HybridKEM (X25519+ML-KEM-768), Paillier, ElGamal, X.509 certificate parsing/verification (RSA, ECDSA, Ed25519), X.509 chain building/verification with trust store, PKCS#12 (RFC 7292) parse/create, CMS SignedData (RFC 5652) parse/verify/sign, TLS 1.3 key schedule (RFC 8446/8448) with HKDF, transcript hash, AEAD adapter, TLS 1.3 record layer encryption, TLS 1.3 client handshake (full 1-RTT flow with X25519 key exchange, CertificateVerify signature verification, and handshake state machine), TLS 1.3 server handshake with bidirectional application data exchange, HOTP/TOTP (RFC 4226/6238), and SPAKE2+ (RFC 9382 on P-256). 441 tests passing (20 auth + 46 bignum + 230 crypto + 47 pki + 72 tls + 26 utils).

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
│   ├── hitls-crypto/    # Crypto: AES, SM4, ChaCha20, GCM, SHA-2, SHA-3, HMAC, CMAC, RSA, ECDSA, ECDH, Ed25519, X25519, DH, DSA, SM2, DRBG, ML-KEM, ML-DSA, HPKE, HybridKEM, Paillier, ElGamal... (230 tests)
│   ├── hitls-tls/       # TLS 1.3 key schedule, record encryption, client & server handshake (72 tests)
│   ├── hitls-pki/       # X.509 (parse, verify, chain build), PKCS#12 (RFC 7292), CMS SignedData (RFC 5652) (47 tests)
│   ├── hitls-auth/      # HOTP/TOTP (RFC 4226/6238), SPAKE2+ (RFC 9382), Privacy Pass (20 tests)
│   └── hitls-cli/       # Command-line tool (openssl-like interface)
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
| SM9 | `sm9` | Stub |
| Paillier (Homomorphic) | `paillier` | **Done** |
| ElGamal | `elgamal` | **Done** |

### Post-Quantum

| Algorithm | Feature Flag | Status |
|-----------|-------------|--------|
| ML-KEM (Kyber) 512/768/1024 | `mlkem` | **Done** |
| ML-DSA (Dilithium) 44/65/87 | `mldsa` | **Done** |
| SLH-DSA (SPHINCS+) | `slh-dsa` | Stub |
| XMSS / XMSS^MT | `xmss` | Stub |
| FrodoKEM | `frodokem` | Stub |
| Classic McEliece | `mceliece` | Stub |
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
| TLS 1.3 | `hitls-tls` | Key Schedule + Record Encryption + Client & Server Handshake done |
| TLS 1.2 | `hitls-tls` | Skeleton |
| DTLS 1.2 | `hitls-tls` | Skeleton |
| TLCP (GM/T 0024) | `hitls-tls` | Skeleton |
| X.509 Certificates | `hitls-pki` | **Done** (parse + verify + chain) |
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
# Run all tests (441 tests)
cargo test --workspace --all-features

# Run tests for a specific crate
cargo test -p hitls-crypto --all-features   # 230 tests (3 ignored)
cargo test -p hitls-tls --all-features      # 72 tests
cargo test -p hitls-pki --all-features      # 47 tests
cargo test -p hitls-bignum                  # 46 tests
cargo test -p hitls-utils                   # 26 tests
cargo test -p hitls-auth --all-features     # 20 tests

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

Phase 0–18 complete. Remaining phases:

| Phase | Name | Est. LOC | Est. Tests | Critical Path |
|-------|------|----------|------------|---------------|
| 19 | Remaining PQC (SLH-DSA, XMSS, FrodoKEM, McEliece, SM9) | ~7,000 | ~35 | No |
| 20 | CLI Tool + Integration Tests | ~1,910 | ~20 | No |

Target: ~40,000 lines of Rust, ~500+ tests. See [plan file](.claude/plans/) for details.

## Minimum Supported Rust Version

**MSRV: 1.75**

## License

Licensed under the [Mulan Permissive Software License, Version 2](http://license.coscl.org.cn/MulanPSL2).

## Acknowledgments

This project is a Rust rewrite of [openHiTLS](https://gitee.com/openhitls/openhitls), an open-source cryptographic and TLS library originally written in C.
