# openHiTLS-rs

A production-grade cryptographic and TLS library written in pure Rust, rewritten from [openHiTLS](https://gitee.com/openhitls/openhitls) (C implementation).

> **Status: Active Development (Phase 6 Complete)**
>
> Core cryptographic primitives implemented: hash functions (SHA-2, SM3, SHA-1, MD5), HMAC, symmetric ciphers (AES, SM4), block cipher modes (ECB, CBC, CTR, GCM), KDFs (HKDF, PBKDF2), RSA (PKCS#1 v1.5, OAEP, PSS), ECC (P-256, P-384), ECDSA, and ECDH. 136 tests passing (46 bignum + 90 crypto).

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
│   ├── hitls-utils/     # Utilities: ASN.1, Base64, PEM, OID (11 tests)
│   ├── hitls-bignum/    # Big number: Montgomery, Miller-Rabin, GCD (46 tests)
│   ├── hitls-crypto/    # Crypto: AES, SM4, GCM, SHA-2, HMAC, RSA, ECDSA, ECDH... (90 tests)
│   ├── hitls-tls/       # TLS 1.2/1.3, DTLS, TLCP protocol
│   ├── hitls-pki/       # X.509, PKCS#12, CMS/PKCS#7
│   ├── hitls-auth/      # HOTP/TOTP, SPAKE2+, Privacy Pass
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
| SHA3 / SHAKE | `sha3` | Stub | — |

### Symmetric Ciphers & Modes

| Algorithm | Feature Flag | Status | Tests |
|-----------|-------------|--------|-------|
| AES-128 / AES-192 / AES-256 | `aes` (default) | **Done** | FIPS 197 |
| SM4 | `sm4` | **Done** | GB/T 32907-2016 |
| ECB mode | `modes` | **Done** | NIST SP 800-38A |
| CBC mode (PKCS#7) | `modes` | **Done** | NIST SP 800-38A |
| CTR mode | `modes` | **Done** | NIST SP 800-38A |
| GCM mode (AEAD) | `modes` | **Done** | NIST SP 800-38D |
| ChaCha20-Poly1305 | `chacha20` | Stub | — |
| CFB, OFB, CCM, XTS | `modes` | Stub | — |

### MAC

| Algorithm | Feature Flag | Status | Tests |
|-----------|-------------|--------|-------|
| HMAC-SHA-256 | `hmac` (default) | **Done** | RFC 4231 |
| CMAC | `cmac` | Stub | — |
| GMAC | `gmac` | Stub | — |

### Asymmetric / Public Key

| Algorithm | Feature Flag | Status |
|-----------|-------------|--------|
| RSA (PKCS#1 v1.5, PSS, OAEP) | `rsa` (default) | **Done** |
| ECDSA (P-256, P-384) | `ecdsa` (default) | **Done** |
| ECDH (P-256, P-384) | `ecdh` | **Done** |
| ECC core (Jacobian, Weierstrass) | `ecc` | **Done** |
| Ed25519 | `ed25519` | Stub |
| X25519 | `x25519` | Stub |
| DSA | `dsa` | Stub |
| DH | `dh` | Stub |
| SM2 (Sign, Encrypt, Key Exchange) | `sm2` | Stub |
| SM9 | `sm9` | Stub |
| Paillier / ElGamal | `paillier` / `elgamal` | Stub |

### Post-Quantum

| Algorithm | Feature Flag | Status |
|-----------|-------------|--------|
| ML-KEM (Kyber) 512/768/1024 | `mlkem` | Stub |
| ML-DSA (Dilithium) 44/65/87 | `mldsa` | Stub |
| SLH-DSA (SPHINCS+) | `slh-dsa` | Stub |
| XMSS / XMSS^MT | `xmss` | Stub |
| FrodoKEM | `frodokem` | Stub |
| Classic McEliece | `mceliece` | Stub |
| Hybrid KEM (X25519+ML-KEM, etc.) | `hybridkem` | Stub |

### KDF & DRBG

| Algorithm | Feature Flag | Status | Tests |
|-----------|-------------|--------|-------|
| HKDF | `hkdf` | **Done** | RFC 5869 |
| PBKDF2 | `pbkdf2` | **Done** | Verified with OpenSSL |
| scrypt | `scrypt` | Stub | — |
| DRBG (Hash, HMAC, CTR) | `drbg` | Stub | — |
| HPKE | `hpke` | Stub | — |

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
| TLS 1.3 | `hitls-tls` | Skeleton |
| TLS 1.2 | `hitls-tls` | Skeleton |
| DTLS 1.2 | `hitls-tls` | Skeleton |
| TLCP (GM/T 0024) | `hitls-tls` | Skeleton |
| X.509 Certificates | `hitls-pki` | Skeleton |
| PKCS#12 | `hitls-pki` | Skeleton |
| CMS/PKCS#7 | `hitls-pki` | Skeleton |

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
# Run all tests (136 tests)
cargo test --workspace --all-features

# Run tests for a specific crate
cargo test -p hitls-crypto --all-features   # 90 tests (1 ignored)
cargo test -p hitls-bignum                  # 46 tests
cargo test -p hitls-utils                   # 11 tests

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
| `sm2` | `ecc`, `sm3` |
| `tlcp` | `sm2`, `sm3`, `sm4` (via `hitls-tls`) |

## Design Principles

- **Trait-based providers** — All algorithms implement common traits (`Digest`, `Aead`, `Signer`, `Verifier`, etc.) for static dispatch with zero-cost abstraction
- **Zeroize on drop** — All secret material (keys, intermediate states) is automatically zeroed when dropped
- **Constant-time operations** — Cryptographic comparisons and branching use the `subtle` crate to prevent timing side-channels
- **Strong error types** — `CryptoError`, `TlsError`, `PkiError` with `thiserror` for clear, actionable error messages
- **Builder pattern** — TLS configuration uses builder pattern for ergonomic and safe construction

## Minimum Supported Rust Version

**MSRV: 1.75**

## License

Licensed under the [Mulan Permissive Software License, Version 2](http://license.coscl.org.cn/MulanPSL2).

## Acknowledgments

This project is a Rust rewrite of [openHiTLS](https://gitee.com/openhitls/openhitls), an open-source cryptographic and TLS library originally written in C.
