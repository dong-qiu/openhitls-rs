# openHiTLS-rs

A production-grade cryptographic and TLS library written in pure Rust, rewritten from [openHiTLS](https://gitee.com/openhitls/openhitls) (C implementation).

> **Status: Early Development (Phase 0 — Scaffolding Complete)**
>
> The workspace structure, type definitions, and module skeletons are in place. Algorithm implementations are being actively developed.

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
│   ├── hitls-utils/     # Utilities: ASN.1, Base64, PEM, OID
│   ├── hitls-bignum/    # Big number arithmetic (Montgomery, Miller-Rabin)
│   ├── hitls-crypto/    # Cryptographic algorithms (30+ algorithms)
│   ├── hitls-tls/       # TLS 1.2/1.3, DTLS, TLCP protocol implementation
│   ├── hitls-pki/       # X.509, PKCS#12, CMS/PKCS#7
│   ├── hitls-auth/      # HOTP/TOTP, SPAKE2+, Privacy Pass
│   └── hitls-cli/       # Command-line tool (openssl-like interface)
├── tests/vectors/       # Standard test vectors (NIST CAVP, Wycheproof, GM/T)
├── benches/             # Performance benchmarks
└── fuzz/                # Fuzz testing targets
```

## Supported Algorithms

### Hash

| Algorithm | Feature Flag | Status |
|-----------|-------------|--------|
| SHA-224 / SHA-256 / SHA-384 / SHA-512 | `sha2` (default) | Stub |
| SHA3-224 / SHA3-256 / SHA3-384 / SHA3-512 / SHAKE128 / SHAKE256 | `sha3` | Stub |
| SM3 | `sm3` | Stub |
| SHA-1 | `sha1` | Stub |
| MD5 | `md5` | Stub |

### Symmetric Ciphers & Modes

| Algorithm | Feature Flag | Status |
|-----------|-------------|--------|
| AES-128 / AES-192 / AES-256 | `aes` (default) | Stub |
| SM4 | `sm4` | Stub |
| ChaCha20 | `chacha20` | Stub |
| Modes: ECB, CBC, CTR, CFB, OFB, GCM, CCM, XTS, Key Wrap | `modes` | Stub |

### MAC

| Algorithm | Feature Flag | Status |
|-----------|-------------|--------|
| HMAC | `hmac` (default) | Stub |
| CMAC | `cmac` | Stub |
| GMAC | `gmac` | Stub |
| SipHash | `siphash` | Stub |

### Asymmetric / Public Key

| Algorithm | Feature Flag | Status |
|-----------|-------------|--------|
| RSA (PKCS#1 v1.5, PSS, OAEP) | `rsa` (default) | Stub |
| ECDSA (P-256, P-384, P-521, Brainpool) | `ecdsa` (default) | Stub |
| ECDH | `ecdh` | Stub |
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

| Algorithm | Feature Flag | Status |
|-----------|-------------|--------|
| HKDF | `hkdf` | Stub |
| PBKDF2 | `pbkdf2` | Stub |
| scrypt | `scrypt` | Stub |
| DRBG (Hash, HMAC, CTR) | `drbg` | Stub |
| HPKE | `hpke` | Stub |

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
# Run all tests
cargo test --all

# Run tests for a specific crate
cargo test -p hitls-bignum
cargo test -p hitls-utils
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
