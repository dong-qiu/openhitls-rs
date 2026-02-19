# openHiTLS-rs

A production-grade cryptographic and TLS library written in pure Rust, rewritten from [openHiTLS](https://gitee.com/openhitls/openhitls) (C implementation).

> **Status: Phase 78 Complete — Trusted CA Keys (RFC 6066) + USE_SRTP (RFC 5764) + STATUS_REQUEST_V2 (RFC 6961) + CMS AuthenticatedData (RFC 5652 §9)**
>
> 2256 tests passing (33 auth + 49 bignum + 603 crypto + 15 wycheproof + 341 pki + 904 tls + 26 types + 53 utils + 117 cli + 113 integration + 2 doc-tests; 40 ignored). 66 structured fuzz seed corpus files across all 10 fuzz targets. 5000+ Wycheproof edge-case vectors, 10 fuzz targets, security audit (constant-time, zeroize, unsafe code review). Full coverage: hash (SHA-2, SHA-3/SHAKE, SM3, SHA-1, MD5), HMAC/CMAC/GMAC/SipHash, symmetric (AES, SM4, ChaCha20), modes (ECB, CBC, CTR, GCM, CFB, OFB, CCM, XTS, Key Wrap), ChaCha20-Poly1305, KDFs (HKDF, PBKDF2, scrypt), DRBGs (HMAC-DRBG, CTR-DRBG, Hash-DRBG), entropy health testing (NIST SP 800-90B RCT+APT, entropy pool, conditioning, pluggable noise sources), RSA (PKCS#1v1.5, OAEP, PSS), ECC (P-224, P-256, P-384, P-521, Brainpool P-256r1/P-384r1/P-512r1), ECDSA, ECDH, Ed25519, X25519, Ed448 (RFC 8032), X448 (RFC 7748), Curve448 (Goldilocks), DH, DSA, SM2, SM9 (IBE with BN256 pairing), PQC (ML-KEM, ML-DSA, SLH-DSA, XMSS, FrodoKEM, Classic McEliece), HPKE, HybridKEM, Paillier, ElGamal, X.509 (parse/verify/chain/CSR generation/certificate generation/to_text, EKU/SAN/AKI/SKI/AIA/NameConstraints/CertificatePolicies enforcement, hostname verification (RFC 6125)), PKCS#8 (parse/encode), PKCS#12, CMS SignedData (Ed25519/Ed448, SKI signer lookup, RSA-PSS, noattr) + EnvelopedData + EncryptedData + DigestedData + AuthenticatedData, TLS 1.3 (key schedule + record + client/server handshake + PSK/session tickets + 0-RTT early data + post-handshake client auth + certificate compression + X25519MLKEM768 hybrid KEM + SM4-GCM/CCM (RFC 8998) + AES_128_CCM_8_SHA256 + PADDING (RFC 7685) + OID Filters (RFC 8446 §4.2.5)), TLS 1.2 handshake (91 cipher suites: ECDHE/RSA/DHE_RSA/DHE_DSS/DH_ANON/ECDH_ANON/PSK/DHE_PSK/RSA_PSK/ECDHE_PSK key exchange, GCM/CBC/ChaCha20/CCM/CCM_8, Bleichenbacher protection, ALPN, SNI, session resumption, session ticket, EMS, ETM, renegotiation (RFC 5746), mTLS, AES-CCM (RFC 6655/7251), AES-CCM_8 (8-byte tag), PSK+CCM, DHE_DSS (RFC 5246), DH_ANON/ECDH_ANON (RFC 5246/4492), OCSP stapling CertificateStatus, hostname verification (RFC 6125), cert chain validation, CertVerifyCallback + SniCallback), DTLS 1.2 (record layer + handshake + fragmentation + retransmission + cookie exchange + anti-replay + session cache + abbreviated handshake + async I/O), Heartbeat extension (RFC 6520, negotiation), GREASE (RFC 8701), TLCP (GM/T 0024, 4 cipher suites, double certificate, ECDHE + ECC key exchange), DTLCP (DTLS + TLCP, 4 cipher suites, cookie exchange, anti-replay), custom extensions framework, NSS key logging (SSLKEYLOGFILE), Record Size Limit (RFC 8449), Fallback SCSV (RFC 7507), OCSP stapling, SCT (RFC 6962), async I/O (tokio), hardware AES (AES-NI + ARMv8 NEON), FIPS/CMVP (KAT, PCT, integrity, entropy health tests), TLS 1.2 PRF, HOTP/TOTP, SPAKE2+, Privacy Pass (RFC 9578), and CLI tool (dgst, genpkey, x509, verify, enc, pkey, crl, req, s-client, s-server, list, rand, pkeyutl, speed, pkcs12, mac).

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
│   ├── hitls-utils/     # Utilities: ASN.1, Base64, PEM, OID (53 tests)
│   ├── hitls-bignum/    # Big number: Montgomery, Miller-Rabin, GCD (49 tests)
│   ├── hitls-crypto/    # Crypto: AES, SM4, ChaCha20, GCM, SHA-2, SHA-3, HMAC, CMAC, RSA, ECC (P-224/P-256/P-384/P-521/Brainpool), ECDSA, ECDH, Ed25519, X25519, Ed448, X448, Curve448, DH, DSA, SM2, SM9, DRBG (HMAC/CTR/Hash), Entropy (SP 800-90B health tests), ML-KEM, ML-DSA, SLH-DSA, XMSS, FrodoKEM, McEliece, HPKE, HybridKEM, Paillier, ElGamal, SM4-CCM, CBC-MAC-SM4 (603 tests + 15 Wycheproof)
│   ├── hitls-tls/       # TLS 1.3/1.2/DTLS 1.2/TLCP/DTLCP, 10 connection types (5 sync + 5 async), async I/O (tokio), custom extensions, NSS key logging, 91 cipher suites (incl. TLS 1.2 AES-CCM RFC 6655/7251, AES-CCM_8 8-byte tag, PSK+CCM/CCM_8, DHE_PSK CCM_8, ECDHE_PSK CCM_8, DHE_RSA CCM_8, ECDHE_ECDSA CCM_8, PSK CBC-SHA256/SHA384, ECDHE_PSK GCM, DHE_DSS RFC 5246, DH_ANON/ECDH_ANON RFC 5246/4492), renegotiation (RFC 5746), hostname verification (RFC 6125), cert chain validation, CertVerifyCallback + SniCallback, ConnectionInfo APIs, graceful shutdown (close_notify), server/client session cache (TTL expiration, cipher_server_preference), write record fragmentation, KeyUpdate loop protection (128 limit), Max Fragment Length (RFC 6066), Signature Algorithms Cert (RFC 8446 §4.2.3), hybrid KEM (X25519MLKEM768), TLS 1.3 SM4-GCM/CCM (RFC 8998) + AES_128_CCM_8_SHA256, RFC 5705/8446 key material export, Record Size Limit (RFC 8449), Fallback SCSV (RFC 7507), OCSP stapling, SCT (RFC 6962), Certificate Authorities (RFC 8446 §4.2.4), early exporter master secret (RFC 8446 §7.5), PADDING (RFC 7685), OID Filters (RFC 8446 §4.2.5), DTLS 1.2 session cache + abbreviated handshake + async I/O, Heartbeat (RFC 6520), GREASE (RFC 8701), MsgCallback/InfoCallback/RecordPaddingCallback/DhTmpCallback/CookieGenCallback/CookieVerifyCallback/ClientHelloCallback, Trusted CA Keys (RFC 6066 §6), USE_SRTP (RFC 5764), STATUS_REQUEST_V2 (RFC 6961) (904 tests)
│   ├── hitls-pki/       # X.509 (parse, verify [RSA/ECDSA/Ed25519/Ed448/SM2/RSA-PSS], chain, CRL, OCSP, CSR generation, certificate generation, to_text, EKU/SAN/AKI/SKI/AIA/NameConstraints/CertificatePolicies enforcement, hostname verification (RFC 6125)), PKCS#8 (RFC 5958, Ed448/X448), SPKI parsing, PKCS#12 (RFC 7292), CMS SignedData (Ed25519/Ed448, SKI signer lookup, RSA-PSS, noattr, detached mode) + EnvelopedData + EncryptedData + DigestedData + AuthenticatedData (RFC 5652) (341 tests, 1 ignored)
│   ├── hitls-auth/      # HOTP/TOTP (RFC 4226/6238), SPAKE2+ (RFC 9382), Privacy Pass (RFC 9578, RSA blind sigs) (33 tests)
│   └── hitls-cli/       # Command-line tool (dgst, genpkey, x509, verify, enc, pkey, crl, req, s-client, s-server, list, rand, pkeyutl, speed, pkcs12, mac)
├── tests/interop/       # Integration tests: 113 cross-crate tests (TCP loopback, DTLS 1.2, TLCP, DTLCP, mTLS; 3 ignored)
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
| TLS 1.3 | `hitls-tls` | **Done** — Key Schedule + Record + Client & Server Handshake + HRR + KeyUpdate + PSK/0-RTT + Certificate Compression + X25519MLKEM768 Hybrid KEM + SM4-GCM/CCM (RFC 8998) + AES_128_CCM_8_SHA256 |
| TLS 1.2 PRF | `hitls-tls` | **Done** — PRF (RFC 5246 section 5) |
| TLS 1.2 | `hitls-tls` | **Done** — 91 cipher suites (ECDHE/RSA/DHE_RSA/DHE_DSS/DH_ANON/ECDH_ANON/PSK/DHE_PSK/RSA_PSK/ECDHE_PSK key exchange, GCM/CBC/ChaCha20/CCM/CCM_8, Bleichenbacher protection), ALPN, SNI, session resumption, session ticket (RFC 5077), EMS (RFC 7627), ETM (RFC 7366), renegotiation (RFC 5746, server-initiated + verify_data validation), mTLS, PSK (RFC 4279/5489/5487), AES-CCM (RFC 6655/7251), AES-CCM_8 (8-byte tag), PSK+CCM/CCM_8, DHE_PSK CCM_8, ECDHE_PSK CCM_8, DHE_RSA CCM_8, ECDHE_ECDSA CCM_8, PSK CBC-SHA256/SHA384, ECDHE_PSK GCM, DHE_DSS (RFC 5246), DH_ANON/ECDH_ANON (RFC 5246/4492) |
| DTLS 1.2 | `hitls-tls` | **Done** — Record layer + Handshake + Fragmentation/Reassembly + Cookie Exchange + Anti-Replay + Retransmission + Session Cache + Abbreviated Handshake + Async I/O |
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
| PKCS#8 (RFC 5958) | `hitls-pki` | **Done** (parse + encode, Ed448/X448) |
| PKCS#12 (RFC 7292) | `hitls-pki` | **Done** (parse + create) |
| CMS SignedData (RFC 5652) | `hitls-pki` | **Done** (parse + verify + sign, Ed25519/Ed448, SKI signer lookup, RSA-PSS, noattr, detached mode) |
| CMS EnvelopedData (RFC 5652) | `hitls-pki` | **Done** (RSA key transport + AES key wrap) |
| CMS EncryptedData (RFC 5652) | `hitls-pki` | **Done** (password-based encryption) |
| CMS DigestedData (RFC 5652) | `hitls-pki` | **Done** (digest verification) |
| CMS AuthenticatedData (RFC 5652) | `hitls-pki` | **Done** (HMAC-SHA-256/384/512 create + verify) |
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
# Run all tests (2256 tests, 40 ignored)
cargo test --workspace --all-features

# Run tests for a specific crate
cargo test -p hitls-crypto --all-features   # 603 tests (31 ignored) + 15 Wycheproof
cargo test -p hitls-tls --all-features      # 904 tests
cargo test -p hitls-pki --all-features      # 341 tests (1 ignored)
cargo test -p hitls-bignum                  # 49 tests
cargo test -p hitls-utils                   # 53 tests
cargo test -p hitls-auth --all-features     # 33 tests
cargo test -p hitls-cli --all-features      # 117 tests (5 ignored)
cargo test -p hitls-integration-tests       # 113 tests (3 ignored)

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

### Completed (Phase 0–78)

All 48+ cryptographic algorithm modules including Ed448/X448/Curve448, X.509 (parse/verify/chain/CRL/OCSP/CSR/cert generation/to_text), PKCS#8, PKCS#12, CMS SignedData (Ed25519/Ed448, SKI signer lookup, RSA-PSS, noattr, detached mode) + EnvelopedData + EncryptedData + DigestedData + AuthenticatedData (RFC 5652), TLS 1.3 (full spec: PSK/0-RTT/KeyUpdate/HRR/post-HS auth/cert compression/X25519MLKEM768 hybrid KEM/SM4-GCM/CCM (RFC 8998)/AES_128_CCM_8_SHA256/certificate_authorities (RFC 8446 §4.2.4)/early exporter master secret (RFC 8446 §7.5)/Signature Algorithms Cert (RFC 8446 §4.2.3)/PADDING (RFC 7685)/OID Filters (RFC 8446 §4.2.5)), TLS 1.2 (91 suites: ECDHE/RSA/DHE_RSA/DHE_DSS/DH_ANON/ECDH_ANON/PSK/DHE_PSK/RSA_PSK/ECDHE_PSK key exchange, GCM/CBC/ChaCha20/CCM/CCM_8, Bleichenbacher protection, ALPN, SNI, session resumption, session ticket (RFC 5077), EMS (RFC 7627), ETM (RFC 7366), renegotiation (RFC 5746, server-initiated + verify_data validation), mTLS, PSK (RFC 4279/5487/5489), AES-CCM (RFC 6655/7251), AES-CCM_8 (8-byte tag), PSK+CCM, PSK CBC-SHA256/SHA384, ECDHE_PSK GCM, DHE_DSS (RFC 5246), DH_ANON/ECDH_ANON (RFC 5246/4492), OCSP stapling CertificateStatus, Max Fragment Length (RFC 6066), server/client session cache with TTL expiration, cipher_server_preference, write record fragmentation, KeyUpdate loop protection), DTLS 1.2 (RFC 6347, session cache, abbreviated handshake, async I/O), Heartbeat (RFC 6520), GREASE (RFC 8701), Trusted CA Keys (RFC 6066 §6), USE_SRTP (RFC 5764), STATUS_REQUEST_V2 (RFC 6961), TLCP (GM/T 0024, 4 suites), DTLCP (DTLS+TLCP, 4 suites), custom extensions framework, NSS key logging, TLS callbacks (MsgCallback/InfoCallback/RecordPaddingCallback/DhTmpCallback/CookieGenCallback/CookieVerifyCallback/ClientHelloCallback), CBC-MAC-SM4, 10 connection types (5 sync + 5 async: TLS 1.3, TLS 1.2, DTLS 1.2, TLCP, DTLCP), async I/O (tokio), hardware AES (AES-NI + ARMv8 NEON), TLS extensions (Record Size Limit RFC 8449, Fallback SCSV RFC 7507, OCSP stapling, SCT RFC 6962, Certificate Authorities RFC 8446, Signature Algorithms Cert RFC 8446, Max Fragment Length RFC 6066, PADDING RFC 7685, OID Filters RFC 8446, Heartbeat RFC 6520, GREASE RFC 8701, Trusted CA Keys RFC 6066, USE_SRTP RFC 5764, STATUS_REQUEST_V2 RFC 6961), TLS 1.2 PRF, auth protocols (HOTP/TOTP/SPAKE2+/Privacy Pass RFC 9578), PQC (ML-KEM/ML-DSA/SLH-DSA/XMSS/FrodoKEM/McEliece), ECC curves (P-224/P-521/Brainpool), DRBGs (HMAC/CTR/Hash), CLI tool (14 commands), TCP loopback integration tests, 5000+ Wycheproof edge-case vectors, 10 fuzz targets, and security audit. 2256 tests passing (40 ignored) across 10 crates.

### Completed Migration Phases (Phase 21–39)

The original C implementation ([openHiTLS](https://gitee.com/openhitls/openhitls)) contains ~460K lines covering 48 crypto modules, TLS protocol variants, and full PKI infrastructure. The Rust port covers ~99% of core features with all crypto algorithms, TLS 1.3/1.2 (ECDHE/RSA/DHE_RSA/DHE_DSS/DH_ANON/ECDH_ANON/PSK/DHE_PSK/RSA_PSK/ECDHE_PSK + post-quantum hybrid KEM + SM4-GCM/CCM + AES-CCM + AES-CCM_8 + PSK+CCM), DTLS 1.2, TLCP, DTLCP, TLS extensions (Trusted CA Keys/USE_SRTP/STATUS_REQUEST_V2), TLS callbacks (7 types), CMS (SignedData/EnvelopedData/EncryptedData/DigestedData/AuthenticatedData), CBC-MAC-SM4, Privacy Pass, and 14 CLI commands fully implemented. Below are the detailed phase tables for completed work.

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
| TLS 1.2 Handshake | RFC 5246 | **Done** (91 cipher suites: ECDHE/RSA/DHE_RSA/DHE_DSS/DH_ANON/ECDH_ANON/PSK/DHE_PSK/RSA_PSK/ECDHE_PSK, GCM/CBC/ChaCha20/CCM/CCM_8) |
| TLS 1.2 Cipher Suites (50+) | RFC 5246 | **Done** (91 suites: 14 ECDHE + 6 RSA + 7 DHE_RSA + 6 DHE_DSS + 6 DH_ANON + 2 ECDH_ANON + 20 PSK + 6 CCM + 2 CCM_8 + 4 PSK+CCM + 8 PSK CBC-SHA256/SHA384 + ECDHE_PSK GCM + 10 CCM/CCM_8 completion) |
| Session Resumption (ID-based) | RFC 5246 §7.4.1.2 | **Done** |
| Client Certificate Auth (mTLS) | RFC 5246 §7.4.4 | **Done** |
| Renegotiation Indication | RFC 5746 | **Done** (Phase 35 initial, Phase 68 full renegotiation) |
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
| Secure Renegotiation Indication | RFC 5746 | **Done** (Phase 68: full renegotiation) |
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

Closes test coverage gaps, CMS EdDSA stub, enc CLI limitation, and TLS 1.2 OCSP/SCT implementation.

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

#### Phase 53: C Test Vectors Round 2 + CertificatePolicies + CMS Chain/NoAttr Tests — DONE

Ports additional C test vectors, adds CertificatePolicies extension parsing, CMS noattr verification, and RSA-PSS CMS support. 56 new PKI tests.

| Feature | Description | Status | Notes |
|---------|-------------|--------|-------|
| AKI/SKI test vector suite | 10 tests from C akiski_suite (15 PEM files) | **Done** | Key match/mismatch, no AKI/SKI, critical, issuer+serial, multilevel |
| Extension edge cases | 10 tests: duplicate extensions, malformed KeyUsage, zero/large serial | **Done** | DER test vectors from C certcheck/extensions dirs |
| Cert parsing edge cases | 10 tests: missing issuer/pubkey/sigalg, SAN-no-subject, email-in-DN, TeletexString, DSA | **Done** | Real C test vector DER files |
| CertificatePolicies | Types + parsing + 5 tests (RFC 5280 §4.2.1.4) | **Done** | anyPolicy, CPS qualifier, builder roundtrip |
| CMS noattr verification | 11 tests: P-256/P-384/P-521/RSA attached+detached without signed attributes | **Done** | Added RSA-PSS CMS verify support |
| CMS chain cert tests | 2 tests: chain cert parsing + 3-level chain verification | **Done** | root → mid_ca → device chain |
| Sig param consistency | 3 tests: RSA, RSA-PSS, SM2 inner/outer AlgId match | **Done** | Chain verification with C sigParam test vectors |
| CSR parse/verify | 5 tests: RSA/ECDSA/SM2 CSR parsing + signature verification | **Done** | C test vector PEM CSR files |

**Scope**: `hitls-utils/src/oid/mod.rs` (+3 OIDs), `hitls-pki/src/x509/mod.rs` (CertificatePolicies + 30 tests), `hitls-pki/src/x509/verify.rs` (+13 tests), `hitls-pki/src/cms/mod.rs` (RSA-PSS verify + 13 tests), `tests/vectors/` (~50 copied test vector files)

#### Phase 51: C Test Vectors Porting + CMS Real File Tests + PKCS#12 Interop — DONE

52 new PKI tests: chain verification with real C project certs, CMS real file parsing/verification, PKCS#12 interop, cert parsing edge cases.

#### Phase 52: X.509 Extension Parsing + EKU/SAN/AKI/SKI Enforcement + CMS SKI Lookup — DONE

39 new PKI tests: typed extension parsing for EKU/SAN/AKI/SKI/AIA/NameConstraints, EKU enforcement in chain verifier, AKI/SKI issuer matching, CMS SKI signer lookup, Name Constraints enforcement.

#### Phase 54: PKI Signature Coverage + OCSP/CRL Testing + CMS Error Paths — DONE

41 new PKI tests: Ed448/SM2/RSA-PSS verify in cert/CRL/OCSP, OCSP verify_signature tests, CRL DER test vectors from C, CMS EnvelopedData error paths.

#### Phase 55: TLS RFC 5705 Key Export + CMS Detached Sign + pkeyutl Completeness — DONE

24 new tests: TLS 1.3/1.2 export_keying_material (RFC 5705/8446 §7.5), CMS detached SignedData, PKCS#8 Ed448/X448, SPKI parsing, pkeyutl derive/sign/verify.

#### Phase 56: Integration Test Expansion + TLCP Public API + Code Quality — DONE

30 new tests: ML-KEM panic→Result fix, TLCP public handshake-in-memory API, 5 DTLS 1.2 + 4 TLCP + 3 DTLCP + 4 mTLS integration tests, 12 TLS 1.3 server unit tests.

#### Phase 57–61: Unit Test Coverage Expansion — DONE

175 new tests across Phase 57–61, systematically covering under-tested modules:

| Phase | Tests | Key Coverage Areas |
|-------|-------|--------------------|
| Phase 57 | +40 | X25519 RFC 7748 iterated vectors, HKDF error paths, SM3/SM4 incremental, Base64/PEM negative, anti-replay edges, TLS 1.2 client/DTLS state machines |
| Phase 58 | +36 | Ed25519 RFC 8032 vectors, ECDSA negative cases, ASN.1 decoder negatives, HMAC RFC 2202/4231, ChaCha20-Poly1305, TLS 1.3/1.2 wrong-state |
| Phase 59 | +35 | CFB/OFB/ECB/XTS edge cases, ML-KEM/ML-DSA negative, DRBG reseed, GMAC/CMAC NIST vectors, SHA-1 million-a, scrypt/PBKDF2, TLS transcript hash |
| Phase 60 | +36 | CTR/CCM/GCM/KeyWrap negatives + NIST vectors, DSA wrong-key, HPKE tampered/PSK, HybridKEM, SM3, Entropy health, Privacy Pass |
| Phase 61 | +34 | RSA cross-padding/OAEP/cross-key, ECDH key validation, SM2 public-only, ElGamal/Paillier ct manipulation, ECC infinity, MD5/SM4/SHA-2/SHA-3/AES edges, BigNum arithmetic, OTP/SPAKE2+ boundaries |

#### Phase 62: TLS 1.2 CCM Cipher Suites (RFC 6655 / RFC 7251) -- DONE

6 AES-CCM cipher suites for TLS 1.2 with 8 new tests (3 AEAD + 5 record layer).

| Feature | Standard | Status |
|---------|----------|--------|
| TLS_RSA_WITH_AES_128_CCM (0xC09C) | RFC 6655 | **Done** |
| TLS_RSA_WITH_AES_256_CCM (0xC09D) | RFC 6655 | **Done** |
| TLS_DHE_RSA_WITH_AES_128_CCM (0xC09E) | RFC 6655 | **Done** |
| TLS_DHE_RSA_WITH_AES_256_CCM (0xC09F) | RFC 6655 | **Done** |
| TLS_ECDHE_ECDSA_WITH_AES_128_CCM (0xC0AC) | RFC 7251 | **Done** |
| TLS_ECDHE_ECDSA_WITH_AES_256_CCM (0xC0AD) | RFC 7251 | **Done** |
| AesCcmAead adapter (hitls_crypto::modes::ccm) | — | **Done** |
| CLI list command updated | — | **Done** |

#### Phase 63: CCM_8 + PSK+CCM Cipher Suites -- DONE

TLS 1.3 AES_128_CCM_8_SHA256 (0x1305) with 8-byte AEAD tag, 2 TLS 1.2 CCM_8 suites (RSA), 4 TLS 1.2 PSK+CCM suites, AesCcm8Aead adapter, 12 new tests.

| Feature | Standard | Status |
|---------|----------|--------|
| TLS_AES_128_CCM_8_SHA256 (0x1305) | RFC 8446 | **Done** |
| TLS_RSA_WITH_AES_128_CCM_8 (0xC0A0) | RFC 6655 | **Done** |
| TLS_RSA_WITH_AES_256_CCM_8 (0xC0A1) | RFC 6655 | **Done** |
| TLS_PSK_WITH_AES_256_CCM (0xC0A5) | RFC 6655 | **Done** |
| TLS_DHE_PSK_WITH_AES_128_CCM (0xC0A6) | RFC 6655 | **Done** |
| TLS_DHE_PSK_WITH_AES_256_CCM (0xC0A7) | RFC 6655 | **Done** |
| TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 (0xD005) | RFC 7251 | **Done** |
| AesCcm8Aead adapter (8-byte tag) | — | **Done** |

#### Phase 64: PSK CBC-SHA256/SHA384 + ECDHE_PSK GCM Cipher Suites -- DONE

8 new TLS 1.2 cipher suites for PSK variants with CBC-SHA256/SHA384 and ECDHE_PSK with GCM, completing PSK cipher suite coverage. 5 new tests.

| Feature | Standard | Status |
|---------|----------|--------|
| TLS_PSK_WITH_AES_128_CBC_SHA256 (0x00AE) | RFC 5487 | **Done** |
| TLS_PSK_WITH_AES_256_CBC_SHA384 (0x00AF) | RFC 5487 | **Done** |
| TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 (0x00B2) | RFC 5487 | **Done** |
| TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 (0x00B3) | RFC 5487 | **Done** |
| TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 (0x00B6) | RFC 5487 | **Done** |
| TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 (0x00B7) | RFC 5487 | **Done** |
| TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 (0xD001) | draft-ietf-tls-ecdhe-psk-aead | **Done** |
| TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 (0xD002) | draft-ietf-tls-ecdhe-psk-aead | **Done** |

#### Phase 66: DHE_DSS Cipher Suites (DSA Authentication for TLS 1.2) -- DONE

6 new TLS 1.2 DHE_DSS cipher suites with DSA authentication (RFC 5246). New `AuthAlg::Dsa` variant, `DSA_SHA256`/`DSA_SHA384` signature schemes, `ServerPrivateKey::Dsa` for server signing, DSA SKE verification via SPKI. 8 new tests.

| Feature | Standard | Status |
|---------|----------|--------|
| TLS_DHE_DSS_WITH_AES_128_CBC_SHA (0x0032) | RFC 5246 | **Done** |
| TLS_DHE_DSS_WITH_AES_256_CBC_SHA (0x0038) | RFC 5246 | **Done** |
| TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 (0x0040) | RFC 5246 | **Done** |
| TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 (0x006A) | RFC 5246 | **Done** |
| TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 (0x00A2) | RFC 5246 | **Done** |
| TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 (0x00A3) | RFC 5246 | **Done** |
| AuthAlg::Dsa + DSA_SHA256/SHA384 signature schemes | — | **Done** |
| ServerPrivateKey::Dsa (params_der + private_key) | — | **Done** |

#### Phase 67: DH_ANON + ECDH_ANON Cipher Suites (Anonymous Key Exchange for TLS 1.2) -- DONE

8 new TLS 1.2 anonymous cipher suites with no authentication (RFC 5246 / RFC 4492). New `KeyExchangeAlg::DheAnon`/`EcdheAnon`, `AuthAlg::Anon`, unsigned ServerKeyExchange codec (`ServerKeyExchangeDheAnon`/`ServerKeyExchangeEcdheAnon`), anonymous handshake flow (no Certificate, no signature). 10 new tests.

| Feature | Standard | Status |
|---------|----------|--------|
| TLS_DH_ANON_WITH_AES_128_CBC_SHA (0x0034) | RFC 5246 | **Done** |
| TLS_DH_ANON_WITH_AES_256_CBC_SHA (0x003A) | RFC 5246 | **Done** |
| TLS_DH_ANON_WITH_AES_128_CBC_SHA256 (0x006C) | RFC 5246 | **Done** |
| TLS_DH_ANON_WITH_AES_256_CBC_SHA256 (0x006D) | RFC 5246 | **Done** |
| TLS_DH_ANON_WITH_AES_128_GCM_SHA256 (0x00A6) | RFC 5246 | **Done** |
| TLS_DH_ANON_WITH_AES_256_GCM_SHA384 (0x00A7) | RFC 5246 | **Done** |
| TLS_ECDH_ANON_WITH_AES_128_CBC_SHA (0xC018) | RFC 4492 | **Done** |
| TLS_ECDH_ANON_WITH_AES_256_CBC_SHA (0xC019) | RFC 4492 | **Done** |
| KeyExchangeAlg::DheAnon/EcdheAnon + AuthAlg::Anon | — | **Done** |
| Unsigned ServerKeyExchange codec (DheAnon/EcdheAnon) | — | **Done** |

#### Phase 68: TLS 1.2 Renegotiation (RFC 5746) -- DONE

Server-initiated TLS 1.2 renegotiation with full RFC 5746 verify_data validation, HelloRequest message type, NoRenegotiation alert, re-handshake over encrypted connection (both sync and async paths). 10 new tests.

| Feature | Standard | Status |
|---------|----------|--------|
| HelloRequest message type (0) + codec | RFC 5246 | **Done** |
| NoRenegotiation alert (100) | RFC 5746 | **Done** |
| `allow_renegotiation` config option | — | **Done** |
| Client renegotiation support (reset_for_renegotiation, verify_data in renegotiation_info) | RFC 5746 | **Done** |
| Server renegotiation support (HelloRequest, verify_data validation) | RFC 5746 | **Done** |
| Server renegotiation_info in initial ServerHello (RFC 5746 fix) | RFC 5746 | **Done** |
| Renegotiating connection state + re-handshake over encrypted connection | RFC 5246 | **Done** |
| Async renegotiation (tokio) | — | **Done** |
| No session resumption during renegotiation (always full handshake) | — | **Done** |
| Application data buffering during renegotiation | — | **Done** |

#### Phase 69: Connection Info APIs + Graceful Shutdown + ALPN Completion -- DONE

ConnectionInfo struct (peer certs, ALPN, SNI, named group, verify_data), TLS 1.3 ALPN (client + server), TLS 1.2 client ALPN parsing, close_notify tracking, graceful shutdown, public getters on all 8 connection types. 8 new tests.

| Feature | Standard | Status |
|---------|----------|--------|
| ConnectionInfo struct | — | **Done** |
| TLS 1.3 ALPN (client + server) | RFC 7301 | **Done** |
| TLS 1.2 client ALPN parsing | RFC 7301 | **Done** |
| Graceful shutdown (close_notify tracking) | RFC 5246/8446 | **Done** |
| Public getter methods on all 8 connection types | — | **Done** |

#### Phase 70: Hostname Verification + Certificate Chain Validation + SNI Callback -- DONE

Security-critical: client now validates server certificate chain against trusted CAs and verifies hostname matching. RFC 6125 hostname verification (SAN/CN, wildcards, IP), certificate chain validation via CertificateVerifier, CertVerifyCallback for custom verification, SniCallback for server cert selection. Wired into all 5 client handshake paths. 15 new tests.

| Feature | Standard | Status |
|---------|----------|--------|
| Hostname verification (SAN dNSName/iPAddress, wildcard, CN fallback) | RFC 6125 / RFC 9525 | **Done** |
| Certificate chain validation (CertificateVerifier + trusted_certs) | RFC 5280 | **Done** |
| CertVerifyCallback (custom verification override) | — | **Done** |
| SniCallback (server cert selection by hostname) | — | **Done** |
| SniAction enum (Accept/AcceptWithConfig/Reject/Ignore) | — | **Done** |
| verify_hostname config option (default: true) | — | **Done** |
| PkiError::HostnameMismatch error variant | — | **Done** |
| Wired into TLS 1.3/1.2/DTLS 1.2/TLCP/DTLCP client paths | — | **Done** |
| SNI callback in TLS 1.3 + TLS 1.2 server | — | **Done** |

#### Phase 65: PSK CCM Completion + CCM_8 Authentication Cipher Suites -- DONE

10 new TLS 1.2 cipher suites completing PSK+CCM and CCM_8 coverage across all key exchange types. 11 new tests.

| Feature | Standard | Status |
|---------|----------|--------|
| TLS_PSK_WITH_AES_128_CCM (0xC0A4) | RFC 6655 | **Done** |
| TLS_PSK_WITH_AES_128_CCM_8 (0xC0A8) | RFC 6655 | **Done** |
| TLS_PSK_WITH_AES_256_CCM_8 (0xC0A9) | RFC 6655 | **Done** |
| TLS_DHE_PSK_WITH_AES_128_CCM_8 (0xC0AA) | RFC 6655 | **Done** |
| TLS_DHE_PSK_WITH_AES_256_CCM_8 (0xC0AB) | RFC 6655 | **Done** |
| TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 (0xD005) | RFC 7251 | **Done** |
| TLS_DHE_RSA_WITH_AES_128_CCM_8 (0xC0A2) | RFC 6655 | **Done** |
| TLS_DHE_RSA_WITH_AES_256_CCM_8 (0xC0A3) | RFC 6655 | **Done** |
| TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 (0xC0AE) | RFC 7251 | **Done** |
| TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 (0xC0AF) | RFC 7251 | **Done** |

#### Phase 71: Server-Side Session Cache + Session Expiration + Cipher Preference -- DONE

Server-side `Arc<Mutex<dyn SessionCache>>` in TlsConfig, auto-store after full handshake, auto-lookup on ClientHello, InMemorySessionCache with TTL expiration (default 2h), cleanup(), cipher_server_preference config. Wired into sync+async TLS 1.2 server + renegotiation + TLS 1.3. 13 new tests.

| Feature | Status |
|---------|--------|
| `Arc<Mutex<dyn SessionCache>>` in TlsConfig | **Done** |
| Auto-store session after full handshake | **Done** |
| Auto-lookup session on ClientHello | **Done** |
| InMemorySessionCache with TTL expiration (default 2h) | **Done** |
| `cleanup()` method to evict expired sessions | **Done** |
| `cipher_server_preference` config (default: true) | **Done** |
| Wired into sync+async TLS 1.2 server + renegotiation | **Done** |
| TLS 1.3 cipher preference | **Done** |

#### Phase 72: Client-Side Session Cache + Write Record Fragmentation -- DONE

Client auto-store sessions after handshake/NST, auto-lookup from cache by server_name, explicit resumption_session takes priority, write() auto-splits data into max_fragment_size chunks across all 8 connection types (4 sync + 4 async). 12 new tests.

| Feature | Status |
|---------|--------|
| Client auto-store session after handshake/NST | **Done** |
| Auto-lookup from cache by `server_name` | **Done** |
| Explicit `resumption_session` takes priority over cache | **Done** |
| TLS 1.2 `session_resumption` flag guard | **Done** |
| Write record fragmentation (auto-split by `max_fragment_size`) | **Done** |
| All 8 connection types (4 sync + 4 async) | **Done** |

#### Testing-Phase 72: CLI Command Unit Tests + Session Cache Concurrency -- DONE

72 new tests: dgst/x509cmd/genpkey/pkey/req/crl/verify CLI command unit tests (+66) and session cache Arc<Mutex<>> concurrency tests (+6).

#### Phase 73: KeyUpdate Loop Protection + Max Fragment Length (RFC 6066) + Signature Algorithms Cert (RFC 8446 §4.2.3) -- DONE

KeyUpdate recv counter with 128-limit DoS protection, MaxFragmentLength enum + codec + TLS 1.2 client/server negotiation + record layer enforcement, signature_algorithms_cert codec + TLS 1.3 ClientHello + server parsing. 13 new tests.

| Feature | Standard | Status |
|---------|----------|--------|
| KeyUpdate loop protection (128 consecutive limit) | RFC 8446 | **Done** |
| Max Fragment Length (512/1024/2048/4096) | RFC 6066 | **Done** |
| MaxFragmentLength client/server negotiation (TLS 1.2) | RFC 6066 | **Done** |
| Record layer enforcement of negotiated fragment size | RFC 6066 | **Done** |
| Signature Algorithms Cert extension | RFC 8446 §4.2.3 | **Done** |
| TLS 1.3 ClientHello building + server parsing | RFC 8446 | **Done** |

#### Testing-Phase 73: Async TLS 1.3 Unit Tests + Cipher Suite Integration -- DONE

33 new tests: 12 async TLS 1.3 connection tests + 21 TCP loopback cipher suite integration tests covering CCM/CCM_8/PSK/DH_ANON/ECDH_ANON/TLS 1.3 variants.

#### Phase 74: Certificate Authorities (RFC 8446 §4.2.4) + Early Exporter Master Secret + DTLS 1.2 Session Cache -- DONE

certificate_authorities codec + config + TLS 1.3 ClientHello + server parsing, early exporter master secret derivation + export_early_keying_material() API, DTLS 1.2 session cache auto-store. 15 new tests.

| Feature | Standard | Status |
|---------|----------|--------|
| Certificate Authorities extension codec | RFC 8446 §4.2.4 | **Done** |
| TLS 1.3 ClientHello + server parsing | RFC 8446 | **Done** |
| Early exporter master secret derivation | RFC 8446 §7.5 | **Done** |
| `export_early_keying_material()` API on all 4 TLS 1.3 connections | RFC 8446 | **Done** |
| DTLS 1.2 session cache auto-store by server_name/session_id | RFC 6347 | **Done** |

#### Testing-Phase 74: Fuzz Seed Corpus + Error Scenario Integration Tests -- DONE

66 binary seed files across all 10 fuzz targets + 18 integration tests covering version/cipher mismatch, PSK wrong key, ALPN, concurrent connections, 64KB fragmentation, ConnectionInfo, graceful shutdown.

#### Testing-Phase 75: Phase 74 Feature Integration Tests + Async Export Unit Tests -- DONE

16 new tests: 10 integration tests (certificate_authorities, export_keying_material, session cache resumption) + 6 async unit tests (export APIs, CA config).

#### Phase 75: PADDING (RFC 7685) + OID Filters (RFC 8446 §4.2.5) + DTLS 1.2 Abbreviated Handshake -- DONE

PADDING type 21 codec + config padding_target + TLS 1.3 ClientHello integration, OID Filters type 48 codec + config oid_filters + TLS 1.3 CertificateRequest, DTLS 1.2 abbreviated handshake (session cache lookup + abbreviated flow). 15 new tests.

| Feature | Standard | Status |
|---------|----------|--------|
| PADDING extension (type 21) codec + config | RFC 7685 | **Done** |
| TLS 1.3 ClientHello padding integration | RFC 7685 | **Done** |
| OID Filters extension (type 48) codec + config | RFC 8446 §4.2.5 | **Done** |
| TLS 1.3 CertificateRequest OID Filters | RFC 8446 | **Done** |
| DTLS 1.2 abbreviated handshake (session resumption) | RFC 6347 | **Done** |

#### Phase 76: Async DTLS 1.2 + Heartbeat Extension (RFC 6520) + GREASE (RFC 8701) -- DONE

AsyncDtls12ClientConnection + AsyncDtls12ServerConnection with full/abbreviated handshake, read/write/shutdown, anti-replay, session cache. Heartbeat type 15 codec + config. GREASE config flag + ClientHello injection. 19 new tests.

| Feature | Standard | Status |
|---------|----------|--------|
| `AsyncDtls12ClientConnection<S>` (full + abbreviated handshake) | RFC 6347 | **Done** |
| `AsyncDtls12ServerConnection<S>` (full + abbreviated handshake) | RFC 6347 | **Done** |
| Async read/write/shutdown with anti-replay + epoch management | RFC 6347 | **Done** |
| Session cache auto-store (client + server) | RFC 6347 | **Done** |
| Heartbeat extension type 15 codec (build/parse) | RFC 6520 | **Done** |
| `heartbeat_mode` config (0=disabled, 1=peer_allowed, 2=peer_not_allowed) | RFC 6520 | **Done** |
| GREASE `grease` config flag | RFC 8701 | **Done** |
| GREASE injection: cipher suites, extensions, versions, groups, sig_algs, key_share | RFC 8701 | **Done** |

#### Testing-Phase 76: cert_verify Unit Tests + Config Callbacks + Integration Tests -- DONE

26 new tests: 13 cert_verify unit tests (verify_server_certificate code paths), 7 config callback tests (CertVerifyCallback/SniCallback/key_log_callback), 6 integration tests (TLS 1.3/1.2 cert_verify_callback, key_log_callback, renegotiation).

#### Phase 77: TLS Callback Framework + Missing Alert Codes + CBC-MAC-SM4 -- DONE

| Feature | Description |
|---------|-------------|
| TLS Callback Framework | 7 callbacks: `MsgCallback`, `InfoCallback`, `RecordPaddingCallback`, `DhTmpCallback`, `CookieGenCallback`, `CookieVerifyCallback`, `ClientHelloCallback` + `ClientHelloInfo`/`ClientHelloAction` |
| Record Padding Callback | Wired into TLS 1.3 `RecordEncryptor::encrypt_record()` for custom padding |
| Cookie Callbacks | Wired into DTLS 1.2 + DTLCP servers for custom cookie gen/verify |
| ClientHello Callback | Wired into TLS 1.3 + TLS 1.2 servers (after SNI, before cipher selection) |
| Missing Alert Codes | 6 legacy codes: `DecryptionFailed(21)`, `DecompressionFailure(30)`, `NoCertificateReserved(41)`, `ExportRestrictionReserved(60)`, `CertificateUnobtainable(111)`, `BadCertificateHashValue(114)` |
| CBC-MAC-SM4 | SM4 block cipher CBC-MAC with zero-padding, feature-gated `cbc-mac = ["sm4"]` |

21 new tests: 10 config callback tests, 1 alert test, 10 CBC-MAC-SM4 tests (rebased on Testing-Phase 80, 2218→2239).

#### Phase 78: Trusted CA Keys (RFC 6066 §6) + USE_SRTP (RFC 5764) + STATUS_REQUEST_V2 (RFC 6961) + CMS AuthenticatedData (RFC 5652 §9) -- DONE

| Feature | Description |
|---------|-------------|
| Trusted CA Keys (RFC 6066 §6, type 3) | ExtensionType constant + codec (build/parse) + config `trusted_ca_keys: Vec<TrustedAuthority>` + ClientHello (TLS 1.3 + 1.2) |
| USE_SRTP (RFC 5764, type 14) | ExtensionType constant + codec (build/parse) + config `srtp_profiles: Vec<u16>` + ClientHello (TLS 1.3 + 1.2) |
| STATUS_REQUEST_V2 (RFC 6961, type 17) | ExtensionType constant + codec (build/parse) + config `enable_ocsp_multi_stapling: bool` + ClientHello (TLS 1.3 + 1.2) |
| CMS AuthenticatedData (RFC 5652 §9) | AuthenticatedData struct + parse/encode + create (`CmsMessage::authenticate`) + verify (`CmsMessage::verify_mac`) + HMAC-SHA-256/384/512 |

15 new tests: 9 codec tests + 3 config tests + 5 CMS AuthenticatedData tests (2239→2254).

#### Other Identified Gaps (Low Priority / Deferred)

| Category | Item | Priority | Notes |
|----------|------|----------|-------|
| Crypto | SM4 CTR-DRBG variant | Low | CTR-DRBG currently supports AES only |
| Crypto | eFrodoKEM variants | Low | Ephemeral FrodoKEM optimization |
| Crypto | ~~CBC-MAC-SM4 (standalone)~~ | ~~Low~~ | **Done** (Phase 77, feature-gated `cbc-mac`) |
| Crypto | Multi-buffer SHA-256 | Low | Performance optimization, not a functional gap |
| Architecture | EAL Provider Framework | Low | Rust trait dispatch is more idiomatic than C plugin model |
| CLI | genrsa, rsa, prime, keymgmt, provider, sm | Low | Functionality covered by existing commands (genpkey, pkey, etc.) |

### Coverage Summary (vs. C Implementation)

| Component | C (lines) | Rust (lines) | Feature Coverage | Remaining Gaps |
|-----------|-----------|--------------|------------------|----------------|
| Crypto Algorithms | ~132K | ~26K | **100%** (all 48 modules + SM4-CCM + hardware AES + all 13 DH groups + FIPS/CMVP + entropy health testing + Ed448/X448/Curve448) | — |
| TLS Protocol | ~52K | ~14K | **100%** (TLS 1.3 + 1.2 + DTLS 1.2 + TLCP + DTLCP + 10 connection types (5 sync + 5 async) + X25519MLKEM768 + SM4-GCM/CCM + AES-CCM (RFC 6655/7251) + AES-CCM_8 + PSK+CCM + PSK CBC-SHA256/SHA384 + ECDHE_PSK GCM + DHE_DSS (RFC 5246) + DH_ANON/ECDH_ANON (RFC 5246/4492) + renegotiation (RFC 5746) + hostname verification (RFC 6125) + cert chain validation + CertVerifyCallback/SniCallback + 7 TLS callbacks + server/client session cache + write record fragmentation + KeyUpdate loop protection + Max Fragment Length (RFC 6066) + Signature Algorithms Cert + PADDING/OID Filters + Heartbeat (RFC 6520) + GREASE (RFC 8701) + Trusted CA Keys (RFC 6066) + USE_SRTP (RFC 5764) + STATUS_REQUEST_V2 (RFC 6961) + RSL/SCSV/OCSP/SCT + async I/O + key logging + custom extensions + all 5 FFDHE groups) | — |
| PKI / X.509 | ~17K | ~4K | **100%** (parse/verify/chain/CRL/OCSP/CSR/cert gen/to_text/hostname verification (RFC 6125)/PKCS#8/PKCS#12/CMS SignedData+EnvelopedData+EncryptedData+DigestedData+AuthenticatedData) | — |
| Base Support Layer | ~12K | ~2K | **95%** (ASN.1/Base64/PEM/OID/errors) | — |
| CLI Tools | ~8K | ~2.2K | **100%** (dgst/genpkey/x509/verify/enc/pkey/crl/req/s-client/s-server/list/rand/pkeyutl/speed/pkcs12/mac) | — |
| FIPS/CMVP | ~5K | ~0.6K | **90%** (state machine, 7 KATs incl. entropy, 3 PCTs, integrity check, feature-gated) | Conditional algorithm disabling |
| Test Infrastructure | ~20K | ~3.5K | **95%** (2254 tests + 5000+ Wycheproof vectors + 10 fuzz targets + security audit) | SDV compliance tests |
| **Total** | **~460K** | **~53K** | **~99%** (production-ready for modern TLS deployments, 91 TLS 1.2 cipher suites) | Low-priority items only |

## Minimum Supported Rust Version

**MSRV: 1.75**

## License

Licensed under the [Mulan Permissive Software License, Version 2](http://license.coscl.org.cn/MulanPSL2).

## Acknowledgments

This project is a Rust rewrite of [openHiTLS](https://gitee.com/openhitls/openhitls), an open-source cryptographic and TLS library originally written in C.
