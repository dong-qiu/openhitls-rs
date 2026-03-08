# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in openHiTLS-rs, please report it responsibly:

1. **Do NOT** open a public issue.
2. Email the maintainers with a detailed description of the vulnerability, including reproduction steps.
3. Allow reasonable time for a fix before public disclosure.

## Security Design

### Constant-Time Operations

All cryptographic comparisons (MAC tags, Finished messages, signatures) use `subtle::ConstantTimeEq` to prevent timing side-channel attacks. The `==` operator is never used for comparing secret data.

### Zeroize on Drop

All structs holding secret material (private keys, symmetric keys, master secrets, session keys) implement `Zeroize` and `ZeroizeOnDrop` via the `zeroize` crate. This ensures secrets are cleared from memory when no longer needed.

### Unsafe Code

Unsafe code is localized to 96 blocks across `hitls-bignum` and `hitls-crypto`, primarily for:

| Category | Files | Purpose |
|----------|-------|---------|
| Hardware intrinsics | `aes/aes_ni.rs`, `aes/aes_neon.rs`, `ghash/clmul.rs`, `ghash/pmull.rs`, `chacha20/neon.rs`, `chacha20/sse2.rs`, `sha1/ce.rs`, `sha2/sha_ni.rs`, `sha2/sha512_ce.rs`, `sha3/armv8.rs` | CPU feature-gated SIMD acceleration |
| Benes network | `mceliece/benes.rs` | Pointer arithmetic for Classic McEliece |
| BigNum CIOS | `hitls-bignum/src/montgomery.rs` | Montgomery multiplication via `MaybeUninit` |

All unsafe blocks are guarded by `is_x86_feature_detected!` / `is_aarch64_feature_detected!` runtime checks or `MaybeUninit` initialization proofs.

### Random Number Generation

All randomness is sourced from `getrandom` (OS-provided CSPRNG). No userspace PRNGs are used for key generation or nonce creation.

## Algorithm Status

### Production Ready

- AES-128/256 (ECB, CBC, CTR, GCM, CCM, XTS)
- ChaCha20-Poly1305
- SHA-1, SHA-256, SHA-384, SHA-512, SHA-3, SHAKE128/256
- HMAC, HKDF, PBKDF2, scrypt
- RSA (2048+ bit, PKCS#1v1.5, OAEP, PSS)
- ECDSA (P-256, P-384, P-521)
- ECDH (P-256, P-384, P-521)
- Ed25519, X25519
- SM2, SM3, SM4 (Chinese national standards)
- TLS 1.3, TLS 1.2, DTLS 1.2, TLCP
- X.509 certificate parsing and chain verification

### Experimental / Research

- ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205) — Post-quantum algorithms
- FrodoKEM, Classic McEliece — Alternative PQ KEMs
- SM9 — Chinese identity-based encryption
- Paillier, ElGamal — Homomorphic/threshold schemes
- XMSS — Hash-based signatures

### Known Limitations

1. **ECDSA DER encoding leniency**: The ASN.1 parser accepts some non-strict DER encodings (BER, missing leading zeros). This does not affect signature security but may allow signature malleability. Tracked via Wycheproof test vectors.

2. **ECDH SPKI validation**: When parsing X.509 SubjectPublicKeyInfo for ECDH, curve parameters in the DER structure are not validated against the expected curve. Applications should validate curve choice at a higher level.

3. **No side-channel hardened ECC**: Elliptic curve operations use standard double-and-add algorithms with some constant-time measures, but are not fully hardened against all power/EM side channels.

## Testing

- **4,065+ unit and integration tests** across all crates (35 ignored for timing/network/slow tests)
- **Wycheproof test vectors**: 5,000+ edge-case vectors from Google/C2SP covering AES-GCM, ChaCha20-Poly1305, ECDSA, ECDH, Ed25519, X25519, RSA, HKDF, HMAC, AES-CCM, AES-CBC
- **Fuzz targets**: 68 libfuzzer targets (429 corpus seeds) covering parsers, protocols, AEAD, crypto verification, PQC, and X.509
- **Constant-time verification**: 16 dudect-style timing tests with Welch's t-test
- **Differential testing**: 5 OpenSSL cross-validation tests (SHA-256, SHA-384, HMAC, AES-GCM, AES-CBC)
- **Formal verification**: Kani proof harnesses for constant-time primitives
- **Miri**: Memory safety verification for bignum and utils crates
- **ASan**: AddressSanitizer CI job on nightly
- **Clippy**: Zero-warning policy with `-D warnings` (cognitive complexity threshold: 15)
- **cargo-audit**: Automated dependency vulnerability scanning
- **cargo-deny**: Supply-chain policy enforcement (license, advisory, source restrictions)
- **cargo-vet**: Third-party dependency trust auditing
- **cargo-semver-checks**: API compatibility verification
- **Reproducible builds**: Binary reproducibility verification in CI
- **SBOM**: CycloneDX Software Bill of Materials generation with SLSA provenance

## Disclaimer

This library is provided as-is for research and educational purposes. It has not undergone a formal third-party security audit. Use in production systems is at your own risk.
