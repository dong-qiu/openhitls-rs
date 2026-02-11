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

Unsafe code is restricted to three files, all in the `hitls-crypto` crate:

| File | Purpose | Safety Justification |
|------|---------|---------------------|
| `aes/aes_ni.rs` | x86-64 AES-NI hardware acceleration | Guarded by `is_x86_feature_detected!("aes")` runtime check. Pointer casts are to aligned `[u8; 16]` arrays. |
| `aes/aes_neon.rs` | ARMv8 NEON AES acceleration | Guarded by `is_aarch64_feature_detected!("aes")` runtime check. Same alignment guarantees. |
| `mceliece/benes.rs` | Classic McEliece Benes network | Pointer arithmetic for efficient bitwise operations on fixed-size arrays. |

All other crates use `#![forbid(unsafe_code)]`.

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

- **997+ unit and integration tests** across all crates
- **Wycheproof test vectors**: 5000+ edge-case vectors from Google/C2SP covering AES-GCM, ChaCha20-Poly1305, ECDSA, ECDH, Ed25519, X25519, RSA, HKDF, HMAC, AES-CCM, AES-CBC
- **Fuzz targets**: 10 libfuzzer targets for parser code (ASN.1, Base64, PEM, X.509, CRL, PKCS#8, PKCS#12, CMS, TLS record, TLS handshake)
- **Miri**: Memory safety verification for bignum and utils crates
- **Clippy**: Zero-warning policy with `-D warnings`
- **cargo-audit**: Automated dependency vulnerability scanning

## Disclaimer

This library is provided as-is for research and educational purposes. It has not undergone a formal third-party security audit. Use in production systems is at your own risk.
