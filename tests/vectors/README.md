# Test Vectors

This directory contains standard test vectors for validating cryptographic implementations.

## Sources

- **NIST CAVP**: AES, SHA, RSA, ECDSA, DRBG
- **Wycheproof**: Edge case coverage (Google)
- **GM/T Standards**: SM2/SM3/SM4 test vectors
- **RFC Appendices**: HKDF, HMAC, ChaCha20, Curve25519
- **NIST PQC**: ML-KEM, ML-DSA, SLH-DSA test vectors
- **ACVP**: Automated Cryptographic Validation Protocol vectors

## Directory Structure

```
vectors/
├── aes/        # NIST CAVP AES test vectors
├── sha/        # NIST CAVP SHA test vectors
├── rsa/        # NIST FIPS 186 RSA test vectors
├── ecdsa/      # NIST FIPS 186 ECDSA test vectors
├── drbg/       # NIST SP 800-90A DRBG test vectors
├── hkdf/       # RFC 5869 HKDF test vectors
├── sm2/        # GM/T 0003 SM2 test vectors
├── sm3/        # GM/T 0004 SM3 test vectors
├── sm4/        # GM/T 0002 SM4 test vectors
├── mlkem/      # NIST PQC ML-KEM test vectors
├── mldsa/      # NIST PQC ML-DSA test vectors
└── wycheproof/ # Wycheproof edge case test vectors
```
