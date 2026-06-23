# Changelog

All notable changes to openHiTLS-rs are documented here. `DEV_LOG.md` holds the
exhaustive per-phase record; this file is the release-level summary.

## [0.2.0] — 2026-06-24

A large milestone release: **480 commits since `v0.1`**, completing C→Rust
feature parity and bringing the TLS, PKI, PQC, FIPS and 国密 surfaces to
production-grade, then hardening them against an external protocol-conformance
suite.

### Cryptography (`hitls-crypto`, `hitls-bignum`)
- **Post-quantum**: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205),
  XMSS / XMSS-MT (RFC 8391), HybridKEM (12 variants incl. X25519+ML-KEM and
  ECDH+ML-KEM), Classic McEliece, FrodoKEM.
- **HPKE** (RFC 9180) full mode matrix.
- **国密 (GM)**: SM2 (sign/verify/encrypt/key-exchange), SM3, SM4 (all modes),
  SM9 (sign/encrypt/key-exchange).
- **FIPS/CMVP**: CAST/KAT/PCT self-tests (incl. ML-KEM/ML-DSA/SLH-DSA),
  entropy health checks.
- **Hardware acceleration**: AES-NI, SHA-NI, SHA-512/SHA-3 CE, GHASH PMULL/CLMUL,
  ChaCha20 NEON/SSE2, VAES/VPCLMULQDQ, ML-KEM/ML-DSA NEON NTT, SHA256 multi-buffer.
- DRBG suite (CTR/Hash/HMAC, incl. SM4-CTR-DF); RSA (PKCS#1 v1.5, OAEP, PSS,
  ISO/IEC 9796-2); full ECC curve set (P-192…P-521, Brainpool, SM2);
  Ed25519/Ed448/X25519/X448; DSA/DH with precomputed tables.

### TLS (`hitls-tls`)
- **TLS 1.3 / 1.2, DTLS 1.2, TLCP, DTLCP** — 91 cipher suites, 10 connection
  types, synchronous **and** asynchronous I/O.
- ECH (split-CH, GREASE anti-fingerprinting, HRR continuation, downgrade
  protection), Post-Handshake Auth, in-handshake mTLS (client **and** server),
  external PSK, 0-RTT early data, certificate compression (RFC 8879),
  KeyUpdate, session resumption + tickets (incl. RFC 5077 ticket-key rotation),
  renegotiation, CRL revocation, EMS three-state policy.
- Callback subsystem: cert-verify, SNI, ClientHello, key-log, OCSP stapling,
  DTLS cookie, record-padding, custom extensions, session cache, **session
  ticket-key rotation**, and per-record **message observation**
  (`SSL_set_msg_callback` parity).

### PKI / Auth / CLI
- **X.509** parse/build/verify with chain validation (path-length,
  NameConstraints/CertificatePolicies parsing, EKU+KeyUsage, **minimum
  security-bits**, CRL/OCSP), hostname verification.
- **PKCS#8** (PBES2 with PRF agility + SM4-CBC / GM support), **PKCS#12**,
  **CMS** SignedData sign **and** verify for RSA-PKCS#1 / ECDSA / Ed25519 /
  SM2 / RSA-PSS (+ EnvelopedData, DigestedData, AuthenticatedData, **signer-chain
  trust validation**), **CRL** builder + extensions.
- `hitls-auth`: HOTP/TOTP, SPAKE2+ (RFC 9383), Privacy Pass (RFC 9474/9577/9578).
- `hitls-cli`: 18+ subcommands (dgst, genpkey, x509, verify, enc, pkey, crl,
  req, s-client, s-server, list, rand, pkeyutl, speed, pkcs12, mac, prime, kdf).

### Quality & assurance
- **9000+ tests**; **tlsfuzzer** protocol-conformance harness — full local
  sweep **6213 PASS / 0 FAIL / 0 XPASS** across 13 listener configurations
  (every remaining XFAIL is documented as accepted-by-design).
- 68 cargo-fuzz targets (OSS-Fuzz), Miri, Kani (formal model checking), dudect
  (constant-time), cargo-mutants, cargo-vet / cargo-deny (supply chain),
  AddressSanitizer, llvm-cov, cargo-semver-checks; OpenSSL 3.6 differential +
  interop; Wycheproof / NIST CAVP-ACVP / RFC / GM-T test vectors.
- Cross-model AI review pre-push gate.

### Notable fixes hardened in this release
- TLS 1.2 FFDHE premaster secret now strips leading zeros (RFC 5246 §8.1.2) —
  fixes an intermittent `bad_record_mac` against compliant peers.
- No-TLS-1.3 ClientHello now draws `protocol_version` (RFC 8446 §4.2.1).
- TLS 1.3 0-RTT-reject record-skip no longer deadlocks on adversarial garbage.
- Strict rejection of malformed `ec_point_formats` / EMS / zero-length ECDHE
  key-share with the spec-correct alerts.

### Notes
- MSRV **1.75**, edition 2021. License **MulanPSL-2.0**.
- Not published to crates.io; consume via git or path dependency.

## [0.1] — 2026-03-06

Initial tagged milestone — core crypto primitives, TLS scaffolding, and the
first performance-optimization pass. See `DEV_LOG.md` for detail.
