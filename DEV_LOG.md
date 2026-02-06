# openHiTLS Rust Migration — Development Log

## Phase 0: Project Scaffolding (Session 2026-02-06)

### Goals
- Initialize Rust workspace with all crate skeletons
- Set up CI/CD pipeline
- Configure linting, formatting, and testing infrastructure
- Create development log and documentation

### Completed Steps

#### 1. Workspace Root (`Cargo.toml`)
- Created workspace with 8 member crates
- Shared package metadata: version 0.1.0, edition 2021, Rust 1.75+, MulanPSL-2.0 license
- Workspace-level dependency declarations for consistency
- Release profile optimized: LTO, single codegen unit, abort on panic

#### 2. `hitls-types` — Common Types and Error Codes
**Files created:**
- `src/lib.rs` — Module root with `#![forbid(unsafe_code)]`
- `src/algorithm.rs` — Rust enums mapped from C `crypt_algid.h`:
  - `HashAlgId` (13 variants), `MacAlgId` (21 variants), `CipherAlgId` (37 variants)
  - `PkeyAlgId` (18 variants), `EccCurveId` (9 curves), `DhParamId` (13 groups)
  - `MlKemParamId`, `MlDsaParamId`, `SlhDsaParamId`, `FrodoKemParamId`
  - `McElieceParamId`, `HybridKemParamId`, `RandAlgId` (19 DRBG variants)
  - `KdfAlgId`, `PointFormat`
- `src/error.rs` — Error types using `thiserror`:
  - `CryptoError` — 30+ variants covering all crypto subsystems
  - `TlsError` — TLS protocol errors with `std::io::Error` support
  - `PkiError` — PKI/certificate errors

**Design decisions:**
- Used `thiserror` instead of manual `Display`/`Error` impls — more maintainable
- Each algorithm category has its own enum, rather than one giant `AlgId` — better type safety
- Preserved all algorithm variants from C even if not yet implemented

#### 3. `hitls-utils` — Utility Functions
**Files created:**
- `src/asn1/` — ASN.1 DER encoder/decoder:
  - `mod.rs` — `Tag`, `TagClass`, `Tlv` types, tag constants
  - `tag.rs` — Tag parsing/encoding with roundtrip tests
  - `decoder.rs` — Streaming `Decoder` with `read_tlv()`, `read_integer()`, `read_sequence()`, etc.
  - `encoder.rs` — `Encoder` builder with `write_integer()`, `write_sequence()`, etc.
- `src/base64/mod.rs` — RFC 4648 Base64 encode/decode with all standard test vectors passing
- `src/pem/mod.rs` — PEM parser/generator with multi-block support
- `src/oid/mod.rs` — OID type with DER serialization + well-known OID constants (RSA, EC, SM2, AES, etc.)

**Design decisions:**
- Self-implemented ASN.1, Base64, PEM (no external crate) for full control
- OID uses `Vec<u32>` arc representation with efficient DER encoding

#### 4. `hitls-bignum` — Big Number Arithmetic
**Files created:**
- `src/bignum.rs` — `BigNum` type: little-endian u64 limbs, `Zeroize` on drop, byte conversion
- `src/ops.rs` — Add, sub, mul, div_rem, mod_exp (square-and-multiply), cmp_abs
- `src/montgomery.rs` — `MontgomeryCtx` with N' computation via Newton's method
- `src/prime.rs` — Miller-Rabin primality test with small prime witnesses

**Design decisions:**
- u64 limbs for 64-bit platforms, DoubleLimb = u128 for multiplication
- All BigNums zeroized on drop (via `zeroize` crate)
- Placeholder division uses binary long division (will be optimized later)

#### 5. `hitls-crypto` — Cryptographic Algorithms
**Files created:**
- `src/lib.rs` — Module root with feature-gated submodule declarations
- `src/provider.rs` — Core trait definitions:
  - `Digest`, `HashAlgorithm` — Hash interface
  - `BlockCipher`, `Aead` — Symmetric cipher interfaces
  - `Mac` — MAC interface
  - `Kdf` — Key derivation interface
  - `Signer`, `Verifier` — Digital signature interfaces
  - `Kem`, `KeyAgreement` — Key exchange interfaces
- 38 algorithm submodule stubs (hash, cipher, MAC, asymmetric, PQC, KDF)

**Feature flags configured:**
- Default: aes, sha2, rsa, ecdsa, hmac
- Algorithm groups: pqc (mlkem + mldsa), tlcp (sm2 + sm3 + sm4)
- Hazmat flag for low-level API exposure

#### 6. `hitls-tls` — TLS Protocol
**Files created:**
- `src/lib.rs` — `TlsVersion`, `CipherSuite`, `TlsRole`, `TlsConnection` trait
- `src/config/mod.rs` — `TlsConfig` with builder pattern
- `src/record/mod.rs` — Record layer with parsing/serialization
- `src/handshake/mod.rs` — Handshake state machine enum + message types
- `src/alert/mod.rs` — Alert types (RFC 8446 Section 6 complete)
- `src/session/mod.rs` — `TlsSession`, `SessionCache` trait
- `src/extensions/mod.rs` — TLS extension type constants
- `src/crypt/mod.rs` — Named groups, signature schemes for TLS

#### 7. `hitls-pki` — PKI Certificate Management
**Files created:**
- `src/x509/mod.rs` — `Certificate`, `CertificateRequest`, `CertificateRevocationList` types
- `src/pkcs12/mod.rs` — `Pkcs12` container
- `src/cms/mod.rs` — CMS/PKCS#7 message types

#### 8. `hitls-auth` — Authentication Protocols
**Files created:**
- `src/otp/mod.rs` — HOTP/TOTP (RFC 4226/6238) scaffolding
- `src/spake2plus/mod.rs` — SPAKE2+ (RFC 9382) scaffolding
- `src/privpass/mod.rs` — Privacy Pass token types

#### 9. `hitls-cli` — Command-Line Tool
**Files created:**
- `src/main.rs` — CLI with `clap` derive: dgst, enc, genpkey, pkey, req, x509, verify, crl, s_client, s_server

#### 10. Infrastructure
- `.github/workflows/ci.yml` — CI pipeline: fmt, clippy, test (multi-OS + multi-Rust), audit, miri, bench
- `.gitignore`, `rustfmt.toml`, `clippy.toml`
- `tests/vectors/README.md` — Test vector directory structure
- `benches/crypto_bench.rs` — BigNum benchmark scaffold

### Build Status
- `cargo check --all-features`: **PASS** (warnings only — unused variables in todo!() stubs)
- `cargo test --all-features`: **PASS** — 24 tests pass (13 bignum + 11 utils)
- hitls-types: 0 warnings
- hitls-utils: 0 errors, 11 tests pass (ASN.1 tag, Base64, OID, PEM)
- hitls-bignum: 0 errors, 13 tests pass (add, sub, mul, div, prime, Montgomery)
- hitls-crypto: compiles with all features, placeholder warnings expected
- hitls-tls, hitls-pki, hitls-auth, hitls-cli: compile cleanly

### Architecture Summary

```
openhitls-rs/
├── Cargo.toml                     # Workspace (8 members)
├── crates/
│   ├── hitls-types/    (~300 LOC)  # Types, errors, algorithm IDs
│   ├── hitls-utils/    (~500 LOC)  # ASN.1, Base64, PEM, OID
│   ├── hitls-bignum/   (~600 LOC)  # Big number arithmetic
│   ├── hitls-crypto/   (~1500 LOC) # 38 algorithm modules + provider traits
│   ├── hitls-tls/      (~400 LOC)  # TLS protocol skeleton
│   ├── hitls-pki/      (~200 LOC)  # PKI/certificate types
│   ├── hitls-auth/     (~150 LOC)  # Auth protocol stubs
│   └── hitls-cli/      (~150 LOC)  # CLI tool with clap
├── tests/vectors/                  # Test vector directory
├── benches/                        # Benchmarks
└── .github/workflows/ci.yml       # CI pipeline
```

---

## Phase 1–2: Tooling + BigNum (Session 2026-02-06)

### Goals
- Fix compilation issues from Phase 0 scaffolding
- Improve BigNum: Montgomery multiplication, modular exponentiation, prime generation
- Add constant-time operations for side-channel safety

### Completed Steps

#### BigNum Improvements (`hitls-bignum`)
- `montgomery.rs` — Full Montgomery context: N' via Newton's method, to/from Montgomery form, Montgomery multiplication, modular exponentiation with sliding window
- `prime.rs` — Miller-Rabin primality test with configurable rounds + small prime sieve
- `rand.rs` — Cryptographic random BigNum generation (random_bits, random_odd, random_range) using `getrandom`
- `ct.rs` — Constant-time operations: ct_eq, ct_select, ct_sub_if_gte
- `ops.rs` — Added: sqr (squaring), mod_add, mod_sub, mod_mul, shl, shr, RSA small example test
- `gcd.rs` — GCD + modular inverse via extended Euclidean algorithm

### Build Status
- 45 bignum tests passing
- 11 utils tests passing
- Total: 56 workspace tests

---

## Phase 3: Hash + HMAC (Session 2026-02-06)

### Goals
- Implement complete SHA-2 family (SHA-256/224/512/384)
- Implement SM3 (Chinese national standard hash)
- Implement SHA-1 and MD5 (legacy, needed for TLS compatibility)
- Implement HMAC with generic hash support

### Completed Steps

#### 1. SHA-2 Family (`sha2/mod.rs`)
- SHA-256: FIPS 180-4 compliant, 64-round compression, MD padding
- SHA-224: Truncated SHA-256 with different initial values
- SHA-512: 80-round compression with u64 state words
- SHA-384: Truncated SHA-512 with different initial values
- Shared `update_32`/`finish_32` and `update_64`/`finish_64` helpers
- Implements `Digest` trait for all four variants
- **Tests**: RFC 6234 vectors — empty, "abc", two-block, incremental

#### 2. SM3 (`sm3/mod.rs`)
- GB/T 32905-2012 compliant, 64-round compression
- P0/P1 permutation functions, FF/GG boolean functions
- **Tests**: empty, "abc", 64-byte input

#### 3. SHA-1 (`sha1/mod.rs`)
- RFC 3174 compliant, 80-round compression with W[80] expansion
- **Tests**: empty, "abc", two-block, incremental

#### 4. MD5 (`md5/mod.rs`)
- RFC 1321 compliant, little-endian byte order
- 4 round functions (F/G/H/I), 64 sin-based constants, G_IDX message schedule
- **Tests**: RFC 1321 vectors — empty, "a", "abc", "message digest", alphabet, alphanumeric, numeric, incremental

#### 5. HMAC (`hmac/mod.rs`)
- RFC 2104 compliant
- Generic via `Box<dyn Digest>` + factory closure pattern
- Key hashing (keys > block_size), ipad/opad XOR
- `new`, `update`, `finish`, `reset`, `mac` (one-shot) API
- Zeroize key material on drop
- **Tests**: RFC 4231 test cases 1-4, 6-7 + reset functionality

### Bug Fixes
- Clippy `needless_range_loop` in SHA-1 (w[j] indexing) — fixed with enumerate
- Clippy `needless_range_loop` in SHA-2 (state[i] indexing) — fixed with enumerate+take
- Formatting fixes across all files via `cargo fmt`

### Build Status
- 30 hitls-crypto tests passing (new)
- 45 bignum + 11 utils = 56 (unchanged)
- **Total: 86 workspace tests**

---

## Phase 4: Symmetric Ciphers + Block Cipher Modes + KDF (Session 2026-02-06)

### Goals
- Implement AES-128/192/256 and SM4 block ciphers
- Implement ECB, CBC, CTR, GCM block cipher modes
- Implement HKDF and PBKDF2 key derivation functions

### Completed Steps

#### 1. AES Block Cipher (`aes/mod.rs`)
- FIPS 197 compliant AES-128/192/256
- S-box based implementation (no T-box): SBOX[256], INV_SBOX[256], RCON[10]
- Key expansion: Nk=key_len/4, Nr=Nk+6, SubWord + RotWord + RCON
- Encrypt: AddRoundKey → (SubBytes→ShiftRows→MixColumns→AddRoundKey)×(Nr-1) → SubBytes→ShiftRows→AddRoundKey
- Decrypt: AddRoundKey(Nr) → (InvShiftRows→InvSubBytes→AddRoundKey→InvMixColumns)×(Nr-1) → InvShiftRows→InvSubBytes→AddRoundKey(0)
- MixColumns via xtime, InvMixColumns via gf_mul
- `BlockCipher` trait implementation
- **Tests**: FIPS 197 Appendix B/C — AES-128 encrypt/decrypt, AES-256 encrypt/roundtrip, AES-192 roundtrip, invalid key

#### 2. SM4 Block Cipher (`sm4/mod.rs`)
- GB/T 32907-2016 compliant
- SBOX[256] + L/L' linear transforms, τ (parallel S-box substitution)
- 32-round Feistel structure with FK[4] and CK[32] constants
- Encrypt/decrypt share `crypt_block`; decrypt reverses round keys
- `BlockCipher` trait implementation
- **Tests**: GB/T 32907 Appendix A — encrypt, decrypt, roundtrip, invalid key

#### 3. ECB Mode (`modes/ecb.rs`)
- Simple block-by-block AES encryption/decryption
- Input must be multiple of block size (no padding)
- **Tests**: NIST SP 800-38A F.1 — AES-128, multi-block, invalid length

#### 4. CBC Mode (`modes/cbc.rs`)
- PKCS#7 padding on encrypt, constant-time unpad on decrypt
- Uses `subtle::ConstantTimeEq` for padding validation (prevents padding oracle)
- **Tests**: NIST SP 800-38A F.2 — roundtrip, short/aligned padding, empty, invalid IV, NIST vector

#### 5. CTR Mode (`modes/ctr.rs`)
- 128-bit big-endian counter increment
- Encrypt = decrypt (XOR keystream)
- **Tests**: NIST SP 800-38A F.5 — AES-128, multi-block, partial block, empty

#### 6. GCM Mode (`modes/gcm.rs`)
- NIST SP 800-38D compliant AES-GCM
- GHASH: 4-bit precomputed table (16 Gf128 entries), TABLE_P4[16] reduction constants
- `Gf128` struct (h: u64, l: u64) for GF(2^128) arithmetic
- GCM flow: H=Encrypt(0), J0 from nonce (12-byte fast path or GHASH), EK0=Encrypt(J0), CTR encrypt with inc32, GHASH over AAD+CT+lengths, tag=GHASH^EK0
- Constant-time tag verification via `subtle::ConstantTimeEq`
- **Tests**: NIST SP 800-38D — cases 1 (empty), 2 (16-byte PT), 4 (60-byte PT with AAD), auth failure, short ciphertext

#### 7. HKDF (`hkdf/mod.rs`)
- RFC 5869 compliant
- Extract: HMAC-SHA-256(salt, ikm), empty salt → hash_len zero bytes
- Expand: iterative HMAC(PRK, T_prev||info||counter_byte)
- One-shot `derive(salt, ikm, info, okm_len)` convenience method
- Zeroize PRK on drop
- **Tests**: RFC 5869 Appendix A — test cases 1, 2, 3

#### 8. PBKDF2 (`pbkdf2/mod.rs`)
- RFC 8018 compliant with HMAC-SHA-256 as PRF
- F(P, S, c, i) = U1 ^ U2 ^ ... ^ Uc, uses HMAC reset optimization
- Zeroize intermediate U and T values
- **Tests**: PBKDF2-HMAC-SHA256 with c=1 and c=80000 (verified against OpenSSL + Python), short output, invalid params

### Bug Fixes
- **Error variant mismatches**: `InvalidLength` → `InvalidArg`, `InvalidKeyLength` needs struct fields `{ expected, got }`, `VerifyFailed` → `AeadTagVerifyFail`
- **Added `InvalidPadding`** variant to `CryptoError` enum for CBC padding errors
- **GCM GHASH byte iteration order**: Changed from left-to-right to right-to-left (LSB-first), matching the C reference `noasm_ghash.c`
- **GCM test case 3**: Originally mixed NIST Test Case 3 (64-byte PT, no AAD) with Test Case 4 (60-byte PT + AAD) — corrected to proper Test Case 4 parameters
- **PBKDF2 test vector**: Expected value for c=1, dkLen=64 was incorrect — verified correct value against OpenSSL and Python (both `hashlib.pbkdf2_hmac` and manual implementation)
- **Clippy `needless_range_loop`** in SM4 `crypt_block` — fixed with `for &rk_i in rk.iter()`

### Files Modified
| File | Operation |
|------|-----------|
| `crates/hitls-types/src/error.rs` | Added `InvalidPadding` variant |
| `crates/hitls-crypto/src/aes/mod.rs` | Full AES implementation (~350 lines) |
| `crates/hitls-crypto/src/sm4/mod.rs` | Full SM4 implementation (~200 lines) |
| `crates/hitls-crypto/src/modes/ecb.rs` | ECB mode (~85 lines) |
| `crates/hitls-crypto/src/modes/cbc.rs` | CBC mode with PKCS#7 (~155 lines) |
| `crates/hitls-crypto/src/modes/ctr.rs` | CTR mode (~110 lines) |
| `crates/hitls-crypto/src/modes/gcm.rs` | GCM mode + GHASH (~350 lines) |
| `crates/hitls-crypto/src/hkdf/mod.rs` | HKDF (~140 lines) |
| `crates/hitls-crypto/src/pbkdf2/mod.rs` | PBKDF2 (~100 lines) |

### Build Status
- 65 hitls-crypto tests passing (35 new)
- 45 bignum + 11 utils = 56 (unchanged)
- **Total: 121 workspace tests**
- Clippy: zero warnings
- Fmt: clean

### Next Steps (Phase 5)
- Implement RSA key generation, encryption, and signing
- Implement ECDSA / ECDH (P-256, P-384)
- Implement SM2 (signature + encryption)
- Implement Ed25519 / X25519
