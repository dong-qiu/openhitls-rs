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

---

## Phase 5: RSA Asymmetric Cryptography (Session 2026-02-06)

### Goals
- Implement RSA key generation (2048/3072/4096-bit)
- Implement RSA raw operations with CRT optimization
- Implement PKCS#1 v1.5 padding (signatures + encryption)
- Implement OAEP padding (encryption)
- Implement PSS padding (signatures)
- Implement MGF1 mask generation function

### Completed Steps

#### 0. BigNum Supplement: `to_bytes_be_padded`
- Added `to_bytes_be_padded(len)` method to `BigNum` in `hitls-bignum/src/bignum.rs`
- Exports big-endian bytes left-padded with zeros to exactly `len` bytes
- Required by RSA: output must always be k bytes (modulus byte length)
- Added test `test_to_bytes_be_padded`

#### 1. RSA Core (`rsa/mod.rs`)
- **Data structures**:
  - `RsaPublicKey` — n, e (BigNum), bits, k (modulus byte length)
  - `RsaPrivateKey` — n, d, e, p, q, dp, dq, qinv (CRT parameters), bits, k
  - `RsaPadding` enum — Pkcs1v15Encrypt, Pkcs1v15Sign, Oaep, Pss, None
  - `RsaHashAlg` enum — Sha1, Sha256, Sha384, Sha512
- **Key generation** (`RsaPrivateKey::generate(bits)`):
  - e = 65537
  - Random prime generation with Miller-Rabin (5 rounds for >= 1024-bit) + gcd(p-1, e) = 1 check
  - CRT parameters: dp = d mod (p-1), dq = d mod (q-1), qinv = q^(-1) mod p
  - Retry up to 5000 candidates per prime
- **Raw operations**:
  - `raw_encrypt`: c = m^e mod n (Montgomery exponentiation)
  - `raw_decrypt`: CRT — m1 = c^dp mod p, m2 = c^dq mod q, h = qinv*(m1-m2+p) mod p, m = m2+h*q
- **Public API**: `encrypt(padding, pt)`, `decrypt(padding, ct)`, `sign(padding, digest)`, `verify(padding, digest, sig)`, `public_key()`, `new()`, `generate()`

#### 2. MGF1 Mask Generation Function
- `mgf1_sha256(seed, mask_len)` — RFC 8017 B.2.1
- SHA-256 based, deterministic: T = Hash(seed || counter_be32) for counter = 0, 1, ...
- ~20 lines, used by OAEP and PSS

#### 3. PKCS#1 v1.5 Padding (`rsa/pkcs1v15.rs`)
- **Signatures** (EMSA-PKCS1-v1_5, RFC 8017 §9.2):
  - `pkcs1v15_sign_pad(digest, k)` — EM = 0x00 || 0x01 || PS(0xFF...) || 0x00 || DigestInfo
  - `pkcs1v15_verify_unpad(em, digest, k)` — constant-time comparison via `subtle::ConstantTimeEq`
  - DigestInfo DER prefixes for SHA-1/256/384/512
- **Encryption** (RSAES-PKCS1-v1_5, RFC 8017 §7.2):
  - `pkcs1v15_encrypt_pad(msg, k)` — EM = 0x00 || 0x02 || PS(random non-zero) || 0x00 || M
  - `pkcs1v15_decrypt_unpad(em)` — finds 0x00 separator, verifies PS >= 8 bytes

#### 4. OAEP Padding (`rsa/oaep.rs`)
- **Encryption** (EME-OAEP, RFC 8017 §7.1.1):
  - `oaep_encrypt_pad(msg, k)` — lHash = SHA-256(""), DB = lHash || PS || 0x01 || M, seed → MGF1 masking
- **Decryption** (EME-OAEP, RFC 8017 §7.1.2):
  - `oaep_decrypt_unpad(em)` — reverse MGF1 masking, constant-time lHash comparison

#### 5. PSS Padding (`rsa/pss.rs`)
- **Signing** (EMSA-PSS-ENCODE, RFC 8017 §9.1.1):
  - `pss_sign_pad(digest, em_bits)` — M' = 0x00(x8) || mHash || salt, H = Hash(M'), maskedDB = DB XOR MGF1(H), EM = maskedDB || H || 0xbc
  - Salt length = hash length (32 bytes) by default
- **Verification** (EMSA-PSS-VERIFY, RFC 8017 §9.1.2):
  - `pss_verify_unpad(em, digest, em_bits)` — recovers salt from DB, recomputes H', constant-time comparison

### Critical Bug Fix: Montgomery REDC Overflow

**File**: `hitls-bignum/src/montgomery.rs`

**Problem**: `mont_reduce()` extracted only `work[m..m+m]` (exactly m limbs) for the result. For multi-limb moduli (> 64 bits), the REDC algorithm can produce results up to 2N, which may require m+1 limbs. The carry at position 2m was silently dropped.

**Symptoms**: All single-limb modulus tests passed (small numbers), but RSA-1024 raw encrypt/decrypt produced incorrect results. The bug only manifested with multi-limb moduli where carry propagation reached position 2m.

**Fix**:
```rust
// BEFORE (buggy):
let result_limbs: Vec<u64> = work[m..m + m].to_vec();
if result >= self.modulus {
    result = result.sub(&self.modulus);
}

// AFTER (fixed):
let result_limbs: Vec<u64> = work[m..].to_vec();
while result >= self.modulus {
    result = result.sub(&self.modulus);
}
```

**Debugging journey**: Raw RSA encrypt/decrypt failed → generated valid OpenSSL RSA-1024 test key → removed CRT to isolate bug → traced to `mod_exp` → isolated to `mont_reduce` → found overflow limb being truncated.

### Files Modified/Created

| File | Operation | Lines |
|------|-----------|-------|
| `crates/hitls-bignum/src/bignum.rs` | Modified: added `to_bytes_be_padded` | +15 |
| `crates/hitls-bignum/src/montgomery.rs` | Modified: REDC overflow fix | +2/-2 |
| `crates/hitls-crypto/src/rsa/mod.rs` | Rewrite from stub | ~400 |
| `crates/hitls-crypto/src/rsa/pkcs1v15.rs` | New file | ~155 |
| `crates/hitls-crypto/src/rsa/oaep.rs` | New file | ~135 |
| `crates/hitls-crypto/src/rsa/pss.rs` | New file | ~195 |

### Test Results

| Crate | Tests | Status |
|-------|-------|--------|
| hitls-bignum | 46 (+1) | All pass |
| hitls-crypto | 73 (+8 RSA, 1 ignored) | All pass |
| **Total** | **119** | **All pass** |

RSA tests (8 pass, 1 ignored):
- `test_rsa_raw_encrypt_decrypt` — raw encrypt/decrypt roundtrip with 1024-bit key
- `test_rsa_pkcs1v15_sign_verify` — PKCS#1 v1.5 sign + verify + tamper detection
- `test_rsa_pkcs1v15_encrypt_decrypt` — PKCS#1 v1.5 encrypt/decrypt roundtrip
- `test_rsa_oaep_encrypt_decrypt` — OAEP encrypt/decrypt roundtrip
- `test_rsa_pss_sign_verify` — PSS sign + verify + tamper detection
- `test_rsa_public_key_extraction` — public key from private key
- `test_rsa_invalid_key_sizes` — rejects < 2048 bits and odd sizes
- `test_mgf1_sha256` — deterministic, correct length, prefix property
- `test_rsa_keygen_basic` — *ignored* (too slow in debug mode, ~minutes for 2048-bit)

### Build Status
- Clippy: zero warnings (`RUSTFLAGS="-D warnings"`)
- Formatting: clean (`cargo fmt --check`)
- 119 workspace tests passing

### Next Steps (Phase 6)
- Implement ECC (elliptic curve arithmetic over P-256, P-384)
- Implement ECDSA (signing / verification)
- Implement ECDH (key agreement)

---

## Phase 6: ECC + ECDSA + ECDH (Session 2026-02-06)

### Goals
- Implement elliptic curve arithmetic over NIST P-256 and P-384 (Weierstrass curves)
- Implement ECDSA signing and verification (FIPS 186-4)
- Implement ECDH key agreement (NIST SP 800-56A)

### Completed Steps

#### 1. ECC Curve Parameters (`ecc/curves.rs`)
- `CurveParams` struct: p, a, b, gx, gy, n, h, field_size
- Hard-coded NIST P-256 (secp256r1) and P-384 (secp384r1) constants
- `get_curve_params(EccCurveId)` factory function
- Both curves satisfy a = p - 3 (enables optimized point doubling)

#### 2. Jacobian Point Arithmetic (`ecc/point.rs`)
- `JacobianPoint` struct: (X, Y, Z) representing affine (X/Z², Y/Z³), infinity at Z=0
- **Point addition** (`point_add`): U1/U2/S1/S2/H/R formula, ~20 modular operations
- **Point doubling** (`point_double`): Optimized for a = -3, uses M = 3·(X+Z²)·(X-Z²)
- **Scalar multiplication** (`scalar_mul`): Double-and-add (MSB → LSB)
- **Combined scalar mul** (`scalar_mul_add`): Shamir's trick for k1·G + k2·Q (ECDSA verification)
- **Jacobian → affine**: z_inv = Z⁻¹ mod p, x = X·z_inv², y = Y·z_inv³
- All functions return `Result<JacobianPoint, CryptoError>` (BigNum mod ops return Result)

#### 3. ECC Public API (`ecc/mod.rs`)
- `EcGroup` — Curve instance with parameters, provides scalar multiplication API
  - `new(curve_id)`, `generator()`, `order()`, `field_size()`
  - `scalar_mul(k, point)`, `scalar_mul_base(k)`, `scalar_mul_add(k1, k2, q)`
- `EcPoint` — Affine point (x, y, infinity flag)
  - `new(x, y)`, `infinity()`, `is_infinity()`, `x()`, `y()`
  - `is_on_curve(group)` — Verifies y² ≡ x³ + ax + b (mod p)
  - `to_uncompressed(group)` → `0x04 || x || y`
  - `from_uncompressed(group, data)` — Decode + on-curve validation
- **Tests** (9): generator on curve (P-256/P-384), 2G == G+G, n·G = infinity, encoding roundtrip, invalid point rejection, small scalar values, infinity encoding error, unsupported curve

#### 4. ECDH Key Agreement (`ecdh/mod.rs`)
- `EcdhKeyPair` struct with EcGroup, private_key (BigNum), public_key (EcPoint)
- `generate(curve_id)` — Random d ∈ [1, n-1], Q = d·G
- `from_private_key(curve_id, bytes)` — Import with validation (d ∈ [1, n-1])
- `compute_shared_secret(peer_pub_bytes)` → x-coordinate of d·Q_peer, padded to field_size
- Public key zeroized on drop via `Zeroize` trait
- **Tests** (3): P-256 shared secret (Alice==Bob), P-384 shared secret, from_private_key roundtrip

#### 5. ECDSA Signing & Verification (`ecdsa/mod.rs`)
- `EcdsaKeyPair` struct with EcGroup, private_key (BigNum), public_key (EcPoint)
- `generate(curve_id)` — Random key pair
- `from_private_key(curve_id, bytes)` — Import private key
- `from_public_key(curve_id, bytes)` — Import public key (verify-only)
- **Signing** (FIPS 186-4):
  1. e = truncate(digest, bit_len(n))
  2. k = random [1, n-1]
  3. (x1, _) = k·G; r = x1 mod n (retry if r=0)
  4. s = k⁻¹·(e + d·r) mod n (retry if s=0)
  5. Return DER(SEQUENCE { INTEGER r, INTEGER s })
- **Verification**:
  1. Validate r, s ∈ [1, n-1]
  2. w = s⁻¹ mod n, u1 = e·w, u2 = r·w
  3. (x1, _) = u1·G + u2·Q (Shamir's trick)
  4. Check x1 mod n == r
- `truncate_digest()` — Truncates hash to curve order bit length
- DER encoding/decoding via `hitls-utils` ASN.1 `Encoder`/`Decoder`
- Private key zeroized on drop
- **Tests** (5): sign/verify P-256, sign/verify P-384, tamper detection, public-key-only verify, DER roundtrip

### Compilation Fixes
- **BigNum `mod_mul`/`mod_add`/`mod_sub` return `Result`** — All 27 call sites in point.rs, ecc/mod.rs, ecdsa/mod.rs needed `?` operator
- **`hitls-utils` not a dependency for `ecdsa`** — Added `hitls-utils` as optional dependency, added `"hitls-utils"` to ecdsa feature
- **`CurveParams` needs `Clone`** — Added `#[derive(Clone)]` to CurveParams

### Files Created/Modified

| File | Operation | Approx Lines |
|------|-----------|-------------|
| `crates/hitls-crypto/src/ecc/curves.rs` | New: P-256/P-384 parameters | ~75 |
| `crates/hitls-crypto/src/ecc/point.rs` | New: Jacobian point arithmetic | ~235 |
| `crates/hitls-crypto/src/ecc/mod.rs` | Rewrite: EcGroup + EcPoint | ~320 |
| `crates/hitls-crypto/src/ecdsa/mod.rs` | Rewrite: ECDSA sign/verify | ~300 |
| `crates/hitls-crypto/src/ecdh/mod.rs` | Rewrite: ECDH key agreement | ~145 |
| `crates/hitls-crypto/Cargo.toml` | Modified: added hitls-utils dep | +2 |

### Test Results

| Crate | Tests | Status |
|-------|-------|--------|
| hitls-bignum | 46 | All pass |
| hitls-crypto | 90 (+17, 1 ignored) | All pass |
| **Total** | **136** | **All pass** |

New tests (17):
- ECC core (9): generator on curve ×2, double==add, n·G=infinity, encoding roundtrip, invalid point, small scalars, infinity encoding, unsupported curve
- ECDSA (5): sign/verify P-256, sign/verify P-384, tamper detection, public-key-only verify, DER roundtrip
- ECDH (3): P-256 shared secret, P-384 shared secret, from_private_key roundtrip

### Build Status
- Clippy: zero warnings (`RUSTFLAGS="-D warnings"`)
- Formatting: clean (`cargo fmt --check`)
- 136 workspace tests passing

### Next Steps (Phase 7)
- Implement Ed25519 / X25519 (Montgomery/Edwards curves)
- Implement DH (finite field Diffie-Hellman)

---

## Phase 7: Ed25519 + X25519 + DH (Session 2026-02-06)

### Goals
- Implement Curve25519 field arithmetic (GF(2^255-19), Fp51 representation)
- Implement Edwards curve point operations for Ed25519
- Implement Ed25519 signing and verification (RFC 8032)
- Implement X25519 key exchange (RFC 7748)
- Implement classic DH key exchange with RFC 7919 predefined groups

### Completed Steps

#### 1. Curve25519 Field Arithmetic (`curve25519/field.rs`)
- `Fe25519` type: 5 × u64 limbs (Fp51), each limb ≤ 51 bits
- Operations: add, sub, mul, square, neg, invert (Fermat), pow25523, mul121666
- Encoding: from_bytes/to_bytes (32-byte little-endian)
- Utilities: reduce, conditional_swap (constant-time), is_negative, is_zero
- Fp51 multiplication: schoolbook 5×5, overflow limbs ×19 fold-back, u128 intermediates
- Inversion via addition chain: z^(p-2) = z^(2^255-21)
- **Tests** (7): zero/one, mul identity, mul/square consistency, invert, encode/decode roundtrip, add/sub roundtrip, conditional swap

#### 2. Edwards Curve Point Operations (`curve25519/edwards.rs`)
- Twisted Edwards curve: -x² + y² = 1 + d·x²·y² (d = -121665/121666)
- `GeExtended` type: extended coordinates (X, Y, Z, T) where T = XY/Z
- Point operations: identity, basepoint, point_add (Hisil 2008), point_double (dbl-2008-hwcd for a=-1)
- Scalar multiplication: double-and-add (MSB → LSB), plus base-point variant
- Point encoding/decoding: y-coordinate + x sign bit, sqrt recovery via pow25523
- Constants: D, D2, SQRT_M1, BASE_X, BASE_Y (all as Fe25519 Fp51 limbs)
- **Tests** (5): identity encoding, basepoint roundtrip, double==add, scalar_mul ×1, scalar_mul ×2

#### 3. Ed25519 Signing & Verification (`ed25519/mod.rs`)
- `Ed25519KeyPair` struct: 32-byte seed + 32-byte public key
- Key derivation: SHA-512(seed) → clamp(h[0..32]) → scalar_mul_base → public key
- **Signing** (RFC 8032 §5.1.6): r = SHA-512(prefix||msg) mod L, R = r·B, k = SHA-512(R||A||msg) mod L, S = (r + k·a) mod L
- **Verification** (RFC 8032 §5.1.7): Check S·B == R + k·A
- Scalar mod L via BigNum (512-bit reduction)
- `scalar_muladd(a, b, c)`: (a*b + c) mod L
- `scalar_is_canonical(s)`: check s < L
- **Tests** (6): RFC 8032 §7.1 vectors 1 & 2, sign/verify roundtrip, tamper detection, public-key-only verify, invalid signature rejection

#### 4. X25519 Key Exchange (`x25519/mod.rs`)
- `X25519PrivateKey` / `X25519PublicKey` types (32 bytes each)
- Montgomery ladder scalar multiplication (RFC 7748 §5)
- Key generation, public key derivation, Diffie-Hellman shared secret
- All-zero output check (point at infinity rejection)
- **Tests** (3): RFC 7748 §6.1 test vector, key exchange symmetry, basepoint determinism

#### 5. DH Key Exchange (`dh/mod.rs`, `dh/groups.rs`)
- `DhParams` struct: prime p, generator g (BigNum)
- `DhKeyPair`: private x ∈ [2, p-2], public y = g^x mod p
- Predefined groups: RFC 7919 ffdhe2048 and ffdhe3072 (g = 2)
- Shared secret: s = peer_pub^x mod p, padded to prime_size
- Peer public key validation: 2 ≤ peer_pub ≤ p-2
- **Tests** (3): ffdhe2048 exchange, custom params (p=23, g=5), from_group construction

### Critical Bugs Found & Fixed

#### Fp51 Inversion Addition Chain (`field.rs`)
- **Bug**: After computing z^(2^250-1), the chain did 2 squares + mul(f) + 3 squares + mul(z11) = z^(2^255-13)
- **Fix**: 5 squares + mul(z11) = z^(2^255-32+11) = z^(2^255-21) = z^(p-2)

#### Edwards Curve Constants (`edwards.rs`)
- **Bug**: D[3], D[4], BASE_Y[1-3], BASE_X[3-4] had incorrect Fp51 limb values
- **Fix**: Recomputed all constants from first principles using Python, verified against known encodings

#### Edwards Point Doubling Formula (`edwards.rs`)
- **Bug**: Used a=1 doubling formula on a=-1 twisted Edwards curve
- **Fix**: Switched to "dbl-2008-hwcd" formula: D=-A, G=D+B, F=G-C, H=D-B

#### X25519 Montgomery Ladder (`x25519/mod.rs`)
- **Bug**: `z_2 = E * (AA + 121666*E)` — AA should be BB
- **Fix**: `z_2 = E * (BB + 121666*E)` — verified by deriving from Montgomery curve doubling formula

#### Sub Function Constants (`field.rs`)
- **Bug**: 2p constants for non-negative subtraction had wrong values
- **Fix**: Recomputed correct 2p limb values

### Files Created/Modified

| File | Operation | Approx Lines |
|------|-----------|-------------|
| `crates/hitls-crypto/src/curve25519/mod.rs` | New: module declarations | ~5 |
| `crates/hitls-crypto/src/curve25519/field.rs` | New: Fp51 field arithmetic | ~550 |
| `crates/hitls-crypto/src/curve25519/edwards.rs` | New: Edwards point operations | ~280 |
| `crates/hitls-crypto/src/ed25519/mod.rs` | Rewrite: Ed25519 sign/verify | ~380 |
| `crates/hitls-crypto/src/x25519/mod.rs` | Rewrite: X25519 key exchange | ~210 |
| `crates/hitls-crypto/src/dh/mod.rs` | Rewrite: DH key exchange | ~165 |
| `crates/hitls-crypto/src/dh/groups.rs` | New: RFC 7919 ffdhe parameters | ~90 |
| `crates/hitls-crypto/src/lib.rs` | Modified: added curve25519 module | +2 |
| `crates/hitls-crypto/Cargo.toml` | Modified: ed25519 feature deps | +1 |

### Test Results

| Crate | Tests | Status |
|-------|-------|--------|
| hitls-bignum | 46 | All pass |
| hitls-crypto | 114 (+24, 1 ignored) | All pass |
| hitls-utils | 11 | All pass |
| **Total** | **171** | **All pass** |

New tests (24):
- Curve25519 field (7): zero/one, mul identity, mul/square, invert, encode/decode, add/sub, cswap
- Edwards points (5): identity, basepoint roundtrip, double==add, scalar×1, scalar×2
- Ed25519 (6): RFC 8032 vectors 1 & 2, roundtrip, tamper, pubkey-only, invalid sig
- X25519 (3): RFC 7748 vector, symmetry, determinism
- DH (3): ffdhe2048, custom params, from_group

### Build Status
- Clippy: zero warnings (`RUSTFLAGS="-D warnings"`)
- Formatting: clean (`cargo fmt --check`)
- 171 workspace tests passing

### Next Steps (Phase 8)
- Implement DSA (digital signature algorithm)
- Implement SM2 (signature + encryption + key exchange)
- Implement DRBG (deterministic random bit generator)

---

## Phase 8: DSA + SM2 + HMAC-DRBG (Session 2026-02-06)

### Goals
- Implement DSA signing and verification (FIPS 186-4)
- Implement SM2 signing, verification, encryption, and decryption (GB/T 32918)
- Implement HMAC-DRBG (NIST SP 800-90A)

### Completed Steps

#### 1. SM2P256V1 Curve Parameters (`ecc/curves.rs`)
- Added SM2P256V1 (GB/T 32918.5-2017) parameters to existing `get_curve_params`
- `EccCurveId::Sm2Prime256` → full CurveParams with p, a, b, gx, gy, n, h=1, field_size=32
- SM2 curve has a = p - 3, so existing Jacobian point_double optimization works directly

#### 2. DSA Signing & Verification (`dsa/mod.rs`)
- `DsaParams` struct: p (prime modulus), q (subgroup order), g (generator)
- `DsaKeyPair`: generate, from_private_key, from_public_key
- **Signing** (FIPS 186-4): r = (g^k mod p) mod q, s = k^(-1)·(e + x·r) mod q
- **Verification**: w = s^(-1), u1 = e·w, u2 = r·w, v = (g^u1 · y^u2 mod p) mod q, check v == r
- `digest_to_bignum()` — truncates digest to q's bit length (right-shift)
- DER signature encoding/decoding via hitls-utils ASN.1
- **Tests** (5): sign/verify, tamper detection, public-key-only verify, DER roundtrip, invalid params

#### 3. SM2 Signature + Encryption (`sm2/mod.rs`)
- `Sm2KeyPair` struct: EcGroup, private_key (BigNum), public_key (EcPoint)
- **ZA computation** (GB/T 32918.2 §5.5): ZA = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA)
  - Default IDA = "1234567812345678" (16 bytes)
- **Signing** (GB/T 32918.2 §6.1):
  - e = SM3(ZA || M), k random, (x1, _) = k·G
  - r = (e + x1) mod n, s = (1+d)^(-1) · (k - r·d) mod n
  - Note: different from ECDSA! s uses (1+d)^(-1), not k^(-1)
- **Verification** (GB/T 32918.2 §7.1):
  - t = (r + s) mod n, (x1', _) = s·G + t·PA (Shamir's trick), R' = (e + x1') mod n, check R' == r
- **Encryption** (GB/T 32918.4, new format C1||C3||C2):
  - k random, C1 = k·G, (x2, y2) = k·PB
  - t = KDF(x2 || y2, len(M)), C2 = M ⊕ t, C3 = SM3(x2 || M || y2)
- **Decryption**: (x2, y2) = dB · C1, reverse KDF, constant-time C3 comparison
- **SM2 KDF**: counter-mode SM3(x2 || y2 || counter_be32)
- **Tests** (7): sign/verify, custom ID, tamper detection, pubkey-only verify, encrypt/decrypt, tampered decrypt rejection, short message encrypt

#### 4. HMAC-DRBG (`drbg/mod.rs`)
- `HmacDrbg` struct: K (32 bytes), V (32 bytes), reseed_counter
- **Instantiate** (SP 800-90A §10.1.2.1): K=0x00..00, V=0x01..01, update(seed_material)
- **Update** (SP 800-90A §10.1.2.2): two-round HMAC for non-empty data
- **Generate** (SP 800-90A §10.1.2.5): produce output blocks via V=HMAC(K,V), final update
- **Reseed** (SP 800-90A §10.1.2.4): update(entropy || additional_input)
- Reseed interval: 2^48
- `from_system_entropy()` convenience constructor using getrandom
- **Tests** (6): instantiate, generate, reseed, additional input, deterministic, large output

### Bug Found & Fixed

#### DSA Tamper Detection with Small Groups
- **Problem**: Test used 1-byte digests `[0x01]` and `[0x05]` with q=11 (bit_len=4). `digest_to_bignum` shifts right by 4, producing 0 for both — identical after truncation!
- **Fix**: Use digests where the top nibble differs (`[0x10]` → e=1, `[0x20]` → e=2, etc.) and test multiple tampered values to handle ~1/11 collision probability with small q.

### Cargo.toml Changes
```toml
dsa = ["hitls-bignum", "hitls-utils"]
sm2 = ["ecc", "sm3", "hitls-utils"]
drbg = ["hmac", "sha2"]
```

### Files Created/Modified

| File | Operation | Approx Lines |
|------|-----------|-------------|
| `crates/hitls-crypto/src/ecc/curves.rs` | Modified: added SM2P256V1 | +15 |
| `crates/hitls-crypto/src/dsa/mod.rs` | Rewrite: DSA sign/verify | ~320 |
| `crates/hitls-crypto/src/sm2/mod.rs` | Rewrite: SM2 sign/verify/encrypt/decrypt | ~450 |
| `crates/hitls-crypto/src/drbg/mod.rs` | Rewrite: HMAC-DRBG | ~245 |
| `crates/hitls-crypto/Cargo.toml` | Modified: feature deps | +3 |

### Test Results

| Crate | Tests | Status |
|-------|-------|--------|
| hitls-bignum | 46 | All pass |
| hitls-crypto | 132 (+18, 1 ignored) | All pass |
| hitls-utils | 11 | All pass |
| **Total** | **189** | **All pass** |

New tests (18):
- DSA (5): sign/verify, tamper detection, pubkey-only verify, DER roundtrip, invalid params
- SM2 (7): sign/verify, custom ID, tamper, pubkey-only verify, encrypt/decrypt, tampered decrypt, short message
- HMAC-DRBG (6): instantiate, generate, reseed, additional input, deterministic, large output

### Build Status
- Clippy: zero warnings (`RUSTFLAGS="-D warnings"`)
- Formatting: clean (`cargo fmt --check`)
- 189 workspace tests passing

---

## Phase 9: SHA-3/SHAKE + ChaCha20-Poly1305 + Symmetric Suite Completion (Session 2026-02-06)

### Goals
- Implement SHA-3/SHAKE (Keccak sponge construction, FIPS 202)
- Implement ChaCha20 stream cipher + Poly1305 MAC + ChaCha20-Poly1305 AEAD (RFC 8439)
- Complete block cipher modes: CFB, OFB, CCM, XTS
- Complete MAC algorithms: CMAC, GMAC, SipHash
- Implement scrypt memory-hard KDF (RFC 7914)

After this phase, the symmetric cryptography subsystem is 100% complete.

### Completed Steps

#### 1. SHA-3/SHAKE (`sha3/mod.rs`)
- FIPS 202 compliant Keccak sponge construction
- Keccak-f[1600] permutation: 25 × u64 lanes, 24 rounds, 5 steps (θ, ρ, π, χ, ι)
- Generic `KeccakState` struct parameterized by rate, suffix, and output length
- SHA3-224 (rate=144), SHA3-256 (rate=136), SHA3-384 (rate=104), SHA3-512 (rate=72)
- SHAKE128 (rate=168, XOF), SHAKE256 (rate=136, XOF)
- Domain separation: 0x06 for SHA-3, 0x1F for SHAKE
- API: `new()`, `update()`, `finish()`, `reset()`, `digest()` for SHA-3; `squeeze(len)` for SHAKE
- **Tests** (8): SHA3-256 empty/abc/two-block, SHA3-512 empty/abc, SHA3-224/384 basic, SHAKE128/256 variable output

#### 2. ChaCha20 Stream Cipher (`chacha20/mod.rs`)
- RFC 8439 §2.3 compliant
- Quarter round: a+=b; d^=a; d<<<16; c+=d; b^=c; b<<<12; a+=b; d^=a; d<<<8; c+=d; b^=c; b<<<7
- State: 4 constants + 8 key words + 1 counter + 3 nonce words (16 × u32)
- 20 rounds (10 double rounds): alternating column and diagonal quarter rounds
- 64-byte keystream blocks, XOR with plaintext
- **Tests** (2): RFC 8439 §2.4.2 test vector, encrypt/decrypt roundtrip

#### 3. Poly1305 MAC (`chacha20/mod.rs`)
- RFC 8439 §2.5 compliant
- Radix-2^26 representation: 5 × u32 limbs for accumulator and clamped r
- Clamping: r[3,7,11,15] top 4 bits cleared; r[4,8,12] bottom 2 bits cleared
- Accumulate: add 16-byte blocks with high bit set, multiply by r mod (2^130-5)
- Finalization: convert limbs to base-2^32, add s with carry chain
- **Tests** (2): RFC 8439 §2.5.2 test vector, Poly1305 tag verification

#### 4. ChaCha20-Poly1305 AEAD (`chacha20/mod.rs`)
- RFC 8439 §2.8 compliant
- poly_key derived from ChaCha20(key, nonce, counter=0)[0..32]
- Encryption from counter=1
- MAC data: pad16(aad) || pad16(ciphertext) || len(aad) as u64le || len(ct) as u64le
- Constant-time tag verification via `subtle::ConstantTimeEq`
- **Tests** (4): RFC 8439 §2.8.2 encrypt/decrypt, auth failure (tampered tag), AEAD with AAD, empty plaintext

#### 5. CFB Mode (`modes/cfb.rs`)
- NIST SP 800-38A §6.3 compliant (CFB-128)
- Encrypt: C_i = P_i ⊕ E_K(C_{i-1}), C_0 = IV
- Decrypt: P_i = C_i ⊕ E_K(C_{i-1}), C_0 = IV
- Handles partial last block (no padding needed)
- **Tests** (2): encrypt/decrypt roundtrip, partial block

#### 6. OFB Mode (`modes/ofb.rs`)
- NIST SP 800-38A §6.4 compliant
- O_i = E_K(O_{i-1}), symmetric encrypt/decrypt operation
- `ofb_crypt()` — single function for both encrypt and decrypt
- **Tests** (2): encrypt/decrypt roundtrip, partial block

#### 7. CCM Mode (`modes/ccm.rs`)
- NIST SP 800-38C compliant AEAD mode
- CBC-MAC authentication tag: B0 flags encoding, AAD length encoding, plaintext padding
- CTR encryption: counter block formatting, S0 for tag encryption
- Nonce: 7-13 bytes; Tag: 4-16 bytes (even)
- Constant-time tag verification
- **Tests** (4): NIST SP 800-38C examples 1 & 2, auth failure, empty plaintext

#### 8. XTS Mode (`modes/xts.rs`)
- IEEE P1619 / NIST SP 800-38E compliant
- Two AES keys: K1 for data encryption, K2 for tweak encryption
- T = E_{K2}(tweak), PP = P_i ⊕ T, CC = E_{K1}(PP), C_i = CC ⊕ T
- `gf_mul_alpha()`: GF(2^128) multiplication by α (left-shift + conditional XOR 0x87)
- Ciphertext stealing for last incomplete block
- **Tests** (3): encrypt/decrypt roundtrip, multi-block, minimum size validation

#### 9. CMAC-AES (`cmac/mod.rs`)
- RFC 4493 / NIST SP 800-38B compliant
- Subkey derivation: L = E_K(0), K1 = dbl(L), K2 = dbl(K1) with Rb = 0x87
- `dbl()`: left-shift 128-bit block by 1 bit, conditional XOR with Rb
- Last block: complete → XOR K1; incomplete → pad(10*) + XOR K2
- Incremental API: `new()`, `update()`, `finish()`, `reset()`
- Zeroize subkeys and state on drop
- **Tests** (5): RFC 4493 vectors (empty, 16-byte, 40-byte, 64-byte message), reset

#### 10. GMAC (`gmac/mod.rs`)
- NIST SP 800-38D compliant (GCM with empty plaintext)
- Reuses `Gf128`, `ghash_precompute()`, `ghash_update()` from `modes/gcm.rs` (made `pub(crate)`)
- H = E_K(0), J0 from IV, GHASH(AAD || len_block), tag = GHASH ⊕ E_K(J0)
- **Tests** (2): GMAC tag generation, different IV lengths

#### 11. SipHash-2-4 (`siphash/mod.rs`)
- Aumasson & Bernstein reference implementation
- 4 × u64 internal state (v0-v3), initialized from 128-bit key
- SipRound: 4 add/rotate/xor operations
- 2 compression rounds per 8-byte input block, 4 finalization rounds
- Last block padding: length byte in MSB
- Incremental API: `new()`, `update()`, `finish()`, `hash()` (one-shot)
- **Tests** (2): reference test vectors, incremental vs one-shot

#### 12. scrypt KDF (`scrypt/mod.rs`)
- RFC 7914 compliant
- Flow: PBKDF2(password, salt, 1, p*128*r) → ROMix each block → PBKDF2(password, B, 1, dk_len)
- ROMix: sequential memory-hard function with V[N] lookup table
- BlockMix: interleaved Salsa20/8 core, output reordering (even||odd)
- Salsa20/8 core: 8-round (4 double-round) variant with feedforward addition
- Parameter validation: N must be power of 2, r*p < 2^30
- **Tests** (5): RFC 7914 §12 vectors 1 & 2, Salsa20/8 core, invalid parameters

### Bugs Found & Fixed

#### Poly1305 Radix-2^26 Finalization (`chacha20/mod.rs`)
- **Problem**: Assembly step converted radix-2^26 limbs to u64 with overlapping bit ranges. `a0 = acc[0] | (acc[1] << 26)` contained bits 0-51, and `a1 = (acc[1] >> 6) | (acc[2] << 20)` contained bits 32-77. Carry from a0 to a1 double-counted bits 32-51.
- **Fix**: Convert to u32 base-2^32 words first using `wrapping_shl` (truncates in u32 space), then add `s` with carry chain:
```rust
let h0 = self.acc[0] | self.acc[1].wrapping_shl(26);
let h1 = (self.acc[1] >> 6) | self.acc[2].wrapping_shl(20);
let h2 = (self.acc[2] >> 12) | self.acc[3].wrapping_shl(14);
let h3 = (self.acc[3] >> 18) | self.acc[4].wrapping_shl(8);
// Then add s[0..4] with u64 carry chain
```
- **Verification**: Python simulation of both buggy and fixed approaches confirmed the exact wrong/correct output.

#### Salsa20/8 Core Test Vector (`scrypt/mod.rs`)
- **Problem**: Input hex string's last 14 bytes (`d4d235736e4837319c726748f8eb`) were wrong.
- **Fix**: Corrected to `1d2909c74829edebc68db8b8c25e` per RFC 7914 §8.
- **Verification**: Python reference implementation produces matching output with correct input.

#### scrypt Test Vectors 1 & 2 (`scrypt/mod.rs`)
- **Problem**: Expected output hex strings for both test vectors had copy-paste errors.
- **Fix**: Corrected to match RFC 7914 §12 values, verified with full Python scrypt implementation.

### Clippy Fixes (7 warnings)
- `chacha20/mod.rs` — unused `mut` on variable; `needless_range_loop` on g[] indexing
- `sha3/mod.rs` — loop variable only used to index RC array; unnecessary `to_vec()` in absorb
- `modes/ccm.rs` — manual range contains → `!(4..=16).contains(&tag_len)`
- `cmac/mod.rs` — `needless_range_loop` on last_block (×2)

### GCM Module Changes (`modes/gcm.rs`)
- Made `Gf128`, `ghash_precompute()`, and `ghash_update()` `pub(crate)` for GMAC reuse
- No functional changes to GCM itself

### Cargo.toml Feature Changes
```toml
sha3 = []
chacha20 = []
modes = ["aes"]
cmac = ["aes"]
gmac = ["aes", "modes"]
siphash = []
scrypt = ["pbkdf2"]
```

### Files Created/Modified

| File | Operation | Approx Lines |
|------|-----------|-------------|
| `crates/hitls-crypto/src/sha3/mod.rs` | Rewrite: SHA-3/SHAKE | ~400 |
| `crates/hitls-crypto/src/chacha20/mod.rs` | Rewrite: ChaCha20 + Poly1305 + AEAD | ~420 |
| `crates/hitls-crypto/src/modes/cfb.rs` | Rewrite: CFB-128 | ~80 |
| `crates/hitls-crypto/src/modes/ofb.rs` | Rewrite: OFB | ~60 |
| `crates/hitls-crypto/src/modes/ccm.rs` | Rewrite: CCM AEAD | ~290 |
| `crates/hitls-crypto/src/modes/xts.rs` | Rewrite: XTS | ~150 |
| `crates/hitls-crypto/src/modes/gcm.rs` | Modified: pub(crate) exports | +3 |
| `crates/hitls-crypto/src/cmac/mod.rs` | Rewrite: CMAC-AES | ~265 |
| `crates/hitls-crypto/src/gmac/mod.rs` | Rewrite: GMAC | ~175 |
| `crates/hitls-crypto/src/siphash/mod.rs` | Rewrite: SipHash-2-4 | ~175 |
| `crates/hitls-crypto/src/scrypt/mod.rs` | Rewrite: scrypt KDF | ~250 |

### Test Results

| Crate | Tests | Status |
|-------|-------|--------|
| hitls-bignum | 46 | All pass |
| hitls-crypto | 175 (+43, 1 ignored) | All pass |
| hitls-utils | 11 | All pass |
| **Total** | **232** | **All pass** |

New tests (43):
- SHA-3 (8): SHA3-256 empty/abc/two-block, SHA3-512 empty/abc, SHA3-224/384 basic, SHAKE128/256
- ChaCha20-Poly1305 (8): ChaCha20 RFC vector, roundtrip, Poly1305 RFC vector, tag verify, AEAD encrypt/decrypt, auth failure, AAD, empty PT
- CFB (2): roundtrip, partial block
- OFB (2): roundtrip, partial block
- CCM (4): NIST examples 1 & 2, auth failure, empty PT
- XTS (3): roundtrip, multi-block, minimum size
- CMAC (5): RFC 4493 vectors (empty/16B/40B/64B), reset
- GMAC (2): tag generation, different IV
- SipHash (2): reference vectors, incremental vs one-shot
- scrypt (5): RFC 7914 vectors 1 & 2, Salsa20/8 core, invalid params ×2

### Build Status
- Clippy: zero warnings (`RUSTFLAGS="-D warnings"`)
- Formatting: clean (`cargo fmt --check`)
- 232 workspace tests passing

### Symmetric Subsystem Completion

With Phase 9, all symmetric/hash/MAC/KDF primitives are fully implemented:

| Category | Algorithms |
|----------|-----------|
| Hash | SHA-2 (224/256/384/512), SHA-3 (224/256/384/512), SHAKE (128/256), SM3, SHA-1, MD5 |
| Symmetric | AES (128/192/256), SM4, ChaCha20 |
| Modes | ECB, CBC, CTR, GCM, CFB, OFB, CCM, XTS |
| AEAD | AES-GCM, ChaCha20-Poly1305, AES-CCM |
| MAC | HMAC, CMAC, GMAC, Poly1305, SipHash |
| KDF | HKDF, PBKDF2, scrypt |
| DRBG | HMAC-DRBG |

Remaining work: post-quantum cryptography (SLH-DSA, etc.), TLS protocol, PKI, authentication protocols.

---

## Phase 10: ML-KEM (FIPS 203) + ML-DSA (FIPS 204) (Session 2026-02-07)

### Goals
- Implement ML-KEM (Module-Lattice Key Encapsulation Mechanism, FIPS 203)
- Implement ML-DSA (Module-Lattice Digital Signature Algorithm, FIPS 204)
- Support all parameter sets: ML-KEM-512/768/1024 and ML-DSA-44/65/87

### Completed Steps

#### 1. ML-KEM NTT (`mlkem/ntt.rs`)
- Z_q[X]/(X^256+1) over q = 3329, using Montgomery arithmetic (R = 2^16)
- 7-layer NTT (Cooley-Tukey) and INTT (Gentleman-Sande)
- Barrett reduction, Montgomery reduction (QINV = -3327)
- Basemul for degree-1 polynomial pairs in NTT domain
- `to_mont()` for converting to Montgomery representation
- F_INV128 = 1441 (R²/128 mod q) for INTT normalization
- ZETAS[128] table in Montgomery form (ζ = 17, primitive 256th root of unity)
- **Tests** (3): NTT/INTT roundtrip, Barrett reduce, Montgomery reduce

#### 2. ML-KEM Polynomial Operations (`mlkem/poly.rs`)
- **CBD sampling**: cbd2 (η=2, 128 bytes → 256 coefficients), cbd3 (η=3, 192 bytes)
- **Compress/Decompress**: round(x·2^d/q) and round(y·q/2^d) for d ∈ {1,4,5,10,11,12}
- **ByteEncode/ByteDecode**: generic bit-packing for d-bit coefficients
- **Rejection sampling** (ExpandA): SHAKE128 XOF → 3 bytes → 2 candidates (12-bit, reject ≥ q)
- **PRF**: SHAKE256(seed || nonce) for CBD input
- **Tests** (1): compress/decompress roundtrip

#### 3. ML-KEM Main (`mlkem/mod.rs`)
- **K-PKE** (internal public-key encryption):
  - KeyGen: (ρ,σ) = G(d), A = ExpandA(ρ), s/e = CBD(σ), t̂ = Â·ŝ + ê
  - Encrypt: r̂ = NTT(r), u = INTT(Â^T·r̂) + e1, v = INTT(t̂·r̂) + e2 + Decompress(m,1)·⌈q/2⌉
  - Decrypt: w = v - INTT(ŝ·NTT(u)), m = Compress(w, 1)
- **ML-KEM** (outer KEM with FO transform):
  - KeyGen: ek = ek_pke, dk = dk_pke || ek || H(ek) || z
  - Encaps: (K, r) = G(m || H(ek)), ct = Encrypt(ek, m, r)
  - Decaps: m' = Decrypt(dk, ct), re-encrypt + compare → K or J(z||ct)
- Parameter sets: ML-KEM-512 (k=2), ML-KEM-768 (k=3), ML-KEM-1024 (k=4)
- **Tests** (10): 512/768/1024 encaps/decaps roundtrip, tampered ciphertext (implicit rejection), key lengths, invalid params, encoding

#### 4. ML-DSA NTT (`mldsa/ntt.rs`)
- Z_q[X]/(X^256+1) over q = 8380417, using Montgomery arithmetic (R = 2^32)
- 8-layer NTT (Cooley-Tukey) and INTT (Gentleman-Sande)
- Barrett-like reduce32, conditional add (caddq), freeze
- Pointwise multiplication and multiply-accumulate
- F_INV256 = 41978 (R²/256 mod q) for INTT normalization
- ZETAS[256] table (ψ = 1753, primitive 512th root of unity)
- QINV = 58728449 (q^{-1} mod 2^32)
- **Tests** (4): NTT/INTT roundtrip, Montgomery reduce, reduce32, freeze

#### 5. ML-DSA Polynomial Operations (`mldsa/poly.rs`)
- **Power2Round** (Algorithm 35): decompose r = r1·2^D + r0, D=13
- **Decompose** (Algorithm 36): a = a1·2γ₂ + a0, centered mod
- **HighBits/LowBits**: extract high/low parts of decomposition
- **MakeHint/UseHint**: hint encoding for signature verification
- **Rejection sampling**: ExpandA (SHAKE128, 23-bit), ExpandS (SHAKE256, nibble rejection), ExpandMask (18/20-bit), SampleInBall (sparse ±1)
- **Bit packing**: pack/unpack for t1 (10-bit), t0 (13-bit signed), eta (3/4-bit), z (18/20-bit), w1 (4/6-bit)
- **Tests** (6): power2round, decompose, pack/unpack t1, t0, eta, z

#### 6. ML-DSA Main (`mldsa/mod.rs`)
- **KeyGen** (Algorithm 1): ξ → (ρ,ρ',K), A = ExpandA(ρ), s1/s2 = ExpandS(ρ'), t = A·s1+s2, (t1,t0) = Power2Round(t)
- **Sign** (Algorithm 2): deterministic signing with Fiat-Shamir, rejection sampling loop:
  1. y = ExpandMask(ρ', κ), w = A·NTT(y), w1 = HighBits(w)
  2. c̃ = H(μ || w1), c = SampleInBall(c̃)
  3. z = y + c·s1, check ||z||∞ < γ₁-β
  4. Check ||LowBits(w-c·s2)||∞ < γ₂-β
  5. Check ||c·t0||∞ < γ₂, compute hints
- **Verify** (Algorithm 3): w' = A·z - c·t1·2^D, w1' = UseHint(h, w'), check c̃' = c̃
- Parameter sets: ML-DSA-44 (k=4,l=4), ML-DSA-65 (k=6,l=5), ML-DSA-87 (k=8,l=7)
- **Tests** (6): 44/65/87 sign/verify roundtrip, tampered signature, key lengths, invalid params

### Critical Bugs Found & Fixed

#### ML-KEM CBD2 Coefficient Extraction (`mlkem/poly.rs`)
- **Bug**: Loop was `N/4=64` iterations, each reading 4 bytes and producing 4 coefficients. But buffer is only 128 bytes (64×4 = 256 bytes needed, only 128 available).
- **Fix**: Changed to `N/8=32` iterations producing 8 coefficients per 32-bit word (bit-pair extraction: `(d >> 4j) & 3` for both halves of each nibble pair).

#### ML-KEM Montgomery Domain Mismatch (`mlkem/mod.rs`)
- **Bug**: `basemul_acc` introduces R^{-1} factor. Adding `e_hat` (normal NTT domain) to `t_hat` (with R^{-1} from basemul) is a domain mismatch.
- **Fix**: Added `ntt::to_mont(&mut t_hat[i])` after basemul to cancel R^{-1} before adding `e_hat`.
- **Key insight**: `to_mont` multiplies by R via `fqmul(coeff, R²_mod_q)`, which produces `coeff * R² * R^{-1} = coeff * R`.

#### ML-DSA sample_mask_poly 18-bit Extraction (`mldsa/poly.rs`)
- **Bug**: For gamma1=2^17, only extracted 10 bits per coefficient (buf[off] | (buf[off+1] & 0x03) << 8) instead of 18 bits. Used 5 bytes for 4 coefficients instead of 9 bytes.
- **Impact**: All mask polynomial values clustered in [gamma1-1023, gamma1] instead of being uniformly distributed in [-gamma1+1, gamma1]. This caused ||z||∞ to always be near gamma1, making the signing loop never terminate.
- **Fix**: Correct 9-byte extraction pattern: `buf[off] | (buf[off+1] << 8) | ((buf[off+2] & 0x03) << 16)` for first coefficient, etc.

#### ML-DSA ct_len Parameter (`mldsa/mod.rs`)
- **Bug**: `ct_len: 32` for all three parameter sets. FIPS 204 specifies c̃ length = λ/4 bytes.
- **Impact**: ML-DSA-65/87 signatures had wrong length (3293 vs 3309, 4563 vs 4627), causing `decode_sig` to reject them.
- **Fix**: ML-DSA-44: ct_len=32 (λ=128), ML-DSA-65: ct_len=48 (λ=192), ML-DSA-87: ct_len=64 (λ=256).

#### ML-DSA make_hint Reduction (`mldsa/poly.rs`)
- **Bug**: `highbits(caddq(r + z))` — `caddq` only adds q to negative values. But `r ∈ [0,q)` and `z ∈ (-q/2, q/2)`, so `r+z` can be in `(q, 3q/2)` which `caddq` doesn't handle.
- **Fix**: Changed to `highbits(freeze(r + z))` which applies full Barrett reduction + conditional add.

#### ML-DSA kappa Overflow (`mldsa/mod.rs`)
- **Bug**: `kappa: u16` overflowed when the signing loop iterated many times.
- **Fix**: Changed to `kappa: u32`.

### Montgomery Arithmetic Design Notes

**ML-KEM** (q=3329, R=2^16):
- 7-layer NTT (len 128→2), basemul for degree-1 polynomial pairs
- F_INV128 = R²/128 mod q = 1441
- `to_mont` needed in keygen: t_hat stays in NTT domain, must cancel basemul's R^{-1} before adding e_hat

**ML-DSA** (q=8380417, R=2^32):
- 8-layer NTT (len 128→1), pointwise multiplication
- F_INV256 = R²/256 mod q = 41978
- After `pointwise_mul` + `invntt`: result is correct (value × R^{-1} × 256 × R²/256 × R^{-1} = value)
- Standalone NTT→INTT: returns result × R (apply `montgomery_reduce` to recover)

### Cargo.toml Feature Changes
```toml
mlkem = ["sha3"]
mldsa = ["sha3"]
```

### Files Created/Modified

| File | Operation | Approx Lines |
|------|-----------|-------------|
| `crates/hitls-crypto/src/mlkem/ntt.rs` | New: NTT/INTT (q=3329) | ~130 |
| `crates/hitls-crypto/src/mlkem/poly.rs` | New: CBD, compress, encode, sampling | ~320 |
| `crates/hitls-crypto/src/mlkem/mod.rs` | Rewrite: ML-KEM KeyGen/Encaps/Decaps | ~410 |
| `crates/hitls-crypto/src/mldsa/ntt.rs` | New: NTT/INTT (q=8380417) | ~250 |
| `crates/hitls-crypto/src/mldsa/poly.rs` | New: Power2Round, Decompose, hints, sampling, packing | ~570 |
| `crates/hitls-crypto/src/mldsa/mod.rs` | Rewrite: ML-DSA KeyGen/Sign/Verify | ~600 |
| `crates/hitls-crypto/Cargo.toml` | Modified: mlkem/mldsa features | +2 |

### Test Results

| Crate | Tests | Status |
|-------|-------|--------|
| hitls-bignum | 46 | All pass |
| hitls-crypto | 205 (+30, 1 ignored) | All pass |
| hitls-utils | 11 | All pass |
| **Total** | **262** | **All pass** |

New tests (30):
- ML-KEM NTT (3): roundtrip, Barrett, Montgomery
- ML-KEM poly (1): compress/decompress
- ML-KEM KEM (10): 512/768/1024 roundtrip, tampered CT, key lengths, invalid params, encoding
- ML-DSA NTT (4): roundtrip, Montgomery, reduce32, freeze
- ML-DSA poly (6): power2round, decompose, pack/unpack t1/t0/eta/z
- ML-DSA DSA (6): 44/65/87 roundtrip, tampered sig, key lengths, invalid params

### Build Status
- Clippy: zero warnings (`RUSTFLAGS="-D warnings"`)
- Formatting: clean (`cargo fmt --check`)
- 262 workspace tests passing

### Post-Quantum Cryptography Status

| Algorithm | Status | Parameter Sets |
|-----------|--------|---------------|
| ML-KEM (FIPS 203) | **Done** | 512, 768, 1024 |
| ML-DSA (FIPS 204) | **Done** | 44, 65, 87 |
| SLH-DSA (SPHINCS+) | Stub | — |
| XMSS / XMSS^MT | Stub | — |
| FrodoKEM | Stub | — |
| Classic McEliece | Stub | — |
| Hybrid KEM | Stub | — |

---

## Phase 11: HPKE + AES Key Wrap + HybridKEM + Paillier + ElGamal (Session 2026-02-06)

### Goals
- Implement 5 remaining crypto utility modules
- Complete all crypto primitives needed before PKI/TLS phases

### Implementation

#### AES Key Wrap (RFC 3394)
- `modes/wrap.rs`: `key_wrap()`, `key_unwrap()` with 6-round Feistel structure
- Default IV = 0xA6 repeated 8 times
- Constant-time IV verification using `subtle::ConstantTimeEq`
- 3 tests: RFC 3394 §4.1/4.2/4.3 (128/192/256-bit KEK)

#### HPKE (RFC 9180)
- `hpke/mod.rs`: Full DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM
- Base mode (0x00) and PSK mode (0x01)
- `LabeledExtract`/`LabeledExpand` with proper suite_id construction
- KEM: `DeriveKeyPair`, `ExtractAndExpand` (eae_prk label), `Encap`/`Decap`
- Key schedule: `psk_id_hash`, `info_hash`, `ks_context`, `secret`, `key`, `base_nonce`, `exporter_secret`
- Seal/Open with nonce = base_nonce XOR I2OSP(seq, Nn)
- Export secret via `LabeledExpand(exporter_secret, "sec", ctx, L)`
- Added `Hkdf::from_prk()` for extract-then-expand pattern
- 7 tests: RFC 9180 A.1 vectors (KEM derive, encap/decap, key schedule, seal seq0/seq1, export, roundtrip)
- **Bug found**: ExtractAndExpand extract label is `"eae_prk"`, NOT `"shared_secret"`

#### HybridKEM (X25519 + ML-KEM-768)
- `hybridkem/mod.rs`: Combines X25519 DH + ML-KEM-768 encapsulation
- Shared secret = SHA-256(ss_classical || ss_pq)
- Ciphertext = X25519 ephemeral pk (32 bytes) || ML-KEM ciphertext
- Public key = X25519 pk (32 bytes) || ML-KEM ek (1184 bytes)
- 4 tests: roundtrip, public key length, tampered ciphertext, invalid length

#### Paillier (Additive Homomorphic Encryption)
- `paillier/mod.rs`: g = n+1 simplification
- `from_primes()` for fast testing with known primes
- Encrypt: c = (1 + m*n) * r^n mod n^2
- Decrypt: m = L(c^lambda mod n^2) * mu mod n
- Homomorphic addition: E(m1+m2) = E(m1) * E(m2) mod n^2
- 6 tests (1 ignored): encrypt/decrypt, zero, homomorphic add, large message, overflow check, 512-bit keygen

#### ElGamal (Discrete-Log Encryption)
- `elgamal/mod.rs`: Standard ElGamal with safe prime support
- `from_params()` and `from_private_key()` for testing
- `generate()` with safe prime generation (p = 2q + 1)
- Ciphertext format: 4-byte c1_len || c1 || c2
- 7 tests (1 ignored): small params, random params, message=1, large message, invalid input, deterministic pubkey, safe prime keygen

### Cargo.toml Changes
```toml
hpke = ["hkdf", "x25519", "sha2", "aes", "modes"]
hybridkem = ["x25519", "mlkem", "sha2"]
```

### Test Results
- **287 tests total** (46 bignum + 230 crypto + 11 utils), 3 ignored
- All clippy warnings resolved, formatting clean

### Next Steps
- Phase 12: X.509 Certificate Parsing + Basic PKI (critical path)
- Phase 13: X.509 Verification + Chain Building
- Phase 14: TLS 1.3 Key Schedule + Crypto Adapter

---

## Phase 12: X.509 Certificate Parsing + Signature Verification

**Date**: 2026-02-07

### Overview
Implemented X.509 certificate parsing from DER/PEM and signature verification using issuer's public key. Extended the ASN.1 decoder with 7 new methods required for X.509 structure parsing.

### ASN.1 Decoder Extensions (`hitls-utils/src/asn1/decoder.rs`)
Added 7 methods to `Decoder<'a>`:
- `peek_tag()` — non-consuming tag peek for detecting optional fields
- `read_set()` — SET parsing (for RDN in Distinguished Names)
- `read_boolean()` — BOOLEAN parsing (for extension critical flag)
- `read_context_specific(tag_num, constructed)` — context-specific tagged value
- `try_read_context_specific(tag_num, constructed)` — peek-then-read for OPTIONAL fields
- `read_string()` — UTF8String/PrintableString/IA5String/T61String/BMPString → String
- `read_time()` — UTCTime/GeneralizedTime → UNIX timestamp

Helper function `datetime_to_unix()` converts (year, month, day, hour, min, sec) to UNIX timestamp using Gregorian calendar formula with epoch offset 719468.

### OID Additions (`hitls-utils/src/oid/mod.rs`)
- 7 extension OIDs: basicConstraints(2.5.29.19), keyUsage(2.5.29.15), extKeyUsage(2.5.29.37), subjectAltName(2.5.29.17), subjectKeyIdentifier(2.5.29.14), authorityKeyIdentifier(2.5.29.35), crlDistributionPoints(2.5.29.31)
- 8 DN attribute OIDs: CN(2.5.4.3), C(2.5.4.6), O(2.5.4.10), OU(2.5.4.11), ST(2.5.4.8), L(2.5.4.7), serialNumber(2.5.4.5), emailAddress(1.2.840.113549.1.9.1)
- 2 signature OIDs: sha1WithRSAEncryption, ecdsaWithSHA512
- `oid_to_dn_short_name()` maps OID arcs to "CN", "C", "O", etc.

### X.509 Implementation (`hitls-pki/src/x509/mod.rs`)

#### Certificate Struct Extensions
Added 4 new fields (additive, existing fields unchanged):
- `tbs_raw: Vec<u8>` — raw TBS bytes for signature verification
- `signature_algorithm: Vec<u8>` — outer signature algorithm OID
- `signature_params: Option<Vec<u8>>` — outer signature algorithm params
- `signature_value: Vec<u8>` — signature bytes

#### Parsing (`Certificate::from_der`)
1. Decode outer SEQUENCE
2. Extract TBS raw bytes using `remaining()` before/after technique
3. Parse TBS: version[0], serialNumber, signature AlgId, issuer Name, validity, subject Name, SPKI, extensions[3]
4. Parse outer signatureAlgorithm + signatureValue

Key technique for TBS byte extraction:
```rust
let remaining_before = outer.remaining();
let tbs_tlv = outer.read_tlv()?;
let tbs_consumed = remaining_before.len() - outer.remaining().len();
let tbs_raw = remaining_before[..tbs_consumed].to_vec();
```

#### Distinguished Name Parsing
- RDNSequence: SEQUENCE OF SET OF SEQUENCE { OID, string }
- Maps OID to short name via `oid_to_dn_short_name()`
- `DistinguishedName::get("CN")` accessor
- `Display` impl: "CN=Test, O=OpenHiTLS, C=CN"

#### Signature Verification (`Certificate::verify_signature`)
Supports:
- SHA-1/256/384/512 with RSA PKCS#1 v1.5
- ECDSA with SHA-256/384/512 (P-256, P-384 curves)
- Ed25519 (raw message, no pre-hashing)

RSA key parsing: SPKI public_key → DER SEQUENCE { modulus INTEGER, exponent INTEGER } → RsaPublicKey::new(n, e)
EC key parsing: SPKI algorithm_params → curve OID → EccCurveId, public_key → uncompressed point

### Test Certificates
Generated with OpenSSL, embedded as hex constants:
- Self-signed RSA 2048 (SHA-256, CN=Test RSA, O=OpenHiTLS, C=CN, 36500-day validity)
- Self-signed ECDSA P-256 (SHA-256, CN=Test ECDSA, O=OpenHiTLS, C=CN)

### Test Results
- **310 tests total** (46 bignum + 230 crypto + 22 utils + 12 pki), 3 ignored
- 12 new ASN.1 decoder tests + 12 new X.509 tests
- All clippy warnings resolved, formatting clean

### Next Steps
- Phase 13: X.509 Verification + Chain Building
- Phase 14: TLS 1.3 Key Schedule + Crypto Adapter

---

## Phase 13: X.509 Verification + Chain Building (Session 2026-02-07)

### Goals
- Build and verify X.509 certificate chains (end-entity → intermediate → root CA)
- Parse BasicConstraints and KeyUsage extensions into structured types
- Implement trust store, time validity checking, and path length enforcement

### Completed Steps

#### 1. Extension Types and Parsing (`hitls-pki/src/x509/mod.rs`)
- `BasicConstraints` struct: `is_ca: bool`, `path_len_constraint: Option<u32>`
- `KeyUsage` struct with BIT STRING MSB-first flag constants (DIGITAL_SIGNATURE=0x80, KEY_CERT_SIGN=0x04, etc.)
- `parse_basic_constraints()` — SEQUENCE { BOOLEAN, INTEGER? } from extension value bytes
- `parse_key_usage()` — BIT STRING → u16 mask with unused-bits handling
- Certificate convenience methods: `basic_constraints()`, `key_usage()`, `is_ca()`, `is_self_signed()`
- `PartialEq`/`Eq` for `DistinguishedName` (needed for issuer/subject matching)

#### 2. PkiError Extensions (`hitls-types/src/error.rs`)
Added 4 new variants:
- `IssuerNotFound` — issuer certificate not in intermediates or trust store
- `BasicConstraintsViolation(String)` — non-CA cert used as issuer
- `KeyUsageViolation(String)` — CA lacks keyCertSign bit
- `MaxDepthExceeded(u32)` — chain exceeds configured depth limit

#### 3. CertificateVerifier + Chain Building (`hitls-pki/src/x509/verify.rs`, ~200 lines)
- `CertificateVerifier` struct with trust store, max_depth (default 10), verification_time
- Builder-style API: `add_trusted_cert()`, `add_trusted_certs_pem()`, `set_max_depth()`, `set_verification_time()`
- `verify_cert(cert, intermediates)` → `Result<Vec<Certificate>, PkiError>` chain building algorithm:
  1. Start with end-entity, find issuer by DN matching
  2. Verify each signature in chain
  3. Check time validity if configured
  4. Validate BasicConstraints (is_ca) and KeyUsage (keyCertSign) for all CA certs
  5. Enforce pathLenConstraint
  6. Enforce max depth, circular reference protection (100 iteration limit)
- `parse_certs_pem()` utility to parse multiple certs from a single PEM string

### Bug Found & Fixed
- **KeyUsage BIT STRING MSB numbering**: BIT STRING bit 0 = MSB of first byte (0x80), not LSB. Original constants used `1 << n` (LSB-first), causing keyCertSign check to fail. Fixed by using MSB-first values: DIGITAL_SIGNATURE=0x0080, KEY_CERT_SIGN=0x0004, CRL_SIGN=0x0002, etc.

### Test Certificates
Used real 3-cert RSA chain from C project (`testcode/testdata/tls/certificate/pem/rsa_sha256/`):
- Root CA: CN=certificate.testca.com (self-signed, pathLen=30)
- Intermediate CA: CN=certificate.testin.com (CA=true)
- End-entity: CN=certificate.testend22.com

### Test Results
- **326 tests total** (46 bignum + 230 crypto + 22 utils + 28 pki), 3 ignored
- 16 new chain verification tests:
  - Extension parsing: basic_constraints (CA/intermediate/EE), key_usage, is_ca, is_self_signed
  - Chain verification: full 3-cert chain, self-signed root, missing intermediate, expired cert, max depth exceeded, wrong trust anchor, direct trust, time within validity, parse multi-cert PEM, add_trusted_certs_pem
- All clippy warnings resolved, formatting clean

### Next Steps
- Phase 14: TLS 1.3 Key Schedule + Crypto Adapter
- Phase 15: TLS Record Layer Encryption

---

## Phase 14: TLS 1.3 Key Schedule + Crypto Adapter (Session 2026-02-06)

### Goals
- Implement TLS 1.3 key schedule (RFC 8446 §7.1): Early → Handshake → Master → Traffic Secrets
- Build HKDF primitives (Extract, Expand, Expand-Label, Derive-Secret) directly in hitls-tls
- Create transcript hash abstraction for running hash over handshake messages
- Build AEAD adapter wrapping AES-GCM and ChaCha20-Poly1305
- Derive concrete traffic keys (AEAD key + IV) from traffic secrets
- Validate against RFC 8448 (TLS 1.3 Example Handshake Traces)

### Completed Steps

#### 1. Cargo.toml + CipherSuiteParams (`crypt/mod.rs`, ~70 lines)
- Added `hitls-crypto` features `modes` and `chacha20` + `subtle` dependency
- `CipherSuiteParams` struct: suite, hash_len, key_len, iv_len, tag_len
- `from_suite()`: TLS_AES_128_GCM_SHA256→(32,16,12,16), TLS_AES_256_GCM_SHA384→(48,32,12,16), TLS_CHACHA20_POLY1305_SHA256→(32,32,12,16)
- `hash_factory()`: returns `Box<dyn Fn() -> Box<dyn Digest> + Send + Sync>` for SHA-256 or SHA-384
- `HashFactory` type alias for the factory closure type

#### 2. HKDF Primitives (`crypt/hkdf.rs`, ~180 lines)
- **Inline HMAC implementation**: `hmac_hash(factory, key, data)` — avoids `hitls_crypto::Hmac` which requires `'static` closures
- `prepare_key_block()` — hash-or-pad key to block_size, returns (key_block, block_size, output_size)
- `hkdf_extract(factory, salt, ikm)` — HMAC(salt, ikm); empty salt → hash_len zero bytes
- `hkdf_expand(factory, prk, info, length)` — iterative HMAC expansion per RFC 5869
- `encode_hkdf_label(length, label, context)` — TLS 1.3 HkdfLabel binary encoding with "tls13 " prefix
- `hkdf_expand_label(factory, secret, label, context, length)` — HKDF-Expand with HkdfLabel
- `derive_secret(factory, secret, label, transcript_hash)` — HKDF-Expand-Label(secret, label, hash, hash_len)
- 6 tests: RFC 5869 vectors (extract, expand, empty salt), SHA-384 extract, label encoding, derive_secret

#### 3. Transcript Hash (`crypt/transcript.rs`, ~65 lines)
- `TranscriptHash` struct: factory + message_buffer + hash_len
- `update(data)` — appends to buffer
- `current_hash()` — replays all buffered data through fresh hasher (non-destructive)
- `empty_hash()` — Hash("") for Derive-Secret(secret, "derived", "")
- Buffer-replay design since `Box<dyn Digest>` doesn't support Clone
- 2 tests: empty hash (SHA-256("") = e3b0c442...), incremental non-destructive

#### 4. Key Schedule (`crypt/key_schedule.rs`, ~270 lines)
- `KeyScheduleStage` enum: Initial, EarlySecret, HandshakeSecret, MasterSecret
- `KeySchedule` struct: params + hash_factory + stage + current_secret (zeroized on drop)
- Stage-enforced transitions:
  - `derive_early_secret(psk)` — Initial → EarlySecret: HKDF-Extract(salt=0, IKM=psk or 0)
  - `derive_handshake_secret(dhe)` — EarlySecret → HandshakeSecret: Derive-Secret(ES, "derived", "") → salt → Extract(salt, DHE)
  - `derive_master_secret()` — HandshakeSecret → MasterSecret: Derive-Secret(HS, "derived", "") → salt → Extract(salt, 0)
- Non-mutating derivations: `derive_handshake_traffic_secrets()`, `derive_app_traffic_secrets()`, `derive_exporter_master_secret()`, `derive_resumption_master_secret()`
- `derive_finished_key(base_key)` — HKDF-Expand-Label(key, "finished", "", hash_len)
- `compute_finished_verify_data(finished_key, hash)` — HMAC(key, hash) using inline hmac_hash
- `update_traffic_secret(current)` — HKDF-Expand-Label(secret, "traffic upd", "", hash_len)
- 5 tests: full RFC 8448 key schedule (early→HS→master→app traffic secrets), finished key, stage enforcement, traffic update, SHA-384 path

#### 5. AEAD Adapter (`crypt/aead.rs`, ~115 lines)
- `TlsAead` trait: encrypt(nonce, aad, plaintext), decrypt(nonce, aad, ct_with_tag), tag_size()
- `AesGcmAead` — wraps `hitls_crypto::modes::gcm::gcm_encrypt/decrypt`, key zeroized on drop
- `ChaCha20Poly1305Aead` — wraps `hitls_crypto::chacha20::ChaCha20Poly1305`
- `create_aead(suite, key)` — factory function dispatching by cipher suite
- 2 tests: AES-GCM and ChaCha20-Poly1305 roundtrip

#### 6. Traffic Keys (`crypt/traffic_keys.rs`, ~40 lines)
- `TrafficKeys` struct: key + iv (both zeroized on drop)
- `derive(params, traffic_secret)` — key = HKDF-Expand-Label(secret, "key", "", key_len), iv = HKDF-Expand-Label(secret, "iv", "", iv_len)
- 1 test: RFC 8448 server HS traffic secret → key/iv verification

### Bugs Found & Fixed

1. **`Hmac::new`/`Hmac::mac` require `'static` closures**: `hitls_crypto::Hmac` boxes the factory closure internally, requiring `'static`. But HKDF functions pass `&dyn Fn()` references with non-static lifetimes. Solved by implementing HMAC inline in hkdf.rs using direct `Digest` trait calls (ipad/opad XOR + inner/outer hash).

2. **RFC 8448 test vector transcription errors**: Initial transcription of server_handshake_traffic_secret had byte 20 as `dd` instead of correct `de`. The transcript hash at CH..SF was completely wrong (`96083e22...` vs correct `9608102a...`). Verified against RFC 8448 text and OpenSSL to confirm our implementation was correct.

### Test Results
- **342 tests total** (46 bignum + 230 crypto + 22 utils + 28 pki + 16 tls), 3 ignored
- 16 new TLS tests across 5 modules
- All clippy warnings resolved, formatting clean
- Full RFC 8448 Section 3 verification: early_secret, handshake_secret, client/server HS traffic secrets, master_secret, client/server app traffic secrets, traffic keys (key + iv)

### Next Steps
- Phase 15: TLS Record Layer Encryption
- Phase 16: TLS 1.3 Client Handshake

---

## Phase 15: TLS Record Layer Encryption (Session 2026-02-08)

### Goals
- Implement TLS 1.3 record-layer AEAD encryption/decryption (RFC 8446 §5)
- Nonce construction: IV XOR zero-padded sequence number (§5.3)
- Inner plaintext framing: content type hiding + padding (§5.4)
- AAD generation for TLS 1.3 (§5.2)
- Sequence number management with overflow protection
- Transparent plaintext/encrypted mode switching in RecordLayer

### Completed Steps

#### 1. Constants and Helper Functions (`record/encryption.rs`)
- `MAX_PLAINTEXT_LENGTH = 16384` (2^14), `MAX_CIPHERTEXT_OVERHEAD = 256`, `MAX_CIPHERTEXT_LENGTH = 16640`
- `build_nonce_from_iv_seq(iv, seq)` — 12-byte nonce = IV XOR [0000 || seq_be64]
- `build_aad(ciphertext_len)` — 5-byte AAD: [0x17, 0x03, 0x03, len_hi, len_lo]
- `build_inner_plaintext(content_type, plaintext, padding_len)` — content || type || zeros
- `parse_inner_plaintext(inner)` — scan from end for first non-zero byte (real content type)

#### 2. RecordEncryptor (~80 lines)
- Holds `Box<dyn TlsAead>` + IV (zeroized on drop) + 64-bit sequence number
- `new(suite, keys)` — creates AEAD via `create_aead(suite, &keys.key)`
- `encrypt_record(content_type, plaintext)` — builds inner plaintext, constructs nonce/AAD, AEAD encrypts, returns Record with outer type ApplicationData + version 0x0303
- Validates plaintext ≤ 16384, ciphertext ≤ 16640, checks seq overflow before increment

#### 3. RecordDecryptor (~80 lines)
- Same structure as encryptor (AEAD + IV + seq)
- `decrypt_record(record)` — validates ApplicationData outer type, constructs nonce/AAD, AEAD decrypts, strips inner plaintext padding, returns (real_content_type, plaintext)
- Validates fragment size bounds, plaintext size after decryption

#### 4. Enhanced RecordLayer (`record/mod.rs`, +55 lines)
- Added `pub mod encryption;` submodule
- Extended `RecordLayer` with optional `encryptor`/`decryptor` fields
- `activate_write_encryption(suite, keys)` / `activate_read_decryption(suite, keys)` — sets up AEAD for each direction
- `seal_record(content_type, plaintext)` — encrypt (if active) + serialize to wire bytes
- `open_record(data)` — parse + decrypt (if active), returns (content_type, plaintext, consumed)
- Existing `parse_record()`/`serialize_record()` unchanged, used internally

### Test Results
- **354 tests total** (46 bignum + 230 crypto + 22 utils + 28 pki + 28 tls), 3 ignored
- 12 new record encryption tests:
  - Encrypt/decrypt roundtrip (AES-128-GCM, ChaCha20-Poly1305)
  - Content type hiding (all types → ApplicationData outer)
  - Padding handling (build + parse inner plaintext)
  - Sequence number increment tracking
  - Nonce construction (manual XOR verification)
  - AAD construction (byte-level check)
  - Max record size enforcement (16384 OK, 16385 rejected)
  - Ciphertext overflow detection
  - Plaintext mode passthrough
  - Key change mid-stream (seq reset, old key fails)
  - Tampered record authentication failure
- All clippy warnings resolved, formatting clean

### Next Steps
- Phase 16: TLS 1.3 Client Handshake
- Phase 17: TLS 1.3 Server + Application Data

---

## Phase 16: TLS 1.3 Client Handshake (Session 2026-02-08)

### Goals
- Implement TLS 1.3 full 1-RTT client handshake (RFC 8446)
- Handshake message codec (ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished)
- Extensions codec (supported_versions, supported_groups, signature_algorithms, key_share, SNI)
- X25519 ephemeral key exchange
- CertificateVerify signature verification (RSA-PSS, ECDSA, Ed25519)
- Client handshake state machine
- TlsClientConnection with Read + Write transport

### Completed Steps

#### 1. Handshake Message Codec (`handshake/codec.rs`)
- `HandshakeType` enum: ClientHello(1), ServerHello(2), EncryptedExtensions(8), Certificate(11), CertificateVerify(15), Finished(20)
- `HandshakeMessage` enum with type-safe variants for each message
- `encode_handshake()` / `decode_handshake()` — 4-byte header (type + 24-bit length) + message body
- ClientHello encoding: protocol_version(0x0303), random(32), session_id, cipher_suites, compression_methods(0), extensions
- ServerHello decoding: validates version, extracts random, session_id, cipher_suite, extensions
- EncryptedExtensions, Certificate (certificate_list with DER entries), CertificateVerify (algorithm + signature), Finished (verify_data)

#### 2. Extensions Codec (`handshake/extensions_codec.rs`)
- `ExtensionType` enum: ServerName(0), SupportedGroups(10), SignatureAlgorithms(13), SupportedVersions(43), KeyShare(51)
- `encode_extensions()` — encodes list of extensions with 2-byte type + 2-byte length prefix
- `decode_extensions()` — parses extension list from byte buffer
- SNI extension: host_name type(0) with 2-byte list length + 1-byte name type + 2-byte name length
- SupportedVersions: client sends list, server sends single version (0x0304 for TLS 1.3)
- SupportedGroups: list of NamedGroup u16 values (x25519=0x001D)
- SignatureAlgorithms: list of SignatureScheme u16 values
- KeyShare: client sends list of (group, key_exchange) entries, server sends single entry

#### 3. Key Exchange (`handshake/key_exchange.rs`)
- X25519 ephemeral key pair generation using `getrandom`
- `generate_x25519_keypair()` — returns (private_key, public_key) with clamping applied
- `compute_x25519_shared_secret(private, peer_public)` — delegates to hitls-crypto X25519
- Integration with KeyShare extension encoding/decoding

#### 4. CertificateVerify Signature Verification (`handshake/verify.rs`)
- `verify_certificate_verify(cert, algorithm, signature, transcript_hash)` — verifies server's CertificateVerify
- Constructs verification message: 64 spaces + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash (RFC 8446 §4.4.3)
- Supports RSA-PSS (SHA-256/SHA-384), ECDSA (P-256/P-384), Ed25519 signature schemes
- Extracts public key from X.509 certificate and dispatches to appropriate crypto verifier

#### 5. Extended TlsConfig (`config/mod.rs`)
- Added `signature_algorithms: Vec<SignatureScheme>` — advertised signature algorithms
- Added `supported_groups: Vec<NamedGroup>` — advertised key exchange groups
- Added `verify_peer: bool` — whether to verify server certificate
- Added `trusted_certs: Vec<Certificate>` — trust store for peer verification
- Builder methods: `with_signature_algorithms()`, `with_supported_groups()`, `with_verify_peer()`, `with_trusted_certs()`

#### 6. Client Handshake State Machine (`handshake/client.rs`)
- `ClientHandshakeState` enum: Start, WaitServerHello, WaitEncryptedExtensions, WaitCertificate, WaitCertificateVerify, WaitFinished, Connected
- Full 1-RTT flow: ClientHello -> ServerHello -> [key switch] -> EncryptedExtensions -> Certificate -> CertificateVerify -> Finished -> [send client Finished] -> Connected
- Transcript hash maintained across all handshake messages
- Key schedule integration: early secret -> handshake secret (with DHE) -> handshake traffic keys -> master secret -> application traffic keys
- Record layer encryption activated after ServerHello (read) and after sending client Finished (write)

#### 7. TlsClientConnection (`connection.rs`)
- `TlsClientConnection<S: Read + Write>` — generic over transport stream
- Implements `TlsConnection` trait: `handshake()`, `read()`, `write()`, `close()`
- `handshake()` drives the state machine to completion, reading/writing records over the transport
- Post-handshake `read()`/`write()` use encrypted record layer for application data

### Scope Constraints
- X25519 key exchange only (no P-256/P-384 ECDHE)
- No HelloRetryRequest (HRR) handling
- No client certificate authentication
- No PSK or 0-RTT resumption

### Files Created/Modified
- **NEW**: `handshake/codec.rs`, `handshake/extensions_codec.rs`, `handshake/key_exchange.rs`, `handshake/verify.rs`, `handshake/client.rs`, `connection.rs`
- **MODIFIED**: `handshake/mod.rs`, `config/mod.rs`, `lib.rs`, `Cargo.toml`

### Test Results
- **377 tests total** (46 bignum + 230 crypto + 22 utils + 28 pki + 51 tls), 3 ignored
- 23 new TLS tests covering:
  - Handshake message encoding/decoding (ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished)
  - Extensions encoding/decoding (SNI, supported_versions, supported_groups, signature_algorithms, key_share)
  - X25519 key exchange (keypair generation, shared secret computation)
  - CertificateVerify signature verification (RSA-PSS, ECDSA, Ed25519)
  - TlsConfig builder with new fields
  - Client handshake state machine transitions
  - TlsClientConnection handshake flow
- All clippy warnings resolved, formatting clean

### Next Steps
- Phase 17: TLS 1.3 Server Handshake + Application Data

---

## Phase 17: TLS 1.3 Server Handshake + Application Data (Session 2026-02-08)

### Goals
- Implement TLS 1.3 server handshake state machine (RFC 8446)
- Server-side CertificateVerify signing (Ed25519, ECDSA, RSA-PSS)
- TlsServerConnection with Read + Write transport
- Full client-server handshake interop with bidirectional application data exchange

### Completed Steps

#### 1. Server Handshake State Machine (`handshake/server.rs`)
- `ServerHandshakeState` enum: Start, WaitClientHello, WaitClientFinished, Connected
- `ServerHandshake` struct with full 1-RTT server-side flow
- `process_client_hello()` — parses ClientHello, selects cipher suite, performs X25519 key exchange, builds ServerHello + EncryptedExtensions + Certificate + CertificateVerify + Finished
- `process_client_finished()` — verifies client Finished verify_data, derives application traffic keys
- Key schedule integration: early secret -> handshake secret (with DHE) -> handshake traffic keys -> master secret -> application traffic keys
- Transcript hash maintained across all handshake messages

#### 2. Server CertificateVerify Signing (`handshake/signing.rs`)
- `sign_certificate_verify(private_key, algorithm, transcript_hash)` — produces server CertificateVerify signature
- Constructs signing message: 64 spaces + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash (RFC 8446 section 4.4.3)
- Supports Ed25519, ECDSA (P-256/P-384), RSA-PSS (SHA-256/SHA-384) signature schemes
- `ServerPrivateKey` enum in config for holding server key material

#### 3. Extended Handshake Codec (`handshake/codec.rs`)
- `decode_client_hello()` — parses ClientHello message (protocol_version, random, session_id, cipher_suites, compression_methods, extensions)
- `encode_server_hello()` — builds ServerHello message
- `encode_encrypted_extensions()` — builds EncryptedExtensions message
- `encode_certificate()` — builds Certificate message with DER certificate entries
- `encode_certificate_verify()` — builds CertificateVerify message (algorithm + signature)

#### 4. Extended Extensions Codec (`handshake/extensions_codec.rs`)
- ServerHello extension builders: `build_supported_versions_sh()`, `build_key_share_sh()`
- ClientHello extension parsers: `parse_supported_versions_ch()`, `parse_supported_groups_ch()`, `parse_signature_algorithms_ch()`, `parse_key_share_ch()`, `parse_server_name_ch()`

#### 5. TlsServerConnection (`connection.rs`)
- `TlsServerConnection<S: Read + Write>` implementing `TlsConnection` trait
- Full `handshake()` orchestration: reads ClientHello, sends server flight (SH + EE + Cert + CV + Finished), reads client Finished
- Post-handshake `read()`/`write()` for encrypted application data
- `shutdown()` for close_notify

#### 6. Config Extensions (`config/mod.rs`)
- `ServerPrivateKey` enum: Ed25519(bytes), EcdsaP256(bytes), EcdsaP384(bytes), RsaPss(bytes)
- Added `certificate_chain: Vec<Vec<u8>>` — DER-encoded server certificate chain
- Added `private_key: Option<ServerPrivateKey>` — server signing key
- Builder methods: `with_certificate_chain()`, `with_private_key()`

#### 7. Handshake Module Updates (`handshake/mod.rs`)
- Added `WaitClientFinished` state to handshake state enum
- Added `pub mod server;` and `pub mod signing;` module declarations

### Scope Constraints
- X25519 key exchange only (no P-256/P-384 ECDHE)
- No HelloRetryRequest (HRR) handling
- No client certificate authentication
- No PSK or 0-RTT resumption

### Files Created/Modified
- **NEW**: `handshake/server.rs`, `handshake/signing.rs`
- **MODIFIED**: `config/mod.rs`, `handshake/codec.rs`, `handshake/extensions_codec.rs`, `connection.rs`, `handshake/mod.rs`

### Test Results
- **398 tests total** (46 bignum + 230 crypto + 22 utils + 28 pki + 72 tls), 3 ignored
- 21 new TLS tests covering:
  - ClientHello decoding, ServerHello/EncryptedExtensions/Certificate/CertificateVerify encoding
  - ServerHello extension builders, ClientHello extension parsers
  - Server CertificateVerify signing (Ed25519, ECDSA, RSA-PSS)
  - Server handshake state machine transitions
  - TlsServerConnection handshake flow
  - Full client-server handshake interop with bidirectional application data exchange
- All clippy warnings resolved, formatting clean

### Next Steps
- Phase 18: PKCS#12 + CMS + Auth Protocols

---

## Phase 18: PKCS#12 + CMS + Auth Protocols (Session 2026-02-08)

### Goals
- Implement HOTP/TOTP (RFC 4226/6238) in hitls-auth
- Implement SPAKE2+ (RFC 9382) on P-256 in hitls-auth
- Implement PKCS#12 (RFC 7292) parse/create in hitls-pki
- Implement CMS SignedData (RFC 5652) parse/verify/sign in hitls-pki
- Add ECC point_add/point_negate public methods in hitls-crypto
- Add 20+ new OIDs in hitls-utils

### Completed Steps

#### 1. HOTP/TOTP (`hitls-auth/src/otp/`)
- `Hotp` — HOTP (RFC 4226) implementation with configurable digit length (6-8)
- `Totp` — TOTP (RFC 6238) implementation with configurable time step and T0
- HMAC-based one-time password generation with dynamic truncation
- Verified against RFC 4226 Appendix D and RFC 6238 Appendix B test vectors

#### 2. SPAKE2+ (`hitls-auth/src/spake2plus/`)
- Full SPAKE2+ protocol (RFC 9382) on P-256 curve
- `Spake2PlusProver` and `Spake2PlusVerifier` roles
- Password-to-scalar derivation using HKDF
- Point blinding with M/N generators (RFC 9382 constants)
- Key confirmation via HMAC-based MAC exchange
- State machine enforcement (prevents out-of-order calls)

#### 3. PKCS#12 (`hitls-pki/src/pkcs12/`)
- `Pkcs12::parse(der, password)` — parse PFX/P12 files with MAC verification
- `Pkcs12::create(cert, key, password)` — create new PKCS#12 archives
- PKCS#12 key derivation (ID=1 key, ID=2 IV, ID=3 MAC) per RFC 7292 Appendix B
- 3DES-CBC encryption for key bags, SHA-1 HMAC for integrity
- Supports CertBag (x509Certificate) and PKCS8ShroudedKeyBag

#### 4. CMS SignedData (`hitls-pki/src/cms/`)
- `CmsSignedData::parse(der)` — parse CMS SignedData structures
- `CmsSignedData::verify(cert)` — verify signatures against signer certificate
- `CmsSignedData::sign(data, cert, key, hash_alg)` — create new SignedData
- SignerInfo with signed attributes (content-type, message-digest, signing-time)
- Supports RSA PKCS#1 v1.5 and ECDSA signature algorithms

#### 5. ECC Extensions (`hitls-crypto/src/ecc/`)
- `point_add()` — public method for elliptic curve point addition
- `point_negate()` — public method for elliptic curve point negation
- Used by SPAKE2+ for point blinding operations

#### 6. OID Extensions (`hitls-utils/src/oid/`)
- 20+ new OID constants added:
  - PKCS#12 bag types: KEY_BAG, PKCS8_SHROUDED_KEY_BAG, CERT_BAG, SAFE_CONTENTS_BAG
  - PKCS#12 certificate types: X509_CERTIFICATE
  - PBES2/PBKDF2: PBES2, PBKDF2, HMAC_SHA1, HMAC_SHA256
  - Encryption: DES_EDE3_CBC
  - PKCS#9 attributes: CONTENT_TYPE, MESSAGE_DIGEST, SIGNING_TIME
  - PKCS#7 content types: PKCS7_DATA, PKCS7_SIGNED_DATA, PKCS7_ENCRYPTED_DATA
  - Hash: SHA1
  - CMS: CMS_DATA, CMS_SIGNED_DATA

### Dependencies Added
- `hitls-auth`: Added hitls-bignum, subtle, getrandom
- `hitls-pki`: Added getrandom
- `hitls-crypto`: Additional feature dependencies

### Files Created/Modified
- **NEW**: `hitls-auth/src/otp/mod.rs`, `hitls-auth/src/spake2plus/mod.rs`
- **NEW**: `hitls-pki/src/pkcs12/mod.rs`, `hitls-pki/src/cms/mod.rs`
- **MODIFIED**: `hitls-auth/src/lib.rs`, `hitls-auth/Cargo.toml`
- **MODIFIED**: `hitls-pki/src/lib.rs`, `hitls-pki/Cargo.toml`
- **MODIFIED**: `hitls-crypto/src/ecc/` (point_add, point_negate public methods)
- **MODIFIED**: `hitls-utils/src/oid/mod.rs` (20+ new OID constants)

### Test Results
- **441 tests total** (20 auth + 46 bignum + 230 crypto + 47 pki + 72 tls + 26 utils), 3 ignored
- 43 new tests:
  - 11 OTP tests (RFC 4226 Appendix D + RFC 6238 Appendix B test vectors)
  - 9 SPAKE2+ tests (full exchange, wrong password, confirmation, state machine)
  - 4 OID tests
  - 10 PKCS#12 tests (roundtrip, MAC, wrong password)
  - 9 CMS tests (encode/parse roundtrip, content type, digest, signed attrs)
- All clippy warnings resolved, formatting clean

### Next Steps
- Phase 19: SLH-DSA (FIPS 205) + XMSS (RFC 8391)

---

## Phase 19: SLH-DSA (FIPS 205) + XMSS (RFC 8391) (Session 2026-02-08)

### Goals
- Implement SLH-DSA (Stateless Hash-Based Digital Signature Algorithm, FIPS 205) in hitls-crypto
- Implement XMSS (eXtended Merkle Signature Scheme, RFC 8391) in hitls-crypto
- Full parameter set support for both schemes
- Comprehensive tests with roundtrip verification

### Completed Steps

#### 1. SLH-DSA (`hitls-crypto/src/slh_dsa/`)

**Files created (7)**:
- `mod.rs` — Public API: `SlhDsaKeyPair`, `SlhDsaPublicKey`, `keygen()`, `sign()`, `verify()`
- `params.rs` — 12 parameter sets: SHA2/SHAKE x {128,192,256} x {s,f}
- `address.rs` — 32-byte uncompressed (SHAKE) and 22-byte compressed (SHA-2) address schemes
- `hash.rs` — Hash function abstraction: F, H, H_msg, PRF, PRF_msg for both SHA-2 and SHAKE modes
- `wots.rs` — WOTS+ one-time signatures (W=16): chain, sign, pk_from_sig, pk_gen
- `fors.rs` — FORS (Forest of Random Subsets): k trees of height a, sign and pk_from_sig
- `hypertree.rs` — Hypertree: d layers of XMSS-like trees, sign and verify

**Implementation details**:
- SHAKE mode: `SHAKE256(PK.seed || ADRS || M)` — straightforward sponge construction
- SHA-2 mode: `SHA-256/512` with padded prefix block, `MGF1` for `H_msg`, `HMAC` for `PRF_msg`
- Address scheme: 32-byte uncompressed for SHAKE, 22-byte compressed for SHA-2
- WOTS+ with Winternitz parameter W=16 (len1 + len2 chains)
- FORS with k trees of height a (varies by parameter set)
- Hypertree with d layers, each containing 2^(h/d) leaves

**Tests (10)**:
- Sign/verify roundtrip for SLH-DSA-SHA2-128f and SLH-DSA-SHAKE-128f
- Signature tamper detection
- Cross-key rejection (different key pair cannot verify)
- Signature and public key length validation
- Empty message and large message signing
- 2 tests ignored (128s variants with hp=9 are slow due to 512 leaves per tree)

#### 2. XMSS (`hitls-crypto/src/xmss/`)

**Files created (6)**:
- `mod.rs` — Public API: `XmssKeyPair`, `XmssPublicKey`, `keygen()`, `sign()`, `verify()`, stateful signing with leaf index tracking
- `params.rs` — 9 single-tree parameter sets: SHA-256/SHAKE128/SHAKE256 x h=10/16/20 (all n=32)
- `address.rs` — 32-byte address structure with OTS, L-tree, and hash tree address types
- `hash.rs` — Hash function abstraction: F, H, H_msg, PRF with ROBUST mode bitmask XOR
- `wots.rs` — WOTS+ one-time signatures: chain, sign, pk_from_sig, pk_gen (shared design with SLH-DSA)
- `tree.rs` — XMSS tree operations: L-tree compression, treehash, compute_root, sign_tree, verify_tree

**Implementation details**:
- ROBUST mode with bitmask XOR (3 hash calls per F operation, 5 per H operation)
- L-tree compression for WOTS+ public keys (iterative pairwise hashing to compress len chains into single node)
- Stateful design: `sign()` takes `&mut self`, advances leaf index, returns error on key exhaustion
- `remaining_signatures()` method to check how many signatures remain
- Single-tree only (no XMSS^MT multi-tree variant)

**Tests (9)**:
- Sign/verify roundtrip for XMSS-SHA2_10_256, XMSS-SHAKE_10_128, XMSS-SHAKE256_10_256
- Stateful signing: two consecutive signatures with automatic index advance
- Remaining signatures count validation
- Signature tamper detection
- Cross-key rejection
- Signature length validation
- 1 test ignored (XMSS-SHA2_16_256 with h=16 builds 65536 leaves — very slow)

### Bug Found and Fixed
- **wots_pk_gen sk_seed bug**: Initially passed empty `&[]` to PRF instead of actual `sk_seed` in `wots_pk_gen`. This caused tree leaves computed during keygen to differ from what sign/verify expects, because keygen and signing would derive different WOTS+ secret keys. The fix was to properly propagate the `sk_seed` parameter through `wots_pk_gen` -> `xmss_compute_root` -> `hypertree_sign`. This bug affected both SLH-DSA and XMSS since they share the WOTS+ construction.

### Files Created/Modified
- **NEW**: `hitls-crypto/src/slh_dsa/mod.rs`, `params.rs`, `address.rs`, `hash.rs`, `wots.rs`, `fors.rs`, `hypertree.rs`
- **NEW**: `hitls-crypto/src/xmss/mod.rs`, `params.rs`, `address.rs`, `hash.rs`, `wots.rs`, `tree.rs`
- **MODIFIED**: `hitls-crypto/src/lib.rs` (module declarations)
- **MODIFIED**: `hitls-crypto/Cargo.toml` (feature flags for slh-dsa and xmss)

### Test Results
- **460 tests total** (20 auth + 46 bignum + 249 crypto + 47 pki + 72 tls + 26 utils), 6 ignored
- 19 new crypto tests (10 SLH-DSA + 9 XMSS)
- 3 newly ignored tests (2 SLH-DSA 128s slow variants + 1 XMSS h=16 slow variant)
- All clippy warnings resolved, formatting clean

### Next Steps
- Phase 20: Remaining PQC (FrodoKEM, McEliece, SM9) + CLI Tool + Integration Tests

---

## Phase 20: FrodoKEM + SM9 + Classic McEliece + CLI Tool + Integration Tests (Session 2026-02-06)

### Goals
- Implement FrodoKEM (LWE-based KEM) with 12 parameter sets
- Implement SM9 (identity-based encryption with BN256 pairing)
- Implement Classic McEliece (code-based KEM) with 12 parameter sets
- Create functional CLI tool with dgst, genpkey, x509, verify commands
- Add cross-crate integration tests

### Completed Steps

#### 1. FrodoKEM (LWE-based KEM)
**New files:**
- `hitls-crypto/src/frodokem/params.rs` — 12 param sets (640/976/1344 × SHAKE/AES × Level 1/3/5)
- `hitls-crypto/src/frodokem/matrix.rs` — Matrix A generation (SHAKE128/AES128), matrix multiply-add
- `hitls-crypto/src/frodokem/pke.rs` — Inner PKE: keygen, encrypt, decrypt
- `hitls-crypto/src/frodokem/util.rs` — Pack/unpack, encode/decode, CDF sampling, CT verify/select
- `hitls-crypto/src/frodokem/mod.rs` — Public API (FrodoKemKeyPair) + 8 tests

**Tests:** 8 (2 ignored for slow 976/1344 variants)

#### 2. SM9 (Identity-Based Encryption)
**New files (11):**
- `hitls-crypto/src/sm9/curve.rs` — BN256 curve parameters
- `hitls-crypto/src/sm9/fp.rs` — Fp modular arithmetic
- `hitls-crypto/src/sm9/fp2.rs` — Fp2 = Fp[u]/(u²+2)
- `hitls-crypto/src/sm9/fp4.rs` — Fp4 = Fp2[v]/(v²-u)
- `hitls-crypto/src/sm9/fp12.rs` — Fp12 = Fp4[w]/(w³-v) with final exponentiation
- `hitls-crypto/src/sm9/ecp.rs` — G1 points (Jacobian coordinates)
- `hitls-crypto/src/sm9/ecp2.rs` — G2 points on twisted curve
- `hitls-crypto/src/sm9/pairing.rs` — R-ate pairing (Miller loop + final exp)
- `hitls-crypto/src/sm9/hash.rs` — H1/H2 hash-to-range, KDF
- `hitls-crypto/src/sm9/alg.rs` — Sign/Verify, Encrypt/Decrypt, key extraction
- `hitls-crypto/src/sm9/mod.rs` — Public API (Sm9MasterKey, Sm9UserKey) + 8 tests

**Tests:** 8

#### 3. Classic McEliece (Code-Based KEM)
**New files (10):**
- `hitls-crypto/src/mceliece/params.rs` — 12 param sets (3 families × 4 variants)
- `hitls-crypto/src/mceliece/gf.rs` — GF(2^13) arithmetic (LOG/EXP tables, OnceLock init)
- `hitls-crypto/src/mceliece/poly.rs` — Polynomial over GF(2^13), irreducible poly generation
- `hitls-crypto/src/mceliece/matrix.rs` — Parity-check matrix, Gaussian elimination
- `hitls-crypto/src/mceliece/benes.rs` — Benes network (control bits from permutation)
- `hitls-crypto/src/mceliece/decode.rs` — Berlekamp-Massey decoding
- `hitls-crypto/src/mceliece/encode.rs` — Error vector generation, syndrome computation
- `hitls-crypto/src/mceliece/keygen.rs` — Full keygen (Goppa poly + support + SHAKE256 PRG)
- `hitls-crypto/src/mceliece/vector.rs` — Bit vector operations
- `hitls-crypto/src/mceliece/mod.rs` — Public API (McElieceKeyPair) + 12 tests

**Key bugs fixed:**
- GF(2^13) generator must be 3 (not 2): `a * 3 = (a << 1) ^ a` with reduction
- Benes layer_bytes formula `n >> 4` only works for n >= 16

**Tests:** 12 (2 ignored for slow 6688128/8192128 keygen)

#### 4. CLI Tool
**New files (7):**
- `hitls-cli/src/dgst.rs` — Hash files with SHA-256, SHA-512, SM3, MD5, SHA-1, SHA3-256, SHA3-512
- `hitls-cli/src/genpkey.rs` — Generate RSA, EC, Ed25519, X25519, ML-KEM, ML-DSA keys
- `hitls-cli/src/x509cmd.rs` — Parse and display X.509 certificates
- `hitls-cli/src/verify.rs` — Verify certificate chains with trust store
- `hitls-cli/src/enc.rs` — AES-256-GCM encrypt/decrypt (partial)
- `hitls-cli/src/pkey.rs` — Display PEM key info (partial)
- `hitls-cli/src/crl.rs` — CRL display (stub)

**Modified:** `hitls-cli/src/main.rs`, `hitls-cli/Cargo.toml`

#### 5. Integration Tests
**New files:**
- `tests/interop/Cargo.toml` — Integration test crate
- `tests/interop/src/lib.rs` — 10 cross-crate roundtrip tests:
  1. RSA + ECDSA sign/verify same message
  2. AES-GCM encrypt + HMAC-SHA256 integrity
  3. PBKDF2 → AES-GCM encrypt/decrypt
  4. Ed25519 sign/verify with serialized public key
  5. P-384 ECDSA sign/verify
  6. X.509 cert parse + signature verify
  7. X.509 chain verification (root → intermediate → leaf)
  8. ML-KEM all param sets (512/768/1024)
  9. ML-DSA all param sets (44/65/87)
  10. HybridKEM (X25519+ML-KEM-768) roundtrip

### Files Changed
- **NEW**: 29 source files across frodokem, sm9, mceliece, CLI, and integration tests
- **MODIFIED**: `Cargo.toml` (workspace members), `hitls-crypto/Cargo.toml` (feature flags), `hitls-types/src/error.rs` (new error variants)

### Test Results
- **499 tests total** (20 auth + 46 bignum + 278 crypto + 47 pki + 72 tls + 26 utils + 10 integration), 18 ignored
- 39 new tests (8 FrodoKEM + 8 SM9 + 12 McEliece + 10 integration + 1 CLI build)
- All clippy warnings resolved, formatting clean

### Migration Complete
All 21 phases (0-20) of the openHiTLS C-to-Rust migration are now complete.

---

## Phase 21, Step 3: PSK / Session Tickets

- Implemented PSK session resumption for TLS 1.3 (RFC 8446 §4.2.11, §4.6.1)
- Added NewSessionTicket codec (encode/decode), ticket encryption/decryption (XOR + HMAC)
- Added PSK extension codec: pre_shared_key (CH/SH), psk_key_exchange_modes
- Added KeySchedule methods: derive_binder_key, derive_resumption_psk
- Client: PSK in ClientHello with binder computation, PSK mode detection, NST processing
- Server: PSK verification (binder check), PSK mode (skip cert/CV), NST generation
- Connection: server sends NST post-handshake, client handles NST in read() loop
- InMemorySessionCache with max-size eviction
- 8 new tests: session resumption roundtrip, NST generation, ticket encrypt/decrypt, binder computation, cache operations, PSK extension codec, resumption_master_secret derivation
- 97 TLS tests, 524 workspace total

---

## Phase 21, Step 4: 0-RTT Early Data

- Implemented 0-RTT Early Data for TLS 1.3 (RFC 8446 §4.2.10, §2.3)
- Added EndOfEarlyData codec (encode/decode) for handshake message type
- Added KeySchedule method: derive_early_traffic_secret (client_early_traffic_secret from PSK-based early secret)
- Added early_data extension support in ClientHello, EncryptedExtensions, and NewSessionTicket
- Connection integration: queue_early_data for client-side 0-RTT data, EndOfEarlyData (EOED) flow for transitioning out of early data
- Server-side: early data acceptance/rejection logic in EncryptedExtensions
- 5 new tests: test_end_of_early_data_codec, test_early_data_accepted, test_early_data_rejected, test_early_data_multiple_records, test_early_data_nst_extension
- **Key bugs fixed:**
  1. Server early traffic secret was derived from Hash(CH||SH) instead of Hash(CH) — fixed by moving early key derivation before ServerHello in build_server_flight
  2. Client app traffic secrets were derived from Hash(CH..SF..EOED) instead of Hash(CH..SF) — fixed by reordering EOED transcript update to after app secret derivation per RFC 8446 §7.1
- 102 TLS tests, 529 workspace total

---

## Phase 21, Step 5: Post-Handshake Client Auth

- Implemented Post-Handshake Client Authentication for TLS 1.3 (RFC 8446 §4.6.2)
- CertificateRequest codec (encode/decode) in codec.rs
- build_post_handshake_auth() extension in extensions_codec.rs
- Config additions: client_certificate_chain, client_private_key, post_handshake_auth
- is_server parameter added to sign_certificate_verify and verify_certificate_verify
- Client: handle_post_hs_cert_request method, builds Certificate + CertificateVerify + Finished response
- Server: request_client_auth() method on TlsServerConnection, sends CertificateRequest, reads/verifies client response
- Helper: build_ed25519_der_cert() for building test certs
- **Bug fixed**: SPKI construction in cert builder was missing AlgorithmIdentifier SEQUENCE wrapper
- 6 new tests: test_certificate_request_codec, test_post_hs_auth_codec, test_post_hs_auth_roundtrip, test_post_hs_auth_no_cert, test_post_hs_auth_not_offered, test_post_hs_auth_server_not_connected
- 108 TLS tests, 535 workspace total

---

## Phase 22: ECC Curve Additions

### Goals
- Add P-224, P-521, Brainpool P-256r1, Brainpool P-384r1, Brainpool P-512r1 curves
- Extend ECDSA and ECDH to support all new curves
- Add OID mappings and X.509/CMS curve support

### Completed Steps

#### 1. New ECC Curves
- **P-224 (secp224r1)**: FIPS 186-4, 224-bit prime curve
- **P-521 (secp521r1)**: FIPS 186-4, 521-bit prime curve
- **Brainpool P-256r1**: RFC 5639, 256-bit prime curve
- **Brainpool P-384r1**: RFC 5639, 384-bit prime curve
- **Brainpool P-512r1**: RFC 5639, 512-bit prime curve

#### 2. Key Implementation Details
- Added generic point doubling for Brainpool curves where a ≠ p−3 (NIST curves use an optimized doubling formula that assumes a = p−3; Brainpool curves have arbitrary a values)
- Fixed Brainpool P-384r1 prime (p) and P-512r1 curve parameter (a) hex values from RFC 5639
- Added OID constants for all new curves
- Extended X.509 and CMS curve mappings to support the new curves

#### 3. Tests
- 16 new ECC tests (point operations, scalar multiplication, roundtrips for each curve)
- 5 new ECDSA tests (sign/verify for each new curve)
- 5 new ECDH tests (key exchange for each new curve)
- 26 new tests total, 1 additional ignored (slow keygen)

### Test Results
- **561 tests total** (20 auth + 46 bignum + 304 crypto + 47 pki + 108 tls + 26 utils + 10 integration), 19 ignored
- hitls-crypto: 304 tests (19 ignored)
- All clippy warnings resolved, formatting clean

---

## Phase 21 Completion — Certificate Compression (RFC 8879)

### Summary
Implemented the remaining Phase 21 feature: TLS Certificate Compression (RFC 8879). Also fixed the README Phase 21 table to correctly mark HRR and KeyUpdate as Done (they were already implemented but the docs were outdated).

### Changes

#### 1. Certificate Compression (RFC 8879)
- **Extension**: `compress_certificate` (type 27) — client sends list of supported compression algorithms in ClientHello
- **Message**: `CompressedCertificate` (handshake type 25) — server sends compressed Certificate message body
- **Algorithm**: zlib (algorithm ID 1) via `flate2` crate, feature-gated behind `cert-compression`
- **Protocol flow**: Client advertises → Server compresses Certificate body → Client decompresses and processes normally
- **Transcript**: Uses CompressedCertificate message as-is in transcript hash (per RFC 8879 §4)
- **Safety**: 16 MiB decompression limit, uncompressed_length validation

#### 2. Dependencies
- Added `flate2 = "1"` to workspace (pure Rust via miniz_oxide backend)
- Feature flag `cert-compression = ["flate2"]` in hitls-tls

#### 3. Files Modified
- `Cargo.toml` (workspace): Added `flate2` dependency
- `crates/hitls-tls/Cargo.toml`: Added `flate2` optional dep + `cert-compression` feature
- `crates/hitls-tls/src/extensions/mod.rs`: Added `COMPRESS_CERTIFICATE` constant
- `crates/hitls-tls/src/handshake/mod.rs`: Added `CompressedCertificate` variant
- `crates/hitls-tls/src/handshake/codec.rs`: Added codec, compress/decompress helpers
- `crates/hitls-tls/src/handshake/extensions_codec.rs`: Added build/parse for extension
- `crates/hitls-tls/src/config/mod.rs`: Added `cert_compression_algos` config field
- `crates/hitls-tls/src/handshake/client.rs`: Extension in CH, `process_compressed_certificate()`
- `crates/hitls-tls/src/handshake/server.rs`: Parse extension, compress Certificate when negotiated
- `crates/hitls-tls/src/connection.rs`: Dispatch CompressedCertificate in WaitCertCertReq state

#### 4. Tests (7 new)
- `test_compressed_certificate_codec_roundtrip` — encode/decode CompressedCertificate message
- `test_compress_decompress_zlib` — compress/decompress Certificate body roundtrip
- `test_build_parse_compress_certificate` — extension encode/decode roundtrip
- `test_build_parse_compress_certificate_single` — single algorithm extension
- `test_cert_compression_config` — config builder test
- `test_cert_compression_handshake` — full client-server handshake with compression
- `test_cert_compression_server_disabled` — normal Certificate when server doesn't enable compression

### Test Results
- **568 tests total** (20 auth + 46 bignum + 304 crypto + 47 pki + 115 tls + 26 utils + 10 integration), 19 ignored
- All clippy warnings resolved, formatting clean

---

## Phase 23: CTR-DRBG + Hash-DRBG + PKCS#8 Key Parsing (Session 2026-02-08)

### Goals
- Add CTR-DRBG (NIST SP 800-90A §10.2) and Hash-DRBG (§10.1.1) to complement existing HMAC-DRBG
- Implement PKCS#8 private key parsing/encoding (RFC 5958) for interoperability
- Refactor DRBG module into multi-file structure

### Completed Steps

#### 1. DRBG Module Refactoring
- Split single-file `drbg/mod.rs` into multi-file module:
  - `mod.rs` — re-exports + shared constants
  - `hmac_drbg.rs` — existing HmacDrbg (moved from mod.rs, unchanged)
  - `ctr_drbg.rs` — new CTR-DRBG
  - `hash_drbg.rs` — new Hash-DRBG
- Updated `drbg` feature to include `aes` dependency: `drbg = ["hmac", "sha2", "aes"]`

#### 2. CTR-DRBG (NIST SP 800-90A §10.2)
- **Structure**: `CtrDrbg { key: [u8; 32], v: [u8; 16], reseed_counter: u64 }`
- **Constants**: KEY_LEN=32 (AES-256), BLOCK_LEN=16, SEED_LEN=48, RESEED_INTERVAL=2^48
- **Core functions**:
  - `new(seed_material)` — instantiate without DF (requires 48-byte seed)
  - `with_df(entropy, nonce, personalization)` — instantiate with block_cipher_df
  - `update(provided_data)` — generate AES-ECB blocks via V+1→encrypt, XOR with data, split into Key+V
  - `generate(output, additional_input)` — check reseed, optional update, generate blocks, final update
  - `reseed(entropy, additional_input)` — combine + update + reset counter
  - `block_cipher_df(input, output_len)` — BCC-based derivation using AES CBC-MAC
- Uses `crate::aes::AesKey` for single-block AES-256 encryption
- 11 tests: instantiate, invalid_len, generate, deterministic, reseed, additional_input, large_output, with_df, nist_vector, block_cipher_df, increment_counter

#### 3. Hash-DRBG (NIST SP 800-90A §10.1.1)
- **Structure**: `HashDrbg { v: Vec<u8>, c: Vec<u8>, seed_len: usize, hash_type: HashDrbgType, reseed_counter: u64 }`
- **Hash types**: Sha256 (seedLen=55), Sha384 (seedLen=111), Sha512 (seedLen=111) per SP 800-90A Table 2
- **Core functions**:
  - `new(hash_type, seed_material)` — V = hash_df(seed), C = hash_df(0x00||V)
  - `hash_df(input, output_len)` — counter-mode: Hash(counter || len_bits_be32 || input)
  - `generate(output, additional_input)` — optional w=Hash(0x02||V||adin), hashgen, H=Hash(0x03||V), V=(V+H+C+counter)
  - `hashgen(v, output_len)` — data=V, generate Hash(data) blocks, data+=1 mod 2^seedlen
  - `reseed(entropy, additional_input)` — seed=0x01||V||entropy||adin, V=hash_df, C=hash_df(0x00||V)
  - `v_add(values)` / `v_add_u64(val)` — big-endian modular addition with carry
- 11 tests: sha256_instantiate, sha256_generate, sha256_deterministic, sha256_reseed, sha256_additional_input, sha512_generate, sha384_generate, large_output, hash_df, v_add, v_add_u64

#### 4. PKCS#8 Key Parsing (RFC 5958)
- **File**: `crates/hitls-pki/src/pkcs8/mod.rs`
- **Enum**: `Pkcs8PrivateKey { Rsa, Ec, Ed25519, X25519, Dsa }`
- **OID dispatch**:
  - RSA (`1.2.840.113549.1.1.1`) → parse RSAPrivateKey SEQUENCE → `RsaPrivateKey::new(n,d,e,p,q)`
  - EC (`1.2.840.10045.2.1`) → params=curve OID→EccCurveId, ECPrivateKey → `EcdsaKeyPair::from_private_key()`
  - Ed25519 (`1.3.101.112`) → inner OCTET STRING 32 bytes → `Ed25519KeyPair::from_seed()`
  - X25519 (`1.3.101.110`) → inner OCTET STRING 32 bytes → `X25519PrivateKey::new()`
  - DSA (`1.2.840.10040.4.1`) → params=(p,q,g), privateKey INTEGER → `DsaKeyPair::from_private_key()`
- **Encode helpers**: `encode_pkcs8_der_raw()`, `encode_pkcs8_pem_raw()`, `encode_ed25519_pkcs8_der()`, `encode_x25519_pkcs8_der()`, `encode_ec_pkcs8_der()`
- Added DSA OID to `hitls-utils/src/oid/mod.rs`
- Added `pkcs8` feature to `hitls-pki/Cargo.toml`, added `x25519` and `dsa` to hitls-crypto deps
- 10 tests: parse_ed25519, parse_x25519, parse_rsa_pem (real 2048-bit key from C test data), parse_ec_p256, parse_ec_p384, parse_dsa, pem_roundtrip, ec_roundtrip, ed25519_roundtrip, invalid_version

### Files Created/Modified

| File | Operation | Approx Lines |
|------|-----------|-------------|
| `crates/hitls-crypto/src/drbg/mod.rs` | Rewritten: module root with re-exports | ~20 |
| `crates/hitls-crypto/src/drbg/hmac_drbg.rs` | New: moved from mod.rs | ~280 |
| `crates/hitls-crypto/src/drbg/ctr_drbg.rs` | New: CTR-DRBG | ~450 |
| `crates/hitls-crypto/src/drbg/hash_drbg.rs` | New: Hash-DRBG | ~500 |
| `crates/hitls-pki/src/pkcs8/mod.rs` | New: PKCS#8 parse/encode | ~650 |
| `crates/hitls-crypto/Cargo.toml` | Modified: drbg adds aes | +1 |
| `crates/hitls-pki/Cargo.toml` | Modified: pkcs8 feature, x25519+dsa deps | +5 |
| `crates/hitls-pki/src/lib.rs` | Modified: add pkcs8 module | +1 |
| `crates/hitls-utils/src/oid/mod.rs` | Modified: add DSA OID | +5 |

### Bugs Found & Fixed
- **`crate::aes::Aes` not found**: AES struct is `AesKey`, not `Aes`. Fixed import.
- **`CryptoError::UnsupportedAlgorithm` doesn't exist**: Used `CryptoError::DecodeUnknownOid` instead.
- **Invalid RSA test key**: Made-up n,d,p,q values weren't mathematically valid (p*q≠n). Replaced with real RSA PEM from C test data.
- **Clippy `manual_div_ceil`**: Changed to `.div_ceil()` method.

### Test Results

| Crate | Tests | Status |
|-------|-------|--------|
| hitls-auth | 20 | All pass |
| hitls-bignum | 46 | All pass |
| hitls-crypto | 326 (+22, 19 ignored) | All pass |
| hitls-pki | 57 (+10) | All pass |
| hitls-tls | 115 | All pass |
| hitls-utils | 26 | All pass |
| integration | 10 | All pass |
| **Total** | **600** | **All pass** |

New tests (32):
- CTR-DRBG (11): instantiate, invalid_len, generate, deterministic, reseed, additional_input, large_output, with_df, nist_vector, block_cipher_df, increment_counter
- Hash-DRBG (11): sha256_instantiate, sha256_generate, sha256_deterministic, sha256_reseed, sha256_additional_input, sha512_generate, sha384_generate, large_output, hash_df, v_add, v_add_u64
- PKCS#8 (10): parse_ed25519, parse_x25519, parse_rsa_pem, parse_ec_p256, parse_ec_p384, parse_dsa, pem_roundtrip, ec_roundtrip, ed25519_roundtrip, invalid_version

### Build Status
- Clippy: zero warnings (`RUSTFLAGS="-D warnings"`)
- Formatting: clean (`cargo fmt --check`)
- 600 workspace tests passing (19 ignored)

---

## Phase 24: CRL Parsing + Validation + Revocation Checking + OCSP (Session 2026-02-09)

### Goals
- Parse X.509 CRLs (Certificate Revocation Lists) per RFC 5280 §5
- Verify CRL signatures against issuer certificates
- Integrate revocation checking into CertificateVerifier
- Implement basic OCSP (RFC 6960) request/response parsing (offline, no HTTP)

### Completed Steps

#### Step 1: Add CRL/OCSP OIDs + Make mod.rs Helpers pub(crate)

**File**: `crates/hitls-utils/src/oid/mod.rs`
- Added 9 CRL/OCSP OIDs: `crl_number`, `crl_reason`, `invalidity_date`, `delta_crl_indicator`, `issuing_distribution_point`, `authority_info_access`, `ocsp`, `ocsp_basic`, `ca_issuers`

**File**: `crates/hitls-pki/src/x509/mod.rs`
- Changed 9 helpers to `pub(crate)`: `parse_algorithm_identifier`, `parse_name`, `parse_extensions`, `HashAlg`, `compute_hash`, `verify_rsa`, `verify_ecdsa`, `verify_ed25519`, `oid_to_curve_id`
- Added `pub mod crl;` and `pub mod ocsp;` declarations
- Replaced CRL struct stubs with `pub use crl::{ ... }` re-exports
- Added OCSP type re-exports

#### Step 2: CRL Parsing + Verification (13 tests)

**File**: `crates/hitls-pki/src/x509/crl.rs` (new, ~410 lines)

Structures:
- `CertificateRevocationList`: raw, version, signature_algorithm, signature_params, issuer, this_update, next_update, revoked_certs, extensions, tbs_raw, signature_value
- `RevokedCertificate`: serial_number, revocation_date, reason, invalidity_date, extensions
- `RevocationReason` enum (0=Unspecified through 10=AaCompromise, 7 unused)

API:
- `from_der()`, `from_pem()` — full CRL parsing with version detection, entry extensions
- `is_revoked(serial)` — serial number lookup with leading-zero stripping
- `verify_signature(issuer)` — reuses RSA/ECDSA/Ed25519 signature verification
- `crl_number()` — extract CRL number extension
- `parse_crls_pem()` — parse multiple CRLs from PEM
- `verify_signature_with_oid()` — pub(crate) helper reused by OCSP

Test data from C project: `testcode/testdata/cert/test_for_crl/` (PEM-encoded .crl files)

**Bugs found and fixed**:
- **ASN.1 Tag number for SEQUENCE**: `tags::SEQUENCE = 0x30` but `Tag.number` stores only the 5-bit tag number (0x10). Used `tag.number == 0x10` for SEQUENCE comparisons.
- **PEM vs DER**: Test `.crl` files are PEM-encoded despite `.crl` extension. Changed to `include_str!` + `from_pem()`.
- **Zero-length nextUpdate**: One CRL has empty UTCTIME for nextUpdate. Used `.ok()` to treat parse failure as absent.

#### Step 3: Revocation Checking in CertificateVerifier (3 tests)

**File**: `crates/hitls-pki/src/x509/verify.rs`

New fields/methods:
- `crls: Vec<CertificateRevocationList>`, `check_revocation: bool` (default false)
- `add_crl()`, `add_crls_pem()`, `set_check_revocation()` builder methods

Revocation checking logic (`check_revocation_status`):
- For each cert in chain except root: find CRL matching issuer DN
- Verify CRL signature with issuer cert
- Check CRL time validity (thisUpdate ≤ now ≤ nextUpdate)
- If cert serial found in revoked list → `Err(PkiError::CertRevoked)`
- Soft-fail if no CRL found for issuer (no error, just skip)

Tests: `verify_chain_with_crl_revoked`, `verify_chain_with_crl_not_revoked`, `verify_chain_no_revocation_check_default`

#### Step 4: Basic OCSP Message Parsing (8 tests)

**File**: `crates/hitls-pki/src/x509/ocsp.rs` (new, ~480 lines)

Structures:
- `OcspCertId`: hash_algorithm, issuer_name_hash, issuer_key_hash, serial_number
- `OcspRequest`: request_list, nonce
- `OcspResponse`: status, basic_response
- `OcspBasicResponse`: tbs_raw, responder_id, produced_at, responses, signature_algorithm, signature, certs
- `OcspSingleResponse`: cert_id, status, this_update, next_update
- `OcspCertStatus`: Good, Revoked { time, reason }, Unknown
- `OcspResponseStatus`: Successful, MalformedRequest, InternalError, TryLater, SigRequired, Unauthorized
- `ResponderId`: ByName, ByKey

API:
- `OcspCertId::new(cert, issuer)` — SHA-256 based cert ID
- `OcspCertId::to_der()`, `matches()` — encode/compare
- `OcspRequest::new(cert, issuer)`, `to_der()` — build OCSP request
- `OcspResponse::from_der()` — parse full OCSP response
- `OcspBasicResponse::verify_signature(issuer)`, `find_response(cert_id)`

Encoder helper pattern: `enc_seq()`, `enc_octet()`, `enc_oid()`, etc. — wrapper functions for Encoder's `&mut Self` → `finish(self)` ownership issue.

Synthetic test data: `build_test_ocsp_response()` constructs DER for testing without real OCSP server data.

### Test Results

| Crate | Tests | Status |
|-------|-------|--------|
| hitls-auth | 20 | All pass |
| hitls-bignum | 46 | All pass |
| hitls-crypto | 326 (19 ignored) | All pass |
| hitls-pki | 81 (+24) | All pass |
| hitls-tls | 115 | All pass |
| hitls-utils | 26 | All pass |
| integration | 10 | All pass |
| **Total** | **624** | **All pass** |

New tests (24):
- CRL (13): parse_crl_v1_pem, parse_crl_v2_pem, parse_crl_v2_empty, parse_crl_no_next_update, parse_crl_reason_codes, parse_crl_invalidity_date, verify_crl_signature, verify_crl_v2_signature, verify_crl_signature_wrong_issuer, is_revoked_found, is_revoked_not_found, parse_crls_pem_multiple, crl_v2_reason_key_compromise
- Verify+CRL (3): verify_chain_with_crl_revoked, verify_chain_with_crl_not_revoked, verify_chain_no_revocation_check_default
- OCSP (8): ocsp_cert_id_new, ocsp_cert_id_matches, ocsp_cert_id_to_der_roundtrip, ocsp_request_to_der, ocsp_response_non_successful, ocsp_response_parse_good, ocsp_response_parse_revoked, ocsp_response_find_response

### Build Status
- Clippy: zero warnings (`RUSTFLAGS="-D warnings"`)
- Formatting: clean (`cargo fmt --check`)
- 624 workspace tests passing (19 ignored)
