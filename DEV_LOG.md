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
