# Performance Comparison: openHiTLS (C) vs openHiTLS-rs (Rust)

> **Date**: 2026-03-02 (P1–P62, I83–I84 complete) | **Platform**: Apple M4, macOS 15.4, 10 cores, 16 GB RAM
> **Benchmark suite**: 291 test points across 59 algorithm groups (expanded from 120 points / 21 groups)

---

## 1. Executive Summary

Comprehensive benchmarks across 59 algorithm groups (291 test points) comparing the original C openHiTLS against the Rust rewrite. All Rust numbers from Criterion 0.5 runs (rustc 1.93.0, 2026-03-02) after all 62 performance optimization phases. The benchmark suite covers 100% of implemented algorithm modules.

| Category | Verdict | Detail |
|----------|---------|--------|
| **AES (CBC/CTR/GCM)** | **Rust 2.8–8.4x faster** | Both use ARM Crypto Extension; Rust benefits from monomorphization + LTO |
| **AES (ECB/XTS/CFB/OFB/CCM)** | **Rust-only data** | 1.2–2.9 GB/s (ECB), 1.2–1.5 GB/s (XTS), 0.7–1.1 GB/s (CFB), 0.8–1.3 GB/s (CCM) |
| **ChaCha20-Poly1305** | **Rust 1.3x faster** | Rust 450 MB/s vs C 344 MB/s (isolated run) |
| **Hash (SHA-256/384/512)** | **Rust 1.6–4.4x faster** | SHA-256 HW 4.4x; SHA-512/384 HW 1.6–2.9x |
| **SHA-3 / SHAKE** | **Rust-only data** | SHA3-256: 321 MB/s, SHAKE128: 196 MB/s (software Keccak + HW accel) |
| **SM3** | **C 1.7x faster** | P56 ring buffer; no HW accel available |
| **HMAC** | **Rust 0.9–6.9x** | HMAC-SHA256 6.9x; HMAC-SHA512 2.6x; HMAC-SM3 near parity (C 1.09x) |
| **CMAC / GMAC** | **Rust-only data** | CMAC-AES128: 908 MB/s; GMAC-AES128: 865 MB/s |
| **SM4 (CBC/GCM/CCM)** | **Rust 1.1–1.7x faster** | T-table + GHASH HW; all ops now Rust faster |
| **ECDSA P-256** | **Near parity** | P-256 fast path: sign C 1.18x, **verify Rust 1.14x faster** (P54) |
| **ECDSA P-384/P-521** | **Rust-only data** | P-384: sign 421 ops/s, verify 336 ops/s; P-521: 253/173 ops/s |
| **ECDH P-256/384/521** | **C 1.2x (P-256)** | P-256 fast path; P-384/P-521 generic windowed scalar mul |
| **Ed25519 / X25519** | **Near parity** | Sign near parity; verify C 1.24x; X25519 C 1.49x |
| **Ed448 / X448** | **Rust-only data** | Ed448 sign 1.5K ops/s; X448 DH 2.3K ops/s |
| **SM2** | **Rust 2.0–5.3x faster** | Specialized Montgomery field + precomputed comb table |
| **RSA-2048** | **Rust-only data** | C RSA not registered in benchmark binary |
| **ML-KEM (Kyber)** | **C 1.6–4.1x faster** | Major improvement from P58 clone elim + P59 Keccak unroll |
| **ML-DSA (Dilithium)** | **Rust 1.0–1.7x faster (sign)** | ML-DSA-44/87 sign now **faster than C** |
| **SLH-DSA (SPHINCS+)** | **Rust-only data** | SHA2-128f keygen 2.8K ops/s, sign 117 ops/s, verify 2.0K ops/s |
| **HybridKEM** | **Rust-only data** | X25519+ML-KEM-768 encaps: 15.5K ops/s |
| **FrodoKEM** | **Rust-only data** | 640-SHAKE: 241/408/402 ops/s (kg/enc/dec); 976-SHAKE: 105/185/184 ops/s |
| **McEliece-6688128** | **Rust-only data** | Encaps 2.4K ops/s; decaps 59 ops/s (code-based KEM) |
| **XMSS** | **Rust-only data** | SHA2-10-256 verify: 6.0K ops/s (hash-based stateful signature) |
| **DH (FFDHE)** | **C 3.1–7.1x faster** | P53 CIOS inner loop; gap narrowed ~30% from P52 |
| **KDF (HKDF/PBKDF2/scrypt)** | **Rust-only data** | HKDF 32B: 641 ns; PBKDF2-10K: 1.67 ms; scrypt-16384: 31 ms |

**Bottom line**: Symmetric ciphers (AES, ChaCha20) and hashes (SHA-256/384/512) remain **faster in Rust**. Phase P54–P62 delivered major improvements: **ECDSA P-256 verify now faster than C** (P54 scalar field), **ML-DSA-44/87 sign now faster than C** (P57/P59 Keccak unroll), ML-KEM gap narrowed to 1.6–4.1x (P58/P59), Ed25519 verify improved 23% (P55), X25519 DH improved 12% (P60). The benchmark suite now covers all 33 algorithm modules with 291 test points across 59 groups.

> **Note**: Core symmetric/hash/HMAC C-comparison numbers from isolated benchmark runs (thermal-stable). New algorithm benchmarks from targeted isolated runs. BigNum-dependent (RSA, DH, mod_exp) from P53 isolated runs.

---

## 2. Test Environment

| Item | Specification |
|------|---------------|
| **CPU** | Apple M4 (ARM64, 10 cores, AES + SHA2 + SHA512 Crypto Extension) |
| **RAM** | 16 GB |
| **OS** | macOS 15.4 (Darwin 25.3.0, arm64) |
| **C Compiler** | Apple Clang 17.0.0 (`-O2`, static link) |
| **C Build** | CMake Release, `libhitls_crypto.a` static library |
| **Rust Compiler** | rustc 1.93.0 (2026-01-19) |
| **Rust Build** | `--release`, LTO enabled, `codegen-units=1` |
| **Rust Benchmark** | Criterion 0.5 (100 samples, statistical analysis, 95% CI) |
| **C Benchmark** | Custom framework (`clock_gettime`, 5,000–10,000 iterations) |
| **Optimization Level** | P1–P62 complete (62 performance phases) |
| **Benchmark Coverage** | 291 test points, 59 algorithm groups, 33/33 modules covered |

**Note**: CPU frequency scaling is managed by macOS on Apple Silicon. Slow algorithms (SLH-DSA, FrodoKEM, McEliece, XMSS) use `sample_size(10)`. Criterion provides statistical outlier detection; C benchmarks report single-run mean.

---

## 3. Results

### 3.1 Hash Functions (8 KB payload)

| Algorithm | C (MB/s) | Rust (MB/s) | Ratio (R/C) | Notes |
|-----------|----------|-------------|-------------|-------|
| SHA-256 | 571.7 | 2,561 | **4.48** | **HW accel (SHA-NI), Rust 4.5x faster** |
| SHA-384 | 540.7 | 1,601 | **2.96** | **HW accel (SHA-512 CE), Rust 3.0x faster** |
| SHA-512 | 885.7 | 1,607 | **1.81** | **HW accel (SHA-512 CE), Rust 1.8x faster** |
| SM3 | 528.0 | 431 | **0.82** | No HW accel; C 1.2x faster (P56 ring buffer) |

<details>
<summary>Methodology</summary>

- **C**: `openhitls_benchmark_static -t 10000 -l 8192` — SHA-256: 69,792 ops/s, SHA-512: 108,120 ops/s, SM3: 64,448 ops/s; SHA-384 fresh: 65,987 ops/s
- **Rust**: Criterion mean — SHA-256: 3.20 µs, SHA-384: 5.12 µs, SHA-512: 5.10 µs, SM3: 19.01 µs
- MB/s = 8192 / (time_µs × 1e-6) / 1e6
</details>

**Analysis**: All three SHA-2 variants use hardware acceleration in Rust: SHA-256 via ARMv8 SHA-NI (Phase P1), SHA-512/384 via ARMv8.2 SHA-512 Crypto Extensions (Phase P11). SHA-256 achieves **4.5x speedup over C**, suggesting the C implementation may not fully utilize SHA-NI. SM3 gap narrowed to C 1.2x (was 1.7x in P62-era measurements; fresh run shows improved SM3 performance from P56 ring buffer + Keccak-related compiler optimizations).

---

### 3.2 Symmetric Ciphers (8 KB payload)

| Algorithm | C Enc (MB/s) | Rust Enc (MB/s) | C Dec (MB/s) | Rust Dec (MB/s) | Ratio (Enc) | Ratio (Dec) |
|-----------|-------------|-----------------|-------------|-----------------|-------------|-------------|
| AES-128-CBC | 324.6 | 904 | 331.3 | 2,796 | **2.78** | **8.44** |
| AES-256-CBC | 237.2 | 754 | 261.9 | 2,020 | **3.18** | **7.71** |
| AES-128-CTR | 315.0 | 1,402 | — | — | **4.45** | — |
| AES-256-CTR | 243.4 | 1,129 | — | — | **4.64** | — |
| AES-128-GCM | 155.7 | 813 | 165.8 | 831 | **5.22** | **5.01** |
| AES-256-GCM | 144.4 | 760 | 142.4 | 778 | **5.26** | **5.46** |
| ChaCha20-Poly1305 | 344.1 | 450 | 333.0 | 461 | **1.31** | **1.38** |
| SM4-CBC | 119.9 | 131 | 127.1 | 171 | **1.09** | **1.35** |
| SM4-GCM | 87.6 | 152 | 87.6 | 145 | **1.74** | **1.65** |

> Ratio > 1.0 = Rust faster. CTR mode is symmetric (encrypt = decrypt).

**Analysis** (isolated benchmark runs, eliminating thermal throttling from full-suite):
- **AES-CBC**: Rust is 2.8–8.4x faster. CBC decrypt parallelizable — Rust AES-NI pipelines multiple `AESDEC` instructions. Phase P21 (monomorphization) and P25 (stack arrays) further improved generic path.
- **AES-CTR**: Rust 4.5–4.6x faster — CTR mode naturally allows parallel block encryption.
- **AES-GCM**: Rust 5.0–5.5x faster — both encryption (AES-NI) and authentication (GHASH PMULL) hardware-accelerated. Phase P21 monomorphization + P62 GHASH batch.
- **ChaCha20-Poly1305**: Rust ~1.3x faster — NEON SIMD optimization.
- **SM4-CBC**: Rust 1.1–1.4x faster (all ops now Rust faster). Phase P8 T-table optimization.
- **SM4-GCM**: Rust 1.6–1.7x faster — T-table SM4 combined with hardware GHASH (ARMv8 PMULL).

---

### 3.3 MAC Algorithms (8 KB payload)

| Algorithm | C (MB/s) | Rust (MB/s) | Ratio (R/C) | Notes |
|-----------|----------|-------------|-------------|-------|
| HMAC-SHA256 | 319.8 | 2,198 | **6.87** | **Rust 6.9x faster** (SHA-256 HW + P26 zero-overhead HMAC) |
| HMAC-SHA512 | 507.7 | 1,325 | **2.61** | **Rust 2.6x faster** (SHA-512 HW + P26 HMAC caching) |
| HMAC-SM3 | 327.7 | 302 | **0.92** | Near parity (C 1.09x); P26 HMAC caching eliminated factory overhead |

<details>
<summary>C fresh data (5000 iterations)</summary>

- HMAC-SHA256: 39,026 ops/s → 319.8 MB/s
- HMAC-SHA512: 61,973 ops/s → 507.7 MB/s
- HMAC-SM3: 40,000 ops/s → 327.7 MB/s
</details>

**Analysis**: HMAC performance directly follows the underlying hash, amplified by P26 zero-overhead HMAC (`reset()` reuse, no `Box<dyn Fn>` factory). HMAC-SHA256 is **6.9x faster in Rust** (SHA-256 HW + negligible HMAC overhead). HMAC-SHA512 is **2.6x faster**. HMAC-SM3 near parity (C 1.09x).

---

### 3.4 Asymmetric / Public Key Operations

| Algorithm | Operation | C (ops/s) | Rust (ops/s) | Ratio (R/C) | Notes |
|-----------|-----------|----------|-------------|-------------|-------|
| ECDSA P-256 | Sign | 26,848 | 23,760 | **0.885** | P-256 fast path + P54 scalar field |
| ECDSA P-256 | Verify | 10,473 | 11,760 | **1.123** | **Rust 1.12x faster!** (P54 scalar field) |
| ECDSA P-384 | Sign | — | 421 | — | Generic windowed scalar mul (P52) |
| ECDSA P-384 | Verify | — | 336 | — | — |
| ECDSA P-521 | Sign | — | 253 | — | — |
| ECDSA P-521 | Verify | — | 173 | — | — |
| ECDH P-256 | Key Derive | 13,584 | 12,200 | **0.898** | C 1.11x faster |
| ECDH P-384 | Key Derive | 969 | 486 | **0.501** | C 2.0x faster (generic BigNum) |
| ECDH P-521 | Key Derive | 5,059 | 253 | **0.050** | C 20x faster (generic BigNum) |
| Ed25519 | Sign | 66,193 | 69,980 | **1.057** | **Rust 1.06x faster** (P12 precomputed comb) |
| Ed25519 | Verify | 24,016 | 20,770 | **0.865** | C 1.16x faster (P55 projective cmp) |
| Ed448 | Sign | — | 1,512 | — | Generic Ed448, no fast path |
| Ed448 | Verify | — | 702 | — | — |
| X25519 | DH | 49,594 | 34,720 | **0.700** | C 1.43x faster (P60 Fe25519 opt) |
| X448 | DH | — | 2,259 | — | Curve448 field arithmetic |
| SM2 | Sign | 2,560 | 13,140 | **5.13** | **Rust 5.1x faster!** (P10 specialized field) |
| SM2 | Verify | 4,527 | 9,590 | **2.12** | **Rust 2.1x faster!** |
| SM2 | Encrypt | 1,283 | 5,270 | **4.11** | **Rust 4.1x faster!** |
| SM2 | Decrypt | 2,584 | 10,390 | **4.02** | **Rust 4.0x faster!** |
| RSA-2048 | Sign (PSS) | — | 791 | — | C RSA not in benchmark binary |
| RSA-2048 | Verify (PSS) | — | 21,440 | — | — |
| RSA-2048 | Encrypt (OAEP) | — | 23,780 | — | — |
| RSA-2048 | Decrypt (OAEP) | — | 819 | — | — |

**Analysis**:
- **ECDSA P-256**: Phase P54 (scalar field optimization) — verify now **Rust 1.12x faster than C**. Sign gap narrowed to C 1.13x.
- **ECDSA P-384/P-521**: First benchmarked. Uses generic windowed scalar mul (P52). P-384 sign ~421 ops/s, P-521 ~253 ops/s. C is significantly faster for P-384/P-521 (no specialized field arithmetic in Rust).
- **ECDH P-256/384/521**: P-256 uses fast path (C 1.11x). P-384/P-521 use generic BigNum — C's assembly-optimized `bn_mul_mont` gives large advantage.
- **Ed25519/X25519**: Ed25519 sign near parity; verify C 1.16x. X25519 DH at C 1.43x (P60 Fe25519 sub_fast).
- **Ed448/X448**: First benchmarked. Ed448 sign 1.5K ops/s, X448 DH 2.3K ops/s. ~46x slower than Ed25519/X25519 due to larger field and no specialized arithmetic.
- **SM2**: Specialized field arithmetic (Phase P10) makes SM2 **dramatically faster in Rust** — sign 5.1x, verify 2.1x faster.

---

### 3.5 Post-Quantum Cryptography

| Algorithm | Operation | C (ops/s) | Rust (ops/s) | Ratio (R/C) |
|-----------|-----------|----------|-------------|-------------|
| ML-KEM-512 | KeyGen | 92,755 | 46,460 | **0.501** |
| ML-KEM-512 | Encaps | 167,182 | 45,210 | **0.270** |
| ML-KEM-512 | Decaps | 125,729 | 64,720 | **0.515** |
| ML-KEM-768 | KeyGen | 38,814 | 29,840 | **0.769** |
| ML-KEM-768 | Encaps | 119,805 | 32,810 | **0.274** |
| ML-KEM-768 | Decaps | 86,794 | 38,300 | **0.441** |
| ML-KEM-1024 | KeyGen | 32,864 | 19,000 | **0.578** |
| ML-KEM-1024 | Encaps | 91,958 | 22,350 | **0.243** |
| ML-KEM-1024 | Decaps | 65,644 | 24,560 | **0.374** |
| ML-DSA-44 | KeyGen | 25,553 | 14,470 | **0.566** |
| ML-DSA-44 | Sign | 7,413 | 12,530 | **1.690** |
| ML-DSA-44 | Verify | 20,882 | 12,660 | **0.606** |
| ML-DSA-65 | KeyGen | 14,894 | 7,610 | **0.511** |
| ML-DSA-65 | Sign | 4,566 | 4,510 | **0.988** |
| ML-DSA-65 | Verify | 12,998 | 9,020 | **0.694** |
| ML-DSA-87 | KeyGen | 8,563 | 4,870 | **0.569** |
| ML-DSA-87 | Sign | 3,517 | 4,510 | **1.283** |
| ML-DSA-87 | Verify | 7,018 | 5,170 | **0.737** |

**Analysis**: PQC performance after P54–P62 optimizations (P57 ML-DSA zero-alloc, P58 ML-KEM clone elim, P59 Keccak unroll):
- **ML-KEM**: C remains 1.6–4.1x faster. ML-KEM-768 decaps at 38.3K ops/s (P58/P59).
- **ML-DSA**: ML-DSA-44 sign now **1.69x faster than C** (12,530 vs 7,413). ML-DSA-87 sign **1.28x faster than C**. P57 zero-alloc retry loop + P59 Keccak unroll.

---

### 3.6 SLH-DSA (FIPS 205, Stateless Hash-Based Signatures)

| Variant | KeyGen (ops/s) | Sign (ops/s) | Verify (ops/s) | Sign Time |
|---------|---------------|-------------|----------------|-----------|
| SHA2-128f | 2,826 | 117 | 2,023 | 8.57 ms |
| SHAKE-128f | 497 | 19 | 351 | 53.4 ms |
| SHA2-192f | 1,416 | 51 | 990 | 19.6 ms |
| SHA2-256f | 540 | 25 | 946 | 39.8 ms |

**Analysis**: First comprehensive SLH-DSA benchmarks. Only `-f` (fast) variants benchmarked; `-s` (small signature) variants are 5–10x slower. SHA2 variants are 5–6x faster than SHAKE variants due to hardware SHA-2 acceleration (SHA-NI/SHA-512 CE). SHA2-128f is the fastest practical variant (sign ~117 ops/s, verify ~2K ops/s). No C reference data available.

---

### 3.7 Diffie-Hellman Key Exchange

| Group | C KeyGen (ops/s) | Rust KeyGen (ops/s) | C Derive (ops/s) | Rust Derive (ops/s) | Ratio (KeyGen) | Ratio (Derive) |
|-------|-------------------|---------------------|-------------------|---------------------|----------------|----------------|
| FFDHE-2048 | 1,219 | 214 | 997 | 207 | **0.175** | **0.207** |
| FFDHE-3072 | 489 | 61 | 467 | 72 | **0.125** | **0.155** |
| FFDHE-4096 | 290 | 29 | 288 | 29 | **0.100** | **0.100** |

**Analysis**: C is 4.8–10x faster for DH operations. The gap increases with key size because the O(n²) Montgomery multiplication inner loop — C uses hand-tuned assembly (`bn_mul_mont`) while Rust compiles `u128` operations to `umulh`+`mul`. DH is rarely the bottleneck in modern TLS (ECDHE is strongly preferred).

---

### 3.8 ECDH Multi-Curve

| Curve | C KeyGen (ops/s) | C Derive (ops/s) | Rust Derive (ops/s) | Ratio (Derive) |
|-------|-------------------|-------------------|---------------------|----------------|
| P-224 | 86,438 | 30,903 | — | — |
| P-256 | 41,174 | 13,584 | 12,200 | **0.898** |
| P-384 | 1,041 | 969 | 486 | **0.501** |
| P-521 | 12,182 | 5,059 | 253 | **0.050** |
| brainpoolP256r1 | 2,524 | 2,574 | — | — |

**Analysis**: P-256 uses specialized field arithmetic (near parity with C). P-384 uses generic windowed scalar mul — C is 2x faster. P-521 shows a large gap (C 20x) due to Rust using generic BigNum for 521-bit field operations while C has optimized assembly. Opportunity for P-521 specialized field arithmetic (similar to P-256 Phase P5).

---

### 3.9 Additional Symmetric Ciphers (8 KB payload)

| Algorithm | Encrypt (MB/s) | Decrypt (MB/s) | Notes |
|-----------|---------------|----------------|-------|
| AES-128-ECB | 2,904 | 2,893 | Parallel blocks, AES-NI |
| AES-256-ECB | 762 | 575 | Single-key AES-NI |
| AES-128-XTS | 1,348 | 1,465 | Dual-key (tweak + data) |
| AES-256-XTS | 1,240 | 1,279 | — |
| AES-128-CFB | 947 | 1,108 | Decrypt parallelizable |
| AES-256-CFB | 724 | 1,100 | — |
| AES-128-OFB | 1,699 | — | Symmetric mode |
| AES-256-OFB | 1,270 | — | — |
| AES-128-CCM | 786 | 781 | AEAD (CBC-MAC + CTR) |
| AES-128-HCTR | 4.3 | 3.8 | Software-only (polynomial hash) |
| AES-128 Wrap | — | — | 727 ns / 1,258 ns (wrap/unwrap, 24B) |
| AES-256 Wrap | — | — | 985 ns / 1,129 ns |
| SM4-CCM | 55.4 | 54.1 | SM4 T-table + CBC-MAC |

**Analysis**: ECB provides the highest throughput (~2.9 GB/s for AES-128) as it's pure block cipher without chaining. XTS (disk encryption) adds modest overhead for the tweak computation. CFB/OFB are streaming modes with good throughput. CCM is slower than GCM (~786 vs 813 MB/s for AES-128) due to the sequential CBC-MAC pass. HCTR is extremely slow (4 MB/s) due to the polynomial hash component running in software.

---

### 3.10 Additional Hash Functions & XOFs (8 KB payload)

| Algorithm | Throughput (MB/s) | Notes |
|-----------|-------------------|-------|
| SHA3-256 | 321 | Keccak-f1600 (P59 unroll + P18 HW accel) |
| SHA3-384 | 247 | Wider capacity → lower rate |
| SHA3-512 | 171 | — |
| SHAKE128 | 196 | XOF (128-bit security) |
| SHAKE256 | 158 | XOF (256-bit security) |
| SHA-1 | 473 | Legacy; no HW acceleration |
| MD5 | 343 | Legacy; no HW acceleration |

**Analysis**: SHA-3 performance is dominated by the Keccak-f1600 permutation. Phase P59 (software unroll) and P18 (ARMv8 SHA-3 HW acceleration with EOR3/RAX1/BCAX) provide significant speedups on supported hardware. SHA-3 throughput (171–321 MB/s) is substantially lower than SHA-2 (1,607–2,561 MB/s) due to the Keccak sponge construction overhead. SHA-1 and MD5 are included for completeness (legacy protocols); no hardware acceleration is used for these.

---

### 3.11 Additional MAC Algorithms (8 KB payload)

| Algorithm | Throughput (MB/s) | Notes |
|-----------|-------------------|-------|
| HMAC-SHA384 | 1,101 | SHA-512 CE based |
| CMAC-AES128 | 908 | AES-NI block cipher MAC |
| CMAC-AES256 | 1,168 | — |
| GMAC-AES128 | 865 | GHASH (PMULL HW) |
| SipHash-2-4 | 1,764 | Fast keyed hash (non-crypto) |
| CBC-MAC-SM4 | 67 | SM4 T-table, sequential |

**Analysis**: SipHash provides the highest throughput (1.76 GB/s) as it's designed for speed (hash table protection, not cryptographic MAC). HMAC-SHA384 benefits from SHA-512 hardware acceleration (1.1 GB/s). CMAC/GMAC leverage AES-NI and GHASH PMULL respectively. CBC-MAC-SM4 is slow (67 MB/s) due to SM4's software-only implementation and sequential block chaining.

---

### 3.12 Key Derivation Functions

| Algorithm | Time | Notes |
|-----------|------|-------|
| HKDF extract+expand (32B) | 641 ns | SHA-256 based |
| HKDF extract+expand (64B) | 885 ns | — |
| PBKDF2 (1,000 iterations) | 166 µs | SHA-256, 32B output |
| PBKDF2 (10,000 iterations) | 1.67 ms | — |
| scrypt (N=1024, r=8, p=1) | 1.84 ms | Low-memory setting |
| scrypt (N=16384, r=8, p=1) | 31.0 ms | Standard setting |

---

### 3.13 DRBG Performance

| Algorithm | Generate 32B | Notes |
|-----------|-------------|-------|
| CTR-DRBG (AES-256) | 381 ns | P20 cached AES key |
| HMAC-DRBG (SHA-256) | 703 ns | — |
| Hash-DRBG (SHA-256) | 465 ns | — |
| SM4-CTR-DRBG | 1,704 ns | SM4 T-table |

**Analysis**: CTR-DRBG is the fastest at 381 ns per 32B generation, benefiting from Phase P20 (cached AES key eliminates per-block key expansion). HMAC-DRBG is slowest due to two HMAC operations per generate. SM4-CTR-DRBG is ~4.5x slower than AES-CTR-DRBG due to SM4's software-only implementation.

---

### 3.14 Additional PQC & Miscellaneous

| Algorithm | Operation | Time | Ops/s |
|-----------|-----------|------|-------|
| HybridKEM X25519+ML-KEM-768 | Encaps | 64.5 µs | 15,500 |
| HPKE (X25519+AES-128-GCM) | Seal | 43.3 µs | 23,100 |
| HPKE (X25519+AES-128-GCM) | Open | 51.7 µs | 19,330 |
| FrodoKEM-640-SHAKE | KeyGen | 4.15 ms | 241 |
| FrodoKEM-640-SHAKE | Encaps | 2.45 ms | 408 |
| FrodoKEM-640-SHAKE | Decaps | 2.49 ms | 402 |
| FrodoKEM-976-SHAKE | KeyGen | 9.49 ms | 105 |
| FrodoKEM-976-SHAKE | Encaps | 5.40 ms | 185 |
| FrodoKEM-976-SHAKE | Decaps | 5.43 ms | 184 |
| McEliece-6688128 | Encaps | 410 µs | 2,440 |
| McEliece-6688128 | Decaps | 16.9 ms | 59 |
| XMSS SHA2-10-256 | Verify | 165 µs | 6,044 |
| Paillier-512 | Encrypt | 227 µs | 4,400 |
| Paillier-512 | Decrypt | 203 µs | 4,940 |

**Note**: DSA and ElGamal benchmarks use small demonstration parameters (p=23) and are not representative of cryptographic-strength operations. McEliece keygen is excluded as it takes ~5 seconds.

---

### 3.15 BigNum Arithmetic

| Operation | 256-bit | 512-bit | 1024-bit | 2048-bit | 4096-bit |
|-----------|---------|---------|----------|----------|----------|
| Multiply | 41.1 ns | 93.3 ns | 275.9 ns | 813.6 ns | 4,672 ns |
| Add | 41.7 ns | 40.5 ns | 69.1 ns | 179.9 ns | 253.6 ns |

**Modular exponentiation** (CIOS Montgomery, Phase P7/P15/P22/P53):

| Operation | Time |
|-----------|------|
| mod_exp 1024-bit | 631.8 µs |
| mod_exp 2048-bit | 3.97 ms |
| mod_exp 4096-bit | 34.0 ms |

---

## 4. Performance Heatmap

```
                        C faster <------------------> Rust faster
                        x12    x8     x4    1.0    x2     x5    x8

DH-4096 keygen          ████████████████░░░░░░░░░░░░░░░░░░░░░░░░░  C x10
ML-KEM-768 encaps       █████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x3.7
DH-2048 keygen          ███████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x5.7
SM3                     █████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x1.22
X25519 DH               █████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x1.43
Ed25519 verify          ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x1.16
ECDH P-256              ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x1.11
ECDSA P-256 sign        ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x1.13
Ed25519 sign            ░░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░░░░  R x1.06
ML-DSA-65 sign          ░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░░░░░  Parity
SM4-CBC enc             ░░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░░░░  R x1.09
ECDSA P-256 verify      ░░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░░░░  R x1.12
ML-DSA-87 sign          ░░░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░░░  R x1.28
ChaCha20-Poly1305 enc   ░░░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░░░  R x1.31
SM4-CBC dec             ░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░  R x1.35
ML-DSA-44 sign          ░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░  R x1.69
SM4-GCM enc             ░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░  R x1.74
SHA-512                 ░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░  R x1.81
SM2 verify              ░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░  R x2.12
HMAC-SHA512             ░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░  R x2.61
AES-128-CBC enc         ░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░  R x2.78
SHA-384                 ░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░  R x2.96
AES-256-CBC enc         ░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░  R x3.18
SHA-256                 ░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░  R x4.48
AES-128-CTR             ░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░  R x4.45
SM2 sign                ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░  R x5.13
AES-128-GCM enc         ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░  R x5.22
HMAC-SHA256             ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░  R x6.87
AES-128-CBC dec         ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██████  R x8.44
```

---

## 5. Performance Optimization History (Phase P1–P62)

### Major Optimization Phases

| Phase | Optimization | Primary Impact |
|-------|-------------|----------------|
| **P1–P4** | HW acceleration (SHA-2 SHA-NI, GHASH PMULL, P-256 field, ChaCha20 NEON) | Symmetric/hash parity with C |
| **P5** | P-256 deep optimization (comb table, specialized reduction) | ECDSA sign 21x, verify 14x |
| **P6** | ML-KEM NEON NTT (8-wide Montgomery) | ML-KEM-768 encaps 2.0x, decaps 2.6x |
| **P7** | BigNum CIOS Montgomery (fused mul+reduce) | DH-2048 1.25x, RSA-2048 sign 1.11x |
| **P8** | SM4 T-table lookup (compile-time tables) | SM4-CBC 2.37x, SM4-GCM 3.09x |
| **P9** | ML-DSA NEON NTT (4-wide i32 intrinsics) | NTT 2.31x, INTT 2.54x |
| **P10** | SM2 specialized field arithmetic (comb table) | SM2 sign 25.3x, verify 21.1x |
| **P11** | SHA-512 ARMv8.2 hardware acceleration | SHA-512 2.4x, SHA-384 3.9x |
| **P12** | Ed25519 precomputed base table (comb method) | Sign 3.1x, verify 1.5x |
| **P13–P14** | ML-DSA batch squeeze + Keccak heap elimination | Reduced SHAKE overhead |
| **P15–P16** | BigNum sqr_limbs + SM3 compression optimization | Modular ops + SM3 speedup |
| **P17** | P-256 scalar field (Montgomery mod curve order) | ECDSA sign k-inversion speedup |
| **P18** | Keccak ARMv8 SHA-3 HW acceleration | EOR3/RAX1/BCAX Keccak HW path |
| **P19–P20** | SHAKE squeeze_into + CTR-DRBG key caching | Zero-alloc SHAKE + 67→1 key expansions |
| **P21** | AES-GCM/CBC monomorphization | Eliminated vtable indirect calls |
| **P22–P49** | TLS record layer + RSA + HMAC + CBC + ML-KEM/DSA heap elimination | 100+ allocs eliminated per handshake |
| **P50** | ML-KEM byte-aligned bit-packing | Bulk encode/decode |
| **P51–P52** | SM9 + ECC/EdDSA windowed scalar multiplication | ~50% fewer point additions |
| **P53** | BigNum CIOS inner loop (bounds-check elimination) | DH 1.44x, RSA 1.43x, mod_exp ~1.42x |
| **P54** | ECDSA P-256 verify scalar field optimization | **Verify now Rust faster than C** |
| **P55** | Ed25519/Ed448 projective coordinate comparison | Ed25519 verify 23% faster |
| **P56** | SM3 ring buffer compression | SM3 ~16% faster |
| **P57–P58** | ML-DSA zero-alloc + ML-KEM clone elimination | PQC per-op allocs eliminated |
| **P59** | Keccak keccak_f1600 software unrolling | All SHAKE/SHA-3 ~20% faster |
| **P60** | X25519 Fe25519 inversion + carry optimization | X25519 DH 12% faster |
| **P62** | GHASH HW zero-copy batch processing | AES-GCM marginal improvement |

### Key Milestones

| Milestone | Before | After | Speedup |
|-----------|--------|-------|---------|
| ECDSA P-256 sign | 2,415 µs | 42.1 µs | **57x** |
| ECDSA P-256 verify | — | 85.0 µs | **Rust 1.12x > C** (P54) |
| SM2 sign | 2,331 µs | 76.1 µs | **31x** |
| Ed25519 sign | 56.1 µs | 14.3 µs | **3.9x** |
| SHA-256 @8KB | 42.25 µs | 3.20 µs | **13.2x** |
| ML-KEM-768 encaps | ~109 µs | 30.5 µs | **3.6x** |
| ML-DSA-44 sign | ~355 µs | 79.8 µs | **4.4x** |
| DH-4096 keygen | 35.5 ms | 34.4 ms | **1.03x** (P53) |
| RSA-2048 sign | 1.37 ms | 1.26 ms | **1.09x** (P53) |

---

## 6. Detailed Methodology

### 6.1 C Benchmark Framework

The C benchmark (`openhitls_benchmark`) uses a custom framework:
- Pre-allocates data buffers and key contexts before timing
- Runs N iterations in a tight loop, measures wall-clock time via `clock_gettime(CLOCK_REALTIME)`
- Reports: `time_elapsed_ms`, `ops/s = iterations / (time_elapsed_ms / 1000)`
- Single-run mean (no statistical analysis)

**Command**: `./openhitls_benchmark_static -t <iterations> -l <payload_bytes>`

**Note**: RSA is declared (`extern BenchCtx RsaBenchCtx`) but **not registered** in the `g_benchs[]` array, so RSA C benchmarks cannot be run with the current binary.

### 6.2 Rust Criterion Framework

Criterion 0.5 provides:
- Automatic warm-up phase
- 100 statistical samples with confidence intervals (95% CI)
- Outlier detection and noise filtering
- Reports: mean time per operation, throughput (MiB/s or GiB/s)

**Command**: `cargo bench -p hitls-crypto --all-features`

**Suite composition**: 59 benchmark groups, 291 test points:
- Symmetric ciphers: 17 groups (AES modes, SM4 modes, ChaCha20)
- Hash functions: 5 groups (SHA-2, SHA-3, SHAKE, SHA-1, MD5, SM3)
- MAC algorithms: 6 groups (HMAC variants, CMAC, GMAC, SipHash, CBC-MAC)
- Asymmetric: 9 groups (ECDSA, ECDH, EdDSA, X-DH, SM2, RSA)
- Post-quantum: 6 groups (ML-KEM, ML-DSA, SLH-DSA, HybridKEM, HPKE, SM9)
- Large-key/slow: 7 groups (DH, DSA, FrodoKEM, XMSS, McEliece, ElGamal, Paillier)
- KDF/DRBG: 4 groups (scrypt, HKDF/PBKDF2, DRBG, DRBG-extra)
- BigNum: 1 group (add, mul, mod_exp at multiple bit widths)

### 6.3 Comparability Notes

1. **Payload size**: All symmetric/hash comparisons use 8 KB (8192 bytes) payload
2. **Key setup**: Both frameworks pre-generate keys before timing; key generation is excluded
3. **Memory allocation**: Both allocate output buffers before the timing loop
4. **Compiler optimization**: C uses `-O2`, Rust uses release profile with LTO + `codegen-units=1`
5. **Hardware acceleration**: Both implementations compile with ARM Crypto Extension support enabled

### 6.4 Caveats

- **Single machine**: All results are from a single Apple M4. x86-64 results may differ (Intel SHA-NI, AVX2)
- **Full suite thermal effects**: The ~35-minute full benchmark run may show 10–20% thermal throttling in later tests. Key comparison benchmarks run in isolated batches for accuracy
- **Criterion overhead**: Criterion's statistical framework adds per-sample overhead (~microseconds)
- **No CPU pinning**: macOS does not support `taskset`-style CPU pinning on Apple Silicon
- **Small-parameter benchmarks**: DSA and ElGamal use demonstration parameters (p=23) — not representative of real-world cryptographic performance
- **Sample size**: Slow algorithms (SLH-DSA, FrodoKEM, McEliece, XMSS, scrypt) use `sample_size(10)`; results have wider confidence intervals

---

## Appendix A: Throughput Summary (8 KB payload, MB/s)

| Algorithm | Throughput (MB/s) | Category |
|-----------|-------------------|----------|
| AES-128-ECB encrypt | 2,904 | Symmetric |
| AES-128-ECB decrypt | 2,893 | Symmetric |
| SHA-256 | 2,561 | Hash |
| AES-128-CBC decrypt | 2,676 | Symmetric |
| HMAC-SHA256 | 1,849 | MAC |
| SipHash-2-4 | 1,764 | MAC |
| AES-128-OFB | 1,699 | Symmetric |
| SHA-512 | 1,607 | Hash |
| SHA-384 | 1,601 | Hash |
| AES-128-XTS decrypt | 1,465 | Symmetric |
| AES-128-XTS encrypt | 1,348 | Symmetric |
| AES-256-OFB | 1,270 | Symmetric |
| AES-256-XTS decrypt | 1,279 | Symmetric |
| AES-256-XTS encrypt | 1,240 | Symmetric |
| AES-128-CTR | 1,203 | Symmetric |
| CMAC-AES256 | 1,168 | MAC |
| AES-256-CTR | 1,127 | Symmetric |
| HMAC-SHA512 | 1,122 | MAC |
| HMAC-SHA384 | 1,101 | MAC |
| AES-128-CFB decrypt | 1,108 | Symmetric |
| AES-256-CFB decrypt | 1,100 | Symmetric |
| AES-128-CFB encrypt | 947 | Symmetric |
| CMAC-AES128 | 908 | MAC |
| GMAC-AES128 | 865 | MAC |
| AES-128-GCM encrypt | 768 | AEAD |
| AES-128-CCM encrypt | 786 | AEAD |
| AES-128-CCM decrypt | 781 | AEAD |
| AES-256-GCM encrypt | 686 | AEAD |
| AES-256-CFB encrypt | 724 | Symmetric |
| AES-128-GCM decrypt | 481 | AEAD |
| SHA-1 | 473 | Hash |
| ChaCha20-Poly1305 encrypt | 419 | AEAD |
| SM3 | 431 | Hash |
| MD5 | 343 | Hash |
| SHA3-256 | 321 | Hash |
| HMAC-SM3 | 318 | MAC |
| SHA3-384 | 247 | Hash |
| SHAKE128 | 196 | XOF |
| SHA3-512 | 171 | Hash |
| SHAKE256 | 158 | XOF |
| SM4-GCM encrypt | 157 | Symmetric |
| SM4-GCM decrypt | 162 | Symmetric |
| SM4-CBC encrypt | 116 | Symmetric |
| SM4-CBC decrypt | 156 | Symmetric |
| CBC-MAC-SM4 | 67 | MAC |
| SM4-CCM encrypt | 55 | AEAD |
| SM4-CCM decrypt | 54 | AEAD |
| AES-128-HCTR encrypt | 4.3 | Symmetric |

## Appendix B: Public Key Operations Summary (ops/sec)

| Algorithm | Operation | Ops/sec |
|-----------|-----------|---------|
| Ed25519 | sign | 69,980 |
| ML-KEM-512 | decaps | 64,720 |
| ML-KEM-512 | keygen | 46,460 |
| ML-KEM-512 | encaps | 45,210 |
| ML-KEM-768 | decaps | 38,300 |
| X25519 | DH | 34,720 |
| ML-KEM-768 | encaps | 32,810 |
| ML-KEM-768 | keygen | 29,840 |
| ML-KEM-1024 | decaps | 24,560 |
| RSA-2048 | encrypt (OAEP) | 23,780 |
| ECDSA P-256 | sign | 23,760 |
| HPKE | seal | 23,100 |
| ML-KEM-1024 | encaps | 22,350 |
| RSA-2048 | verify (PSS) | 21,440 |
| Ed25519 | verify | 20,770 |
| HPKE | open | 19,330 |
| ML-KEM-1024 | keygen | 19,000 |
| HybridKEM X25519+ML-KEM-768 | encaps | 15,500 |
| ML-DSA-44 | keygen | 14,470 |
| SM2 | sign | 13,140 |
| ML-DSA-44 | verify | 12,660 |
| ML-DSA-44 | sign | 12,530 |
| ECDH P-256 | key_derive | 12,200 |
| ECDSA P-256 | verify | 11,760 |
| SM2 | decrypt | 10,390 |
| SM2 | verify | 9,590 |
| ML-DSA-65 | verify | 9,020 |
| ML-DSA-65 | keygen | 7,610 |
| XMSS SHA2-10-256 | verify | 6,044 |
| SM2 | encrypt | 5,270 |
| ML-DSA-87 | verify | 5,170 |
| Paillier-512 | decrypt | 4,940 |
| ML-DSA-87 | keygen | 4,870 |
| ML-DSA-65 | sign | 4,510 |
| ML-DSA-87 | sign | 4,510 |
| Paillier-512 | encrypt | 4,400 |
| SLH-DSA SHA2-128f | keygen | 2,826 |
| McEliece-6688128 | encaps | 2,440 |
| X448 | DH | 2,259 |
| SLH-DSA SHA2-128f | verify | 2,023 |
| Ed448 | sign | 1,512 |
| SLH-DSA SHA2-192f | keygen | 1,416 |
| SLH-DSA SHA2-192f | verify | 990 |
| SLH-DSA SHA2-256f | verify | 946 |
| RSA-2048 | decrypt (OAEP) | 819 |
| RSA-2048 | sign (PSS) | 791 |
| Ed448 | verify | 702 |
| SLH-DSA SHA2-256f | keygen | 540 |
| SLH-DSA SHAKE-128f | keygen | 497 |
| ECDH P-384 | key_derive | 486 |
| ECDSA P-384 | sign | 421 |
| FrodoKEM-640-SHAKE | encaps | 408 |
| FrodoKEM-640-SHAKE | decaps | 402 |
| SLH-DSA SHAKE-128f | verify | 351 |
| ECDSA P-384 | verify | 336 |
| ECDH P-521 | key_derive | 253 |
| ECDSA P-521 | sign | 253 |
| FrodoKEM-640-SHAKE | keygen | 241 |
| ffdhe2048 | keygen | 214 |
| ffdhe2048 | key_derive | 207 |
| FrodoKEM-976-SHAKE | encaps | 185 |
| FrodoKEM-976-SHAKE | decaps | 184 |
| ECDSA P-521 | verify | 173 |
| SLH-DSA SHA2-128f | sign | 117 |
| FrodoKEM-976-SHAKE | keygen | 105 |
| ffdhe3072 | key_derive | 72 |
| ffdhe3072 | keygen | 61 |
| McEliece-6688128 | decaps | 59 |
| SLH-DSA SHA2-192f | sign | 51 |
| ffdhe4096 | keygen | 29 |
| ffdhe4096 | key_derive | 29 |
| SLH-DSA SHA2-256f | sign | 25 |
| SLH-DSA SHAKE-128f | sign | 19 |

## Appendix C: Full Criterion Mean Times (2026-03-02)

All times in nanoseconds unless noted.

```
=== Block Ciphers ===
aes-128 encrypt_block:      6.83 ns    aes-128 decrypt_block:      7.32 ns
aes-256 encrypt_block:     10.01 ns    aes-256 decrypt_block:     15.21 ns
sm4 encrypt_block:        134.90 ns    sm4 decrypt_block:        139.93 ns

=== AES-GCM (AEAD) ===
aes-128-gcm enc @1KB:     2,004 ns    aes-128-gcm dec @1KB:     1,840 ns
aes-128-gcm enc @8KB:    10,672 ns    aes-128-gcm dec @8KB:    17,014 ns
aes-128-gcm enc @16KB:   36,272 ns    aes-128-gcm dec @16KB:   21,332 ns
aes-256-gcm enc @1KB:     1,913 ns    aes-256-gcm dec @1KB:     1,829 ns
aes-256-gcm enc @8KB:    11,954 ns    aes-256-gcm dec @8KB:    11,112 ns
aes-256-gcm enc @16KB:   22,263 ns    aes-256-gcm dec @16KB:   22,229 ns

=== AES-CBC ===
aes-128-cbc enc @1KB:     1,492 ns    aes-128-cbc dec @1KB:       800 ns
aes-128-cbc enc @8KB:     9,252 ns    aes-128-cbc dec @8KB:     3,062 ns
aes-128-cbc enc @16KB:   18,132 ns    aes-128-cbc dec @16KB:    5,478 ns
aes-256-cbc enc @1KB:     1,784 ns    aes-256-cbc dec @1KB:     1,627 ns
aes-256-cbc enc @8KB:    31,377 ns    aes-256-cbc dec @8KB:    13,368 ns
aes-256-cbc enc @16KB:   34,122 ns    aes-256-cbc dec @16KB:   10,240 ns

=== AES-CTR ===
aes-128-ctr @1KB:         1,047 ns    aes-256-ctr @1KB:         1,534 ns
aes-128-ctr @8KB:         6,813 ns    aes-256-ctr @8KB:         7,269 ns
aes-128-ctr @16KB:       12,791 ns    aes-256-ctr @16KB:       13,678 ns

=== AES-CCM (AEAD) ===
aes-128-ccm enc @1KB:     1,633 ns    aes-128-ccm dec @1KB:     1,628 ns
aes-128-ccm enc @8KB:    10,428 ns    aes-128-ccm dec @8KB:    10,487 ns
aes-128-ccm enc @16KB:   19,783 ns    aes-128-ccm dec @16KB:   20,264 ns

=== AES-ECB ===
aes-128-ecb enc @1KB:       744 ns    aes-128-ecb dec @1KB:       762 ns
aes-128-ecb enc @8KB:     2,822 ns    aes-128-ecb dec @8KB:     2,833 ns
aes-128-ecb enc @16KB:    6,354 ns    aes-128-ecb dec @16KB:   11,117 ns
aes-256-ecb enc @1KB:     1,337 ns    aes-256-ecb dec @1KB:       995 ns
aes-256-ecb enc @8KB:    10,758 ns    aes-256-ecb dec @8KB:    14,240 ns
aes-256-ecb enc @16KB:   12,952 ns    aes-256-ecb dec @16KB:    9,758 ns

=== AES-XTS ===
aes-128-xts enc @1KB:     1,265 ns    aes-128-xts dec @1KB:     1,170 ns
aes-128-xts enc @8KB:     6,076 ns    aes-128-xts dec @8KB:     5,589 ns
aes-128-xts enc @16KB:   11,341 ns    aes-128-xts dec @16KB:   10,618 ns
aes-256-xts enc @1KB:     1,419 ns    aes-256-xts dec @1KB:     1,418 ns
aes-256-xts enc @8KB:     6,605 ns    aes-256-xts dec @8KB:     6,402 ns
aes-256-xts enc @16KB:   12,332 ns    aes-256-xts dec @16KB:   12,070 ns

=== AES-CFB ===
aes-128-cfb enc @1KB:     1,309 ns    aes-128-cfb dec @1KB:     1,079 ns
aes-128-cfb enc @8KB:     8,649 ns    aes-128-cfb dec @8KB:     7,393 ns
aes-128-cfb enc @16KB:   16,951 ns    aes-128-cfb dec @16KB:   13,377 ns
aes-256-cfb enc @1KB:     3,341 ns    aes-256-cfb dec @1KB:     1,554 ns
aes-256-cfb enc @8KB:    11,306 ns    aes-256-cfb dec @8KB:     7,443 ns
aes-256-cfb enc @16KB:   19,653 ns    aes-256-cfb dec @16KB:   14,693 ns

=== AES-OFB ===
aes-128-ofb @1KB:         1,437 ns    aes-256-ofb @1KB:         1,356 ns
aes-128-ofb @8KB:         4,823 ns    aes-256-ofb @8KB:         6,446 ns
aes-128-ofb @16KB:        9,827 ns    aes-256-ofb @16KB:       12,402 ns

=== AES Key Wrap ===
aes-128 wrap:             1,512 ns    aes-128 unwrap:           1,257 ns
aes-256 wrap:               985 ns    aes-256 unwrap:           1,129 ns

=== AES-HCTR ===
aes-128-hctr enc @1KB:  271,627 ns    aes-128-hctr dec @1KB:  275,159 ns
aes-128-hctr enc @8KB: 1904,400 ns    aes-128-hctr dec @8KB: 2159,087 ns
aes-128-hctr enc @16KB:4152,790 ns    aes-128-hctr dec @16KB:3870,156 ns

=== ChaCha20-Poly1305 ===
chacha20 enc @1KB:        2,294 ns    chacha20 dec @1KB:        2,734 ns
chacha20 enc @8KB:       19,553 ns    chacha20 dec @8KB:       17,113 ns
chacha20 enc @16KB:      44,801 ns    chacha20 dec @16KB:      93,781 ns

=== SM4 Block / SM4-CBC / SM4-GCM / SM4-CCM ===
sm4 encrypt_block:        134.9 ns    sm4 decrypt_block:        139.9 ns
sm4-cbc enc @1KB:         7,754 ns    sm4-cbc dec @1KB:         5,615 ns
sm4-cbc enc @8KB:        70,669 ns    sm4-cbc dec @8KB:        52,426 ns
sm4-cbc enc @16KB:      146,372 ns    sm4-cbc dec @16KB:      225,013 ns
sm4-gcm enc @1KB:         8,029 ns    sm4-gcm dec @1KB:         7,810 ns
sm4-gcm enc @8KB:        52,206 ns    sm4-gcm dec @8KB:        50,592 ns
sm4-gcm enc @16KB:      123,932 ns    sm4-gcm dec @16KB:      104,256 ns
sm4-ccm enc @1KB:        27,066 ns    sm4-ccm dec @1KB:        17,545 ns
sm4-ccm enc @8KB:       148,091 ns    sm4-ccm dec @8KB:       151,430 ns
sm4-ccm enc @16KB:      234,834 ns    sm4-ccm dec @16KB:      223,616 ns

=== Hash Functions ===
sha256 @1KB:                407 ns    sha384 @1KB:                728 ns
sha512 @1KB:                729 ns    sm3 @1KB:                 2,524 ns
sha256 @8KB:              3,198 ns    sha384 @8KB:              5,116 ns
sha512 @8KB:              5,098 ns    sm3 @8KB:                19,014 ns
sha256 @16KB:             6,419 ns    sha384 @16KB:            10,046 ns
sha512 @16KB:            10,117 ns    sm3 @16KB:               38,397 ns

=== SHA-3 / SHAKE ===
sha3-256 @1KB:            3,368 ns    sha3-384 @1KB:            4,279 ns
sha3-512 @1KB:            6,401 ns
sha3-256 @8KB:           25,540 ns    sha3-384 @8KB:           33,096 ns
sha3-512 @8KB:           47,852 ns
sha3-256 @16KB:          51,414 ns    sha3-384 @16KB:          66,343 ns
sha3-512 @16KB:          96,245 ns
shake128 @1KB:            5,497 ns    shake256 @1KB:            6,489 ns
shake128 @8KB:           41,766 ns    shake256 @8KB:           51,738 ns
shake128 @16KB:          84,237 ns    shake256 @16KB:         103,246 ns

=== SHA-1 / MD5 (Legacy) ===
sha1 @1KB:                2,316 ns    md5 @1KB:                 3,108 ns
sha1 @8KB:               17,341 ns    md5 @8KB:                23,911 ns
sha1 @16KB:              33,607 ns    md5 @16KB:               47,550 ns

=== HMAC ===
hmac-sha256 @1KB:           642 ns    hmac-sha512 @1KB:         1,454 ns
hmac-sha384 @1KB:         1,510 ns    hmac-sm3 @1KB:            4,104 ns
hmac-sha256 @8KB:         4,431 ns    hmac-sha512 @8KB:         7,300 ns
hmac-sha384 @8KB:         7,442 ns    hmac-sm3 @8KB:           25,704 ns
hmac-sha256 @16KB:        8,597 ns    hmac-sha512 @16KB:       13,413 ns
hmac-sha384 @16KB:       14,768 ns    hmac-sm3 @16KB:          51,812 ns

=== Other MAC ===
cmac-aes128 @1KB:         1,397 ns    cmac-aes256 @1KB:         1,289 ns
cmac-aes128 @8KB:         9,016 ns    cmac-aes256 @8KB:         7,016 ns
cmac-aes128 @16KB:       10,517 ns    cmac-aes256 @16KB:       13,986 ns
gmac-aes128 @1KB:         1,301 ns    gmac-aes128 @8KB:         9,475 ns
gmac-aes128 @16KB:       18,010 ns
siphash @64B:                43 ns    siphash @1KB:             1,935 ns
siphash @8KB:             4,644 ns
cbc-mac-sm4 @1KB:        18,956 ns    cbc-mac-sm4 @8KB:       121,710 ns
cbc-mac-sm4 @16KB:      170,765 ns

=== Elliptic Curves ===
ecdsa-p256 sign:         42,082 ns    ecdsa-p256 verify:       85,025 ns
ecdsa-p384 sign:      2,372,435 ns    ecdsa-p384 verify:    2,976,377 ns
ecdsa-p521 sign:      3,945,688 ns    ecdsa-p521 verify:    5,791,941 ns
ecdh p256 derive:        81,993 ns    ecdh p384 derive:     2,057,566 ns
ecdh p521 derive:     3,952,067 ns    x25519 dh:               28,799 ns
x448 dh:                442,684 ns
ed25519 sign:            14,289 ns    ed25519 verify:          48,156 ns
ed448 sign:             661,312 ns    ed448 verify:         1,424,415 ns
sm2 sign:                76,091 ns    sm2 verify:             104,303 ns
sm2 encrypt:            189,573 ns    sm2 decrypt:             96,274 ns

=== RSA-2048 ===
rsa-2048 sign pss:    1,264,572 ns    rsa-2048 verify pss:     46,639 ns
rsa-2048 enc oaep:       42,053 ns    rsa-2048 dec oaep:    1,220,360 ns

=== ML-KEM (FIPS 203) ===
mlkem-512 keygen:        21,525 ns    mlkem-512 encaps:        22,118 ns
mlkem-512 decaps:        15,452 ns
mlkem-768 keygen:        33,509 ns    mlkem-768 encaps:        30,474 ns
mlkem-768 decaps:        26,109 ns
mlkem-1024 keygen:       52,639 ns    mlkem-1024 encaps:       44,744 ns
mlkem-1024 decaps:       40,716 ns

=== ML-DSA (FIPS 204) ===
mldsa-44 keygen:         69,115 ns    mldsa-44 sign:           79,827 ns
mldsa-44 verify:         79,019 ns
mldsa-65 keygen:        131,463 ns    mldsa-65 sign:          221,747 ns
mldsa-65 verify:        110,842 ns
mldsa-87 keygen:        205,472 ns    mldsa-87 sign:          221,586 ns
mldsa-87 verify:        193,421 ns

=== SLH-DSA (FIPS 205) ===
slh-dsa sha2-128f keygen:   353,811 ns  sign:    8,574,090 ns  verify:     494,304 ns
slh-dsa shake-128f keygen: 2,011,752 ns  sign:   53,423,060 ns  verify:   2,848,341 ns
slh-dsa sha2-192f keygen:   706,002 ns  sign:   19,601,932 ns  verify:   1,010,280 ns
slh-dsa sha2-256f keygen: 1,853,597 ns  sign:   39,836,176 ns  verify:   1,057,136 ns

=== HybridKEM / HPKE ===
hybridkem x25519+mlkem768 encaps:  64,501 ns
hpke seal:                         43,290 ns
hpke open:                         51,726 ns

=== FrodoKEM ===
frodokem-640-shake keygen: 4,147,000 ns  encaps: 2,454,100 ns  decaps: 2,489,800 ns
frodokem-976-shake keygen: 9,486,000 ns  encaps: 5,396,000 ns  decaps: 5,428,000 ns

=== McEliece ===
mceliece-6688128 encaps:     409,700 ns  decaps: 16,900,000 ns

=== XMSS ===
xmss sha2-10-256 verify:    165,500 ns

=== Paillier-512 ===
paillier-512 encrypt:    227,125 ns    paillier-512 decrypt:    202,578 ns

=== Diffie-Hellman ===
dh-2048 keygen:       4,681,182 ns    dh-2048 derive:       4,839,282 ns
dh-3072 keygen:      16,388,823 ns    dh-3072 derive:      13,825,022 ns
dh-4096 keygen:      34,440,220 ns    dh-4096 derive:      34,635,132 ns

=== Key Derivation ===
hkdf extract+expand 32B:    641 ns    hkdf extract+expand 64B:    885 ns
pbkdf2 1000 iters:      166,135 ns    pbkdf2 10000 iters:   1,666,405 ns
scrypt n=1024:        1,837,346 ns    scrypt n=16384:      30,989,102 ns

=== DRBG ===
ctr-drbg gen 32B:           381 ns    hmac-drbg gen 32B:          703 ns
hash-drbg-sha256 gen 32B:   465 ns    sm4-ctr-drbg gen 32B:     1,704 ns

=== BigNum ===
bignum mul 256:              41 ns    bignum add 256:              42 ns
bignum mul 512:              93 ns    bignum add 512:              41 ns
bignum mul 1024:            276 ns    bignum add 1024:             69 ns
bignum mul 2048:            814 ns    bignum add 2048:            180 ns
bignum mul 4096:          4,673 ns    bignum add 4096:            254 ns
bignum mod_exp 1024:    631,772 ns    bignum mod_exp 2048:  3,973,603 ns
bignum mod_exp 4096:  33,982,960 ns
```

## Appendix D: Historical Comparison (P62 → Current)

| Benchmark | P62 (2026-03-01) | Current (2026-03-02) | Change | Notes |
|-----------|-----------------|---------------------|--------|-------|
| SHA-256 @8KB | 3.27 µs | 3.20 µs | -2% | Within noise |
| SHA-512 @8KB | 5.80 µs | 5.10 µs | -12% | Improved |
| SM3 @8KB | 27.03 µs | 19.01 µs | **-30%** | Fresh data shows P56 ring buffer fully effective |
| ECDSA P-256 sign | 43.82 µs | 42.08 µs | -4% | Within noise |
| ECDSA P-256 verify | 84.04 µs | 85.02 µs | +1% | Within noise |
| Ed25519 sign | 15.40 µs | 14.29 µs | -7% | Slight improvement |
| ML-KEM-768 encaps | 29.00 µs | 30.47 µs | +5% | Within noise |
| ML-DSA-44 sign | 80.28 µs | 79.83 µs | 0% | Stable |

> P62-era data from isolated benchmark runs. Current data from targeted group runs. Some variation expected due to Criterion statistical sampling.

## Appendix E: Raw Data Sources

| Source | File | Description |
|--------|------|-------------|
| Rust Criterion | `target/criterion/` | Full statistical reports (HTML + JSON), 59 groups / 291 test points |
| Rust CLI speed | `cargo run --release -p hitls-cli -- speed all` | Quick throughput check |
| C cipher (8KB) | original session | AES/SM4/ChaCha20 encrypt/decrypt, 10000 iterations |
| C hash (multi-size) | original session | SHA/SM3 at 16B–16KB, 10000 iterations |
| C MAC (8KB) | `Mac*` -t 5000 | HMAC, 5000 iterations |
| C ECDSA | original session | P-256, 10000 iterations |
| C ECDH | `Ecdh*` -t 5000 | P-224/256/384/521, 5000 iterations |
| C Ed25519/X25519 | original session | Sign/verify/DH, 10000 iterations |
| C SM2 | original session | KeyGen/sign/verify/enc/dec, 10000 iterations |
| C ML-KEM | original session | 512/768/1024, 10000 iterations |
| C ML-DSA | original session | 44/65/87, 10000 iterations |
| C DH | `Dh*` -t 1000 | RFC 7919 groups, 1000 iterations |

## Appendix F: Benchmark Suite Coverage

| Category | Groups | Test Points | Algorithms |
|----------|--------|-------------|------------|
| Symmetric ciphers | 16 | 118 | AES (ECB/CBC/CTR/GCM/CCM/XTS/CFB/OFB/Wrap/HCTR), SM4 (block/CBC/GCM/CCM), ChaCha20-Poly1305 |
| Hash functions | 6 | 33 | SHA-256/384/512, SHA3-256/384/512, SHAKE128/256, SHA-1, MD5, SM3 |
| MAC algorithms | 8 | 27 | HMAC-SHA256/384/512, HMAC-SM3, CMAC-AES128/256, GMAC-AES128/256, SipHash, CBC-MAC-SM4 |
| Asymmetric | 10 | 23 | ECDSA (P-256/384/521), ECDH (P-256/384/521), Ed25519, Ed448, X25519, X448, SM2, RSA-2048 |
| Post-quantum | 6 | 45 | ML-KEM (512/768/1024), ML-DSA (44/65/87), SLH-DSA (4 variants), SM9, HPKE, HybridKEM |
| Large-key/slow | 7 | 22 | DH (2048/3072/4096), DSA, FrodoKEM (640/976-SHAKE), XMSS, McEliece, ElGamal, Paillier |
| KDF/DRBG | 5 | 10 | HKDF, PBKDF2, scrypt, CTR-DRBG, HMAC-DRBG, Hash-DRBG, SM4-CTR-DRBG |
| BigNum | 1 | 13 | add, mul, mod_exp @ 256/512/1024/2048/4096-bit |
| **Total** | **59** | **291** | **33 algorithm modules, 100% coverage** |
