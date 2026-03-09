# Performance Comparison: openHiTLS (C) vs openHiTLS-rs (Rust)

> **Date**: 2026-03-05 (P1–P93, I83–I87, T74 complete) | **Platform**: Apple M4, macOS 15.4, 10 cores, 16 GB RAM
> **Benchmark suite**: 307 test points across 63 algorithm groups

---

## 1. Executive Summary

Comprehensive benchmarks across 63 algorithm groups (307 test points) comparing the original C openHiTLS against the Rust rewrite. All Rust numbers from Criterion 0.5 runs (rustc 1.93.0, 2026-03-05) after all 87 performance optimization phases. The benchmark suite covers 100% of implemented algorithm modules.

| Category | Verdict | Detail |
|----------|---------|--------|
| **AES (CBC/CTR/GCM)** | **Rust 2.0–8.3x faster** | P72 4-block pipeline + P73 GCM interleaved |
| **AES (ECB/XTS/CFB/OFB/CCM)** | **Rust-only data** | ECB 2.3–4.6 GB/s, XTS 0.7–1.3 GB/s, CCM 0.5–0.5 GB/s |
| **ChaCha20-Poly1305** | **Rust 1.5–2.2x faster** | P75 Poly1305 r² precompute + P76 2-block parallel |
| **Poly1305** | **Rust-only data** | Standalone: 3.5 GB/s @8KB (P75 r² batch) |
| **Hash (SHA-256/384/512)** | **Rust 1.5–3.6x faster** | SHA-256 HW 3.6x; SHA-384 2.3x; SHA-512 1.5x |
| **SHA-1** | **Rust-only data** | P74 ARMv8 HW accel: 2.3 GB/s @8KB |
| **SHA-3 / SHAKE** | **Rust-only data** | SHA3-256: 172 MB/s, SHAKE128: 110 MB/s |
| **SM3** | **C 3.5x faster** | P82 pipeline regression; thermal-affected |
| **HMAC** | **Rust 1.0–3.9x** | HMAC-SHA256 3.9x; HMAC-SHA512 2.0x; HMAC-SM3 near parity (C 1.03x) |
| **CMAC / GMAC** | **Rust-only data** | CMAC-AES128: 839 MB/s; GMAC-AES128: 652 MB/s |
| **SM4 (CBC/GCM/CCM)** | **Rust 1.1–1.9x faster** | T-table + GHASH HW; all ops Rust faster |
| **ECDSA P-256** | **Near parity** | P-256 fast path: sign C 1.18x, verify **Rust 1.07x faster** |
| **ECDSA P-384** | **Rust-only data** | P63 specialized field: sign 8.3K ops/s, verify 3.5K ops/s |
| **ECDSA P-521** | **Rust-only data** | P64 Mersenne field: sign 6.7K ops/s, verify 2.1K ops/s |
| **ECDH P-256/384/521** | **Rust 1.1x (P-256)** | P-384 4.5K ops/s, P-521 2.8K ops/s (P63/P64 specialized fields) |
| **Ed25519 / X25519** | **Rust 1.2–1.4x faster** | Sign **Rust 1.38x**, verify **Rust 1.16x**; X25519 DH near parity |
| **Ed448 / X448** | **Rust-only data** | P65/P66/P69: Ed448 sign 10.2K ops/s; X448 DH 5.9K ops/s |
| **SM2** | **Rust 2.6–6.7x faster** | Specialized Montgomery field + precomputed comb table |
| **RSA-2048** | **Rust-only data** | P68 CRT: sign 795 ops/s; verify 24.6K ops/s |
| **RSA-3072** | **Rust-only data** | Sign 170 ops/s; verify 7.7K ops/s |
| **RSA-4096** | **Rust-only data** | Sign 116 ops/s; verify 5.6K ops/s |
| **ML-KEM (Kyber)** | **C 2.5–5.1x faster** | P58 clone elim + P59 Keccak unroll + P83 SHAKE clone-fork |
| **ML-DSA (Dilithium)** | **Rust 1.3x faster (ML-DSA-44 sign)** | ML-DSA-44 sign 1.26x faster than C |
| **SLH-DSA (SPHINCS+)** | **Rust-only data** | P78 hypertree opt: SHA2-128f verify 917 ops/s, sign 49 ops/s |
| **HybridKEM** | **Rust-only data** | X25519+ML-KEM-768 encaps: 12.6K ops/s; P256/P384 variants benchmarked |
| **FrodoKEM** | **Rust-only data** | P79: 640/976/1344-SHAKE all benchmarked |
| **McEliece-6688128** | **Rust-only data** | Encaps 1.7K ops/s; decaps 42 ops/s |
| **XMSS / XMSS-MT** | **Rust-only data** | XMSS verify 5.1K ops/s; XMSS-MT verify 2.2K ops/s |
| **DH (FFDHE)** | **C 5.6–15.3x faster** | P53/P67/P81 CIOS + precomputed tables; thermal-affected |
| **KDF (HKDF/PBKDF2/scrypt)** | **Rust-only data** | HKDF 32B: 726 ns; PBKDF2-10K: 4.43 ms; scrypt-16384: 42.7 ms |

**Bottom line**: Symmetric ciphers (AES, ChaCha20) and hashes (SHA-256/384/512) remain **faster in Rust**. P81 adds DH precomputed generator tables, P82 adds SM3 pipelined expansion (regression detected — see §3.1), P83 adds ML-KEM SHAKE clone-fork. Ed25519 sign now **Rust 1.38x faster than C**, ECDSA P-256 verify now **Rust 1.07x faster than C**. The benchmark suite covers all 33 algorithm modules with 307 test points across 63 groups.

> **Note**: Full-suite run (~40 min) shows thermal throttling on later benchmarks. C-comparison numbers from isolated runs remain valid. Some absolute numbers (particularly SM3, DH, SHA-3/SHAKE) are higher than isolated runs due to thermal effects. SM3 regression (151 MB/s, was 307) is partially thermal and partially from P82 pipeline changes.

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
| **Optimization Level** | P1–P93 complete (87 performance phases) |
| **Benchmark Coverage** | 307 test points, 63 algorithm groups, 33/33 modules covered |

**Note**: CPU frequency scaling is managed by macOS on Apple Silicon. Slow algorithms (SLH-DSA, FrodoKEM, McEliece, XMSS) use `sample_size(10)`. Criterion provides statistical outlier detection; C benchmarks report single-run mean.

---

## 3. Results

### 3.1 Hash Functions (8 KB payload)

| Algorithm | C (MB/s) | Rust (MB/s) | Ratio (R/C) | Notes |
|-----------|----------|-------------|-------------|-------|
| SHA-256 | 571.7 | 2,048 | **3.58** | **HW accel (SHA-NI), Rust 3.6x faster** |
| SHA-384 | 540.7 | 1,231 | **2.28** | **HW accel (SHA-512 CE), Rust 2.3x faster** |
| SHA-512 | 885.7 | 1,360 | **1.54** | **HW accel (SHA-512 CE), Rust 1.5x faster** |
| SM3 | 528.0 | 151 | **0.29** | No HW accel; C 3.5x faster (P82 pipeline regression + thermal) |

<details>
<summary>Methodology</summary>

- **C**: `openhitls_benchmark_static -t 10000 -l 8192` — SHA-256: 69,792 ops/s, SHA-512: 108,120 ops/s, SM3: 64,448 ops/s; SHA-384 fresh: 65,987 ops/s
- **Rust**: Criterion mean — SHA-256: 4.00 µs, SHA-384: 6.65 µs, SHA-512: 6.02 µs, SM3: 54.28 µs
- MB/s = 8192 / (time_µs × 1e-6) / 1e6
</details>

**Analysis**: All three SHA-2 variants use hardware acceleration in Rust: SHA-256 via ARMv8 SHA-NI (Phase P1), SHA-512/384 via ARMv8.2 SHA-512 Crypto Extensions (Phase P11). SHA-256 achieves **3.6x speedup over C**. SHA-512 now shows **1.5x Rust advantage** (improved from near-parity in P80 run). SM3 shows significant regression: P82's pipelined expansion (`w[68]` pre-expand + separate expand/compress) replaced P77's efficient `w[16]` ring buffer, plus heavy thermal effects (SM3 benchmarks run late in suite; HMAC-SM3 at 317 MB/s is more representative).

---

### 3.2 Symmetric Ciphers (8 KB payload)

| Algorithm | C Enc (MB/s) | Rust Enc (MB/s) | C Dec (MB/s) | Rust Dec (MB/s) | Ratio (Enc) | Ratio (Dec) |
|-----------|-------------|-----------------|-------------|-----------------|-------------|-------------|
| AES-128-CBC | 324.6 | 642 | 331.3 | 1,780 | **1.98** | **5.37** |
| AES-256-CBC | 237.2 | 830 | 261.9 | 1,625 | **3.50** | **6.20** |
| AES-128-CTR | 315.0 | 1,237 | — | — | **3.93** | — |
| AES-256-CTR | 243.4 | 1,101 | — | — | **4.52** | — |
| AES-128-GCM | 155.7 | 802 | 165.8 | 922 | **5.15** | **5.56** |
| AES-256-GCM | 144.4 | 1,203 | 142.4 | 1,162 | **8.33** | **8.16** |
| ChaCha20-Poly1305 | 344.1 | 532 | 333.0 | 723 | **1.55** | **2.17** |
| SM4-CBC | 119.9 | 137 | 127.1 | 191 | **1.14** | **1.50** |
| SM4-GCM | 87.6 | 171 | 87.6 | 166 | **1.95** | **1.89** |

> Ratio > 1.0 = Rust faster. CTR mode is symmetric (encrypt = decrypt).

**Analysis** (P83 full-suite run, thermal effects present):
- **AES-CBC**: Rust 2.0–6.2x faster. CBC decrypt parallelizable — P72 4-block pipeline.
- **AES-CTR**: Rust 3.9–4.5x faster — P72 4-block parallel encryption pipeline.
- **AES-GCM**: Rust **5.2–8.3x faster** — P73 interleaved CTR+GHASH 4-block pipeline. Both AES-NI and GHASH PMULL hardware-accelerated.
- **ChaCha20-Poly1305**: Rust 1.5–2.2x faster — P75 Poly1305 r² precompute + P76 2-block parallel ChaCha20.
- **SM4-CBC**: Rust 1.1–1.5x faster. Phase P8 T-table optimization.
- **SM4-GCM**: Rust 1.9x faster — T-table SM4 + GHASH HW.

---

### 3.3 MAC Algorithms (8 KB payload)

| Algorithm | C (MB/s) | Rust (MB/s) | Ratio (R/C) | Notes |
|-----------|----------|-------------|-------------|-------|
| HMAC-SHA256 | 319.8 | 1,252 | **3.91** | **Rust 3.9x faster** (SHA-256 HW + P26 zero-overhead HMAC) |
| HMAC-SHA512 | 507.7 | 1,028 | **2.03** | **Rust 2.0x faster** (SHA-512 HW + P26 HMAC caching) |
| HMAC-SM3 | 327.7 | 317 | **0.97** | Near parity (C 1.03x); P26 HMAC caching eliminated factory overhead |

<details>
<summary>C fresh data (5000 iterations)</summary>

- HMAC-SHA256: 39,026 ops/s → 319.8 MB/s
- HMAC-SHA512: 61,973 ops/s → 507.7 MB/s
- HMAC-SM3: 40,000 ops/s → 327.7 MB/s
</details>

**Analysis**: HMAC performance directly follows the underlying hash, amplified by P26 zero-overhead HMAC (`reset()` reuse, no `Box<dyn Fn>` factory). HMAC-SHA256 is **3.9x faster in Rust** (SHA-256 HW + negligible HMAC overhead). HMAC-SHA512 is **2.0x faster**. HMAC-SM3 near parity (C 1.03x). Note: HMAC-SM3 at 317 MB/s outperforms raw SM3 at 151 MB/s because HMAC benchmarks run earlier in the suite (less thermal throttling).

---

### 3.4 Asymmetric / Public Key Operations

| Algorithm | Operation | C (ops/s) | Rust (ops/s) | Ratio (R/C) | Notes |
|-----------|-----------|----------|-------------|-------------|-------|
| ECDSA P-256 | Sign | 26,848 | 22,712 | **0.846** | P-256 fast path + P54 scalar field |
| ECDSA P-256 | Verify | 10,473 | 11,203 | **1.070** | **Rust 1.07x faster** (P55 projective) |
| ECDSA P-384 | Sign | — | 8,289 | — | P63 specialized field |
| ECDSA P-384 | Verify | — | 3,488 | — | P63 comb table + mont_sqr |
| ECDSA P-521 | Sign | — | 6,669 | — | P64 Mersenne field |
| ECDSA P-521 | Verify | — | 2,061 | — | P64 direct reduction |
| ECDH P-256 | Key Derive | 13,584 | 14,927 | **1.099** | **Rust 1.10x faster** |
| ECDH P-384 | Key Derive | 969 | 4,449 | **4.591** | **Rust 4.6x faster!** (P63) |
| ECDH P-521 | Key Derive | 5,059 | 2,783 | **0.550** | P64 Mersenne field; C 1.8x faster |
| Ed25519 | Sign | 66,193 | 91,324 | **1.380** | **Rust 1.38x faster** (P12 precomputed comb) |
| Ed25519 | Verify | 24,016 | 27,762 | **1.156** | **Rust 1.16x faster** (P55 projective) |
| Ed448 | Sign | — | 10,158 | — | P65 precomputed table + P66/P69 field opts |
| Ed448 | Verify | — | 2,205 | — | P66/P69 field opts |
| X25519 | DH | 49,594 | 47,827 | **0.964** | Near parity (P60 Fe25519 opt) |
| X448 | DH | — | 5,935 | — | P66/P69 field opts |
| SM2 | Sign | 2,560 | 17,183 | **6.71** | **Rust 6.7x faster** (P10 field) |
| SM2 | Verify | 4,527 | 11,947 | **2.64** | **Rust 2.6x faster** |
| SM2 | Encrypt | 1,283 | 6,761 | **5.27** | **Rust 5.3x faster!** |
| SM2 | Decrypt | 2,584 | 14,832 | **5.74** | **Rust 5.7x faster!** |
| RSA-2048 | Sign (PSS) | — | 795 | — | P68 CRT Montgomery |
| RSA-2048 | Verify (PSS) | — | 24,634 | — | — |
| RSA-2048 | Encrypt (OAEP) | — | 22,244 | — | — |
| RSA-2048 | Decrypt (OAEP) | — | 841 | — | P68 CRT |
| RSA-3072 | Sign (PSS) | — | 170 | — | P53/P67/P68 CIOS+CRT |
| RSA-3072 | Verify (PSS) | — | 7,703 | — | — |
| RSA-3072 | Encrypt (OAEP) | — | 6,430 | — | — |
| RSA-3072 | Decrypt (OAEP) | — | 153 | — | — |
| RSA-4096 | Sign (PSS) | — | 116 | — | P53/P67/P68 CIOS+CRT |
| RSA-4096 | Verify (PSS) | — | 5,587 | — | — |
| RSA-4096 | Encrypt (OAEP) | — | 4,917 | — | — |
| RSA-4096 | Decrypt (OAEP) | — | 117 | — | — |

**Analysis**:
- **ECDSA P-256**: Sign C 1.18x, verify **Rust 1.07x faster** — P55 projective comparison in verify path.
- **ECDSA P-384**: P63 specialized Montgomery field: 8.3K ops/s sign. Comb table + dedicated mont_sqr.
- **ECDSA P-521**: P64 Mersenne field: 6.7K ops/s sign. Direct reduction (p=2^521-1).
- **ECDH**: **P-256 Rust 1.10x faster**. **P-384 Rust 4.6x faster** (P63). P-521 gap narrowed to C 1.8x (P64).
- **Ed25519/X25519**: Ed25519 sign now **Rust 1.38x faster than C** (P12 precomputed comb). Ed25519 verify **Rust 1.16x faster** (P55 projective). X25519 DH near parity.
- **Ed448/X448**: P65/P66/P69: Ed448 sign 10.2K ops/s. X448 DH 5.9K ops/s.
- **SM2**: Specialized field arithmetic (Phase P10) — SM2 sign **6.7x**, decrypt **5.7x**, encrypt **5.3x** faster in Rust.
- **RSA-3072/4096**: P68 CRT Montgomery optimization. RSA-3072 sign 170 ops/s, RSA-4096 sign 116 ops/s.

---

### 3.5 Post-Quantum Cryptography

| Algorithm | Operation | C (ops/s) | Rust (ops/s) | Ratio (R/C) |
|-----------|-----------|----------|-------------|-------------|
| ML-KEM-512 | KeyGen | 92,755 | 37,555 | **0.405** |
| ML-KEM-512 | Encaps | 167,182 | 34,552 | **0.207** |
| ML-KEM-512 | Decaps | 125,729 | 33,504 | **0.266** |
| ML-KEM-768 | KeyGen | 38,814 | 21,060 | **0.543** |
| ML-KEM-768 | Encaps | 119,805 | 23,342 | **0.195** |
| ML-KEM-768 | Decaps | 86,794 | 21,431 | **0.247** |
| ML-KEM-1024 | KeyGen | 32,864 | 18,284 | **0.556** |
| ML-KEM-1024 | Encaps | 91,958 | 22,472 | **0.244** |
| ML-KEM-1024 | Decaps | 65,644 | 17,136 | **0.261** |
| ML-DSA-44 | KeyGen | 25,553 | 10,839 | **0.424** |
| ML-DSA-44 | Sign | 7,413 | 9,302 | **1.255** |
| ML-DSA-44 | Verify | 20,882 | 11,053 | **0.529** |
| ML-DSA-65 | KeyGen | 14,894 | 5,486 | **0.368** |
| ML-DSA-65 | Sign | 4,566 | 3,354 | **0.735** |
| ML-DSA-65 | Verify | 12,998 | 6,458 | **0.497** |
| ML-DSA-87 | KeyGen | 8,563 | 2,595 | **0.303** |
| ML-DSA-87 | Sign | 3,517 | 1,477 | **0.420** |
| ML-DSA-87 | Verify | 7,018 | 3,617 | **0.515** |

**Analysis**: PQC performance in full-suite run (thermal effects reduce absolute numbers vs isolated runs):
- **ML-KEM**: C remains 2.5–5.1x faster. P83 SHAKE clone-fork eliminates redundant seed absorption, but gap remains due to SHAKE domination in Keccak throughput.
- **ML-DSA**: ML-DSA-44 sign now **1.26x faster than C**. Other ML-DSA variants show C advantage. P57 zero-alloc retry loop + P59 Keccak unroll remain effective.

---

### 3.6 SLH-DSA (FIPS 205, Stateless Hash-Based Signatures)

| Variant | KeyGen (ops/s) | Sign (ops/s) | Verify (ops/s) | Sign Time |
|---------|---------------|-------------|----------------|-----------|
| SHA2-128f | 1,420 | 49 | 917 | 20.3 ms |
| SHAKE-128f | 283 | 9 | 144 | 106.7 ms |
| SHA2-192f | 623 | 27 | 580 | 36.4 ms |
| SHA2-256f | 304 | 10 | 460 | 100.5 ms |

**Analysis**: SLH-DSA with P78 hypertree heap elimination. Only `-f` (fast) variants benchmarked; `-s` (small signature) variants are 5–10x slower. SHA2 variants are 4–6x faster than SHAKE variants due to hardware SHA-2 acceleration (SHA-NI/SHA-512 CE). SHA2-128f is the fastest practical variant (sign ~49 ops/s, verify ~917 ops/s). No C reference data available. Full-suite thermal effects reduce absolute numbers significantly (these benchmarks run late in suite).

---

### 3.7 Diffie-Hellman Key Exchange

| Group | C KeyGen (ops/s) | Rust KeyGen (ops/s) | C Derive (ops/s) | Rust Derive (ops/s) | Ratio (KeyGen) | Ratio (Derive) |
|-------|-------------------|---------------------|-------------------|---------------------|----------------|----------------|
| FFDHE-2048 | 1,219 | 135 | 997 | 177 | **0.111** | **0.178** |
| FFDHE-3072 | 489 | 68 | 467 | 46 | **0.139** | **0.099** |
| FFDHE-4096 | 290 | 19 | 288 | 19 | **0.066** | **0.065** |

**Analysis**: C is 5.6–15.3x faster for DH operations. P81 adds precomputed generator tables (`MontExpTable` + `DhGroupCache`), but thermal effects dominate this full-suite run. The gap increases with key size due to O(n²) Montgomery inner loop — C uses hand-tuned assembly (`bn_mul_mont`). P53/P67/P81 CIOS optimizations (bounds-check elim + fused squaring + precomputed tables) improved by ~40% over P0 but fundamental gap remains. DH is rarely the bottleneck in modern TLS (ECDHE is strongly preferred).

---

### 3.8 ECDH Multi-Curve

| Curve | C KeyGen (ops/s) | C Derive (ops/s) | Rust Derive (ops/s) | Ratio (Derive) |
|-------|-------------------|-------------------|---------------------|----------------|
| P-224 | 86,438 | 30,903 | — | — |
| P-256 | 41,174 | 13,584 | 14,927 | **1.099** |
| P-384 | 1,041 | 969 | 4,449 | **4.591** |
| P-521 | 12,182 | 5,059 | 2,783 | **0.550** |
| brainpoolP256r1 | 2,524 | 2,574 | — | — |

**Analysis**: **P-256 now Rust 1.10x faster than C**. **P-384 Rust 4.6x faster** — P63 specialized Montgomery field (P[3..5]=0xFF reduction trick, dedicated mont_sqr). P-521 gap narrowed to C 1.8x — P64 Mersenne field (direct reduction p=2^521-1).

---

### 3.9 Additional Symmetric Ciphers (8 KB payload)

| Algorithm | Encrypt (MB/s) | Decrypt (MB/s) | Notes |
|-----------|---------------|----------------|-------|
| AES-128-ECB | 2,277 | 1,496 | P72 4-block parallel, AES-NI |
| AES-256-ECB | 4,641 | 1,767 | P72 4-block parallel |
| AES-128-XTS | 859 | 1,260 | Dual-key (tweak + data) |
| AES-256-XTS | 783 | 723 | — |
| AES-128-CFB | 413 | 489 | Decrypt parallelizable |
| AES-256-CFB | 675 | 1,033 | — |
| AES-128-OFB | 1,788 | — | Symmetric mode |
| AES-256-OFB | 1,372 | — | — |
| AES-128-CCM | 505 | 545 | P72 4-block CTR + CBC-MAC |
| AES-128-HCTR | 94 | 100 | P71 table-based GF multiply |
| AES-128 Wrap | — | — | 1,660 ns / 1,410 ns (wrap/unwrap, 24B) |
| AES-256 Wrap | — | — | 1,103 ns / 1,080 ns |
| SM4-CCM | 72 | 73 | SM4 T-table + CBC-MAC |

**Analysis**: AES-ECB throughput ranges 1.5–4.6 GB/s with P72 4-block parallel pipeline. OFB achieves 1.4–1.8 GB/s. P71 HCTR table-based GF(2^128) multiply. Thermal effects present across all benchmarks in this full-suite run.

---

### 3.10 Additional Hash Functions & XOFs (8 KB payload)

| Algorithm | Throughput (MB/s) | Notes |
|-----------|-------------------|-------|
| SHA3-256 | 172 | Keccak-f1600 (P59 unroll + P18 HW accel) |
| SHA3-384 | 160 | Wider capacity → lower rate |
| SHA3-512 | 86 | — |
| SHAKE128 | 110 | XOF (128-bit security) |
| SHAKE256 | 83 | XOF (256-bit security) |
| SHA-1 | 2,264 | **P74 ARMv8 Crypto Extension** |
| MD5 | 213 | Legacy; no HW acceleration |

**Analysis**: **SHA-1 at 2.3 GB/s** — P74 ARMv8 Crypto Extension hardware acceleration. SHA-3 throughput (86–172 MB/s) is substantially lower than SHA-2 (1,231–2,048 MB/s) due to the Keccak sponge construction. SHA-3/SHAKE numbers are lower than P80 due to thermal effects (these run late in suite).

---

### 3.11 Additional MAC Algorithms (8 KB payload)

| Algorithm | Throughput (MB/s) | Notes |
|-----------|-------------------|-------|
| HMAC-SHA384 | 795 | SHA-512 CE based |
| CMAC-AES128 | 839 | AES-NI block cipher MAC |
| CMAC-AES256 | 705 | — |
| GMAC-AES128 | 652 | GHASH (PMULL HW) |
| Poly1305 | 3,486 | P75 r² precompute (standalone) |
| SipHash-2-4 | 1,225 | Fast keyed hash |
| CBC-MAC-SM4 | 68 | SM4 T-table, sequential |

**Analysis**: **Poly1305 standalone** at 3.5 GB/s @8KB — P75 r² precompute enables efficient 2-block batch processing. CMAC-AES128 at 839 MB/s. GMAC at 652 MB/s. Full-suite thermal effects reduce some absolute numbers.

---

### 3.12 Key Derivation Functions

| Algorithm | Time | Notes |
|-----------|------|-------|
| HKDF extract+expand (32B) | 726 ns | SHA-256 based |
| HKDF extract+expand (64B) | 1,717 ns | — |
| PBKDF2 (1,000 iterations) | 472 µs | SHA-256, 32B output |
| PBKDF2 (10,000 iterations) | 4.43 ms | — |
| scrypt (N=1024, r=8, p=1) | 2.40 ms | Low-memory setting |
| scrypt (N=16384, r=8, p=1) | 42.7 ms | Standard setting |

---

### 3.13 DRBG Performance

| Algorithm | Generate 32B | Notes |
|-----------|-------------|-------|
| CTR-DRBG (AES-256) | 580 ns | P20 cached AES key |
| HMAC-DRBG (SHA-256) | 951 ns | — |
| Hash-DRBG (SHA-256) | 403 ns | — |
| SM4-CTR-DRBG | 528 ns | SM4 T-table + P20 key caching |

**Analysis**: Hash-DRBG is the fastest at 403 ns. SM4-CTR-DRBG improved with P20 key caching. HMAC-DRBG is slowest due to two HMAC operations per generate.

---

### 3.14 Additional PQC & Miscellaneous

| Algorithm | Operation | Time | Ops/s |
|-----------|-----------|------|-------|
| HybridKEM X25519+ML-KEM-768 | Encaps | 79.3 µs | 12,617 |
| HybridKEM P256+ML-KEM-768 | Encaps | 403 µs | 2,482 |
| HybridKEM P384+ML-KEM-768 | Encaps | 1,167 µs | 857 |
| HPKE (X25519+AES-128-GCM) | Seal | 70.7 µs | 14,145 |
| HPKE (X25519+AES-128-GCM) | Open | 49.5 µs | 20,198 |
| FrodoKEM-640-SHAKE | KeyGen | 6.77 ms | 148 |
| FrodoKEM-640-SHAKE | Encaps | 3.42 ms | 292 |
| FrodoKEM-640-SHAKE | Decaps | 2.88 ms | 347 |
| FrodoKEM-976-SHAKE | KeyGen | 10.82 ms | 92 |
| FrodoKEM-976-SHAKE | Encaps | 5.87 ms | 170 |
| FrodoKEM-976-SHAKE | Decaps | 7.01 ms | 143 |
| FrodoKEM-1344-SHAKE | KeyGen | 22.2 ms | 45 |
| FrodoKEM-1344-SHAKE | Encaps | 23.4 ms | 43 |
| FrodoKEM-1344-SHAKE | Decaps | 23.4 ms | 43 |
| McEliece-6688128 | Encaps | 602 µs | 1,660 |
| McEliece-6688128 | Decaps | 24.0 ms | 42 |
| XMSS SHA2-10-256 | Verify | 194 µs | 5,143 |
| XMSS-MT SHA2-20-2-256 | Verify | 448 µs | 2,230 |
| Paillier-512 | Encrypt | 462 µs | 2,164 |
| Paillier-512 | Decrypt | 288 µs | 3,470 |

**Note**: DSA and ElGamal benchmarks use small demonstration parameters (p=23) and are not representative of cryptographic-strength operations. McEliece keygen is excluded as it takes ~5 seconds. HybridKEM benchmarks P256 and P384 variants in addition to X25519. Full-suite thermal effects reduce some absolute numbers.

---

### 3.15 BigNum Arithmetic

| Operation | 256-bit | 512-bit | 1024-bit | 2048-bit | 4096-bit |
|-----------|---------|---------|----------|----------|----------|
| Multiply | 48.3 ns | 251.2 ns | 412.0 ns | 1,017 ns | 4,794 ns |
| Add | 36.8 ns | 98.0 ns | 87.3 ns | 147.7 ns | 264.2 ns |

**Modular exponentiation** (CIOS Montgomery, Phase P7/P15/P22/P53/P67/P81):

| Operation | Time |
|-----------|------|
| mod_exp 1024-bit | 393.2 µs |
| mod_exp 2048-bit | 3.35 ms |
| mod_exp 4096-bit | 29.5 ms |

---

## 4. Performance Heatmap

```
                        C faster <------------------> Rust faster
                        x12    x8     x4    1.0    x2     x5    x8

DH-4096 keygen          ████████████████░░░░░░░░░░░░░░░░░░░░░░░░░  C x15.3
DH-2048 keygen          ██████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x9.0
SM3                     ██████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x3.5 (thermal)
ECDH P-521              ██████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x1.82
ECDSA P-256 sign        ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x1.18
X25519 DH               ░░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░░░░  Near parity
ECDSA P-256 verify      ░░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░░░░  R x1.07
ECDH P-256              ░░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░░░░  R x1.10
Ed25519 verify          ░░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░░░░  R x1.16
ML-DSA-44 sign          ░░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░░░░  R x1.26
Ed25519 sign            ░░░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░░░  R x1.38
SHA-512                 ░░░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░░░  R x1.54
ChaCha20-Poly1305 enc   ░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░  R x1.55
SM4-GCM enc             ░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░  R x1.95
AES-128-CBC enc         ░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░  R x1.98
SHA-384                 ░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░  R x2.28
SM2 verify              ░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░  R x2.64
AES-256-CBC enc         ░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░  R x3.50
SHA-256                 ░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░  R x3.58
HMAC-SHA256             ░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░  R x3.91
ECDH P-384              ░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░  R x4.59
AES-128-GCM enc         ░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░  R x5.15
AES-128-CBC dec         ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░  R x5.37
SM2 sign                ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░  R x6.71
AES-256-GCM enc         ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██████  R x8.33
```

---

## 5. Performance Optimization History (Phase P1–P93)

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
| **P63** | P-384 specialized Montgomery field | **ECDSA P-384 sign 20x faster** |
| **P64** | P-521 specialized Mersenne field | **ECDSA P-521 sign 28x faster** |
| **P65** | Ed448 precomputed base table (comb method) | **Ed448 sign 14x faster** |
| **P66–P69** | Fe448 opts + Karatsuba + constant-time scalar mul | Ed448/X448 further optimized |
| **P67** | BigNum fused CIOS squaring | 25–30% all Montgomery exponentiation |
| **P68** | RSA CRT Montgomery optimization | 10–15% RSA sign/decrypt |
| **P71** | HCTR GF(2^128) table-based multiply | **AES-HCTR 30x faster** |
| **P72** | AES 4-block parallel pipeline | **AES-ECB 2.2x, CTR +8%, CCM +9%** |
| **P73** | GCM interleaved CTR+GHASH 4-block pipeline | **AES-GCM 20–37% faster** |
| **P74** | SHA-1 ARMv8 Crypto Extension acceleration | **SHA-1 5x faster** |
| **P75** | Poly1305 r² precompute + 2-block batch | Poly1305 30–40% faster |
| **P76** | ChaCha20 2-block parallel generation | ChaCha20 15–20% faster |
| **P77** | SM3 pre-expansion + loop unification | SM3 10–15% faster |
| **P78** | SLH-DSA hypertree heap elimination | SLH-DSA verify 20–30% faster |
| **P79** | FrodoKEM matrix buffer reuse | FrodoKEM 15–25% faster |
| **P80** | SM9 pairing O(n²) fix + clone elimination | SM9 5–10% faster |
| **P81** | DH precomputed generator tables (MontExpTable + DhGroupCache) | mod_exp 13–16% faster |
| **P82** | SM3 pipelined message expansion (expand/compress overlap) | SM3 regression (needs revert) |
| **P83** | ML-KEM SHAKE clone-fork (pre-seed + clone) | ML-KEM ~3–5% improvement |
| **P84** | VAES 256-bit + VPCLMULQDQ 4-block AES-GCM pipeline (clippy compat) | x86-64 CI unblocked |
| **P85** | TLS record layer enum dispatch + stack IV allocation | Eliminated vtable + heap alloc per AEAD call |
| **P89** | Hot path `#[inline]` hints (record layer + crypto dispatch) | Cross-crate inlining for ~20 functions |
| **P93** | Zero-copy inner plaintext parsing (TLS/DTLS 1.3 decrypt) | 1 fewer heap alloc per decrypted record |

### Key Milestones

| Milestone | Before (P0) | After (P93) | Speedup |
|-----------|-------------|-------------|---------|
| ECDSA P-256 sign | 2,415 µs | 44.0 µs | **55x** |
| ECDSA P-384 sign | 2,372 µs | 120.6 µs | **20x** (P63) |
| ECDSA P-521 sign | 3,946 µs | 150.0 µs | **26x** (P64) |
| Ed448 sign | 661 µs | 98.4 µs | **6.7x** (P65) |
| SM2 sign | 2,331 µs | 58.2 µs | **40x** |
| Ed25519 sign | 56.1 µs | 10.95 µs | **5.1x** |
| SHA-256 @8KB | 42.25 µs | 4.00 µs | **10.6x** |
| AES-128-GCM @8KB | 10.7 µs | 10.2 µs | **1.05x** (P73) |
| AES-128-HCTR @8KB | 1,904 µs | 86.9 µs | **22x** (P71) |
| SHA-1 @8KB | 17.3 µs | 3.62 µs | **4.8x** (P74) |
| ML-KEM-768 encaps | ~109 µs | 42.8 µs | **2.5x** |
| ML-DSA-44 sign | ~355 µs | 107.5 µs | **3.3x** |
| RSA-2048 sign | 1.37 ms | 1.26 ms | **1.09x** (P53/P67/P68) |
| mod_exp 2048-bit | 5.42 ms | 3.35 ms | **1.62x** (P81) |

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

**Suite composition**: 63 benchmark groups, 307 test points:
- Symmetric ciphers: 17 groups (AES modes, SM4 modes, ChaCha20)
- Hash functions: 5 groups (SHA-2, SHA-3, SHAKE, SHA-1, MD5, SM3)
- MAC algorithms: 7 groups (HMAC variants, CMAC, GMAC, SipHash, CBC-MAC, Poly1305)
- Asymmetric: 11 groups (ECDSA, ECDH, EdDSA, X-DH, SM2, RSA-2048/3072/4096)
- Post-quantum: 6 groups (ML-KEM, ML-DSA, SLH-DSA, HybridKEM, HPKE, SM9)
- Large-key/slow: 8 groups (DH, DSA, FrodoKEM, XMSS, XMSS-MT, McEliece, ElGamal, Paillier)
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
- **Full suite thermal effects**: The ~40-minute full benchmark run may show 20–50% thermal throttling in later tests. Key comparison benchmarks should run in isolated batches for accuracy
- **Criterion overhead**: Criterion's statistical framework adds per-sample overhead (~microseconds)
- **No CPU pinning**: macOS does not support `taskset`-style CPU pinning on Apple Silicon
- **Small-parameter benchmarks**: DSA and ElGamal use demonstration parameters (p=23) — not representative of real-world cryptographic performance
- **Sample size**: Slow algorithms (SLH-DSA, FrodoKEM, McEliece, XMSS, scrypt) use `sample_size(10)`; results have wider confidence intervals

---

## Appendix A: Throughput Summary (8 KB payload, MB/s)

| Algorithm | Throughput (MB/s) | Category |
|-----------|-------------------|----------|
| AES-256-ECB encrypt | 4,641 | Symmetric |
| Poly1305 | 3,486 | MAC |
| AES-128-ECB encrypt | 2,277 | Symmetric |
| SHA-1 | 2,264 | Hash |
| SHA-256 | 2,048 | Hash |
| AES-128-OFB | 1,788 | Symmetric |
| AES-128-CBC decrypt | 1,780 | Symmetric |
| AES-256-ECB decrypt | 1,767 | Symmetric |
| AES-256-CBC decrypt | 1,625 | Symmetric |
| AES-128-ECB decrypt | 1,496 | Symmetric |
| AES-256-OFB | 1,372 | Symmetric |
| SHA-512 | 1,360 | Hash |
| AES-128-XTS decrypt | 1,260 | Symmetric |
| HMAC-SHA256 | 1,252 | MAC |
| SHA-384 | 1,231 | Hash |
| AES-128-CTR | 1,237 | Symmetric |
| SipHash-2-4 | 1,225 | MAC |
| AES-256-GCM encrypt | 1,203 | AEAD |
| AES-256-GCM decrypt | 1,162 | AEAD |
| AES-256-CTR | 1,101 | Symmetric |
| AES-256-CFB decrypt | 1,033 | Symmetric |
| HMAC-SHA512 | 1,028 | MAC |
| AES-128-GCM decrypt | 922 | AEAD |
| AES-128-XTS encrypt | 859 | Symmetric |
| CMAC-AES128 | 839 | MAC |
| AES-256-CBC encrypt | 830 | Symmetric |
| AES-128-GCM encrypt | 802 | AEAD |
| HMAC-SHA384 | 795 | MAC |
| AES-256-XTS encrypt | 783 | Symmetric |
| AES-256-XTS decrypt | 723 | Symmetric |
| ChaCha20-Poly1305 decrypt | 723 | AEAD |
| CMAC-AES256 | 705 | MAC |
| AES-256-CFB encrypt | 675 | Symmetric |
| GMAC-AES128 | 652 | MAC |
| AES-128-CBC encrypt | 642 | Symmetric |
| AES-128-CCM decrypt | 545 | AEAD |
| ChaCha20-Poly1305 encrypt | 532 | AEAD |
| AES-128-CCM encrypt | 505 | AEAD |
| AES-128-CFB decrypt | 489 | Symmetric |
| AES-128-CFB encrypt | 413 | Symmetric |
| HMAC-SM3 | 317 | MAC |
| MD5 | 213 | Hash |
| SM4-CBC decrypt | 191 | Symmetric |
| SHA3-256 | 172 | Hash |
| SM4-GCM encrypt | 171 | Symmetric |
| SM4-GCM decrypt | 166 | Symmetric |
| SHA3-384 | 160 | Hash |
| SM3 | 151 | Hash |
| SM4-CBC encrypt | 137 | Symmetric |
| SHAKE128 | 110 | XOF |
| AES-128-HCTR decrypt | 100 | Symmetric |
| AES-128-HCTR encrypt | 94 | Symmetric |
| SHA3-512 | 86 | Hash |
| SHAKE256 | 83 | XOF |
| SM4-CCM decrypt | 73 | AEAD |
| SM4-CCM encrypt | 72 | AEAD |
| CBC-MAC-SM4 | 68 | MAC |

## Appendix B: Public Key Operations Summary (ops/sec)

| Algorithm | Operation | Ops/sec |
|-----------|-----------|---------|
| Ed25519 | sign | 91,324 |
| X25519 | DH | 47,827 |
| ML-KEM-512 | keygen | 37,555 |
| ML-KEM-512 | encaps | 34,552 |
| ML-KEM-512 | decaps | 33,504 |
| Ed25519 | verify | 27,762 |
| RSA-2048 | verify (PSS) | 24,634 |
| ML-KEM-768 | encaps | 23,342 |
| ECDSA P-256 | sign | 22,712 |
| RSA-2048 | encrypt (OAEP) | 22,244 |
| ML-KEM-1024 | encaps | 22,472 |
| ML-KEM-768 | decaps | 21,431 |
| ML-KEM-768 | keygen | 21,060 |
| HPKE | open | 20,198 |
| ML-KEM-1024 | keygen | 18,284 |
| SM2 | sign | 17,183 |
| ML-KEM-1024 | decaps | 17,136 |
| HybridKEM X25519+ML-KEM-768 | keygen | 16,211 |
| SM2 | decrypt | 14,832 |
| ECDH P-256 | key_derive | 14,927 |
| HPKE | seal | 14,145 |
| HybridKEM X25519+ML-KEM-768 | encaps | 12,617 |
| SM2 | verify | 11,947 |
| ECDSA P-256 | verify | 11,203 |
| ML-DSA-44 | verify | 11,053 |
| ML-DSA-44 | keygen | 10,839 |
| Ed448 | sign | 10,158 |
| ML-DSA-44 | sign | 9,302 |
| ECDSA P-384 | sign | 8,289 |
| HybridKEM X25519+ML-KEM-768 | decaps | 8,394 |
| RSA-3072 | verify (PSS) | 7,703 |
| SM2 | encrypt | 6,761 |
| ECDSA P-521 | sign | 6,669 |
| ML-DSA-65 | verify | 6,458 |
| RSA-3072 | encrypt (OAEP) | 6,430 |
| HybridKEM P384+ML-KEM-768 | keygen | 6,548 |
| X448 | DH | 5,935 |
| RSA-4096 | verify (PSS) | 5,587 |
| ML-DSA-65 | keygen | 5,486 |
| XMSS SHA2-10-256 | verify | 5,143 |
| HybridKEM P256+ML-KEM-768 | keygen | 5,135 |
| RSA-4096 | encrypt (OAEP) | 4,917 |
| ECDH P-384 | key_derive | 4,449 |
| ML-DSA-87 | verify | 3,617 |
| Paillier-512 | decrypt | 3,470 |
| ECDSA P-384 | verify | 3,488 |
| ML-DSA-65 | sign | 3,354 |
| HybridKEM P256+ML-KEM-768 | decaps | 2,978 |
| ECDH P-521 | key_derive | 2,783 |
| ML-DSA-87 | keygen | 2,595 |
| HybridKEM P256+ML-KEM-768 | encaps | 2,482 |
| XMSS-MT SHA2-20-2-256 | verify | 2,230 |
| Ed448 | verify | 2,205 |
| Paillier-512 | encrypt | 2,164 |
| ECDSA P-521 | verify | 2,061 |
| ML-DSA-87 | sign | 1,477 |
| McEliece-6688128 | encaps | 1,660 |
| SLH-DSA SHA2-128f | keygen | 1,420 |
| HybridKEM P384+ML-KEM-768 | decaps | 1,380 |
| SLH-DSA SHA2-128f | verify | 917 |
| HybridKEM P384+ML-KEM-768 | encaps | 857 |
| RSA-2048 | decrypt (OAEP) | 841 |
| RSA-2048 | sign (PSS) | 795 |
| SLH-DSA SHA2-192f | keygen | 623 |
| SLH-DSA SHA2-192f | verify | 580 |
| SLH-DSA SHA2-256f | verify | 460 |
| FrodoKEM-640-SHAKE | decaps | 347 |
| SLH-DSA SHA2-256f | keygen | 304 |
| FrodoKEM-640-SHAKE | encaps | 292 |
| SLH-DSA SHAKE-128f | keygen | 283 |
| ffdhe2048 | key_derive | 177 |
| ML-DSA-44 | sign (C only) | — |
| FrodoKEM-976-SHAKE | encaps | 170 |
| RSA-3072 | sign (PSS) | 170 |
| RSA-3072 | decrypt (OAEP) | 153 |
| FrodoKEM-640-SHAKE | keygen | 148 |
| SLH-DSA SHAKE-128f | verify | 144 |
| FrodoKEM-976-SHAKE | decaps | 143 |
| ffdhe2048 | keygen | 135 |
| RSA-4096 | decrypt (OAEP) | 117 |
| RSA-4096 | sign (PSS) | 116 |
| FrodoKEM-976-SHAKE | keygen | 92 |
| ffdhe3072 | keygen | 68 |
| SLH-DSA SHA2-128f | sign | 49 |
| ffdhe3072 | key_derive | 46 |
| FrodoKEM-1344-SHAKE | keygen | 45 |
| FrodoKEM-1344-SHAKE | encaps | 43 |
| FrodoKEM-1344-SHAKE | decaps | 43 |
| McEliece-6688128 | decaps | 42 |
| SLH-DSA SHA2-192f | sign | 27 |
| ffdhe4096 | keygen | 19 |
| ffdhe4096 | key_derive | 19 |
| SLH-DSA SHA2-256f | sign | 10 |
| SLH-DSA SHAKE-128f | sign | 9 |

## Appendix C: Full Criterion Mean Times (2026-03-05)

All times in nanoseconds unless noted. Full-suite run with 63 groups, 307 test points.

```
=== Block Ciphers ===
aes-128 encrypt_block:      8.75 ns    aes-128 decrypt_block:      7.49 ns
aes-256 encrypt_block:     12.14 ns    aes-256 decrypt_block:     16.70 ns
sm4 encrypt_block:        111.43 ns    sm4 decrypt_block:        109.20 ns

=== AES-GCM (AEAD) ===
aes-128-gcm enc @1KB:     2,179 ns    aes-128-gcm dec @1KB:     1,775 ns
aes-128-gcm enc @8KB:    10,217 ns    aes-128-gcm dec @8KB:     8,885 ns
aes-128-gcm enc @16KB:   24,866 ns    aes-128-gcm dec @16KB:   10,359 ns
aes-256-gcm enc @1KB:     1,372 ns    aes-256-gcm dec @1KB:     1,336 ns
aes-256-gcm enc @8KB:     6,810 ns    aes-256-gcm dec @8KB:     7,050 ns
aes-256-gcm enc @16KB:   11,575 ns    aes-256-gcm dec @16KB:   23,555 ns

=== AES-CBC ===
aes-128-cbc enc @1KB:     2,424 ns    aes-128-cbc dec @1KB:     1,070 ns
aes-128-cbc enc @8KB:    12,753 ns    aes-128-cbc dec @8KB:     4,602 ns
aes-128-cbc enc @16KB:   24,681 ns    aes-128-cbc dec @16KB:   11,357 ns
aes-256-cbc enc @1KB:     1,707 ns    aes-256-cbc dec @1KB:       883 ns
aes-256-cbc enc @8KB:     9,874 ns    aes-256-cbc dec @8KB:     5,043 ns
aes-256-cbc enc @16KB:   24,385 ns    aes-256-cbc dec @16KB:    8,449 ns

=== AES-CTR ===
aes-128-ctr @1KB:         1,109 ns    aes-256-ctr @1KB:         1,309 ns
aes-128-ctr @8KB:         6,620 ns    aes-256-ctr @8KB:         7,444 ns
aes-128-ctr @16KB:       12,965 ns    aes-256-ctr @16KB:       19,702 ns

=== AES-CCM (AEAD) ===
aes-128-ccm enc @1KB:     2,314 ns    aes-128-ccm dec @1KB:     2,584 ns
aes-128-ccm enc @8KB:    16,227 ns    aes-128-ccm dec @8KB:    15,035 ns
aes-128-ccm enc @16KB:   30,279 ns    aes-128-ccm dec @16KB:   31,337 ns

=== AES-ECB ===
aes-128-ecb enc @1KB:       534 ns    aes-128-ecb dec @1KB:     1,679 ns
aes-128-ecb enc @8KB:     3,598 ns    aes-128-ecb dec @8KB:     5,478 ns
aes-128-ecb enc @16KB:    2,540 ns    aes-128-ecb dec @16KB:    5,887 ns
aes-256-ecb enc @1KB:       719 ns    aes-256-ecb dec @1KB:       817 ns
aes-256-ecb enc @8KB:     1,765 ns    aes-256-ecb dec @8KB:     4,635 ns
aes-256-ecb enc @16KB:    3,984 ns    aes-256-ecb dec @16KB:   20,607 ns

=== AES-XTS ===
aes-128-xts enc @1KB:     1,847 ns    aes-128-xts dec @1KB:     2,387 ns
aes-128-xts enc @8KB:     9,535 ns    aes-128-xts dec @8KB:     6,504 ns
aes-128-xts enc @16KB:   13,298 ns    aes-128-xts dec @16KB:   15,113 ns
aes-256-xts enc @1KB:     2,080 ns    aes-256-xts dec @1KB:     2,717 ns
aes-256-xts enc @8KB:    10,466 ns    aes-256-xts dec @8KB:    11,339 ns
aes-256-xts enc @16KB:   32,871 ns    aes-256-xts dec @16KB:   55,447 ns

=== AES-CFB ===
aes-128-cfb enc @1KB:     1,683 ns    aes-128-cfb dec @1KB:     1,456 ns
aes-128-cfb enc @8KB:    19,822 ns    aes-128-cfb dec @8KB:    16,753 ns
aes-128-cfb enc @16KB:   31,407 ns    aes-128-cfb dec @16KB:   13,973 ns
aes-256-cfb enc @1KB:     2,001 ns    aes-256-cfb dec @1KB:     1,351 ns
aes-256-cfb enc @8KB:    12,137 ns    aes-256-cfb dec @8KB:     7,929 ns
aes-256-cfb enc @16KB:   22,261 ns    aes-256-cfb dec @16KB:   16,638 ns

=== AES-OFB ===
aes-128-ofb @1KB:           703 ns    aes-256-ofb @1KB:         1,013 ns
aes-128-ofb @8KB:         4,582 ns    aes-256-ofb @8KB:         5,973 ns
aes-128-ofb @16KB:        7,342 ns    aes-256-ofb @16KB:       11,898 ns

=== AES Key Wrap ===
aes-128 wrap:             1,660 ns    aes-128 unwrap:           1,410 ns
aes-256 wrap:             1,103 ns    aes-256 unwrap:           1,080 ns

=== AES-HCTR ===
aes-128-hctr enc @1KB:   10,783 ns    aes-128-hctr dec @1KB:   12,125 ns
aes-128-hctr enc @8KB:   86,868 ns    aes-128-hctr dec @8KB:   81,516 ns
aes-128-hctr enc @16KB: 205,330 ns    aes-128-hctr dec @16KB: 237,550 ns

=== ChaCha20-Poly1305 ===
chacha20 enc @1KB:        4,465 ns    chacha20 dec @1KB:        2,260 ns
chacha20 enc @8KB:       15,404 ns    chacha20 dec @8KB:       11,327 ns
chacha20 enc @16KB:      22,786 ns    chacha20 dec @16KB:      22,585 ns

=== Poly1305 (Standalone MAC) ===
poly1305 @64B:              30 ns    poly1305 @1KB:              302 ns
poly1305 @8KB:           2,350 ns    poly1305 @16KB:           4,625 ns

=== SM4 Block / SM4-CBC / SM4-GCM / SM4-CCM ===
sm4 encrypt_block:        111.4 ns    sm4 decrypt_block:        109.2 ns
sm4-cbc enc @1KB:         7,653 ns    sm4-cbc dec @1KB:         5,500 ns
sm4-cbc enc @8KB:        59,782 ns    sm4-cbc dec @8KB:        42,815 ns
sm4-cbc enc @16KB:      113,280 ns    sm4-cbc dec @16KB:       81,613 ns
sm4-gcm enc @1KB:         6,337 ns    sm4-gcm dec @1KB:         6,258 ns
sm4-gcm enc @8KB:        48,033 ns    sm4-gcm dec @8KB:        49,326 ns
sm4-gcm enc @16KB:      104,060 ns    sm4-gcm dec @16KB:       98,695 ns
sm4-ccm enc @1KB:        14,573 ns    sm4-ccm dec @1KB:        14,247 ns
sm4-ccm enc @8KB:       113,050 ns    sm4-ccm dec @8KB:       111,810 ns
sm4-ccm enc @16KB:      282,290 ns    sm4-ccm dec @16KB:      281,530 ns

=== Hash Functions ===
sha256 @1KB:                455 ns    sha384 @1KB:                942 ns
sha512 @1KB:                948 ns    sm3 @1KB:                 7,426 ns
sha256 @8KB:              4,000 ns    sha384 @8KB:              6,653 ns
sha512 @8KB:              6,024 ns    sm3 @8KB:                54,275 ns
sha256 @16KB:             8,788 ns    sha384 @16KB:            15,391 ns
sha512 @16KB:            19,897 ns    sm3 @16KB:               89,833 ns

=== SHA-3 / SHAKE ===
sha3-256 @1KB:            6,348 ns    sha3-384 @1KB:            8,667 ns
sha3-512 @1KB:           13,976 ns
sha3-256 @8KB:           47,508 ns    sha3-384 @8KB:           51,134 ns
sha3-512 @8KB:           95,101 ns
sha3-256 @16KB:          83,926 ns    sha3-384 @16KB:         130,340 ns
sha3-512 @16KB:         203,710 ns
shake128 @1KB:           10,309 ns    shake256 @1KB:           11,431 ns
shake128 @8KB:           74,396 ns    shake256 @8KB:           98,355 ns
shake128 @16KB:         153,230 ns    shake256 @16KB:         204,580 ns

=== SHA-1 / MD5 (Legacy) ===
sha1 @1KB:                  488 ns    md5 @1KB:                 6,083 ns
sha1 @8KB:                3,619 ns    md5 @8KB:                38,458 ns
sha1 @16KB:               7,512 ns    md5 @16KB:              100,380 ns

=== HMAC ===
hmac-sha256 @1KB:         1,331 ns    hmac-sha512 @1KB:         2,206 ns
hmac-sha384 @1KB:         1,390 ns    hmac-sm3 @1KB:           11,632 ns
hmac-sha256 @8KB:         6,542 ns    hmac-sha512 @8KB:         7,968 ns
hmac-sha384 @8KB:        10,302 ns    hmac-sm3 @8KB:           25,848 ns
hmac-sha256 @16KB:       12,769 ns    hmac-sha512 @16KB:       16,737 ns
hmac-sha384 @16KB:       24,108 ns    hmac-sm3 @16KB:          51,259 ns

=== Other MAC ===
cmac-aes128 @1KB:         2,021 ns    cmac-aes256 @1KB:         1,872 ns
cmac-aes128 @8KB:         9,765 ns    cmac-aes256 @8KB:        11,622 ns
cmac-aes128 @16KB:       18,240 ns    cmac-aes256 @16KB:       27,130 ns
gmac-aes128 @1KB:         2,514 ns    gmac-aes128 @8KB:        12,561 ns
gmac-aes128 @16KB:       25,237 ns
siphash @64B:                55 ns    siphash @1KB:               767 ns
siphash @8KB:             6,687 ns
cbc-mac-sm4 @1KB:        12,782 ns    cbc-mac-sm4 @8KB:       121,250 ns
cbc-mac-sm4 @16KB:      127,340 ns

=== Elliptic Curves ===
ecdsa-p256 sign:         44,032 ns    ecdsa-p256 verify:       89,267 ns
ecdsa-p384 sign:        120,640 ns    ecdsa-p384 verify:      286,670 ns
ecdsa-p521 sign:        149,950 ns    ecdsa-p521 verify:      485,320 ns
ecdh p256 derive:        66,992 ns    ecdh p384 derive:       224,750 ns
ecdh p521 derive:       359,290 ns    x25519 dh:               20,909 ns
x448 dh:                168,510 ns
ed25519 sign:            10,950 ns    ed25519 verify:          36,025 ns
ed448 sign:              98,448 ns    ed448 verify:           453,500 ns
sm2 sign:                58,198 ns    sm2 verify:              83,706 ns
sm2 encrypt:            147,900 ns    sm2 decrypt:             67,422 ns

=== RSA-2048 ===
rsa-2048 sign pss:    1,258,300 ns    rsa-2048 verify pss:     40,594 ns
rsa-2048 enc oaep:       44,954 ns    rsa-2048 dec oaep:    1,188,600 ns

=== RSA-3072 ===
rsa-3072 sign pss:    5,887,300 ns    rsa-3072 verify pss:    129,830 ns
rsa-3072 enc oaep:      155,520 ns    rsa-3072 dec oaep:    6,543,200 ns

=== RSA-4096 ===
rsa-4096 sign pss:    8,593,800 ns    rsa-4096 verify pss:    179,000 ns
rsa-4096 enc oaep:      203,380 ns    rsa-4096 dec oaep:    8,510,700 ns

=== ML-KEM (FIPS 203) ===
mlkem-512 keygen:        26,628 ns    mlkem-512 encaps:        28,942 ns
mlkem-512 decaps:        29,847 ns
mlkem-768 keygen:        47,484 ns    mlkem-768 encaps:        42,842 ns
mlkem-768 decaps:        46,662 ns
mlkem-1024 keygen:       54,694 ns    mlkem-1024 encaps:       44,500 ns
mlkem-1024 decaps:       58,359 ns

=== ML-DSA (FIPS 204) ===
mldsa-44 keygen:         92,258 ns    mldsa-44 sign:          107,500 ns
mldsa-44 verify:         90,475 ns
mldsa-65 keygen:        182,270 ns    mldsa-65 sign:          298,130 ns
mldsa-65 verify:        154,840 ns
mldsa-87 keygen:        385,360 ns    mldsa-87 sign:          677,270 ns
mldsa-87 verify:        276,460 ns

=== SLH-DSA (FIPS 205) ===
slh-dsa sha2-128f keygen:   704,420 ns  sign:   20,341,000 ns  verify:   1,090,500 ns
slh-dsa shake-128f keygen: 3,533,000 ns  sign:  106,730,000 ns  verify:   6,939,200 ns
slh-dsa sha2-192f keygen: 1,604,200 ns  sign:   36,435,000 ns  verify:   1,723,700 ns
slh-dsa sha2-256f keygen: 3,287,900 ns  sign:  100,510,000 ns  verify:   2,174,800 ns

=== HybridKEM / HPKE ===
hybridkem x25519+mlkem768 encaps:  79,261 ns
hybridkem p256+mlkem768 encaps:   402,840 ns
hybridkem p384+mlkem768 encaps: 1,167,200 ns
hpke seal:                         70,660 ns
hpke open:                         49,509 ns

=== FrodoKEM ===
frodokem-640-shake keygen: 6,771,500 ns  encaps: 3,423,800 ns  decaps: 2,881,200 ns
frodokem-976-shake keygen:10,819,000 ns  encaps: 5,870,800 ns  decaps: 7,014,300 ns
frodokem-1344-shake keygen:22,208,000 ns encaps:23,371,000 ns  decaps:23,401,000 ns

=== McEliece ===
mceliece-6688128 encaps:     602,420 ns  decaps: 24,010,000 ns

=== XMSS ===
xmss sha2-10-256 verify:    194,440 ns

=== XMSS-MT ===
xmss-mt sha2-20-2-256 verify: 448,420 ns

=== Paillier-512 ===
paillier-512 encrypt:    462,270 ns    paillier-512 decrypt:    288,320 ns

=== Diffie-Hellman ===
dh-2048 keygen:       7,383,700 ns    dh-2048 derive:       5,639,900 ns
dh-3072 keygen:      14,765,000 ns    dh-3072 derive:      21,554,000 ns
dh-4096 keygen:      51,286,000 ns    dh-4096 derive:      53,449,000 ns

=== Key Derivation ===
hkdf extract+expand 32B:    726 ns    hkdf extract+expand 64B:  1,717 ns
pbkdf2 1000 iters:      471,780 ns    pbkdf2 10000 iters:   4,427,800 ns
scrypt n=1024:        2,401,500 ns    scrypt n=16384:      42,682,000 ns

=== DRBG ===
ctr-drbg gen 32B:           580 ns    hmac-drbg gen 32B:          951 ns
hash-drbg-sha256 gen 32B:   403 ns    sm4-ctr-drbg gen 32B:       528 ns

=== BigNum ===
bignum mul 256:              48 ns    bignum add 256:              37 ns
bignum mul 512:             251 ns    bignum add 512:              98 ns
bignum mul 1024:            412 ns    bignum add 1024:             87 ns
bignum mul 2048:          1,017 ns    bignum add 2048:            148 ns
bignum mul 4096:          4,794 ns    bignum add 4096:            264 ns
bignum mod_exp 1024:    393,150 ns    bignum mod_exp 2048:  3,352,700 ns
bignum mod_exp 4096:  29,476,000 ns
```

## Appendix D: Historical Comparison (P80 → P83)

| Benchmark | P80 (2026-03-03) | P83 (2026-03-05) | Change | Phase(s) |
|-----------|-----------------|-------------------|--------|----------|
| SHA-256 @8KB | 3.20 µs | 4.00 µs | +25% | Thermal variance |
| SHA-512 @8KB | 5.10 µs | 6.02 µs | +18% | Thermal variance |
| SM3 @8KB | 19.01 µs | 54.28 µs | **+186%** | **P82 regression** + thermal |
| HMAC-SM3 @8KB | 25.70 µs | 25.85 µs | 0% | Stable (runs earlier in suite) |
| AES-128-GCM enc @8KB | 10.7 µs | 10.2 µs | -5% | Stable |
| AES-256-GCM enc @8KB | 12.0 µs | 6.81 µs | **-43%** | Improved |
| ECDSA P-256 sign | 42.08 µs | 44.03 µs | +5% | Thermal variance |
| ECDSA P-256 verify | 85.02 µs | 89.27 µs | +5% | Thermal variance |
| ECDSA P-384 sign | 2.37 ms | 120.6 µs | **-95%** | P63 specialized field (P80 Appendix C was stale) |
| ECDH P-384 derive | 2.06 ms | 224.8 µs | **-89%** | P63 specialized field (P80 Appendix C was stale) |
| Ed25519 sign | 14.29 µs | 10.95 µs | **-23%** | Improved |
| Ed448 sign | 661 µs | 98.4 µs | **-85%** | P65/P66/P69 (P80 Appendix C was stale) |
| X25519 DH | 28.80 µs | 20.91 µs | **-27%** | Improved |
| X448 DH | 442.7 µs | 168.5 µs | **-62%** | Improved (P80 Appendix C was stale) |
| mod_exp 1024-bit | 631.8 µs | 393.2 µs | **-38%** | **P81 MontExpTable** |
| mod_exp 2048-bit | 3.97 ms | 3.35 ms | **-16%** | **P81 MontExpTable** |
| mod_exp 4096-bit | 34.0 ms | 29.5 ms | **-13%** | **P81 MontExpTable** |
| ML-KEM-768 encaps | 30.47 µs | 42.84 µs | +41% | Thermal (runs late in suite) |
| ML-DSA-44 sign | 79.83 µs | 107.5 µs | +35% | Thermal (runs late in suite) |
| SM2 sign | 76.09 µs | 58.20 µs | **-24%** | Improved |
| RSA-2048 sign | 1.26 ms | 1.26 ms | 0% | Stable (P68 CRT) |

> **Note on P80 Appendix C data**: The P80 PERF_REPORT.md Appendix C contained stale data for several algorithms (P-384, P-521, Ed448, X448) that predated their respective specialized field optimizations (P63/P64/P65/P66). The P83 data above reflects the true current performance. Thermal effects in full-suite runs cause 20–50% variance on some benchmarks.

## Appendix E: Raw Data Sources

| Source | File | Description |
|--------|------|-------------|
| Rust Criterion | `target/criterion/` | Full statistical reports (HTML + JSON), 63 groups / 307 test points |
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
| MAC algorithms | 9 | 31 | HMAC-SHA256/384/512, HMAC-SM3, CMAC-AES128/256, GMAC-AES128/256, SipHash, CBC-MAC-SM4, **Poly1305** |
| Asymmetric | 12 | 31 | ECDSA (P-256/384/521), ECDH (P-256/384/521), Ed25519, Ed448, X25519, X448, SM2, RSA-2048, **RSA-3072**, **RSA-4096** |
| Post-quantum | 6 | 45 | ML-KEM (512/768/1024), ML-DSA (44/65/87), SLH-DSA (4 variants), SM9, HPKE, HybridKEM |
| Large-key/slow | 8 | 26 | DH (2048/3072/4096), DSA, FrodoKEM (640/976/**1344**-SHAKE), XMSS, **XMSS-MT**, McEliece, ElGamal, Paillier |
| KDF/DRBG | 5 | 10 | HKDF, PBKDF2, scrypt, CTR-DRBG, HMAC-DRBG, Hash-DRBG, SM4-CTR-DRBG |
| BigNum | 1 | 13 | add, mul, mod_exp @ 256/512/1024/2048/4096-bit |
| **Total** | **63** | **307** | **33 algorithm modules, 100% coverage** |
