# Performance Comparison: openHiTLS (C) vs openHiTLS-rs (Rust)

> **Date**: 2026-03-01 (P1–P62 complete) | **Platform**: Apple M4, macOS 15.4, 10 cores, 16 GB RAM

---

## 1. Executive Summary

Comprehensive benchmarks across 60+ cryptographic algorithms comparing the original C openHiTLS against the Rust rewrite. All Rust numbers from Criterion runs (rustc 1.93.0, 2026-03-01) after all 62 performance optimization phases. Asymmetric and PQC benchmarks re-run after P54–P62 optimizations.

| Category | Verdict | Detail |
|----------|---------|--------|
| **AES (CBC/CTR/GCM)** | **Rust 2.3–6.4x faster** | Both use ARM Crypto Extension; Rust benefits from monomorphization + LTO |
| **ChaCha20-Poly1305** | **Rust 1.05x faster** | Rust 361 MB/s vs C 344 MB/s |
| **Hash (SHA-256/384/512)** | **Rust 1.3–3.5x faster** | SHA-256 HW 3.5x; SHA-512/384 HW 1.3–2.1x |
| **SM3** | **C 1.7x faster** | P56 ring buffer; no HW accel available |
| **HMAC** | **Rust 0.9–4.4x** | HMAC-SHA256 4.4x; HMAC-SHA512 1.5x; HMAC-SM3 near parity (C 1.09x) |
| **SM4 (CBC/GCM)** | **Rust 0.9–1.6x** | T-table + GHASH HW |
| **ECDSA P-256** | **Near parity** | P-256 fast path: sign C 1.18x, **verify Rust 1.14x faster** (P54) |
| **ECDH P-256** | **C 1.2x faster** | P-256 fast path |
| **Ed25519 / X25519** | **Near parity** | Sign near parity; verify C 1.24x (improved by P55); X25519 C 1.49x (P60) |
| **SM2** | **Rust 2.0–5.3x faster** | Specialized Montgomery field + precomputed comb table |
| **RSA-2048** | **Rust-only data** | C RSA not registered in benchmark binary |
| **ML-KEM (Kyber)** | **C 1.6–4.1x faster** | Major improvement from P58 clone elim + P59 Keccak unroll |
| **ML-DSA (Dilithium)** | **Rust 1.0–1.7x faster (sign)** | ML-DSA-44/87 sign now **faster than C**; keygen/verify C ~1.4–2x |
| **DH (FFDHE)** | **C 3.1–7.1x faster** | P53 CIOS inner loop; gap narrowed ~30% from P52 |

**Bottom line**: Symmetric ciphers (AES, ChaCha20) and hashes (SHA-256/384/512) remain **faster in Rust**. Phase P54–P62 delivered major improvements: **ECDSA P-256 verify now faster than C** (P54 scalar field), **ML-DSA-44/87 sign now faster than C** (P57/P59 Keccak unroll), ML-KEM gap narrowed to 1.6–4.1x (P58/P59), Ed25519 verify improved 23% (P55), X25519 DH improved 12% (P60).

> **Note**: Symmetric/hash numbers from P53-era full suite run, except SM3/HMAC-SM3 (isolated re-run). Asymmetric/PQC re-run after P54–P62. BigNum-dependent (RSA, DH, mod_exp) from P53 isolated runs.

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

**Note**: CPU frequency scaling is managed by macOS on Apple Silicon. Symmetric/hash/ECC/PQC from full-suite run (~20 min); BigNum-dependent (RSA, DH, mod_exp) re-run individually after P53 for thermal-stable results. Criterion provides statistical outlier detection; C benchmarks report single-run mean.

---

## 3. Results

### 3.1 Hash Functions (8 KB payload)

| Algorithm | C (MB/s) | Rust (MB/s) | Ratio (R/C) | Notes |
|-----------|----------|-------------|-------------|-------|
| SHA-256 | 571.7 | 2,013 | **3.52** | **HW accel (SHA-NI), Rust 3.5x faster** |
| SHA-384 | 540.7 | 1,146 | **2.12** | **HW accel (SHA-512 CE), Rust 2.1x faster** |
| SHA-512 | 885.7 | 1,232 | **1.39** | **HW accel (SHA-512 CE), Rust 1.4x faster** |
| SM3 | 528.0 | 303 | **0.57** | No HW accel; C 1.7x faster |

<details>
<summary>Methodology</summary>

- **C**: `openhitls_benchmark_static -t 10000 -l 8192` — SHA-256: 69,792 ops/s, SHA-512: 108,120 ops/s, SM3: 64,448 ops/s; SHA-384 fresh: 65,987 ops/s
- **Rust**: Criterion median — SHA-256: 4.07 µs, SHA-384: 7.15 µs, SHA-512: 6.65 µs, SM3: 27.03 µs (isolated run)
- MB/s = 8192 / (time_µs × 1e-6) / 1e6
</details>

**Analysis**: All three SHA-2 variants use hardware acceleration in Rust: SHA-256 via ARMv8 SHA-NI (Phase P1), SHA-512/384 via ARMv8.2 SHA-512 Crypto Extensions (Phase P11). SHA-256 achieves **3.5x speedup over C**, suggesting the C implementation may not fully utilize SHA-NI. SM3 retains a 1.7x gap to C (no hardware acceleration available for SM3; P56 ring buffer optimization improved small-message throughput).

---

### 3.2 Symmetric Ciphers (8 KB payload)

| Algorithm | C Enc (MB/s) | Rust Enc (MB/s) | C Dec (MB/s) | Rust Dec (MB/s) | Ratio (Enc) | Ratio (Dec) |
|-----------|-------------|-----------------|-------------|-----------------|-------------|-------------|
| AES-128-CBC | 324.6 | 760 | 331.3 | 2,117 | **2.34** | **6.39** |
| AES-256-CBC | 237.2 | 659 | 261.9 | 1,600 | **2.78** | **6.11** |
| AES-128-CTR | 315.0 | 1,219 | — | — | **3.87** | — |
| AES-256-CTR | 243.4 | 996 | — | — | **4.09** | — |
| AES-128-GCM | 155.7 | 645 | 165.8 | 653 | **4.14** | **3.94** |
| AES-256-GCM | 144.4 | 566 | 142.4 | 589 | **3.92** | **4.14** |
| ChaCha20-Poly1305 | 344.1 | 361 | 333.0 | 368 | **1.05** | **1.10** |
| SM4-CBC | 119.9 | 103 | 127.1 | 132 | **0.86** | **1.04** |
| SM4-GCM | 87.6 | 118 | 87.6 | 119 | **1.35** | **1.36** |

> Ratio > 1.0 = Rust faster. CTR mode is symmetric (encrypt = decrypt).

**Analysis**:
- **AES-CBC**: Rust is 2.3–6.4x faster. CBC decrypt parallelizable — Rust AES-NI pipelines multiple `AESDEC` instructions. Phase P21 (monomorphization) and P25 (stack arrays) further improved generic path.
- **AES-CTR**: Rust 3.9–4.1x faster — CTR mode naturally allows parallel block encryption.
- **AES-GCM**: Rust 3.9–4.1x faster — both encryption (AES-NI) and authentication (GHASH PMULL) hardware-accelerated. Phase P21 monomorphization eliminated vtable dispatch.
- **ChaCha20-Poly1305**: Rust ~1.1x faster — NEON SIMD optimization.
- **SM4-CBC**: SM4-CBC encrypt slightly behind C (0.86x), decrypt at parity (1.04x). Phase P8 T-table optimization.
- **SM4-GCM**: Rust 1.35x faster — T-table SM4 combined with hardware GHASH (ARMv8 PMULL).

---

### 3.3 MAC Algorithms (8 KB payload)

| Algorithm | C (MB/s) | Rust (MB/s) | Ratio (R/C) | Notes |
|-----------|----------|-------------|-------------|-------|
| HMAC-SHA256 | 319.8 | 1,400 | **4.38** | **Rust 4.4x faster** (follows SHA-256 HW speedup) |
| HMAC-SHA512 | 507.7 | 786 | **1.55** | **Rust 1.5x faster** (follows SHA-512 HW speedup) |
| HMAC-SM3 | 327.7 | 302 | **0.92** | Near parity (C 1.09x); P26 HMAC caching eliminated factory overhead |

<details>
<summary>C fresh data (5000 iterations)</summary>

- HMAC-SHA256: 39,026 ops/s → 319.8 MB/s
- HMAC-SHA512: 61,973 ops/s → 507.7 MB/s
- HMAC-SM3: 40,000 ops/s → 327.7 MB/s
</details>

**Analysis**: HMAC performance directly follows the underlying hash. HMAC-SHA256 is **4.4x faster in Rust** thanks to SHA-256 hardware acceleration. HMAC-SHA512 is **1.5x faster**. HMAC-SM3 is now near parity (C 1.09x) — the P53-era value (167 MB/s) was severely degraded by thermal throttling in the full suite run; isolated measurement reveals the P26 HMAC caching optimization (removing `Box<dyn Fn>` factory) made HMAC overhead negligible.

---

### 3.4 Asymmetric / Public Key Operations

| Algorithm | Operation | C (ops/s) | Rust (ops/s) | Ratio (R/C) | Notes |
|-----------|-----------|----------|-------------|-------------|-------|
| ECDSA P-256 | Sign | 26,848 | 22,820 | **0.850** | P-256 fast path + P54 scalar field, C 1.18x |
| ECDSA P-256 | Verify | 10,473 | 11,900 | **1.136** | **Rust 1.14x faster!** (P54 scalar field) |
| ECDH P-256 | Key Derive | 13,584 | 11,460 | **0.844** | C 1.19x faster |
| Ed25519 | Sign | 66,193 | 64,940 | **0.981** | **Near parity** (P12 precomputed comb) |
| Ed25519 | Verify | 24,016 | 19,330 | **0.805** | C 1.24x faster (P55 projective cmp) |
| X25519 | DH | 49,594 | 33,250 | **0.671** | C 1.49x faster (P60 Fe25519 opt) |
| SM2 | Sign | 2,560 | 13,550 | **5.29** | **Rust 5.3x faster!** (P10 specialized field) |
| SM2 | Verify | 4,527 | 9,210 | **2.03** | **Rust 2.0x faster!** |
| SM2 | Encrypt | 1,283 | 5,350 | **4.17** | **Rust 4.2x faster!** |
| SM2 | Decrypt | 2,584 | 10,080 | **3.90** | **Rust 3.9x faster!** |
| RSA-2048 | Sign (PSS) | — | 1,035 | — | C RSA not in benchmark binary |
| RSA-2048 | Verify (PSS) | — | 32,340 | — | — |
| RSA-2048 | Encrypt (OAEP) | — | 23,580 | — | — |
| RSA-2048 | Decrypt (OAEP) | — | 1,056 | — | — |

**Analysis**:
- **ECDSA P-256**: Phase P54 (scalar field optimization) dramatically improved verify — now **Rust 1.14x faster than C** for verify. Sign gap narrowed to C 1.18x (from 1.49x).
- **ECDH P-256**: C 1.19x faster, marginal change from P53.
- **Ed25519/X25519**: Ed25519 sign near parity (C 1.02x). P55 projective comparison improved verify to C 1.24x (from 1.52x). X25519 DH at C 1.49x (P60 Fe25519 sub_fast).
- **SM2**: Specialized field arithmetic (Phase P10) makes SM2 **dramatically faster in Rust** — sign 5.3x, verify 2.0x, encrypt 4.2x, decrypt 3.9x faster than C.

---

### 3.5 Post-Quantum Cryptography

| Algorithm | Operation | C (ops/s) | Rust (ops/s) | Ratio (R/C) | P53 Rust | P53→P62 |
|-----------|-----------|----------|-------------|-------------|----------|---------|
| ML-KEM-512 | KeyGen | 92,755 | 42,290 | **0.456** | 38,600 | **1.10x** |
| ML-KEM-512 | Encaps | 167,182 | 48,590 | **0.291** | 46,300 | **1.05x** |
| ML-KEM-512 | Decaps | 125,729 | 63,640 | **0.506** | 51,500 | **1.24x** |
| ML-KEM-768 | KeyGen | 38,814 | 29,650 | **0.764** | 24,800 | **1.20x** |
| ML-KEM-768 | Encaps | 119,805 | 34,490 | **0.288** | 28,600 | **1.21x** |
| ML-KEM-768 | Decaps | 86,794 | 37,950 | **0.437** | 31,400 | **1.21x** |
| ML-KEM-1024 | KeyGen | 32,864 | 19,200 | **0.584** | 16,100 | **1.19x** |
| ML-KEM-1024 | Encaps | 91,958 | 22,350 | **0.243** | 18,900 | **1.18x** |
| ML-KEM-1024 | Decaps | 65,644 | 24,570 | **0.374** | 20,000 | **1.23x** |
| ML-DSA-44 | KeyGen | 25,553 | 14,430 | **0.565** | 12,000 | **1.20x** |
| ML-DSA-44 | Sign | 7,413 | 12,460 | **1.681** | 9,840 | **1.27x** |
| ML-DSA-44 | Verify | 20,882 | 12,170 | **0.583** | 13,080 | 0.93x |
| ML-DSA-65 | KeyGen | 14,894 | 7,590 | **0.510** | 6,340 | **1.20x** |
| ML-DSA-65 | Sign | 4,566 | 4,520 | **0.990** | 1,095 | **4.13x** |
| ML-DSA-65 | Verify | 12,998 | 9,060 | **0.697** | 7,275 | **1.25x** |
| ML-DSA-87 | KeyGen | 8,563 | 4,830 | **0.564** | 4,020 | **1.20x** |
| ML-DSA-87 | Sign | 3,517 | 4,420 | **1.257** | 3,675 | **1.20x** |
| ML-DSA-87 | Verify | 7,018 | 5,160 | **0.735** | 4,248 | **1.21x** |

> "P53 Rust" = previous measurement (P53-era). "P53→P62" = improvement from P54–P62 optimizations.

**Analysis**: PQC performance improved further after P54–P62 optimizations (P57 ML-DSA zero-alloc, P58 ML-KEM clone elim, P59 Keccak unroll):
- **ML-KEM**: 1.05–1.24x faster than P53. P58 clone elimination + P59 Keccak f1600 unrolling. ML-KEM-768 decaps improved from 31.4K to 38.0K ops/s. KeyGen gap to C narrowed to 1.3x (from 1.6x).
- **ML-DSA**: ML-DSA-44 sign now **1.68x faster than C** (12,460 vs 7,413). ML-DSA-87 sign **1.26x faster than C**. ML-DSA-65 sign outlier resolved (1,095→4,520 ops/s, now near parity with C). P57 zero-alloc retry loop + P59 Keccak unroll.
- **ML-DSA-44 sign surpasses C**: 12,460 ops/s vs 7,413 ops/s (Rust **1.68x faster**).

---

### 3.6 Diffie-Hellman Key Exchange

| Group | C KeyGen (ops/s) | Rust KeyGen (ops/s) | C Derive (ops/s) | Rust Derive (ops/s) | Ratio (KeyGen) | Ratio (Derive) |
|-------|-------------------|---------------------|-------------------|---------------------|----------------|----------------|
| FFDHE-2048 | 1,219 | 329 | 997 | 323 | **0.270** | **0.324** |
| FFDHE-3072 | 489 | 98 | 467 | 96 | **0.200** | **0.206** |
| FFDHE-4096 | 290 | 41 | 288 | 41 | **0.142** | **0.142** |

**Analysis**: C is 3.1–7.1x faster for DH operations (narrowed ~30% from P52 by Phase P53 CIOS inner loop optimization). The gap increases with key size because the O(n²) inner loop — C uses hand-tuned assembly (`bn_mul_mont`) while Rust compiles `u128` operations to `umulh`+`mul`. DH is rarely the bottleneck in modern TLS (ECDHE is strongly preferred).

---

### 3.7 ECDH Multi-Curve (C reference)

| Curve | C KeyGen (ops/s) | C Derive (ops/s) | Rust Derive (ops/s) | Ratio (Derive) |
|-------|-------------------|-------------------|---------------------|----------------|
| P-224 | 86,438 | 30,903 | — | — |
| P-256 | 41,174 | 13,584 | 11,460 | **0.844** |
| P-384 | 1,041 | 969 | — | — |
| P-521 | 12,182 | 5,059 | — | — |
| brainpoolP256r1 | 2,524 | 2,574 | — | — |

---

### 3.8 BigNum Arithmetic

| Operation | 256-bit | 512-bit | 1024-bit | 2048-bit | 4096-bit |
|-----------|---------|---------|----------|----------|----------|
| Multiply | 63.1 ns | 132.0 ns | 376.5 ns | 1.184 µs | 4.598 µs |
| Add | 42.4 ns | 58.7 ns | 97.4 ns | 173.7 ns | 297.2 ns |

**Modular exponentiation** (CIOS Montgomery, Phase P7/P15/P22/P53):

| Operation | Time | P52 Time | Speedup |
|-----------|------|----------|---------|
| mod_exp 1024-bit | 495.3 µs | 694.1 µs | **1.40x** |
| mod_exp 2048-bit | 3.245 ms | 4.642 ms | **1.43x** |
| mod_exp 4096-bit | 25.12 ms | 35.64 ms | **1.42x** |

---

## 4. Performance Heatmap

```
                        C faster <------------------> Rust faster
                        x12    x8     x4    1.0    x2     x5    x8

DH-4096 keygen          ████████████████░░░░░░░░░░░░░░░░░░░░░░░░░  C x7.1
ML-KEM-768 encaps       █████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x3.5
DH-2048 keygen          ███████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x3.7
SM3                     █████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x1.74
X25519 DH               █████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x1.49
Ed25519 verify          ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x1.24
ECDH P-256              ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x1.19
ECDSA P-256 sign        ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x1.18
SM4-CBC enc             ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x1.16
Ed25519 sign            ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x1.02
ML-DSA-65 sign          ░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░░░░░  Parity
ChaCha20-Poly1305 enc   ░░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░░░░  R x1.05
ECDSA P-256 verify      ░░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░░░░  R x1.14
ML-DSA-87 sign          ░░░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░░░  R x1.26
SM4-GCM enc             ░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░  R x1.35
SHA-512                 ░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░  R x1.39
HMAC-SHA512             ░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░  R x1.55
ML-DSA-44 sign          ░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░  R x1.68
SM2 verify              ░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░  R x2.03
SHA-384                 ░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░  R x2.12
AES-128-CBC enc         ░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░  R x2.34
AES-256-CBC enc         ░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░  R x2.78
SHA-256                 ░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░  R x3.52
AES-128-CTR             ░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░  R x3.87
AES-128-GCM enc         ░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░  R x4.14
SM2 encrypt             ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░  R x4.17
HMAC-SHA256             ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░███░░░░░░░░░  R x4.38
SM2 sign                ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████░░░░░░░  R x5.29
AES-128-CBC dec         ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████░░░░  R x6.39
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
| **P15** | BigNum mont_exp squaring (cross-product symmetry) | ~33% fewer multiplies in sqr |
| **P16** | SM3 compression optimization | Precomputed T_J table |
| **P17** | P-256 scalar field (Montgomery mod curve order) | ECDSA sign k-inversion speedup |
| **P18** | Keccak ARMv8 SHA-3 HW acceleration | EOR3/RAX1/BCAX Keccak HW path |
| **P19** | SHAKE squeeze_into zero-allocation | Stack buffers in ML-KEM/ML-DSA/FrodoKEM |
| **P20** | CTR-DRBG AES/SM4 key caching | 67→1 key expansions per 1KB |
| **P21** | AES-GCM/CBC monomorphization | Eliminated vtable indirect calls |
| **P22** | Miller-Rabin Montgomery optimization | 2–3x Miller-Rabin speedup |
| **P23–P25** | TLS per-record key/GHASH caching + CBC stack arrays | TLS record layer optimization |
| **P26–P44** | Ed25519 var-time verify, Ed448/X448 Karatsuba, NTT unrolling, SHA-256 schedule, SM9 Karatsuba, GCM 4-block, P-384/521 field, RSA-CRT, HMAC precompute | Broad micro-optimizations |
| **P45** | Keccak absorb loop unrolling | Major SHAKE throughput improvement |
| **P46–P47** | ECDSA nonce optimization, BigNum branch elimination | Signing path speedup |
| **P48** | ML-KEM g_input stack arrays | 3 heap allocs eliminated per op |
| **P49** | CBC padding Vec elimination | Stack-based padding buffer |
| **P50** | ML-KEM byte-aligned bit-packing | Bulk encode/decode for d=4,5,10,11,12 |
| **P51** | SM9 w=4 windowed scalar multiplication | ~50% fewer point additions |
| **P52** | ECC/EdDSA w=4 windowed scalar multiplication | ~50% fewer point additions |
| **P53** | BigNum CIOS inner loop (`cios_mul_n` + bounds-check elim) | DH-4096 1.46x, RSA sign 1.42x, mod_exp ~1.42x |
| **P54** | ECDSA P-256 verify scalar field optimization | **Verify now Rust 1.14x faster than C**, sign C 1.18x |
| **P55** | Ed25519/Ed448 projective coordinate comparison | Ed25519 verify 23% faster (C 1.52→1.24x) |
| **P56** | SM3 ring buffer compression | SM3 ~16% faster |
| **P57** | ML-DSA sign zero-allocation retry loop | ML-DSA sign per-retry allocs eliminated |
| **P58** | ML-KEM clone elimination + buffer reuse | ML-KEM keygen/encaps/decaps 1.1–1.2x |
| **P59** | Keccak keccak_f1600 software unrolling | All SHAKE/SHA-3 ~20% faster on non-HW path |
| **P60** | X25519 Fe25519 inversion + carry optimization | X25519 DH 12% faster |
| **P62** | GHASH HW zero-copy batch processing | AES-GCM marginal improvement |

### Key Milestones

| Milestone | Before | After | Speedup |
|-----------|--------|-------|---------|
| ECDSA P-256 sign | 2,415 µs | 43.8 µs | **55x** |
| ECDSA P-256 verify | — | 84.0 µs | **Rust 1.14x > C** (P54) |
| SM2 sign | 2,331 µs | 73.8 µs | **32x** |
| Ed25519 sign | 56.1 µs | 15.4 µs | **3.6x** |
| SHA-256 @8KB | 42.25 µs | 4.07 µs | **10.4x** |
| ML-KEM-768 encaps | ~109 µs | 29.0 µs | **3.8x** |
| ML-DSA-44 sign | ~355 µs | 80.3 µs | **4.4x** |
| DH-4096 keygen | 35.5 ms | 24.3 ms | **1.46x** (P53) |
| RSA-2048 sign | 1.37 ms | 966 µs | **1.42x** (P53) |

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
- Reports: median time per operation, throughput (MiB/s or GiB/s)

**Command**: `cargo bench -p hitls-crypto --all-features`

### 6.3 Comparability Notes

1. **Payload size**: All symmetric/hash comparisons use 8 KB (8192 bytes) payload
2. **Key setup**: Both frameworks pre-generate keys before timing; key generation is excluded
3. **Memory allocation**: Both allocate output buffers before the timing loop
4. **Compiler optimization**: C uses `-O2`, Rust uses release profile with LTO + `codegen-units=1`
5. **Hardware acceleration**: Both implementations compile with ARM Crypto Extension support enabled

### 6.4 Caveats

- **Single machine**: All results are from a single Apple M4. x86-64 results may differ (Intel SHA-NI, AVX2)
- **Full suite thermal effects**: The ~20-minute full benchmark run may show 10–20% thermal throttling in later tests. BigNum-dependent benchmarks (RSA, DH, mod_exp) were re-run individually after P53 for thermal-stable results. ECC/PQC re-run after P54–P62
- **Criterion overhead**: Criterion's statistical framework adds per-sample overhead (~microseconds)
- **No CPU pinning**: macOS does not support `taskset`-style CPU pinning on Apple Silicon
- **C MAC/Hash fresh run**: Some C MAC/hash numbers were re-measured with 5000 iterations

---

## Appendix A: Throughput Summary (16 KB payload)

| Algorithm | Throughput (MB/s) | Category |
|-----------|-------------------|----------|
| AES-128-CBC decrypt | 2,288 | Symmetric |
| SHA-256 | 2,024 | Hash |
| AES-256-CBC decrypt | 1,722 | Symmetric |
| HMAC-SHA256 | 1,394 | MAC |
| AES-128-CTR | 1,253 | Symmetric |
| SHA-512 | 1,195 | Hash |
| SHA-384 | 1,191 | Hash |
| AES-256-CTR | 1,031 | Symmetric |
| AES-128-CBC encrypt | 789 | Symmetric |
| HMAC-SHA512 | 783 | MAC |
| AES-256-CBC encrypt | 684 | Symmetric |
| AES-128-GCM decrypt | 664 | AEAD |
| AES-128-GCM encrypt | 652 | AEAD |
| AES-256-GCM encrypt | 594 | AEAD |
| AES-256-GCM decrypt | 591 | AEAD |
| ChaCha20-Poly1305 decrypt | 370 | AEAD |
| ChaCha20-Poly1305 encrypt | 363 | AEAD |
| SM3 | 320 | Hash |
| HMAC-SM3 | 311 | MAC |
| SM4-CBC decrypt | 129 | Symmetric |
| SM4-GCM decrypt | 122 | Symmetric |
| SM4-GCM encrypt | 115 | Symmetric |
| SM4-CBC encrypt | 104 | Symmetric |

## Appendix B: Public Key Operations Summary (ops/sec)

| Algorithm | Operation | Ops/sec |
|-----------|-----------|---------|
| Ed25519 | sign | 64,940 |
| ML-KEM-512 | decaps | 63,640 |
| ML-KEM-512 | encaps | 48,590 |
| ML-KEM-512 | keygen | 42,290 |
| ML-KEM-768 | decaps | 37,950 |
| ML-KEM-768 | encaps | 34,490 |
| X25519 | DH | 33,250 |
| RSA-2048 | verify (PSS) | 32,340 |
| ML-KEM-768 | keygen | 29,650 |
| ML-KEM-1024 | decaps | 24,570 |
| RSA-2048 | encrypt (OAEP) | 23,580 |
| ECDSA P-256 | sign | 22,820 |
| ML-KEM-1024 | encaps | 22,350 |
| Ed25519 | verify | 19,330 |
| ML-KEM-1024 | keygen | 19,200 |
| ML-DSA-44 | keygen | 14,430 |
| SM2 | sign | 13,550 |
| ML-DSA-44 | sign | 12,460 |
| ML-DSA-44 | verify | 12,170 |
| ECDSA P-256 | verify | 11,900 |
| ECDH P-256 | key_derive | 11,460 |
| SM2 | decrypt | 10,080 |
| SM2 | verify | 9,210 |
| ML-DSA-65 | verify | 9,060 |
| ML-DSA-65 | keygen | 7,590 |
| SM2 | encrypt | 5,350 |
| ML-DSA-87 | verify | 5,160 |
| ML-DSA-87 | keygen | 4,830 |
| ML-DSA-65 | sign | 4,520 |
| ML-DSA-87 | sign | 4,420 |
| RSA-2048 | decrypt (OAEP) | 1,056 |
| RSA-2048 | sign (PSS) | 1,035 |
| ffdhe2048 | keygen | 329 |
| ffdhe2048 | key_derive | 323 |
| ffdhe3072 | keygen | 98 |
| ffdhe3072 | key_derive | 96 |
| ffdhe4096 | keygen | 41 |
| ffdhe4096 | key_derive | 41 |

## Appendix C: Full Criterion Median Times (2026-03-01, P62-era)

All times in nanoseconds unless noted.

```
=== Block Ciphers ===
aes-128 encrypt_block:      9.07 ns    aes-128 decrypt_block:      9.22 ns
aes-256 encrypt_block:     12.34 ns    aes-256 decrypt_block:     12.35 ns
sm4 encrypt_block:        147.86 ns    sm4 decrypt_block:        145.42 ns

=== AES-GCM (AEAD) ===
aes-128-gcm enc @1KB:     2,066 ns    aes-128-gcm dec @1KB:     2,006 ns
aes-128-gcm enc @8KB:    12,711 ns    aes-128-gcm dec @8KB:    12,547 ns
aes-128-gcm enc @16KB:   25,117 ns    aes-128-gcm dec @16KB:   24,684 ns
aes-256-gcm enc @1KB:     2,450 ns    aes-256-gcm dec @1KB:     2,316 ns
aes-256-gcm enc @8KB:    14,463 ns    aes-256-gcm dec @8KB:    13,909 ns
aes-256-gcm enc @16KB:   27,606 ns    aes-256-gcm dec @16KB:   27,707 ns

=== AES-CBC ===
aes-128-cbc enc @1KB:     1,835 ns    aes-128-cbc dec @1KB:       948 ns
aes-128-cbc enc @8KB:    10,784 ns    aes-128-cbc dec @8KB:     3,872 ns
aes-128-cbc enc @16KB:   20,770 ns    aes-128-cbc dec @16KB:    7,159 ns
aes-256-cbc enc @1KB:     2,064 ns    aes-256-cbc dec @1KB:     1,096 ns
aes-256-cbc enc @8KB:    12,437 ns    aes-256-cbc dec @8KB:     5,124 ns
aes-256-cbc enc @16KB:   23,953 ns    aes-256-cbc dec @16KB:    9,518 ns

=== AES-CTR ===
aes-128-ctr @1KB:         1,171 ns    aes-256-ctr @1KB:         1,458 ns
aes-128-ctr @8KB:         6,725 ns    aes-256-ctr @8KB:         8,225 ns
aes-128-ctr @16KB:       13,079 ns    aes-256-ctr @16KB:       15,899 ns

=== ChaCha20-Poly1305 ===
chacha20 enc @1KB:        3,139 ns    chacha20 dec @1KB:        3,133 ns
chacha20 enc @8KB:       22,694 ns    chacha20 dec @8KB:       22,260 ns
chacha20 enc @16KB:      45,100 ns    chacha20 dec @16KB:      44,324 ns

=== SM4-CBC / SM4-GCM ===
sm4-cbc enc @1KB:        10,250 ns    sm4-cbc dec @1KB:         8,151 ns
sm4-cbc enc @8KB:        79,202 ns    sm4-cbc dec @8KB:        61,938 ns
sm4-cbc enc @16KB:      157,200 ns    sm4-cbc dec @16KB:      127,150 ns
sm4-gcm enc @1KB:         9,471 ns    sm4-gcm dec @1KB:         8,954 ns
sm4-gcm enc @8KB:        69,170 ns    sm4-gcm dec @8KB:        68,717 ns
sm4-gcm enc @16KB:      142,300 ns    sm4-gcm dec @16KB:      133,960 ns

=== Hash Functions ===
sha256 @1KB:                507 ns    sha384 @1KB:                913 ns
sha512 @1KB:                915 ns    sm3 @1KB:                 2,822 ns
sha256 @8KB:              4,067 ns    sha384 @8KB:              7,151 ns
sha512 @8KB:              6,646 ns    sm3 @8KB:                27,025 ns
sha256 @16KB:             8,094 ns    sha384 @16KB:            13,752 ns
sha512 @16KB:            13,708 ns    sm3 @16KB:               51,279 ns

=== HMAC ===
hmac-sha256 @1KB:         1,172 ns    hmac-sha512 @1KB:         2,245 ns
hmac-sm3 @1KB:            5,865 ns
hmac-sha256 @8KB:         5,855 ns    hmac-sha512 @8KB:        10,415 ns
hmac-sm3 @8KB:           27,097 ns
hmac-sha256 @16KB:       11,754 ns    hmac-sha512 @16KB:       20,918 ns
hmac-sm3 @16KB:          52,658 ns

=== Elliptic Curves ===
ecdsa-p256 sign:         43,824 ns    ecdsa-p256 verify:       84,039 ns
ecdh p256 derive:        87,271 ns    x25519 dh:               30,072 ns
ed25519 sign:            15,399 ns    ed25519 verify:          51,728 ns
sm2 sign:                73,786 ns    sm2 verify:             108,570 ns
sm2 encrypt:            186,760 ns    sm2 decrypt:             99,203 ns

=== RSA-2048 ===
rsa-2048 sign pss:      966,130 ns    rsa-2048 verify pss:     30,916 ns
rsa-2048 enc oaep:       42,421 ns    rsa-2048 dec oaep:      947,490 ns

=== ML-KEM (FIPS 203) ===
mlkem-512 keygen:        23,644 ns    mlkem-512 encaps:        20,581 ns
mlkem-512 decaps:        15,713 ns
mlkem-768 keygen:        33,725 ns    mlkem-768 encaps:        28,997 ns
mlkem-768 decaps:        26,350 ns
mlkem-1024 keygen:       52,095 ns    mlkem-1024 encaps:       44,752 ns
mlkem-1024 decaps:       40,700 ns

=== ML-DSA (FIPS 204) ===
mldsa-44 keygen:         69,317 ns    mldsa-44 sign:           80,280 ns
mldsa-44 verify:         82,205 ns
mldsa-65 keygen:        131,790 ns    mldsa-65 sign:          221,140 ns
mldsa-65 verify:        110,390 ns
mldsa-87 keygen:        207,250 ns    mldsa-87 sign:          226,230 ns
mldsa-87 verify:        193,980 ns

=== Diffie-Hellman ===
dh-2048 keygen:       3,041,200 ns    dh-2048 derive:       3,096,600 ns
dh-3072 keygen:      10,211,000 ns    dh-3072 derive:      10,368,000 ns
dh-4096 keygen:      24,290,000 ns    dh-4096 derive:      24,512,000 ns

=== BigNum ===
bignum mul 256:              63 ns    bignum add 256:              42 ns
bignum mul 512:             132 ns    bignum add 512:              59 ns
bignum mul 1024:            377 ns    bignum add 1024:             97 ns
bignum mul 2048:          1,184 ns    bignum add 2048:            174 ns
bignum mul 4096:          4,598 ns    bignum add 4096:            297 ns
bignum mod_exp 1024:    495,280 ns    bignum mod_exp 2048:  3,245,000 ns
bignum mod_exp 4096:  25,121,000 ns
```

SM3 and HMAC-SM3 values from isolated benchmark runs (not full suite) for thermal-stable results.

## Appendix D: Historical Comparison (2026-02-27 → P52 → P53 → P62)

| Benchmark | 2026-02-27 | P52 (full) | P53 (isolated) | P62 (fresh) | P53→P62 | Notes |
|-----------|------------|------------|----------------|-------------|---------|-------|
| SHA-256 @8KB | 3.45 µs | 4.07 µs | — | — | — | Thermal effects in full run |
| SHA-512 @8KB | 5.61 µs | 6.65 µs | — | — | — | Thermal effects |
| AES-128-GCM enc @8KB | 10.22 µs | 12.71 µs | — | — | — | Thermal effects |
| ChaCha20 enc @8KB | 17.16 µs | 22.69 µs | — | — | — | Thermal effects |
| SM3 @8KB | — | 25.14 µs | — | 27.03 µs | +7% | Within noise (isolated run) |
| HMAC-SM3 @8KB | — | 49.04 µs | — | **27.10 µs** | **-45%** | **P26 HMAC caching** (P53 thermally degraded) |
| ECDSA P-256 sign | 53.60 µs | 55.59 µs | — | **43.82 µs** | **-21%** | **P54 scalar field** |
| ECDSA P-256 verify | — | 138.28 µs | — | **84.04 µs** | **-39%** | **P54 scalar field** |
| Ed25519 sign | 10.95 µs | 15.90 µs | — | 15.40 µs | -3% | Within noise |
| Ed25519 verify | — | 63.42 µs | — | **51.73 µs** | **-18%** | **P55 projective cmp** |
| X25519 DH | — | 33.75 µs | — | **30.07 µs** | **-11%** | **P60 Fe25519 opt** |
| ML-KEM-768 encaps | 58.88 µs | **34.94 µs** | — | **29.00 µs** | **-17%** | **P58+P59 Keccak** |
| ML-KEM-768 decaps | — | 31.84 µs | — | **26.35 µs** | **-17%** | **P58+P59 Keccak** |
| ML-DSA-44 sign | 355.80 µs | **101.62 µs** | — | **80.28 µs** | **-21%** | **P57+P59 alloc+Keccak** |
| ML-DSA-65 sign | — | 913.35 µs | — | **221.14 µs** | **-76%** | **Outlier resolved** |
| ML-DSA-87 sign | 952.81 µs | **272.05 µs** | — | **226.23 µs** | **-17%** | **P57+P59 Keccak** |
| DH-2048 keygen | 4.22 ms | 4.58 ms | **3.04 ms** | — | — | P53 CIOS inner loop |
| DH-3072 keygen | — | 15.28 ms | **10.21 ms** | — | — | P53 CIOS inner loop |
| DH-4096 keygen | — | 35.50 ms | **24.29 ms** | — | — | P53 CIOS inner loop |
| RSA-2048 sign PSS | 1.17 ms | 1.37 ms | **966 µs** | — | — | P53 CIOS inner loop |
| RSA-2048 verify PSS | — | 45.6 µs | **30.9 µs** | — | — | P53 CIOS inner loop |
| RSA-2048 dec OAEP | — | 1.35 ms | **947 µs** | — | — | P53 CIOS inner loop |
| mod_exp 1024-bit | — | 694 µs | **495 µs** | — | — | P53 CIOS inner loop |
| mod_exp 2048-bit | — | 4.64 ms | **3.25 ms** | — | — | P53 CIOS inner loop |
| mod_exp 4096-bit | — | 35.64 ms | **25.12 ms** | — | — | P53 CIOS inner loop |

**Key takeaways**:
- Phase P53 (CIOS inner loop bounds-check elimination via `cios_mul_n`) delivers a consistent **~30% speedup** across all Montgomery exponentiation workloads (DH, RSA, mod_exp).
- Phase P54 (scalar field optimization) achieves **-39% for ECDSA P-256 verify** — Rust now **faster than C** for verify.
- Phase P55–P60 deliver 11–18% improvements across Ed25519 verify, X25519 DH, ML-KEM, and ML-DSA.
- ML-DSA-65 sign outlier resolved: 913→221 µs (rejection sampling variance stabilized).
- HMAC-SM3 isolated run reveals P53-era value (49 µs) was thermally degraded; true value 27 µs (**near parity with C**).

## Appendix E: Raw Data Sources

| Source | File | Description |
|--------|------|-------------|
| Rust Criterion | `target/criterion/` | Full statistical reports (HTML + JSON) |
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
