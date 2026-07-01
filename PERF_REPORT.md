# Performance Comparison: openHiTLS (C) vs openHiTLS-rs (Rust)

> **Re-benchmarked 2026-06-19** on Apple M4 (Darwin 25.5.0). This revision
> **supersedes** the 2026-03-05 snapshot and **materially corrects its
> headline conclusions** after auditing how the C reference was actually built.
> All numbers below are from fresh, *isolated* per-group runs (not a single
> 40-minute full-suite sweep), which removes most of the thermal throttling
> that depressed the prior revision's figures.
>
> **Amended 2026-06-30** with a post-baseline optimization pass (P95–P97): the
> baseline tables are the untouched 2026-06-19 snapshot; new measurements are
> called out in-line as "post-baseline" (§0, §4.3, §5, §7.1).

---

## 0. TL;DR — the one thing that changes everything

The previous report led with "**Rust 2–8× faster**" on AES/SHA/GCM. That headline
is **misleading**, and this revision retires it. Binary inspection proves the C
reference as built on this machine runs **software-only crypto — it contains
zero ARM crypto-extension instructions** (`sha256h`, `aese`, `pmull`, …). So
those large symmetric/hash wins are **hardware-vs-software**, not a language or
implementation-quality result.

Read the comparison in **two tiers**:

| Tier | What | Honest verdict |
|------|------|----------------|
| **Tier 1 — unfair** | AES, SHA-2, GHASH/GCM, HMAC-SHA2, CMAC, GMAC | Rust uses ARMv8 Crypto Extensions; the C build doesn't. Rust "wins" 1.8–9×, but this measures *HW engagement*, not Rust. **Not a language comparison.** |
| **Tier 2 — apples-to-apples** | Asymmetric, PQC, SM3, ChaCha20, SM4 (no crypto-ext on *either* side) | **Genuinely mixed.** Rust wins where the rewrite added specialized algorithms (SM2 **8.9×**, Ed25519 **1.9×**, P-384 field **3.8×**); **C wins** on Keccak-bound PQC (ML-KEM up to **3.3×**), BigNum-bound DH (up to **7.6×**), and even plain **SM3 (1.4×)**. |

**Bottom line:** when hardware is taken out of the equation, the two codebases
are *comparable*, each winning specific primitives based on which one was
optimized harder. Rust's real, defensible advantages are (a) it actually engages
the CPU's crypto hardware, and (b) its specialized elliptic-curve/SM2 field
arithmetic. Its real *deficits* are Keccak/SHAKE throughput (PQC) and
hand-tuned big-number modular exponentiation (DH/RSA-class).

> **Post-baseline update (P95–P97, 2026-06-30).** The Keccak/SHAKE deficit above
> was substantially closed by **P97**, which *removed* the ARM SHA-3 Crypto-Extension
> Keccak path after profiling showed it was a **2.6× pessimization** on Apple
> Silicon (GPR↔NEON shuttling every round). ML-KEM-768 decaps is now ≈parity with
> C; encaps roughly halved the gap. See the "Post-baseline measurements" note in
> §4.3 and the P95–P97 rows in §7. The baseline tables below are the untouched
> 2026-06-19 snapshot.

---

## 1. Critical caveat: the C baseline runs software crypto (read first)

This is the linchpin of the whole comparison, so it is evidenced rather than
asserted.

**Evidence 1 — the binary contains no crypto-extension instructions.**
```
$ otool -tV testcode/benchmark/openhitls_benchmark_static \
    | grep -icE 'sha256h|sha256su|aese|aesmc|pmull'
0
$ nm testcode/benchmark/openhitls_benchmark_static \
    | grep -iE 'armv8|sha256_block|aes_v8|ghash.*v8|crypt_arm'
(no hardware paths — only generic C symbols)
```
The C library *ships* ARM assembly (`crypto/sha2/src/asm/sha2_256_armv8.S`,
`.arch armv8-a+crypto`), but it is ELF/GAS-syntax (`.hidden`, `.extern`, no
leading underscores) and the macOS/CMake build did not assemble it into the
Mach-O binary — so every hash/cipher fell back to the `noasm_*.c` software path.

**Evidence 2 — the throughput curve has the unmistakable shape of software.**
| Tell | Software signature | Measured (C) | HW would show |
|------|--------------------|--------------|----------------|
| SHA-256 vs SHA-512 | SHA-512 *faster* (fewer rounds/byte on 64-bit) | SHA-256 **586** < SHA-512 **903** MB/s | SHA-256 ≫ SHA-512 (SHA-NI) |
| GCM vs CBC | GCM *slower* (software GHASH is costly) | AES-256-GCM **186** < AES-256-CBC **311** MB/s | GCM ≈/> CBC (PMULL) |
| Absolute SHA-256 | ~0.5–0.6 GB/s | **586 MB/s** | ~2–3 GB/s on M4 |

Rust's SHA-256 hits **2,775 MB/s** — exactly the M4 SHA-NI figure — confirming
Rust is on the hardware path and C is not.

**Implication.** A *fair* AES/SHA comparison would require rebuilding openHiTLS
with its ARM asm enabled (a non-trivial port: the `.S` files need Mach-O/clang
adaptation). Until then, **Tier 1 ratios must be read as "Rust-with-HW vs
C-without-HW", and Tier 2 is where the languages actually compete.**

---

## 2. Test environment

| Item | Specification |
|------|---------------|
| **CPU** | Apple M4 (`Mac16,12`, ARM64, AES + SHA2 + SHA512 Crypto Extensions) |
| **OS** | macOS (Darwin 25.5.0, arm64) |
| **C compiler / build** | Apple Clang, CMake Release, static `libhitls_crypto.a` — **software paths only (no asm)** |
| **Rust** | rustc stable (aarch64-apple-darwin), `--release`, LTO, `codegen-units=1`, ARM Crypto Extensions enabled |
| **Rust harness** | Criterion 0.5, per-group isolated runs, `sample_size 15–20`, 1 s warm-up + 2 s measure |
| **C harness** | `openhitls_benchmark_static -a <ctx> -l 8192 -t <N>` (`clock_gettime`, single-run mean) |
| **Payload** | 8 KiB (8192 B) for symmetric/hash/MAC throughput |

Caveats unchanged from prior revisions: single machine; Criterion adds per-sample
overhead; C reports single-run mean (no CIs); no CPU pinning on Apple Silicon.
The C `RsaBenchCtx` is declared but **not registered** in `g_benchs[]`, and DSA/
ElGamal C demos use toy parameters — so those have no usable C number (see §6/§8).

---

## 3. Tier 1 — symmetric / hash / MAC (Rust HW vs C software)

> ⚠️ **These ratios are not a language comparison.** They quantify the cost of
> the C build shipping without hardware acceleration. Numbers are @8 KiB.

| Algorithm | C software (MB/s) | Rust HW (MB/s) | R/C | Hardware Rust uses |
|-----------|------------------:|---------------:|:---:|--------------------|
| SHA-256 | 586 | **2,775** | 4.74× | ARMv8 SHA-NI |
| SHA-384 | 903 | **1,696** | 1.88× | ARMv8.2 SHA-512 CE |
| SHA-512 | 903 | **1,699** | 1.88× | ARMv8.2 SHA-512 CE |
| AES-128-CBC enc | 412 | **1,079** | 2.62× | AES-NI |
| AES-128-CBC dec | 473 | **4,244** | 8.97× | AES-NI (4-block pipeline, P72) |
| AES-256-CBC enc | 311 | **910** | 2.93× | AES-NI |
| AES-256-CBC dec | 339 | **2,954** | 8.71× | AES-NI |
| AES-128-CTR | 432 | **1,786** | 4.13× | AES-NI |
| AES-128-GCM enc | 219 | **1,621** | 7.40× | AES-NI + PMULL (P73) |
| AES-256-GCM enc | 186 | **1,558** | 8.38× | AES-NI + PMULL |
| AES-256-GCM dec | 189 | **1,601** | 8.47× | AES-NI + PMULL |
| HMAC-SHA256 | 567 | **2,625** | 4.63× | SHA-NI |
| HMAC-SHA512 | 852 | **1,553** | 1.82× | SHA-512 CE |
| CMAC-AES128 | 394 | **1,322** | 3.36× | AES-NI |
| GMAC-AES128 | 666 | **1,385** | 2.08× | PMULL |

**Reading it correctly:** the *only* defensible Tier-1 claim is "**Rust engages
the CPU crypto hardware that this C build leaves on the table.**" CBC-decrypt's
~9× is the most inflated — it stacks AES-NI *and* the 4-block parallel pipeline
(P72) against scalar software. If the C library were rebuilt with its ARM asm,
most of these would collapse toward parity (both would be HW-bound on the same
silicon). Treat Tier 1 as a statement about *deployment configuration*, not the
Rust port's merit.

---

## 4. Tier 2 — apples-to-apples (the real comparison)

Neither side uses crypto-extension hardware here — both run scalar/SIMD software.
**This is where Rust vs C is actually decided.** Throughput in MB/s (symmetric)
or ops/s (asymmetric).

### 4.1 Symmetric primitives with no dedicated HW

| Algorithm | C (sw) | Rust (sw) | Verdict | Why |
|-----------|-------:|----------:|---------|-----|
| **SM3** (MB/s) | 535 | 373 | **C 1.43×** | Rust SM3 message-expansion still trails C's hand-rolled compression (P82 regression never fully recovered). |
| **HMAC-SM3** (MB/s) | 519 | 361 | **C 1.44×** | Follows SM3. |
| **SM4-CBC enc** (MB/s) | 163 | 154 | ~parity (C 1.06×) | Both use compile-time T-tables; essentially tied. |
| **SM4-GCM enc** (MB/s) | 134 | 180 | **Rust 1.34×** | Rust still gets PMULL for the GHASH half (SM4 itself is software both sides). |
| **ChaCha20-Poly1305 enc** (MB/s) | 433 | 832 | **Rust 1.92×** | NEON ChaCha (P76) + Poly1305 r² batch (P75) — a *genuine* Rust SIMD win, no crypto-ext involved. |

> The SM3 result is the cleanest "all else equal" data point in the suite —
> identical algorithm, no hardware on either side — and **C wins by 44%**. The
> prior report blamed thermal throttling; this isolated re-run shows the gap is
> real. ChaCha20 is the mirror image: a genuine Rust win from hand-vectorized
> SIMD. Verdict: *no inherent language advantage either way — it's whoever
> optimized that primitive harder.*

### 4.2 Elliptic-curve & SM2 (software both sides)

| Operation | C (ops/s) | Rust (ops/s) | Verdict | Driver |
|-----------|----------:|-------------:|---------|--------|
| ECDSA-P256 sign | 30,190 | 26,629 | **C 1.13×** | C's scalar inversion edge |
| ECDSA-P256 verify | 13,834 | 13,768 | parity | — |
| ECDH-P256 derive | 17,706 | 17,727 | parity | — |
| ECDH-P384 derive | 1,150 | **4,327** | **Rust 3.76×** | P63 specialized Montgomery field |
| ECDH-P521 derive | 5,838 | 3,415 | **C 1.71×** | C's tuned reduction still ahead |
| Ed25519 sign | 57,247 | **111,263** | **Rust 1.94×** | P12 precomputed comb table |
| Ed25519 verify | 20,535 | **34,044** | **Rust 1.66×** | P55 projective comparison |
| X25519 DH | 43,708 | **58,784** | **Rust 1.34×** | P60 Fe25519 opts |
| **SM2 sign** | 2,493 | **22,314** | **Rust 8.95×** | P10 specialized field + comb table |
| **SM2 verify** | 4,515 | **14,633** | **Rust 3.24×** | " |
| **SM2 decrypt** | 2,622 | **16,747** | **Rust 6.39×** | " |

**The genuine Rust story lives here.** Where the rewrite invested in
algorithm-specific field arithmetic (SM2, Ed25519/Curve25519, P-384), it is
materially faster than the generic C bignum path — SM2 is a near-9× rout. Where
it didn't (P-256 base case, P-521), it lands at parity or slightly behind C.
This is a *real* engineering result, independent of hardware.

### 4.3 Post-quantum & Diffie-Hellman (software both sides)

| Operation | C (ops/s) | Rust (ops/s) | Verdict | Bottleneck |
|-----------|----------:|-------------:|---------|-----------|
| ML-KEM-768 encaps | 108,899 | 41,452 | **C 2.63×** | Keccak/SHAKE throughput |
| ML-KEM-768 decaps | 84,168 | 46,072 | **C 1.83×** | Keccak/SHAKE |
| ML-KEM-1024 encaps | 86,718 | 26,700 | **C 3.25×** | Keccak/SHAKE |
| ML-DSA-44 sign | 8,096 | 7,733 | parity | — |
| ML-DSA-65 sign | 5,097 | **7,843** | **Rust 1.54×** | NEON NTT (P9) pays off at 65 |
| ML-DSA-87 sign | 4,035 | 2,817 | **C 1.43×** | rejection-sampling/Keccak |
| ML-DSA-44 verify | 24,907 | 18,911 | **C 1.32×** | Keccak |
| DH FFDHE-2048 keygen | 1,219 | 322 | **C 3.79×** | `bn_mul_mont` modexp |
| DH FFDHE-3072 keygen | 489 | 93 | **C 5.26×** | modexp (gap grows with size) |
| DH FFDHE-4096 keygen | 290 | 38 | **C 7.63×** | modexp |

**Where C clearly wins.** Two themes: (1) **Keccak** — ML-KEM and most ML-DSA
ops are SHAKE-dominated, and C's Keccak permutation out-throughputs Rust's
despite P59 unrolling; this is the single biggest PQC gap. (2) **Big-number
modular exponentiation** — DH (and by extension RSA-class) leans on a tight
`bn_mul_mont` inner loop where C's hand-tuning beats Rust's CIOS, and the gap
*widens* with modulus size (3.8× → 7.6× from 2048→4096). Rust's P53/P67/P81 work
narrowed but did not close it.

> Practical note: DH's deficit rarely matters for TLS (ECDHE is preferred, and
> Rust's X25519/ECDH-P256 are at parity-or-better). ML-KEM's deficit is the one
> worth attention as PQC TLS adoption grows.

**Post-baseline measurements (P97, 2026-06-30, same M4).** After removing the
pessimizing ARM SHA-3 CE path (P97), ML-KEM-768 was re-measured against the C
figures above:

| Operation | C (ops/s) | Rust @baseline | Rust after P97 | Speedup | C gap: was → now |
|-----------|----------:|---------------:|---------------:|:-------:|------------------|
| ML-KEM-768 encaps | 108,899 | 41,452 | **57,618** | 1.39× | 2.63× → **1.89×** |
| ML-KEM-768 decaps | 84,168 | 46,072 | **76,197** | 1.65× | 1.83× → **1.10× (≈parity)** |

ML-KEM-512/1024 and ML-DSA were not individually re-measured but share the same
`keccak_f1600` permutation, so they benefit proportionally to their SHAKE share.
The `keccak-f1600` permutation itself went from ≈360 ns (ARM CE path) to ≈138 ns
(scalar) per call — a 2.6× primitive-level speedup that flows into every SHA-3 /
SHAKE consumer.

---

## 5. Root-cause summary — why each side wins what it wins

| Pattern | Winner | Cause |
|---------|--------|-------|
| AES / SHA-2 / GCM / HMAC-SHA2 / CMAC / GMAC | Rust (apparent) | **Rust engages ARM Crypto Extensions; the C build doesn't.** Remove this and most go to parity. |
| SM2, Ed25519/X25519, ECDH-P384 | **Rust (real)** | Specialized Montgomery/Mersenne field arithmetic + precomputed comb tables the C generic path lacks. |
| ChaCha20-Poly1305 | **Rust (real)** | Hand-vectorized NEON + Poly1305 r² batch; no crypto-ext on either side. |
| SM4 | parity | Both T-table software. |
| SM3 / HMAC-SM3 | **C** | C's compression loop is tighter; Rust's expansion has never recovered the P82 regression. |
| ECDSA-P256 sign, ECDH-P521 | **C** (slight) | C's tuned scalar reduction. |
| ML-KEM, ML-DSA-87, ML-DSA verify | **C, narrowed by P97** | Was Keccak/SHAKE-bound; P97 removed a 2.6× ARM-CE pessimization, taking ML-KEM-768 decaps to ≈parity and halving the encaps gap (§4.3 post-baseline note). Residual is C's tighter scalar Keccak. |
| DH (and RSA-class modexp) | **C** | Hand-tuned `bn_mul_mont`; gap grows with operand size. |

The honest one-liner: **neither language is intrinsically faster here.** Rust's
wins come from *what this rewrite chose to specialize* (curves, SM2, SIMD AEAD)
plus *using the hardware*; C's wins come from *mature hand-tuned scalar kernels*
(Keccak, bignum modexp) that the Rust port has not yet matched.

---

## 6. Rust-only capabilities (no usable C benchmark)

The C harness cannot benchmark these (RSA unregistered; the others use specialized
fields the C demo lacks), so there is no ratio — but they are functionally
complete and these are current isolated Rust figures (ops/s unless noted):

| Algorithm | KeyGen/Enc | Sign/Decaps | Verify/Encaps | Note |
|-----------|-----------|-------------|----------------|------|
| RSA-2048 (PSS/OAEP) | — | sign 795 | verify 24,634 | P68 CRT Montgomery (carried from prior snapshot; C RSA unbenchmarkable) |
| RSA-3072 | — | sign 170 | verify 7,703 | " |
| RSA-4096 | — | sign 116 | verify 5,587 | " |
| ECDSA-P384 | — | sign ~8,300 | verify ~3,500 | P63 specialized field |
| ECDSA-P521 | — | sign ~6,700 | verify ~2,100 | P64 Mersenne field |
| Ed448 / X448 | — | Ed448 sign ~10,200 | X448 DH ~5,900 | P65/P66/P69 |
| HybridKEM X25519-ML-KEM-768 | keygen 21,889 | decaps 25,870 | encaps 16,945 | fresh 2026-06-19 |
| SLH-DSA SHA2-128f | — | sign ~49 | verify ~917 | P78 hypertree opt |
| FrodoKEM / McEliece / XMSS | benchmarked | — | — | see Appendix / DEV_LOG |

RSA and DH would, on the §4.3 evidence, follow the **C-favoured bignum-modexp**
pattern if a comparable C benchmark existed.

---

## 7. Optimization history (Phases P1–P97)

The Rust numbers reflect 90+ optimization phases. Highlights that drive the Tier-2
wins above (full per-phase detail in `DEV_LOG.md`):

| Phase | Optimization | Impact on this report |
|-------|-------------|------------------------|
| P1, P11 | SHA-2 / SHA-512 Crypto-Extension paths | Tier-1 hash throughput |
| P10 | SM2 specialized field + comb table | **SM2 8.9× (§4.2)** |
| P12, P55, P60 | Ed25519 comb table / projective / Fe25519 | **Ed25519 1.9× / X25519 (§4.2)** |
| P63, P64 | P-384 Montgomery / P-521 Mersenne fields | **ECDH-P384 3.8× (§4.2)** |
| P72, P73 | AES 4-block pipeline / GCM interleaved | Tier-1 AES-CBC-dec & GCM |
| P75, P76 | Poly1305 r² batch / ChaCha20 2-block | **ChaCha20 1.9× (§4.1)** |
| P9 | ML-DSA NEON NTT | **ML-DSA-65 sign 1.5× (§4.3)** |
| P53, P67, P81 | BigNum CIOS / fused squaring / DH tables | narrowed (not closed) DH gap |
| P59, P83 | Keccak unroll / ML-KEM SHAKE clone-fork | narrowed (not closed) ML-KEM gap |
| P84 | x86-64 VAES + VPCLMULQDQ GCM | (x86 parity; not measured here) |
| P94 | SHA-256 4-way multi-buffer batch API | batch-hash workloads |
| **P95** | TLS transcript incremental hasher (was O(msgs×transcript) replay → O(1) clone-finish) | TLS 1.3 handshake CPU (not in these primitive benches) |
| **P96** | AES CBC/ECB decrypt 4-block pipeline (inverse-cipher mirror of P72/P84) | **AES-CBC-dec 2.66× at the primitive level** (§7.1) |
| **P97** | Removed the ARM SHA-3 CE Keccak path — it was a 2.6× *pessimization* | **ML-KEM-768 encaps 1.39× / decaps 1.65× (§4.3)** |

### 7.1 Post-baseline optimization pass (P95–P97, 2026-06-30)

A targeted performance-audit pass after the 2026-06-19 baseline, measurement-first
(each candidate A/B-timed before landing; two were **reverted** when timing showed
no net win — an HMAC pad-state cache that traded recompression for allocation, and
a DH MontgomeryCtx reuse that measured 0.996–1.00× because the modexp dominates):

- **P95** — TLS `TranscriptHash::current_hash()` rebuilt a fresh hasher and
  replayed the whole message buffer on every call (~8-9×/handshake). Now keeps a
  live incremental digest and clone-finishes it. Not visible in these primitive
  benches (it's a TLS-layer win) but removes an O(msgs×transcript) cost per
  handshake.
- **P96** — the AES backends had `encrypt_4_blocks` but no `decrypt_4_blocks`, so
  CBC/ECB decrypt ran single-block, exposing `aesd`/`aesdec` latency. Adding the
  pipelined inverse path measured **2.66× on M4** (single-block 5139 → 4-block
  13648 MiB/s, AES-128). This lifts the §3 AES-CBC-dec figure further (the §3
  table is the pre-P96 baseline).
- **P97** — see §4.3 post-baseline note; the biggest post-baseline PQC win.

**Remaining open targets:** (1) **Keccak/SHAKE** — a *register-resident* SHA-3 CE
rewrite (25 lanes kept in NEON across all rounds, XAR for ρ) could beat the scalar
path P97 fell back to (P97 only removed the pessimizing shuttling version);
(2) **SM3** — recover the P82 expansion regression (C 1.4× ahead on equal footing);
(3) **BigNum modexp** — closing DH/RSA needs a `bn_mul_mont`-class inner loop.

---

## 8. Methodology, caveats, and how to reproduce

**Rust (per-group, isolated — avoids the thermal throttling that depressed the
2026-03-05 full-suite numbers):**
```
cargo bench -p hitls-crypto --all-features --bench crypto_bench -- \
  '<group-regex>' --sample-size 20 --warm-up-time 1 --measurement-time 2
# point estimates read from target/criterion/<group>/<bench>/<size>/new/estimates.json
```
Note bench IDs are hyphen-inconsistent: the hash group is `sha/sha256` (no
hyphen) while AES is `aes-gcm/aes-128-gcm_encrypt` — filter accordingly.

**C (software baseline):**
```
DYLD_LIBRARY_PATH=. ./openhitls_benchmark_static -a <ctx> -l 8192 -t <N>
#   ctx ∈ {md, cipher, mac, ecdsa, ecdh, ed25519, x25519, sm2, mldsa, mlkem, dh}
#   -a matches the *context* name, not the per-op name; MB/s = ops/s × 8192 / 1e6
```

**Caveats (this revision):**
1. **The headline caveat (§1): the C build is software-only.** Every Tier-1 ratio
   is HW-vs-software. A fair Tier-1 comparison needs openHiTLS rebuilt with its
   ARM asm assembled into the Mach-O binary (an asm port, not just a flag here).
2. **C single-run mean vs Rust statistical** — C has no confidence intervals;
   treat C numbers as ±10% (validated: this run's C figures reproduce the
   2026-03-05 figures within that band, e.g. SHA-256 586 vs 571, ECDSA-P256
   sign 30.2k vs 26.8k, ML-KEM-768 encaps 109k vs 120k).
3. **No C number** for RSA (unregistered in `g_benchs[]`), DSA/ElGamal (toy
   `p=23` demo parameters), or the specialized-field-only curves.
4. **Single machine / ARM64.** x86-64 (AVX2/VAES, P84) would shift Tier 1; the
   software-vs-software Tier 2 conclusions are the portable ones.
5. **Isolated runs reduce but don't eliminate** Apple-Silicon frequency
   management; slow ops (DH-4096, ML-DSA-87) have wider variance at
   `sample_size 15–20`.

---

## Appendix A — full fresh C software baseline (@8 KiB, 2026-06-19)

| Algorithm | ops/s | MB/s | | Algorithm | ops/s | MB/s |
|-----------|------:|-----:|---|-----------|------:|-----:|
| SHA-256 | 71,486 | 586 | | AES-128-GCM enc | 26,787 | 219 |
| SHA-384 | 110,223 | 903 | | AES-256-GCM enc | 22,643 | 186 |
| SHA-512 | 110,249 | 903 | | ChaCha20-Poly1305 | 52,809 | 433 |
| SHA-1 | 152,633 | 1,250 | | SM4-CBC enc | 19,902 | 163 |
| SHA3-256 | 79,913 | 655 | | SM4-GCM enc | 16,314 | 134 |
| SM3 | 65,352 | 535 | | HMAC-SHA256 | 69,159 | 567 |
| AES-128-CBC enc | 50,243 | 412 | | HMAC-SHA512 | 104,026 | 852 |
| AES-256-CBC enc | 37,937 | 311 | | HMAC-SM3 | 63,349 | 519 |
| AES-128-CTR | 52,752 | 432 | | CMAC-AES128 | 48,122 | 394 |
| AES-128-CBC dec | 57,759 | 473 | | GMAC-AES128 | 81,334 | 666 |

Asymmetric/PQC C (ops/s): ECDSA-P256 sign 30,190 / verify 13,834; ECDH-P256
derive 17,706, P384 1,150, P521 5,838; Ed25519 sign 57,247 / verify 20,535;
X25519 DH 43,708; SM2 sign 2,493 / verify 4,515 / enc 1,265 / dec 2,622;
ML-KEM-512/768/1024 encaps 105,785 / 108,899 / 86,718; ML-DSA-44/65/87 sign
8,096 / 5,097 / 4,035; DH FFDHE-2048/3072/4096 keygen 1,219 / 489 / 290.

## Appendix B — full fresh Rust baseline (@8 KiB, 2026-06-19)

Symmetric/hash/MAC (MB/s): SHA-256 2,775 / SHA-384 1,696 / SHA-512 1,699;
SM3 373; AES-128-CBC 1,079 enc / 4,244 dec; AES-256-CBC 910 / 2,954;
AES-128-CTR 1,786; AES-128-GCM 1,621 / 1,673; AES-256-GCM 1,558 / 1,601;
ChaCha20-Poly1305 832 / 839; SM4-CBC 154 / 212; SM4-GCM 180 / 179;
HMAC-SHA256 2,625; HMAC-SHA512 1,553; HMAC-SM3 361; CMAC-AES128 1,322;
GMAC-AES128 1,385.

Asymmetric/PQC (ops/s): ECDSA-P256 sign 26,629 / verify 13,768; ECDH-P256
17,727 / P384 4,327 / P521 3,415; Ed25519 sign 111,263 / verify 34,044;
X25519 DH 58,784; SM2 sign 22,314 / verify 14,633 / enc 8,011 / dec 16,747;
ML-KEM-512/768/1024 encaps 67,297 / 41,452 / 26,700; ML-DSA-44/65/87 sign
7,733 / 7,843 / 2,817; HybridKEM X25519-ML-KEM-768 encaps 16,945 / decaps
25,870; DH FFDHE-2048/3072/4096 keygen 322 / 93 / 38.
