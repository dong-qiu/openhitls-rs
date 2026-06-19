# openHiTLS-rs — Quality Assurance Report

> **Re-audited 2026-06-19.** This revision replaces the archived T86 (2026-03-04)
> snapshot with a current assessment. The single largest quality change since
> then is the **C→Rust byte-exact test-migration flywheel** (§2), which both
> grew the suite from ~4,000 → **~9,350 tests** and caught a string of *real
> production crypto bugs* that the prior self-test-only suite could not.
> `DEV_LOG.md` remains the authoritative per-phase record.

---

## 1. Current quality safety net

### 1.1 Defense layers (8-layer model)

| # | Layer | Mechanism | Status |
|---|-------|-----------|--------|
| 1 | Type safety | `#![forbid(unsafe_code)]` in **5 crates** (types, utils, pki, auth, tls); unsafe isolated to `hitls-crypto`/`hitls-bignum` (SIMD only) | enforced at compile |
| 2 | Unit tests | ~9,350 inline `#[test]` across 9 crates | 100% pass |
| 3 | **Byte-exact KAT migration** | 65 `migrated_*.rs` files, **4,412** functions vs independent C/NIST/RFC vectors | the flywheel (§2) |
| 4 | Property testing | 54 `proptest!` blocks across 6 crates (+ shrunk regression seeds) | broad |
| 5 | Fuzzing | 68 cargo-fuzz targets, 447 corpus seeds; smoke on PR, full weekly | continuous |
| 6 | Protocol conformance | tlsfuzzer harness (TLS 1.3/1.2 wire, mTLS, PSK, cert-matrix) + transcript-mutation E2E (145 rogue-server tests) | continuous |
| 7 | Side-channel | `subtle::ConstantTimeEq`, `ct_verify`, 16 dudect timing tests, workspace timing-oracle audit (T84) | audited |
| 8 | Supply chain / CI | cargo-vet, cargo-deny, SBOM/SLSA, Miri, Kani, ASan, careful, mutants, semver-checks | 43 CI jobs |

### 1.2 Per-crate test distribution (measured 2026-06-19, `cargo test -p <crate> --all-features`)

| Crate | Tests | Ignored | % | Focus |
|-------|------:|--------:|:---:|-------|
| hitls-crypto | 4,523 | 25 | 48.4% | 48 algorithm modules + HW accel + specialized fields + **4,000+ byte-exact KATs** + proptest + HW↔SW cross-validation + timing + zeroize + FIPS PCT/KAT |
| hitls-tls | 1,720 | 0 | 18.4% | TLS 1.3/1.2/DTLS/TLCP/DTLCP handshake/record/extensions, mTLS, PSK, renegotiation, sync+async, security levels, CRL, PHA |
| hitls-pki | 1,683 | 0 | 18.0% | X.509, PKCS#8/12, CMS, CRL builder+ext, codec KATs, hostname verification, proptest |
| hitls-integration | 542 | 13 | 5.8% | Cross-crate TCP/loopback, OpenSSL interop, transcript-mutation, DTLS resilience, resumption, callbacks |
| hitls-cli | 310 | 7 | 3.3% | 18 commands, s_client/s_server, speed, prime/kdf, edge cases |
| hitls-bignum | 325 | 1 | 3.5% | Montgomery, Miller-Rabin, prime gen, modular/constant-time, proptest |
| hitls-auth | 131 | 0 | 1.4% | HOTP/TOTP, SPAKE2+ (RFC 9383), Privacy Pass (RFC 9474), proptest |
| hitls-utils | 90 | 0 | 1.0% | ASN.1, Base64, PEM, OID, proptest roundtrips |
| hitls-types | 26 | 0 | 0.3% | Enums, error types |
| **Total** | **~9,350** | **46** | 100% | |

> The distribution shifted markedly from the T86 snapshot (crypto 1,466 → 4,523;
> pki 438 → 1,683): the growth is overwhelmingly **byte-exact KAT migration**,
> not padding — every added test checks output against an independent oracle.

### 1.3 CI/CD pipeline

43 jobs across 5 workflow files. Hard gates (aggregate `CI Gate` status check):
format, clippy `-D warnings`, per-crate + feature-combo tests (nextest), MSRV
1.75, cross-compile (i686), WASM, docs, conventional-commits, supply-chain
(cargo-vet/deny), unused-deps. Advisory/scheduled: Miri, Kani, ASan, TSan,
cargo-careful, cargo-mutants, cargo-semver-checks, llvm-cov, fuzz smoke (sharded)
+ weekly deep fuzz, tlsfuzzer, reproducible-build, SBOM/provenance. PR/push
wall-clock optimised ~84 min → ~10 min.

### 1.4 Standard compliance coverage

Wycheproof + NIST CAVP/ACVP + RFC + GM/T vectors. Vector corpora under
`tests/vectors/` (wycheproof, certcheck, chain, cms, crl, csr, pkcs12,
c-asn1-fixtures). FIPS/CMVP: 7 KATs, 3 PCTs, integrity check, SP 800-90B entropy
health.

---

## 2. The C→Rust migration flywheel — the dominant quality mechanism

The defining quality advance since T86 is **byte-exact differential testing**
against the original C implementation's SDV vectors (and NIST/RFC vectors). The
`xtask migrate-c-tests` tool consumes C `.data` files and emits Rust `#[test]`
functions that assert **byte-for-byte equality** with the reference output.

**Why this matters more than the raw count.** A byte-exact KAT against an
*independent* oracle **cannot false-pass**: a wrong implementation that is merely
*self-consistent* (encrypt→decrypt round-trips, sign→verify passes) sails through
unit tests but fails a byte-exact KAT. This converted the test suite from
"does it agree with itself" to "does it agree with the standard," and in doing so
**surfaced real production bugs that had survived all prior testing**:

| Bug (production crypto) | How it hid | Caught by |
|-------------------------|-----------|-----------|
| SLH-DSA wrong domain-separation | self-consistent sign/verify | FIPS 205 KAT (I129) |
| CTR-DRBG-df derivation | round-tripped | NIST KAT (I131) |
| ASN.1 encoder edge cases | parsed its own output | byte-exact DER (I133) |
| ML-DSA packing | self-consistent | FIPS 204 KAT (I137) |
| CBC-MAC | self-consistent | KAT (I144) |
| FrodoKEM / McEliece decaps | encaps↔decaps agreed | byte-exact (I145/I160) |
| **XMSS PRF_KEYGEN** (RFC 8702 §6.4) | verify never calls keygen path | byte-exact `PK.root` (I146) |
| **SPAKE2+** non-RFC key schedule | both ends used same wrong KDF | RFC 9383 vectors (I161) |
| **Privacy Pass** non-RFC blind-RSA | self-consistent blinding | RFC 9474 vectors (I162) |
| 3× ASN.1 codec hardening (strict-DER, SM2, RFC 8410) | lenient round-trips | byte-exact codec (I167–I169) |

This is the strongest signal in the report: **the suite is not just large, it is
adversarial against the implementation's own assumptions.** Coverage spans Phase
A–F + J–M (SHA-2/HMAC/CMAC/AES/Curve25519/DSA/DH/SM4/SM2/HPKE/SLH-DSA/XMSS/SM9/
ML-KEM/ML-DSA + PKI codecs + auth), with a `--check` CI drift gate and a
documented N/A exemption list (`docs/c-test-na-list.md`).

---

## 3. Deficiency history (D1–D35) — all closed; verification posture

The T86 audit tracked 35 deficiencies (D1–D35). **All are closed or
documented-N/A**; the table below is the historical summary (full per-D detail in
the git history of this file / DEV_LOG). They are retained as an audit trail, not
an open backlog.

| Severity at finding | Examples | Resolution |
|---------------------|----------|------------|
| Critical | D1 0-RTT replay (T9), D12 timing infra (T49), D13 TLS conn unit tests (T45/46) | closed |
| High | D4 DTLS loss, D5 TLCP dual-cert, D14 proptest scope, D16 HW↔SW cross-val (T47), D27 Miri unsafe coverage | closed/mostly |
| Medium/Low | D6 proptest, D7 coverage metrics, D9/D11 semantic fuzz, D17 zeroize runtime, D18 feature combos, D26 bench regression, D32 semver, D33 mutation | closed |
| False positives | D34 Mutex `.unwrap()` (T86), D35 `panic!` SLH-DSA params (T83) | closed as FP |

**Panic-free / unsafe posture (re-confirmed 2026-06-19).** Unsafe code is
compile-time forbidden in 5 crates and isolated to `hitls-crypto` (253 sites) +
`hitls-bignum` (24), all SIMD/intrinsics with `// SAFETY:` rationale. The
"zero attacker-reachable production panic" posture was established by the T83/T86
audits; it is **not** enforced by a `clippy::unwrap_used` lint (that would emit
~2,000 false positives against the 8,000+ legitimate test-code `unwrap()`s).
Instead it is enforced ongoing by the **pre-push AI-review CRITICAL rule**, which
blocks any new `unwrap()`/`expect()`/`panic!` on attacker-controlled input in
library code. This is a deliberate, documented trade-off, not a gap.

---

## 4. Current open items (honest assessment)

These are *known* and tracked, not regressions:

| Item | Status | Note |
|------|--------|------|
| **Async TLS 1.2 coverage** | **closed 2026-06-19 (T295)** | was 59.7% → 75.7% line; cipher matrix + renegotiation + large-payload added |
| CLI subprocess-only coverage | by design | `s_client` 38% / `s_server` 49% line coverage *as instrumented* — they are exercised by subprocess integration + tlsfuzzer, which don't show in `llvm-cov` |
| TLS 1.2 state-machine branches | growable | `connection12/{server,client}.rs` 68–71% — next coverage target after T295 |
| MSRV 1.75 dependency debt | held by policy | getrandom 0.4 / clap 4.6+ / proptest 1.9+ pinned to avoid MSRV 1.85 (PR #259 closed); raising MSRV is a separate decision |
| Performance gaps (SM3, Keccak/SHAKE, DH modexp) | tracked in `PERF_REPORT.md` | *performance*, not correctness/security — see the 2026-06-19 re-benchmark |
| C-data-defective vectors | documented N/A | SM4-HCTR(4)/GCM-decrypt(3) rows excluded in `c-test-na-list.md` |

The test-strategy posture for the sampled layers (TLS/DTLS state machines) is
made explicit and auditable in `docs/tls-test-coverage-contract.md` — sampling
there is a documented *strategy*, not an omission.

---

## 5. Overall quality score (re-rated 2026-06-19)

| Dimension | Score | Evidence |
|-----------|:-----:|----------|
| Static analysis | 10/10 | zero clippy warnings (`-D warnings`), 5 crates forbid-unsafe, MSRV CI |
| Unit + differential test coverage | **10/10** | ~9,350 tests incl. 4,412 **byte-exact** KATs against independent oracles |
| Differential-bug detection | **10/10** | flywheel caught 10+ real production bugs self-tests missed (§2) |
| Fuzz coverage | 9/10 | 68 targets, 447 corpus, PR smoke + weekly deep |
| Property testing | 9/10 | 54 proptest blocks, 6 crates, shrunk regression seeds |
| Protocol conformance | 9.5/10 | tlsfuzzer (TLS 1.3/1.2/mTLS/PSK) + 145 transcript-mutation E2E |
| CI/CD automation | 9.5/10 | 43 jobs: nextest, Miri, Kani, ASan, mutants, semver, vet, ~10 min gate |
| Standard vectors | 10/10 | Wycheproof + NIST + RFC + GM/T |
| Side-channel defense | 9/10 | 16 dudect tests, subtle, ct_verify, workspace timing-oracle audit (T84) |
| Code quality (panic-free) | 10/10 | 0 attacker-reachable production panic (T83/T86 audit + AI-review gate) |
| **Overall** | **~9.6/10** | **Production-grade; differential-testing posture is the standout strength** |

---

## 6. Methodology & reproduce

```bash
# test counts (per-crate, all targets incl. migrated KATs)
cargo test -p <crate> --all-features 2>&1 | grep "test result"
# fuzz targets / proptest / unsafe sites
ls fuzz/fuzz_targets/*.rs | wc -l ; grep -rho "proptest!" crates/*/src crates/*/tests | wc -l
grep -rn "unsafe" crates/<crate>/src | grep -v "forbid\|SAFETY"
# coverage
cargo llvm-cov -p <crate> --all-features --summary-only
```

**Caveats.** Test counts are a 2026-06-19 snapshot (they grow every phase;
DEV_LOG is authoritative). CLI tools are covered by subprocess tests invisible to
`llvm-cov`. The "0 production panic" claim is an audited posture enforced by AI
review, not a lint. The deficiency map D1–D35 is historical; current open items
are in §4.
