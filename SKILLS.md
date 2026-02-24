# SKILLS.md — Claude Code Skills Index

This document lists all Claude Code skills available in the openHiTLS-rs project. Skills are invoked via `/skill-name [arguments]` in Claude Code.

## Skills Overview

| # | Skill | Command | Category | Description |
|---|-------|---------|----------|-------------|
| 1 | [check](#check) | `/check` | Build & CI | Full build-test-lint-format pipeline |
| 2 | [test](#test) | `/test [crate]` | Build & CI | Run workspace or crate tests |
| 3 | [lint](#lint) | `/lint` | Build & CI | Clippy + rustfmt checks |
| 4 | [bench](#bench) | `/bench [group]` | Performance | Run Criterion benchmarks |
| 5 | [profile](#profile) | `/profile [target]` | Performance | CPU/memory profiling with flamegraphs |
| 6 | [coverage](#coverage) | `/coverage [crate]` | Testing | Generate code coverage reports |
| 7 | [fuzz](#fuzz) | `/fuzz [target] [sec]` | Testing | Fuzz testing with cargo-fuzz |
| 8 | [miri](#miri) | `/miri [crate]` | Testing | Detect undefined behavior in unsafe code |
| 9 | [security-review](#security-review) | `/security-review [file]` | Security | Cryptographic security pattern review |
| 10 | [audit](#audit) | `/audit` | Security | Dependency vulnerability scanning |
| 11 | [vet](#vet) | `/vet` | Security | Third-party dependency trust verification |
| 12 | [doc](#doc) | `/doc [crate]` | Documentation | Build and verify rustdoc |
| 13 | [changelog](#changelog) | `/changelog [version]` | Documentation | Generate changelog from git history |
| 14 | [phase-docs](#phase-docs) | `/phase-docs <id> <title>` | Documentation | Update docs after completing a phase |
| 15 | [commit](#commit) | `/commit [message]` | Git & Release | Create conventional commit |
| 16 | [review-pr](#review-pr) | `/review-pr <pr>` | Git & Release | Review a pull request |
| 17 | [semver](#semver) | `/semver` | Git & Release | Check for semver-breaking changes |
| 18 | [msrv](#msrv) | `/msrv` | Compatibility | Verify MSRV (Rust 1.75) compliance |
| 19 | [cross](#cross) | `/cross [target]` | Compatibility | Cross-compile for different platforms |
| 20 | [bloat](#bloat) | `/bloat [crate]` | Optimization | Analyze binary size and dependency bloat |

---

## Skill Details

### check

**Command**: `/check`
**Category**: Build & CI
**File**: `.claude/skills/check/SKILL.md`

Runs the complete verification pipeline: build → test → clippy → format. Stops on the first failure and reports a summary table. Use before committing or after major changes.

**Steps**: `cargo build` → `cargo test` (expect 2585 passed, 40 ignored) → `clippy` (zero warnings) → `cargo fmt --check`

---

### test

**Command**: `/test [crate-name]`
**Category**: Build & CI
**File**: `.claude/skills/test/SKILL.md`

Runs tests for the entire workspace or a specific crate. Reports pass/fail/ignored counts and compares against expected values.

**Expected counts**: hitls-crypto 652, hitls-tls 1164, hitls-pki 349, hitls-bignum 49, hitls-utils 53, hitls-auth 33, hitls-cli 117, integration 125. **Total: 2585 tests, 40 ignored.**

---

### lint

**Command**: `/lint`
**Category**: Build & CI
**File**: `.claude/skills/lint/SKILL.md`

Runs clippy with `-D warnings` (zero warnings required) and `cargo fmt --check`. Reports clean status or lists all warnings and files needing formatting.

---

### bench

**Command**: `/bench [bench-group]`
**Category**: Performance
**File**: `.claude/skills/bench/SKILL.md`

Runs Criterion benchmarks for the crypto crate. Supports filtering by group name (sha2, aes_gcm, rsa, ecdsa, x25519, mlkem, etc.). Reports median times, throughput, and comparison with previous baselines.

**18 benchmark groups**: sha2, sha3, sm3, hmac, aes_gcm, aes_cbc, chacha20, sm4_cbc, sm4_gcm, rsa, ecdsa, ed25519, x25519, ecdh, dh, sm2, mlkem, mldsa.

---

### profile

**Command**: `/profile [target]`
**Category**: Performance
**File**: `.claude/skills/profile/SKILL.md`

Profiles CPU usage of benchmarks using flamegraph, samply, or Instruments. Generates flamegraph SVGs, identifies top hotspot functions, and suggests optimizations for crypto-specific bottlenecks (Montgomery multiplication, scalar multiplication, GHASH, etc.).

---

### coverage

**Command**: `/coverage [crate-name]`
**Category**: Testing
**File**: `.claude/skills/coverage/SKILL.md`

Generates code coverage reports using cargo-llvm-cov. Supports workspace or per-crate analysis, HTML report generation, and per-file line coverage breakdown. Targets: algorithm implementations >90%, TLS state machine >85%, PKI/CLI >75%.

---

### fuzz

**Command**: `/fuzz [target] [duration-seconds]`
**Category**: Testing
**File**: `.claude/skills/fuzz/SKILL.md`

Runs fuzz testing using cargo-fuzz with libFuzzer. 10 fuzz targets covering X.509, PKCS#8, PKCS#12, CMS, PEM, ASN.1, TLS handshake/record, BigNum, and DRBG. Reports execution stats, corpus growth, and any crashes found with triage steps.

---

### miri

**Command**: `/miri [crate-name]`
**Category**: Testing
**File**: `.claude/skills/miri/SKILL.md`

Runs Miri (MIR Interpreter) to detect undefined behavior in unsafe code. Focuses on `hitls-bignum` and `hitls-crypto` — the only crates with unsafe code. Detects out-of-bounds access, use-after-free, alignment issues, invalid values, and data races.

---

### security-review

**Command**: `/security-review [file-or-crate]`
**Category**: Security
**File**: `.claude/skills/security-review/SKILL.md`

Reviews code for cryptographic security patterns using an Explore agent. Checks: zeroize-on-drop for secrets, constant-time comparisons, unsafe code audit, no-panic in library code, proper RNG usage (getrandom not rand), and feature gate compliance. Reports findings with severity levels.

---

### audit

**Command**: `/audit`
**Category**: Security
**File**: `.claude/skills/audit/SKILL.md`

Runs cargo-audit to check all dependencies against the RustSec advisory database. Reports CVEs with severity, affected crate/version, and fix availability. Also checks for yanked crates.

---

### vet

**Command**: `/vet`
**Category**: Security
**File**: `.claude/skills/vet/SKILL.md`

Verifies third-party dependency trust using cargo-vet. Reports vetted vs unvetted dependencies, suggests audits, and prioritizes crypto-critical deps (subtle, zeroize, getrandom) and serialization deps (der, asn1, pem).

---

### doc

**Command**: `/doc [crate-name]`
**Category**: Documentation
**File**: `.claude/skills/doc/SKILL.md`

Builds rustdoc with warnings-as-errors. Reports missing documentation, broken links, and undocumented public items. Supports per-crate builds and browser opening.

---

### changelog

**Command**: `/changelog [version]`
**Category**: Documentation
**File**: `.claude/skills/changelog/SKILL.md`

Generates a changelog from git history in Keep a Changelog format. Categorizes commits by prefix (feat/fix/refactor/docs/test/chore/perf) and outputs Added/Fixed/Changed/Security sections.

---

### phase-docs

**Command**: `/phase-docs <phase-id> <phase-title>`
**Category**: Documentation
**File**: `.claude/skills/phase-docs/SKILL.md`

Updates all documentation files after completing a development phase: DEV_LOG.md, PROMPT_LOG.md, ARCH_LOG.md (for R-phases), CLAUDE.md status/counts, and README.md test counts. Follows project-specific heading and date conventions.

---

### commit

**Command**: `/commit [message]`
**Category**: Git & Release
**File**: `.claude/skills/commit/SKILL.md`

Creates a git commit following project conventions: analyzes changes, selects appropriate prefix (feat/fix/refactor/docs/test/chore), stages specific files (never `git add -A`), and appends Co-Authored-By trailer. Supports phase-based commit patterns.

---

### review-pr

**Command**: `/review-pr <pr-number-or-branch>`
**Category**: Git & Release
**File**: `.claude/skills/review-pr/SKILL.md`

Reviews a PR or branch diff using an Explore agent. Checks code quality (rustfmt, clippy, error handling, tests), security (zeroize, constant-time, unsafe, RNG), architecture (patterns, API consistency, dependencies), and documentation. Outputs findings table with severity and verdict.

---

### semver

**Command**: `/semver`
**Category**: Git & Release
**File**: `.claude/skills/semver/SKILL.md`

Checks for semver-incompatible API changes using cargo-semver-checks. Detects removed types/functions, changed signatures, and classifies changes as major/minor/patch. Essential before releases to prevent accidental breakage.

---

### msrv

**Command**: `/msrv`
**Category**: Compatibility
**File**: `.claude/skills/msrv/SKILL.md`

Verifies that the project builds and tests pass with the declared MSRV (Rust 1.75). Identifies APIs or syntax requiring newer Rust versions. Checks for common MSRV pitfalls (let-else, c-string literals, diagnostic attributes).

---

### cross

**Command**: `/cross [target-triple]`
**Category**: Compatibility
**File**: `.claude/skills/cross/SKILL.md`

Cross-compiles for different target platforms using rustup targets or the `cross` tool. Supports Tier 1 (x86_64/aarch64 Linux, macOS), Tier 2 (musl, Windows), and Tier 3 (WASM, Android) targets. Checks platform-specific concerns: endianness, hardware crypto, entropy, SIMD.

---

### bloat

**Command**: `/bloat [crate-name]`
**Category**: Optimization
**File**: `.claude/skills/bloat/SKILL.md`

Analyzes binary size using cargo-bloat. Shows top 30 largest functions, per-crate size contribution, and total binary size. Provides size budgets and optimization recommendations (feature gates, LTO, stripping, opt-level).

---

## Category Summary

| Category | Skills | Purpose |
|----------|--------|---------|
| **Build & CI** | check, test, lint | Core build verification pipeline |
| **Performance** | bench, profile | Benchmark execution and hotspot analysis |
| **Testing** | coverage, fuzz, miri | Coverage, fuzzing, and UB detection |
| **Security** | security-review, audit, vet | Code review, CVE scanning, supply chain |
| **Documentation** | doc, changelog, phase-docs | Rustdoc, release notes, phase tracking |
| **Git & Release** | commit, review-pr, semver | Commits, PR review, API compatibility |
| **Compatibility** | msrv, cross | Rust version and platform support |
| **Optimization** | bloat | Binary size analysis |
