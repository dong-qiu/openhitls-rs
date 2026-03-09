# CLAUDE.md — Project Guide for Claude Code

This file provides context for Claude Code when working on the openHiTLS-rs codebase.

## Project Overview

openHiTLS-rs is a pure Rust rewrite of [openHiTLS](https://gitee.com/openhitls/openhitls) (C implementation), providing production-grade cryptographic primitives and TLS protocol support.

- **Language**: Rust (MSRV 1.75, edition 2021)
- **License**: MulanPSL-2.0
- **Status**: Phases I1–I87, T1–T79, R1–R12, P1–P93 complete (4046 tests, 35 ignored)

## Workspace Structure

```
openhitls-rs/
├── crates/
│   ├── hitls-types/     # Shared types: algorithm IDs, error enums
│   ├── hitls-utils/     # Hex, ASN.1, Base64, PEM, OID utilities
│   ├── hitls-bignum/    # Big number arithmetic (CIOS Montgomery, Miller-Rabin, prime generation)
│   ├── hitls-crypto/    # Cryptographic algorithms (feature-gated): symmetric, hash, MAC, RSA, ECC, EdDSA, DH, DSA, SM2/SM9, PQC, HybridKEM, HPKE, DRBG, FIPS/CMVP
│   ├── hitls-tls/       # TLS 1.3/1.2 (91 cipher suites), DTLS 1.2, TLCP, DTLCP; sync + async; extensions, callbacks, session cache, renegotiation, GREASE, CRL revocation, PHA
│   ├── hitls-pki/       # X.509, PKCS#8, PKCS#12, CMS, CRL builder+extensions, hostname verification
│   ├── hitls-auth/      # HOTP/TOTP, SPAKE2+, Privacy Pass
│   └── hitls-cli/       # CLI tool: dgst, genpkey, x509, verify, enc, pkey, crl, req, s-client, s-server, list, rand, pkeyutl, speed, pkcs12, mac, prime, kdf
├── tests/interop/       # Integration tests — 15 test files + helper lib
├── tests/vectors/       # Standard test vectors (NIST, Wycheproof, GM/T)
├── fuzz/                # Fuzz targets (cargo-fuzz)
```

## Build & Test Commands

```bash
# Build
cargo build --workspace --all-features

# Run all tests
cargo test --workspace --all-features

# Run tests for a specific crate
cargo test -p hitls-crypto --all-features
cargo test -p hitls-tls --all-features
cargo test -p hitls-pki --all-features
cargo test -p hitls-bignum
cargo test -p hitls-utils
cargo test -p hitls-auth --all-features
cargo test -p hitls-cli --all-features
cargo test -p hitls-integration-tests

# Lint (must pass with zero warnings)
RUSTFLAGS="-D warnings" cargo clippy --workspace --all-features --all-targets

# Format check
cargo fmt --all -- --check
```

## Code Style & Conventions

### Formatting
- `rustfmt.toml`: max_width=100, use_field_init_shorthand, use_try_shorthand
- `clippy.toml`: cognitive-complexity-threshold=15
- Always run `cargo fmt` before committing
- **Sync before task**: Before starting any implementation task, always sync the remote main branch first (`git fetch origin main && git rebase origin/main`) to ensure the local codebase is up to date

### Git Branching Model
- **Trunk-based development**: The remote repository has **only one branch: `main`**. Never create or push branches to the remote
- **Local worktrees for parallel development**: 4 persistent worktrees under `worktrees/`, each on a dedicated local branch:
  - `worktrees/perf-enhanced` → `perf` (performance optimization)
  - `worktrees/bug-fix` → `bug-fix` (defect fixes)
  - `worktrees/refactoring` → `refactoring` (code restructuring)
  - `worktrees/test-enhanced` → `testing` (test coverage improvement)
- **Worktree workflow**:
  1. Develop in worktree: `cd worktrees/perf-enhanced` → commit changes
  2. Rebase onto main: `git rebase main` (in worktree branch)
  3. Fast-forward merge: `cd <root>` → `git checkout main` → `git merge perf --ff-only`
  4. Sync & push: `git fetch origin main && git rebase origin/main` → `git push origin main`
- **Merge policy**: always `--ff-only` (fast-forward only) to keep linear history; if conflicts, rebase the worktree branch first
- Push command: always `git push origin main`

### Error Handling
- Use `hitls_types::CryptoError` for all crypto errors (thiserror-based)
- Return `Result<T, CryptoError>` from all public APIs
- Never panic in library code; use `Result` instead

### Security Patterns
- **Zeroize on drop**: All secret material (keys, intermediate states) must implement `Zeroize` via `#[derive(Zeroize)]` and `#[zeroize(drop)]`
- **Constant-time comparisons**: Use `subtle::ConstantTimeEq` for cryptographic comparisons, never `==`
- **No unsafe code** in `hitls-types`, `hitls-utils`, and most crates. Only `hitls-bignum` and `hitls-crypto` may use unsafe (for SIMD, etc.)
- **Random generation**: Use `getrandom` crate, never `rand`

### Feature Flags
- `hitls-crypto` uses feature flags for algorithm selection
- Default features: `aes`, `sha2`, `rsa`, `ecdsa`, `hmac`
- Each algorithm module is gated by `#[cfg(feature = "...")]` in `lib.rs`
- Feature dependencies are declared in `Cargo.toml` (e.g., `hkdf = ["hmac"]`)

### API Patterns
- **SHA-256**: `Sha256::new()`, `.update(data)?`, `.finish()? -> [u8; 32]` (returns array, not `finish(&mut [u8])`)
- **HMAC**: `Hmac::new(factory, key)?`, `.update(data)?`, `.finish(&mut out)?` (writes to buffer)
- **HMAC Digest trait**: `finish(&mut self, out: &mut [u8])` pattern (different from SHA-256 direct API)
- **BigNum**: `BigNum::from_bytes_be()`, `.to_bytes_be()`, `.mod_exp()`, `.mod_inv()`, `.gcd()` — all return `Result`
- **X25519**: `X25519PrivateKey::new(bytes)` applies clamping; `.diffie_hellman(&pub_key)? -> Vec<u8>`

### Test Conventions
- Use standard test vectors from RFCs/NIST where available
- Slow tests (prime generation, keygen) are marked `#[ignore]`
- Hex helpers: `use hitls_utils::hex::{hex, to_hex};` — shared across all crates
- Tests live in `#[cfg(test)] mod tests` within each module file

### Post-Task Documentation Updates
After completing each implementation task (phase/feature), **always** update the following files:
- `DEV_LOG.md` — Add a new phase entry with summary, files modified, implementation details, test counts, and build status (all phase types: N, TN, RN, PN). **After adding the entry, refresh the Phase Index tables at the top of the file**: recalculate the `#` column (sequential row number) for the affected category table (Implementation/Testing/Refactoring/Performance) to ensure numbering is contiguous.
- `PROMPT_LOG.md` — Record the prompt and result for the phase. The `>` quoted line must contain the user's **original CLI input verbatim** (not a Claude-generated summary or English translation). Copy the user's exact text as-is.
- `CLAUDE.md` — Update status line, test counts, workspace structure annotations, and phase number references to match DEV_LOG.md
- `README.md` — Update test counts in Building & Testing section; update protocol/algorithm tables if new features added

### Phase Numbering Rules
- **No sub-phases**: All phases use integer IDs (e.g., Phase I44, not Phase I44a/I44b). If a task has multiple parts, use a single Phase entry with `### Part A / Part B` subsections inside.
- **Four categories**: Implementation (I-prefix, e.g., I43), Testing (T-prefix, e.g., T6), Refactoring (R-prefix, e.g., R1), Performance (P-prefix, e.g., P1).
- **Sequential within category**: New phases append to the end of their category with the next available number.
- **Global consistency**: When DEV_LOG.md phase numbering changes, synchronize all references in `CLAUDE.md`, `README.md`, and `PROMPT_LOG.md` to match.

## C Reference Code

The original C implementation is at `/Users/dongqiu/Dev/code/openhitls/`:
- Crypto algorithms: `crypto/` directory
- Algorithm IDs: `include/crypto/crypt_algid.h`
- Error codes: `include/crypto/crypt_errno.h`
- TLS protocol: `tls/` directory (~63K lines)
- PKI/X.509: `pki/` directory (~18K lines)

## Migration Roadmap

Phases I1–I87, T1–T79, R1–R12, P1–P93 complete (4046 tests, 35 ignored). **100% C→Rust feature parity achieved. Architecture refactoring complete. Performance optimization and quality improvement complete.**

### Completed Phases (Summary)

- **Implementation (I1–I87)**: All crypto primitives (48 modules), TLS 1.3/1.2/DTLS/TLCP/DTLCP (91 cipher suites, 10 connection types), PKI/X.509/CMS, FIPS/CMVP, entropy health, CLI (18 commands), async I/O, HPKE (RFC 9180), HybridKEM (12 variants), XMSS-MT, CRL extensions, security levels, PHA
- **Testing (T1–T79)**: Unit tests, proptest, fuzz (68 targets, 447 corpus seeds), CI hardening (Miri, cargo-deny, cargo-careful, cargo-mutants, cargo-semver-checks, nextest, llvm-cov), feature flag isolation, constant-time verification (16 dudect tests), OpenSSL differential testing, cargo-vet supply chain audit, SBOM/SLSA/ASan, Kani formal verification
- **Refactoring (R1–R12)**: Enum dispatch, sync/async body macros, module decomposition, dev profile opt-level overrides
- **Performance (P1–P93)**: HW accel (AES-NI, SHA-NI, SHA-512 CE, SHA-3 EOR3/RAX1/BCAX, GHASH PMULL/CLMUL, ChaCha20 NEON/SSE2, SHA-1 CE, VAES/VPCLMULQDQ), specialized fields (P-256/P-384/P-521/SM2 Montgomery, Ed25519/Ed448 precomputed tables), CIOS BigNum optimizations, ML-KEM/ML-DSA NEON NTT, SM4 T-table, AES 4-block pipeline, GCM interleaved pipeline, Poly1305 r² batch, pervasive Vec→stack allocation, monomorphization, RSA CRT caching, DH precomputed tables, TLS record enum dispatch + stack IV + zero-copy decrypt

See `DEV_LOG.md` for detailed per-phase descriptions and `PROMPT_LOG.md` for prompt/response log.
