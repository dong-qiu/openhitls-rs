# Prompt Log

Record of all user prompts and key execution results during the openHiTLS-rs development process.

---

## Session 1: Phase 0 — Project Scaffolding

### Prompt 1: Implement the migration plan
> Implement the following plan: [C-to-Rust migration plan for openHiTLS]

**Result**: Created Rust workspace with 8 crates (hitls-types, hitls-utils, hitls-bignum, hitls-crypto, hitls-tls, hitls-pki, hitls-auth, hitls-cli). All module skeletons, type definitions, algorithm ID enums (~200), error types, trait-based provider system, and CI/CD configuration created. 98 files, 6095 lines of code. 24 tests passing.

### Prompt 2: Record the development process
> 请将整个开发过程记录下来

**Result**: Created `DEV_LOG.md` in memory directory to record development progress.

### Prompt 3: Where is the development log?
> 记录开发过程的日志在什么位置

**Result**: Explained the log is stored in Claude's persistent memory at `~/.claude/projects/.../memory/dev-log.md`.

### Prompt 4: Put the log in the project root too
> 开发过程的日志同步也放在openhitls-rs的根目录下

**Result**: Created `DEV_LOG.md` in `openhitls-rs/` root directory.

### Prompt 5: Are local tests completed?
> 是否已经完成本地测试？

**Result**: Confirmed all 24 tests pass (13 bignum + 11 utils), `cargo fmt --check` passes, `cargo check --all-features` passes.

### Prompt 6: Should we move the Rust project out?
> 迁移后的rust版本的项目在原来项目的目录下，是保持当前状态较好，还是将这个目录迁移出去

**Result**: Recommended moving to sibling directory for cleaner separation. Suggested structure:
```
/Users/dongqiu/Dev/code/
├── openhitls/          # C project (read-only reference)
└── openhitls-rs/       # Rust project (independent git repo)
```

### Prompt 7: Move it out as suggested
> 按照建议迁移出去

**Result**: Moved `openhitls-rs/` from inside the C project to `/Users/dongqiu/Dev/code/openhitls-rs/`. Initialized independent git repository with `main` branch. All 24 tests verified passing at new location. Old directory removed.

---

## Session 2: GitHub & CI Fixes

### Prompt 8: Create GitHub repo and push
> 请在github上建立一个仓库，并将openhitls-rs这个仓库推动到远程仓库

**Result**: Created public GitHub repo at https://github.com/dong-qiu/openhitls-rs and pushed all code (98 files, `main` branch).

### Prompt 9: Add a README
> 请补充一个readme

**Result**: Created comprehensive `README.md` covering project overview, workspace structure, full algorithm support table with feature flags and status, build/test instructions, design principles, MSRV, and license. Committed and pushed.

### Prompt 10: Fix remote CI failures
> 远程的CI出现问题，请分析原因并修复

**Analysis**: 7 CI jobs were failing:
1. **Test / Clippy / Bench / Feature Combinations** — `RUSTFLAGS: -D warnings` turned stub code warnings (dead_code, unused_variables) into compilation errors (242 errors)
2. **Clippy** — `derivable_impls` lint on `PointFormat::Default`, `manual_div_ceil` in bignum/base64, `new_without_default` on hash stubs, `new_ret_no_self` on `Pkcs12::new()`
3. **Security Audit** — `Cargo.lock` not committed (excluded by `.gitignore`)
4. **Benchmark** — `--bench crypto_bench` target not found in workspace

**Fixes applied**:
- Added `#![allow(dead_code, unused_variables, clippy::new_without_default)]` to `hitls-crypto` and `hitls-auth`
- Changed `PointFormat` to use `#[derive(Default)]` + `#[default]`
- Replaced manual div_ceil patterns with `.div_ceil()` in bignum and base64
- Renamed `Pkcs12::new()` to `Pkcs12::create()`
- Removed `Cargo.lock` from `.gitignore` and committed it
- Changed bench CI step to `cargo bench --no-run`

**Result**: All 10 CI jobs passing:
```
success  Format Check
success  Clippy Lint
success  Test (ubuntu-latest, stable)
success  Test (ubuntu-latest, 1.75)
success  Test (macos-latest, stable)
success  Test (macos-latest, 1.75)
success  Test Feature Combinations
success  Security Audit
success  Miri (UB detection)
success  Benchmark Check
```

### Prompt 11: Record all prompts to PROMPT_LOG.md
> 请将我输入的所有提示词和运行结果记录到PROMPT_LOG.md中

**Result**: Created this file (`PROMPT_LOG.md`) documenting all user prompts and their execution results.

---

## Session 3: Phase 2 — 完善 hitls-bignum 大数运算库

### Prompt 12: Implement Phase 2 bignum plan
> Implement the following plan: Phase 2 — 完善 hitls-bignum 大数运算库

Plan included 13 steps covering Montgomery arithmetic, shift/square operations, Knuth division, GCD/modular inverse, constant-time ops, random generation, and comprehensive tests.

**Result**: Implemented all 13 steps across 10 files (+1188/-97 lines):

**Modified files (7)**:
- `bignum.rs` — Added `from_limbs`, `is_one`, `is_even`, `is_odd`, `get_bit`, `set_bit`; `normalize` → `pub(crate)`; `Ord`/`PartialOrd` traits
- `ops.rs` — `shl`/`shr` (word+bit shift), `sqr` (optimized squaring with symmetry), `mod_add`/`mod_sub`/`mod_mul`; replaced binary long division with Knuth Algorithm D; `mod_exp` now uses Montgomery for odd moduli
- `montgomery.rs` — Full rewrite: `MontgomeryCtx` with R² precomputation, REDC reduction, `to_mont`/`from_mont`, `mont_mul`/`mont_sqr`, windowed `mont_exp` (window sizes 1–6)
- `prime.rs` — Replaced private `shift_right_one` with `shr(1)`
- `lib.rs` — Added `gcd`, `rand`, `ct` module declarations
- `Cargo.toml` — Added `getrandom = "0.2"` dependency
- `Cargo.lock` — Updated

**New files (3)**:
- `gcd.rs` — Euclidean GCD + extended Euclidean modular inverse (`mod_inv`)
- `ct.rs` — Constant-time `ct_eq`, `ct_select`, `ct_sub_if_gte` using `subtle` crate
- `rand.rs` — `random(bits, odd)` and `random_range(upper)` using `getrandom`

**Test results**: 45 tests pass (was 13, +32 new), 0 clippy warnings. Tests cover Montgomery roundtrip, Fermat's little theorem, RSA encrypt/decrypt (p=61,q=53), GCD, modular inverse, shift roundtrips, Knuth division verification (`q*b + r == a`), constant-time ops, random number properties.

Committed as `bad1d4c` and pushed to `origin/main`.

### Prompt 13: Commit and push to remote
> 请提交修改并推送至远程仓库

**Result**: Already committed and pushed in previous step as commit `bad1d4c`.

### Prompt 14: Fix remote CI failures
> 远程CI没有通过，请分析原因并修复问题

**Analysis**: CI run `21756033000` failed on 2 jobs:

1. **Clippy Lint** — `unnecessary_cast`: In Knuth division (`ops.rs:454`), `(diff >> LIMB_BITS) as i128` where `diff` is already `i128`
2. **Format Check** — `cargo fmt --check` detected formatting differences in `bignum.rs` (Ord impl if/else), `ct.rs` (long lines, if/else formatting), `montgomery.rs` (chained method call), `ops.rs` (array literal, trailing spaces)

**Fixes applied**:
- Removed redundant `as i128` cast in Knuth division
- Ran `cargo fmt --all` to normalize formatting across all files

**Result**: All 3 local checks pass (fmt, clippy, tests). Committed as `f69972d` and pushed to `origin/main`.

### Prompt 15: Record all prompts to PROMPT_LOG.md
> 请将我输入的所有提示词和运行结果记录到PROMPT_LOG.md中

**Result**: Updated this file with Session 3 entries (Prompts 12–15).
