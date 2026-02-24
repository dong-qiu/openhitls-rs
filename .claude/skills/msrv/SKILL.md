---
name: msrv
description: Verify minimum supported Rust version (MSRV) compliance. Use when the user asks about Rust version compatibility or MSRV checks.
allowed-tools: Bash(cargo +1.75:*), Bash(cargo msrv:*), Bash(cargo install:*), Bash(rustup:*)
---

Verify MSRV (Minimum Supported Rust Version) compliance for openHiTLS-rs.

## Behavior

The project's MSRV is **1.75** (declared in Cargo.toml).

1. **Quick check** — build with the MSRV toolchain:
   ```
   cargo +1.75 build --workspace --all-features
   ```

2. If toolchain 1.75 is not installed:
   ```
   rustup toolchain install 1.75
   ```

3. **Full check** — also run tests:
   ```
   cargo +1.75 test --workspace --all-features
   ```

4. If using cargo-msrv for automated detection:
   ```
   cargo install cargo-msrv
   cargo msrv --workspace
   ```

5. Report:
   - Whether MSRV 1.75 builds successfully
   - Any features or APIs requiring a newer Rust version
   - Suggested MSRV if current one is too low

## Common MSRV Issues

- `let ... else` syntax (stabilized 1.65)
- `#[diagnostic::on_unimplemented]` (stabilized 1.78 — avoid!)
- `impl Trait` in return position in traits (stabilized 1.75)
- Async traits (stabilized 1.75)
- C-string literals `c"..."` (stabilized 1.77 — avoid!)

## Tips

- Always check MSRV before bumping edition or using new features
- CI should test against MSRV in addition to stable/nightly
- Use `rust-version = "1.75"` in `Cargo.toml` for cargo's built-in check
