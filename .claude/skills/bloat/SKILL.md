---
name: bloat
description: Analyze binary size and dependency bloat using cargo-bloat. Use when the user asks about binary size, large dependencies, or size optimization.
argument-hint: "[crate-name]"
allowed-tools: Bash(cargo bloat:*), Bash(cargo install:*)
---

Analyze binary size and identify bloat in openHiTLS-rs.

## Usage

- `/bloat` — analyze the CLI binary
- `/bloat --crates` — show size contribution per crate
- `/bloat hitls-crypto` — analyze a specific crate

## Behavior

1. If cargo-bloat is not installed:
   ```
   cargo install cargo-bloat
   ```

2. Analyze largest functions:
   ```
   cargo bloat --release --all-features -p hitls-cli -n 30
   ```

3. Analyze per-crate contribution:
   ```
   cargo bloat --release --all-features -p hitls-cli --crates
   ```

4. Report:
   - Total binary size
   - Top 30 largest functions with sizes
   - Per-crate size contribution table
   - Recommendations for size reduction

## Size Budget Guidelines

| Component | Target | Notes |
|-----------|--------|-------|
| hitls-crypto | <2 MB | Feature-gated algorithms |
| hitls-tls | <500 KB | Protocol logic |
| hitls-pki | <300 KB | Certificate handling |
| hitls-cli | <5 MB | Full-featured binary |

## Optimization Tips

- Use `#[cfg(feature)]` to exclude unused algorithms
- Check for accidental inclusion of debug info in release
- Use `opt-level = "z"` for size-optimized builds
- Enable LTO: `lto = true` in release profile
- Strip symbols: `strip = true` in release profile
