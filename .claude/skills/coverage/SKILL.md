---
name: coverage
description: Generate code coverage reports using cargo-llvm-cov. Use when the user asks about test coverage, uncovered code, or coverage percentages.
argument-hint: "[crate-name]"
allowed-tools: Bash(cargo llvm-cov:*), Bash(cargo install:*), Bash(rustup component:*)
---

Generate code coverage reports for openHiTLS-rs.

## Usage

- `/coverage` — workspace coverage summary
- `/coverage hitls-crypto` — coverage for a specific crate
- `/coverage hitls-tls --html` — generate HTML report

## Behavior

1. If cargo-llvm-cov is not installed:
   ```
   cargo install cargo-llvm-cov
   rustup component add llvm-tools-preview
   ```

2. If `$ARGUMENTS` is empty, run workspace coverage:
   ```
   cargo llvm-cov --workspace --all-features
   ```

3. If a crate is specified:
   ```
   cargo llvm-cov -p $ARGUMENTS --all-features
   ```

4. For HTML report (if `--html` in arguments):
   ```
   cargo llvm-cov --workspace --all-features --html --output-dir target/coverage
   ```

5. Report:
   - Per-file line coverage percentages
   - Overall project coverage percentage
   - Files with lowest coverage (potential gaps)
   - Uncovered functions/branches of interest

## Coverage Targets

For a crypto library, target coverage priorities:
- **Critical**: Algorithm implementations (>90% target)
- **High**: TLS state machine, handshake logic (>85% target)
- **Medium**: PKI parsing, CLI commands (>75% target)
- **Low**: Error paths, edge cases (>60% target)

## Tips

- Use `--ignore-filename-regex "tests/"` to exclude test files from metrics
- Use `cargo llvm-cov report --lcov > lcov.info` for CI integration
- HTML reports open in browser from `target/coverage/html/index.html`
