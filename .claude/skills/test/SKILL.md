---
name: test
description: Run tests for the workspace or a specific crate. Use when the user asks to run tests, verify changes, or check test counts.
argument-hint: "[crate-name]"
allowed-tools: Bash(cargo test:*)
---

Run tests for the openHiTLS-rs workspace.

## Usage

- `/test` — run full workspace tests
- `/test hitls-crypto` — run tests for a specific crate
- `/test hitls-tls` — run tests for TLS crate

## Behavior

1. If `$ARGUMENTS` is empty, run:
   ```
   cargo test --workspace --all-features
   ```

2. If `$ARGUMENTS` specifies a crate name, run:
   ```
   cargo test -p $ARGUMENTS --all-features
   ```

3. After tests complete, report:
   - Total passed / failed / ignored counts
   - Compare against expected counts from the table below
   - Flag any unexpected failures

## Expected Test Counts

Snapshot measured 2026-06-19 via `cargo test -p <crate> --all-features` (all
targets: lib + integration + migrated C→Rust KAT files). These grow every phase
— `DEV_LOG.md` is the authoritative per-phase tally; refresh this table when it
drifts materially (a small positive delta is almost always new tests, not a
regression).

| Crate | Expected Tests | Ignored |
|-------|---------------|---------|
| hitls-crypto | 4523 | 25 |
| hitls-tls | 1720 | 0 |
| hitls-pki | 1683 | 0 |
| hitls-bignum | 325 | 1 |
| hitls-utils | 90 | 0 |
| hitls-auth | 131 | 0 |
| hitls-cli | 310 | 7 |
| hitls-integration-tests | 542 | 13 |
| **Total workspace** | **9324** | **46** |

If test counts differ from expected, explicitly note the delta and whether it indicates new tests or regressions.
