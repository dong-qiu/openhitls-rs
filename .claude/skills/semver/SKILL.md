---
name: semver
description: Check for semver-breaking API changes using cargo-semver-checks. Use when preparing a release or after public API modifications.
allowed-tools: Bash(cargo semver-checks:*), Bash(cargo install:*)
---

Check for semver-incompatible API changes in openHiTLS-rs.

## Behavior

1. If cargo-semver-checks is not installed:
   ```
   cargo install cargo-semver-checks
   ```

2. Run semver check against the latest published version:
   ```
   cargo semver-checks check-release --workspace
   ```

3. Or check against a specific baseline:
   ```
   cargo semver-checks check-release --baseline-rev <git-ref>
   ```

4. Report:
   - Breaking changes detected (with locations)
   - Classification: major/minor/patch change required
   - Specific items that changed (removed types, changed signatures, etc.)

## Semver Rules for This Project

| Change Type | Semver Impact | Examples |
|-------------|---------------|---------|
| Remove public type/fn | **MAJOR** | Removing `CryptoError::Foo` variant |
| Change fn signature | **MAJOR** | Adding required parameter |
| Add enum variant (non-exhaustive) | **MINOR** | Adding `CryptoError::NewError` |
| Add new public fn/type | **MINOR** | New algorithm module |
| Bug fix, internal refactor | **PATCH** | Fixing algorithm output |
| Add trait impl | **MINOR** | `impl Display for ...` |

## Tips

- Run before every release to catch accidental breakage
- Use `#[non_exhaustive]` on public enums to allow future variants
- Prefer adding new types over modifying existing ones
- Mark experimental APIs with `#[doc(hidden)]` until stable
