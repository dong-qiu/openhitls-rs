---
name: audit
description: Run cargo-audit to check for known vulnerabilities in dependencies. Use when the user asks about dependency security, CVEs, or supply chain safety.
allowed-tools: Bash(cargo audit:*), Bash(cargo install:*)
---

Audit dependencies for known security vulnerabilities.

## Behavior

1. Run the advisory database check:
   ```
   cargo audit
   ```

2. If cargo-audit is not installed, install it first:
   ```
   cargo install cargo-audit
   ```

3. Report findings:
   - Total advisories found (critical/high/medium/low)
   - For each advisory: ID, crate, version, severity, description
   - Recommended fix (upgrade path or alternative crate)

4. Optionally check for yanked crates:
   ```
   cargo audit --deny yanked
   ```

## Output Format

| Advisory | Crate | Version | Severity | Fix Available |
|----------|-------|---------|----------|---------------|
| RUSTSEC-XXXX-XXXX | name | x.y.z | HIGH | Yes/No |

## Tips

- Run periodically and before releases
- Use `cargo audit fix` to auto-apply fixes (when available)
- The advisory database is maintained by the RustSec project
