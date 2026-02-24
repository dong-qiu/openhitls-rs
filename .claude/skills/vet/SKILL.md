---
name: vet
description: Run cargo-vet to verify third-party dependency trust. Use when the user asks about supply chain security, dependency auditing, or trust verification.
allowed-tools: Bash(cargo vet:*), Bash(cargo install:*)
---

Verify third-party dependency trust using cargo-vet.

## Behavior

1. If cargo-vet is not installed:
   ```
   cargo install cargo-vet
   ```

2. Check all dependencies:
   ```
   cargo vet
   ```

3. If unvetted dependencies found, show details:
   ```
   cargo vet suggest
   ```

4. Report:
   - Number of vetted vs unvetted dependencies
   - List of unvetted crates with their audit requirements
   - Suggested audits or exemptions

## Trust Criteria for This Project

| Criteria | Description |
|----------|-------------|
| `safe-to-deploy` | No unsafe, no ambient authority, no build scripts with side effects |
| `safe-to-run` | Safe for testing/dev, may have build scripts |
| `crypto-safe` | Additional: constant-time, no timing leaks, proper RNG usage |

## Priority Audit Targets

For a crypto library, prioritize auditing:
1. **Direct crypto deps**: `subtle`, `zeroize`, `getrandom`
2. **Serialization**: `der`, `asn1`, `pem`
3. **Network I/O**: `tokio` (for async TLS)
4. **Build deps**: proc-macros, build scripts

## Tips

- Import audit results from trusted organizations: `cargo vet import`
- Record your own audits: `cargo vet certify <crate> <version>`
- Use `cargo vet diff <crate> <v1> <v2>` to review version bumps
