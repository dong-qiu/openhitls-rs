---
name: review-pr
description: Review a pull request for code quality, security, and project conventions. Use when the user asks to review a PR or diff.
argument-hint: "<pr-number-or-branch>"
context: fork
agent: Explore
allowed-tools: Read, Grep, Glob, Bash(git diff:*), Bash(gh pr:*)
---

Review pull request or branch `$ARGUMENTS` for the openHiTLS-rs project.

Use ultrathink to carefully evaluate each review criterion.

## Behavior

1. Get the diff:
   - If `$ARGUMENTS` is a PR number: `gh pr diff $ARGUMENTS`
   - If `$ARGUMENTS` is a branch: `git diff main...$ARGUMENTS`

2. Review against the following checklist.

## Review Checklist

### Code Quality
- [ ] Follows rustfmt conventions (max_width=100)
- [ ] No clippy warnings (cognitive-complexity-threshold=30)
- [ ] Error handling uses `Result<T, CryptoError>` — no `unwrap()` in lib code
- [ ] Tests added for new functionality
- [ ] No unnecessary dependencies added

### Security (for crypto/TLS code)
- [ ] Secret material has `#[derive(Zeroize)]` and `#[zeroize(drop)]`
- [ ] Cryptographic comparisons use `subtle::ConstantTimeEq`
- [ ] No `unsafe` outside `hitls-bignum` and `hitls-crypto`
- [ ] Random generation uses `getrandom`, not `rand`
- [ ] Feature gates are correct and complete

### Architecture
- [ ] New modules follow existing patterns
- [ ] Public API is consistent with adjacent modules
- [ ] No circular dependencies introduced
- [ ] Feature flags properly declared and gated

### Documentation
- [ ] Public items have doc comments
- [ ] CLAUDE.md updated if test counts changed
- [ ] DEV_LOG.md entry added for the phase

## Output Format

```
## PR Review: $ARGUMENTS

### Summary
<1-2 sentence overview>

### Findings
| # | File:Line | Severity | Category | Finding |
|---|-----------|----------|----------|---------|
| 1 | path:42 | HIGH/MED/LOW | Security | ... |

### Verdict
APPROVE / REQUEST CHANGES / COMMENT

### Suggestions
- Numbered list of improvements
```
