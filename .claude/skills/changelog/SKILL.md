---
name: changelog
description: Generate or update CHANGELOG.md from git history. Use when the user asks to create a changelog or prepare release notes.
argument-hint: "[version]"
allowed-tools: Bash(git log:*), Bash(git tag:*)
---

Generate or update the changelog for openHiTLS-rs.

## Usage

- `/changelog` — generate changelog from last tag to HEAD
- `/changelog v0.2.0` — generate changelog for a specific version

## Behavior

1. Find the latest tag:
   ```
   git tag --sort=-version:refname | head -1
   ```

2. Get all commits since that tag (or since beginning if no tags):
   ```
   git log <last-tag>..HEAD --oneline --no-merges
   ```

3. Categorize commits by their prefix:

   | Prefix | Section |
   |--------|---------|
   | `feat:` | Added |
   | `fix:` | Fixed |
   | `refactor:` | Changed |
   | `docs:` | Documentation |
   | `test:` | Testing |
   | `chore:` | Maintenance |
   | `perf:` | Performance |

4. Generate changelog entry in Keep a Changelog format:

   ```markdown
   ## [version] - YYYY-MM-DD

   ### Added
   - Feature descriptions

   ### Fixed
   - Bug fix descriptions

   ### Changed
   - Refactoring descriptions

   ### Security
   - Security-relevant changes
   ```

5. If `$ARGUMENTS` specifies a version, use that; otherwise use `[Unreleased]`.

## Conventions

- Follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format
- Follow [Semantic Versioning](https://semver.org/)
- Group by category, then list chronologically within each group
- Include commit hash references for traceability
- Highlight breaking changes prominently
