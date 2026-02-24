---
name: doc
description: Build and check rustdoc documentation. Use when the user asks to generate docs, check doc coverage, or fix doc warnings.
argument-hint: "[crate-name]"
allowed-tools: Bash(cargo doc:*), Bash(RUSTDOCFLAGS=*)
---

Build and verify rustdoc documentation for openHiTLS-rs.

## Usage

- `/doc` — build all docs with warnings as errors
- `/doc hitls-crypto` — build docs for a specific crate
- `/doc --open` — build and open in browser

## Behavior

1. If `$ARGUMENTS` is empty, build workspace docs:
   ```
   RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
   ```

2. If a crate is specified:
   ```
   RUSTDOCFLAGS="-D warnings" cargo doc -p $ARGUMENTS --all-features --no-deps
   ```

3. If `--open` is in arguments:
   ```
   cargo doc --workspace --all-features --no-deps --open
   ```

4. Report:
   - Build success/failure
   - Any documentation warnings (missing docs, broken links)
   - Undocumented public items count

## Doc Conventions

- All public API items should have doc comments (`///`)
- Module-level docs use `//!`
- Include examples in doc comments where practical:
  ```rust
  /// # Examples
  /// ```
  /// use hitls_crypto::hash::Sha256;
  /// let digest = Sha256::new().update(b"hello").unwrap().finish().unwrap();
  /// ```
  ```
- Link to RFCs and standards in algorithm documentation
- Use `#[doc(hidden)]` for internal-only public items

## Tips

- Doc tests are compiled and run with `cargo test --doc`
- Use `cargo doc --document-private-items` for internal documentation
- Generated docs are in `target/doc/`
