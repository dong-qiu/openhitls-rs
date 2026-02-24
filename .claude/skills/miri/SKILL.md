---
name: miri
description: Run Miri to detect undefined behavior in unsafe code. Use when the user asks to check unsafe code, memory safety, or UB detection.
argument-hint: "[crate-name]"
allowed-tools: Bash(cargo +nightly:*), Bash(rustup:*)
---

Run Miri (MIR Interpreter) to detect undefined behavior in openHiTLS-rs.

## Usage

- `/miri hitls-bignum` — check bignum unsafe code
- `/miri hitls-crypto` — check crypto unsafe code

## Behavior

1. Ensure Miri is installed:
   ```
   rustup +nightly component add miri
   ```

2. Run Miri on the specified crate:
   ```
   cargo +nightly miri test -p $ARGUMENTS --all-features
   ```

3. If `$ARGUMENTS` is empty, run on crates with unsafe code:
   ```
   cargo +nightly miri test -p hitls-bignum
   cargo +nightly miri test -p hitls-crypto --all-features
   ```

4. Report:
   - UB detected (with locations and descriptions)
   - Number of tests passed under Miri
   - Any tests that Miri cannot run (FFI, unsupported operations)

## What Miri Detects

| Category | Examples |
|----------|---------|
| Memory | Out-of-bounds access, use-after-free, double-free |
| Alignment | Unaligned pointer access |
| Validity | Invalid bool/enum values, dangling references |
| Concurrency | Data races, deadlocks |
| Leaks | Memory leaks (with `-Zmiri-leak-check`) |

## Limitations

- Very slow (10-100x slower than normal execution)
- Cannot test FFI calls
- Some operations are unsupported (certain syscalls, inline assembly)
- May need `MIRIFLAGS` for specific configurations:
  ```
  MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test -p hitls-bignum
  ```

## Tips

- Focus on `hitls-bignum` and `hitls-crypto` (only crates with unsafe code)
- Run a subset of tests if full suite is too slow
- Use `MIRIFLAGS="-Zmiri-backtrace=full"` for detailed error traces
