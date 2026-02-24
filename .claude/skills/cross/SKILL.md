---
name: cross
description: Cross-compile and test for different target platforms. Use when the user asks about cross-compilation, platform support, or multi-target builds.
argument-hint: "[target-triple]"
allowed-tools: Bash(cargo build:*), Bash(cross:*), Bash(cargo install:*), Bash(rustup target:*)
---

Cross-compile openHiTLS-rs for different target platforms.

## Usage

- `/cross` — list supported targets and current status
- `/cross aarch64-unknown-linux-gnu` — build for ARM64 Linux
- `/cross x86_64-unknown-linux-musl` — build for static musl Linux
- `/cross wasm32-unknown-unknown` — build for WebAssembly

## Behavior

1. If `$ARGUMENTS` is empty, list target status:
   ```
   rustup target list --installed
   ```

2. For standard targets, use cargo with the target flag:
   ```
   rustup target add $ARGUMENTS
   cargo build --workspace --all-features --target $ARGUMENTS
   ```

3. For targets requiring cross-compilation toolchain:
   ```
   cargo install cross
   cross build --workspace --all-features --target $ARGUMENTS
   cross test --workspace --all-features --target $ARGUMENTS
   ```

4. Report:
   - Build success/failure per crate
   - Any platform-specific compilation errors
   - Feature/cfg differences for the target

## Supported Targets

| Target | Tier | Notes |
|--------|------|-------|
| `x86_64-unknown-linux-gnu` | 1 | Primary Linux |
| `aarch64-unknown-linux-gnu` | 1 | ARM64 Linux (server) |
| `x86_64-apple-darwin` | 1 | macOS Intel |
| `aarch64-apple-darwin` | 1 | macOS Apple Silicon |
| `x86_64-unknown-linux-musl` | 2 | Static Linux binary |
| `x86_64-pc-windows-msvc` | 2 | Windows |
| `wasm32-unknown-unknown` | 3 | WebAssembly (no_std subset) |
| `aarch64-linux-android` | 3 | Android |

## Platform Considerations

- **Endianness**: BigNum code must handle both big/little endian
- **Hardware crypto**: AES-NI (x86), ARMv8 Crypto Extensions (aarch64)
- **Entropy**: `getrandom` adapts per platform, but verify on each target
- **SIMD**: Conditional compilation for platform-specific intrinsics
- **no_std**: Some targets may need `#![no_std]` support
