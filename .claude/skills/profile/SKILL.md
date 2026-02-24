---
name: profile
description: Profile CPU and memory usage of benchmarks or tests. Use when the user asks to profile, find hotspots, or optimize performance.
argument-hint: "[target]"
allowed-tools: Bash(cargo bench:*), Bash(cargo flamegraph:*), Bash(cargo install:*), Bash(samply:*), Bash(instruments:*)
---

Profile openHiTLS-rs code to find performance hotspots.

## Usage

- `/profile sha2` — profile SHA-2 benchmarks
- `/profile rsa --flamegraph` — generate flamegraph
- `/profile hitls-crypto` — profile all crypto benchmarks

## Behavior

### Option 1: Flamegraph (default)

1. If cargo-flamegraph is not installed:
   ```
   cargo install flamegraph
   ```

2. Generate flamegraph from benchmark:
   ```
   cargo flamegraph --bench crypto_bench --all-features -- --bench "$ARGUMENTS"
   ```

3. Output: `flamegraph.svg` in project root

### Option 2: samply (macOS/Linux)

1. If samply is not installed:
   ```
   cargo install samply
   ```

2. Profile with samply:
   ```
   cargo build --bench crypto_bench --release --all-features
   samply record target/release/deps/crypto_bench-* --bench "$ARGUMENTS"
   ```

3. Opens Firefox Profiler in browser

### Option 3: Instruments (macOS only)

```
cargo instruments --bench crypto_bench --all-features -t "Time Profiler" -- --bench "$ARGUMENTS"
```

## Report

After profiling, report:
- Top 10 hottest functions with percentage of total time
- Call stack for the main hot path
- Optimization suggestions based on findings

## Common Hotspots in Crypto Code

| Algorithm | Typical Hotspot | Optimization |
|-----------|----------------|-------------|
| RSA | ModExp (Montgomery multiplication) | Assembly, better reduction |
| ECC | Scalar multiplication | Window method, endomorphism |
| AES-GCM | GHASH polynomial multiplication | PMULL/CLMUL intrinsics |
| SHA-256 | Compression function | SHA-NI intrinsics |
| BigNum | Division, multiplication | Karatsuba, assembly |
