---
name: bench
description: Run Criterion benchmarks for the workspace or a specific group. Use when the user asks to benchmark, measure performance, or compare algorithm speeds.
argument-hint: "[bench-group]"
allowed-tools: Bash(cargo bench:*)
---

Run Criterion benchmarks for openHiTLS-rs.

## Usage

- `/bench` — run all benchmarks
- `/bench sha2` — run benchmarks matching "sha2"
- `/bench aes -- --sample-size 200` — custom Criterion flags

## Behavior

1. If `$ARGUMENTS` is empty, run:
   ```
   cargo bench --package hitls-crypto --all-features
   ```

2. If `$ARGUMENTS` specifies a filter, run:
   ```
   cargo bench --package hitls-crypto --all-features -- "$ARGUMENTS"
   ```

3. After benchmarks complete, report:
   - Median times for each benchmark
   - Throughput (MB/s) for data-processing benchmarks
   - Comparison with previous run (if Criterion baseline exists)

## Benchmark Groups

| Group | Algorithms |
|-------|-----------|
| sha2 | SHA-256, SHA-384, SHA-512 |
| sha3 | SHA3-256 |
| sm3 | SM3 |
| hmac | HMAC-SHA256, HMAC-SHA512, HMAC-SM3 |
| aes_gcm | AES-128-GCM, AES-256-GCM |
| aes_cbc | AES-128-CBC, AES-256-CBC |
| chacha20 | ChaCha20-Poly1305 |
| sm4_cbc | SM4-CBC |
| sm4_gcm | SM4-GCM |
| rsa | RSA-2048/3072/4096 keygen + sign/verify |
| ecdsa | ECDSA P-256/P-384 sign/verify |
| ed25519 | Ed25519 sign/verify |
| x25519 | X25519 key exchange |
| ecdh | ECDH P-256/P-384 |
| dh | FFDHE-2048/3072/4096 |
| sm2 | SM2 sign/verify |
| mlkem | ML-KEM-512/768/1024 |
| mldsa | ML-DSA-44/65/87 |

## Tips

- Use `--save-baseline <name>` to save a baseline for later comparison
- Use `--baseline <name>` to compare against a saved baseline
- Results are stored in `target/criterion/`
