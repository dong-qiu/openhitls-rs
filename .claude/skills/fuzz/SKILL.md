---
name: fuzz
description: Run cargo-fuzz targets to find crashes and edge cases. Use when the user asks to fuzz, find bugs, or stress-test parsers.
argument-hint: "[target] [duration]"
allowed-tools: Bash(cargo fuzz:*), Bash(cargo +nightly:*)
---

Run fuzz testing for openHiTLS-rs using cargo-fuzz.

## Usage

- `/fuzz` — list all fuzz targets
- `/fuzz x509_parse` — fuzz the X.509 parser
- `/fuzz x509_parse 60` — fuzz for 60 seconds
- `/fuzz tls_handshake 300` — fuzz TLS handshake for 5 minutes

## Behavior

1. If `$ARGUMENTS` is empty, list available targets:
   ```
   cargo fuzz list
   ```

2. If a target is specified (with optional duration in seconds, default 60):
   ```
   cargo +nightly fuzz run <target> -- -max_total_time=<duration>
   ```

3. After fuzzing completes, report:
   - Total executions and exec/sec
   - Corpus size (new inputs discovered)
   - Any crashes found (with artifact paths)
   - Coverage metrics if available

## Available Targets

| Target | Description |
|--------|-------------|
| fuzz_x509 | X.509 certificate parsing |
| fuzz_pkcs8 | PKCS#8 private key parsing |
| fuzz_pkcs12 | PKCS#12 container parsing |
| fuzz_cms | CMS message parsing |
| fuzz_pem | PEM decoding |
| fuzz_asn1 | ASN.1 DER/BER parsing |
| fuzz_tls_handshake | TLS handshake message parsing |
| fuzz_tls_record | TLS record layer parsing |
| fuzz_bignum | BigNum arithmetic operations |
| fuzz_drbg | DRBG generate/reseed |

## Prerequisites

- Requires nightly toolchain: `rustup toolchain install nightly`
- Requires cargo-fuzz: `cargo install cargo-fuzz`

## Crash Triage

If crashes are found:
1. Reproduce: `cargo +nightly fuzz run <target> <artifact_path>`
2. Minimize: `cargo +nightly fuzz tmin <target> <artifact_path>`
3. Report the crash input and stack trace
