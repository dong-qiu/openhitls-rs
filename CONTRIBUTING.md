# Contributing to openHiTLS-rs

Thank you for your interest in contributing! This document explains the process.

## Security Issues

**Do NOT open a public issue for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Getting Started

### Prerequisites

- Rust 1.75+ (MSRV)
- OpenSSL CLI (for differential tests)

### Building

```bash
cargo build --workspace --all-features
```

### Running Tests

```bash
# All tests
cargo test --workspace --all-features

# Specific crate
cargo test -p hitls-crypto --all-features
```

### Linting

All code must pass with zero warnings:

```bash
RUSTFLAGS="-D warnings" cargo clippy --workspace --all-features --all-targets
cargo fmt --all -- --check
```

## Pull Request Process

1. Fork the repository and create a feature branch
2. Make your changes following the code conventions below
3. Ensure all tests pass and clippy reports no warnings
4. Submit a PR against `main`

## Code Conventions

### Error Handling

- Use `hitls_types::CryptoError` for all errors
- Return `Result<T, CryptoError>` from public APIs
- Never panic in library code — use `Result` instead
- Use `.expect("reason")` instead of `.unwrap()` where panics are logically impossible

### Security Patterns

- **Zeroize**: All secret material must derive `Zeroize` and `ZeroizeOnDrop`
- **Constant-time**: Use `subtle::ConstantTimeEq` for cryptographic comparisons, never `==`
- **Randomness**: Use `getrandom`, never `rand`
- **No unsafe**: Avoid `unsafe` unless strictly necessary (SIMD intrinsics). All unsafe blocks must have safety comments

### Formatting

- Max line width: 100 characters
- Run `cargo fmt` before committing
- Cognitive complexity threshold: 15

### Testing

- Use standard test vectors from RFCs/NIST where available
- Mark slow tests with `#[ignore]`
- Add doc-tests for public API additions

## License

By contributing, you agree that your contributions will be licensed under the MulanPSL-2.0 license.
