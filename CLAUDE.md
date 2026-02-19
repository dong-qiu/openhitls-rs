# CLAUDE.md — Project Guide for Claude Code

This file provides context for Claude Code when working on the openHiTLS-rs codebase.

## Project Overview

openHiTLS-rs is a pure Rust rewrite of [openHiTLS](https://gitee.com/openhitls/openhitls) (C implementation), providing production-grade cryptographic primitives and TLS protocol support.

- **Language**: Rust (MSRV 1.75, edition 2021)
- **License**: MulanPSL-2.0
- **Status**: Phase 79 complete + Testing-Phase 85 — aead/crypt/alert/signing/config unit tests (2397 tests)

## Workspace Structure

```
openhitls-rs/
├── crates/
│   ├── hitls-types/     # Shared types: algorithm IDs, error enums
│   ├── hitls-utils/     # ASN.1, Base64, PEM, OID utilities
│   ├── hitls-bignum/    # Big number arithmetic (Montgomery, Miller-Rabin)
│   ├── hitls-crypto/    # All cryptographic algorithms (feature-gated); hardware AES acceleration (ARMv8/x86-64); ECC: P-192, P-224, P-256, P-384, P-521, Brainpool P-256r1/P-384r1/P-512r1; Curve448: Ed448, X448; DRBG: HMAC/CTR/Hash; SM4-CCM; HCTR mode; CBC-MAC-SM4; FIPS/CMVP (KAT, PCT, integrity); Entropy health testing (NIST SP 800-90B, RCT+APT); Wycheproof test vectors (603 tests + 15 Wycheproof)
│   ├── hitls-tls/       # TLS 1.3 key schedule, record encryption, client & server handshake, PSK/session tickets, 0-RTT early data, post-handshake client auth, hybrid KEM (X25519MLKEM768), async I/O (tokio), TLS 1.3 SM4-GCM/CCM (RFC 8998) + AES_128_CCM_8_SHA256, RFC 5705/8446 key material export, early exporter master secret (RFC 8446 §7.5), TLS 1.2 handshake (ECDHE/RSA/DHE_RSA/DHE_DSS/DH_ANON/ECDH_ANON/PSK/DHE_PSK/RSA_PSK/ECDHE_PSK key exchange, GCM/CBC/ChaCha20/CCM/CCM_8, ALPN, SNI, session resumption, session ticket (RFC 5077), EMS (RFC 7627), ETM (RFC 7366), renegotiation (RFC 5746), mTLS, Bleichenbacher protection, AES-CCM (RFC 6655/7251), AES-CCM_8 (8-byte tag), PSK+CCM, PSK CBC-SHA256/SHA384 (RFC 5487), ECDHE_PSK GCM (draft-ietf-tls-ecdhe-psk-aead), DHE_DSS (RFC 5246), DH_ANON/ECDH_ANON (RFC 5246/4492), OCSP stapling CertificateStatus), hostname verification (RFC 6125), cert chain validation (CertificateVerifier), CertVerifyCallback + SniCallback, ConnectionInfo APIs, graceful shutdown (close_notify tracking), server-side session cache (Arc<Mutex<dyn SessionCache>>), client-side session cache (auto-store/auto-lookup by server_name), session TTL expiration, cipher_server_preference config, write record fragmentation (auto-split by max_fragment_size), KeyUpdate loop protection (128 consecutive limit), Max Fragment Length (RFC 6066, TLS 1.2 client/server negotiation), Signature Algorithms Cert (RFC 8446 §4.2.3, TLS 1.3 ClientHello + server parsing), Certificate Authorities (RFC 8446 §4.2.4, codec + config + TLS 1.3 ClientHello + server parsing), PADDING (RFC 7685, codec + config + TLS 1.3 ClientHello), OID Filters (RFC 8446 §4.2.5, codec + config + TLS 1.3 CertificateRequest), Trusted CA Keys (RFC 6066 §6, type 3, codec + config + ClientHello), USE_SRTP (RFC 5764, type 14, codec + config + ClientHello), STATUS_REQUEST_V2 (RFC 6961, type 17, codec + config + ClientHello), DTLS 1.2 (RFC 6347, session cache auto-store, abbreviated handshake/session resumption, async I/O), Heartbeat extension (RFC 6520, type 15, codec + config, negotiation only), GREASE (RFC 8701, ClientHello cipher suites/extensions/versions/groups/sig_algs/key_share), TLCP (GM/T 0024), DTLCP (DTLS+TLCP), custom extensions framework, NSS key logging, Record Size Limit (RFC 8449), Fallback SCSV (RFC 7507), OCSP stapling, SCT, Ed448/X448 signing + key exchange, TLS 1.2 PRF, MsgCallback/InfoCallback/RecordPaddingCallback/DhTmpCallback/CookieGenCallback/CookieVerifyCallback/ClientHelloCallback, flight_transmit_enable, empty_records_limit (DoS protection) (913 tests)
│   ├── hitls-pki/       # X.509 (parse, verify [RSA/ECDSA/Ed25519/Ed448/SM2/RSA-PSS], chain, CRL, OCSP, CSR generation, Certificate generation, to_text output, SigningKey abstraction, EKU/SAN/AKI/SKI/AIA/NameConstraints/CertificatePolicies enforcement, hostname verification (RFC 6125)), PKCS#12 (RFC 7292), CMS SignedData (Ed25519/Ed448, SKI signer lookup, RSA-PSS, noattr, detached mode) + EnvelopedData + EncryptedData + DigestedData + AuthenticatedData (RFC 5652 §9, HMAC-SHA-256/384/512), PKCS#8 (RFC 5958, Ed448/X448), SPKI public key parsing (341 tests, 1 ignored)
│   ├── hitls-auth/      # HOTP/TOTP (RFC 4226/6238), SPAKE2+ (RFC 9382, P-256), Privacy Pass (RFC 9578, RSA blind sigs) (33 tests)
│   └── hitls-cli/       # Command-line tool (dgst, genpkey, x509, verify, enc, pkey, crl, req, s-client, s-server, list, rand, pkeyutl, speed, pkcs12, mac)
├── tests/interop/       # Integration tests (122 cross-crate tests, 3 ignored)
├── tests/vectors/       # Standard test vectors (Wycheproof JSON)
├── fuzz/                # Fuzz targets (cargo-fuzz, 10 targets)
└── benches/             # Performance benchmarks
```

## Build & Test Commands

```bash
# Build
cargo build --workspace --all-features

# Run all tests (2397 tests, 40 ignored)
cargo test --workspace --all-features

# Run tests for a specific crate
cargo test -p hitls-crypto --all-features   # 603 tests (31 ignored) + 15 Wycheproof
cargo test -p hitls-tls --all-features      # 1036 tests
cargo test -p hitls-pki --all-features      # 341 tests (1 ignored)
cargo test -p hitls-bignum                  # 49 tests
cargo test -p hitls-utils                   # 53 tests
cargo test -p hitls-auth --all-features     # 33 tests
cargo test -p hitls-cli --all-features      # 117 tests (5 ignored)
cargo test -p hitls-integration-tests       # 122 tests (3 ignored)

# Lint (must pass with zero warnings)
RUSTFLAGS="-D warnings" cargo clippy --workspace --all-features --all-targets

# Format check
cargo fmt --all -- --check
```

## Code Style & Conventions

### Formatting
- `rustfmt.toml`: max_width=100, use_field_init_shorthand, use_try_shorthand
- `clippy.toml`: cognitive-complexity-threshold=30
- Always run `cargo fmt` before committing
- **Sync before task**: Before starting any implementation task, always pull the latest remote main branch first (`git pull origin main`) to ensure the local codebase is up to date

### Error Handling
- Use `hitls_types::CryptoError` for all crypto errors (thiserror-based)
- Return `Result<T, CryptoError>` from all public APIs
- Never panic in library code; use `Result` instead

### Security Patterns
- **Zeroize on drop**: All secret material (keys, intermediate states) must implement `Zeroize` via `#[derive(Zeroize)]` and `#[zeroize(drop)]`
- **Constant-time comparisons**: Use `subtle::ConstantTimeEq` for cryptographic comparisons, never `==`
- **No unsafe code** in `hitls-types`, `hitls-utils`, and most crates. Only `hitls-bignum` and `hitls-crypto` may use unsafe (for SIMD, etc.)
- **Random generation**: Use `getrandom` crate, never `rand`

### Feature Flags
- `hitls-crypto` uses feature flags for algorithm selection
- Default features: `aes`, `sha2`, `rsa`, `ecdsa`, `hmac`
- Each algorithm module is gated by `#[cfg(feature = "...")]` in `lib.rs`
- Feature dependencies are declared in `Cargo.toml` (e.g., `hkdf = ["hmac"]`)

### API Patterns
- **SHA-256**: `Sha256::new()`, `.update(data)?`, `.finish()? -> [u8; 32]` (returns array, not `finish(&mut [u8])`)
- **HMAC**: `Hmac::new(factory, key)?`, `.update(data)?`, `.finish(&mut out)?` (writes to buffer)
- **HMAC Digest trait**: `finish(&mut self, out: &mut [u8])` pattern (different from SHA-256 direct API)
- **BigNum**: `BigNum::from_bytes_be()`, `.to_bytes_be()`, `.mod_exp()`, `.mod_inv()`, `.gcd()` — all return `Result`
- **X25519**: `X25519PrivateKey::new(bytes)` applies clamping; `.diffie_hellman(&pub_key)? -> Vec<u8>`

### Test Conventions
- Use standard test vectors from RFCs/NIST where available
- Slow tests (prime generation, keygen) are marked `#[ignore]`
- Hex helper functions: `fn hex(s: &str) -> Vec<u8>` and `fn to_hex(bytes: &[u8]) -> String`
- Tests live in `#[cfg(test)] mod tests` within each module file

### Post-Task Documentation Updates
After completing each implementation task (phase/feature), **always** update the following files:
- `DEV_LOG.md` — Add a new phase entry with summary, files modified, implementation details, test counts, and build status
- `PROMPT_LOG.md` — Record the prompt and result for the phase
- `CLAUDE.md` — Update status line, test counts, hitls-tls feature list, and completed phases list
- `README.md` — Update feature list, test counts, and any new module descriptions as needed

## C Reference Code

The original C implementation is at `/Users/dongqiu/Dev/code/openhitls/`:
- Crypto algorithms: `crypto/` directory
- Algorithm IDs: `include/crypto/crypt_algid.h`
- Error codes: `include/crypto/crypt_errno.h`
- TLS protocol: `tls/` directory (~63K lines)
- PKI/X.509: `pki/` directory (~18K lines)

## Migration Roadmap

Phases 0-79 complete (2397 tests, 40 ignored).

### Completed
- Phase 40: Async I/O (tokio) + Hardware AES Acceleration (ARMv8/x86-64) + Criterion Benchmarks -- DONE
- Phase 41: DTLCP + Custom Extensions + Key Logging -- DONE
- Phase 42: Wycheproof (5000+ vectors) + Fuzzing (10 targets) + Security Audit -- DONE
- Phase 43: Feature Completeness (PKI text output, TLS 1.3 SM4-GCM/CCM, CMS EnvelopedData, Privacy Pass, CLI commands) -- DONE
- Phase 44: Remaining Features (NistP192, HCTR mode, CMS EncryptedData) -- DONE
- Phase 45: Complete DH Groups + TLS FFDHE Expansion (all 13 DH groups, FFDHE6144/8192 in TLS) -- DONE
- Phase 46: FIPS/CMVP Compliance Framework (KAT self-tests, FIPS state machine, PCT, integrity check, feature-gated) -- DONE
- Phase 47: CLI Enhancements + CMS DigestedData (pkcs12/mac CLI commands, CMS DigestedData RFC 5652 §5) -- DONE
- Phase 48: Entropy Health Testing (NIST SP 800-90B RCT+APT, entropy pool, conditioning, noise source trait, DRBG/FIPS integration) -- DONE
- Phase 49: Ed448 / X448 / Curve448 (GF(2^448-2^224-1) field, Edwards a=1 d=-39081 curve, RFC 8032 Ed448 sign/verify with SHAKE256+dom4, RFC 7748 X448 DH, TLS integration) -- DONE
- Phase 50: Test Coverage + CMS Ed25519/Ed448 + enc CLI + TLS 1.2 OCSP/SCT (alert/session/record tests, CMS EdDSA signing/verification, multi-cipher enc CLI, TLS 1.2 CertificateStatus message) -- DONE
- Phase 51: C Test Vectors Porting + CMS Real File Tests + PKCS#12 Interop (52 new PKI tests: chain verification with real certs, CMS real file parsing/verification, PKCS#12 interop, cert parsing edge cases) -- DONE
- Phase 52: X.509 Extension Parsing + EKU/SAN/AKI/SKI Enforcement + CMS SKI Lookup (39 new PKI tests: typed extension parsing for EKU/SAN/AKI/SKI/AIA/NameConstraints, EKU enforcement in chain verifier, AKI/SKI issuer matching, CMS SKI signer lookup, Name Constraints enforcement) -- DONE
- Phase 53: C Test Vectors Round 2 + CertificatePolicies + CMS Chain/NoAttr Tests (56 new PKI tests: AKI/SKI chain matching suite, extension edge cases, cert parsing edge cases, CertificatePolicies extension, CMS noattr verification, CMS RSA-PSS support, sig param consistency, CSR parse/verify from C vectors) -- DONE
- Phase 54: PKI Signature Coverage + OCSP/CRL Testing + CMS Error Paths (41 new PKI tests: Ed448/SM2/RSA-PSS verify in cert/CRL/OCSP, OCSP verify_signature tests, CRL DER test vectors from C, CMS EnvelopedData error paths, text/PKCS#12/chain test quality) -- DONE
- Phase 55: TLS RFC 5705 Key Export + CMS Detached Sign + pkeyutl Completeness (24 new tests: TLS 1.3/1.2 export_keying_material RFC 5705/8446 §7.5, CMS detached SignedData, PKCS#8 Ed448/X448, SPKI parsing, pkeyutl derive X25519/X448/ECDH + sign/verify ECDSA/Ed448/RSA-PSS) -- DONE
- Phase 56: Integration Test Expansion + TLCP Public API + Code Quality (30 new tests: ML-KEM panic→Result fix, TLCP public handshake-in-memory API, 5 DTLS 1.2 integration tests, 4 TLCP integration tests, 3 DTLCP integration tests, 4 mTLS integration tests, 12 TLS 1.3 server unit tests) -- DONE
- Phase 57: Unit Test Coverage Expansion (40 new tests: X25519 RFC 7748 §5.2 iterated vectors, HKDF from_prk/error paths, SM3/SM4 incremental+1M iteration vectors, Base64 negative tests, PEM negative tests, anti-replay window edge cases, TLS 1.2 client12 wrong-state/KX/ticket tests, DTLS 1.2 client HVR/wrong-state tests, DTLS 1.2 server cookie retry/wrong-cookie tests) -- DONE
- Phase 58: Unit Test Coverage Expansion (36 new tests: Ed25519 RFC 8032 vectors + error paths, ECDSA negative cases, ASN.1 decoder negative tests, HMAC RFC 2202/4231 vectors, ChaCha20-Poly1305 edge cases, TLS 1.3 client wrong-state tests, TLS 1.2 server wrong-state tests) -- DONE
- Phase 59: Unit Test Coverage Expansion (35 new tests: CFB/OFB/ECB/XTS cipher mode edge cases, ML-KEM failure/implicit rejection, ML-DSA corruption/wrong key, DRBG reseed divergence, SipHash key validation, GMAC/CMAC NIST vectors + error paths, SHA-1 reset/million-a, scrypt/PBKDF2 validation, TLS transcript hash SHA-384/replace_with_message_hash) -- DONE
- Phase 60: Unit Test Coverage Expansion (36 new tests: CTR invalid nonce/key + AES-256 NIST vector, CCM nonce/tag validation + tampered tag, AES Key Wrap short/non-aligned/corrupted + RFC 3394 §4.6, GCM invalid key + AES-256 NIST Case 14 + empty-pt-with-AAD, DSA wrong key/public-only/different digest, HPKE tampered ct/wrong AAD/PSK roundtrip/empty PSK rejection, HybridKEM cross-key/ct-length/multiple-encap, SM3 reset-reuse/block-boundary, Entropy zero-len/large/multiple-small/disabled-health/pool-min-capacity/partial-pop/RCT-reset, Privacy Pass wrong-challenge/empty-key/wire-roundtrip) -- DONE
- Phase 61: Unit Test Coverage Expansion (34 new tests: RSA cross-padding/OAEP-length/cross-key, ECDH zero/large/format/self-DH, SM2 public-only sign/decrypt + corrupted sig, ElGamal truncated/tampered ct, Paillier invalid-ct/triple-homomorphic, ECC scalar-mul-zero/point-add-negate, MD5 reset/boundary, SM4 consecutive-roundtrip/all-FF, SHA-256 reset/SHA-384 incremental/SHA-512 boundary, SHA-3 reset/SHAKE multi-squeeze, AES invalid-block-length, BigNum div-by-one/sqr-mul-consistency, HOTP empty-secret/1-digit/TOTP-boundary, SPAKE2+ setup-before-generate/empty-password/invalid-share) -- DONE
- Phase 62: TLS 1.2 CCM Cipher Suites (8 new tests: 6 AES-CCM suites per RFC 6655/7251 — TLS_RSA_WITH_AES_128/256_CCM, TLS_DHE_RSA_WITH_AES_128/256_CCM, TLS_ECDHE_ECDSA_WITH_AES_128/256_CCM, AesCcmAead adapter, 3 AEAD + 5 record layer tests) -- DONE
- Phase 63: CCM_8 + PSK+CCM Cipher Suites (RFC 6655, TLS 1.3 AES_128_CCM_8_SHA256 0x1305, 2 TLS 1.2 CCM_8 suites, 4 TLS 1.2 PSK+CCM suites, AesCcm8Aead adapter) -- DONE
- Phase 64: PSK CBC-SHA256/SHA384 + ECDHE_PSK GCM Cipher Suites (RFC 5487 + draft-ietf-tls-ecdhe-psk-aead, 8 new suites: PSK/DHE_PSK/RSA_PSK CBC-SHA256/SHA384, ECDHE_PSK GCM-SHA256/SHA384) -- DONE
- Phase 65: PSK CCM completion + CCM_8 authentication cipher suites (10 new suites: PSK AES_128_CCM/AES_128+256_CCM_8, DHE_PSK AES_128+256_CCM_8, ECDHE_PSK AES_128_CCM_8_SHA256, DHE_RSA AES_128+256_CCM_8, ECDHE_ECDSA AES_128+256_CCM_8, +11 tests) -- DONE
- Phase 66: DHE_DSS cipher suites (6 new suites: DHE_DSS_WITH_AES_128/256_CBC_SHA, DHE_DSS_WITH_AES_128/256_CBC_SHA256, DHE_DSS_WITH_AES_128_GCM_SHA256/AES_256_GCM_SHA384, AuthAlg::Dsa, DSA_SHA256/SHA384 signature schemes, ServerPrivateKey::Dsa, +8 tests) -- DONE
- Phase 67: DH_ANON + ECDH_ANON cipher suites (8 new suites: DH_ANON_WITH_AES_128/256_CBC_SHA, DH_ANON_WITH_AES_128/256_CBC_SHA256, DH_ANON_WITH_AES_128_GCM_SHA256/AES_256_GCM_SHA384, ECDH_ANON_WITH_AES_128/256_CBC_SHA, KeyExchangeAlg::DheAnon/EcdheAnon, AuthAlg::Anon, unsigned ServerKeyExchange codec, anonymous handshake flow, +10 tests) -- DONE
- Phase 68: TLS 1.2 renegotiation (RFC 5746) (HelloRequest message type + codec, NoRenegotiation alert, allow_renegotiation config, reset_for_renegotiation() for client/server, RFC 5746 renegotiation_info with verify_data validation, re-handshake over encrypted connection, server renegotiation_info in initial ServerHello fix, sync + async paths, +10 tests) -- DONE
- Phase 69: Connection info APIs + graceful shutdown + ALPN completion (ConnectionInfo struct with peer certs/ALPN/SNI/named group/verify_data, TLS 1.3 ALPN client+server, TLS 1.2 client ALPN parsing, close_notify tracking, graceful shutdown, public getters on all 8 connection types, sync + async paths, +8 tests) -- DONE
- Phase 70: Hostname verification + cert chain validation + SNI callback (RFC 6125 hostname verification (SAN/CN matching, wildcards, IP addresses), cert chain validation via CertificateVerifier (trusted_certs), CertVerifyCallback for custom verification override, SniCallback for server-side certificate selection by hostname, verify_hostname config (default: true), wired into all 5 client handshake paths (TLS 1.2/1.3/DTLS/TLCP/DTLCP), +15 tests) -- DONE
- Phase 71: Server-side session cache + session expiration + cipher preference (Arc<Mutex<dyn SessionCache>> in TlsConfig, auto-store after full handshake, auto-lookup on ClientHello, InMemorySessionCache TTL expiration (default 2h), cleanup(), cipher_server_preference config (default: true, toggle client preference), wired into sync+async TLS 1.2 server + renegotiation paths, TLS 1.3 cipher preference, +13 tests) -- DONE
- Phase 72: Client-side session cache + write record fragmentation (client auto-store sessions after handshake/NST, auto-lookup from cache by server_name, explicit resumption_session takes priority, TLS 1.2 session_resumption flag guard, write() auto-splits data into max_fragment_size chunks, all 8 connection types (4 sync + 4 async), +12 tests) -- DONE
- Testing-Phase 72: CLI command unit tests + Session Cache concurrency (dgst/x509cmd/genpkey/pkey/req/crl/verify: +66 tests covering hash algorithms, cert operations, key generation, CSR generation, CRL display, cert verification; Session Cache Arc<Mutex<>> concurrency: +6 tests covering concurrent puts/gets/eviction/trait-object usage, total +72 tests, 1892→1964) -- DONE
- Phase 73: KeyUpdate loop protection + Max Fragment Length (RFC 6066) + Signature Algorithms Cert (RFC 8446 §4.2.3) (key_update_recv_count counter with 128-limit DoS protection, MaxFragmentLength enum + codec + TLS 1.2 client/server negotiation + record layer enforcement, signature_algorithms_cert codec + TLS 1.3 ClientHello building + server parsing, all sync + async paths, +13 tests) -- DONE
- Testing-Phase 73: Async TLS 1.3 unit tests + cipher suite integration (connection_async.rs: +12 tests covering read/write before handshake, full handshake+data, version/cipher check, shutdown, 32KB payload, multi-message, key_update, take_session, connection_info, ALPN, session_resumed; cipher suite integration: +21 TCP loopback tests covering ECDHE_ECDSA CCM/CCM_8, DHE_RSA CCM/CCM_8, PSK/DHE_PSK/ECDHE_PSK GCM+CCM+ChaCha20, DH_ANON/ECDH_ANON GCM+CBC, TLS 1.3 AES256-GCM/ChaCha20/CCM_8/RSA-cert, total +33 tests, 1988→2021) -- DONE
- Phase 74: Certificate Authorities extension (RFC 8446 §4.2.4) + Early Exporter Master Secret (RFC 8446 §7.5) + DTLS 1.2 session cache (certificate_authorities codec + config + TLS 1.3 ClientHello + server parsing, early exporter master secret derivation + export_early_keying_material() API on all 4 TLS 1.3 connections, DTLS 1.2 session cache auto-store by server_name/session_id, +15 tests) -- DONE
- Testing-Phase 74: Fuzz seed corpus + error scenario integration tests (C1: 66 binary seed files across all 10 fuzz targets in fuzz/corpus/<target>/; C2: +18 integration tests covering version mismatch, cipher suite mismatch, PSK wrong key, ALPN negotiation, 5 concurrent TLS 1.3/1.2 connections, 64KB payload fragmentation, ConnectionInfo field validation, session_resumed checks, multi-message exchange, graceful shutdown, multi-suite negotiation, empty write, total +18 tests, 2036→2054) -- DONE
- Testing-Phase 75: Phase 74 feature integration tests + async export unit tests (E1: +10 integration tests covering certificate_authorities config handshake, export_keying_material client/server match + different labels + before handshake + various lengths + server-side, export_early_keying_material no-PSK error, TLS 1.2 export_keying_material match, TLS 1.2 session cache + ticket resumption; E2: +6 async unit tests covering export_keying_material before handshake, early export no-PSK, both-sides match, different labels, CA config, deterministic, total +16 tests, 2054→2070) -- DONE
- Phase 75: PADDING extension (RFC 7685) + OID Filters (RFC 8446 §4.2.5) + DTLS 1.2 abbreviated handshake (PADDING type 21 codec + config padding_target + TLS 1.3 ClientHello integration, OID Filters type 48 codec + config oid_filters + TLS 1.3 CertificateRequest, DTLS 1.2 abbreviated handshake: session cache lookup + abbreviated flow (server CCS+Finished first) mirroring TLS 1.2, +15 tests, 2070→2085) -- DONE
- Phase 76: Async DTLS 1.2 + Heartbeat extension (RFC 6520) + GREASE (RFC 8701) (AsyncDtls12ClientConnection + AsyncDtls12ServerConnection with full/abbreviated handshake, read/write/shutdown, anti-replay, session cache; Heartbeat type 15 codec + config heartbeat_mode; GREASE config flag + ClientHello injection into cipher suites/extensions/groups/sig_algs/key_share, +19 tests, 2086→2105) -- DONE
- Testing-Phase 76: cert_verify unit tests + config callbacks + integration tests (cert_verify module with 7 unit tests, config callback tests for CertVerifyCallback/SniCallback/cert_verify_callback, 19 integration tests covering cipher suites/ALPN/SNI/session resumption/mTLS/renegotiation/key export/DTLS, +26 tests, 2105→2131) -- DONE
- Testing-Phase 77: SniCallback + PADDING + OID Filters + DTLS abbreviated + PskServerCallback integration tests (+13 tests, 2131→2144) -- DONE
- Testing-Phase 78: GREASE + Heartbeat + Async DTLS edge cases + extension codec negative tests (+22 tests, 2144→2166) -- DONE
- Testing-Phase 79: DTLS 1.2 handshake + TLS 1.3 server + record layer + PRF unit tests (DTLS 1.2 server: abbreviated via cache, wrong-state CKE/Finished/abbreviated-Finished/CH-with-cookie, message_seq, dtls_get_body; DTLS 1.2 client: wrong-state cert/SKE/SHD/Finished/abbreviated-Finished, non-abbreviated session mismatch, empty cert rejected, dtls_get_body; TLS 1.3 server: SECP256R1 key share, no common suite, server cipher preference, HRR wrong group retry; Record layer: multi-record parse, TLS 1.2 AEAD/CBC roundtrip, cipher mode switch; PRF: zero/large output, cross-hash, empty secret, seed uniqueness, +28 tests, 2166→2194) -- DONE
- Testing-Phase 80: TLCP server + transcript + key_schedule12 + cert_verify + TLS 1.3 client + session unit tests (TLCP server: wrong-state CKE/CCS/Finished, suite negotiation no match, Finished too short; Transcript: binary data, double replace, fresh hash, update after replace; Key schedule 1.2: server verify_data label, EMS→key block pipeline, deterministic, CCM suite; Cert verify: CN hostname match, multiple trusted certs, wrong trusted cert, callback hostname error; TLS 1.3 client: ALPN in CH, SNI in CH, sig_algs_cert, certificate_authorities; Session: ALPN not serialized, ticket lifetime roundtrip, EMS flag roundtrip, +24 tests, 2194→2218) -- DONE
- Phase 77: TLS callback framework + missing alert codes + CBC-MAC-SM4 (7 TLS callbacks: MsgCallback/InfoCallback/RecordPaddingCallback/DhTmpCallback/CookieGenCallback/CookieVerifyCallback/ClientHelloCallback + ClientHelloInfo/ClientHelloAction, 6 legacy alert codes added to AlertDescription, CBC-MAC-SM4 with zero-padding (feature-gated cbc-mac), record_padding_cb wired into TLS 1.3 encryption, cookie callbacks wired into DTLS/DTLCP, client_hello_callback wired into TLS 1.3/1.2 server, +21 tests, 2218→2239) -- DONE
- Phase 78: Trusted CA Keys (RFC 6066 §6) + USE_SRTP (RFC 5764) + STATUS_REQUEST_V2 (RFC 6961) + CMS AuthenticatedData (RFC 5652 §9) (Trusted CA Keys type 3 codec + config trusted_ca_keys + ClientHello TLS 1.3/1.2, USE_SRTP type 14 codec + config srtp_profiles + ClientHello TLS 1.3/1.2, STATUS_REQUEST_V2 type 17 codec + config enable_ocsp_multi_stapling + ClientHello TLS 1.3/1.2, CMS AuthenticatedData parse/encode/create/verify with HMAC-SHA-256/384/512, +17 tests, 2239→2256) -- DONE
- Phase 79: DTLS config enhancements + integration tests (flight_transmit_enable + empty_records_limit DoS protection in RecordLayer, 9 integration tests covering MsgCallback TLS 1.3/1.2 + InfoCallback + ClientHelloCallback + CBC-MAC-SM4 + CMS AuthenticatedData + RecordPaddingCallback + DTLS config + empty records limit, +18 tests, 2256→2274) -- DONE
- Testing-Phase 81: client_tlcp + cipher suite params + verify Ed448 + HKDF edge cases (TLCP client: wrong-state ServerHello/Certificate/SKE/SHD/CCS/Finished, no TLCP suites error; Cipher suite params: TLS 1.3 AES-128-GCM/AES-256-GCM/ChaCha20/CCM_8/invalid/hash_factory SHA-256/SHA-384, TLS 1.2 CBC-SHA/PSK-GCM/invalid/DHE-RSA-GCM; Verify: Ed448 roundtrip/wrong sig, Ed25519 client context; HKDF: empty info expand, SHA-384 expand_label, empty data HMAC, exact hash length expand, +25 tests, 2274→2299) -- DONE
- Testing-Phase 82: codec/server12/client12/dtls12/config unit tests (Codec: decode_server_hello too short version/random, decode_client_hello too short/odd suites, decode_key_update invalid; Server12: abbreviated_finished wrong state, cert_verify wrong state, build_new_session_ticket no key/with key no master; Client12: CCS wrong state, abbreviated_finished wrong state, cert_request wrong state, process_finished wrong state, new_session_ticket lifetime zero; DTLS 1.2: version/cipher_suite/bidirectional/is_connected/multiple_sequential; Config: role setter, builder long chain, default cipher_suites/groups/sig_algs non-empty, +24 tests, 2299→2323) -- DONE
- Testing-Phase 83: session/client/server/async/dtls12-async unit tests (Session: cleanup noop zero lifetime, encrypt/decrypt ticket wrong key length, decode without EMS byte, cleanup fresh sessions; TLS 1.3 client: accessors after init, heartbeat extension, supported_groups extension, new_session_ticket no params, process_finished wrong state; TLS 1.3 server: accessors after init, process_finished wrong state, process_hello_retry wrong state, rejects TLS1.2-only supported_versions, ALPN no match; Async TLS 1.3: key_update request_response, export zero length, server export before handshake, accessor methods, different contexts export; Async DTLS 1.2: take_session returns none, server_name accessor, is_session_resumed first handshake, peer_certificates empty, bidirectional data, +25 tests, 2323→2348) -- DONE
- Testing-Phase 84: record/extensions/export/codec/connection unit tests (Record: EtM seal+open roundtrip, CCS passthrough with active decryptor, empty encrypted record rejected, record size limit boundary; Extensions: type constants, context flag values, wrong context ignored, empty received, zero context contains nothing; Export: non-UTF-8 label rejected, different randoms differ, different secrets differ, early export forbidden label, context affects output; Codec: GREASE key_share includes real entry, parse_extensions truncated/empty, parse_pre_shared_key_ch truncated, parse_alpn_sh list length mismatch; Connection: take_session before handshake, connection_info before handshake, accessors before handshake, queue_early_data+accepted, server key_update before connected, +24 tests, 2348→2372) -- DONE
- Testing-Phase 85: aead/crypt/alert/signing/config unit tests (AEAD: AES-GCM/CCM/CCM8 invalid key length, tag_size consistency, GCM decrypt wrong nonce; Crypt: NamedGroup is_kem variants, KeyExchangeAlg is_psk/requires_certificate all variants, TLS 1.2 CBC is_cbc flag, TLS 1.3 hash_factory output size; Alert: level from_u8 all invalid, description undefined gaps, clone+copy, to_bytes roundtrip, TLS 1.3 specific codes; Signing: DSA rejected, empty client list, Ed448 roundtrip, DSA sign rejected, RSA wrong scheme; Config: last setter wins, verify_hostname default, empty_records_limit custom, multiple trusted_certs, version range combinations, +25 tests, 2372→2397) -- DONE

See `DEV_LOG.md` for detailed implementation history and `PROMPT_LOG.md` for prompt/response log.
