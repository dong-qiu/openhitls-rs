// Phase J-4 — CMVP (FIPS 140 self-test + integrity) migration.
//
// Source: openHiTLS C SDV cmvp/test_suite_sdv_cmvp.data + .c
//         (SDV_CRYPTO_CMVP_SELFTEST_TC* + SDV_CRYPTO_CMVP_INTEGRITY_TC*).
//
// The C CMVP suite has **empty data rows** + `(void)` test bodies — it is not a
// data-driven KAT suite. It exercises the EAL CMVP self-test framework:
//   - SELFTEST_TC*  : per-algorithm `CRYPT_CMVP_SelftestMac/Md/...(alg) == true`
//                     for the FIPS-approved set, `== false` for MAX / -1.
//   - INTEGRITY_TC* : `CMVP_CheckIntegrity(...)` succeeds (TC001) / fails on a
//                     tampered or missing integrity file (TC002-006).
//
// The Rust `hitls_crypto::fips` module exposes the self-test at the **aggregate**
// level (`FipsModule::run_self_tests()` runs the internal KAT + PCT suite over
// SHA-256 / HMAC-SHA256 / AES-128-GCM / HMAC-DRBG / HKDF / ECDSA-P256 / entropy
// — the same primitive families the C per-algorithm `Selftest*` calls cover) and
// the integrity check via `FipsModule::check_integrity(path, key, expected_hmac)`
// (HMAC-SHA256 over a file). There is no public per-algorithm `Selftest<alg>`
// entry point, so the C per-algorithm granularity (and the invalid-id `== false`
// rows) route to API-surface — the Rust port aggregates the self-tests. This
// migrates the CMVP suite's functional intent: self-tests pass + module reaches
// Operational, and the integrity check accepts a correct HMAC / rejects a
// tampered one or a missing file.

#![cfg(feature = "fips")]

use hitls_crypto::fips::{FipsModule, FipsState};
use hitls_crypto::hmac::Hmac;
use hitls_crypto::provider::Digest;
use hitls_crypto::sha2::Sha256;
use std::fs;
use std::path::PathBuf;

/// HMAC-SHA256(key, data) — mirrors what `check_integrity` computes over a file.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    Hmac::mac(|| -> Box<dyn Digest> { Box::new(Sha256::new()) }, key, data).unwrap()
}

/// Unique temp file path for one test (no `Date`/`rand` in this env — vary by
/// the caller-supplied tag).
fn temp_file(tag: &str, contents: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("hitls_cmvp_j4_{tag}.bin"));
    fs::write(&path, contents).unwrap();
    path
}

/// C SELFTEST_TC* aggregate: a fresh module starts PreOperational, runs the FIPS
/// self-test suite (KAT + PCT over the FIPS-approved primitive families), and
/// transitions to Operational. The internal KATs are the Rust analogue of the C
/// per-algorithm `CRYPT_CMVP_Selftest*(alg) == true` rows.
#[test]
fn tc_cmvp_selftest_aggregate_passes_module_operational() {
    let mut module = FipsModule::new();
    assert_eq!(module.state(), FipsState::PreOperational);
    assert!(!module.is_operational());

    module.run_self_tests().expect("FIPS self-tests must pass");

    assert_eq!(module.state(), FipsState::Operational);
    assert!(module.is_operational());
}

/// C INTEGRITY_TC001: integrity check succeeds when the expected HMAC matches
/// the module artifact. Here we compute HMAC-SHA256 over a known file with a
/// known key and assert `check_integrity` accepts it.
#[test]
fn tc_cmvp_integrity_check_success() {
    let key = b"cmvp-integrity-key";
    let contents = b"openHiTLS-rs FIPS module artifact bytes";
    let path = temp_file("ok", contents);
    let expected = hmac_sha256(key, contents);

    let mut module = FipsModule::new();
    let res = module.check_integrity(path.to_str().unwrap(), key, &expected);
    fs::remove_file(&path).ok();
    res.expect("integrity check must succeed for the correct HMAC");
}

/// C INTEGRITY_TC002-006 (file error / tampered): a wrong expected HMAC must
/// make the integrity check fail.
#[test]
fn tc_cmvp_integrity_check_tampered_hmac_fails() {
    let key = b"cmvp-integrity-key";
    let contents = b"openHiTLS-rs FIPS module artifact bytes";
    let path = temp_file("tampered", contents);
    let mut expected = hmac_sha256(key, contents);
    expected[0] ^= 0x01; // flip one byte of the expected HMAC

    let mut module = FipsModule::new();
    let res = module.check_integrity(path.to_str().unwrap(), key, &expected);
    fs::remove_file(&path).ok();
    assert!(res.is_err(), "integrity check must reject a tampered HMAC");
}

/// C INTEGRITY file-error: a missing module file must make the check fail.
#[test]
fn tc_cmvp_integrity_check_missing_file_fails() {
    let key = b"cmvp-integrity-key";
    let missing = std::env::temp_dir().join("hitls_cmvp_j4_does_not_exist.bin");
    fs::remove_file(&missing).ok();
    let bogus = hmac_sha256(key, b"");

    let mut module = FipsModule::new();
    let res = module.check_integrity(missing.to_str().unwrap(), key, &bogus);
    assert!(res.is_err(), "integrity check must fail for a missing file");
}
