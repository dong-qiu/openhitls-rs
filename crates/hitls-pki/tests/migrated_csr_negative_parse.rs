//! CSR (PKCS#10 / RFC 2986) negative-parse tests — T188 (#44).
//!
//! Inspired by `openhitls/testcode/sdv/testcase/pki/csr/test_suite_sdv_x509_csr.{c,data}`.
//! The C `.data` file has ~100 row labels covering ~14 TC families, mostly
//! POSITIVE round-trips across algorithm variants (RSA/ECDSA/Ed25519/SM2/ML-DSA
//! × multiple hashes). The truly negative subset is small and clusters around
//! a handful of failure categories:
//!
//! - bad signature value (bit-flip)
//! - unsupported signature algorithm OID
//! - missing / malformed Subject DN
//! - truncated DER
//! - wrong CSR version (RFC 2986 requires v1 = INTEGER 0)
//! - wrong PEM block label
//! - garbage input
//!
//! We synthesise the malformed CSRs by building a valid one with
//! `CertificateRequestBuilder` and patching specific bytes (the same
//! methodology used in T186 rogue-server / T187 CRL signature tamper). This
//! gives byte-precise control without checking in dozens of binary fixtures.
//!
//! ## Coverage (negative categories per issue acceptance criteria)
//!
//! | Test | Failure category | C TC analogue | Asserted PkiError |
//! |------|------------------|---------------|-------------------|
//! | `csr_tampered_signature_fails_verify` | bad-sig | PARSE_FUNC TC tampered-sig | `verify_signature() == Ok(false)` |
//! | `csr_unsupported_signature_algorithm_rejected` | unsupported-alg | PARSE TC unknown OID | `InvalidCert("unsupported CSR signature algorithm")` |
//! | `csr_truncated_der_rejected` | truncated DER | PARSE_API TC short input | `Asn1Error` |
//! | `csr_garbage_bytes_rejected` | garbage | PARSE_API TC | `Asn1Error` |
//! | `csr_empty_input_rejected` | empty | PARSE_API TC NULL/0-len | `Asn1Error` |
//! | `csr_pem_wrong_block_label_rejected` | wrong PEM label | PARSE_FUNC TC PEM | `InvalidCert("no CERTIFICATE REQUEST block found")` |
//! | `csr_pem_no_block_rejected` | bare text | PARSE_FUNC TC bad PEM | `Asn1Error` or `InvalidCert(...)` |
//! | `csr_unknown_oid_after_bit_flip` | mutated alg OID | PARSE_FUNC TC | `InvalidCert("unsupported")` |
//! | `csr_valid_baseline_parses_and_verifies` | positive baseline | PARSE_FUNC TC valid | Ok + `verify_signature() == Ok(true)` |
//! | `csr_pem_roundtrip` | PEM positive | PARSE_FUNC TC PEM | Ok + verify_signature() == Ok(true) |
//!
//! Positive multi-algorithm round-trips (RSA-SHA384/512, ECDSA-SHA384/512,
//! Ed25519, SM2, RSA-PSS, ML-DSA) are NOT migrated here — the existing
//! `crates/hitls-pki/src/x509/mod.rs:1346-1413` unit tests already cover
//! them. This file specifically targets the negative attack-surface gap
//! flagged by issue #44.
//!
//! ## TODO(#44-strict-version)
//!
//! Today's parser accepts any value in the `version INTEGER` field and just
//! stashes it. RFC 2986 §4 says it MUST be 0. `csr_wrong_version_accepted_gap`
//! pins the gap; a future fix should enforce `version == 0` and flip the
//! assertion.

#![cfg(feature = "x509")]

use hitls_pki::x509::{
    CertificateRequest, CertificateRequestBuilder, DistinguishedName, SigningKey,
};
use hitls_types::PkiError;

// ---------------------------------------------------------------------------
// Test helpers — build a baseline valid CSR; produce bytes to mutate.
// ---------------------------------------------------------------------------

/// Build a valid Ed25519-signed CSR with a single-RDN Subject DN and no
/// extensions. Returns the parsed `CertificateRequest` and its DER bytes.
fn build_valid_ed25519_csr() -> (CertificateRequest, Vec<u8>) {
    let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
    let sk = SigningKey::Ed25519(kp);
    let dn = DistinguishedName {
        entries: vec![("CN".to_string(), "Test CSR #44".to_string())],
    };
    let csr = CertificateRequestBuilder::new(dn).build(&sk).unwrap();
    let der = csr.raw.clone();
    (csr, der)
}

/// Build a valid RSA-2048-SHA256-signed CSR.
fn build_valid_rsa_csr() -> (CertificateRequest, Vec<u8>) {
    let rsa = hitls_crypto::rsa::RsaPrivateKey::generate(2048).unwrap();
    let sk = SigningKey::Rsa(rsa);
    let dn = DistinguishedName {
        entries: vec![("CN".to_string(), "RSA CSR #44".to_string())],
    };
    let csr = CertificateRequestBuilder::new(dn).build(&sk).unwrap();
    let der = csr.raw.clone();
    (csr, der)
}

// ---------------------------------------------------------------------------
// Group 1: Positive baselines (keep close to negatives so regressions surface)
// ---------------------------------------------------------------------------

/// Positive baseline: a freshly-built CSR parses and self-verifies.
#[test]
fn csr_valid_baseline_parses_and_verifies() {
    let (csr_built, der) = build_valid_ed25519_csr();
    let csr_parsed = CertificateRequest::from_der(&der).expect("DER parse");
    assert_eq!(csr_parsed.subject.entries[0].1, "Test CSR #44");
    assert!(
        csr_parsed.verify_signature().unwrap(),
        "self-signature must verify"
    );
    // Also sanity-check the in-memory CSR's signature path.
    assert!(csr_built.verify_signature().unwrap());
}

/// PEM round-trip baseline.
#[test]
fn csr_pem_roundtrip() {
    let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
    let sk = SigningKey::Ed25519(kp);
    let dn = DistinguishedName {
        entries: vec![("CN".to_string(), "PEM CSR".to_string())],
    };
    let pem = CertificateRequestBuilder::new(dn)
        .build_pem(&sk)
        .expect("PEM build");
    assert!(pem.contains("-----BEGIN CERTIFICATE REQUEST-----"));
    let parsed = CertificateRequest::from_pem(&pem).expect("PEM parse");
    assert!(parsed.verify_signature().unwrap());
}

// ---------------------------------------------------------------------------
// Group 2: Negative — signature & algorithm path
// ---------------------------------------------------------------------------

/// Bad-signature category: build a valid CSR, flip a byte inside the
/// `signatureValue` BIT STRING. DER reparses cleanly but signature check
/// must fail.
#[test]
fn csr_tampered_signature_fails_verify() {
    let (_, mut der) = build_valid_ed25519_csr();
    let last = der.len() - 1;
    der[last] ^= 0xFF;
    let tampered = CertificateRequest::from_der(&der).expect("tampered DER still parses");
    assert!(
        !tampered.verify_signature().unwrap_or(true),
        "tampered signature must NOT verify"
    );
}

/// Unsupported-algorithm category: replace the Ed25519 signature OID
/// (`1.3.101.112` = DER tail `2B 65 70`) with an unknown OID
/// (`1.3.101.99` = `2B 65 63`). Parser accepts the wrong OID at DER level
/// but `verify_signature()` must reject the unsupported algorithm.
#[test]
fn csr_unsupported_signature_algorithm_rejected() {
    let (_, mut der) = build_valid_ed25519_csr();
    // The Ed25519 OID `06 03 2B 65 70` appears twice in an Ed25519 CSR:
    // once in SubjectPublicKeyInfo (inside TBS) and once in
    // signatureAlgorithm (outside TBS, after attributes). We want the
    // second occurrence (signature alg); use rposition.
    let needle: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
    let pos = (0..=der.len().saturating_sub(needle.len()))
        .rev()
        .find(|&i| &der[i..i + needle.len()] == needle)
        .expect("must find Ed25519 algorithm OID in CSR DER");
    // Turn 1.3.101.112 (Ed25519) into 1.3.101.99 (unassigned in this arc).
    der[pos + 4] = 0x63;
    let csr = CertificateRequest::from_der(&der).expect("DER still parses");
    let err = csr
        .verify_signature()
        .expect_err("unsupported algorithm must error");
    match err {
        PkiError::InvalidCert(ref m) if m.contains("unsupported") => {}
        other => panic!("expected InvalidCert(\"unsupported ...\"), got: {other:?}"),
    }
}

/// Mutated-OID twin of the above using RSA — flips a byte deep inside the
/// `sha256WithRSAEncryption` OID to produce an unknown OID.
#[test]
fn csr_unknown_oid_after_bit_flip() {
    let (_, mut der) = build_valid_rsa_csr();
    // sha256WithRSAEncryption = 1.2.840.113549.1.1.11
    // DER value: 2A 86 48 86 F7 0D 01 01 0B (9 bytes)
    let needle: &[u8] = &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
    ];
    let pos = der
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("must find sha256WithRSAEncryption OID");
    // Flip the trailing byte: 0x0B (11) → 0x7F (127, unassigned in this arc)
    der[pos + needle.len() - 1] = 0x7F;
    let csr = CertificateRequest::from_der(&der).expect("DER still parses");
    let err = csr
        .verify_signature()
        .expect_err("mutated OID → unsupported");
    match err {
        PkiError::InvalidCert(ref m) if m.contains("unsupported") => {}
        other => panic!("expected InvalidCert(\"unsupported ...\"), got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Group 3: Negative — structural DER errors
// ---------------------------------------------------------------------------

/// Truncated DER: cut the CSR in half.
#[test]
fn csr_truncated_der_rejected() {
    let (_, der) = build_valid_ed25519_csr();
    let half = &der[..der.len() / 2];
    let err = CertificateRequest::from_der(half).expect_err("truncated must fail");
    assert!(
        matches!(err, PkiError::Asn1Error(_)),
        "expected Asn1Error, got: {err:?}"
    );
}

/// Garbage bytes: random non-DER input.
#[test]
fn csr_garbage_bytes_rejected() {
    let garbage = [0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34];
    let err = CertificateRequest::from_der(&garbage).expect_err("garbage must fail");
    assert!(
        matches!(err, PkiError::Asn1Error(_)),
        "expected Asn1Error, got: {err:?}"
    );
}

/// Empty input.
#[test]
fn csr_empty_input_rejected() {
    let err = CertificateRequest::from_der(&[]).expect_err("empty input must fail");
    assert!(
        matches!(err, PkiError::Asn1Error(_)),
        "expected Asn1Error, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Group 4: Negative — PEM framing
// ---------------------------------------------------------------------------

/// Valid PEM frame but wrong block label.
#[test]
fn csr_pem_wrong_block_label_rejected() {
    let (_, der) = build_valid_ed25519_csr();
    // Encode the CSR bytes under a CERTIFICATE label (not "CERTIFICATE REQUEST").
    let wrong = hitls_utils::pem::encode("CERTIFICATE", &der);
    let err = CertificateRequest::from_pem(&wrong).expect_err("wrong label must fail");
    match err {
        PkiError::InvalidCert(ref m) if m.contains("CERTIFICATE REQUEST") => {}
        other => {
            panic!("expected InvalidCert(\"no CERTIFICATE REQUEST block found\"), got: {other:?}")
        }
    }
}

/// Bare text without any PEM headers at all.
#[test]
fn csr_pem_no_block_rejected() {
    let bare = "not a pem document at all\n";
    let result = CertificateRequest::from_pem(bare);
    assert!(result.is_err(), "bare text must fail to parse as CSR PEM");
}

// ---------------------------------------------------------------------------
// Group 5: Gap pins — RFC 2986 MUSTs Rust does not enforce today
// ---------------------------------------------------------------------------

/// RFC 2986 §4 says `version` MUST be `0` (v1). The Rust parser reads the
/// INTEGER but does not enforce the value. Pin the gap: flip the version
/// byte and confirm the parser still accepts.
///
/// The version INTEGER appears at the very start of the inner TBS
/// (CertificationRequestInfo) — after the outer SEQUENCE header + inner
/// SEQUENCE header. We locate `02 01 00` (INTEGER, len=1, value=0) early
/// in the DER and bump the value byte to 0x07 (an invalid v8).
///
/// TODO(#44-strict-version): reject CSRs with version != 0 per RFC 2986 §4.
#[test]
fn csr_wrong_version_accepted_gap() {
    let (_, mut der) = build_valid_ed25519_csr();
    // The first `02 01 00` after byte 4 (outer hdr) is the version field
    // inside CertificationRequestInfo.
    let pos = der
        .windows(3)
        .position(|w| w == [0x02, 0x01, 0x00])
        .expect("version INTEGER must be present");
    der[pos + 2] = 0x07;
    let parsed = CertificateRequest::from_der(&der).expect("Rust currently accepts version != 0");
    assert_eq!(
        parsed.version, 0x07,
        "parser stores the corrupted version verbatim (TODO(#44-strict-version))"
    );
}
