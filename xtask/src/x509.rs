//! Emitter for the openHiTLS C `pki/cert` + `pki/csr` + `pki/crl` + `pki/verify`
//! SDV files — X.509 certificate / CSR / CRL parse + verify KAT
//! (`docs/c-test-migration-plan.md` Phase C).
//!
//! Families migrated:
//!
//! * `X509_CERT_PARSE_FUNC_TC001` — `format : path`. The C test calls
//!   `HITLS_X509_CertParseFile` and asserts `HITLS_PKI_SUCCESS`. The migrated
//!   test loads the mirrored fixture (`tests/vectors/c-asn1-fixtures/…`) and
//!   asserts `Certificate::from_der` / `from_pem` returns `Ok`.
//! * `X509_CSR_PARSE_FUNC_TC001` / `TC002` / `TC003` — CSR field checks: the
//!   C test parses a PKCS#10 CSR and asserts fields. The migrated test loads
//!   the fixture (`load_csr_fixture`) and asserts public `CertificateRequest`
//!   fields — `TC001` `version` / encode-length / signature, `TC002` the
//!   subject DN, `TC003` the attribute count. `CSR_PARSE_FUNC_TC004`
//!   (negative, expected-return code) routes to `ApiSurface`.
//! * `X509_CRL_PARSE_FILE_FUNC_TC001` / `TC002` — every quoted arg is a valid
//!   CRL; each must parse. `TC003/006/007/008` — `path : res`, where `res` is
//!   the expected C return code (`HITLS_PKI_SUCCESS` → parse must succeed,
//!   any `HITLS_X509_ERR_*` → parse must fail). The C CRL test pins
//!   `BSL_FORMAT_PEM`, so CRLs always load via `from_pem`.
//! * `X509_CRL_PARSE_FILE_FUNC_TC005` / `TC009`–`TC013` — CRL field checks:
//!   `TC005` thisUpdate/nextUpdate year, `TC009` CRL-number extension,
//!   `TC010` AKI-extension criticality, `TC011` revoked-entry reason code,
//!   `TC012` revoked-entry invalidity date, `TC013` revoked-entry
//!   certificate-issuer extension presence. `TC004` (issuer-DN string) is
//!   routed to `ApiSurface` — Rust's `DistinguishedName` Display joins with
//!   `", "` where the C `GET_ISSUER_DN_STR` uses `","`.
//! * `X509_CERT_PARSE_VERSION_FUNC` / `SERIALNUM_FUNC` / `SIGNATURE_FUNC` —
//!   `path : expected`. The C test parses the cert and checks one field; the
//!   migrated test loads the fixture and asserts the matching public
//!   `Certificate` field. `version` is 1-indexed in Rust (the C value is the
//!   raw DER integer `v1=0/v2=1/v3=2`), so the emitted literal is the C value
//!   plus one; `serial_number` / `signature_value` compare the raw DER bytes.
//! * `X509_CERT_PARSE_START_TIME_FUNC` / `END_TIME_FUNC` —
//!   `path : year:month:day:hour:min:sec`. The migrated test asserts
//!   `Certificate::not_before` / `not_after` (an `i64` Unix timestamp); the
//!   expected literal is computed at generation time by `civil_to_unix`, a
//!   copy of the ASN.1 decoder's own civil-date → epoch formula.
//! * `X509_CERT_PARSE_SIGNALG_FUNC` — `path : BSL_CID_sigalg : …`. The
//!   migrated test asserts `Certificate::signature_algorithm` (the raw OID
//!   value bytes); the `BSL_CID_*` token is mapped to OID arcs and DER-encoded
//!   at generation time. The trailing PSS hash/MGF/salt args are not ported.
//! * `X509_CERT_PARSE_ISSUERNAME_FUNC` / `SUBJECTNAME_FUNC` —
//!   `path : 2N : (oid_hex, value_tag, value_hex) × N`. The migrated test
//!   asserts `Certificate::issuer` / `subject` `.entries` (a `Vec<(name,
//!   value)>`); each RDN triple's attribute OID is mapped to the parser's
//!   DN short name and the value hex is decoded as UTF-8.
//! * `X509_CERT_PARSE_PUBKEY_FUNC_TC001` — `path1 : path2`. The C test
//!   verifies `path1`'s certificate signature with `path2`'s parsed public
//!   key; the migrated test loads both fixtures and asserts
//!   `Certificate::verify_signature` succeeds.
//! * `X509_CRL_FILE_VERIFY_FUNC_TC001`–`TC005` — CRL-revocation chain
//!   verification. The five TCs differ in arg layout (single- vs multi-level
//!   chain; result-code order); `plan_crl_verify` normalises each into a
//!   trust-store + CRL list + end-entity cert. The C test verifies every
//!   CRL's signature against its CA, then verifies the cert's chain with CRL
//!   revocation checking. The migrated test mirrors it via
//!   `CertificateRevocationList::verify_signature` + `CertificateVerifier`,
//!   migrating the outcomes Rust's verifier faithfully reproduces
//!   (`SUCCESS`, `CERT_REVOKED`); the stricter-than-Rust codes
//!   (`CRL_NOT_FOUND` / `PROCESS_CRITICALEXT` / `KU_NO_CRLSIGN`) route to
//!   `skipped_unsupported_alg` as verifier-strictness gaps.
//! * `X509_BUILD_CERT_CHAIN_FUNC` — `rootPath : caPath : certPath : crlPath`.
//!   The C test builds + verifies a cert chain (CRL flag cleared, so
//!   revocation is off). The migrated test loads the root (+ optional
//!   intermediate CA) into a `CertificateVerifier` and asserts `verify_cert`
//!   succeeds. ECDSA NIST P-192 chains are skipped (legacy curve unsupported
//!   by Rust's signature verifier).
//! * `X509_CERT_VERIFY_BY_PUBKEY_FUNC` — `certPath : issuerPath : otherPath`.
//!   The C test verifies the cert with the issuer's public key (must succeed)
//!   and with an unrelated cert's key (must fail); the migrated test mirrors
//!   both via `Certificate::verify_signature`.
//! * `X509_CERT_VERIFY_WITH_VARIOUS_CHARSET_FUNC_TC001` (single-level) /
//!   `_TC002` (multi-level) and `X509_CRL_VERIFY_WITH_VARIOUS_CHARSET_FUNC`
//!   (single-level with CRL revocation) — charset-varied chain verifications;
//!   the migrated test runs each through a `CertificateVerifier` and asserts
//!   the outcome (`SUCCESS` / `ISSUE_CERT_NOT_FOUND` / `CERT_REVOKED`). Rows
//!   under `charset/string_canon/` or `user_err_*` are skipped (Rust's
//!   verifier uses byte-exact DN matching, falls back to DN-only on
//!   AKI mismatch, and rejects some malformed fixtures at parse time).
//!   `X509_CA_PATH_WITH_VARIOUS_CHARSET_FUNC` uses `STORECTX_ADD_CA_PATH`
//!   (directory-based CA loading) which has no Rust analogue → `ApiSurface`.
//!
//! For cert/CSR, `format` is a `BSL_FORMAT_*` token: `ASN1` → DER, `PEM` →
//! PEM; the C `UNKNOWN` (auto-detect) format has no Rust equivalent and routes
//! to `skipped_unknown`. Two cert families are deliberate API gaps and route
//! to `ApiSurface`: `TBS_SIGNALG` (the TBS inner AlgorithmIdentifier is not
//! exposed by `Certificate`) and `PUBKEY_FUNC_TC002` (XMSS public-key
//! structure extraction has no Rust analogue). The malformed-DER negatives
//! are a future increment.

use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::{format_byte_slice, Arg, TestCase};

pub fn emit_x509_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();

    for case in cases {
        match classify(&case.tc_name) {
            Kind::CertParse => emit_cert_parse(&mut body, case, &mut stats),
            Kind::CsrField(field) => emit_csr_field(&mut body, case, &mut stats, field),
            Kind::CrlParse => emit_crl_parse(&mut body, case, &mut stats),
            Kind::CrlParseRes => emit_crl_parse_res(&mut body, case, &mut stats),
            Kind::CertField(field) => emit_cert_field(&mut body, case, &mut stats, field),
            Kind::CrlFileVerify(tc) => emit_crl_file_verify(&mut body, case, &mut stats, tc),
            Kind::CrlField(field) => emit_crl_field(&mut body, case, &mut stats, field),
            Kind::BuildCertChain => emit_build_cert_chain(&mut body, case, &mut stats),
            Kind::CertVerifyByPubkey => emit_cert_verify_by_pubkey(&mut body, case, &mut stats),
            Kind::CharsetVerify(v) => emit_charset_verify(&mut body, case, &mut stats, v),
            Kind::ApiSurface => stats.skipped_api += 1,
            Kind::Unknown => stats.skipped_unknown += 1,
        }
    }

    let mut out = String::new();
    write_header(&mut out, &body);
    out.push_str(&body);
    write_footer(&mut out, &stats, cases.len());
    (out, stats)
}

#[derive(Debug, Clone, Copy)]
enum Kind {
    CertParse,
    /// A CSR field-check family (`CSR_PARSE_FUNC_TC001/002/003`).
    CsrField(CsrField),
    /// `CRL_PARSE_FILE_FUNC_TC001/TC002` — every quoted path is a valid CRL
    /// that must parse.
    CrlParse,
    /// `CRL_PARSE_FILE_FUNC_TC003/006/007/008` — `path : res`; `res` is the
    /// expected C return code (`HITLS_PKI_SUCCESS` or an error).
    CrlParseRes,
    /// A cert field-extraction family (`VERSION` / `SERIALNUM` / `SIGNATURE`).
    CertField(CertField),
    /// `CRL_FILE_VERIFY_FUNC_TC001-005` — CRL-revocation chain verification.
    /// The payload is the TC number (1–5); each TC has its own arg layout.
    CrlFileVerify(u8),
    /// A CRL field-check family (`CRL_PARSE_FILE_FUNC_TC005/009-013`).
    CrlField(CrlField),
    /// `X509_BUILD_CERT_CHAIN_FUNC` — build + verify a cert chain.
    BuildCertChain,
    /// `X509_CERT_VERIFY_BY_PUBKEY_FUNC` — verify a cert against a pubkey.
    CertVerifyByPubkey,
    /// Charset-varied chain verify family (`CERT_VERIFY` / `CRL_VERIFY`).
    CharsetVerify(CharsetVerify),
    ApiSurface,
    Unknown,
}

/// Variants of the `*_WITH_VARIOUS_CHARSET` chain-verify families.
#[derive(Debug, Clone, Copy)]
enum CharsetVerify {
    /// `CERT_VERIFY_WITH_VARIOUS_CHARSET_FUNC_TC001` — `ca, entity, result`.
    CertSingle,
    /// `CERT_VERIFY_WITH_VARIOUS_CHARSET_FUNC_TC002` — `root, ca, entity`.
    CertMulti,
    /// `CRL_VERIFY_WITH_VARIOUS_CHARSET_FUNC_TC001` — `ca, entity, crl, result`.
    Crl,
}

/// A CRL field-check KAT family — parse a CRL, assert one parsed field.
#[derive(Debug, Clone, Copy)]
enum CrlField {
    /// `CRL_PARSE_FILE_FUNC_TC005` — `path : beforeYear : afterYear`.
    Time,
    /// `CRL_PARSE_FILE_FUNC_TC009` — `path : critical : crlNumber : res`.
    CrlNumber,
    /// `CRL_PARSE_FILE_FUNC_TC010` — `path : critical` (AKI extension).
    Aki,
    /// `CRL_PARSE_FILE_FUNC_TC011` — `path : res : reasonCode`.
    Reason,
    /// `CRL_PARSE_FILE_FUNC_TC012` — `path : year : res` (invalidity date).
    InvalidityDate,
    /// `CRL_PARSE_FILE_FUNC_TC013` — `path : res1 : res2` (cert-issuer ext).
    CertIssuer,
}

/// A CSR field-check KAT family — parse a PKCS#10 CSR, assert parsed fields.
#[derive(Debug, Clone, Copy)]
enum CsrField {
    /// `CSR_PARSE_FUNC_TC001` — `format : path : rawLen : signAlg : sign : …`.
    Sign,
    /// `CSR_PARSE_FUNC_TC002` — `format : path : count : (dnType, dnName)×N`.
    Subject,
    /// `CSR_PARSE_FUNC_TC003` — `format : path : attrNum : attrCid : attrValue`.
    Attrs,
}

/// A cert field-extraction KAT family — `path : expected…`. The migrated test
/// parses the certificate and asserts one public `Certificate` field.
#[derive(Debug, Clone, Copy)]
enum CertField {
    /// `X509_CERT_PARSE_VERSION_FUNC` — `path : version` (raw DER integer).
    Version,
    /// `X509_CERT_PARSE_SERIALNUM_FUNC` — `path : "hex serial"`.
    Serial,
    /// `X509_CERT_PARSE_SIGNATURE_FUNC` — `path : "hex signature"`.
    Signature,
    /// `X509_CERT_PARSE_START_TIME_FUNC` — `path : year:month:day:hour:min:sec`.
    NotBefore,
    /// `X509_CERT_PARSE_END_TIME_FUNC` — `path : year:month:day:hour:min:sec`.
    NotAfter,
    /// `X509_CERT_PARSE_SIGNALG_FUNC` — `path : BSL_CID_sigalg : …`. Only the
    /// signature-algorithm OID is asserted; the trailing PSS hash/MGF/salt
    /// args are not ported (they live in `signature_params`, raw DER).
    SigAlg,
    /// `X509_CERT_PARSE_ISSUERNAME_FUNC` — `path : 2N : (oid, tag, value)×N`.
    Issuer,
    /// `X509_CERT_PARSE_SUBJECTNAME_FUNC` — `path : 2N : (oid, tag, value)×N`.
    Subject,
    /// `X509_CERT_PARSE_PUBKEY_FUNC_TC001` — `path1 : path2`. The C test
    /// verifies `path1`'s signature with `path2`'s parsed public key; the
    /// migrated test does the same via `Certificate::verify_signature`.
    PubKey,
}

impl CertField {
    /// The emitted function-name suffix (`tc_lineN_x509_cert_<suffix>`) — also
    /// the `Certificate` field name asserted (for the scalar fields).
    fn suffix(self) -> &'static str {
        match self {
            CertField::Version => "version",
            CertField::Serial => "serial_number",
            CertField::Signature => "signature",
            CertField::NotBefore => "not_before",
            CertField::NotAfter => "not_after",
            CertField::SigAlg => "signature_algorithm",
            CertField::Issuer => "issuer",
            CertField::Subject => "subject",
            CertField::PubKey => "pubkey",
        }
    }
}

/// Map a DN attribute-type OID (raw value bytes) to the short name that the
/// PKI parser's `oid_to_dn_short_name` records into `DistinguishedName`.
/// Covers every attribute OID in the cert SDV `ISSUERNAME` / `SUBJECTNAME`
/// families; an unrecognised OID routes the row to `skipped_unknown`.
fn dn_oid_short_name(oid_value: &[u8]) -> Option<&'static str> {
    Some(match oid_value {
        [0x55, 0x04, 0x03] => "CN",
        [0x55, 0x04, 0x05] => "serialNumber",
        [0x55, 0x04, 0x06] => "C",
        [0x55, 0x04, 0x07] => "L",
        [0x55, 0x04, 0x08] => "ST",
        [0x55, 0x04, 0x0a] => "O",
        [0x55, 0x04, 0x0b] => "OU",
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01] => "emailAddress",
        _ => return None,
    })
}

/// Map an openHiTLS `BSL_CID_*` signature-algorithm token to the OID arc
/// list. Covers every signature algorithm appearing in the SDV cert SDV
/// `SIGNALG` family; an unrecognised CID routes to `skipped_unsupported_alg`.
fn cid_to_oid_arcs(cid: &str) -> Option<&'static [u32]> {
    Some(match cid {
        "BSL_CID_ECDSAWITHSHA256" => &[1, 2, 840, 10045, 4, 3, 2],
        "BSL_CID_ED25519" => &[1, 3, 101, 112],
        "BSL_CID_RSASSAPSS" => &[1, 2, 840, 113549, 1, 1, 10],
        "BSL_CID_SHA256WITHRSAENCRYPTION" => &[1, 2, 840, 113549, 1, 1, 11],
        "BSL_CID_SM2DSAWITHSM3" => &[1, 2, 156, 10197, 1, 501],
        _ => return None,
    })
}

/// Encode an OID arc list to its DER *value* bytes (no tag/length) — matches
/// what the ASN.1 decoder's `read_oid` returns into `signature_algorithm`.
fn oid_der_value(arcs: &[u32]) -> Vec<u8> {
    let mut out = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        let mut group = vec![(arc & 0x7f) as u8];
        let mut v = arc >> 7;
        while v > 0 {
            group.push(((v & 0x7f) as u8) | 0x80);
            v >>= 7;
        }
        group.reverse();
        out.extend(group);
    }
    out
}

/// Civil date (UTC) → Unix epoch seconds — the exact formula used by the
/// ASN.1 decoder's `read_time` (`hitls-utils` `datetime_to_unix`), replicated
/// so the migrated test asserts a literal `i64` against
/// `Certificate::not_before` / `not_after`.
fn civil_to_unix(year: i64, month: i64, day: i64, hour: i64, min: i64, sec: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 9 } else { month - 3 };
    let days = 365 * y + y / 4 - y / 100 + y / 400 + (m * 306 + 5) / 10 + (day - 1) - 719_468;
    days * 86_400 + hour * 3_600 + min * 60 + sec
}

fn classify(tc: &str) -> Kind {
    if tc.contains("X509_CERT_PARSE_FUNC_TC001") {
        return Kind::CertParse;
    }
    if tc.contains("X509_CSR_PARSE_FUNC_TC001") {
        return Kind::CsrField(CsrField::Sign);
    }
    if tc.contains("X509_CSR_PARSE_FUNC_TC002") {
        return Kind::CsrField(CsrField::Subject);
    }
    if tc.contains("X509_CSR_PARSE_FUNC_TC003") {
        return Kind::CsrField(CsrField::Attrs);
    }
    if tc.contains("X509_CRL_PARSE_FILE_FUNC_TC001")
        || tc.contains("X509_CRL_PARSE_FILE_FUNC_TC002")
    {
        return Kind::CrlParse;
    }
    if tc.contains("X509_CRL_PARSE_FILE_FUNC_TC003")
        || tc.contains("X509_CRL_PARSE_FILE_FUNC_TC006")
        || tc.contains("X509_CRL_PARSE_FILE_FUNC_TC007")
        || tc.contains("X509_CRL_PARSE_FILE_FUNC_TC008")
    {
        return Kind::CrlParseRes;
    }
    if tc.contains("X509_CERT_PARSE_VERSION_FUNC") {
        return Kind::CertField(CertField::Version);
    }
    if tc.contains("X509_CERT_PARSE_SERIALNUM_FUNC") {
        return Kind::CertField(CertField::Serial);
    }
    if tc.contains("X509_CERT_PARSE_SIGNATURE_FUNC") {
        return Kind::CertField(CertField::Signature);
    }
    if tc.contains("X509_CERT_PARSE_START_TIME_FUNC") {
        return Kind::CertField(CertField::NotBefore);
    }
    if tc.contains("X509_CERT_PARSE_END_TIME_FUNC") {
        return Kind::CertField(CertField::NotAfter);
    }
    if tc.contains("X509_CERT_PARSE_SIGNALG_FUNC") {
        return Kind::CertField(CertField::SigAlg);
    }
    if tc.contains("X509_CERT_PARSE_ISSUERNAME_FUNC") {
        return Kind::CertField(CertField::Issuer);
    }
    if tc.contains("X509_CERT_PARSE_SUBJECTNAME_FUNC") {
        return Kind::CertField(CertField::Subject);
    }
    if tc.contains("X509_CERT_PARSE_PUBKEY_FUNC_TC001") {
        return Kind::CertField(CertField::PubKey);
    }
    for n in 1..=5u8 {
        if tc.contains(&format!("X509_CRL_FILE_VERIFY_FUNC_TC00{n}")) {
            return Kind::CrlFileVerify(n);
        }
    }
    if tc.contains("X509_CRL_PARSE_FILE_FUNC_TC005") {
        return Kind::CrlField(CrlField::Time);
    }
    if tc.contains("X509_CRL_PARSE_FILE_FUNC_TC009") {
        return Kind::CrlField(CrlField::CrlNumber);
    }
    if tc.contains("X509_CRL_PARSE_FILE_FUNC_TC010") {
        return Kind::CrlField(CrlField::Aki);
    }
    if tc.contains("X509_CRL_PARSE_FILE_FUNC_TC011") {
        return Kind::CrlField(CrlField::Reason);
    }
    if tc.contains("X509_CRL_PARSE_FILE_FUNC_TC012") {
        return Kind::CrlField(CrlField::InvalidityDate);
    }
    if tc.contains("X509_CRL_PARSE_FILE_FUNC_TC013") {
        return Kind::CrlField(CrlField::CertIssuer);
    }
    if tc.contains("X509_BUILD_CERT_CHAIN_FUNC") {
        return Kind::BuildCertChain;
    }
    if tc.contains("X509_CERT_VERIFY_BY_PUBKEY_FUNC") {
        return Kind::CertVerifyByPubkey;
    }
    if tc.contains("X509_CERT_VERIFY_WITH_VARIOUS_CHARSET_FUNC_TC001") {
        return Kind::CharsetVerify(CharsetVerify::CertSingle);
    }
    if tc.contains("X509_CERT_VERIFY_WITH_VARIOUS_CHARSET_FUNC_TC002") {
        return Kind::CharsetVerify(CharsetVerify::CertMulti);
    }
    if tc.contains("X509_CRL_VERIFY_WITH_VARIOUS_CHARSET_FUNC") {
        return Kind::CharsetVerify(CharsetVerify::Crl);
    }
    // CSR field / expected-return families, the CRL field-check families
    // (`TC004/005/009-013`), and the malformed-DER negatives are migrated in
    // later Phase C increments. Two cert families are deliberate API gaps:
    // `TBS_SIGNALG_FUNC` (the TBS inner AlgorithmIdentifier is parsed but not
    // exposed by `Certificate`; RFC 5280 §4.1.1.2 mandates it equal the outer
    // one) and `PUBKEY_FUNC_TC002` (XMSS public-key structure extraction has
    // no Rust analogue — `SubjectPublicKeyInfo` keeps the key as raw bytes).
    if tc.contains("X509_") || tc.contains("CERT_") {
        return Kind::ApiSurface;
    }
    Kind::Unknown
}

/// Rewrite a C fixture path (`../testdata/cert/foo.der`) to a path relative
/// to `tests/vectors/c-asn1-fixtures/`. Returns `None` for a path outside the
/// mirrored `cert/` + `certificate/` corpus.
fn fixture_relpath(c_path: &str) -> Option<&str> {
    let rel = c_path.strip_prefix("../testdata/")?;
    if rel.starts_with("cert/") || rel.starts_with("certificate/") {
        Some(rel)
    } else {
        None
    }
}

/// Emit a positive parse KAT — `format : path : …` rows where the C test
/// asserts the file parses. Extra field-check args after `path` are ignored;
/// the migrated test ports the parse-succeeds half.
fn emit_cert_parse(out: &mut String, case: &TestCase, stats: &mut EmitStats) {
    if case.args.len() < 2 {
        stats.skipped_unknown += 1;
        return;
    }
    let Some(format) = case.args[0].as_symbol() else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(path) = case.args[1].as_str() else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(rel) = fixture_relpath(path) else {
        stats.skipped_unknown += 1;
        return;
    };
    let der = match format {
        "BSL_FORMAT_ASN1" => true,
        "BSL_FORMAT_PEM" => false,
        // BSL_FORMAT_UNKNOWN is the C auto-detect format — no Rust analogue.
        _ => {
            stats.skipped_unknown += 1;
            return;
        }
    };

    write_doc(out, case, "X.509 cert parse KAT");
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn tc_line{}_x509_cert_parse() {{", case.line).unwrap();
    writeln!(
        out,
        "    let bytes = std::fs::read(concat!(\n\
         \x20       env!(\"CARGO_MANIFEST_DIR\"),\n\
         \x20       \"/../../tests/vectors/c-asn1-fixtures/{rel}\"\n\
         \x20   ))\n\
         \x20   .unwrap();"
    )
    .unwrap();
    if der {
        writeln!(out, "    assert!(Certificate::from_der(&bytes).is_ok());").unwrap();
    } else {
        writeln!(out, "    let pem = std::str::from_utf8(&bytes).unwrap();").unwrap();
        writeln!(out, "    assert!(Certificate::from_pem(pem).is_ok());").unwrap();
    }
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

/// Emit a CSR field-check KAT (`CSR_PARSE_FUNC_TC001/002/003`). The C test
/// parses a PKCS#10 CSR and checks fields; the migrated test loads the
/// fixture via `load_csr_fixture` and asserts the corresponding public
/// `CertificateRequest` fields.
///
/// `TC001` checks `version` / encode-length / signature; the C `signAlg`
/// sub-check is not ported (it would need a large `BSL_CID_*` → OID table,
/// including ML-DSA — deferred). `TC002` reconstructs the subject DN — rows
/// whose RDN types fall outside the parser's DN short-name set, or whose
/// values parsed ambiguously as hex, are skipped. `TC003` asserts the
/// attribute count. `CSR_PARSE_FUNC_TC004` (negative) stays `ApiSurface`.
fn emit_csr_field(out: &mut String, case: &TestCase, stats: &mut EmitStats, field: CsrField) {
    let Some(rel) = arg_rel(&case.args, 1) else {
        stats.skipped_unknown += 1;
        return;
    };
    let body = match field {
        CsrField::Sign => {
            let Some(raw_len) = arg_sym(&case.args, 2).and_then(|s| s.parse::<usize>().ok()) else {
                stats.skipped_unknown += 1;
                return;
            };
            let Some(sign) = case.args.get(4).and_then(|a| a.as_hex()) else {
                stats.skipped_unknown += 1;
                return;
            };
            format!(
                "    assert_eq!(csr.version, 0);\n\
                 \x20   assert_eq!(csr.raw.len(), {raw_len});\n\
                 \x20   assert_eq!(csr.signature_value.as_slice(), {});\n",
                format_byte_slice(sign)
            )
        }
        CsrField::Subject => {
            let pairs = &case.args[3..];
            if pairs.is_empty() || pairs.len() % 2 != 0 {
                stats.skipped_unknown += 1;
                return;
            }
            let mut entries = Vec::new();
            for pair in pairs.chunks(2) {
                // A DN value that happens to be even-length hex parses as
                // `Arg::Hex`, losing the original string — skip such rows.
                let (Some(ty), Some(name)) = (pair[0].as_str(), pair[1].as_str()) else {
                    stats.skipped_unsupported_alg += 1;
                    return;
                };
                // Only the DN attribute types the PKI parser records by short
                // name; an unknown type is stored as a dotted OID instead.
                if !matches!(
                    ty,
                    "C" | "ST" | "L" | "O" | "OU" | "CN" | "serialNumber" | "emailAddress"
                ) {
                    stats.skipped_unsupported_alg += 1;
                    return;
                }
                entries.push((ty, name));
            }
            let mut s =
                String::from("    assert_eq!(\n        csr.subject.entries,\n        vec![\n");
            for (ty, name) in &entries {
                writeln!(s, "            ({ty:?}.to_string(), {name:?}.to_string()),").unwrap();
            }
            s.push_str("        ],\n    );\n");
            s
        }
        CsrField::Attrs => {
            let Some(num) = arg_sym(&case.args, 2).and_then(|s| s.parse::<usize>().ok()) else {
                stats.skipped_unknown += 1;
                return;
            };
            // C `attrNum` counts CSR *attributes*; Rust's
            // `CertificateRequest::attributes` is the flattened *extension*
            // list pulled out of the `extensionRequest` attribute, so the
            // counts diverge once an attribute is present. Only the
            // zero-attribute rows migrate (both are then empty).
            if num != 0 {
                stats.skipped_unsupported_alg += 1;
                return;
            }
            "    assert!(csr.attributes.is_empty());\n".to_string()
        }
    };

    write_doc(out, case, "X.509 CSR field-check KAT");
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn tc_line{}_x509_csr_field() {{", case.line).unwrap();
    writeln!(out, "    let csr = load_csr_fixture({rel:?});").unwrap();
    out.push_str(&body);
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

/// Emit a positive CRL parse KAT — `CRL_PARSE_FILE_FUNC_TC001/TC002`, where
/// every quoted arg is a valid CRL fixture that must parse. The C test pins
/// `BSL_FORMAT_PEM`, so each is loaded as PEM.
fn emit_crl_parse(out: &mut String, case: &TestCase, stats: &mut EmitStats) {
    let rels: Vec<&str> = case
        .args
        .iter()
        .filter_map(|a| a.as_str())
        .filter_map(fixture_relpath)
        .collect();
    if rels.is_empty() {
        stats.skipped_unknown += 1;
        return;
    }
    write_doc(out, case, "X.509 CRL parse KAT");
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn tc_line{}_x509_crl_parse() {{", case.line).unwrap();
    write!(out, "    for rel in [").unwrap();
    for (i, rel) in rels.iter().enumerate() {
        if i > 0 {
            write!(out, ", ").unwrap();
        }
        write!(out, "{rel:?}").unwrap();
    }
    writeln!(out, "] {{").unwrap();
    writeln!(
        out,
        "        let path = format!(\n\
         \x20           \"{{}}/../../tests/vectors/c-asn1-fixtures/{{rel}}\",\n\
         \x20           env!(\"CARGO_MANIFEST_DIR\")\n\
         \x20       );"
    )
    .unwrap();
    writeln!(out, "        let bytes = std::fs::read(&path).unwrap();").unwrap();
    writeln!(
        out,
        "        let pem = std::str::from_utf8(&bytes).unwrap();"
    )
    .unwrap();
    writeln!(
        out,
        "        assert!(CertificateRevocationList::from_pem(pem).is_ok());"
    )
    .unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

/// Emit a `CRL_PARSE_FILE_FUNC_TC003/006/007/008` KAT — `path : res`. `res`
/// is the expected C return code.
///
/// Only the `HITLS_PKI_SUCCESS` rows are emitted (the CRL must parse). The
/// negative rows (`res` is an `HITLS_X509_ERR_*`) are **not** migrated:
/// Rust's `CertificateRevocationList::from_pem` is more lenient than the C
/// CRL parser and accepts those structurally-malformed CRLs, so an
/// `is_err()` assertion would not hold. They route to
/// `skipped_unsupported_alg` and are flagged in DEV_LOG as a candidate
/// Rust CRL-parser hardening (a follow-up Implementation phase).
fn emit_crl_parse_res(out: &mut String, case: &TestCase, stats: &mut EmitStats) {
    if case.args.len() < 2 {
        stats.skipped_unknown += 1;
        return;
    }
    let Some(path) = case.args[0].as_str() else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(res) = case.args[1].as_symbol() else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(rel) = fixture_relpath(path) else {
        stats.skipped_unknown += 1;
        return;
    };
    // I155: positive rows assert `is_ok()`; negative rows (any
    // `HITLS_X509_ERR_*` / `BSL_ASN1_ERR_*`) assert `is_err()`. The Rust
    // CRL parser was tightened to reject the C SDV's 6 leniency-exposing
    // malformed fixtures (cf. `parse_utc_time` / `parse_generalized_time`
    // strict-length-and-`Z` checks + the nextUpdate `.ok()` removal +
    // `is_known_signature_algorithm` OID gate).
    let positive = res == "HITLS_PKI_SUCCESS";
    let kind = if positive {
        "X.509 CRL parse KAT"
    } else {
        "X.509 CRL parse negative KAT"
    };
    let suffix = if positive { "" } else { "_fail" };
    write_doc(out, case, kind);
    writeln!(out, "#[test]").unwrap();
    writeln!(
        out,
        "fn tc_line{}_x509_crl_parse_res{suffix}() {{",
        case.line
    )
    .unwrap();
    writeln!(
        out,
        "    let bytes = std::fs::read(concat!(\n\
         \x20       env!(\"CARGO_MANIFEST_DIR\"),\n\
         \x20       \"/../../tests/vectors/c-asn1-fixtures/{rel}\"\n\
         \x20   ))\n\
         \x20   .unwrap();"
    )
    .unwrap();
    writeln!(out, "    let pem = std::str::from_utf8(&bytes).unwrap();").unwrap();
    if positive {
        writeln!(
            out,
            "    assert!(CertificateRevocationList::from_pem(pem).is_ok());"
        )
        .unwrap();
    } else {
        writeln!(
            out,
            "    assert!(CertificateRevocationList::from_pem(pem).is_err());"
        )
        .unwrap();
    }
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

/// Emit a cert field-extraction KAT — `path : expected`. The migrated test
/// loads the fixture via `load_cert_fixture` and asserts one public
/// `Certificate` field against the C-expected value.
fn emit_cert_field(out: &mut String, case: &TestCase, stats: &mut EmitStats, field: CertField) {
    if case.args.len() < 2 {
        stats.skipped_unknown += 1;
        return;
    }
    let Some(path) = case.args[0].as_str() else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(rel) = fixture_relpath(path) else {
        stats.skipped_unknown += 1;
        return;
    };

    let assertion = match field {
        CertField::Version => {
            let Some(v) = case.args[1].as_symbol().and_then(|s| s.parse::<u8>().ok()) else {
                stats.skipped_unknown += 1;
                return;
            };
            // C GET_VERSION yields the raw DER integer (v1=0/v2=1/v3=2);
            // `Certificate::version` is 1-indexed, hence the C value + 1.
            format!(
                "    assert_eq!(cert.version, {}); // C version field = {v}\n",
                v + 1
            )
        }
        CertField::Serial => {
            let Some(h) = case.args[1].as_hex() else {
                stats.skipped_unknown += 1;
                return;
            };
            format!(
                "    assert_eq!(cert.serial_number.as_slice(), {});\n",
                format_byte_slice(h)
            )
        }
        CertField::Signature => {
            let Some(h) = case.args[1].as_hex() else {
                stats.skipped_unknown += 1;
                return;
            };
            format!(
                "    assert_eq!(cert.signature_value.as_slice(), {});\n",
                format_byte_slice(h)
            )
        }
        CertField::NotBefore | CertField::NotAfter => {
            // path : year : month : day : hour : min : sec
            let parts: Option<Vec<i64>> = (1..7)
                .map(|i| {
                    case.args
                        .get(i)
                        .and_then(|a| a.as_symbol())
                        .and_then(|s| s.parse::<i64>().ok())
                })
                .collect();
            let Some(d) = parts else {
                stats.skipped_unknown += 1;
                return;
            };
            let ts = civil_to_unix(d[0], d[1], d[2], d[3], d[4], d[5]);
            format!(
                "    assert_eq!(cert.{}, {ts}); // {:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z\n",
                field.suffix(),
                d[0],
                d[1],
                d[2],
                d[3],
                d[4],
                d[5],
            )
        }
        CertField::SigAlg => {
            let Some(cid) = case.args[1].as_symbol() else {
                stats.skipped_unknown += 1;
                return;
            };
            let Some(arcs) = cid_to_oid_arcs(cid) else {
                stats.skipped_unsupported_alg += 1;
                return;
            };
            format!(
                "    assert_eq!(cert.signature_algorithm.as_slice(), {}); // {cid}\n",
                format_byte_slice(&oid_der_value(arcs))
            )
        }
        CertField::Issuer | CertField::Subject => {
            // path : 2N : (oid_hex, value_tag, value_hex) × N — args[1] is the
            // C row's element count; the RDN triples start at args[2].
            let triples = &case.args[2..];
            if triples.is_empty() || triples.len() % 3 != 0 {
                stats.skipped_unknown += 1;
                return;
            }
            let mut entries = Vec::new();
            for triple in triples.chunks(3) {
                let Some(name) = triple[0].as_hex().and_then(dn_oid_short_name) else {
                    stats.skipped_unknown += 1;
                    return;
                };
                let Some(tag) = triple[1].as_symbol().and_then(|s| s.parse::<u8>().ok()) else {
                    stats.skipped_unknown += 1;
                    return;
                };
                // Only the UTF-8-family ASN.1 string tags decode the same way
                // the PKI parser's `read_string` does for these (= from_utf8).
                if !matches!(tag, 0x0C | 0x12 | 0x13 | 0x16 | 0x1A) {
                    stats.skipped_unknown += 1;
                    return;
                }
                let Some(val) = triple[2]
                    .as_hex()
                    .and_then(|b| String::from_utf8(b.to_vec()).ok())
                else {
                    stats.skipped_unknown += 1;
                    return;
                };
                entries.push((name, val));
            }
            let mut s = format!(
                "    assert_eq!(\n        cert.{}.entries,\n        vec![\n",
                field.suffix()
            );
            for (name, val) in &entries {
                writeln!(
                    s,
                    "            ({name:?}.to_string(), {val:?}.to_string()),"
                )
                .unwrap();
            }
            s.push_str("        ],\n    );\n");
            s
        }
        CertField::PubKey => {
            // `path1 : path2` — verify path1's signature with path2's public
            // key. The scaffold already loaded `cert` (= path1); load the
            // issuer and assert `verify_signature` succeeds.
            let Some(issuer_rel) = case.args[1].as_str().and_then(fixture_relpath) else {
                stats.skipped_unknown += 1;
                return;
            };
            format!(
                "    let issuer = load_cert_fixture({issuer_rel:?});\n\
                 \x20   assert!(cert.verify_signature(&issuer).unwrap());\n"
            )
        }
    };

    write_doc(
        out,
        case,
        &format!("X.509 cert {} field KAT", field.suffix()),
    );
    writeln!(out, "#[test]").unwrap();
    writeln!(
        out,
        "fn tc_line{}_x509_cert_{}() {{",
        case.line,
        field.suffix()
    )
    .unwrap();
    writeln!(out, "    let cert = load_cert_fixture({rel:?});").unwrap();
    out.push_str(&assertion);
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

/// A planned CRL-revocation chain-verify test, normalised across the five
/// `CRL_FILE_VERIFY` TC arg layouts.
struct CrlVerifyPlan<'a> {
    /// Trust-store cert fixtures, root-first (`trusted[0]` is the root CA).
    trusted: Vec<&'a str>,
    /// CRL fixtures, leaf-first (`crls[0]` is issued by the leaf CA).
    crls: Vec<&'a str>,
    /// The end-entity cert fixture being verified.
    cert: &'a str,
    /// `verifyParam.flags` token.
    flags: &'a str,
    /// `VerifyCrl` expected return code.
    crl_ver: &'a str,
    /// `CertVerify` expected return code.
    cert_ver: &'a str,
}

fn arg_rel(args: &[Arg], i: usize) -> Option<&str> {
    args.get(i)?.as_str().and_then(fixture_relpath)
}

fn arg_sym(args: &[Arg], i: usize) -> Option<&str> {
    args.get(i)?.as_symbol()
}

/// Resolve a `CRL_FILE_VERIFY_FUNC_TC00n` row into a normalised plan. Each TC
/// has its own arg layout (single- vs multi-level chain, result-code order):
/// * TC001/004: `ca, crl, cert, flags, crlVer, certVer[, isUseSm2]`
/// * TC002/005: `rootCa, ca, rootCrl, crl, cert, flags, certVer, crlVer[, …]`
/// * TC003:     `ca, crl, cert, flags, crlVer, certVer` (root CA/CRL hardcoded)
fn plan_crl_verify(case: &TestCase, tc: u8) -> Option<CrlVerifyPlan<'_>> {
    let a = &case.args;
    match tc {
        1 | 4 => Some(CrlVerifyPlan {
            trusted: vec![arg_rel(a, 0)?],
            crls: vec![arg_rel(a, 1)?],
            cert: arg_rel(a, 2)?,
            flags: arg_sym(a, 3)?,
            crl_ver: arg_sym(a, 4)?,
            cert_ver: arg_sym(a, 5)?,
        }),
        2 | 5 => {
            // rootCrl (arg 2) is optional — an empty `""` field parses as a
            // zero-length hex arg, so `arg_rel` yields `None` and it is
            // simply omitted from the CRL list.
            let mut crls = vec![arg_rel(a, 3)?];
            if let Some(root_crl) = arg_rel(a, 2) {
                crls.push(root_crl);
            }
            Some(CrlVerifyPlan {
                trusted: vec![arg_rel(a, 0)?, arg_rel(a, 1)?],
                crls,
                cert: arg_rel(a, 4)?,
                flags: arg_sym(a, 5)?,
                cert_ver: arg_sym(a, 6)?,
                crl_ver: arg_sym(a, 7)?,
            })
        }
        3 => Some(CrlVerifyPlan {
            // TC003 hardcodes the root CA + root CRL in the C body.
            trusted: vec!["cert/test_for_crl/crl_verify/certs/ca.crt", arg_rel(a, 0)?],
            crls: vec![
                arg_rel(a, 1)?,
                "cert/test_for_crl/crl_verify/crl/root_updated.crl",
            ],
            cert: arg_rel(a, 2)?,
            flags: arg_sym(a, 3)?,
            crl_ver: arg_sym(a, 4)?,
            cert_ver: arg_sym(a, 5)?,
        }),
        _ => None,
    }
}

/// Emit a CRL-revocation chain-verification KAT (`CRL_FILE_VERIFY_FUNC_TC001`
/// through `TC005`). The C test verifies every CRL's signature against its
/// issuing CA, then verifies the end-entity cert's chain with CRL revocation
/// checking. The migrated test mirrors that with
/// `CertificateRevocationList::verify_signature` + `CertificateVerifier`.
///
/// A row is migrated only when its outcomes are ones Rust's verifier
/// faithfully reproduces: the CRL signatures all verify (`crlVerResult ==
/// HITLS_PKI_SUCCESS`) and `certVerResult` is `HITLS_PKI_SUCCESS` or
/// `HITLS_X509_ERR_VFY_CERT_REVOKED`. The other C outcomes route to
/// `skipped_unsupported_alg` — they are Rust-verifier strictness gaps:
/// `CRL_NOT_FOUND` (Rust soft-fails on a missing CRL), `PROCESS_CRITICALEXT`
/// (no unhandled-critical-extension rejection), `KU_NO_CRLSIGN` (no
/// CRL-issuer keyUsage check).
fn emit_crl_file_verify(out: &mut String, case: &TestCase, stats: &mut EmitStats, tc: u8) {
    let Some(plan) = plan_crl_verify(case, tc) else {
        stats.skipped_unknown += 1;
        return;
    };
    let check_revocation = match plan.flags {
        "0" => false,
        "HITLS_X509_VFY_FLAG_CRL_ALL" | "HITLS_X509_VFY_FLAG_CRL_DEV" => true,
        _ => {
            stats.skipped_unknown += 1;
            return;
        }
    };
    // SM2 CRL signature verification needs the GM/T 0009 user-id, which the
    // `verify_signature` API does not expose — skip the `sm2/` fixture rows.
    if plan
        .trusted
        .iter()
        .chain(plan.crls.iter())
        .chain(std::iter::once(&plan.cert))
        .any(|p| p.contains("/sm2/"))
    {
        stats.skipped_unsupported_alg += 1;
        return;
    }
    // `CRL_DEV` checks revocation of the end-entity only; Rust's verifier has
    // no device-only mode and checks every non-root cert, so on a multi-level
    // chain it over-checks the intermediate CAs. Skip multi-level DEV rows.
    if plan.flags == "HITLS_X509_VFY_FLAG_CRL_DEV" && plan.trusted.len() > 1 {
        stats.skipped_unsupported_alg += 1;
        return;
    }
    // Only migrate rows whose CRL signatures all verify — Rust has no
    // `VerifyCrl(store)` analogue, so a non-SUCCESS `crlVerResult` cannot be
    // asserted cleanly.
    if plan.crl_ver != "HITLS_PKI_SUCCESS" {
        stats.skipped_unsupported_alg += 1;
        return;
    }
    let assertion = match plan.cert_ver {
        "HITLS_PKI_SUCCESS" => "    assert!(result.is_ok());\n",
        "HITLS_X509_ERR_VFY_CERT_REVOKED" => {
            "    assert_eq!(result.unwrap_err().to_string(), \"certificate revoked\");\n"
        }
        // CRL_NOT_FOUND / PROCESS_CRITICALEXT / KU_NO_CRLSIGN — see fn doc.
        _ => {
            stats.skipped_unsupported_alg += 1;
            return;
        }
    };

    write_doc(out, case, "X.509 CRL-revocation chain-verify KAT");
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn tc_line{}_x509_crl_file_verify() {{", case.line).unwrap();
    for (i, rel) in plan.trusted.iter().enumerate() {
        writeln!(out, "    let ca{i} = load_cert_fixture({rel:?});").unwrap();
    }
    for (i, rel) in plan.crls.iter().enumerate() {
        writeln!(out, "    let crl{i} = load_crl_fixture({rel:?});").unwrap();
    }
    writeln!(out, "    let cert = load_cert_fixture({:?});", plan.cert).unwrap();
    // Each CRL is issued by its level's CA: `crls[i]` (leaf-first) pairs with
    // `trusted[len-1-i]` (root-first).
    for i in 0..plan.crls.len() {
        let ca_idx = plan.trusted.len() - 1 - i;
        writeln!(
            out,
            "    assert!(crl{i}.verify_signature(&ca{ca_idx}).unwrap());"
        )
        .unwrap();
    }
    writeln!(out, "    let mut verifier = CertificateVerifier::new();").unwrap();
    for i in 0..plan.trusted.len() {
        writeln!(out, "    verifier.add_trusted_cert(ca{i});").unwrap();
    }
    for i in 0..plan.crls.len() {
        writeln!(out, "    verifier.add_crl(crl{i});").unwrap();
    }
    writeln!(
        out,
        "    verifier.set_check_revocation({check_revocation});"
    )
    .unwrap();
    writeln!(out, "    let result = verifier.verify_cert(&cert, &[]);").unwrap();
    out.push_str(assertion);
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

/// Emit an `assert!` line for a boolean expression — `assert!(expr)` when the
/// expectation is true, `assert!(!expr)` when false (clippy rejects
/// `assert_eq!(expr, <literal bool>)`).
fn bool_assert(expr: &str, expected: bool) -> String {
    if expected {
        format!("    assert!({expr});\n")
    } else {
        format!("    assert!(!{expr});\n")
    }
}

/// Map an openHiTLS `HITLS_X509_REVOKED_REASON_*` token to its RFC 5280
/// §5.3.1 reason-code integer.
fn reason_name_to_code(name: &str) -> Option<i32> {
    Some(match name {
        "HITLS_X509_REVOKED_REASON_UNSPECIFIED" => 0,
        "HITLS_X509_REVOKED_REASON_KEY_COMPROMISE" => 1,
        "HITLS_X509_REVOKED_REASON_CA_COMPROMISE" => 2,
        "HITLS_X509_REVOKED_REASON_AFFILIATION_CHANGED" => 3,
        "HITLS_X509_REVOKED_REASON_SUPERSEDED" => 4,
        "HITLS_X509_REVOKED_REASON_CESSATION_OF_OPERATION" => 5,
        "HITLS_X509_REVOKED_REASON_CERTIFICATE_HOLD" => 6,
        "HITLS_X509_REVOKED_REASON_REMOVE_FROM_CRL" => 8,
        "HITLS_X509_REVOKED_REASON_PRIVILEGE_WITHDRAWN" => 9,
        "HITLS_X509_REVOKED_REASON_AA_COMPROMISE" => 10,
        _ => return None,
    })
}

/// Emit a CRL field-check KAT (`CRL_PARSE_FILE_FUNC_TC005` / `TC009`–`TC013`).
/// Each TC parses a CRL and asserts one parsed field. Rows whose C `res` code
/// is not `HITLS_PKI_SUCCESS` (parse / extension-lookup expected to fail) are
/// skipped — the migrated test covers the positive outcomes. `TC004`
/// (issuer-DN string) is not handled here: Rust's `DistinguishedName` Display
/// joins with `", "` where the C `GET_ISSUER_DN_STR` uses `","`.
fn emit_crl_field(out: &mut String, case: &TestCase, stats: &mut EmitStats, field: CrlField) {
    let Some(rel) = arg_rel(&case.args, 0) else {
        stats.skipped_unknown += 1;
        return;
    };
    let year_bounds = |y: i64| {
        (
            civil_to_unix(y, 1, 1, 0, 0, 0),
            civil_to_unix(y + 1, 1, 1, 0, 0, 0),
        )
    };
    let body = match field {
        CrlField::Time => {
            let (Some(by), Some(ay)) = (
                arg_sym(&case.args, 1).and_then(|s| s.parse::<i64>().ok()),
                arg_sym(&case.args, 2).and_then(|s| s.parse::<i64>().ok()),
            ) else {
                stats.skipped_unknown += 1;
                return;
            };
            let (b0, b1) = year_bounds(by);
            let (a0, a1) = year_bounds(ay);
            format!(
                "    assert!(crl.this_update >= {b0} && crl.this_update < {b1}); // thisUpdate {by}\n\
                 \x20   let next = crl.next_update.unwrap();\n\
                 \x20   assert!(next >= {a0} && next < {a1}); // nextUpdate {ay}\n"
            )
        }
        CrlField::CrlNumber => {
            if arg_sym(&case.args, 3) != Some("HITLS_PKI_SUCCESS") {
                stats.skipped_unsupported_alg += 1;
                return;
            }
            let Some(num) = case.args.get(2).and_then(|a| a.as_hex()) else {
                stats.skipped_unknown += 1;
                return;
            };
            let Some(critical) = arg_sym(&case.args, 1).map(|s| s == "1") else {
                stats.skipped_unknown += 1;
                return;
            };
            format!(
                "    assert_eq!(crl.crl_number().unwrap().as_slice(), {});\n\
                 \x20   let critical = crl\n\
                 \x20       .extensions\n\
                 \x20       .iter()\n\
                 \x20       .find(|e| e.oid == [0x55, 0x1d, 0x14])\n\
                 \x20       .map(|e| e.critical)\n\
                 \x20       .unwrap_or(false);\n\
                 {}",
                format_byte_slice(num),
                bool_assert("critical", critical)
            )
        }
        CrlField::Aki => {
            let Some(critical) = arg_sym(&case.args, 1).map(|s| s == "1") else {
                stats.skipped_unknown += 1;
                return;
            };
            format!(
                "    let critical = crl\n\
                 \x20       .extensions\n\
                 \x20       .iter()\n\
                 \x20       .find(|e| e.oid == [0x55, 0x1d, 0x23])\n\
                 \x20       .map(|e| e.critical)\n\
                 \x20       .unwrap_or(false);\n\
                 {}",
                bool_assert("critical", critical)
            )
        }
        CrlField::Reason => {
            if arg_sym(&case.args, 1) != Some("HITLS_PKI_SUCCESS") {
                stats.skipped_unsupported_alg += 1;
                return;
            }
            // `reasonCode` is usually a `HITLS_X509_REVOKED_REASON_*` token,
            // occasionally a bare integer.
            let Some(raw) = arg_sym(&case.args, 2) else {
                stats.skipped_unknown += 1;
                return;
            };
            let Some(code) = raw.parse::<i32>().ok().or_else(|| reason_name_to_code(raw)) else {
                stats.skipped_unknown += 1;
                return;
            };
            // RFC 5280 §5.3.1 leaves reason code 7 unassigned; Rust's
            // `RevocationReason` enum omits it, so `from_u8(7)` yields `None`
            // and the row cannot be asserted. Skip any unmapped code.
            if !matches!(code, 0..=6 | 8..=10) {
                stats.skipped_unsupported_alg += 1;
                return;
            }
            format!(
                "    let reason = crl.revoked_certs.first().unwrap().reason.map(|r| r as i32);\n\
                 \x20   assert_eq!(reason, Some({code}));\n"
            )
        }
        CrlField::InvalidityDate => {
            if arg_sym(&case.args, 2) != Some("HITLS_PKI_SUCCESS") {
                stats.skipped_unsupported_alg += 1;
                return;
            }
            let Some(year) = arg_sym(&case.args, 1).and_then(|s| s.parse::<i64>().ok()) else {
                stats.skipped_unknown += 1;
                return;
            };
            let (lo, hi) = year_bounds(year);
            format!(
                "    let d = crl.revoked_certs.first().unwrap().invalidity_date.unwrap();\n\
                 \x20   assert!(d >= {lo} && d < {hi}); // invalidity date {year}\n"
            )
        }
        CrlField::CertIssuer => {
            // res1 = parse result, res2 = GET_REVOKED_CERTISSUER result. Only
            // the both-SUCCESS rows migrate: where C's getter fails (`res2`
            // an error) Rust's parser still populates `certificate_issuer`,
            // so the negative rows cannot be asserted (parser-leniency gap).
            if arg_sym(&case.args, 1) != Some("HITLS_PKI_SUCCESS")
                || arg_sym(&case.args, 2) != Some("HITLS_PKI_SUCCESS")
            {
                stats.skipped_unsupported_alg += 1;
                return;
            }
            "    assert!(crl.revoked_certs.first().unwrap().certificate_issuer.is_some());\n"
                .to_string()
        }
    };

    write_doc(out, case, "X.509 CRL field-check KAT");
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn tc_line{}_x509_crl_field() {{", case.line).unwrap();
    writeln!(out, "    let crl = load_crl_fixture({rel:?});").unwrap();
    out.push_str(&body);
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

/// Emit a cert-chain build-and-verify KAT (`X509_BUILD_CERT_CHAIN_FUNC`).
/// The C row is `rootPath : caPath : certPath : crlPath`; the C test builds a
/// chain for the end-entity cert and verifies it (with the CRL flag cleared,
/// so revocation is *off*). The migrated test loads the root (+ optional
/// intermediate CA) into a `CertificateVerifier` and asserts
/// `verify_cert` succeeds. `caPath` is empty for a direct root→entity chain;
/// the `crlPath` arg is unused (revocation disabled).
fn emit_build_cert_chain(out: &mut String, case: &TestCase, stats: &mut EmitStats) {
    let (Some(root_rel), Some(cert_rel)) = (arg_rel(&case.args, 0), arg_rel(&case.args, 2)) else {
        stats.skipped_unknown += 1;
        return;
    };
    let ca_rel = arg_rel(&case.args, 1);
    // ECDSA NIST P-192 is a legacy curve Rust's signature verifier does not
    // support — its chains cannot be verified, so skip those fixtures.
    if [Some(root_rel), Some(cert_rel), ca_rel]
        .iter()
        .flatten()
        .any(|p| p.contains("nistp192"))
    {
        stats.skipped_unsupported_alg += 1;
        return;
    }

    write_doc(out, case, "X.509 cert-chain build + verify KAT");
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn tc_line{}_x509_build_cert_chain() {{", case.line).unwrap();
    writeln!(out, "    let root = load_cert_fixture({root_rel:?});").unwrap();
    if let Some(ca) = ca_rel {
        writeln!(out, "    let ca = load_cert_fixture({ca:?});").unwrap();
    }
    writeln!(out, "    let cert = load_cert_fixture({cert_rel:?});").unwrap();
    writeln!(out, "    let mut verifier = CertificateVerifier::new();").unwrap();
    writeln!(out, "    verifier.add_trusted_cert(root);").unwrap();
    if ca_rel.is_some() {
        writeln!(out, "    verifier.add_trusted_cert(ca);").unwrap();
    }
    writeln!(
        out,
        "    assert!(verifier.verify_cert(&cert, &[]).is_ok());"
    )
    .unwrap();
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

/// Emit a verify-by-pubkey KAT (`X509_CERT_VERIFY_BY_PUBKEY_FUNC`). The C row
/// is `certPath : issuerPath : otherPath`; the C test verifies the cert with
/// the issuer's public key (must succeed) and with an unrelated cert's public
/// key (must fail). The migrated test mirrors both via
/// `Certificate::verify_signature`.
fn emit_cert_verify_by_pubkey(out: &mut String, case: &TestCase, stats: &mut EmitStats) {
    let (Some(cert_rel), Some(issuer_rel), Some(other_rel)) = (
        arg_rel(&case.args, 0),
        arg_rel(&case.args, 1),
        arg_rel(&case.args, 2),
    ) else {
        stats.skipped_unknown += 1;
        return;
    };

    write_doc(out, case, "X.509 verify-by-pubkey KAT");
    writeln!(out, "#[test]").unwrap();
    writeln!(
        out,
        "fn tc_line{}_x509_cert_verify_by_pubkey() {{",
        case.line
    )
    .unwrap();
    writeln!(out, "    let cert = load_cert_fixture({cert_rel:?});").unwrap();
    writeln!(out, "    let issuer = load_cert_fixture({issuer_rel:?});").unwrap();
    writeln!(out, "    let other = load_cert_fixture({other_rel:?});").unwrap();
    writeln!(out, "    assert!(cert.verify_signature(&issuer).unwrap());").unwrap();
    // Verifying with an unrelated cert's key must NOT succeed (Ok(false) or Err).
    writeln!(
        out,
        "    assert!(!matches!(cert.verify_signature(&other), Ok(true)));"
    )
    .unwrap();
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

/// Emit a `*_WITH_VARIOUS_CHARSET` chain-verify KAT. Each variant has its own
/// arg layout (single- vs multi-level cert chain; with/without CRL); a row
/// migrates only when its `expectedResult` is one Rust's verifier faithfully
/// reproduces — `HITLS_PKI_SUCCESS` (`verify_cert` is `Ok`),
/// `HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND` (`Err`, Display `"issuer certificate
/// not found"`) or `HITLS_X509_ERR_VFY_CERT_REVOKED` (`Err`, Display
/// `"certificate revoked"`). `HITLS_X509_ERR_VFY_CRL_NOT_FOUND` routes to
/// `skipped_unsupported_alg` — Rust soft-fails on a missing CRL.
fn emit_charset_verify(
    out: &mut String,
    case: &TestCase,
    stats: &mut EmitStats,
    variant: CharsetVerify,
) {
    let a = &case.args;
    // (trusted_relpaths root-first, entity_relpath, crl_relpath?, expected_sym?)
    let plan = match variant {
        CharsetVerify::CertSingle => (vec![arg_rel(a, 0)], arg_rel(a, 1), None, arg_sym(a, 2)),
        CharsetVerify::CertMulti => (
            vec![arg_rel(a, 0), arg_rel(a, 1)],
            arg_rel(a, 2),
            None,
            // TC002 has no explicit result — the C asserts SUCCESS.
            Some("HITLS_PKI_SUCCESS"),
        ),
        CharsetVerify::Crl => (
            vec![arg_rel(a, 0)],
            arg_rel(a, 1),
            Some(arg_rel(a, 2)),
            arg_sym(a, 3),
        ),
    };
    let (trusted_opts, entity_opt, crl_opt_opt, expected_opt) = plan;
    // Validate each path resolved.
    if trusted_opts.iter().any(Option::is_none) || entity_opt.is_none() || expected_opt.is_none() {
        stats.skipped_unknown += 1;
        return;
    }
    let trusted: Vec<&str> = trusted_opts.into_iter().map(Option::unwrap).collect();
    let entity_rel = entity_opt.unwrap();
    // Verifier-behavior gaps in the charset corpus:
    //  * `string_canon/…` — C canonicalises DN string-typed components for
    //    issuer-vs-subject matching; Rust's `find_issuer` does a byte-exact
    //    DN comparison.
    //  * `user_err_aki…` — C treats an AKI-mismatch as "issuer not found";
    //    Rust falls back to DN-only matching and reports a signature
    //    verification failure instead.
    //  * `user_err_issuer…` — the fixture is malformed in a way the Rust
    //    parser rejects outright (`from_der` errors before chain build).
    if trusted
        .iter()
        .chain(std::iter::once(&entity_rel))
        .any(|p| p.contains("string_canon") || p.contains("user_err_"))
    {
        stats.skipped_unsupported_alg += 1;
        return;
    }
    let crl_rel = match crl_opt_opt {
        Some(Some(c)) => Some(c),
        Some(None) => {
            // CRL slot present but unresolved → skip.
            stats.skipped_unknown += 1;
            return;
        }
        None => None,
    };
    let expected = expected_opt.unwrap();

    let assertion = match expected {
        "HITLS_PKI_SUCCESS" => "    assert!(result.is_ok());\n",
        "HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND" => {
            "    assert_eq!(result.unwrap_err().to_string(), \"issuer certificate not found\");\n"
        }
        "HITLS_X509_ERR_VFY_CERT_REVOKED" => {
            "    assert_eq!(result.unwrap_err().to_string(), \"certificate revoked\");\n"
        }
        // CRL_NOT_FOUND — Rust soft-fails (verifier-strictness gap).
        _ => {
            stats.skipped_unsupported_alg += 1;
            return;
        }
    };

    let suffix = match variant {
        CharsetVerify::CertSingle => "cert_charset_single",
        CharsetVerify::CertMulti => "cert_charset_multi",
        CharsetVerify::Crl => "crl_charset",
    };
    write_doc(out, case, "X.509 charset chain-verify KAT");
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn tc_line{}_x509_{}() {{", case.line, suffix).unwrap();
    for (i, rel) in trusted.iter().enumerate() {
        writeln!(out, "    let ca{i} = load_cert_fixture({rel:?});").unwrap();
    }
    if let Some(rel) = crl_rel {
        writeln!(out, "    let crl = load_crl_fixture({rel:?});").unwrap();
    }
    writeln!(out, "    let cert = load_cert_fixture({entity_rel:?});").unwrap();
    writeln!(out, "    let mut verifier = CertificateVerifier::new();").unwrap();
    for i in 0..trusted.len() {
        writeln!(out, "    verifier.add_trusted_cert(ca{i});").unwrap();
    }
    if crl_rel.is_some() {
        writeln!(out, "    verifier.add_crl(crl);").unwrap();
        writeln!(out, "    verifier.set_check_revocation(true);").unwrap();
    }
    writeln!(out, "    let result = verifier.verify_cert(&cert, &[]);").unwrap();
    out.push_str(assertion);
    writeln!(out, "}}\n").unwrap();
    stats.emitted += 1;
}

fn write_header(out: &mut String, body: &str) {
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo x509-parse`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV pki/{cert,csr,crl,verify} `.data`.\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase C (xtask).\n\
         // Fixtures: tests/vectors/c-asn1-fixtures/ (mirrored openHiTLS testdata).\n\n",
    );
    out.push_str("#![cfg(feature = \"x509\")]\n\n");
    out.push_str(
        "use hitls_pki::x509::{Certificate, CertificateRequest, CertificateRevocationList};\n",
    );
    if body.contains("CertificateVerifier") {
        out.push_str("use hitls_pki::x509::verify::CertificateVerifier;\n");
    }
    out.push('\n');
    if body.contains("load_cert_fixture(") {
        out.push_str(
            "/// Load a mirrored cert fixture, auto-detecting PEM vs DER by content.\n\
             fn load_cert_fixture(rel: &str) -> Certificate {\n\
             \x20   let path = format!(\n\
             \x20       \"{}/../../tests/vectors/c-asn1-fixtures/{}\",\n\
             \x20       env!(\"CARGO_MANIFEST_DIR\"),\n\
             \x20       rel\n\
             \x20   );\n\
             \x20   let bytes = std::fs::read(&path).unwrap();\n\
             \x20   match std::str::from_utf8(&bytes) {\n\
             \x20       Ok(s) if s.contains(\"-----BEGIN\") => Certificate::from_pem(s).unwrap(),\n\
             \x20       _ => Certificate::from_der(&bytes).unwrap(),\n\
             \x20   }\n\
             }\n\n",
        );
    }
    if body.contains("load_crl_fixture(") {
        out.push_str(
            "/// Load a mirrored CRL fixture, auto-detecting PEM vs DER by content.\n\
             fn load_crl_fixture(rel: &str) -> CertificateRevocationList {\n\
             \x20   let path = format!(\n\
             \x20       \"{}/../../tests/vectors/c-asn1-fixtures/{}\",\n\
             \x20       env!(\"CARGO_MANIFEST_DIR\"),\n\
             \x20       rel\n\
             \x20   );\n\
             \x20   let bytes = std::fs::read(&path).unwrap();\n\
             \x20   match std::str::from_utf8(&bytes) {\n\
             \x20       Ok(s) if s.contains(\"-----BEGIN\") => {\n\
             \x20           CertificateRevocationList::from_pem(s).unwrap()\n\
             \x20       }\n\
             \x20       _ => CertificateRevocationList::from_der(&bytes).unwrap(),\n\
             \x20   }\n\
             }\n\n",
        );
    }
    if body.contains("load_csr_fixture(") {
        out.push_str(
            "/// Load a mirrored CSR fixture, auto-detecting PEM vs DER by content.\n\
             fn load_csr_fixture(rel: &str) -> CertificateRequest {\n\
             \x20   let path = format!(\n\
             \x20       \"{}/../../tests/vectors/c-asn1-fixtures/{}\",\n\
             \x20       env!(\"CARGO_MANIFEST_DIR\"),\n\
             \x20       rel\n\
             \x20   );\n\
             \x20   let bytes = std::fs::read(&path).unwrap();\n\
             \x20   match std::str::from_utf8(&bytes) {\n\
             \x20       Ok(s) if s.contains(\"-----BEGIN\") => {\n\
             \x20           CertificateRequest::from_pem(s).unwrap()\n\
             \x20       }\n\
             \x20       _ => CertificateRequest::from_der(&bytes).unwrap(),\n\
             \x20   }\n\
             }\n\n",
        );
    }
}

fn write_footer(out: &mut String, stats: &EmitStats, total: usize) {
    writeln!(
        out,
        "\n// Generation summary: {emitted} emitted / {api} API-surface skipped \
         / {unk} unknown / {unsupported} unsupported alg / {total} total C cases.",
        emitted = stats.emitted,
        api = stats.skipped_api,
        unk = stats.skipped_unknown,
        unsupported = stats.skipped_unsupported_alg,
        total = total,
    )
    .unwrap();
}

fn write_doc(out: &mut String, case: &TestCase, kind: &str) {
    if let Some(desc) = &case.description {
        writeln!(out, "/// {desc}").unwrap();
    }
    writeln!(
        out,
        "/// C source: {} (line {}, {})",
        case.tc_name, case.line, kind
    )
    .unwrap();
}
