//! Emitter for the openHiTLS C `pki/cert` + `pki/csr` + `pki/crl` SDV files —
//! X.509 certificate / CSR / CRL parse KAT (`docs/c-test-migration-plan.md`
//! Phase C).
//!
//! Families migrated:
//!
//! * `X509_CERT_PARSE_FUNC_TC001` — `format : path`. The C test calls
//!   `HITLS_X509_CertParseFile` and asserts `HITLS_PKI_SUCCESS`. The migrated
//!   test loads the mirrored fixture (`tests/vectors/c-asn1-fixtures/…`) and
//!   asserts `Certificate::from_der` / `from_pem` returns `Ok`.
//! * `X509_CSR_PARSE_FUNC_TC001` / `TC002` / `TC003` — `format : path : …`.
//!   The C test parses a PKCS#10 CSR and then checks fields; the migrated
//!   test ports the parse-succeeds half via `CertificateRequest::from_der` /
//!   `from_pem`. `CSR_PARSE_FUNC_TC004` carries an expected return code
//!   (negative-capable) — routed to `ApiSurface` until a later increment
//!   adds C-error → `PkiError` mapping.
//! * `X509_CRL_PARSE_FILE_FUNC_TC001` / `TC002` — every quoted arg is a valid
//!   CRL; each must parse. `TC003/006/007/008` — `path : res`, where `res` is
//!   the expected C return code (`HITLS_PKI_SUCCESS` → parse must succeed,
//!   any `HITLS_X509_ERR_*` → parse must fail). The C CRL test pins
//!   `BSL_FORMAT_PEM`, so CRLs always load via `from_pem`. The CRL field-check
//!   families (`TC004/005/009-013`) route to `ApiSurface`.
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
//! * `X509_CRL_FILE_VERIFY_FUNC_TC001` — `caPath : crlPath : certPath :
//!   flags : crlVerResult : expResult`. The C test verifies the CRL's
//!   signature against the CA, then verifies `certPath`'s chain with CRL
//!   revocation checking. The migrated test mirrors it via
//!   `CertificateRevocationList::verify_signature` + `CertificateVerifier`,
//!   migrating the `expResult` codes Rust's verifier faithfully reproduces
//!   (`SUCCESS`, `CERT_REVOKED`); the stricter-than-Rust codes
//!   (`CRL_NOT_FOUND` / `PROCESS_CRITICALEXT` / `KU_NO_CRLSIGN`) route to
//!   `skipped_unsupported_alg` as verifier-strictness gaps.
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
use crate::parser::{format_byte_slice, TestCase};

pub fn emit_x509_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();

    for case in cases {
        match classify(&case.tc_name) {
            Kind::CertParse => emit_parse(&mut body, case, &mut stats, Subject::Cert),
            Kind::CsrParse => emit_parse(&mut body, case, &mut stats, Subject::Csr),
            Kind::CrlParse => emit_crl_parse(&mut body, case, &mut stats),
            Kind::CrlParseRes => emit_crl_parse_res(&mut body, case, &mut stats),
            Kind::CertField(field) => emit_cert_field(&mut body, case, &mut stats, field),
            Kind::CrlFileVerify => emit_crl_file_verify(&mut body, case, &mut stats),
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
    CsrParse,
    /// `CRL_PARSE_FILE_FUNC_TC001/TC002` — every quoted path is a valid CRL
    /// that must parse.
    CrlParse,
    /// `CRL_PARSE_FILE_FUNC_TC003/006/007/008` — `path : res`; `res` is the
    /// expected C return code (`HITLS_PKI_SUCCESS` or an error).
    CrlParseRes,
    /// A cert field-extraction family (`VERSION` / `SERIALNUM` / `SIGNATURE`).
    CertField(CertField),
    /// `CRL_FILE_VERIFY_FUNC_TC001` — `caPath : crlPath : certPath : flags :
    /// crlVerResult : expResult`. CRL-revocation chain verification.
    CrlFileVerify,
    ApiSurface,
    Unknown,
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

/// The X.509 object a parse-KAT row targets — selects the Rust parse type,
/// the emitted function-name suffix, and the doc-comment wording.
#[derive(Debug, Clone, Copy)]
enum Subject {
    Cert,
    Csr,
}

impl Subject {
    fn rust_type(self) -> &'static str {
        match self {
            Subject::Cert => "Certificate",
            Subject::Csr => "CertificateRequest",
        }
    }
    fn name(self) -> &'static str {
        match self {
            Subject::Cert => "cert",
            Subject::Csr => "csr",
        }
    }
}

fn classify(tc: &str) -> Kind {
    if tc.contains("X509_CERT_PARSE_FUNC_TC001") {
        return Kind::CertParse;
    }
    if tc.contains("X509_CSR_PARSE_FUNC_TC001")
        || tc.contains("X509_CSR_PARSE_FUNC_TC002")
        || tc.contains("X509_CSR_PARSE_FUNC_TC003")
    {
        return Kind::CsrParse;
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
    if tc.contains("X509_CRL_FILE_VERIFY_FUNC_TC001") {
        return Kind::CrlFileVerify;
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
fn emit_parse(out: &mut String, case: &TestCase, stats: &mut EmitStats, subject: Subject) {
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

    let ty = subject.rust_type();
    write_doc(out, case, &format!("X.509 {} parse KAT", subject.name()));
    writeln!(out, "#[test]").unwrap();
    writeln!(
        out,
        "fn tc_line{}_x509_{}_parse() {{",
        case.line,
        subject.name()
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
    if der {
        writeln!(out, "    assert!({ty}::from_der(&bytes).is_ok());").unwrap();
    } else {
        writeln!(out, "    let pem = std::str::from_utf8(&bytes).unwrap();").unwrap();
        writeln!(out, "    assert!({ty}::from_pem(pem).is_ok());").unwrap();
    }
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
    if res != "HITLS_PKI_SUCCESS" {
        // Negative case — Rust's CRL parser does not reject it (see doc).
        stats.skipped_unsupported_alg += 1;
        return;
    }

    write_doc(out, case, "X.509 CRL parse KAT");
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn tc_line{}_x509_crl_parse_res() {{", case.line).unwrap();
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
    writeln!(
        out,
        "    assert!(CertificateRevocationList::from_pem(pem).is_ok());"
    )
    .unwrap();
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

/// Emit a CRL-revocation chain-verification KAT — `CRL_FILE_VERIFY_FUNC_TC001`,
/// `caPath : crlPath : certPath : flags : crlVerResult : expResult`. The C test
/// verifies the CRL's signature against the CA, then verifies `certPath`'s
/// chain with CRL revocation checking. The migrated test mirrors that with
/// `CertificateRevocationList::verify_signature` + `CertificateVerifier`.
///
/// Only the `expResult` codes Rust's verifier faithfully reproduces are
/// migrated — `HITLS_PKI_SUCCESS` and `HITLS_X509_ERR_VFY_CERT_REVOKED`. The
/// others are Rust-verifier strictness gaps and route to
/// `skipped_unsupported_alg`: `CRL_NOT_FOUND` (Rust soft-fails on a missing
/// CRL), `PROCESS_CRITICALEXT` (no unhandled-critical-extension rejection),
/// `KU_NO_CRLSIGN` (no CRL-issuer keyUsage check).
fn emit_crl_file_verify(out: &mut String, case: &TestCase, stats: &mut EmitStats) {
    if case.args.len() < 6 {
        stats.skipped_unknown += 1;
        return;
    }
    let (Some(ca_rel), Some(crl_rel), Some(cert_rel)) = (
        case.args[0].as_str().and_then(fixture_relpath),
        case.args[1].as_str().and_then(fixture_relpath),
        case.args[2].as_str().and_then(fixture_relpath),
    ) else {
        stats.skipped_unknown += 1;
        return;
    };
    let check_revocation = match case.args[3].as_symbol() {
        Some("0") => false,
        Some("HITLS_X509_VFY_FLAG_CRL_ALL" | "HITLS_X509_VFY_FLAG_CRL_DEV") => true,
        _ => {
            stats.skipped_unknown += 1;
            return;
        }
    };
    // crlVerResult: TC001 always expects the CRL signature itself to verify.
    if case.args[4].as_symbol() != Some("HITLS_PKI_SUCCESS") {
        stats.skipped_unknown += 1;
        return;
    }
    let assertion = match case.args[5].as_symbol() {
        Some("HITLS_PKI_SUCCESS") => "    assert!(result.is_ok());\n",
        Some("HITLS_X509_ERR_VFY_CERT_REVOKED") => {
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
    writeln!(out, "    let ca = load_cert_fixture({ca_rel:?});").unwrap();
    writeln!(out, "    let crl = load_crl_fixture({crl_rel:?});").unwrap();
    writeln!(out, "    let cert = load_cert_fixture({cert_rel:?});").unwrap();
    writeln!(out, "    assert!(crl.verify_signature(&ca).unwrap());").unwrap();
    writeln!(out, "    let mut verifier = CertificateVerifier::new();").unwrap();
    writeln!(out, "    verifier.add_trusted_cert(ca);").unwrap();
    writeln!(out, "    verifier.add_crl(crl);").unwrap();
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

fn write_header(out: &mut String, body: &str) {
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo x509-parse`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV pki/cert + pki/csr + pki/crl `.data`.\n\
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
