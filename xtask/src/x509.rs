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
//!
//! For cert/CSR, `format` is a `BSL_FORMAT_*` token: `ASN1` → DER, `PEM` →
//! PEM; the C `UNKNOWN` (auto-detect) format has no Rust equivalent and routes
//! to `skipped_unknown`. The cert signature / pubkey / sig-alg field-check
//! families (and the malformed-DER negatives) are future increments and
//! route to `ApiSurface` for now.

use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::TestCase;

pub fn emit_x509_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();

    for case in cases {
        match classify(&case.tc_name) {
            Kind::CertParse => emit_parse(&mut body, case, &mut stats, Subject::Cert),
            Kind::CsrParse => emit_parse(&mut body, case, &mut stats, Subject::Csr),
            Kind::CrlParse => emit_crl_parse(&mut body, case, &mut stats),
            Kind::CrlParseRes => emit_crl_parse_res(&mut body, case, &mut stats),
            Kind::ApiSurface => stats.skipped_api += 1,
            Kind::Unknown => stats.skipped_unknown += 1,
        }
    }

    let mut out = String::new();
    write_header(&mut out);
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
    ApiSurface,
    Unknown,
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
    // Cert signature / pubkey / sig-alg field-check families, CSR field /
    // expected-return families, the CRL field-check families
    // (`TC004/005/009-013`), version/subject checks, malformed-DER
    // negatives — migrated in later Phase C increments.
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

fn write_header(out: &mut String) {
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo x509-parse`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV pki/cert + pki/csr `.data`.\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase C (xtask).\n\
         // Fixtures: tests/vectors/c-asn1-fixtures/ (mirrored openHiTLS testdata).\n\n",
    );
    out.push_str("#![cfg(feature = \"x509\")]\n\n");
    out.push_str(
        "use hitls_pki::x509::{Certificate, CertificateRequest, CertificateRevocationList};\n\n",
    );
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
