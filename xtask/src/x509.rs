//! Emitter for the openHiTLS C `pki/cert` + `pki/csr` SDV files — X.509
//! certificate / CSR parse KAT (`docs/c-test-migration-plan.md` Phase C).
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
//!
//! `format` is a `BSL_FORMAT_*` token: `ASN1` → DER, `PEM` → PEM. The C
//! `UNKNOWN` (auto-detect) format has no Rust equivalent — those rows route
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
    // Cert signature / pubkey / sig-alg field-check families, CSR field /
    // expected-return families, version/subject checks, malformed-DER
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

fn write_header(out: &mut String) {
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo x509-parse`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV pki/cert + pki/csr `.data`.\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase C (xtask).\n\
         // Fixtures: tests/vectors/c-asn1-fixtures/ (mirrored openHiTLS testdata).\n\n",
    );
    out.push_str("#![cfg(feature = \"x509\")]\n\n");
    out.push_str("use hitls_pki::x509::{Certificate, CertificateRequest};\n\n");
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
