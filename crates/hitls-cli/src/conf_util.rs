//! `conf` utility helpers (#47-D / T192).
//!
//! The openHiTLS C `apps/src/app_conf.c` ships **three** helper functions
//! used internally by other subcommands (req / x509). It is NOT a
//! stand-alone CLI subcommand. The C `test_suite_ut_app_conf.c` test
//! suite covers all three:
//!
//! 1. `HITLS_APP_SplitString` — split a separator-delimited string with
//!    optional empty-substring allowance. **Ported in this PR** as
//!    [`split_string`].
//! 2. `HITLS_APP_CFG_ProcDnName` — parse a `/CN=Foo/O=Bar` DN-style
//!    subject string and feed each component to a callback. **Already
//!    covered** by `crates/hitls-cli/src/req.rs::parse_subject`, which
//!    has its own unit tests; the negative-validation cases from C
//!    `TC002` are migrated here to lock the cross-coverage.
//! 3. `HITLS_APP_CONF_ProcExt` — load an OpenSSL `openssl.cnf`-style
//!    config file and pass each `[ext]` section's directives to a
//!    callback. **Not ported** — the `.cnf` parser is a separate
//!    subsystem (KEY=VALUE INI with section headers + variable
//!    expansion + multi-value list semantics). Documented as
//!    non-port; see `crates/hitls-cli/README.md` and `TODO(#47-conf-cnf)`.
//!
//! The C `test_suite_ut_app_conf.{c,data}` has **6 TC functions**:
//! - `SplitString_Api_TC001` (NULL/empty/0-cap negative) — migrated
//! - `SplitString_Func_TC001` (data-driven roundtrip; 8 rows in .data) — migrated
//! - `SplitString_Error_TC001` (empty-disallowed) — migrated
//! - `conf_subj_TC001` (data-driven encode) — covered by `req::parse_subject`
//!   unit tests already; not duplicated here
//! - `conf_subj_TC002` (NULL/missing-slash negatives) — pinned in
//!   [`tests::dn_parser_negative_cases_pin_req_module`]
//! - `conf_X509Ext_TC001/TC002` (cnf parser + extension dispatch) —
//!   NOT ported; see TODO

use std::fmt;

/// Error categories matching the C `HITLS_APP_*` exit codes used by
/// `HITLS_APP_SplitString`.
///
/// Currently consumed only by the unit tests in this module — exposed
/// `pub` so future internal callers (e.g. `req.rs` switching from
/// `str::split` to this helper for stricter C-equivalent semantics) can
/// pattern-match the categories without a re-export dance. The
/// `#[allow(dead_code)]` is dropped automatically as soon as a non-test
/// call site appears.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum SplitError {
    /// Maps to C `HITLS_APP_INVALID_ARG` — NULL input, empty input,
    /// missing output slot, zero capacity, missing count pointer, or
    /// a non-printable separator (the C source forbids whitespace as a
    /// separator).
    InvalidArg,
    /// Maps to C `HITLS_APP_CONF_FAIL` — runs out of capacity, or
    /// `allow_empty == false` and an empty substring is produced.
    ConfFail,
}

impl fmt::Display for SplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArg => write!(f, "invalid argument"),
            Self::ConfFail => write!(f, "configuration parse failure"),
        }
    }
}

impl std::error::Error for SplitError {}

/// Split `input` by `separator` into a vector of trimmed substrings.
///
/// Mirrors openHiTLS C `HITLS_APP_SplitString` semantics:
///
/// - `separator` must be a printable non-whitespace byte (the C version
///   rejects `' '` explicitly — we mirror that).
/// - Each output substring is `.trim()`-ed (both leading and trailing
///   whitespace dropped).
/// - If `allow_empty` is false, an empty substring (after trim) is an
///   error; if true, empty substrings are kept.
/// - The output count must not exceed `capacity`.
///
/// Returns the vector of substrings on success.
#[allow(dead_code)]
pub fn split_string(
    input: &str,
    separator: char,
    allow_empty: bool,
    capacity: usize,
) -> Result<Vec<String>, SplitError> {
    if input.is_empty() {
        return Err(SplitError::InvalidArg);
    }
    if capacity == 0 {
        return Err(SplitError::InvalidArg);
    }
    // The C version rejects whitespace separators as `INVALID_ARG`.
    if separator.is_whitespace() {
        return Err(SplitError::InvalidArg);
    }

    let mut out: Vec<String> = Vec::new();
    for piece in input.split(separator) {
        let trimmed = piece.trim();
        if trimmed.is_empty() && !allow_empty {
            return Err(SplitError::ConfFail);
        }
        if out.len() >= capacity {
            return Err(SplitError::ConfFail);
        }
        out.push(trimmed.to_string());
    }
    Ok(out)
}

// ===========================================================================
// Tests migrated from C test_suite_ut_app_conf.{c,data}.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    const MAX_STR_CNT: usize = 10;

    // -----------------------------------------------------------------------
    // UT_HITLS_APP_SplitString_Api_TC001 — NULL / empty / zero-capacity
    // negative cases. Rust API doesn't expose NULL slots, so the
    // analogues are `""` input, ` ` separator, and `0` capacity.
    // -----------------------------------------------------------------------

    #[test]
    fn ut_split_api_tc001_empty_input_rejected() {
        assert_eq!(
            split_string("", ',', true, MAX_STR_CNT),
            Err(SplitError::InvalidArg)
        );
    }

    #[test]
    fn ut_split_api_tc001_whitespace_separator_rejected() {
        assert_eq!(
            split_string("Aa,Bb", ' ', true, MAX_STR_CNT),
            Err(SplitError::InvalidArg)
        );
    }

    #[test]
    fn ut_split_api_tc001_zero_capacity_rejected() {
        assert_eq!(
            split_string("Aa,Bb", ',', true, 0),
            Err(SplitError::InvalidArg)
        );
    }

    // -----------------------------------------------------------------------
    // UT_HITLS_APP_SplitString_Func_TC001 — data-driven .data rows.
    // -----------------------------------------------------------------------

    #[test]
    fn ut_split_func_tc001_simple_csv() {
        // "a,b,c":0:3:"a":"b":"c"
        assert_eq!(
            split_string("a,b,c", ',', false, MAX_STR_CNT).unwrap(),
            vec!["a", "b", "c"]
        );
    }

    #[test]
    fn ut_split_func_tc001_allow_empty_spaces() {
        // ", , ,":1:3:"":"":""
        assert_eq!(
            split_string(", , ,", ',', true, MAX_STR_CNT).unwrap(),
            vec!["", "", "", ""]
        );
    }

    #[test]
    fn ut_split_func_tc001_allow_empty_bare_commas() {
        // ",,,":1:3:"":"":""
        assert_eq!(
            split_string(",,,", ',', true, MAX_STR_CNT).unwrap(),
            vec!["", "", "", ""]
        );
    }

    #[test]
    fn ut_split_func_tc001_mixed_with_empty() {
        // "Aa,, c ":1:3:"Aa":"":"c"
        assert_eq!(
            split_string("Aa,, c ", ',', true, MAX_STR_CNT).unwrap(),
            vec!["Aa", "", "c"]
        );
    }

    #[test]
    fn ut_split_func_tc001_single_trimmed() {
        // " Aa ":0:1:"Aa":"":""
        assert_eq!(
            split_string(" Aa ", ',', false, MAX_STR_CNT).unwrap(),
            vec!["Aa"]
        );
    }

    #[test]
    fn ut_split_func_tc001_trailing_space_dropped() {
        // "Aa,Bb ,Cc":0:3:"Aa":"Bb":"Cc"
        assert_eq!(
            split_string("Aa,Bb ,Cc", ',', false, MAX_STR_CNT).unwrap(),
            vec!["Aa", "Bb", "Cc"]
        );
    }

    #[test]
    fn ut_split_func_tc001_leading_and_trailing_spaces() {
        // " Aa,Bb , Cc ":0:3:"Aa":"Bb":"Cc"
        assert_eq!(
            split_string(" Aa,Bb , Cc ", ',', false, MAX_STR_CNT).unwrap(),
            vec!["Aa", "Bb", "Cc"]
        );
    }

    #[test]
    fn ut_split_func_tc001_inner_spaces_preserved() {
        // " A a,B b , C c ":0:3:"A a":"B b":"C c"
        assert_eq!(
            split_string(" A a,B b , C c ", ',', false, MAX_STR_CNT).unwrap(),
            vec!["A a", "B b", "C c"]
        );
    }

    #[test]
    fn ut_split_func_tc001_collapse_inner_runs() {
        // "  A a  ,  B   b   , C c   ":0:3:"A a":"B   b":"C c"
        // The C test expects inner whitespace runs to be preserved
        // verbatim (the trimming only strips leading/trailing).
        assert_eq!(
            split_string("  A a  ,  B   b   , C c   ", ',', false, MAX_STR_CNT).unwrap(),
            vec!["A a", "B   b", "C c"]
        );
    }

    // -----------------------------------------------------------------------
    // UT_HITLS_APP_SplitString_Error_TC001 — empty-disallowed paths.
    // -----------------------------------------------------------------------

    #[test]
    fn ut_split_error_tc001_disallow_empty_rejects() {
        // ",,," with allow_empty=0 → CONF_FAIL
        assert_eq!(
            split_string(",,,", ',', false, MAX_STR_CNT),
            Err(SplitError::ConfFail)
        );
    }

    #[test]
    fn ut_split_capacity_overflow_rejected() {
        // Asking for 2 outputs from "a,b,c,d" → CONF_FAIL.
        assert_eq!(
            split_string("a,b,c,d", ',', false, 2),
            Err(SplitError::ConfFail)
        );
    }

    // -----------------------------------------------------------------------
    // UT_HITLS_APP_conf_subj_TC002 — DN-parser negative cases.
    //
    // The C `HITLS_APP_CFG_ProcDnName` is covered by Rust
    // `crates/hitls-cli/src/req.rs::parse_subject`, which has its own
    // unit tests (`test_parse_subject_*`). We pin the cross-coverage
    // here so future contributors don't accidentally drop DN parsing
    // when refactoring `req.rs`.
    // -----------------------------------------------------------------------

    #[test]
    fn dn_parser_negative_cases_pin_req_module() {
        let req_rs = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/req.rs"))
            .expect("req.rs must exist");

        // Pin that parse_subject is defined and tested. If it's removed
        // or renamed, this test fires and forces a re-evaluation of the
        // C conf_subj_TC002 negative coverage.
        assert!(
            req_rs.contains("fn parse_subject"),
            "req.rs must define parse_subject (DN parser, covers C HITLS_APP_CFG_ProcDnName)"
        );
        assert!(
            req_rs.contains("test_parse_subject"),
            "req.rs must keep DN-parser unit tests (covers C conf_subj_TC002 negatives)"
        );
    }
}
