//! Emitter for openHiTLS C `test_suite_sdv_bn.data` — BigNum arithmetic KATs.
//!
//! Migrates the deterministic `*_FUNC_TC*` families to byte-exact Rust tests
//! against `hitls_bignum::BigNum`. BigNum is signed and derives no
//! `PartialEq`, so the generated tests compare via `to_bytes_be()` (magnitude)
//! + `is_negative()` (sign) — see the `eq_signed` prelude helper.
//!
//! Families (operand/result hex carry a `sign` int: 0 = +, 1 = −):
//! * `BN_RSHIFT_FUNC_TC001` (`sign : hex : n : signRes : result`) → `shr(n)`
//! * `BN_MOD_FUNC_TC001` (`s1 : a : s2 : m : r`) → `mod_reduce` (positive
//!   modulus only — Rust/C differ on a negative modulus)
//! * `BN_SUB_FUNC_TC001` (`s1 : a : s2 : b : sRes : r`) → `sub`
//! * `BN_ADD_FUNC_TC001` (`s1 : s2 : s3 : a : b : r : expectRet`) → `add`
//!   (only `expectRet == CRYPT_SUCCESS` rows; Rust `add` cannot error)
//! * `BN_GCD_FUNC_TC001` (`s1 : a : s2 : b : r`) → `gcd`
//! * `BN_SQR_FUNC_TC001` (`s1 : a : r`) → `sqr`
//! * `BN_MODEXP_FUNC_TC001` (`s1 : a : e : m : r`) → `mod_exp`
//! * `BN_MODINV_FUNC_TC002` (`s : a : m : r`) → `mod_inv` (empty `r` ⇒ no
//!   inverse ⇒ `is_err`)
//! * `BN_DIV_FUNC_TC001` (`s1 : a : s2 : b : sQ : q : sR : r`) → `div_rem`
//!   (positive operands only — Rust/C differ on a negative dividend)
//! * `BN_PRIME_CHECK_FUNC_TC001` (`hex : isPrime`) → `is_probably_prime(64)`
//!
//! Skipped (→ API-surface): `CMP` (no signed-compare API, only `cmp_abs`),
//! `U64`/`UINT` (length-driven, not hex KATs), the single-limb families
//! (`ADDLIMB`/`SUB_LIMB`/`MULLIMB`/`DIVLIMB`), all `*_API_TC*` (input-check /
//! RNG), and the negative-modulus / negative-dividend rows noted above.

use std::fmt::Write;

use crate::digest::EmitStats;
use crate::parser::{format_byte_slice, TestCase};

pub fn emit_bn_kat(cases: &[TestCase]) -> (String, EmitStats) {
    let mut body = String::new();
    let mut stats = EmitStats::default();

    for case in cases {
        let name = &case.tc_name;
        if name.contains("BN_RSHIFT_FUNC_TC001") {
            emit_rshift(&mut body, case, &mut stats);
        } else if name.contains("BN_MODINV_FUNC_TC002") {
            emit_modinv(&mut body, case, &mut stats);
        } else if name.contains("BN_MODEXP_FUNC_TC001") {
            emit_modexp(&mut body, case, &mut stats);
        } else if name.contains("BN_MOD_FUNC_TC001") {
            emit_mod(&mut body, case, &mut stats);
        } else if name.contains("BN_SUB_FUNC_TC001") {
            emit_sub(&mut body, case, &mut stats);
        } else if name.contains("BN_ADD_FUNC_TC001") {
            emit_add(&mut body, case, &mut stats);
        } else if name.contains("BN_GCD_FUNC_TC001") {
            emit_gcd(&mut body, case, &mut stats);
        } else if name.contains("BN_SQR_FUNC_TC001") {
            emit_sqr(&mut body, case, &mut stats);
        } else if name.contains("BN_DIV_FUNC_TC001") {
            emit_div(&mut body, case, &mut stats);
        } else if name.contains("BN_PRIME_CHECK_FUNC_TC001") {
            emit_prime(&mut body, case, &mut stats);
        } else {
            stats.skipped_api += 1;
        }
    }

    let mut out = String::new();
    write_header(&mut out);
    out.push_str(&body);
    write_footer(&mut out, &stats, cases.len());
    (out, stats)
}

/// `sign` arg at index `i`: any non-zero integer ⇒ negative.
fn sign_at(case: &TestCase, i: usize) -> bool {
    case.args
        .get(i)
        .and_then(|a| a.as_symbol())
        .and_then(|s| s.parse::<i64>().ok())
        .map(|v| v != 0)
        .unwrap_or(false)
}

fn hex_at(case: &TestCase, i: usize) -> Option<&[u8]> {
    case.args.get(i).and_then(|a| a.as_hex())
}

fn is_zero_hex(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// `bn(<bytes>, <neg>)` constructor expression for the generated test.
fn bn_expr(bytes: &[u8], neg: bool) -> String {
    format!("bn({}, {neg})", format_byte_slice(bytes))
}

fn emit_rshift(out: &mut String, case: &TestCase, stats: &mut EmitStats) {
    // sign : hex : n : signRes : result
    let (Some(hex), Some(result)) = (hex_at(case, 1), hex_at(case, 4)) else {
        stats.skipped_unknown += 1;
        return;
    };
    let Some(n) = case
        .args
        .get(2)
        .and_then(|a| a.as_symbol())
        .and_then(|s| s.parse::<usize>().ok())
    else {
        stats.skipped_unknown += 1;
        return;
    };
    let sign = sign_at(case, 0);
    let sign_res = sign_at(case, 3);
    emit_fn(
        out,
        case,
        "rshift",
        &[format!(
            "assert!(eq_signed(&{}.shr({n}), {}, {sign_res}));",
            bn_expr(hex, sign),
            format_byte_slice(result)
        )],
    );
    stats.emitted += 1;
}

fn emit_mod(out: &mut String, case: &TestCase, stats: &mut EmitStats) {
    // sign1 : hex1 : sign2 : modulo : result
    let (Some(a), Some(m), Some(r)) = (hex_at(case, 1), hex_at(case, 3), hex_at(case, 4)) else {
        stats.skipped_unknown += 1;
        return;
    };
    // Negative modulus or modulus 0 → Rust/C diverge or error; skip.
    if sign_at(case, 2) || is_zero_hex(m) {
        stats.skipped_api += 1;
        return;
    }
    emit_fn(
        out,
        case,
        "mod",
        &[format!(
            "assert!(eq_signed(&{}.mod_reduce(&{}).unwrap(), {}, false));",
            bn_expr(a, sign_at(case, 0)),
            bn_expr(m, false),
            format_byte_slice(r)
        )],
    );
    stats.emitted += 1;
}

fn emit_sub(out: &mut String, case: &TestCase, stats: &mut EmitStats) {
    // sign1 : hex1 : sign2 : hex2 : signRes : result
    let (Some(a), Some(b), Some(r)) = (hex_at(case, 1), hex_at(case, 3), hex_at(case, 5)) else {
        stats.skipped_unknown += 1;
        return;
    };
    emit_fn(
        out,
        case,
        "sub",
        &[format!(
            "assert!(eq_signed(&{}.sub(&{}), {}, {}));",
            bn_expr(a, sign_at(case, 0)),
            bn_expr(b, sign_at(case, 2)),
            format_byte_slice(r),
            sign_at(case, 4)
        )],
    );
    stats.emitted += 1;
}

fn emit_add(out: &mut String, case: &TestCase, stats: &mut EmitStats) {
    // sign1 : sign2 : sign3 : a : b : r : expectRet
    let expect_ret = case.args.get(6).and_then(|a| a.as_symbol());
    if expect_ret != Some("CRYPT_SUCCESS") {
        // Error-path rows (e.g. CRYPT_NULL_INPUT) — Rust `add` cannot error.
        stats.skipped_api += 1;
        return;
    }
    let (Some(a), Some(b), Some(r)) = (hex_at(case, 3), hex_at(case, 4), hex_at(case, 5)) else {
        stats.skipped_unknown += 1;
        return;
    };
    emit_fn(
        out,
        case,
        "add",
        &[format!(
            "assert!(eq_signed(&{}.add(&{}), {}, {}));",
            bn_expr(a, sign_at(case, 0)),
            bn_expr(b, sign_at(case, 1)),
            format_byte_slice(r),
            sign_at(case, 2)
        )],
    );
    stats.emitted += 1;
}

fn emit_gcd(out: &mut String, case: &TestCase, stats: &mut EmitStats) {
    // sign1 : hex1 : sign2 : hex2 : result
    let (Some(a), Some(b), Some(r)) = (hex_at(case, 1), hex_at(case, 3), hex_at(case, 4)) else {
        stats.skipped_unknown += 1;
        return;
    };
    emit_fn(
        out,
        case,
        "gcd",
        &[format!(
            "assert!(eq_signed(&{}.gcd(&{}).unwrap(), {}, false));",
            bn_expr(a, sign_at(case, 0)),
            bn_expr(b, sign_at(case, 2)),
            format_byte_slice(r)
        )],
    );
    stats.emitted += 1;
}

fn emit_sqr(out: &mut String, case: &TestCase, stats: &mut EmitStats) {
    // sign1 : hex1 : result
    let (Some(a), Some(r)) = (hex_at(case, 1), hex_at(case, 2)) else {
        stats.skipped_unknown += 1;
        return;
    };
    emit_fn(
        out,
        case,
        "sqr",
        &[format!(
            "assert!(eq_signed(&{}.sqr(), {}, false));",
            bn_expr(a, sign_at(case, 0)),
            format_byte_slice(r)
        )],
    );
    stats.emitted += 1;
}

fn emit_modexp(out: &mut String, case: &TestCase, stats: &mut EmitStats) {
    // sign1 : base : exp : modulo : result
    let (Some(base), Some(e), Some(m), Some(r)) = (
        hex_at(case, 1),
        hex_at(case, 2),
        hex_at(case, 3),
        hex_at(case, 4),
    ) else {
        stats.skipped_unknown += 1;
        return;
    };
    if is_zero_hex(m) {
        stats.skipped_api += 1;
        return;
    }
    emit_fn(
        out,
        case,
        "modexp",
        &[format!(
            "assert!(eq_signed(&{}.mod_exp(&{}, &{}).unwrap(), {}, false));",
            bn_expr(base, sign_at(case, 0)),
            bn_expr(e, false),
            bn_expr(m, false),
            format_byte_slice(r)
        )],
    );
    stats.emitted += 1;
}

fn emit_modinv(out: &mut String, case: &TestCase, stats: &mut EmitStats) {
    // sign : hex : modulo : result   (empty result ⇒ no inverse ⇒ Err)
    let (Some(a), Some(m), Some(r)) = (hex_at(case, 1), hex_at(case, 2), hex_at(case, 3)) else {
        stats.skipped_unknown += 1;
        return;
    };
    if is_zero_hex(m) {
        stats.skipped_api += 1;
        return;
    }
    let assertion = if r.is_empty() {
        format!(
            "assert!({}.mod_inv(&{}).is_err());",
            bn_expr(a, sign_at(case, 0)),
            bn_expr(m, false)
        )
    } else {
        format!(
            "assert!(eq_signed(&{}.mod_inv(&{}).unwrap(), {}, false));",
            bn_expr(a, sign_at(case, 0)),
            bn_expr(m, false),
            format_byte_slice(r)
        )
    };
    emit_fn(out, case, "modinv", &[assertion]);
    stats.emitted += 1;
}

fn emit_div(out: &mut String, case: &TestCase, stats: &mut EmitStats) {
    // sign1 : hex1 : sign2 : hex2 : signQ : q : signR : r
    let (Some(a), Some(b), Some(q), Some(r)) = (
        hex_at(case, 1),
        hex_at(case, 3),
        hex_at(case, 5),
        hex_at(case, 7),
    ) else {
        stats.skipped_unknown += 1;
        return;
    };
    // Rust div_rem differs from C on negative operands; divisor 0 errors.
    if sign_at(case, 0) || sign_at(case, 2) || is_zero_hex(b) {
        stats.skipped_api += 1;
        return;
    }
    emit_fn(
        out,
        case,
        "div",
        &[
            format!(
                "let (q, r) = {}.div_rem(&{}).unwrap();",
                bn_expr(a, false),
                bn_expr(b, false)
            ),
            format!("assert!(eq_signed(&q, {}, false));", format_byte_slice(q)),
            format!("assert!(eq_signed(&r, {}, false));", format_byte_slice(r)),
        ],
    );
    stats.emitted += 1;
}

fn emit_prime(out: &mut String, case: &TestCase, stats: &mut EmitStats) {
    // hex : isPrime
    let Some(hex) = hex_at(case, 0) else {
        stats.skipped_unknown += 1;
        return;
    };
    let is_prime = sign_at(case, 1); // any non-zero ⇒ prime
    let assertion = if is_prime {
        format!(
            "assert!({}.is_probably_prime(64).unwrap());",
            bn_expr(hex, false)
        )
    } else {
        format!(
            "assert!(!{}.is_probably_prime(64).unwrap());",
            bn_expr(hex, false)
        )
    };
    emit_fn(out, case, "prime", &[assertion]);
    stats.emitted += 1;
}

fn emit_fn(out: &mut String, case: &TestCase, suffix: &str, body: &[String]) {
    write_doc(out, case);
    writeln!(out, "#[test]").unwrap();
    writeln!(out, "fn tc_line{}_bn_{suffix}() {{", case.line).unwrap();
    for stmt in body {
        writeln!(out, "    {stmt}").unwrap();
    }
    writeln!(out, "}}\n").unwrap();
}

fn write_doc(out: &mut String, case: &TestCase) {
    if let Some(desc) = &case.description {
        writeln!(out, "/// {desc}").unwrap();
    }
    writeln!(out, "/// C source: {} (line {})", case.tc_name, case.line).unwrap();
}

fn write_header(out: &mut String) {
    out.push_str(
        "// This file is GENERATED by `cargo xtask migrate-c-tests --algo bn`.\n\
         // DO NOT EDIT BY HAND. Source: openhitls C SDV test_suite_sdv_bn.data\n\
         //\n\
         // Generator: docs/c-test-migration-plan.md Phase A (xtask).\n\n",
    );
    out.push_str("use hitls_bignum::BigNum;\n\n");
    out.push_str(
        "/// Build a BigNum from big-endian magnitude bytes + sign.\n\
         fn bn(bytes: &[u8], neg: bool) -> BigNum {\n\
         \x20   let mut b = BigNum::from_bytes_be(bytes);\n\
         \x20   if neg && !b.is_zero() {\n\
         \x20       b.set_negative(true);\n\
         \x20   }\n\
         \x20   b\n\
         }\n\n",
    );
    out.push_str(
        "/// Signed equality: same magnitude (`to_bytes_be`) AND same sign.\n\
         fn eq_signed(got: &BigNum, bytes: &[u8], neg: bool) -> bool {\n\
         \x20   let exp = bn(bytes, neg);\n\
         \x20   got.to_bytes_be() == exp.to_bytes_be() && got.is_negative() == exp.is_negative()\n\
         }\n\n",
    );
}

fn write_footer(out: &mut String, stats: &EmitStats, total: usize) {
    writeln!(
        out,
        "\n// Generation summary: {emitted} emitted / {api} API-surface skipped \
         / {unk} unknown / {unsupported} unsupported / {total} total C cases.",
        emitted = stats.emitted,
        api = stats.skipped_api,
        unk = stats.skipped_unknown,
        unsupported = stats.skipped_unsupported_alg,
        total = total,
    )
    .unwrap();
}
