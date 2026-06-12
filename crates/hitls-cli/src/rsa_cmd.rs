//! `rsa` CLI subcommand — legacy OpenSSL-compatible RSA-specific key
//! inspection and format conversion. Counterpart of `pkey` restricted
//! to RSA, with the legacy PKCS#1 (`RSA PRIVATE KEY`) PEM output label
//! and `-noout` semantics that `pkey` doesn't expose.
//!
//! ```text
//! rsa -in <priv.pem> [-out <file>] [-text] [-noout]
//! rsa -help
//! ```
//!
//! Mirrors openHiTLS C `apps/src/app_rsa.c` and the
//! `UT_HITLS_APP_rsa_TC*` test family in
//! `testcode/sdv/testcase/apps/test_suite_ut_app_rsa.c`.
//!
//! ## Scope (this PR, #47-E)
//!
//! - **TC001** (6 sub-cases: `-noout`, `-out`, `-out -text`,
//!   `-out -text -noout`, invalid `-out` path, missing `-in` file) —
//!   ported as `ut_rsa_tc001_*`.
//! - **TC002** (`-help`) — ported as `ut_rsa_tc002_help`.
//! - **T003–T012** — these are stub-based C unit tests that replace
//!   internal functions (`HITLS_APP_OptBegin`, `CRYPT_EAL_DecodeBuffKey`,
//!   `BSL_UIO_New`, `BSL_UIO_Ctrl`, `HITLS_APP_OptGetValueStr`, etc.)
//!   to force specific error paths inside the C `HITLS_RsaMain`. The
//!   Rust implementation uses different internal call paths (no
//!   `BSL_UIO` layer, no `CRYPT_EAL_DecodeBuffKey` indirection), so
//!   these stub-based negative paths have **no direct Rust analogue**.
//!   They are scope-cut and documented in `crates/hitls-cli/README.md`.
//!
//! `TODO(#47-rsa-codec-extract)` — the RSA PKCS#1 encoder (CRT
//! computation + 9-INTEGER SEQUENCE) is now inlined in genrsa.rs,
//! pkey.rs, and here. Per the T190 sub-PR-cross-reuse note, the
//! shared codec should be extracted to `hitls-pki::pkcs8` after the
//! #47 series closes.

use std::fs;

/// Exit-code category, modelled on openHiTLS C `app_errno.h`.
///
/// Same enum shape as `genrsa.rs::GenrsaResult` so the integration
/// tests can pin behaviour the same way the C
/// `UT_HITLS_APP_rsa_TC*` cases do.
#[derive(Debug, PartialEq, Eq)]
pub enum RsaResult {
    /// `-help` was requested. Maps to C `HITLS_APP_HELP`.
    Help,
    /// Key decoded (and optionally written/printed). Maps to C
    /// `HITLS_APP_SUCCESS`.
    Success,
    /// An option's value is missing, malformed, or out of the allowed
    /// set. Maps to C `HITLS_APP_OPT_VALUE_INVALID`.
    OptInvalid,
    /// An option flag is unknown. Maps to C `HITLS_APP_OPT_UNKOWN`.
    OptUnknown,
    /// File / output I/O failed (path not writable, etc.). Maps to C
    /// `HITLS_APP_UIO_FAIL`.
    UioFail,
    /// The input PEM could not be decoded as an RSA private key. Maps
    /// to C `HITLS_APP_DECODE_FAIL`.
    DecodeFail,
}

/// Parse + validate `argv` and run the `rsa` subcommand. Output goes
/// to stdout unless `-out <path>` is given.
pub fn run_argv(argv: &[&str]) -> RsaResult {
    let args = &argv[1..];

    let mut input: Option<&str> = None;
    let mut output: Option<&str> = None;
    let mut text = false;
    let mut noout = false;
    let mut help = false;

    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "-help" => {
                help = true;
                i += 1;
            }
            "-in" => {
                let v = match args.get(i + 1) {
                    Some(v) => v,
                    None => return RsaResult::OptInvalid,
                };
                if v.is_empty() {
                    return RsaResult::OptInvalid;
                }
                input = Some(*v);
                i += 2;
            }
            "-out" => {
                let v = match args.get(i + 1) {
                    Some(v) => v,
                    None => return RsaResult::OptInvalid,
                };
                if v.is_empty() {
                    return RsaResult::OptInvalid;
                }
                output = Some(*v);
                i += 2;
            }
            "-text" => {
                text = true;
                i += 1;
            }
            "-noout" => {
                noout = true;
                i += 1;
            }
            "" => return RsaResult::OptUnknown,
            other if other.starts_with('-') => return RsaResult::OptUnknown,
            _ => return RsaResult::OptUnknown,
        }
    }

    if help {
        return RsaResult::Help;
    }

    let in_path = match input {
        Some(p) => p,
        None => return RsaResult::OptInvalid,
    };

    let pem = match fs::read_to_string(in_path) {
        Ok(s) => s,
        Err(_) => return RsaResult::DecodeFail,
    };
    let key = match hitls_pki::pkcs8::parse_pkcs8_pem(&pem) {
        Ok(k) => k,
        Err(_) => return RsaResult::DecodeFail,
    };
    // OpenSSL `rsa` only accepts RSA keys.
    let rsa = match key {
        hitls_pki::pkcs8::Pkcs8PrivateKey::Rsa(r) => r,
        _ => return RsaResult::DecodeFail,
    };

    if text {
        print_rsa_text(&rsa);
    }

    if noout {
        // -noout: don't write the key. SUCCESS as long as decode passed.
        return RsaResult::Success;
    }

    let pkcs1_pem = match encode_rsa_pkcs1_pem(&rsa) {
        Ok(p) => p,
        Err(_) => return RsaResult::DecodeFail,
    };
    if let Some(path) = output {
        if fs::write(path, &pkcs1_pem).is_err() {
            return RsaResult::UioFail;
        }
    } else {
        print!("{pkcs1_pem}");
    }
    RsaResult::Success
}

/// `clap`-style entry point used by `main.rs`.
pub fn run(
    input: &str,
    out: Option<&str>,
    text: bool,
    noout: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut argv: Vec<String> = vec!["rsa".into(), "-in".into(), input.into()];
    if let Some(o) = out {
        argv.push("-out".into());
        argv.push(o.into());
    }
    if text {
        argv.push("-text".into());
    }
    if noout {
        argv.push("-noout".into());
    }
    let argv_ref: Vec<&str> = argv.iter().map(String::as_str).collect();
    match run_argv(&argv_ref) {
        RsaResult::Success | RsaResult::Help => Ok(()),
        RsaResult::OptInvalid => Err("invalid option value".into()),
        RsaResult::OptUnknown => Err("unknown option".into()),
        RsaResult::UioFail => Err("I/O failure writing key".into()),
        RsaResult::DecodeFail => Err("RSA key decode failed".into()),
    }
}

fn print_rsa_text(key: &hitls_crypto::rsa::RsaPrivateKey) {
    let pub_key = key.public_key();
    println!("RSA Private-Key: ({} bit, 2 primes)", pub_key.bits());
}

/// Encode an RSA private key as a PEM-wrapped PKCS#1 `RSAPrivateKey`
/// DER (RFC 8017 §A.1.2). Label: `RSA PRIVATE KEY`.
///
/// **NOTE**: This is the **third** inlined instance of this encoder
/// (also in `genrsa.rs` T189 and `pkey.rs` T190). Per the T190
/// sub-PR-cross-reuse note, the shared codec should be extracted to
/// `hitls-pki::pkcs8::encode_rsa_pkcs1_der` after the #47 series
/// closes. `TODO(#47-rsa-codec-extract)` tracks the refactor.
fn encode_rsa_pkcs1_pem(
    key: &hitls_crypto::rsa::RsaPrivateKey,
) -> Result<String, Box<dyn std::error::Error>> {
    use hitls_bignum::BigNum;
    use hitls_utils::asn1::Encoder;

    let n_be = key.n_bytes();
    let e_be = key.e_bytes();
    let d_be = key.d_bytes();
    let p_be = key.p_bytes();
    let q_be = key.q_bytes();

    let d = BigNum::from_bytes_be(&d_be);
    let p = BigNum::from_bytes_be(&p_be);
    let q = BigNum::from_bytes_be(&q_be);
    let one = BigNum::from_u64(1);
    let p_minus_1 = p.sub(&one);
    let q_minus_1 = q.sub(&one);
    let (_, dp_bn) = d.div_rem(&p_minus_1)?;
    let (_, dq_bn) = d.div_rem(&q_minus_1)?;
    let dp = dp_bn.to_bytes_be();
    let dq = dq_bn.to_bytes_be();
    let qinv = q.mod_inv(&p)?.to_bytes_be();

    let mut enc = Encoder::new();
    enc.write_integer(&[0]);
    enc.write_integer(&n_be);
    enc.write_integer(&e_be);
    enc.write_integer(&d_be);
    enc.write_integer(&p_be);
    enc.write_integer(&q_be);
    enc.write_integer(&dp);
    enc.write_integer(&dq);
    enc.write_integer(&qinv);
    let body = enc.finish();
    let mut wrap = Encoder::new();
    wrap.write_sequence(&body);
    let der = wrap.finish();
    Ok(hitls_utils::pem::encode("RSA PRIVATE KEY", &der))
}

// ===========================================================================
// Tests — migrated from openHiTLS C
// `testcode/sdv/testcase/apps/test_suite_ut_app_rsa.{c,data}` TC001/TC002.
//
// C TC003-T012 use stub injection on internal functions
// (HITLS_APP_OptBegin, CRYPT_EAL_DecodeBuffKey, BSL_UIO_New,
//  BSL_UIO_Ctrl, HITLS_APP_OptGetValueStr) to force specific error
// paths inside C HITLS_RsaMain. The Rust implementation uses different
// internal call paths (no BSL_UIO layer, no CRYPT_EAL_DecodeBuffKey
// indirection), so these stub-based negative paths have no direct
// Rust analogue — documented as scope cuts in README.md.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn write_tmp_rsa_pkcs8(name: &str) -> PathBuf {
        // Build an RSA-2048 PKCS#8 PEM and write it to a tmp file.
        let key = hitls_crypto::rsa::RsaPrivateKey::generate(2048).unwrap();
        // Re-use the encoder path from genrsa.rs by building PKCS#1
        // then wrapping in PKCS#8 via the public hitls_pki helper.
        let pkcs1_pem = encode_rsa_pkcs1_pem(&key).unwrap();
        // For decoding via parse_pkcs8_pem we need PKCS#8. Build it.
        let blocks = hitls_utils::pem::parse(&pkcs1_pem).unwrap();
        let pkcs1_der = &blocks[0].data;
        let oid = hitls_utils::oid::known::rsa_encryption();
        let pkcs8_pem = hitls_pki::pkcs8::encode_pkcs8_pem_raw(&oid, None, pkcs1_der);

        let dir = std::env::temp_dir().join(format!("hitls_cli_rsa_{name}"));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("priv.pem");
        std::fs::write(&path, &pkcs8_pem).unwrap();
        path
    }

    fn tmp_out(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hitls_cli_rsa_{name}_out"));
        let _ = std::fs::create_dir_all(&dir);
        dir.join("out.pem")
    }

    // -----------------------------------------------------------------------
    // C UT_HITLS_APP_rsa_TC001 — 6 sub-cases mirroring the .data argv
    // matrix.
    // -----------------------------------------------------------------------

    #[test]
    fn ut_rsa_tc001_r0_in_noout_success() {
        // {"rsa", "-in", PRV_PATH, "-noout"} → SUCCESS
        let in_path = write_tmp_rsa_pkcs8("tc001_r0");
        assert_eq!(
            run_argv(&["rsa", "-in", in_path.to_str().unwrap(), "-noout"]),
            RsaResult::Success
        );
    }

    #[test]
    fn ut_rsa_tc001_r1_in_out_success() {
        // {"rsa", "-in", PRV_PATH, "-out", OUT_FILE_PATH} → SUCCESS
        let in_path = write_tmp_rsa_pkcs8("tc001_r1");
        let out_path = tmp_out("tc001_r1");
        assert_eq!(
            run_argv(&[
                "rsa",
                "-in",
                in_path.to_str().unwrap(),
                "-out",
                out_path.to_str().unwrap(),
            ]),
            RsaResult::Success
        );
        let written = std::fs::read_to_string(&out_path).unwrap();
        assert!(written.starts_with("-----BEGIN RSA PRIVATE KEY-----"));
    }

    #[test]
    fn ut_rsa_tc001_r2_in_out_text_success() {
        let in_path = write_tmp_rsa_pkcs8("tc001_r2");
        let out_path = tmp_out("tc001_r2");
        assert_eq!(
            run_argv(&[
                "rsa",
                "-in",
                in_path.to_str().unwrap(),
                "-out",
                out_path.to_str().unwrap(),
                "-text",
            ]),
            RsaResult::Success
        );
    }

    #[test]
    fn ut_rsa_tc001_r3_in_out_text_noout_success() {
        let in_path = write_tmp_rsa_pkcs8("tc001_r3");
        let out_path = tmp_out("tc001_r3");
        assert_eq!(
            run_argv(&[
                "rsa",
                "-in",
                in_path.to_str().unwrap(),
                "-out",
                out_path.to_str().unwrap(),
                "-text",
                "-noout",
            ]),
            RsaResult::Success
        );
    }

    #[test]
    fn ut_rsa_tc001_r4_out_path_unwritable_uio_fail() {
        let in_path = write_tmp_rsa_pkcs8("tc001_r4");
        assert_eq!(
            run_argv(&[
                "rsa",
                "-in",
                in_path.to_str().unwrap(),
                "-out",
                "/test/noexist/out.pem",
            ]),
            RsaResult::UioFail
        );
    }

    #[test]
    fn ut_rsa_tc001_r5_in_path_missing_decode_fail() {
        // {"rsa", "-in", "noexist.pem", "-text"} → DECODE_FAIL
        assert_eq!(
            run_argv(&["rsa", "-in", "/nonexistent_rsa_test/key.pem", "-text"]),
            RsaResult::DecodeFail
        );
    }

    // -----------------------------------------------------------------------
    // C UT_HITLS_APP_rsa_TC002 — -help.
    // -----------------------------------------------------------------------

    #[test]
    fn ut_rsa_tc002_help() {
        assert_eq!(run_argv(&["rsa", "-help"]), RsaResult::Help);
    }

    // -----------------------------------------------------------------------
    // Rust-extra: argv-validation negatives modelled on the genrsa.rs
    // pattern (the C source doesn't test these explicitly but they're
    // worth pinning).
    // -----------------------------------------------------------------------

    #[test]
    fn rust_extra_unknown_flag_rejected() {
        assert_eq!(
            run_argv(&["rsa", "-in", "/tmp/x.pem", "-bogus"]),
            RsaResult::OptUnknown
        );
    }

    #[test]
    fn rust_extra_missing_in_rejected() {
        assert_eq!(run_argv(&["rsa", "-noout"]), RsaResult::OptInvalid);
    }

    #[test]
    fn rust_extra_empty_in_value_rejected() {
        assert_eq!(
            run_argv(&["rsa", "-in", "", "-noout"]),
            RsaResult::OptInvalid
        );
    }

    #[test]
    fn rust_extra_ec_input_rejected_as_decode_fail() {
        // Feed an EC PKCS#8 key — the RSA-only `rsa` subcommand must
        // refuse it. C TC*** doesn't test this exact path but RSA-only
        // gating is a real C invariant.
        use hitls_types::EccCurveId;
        let kp = hitls_crypto::ecdsa::EcdsaKeyPair::generate(EccCurveId::NistP256).unwrap();
        let der =
            hitls_pki::pkcs8::encode_ec_pkcs8_der(EccCurveId::NistP256, &kp.private_key_bytes());
        let pem = hitls_utils::pem::encode("PRIVATE KEY", &der);
        let dir = std::env::temp_dir().join("hitls_cli_rsa_ec_in");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ec.pem");
        std::fs::write(&path, &pem).unwrap();
        assert_eq!(
            run_argv(&["rsa", "-in", path.to_str().unwrap(), "-noout"]),
            RsaResult::DecodeFail
        );
    }
}
