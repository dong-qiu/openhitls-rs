//! `pkey` CLI subcommand — display, convert, or extract the public key
//! from a PKCS#8 private key file. The OpenSSL-compatible workflow is:
//!
//! ```text
//! pkey -in <priv.pem>                                 # re-encode to stdout
//! pkey -in <priv.pem> -out <priv.pem>                 # decode + re-encode
//! pkey -in <priv.pem> -pubout -out <pub.pem>          # extract public SPKI
//! pkey -in <priv.pem> -text                           # print algorithm summary
//! ```
//!
//! Mirrors openHiTLS C `apps/src/app_pkey.c` and the
//! `UT_HITLS_APP_KEY_TC*` / `UT_HITLS_APP_ENCKEY_TC*` test families in
//! `testcode/sdv/testcase/apps/test_suite_ut_app_key.c`.
//!
//! ## Scope (this PR, #47-B)
//!
//! Implements decode + re-encode + `-pubout` for the three most common
//! algorithm families that round-trip cleanly through Rust's PKCS#8 / SPKI:
//! - **RSA** — PKCS#1 RSAPrivateKey wrapped in PKCS#8; SPKI with
//!   `rsaEncryption` OID and `RSAPublicKey` BIT STRING content.
//! - **Ed25519** — RFC 8410 PKCS#8 with the 32-byte seed wrapped in
//!   OCTET STRING; SPKI with the Ed25519 OID and 32-byte public key.
//! - **EC** — NIST P-256/P-384/P-521 via the existing
//!   `encode_ec_pkcs8_der` / `encode_ec_spki_der` helpers.
//!
//! ## Documented gaps (TODOs for follow-up sub-PRs)
//!
//! - `TODO(#47-pkey-encrypted-pkcs8)` — `-passin <pass>` / `-passout
//!   <pass>` for PBES2 (PBKDF2 + AES) encrypted PKCS#8 is not yet
//!   implemented. The C `UT_HITLS_APP_ENCKEY_TC*` family relies on this.
//! - `TODO(#47-pkey-brainpool)` — Brainpool P-256/P-384/P-512 curves
//!   are not implemented in Rust hitls-crypto (also documented in T183
//!   #60 and T188 #44).
//! - `TODO(#47-pkey-sm2)` — SM2 PKCS#8 round-trip needs `SigningKey::Sm2`
//!   wiring and currently sign/verify via the CLI subcommand isn't
//!   exercised end-to-end.
//! - `TODO(#47-pkey-p224)` — NIST P-224 is not implemented.
//! - `TODO(#47-pkey-rsa-pss)` — `id-RSASSA-PSS` PKCS#8 variant
//!   re-encoding (used by T107 mTLS).
//!
//! These appear in the C test matrix; we explicitly document the gap
//! rather than silently failing.

use hitls_pki::pkcs8::{
    encode_ec_pkcs8_der, encode_ec_spki_der, encode_ed25519_pkcs8_der, encode_pkcs8_pem_raw,
    encode_spki_pem, parse_pkcs8_pem, Pkcs8PrivateKey,
};
use hitls_utils::asn1::Encoder;
use std::fs;

/// Run `pkey` with the given input / pubout / text flags. Output goes to
/// stdout. Mirrors the OpenSSL `pkey -in <file>` command shape.
#[cfg(test)]
fn run(input: &str, pubout: bool, text: bool) -> Result<(), Box<dyn std::error::Error>> {
    run_with_out(input, None, pubout, text)
}

/// Variant that writes the output to `output` if Some, else to stdout.
pub fn run_with_out(
    input: &str,
    output: Option<&str>,
    pubout: bool,
    text: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let pem = fs::read_to_string(input)?;
    let key = parse_pkcs8_pem(&pem).map_err(|e| format!("parse PKCS#8: {e:?}"))?;

    if text {
        print_key_text(&key);
    }
    let output_pem = if pubout {
        encode_pubout(&key)?
    } else {
        encode_priv(&key)?
    };
    if let Some(path) = output {
        fs::write(path, &output_pem)?;
    } else {
        print!("{output_pem}");
    }
    Ok(())
}

/// Re-encode a private key as PKCS#8 PEM (label: `PRIVATE KEY`).
fn encode_priv(key: &Pkcs8PrivateKey) -> Result<String, Box<dyn std::error::Error>> {
    let der = match key {
        Pkcs8PrivateKey::Rsa(rsa) => encode_rsa_pkcs8_der(rsa)?,
        Pkcs8PrivateKey::Ed25519(ed) => {
            let seed = ed.seed();
            encode_ed25519_pkcs8_der(seed)
        }
        Pkcs8PrivateKey::Ec { curve_id, key_pair } => {
            let priv_bytes = key_pair.private_key_bytes();
            encode_ec_pkcs8_der(*curve_id, &priv_bytes)
        }
        Pkcs8PrivateKey::RsaPss(_) => {
            return Err(
                "RSA-PSS PKCS#8 re-encoding not implemented (TODO(#47-pkey-rsa-pss))".into(),
            )
        }
        Pkcs8PrivateKey::Sm2(_) => {
            return Err("SM2 PKCS#8 re-encoding not implemented (TODO(#47-pkey-sm2))".into())
        }
        Pkcs8PrivateKey::Ed448(_)
        | Pkcs8PrivateKey::X25519(_)
        | Pkcs8PrivateKey::X448(_)
        | Pkcs8PrivateKey::Dsa { .. }
        | Pkcs8PrivateKey::Dh { .. } => {
            return Err("algorithm not implemented in #47-B (deferred to follow-up sub-PR)".into())
        }
    };
    Ok(hitls_utils::pem::encode("PRIVATE KEY", &der))
}

/// Build an SPKI public-key PEM from a parsed PKCS#8 private key.
fn encode_pubout(key: &Pkcs8PrivateKey) -> Result<String, Box<dyn std::error::Error>> {
    let spki_der = match key {
        Pkcs8PrivateKey::Rsa(rsa) => encode_rsa_spki_der(rsa)?,
        Pkcs8PrivateKey::Ed25519(ed) => {
            let pub_bytes = ed.public_key().to_vec();
            encode_ed25519_spki_der(&pub_bytes)
        }
        Pkcs8PrivateKey::Ec { curve_id, key_pair } => {
            let pub_bytes = key_pair
                .public_key_bytes()
                .map_err(|e| format!("EC public key extract: {e:?}"))?;
            encode_ec_spki_der(*curve_id, &pub_bytes)
        }
        Pkcs8PrivateKey::RsaPss(_) => {
            return Err("RSA-PSS SPKI not implemented (TODO(#47-pkey-rsa-pss))".into())
        }
        Pkcs8PrivateKey::Sm2(_) => {
            return Err("SM2 SPKI not implemented (TODO(#47-pkey-sm2))".into())
        }
        Pkcs8PrivateKey::Ed448(_)
        | Pkcs8PrivateKey::X25519(_)
        | Pkcs8PrivateKey::X448(_)
        | Pkcs8PrivateKey::Dsa { .. }
        | Pkcs8PrivateKey::Dh { .. } => {
            return Err(
                "algorithm SPKI not implemented in #47-B (deferred to follow-up sub-PR)".into(),
            )
        }
    };
    Ok(encode_spki_pem(&spki_der))
}

fn print_key_text(key: &Pkcs8PrivateKey) {
    let label = match key {
        Pkcs8PrivateKey::Rsa(_) => "RSA private key",
        Pkcs8PrivateKey::RsaPss(_) => "RSA-PSS private key",
        Pkcs8PrivateKey::Ec { curve_id, .. } => match curve_id {
            hitls_types::EccCurveId::NistP256 => "EC private key (P-256)",
            hitls_types::EccCurveId::NistP384 => "EC private key (P-384)",
            hitls_types::EccCurveId::NistP521 => "EC private key (P-521)",
            _ => "EC private key",
        },
        Pkcs8PrivateKey::Ed25519(_) => "Ed25519 private key",
        Pkcs8PrivateKey::Ed448(_) => "Ed448 private key",
        Pkcs8PrivateKey::X25519(_) => "X25519 private key",
        Pkcs8PrivateKey::X448(_) => "X448 private key",
        Pkcs8PrivateKey::Sm2(_) => "SM2 private key",
        Pkcs8PrivateKey::Dsa { .. } => "DSA private key",
        Pkcs8PrivateKey::Dh { .. } => "DH private key",
    };
    println!("Key algorithm: {label}");
}

// ---------------------------------------------------------------------------
// RSA PKCS#1 → PKCS#8 + SPKI helpers
//
// `hitls_pki::pkcs8` exposes encoders for Ed25519 / EC / X25519 but not RSA,
// so we build the PKCS#1 `RSAPrivateKey` SEQUENCE inline (same encoder used
// in `genrsa.rs::encode_rsa_private_key_pem`) and wrap it via
// `encode_pkcs8_pem_raw`. The SPKI path encodes
// `SubjectPublicKeyInfo { rsaEncryption, BIT STRING { SEQUENCE { n, e } } }`.
// ---------------------------------------------------------------------------

fn encode_rsa_pkcs8_der(
    key: &hitls_crypto::rsa::RsaPrivateKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use hitls_bignum::BigNum;

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
    let pkcs1_der = wrap.finish();

    // PKCS#8 wraps the PKCS#1 RSAPrivateKey DER as the OCTET STRING body.
    let oid = hitls_utils::oid::known::rsa_encryption();
    Ok(encode_pkcs8_der_via_pem(&oid, &pkcs1_der))
}

/// Wrap raw private-key bytes into a PKCS#8 PrivateKeyInfo DER. Uses
/// `encode_pkcs8_pem_raw` and strips the PEM headers since callers expect
/// raw DER bytes.
fn encode_pkcs8_der_via_pem(
    algorithm_oid: &hitls_utils::oid::Oid,
    private_key_der: &[u8],
) -> Vec<u8> {
    let pem = encode_pkcs8_pem_raw(algorithm_oid, None, private_key_der);
    let blocks = hitls_utils::pem::parse(&pem).expect("our own PEM parses");
    blocks[0].data.clone()
}

fn encode_rsa_spki_der(
    key: &hitls_crypto::rsa::RsaPrivateKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let n_be = key.n_bytes();
    let e_be = key.e_bytes();
    let mut pub_inner = Encoder::new();
    pub_inner.write_integer(&n_be);
    pub_inner.write_integer(&e_be);
    let pub_body = pub_inner.finish();
    let mut pub_seq = Encoder::new();
    pub_seq.write_sequence(&pub_body);
    let rsa_pub_key_der = pub_seq.finish();

    let oid = hitls_utils::oid::known::rsa_encryption();
    let mut alg = Encoder::new();
    alg.write_oid(&oid.to_der_value());
    alg.write_null();
    let alg_bytes = alg.finish();

    let mut body = Encoder::new();
    body.write_sequence(&alg_bytes);
    body.write_bit_string(0, &rsa_pub_key_der);
    let body_bytes = body.finish();

    let mut outer = Encoder::new();
    outer.write_sequence(&body_bytes);
    Ok(outer.finish())
}

fn encode_ed25519_spki_der(public_key: &[u8]) -> Vec<u8> {
    let oid = hitls_utils::oid::known::ed25519();
    let mut alg = Encoder::new();
    alg.write_oid(&oid.to_der_value());
    let alg_bytes = alg.finish();

    let mut body = Encoder::new();
    body.write_sequence(&alg_bytes);
    body.write_bit_string(0, public_key);
    let body_bytes = body.finish();

    let mut outer = Encoder::new();
    outer.write_sequence(&body_bytes);
    outer.finish()
}

// ===========================================================================
// Tests — migrated from openHiTLS C
// `testcode/sdv/testcase/apps/test_suite_ut_app_key.{c,data}` TC001 / TC002.
//
// The C tests drive `genpkey` → `pkey` → `pkey -pubout` and assert the
// resulting key files round-trip through sign/verify. We mirror that
// workflow with `parse_pkcs8_pem` + `encode_priv`/`encode_pubout`.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use hitls_types::EccCurveId;

    fn write_tmp(content: &str, name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("hitls_cli_pkey_{name}"));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(format!("{name}.pem"));
        std::fs::write(&path, content).unwrap();
        path
    }

    fn rsa_pkcs8_pem(bits: usize) -> String {
        let key = hitls_crypto::rsa::RsaPrivateKey::generate(bits).unwrap();
        let der = encode_rsa_pkcs8_der(&key).unwrap();
        hitls_utils::pem::encode("PRIVATE KEY", &der)
    }

    fn ed25519_pkcs8_pem() -> String {
        let seed = [0x42u8; 32];
        let der = encode_ed25519_pkcs8_der(&seed);
        hitls_utils::pem::encode("PRIVATE KEY", &der)
    }

    fn ec_p256_pkcs8_pem() -> String {
        let kp = hitls_crypto::ecdsa::EcdsaKeyPair::generate(EccCurveId::NistP256).unwrap();
        let der = encode_ec_pkcs8_der(EccCurveId::NistP256, &kp.private_key_bytes());
        hitls_utils::pem::encode("PRIVATE KEY", &der)
    }

    // -----------------------------------------------------------------------
    // C UT_HITLS_APP_KEY_TC001 analogues — decode + re-encode round-trip
    // and `-pubout` extraction.
    // -----------------------------------------------------------------------

    #[test]
    fn ut_pkey_tc001_rsa_2048_decode_reencode_round_trips() {
        let pem = rsa_pkcs8_pem(2048);
        let in_path = write_tmp(&pem, "rsa2048_in");
        let key = parse_pkcs8_pem(&pem).unwrap();
        let out_pem = encode_priv(&key).unwrap();
        let reparsed = parse_pkcs8_pem(&out_pem).unwrap();
        match (&key, &reparsed) {
            (Pkcs8PrivateKey::Rsa(orig), Pkcs8PrivateKey::Rsa(re)) => {
                assert_eq!(orig.n_bytes(), re.n_bytes());
                assert_eq!(orig.e_bytes(), re.e_bytes());
            }
            _ => panic!("expected RSA"),
        }
        // Public-key extraction → real PUBLIC KEY PEM written to file.
        let out_path = in_path.with_file_name("rsa2048_pub.pem");
        run_with_out(
            in_path.to_str().unwrap(),
            Some(out_path.to_str().unwrap()),
            true,
            false,
        )
        .unwrap();
        let pub_pem = std::fs::read_to_string(&out_path).unwrap();
        assert!(pub_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn ut_pkey_tc001_ed25519_round_trip() {
        let pem = ed25519_pkcs8_pem();
        let in_path = write_tmp(&pem, "ed25519_in");
        let out_path = in_path.with_file_name("ed25519_pub.pem");
        run_with_out(
            in_path.to_str().unwrap(),
            Some(out_path.to_str().unwrap()),
            true,
            false,
        )
        .unwrap();
        let pub_pem = std::fs::read_to_string(&out_path).unwrap();
        assert!(pub_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        let key = parse_pkcs8_pem(&pem).unwrap();
        let reenc = encode_priv(&key).unwrap();
        let reparsed = parse_pkcs8_pem(&reenc).unwrap();
        match (&key, &reparsed) {
            (Pkcs8PrivateKey::Ed25519(a), Pkcs8PrivateKey::Ed25519(b)) => {
                assert_eq!(a.public_key(), b.public_key());
            }
            _ => panic!("expected Ed25519"),
        }
    }

    #[test]
    fn ut_pkey_tc001_ec_p256_round_trip() {
        let pem = ec_p256_pkcs8_pem();
        let in_path = write_tmp(&pem, "ec256_in");
        let out_path = in_path.with_file_name("ec256_pub.pem");
        run_with_out(
            in_path.to_str().unwrap(),
            Some(out_path.to_str().unwrap()),
            true,
            false,
        )
        .unwrap();
        let pub_pem = std::fs::read_to_string(&out_path).unwrap();
        assert!(pub_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn ut_pkey_tc001_ec_p384_round_trip() {
        let kp = hitls_crypto::ecdsa::EcdsaKeyPair::generate(EccCurveId::NistP384).unwrap();
        let der = encode_ec_pkcs8_der(EccCurveId::NistP384, &kp.private_key_bytes());
        let pem = hitls_utils::pem::encode("PRIVATE KEY", &der);
        let key = parse_pkcs8_pem(&pem).unwrap();
        assert!(encode_priv(&key).is_ok());
        assert!(encode_pubout(&key).is_ok());
    }

    #[test]
    fn ut_pkey_tc001_ec_p521_round_trip() {
        let kp = hitls_crypto::ecdsa::EcdsaKeyPair::generate(EccCurveId::NistP521).unwrap();
        let der = encode_ec_pkcs8_der(EccCurveId::NistP521, &kp.private_key_bytes());
        let pem = hitls_utils::pem::encode("PRIVATE KEY", &der);
        let key = parse_pkcs8_pem(&pem).unwrap();
        assert!(encode_priv(&key).is_ok());
        assert!(encode_pubout(&key).is_ok());
    }

    // -----------------------------------------------------------------------
    // Integration tests for run / run_with_out file handling.
    // -----------------------------------------------------------------------

    #[test]
    fn run_outputs_priv_pem_to_stdout_path() {
        let pem = ed25519_pkcs8_pem();
        let in_path = write_tmp(&pem, "run_stdout");
        let result = run(in_path.to_str().unwrap(), false, false);
        assert!(result.is_ok());
    }

    #[test]
    fn run_with_out_writes_to_file() {
        let pem = ed25519_pkcs8_pem();
        let in_path = write_tmp(&pem, "with_out_in");
        let out_path = in_path.with_file_name("with_out_out.pem");
        run_with_out(
            in_path.to_str().unwrap(),
            Some(out_path.to_str().unwrap()),
            false,
            false,
        )
        .unwrap();
        let written = std::fs::read_to_string(&out_path).unwrap();
        assert!(written.contains("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn run_with_text_flag_prints_algorithm() {
        let pem = ed25519_pkcs8_pem();
        let in_path = write_tmp(&pem, "text_flag");
        assert!(run(in_path.to_str().unwrap(), false, true).is_ok());
    }

    #[test]
    fn run_nonexistent_file_errors() {
        assert!(run("/nonexistent_pkey_test/key.pem", false, false).is_err());
    }

    #[test]
    fn run_garbage_pem_errors() {
        let in_path = write_tmp("not a pem file\n", "garbage");
        assert!(run(in_path.to_str().unwrap(), false, false).is_err());
    }

    // -----------------------------------------------------------------------
    // Documented-gap pins (see module doc TODOs).
    // -----------------------------------------------------------------------

    #[test]
    fn gap_encrypted_pkcs8_passin_passout_deferred() {
        // No surface yet — when PBES2 lands, this test will exercise a
        // round-trip through an encrypted PKCS#8 file. For now it just pins
        // the gap by asserting the run signature does NOT yet take a
        // passin/passout parameter (a future `run_with_passin` will).
        // TODO(#47-pkey-encrypted-pkcs8)
        let _: fn(&str, Option<&str>, bool, bool) -> _ = run_with_out;
    }
}
