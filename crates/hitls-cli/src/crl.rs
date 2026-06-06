//! CRL display + verification + format-conversion command.

use std::fs;

use hitls_pki::x509::{Certificate, CertificateRevocationList};

pub struct CrlArgs<'a> {
    pub input: &'a str,
    pub text: bool,
    pub cafile: Option<&'a str>,
    pub inform: Option<&'a str>,
    pub out: Option<&'a str>,
    pub outform: Option<&'a str>,
}

pub fn run(args: &CrlArgs) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(args.input)?;
    let crl = load_crl(&data, args.inform)?;

    if let Some(ca_path) = args.cafile {
        let ca = load_ca_cert(ca_path)?;
        if !crl
            .verify_signature(&ca)
            .map_err(|e| format!("CRL signature verify failed: {e}"))?
        {
            return Err("CRL signature verify failed: signature did not match CA".into());
        }
        println!("verify OK");
    }

    if let Some(out_path) = args.out {
        let bytes = encode_crl(&crl, args.outform)?;
        fs::write(out_path, bytes)?;
        return Ok(());
    }

    if args.text {
        print!("{}", crl.to_text());
    } else {
        println!("CRL file: {}", args.input);
        println!("  Issuer: {}", crl.issuer);
        println!("  Revoked certificates: {}", crl.revoked_certs.len());
    }
    Ok(())
}

fn load_crl(
    data: &[u8],
    inform: Option<&str>,
) -> Result<CertificateRevocationList, Box<dyn std::error::Error>> {
    let format = inform.map(parse_format).transpose()?;
    match format {
        Some(Format::Pem) => from_pem_bytes(data),
        Some(Format::Der) => CertificateRevocationList::from_der(data)
            .map_err(|e| format!("CRL parse failed: {e}").into()),
        None => {
            // Auto-detect: try PEM first if UTF-8, else DER.
            if let Ok(s) = std::str::from_utf8(data) {
                if s.contains("-----BEGIN X509 CRL-----") {
                    return from_pem_bytes(data);
                }
            }
            CertificateRevocationList::from_der(data)
                .map_err(|e| format!("CRL parse failed: {e}").into())
        }
    }
}

fn from_pem_bytes(data: &[u8]) -> Result<CertificateRevocationList, Box<dyn std::error::Error>> {
    let s = std::str::from_utf8(data).map_err(|_| "input is not valid UTF-8 for PEM mode")?;
    let blocks = hitls_utils::pem::parse(s).map_err(|e| format!("PEM parse failed: {e}"))?;
    let der = blocks.first().ok_or("no PEM block found")?;
    CertificateRevocationList::from_der(&der.data)
        .map_err(|e| format!("CRL parse failed: {e}").into())
}

fn load_ca_cert(path: &str) -> Result<Certificate, Box<dyn std::error::Error>> {
    let data = fs::read(path).map_err(|e| format!("CAfile read failed: {e}"))?;
    if let Ok(s) = std::str::from_utf8(&data) {
        if s.contains("-----BEGIN CERTIFICATE-----") {
            return Certificate::from_pem(s)
                .map_err(|e| format!("CAfile parse failed: {e}").into());
        }
    }
    Certificate::from_der(&data).map_err(|e| format!("CAfile parse failed: {e}").into())
}

fn encode_crl(
    crl: &CertificateRevocationList,
    outform: Option<&str>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let format = outform
        .map(parse_format)
        .transpose()?
        .unwrap_or(Format::Pem);
    Ok(match format {
        Format::Pem => crl.to_pem().into_bytes(),
        Format::Der => crl.to_der(),
    })
}

#[derive(Clone, Copy)]
enum Format {
    Pem,
    Der,
}

fn parse_format(s: &str) -> Result<Format, Box<dyn std::error::Error>> {
    match s.to_ascii_uppercase().as_str() {
        "PEM" => Ok(Format::Pem),
        "DER" => Ok(Format::Der),
        other => Err(format!("unsupported format: {other} (use DER or PEM)").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_CRL_PEM: &str =
        include_str!("../../../tests/vectors/crl/crl_parse/crl/demoCA_rsa2048_v2_empty_crl.crl");
    const CRL_V1_PEM: &str = include_str!("../../../tests/vectors/crl/crl_verify/crl/ca.crl");
    const CA_CRT_PEM: &str = include_str!("../../../tests/vectors/crl/crl_verify/certs/ca.crt");
    const SERVER1_CRT_PEM: &str =
        include_str!("../../../tests/vectors/crl/crl_verify/certs/server1.crt");

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("hitls_crl_test_{name}"))
    }

    fn write_tmp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = tmp(name);
        fs::write(&p, bytes).unwrap();
        p
    }

    fn args_for(input: &str) -> CrlArgs<'_> {
        CrlArgs {
            input,
            text: false,
            cafile: None,
            inform: None,
            out: None,
            outform: None,
        }
    }

    #[test]
    fn test_run_pem_crl_empty_revoked() {
        let p = write_tmp("empty.crl", EMPTY_CRL_PEM.as_bytes());
        run(&args_for(p.to_str().unwrap())).unwrap();
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn test_run_pem_crl_with_revoked() {
        let p = write_tmp("v1.crl", CRL_V1_PEM.as_bytes());
        run(&args_for(p.to_str().unwrap())).unwrap();
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn test_run_text_mode() {
        let p = write_tmp("text.crl", EMPTY_CRL_PEM.as_bytes());
        let mut a = args_for(p.to_str().unwrap());
        a.text = true;
        run(&a).unwrap();
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn test_run_der_crl() {
        let blocks = hitls_utils::pem::parse(EMPTY_CRL_PEM).unwrap();
        let der = blocks.first().unwrap().data.clone();
        let p = write_tmp("der.der", &der);
        run(&args_for(p.to_str().unwrap())).unwrap();
        let _ = fs::remove_file(&p);
    }

    // ---- C SDV migrated / boundary tests ----

    // Tightened: nonexistent file → I/O "path not found" (cross-platform).
    #[test]
    fn test_run_nonexistent_file() {
        let path = tmp("nonexistent_subdir").join("file.crl");
        let err = run(&args_for(path.to_str().unwrap())).unwrap_err();
        let s = err.to_string();
        assert!(
            s.contains("No such file") || s.contains("cannot find"),
            "expected POSIX/Windows 'path not found' I/O error, got: {s}"
        );
    }

    // Tightened: malformed DER → "CRL parse failed:" prefix from the from_der wrapper.
    #[test]
    fn test_run_invalid_data() {
        let p = write_tmp("invalid.crl", b"this is not a crl");
        let err = run(&args_for(p.to_str().unwrap())).unwrap_err();
        assert!(
            err.to_string().starts_with("CRL parse failed:"),
            "got: {err}"
        );
        let _ = fs::remove_file(&p);
    }

    // C TC001 row 1: -CAfile CA.crt + -in matching CRL → SUCCESS ("verify OK")
    #[test]
    fn test_run_cafile_signature_ok() {
        let crl_p = write_tmp("vfy.crl", CRL_V1_PEM.as_bytes());
        let ca_p = write_tmp("vfy.crt", CA_CRT_PEM.as_bytes());
        let mut a = args_for(crl_p.to_str().unwrap());
        a.cafile = ca_p.to_str();
        run(&a).unwrap();
        let _ = fs::remove_file(&crl_p);
        let _ = fs::remove_file(&ca_p);
    }

    // C TC001 row 5: -CAfile wrong-CA → UIO_FAIL / signature mismatch
    #[test]
    fn test_run_cafile_signature_mismatch() {
        // server1.crt is signed BY ca.crt but it isn't itself an issuer of ca.crl, so
        // verifying ca.crl against server1.crt's public key must fail.
        let crl_p = write_tmp("vfy_mismatch.crl", CRL_V1_PEM.as_bytes());
        let bad_p = write_tmp("vfy_mismatch.crt", SERVER1_CRT_PEM.as_bytes());
        let mut a = args_for(crl_p.to_str().unwrap());
        a.cafile = bad_p.to_str();
        let err = run(&a).unwrap_err();
        assert!(
            err.to_string().starts_with("CRL signature verify failed:"),
            "got: {err}"
        );
        let _ = fs::remove_file(&crl_p);
        let _ = fs::remove_file(&bad_p);
    }

    // CAfile path missing → IO error wrapped as "CAfile read failed:"
    #[test]
    fn test_run_cafile_missing() {
        let crl_p = write_tmp("ca_missing.crl", EMPTY_CRL_PEM.as_bytes());
        let mut a = args_for(crl_p.to_str().unwrap());
        let ca_path = tmp("nonexistent_subdir").join("ca.crt");
        let ca_path_str = ca_path.to_str().unwrap();
        a.cafile = Some(ca_path_str);
        let err = run(&a).unwrap_err();
        assert!(
            err.to_string().starts_with("CAfile read failed:"),
            "got: {err}"
        );
        let _ = fs::remove_file(&crl_p);
    }

    // CAfile contains garbage bytes → "CAfile parse failed:"
    #[test]
    fn test_run_cafile_malformed() {
        let crl_p = write_tmp("ca_bad.crl", EMPTY_CRL_PEM.as_bytes());
        let ca_p = write_tmp("ca_bad.crt", b"not a certificate");
        let mut a = args_for(crl_p.to_str().unwrap());
        a.cafile = ca_p.to_str();
        let err = run(&a).unwrap_err();
        assert!(
            err.to_string().starts_with("CAfile parse failed:"),
            "got: {err}"
        );
        let _ = fs::remove_file(&crl_p);
        let _ = fs::remove_file(&ca_p);
    }

    // C TC001 row 7: -in DER -out PEM (format conversion)
    #[test]
    fn test_run_convert_der_to_pem() {
        let der = hitls_utils::pem::parse(EMPTY_CRL_PEM)
            .unwrap()
            .first()
            .unwrap()
            .data
            .clone();
        let in_p = write_tmp("conv_in.der", &der);
        let out_p = tmp("conv_out.pem");
        let mut a = args_for(in_p.to_str().unwrap());
        a.inform = Some("DER");
        a.out = out_p.to_str();
        a.outform = Some("PEM");
        run(&a).unwrap();
        let out_pem = fs::read_to_string(&out_p).unwrap();
        assert!(
            out_pem.contains("-----BEGIN X509 CRL-----"),
            "got: {out_pem}"
        );
        let _ = fs::remove_file(&in_p);
        let _ = fs::remove_file(&out_p);
    }

    // C TC001 row 8: -in PEM -out DER (format conversion)
    #[test]
    fn test_run_convert_pem_to_der() {
        let in_p = write_tmp("conv2_in.pem", EMPTY_CRL_PEM.as_bytes());
        let out_p = tmp("conv2_out.der");
        let mut a = args_for(in_p.to_str().unwrap());
        a.inform = Some("PEM");
        a.out = out_p.to_str();
        a.outform = Some("DER");
        run(&a).unwrap();
        let der_bytes = fs::read(&out_p).unwrap();
        assert!(der_bytes.starts_with(&[0x30]), "DER SEQUENCE tag missing");
        // Round-trip parse to confirm valid DER
        CertificateRevocationList::from_der(&der_bytes).unwrap();
        let _ = fs::remove_file(&in_p);
        let _ = fs::remove_file(&out_p);
    }

    // Unknown --inform value → specific error
    #[test]
    fn test_run_invalid_inform() {
        let p = write_tmp("bad_inform.crl", EMPTY_CRL_PEM.as_bytes());
        let mut a = args_for(p.to_str().unwrap());
        a.inform = Some("YAML");
        let err = run(&a).unwrap_err();
        assert_eq!(err.to_string(), "unsupported format: YAML (use DER or PEM)");
        let _ = fs::remove_file(&p);
    }

    // --inform DER on a PEM file → "CRL parse failed:" (bypasses auto-detect)
    #[test]
    fn test_run_inform_der_on_pem_fails() {
        let p = write_tmp("force_der.crl", EMPTY_CRL_PEM.as_bytes());
        let mut a = args_for(p.to_str().unwrap());
        a.inform = Some("DER");
        let err = run(&a).unwrap_err();
        assert!(
            err.to_string().starts_with("CRL parse failed:"),
            "got: {err}"
        );
        let _ = fs::remove_file(&p);
    }
}
