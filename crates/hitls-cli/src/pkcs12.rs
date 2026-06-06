//! PKCS#12 CLI subcommand — parse, extract, and create P12 files.

use std::fs;

pub struct Pkcs12Options<'a> {
    pub input: Option<&'a str>,
    pub password: &'a str,
    pub info: bool,
    pub nokeys: bool,
    pub nocerts: bool,
    pub export: bool,
    pub inkey: Option<&'a str>,
    pub cert_file: Option<&'a str>,
    pub output: Option<&'a str>,
}

pub fn run(opts: &Pkcs12Options) -> Result<(), Box<dyn std::error::Error>> {
    if opts.export {
        return run_export(opts.inkey, opts.cert_file, opts.password, opts.output);
    }

    let input = opts
        .input
        .ok_or("--input is required when not in --export mode")?;
    let p12_data = fs::read(input)?;
    let p12 = hitls_pki::pkcs12::Pkcs12::from_der(&p12_data, opts.password)?;

    if opts.info {
        // Display summary info
        println!("PKCS#12 file: {input}");
        println!(
            "  Private key: {}",
            if p12.private_key.is_some() {
                "present"
            } else {
                "absent"
            }
        );
        println!("  Certificates: {}", p12.certificates.len());
        for (i, cert_der) in p12.certificates.iter().enumerate() {
            if let Ok(cert) = hitls_pki::x509::Certificate::from_der(cert_der) {
                println!("    [{}] Subject: {}", i, cert.subject);
            } else {
                println!("    [{}] (unparseable, {} bytes)", i, cert_der.len());
            }
        }
        return Ok(());
    }

    let mut out = String::new();

    // Extract private key
    if !opts.nokeys {
        if let Some(pk_der) = &p12.private_key {
            let pem = hitls_utils::pem::encode("PRIVATE KEY", pk_der);
            out.push_str(&pem);
        }
    }

    // Extract certificates
    if !opts.nocerts {
        for cert_der in &p12.certificates {
            let pem = hitls_utils::pem::encode("CERTIFICATE", cert_der);
            out.push_str(&pem);
        }
    }

    if let Some(path) = opts.output {
        fs::write(path, &out)?;
    } else {
        print!("{out}");
    }

    Ok(())
}

fn run_export(
    inkey: Option<&str>,
    cert_file: Option<&str>,
    password: &str,
    output: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let private_key = if let Some(key_path) = inkey {
        let pem_data = fs::read_to_string(key_path)?;
        let blocks = hitls_utils::pem::parse(&pem_data)?;
        let key_block = blocks
            .iter()
            .find(|b| b.label.contains("PRIVATE KEY"))
            .ok_or("no PRIVATE KEY block found in key file")?;
        Some(key_block.data.clone())
    } else {
        None
    };

    let mut cert_ders = Vec::new();
    if let Some(cert_path) = cert_file {
        let pem_data = fs::read_to_string(cert_path)?;
        let blocks = hitls_utils::pem::parse(&pem_data)?;
        for block in &blocks {
            if block.label == "CERTIFICATE" {
                cert_ders.push(block.data.clone());
            }
        }
    }

    let cert_refs: Vec<&[u8]> = cert_ders.iter().map(|c| c.as_slice()).collect();

    let p12_der = hitls_pki::pkcs12::Pkcs12::create(private_key.as_deref(), &cert_refs, password)?;

    if let Some(path) = output {
        fs::write(path, &p12_der)?;
        eprintln!("PKCS#12 written to {path} ({} bytes)", p12_der.len());
    } else {
        // Binary output to stdout
        use std::io::Write;
        std::io::stdout().write_all(&p12_der)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_pk_der() -> Vec<u8> {
        use hitls_utils::asn1::Encoder;
        let mut alg_inner = Vec::new();
        let mut e = Encoder::new();
        e.write_oid(&hitls_utils::oid::known::rsa_encryption().to_der_value());
        alg_inner.extend_from_slice(&e.finish());
        let mut e2 = Encoder::new();
        e2.write_null();
        alg_inner.extend_from_slice(&e2.finish());
        let mut e3 = Encoder::new();
        e3.write_sequence(&alg_inner);
        let alg_id = e3.finish();
        let mut e4 = Encoder::new();
        e4.write_octet_string(&[0x42; 64]);
        let key_octet = e4.finish();
        let mut e5 = Encoder::new();
        e5.write_integer(&[0]);
        let version = e5.finish();
        let mut pki_inner = Vec::new();
        pki_inner.extend_from_slice(&version);
        pki_inner.extend_from_slice(&alg_id);
        pki_inner.extend_from_slice(&key_octet);
        let mut e6 = Encoder::new();
        e6.write_sequence(&pki_inner);
        e6.finish()
    }

    fn build_test_cert_der() -> Vec<u8> {
        use hitls_utils::asn1::Encoder;
        let inner = vec![0x30, 0x03, 0x02, 0x01, 0x01];
        let mut e = Encoder::new();
        e.write_sequence(&inner);
        e.finish()
    }

    fn create_test_p12(password: &str) -> Vec<u8> {
        let pk = build_test_pk_der();
        let cert = build_test_cert_der();
        hitls_pki::pkcs12::Pkcs12::create(Some(&pk), &[&cert], password).unwrap()
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("hitls_pkcs12_test_{name}"))
    }

    fn default_opts<'a>() -> Pkcs12Options<'a> {
        Pkcs12Options {
            input: None,
            password: "",
            info: false,
            nokeys: false,
            nocerts: false,
            export: false,
            inkey: None,
            cert_file: None,
            output: None,
        }
    }

    #[test]
    fn test_pkcs12_info_mode() {
        let p12_data = create_test_p12("testpass");
        let tmp = std::env::temp_dir().join("test_pkcs12_info.p12");
        fs::write(&tmp, &p12_data).unwrap();
        let result = run(&Pkcs12Options {
            input: Some(tmp.to_str().unwrap()),
            password: "testpass",
            info: true,
            nokeys: false,
            nocerts: false,
            export: false,
            inkey: None,
            cert_file: None,
            output: None,
        });
        assert!(result.is_ok());
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_pkcs12_extract_to_file() {
        let p12_data = create_test_p12("extract");
        let tmp_p12 = std::env::temp_dir().join("test_pkcs12_extract.p12");
        let tmp_out = std::env::temp_dir().join("test_pkcs12_extract.pem");
        fs::write(&tmp_p12, &p12_data).unwrap();
        let result = run(&Pkcs12Options {
            input: Some(tmp_p12.to_str().unwrap()),
            password: "extract",
            info: false,
            nokeys: false,
            nocerts: false,
            export: false,
            inkey: None,
            cert_file: None,
            output: Some(tmp_out.to_str().unwrap()),
        });
        assert!(result.is_ok());
        let pem = fs::read_to_string(&tmp_out).unwrap();
        assert!(pem.contains("PRIVATE KEY"));
        assert!(pem.contains("CERTIFICATE"));
        let _ = fs::remove_file(&tmp_p12);
        let _ = fs::remove_file(&tmp_out);
    }

    #[test]
    fn test_pkcs12_nokeys() {
        let p12_data = create_test_p12("nokeys");
        let tmp_p12 = std::env::temp_dir().join("test_pkcs12_nokeys.p12");
        let tmp_out = std::env::temp_dir().join("test_pkcs12_nokeys.pem");
        fs::write(&tmp_p12, &p12_data).unwrap();
        let result = run(&Pkcs12Options {
            input: Some(tmp_p12.to_str().unwrap()),
            password: "nokeys",
            info: false,
            nokeys: true,
            nocerts: false,
            export: false,
            inkey: None,
            cert_file: None,
            output: Some(tmp_out.to_str().unwrap()),
        });
        assert!(result.is_ok());
        let pem = fs::read_to_string(&tmp_out).unwrap();
        assert!(!pem.contains("PRIVATE KEY"));
        assert!(pem.contains("CERTIFICATE"));
        let _ = fs::remove_file(&tmp_p12);
        let _ = fs::remove_file(&tmp_out);
    }

    #[test]
    fn test_pkcs12_export_roundtrip() {
        // Create key and cert PEM files
        let pk_der = {
            use hitls_utils::asn1::Encoder;
            let mut alg_inner = Vec::new();
            let mut e = Encoder::new();
            e.write_oid(&hitls_utils::oid::known::rsa_encryption().to_der_value());
            alg_inner.extend_from_slice(&e.finish());
            let mut e2 = Encoder::new();
            e2.write_null();
            alg_inner.extend_from_slice(&e2.finish());
            let mut e3 = Encoder::new();
            e3.write_sequence(&alg_inner);
            let alg_id = e3.finish();

            let mut e4 = Encoder::new();
            e4.write_octet_string(&[0x42; 64]);
            let key_octet = e4.finish();
            let mut e5 = Encoder::new();
            e5.write_integer(&[0]);
            let version = e5.finish();

            let mut pki_inner = Vec::new();
            pki_inner.extend_from_slice(&version);
            pki_inner.extend_from_slice(&alg_id);
            pki_inner.extend_from_slice(&key_octet);
            let mut e6 = Encoder::new();
            e6.write_sequence(&pki_inner);
            e6.finish()
        };
        let cert_der = {
            use hitls_utils::asn1::Encoder;
            let inner = vec![0x30, 0x03, 0x02, 0x01, 0x01];
            let mut e = Encoder::new();
            e.write_sequence(&inner);
            e.finish()
        };

        let key_pem = hitls_utils::pem::encode("PRIVATE KEY", &pk_der);
        let cert_pem = hitls_utils::pem::encode("CERTIFICATE", &cert_der);

        let tmp_key = std::env::temp_dir().join("test_pkcs12_export_key.pem");
        let tmp_cert = std::env::temp_dir().join("test_pkcs12_export_cert.pem");
        let tmp_p12 = std::env::temp_dir().join("test_pkcs12_export.p12");

        fs::write(&tmp_key, &key_pem).unwrap();
        fs::write(&tmp_cert, &cert_pem).unwrap();

        let result = run(&Pkcs12Options {
            input: None,
            password: "exportpass",
            info: false,
            nokeys: false,
            nocerts: false,
            export: true,
            inkey: Some(tmp_key.to_str().unwrap()),
            cert_file: Some(tmp_cert.to_str().unwrap()),
            output: Some(tmp_p12.to_str().unwrap()),
        });
        assert!(result.is_ok());

        // Verify the exported P12
        let p12_data = fs::read(&tmp_p12).unwrap();
        let parsed = hitls_pki::pkcs12::Pkcs12::from_der(&p12_data, "exportpass").unwrap();
        assert!(parsed.private_key.is_some());
        assert_eq!(parsed.certificates.len(), 1);

        let _ = fs::remove_file(&tmp_key);
        let _ = fs::remove_file(&tmp_cert);
        let _ = fs::remove_file(&tmp_p12);
    }

    // ---- C SDV migrated / negative-path tests ----

    // C TC002 r5/r6/r7/r8: wrong password on decode → PASSWD_FAIL
    #[test]
    fn test_pkcs12_wrong_password_fails() {
        let p12_data = create_test_p12("correctpass");
        let tmp_p12 = tmp("wrongpw.p12");
        fs::write(&tmp_p12, &p12_data).unwrap();
        let opts = Pkcs12Options {
            input: tmp_p12.to_str(),
            password: "wrongpass",
            info: true,
            ..default_opts()
        };
        // from_der returns PkiError::Pkcs12Error(_) (HMAC mismatch). The CLI propagates it via `?`,
        // and Display for PkiError::Pkcs12Error renders as "PKCS#12 error: ...".
        let err = run(&opts).unwrap_err();
        let s = err.to_string();
        assert!(
            s.starts_with("pkcs12 error:"),
            "expected PkiError::Pkcs12Error display ('pkcs12 error: ...'), got: {s}"
        );
        let _ = fs::remove_file(&tmp_p12);
    }

    // C TC003 r4: -in noexistfile (decode mode) → BSL_FAIL / I/O "path not found"
    #[test]
    fn test_pkcs12_missing_input_file() {
        let path = tmp("nonexistent_subdir").join("missing.p12");
        let path_s = path.to_str().unwrap();
        let opts = Pkcs12Options {
            input: Some(path_s),
            password: "any",
            info: true,
            ..default_opts()
        };
        let err = run(&opts).unwrap_err();
        let s = err.to_string();
        assert!(
            s.contains("No such file") || s.contains("cannot find"),
            "expected POSIX/Windows 'path not found' I/O error, got: {s}"
        );
    }

    // Decode garbage bytes → Pkcs12 parse failure surfaces via PkiError::Pkcs12Error.
    // Per the T168 audit (PKCS#12 §6), every from_der error path is wrapped by the local
    // `perr` helper into PkiError::Pkcs12Error, so even ASN.1-shape failures surface as such.
    #[test]
    fn test_pkcs12_malformed_p12_data() {
        let tmp_p12 = tmp("garbage.p12");
        fs::write(&tmp_p12, [0xFF; 64]).unwrap();
        let opts = Pkcs12Options {
            input: tmp_p12.to_str(),
            password: "any",
            info: true,
            ..default_opts()
        };
        let err = run(&opts).unwrap_err();
        let s = err.to_string();
        assert!(
            s.starts_with("pkcs12 error:"),
            "expected PkiError::Pkcs12Error display ('pkcs12 error: ...'), got: {s}"
        );
        let _ = fs::remove_file(&tmp_p12);
    }

    // CLI-level guard: no --input + no --export → explicit error
    #[test]
    fn test_pkcs12_no_input_no_export() {
        let opts = default_opts();
        let err = run(&opts).unwrap_err();
        assert_eq!(
            err.to_string(),
            "--input is required when not in --export mode"
        );
    }

    // C TC003 r2: -export -inkey noexistfile → BSL_FAIL / I/O error
    #[test]
    fn test_pkcs12_export_missing_inkey_file() {
        let cert_pem = hitls_utils::pem::encode("CERTIFICATE", &build_test_cert_der());
        let cert_p = tmp("missing_inkey_cert.pem");
        fs::write(&cert_p, &cert_pem).unwrap();
        let out_p = tmp("missing_inkey_out.p12");

        let missing_key = tmp("nonexistent_subdir").join("missing.key");
        let missing_key_s = missing_key.to_str().unwrap();
        let cert_p_s = cert_p.to_str().unwrap();
        let out_p_s = out_p.to_str().unwrap();

        let opts = Pkcs12Options {
            input: None,
            password: "anypass",
            export: true,
            inkey: Some(missing_key_s),
            cert_file: Some(cert_p_s),
            output: Some(out_p_s),
            ..default_opts()
        };
        let err = run(&opts).unwrap_err();
        let s = err.to_string();
        assert!(
            s.contains("No such file") || s.contains("cannot find"),
            "got: {s}"
        );
        let _ = fs::remove_file(&cert_p);
    }

    // C TC003 r3: -export -CAfile noexistfile (cert file) → BSL_FAIL / I/O error
    #[test]
    fn test_pkcs12_export_missing_cert_file() {
        let key_pem = hitls_utils::pem::encode("PRIVATE KEY", &build_test_pk_der());
        let key_p = tmp("missing_cert_key.pem");
        fs::write(&key_p, &key_pem).unwrap();
        let out_p = tmp("missing_cert_out.p12");

        let missing_cert = tmp("nonexistent_subdir").join("missing.crt");
        let missing_cert_s = missing_cert.to_str().unwrap();
        let key_p_s = key_p.to_str().unwrap();
        let out_p_s = out_p.to_str().unwrap();

        let opts = Pkcs12Options {
            input: None,
            password: "anypass",
            export: true,
            inkey: Some(key_p_s),
            cert_file: Some(missing_cert_s),
            output: Some(out_p_s),
            ..default_opts()
        };
        let err = run(&opts).unwrap_err();
        let s = err.to_string();
        assert!(
            s.contains("No such file") || s.contains("cannot find"),
            "got: {s}"
        );
        let _ = fs::remove_file(&key_p);
    }

    // C TC003 r6 spirit: inkey file has no PRIVATE KEY PEM block → explicit error
    #[test]
    fn test_pkcs12_export_inkey_no_private_key_block() {
        let not_a_key = hitls_utils::pem::encode("CERTIFICATE", &build_test_cert_der());
        let cert_p = tmp("no_pk_block_cert.pem");
        let key_p = tmp("no_pk_block_key.pem");
        fs::write(&cert_p, &not_a_key).unwrap();
        fs::write(&key_p, &not_a_key).unwrap();
        let out_p = tmp("no_pk_block_out.p12");

        let key_p_s = key_p.to_str().unwrap();
        let cert_p_s = cert_p.to_str().unwrap();
        let out_p_s = out_p.to_str().unwrap();

        let opts = Pkcs12Options {
            input: None,
            password: "anypass",
            export: true,
            inkey: Some(key_p_s),
            cert_file: Some(cert_p_s),
            output: Some(out_p_s),
            ..default_opts()
        };
        let err = run(&opts).unwrap_err();
        assert_eq!(err.to_string(), "no PRIVATE KEY block found in key file");
        let _ = fs::remove_file(&cert_p);
        let _ = fs::remove_file(&key_p);
    }

    // C TC003 r7 spirit: -CAfile pointing at a PEM file with no CERTIFICATE blocks → empty
    // cert list. Pkcs12::create accepts that, but the resulting P12 has zero certs — assert that
    // explicitly so a future regression where this silently becomes an error is caught.
    #[test]
    fn test_pkcs12_export_cert_file_with_no_certificate_blocks() {
        let key_pem = hitls_utils::pem::encode("PRIVATE KEY", &build_test_pk_der());
        let key_p = tmp("nocert_key.pem");
        fs::write(&key_p, &key_pem).unwrap();
        // Cert file contains only an unrelated PEM block (no CERTIFICATE label).
        let no_cert_pem = hitls_utils::pem::encode("X509 CRL", &[0x30, 0x03, 0x02, 0x01, 0x01]);
        let cert_p = tmp("nocert_certs.pem");
        fs::write(&cert_p, &no_cert_pem).unwrap();
        let out_p = tmp("nocert_out.p12");

        let key_p_s = key_p.to_str().unwrap();
        let cert_p_s = cert_p.to_str().unwrap();
        let out_p_s = out_p.to_str().unwrap();

        let opts = Pkcs12Options {
            input: None,
            password: "anypass",
            export: true,
            inkey: Some(key_p_s),
            cert_file: Some(cert_p_s),
            output: Some(out_p_s),
            ..default_opts()
        };
        run(&opts).unwrap();
        // Round-trip parse the generated P12 → should have 0 certs.
        let p12_data = fs::read(&out_p).unwrap();
        let parsed = hitls_pki::pkcs12::Pkcs12::from_der(&p12_data, "anypass").unwrap();
        assert!(parsed.private_key.is_some());
        assert_eq!(parsed.certificates.len(), 0);

        let _ = fs::remove_file(&key_p);
        let _ = fs::remove_file(&cert_p);
        let _ = fs::remove_file(&out_p);
    }

    // Decode with nocerts=true → output PEM has the PRIVATE KEY but no CERTIFICATE blocks
    #[test]
    fn test_pkcs12_nocerts_mode() {
        let p12_data = create_test_p12("nocerts");
        let tmp_p12 = tmp("nocerts.p12");
        let tmp_out = tmp("nocerts.pem");
        fs::write(&tmp_p12, &p12_data).unwrap();
        let tmp_p12_s = tmp_p12.to_str().unwrap();
        let tmp_out_s = tmp_out.to_str().unwrap();
        let opts = Pkcs12Options {
            input: Some(tmp_p12_s),
            password: "nocerts",
            nocerts: true,
            output: Some(tmp_out_s),
            ..default_opts()
        };
        run(&opts).unwrap();
        let pem = fs::read_to_string(&tmp_out).unwrap();
        assert!(pem.contains("PRIVATE KEY"), "missing PRIVATE KEY block");
        assert!(
            !pem.contains("CERTIFICATE"),
            "CERTIFICATE block should be suppressed: {pem}"
        );
        let _ = fs::remove_file(&tmp_p12);
        let _ = fs::remove_file(&tmp_out);
    }
}
