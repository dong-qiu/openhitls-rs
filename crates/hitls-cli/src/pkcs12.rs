//! PKCS#12 CLI subcommand — parse, extract, and create P12 files.

use std::fs;

#[allow(clippy::too_many_arguments)]
pub fn run(
    input: Option<&str>,
    password: &str,
    info: bool,
    nokeys: bool,
    nocerts: bool,
    export: bool,
    inkey: Option<&str>,
    cert_file: Option<&str>,
    output: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if export {
        return run_export(inkey, cert_file, password, output);
    }

    let input = input.ok_or("--input is required when not in --export mode")?;
    let p12_data = fs::read(input)?;
    let p12 = hitls_pki::pkcs12::Pkcs12::from_der(&p12_data, password)?;

    if info {
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
    if !nokeys {
        if let Some(pk_der) = &p12.private_key {
            let pem = hitls_utils::pem::encode("PRIVATE KEY", pk_der);
            out.push_str(&pem);
        }
    }

    // Extract certificates
    if !nocerts {
        for cert_der in &p12.certificates {
            let pem = hitls_utils::pem::encode("CERTIFICATE", cert_der);
            out.push_str(&pem);
        }
    }

    if let Some(path) = output {
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

    fn create_test_p12(password: &str) -> Vec<u8> {
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
        let pk = e6.finish();
        let cert_inner = vec![0x30, 0x03, 0x02, 0x01, 0x01];
        let mut e7 = Encoder::new();
        e7.write_sequence(&cert_inner);
        let cert = e7.finish();
        hitls_pki::pkcs12::Pkcs12::create(Some(&pk), &[&cert], password).unwrap()
    }

    #[test]
    fn test_pkcs12_info_mode() {
        let p12_data = create_test_p12("testpass");
        let tmp = std::env::temp_dir().join("test_pkcs12_info.p12");
        fs::write(&tmp, &p12_data).unwrap();
        let result = run(
            Some(tmp.to_str().unwrap()),
            "testpass",
            true,
            false,
            false,
            false,
            None,
            None,
            None,
        );
        assert!(result.is_ok());
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_pkcs12_extract_to_file() {
        let p12_data = create_test_p12("extract");
        let tmp_p12 = std::env::temp_dir().join("test_pkcs12_extract.p12");
        let tmp_out = std::env::temp_dir().join("test_pkcs12_extract.pem");
        fs::write(&tmp_p12, &p12_data).unwrap();
        let result = run(
            Some(tmp_p12.to_str().unwrap()),
            "extract",
            false,
            false,
            false,
            false,
            None,
            None,
            Some(tmp_out.to_str().unwrap()),
        );
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
        let result = run(
            Some(tmp_p12.to_str().unwrap()),
            "nokeys",
            false,
            true,
            false,
            false,
            None,
            None,
            Some(tmp_out.to_str().unwrap()),
        );
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

        let result = run(
            None,
            "exportpass",
            false,
            false,
            false,
            true,
            Some(tmp_key.to_str().unwrap()),
            Some(tmp_cert.to_str().unwrap()),
            Some(tmp_p12.to_str().unwrap()),
        );
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
}
