//! X.509 certificate display command implementation.

use std::fs;

pub fn run(input: &str, text: bool, fingerprint: bool) -> Result<(), Box<dyn std::error::Error>> {
    let pem_data = fs::read_to_string(input)?;
    let cert = hitls_pki::x509::Certificate::from_pem(&pem_data)
        .map_err(|e| format!("failed to parse certificate: {e}"))?;

    if text {
        print!("{}", cert.to_text());
    }

    if fingerprint {
        let digest = hitls_crypto::sha2::Sha256::digest(&cert.raw)?;
        let hex = digest
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        println!("SHA256 Fingerprint={hex}");
    }

    if !text && !fingerprint {
        println!("subject= {}", cert.subject);
        println!("issuer= {}", cert.issuer);
        println!("serial= {}", hex_str(&cert.serial_number));
        println!("notBefore= {}", format_time(cert.not_before));
        println!("notAfter= {}", format_time(cert.not_after));
    }

    Ok(())
}

fn hex_str(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn format_time(unix_ts: i64) -> String {
    let secs_per_day = 86400i64;
    let secs_per_hour = 3600i64;
    let secs_per_min = 60i64;

    let days = unix_ts / secs_per_day;
    let rem = unix_ts % secs_per_day;
    let hour = rem / secs_per_hour;
    let min = (rem % secs_per_hour) / secs_per_min;
    let sec = rem % secs_per_min;

    let (year, month, day) = days_to_ymd(days);
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mon = months.get((month - 1) as usize).unwrap_or(&"???");
    format!("{mon} {day:2} {hour:02}:{min:02}:{sec:02} {year} UTC")
}

fn days_to_ymd(mut days: i64) -> (i64, i64, i64) {
    days += 719468;
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // hex_str
    // -----------------------------------------------------------------------

    #[test]
    fn test_hex_str_empty() {
        assert_eq!(hex_str(&[]), "");
    }

    #[test]
    fn test_hex_str_single_byte() {
        assert_eq!(hex_str(&[0xAB]), "ab");
    }

    #[test]
    fn test_hex_str_multiple_bytes() {
        assert_eq!(hex_str(&[0xAB, 0xCD, 0xEF]), "ab:cd:ef");
    }

    // -----------------------------------------------------------------------
    // days_to_ymd
    // -----------------------------------------------------------------------

    #[test]
    fn test_days_to_ymd_epoch() {
        // Unix epoch day 0 = 1970-01-01
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
    }

    #[test]
    fn test_days_to_ymd_year_2000() {
        // 1970 to 2000: 30 years, 7 leap years → 10957 days
        assert_eq!(days_to_ymd(10957), (2000, 1, 1));
    }

    #[test]
    fn test_days_to_ymd_leap_feb29() {
        // 2000 is a leap year; Feb 29 is day 10957 + 59
        assert_eq!(days_to_ymd(11016), (2000, 2, 29));
    }

    #[test]
    fn test_days_to_ymd_dec31() {
        // 1970-12-31 is day 364
        assert_eq!(days_to_ymd(364), (1970, 12, 31));
    }

    // -----------------------------------------------------------------------
    // format_time
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_time_epoch() {
        let s = format_time(0);
        assert!(s.contains("1970"), "expected year 1970 in '{s}'");
        assert!(s.contains("Jan"), "expected Jan in '{s}'");
        assert!(s.contains("00:00:00"), "expected 00:00:00 in '{s}'");
        assert!(s.ends_with("UTC"), "expected UTC suffix in '{s}'");
    }

    #[test]
    fn test_format_time_2024_jan1() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        let s = format_time(1704067200);
        assert!(s.contains("2024"), "expected 2024 in '{s}'");
        assert!(s.contains("Jan"), "expected Jan in '{s}'");
        assert!(s.contains("00:00:00"), "expected 00:00:00 in '{s}'");
    }

    #[test]
    fn test_format_time_includes_utc_suffix() {
        let s = format_time(1_700_000_000);
        assert!(s.ends_with("UTC"));
    }

    // -----------------------------------------------------------------------
    // run() with a real certificate file
    // -----------------------------------------------------------------------

    fn make_test_cert_pem() -> String {
        let seed = [0x42u8; 32];
        let der = hitls_pki::pkcs8::encode_ed25519_pkcs8_der(&seed);
        let key_pem = hitls_utils::pem::encode("PRIVATE KEY", &der);
        let sk = hitls_pki::x509::SigningKey::from_pkcs8_pem(&key_pem).unwrap();
        let dn = hitls_pki::x509::DistinguishedName {
            entries: vec![("CN".to_string(), "Test x509cmd".to_string())],
        };
        let cert =
            hitls_pki::x509::CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 9_999_999_999)
                .unwrap();
        hitls_utils::pem::encode("CERTIFICATE", &cert.raw)
    }

    #[test]
    fn test_run_default_output() {
        use std::fs;
        let pem = make_test_cert_pem();
        let tmp = std::env::temp_dir().join("test_x509cmd_default.pem");
        fs::write(&tmp, &pem).unwrap();
        assert!(run(tmp.to_str().unwrap(), false, false).is_ok());
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_run_fingerprint_mode() {
        use std::fs;
        let pem = make_test_cert_pem();
        let tmp = std::env::temp_dir().join("test_x509cmd_fp.pem");
        fs::write(&tmp, &pem).unwrap();
        assert!(run(tmp.to_str().unwrap(), false, true).is_ok());
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_run_text_mode() {
        use std::fs;
        let pem = make_test_cert_pem();
        let tmp = std::env::temp_dir().join("test_x509cmd_text.pem");
        fs::write(&tmp, &pem).unwrap();
        assert!(run(tmp.to_str().unwrap(), true, false).is_ok());
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_run_nonexistent_file() {
        assert!(run("/nonexistent_x509cmd_test/cert.pem", false, false).is_err());
    }

    #[test]
    fn test_run_invalid_pem() {
        use std::fs;
        let tmp = std::env::temp_dir().join("test_x509cmd_invalid.pem");
        fs::write(&tmp, b"not a certificate at all").unwrap();
        assert!(run(tmp.to_str().unwrap(), false, false).is_err());
        let _ = fs::remove_file(&tmp);
    }
}
