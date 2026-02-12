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
