//! Human-readable text output for X.509 certificates, CRLs, and CSRs.
//!
//! Provides `to_text()` methods that produce output similar to `openssl x509 -text`.

use super::{
    Certificate, CertificateRequest, CertificateRevocationList, DistinguishedName,
    SubjectPublicKeyInfo, X509Extension,
};
use hitls_utils::oid::Oid;

// ---------------------------------------------------------------------------
// OID-to-name mapping
// ---------------------------------------------------------------------------

/// Map a DER-encoded OID value to a human-readable name.
pub fn oid_name(oid_bytes: &[u8]) -> String {
    if let Ok(oid) = Oid::from_der_value(oid_bytes) {
        if let Some(name) = oid_to_name(&oid) {
            return name.to_string();
        }
        return oid.to_dot_string();
    }
    hex_colon(oid_bytes)
}

fn oid_to_name(oid: &Oid) -> Option<&'static str> {
    let arcs = oid.arcs();
    match arcs {
        // Signature algorithms
        [1, 2, 840, 113549, 1, 1, 1] => Some("rsaEncryption"),
        [1, 2, 840, 113549, 1, 1, 5] => Some("sha1WithRSAEncryption"),
        [1, 2, 840, 113549, 1, 1, 11] => Some("sha256WithRSAEncryption"),
        [1, 2, 840, 113549, 1, 1, 12] => Some("sha384WithRSAEncryption"),
        [1, 2, 840, 113549, 1, 1, 13] => Some("sha512WithRSAEncryption"),
        [1, 2, 840, 113549, 1, 1, 10] => Some("RSASSA-PSS"),
        [1, 2, 840, 10045, 2, 1] => Some("id-ecPublicKey"),
        [1, 2, 840, 10045, 4, 3, 2] => Some("ecdsa-with-SHA256"),
        [1, 2, 840, 10045, 4, 3, 3] => Some("ecdsa-with-SHA384"),
        [1, 2, 840, 10045, 4, 3, 4] => Some("ecdsa-with-SHA512"),
        [1, 3, 101, 112] => Some("Ed25519"),
        [1, 3, 101, 110] => Some("X25519"),
        // Named curves
        [1, 3, 132, 0, 33] => Some("secp224r1"),
        [1, 2, 840, 10045, 3, 1, 7] => Some("prime256v1"),
        [1, 3, 132, 0, 34] => Some("secp384r1"),
        [1, 3, 132, 0, 35] => Some("secp521r1"),
        [1, 3, 36, 3, 3, 2, 8, 1, 1, 7] => Some("brainpoolP256r1"),
        [1, 3, 36, 3, 3, 2, 8, 1, 1, 11] => Some("brainpoolP384r1"),
        [1, 3, 36, 3, 3, 2, 8, 1, 1, 13] => Some("brainpoolP512r1"),
        // Hash algorithms
        [2, 16, 840, 1, 101, 3, 4, 2, 1] => Some("SHA-256"),
        [2, 16, 840, 1, 101, 3, 4, 2, 2] => Some("SHA-384"),
        [2, 16, 840, 1, 101, 3, 4, 2, 3] => Some("SHA-512"),
        [1, 3, 14, 3, 2, 26] => Some("SHA-1"),
        // SM
        [1, 2, 156, 10197, 1, 301] => Some("curveSM2"),
        [1, 2, 156, 10197, 1, 501] => Some("SM2-with-SM3"),
        [1, 2, 156, 10197, 1, 401, ..] => Some("SM3"),
        // DSA
        [1, 2, 840, 10040, 4, 1] => Some("DSA"),
        [1, 2, 840, 10040, 4, 3] => Some("dsa-with-SHA1"),
        // Extensions
        [2, 5, 29, 14] => Some("X509v3 Subject Key Identifier"),
        [2, 5, 29, 15] => Some("X509v3 Key Usage"),
        [2, 5, 29, 17] => Some("X509v3 Subject Alternative Name"),
        [2, 5, 29, 19] => Some("X509v3 Basic Constraints"),
        [2, 5, 29, 20] => Some("X509v3 CRL Number"),
        [2, 5, 29, 21] => Some("X509v3 CRL Reason"),
        [2, 5, 29, 24] => Some("X509v3 Invalidity Date"),
        [2, 5, 29, 27] => Some("X509v3 Delta CRL Indicator"),
        [2, 5, 29, 28] => Some("X509v3 Issuing Distribution Point"),
        [2, 5, 29, 31] => Some("X509v3 CRL Distribution Points"),
        [2, 5, 29, 35] => Some("X509v3 Authority Key Identifier"),
        [2, 5, 29, 37] => Some("X509v3 Extended Key Usage"),
        [1, 3, 6, 1, 5, 5, 7, 1, 1] => Some("Authority Information Access"),
        // EKU values
        [1, 3, 6, 1, 5, 5, 7, 3, 1] => Some("TLS Web Server Authentication"),
        [1, 3, 6, 1, 5, 5, 7, 3, 2] => Some("TLS Web Client Authentication"),
        [1, 3, 6, 1, 5, 5, 7, 3, 3] => Some("Code Signing"),
        [1, 3, 6, 1, 5, 5, 7, 3, 4] => Some("E-mail Protection"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn hex_colon(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn hex_dump(data: &[u8], indent: usize) -> String {
    let prefix = " ".repeat(indent);
    let mut lines = Vec::new();
    for chunk in data.chunks(16) {
        let hex = chunk
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        lines.push(format!("{prefix}{hex}"));
    }
    lines.join("\n")
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

fn format_dn(dn: &DistinguishedName) -> String {
    dn.to_string()
}

fn format_pubkey_info(spki: &SubjectPublicKeyInfo) -> String {
    let alg_name = oid_name(&spki.algorithm_oid);
    let mut out = format!("        Public Key Algorithm: {alg_name}\n");

    // Try to detect key type for more detail
    if alg_name == "rsaEncryption" {
        let bit_len = spki.public_key.len().saturating_sub(1) * 8;
        out.push_str(&format!("            RSA Public-Key: ({bit_len} bit)\n"));
    } else if alg_name == "id-ecPublicKey" {
        let curve_name = spki
            .algorithm_params
            .as_ref()
            .and_then(|p| Oid::from_der_value(p).ok())
            .and_then(|o| oid_to_name(&o).map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown".to_string());
        let bit_len = (spki.public_key.len().saturating_sub(1)) * 4;
        out.push_str(&format!(
            "            EC Public-Key: ({bit_len} bit, {curve_name})\n"
        ));
    } else if alg_name == "Ed25519" {
        out.push_str("            ED25519 Public-Key: (256 bit)\n");
    }

    out.push_str(&format!(
        "            pub:\n{}\n",
        hex_dump(&spki.public_key, 16)
    ));
    out
}

fn format_key_usage(bits: u16) -> String {
    let names = [
        (0x8000, "Digital Signature"),
        (0x4000, "Non Repudiation"),
        (0x2000, "Key Encipherment"),
        (0x1000, "Data Encipherment"),
        (0x0800, "Key Agreement"),
        (0x0400, "Key Cert Sign"),
        (0x0200, "CRL Sign"),
        (0x0100, "Encipher Only"),
        (0x0080, "Decipher Only"),
    ];
    let used: Vec<&str> = names
        .iter()
        .filter(|(mask, _)| bits & mask != 0)
        .map(|(_, name)| *name)
        .collect();
    if used.is_empty() {
        "(none)".to_string()
    } else {
        used.join(", ")
    }
}

fn format_extension(ext: &X509Extension) -> String {
    let name = oid_name(&ext.oid);
    let crit = if ext.critical { " critical" } else { "" };
    let mut out = format!("        {name}:{crit}\n");

    // Try to decode well-known extensions
    if let Ok(oid) = Oid::from_der_value(&ext.oid) {
        match oid.arcs() {
            [2, 5, 29, 19] => {
                // BasicConstraints
                out.push_str(&format_basic_constraints(&ext.value));
            }
            [2, 5, 29, 15] => {
                // KeyUsage
                out.push_str(&format_key_usage_ext(&ext.value));
            }
            [2, 5, 29, 14] => {
                // SubjectKeyIdentifier
                out.push_str(&format!(
                    "            {}\n",
                    hex_colon(parse_ski(&ext.value))
                ));
            }
            _ => {
                // Raw hex for unrecognized extensions
                out.push_str(&format!("            {}\n", hex_colon(&ext.value)));
            }
        }
    } else {
        out.push_str(&format!("            {}\n", hex_colon(&ext.value)));
    }
    out
}

fn format_basic_constraints(value: &[u8]) -> String {
    // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }
    use hitls_utils::asn1::Decoder;
    if let Ok(mut dec) = Decoder::new(value).read_sequence() {
        let is_ca = dec.read_boolean().unwrap_or(false);
        let path_len = dec
            .read_integer()
            .ok()
            .map(|bytes| bytes.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64));
        let pl_str = path_len
            .map(|p| p.to_string())
            .unwrap_or_else(|| "none".to_string());
        format!(
            "            CA:{}, pathlen:{pl_str}\n",
            if is_ca { "TRUE" } else { "FALSE" }
        )
    } else {
        format!("            {}\n", hex_colon(value))
    }
}

fn format_key_usage_ext(value: &[u8]) -> String {
    // KeyUsage ::= BIT STRING
    use hitls_utils::asn1::Decoder;
    let mut dec = Decoder::new(value);
    if let Ok((_unused_bits, bit_data)) = dec.read_bit_string() {
        let mut ku: u16 = 0;
        if !bit_data.is_empty() {
            ku |= (bit_data[0] as u16) << 8;
        }
        if bit_data.len() > 1 {
            ku |= bit_data[1] as u16;
        }
        format!("            {}\n", format_key_usage(ku))
    } else {
        format!("            {}\n", hex_colon(value))
    }
}

fn parse_ski(value: &[u8]) -> &[u8] {
    // SubjectKeyIdentifier ::= OCTET STRING
    use hitls_utils::asn1::Decoder;
    let mut dec = Decoder::new(value);
    if let Ok(os) = dec.read_octet_string() {
        return os;
    }
    value
}

// ---------------------------------------------------------------------------
// Certificate::to_text()
// ---------------------------------------------------------------------------

impl Certificate {
    /// Produce human-readable text output similar to `openssl x509 -text`.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str("Certificate:\n");
        out.push_str("    Data:\n");
        out.push_str(&format!(
            "        Version: {} (0x{:x})\n",
            self.version + 1,
            self.version
        ));
        out.push_str(&format!(
            "        Serial Number: {}\n",
            hex_colon(&self.serial_number)
        ));
        out.push_str(&format!(
            "    Signature Algorithm: {}\n",
            oid_name(&self.signature_algorithm)
        ));
        out.push_str(&format!("    Issuer: {}\n", format_dn(&self.issuer)));
        out.push_str("    Validity\n");
        out.push_str(&format!(
            "        Not Before: {}\n",
            format_time(self.not_before)
        ));
        out.push_str(&format!(
            "        Not After : {}\n",
            format_time(self.not_after)
        ));
        out.push_str(&format!("    Subject: {}\n", format_dn(&self.subject)));
        out.push_str("    Subject Public Key Info:\n");
        out.push_str(&format_pubkey_info(&self.public_key));

        if !self.extensions.is_empty() {
            out.push_str("    X509v3 extensions:\n");
            for ext in &self.extensions {
                out.push_str(&format_extension(ext));
            }
        }

        out.push_str(&format!(
            "    Signature Algorithm: {}\n",
            oid_name(&self.signature_algorithm)
        ));
        out.push_str(&format!(
            "         {}\n",
            hex_dump(&self.signature_value, 9).trim_start()
        ));
        out
    }
}

// ---------------------------------------------------------------------------
// CertificateRevocationList::to_text()
// ---------------------------------------------------------------------------

impl CertificateRevocationList {
    /// Produce human-readable text output similar to `openssl crl -text`.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str("Certificate Revocation List (CRL):\n");
        out.push_str(&format!(
            "    Version: {} (0x{:x})\n",
            self.version,
            self.version.saturating_sub(1)
        ));
        out.push_str(&format!(
            "    Signature Algorithm: {}\n",
            oid_name(&self.signature_algorithm)
        ));
        out.push_str(&format!("    Issuer: {}\n", format_dn(&self.issuer)));
        out.push_str(&format!(
            "    Last Update: {}\n",
            format_time(self.this_update)
        ));
        if let Some(next) = self.next_update {
            out.push_str(&format!("    Next Update: {}\n", format_time(next)));
        }

        if !self.extensions.is_empty() {
            out.push_str("    CRL extensions:\n");
            for ext in &self.extensions {
                out.push_str(&format_extension(ext));
            }
        }

        if self.revoked_certs.is_empty() {
            out.push_str("No Revoked Certificates.\n");
        } else {
            out.push_str("Revoked Certificates:\n");
            for rc in &self.revoked_certs {
                out.push_str(&format!(
                    "    Serial Number: {}\n",
                    hex_colon(&rc.serial_number)
                ));
                out.push_str(&format!(
                    "        Revocation Date: {}\n",
                    format_time(rc.revocation_date)
                ));
                if let Some(reason) = &rc.reason {
                    out.push_str(&format!("        Reason: {reason:?}\n"));
                }
            }
        }

        out.push_str(&format!(
            "    Signature Algorithm: {}\n",
            oid_name(&self.signature_algorithm)
        ));
        out.push_str(&format!(
            "         {}\n",
            hex_dump(&self.signature_value, 9).trim_start()
        ));
        out
    }
}

// ---------------------------------------------------------------------------
// CertificateRequest::to_text()
// ---------------------------------------------------------------------------

impl CertificateRequest {
    /// Produce human-readable text output similar to `openssl req -text`.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str("Certificate Request:\n");
        out.push_str("    Data:\n");
        out.push_str(&format!(
            "        Version: {} (0x{:x})\n",
            self.version + 1,
            self.version
        ));
        out.push_str(&format!("        Subject: {}\n", format_dn(&self.subject)));
        out.push_str("        Subject Public Key Info:\n");
        // Indent one extra level for CSR
        let pubkey_text = format_pubkey_info(&self.public_key);
        for line in pubkey_text.lines() {
            out.push_str(&format!("    {line}\n"));
        }

        if !self.attributes.is_empty() {
            out.push_str("    Requested Extensions:\n");
            for ext in &self.attributes {
                out.push_str(&format_extension(ext));
            }
        }

        out.push_str(&format!(
            "    Signature Algorithm: {}\n",
            oid_name(&self.signature_algorithm)
        ));
        out.push_str(&format!(
            "         {}\n",
            hex_dump(&self.signature_value, 9).trim_start()
        ));
        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oid_name_mapping() {
        // RSA
        let rsa_oid = hitls_utils::oid::known::rsa_encryption().to_der_value();
        assert_eq!(oid_name(&rsa_oid), "rsaEncryption");

        // SHA-256 with RSA
        let sha256rsa = hitls_utils::oid::known::sha256_with_rsa_encryption().to_der_value();
        assert_eq!(oid_name(&sha256rsa), "sha256WithRSAEncryption");

        // EC public key
        let ec_oid = hitls_utils::oid::known::ec_public_key().to_der_value();
        assert_eq!(oid_name(&ec_oid), "id-ecPublicKey");

        // P-256
        let p256 = hitls_utils::oid::known::prime256v1().to_der_value();
        assert_eq!(oid_name(&p256), "prime256v1");

        // BasicConstraints
        let bc = hitls_utils::oid::known::basic_constraints().to_der_value();
        assert_eq!(oid_name(&bc), "X509v3 Basic Constraints");

        // KeyUsage
        let ku = hitls_utils::oid::known::key_usage().to_der_value();
        assert_eq!(oid_name(&ku), "X509v3 Key Usage");

        // Ed25519
        let ed = hitls_utils::oid::known::ed25519().to_der_value();
        assert_eq!(oid_name(&ed), "Ed25519");

        // Unknown OID falls back to dot string
        let unknown = Oid::new(&[1, 2, 3, 4, 5]).to_der_value();
        assert_eq!(oid_name(&unknown), "1.2.3.4.5");
    }

    const RSA_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDSzCCAjOgAwIBAgIUWB7v8OWeg9hFf6g9WZ1P+QSLRbUwDQYJKoZIhvcNAQEL
BQAwNDERMA8GA1UEAwwIVGVzdCBSU0ExEjAQBgNVBAoMCU9wZW5IaVRMUzELMAkG
A1UEBhMCQ04wIBcNMjYwMjA3MTMxOTE1WhgPMjEyNjAxMTQxMzE5MTVaMDQxETAP
BgNVBAMMCFRlc3QgUlNBMRIwEAYDVQQKDAlPcGVuSGlUTFMxCzAJBgNVBAYTAkNO
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlWXxSPVfc2evuGXrFShc
/On9IgjzX126fqJLQmrXnOguX4iumQ/ro5lhkh+kd/BBHrKHOc9HZXfF4DJKqVU0
pN1yJvwTOl5DXYHkM6pZKK71boTF7rOmBzmWxynYeOodbvKl2hfCChogWhroGTp/
qPVsb7P+/zmEZ8bLRAW55JH8nsulsuypPxPKlJg7E/cI9txCjOT9m4k8Vyhbl9Ae
y3b4LBvS7vGGe4xGBNl2FhMton15pJaY2fR/81gHndNWsvnXWd2+WCK1JSDQ+iph
o8CwKZGyRHrpRJQabfQzxPa89F2dVd1Fy7ghjfN3f95F/SybN5C/vEtssj4uFFtw
mQIDAQABo1MwUTAdBgNVHQ4EFgQUU1m4LRLxrkjcmC/BtJ+CBdJz3qQwHwYDVR0j
BBgwFoAUU1m4LRLxrkjcmC/BtJ+CBdJz3qQwDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAQEAjZI4TAYBumY+jgZNT8+jOq0ZzFXOOTwhebkPE2ySim9B
lZT2bGYZRzdtYMeoYp4TEBi9RpvbYQmVwy5q4TqMC3lMOp/mudtZz1Xf8bpBfar0
9azOt+kBZl4TbG6a/0RQpZ0P63UD26+D9DhisAL4J6uSs6pZBd/Vi14fVcobVmWM
DceUacALzjMep4BZBuQBi8x9345TSY4fPqt5Resneg8Tn/WWVsYYBTjnZ4VtRyXl
njnqwGMIjoFLWz+HnjFyL5w6BieC1o9VW07tIw3qMJrAcfOOQmFgiUNlSqQkKvQO
UKl9bCAgj+tNwbRWhv1gkGzhRS0git4O4Z9wsAse9A==
-----END CERTIFICATE-----
";

    #[test]
    fn test_cert_to_text_basic() {
        let cert = Certificate::from_pem(RSA_CA_PEM).unwrap();
        let text = cert.to_text();

        assert!(text.contains("Certificate:"));
        assert!(text.contains("Version: 4"));
        assert!(text.contains("Serial Number:"));
        assert!(text.contains("Issuer:"));
        assert!(text.contains("Subject:"));
        assert!(text.contains("Not Before:"));
        assert!(text.contains("Not After :"));
        assert!(text.contains("Public Key Algorithm:"));
        assert!(text.contains("Signature Algorithm:"));
        assert!(text.contains("rsaEncryption"));
        assert!(text.contains("sha256WithRSAEncryption"));
        assert!(text.contains("Test RSA"));
    }

    #[test]
    fn test_cert_to_text_extensions() {
        let cert = Certificate::from_pem(RSA_CA_PEM).unwrap();
        let text = cert.to_text();

        // CA cert has BasicConstraints, SubjectKeyIdentifier, AuthorityKeyIdentifier
        assert!(text.contains("X509v3 extensions:"));
        assert!(text.contains("X509v3 Basic Constraints"));
        assert!(text.contains("CA:TRUE"));
        assert!(text.contains("X509v3 Subject Key Identifier"));
    }

    #[test]
    fn test_key_usage_formatting() {
        // Digital Signature + Key Encipherment = 0xA0 << 8 = 0xA000
        assert_eq!(
            format_key_usage(0xA000),
            "Digital Signature, Key Encipherment"
        );

        // Key Cert Sign + CRL Sign = 0x0600
        assert_eq!(format_key_usage(0x0600), "Key Cert Sign, CRL Sign");

        // Empty
        assert_eq!(format_key_usage(0), "(none)");
    }

    #[test]
    fn test_hex_colon_and_dump() {
        assert_eq!(hex_colon(&[0xab, 0xcd, 0xef]), "ab:cd:ef");
        assert_eq!(hex_colon(&[]), "");

        let dump = hex_dump(&[0x01, 0x02, 0x03], 4);
        assert!(dump.contains("01:02:03"));
        assert!(dump.starts_with("    "));
    }

    // -----------------------------------------------------------------------
    // P5: Additional text output tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_to_text_rsa_cert_fields() {
        let cert = Certificate::from_pem(RSA_CA_PEM).unwrap();
        let text = cert.to_text();
        // Check key details
        assert!(text.contains("CN=Test RSA"));
        assert!(text.contains("O=OpenHiTLS"));
        assert!(text.contains("C=CN"));
        // Should show RSA key algorithm
        assert!(text.contains("rsaEncryption"));
        // Should contain hex dump of public key
        assert!(text.contains("Public-Key:"));
    }

    #[test]
    fn test_to_text_ecdsa_cert() {
        let kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
        let dn = DistinguishedName {
            entries: vec![("CN".to_string(), "ECDSA Text Test".to_string())],
        };
        let sk = crate::x509::SigningKey::Ecdsa {
            curve_id: hitls_types::EccCurveId::NistP256,
            key_pair: kp,
        };
        let cert =
            crate::x509::CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000)
                .unwrap();
        let text = cert.to_text();
        assert!(text.contains("Certificate:"));
        assert!(text.contains("ECDSA Text Test"));
        assert!(text.contains("id-ecPublicKey") || text.contains("ecPublicKey"));
        assert!(text.contains("Signature Algorithm:"));
    }
}
