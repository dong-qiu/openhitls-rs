//! RFC 6125 / RFC 9525 hostname verification against X.509 certificates.

use hitls_types::PkiError;

use super::Certificate;

/// Verify that `cert` is valid for `hostname`.
///
/// 1. If SAN exists, check dNSName and iPAddress entries (SAN takes precedence).
/// 2. If no SAN, fall back to subject CN (deprecated per RFC 9525 but still needed).
/// 3. Wildcard matching: `*.example.com` matches `foo.example.com` only.
pub fn verify_hostname(cert: &Certificate, hostname: &str) -> Result<(), PkiError> {
    let hostname = hostname.trim();
    if hostname.is_empty() {
        return Err(PkiError::HostnameMismatch("empty hostname".into()));
    }

    // Try parsing hostname as an IP address
    if let Some(ip) = parse_ip(hostname) {
        return verify_ip(cert, &ip, hostname);
    }

    // DNS hostname verification
    verify_dns(cert, hostname)
}

/// Verify a DNS hostname against certificate SAN dNSName entries (or CN fallback).
fn verify_dns(cert: &Certificate, hostname: &str) -> Result<(), PkiError> {
    if let Some(san) = cert.subject_alt_name() {
        // SAN exists — only check SAN, never fall back to CN
        for dns_name in &san.dns_names {
            if matches_dns(dns_name, hostname) {
                return Ok(());
            }
        }
        return Err(PkiError::HostnameMismatch(format!(
            "hostname '{}' does not match any SAN dNSName",
            hostname
        )));
    }

    // No SAN — fall back to subject CN (deprecated but needed for compatibility)
    if let Some(cn) = cert.subject.get("CN") {
        if matches_dns(cn, hostname) {
            return Ok(());
        }
    }

    Err(PkiError::HostnameMismatch(format!(
        "hostname '{}' does not match certificate subject",
        hostname
    )))
}

/// Verify an IP address against certificate SAN iPAddress entries.
fn verify_ip(cert: &Certificate, ip_bytes: &[u8], hostname: &str) -> Result<(), PkiError> {
    if let Some(san) = cert.subject_alt_name() {
        for ip_addr in &san.ip_addresses {
            if ip_addr == ip_bytes {
                return Ok(());
            }
        }
    }

    // IP addresses are never matched against DNS SANs or CN per RFC 6125
    Err(PkiError::HostnameMismatch(format!(
        "IP address '{}' does not match any SAN iPAddress",
        hostname
    )))
}

/// Check if a certificate DNS name pattern matches a hostname.
///
/// Supports wildcard matching per RFC 6125 §6.4.3:
/// - Wildcard `*` only in leftmost label
/// - No partial wildcards (`f*o.bar.com` rejected)
/// - At least 2 labels after wildcard (`*.com` rejected)
/// - Wildcard does not match bare domain (`*.example.com` != `example.com`)
/// - Wildcard does not match multi-level (`*.example.com` != `a.b.example.com`)
fn matches_dns(pattern: &str, hostname: &str) -> bool {
    let pattern = pattern.trim_end_matches('.');
    let hostname = hostname.trim_end_matches('.');

    // Case-insensitive comparison
    let pattern_lower = pattern.to_ascii_lowercase();
    let hostname_lower = hostname.to_ascii_lowercase();

    if !pattern_lower.contains('*') {
        // Exact match (case-insensitive)
        return pattern_lower == hostname_lower;
    }

    // Wildcard matching
    let labels: Vec<&str> = pattern_lower.split('.').collect();

    // Wildcard must be in leftmost label only
    if labels.len() < 2 {
        return false;
    }

    // The leftmost label must be exactly "*" — no partial wildcards
    if labels[0] != "*" {
        return false;
    }

    // Must have at least 2 labels after the wildcard (e.g., `*.com` is rejected)
    if labels.len() < 3 {
        return false;
    }

    let host_labels: Vec<&str> = hostname_lower.split('.').collect();

    // Wildcard matches exactly one label
    // So hostname must have exactly one more label than the pattern's non-wildcard part
    if host_labels.len() != labels.len() {
        return false;
    }

    // Compare all labels after the wildcard
    for (p, h) in labels[1..].iter().zip(host_labels[1..].iter()) {
        if p != h {
            return false;
        }
    }

    true
}

/// Parse a string as an IP address, returning the raw bytes (4 for IPv4, 16 for IPv6).
fn parse_ip(s: &str) -> Option<Vec<u8>> {
    // Try IPv4
    if let Ok(ip) = s.parse::<std::net::Ipv4Addr>() {
        return Some(ip.octets().to_vec());
    }

    // Try IPv6
    if let Ok(ip) = s.parse::<std::net::Ipv6Addr>() {
        return Some(ip.octets().to_vec());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::{DistinguishedName, SubjectAltName, SubjectPublicKeyInfo, X509Extension};
    use hitls_utils::oid::known;

    /// Build a minimal certificate with the given SAN and subject CN.
    fn make_cert(san: Option<SubjectAltName>, cn: Option<&str>) -> Certificate {
        let mut extensions = Vec::new();

        if let Some(san) = san {
            let value = encode_san(&san);
            extensions.push(X509Extension {
                oid: known::subject_alt_name().to_der_value(),
                critical: false,
                value,
            });
        }

        let entries = if let Some(cn) = cn {
            vec![("CN".to_string(), cn.to_string())]
        } else {
            vec![]
        };

        Certificate {
            raw: vec![],
            version: 2,
            serial_number: vec![1],
            issuer: DistinguishedName { entries: vec![] },
            subject: DistinguishedName { entries },
            not_before: 0,
            not_after: i64::MAX,
            public_key: SubjectPublicKeyInfo {
                algorithm_oid: vec![],
                algorithm_params: None,
                public_key: vec![],
            },
            extensions,
            tbs_raw: vec![],
            signature_algorithm: vec![],
            signature_params: None,
            signature_value: vec![],
        }
    }

    /// Encode a SubjectAltName to DER for testing purposes.
    fn encode_san(san: &SubjectAltName) -> Vec<u8> {
        let mut items = Vec::new();

        for dns in &san.dns_names {
            // dNSName [2] IA5String
            let bytes = dns.as_bytes();
            let mut entry = vec![0x82]; // context [2]
            encode_length(bytes.len(), &mut entry);
            entry.extend_from_slice(bytes);
            items.push(entry);
        }

        for ip in &san.ip_addresses {
            // iPAddress [7] OCTET STRING
            let mut entry = vec![0x87]; // context [7]
            encode_length(ip.len(), &mut entry);
            entry.extend_from_slice(ip);
            items.push(entry);
        }

        for email in &san.email_addresses {
            // rfc822Name [1] IA5String
            let bytes = email.as_bytes();
            let mut entry = vec![0x81]; // context [1]
            encode_length(bytes.len(), &mut entry);
            entry.extend_from_slice(bytes);
            items.push(entry);
        }

        // Wrap in SEQUENCE
        let inner: Vec<u8> = items.into_iter().flatten().collect();
        let mut result = vec![0x30]; // SEQUENCE
        encode_length(inner.len(), &mut result);
        result.extend_from_slice(&inner);
        result
    }

    fn encode_length(len: usize, out: &mut Vec<u8>) {
        if len < 128 {
            out.push(len as u8);
        } else if len < 256 {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push(len as u8);
        }
    }

    fn san_dns(names: &[&str]) -> SubjectAltName {
        SubjectAltName {
            dns_names: names.iter().map(|s| s.to_string()).collect(),
            ip_addresses: vec![],
            email_addresses: vec![],
            uris: vec![],
        }
    }

    fn san_ip(addrs: &[Vec<u8>]) -> SubjectAltName {
        SubjectAltName {
            dns_names: vec![],
            ip_addresses: addrs.to_vec(),
            email_addresses: vec![],
            uris: vec![],
        }
    }

    fn san_dns_and_ip(names: &[&str], addrs: &[Vec<u8>]) -> SubjectAltName {
        SubjectAltName {
            dns_names: names.iter().map(|s| s.to_string()).collect(),
            ip_addresses: addrs.to_vec(),
            email_addresses: vec![],
            uris: vec![],
        }
    }

    #[test]
    fn test_exact_dns_match() {
        let cert = make_cert(Some(san_dns(&["www.example.com"])), None);
        assert!(verify_hostname(&cert, "www.example.com").is_ok());
    }

    #[test]
    fn test_wildcard_single_level() {
        let cert = make_cert(Some(san_dns(&["*.example.com"])), None);
        assert!(verify_hostname(&cert, "foo.example.com").is_ok());
        assert!(verify_hostname(&cert, "bar.example.com").is_ok());
    }

    #[test]
    fn test_wildcard_no_bare_domain() {
        let cert = make_cert(Some(san_dns(&["*.example.com"])), None);
        assert!(verify_hostname(&cert, "example.com").is_err());
    }

    #[test]
    fn test_wildcard_no_deep_match() {
        let cert = make_cert(Some(san_dns(&["*.example.com"])), None);
        assert!(verify_hostname(&cert, "a.b.example.com").is_err());
    }

    #[test]
    fn test_wildcard_minimum_labels() {
        // *.com should not match example.com (not enough labels after wildcard)
        let cert = make_cert(Some(san_dns(&["*.com"])), None);
        assert!(verify_hostname(&cert, "example.com").is_err());
    }

    #[test]
    fn test_partial_wildcard_rejected() {
        let cert = make_cert(Some(san_dns(&["f*o.example.com"])), None);
        assert!(verify_hostname(&cert, "foo.example.com").is_err());
    }

    #[test]
    fn test_case_insensitive() {
        let cert = make_cert(Some(san_dns(&["www.example.com"])), None);
        assert!(verify_hostname(&cert, "WWW.EXAMPLE.COM").is_ok());
        assert!(verify_hostname(&cert, "Www.Example.Com").is_ok());
    }

    #[test]
    fn test_ipv4_match() {
        let cert = make_cert(Some(san_ip(&[vec![192, 168, 1, 1]])), None);
        assert!(verify_hostname(&cert, "192.168.1.1").is_ok());
        assert!(verify_hostname(&cert, "192.168.1.2").is_err());
    }

    #[test]
    fn test_san_takes_precedence_over_cn() {
        // SAN has different name than CN; hostname matches CN but not SAN → should fail
        let cert = make_cert(
            Some(san_dns(&["other.example.com"])),
            Some("www.example.com"),
        );
        assert!(verify_hostname(&cert, "www.example.com").is_err());
        assert!(verify_hostname(&cert, "other.example.com").is_ok());
    }

    #[test]
    fn test_cn_fallback_no_san() {
        // No SAN at all — should fall back to CN
        let cert = make_cert(None, Some("www.example.com"));
        assert!(verify_hostname(&cert, "www.example.com").is_ok());
        assert!(verify_hostname(&cert, "other.example.com").is_err());
    }

    #[test]
    fn test_ipv6_match() {
        let ipv6_bytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1].to_vec();
        let cert = make_cert(Some(san_ip(&[ipv6_bytes])), None);
        assert!(verify_hostname(&cert, "::1").is_ok());
        assert!(verify_hostname(&cert, "::2").is_err());
    }

    #[test]
    fn test_ip_not_matched_against_dns_san() {
        // Certificate has DNS SAN "192.168.1.1" (as a string, not IP), hostname is IP
        let cert = make_cert(Some(san_dns(&["192.168.1.1"])), None);
        // IP addresses must match iPAddress SAN, not dNSName
        assert!(verify_hostname(&cert, "192.168.1.1").is_err());
    }

    #[test]
    fn test_empty_hostname() {
        let cert = make_cert(Some(san_dns(&["www.example.com"])), None);
        assert!(verify_hostname(&cert, "").is_err());
    }

    #[test]
    fn test_no_san_no_cn() {
        let cert = make_cert(None, None);
        assert!(verify_hostname(&cert, "www.example.com").is_err());
    }

    #[test]
    fn test_multiple_san_entries() {
        let cert = make_cert(
            Some(san_dns_and_ip(
                &["www.example.com", "mail.example.com"],
                &[vec![10, 0, 0, 1]],
            )),
            None,
        );
        assert!(verify_hostname(&cert, "www.example.com").is_ok());
        assert!(verify_hostname(&cert, "mail.example.com").is_ok());
        assert!(verify_hostname(&cert, "10.0.0.1").is_ok());
        assert!(verify_hostname(&cert, "other.example.com").is_err());
    }
}
