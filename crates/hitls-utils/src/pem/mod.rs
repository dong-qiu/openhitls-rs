//! PEM format parsing and generation.

use hitls_types::CryptoError;

/// A parsed PEM block.
#[derive(Debug, Clone)]
pub struct PemBlock {
    /// The label (e.g., "CERTIFICATE", "PRIVATE KEY").
    pub label: String,
    /// The decoded binary data.
    pub data: Vec<u8>,
}

const BEGIN_PREFIX: &str = "-----BEGIN ";
const END_PREFIX: &str = "-----END ";
const DASHES_SUFFIX: &str = "-----";

/// Parse a PEM-encoded string into one or more PEM blocks.
pub fn parse(input: &str) -> Result<Vec<PemBlock>, CryptoError> {
    let mut blocks = Vec::new();
    let mut lines = input.lines().peekable();

    while let Some(line) = lines.next() {
        let line = line.trim();
        if let Some(label) = line
            .strip_prefix(BEGIN_PREFIX)
            .and_then(|s| s.strip_suffix(DASHES_SUFFIX))
        {
            let label = label.to_string();
            let end_marker = format!("{END_PREFIX}{label}{DASHES_SUFFIX}");

            let mut base64_data = String::new();
            let mut found_end = false;
            for inner_line in lines.by_ref() {
                let inner_line = inner_line.trim();
                if inner_line == end_marker {
                    found_end = true;
                    break;
                }
                base64_data.push_str(inner_line);
            }

            if !found_end {
                return Err(CryptoError::DecodeAsn1Fail);
            }

            let data = crate::base64::decode(&base64_data)?;
            blocks.push(PemBlock { label, data });
        }
    }

    Ok(blocks)
}

/// Encode binary data as a PEM string with the given label.
pub fn encode(label: &str, data: &[u8]) -> String {
    let base64 = crate::base64::encode(data);
    let mut output = format!("{BEGIN_PREFIX}{label}{DASHES_SUFFIX}\n");

    // Wrap at 64 characters per line
    for chunk in base64.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(chunk).unwrap());
        output.push('\n');
    }

    output.push_str(&format!("{END_PREFIX}{label}{DASHES_SUFFIX}\n"));
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let data = b"Hello, PEM world!";
        let pem_str = encode("TEST DATA", data);
        let blocks = parse(&pem_str).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].label, "TEST DATA");
        assert_eq!(blocks[0].data, data);
    }

    #[test]
    fn test_multiple_blocks() {
        let pem = "\
-----BEGIN CERTIFICATE-----
AQID
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
BAUG
-----END PRIVATE KEY-----
";
        let blocks = parse(pem).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].label, "CERTIFICATE");
        assert_eq!(blocks[0].data, &[1, 2, 3]);
        assert_eq!(blocks[1].label, "PRIVATE KEY");
        assert_eq!(blocks[1].data, &[4, 5, 6]);
    }
}
