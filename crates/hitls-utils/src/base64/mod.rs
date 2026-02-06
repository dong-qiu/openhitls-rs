//! Base64 encoding and decoding.

use hitls_types::CryptoError;

const ENCODE_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes to a Base64 string.
pub fn encode(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);

    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        output.push(ENCODE_TABLE[((triple >> 18) & 0x3F) as usize] as char);
        output.push(ENCODE_TABLE[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            output.push(ENCODE_TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            output.push('=');
        }

        if chunk.len() > 2 {
            output.push(ENCODE_TABLE[(triple & 0x3F) as usize] as char);
        } else {
            output.push('=');
        }
    }

    output
}

/// Decode a Base64 string to bytes.
pub fn decode(input: &str) -> Result<Vec<u8>, CryptoError> {
    let input = input.as_bytes();
    // Strip whitespace
    let filtered: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();

    if filtered.is_empty() {
        return Ok(Vec::new());
    }

    if filtered.len() % 4 != 0 {
        return Err(CryptoError::InvalidArg);
    }

    let mut output = Vec::with_capacity((filtered.len() / 4) * 3);

    for chunk in filtered.chunks(4) {
        let a = decode_char(chunk[0])?;
        let b = decode_char(chunk[1])?;

        let triple = if chunk[2] == b'=' {
            let val = (a << 18) | (b << 12);
            output.push((val >> 16) as u8);
            continue;
        } else {
            let c = decode_char(chunk[2])?;
            if chunk[3] == b'=' {
                let val = (a << 18) | (b << 12) | (c << 6);
                output.push((val >> 16) as u8);
                output.push((val >> 8) as u8);
                continue;
            } else {
                let d = decode_char(chunk[3])?;
                (a << 18) | (b << 12) | (c << 6) | d
            }
        };

        output.push((triple >> 16) as u8);
        output.push((triple >> 8) as u8);
        output.push(triple as u8);
    }

    Ok(output)
}

fn decode_char(c: u8) -> Result<u32, CryptoError> {
    match c {
        b'A'..=b'Z' => Ok((c - b'A') as u32),
        b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
        b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(CryptoError::InvalidArg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_empty() {
        assert_eq!(encode(b""), "");
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let cases = [
            b"hello" as &[u8],
            b"",
            b"a",
            b"ab",
            b"abc",
            b"Hello, World!",
        ];
        for input in &cases {
            let encoded = encode(input);
            let decoded = decode(&encoded).unwrap();
            assert_eq!(&decoded, input);
        }
    }

    #[test]
    fn test_rfc4648_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }
}
