//! ASN.1 tag parsing and encoding.

use super::{Tag, TagClass};
use hitls_types::CryptoError;

impl Tag {
    /// Parse a tag from the first bytes of `input`.
    /// Returns the tag and number of bytes consumed.
    pub fn from_bytes(input: &[u8]) -> Result<(Self, usize), CryptoError> {
        if input.is_empty() {
            return Err(CryptoError::NullInput);
        }

        let first = input[0];
        let class = match (first >> 6) & 0x03 {
            0 => TagClass::Universal,
            1 => TagClass::Application,
            2 => TagClass::ContextSpecific,
            3 => TagClass::Private,
            _ => unreachable!(),
        };
        let constructed = (first & 0x20) != 0;

        let low_bits = first & 0x1F;
        if low_bits < 0x1F {
            // Short form tag number
            Ok((
                Tag {
                    class,
                    constructed,
                    number: low_bits as u32,
                },
                1,
            ))
        } else {
            // Long form tag number
            let mut number: u32 = 0;
            let mut i = 1;
            loop {
                if i >= input.len() {
                    return Err(CryptoError::DecodeAsn1Fail);
                }
                let byte = input[i];
                number = number.checked_shl(7).ok_or(CryptoError::DecodeAsn1Fail)?
                    | (byte & 0x7F) as u32;
                i += 1;
                if (byte & 0x80) == 0 {
                    break;
                }
            }
            Ok((
                Tag {
                    class,
                    constructed,
                    number,
                },
                i,
            ))
        }
    }

    /// Encode this tag to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let class_bits = match self.class {
            TagClass::Universal => 0x00,
            TagClass::Application => 0x40,
            TagClass::ContextSpecific => 0x80,
            TagClass::Private => 0xC0,
        };
        let constructed_bit = if self.constructed { 0x20 } else { 0x00 };

        if self.number < 0x1F {
            vec![class_bits | constructed_bit | (self.number as u8)]
        } else {
            let mut result = vec![class_bits | constructed_bit | 0x1F];
            let mut num = self.number;
            let mut bytes = Vec::new();
            while num > 0 {
                bytes.push((num & 0x7F) as u8);
                num >>= 7;
            }
            bytes.reverse();
            for (i, b) in bytes.iter().enumerate() {
                if i < bytes.len() - 1 {
                    result.push(b | 0x80);
                } else {
                    result.push(*b);
                }
            }
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_tag() {
        let (tag, len) = Tag::from_bytes(&[0x30]).unwrap();
        assert_eq!(tag.class, TagClass::Universal);
        assert!(tag.constructed);
        assert_eq!(tag.number, 0x10);
        assert_eq!(len, 1);
    }

    #[test]
    fn test_parse_integer_tag() {
        let (tag, len) = Tag::from_bytes(&[0x02]).unwrap();
        assert_eq!(tag.class, TagClass::Universal);
        assert!(!tag.constructed);
        assert_eq!(tag.number, 0x02);
        assert_eq!(len, 1);
    }

    #[test]
    fn test_roundtrip() {
        let tag = Tag {
            class: TagClass::ContextSpecific,
            constructed: true,
            number: 3,
        };
        let bytes = tag.to_bytes();
        let (parsed, _) = Tag::from_bytes(&bytes).unwrap();
        assert_eq!(tag, parsed);
    }
}
