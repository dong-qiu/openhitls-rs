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
                    number: u32::from(low_bits),
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
                    | u32::from(byte & 0x7F);
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

// Kani formal verification proofs
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Proof: short-form tag roundtrip (encode then decode recovers original).
    #[kani::proof]
    #[kani::unwind(5)]
    fn kani_proof_tag_short_roundtrip() {
        let class_val: u8 = kani::any();
        kani::assume(class_val < 4);
        let constructed: bool = kani::any();
        let number: u32 = kani::any();
        kani::assume(number < 0x1F); // short form

        let class = match class_val {
            0 => TagClass::Universal,
            1 => TagClass::Application,
            2 => TagClass::ContextSpecific,
            _ => TagClass::Private,
        };

        let tag = Tag { class, constructed, number };
        let encoded = tag.to_bytes();
        let (decoded, len) = Tag::from_bytes(&encoded).unwrap();
        assert!(len == encoded.len());
        assert!(decoded.number == tag.number);
        assert!(decoded.constructed == tag.constructed);
    }

    /// Proof: Tag::from_bytes never panics on arbitrary 1-byte input.
    #[kani::proof]
    fn kani_proof_tag_parse_no_panic() {
        let byte: u8 = kani::any();
        let input = [byte];
        // Should return Ok or Err, never panic
        let _ = Tag::from_bytes(&input);
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

    #[test]
    fn test_tag_all_four_classes_roundtrip() {
        let classes = [
            TagClass::Universal,
            TagClass::Application,
            TagClass::ContextSpecific,
            TagClass::Private,
        ];
        for &class in &classes {
            for constructed in [false, true] {
                let tag = Tag {
                    class,
                    constructed,
                    number: 5,
                };
                let bytes = tag.to_bytes();
                let (parsed, len) = Tag::from_bytes(&bytes).unwrap();
                assert_eq!(len, 1);
                assert_eq!(tag, parsed);
            }
        }
    }

    #[test]
    fn test_tag_long_form_number_roundtrip() {
        // Tag number 200 (> 30) requires long-form encoding
        let tag = Tag {
            class: TagClass::Universal,
            constructed: false,
            number: 200,
        };
        let bytes = tag.to_bytes();
        assert!(bytes.len() > 1); // Must be multi-byte
        assert_eq!(bytes[0] & 0x1F, 0x1F); // Long-form indicator
        let (parsed, len) = Tag::from_bytes(&bytes).unwrap();
        assert_eq!(len, bytes.len());
        assert_eq!(tag, parsed);
    }

    #[test]
    fn test_tag_empty_input_error() {
        let result = Tag::from_bytes(&[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::NullInput));
    }

    #[test]
    fn test_tag_long_form_truncated_error() {
        // 0x1F = long form, 0x81 = continuation bit set but no following byte
        let result = Tag::from_bytes(&[0x1F, 0x81]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::DecodeAsn1Fail));
    }

    #[test]
    fn test_tag_large_number_encoding() {
        // Tag number 0x4000 (16384) — needs 3 base-128 bytes
        let tag = Tag {
            class: TagClass::ContextSpecific,
            constructed: true,
            number: 0x4000,
        };
        let bytes = tag.to_bytes();
        assert_eq!(bytes[0] & 0x1F, 0x1F); // Long-form indicator
        assert!(bytes.len() >= 4); // 1 header + 3 number bytes
        let (parsed, len) = Tag::from_bytes(&bytes).unwrap();
        assert_eq!(len, bytes.len());
        assert_eq!(tag, parsed);
    }
}
