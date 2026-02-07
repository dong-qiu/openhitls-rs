//! ASN.1 DER decoder.

use super::{Tag, Tlv};
use hitls_types::CryptoError;

/// A streaming ASN.1 DER decoder.
pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Create a new decoder over the given data.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Returns the remaining undecoded bytes.
    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    /// Returns true if all data has been consumed.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Parse the next TLV element.
    pub fn read_tlv(&mut self) -> Result<Tlv<'a>, CryptoError> {
        let (tag, tag_len) = Tag::from_bytes(&self.data[self.pos..])?;
        self.pos += tag_len;

        let (length, _len_len) = self.read_length()?;
        let end = self.pos + length;
        if end > self.data.len() {
            return Err(CryptoError::DecodeAsn1Fail);
        }

        let value = &self.data[self.pos..end];
        self.pos = end;

        Ok(Tlv { tag, value })
    }

    /// Parse a DER length.
    fn read_length(&mut self) -> Result<(usize, usize), CryptoError> {
        if self.pos >= self.data.len() {
            return Err(CryptoError::DecodeAsn1Fail);
        }

        let first = self.data[self.pos];
        self.pos += 1;

        if first < 0x80 {
            Ok((first as usize, 1))
        } else if first == 0x80 {
            // Indefinite length — not valid in DER
            Err(CryptoError::DecodeAsn1Fail)
        } else {
            let num_bytes = (first & 0x7F) as usize;
            if num_bytes > 4 || self.pos + num_bytes > self.data.len() {
                return Err(CryptoError::DecodeAsn1Fail);
            }
            let mut length: usize = 0;
            for i in 0..num_bytes {
                length = (length << 8) | self.data[self.pos + i] as usize;
            }
            self.pos += num_bytes;
            Ok((length, 1 + num_bytes))
        }
    }

    /// Read an INTEGER and return its bytes (big-endian, may include leading zero).
    pub fn read_integer(&mut self) -> Result<&'a [u8], CryptoError> {
        let tlv = self.read_tlv()?;
        if tlv.tag.number != 0x02 {
            return Err(CryptoError::DecodeAsn1Fail);
        }
        Ok(tlv.value)
    }

    /// Read an OCTET STRING.
    pub fn read_octet_string(&mut self) -> Result<&'a [u8], CryptoError> {
        let tlv = self.read_tlv()?;
        if tlv.tag.number != 0x04 {
            return Err(CryptoError::DecodeAsn1Fail);
        }
        Ok(tlv.value)
    }

    /// Read a BIT STRING and return (unused_bits, data).
    pub fn read_bit_string(&mut self) -> Result<(u8, &'a [u8]), CryptoError> {
        let tlv = self.read_tlv()?;
        if tlv.tag.number != 0x03 || tlv.value.is_empty() {
            return Err(CryptoError::DecodeAsn1Fail);
        }
        Ok((tlv.value[0], &tlv.value[1..]))
    }

    /// Read an OID and return the raw bytes.
    pub fn read_oid(&mut self) -> Result<&'a [u8], CryptoError> {
        let tlv = self.read_tlv()?;
        if tlv.tag.number != 0x06 {
            return Err(CryptoError::DecodeAsn1Fail);
        }
        Ok(tlv.value)
    }

    /// Read a SEQUENCE, returning a sub-decoder over its contents.
    pub fn read_sequence(&mut self) -> Result<Decoder<'a>, CryptoError> {
        let tlv = self.read_tlv()?;
        if tlv.tag.number != 0x10 || !tlv.tag.constructed {
            return Err(CryptoError::DecodeAsn1Fail);
        }
        Ok(Decoder::new(tlv.value))
    }

    /// Read a SET, returning a sub-decoder over its contents.
    pub fn read_set(&mut self) -> Result<Decoder<'a>, CryptoError> {
        let tlv = self.read_tlv()?;
        if tlv.tag.number != 0x11 || !tlv.tag.constructed {
            return Err(CryptoError::DecodeAsn1Fail);
        }
        Ok(Decoder::new(tlv.value))
    }

    /// Peek at the next tag without consuming it.
    pub fn peek_tag(&self) -> Result<Tag, CryptoError> {
        if self.pos >= self.data.len() {
            return Err(CryptoError::DecodeAsn1Fail);
        }
        let (tag, _) = Tag::from_bytes(&self.data[self.pos..])?;
        Ok(tag)
    }

    /// Read a BOOLEAN value (DER: 0x00=false, 0xFF=true).
    pub fn read_boolean(&mut self) -> Result<bool, CryptoError> {
        let tlv = self.read_tlv()?;
        if tlv.tag.number != 0x01 || tlv.value.len() != 1 {
            return Err(CryptoError::DecodeAsn1Fail);
        }
        Ok(tlv.value[0] != 0x00)
    }

    /// Read a context-specific tagged value with the expected tag number.
    pub fn read_context_specific(
        &mut self,
        tag_num: u32,
        constructed: bool,
    ) -> Result<Tlv<'a>, CryptoError> {
        let tlv = self.read_tlv()?;
        if tlv.tag.class != super::TagClass::ContextSpecific
            || tlv.tag.number != tag_num
            || tlv.tag.constructed != constructed
        {
            return Err(CryptoError::DecodeAsn1Fail);
        }
        Ok(tlv)
    }

    /// Try to read a context-specific tagged value. Returns `None` if
    /// the next tag does not match, without consuming any bytes.
    pub fn try_read_context_specific(
        &mut self,
        tag_num: u32,
        constructed: bool,
    ) -> Result<Option<Tlv<'a>>, CryptoError> {
        if self.is_empty() {
            return Ok(None);
        }
        let tag = self.peek_tag()?;
        if tag.class == super::TagClass::ContextSpecific
            && tag.number == tag_num
            && tag.constructed == constructed
        {
            Ok(Some(self.read_tlv()?))
        } else {
            Ok(None)
        }
    }

    /// Read a string value (UTF8String, PrintableString, IA5String,
    /// T61String, or BMPString) and return it as a Rust `String`.
    pub fn read_string(&mut self) -> Result<String, CryptoError> {
        let tlv = self.read_tlv()?;
        match tlv.tag.number {
            // UTF8String (0x0C), PrintableString (0x13), IA5String (0x16)
            0x0C | 0x13 | 0x16 => {
                String::from_utf8(tlv.value.to_vec()).map_err(|_| CryptoError::DecodeAsn1Fail)
            }
            // T61String / TeletexString (0x14) — treat as Latin-1
            0x14 => Ok(tlv.value.iter().map(|&b| b as char).collect()),
            // BMPString (0x1E) — UTF-16BE
            0x1E => {
                if tlv.value.len() % 2 != 0 {
                    return Err(CryptoError::DecodeAsn1Fail);
                }
                let u16s: Vec<u16> = tlv
                    .value
                    .chunks(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16(&u16s).map_err(|_| CryptoError::DecodeAsn1Fail)
            }
            _ => Err(CryptoError::DecodeAsn1Fail),
        }
    }

    /// Read a Time value (UTCTime or GeneralizedTime) as a UNIX timestamp.
    pub fn read_time(&mut self) -> Result<i64, CryptoError> {
        let tlv = self.read_tlv()?;
        let s = core::str::from_utf8(tlv.value).map_err(|_| CryptoError::DecodeAsn1Fail)?;
        match tlv.tag.number {
            // UTCTime: YYMMDDHHMMSSZ
            0x17 => parse_utc_time(s),
            // GeneralizedTime: YYYYMMDDHHMMSSZ
            0x18 => parse_generalized_time(s),
            _ => Err(CryptoError::DecodeAsn1Fail),
        }
    }
}

/// Parse UTCTime string "YYMMDDHHMMSSZ" to UNIX timestamp.
/// RFC 5280: 00-49 → 2000-2049, 50-99 → 1950-1999.
fn parse_utc_time(s: &str) -> Result<i64, CryptoError> {
    let s = s.strip_suffix('Z').unwrap_or(s);
    if s.len() < 12 {
        return Err(CryptoError::DecodeAsn1Fail);
    }
    let yy: u32 = s[0..2].parse().map_err(|_| CryptoError::DecodeAsn1Fail)?;
    let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
    let month: u32 = s[2..4].parse().map_err(|_| CryptoError::DecodeAsn1Fail)?;
    let day: u32 = s[4..6].parse().map_err(|_| CryptoError::DecodeAsn1Fail)?;
    let hour: u32 = s[6..8].parse().map_err(|_| CryptoError::DecodeAsn1Fail)?;
    let min: u32 = s[8..10].parse().map_err(|_| CryptoError::DecodeAsn1Fail)?;
    let sec: u32 = s[10..12].parse().map_err(|_| CryptoError::DecodeAsn1Fail)?;
    datetime_to_unix(year, month, day, hour, min, sec)
}

/// Parse GeneralizedTime string "YYYYMMDDHHMMSSZ" to UNIX timestamp.
fn parse_generalized_time(s: &str) -> Result<i64, CryptoError> {
    let s = s.strip_suffix('Z').unwrap_or(s);
    if s.len() < 14 {
        return Err(CryptoError::DecodeAsn1Fail);
    }
    let year: u32 = s[0..4].parse().map_err(|_| CryptoError::DecodeAsn1Fail)?;
    let month: u32 = s[4..6].parse().map_err(|_| CryptoError::DecodeAsn1Fail)?;
    let day: u32 = s[6..8].parse().map_err(|_| CryptoError::DecodeAsn1Fail)?;
    let hour: u32 = s[8..10].parse().map_err(|_| CryptoError::DecodeAsn1Fail)?;
    let min: u32 = s[10..12].parse().map_err(|_| CryptoError::DecodeAsn1Fail)?;
    let sec: u32 = s[12..14].parse().map_err(|_| CryptoError::DecodeAsn1Fail)?;
    datetime_to_unix(year, month, day, hour, min, sec)
}

/// Convert a date-time to a UNIX timestamp (seconds since 1970-01-01 00:00:00 UTC).
fn datetime_to_unix(
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
) -> Result<i64, CryptoError> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 59 {
        return Err(CryptoError::DecodeAsn1Fail);
    }
    // Days from year 0 to the start of the given year (Gregorian)
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 9 } else { month - 3 };
    let days = 365 * y as i64 + y as i64 / 4 - y as i64 / 100
        + y as i64 / 400
        + (m as i64 * 306 + 5) / 10
        + (day as i64 - 1)
        - 719468; // offset so epoch = 1970-01-01
    Ok(days * 86400 + hour as i64 * 3600 + min as i64 * 60 + sec as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_set() {
        // SET { INTEGER 42 }
        let data = [0x31, 0x03, 0x02, 0x01, 0x2A];
        let mut dec = Decoder::new(&data);
        let mut set_dec = dec.read_set().unwrap();
        let val = set_dec.read_integer().unwrap();
        assert_eq!(val, &[0x2A]);
        assert!(set_dec.is_empty());
    }

    #[test]
    fn test_read_boolean() {
        // BOOLEAN TRUE
        let data_true = [0x01, 0x01, 0xFF];
        let mut dec = Decoder::new(&data_true);
        assert!(dec.read_boolean().unwrap());

        // BOOLEAN FALSE
        let data_false = [0x01, 0x01, 0x00];
        let mut dec = Decoder::new(&data_false);
        assert!(!dec.read_boolean().unwrap());
    }

    #[test]
    fn test_peek_tag() {
        let data = [0x02, 0x01, 0x05]; // INTEGER 5
        let dec = Decoder::new(&data);
        let tag = dec.peek_tag().unwrap();
        assert_eq!(tag.number, 0x02);
        assert!(!dec.is_empty()); // peek should not consume
    }

    #[test]
    fn test_read_context_specific() {
        // [0] EXPLICIT { INTEGER 2 } — like X.509 version
        // A0 03 02 01 02
        let data = [0xA0, 0x03, 0x02, 0x01, 0x02];
        let mut dec = Decoder::new(&data);
        let tlv = dec.read_context_specific(0, true).unwrap();
        assert_eq!(tlv.value, &[0x02, 0x01, 0x02]);
    }

    #[test]
    fn test_try_read_context_specific() {
        // [0] EXPLICIT { INTEGER 2 } followed by INTEGER 1
        let data = [0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01];
        let mut dec = Decoder::new(&data);

        // Should match [0]
        let tlv = dec.try_read_context_specific(0, true).unwrap();
        assert!(tlv.is_some());

        // Next is INTEGER, try [1] should return None
        let tlv = dec.try_read_context_specific(1, true).unwrap();
        assert!(tlv.is_none());

        // Can still read the INTEGER
        let val = dec.read_integer().unwrap();
        assert_eq!(val, &[0x01]);
    }

    #[test]
    fn test_read_string_utf8() {
        // UTF8String "Hello"
        let data = [0x0C, 0x05, b'H', b'e', b'l', b'l', b'o'];
        let mut dec = Decoder::new(&data);
        assert_eq!(dec.read_string().unwrap(), "Hello");
    }

    #[test]
    fn test_read_string_printable() {
        // PrintableString "CN"
        let data = [0x13, 0x02, b'C', b'N'];
        let mut dec = Decoder::new(&data);
        assert_eq!(dec.read_string().unwrap(), "CN");
    }

    #[test]
    fn test_read_time_utc() {
        // UTCTime "260207131915Z" → 2026-02-07 13:19:15 UTC
        let time_str = b"260207131915Z";
        let mut data = vec![0x17, time_str.len() as u8];
        data.extend_from_slice(time_str);
        let mut dec = Decoder::new(&data);
        let ts = dec.read_time().unwrap();
        // Verify with known epoch + known date helper
        let expected = datetime_to_unix(2026, 2, 7, 13, 19, 15).unwrap();
        assert_eq!(ts, expected);
    }

    #[test]
    fn test_read_time_generalized() {
        // GeneralizedTime "21260114131915Z" → 2126-01-14 13:19:15 UTC
        let time_str = b"21260114131915Z";
        let mut data = vec![0x18, time_str.len() as u8];
        data.extend_from_slice(time_str);
        let mut dec = Decoder::new(&data);
        let ts = dec.read_time().unwrap();
        // Should be far in the future
        assert!(ts > 4900000000);
    }

    #[test]
    fn test_datetime_to_unix_epoch() {
        // 1970-01-01 00:00:00 UTC = 0
        assert_eq!(datetime_to_unix(1970, 1, 1, 0, 0, 0).unwrap(), 0);
    }

    #[test]
    fn test_datetime_to_unix_known_date() {
        // 2000-01-01 00:00:00 UTC = 946684800
        assert_eq!(datetime_to_unix(2000, 1, 1, 0, 0, 0).unwrap(), 946684800);
    }
}
