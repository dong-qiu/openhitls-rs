//! ASN.1 DER encoder.

/// A builder for constructing DER-encoded ASN.1 data.
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    /// Create a new encoder.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Consume the encoder and return the encoded bytes.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    /// Write a raw TLV with the given tag byte and value.
    pub fn write_tlv(&mut self, tag: u8, value: &[u8]) -> &mut Self {
        self.buf.push(tag);
        self.write_length(value.len());
        self.buf.extend_from_slice(value);
        self
    }

    /// Write a DER length encoding.
    fn write_length(&mut self, length: usize) {
        if length < 0x80 {
            self.buf.push(length as u8);
        } else if length <= 0xFF {
            self.buf.push(0x81);
            self.buf.push(length as u8);
        } else if length <= 0xFFFF {
            self.buf.push(0x82);
            self.buf.push((length >> 8) as u8);
            self.buf.push(length as u8);
        } else if length <= 0xFF_FFFF {
            self.buf.push(0x83);
            self.buf.push((length >> 16) as u8);
            self.buf.push((length >> 8) as u8);
            self.buf.push(length as u8);
        } else {
            self.buf.push(0x84);
            self.buf.push((length >> 24) as u8);
            self.buf.push((length >> 16) as u8);
            self.buf.push((length >> 8) as u8);
            self.buf.push(length as u8);
        }
    }

    /// Write an INTEGER value.
    pub fn write_integer(&mut self, value: &[u8]) -> &mut Self {
        // Add leading zero if high bit is set (to keep it positive)
        if !value.is_empty() && (value[0] & 0x80) != 0 {
            let mut padded = vec![0x00];
            padded.extend_from_slice(value);
            self.write_tlv(0x02, &padded);
        } else {
            self.write_tlv(0x02, value);
        }
        self
    }

    /// Write an OCTET STRING.
    pub fn write_octet_string(&mut self, value: &[u8]) -> &mut Self {
        self.write_tlv(0x04, value)
    }

    /// Write a BIT STRING with the given unused_bits count.
    pub fn write_bit_string(&mut self, unused_bits: u8, value: &[u8]) -> &mut Self {
        let mut content = vec![unused_bits];
        content.extend_from_slice(value);
        self.write_tlv(0x03, &content)
    }

    /// Write an OID from raw encoded bytes.
    pub fn write_oid(&mut self, oid_bytes: &[u8]) -> &mut Self {
        self.write_tlv(0x06, oid_bytes)
    }

    /// Write a NULL.
    pub fn write_null(&mut self) -> &mut Self {
        self.buf.push(0x05);
        self.buf.push(0x00);
        self
    }

    /// Write a SEQUENCE wrapping the given contents.
    pub fn write_sequence(&mut self, contents: &[u8]) -> &mut Self {
        self.write_tlv(0x30, contents)
    }

    /// Write a SET wrapping the given contents.
    pub fn write_set(&mut self, contents: &[u8]) -> &mut Self {
        self.write_tlv(0x31, contents)
    }

    /// Write raw bytes directly (already DER-encoded).
    pub fn write_raw(&mut self, data: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(data);
        self
    }

    /// Write a UTF8String (tag 0x0C).
    pub fn write_utf8_string(&mut self, s: &str) -> &mut Self {
        self.write_tlv(0x0C, s.as_bytes())
    }

    /// Write a PrintableString (tag 0x13).
    pub fn write_printable_string(&mut self, s: &str) -> &mut Self {
        self.write_tlv(0x13, s.as_bytes())
    }

    /// Write an IA5String (tag 0x16).
    pub fn write_ia5_string(&mut self, s: &str) -> &mut Self {
        self.write_tlv(0x16, s.as_bytes())
    }

    /// Write a BOOLEAN (tag 0x01).
    pub fn write_boolean(&mut self, val: bool) -> &mut Self {
        self.write_tlv(0x01, &[if val { 0xFF } else { 0x00 }])
    }

    /// Write an ENUMERATED (tag 0x0A).
    pub fn write_enumerated(&mut self, val: u8) -> &mut Self {
        self.write_tlv(0x0A, &[val])
    }

    /// Write a context-specific tagged value.
    pub fn write_context_specific(
        &mut self,
        tag_num: u8,
        constructed: bool,
        content: &[u8],
    ) -> &mut Self {
        let tag = 0x80 | (if constructed { 0x20 } else { 0 }) | (tag_num & 0x1F);
        self.write_tlv(tag, content)
    }

    /// Write a UTCTime (tag 0x17) from a UNIX timestamp.
    /// Format: YYMMDDHHmmSSZ (dates before 2050 use 2-digit year).
    pub fn write_utc_time(&mut self, timestamp: i64) -> &mut Self {
        let s = unix_to_utc_time(timestamp);
        self.write_tlv(0x17, s.as_bytes())
    }

    /// Write a GeneralizedTime (tag 0x18) from a UNIX timestamp.
    /// Format: YYYYMMDDHHmmSSZ.
    pub fn write_generalized_time(&mut self, timestamp: i64) -> &mut Self {
        let s = unix_to_generalized_time(timestamp);
        self.write_tlv(0x18, s.as_bytes())
    }

    /// Write a Time (UTCTime for years < 2050, GeneralizedTime otherwise).
    pub fn write_time(&mut self, timestamp: i64) -> &mut Self {
        // Per RFC 5280 §4.1.2.5: UTCTime for 1950-2049, GeneralizedTime otherwise
        let (year, _, _, _, _, _) = unix_to_datetime(timestamp);
        if year >= 2050 {
            self.write_generalized_time(timestamp)
        } else {
            self.write_utc_time(timestamp)
        }
    }
}

/// Convert a UNIX timestamp to date-time components.
fn unix_to_datetime(timestamp: i64) -> (i32, u32, u32, u32, u32, u32) {
    // Days from Unix epoch
    let mut days = (timestamp / 86400) as i32;
    let day_secs = (timestamp % 86400) as u32;
    let hour = day_secs / 3600;
    let minute = (day_secs % 3600) / 60;
    let second = day_secs % 60;

    // Civil date from days since epoch (algorithm from Howard Hinnant)
    days += 719468;
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = (days - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i32 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    (year, m, d, hour, minute, second)
}

/// Format a UNIX timestamp as UTCTime string "YYMMDDHHmmSSZ".
fn unix_to_utc_time(timestamp: i64) -> String {
    let (year, month, day, hour, minute, second) = unix_to_datetime(timestamp);
    let yy = (year % 100) as u32;
    format!("{yy:02}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z")
}

/// Format a UNIX timestamp as GeneralizedTime string "YYYYMMDDHHmmSSZ".
fn unix_to_generalized_time(timestamp: i64) -> String {
    let (year, month, day, hour, minute, second) = unix_to_datetime(timestamp);
    format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z")
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::Decoder;

    #[test]
    fn test_write_utf8_string() {
        let mut enc = Encoder::new();
        enc.write_utf8_string("Hello");
        let der = enc.finish();
        assert_eq!(der, &[0x0C, 5, b'H', b'e', b'l', b'l', b'o']);
    }

    #[test]
    fn test_write_printable_string() {
        let mut enc = Encoder::new();
        enc.write_printable_string("CN");
        let der = enc.finish();
        assert_eq!(der, &[0x13, 2, b'C', b'N']);
    }

    #[test]
    fn test_write_utc_time() {
        // 2025-01-15 12:00:00 UTC = 1736942400
        let mut enc = Encoder::new();
        enc.write_utc_time(1_736_942_400);
        let der = enc.finish();
        // Should encode "250115120000Z"
        let expected = b"250115120000Z";
        assert_eq!(der[0], 0x17); // UTCTime tag
        assert_eq!(der[1], expected.len() as u8);
        assert_eq!(&der[2..], expected);
    }

    #[test]
    fn test_write_generalized_time() {
        // 2050-06-20 00:00:00 UTC = 2539296000
        let mut enc = Encoder::new();
        enc.write_generalized_time(2_539_296_000);
        let der = enc.finish();
        let expected = b"20500620000000Z";
        assert_eq!(der[0], 0x18); // GeneralizedTime tag
        assert_eq!(der[1], expected.len() as u8);
        assert_eq!(&der[2..], expected);
    }

    #[test]
    fn test_write_context_specific() {
        let mut enc = Encoder::new();
        // Explicit [0] wrapping an INTEGER 2 (version v3)
        let mut inner = Encoder::new();
        inner.write_integer(&[0x02]);
        let inner_der = inner.finish();
        enc.write_context_specific(0, true, &inner_der);
        let der = enc.finish();
        assert_eq!(der, &[0xA0, 3, 0x02, 1, 0x02]);
    }

    #[test]
    fn test_write_boolean() {
        let mut enc = Encoder::new();
        enc.write_boolean(true);
        enc.write_boolean(false);
        let der = enc.finish();
        assert_eq!(der, &[0x01, 1, 0xFF, 0x01, 1, 0x00]);
    }

    #[test]
    fn test_write_time_roundtrip() {
        // Verify that a written UTCTime can be parsed back by the decoder
        let ts = 1_736_942_400i64; // 2025-01-15 12:00:00 UTC
        let mut enc = Encoder::new();
        enc.write_utc_time(ts);
        let der = enc.finish();
        let mut dec = Decoder::new(&der);
        let parsed_ts = dec.read_time().unwrap();
        assert_eq!(parsed_ts, ts);
    }

    #[test]
    fn test_unix_to_datetime() {
        // 1970-01-01 00:00:00
        assert_eq!(unix_to_datetime(0), (1970, 1, 1, 0, 0, 0));
        // 2025-11-15 00:00:00 = 1763164800
        assert_eq!(unix_to_datetime(1_763_164_800), (2025, 11, 15, 0, 0, 0));
    }
}
