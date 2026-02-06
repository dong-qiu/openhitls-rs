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
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}
