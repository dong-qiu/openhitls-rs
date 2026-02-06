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
}
