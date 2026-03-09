//! ASN.1 DER/BER encoding and decoding.

mod decoder;
mod encoder;
mod tag;

pub use decoder::Decoder;
pub use encoder::Encoder;

/// ASN.1 tag constants.
pub mod tags {
    /// ASN.1 BOOLEAN tag (0x01).
    pub const BOOLEAN: u8 = 0x01;
    /// ASN.1 INTEGER tag (0x02).
    pub const INTEGER: u8 = 0x02;
    /// ASN.1 BIT STRING tag (0x03).
    pub const BIT_STRING: u8 = 0x03;
    /// ASN.1 OCTET STRING tag (0x04).
    pub const OCTET_STRING: u8 = 0x04;
    /// ASN.1 NULL tag (0x05).
    pub const NULL: u8 = 0x05;
    /// ASN.1 OBJECT IDENTIFIER tag (0x06).
    pub const OID: u8 = 0x06;
    /// ASN.1 UTF8String tag (0x0C).
    pub const UTF8_STRING: u8 = 0x0C;
    /// ASN.1 SEQUENCE tag (0x30).
    pub const SEQUENCE: u8 = 0x30;
    /// ASN.1 SET tag (0x31).
    pub const SET: u8 = 0x31;
    /// ASN.1 PrintableString tag (0x13).
    pub const PRINTABLE_STRING: u8 = 0x13;
    /// ASN.1 IA5String tag (0x16).
    pub const IA5_STRING: u8 = 0x16;
    /// ASN.1 UTCTime tag (0x17).
    pub const UTC_TIME: u8 = 0x17;
    /// ASN.1 GeneralizedTime tag (0x18).
    pub const GENERALIZED_TIME: u8 = 0x18;
    /// Context-specific tag class bit (0x80).
    pub const CONTEXT_SPECIFIC: u8 = 0x80;
    /// Constructed encoding bit (0x20).
    pub const CONSTRUCTED: u8 = 0x20;
}

/// Represents a parsed ASN.1 tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    /// The tag class.
    pub class: TagClass,
    /// Whether this is a constructed encoding.
    pub constructed: bool,
    /// The tag number.
    pub number: u32,
}

/// ASN.1 tag class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagClass {
    /// Universal tag class.
    Universal,
    /// Application tag class.
    Application,
    /// Context-specific tag class.
    ContextSpecific,
    /// Private tag class.
    Private,
}

/// A borrowed ASN.1 TLV element.
#[derive(Debug, Clone)]
pub struct Tlv<'a> {
    /// The tag of this TLV element.
    pub tag: Tag,
    /// The value bytes of this TLV element.
    pub value: &'a [u8],
}
