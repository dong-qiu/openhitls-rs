//! ASN.1 DER/BER encoding and decoding.

mod decoder;
mod encoder;
mod tag;

pub use decoder::Decoder;
pub use encoder::Encoder;

/// ASN.1 tag constants.
pub mod tags {
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OID: u8 = 0x06;
    pub const UTF8_STRING: u8 = 0x0C;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;
    pub const PRINTABLE_STRING: u8 = 0x13;
    pub const IA5_STRING: u8 = 0x16;
    pub const UTC_TIME: u8 = 0x17;
    pub const GENERALIZED_TIME: u8 = 0x18;
    pub const CONTEXT_SPECIFIC: u8 = 0x80;
    pub const CONSTRUCTED: u8 = 0x20;
}

/// Represents a parsed ASN.1 tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    pub class: TagClass,
    pub constructed: bool,
    pub number: u32,
}

/// ASN.1 tag class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagClass {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

/// A borrowed ASN.1 TLV element.
#[derive(Debug, Clone)]
pub struct Tlv<'a> {
    pub tag: Tag,
    pub value: &'a [u8],
}
