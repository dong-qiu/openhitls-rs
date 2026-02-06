//! TLS record layer: parsing, serialization, fragmentation, and encryption.

use hitls_types::TlsError;

/// TLS record content types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

/// A parsed TLS record.
#[derive(Debug, Clone)]
pub struct Record {
    pub content_type: ContentType,
    pub version: u16,
    pub fragment: Vec<u8>,
}

/// Record layer state for reading and writing TLS records.
pub struct RecordLayer {
    /// Maximum fragment size (default: 16384).
    pub max_fragment_size: usize,
}

impl RecordLayer {
    pub fn new() -> Self {
        Self {
            max_fragment_size: 16384,
        }
    }

    /// Parse a TLS record from the given bytes.
    pub fn parse_record(&self, data: &[u8]) -> Result<(Record, usize), TlsError> {
        if data.len() < 5 {
            return Err(TlsError::RecordError("incomplete record header".into()));
        }

        let content_type = match data[0] {
            20 => ContentType::ChangeCipherSpec,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            _ => return Err(TlsError::RecordError("unknown content type".into())),
        };

        let version = u16::from_be_bytes([data[1], data[2]]);
        let length = u16::from_be_bytes([data[3], data[4]]) as usize;

        if length > self.max_fragment_size + 256 {
            return Err(TlsError::RecordError("record too large".into()));
        }

        if data.len() < 5 + length {
            return Err(TlsError::RecordError("incomplete record body".into()));
        }

        let fragment = data[5..5 + length].to_vec();
        Ok((
            Record {
                content_type,
                version,
                fragment,
            },
            5 + length,
        ))
    }

    /// Serialize a TLS record to bytes.
    pub fn serialize_record(&self, record: &Record) -> Vec<u8> {
        let mut buf = Vec::with_capacity(5 + record.fragment.len());
        buf.push(record.content_type as u8);
        buf.extend_from_slice(&record.version.to_be_bytes());
        buf.extend_from_slice(&(record.fragment.len() as u16).to_be_bytes());
        buf.extend_from_slice(&record.fragment);
        buf
    }
}

impl Default for RecordLayer {
    fn default() -> Self {
        Self::new()
    }
}
