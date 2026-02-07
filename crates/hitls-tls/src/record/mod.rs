//! TLS record layer: parsing, serialization, fragmentation, and encryption.

pub mod encryption;

use crate::crypt::traffic_keys::TrafficKeys;
use crate::CipherSuite;
use encryption::{RecordDecryptor, RecordEncryptor, MAX_PLAINTEXT_LENGTH, TLS13_LEGACY_VERSION};
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
///
/// Supports both plaintext mode (initial handshake) and encrypted mode
/// (after traffic keys are activated). Encryption is per-direction:
/// write encryption and read decryption are activated independently.
pub struct RecordLayer {
    /// Maximum fragment size (default: 16384).
    pub max_fragment_size: usize,
    /// Optional encryptor for outgoing records.
    encryptor: Option<RecordEncryptor>,
    /// Optional decryptor for incoming records.
    decryptor: Option<RecordDecryptor>,
}

impl RecordLayer {
    pub fn new() -> Self {
        Self {
            max_fragment_size: MAX_PLAINTEXT_LENGTH,
            encryptor: None,
            decryptor: None,
        }
    }

    /// Returns true if write encryption is active.
    pub fn is_encrypting(&self) -> bool {
        self.encryptor.is_some()
    }

    /// Returns true if read decryption is active.
    pub fn is_decrypting(&self) -> bool {
        self.decryptor.is_some()
    }

    /// Activate write encryption with the given traffic keys.
    ///
    /// Called when the handshake transitions to encrypted mode
    /// (e.g., after deriving handshake or application traffic keys).
    /// Replaces any existing encryptor (resets sequence number to 0).
    pub fn activate_write_encryption(
        &mut self,
        suite: CipherSuite,
        keys: &TrafficKeys,
    ) -> Result<(), TlsError> {
        self.encryptor = Some(RecordEncryptor::new(suite, keys)?);
        Ok(())
    }

    /// Activate read decryption with the given traffic keys.
    ///
    /// Replaces any existing decryptor (resets sequence number to 0).
    pub fn activate_read_decryption(
        &mut self,
        suite: CipherSuite,
        keys: &TrafficKeys,
    ) -> Result<(), TlsError> {
        self.decryptor = Some(RecordDecryptor::new(suite, keys)?);
        Ok(())
    }

    /// Deactivate write encryption (return to plaintext mode).
    pub fn deactivate_write_encryption(&mut self) {
        self.encryptor = None;
    }

    /// Deactivate read decryption (return to plaintext mode).
    pub fn deactivate_read_decryption(&mut self) {
        self.decryptor = None;
    }

    /// Encrypt (if active) and serialize a record for sending.
    ///
    /// In plaintext mode, serializes the record directly.
    /// In encrypted mode, wraps in TLS 1.3 inner plaintext and AEAD-encrypts.
    pub fn seal_record(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        if plaintext.len() > self.max_fragment_size {
            return Err(TlsError::RecordError(
                "plaintext exceeds max fragment size".into(),
            ));
        }
        let record = match &mut self.encryptor {
            Some(enc) => enc.encrypt_record(content_type, plaintext)?,
            None => Record {
                content_type,
                version: TLS13_LEGACY_VERSION,
                fragment: plaintext.to_vec(),
            },
        };
        Ok(self.serialize_record(&record))
    }

    /// Parse and optionally decrypt an incoming record.
    ///
    /// Returns (content_type, plaintext, bytes_consumed).
    /// In plaintext mode, returns the record as-is.
    /// In encrypted mode, decrypts ApplicationData records and returns
    /// the actual inner content type and plaintext.
    pub fn open_record(&mut self, data: &[u8]) -> Result<(ContentType, Vec<u8>, usize), TlsError> {
        let (record, consumed) = self.parse_record(data)?;
        match &mut self.decryptor {
            Some(dec) if record.content_type == ContentType::ApplicationData => {
                let (ct, pt) = dec.decrypt_record(&record)?;
                Ok((ct, pt, consumed))
            }
            _ => Ok((record.content_type, record.fragment, consumed)),
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
