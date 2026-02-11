//! TLS record layer: parsing, serialization, fragmentation, and encryption.

#[cfg(feature = "dtls12")]
pub mod anti_replay;
#[cfg(feature = "dtls12")]
pub mod dtls;
pub mod encryption;
pub mod encryption12;
pub mod encryption12_cbc;
#[cfg(feature = "dtlcp")]
pub mod encryption_dtlcp;
#[cfg(feature = "dtls12")]
pub mod encryption_dtls12;
#[cfg(feature = "tlcp")]
pub mod encryption_tlcp;

use crate::crypt::traffic_keys::TrafficKeys;
use crate::CipherSuite;
use encryption::{RecordDecryptor, RecordEncryptor, MAX_PLAINTEXT_LENGTH, TLS13_LEGACY_VERSION};
use encryption12::{RecordDecryptor12, RecordEncryptor12};
use encryption12_cbc::{
    RecordDecryptor12Cbc, RecordDecryptor12EtM, RecordEncryptor12Cbc, RecordEncryptor12EtM,
};
#[cfg(feature = "tlcp")]
use encryption_tlcp::{TlcpDecryptor, TlcpEncryptor};
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
    /// Optional TLS 1.3 encryptor for outgoing records.
    encryptor: Option<RecordEncryptor>,
    /// Optional TLS 1.3 decryptor for incoming records.
    decryptor: Option<RecordDecryptor>,
    /// Optional TLS 1.2 AEAD encryptor for outgoing records.
    encryptor12: Option<RecordEncryptor12>,
    /// Optional TLS 1.2 AEAD decryptor for incoming records.
    decryptor12: Option<RecordDecryptor12>,
    /// Optional TLS 1.2 CBC encryptor for outgoing records.
    encryptor12_cbc: Option<RecordEncryptor12Cbc>,
    /// Optional TLS 1.2 CBC decryptor for incoming records.
    decryptor12_cbc: Option<RecordDecryptor12Cbc>,
    /// Optional TLS 1.2 Encrypt-Then-MAC encryptor (RFC 7366).
    encryptor12_etm: Option<RecordEncryptor12EtM>,
    /// Optional TLS 1.2 Encrypt-Then-MAC decryptor (RFC 7366).
    decryptor12_etm: Option<RecordDecryptor12EtM>,
    /// Optional TLCP encryptor for outgoing records.
    #[cfg(feature = "tlcp")]
    encryptor_tlcp: Option<TlcpEncryptor>,
    /// Optional TLCP decryptor for incoming records.
    #[cfg(feature = "tlcp")]
    decryptor_tlcp: Option<TlcpDecryptor>,
}

impl RecordLayer {
    pub fn new() -> Self {
        Self {
            max_fragment_size: MAX_PLAINTEXT_LENGTH,
            encryptor: None,
            decryptor: None,
            encryptor12: None,
            decryptor12: None,
            encryptor12_cbc: None,
            decryptor12_cbc: None,
            encryptor12_etm: None,
            decryptor12_etm: None,
            #[cfg(feature = "tlcp")]
            encryptor_tlcp: None,
            #[cfg(feature = "tlcp")]
            decryptor_tlcp: None,
        }
    }

    /// Returns true if write encryption is active (TLS 1.2, 1.3, or TLCP).
    pub fn is_encrypting(&self) -> bool {
        if self.encryptor.is_some()
            || self.encryptor12.is_some()
            || self.encryptor12_cbc.is_some()
            || self.encryptor12_etm.is_some()
        {
            return true;
        }
        #[cfg(feature = "tlcp")]
        if self.encryptor_tlcp.is_some() {
            return true;
        }
        false
    }

    /// Returns true if read decryption is active (TLS 1.2, 1.3, or TLCP).
    pub fn is_decrypting(&self) -> bool {
        if self.decryptor.is_some()
            || self.decryptor12.is_some()
            || self.decryptor12_cbc.is_some()
            || self.decryptor12_etm.is_some()
        {
            return true;
        }
        #[cfg(feature = "tlcp")]
        if self.decryptor_tlcp.is_some() {
            return true;
        }
        false
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

    /// Activate TLS 1.2 write encryption with the given key and fixed IV.
    pub fn activate_write_encryption12(
        &mut self,
        suite: CipherSuite,
        key: &[u8],
        fixed_iv: Vec<u8>,
    ) -> Result<(), TlsError> {
        self.encryptor = None; // Clear any TLS 1.3 encryptor
        self.encryptor12 = Some(RecordEncryptor12::new(
            encryption12::tls12_suite_to_aead_suite(suite)?,
            key,
            fixed_iv,
        )?);
        Ok(())
    }

    /// Activate TLS 1.2 read decryption with the given key and fixed IV.
    pub fn activate_read_decryption12(
        &mut self,
        suite: CipherSuite,
        key: &[u8],
        fixed_iv: Vec<u8>,
    ) -> Result<(), TlsError> {
        self.decryptor = None; // Clear any TLS 1.3 decryptor
        self.decryptor12 = Some(RecordDecryptor12::new(
            encryption12::tls12_suite_to_aead_suite(suite)?,
            key,
            fixed_iv,
        )?);
        Ok(())
    }

    /// Activate TLS 1.2 CBC write encryption.
    pub fn activate_write_encryption12_cbc(
        &mut self,
        enc_key: Vec<u8>,
        mac_key: Vec<u8>,
        mac_len: usize,
    ) {
        self.encryptor = None;
        self.encryptor12 = None;
        self.encryptor12_cbc = Some(RecordEncryptor12Cbc::new(enc_key, mac_key, mac_len));
    }

    /// Activate TLS 1.2 CBC read decryption.
    pub fn activate_read_decryption12_cbc(
        &mut self,
        enc_key: Vec<u8>,
        mac_key: Vec<u8>,
        mac_len: usize,
    ) {
        self.decryptor = None;
        self.decryptor12 = None;
        self.decryptor12_cbc = Some(RecordDecryptor12Cbc::new(enc_key, mac_key, mac_len));
    }

    /// Activate TLS 1.2 Encrypt-Then-MAC write encryption (RFC 7366).
    pub fn activate_write_encryption12_etm(
        &mut self,
        enc_key: Vec<u8>,
        mac_key: Vec<u8>,
        mac_len: usize,
    ) {
        self.encryptor = None;
        self.encryptor12 = None;
        self.encryptor12_cbc = None;
        self.encryptor12_etm = Some(RecordEncryptor12EtM::new(enc_key, mac_key, mac_len));
    }

    /// Activate TLS 1.2 Encrypt-Then-MAC read decryption (RFC 7366).
    pub fn activate_read_decryption12_etm(
        &mut self,
        enc_key: Vec<u8>,
        mac_key: Vec<u8>,
        mac_len: usize,
    ) {
        self.decryptor = None;
        self.decryptor12 = None;
        self.decryptor12_cbc = None;
        self.decryptor12_etm = Some(RecordDecryptor12EtM::new(enc_key, mac_key, mac_len));
    }

    /// Activate TLCP write encryption.
    #[cfg(feature = "tlcp")]
    pub fn activate_write_encryption_tlcp(&mut self, enc: TlcpEncryptor) {
        self.encryptor = None;
        self.encryptor12 = None;
        self.encryptor12_cbc = None;
        self.encryptor_tlcp = Some(enc);
    }

    /// Activate TLCP read decryption.
    #[cfg(feature = "tlcp")]
    pub fn activate_read_decryption_tlcp(&mut self, dec: TlcpDecryptor) {
        self.decryptor = None;
        self.decryptor12 = None;
        self.decryptor12_cbc = None;
        self.decryptor_tlcp = Some(dec);
    }

    /// Deactivate write encryption (return to plaintext mode).
    pub fn deactivate_write_encryption(&mut self) {
        self.encryptor = None;
        self.encryptor12 = None;
        self.encryptor12_cbc = None;
        self.encryptor12_etm = None;
        #[cfg(feature = "tlcp")]
        {
            self.encryptor_tlcp = None;
        }
    }

    /// Deactivate read decryption (return to plaintext mode).
    pub fn deactivate_read_decryption(&mut self) {
        self.decryptor = None;
        self.decryptor12 = None;
        self.decryptor12_cbc = None;
        self.decryptor12_etm = None;
        #[cfg(feature = "tlcp")]
        {
            self.decryptor_tlcp = None;
        }
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
        let record = if let Some(enc) = &mut self.encryptor {
            enc.encrypt_record(content_type, plaintext)?
        } else if let Some(enc12) = &mut self.encryptor12 {
            enc12.encrypt_record(content_type, plaintext)?
        } else if let Some(enc12_etm) = &mut self.encryptor12_etm {
            enc12_etm.encrypt_record(content_type, plaintext)?
        } else if let Some(enc12_cbc) = &mut self.encryptor12_cbc {
            enc12_cbc.encrypt_record(content_type, plaintext)?
        } else {
            #[cfg(feature = "tlcp")]
            if let Some(enc_tlcp) = &mut self.encryptor_tlcp {
                let record = enc_tlcp.encrypt_record(content_type, plaintext)?;
                return Ok(self.serialize_record(&record));
            }
            Record {
                content_type,
                version: TLS13_LEGACY_VERSION,
                fragment: plaintext.to_vec(),
            }
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
        // TLS 1.3: encrypted records always have ApplicationData content type
        if let Some(dec) = &mut self.decryptor {
            if record.content_type == ContentType::ApplicationData {
                let (ct, pt) = dec.decrypt_record(&record)?;
                return Ok((ct, pt, consumed));
            }
        }
        // TLS 1.2 AEAD: encrypted records keep their actual content type
        if let Some(dec12) = &mut self.decryptor12 {
            if record.content_type != ContentType::ChangeCipherSpec {
                let pt = dec12.decrypt_record(&record)?;
                return Ok((record.content_type, pt, consumed));
            }
        }
        // TLS 1.2 Encrypt-Then-MAC: encrypted records keep their actual content type
        if let Some(dec12_etm) = &mut self.decryptor12_etm {
            if record.content_type != ContentType::ChangeCipherSpec {
                let pt = dec12_etm.decrypt_record(&record)?;
                return Ok((record.content_type, pt, consumed));
            }
        }
        // TLS 1.2 CBC: encrypted records keep their actual content type
        if let Some(dec12_cbc) = &mut self.decryptor12_cbc {
            if record.content_type != ContentType::ChangeCipherSpec {
                let pt = dec12_cbc.decrypt_record(&record)?;
                return Ok((record.content_type, pt, consumed));
            }
        }
        // TLCP: encrypted records keep their actual content type
        #[cfg(feature = "tlcp")]
        if let Some(dec_tlcp) = &mut self.decryptor_tlcp {
            if record.content_type != ContentType::ChangeCipherSpec {
                let pt = dec_tlcp.decrypt_record(&record)?;
                return Ok((record.content_type, pt, consumed));
            }
        }
        Ok((record.content_type, record.fragment, consumed))
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
