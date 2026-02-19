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
/// Default maximum number of consecutive empty records allowed.
pub const DEFAULT_EMPTY_RECORDS_LIMIT: u32 = 32;

pub struct RecordLayer {
    /// Maximum fragment size (default: 16384).
    pub max_fragment_size: usize,
    /// Counter for consecutive empty plaintext records received.
    pub empty_record_count: u32,
    /// Maximum consecutive empty records before fatal error (DoS protection).
    pub empty_records_limit: u32,
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
            empty_record_count: 0,
            empty_records_limit: DEFAULT_EMPTY_RECORDS_LIMIT,
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

    /// Set the TLS 1.3 record padding callback on the active encryptor (if any).
    pub fn set_record_padding_callback(
        &mut self,
        cb: std::sync::Arc<dyn Fn(u8, usize) -> usize + Send + Sync>,
    ) {
        if let Some(enc) = &mut self.encryptor {
            enc.set_padding_callback(cb);
        }
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

    /// Check and track empty record counts for DoS protection.
    ///
    /// Call this after decrypting/parsing a record. If the plaintext is empty,
    /// increments the counter and returns an error if the limit is exceeded.
    /// Non-empty records reset the counter to zero.
    ///
    /// Per C openHiTLS semantics:
    /// - Only Handshake and CCS records may be empty (unencrypted)
    /// - Empty encrypted records are rejected
    /// - Empty Alert and ApplicationData records are rejected
    pub fn check_empty_record(
        &mut self,
        content_type: ContentType,
        plaintext_len: usize,
    ) -> Result<(), TlsError> {
        if plaintext_len > 0 {
            self.empty_record_count = 0;
            return Ok(());
        }
        // Empty record
        if self.is_decrypting() {
            return Err(TlsError::RecordError("empty encrypted record".into()));
        }
        match content_type {
            ContentType::Handshake | ContentType::ChangeCipherSpec => {}
            _ => {
                return Err(TlsError::RecordError(
                    "empty alert or application data record".into(),
                ));
            }
        }
        self.empty_record_count += 1;
        if self.empty_record_count > self.empty_records_limit {
            return Err(TlsError::RecordError(
                "too many consecutive empty records".into(),
            ));
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // RecordLayer state
    // -----------------------------------------------------------------------

    #[test]
    fn test_new_defaults() {
        let rl = RecordLayer::new();
        assert!(!rl.is_encrypting());
        assert!(!rl.is_decrypting());
        assert_eq!(rl.max_fragment_size, MAX_PLAINTEXT_LENGTH);
    }

    #[test]
    fn test_default_same_as_new() {
        let rl = RecordLayer::default();
        assert!(!rl.is_encrypting());
        assert!(!rl.is_decrypting());
        assert_eq!(rl.max_fragment_size, MAX_PLAINTEXT_LENGTH);
    }

    #[test]
    fn test_activate_deactivate_tls13() {
        let mut rl = RecordLayer::new();
        let keys = TrafficKeys {
            key: vec![0x42; 16],
            iv: vec![0x43; 12],
        };
        rl.activate_write_encryption(CipherSuite::TLS_AES_128_GCM_SHA256, &keys)
            .unwrap();
        assert!(rl.is_encrypting());
        assert!(!rl.is_decrypting());
        rl.activate_read_decryption(CipherSuite::TLS_AES_128_GCM_SHA256, &keys)
            .unwrap();
        assert!(rl.is_decrypting());

        rl.deactivate_write_encryption();
        assert!(!rl.is_encrypting());
        rl.deactivate_read_decryption();
        assert!(!rl.is_decrypting());
    }

    #[test]
    fn test_activate_deactivate_tls12_cbc() {
        let mut rl = RecordLayer::new();
        rl.activate_write_encryption12_cbc(vec![0; 16], vec![0; 20], 20);
        assert!(rl.is_encrypting());
        rl.activate_read_decryption12_cbc(vec![0; 16], vec![0; 20], 20);
        assert!(rl.is_decrypting());
        rl.deactivate_write_encryption();
        rl.deactivate_read_decryption();
        assert!(!rl.is_encrypting());
        assert!(!rl.is_decrypting());
    }

    #[test]
    fn test_activate_deactivate_tls12_etm() {
        let mut rl = RecordLayer::new();
        rl.activate_write_encryption12_etm(vec![0; 16], vec![0; 32], 32);
        assert!(rl.is_encrypting());
        rl.activate_read_decryption12_etm(vec![0; 16], vec![0; 32], 32);
        assert!(rl.is_decrypting());
        rl.deactivate_write_encryption();
        rl.deactivate_read_decryption();
        assert!(!rl.is_encrypting());
        assert!(!rl.is_decrypting());
    }

    // -----------------------------------------------------------------------
    // parse_record / serialize_record
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_serialize_roundtrip() {
        let rl = RecordLayer::new();
        let record = Record {
            content_type: ContentType::Handshake,
            version: 0x0303,
            fragment: vec![0x01, 0x00, 0x00, 0x05, 0x03, 0x03, 0x00, 0x00, 0x00],
        };
        let bytes = rl.serialize_record(&record);
        let (parsed, consumed) = rl.parse_record(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.content_type, ContentType::Handshake);
        assert_eq!(parsed.version, 0x0303);
        assert_eq!(parsed.fragment, record.fragment);
    }

    #[test]
    fn test_parse_content_types() {
        let rl = RecordLayer::new();
        for (ct_byte, expected) in [
            (20u8, ContentType::ChangeCipherSpec),
            (21, ContentType::Alert),
            (22, ContentType::Handshake),
            (23, ContentType::ApplicationData),
        ] {
            let data = [ct_byte, 0x03, 0x03, 0x00, 0x02, 0xAA, 0xBB];
            let (record, consumed) = rl.parse_record(&data).unwrap();
            assert_eq!(consumed, 7);
            assert_eq!(record.content_type, expected);
            assert_eq!(record.fragment, vec![0xAA, 0xBB]);
        }
    }

    #[test]
    fn test_parse_unknown_content_type() {
        let rl = RecordLayer::new();
        let data = [99u8, 0x03, 0x03, 0x00, 0x01, 0xFF];
        assert!(rl.parse_record(&data).is_err());
    }

    #[test]
    fn test_parse_incomplete_header() {
        let rl = RecordLayer::new();
        assert!(rl.parse_record(&[]).is_err());
        assert!(rl.parse_record(&[22]).is_err());
        assert!(rl.parse_record(&[22, 0x03, 0x03]).is_err());
        assert!(rl.parse_record(&[22, 0x03, 0x03, 0x00]).is_err());
    }

    #[test]
    fn test_parse_incomplete_fragment() {
        let rl = RecordLayer::new();
        // Header says 100 bytes but only 5 available
        let data = [22u8, 0x03, 0x03, 0x00, 100, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(rl.parse_record(&data).is_err());
    }

    #[test]
    fn test_parse_oversized_record() {
        let rl = RecordLayer::new();
        // Length = MAX_PLAINTEXT_LENGTH + 257 → too large
        let len = (MAX_PLAINTEXT_LENGTH + 257) as u16;
        let mut data = vec![23u8, 0x03, 0x03];
        data.extend_from_slice(&len.to_be_bytes());
        data.extend(vec![0u8; len as usize]);
        assert!(rl.parse_record(&data).is_err());
    }

    #[test]
    fn test_serialize_empty_fragment() {
        let rl = RecordLayer::new();
        let record = Record {
            content_type: ContentType::Alert,
            version: 0x0303,
            fragment: Vec::new(),
        };
        let bytes = rl.serialize_record(&record);
        assert_eq!(bytes, vec![21, 0x03, 0x03, 0x00, 0x00]);
    }

    #[test]
    fn test_serialize_record_format() {
        let rl = RecordLayer::new();
        let record = Record {
            content_type: ContentType::ApplicationData,
            version: 0x0301,
            fragment: vec![0x01, 0x02, 0x03],
        };
        let bytes = rl.serialize_record(&record);
        assert_eq!(bytes[0], 23); // ApplicationData
        assert_eq!(&bytes[1..3], &[0x03, 0x01]); // version
        assert_eq!(&bytes[3..5], &[0x00, 0x03]); // length
        assert_eq!(&bytes[5..], &[0x01, 0x02, 0x03]); // fragment
    }

    // -----------------------------------------------------------------------
    // seal_record / open_record
    // -----------------------------------------------------------------------

    #[test]
    fn test_seal_open_plaintext() {
        let mut rl = RecordLayer::new();
        let data = b"hello plaintext";
        let sealed = rl.seal_record(ContentType::Handshake, data).unwrap();
        let (ct, pt, consumed) = rl.open_record(&sealed).unwrap();
        assert_eq!(ct, ContentType::Handshake);
        assert_eq!(pt, data);
        assert_eq!(consumed, sealed.len());
    }

    #[test]
    fn test_seal_open_tls13_aes128() {
        let mut rl = RecordLayer::new();
        let keys = TrafficKeys {
            key: vec![0x42; 16],
            iv: vec![0x43; 12],
        };
        rl.activate_write_encryption(CipherSuite::TLS_AES_128_GCM_SHA256, &keys)
            .unwrap();
        rl.activate_read_decryption(CipherSuite::TLS_AES_128_GCM_SHA256, &keys)
            .unwrap();

        let plaintext = b"hello encrypted world";
        let sealed = rl
            .seal_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        // Sealed record should look like ApplicationData on the wire
        assert_eq!(sealed[0], 23);

        let (ct, pt, consumed) = rl.open_record(&sealed).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(pt, plaintext);
        assert_eq!(consumed, sealed.len());
    }

    #[test]
    fn test_seal_open_tls13_aes256() {
        let mut rl = RecordLayer::new();
        let keys = TrafficKeys {
            key: vec![0x44; 32],
            iv: vec![0x45; 12],
        };
        rl.activate_write_encryption(CipherSuite::TLS_AES_256_GCM_SHA384, &keys)
            .unwrap();
        rl.activate_read_decryption(CipherSuite::TLS_AES_256_GCM_SHA384, &keys)
            .unwrap();

        let plaintext = b"AES-256-GCM test data";
        let sealed = rl
            .seal_record(ContentType::ApplicationData, plaintext)
            .unwrap();
        let (ct, pt, _) = rl.open_record(&sealed).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_seal_open_tls13_chacha20() {
        let mut rl = RecordLayer::new();
        let keys = TrafficKeys {
            key: vec![0x46; 32],
            iv: vec![0x47; 12],
        };
        rl.activate_write_encryption(CipherSuite::TLS_CHACHA20_POLY1305_SHA256, &keys)
            .unwrap();
        rl.activate_read_decryption(CipherSuite::TLS_CHACHA20_POLY1305_SHA256, &keys)
            .unwrap();

        let plaintext = b"ChaCha20-Poly1305 test";
        let sealed = rl
            .seal_record(ContentType::ApplicationData, plaintext)
            .unwrap();
        let (ct, pt, _) = rl.open_record(&sealed).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_seal_plaintext_too_large() {
        let mut rl = RecordLayer::new();
        let data = vec![0u8; MAX_PLAINTEXT_LENGTH + 1];
        assert!(rl.seal_record(ContentType::ApplicationData, &data).is_err());
    }

    #[test]
    fn test_open_tampered_ciphertext() {
        let mut rl = RecordLayer::new();
        let keys = TrafficKeys {
            key: vec![0x42; 16],
            iv: vec![0x43; 12],
        };
        rl.activate_write_encryption(CipherSuite::TLS_AES_128_GCM_SHA256, &keys)
            .unwrap();
        rl.activate_read_decryption(CipherSuite::TLS_AES_128_GCM_SHA256, &keys)
            .unwrap();

        let plaintext = b"data to tamper with";
        let mut sealed = rl
            .seal_record(ContentType::ApplicationData, plaintext)
            .unwrap();
        // Tamper with the ciphertext portion (after 5-byte header)
        let mid = 5 + (sealed.len() - 5) / 2;
        sealed[mid] ^= 0xFF;
        assert!(rl.open_record(&sealed).is_err());
    }

    #[test]
    fn test_seal_multiple_sequence_numbers() {
        let mut rl = RecordLayer::new();
        let keys = TrafficKeys {
            key: vec![0x42; 16],
            iv: vec![0x43; 12],
        };
        rl.activate_write_encryption(CipherSuite::TLS_AES_128_GCM_SHA256, &keys)
            .unwrap();
        rl.activate_read_decryption(CipherSuite::TLS_AES_128_GCM_SHA256, &keys)
            .unwrap();

        // Multiple seal+open cycles should work (sequence numbers increment)
        for i in 0u8..5 {
            let msg = vec![i; 10];
            let sealed = rl.seal_record(ContentType::ApplicationData, &msg).unwrap();
            let (ct, pt, _) = rl.open_record(&sealed).unwrap();
            assert_eq!(ct, ContentType::ApplicationData);
            assert_eq!(pt, msg);
        }
    }

    #[test]
    fn test_content_type_hiding_tls13() {
        let mut rl = RecordLayer::new();
        let keys = TrafficKeys {
            key: vec![0x42; 16],
            iv: vec![0x43; 12],
        };
        rl.activate_write_encryption(CipherSuite::TLS_AES_128_GCM_SHA256, &keys)
            .unwrap();
        rl.activate_read_decryption(CipherSuite::TLS_AES_128_GCM_SHA256, &keys)
            .unwrap();

        let types = [
            ContentType::Alert,
            ContentType::Handshake,
            ContentType::ApplicationData,
        ];
        for &inner_type in &types {
            let sealed = rl.seal_record(inner_type, b"test data").unwrap();
            // All encrypted records appear as ApplicationData on the wire
            assert_eq!(sealed[0], 23);
            let (ct, pt, _) = rl.open_record(&sealed).unwrap();
            assert_eq!(ct, inner_type);
            assert_eq!(pt, b"test data");
        }
    }

    #[test]
    fn test_parse_record_extra_data() {
        let rl = RecordLayer::new();
        // Build a valid record followed by extra bytes
        let mut data = vec![22u8, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03];
        data.extend_from_slice(&[0xFF, 0xFF]); // extra bytes
        let (record, consumed) = rl.parse_record(&data).unwrap();
        assert_eq!(consumed, 8); // only consumes the record
        assert_eq!(record.fragment, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_max_fragment_size_custom() {
        let mut rl = RecordLayer::new();
        rl.max_fragment_size = 512;
        // 512 bytes should work
        let data = vec![0u8; 512];
        let sealed = rl.seal_record(ContentType::ApplicationData, &data).unwrap();
        assert!(!sealed.is_empty());
        // 513 bytes should fail
        let data = vec![0u8; 513];
        assert!(rl.seal_record(ContentType::ApplicationData, &data).is_err());
    }

    #[test]
    fn test_parse_multiple_records_sequential() {
        let rl = RecordLayer::new();
        // Build two records back-to-back in one buffer
        let rec1 = Record {
            content_type: ContentType::Handshake,
            version: 0x0303,
            fragment: vec![0x01, 0x02, 0x03],
        };
        let rec2 = Record {
            content_type: ContentType::ApplicationData,
            version: 0x0303,
            fragment: vec![0x04, 0x05],
        };
        let mut buf = rl.serialize_record(&rec1);
        buf.extend(rl.serialize_record(&rec2));

        // Parse first record
        let (parsed1, consumed1) = rl.parse_record(&buf).unwrap();
        assert_eq!(parsed1.content_type, ContentType::Handshake);
        assert_eq!(parsed1.fragment, vec![0x01, 0x02, 0x03]);
        assert_eq!(consumed1, 8); // 5-byte header + 3-byte fragment

        // Parse second record from remaining buffer
        let (parsed2, consumed2) = rl.parse_record(&buf[consumed1..]).unwrap();
        assert_eq!(parsed2.content_type, ContentType::ApplicationData);
        assert_eq!(parsed2.fragment, vec![0x04, 0x05]);
        assert_eq!(consumed2, 7); // 5-byte header + 2-byte fragment
        assert_eq!(consumed1 + consumed2, buf.len());
    }

    #[test]
    fn test_seal_open_tls12_aead_roundtrip() {
        let mut rl = RecordLayer::new();
        let key = vec![0x42u8; 16]; // AES-128 key
        let iv = vec![0x43u8; 4]; // 4-byte implicit IV for GCM
        rl.activate_write_encryption12(
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            &key,
            iv.clone(),
        )
        .unwrap();
        rl.activate_read_decryption12(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, &key, iv)
            .unwrap();

        let plaintext = b"hello TLS 1.2 AEAD";
        let sealed = rl
            .seal_record(ContentType::ApplicationData, plaintext)
            .unwrap();
        // TLS 1.2 AEAD records include explicit nonce + ciphertext + tag
        assert!(sealed.len() > 5 + plaintext.len());

        let (ct, pt, consumed) = rl.open_record(&sealed).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(pt, plaintext);
        assert_eq!(consumed, sealed.len());
    }

    #[test]
    fn test_seal_open_tls12_cbc_roundtrip() {
        let mut rl = RecordLayer::new();
        let enc_key = vec![0x42u8; 16]; // AES-128 key
        let mac_key = vec![0x43u8; 20]; // SHA-1 HMAC key
        rl.activate_write_encryption12_cbc(enc_key.clone(), mac_key.clone(), 20);
        rl.activate_read_decryption12_cbc(enc_key, mac_key, 20);

        let plaintext = b"hello TLS 1.2 CBC";
        let sealed = rl
            .seal_record(ContentType::ApplicationData, plaintext)
            .unwrap();
        // CBC records include IV + ciphertext (padded) + MAC
        assert!(sealed.len() > 5 + plaintext.len());

        let (ct, pt, consumed) = rl.open_record(&sealed).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(pt, plaintext);
        assert_eq!(consumed, sealed.len());
    }

    #[test]
    fn test_cipher_mode_switch_tls13_to_tls12() {
        let mut rl = RecordLayer::new();

        // Start with TLS 1.3 AEAD
        let keys13 = TrafficKeys {
            key: vec![0x42; 16],
            iv: vec![0x43; 12],
        };
        rl.activate_write_encryption(CipherSuite::TLS_AES_128_GCM_SHA256, &keys13)
            .unwrap();
        assert!(rl.is_encrypting());

        // Deactivate and switch to TLS 1.2 AEAD
        rl.deactivate_write_encryption();
        assert!(!rl.is_encrypting());

        let key12 = vec![0x44u8; 16];
        let iv12 = vec![0x45u8; 4];
        rl.activate_write_encryption12(
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            &key12,
            iv12,
        )
        .unwrap();
        assert!(rl.is_encrypting());

        // Should be able to seal with TLS 1.2 now
        let sealed = rl
            .seal_record(ContentType::ApplicationData, b"mode switch test")
            .unwrap();
        assert!(!sealed.is_empty());
    }

    // -----------------------------------------------------------------------
    // Empty record DoS protection
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_record_defaults() {
        let rl = RecordLayer::new();
        assert_eq!(rl.empty_record_count, 0);
        assert_eq!(rl.empty_records_limit, DEFAULT_EMPTY_RECORDS_LIMIT);
    }

    #[test]
    fn test_empty_record_non_empty_resets() {
        let mut rl = RecordLayer::new();
        // Accept some empty handshake records
        rl.check_empty_record(ContentType::Handshake, 0).unwrap();
        rl.check_empty_record(ContentType::Handshake, 0).unwrap();
        assert_eq!(rl.empty_record_count, 2);

        // Non-empty record resets counter
        rl.check_empty_record(ContentType::Handshake, 10).unwrap();
        assert_eq!(rl.empty_record_count, 0);
    }

    #[test]
    fn test_empty_record_limit_exceeded() {
        let mut rl = RecordLayer::new();
        rl.empty_records_limit = 3;

        rl.check_empty_record(ContentType::Handshake, 0).unwrap();
        rl.check_empty_record(ContentType::Handshake, 0).unwrap();
        rl.check_empty_record(ContentType::Handshake, 0).unwrap();

        // 4th empty record exceeds limit of 3
        let err = rl
            .check_empty_record(ContentType::Handshake, 0)
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("too many consecutive empty records"));
    }

    #[test]
    fn test_empty_record_alert_rejected() {
        let mut rl = RecordLayer::new();
        let err = rl.check_empty_record(ContentType::Alert, 0).unwrap_err();
        assert!(err.to_string().contains("empty alert or application data"));
    }

    #[test]
    fn test_empty_record_app_data_rejected() {
        let mut rl = RecordLayer::new();
        let err = rl
            .check_empty_record(ContentType::ApplicationData, 0)
            .unwrap_err();
        assert!(err.to_string().contains("empty alert or application data"));
    }

    #[test]
    fn test_empty_record_ccs_allowed() {
        let mut rl = RecordLayer::new();
        // CCS empty records are allowed (within limit)
        rl.check_empty_record(ContentType::ChangeCipherSpec, 0)
            .unwrap();
        assert_eq!(rl.empty_record_count, 1);
    }

    #[test]
    fn test_empty_record_zero_limit() {
        let mut rl = RecordLayer::new();
        rl.empty_records_limit = 0;

        // Even one empty record exceeds limit of 0
        let err = rl
            .check_empty_record(ContentType::Handshake, 0)
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("too many consecutive empty records"));
    }
}
