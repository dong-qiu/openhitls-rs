//! TLS record layer: parsing, serialization, fragmentation, and encryption.

#[cfg(feature = "dtls12")]
pub mod anti_replay;
#[cfg(any(feature = "dtls12", feature = "dtls13"))]
pub mod dtls;
#[cfg(feature = "dtls13")]
pub mod dtls13;
pub mod encryption;
pub mod encryption12;
pub mod encryption12_cbc;
#[cfg(feature = "dtlcp")]
pub mod encryption_dtlcp;
#[cfg(feature = "dtls12")]
pub mod encryption_dtls12;
#[cfg(feature = "dtls13")]
pub mod encryption_dtls13;
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

/// Unified encryptor variant — at most one is active at any time.
enum RecordEncryptorVariant {
    Tls13(RecordEncryptor),
    Tls12Aead(RecordEncryptor12),
    Tls12Cbc(RecordEncryptor12Cbc),
    Tls12EtM(RecordEncryptor12EtM),
    #[cfg(feature = "tlcp")]
    Tlcp(TlcpEncryptor),
}

impl RecordEncryptorVariant {
    fn encrypt_record(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
    ) -> Result<Record, TlsError> {
        match self {
            Self::Tls13(enc) => enc.encrypt_record(content_type, plaintext),
            Self::Tls12Aead(enc) => enc.encrypt_record(content_type, plaintext),
            Self::Tls12Cbc(enc) => enc.encrypt_record(content_type, plaintext),
            Self::Tls12EtM(enc) => enc.encrypt_record(content_type, plaintext),
            #[cfg(feature = "tlcp")]
            Self::Tlcp(enc) => enc.encrypt_record(content_type, plaintext),
        }
    }
}

/// Unified decryptor variant — at most one is active at any time.
enum RecordDecryptorVariant {
    Tls13(RecordDecryptor),
    Tls12Aead(RecordDecryptor12),
    Tls12Cbc(RecordDecryptor12Cbc),
    Tls12EtM(RecordDecryptor12EtM),
    #[cfg(feature = "tlcp")]
    Tlcp(TlcpDecryptor),
}

impl RecordDecryptorVariant {
    /// Returns true if this is a TLS 1.3 decryptor.
    ///
    /// TLS 1.3 only decrypts `ApplicationData` records (content type hiding),
    /// while TLS 1.2/TLCP skip `ChangeCipherSpec` but decrypt all others.
    fn is_tls13(&self) -> bool {
        matches!(self, Self::Tls13(_))
    }

    /// Unified decrypt — returns (content_type, plaintext).
    ///
    /// TLS 1.3: extracts inner content type from encrypted record.
    /// TLS 1.2/TLCP: preserves the record's original content type.
    fn decrypt_record(&mut self, record: &Record) -> Result<(ContentType, Vec<u8>), TlsError> {
        match self {
            Self::Tls13(dec) => dec.decrypt_record(record),
            Self::Tls12Aead(dec) => Ok((record.content_type, dec.decrypt_record(record)?)),
            Self::Tls12Cbc(dec) => Ok((record.content_type, dec.decrypt_record(record)?)),
            Self::Tls12EtM(dec) => Ok((record.content_type, dec.decrypt_record(record)?)),
            #[cfg(feature = "tlcp")]
            Self::Tlcp(dec) => Ok((record.content_type, dec.decrypt_record(record)?)),
        }
    }
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
    /// Active encryptor for outgoing records (TLS 1.3, 1.2, or TLCP).
    encryptor: Option<RecordEncryptorVariant>,
    /// Active decryptor for incoming records (TLS 1.3, 1.2, or TLCP).
    decryptor: Option<RecordDecryptorVariant>,
    /// Optional protocol-message observation callback (OpenSSL
    /// `SSL_set_msg_callback` parity). Invoked for every record sealed
    /// (outgoing) or opened (incoming) with `(is_outgoing, wire_version,
    /// content_type, message_bytes)`. `None` by default — no overhead.
    msg_callback: Option<crate::config::MsgCallback>,
}

impl RecordLayer {
    pub fn new() -> Self {
        Self {
            max_fragment_size: MAX_PLAINTEXT_LENGTH,
            empty_record_count: 0,
            empty_records_limit: DEFAULT_EMPTY_RECORDS_LIMIT,
            encryptor: None,
            decryptor: None,
            msg_callback: None,
        }
    }

    /// Construct a record layer pre-wired with a protocol-message callback
    /// (taken from `TlsConfig::msg_callback` at connection construction).
    pub fn with_msg_callback(msg_callback: Option<crate::config::MsgCallback>) -> Self {
        Self {
            msg_callback,
            ..Self::new()
        }
    }

    /// Maximum ciphertext expansion over the plaintext fragment limit for an
    /// incoming encrypted record, per the active read protocol: TLS 1.3 caps
    /// TLSCiphertext at 2^14 + 256 (RFC 8446 §5.2, small AEAD tag), whereas
    /// TLS 1.2 / TLCP allow 2^14 + 2048 (RFC 5246 §6.2.1, explicit IV +
    /// padding + MAC). Defaults to the stricter 256 when no decryptor is yet
    /// active.
    fn max_ciphertext_overhead(&self) -> usize {
        match self.decryptor {
            Some(RecordDecryptorVariant::Tls13(_)) | None => 256,
            Some(_) => 2048,
        }
    }

    /// Returns true if write encryption is active (TLS 1.2, 1.3, or TLCP).
    pub fn is_encrypting(&self) -> bool {
        self.encryptor.is_some()
    }

    /// Returns true if read decryption is active (TLS 1.2, 1.3, or TLCP).
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
        self.encryptor = Some(RecordEncryptorVariant::Tls13(RecordEncryptor::new(
            suite, keys,
        )?));
        Ok(())
    }

    /// Set the TLS 1.3 record padding callback on the active encryptor (if any).
    pub fn set_record_padding_callback(
        &mut self,
        cb: std::sync::Arc<dyn Fn(u8, usize) -> usize + Send + Sync>,
    ) {
        if let Some(RecordEncryptorVariant::Tls13(enc)) = &mut self.encryptor {
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
        self.decryptor = Some(RecordDecryptorVariant::Tls13(RecordDecryptor::new(
            suite, keys,
        )?));
        Ok(())
    }

    /// Activate TLS 1.2 write encryption with the given key and fixed IV.
    pub fn activate_write_encryption12(
        &mut self,
        suite: CipherSuite,
        key: &[u8],
        fixed_iv: Vec<u8>,
    ) -> Result<(), TlsError> {
        self.encryptor = Some(RecordEncryptorVariant::Tls12Aead(RecordEncryptor12::new(
            encryption12::tls12_suite_to_aead_suite(suite)?,
            key,
            fixed_iv,
        )?));
        Ok(())
    }

    /// Activate TLS 1.2 read decryption with the given key and fixed IV.
    pub fn activate_read_decryption12(
        &mut self,
        suite: CipherSuite,
        key: &[u8],
        fixed_iv: Vec<u8>,
    ) -> Result<(), TlsError> {
        self.decryptor = Some(RecordDecryptorVariant::Tls12Aead(RecordDecryptor12::new(
            encryption12::tls12_suite_to_aead_suite(suite)?,
            key,
            fixed_iv,
        )?));
        Ok(())
    }

    /// Activate TLS 1.2 CBC write encryption.
    pub fn activate_write_encryption12_cbc(
        &mut self,
        enc_key: &[u8],
        mac_key: &[u8],
        mac_len: usize,
    ) -> Result<(), TlsError> {
        self.encryptor = Some(RecordEncryptorVariant::Tls12Cbc(RecordEncryptor12Cbc::new(
            enc_key, mac_key, mac_len,
        )?));
        Ok(())
    }

    /// Activate TLS 1.2 CBC read decryption.
    pub fn activate_read_decryption12_cbc(
        &mut self,
        enc_key: &[u8],
        mac_key: &[u8],
        mac_len: usize,
    ) -> Result<(), TlsError> {
        self.decryptor = Some(RecordDecryptorVariant::Tls12Cbc(RecordDecryptor12Cbc::new(
            enc_key, mac_key, mac_len,
        )?));
        Ok(())
    }

    /// Activate TLS 1.2 Encrypt-Then-MAC write encryption (RFC 7366).
    pub fn activate_write_encryption12_etm(
        &mut self,
        enc_key: &[u8],
        mac_key: &[u8],
        mac_len: usize,
    ) -> Result<(), TlsError> {
        self.encryptor = Some(RecordEncryptorVariant::Tls12EtM(RecordEncryptor12EtM::new(
            enc_key, mac_key, mac_len,
        )?));
        Ok(())
    }

    /// Activate TLS 1.2 Encrypt-Then-MAC read decryption (RFC 7366).
    pub fn activate_read_decryption12_etm(
        &mut self,
        enc_key: &[u8],
        mac_key: &[u8],
        mac_len: usize,
    ) -> Result<(), TlsError> {
        self.decryptor = Some(RecordDecryptorVariant::Tls12EtM(RecordDecryptor12EtM::new(
            enc_key, mac_key, mac_len,
        )?));
        Ok(())
    }

    /// Activate TLCP write encryption.
    #[cfg(feature = "tlcp")]
    pub fn activate_write_encryption_tlcp(&mut self, enc: TlcpEncryptor) {
        self.encryptor = Some(RecordEncryptorVariant::Tlcp(enc));
    }

    /// Activate TLCP read decryption.
    #[cfg(feature = "tlcp")]
    pub fn activate_read_decryption_tlcp(&mut self, dec: TlcpDecryptor) {
        self.decryptor = Some(RecordDecryptorVariant::Tlcp(dec));
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
        // Protocol-message observation (OpenSSL SSL_set_msg_callback parity):
        // report the outgoing message once, whole (inner content type +
        // pre-encryption / pre-fragmentation plaintext payload).
        if let Some(ref cb) = self.msg_callback {
            cb(true, TLS13_LEGACY_VERSION, content_type as u8, plaintext);
        }
        // RFC 5246 §7.1: ChangeCipherSpec is sent as cleartext (the
        // record-layer encryption only switches AFTER the CCS is on
        // the wire). The symmetric `open_record` path already skips
        // decryption on TLS 1.2 CCS records (`record/mod.rs::open_record`
        // matches `content_type != ChangeCipherSpec`). Phase I112 — keep
        // this matching by also skipping AEAD encryption on send:
        // previously, a `seal_record(ChangeCipherSpec, &[0x01])` issued
        // during renegotiation would emit an encrypted 25-byte payload
        // (TLS 1.2 AES-GCM expansion of a 1-byte plaintext), which
        // OpenSSL / NSS / the receiver-side `process_change_cipher_spec`
        // payload-length check (Phase I112) all reject. CCS is a 1-byte
        // record and never exceeds the fragment limit.
        if content_type == ContentType::ChangeCipherSpec {
            let record = Record {
                content_type,
                version: TLS13_LEGACY_VERSION,
                fragment: plaintext.to_vec(),
            };
            return Ok(self.serialize_record(&record));
        }
        // RFC 5246 §6.2.1 / RFC 8446 §5.1 — a message larger than the current
        // fragment limit (which an RFC 6066 `max_fragment_length` or RFC 8449
        // `record_size_limit` negotiation may have lowered well below 2^14) is
        // split across multiple records, each ≤ `max_fragment_size`. Each
        // fragment is sealed independently (its own AEAD sequence number /
        // padding); the peer reassembles by concatenating the record payloads.
        // Previously an over-limit message (e.g. a Certificate under a small
        // negotiated MFL) was rejected with "record overflow" instead of being
        // fragmented — surfaced by TLS-Anvil's `max_fragment_length` tests.
        let mfs = self.max_fragment_size.max(1);
        if plaintext.len() <= mfs {
            return self.seal_one_record(content_type, plaintext);
        }
        let mut out = Vec::with_capacity(plaintext.len() + 64);
        for chunk in plaintext.chunks(mfs) {
            out.extend_from_slice(&self.seal_one_record(content_type, chunk)?);
        }
        Ok(out)
    }

    /// Seal a single record (≤ `max_fragment_size` plaintext) — encrypt it when
    /// a write encryptor is active, else emit it as a cleartext record — and
    /// return the serialized bytes. Callers fragment via [`seal_record`]; this
    /// never invokes the message callback (that fires once per whole message).
    fn seal_one_record(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        let record = if let Some(enc) = &mut self.encryptor {
            enc.encrypt_record(content_type, plaintext)?
        } else {
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
        let wire_version = record.version;
        // Resolve the inner (content_type, plaintext), decrypting when a read
        // decryptor is active. The result is computed once so the
        // protocol-message callback below sees the final message exactly once.
        let (ct, pt) = if let Some(dec) = &mut self.decryptor {
            if dec.is_tls13() {
                // RFC 8446 §5.1 + §5.2: once read decryption is active,
                // handshake and application_data records MUST be carried
                // as TLSCiphertext (wire content_type = application_data,
                // 23). A plaintext Handshake or ApplicationData record in
                // this phase is a §5.1 violation and MUST be terminated
                // with `unexpected_message` (Phase I110 —
                // `test-tls13-finished-plaintext.py` pins this:
                // previously a plaintext Finished record bypassed the
                // AEAD entirely and was accepted because the Finished
                // verify_data is computed over the transcript, which is
                // independent of record-layer encryption).
                //
                // `Alert` and `ChangeCipherSpec` are explicitly
                // permitted in plaintext at any time (§D.4 middlebox-
                // compat CCS, peer's pre-encryption alert).
                match record.content_type {
                    ContentType::ApplicationData => dec.decrypt_record(&record)?,
                    ContentType::Alert | ContentType::ChangeCipherSpec => {
                        // Permitted in plaintext — return as-is.
                        (record.content_type, record.fragment)
                    }
                    _ => {
                        return Err(TlsError::RecordError(format!(
                            "unexpected content type {:?} in TLS 1.3 \
                             encrypted phase (RFC 8446 §5.1: handshake / \
                             application_data must be carried inside a \
                             TLSCiphertext wrapper) — alert: unexpected_message",
                            record.content_type
                        )));
                    }
                }
            } else if record.content_type != ContentType::ChangeCipherSpec {
                // TLS 1.2/TLCP: decrypt everything except ChangeCipherSpec.
                dec.decrypt_record(&record)?
            } else {
                (record.content_type, record.fragment)
            }
        } else {
            (record.content_type, record.fragment)
        };

        // Protocol-message observation (OpenSSL SSL_set_msg_callback parity).
        if let Some(ref cb) = self.msg_callback {
            cb(false, wire_version, ct as u8, &pt);
        }
        Ok((ct, pt, consumed))
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

        // RFC 8446 §5.1: TLSPlaintext.length MUST NOT exceed 2^14.
        // RFC 8446 §5.2: TLSCiphertext.length MUST NOT exceed 2^14 + 256.
        // On the wire, encrypted records have `opaque_type = ApplicationData`
        // (§5.2 says: "The outer opaque_type field of a TLSCiphertext
        // record is always set to the value 23, application_data"), so we
        // gate by the wire `content_type` rather than by whether the
        // record will actually be decrypted — a still-handshaking peer
        // that mislabels a Handshake record as ApplicationData would have
        // already been rejected by `decrypt_record`'s content-type check.
        // Phase I108 — tlsfuzzer test
        // `too big ClientHello msg, with 16168 bytes of padding` pins this
        // discrimination (an oversized *plaintext* ClientHello previously
        // slipped past because we applied the +256 cipher overhead
        // budget to every record type).
        // The ciphertext-length budget over the plaintext limit is
        // version-dependent: RFC 8446 §5.2 caps TLSCiphertext at 2^14 + 256
        // (small AEAD expansion), but RFC 5246 §6.2.1 caps it at 2^14 + 2048
        // — TLS 1.2 CBC adds an explicit IV, up to 256 bytes of padding, and
        // the MAC, which can push a legal 2^14-plaintext record well past
        // +256. Keying the budget on the active decryptor's protocol (rather
        // than a flat +256) stops us from rejecting valid TLS 1.2 CBC records
        // with `record_overflow`.
        let max_length = if content_type == ContentType::ApplicationData {
            self.max_fragment_size + self.max_ciphertext_overhead()
        } else {
            self.max_fragment_size
        };
        if length > max_length {
            return Err(TlsError::RecordError("record overflow".into()));
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

    #[test]
    fn test_seal_record_fragments_oversized_message() {
        // RFC 5246 §6.2.1 / RFC 8446 §5.1 — a message larger than
        // max_fragment_size (e.g. an RFC 6066 max_fragment_length-limited peer)
        // must be split across records, not rejected. Cleartext path so we can
        // reassemble via parse_record.
        let mut rl = RecordLayer::new();
        rl.max_fragment_size = 64;
        let plaintext: Vec<u8> = (0..200u32).map(|i| i as u8).collect(); // 200 > 64

        let sealed = rl.seal_record(ContentType::Handshake, &plaintext).unwrap();

        let mut data = sealed.as_slice();
        let mut reassembled = Vec::new();
        let mut nrecords = 0;
        while !data.is_empty() {
            let (rec, consumed) = rl.parse_record(data).unwrap();
            assert_eq!(rec.content_type, ContentType::Handshake);
            assert!(
                rec.fragment.len() <= 64,
                "each fragment must honor max_fragment_size"
            );
            reassembled.extend_from_slice(&rec.fragment);
            data = &data[consumed..];
            nrecords += 1;
        }
        assert_eq!(reassembled, plaintext, "fragments must reassemble exactly");
        assert_eq!(nrecords, 4, "200 bytes / 64 → 4 records (64+64+64+8)");

        // A message that fits stays a single record (byte-identical to before).
        let small = vec![0xAB; 10];
        let one = rl.seal_record(ContentType::Handshake, &small).unwrap();
        let (rec, consumed) = rl.parse_record(&one).unwrap();
        assert_eq!(
            consumed,
            one.len(),
            "small message must be exactly one record"
        );
        assert_eq!(rec.fragment, small);
    }

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
        rl.activate_write_encryption12_cbc(&[0; 16], &[0; 20], 20)
            .unwrap();
        assert!(rl.is_encrypting());
        rl.activate_read_decryption12_cbc(&[0; 16], &[0; 20], 20)
            .unwrap();
        assert!(rl.is_decrypting());
        rl.deactivate_write_encryption();
        rl.deactivate_read_decryption();
        assert!(!rl.is_encrypting());
        assert!(!rl.is_decrypting());
    }

    #[test]
    fn test_activate_deactivate_tls12_etm() {
        let mut rl = RecordLayer::new();
        rl.activate_write_encryption12_etm(&[0; 16], &[0; 32], 32)
            .unwrap();
        assert!(rl.is_encrypting());
        rl.activate_read_decryption12_etm(&[0; 16], &[0; 32], 32)
            .unwrap();
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
    fn test_seal_oversized_plaintext_fragments() {
        // A plaintext exceeding the fragment limit is now split across records
        // (RFC 5246 §6.2.1 / RFC 8446 §5.1) rather than rejected. Each emitted
        // record is ≤ max_fragment_size and they reassemble to the original.
        let mut rl = RecordLayer::new();
        let data = vec![0u8; MAX_PLAINTEXT_LENGTH + 1];
        let sealed = rl.seal_record(ContentType::ApplicationData, &data).unwrap();
        let mut d = sealed.as_slice();
        let mut reassembled = Vec::new();
        while !d.is_empty() {
            let (rec, consumed) = rl.parse_record(d).unwrap();
            assert!(rec.fragment.len() <= MAX_PLAINTEXT_LENGTH);
            reassembled.extend_from_slice(&rec.fragment);
            d = &d[consumed..];
        }
        assert_eq!(reassembled.len(), data.len());
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
        // 512 bytes → exactly one record.
        let data = vec![0u8; 512];
        let sealed = rl.seal_record(ContentType::ApplicationData, &data).unwrap();
        let (rec, consumed) = rl.parse_record(&sealed).unwrap();
        assert_eq!(consumed, sealed.len());
        assert_eq!(rec.fragment.len(), 512);
        // 513 bytes → fragmented into two records (512 + 1), not rejected.
        let data = vec![0u8; 513];
        let sealed = rl.seal_record(ContentType::ApplicationData, &data).unwrap();
        let (r1, c1) = rl.parse_record(&sealed).unwrap();
        let (r2, _) = rl.parse_record(&sealed[c1..]).unwrap();
        assert_eq!(r1.fragment.len(), 512);
        assert_eq!(r2.fragment.len(), 1);
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
        rl.activate_write_encryption12_cbc(&enc_key, &mac_key, 20)
            .unwrap();
        rl.activate_read_decryption12_cbc(&enc_key, &mac_key, 20)
            .unwrap();

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

    #[test]
    fn test_seal_open_tls12_etm_roundtrip() {
        let enc_key = vec![0x11; 16];
        let mac_key = vec![0x22; 32];
        let mac_len = 32;

        let mut write_rl = RecordLayer::new();
        write_rl
            .activate_write_encryption12_etm(&enc_key, &mac_key, mac_len)
            .unwrap();

        let mut read_rl = RecordLayer::new();
        read_rl
            .activate_read_decryption12_etm(&enc_key, &mac_key, mac_len)
            .unwrap();

        // Seal a record
        let plaintext = b"EtM roundtrip test payload";
        let sealed = write_rl
            .seal_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        // Open it
        let (ct, pt, consumed) = read_rl.open_record(&sealed).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(pt, plaintext);
        assert_eq!(consumed, sealed.len());
    }

    #[test]
    fn test_ccs_passthrough_with_active_decryptor12() {
        let mut rl = RecordLayer::new();
        rl.activate_read_decryption12(
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            &[0x33; 16],
            vec![0x44; 4],
        )
        .unwrap();
        assert!(rl.is_decrypting());

        // Build a raw CCS record: type=20, version=0x0303, length=1, payload=[1]
        let ccs_record = vec![20, 0x03, 0x03, 0x00, 0x01, 0x01];
        let (ct, data, consumed) = rl.open_record(&ccs_record).unwrap();
        assert_eq!(ct, ContentType::ChangeCipherSpec);
        assert_eq!(data, vec![0x01]);
        assert_eq!(consumed, 6);
    }

    #[test]
    fn test_empty_encrypted_record_rejected() {
        let mut rl = RecordLayer::new();
        // Activate any decryptor to set is_decrypting() = true
        rl.activate_read_decryption12_etm(&[0; 16], &[0; 32], 32)
            .unwrap();
        assert!(rl.is_decrypting());

        // Empty record with active decryptor → should be rejected
        let err = rl
            .check_empty_record(ContentType::ApplicationData, 0)
            .unwrap_err();
        assert!(err.to_string().contains("empty encrypted record"));
    }

    #[test]
    fn test_parse_record_size_limit_boundary() {
        let mut rl = RecordLayer::new();
        rl.max_fragment_size = 100;

        // Phase I108 — `parse_record` now gates by wire content type:
        //   * `ApplicationData` (the wire type that carries TLS 1.3
        //     TLSCiphertext) → cap = max_fragment_size + 256 (§5.2),
        //   * everything else (TLSPlaintext: Handshake / Alert / CCS)
        //     → cap = max_fragment_size (§5.1).

        // ApplicationData exactly at +256 cap (356) is accepted.
        let payload_ad = vec![0xAA; 356];
        let mut record_ad = vec![23, 0x03, 0x03]; // ApplicationData
        record_ad.extend_from_slice(&(356u16).to_be_bytes());
        record_ad.extend_from_slice(&payload_ad);
        assert!(rl.parse_record(&record_ad).is_ok());

        // ApplicationData one over (+256+1 = 357) → record_overflow.
        let payload_ad_over = vec![0xBB; 357];
        let mut record_ad_over = vec![23, 0x03, 0x03];
        record_ad_over.extend_from_slice(&(357u16).to_be_bytes());
        record_ad_over.extend_from_slice(&payload_ad_over);
        let err = rl.parse_record(&record_ad_over).unwrap_err();
        assert!(err.to_string().contains("overflow"));

        // Handshake exactly at cap (100) is accepted.
        let payload_hs = vec![0xCC; 100];
        let mut record_hs = vec![22, 0x03, 0x03]; // Handshake
        record_hs.extend_from_slice(&(100u16).to_be_bytes());
        record_hs.extend_from_slice(&payload_hs);
        assert!(rl.parse_record(&record_hs).is_ok());

        // Handshake one over (101) — would be accepted under the old
        // unified +256 cap (101 < 356) but is now rejected because
        // TLSPlaintext.length MUST NOT exceed 2^14 (here mocked at 100).
        let payload_hs_over = vec![0xDD; 101];
        let mut record_hs_over = vec![22, 0x03, 0x03];
        record_hs_over.extend_from_slice(&(101u16).to_be_bytes());
        record_hs_over.extend_from_slice(&payload_hs_over);
        let err = rl.parse_record(&record_hs_over).unwrap_err();
        assert!(err.to_string().contains("overflow"));
    }
}
