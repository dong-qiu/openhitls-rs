//! TLS 1.3 record encryption and decryption (RFC 8446 Section 5).
//!
//! Handles nonce construction, inner plaintext framing, AAD generation,
//! and sequence number management for TLS 1.3 AEAD record protection.

use crate::crypt::aead::{create_aead, TlsAead};
use crate::crypt::traffic_keys::TrafficKeys;
use crate::record::{ContentType, Record};
use crate::CipherSuite;
use hitls_types::TlsError;
use zeroize::Zeroize;

/// Maximum TLS plaintext fragment size (2^14 bytes, RFC 8446 §5.1).
pub const MAX_PLAINTEXT_LENGTH: usize = 16384;

/// Maximum TLS 1.3 encrypted record overhead (content type + padding + tag).
/// RFC 8446 §5.2: The length MUST NOT exceed 2^14 + 256.
pub const MAX_CIPHERTEXT_OVERHEAD: usize = 256;

/// Maximum TLS 1.3 ciphertext fragment size.
pub const MAX_CIPHERTEXT_LENGTH: usize = MAX_PLAINTEXT_LENGTH + MAX_CIPHERTEXT_OVERHEAD;

/// TLS record header size: content_type(1) + version(2) + length(2).
pub const RECORD_HEADER_LEN: usize = 5;

/// TLS 1.3 legacy record version (0x0303 = TLS 1.2).
pub const TLS13_LEGACY_VERSION: u16 = 0x0303;

/// AEAD nonce size (always 12 for TLS 1.3).
const NONCE_LEN: usize = 12;

/// Build the per-record nonce by XOR-ing IV with zero-padded sequence number.
///
/// RFC 8446 §5.3: `nonce = iv XOR pad_left(sequence_number, iv_length)`
fn build_nonce_from_iv_seq(iv: &[u8], seq: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    let seq_bytes = seq.to_be_bytes();
    // pad_left: first 4 bytes stay zero, last 8 bytes are big-endian seq
    nonce[4..12].copy_from_slice(&seq_bytes);
    for i in 0..NONCE_LEN {
        nonce[i] ^= iv[i];
    }
    nonce
}

/// Build the TLS 1.3 AAD (5 bytes): type || version || ciphertext_length.
///
/// RFC 8446 §5.2: additional_data = TLSCiphertext.opaque_type ||
///     TLSCiphertext.legacy_record_version || TLSCiphertext.length
fn build_aad(ciphertext_len: u16) -> [u8; 5] {
    let len_bytes = ciphertext_len.to_be_bytes();
    [
        ContentType::ApplicationData as u8, // 0x17
        0x03,                               // legacy version high
        0x03,                               // legacy version low
        len_bytes[0],
        len_bytes[1],
    ]
}

/// Build a TLS 1.3 inner plaintext: content || content_type(1) || zeros[padding].
///
/// RFC 8446 §5.4: struct { opaque content[..]; ContentType type; uint8 zeros[..]; }
fn build_inner_plaintext(
    content_type: ContentType,
    plaintext: &[u8],
    padding_len: usize,
) -> Result<Vec<u8>, TlsError> {
    let inner_len = plaintext.len() + 1 + padding_len;
    if plaintext.len() > MAX_PLAINTEXT_LENGTH {
        return Err(TlsError::RecordError(
            "plaintext exceeds maximum length".into(),
        ));
    }
    let mut inner = Vec::with_capacity(inner_len);
    inner.extend_from_slice(plaintext);
    inner.push(content_type as u8);
    inner.resize(inner_len, 0); // zero padding
    Ok(inner)
}

/// Parse inner plaintext: scan from end for first non-zero byte (the content type).
///
/// Returns (actual_content_type, plaintext_content).
fn parse_inner_plaintext(inner: &[u8]) -> Result<(ContentType, &[u8]), TlsError> {
    for i in (0..inner.len()).rev() {
        if inner[i] != 0 {
            let ct = match inner[i] {
                20 => ContentType::ChangeCipherSpec,
                21 => ContentType::Alert,
                22 => ContentType::Handshake,
                23 => ContentType::ApplicationData,
                _ => return Err(TlsError::RecordError("unknown inner content type".into())),
            };
            return Ok((ct, &inner[..i]));
        }
    }
    Err(TlsError::RecordError(
        "inner plaintext has no content type".into(),
    ))
}

/// Encrypts TLS 1.3 records.
///
/// Holds a write AEAD instance, the write IV, and a 64-bit sequence number.
pub struct RecordEncryptor {
    aead: Box<dyn TlsAead>,
    iv: Vec<u8>,
    seq: u64,
    tag_len: usize,
}

impl Drop for RecordEncryptor {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

impl RecordEncryptor {
    /// Create a new encryptor from traffic keys and cipher suite.
    pub fn new(suite: CipherSuite, keys: &TrafficKeys) -> Result<Self, TlsError> {
        let aead = create_aead(suite, &keys.key)?;
        let tag_len = aead.tag_size();
        Ok(Self {
            aead,
            iv: keys.iv.clone(),
            seq: 0,
            tag_len,
        })
    }

    /// Encrypt a plaintext record into a TLS 1.3 ciphertext record.
    ///
    /// The output record has content_type=ApplicationData, version=0x0303,
    /// and fragment = AEAD(inner_plaintext). Increments the sequence number.
    pub fn encrypt_record(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
    ) -> Result<Record, TlsError> {
        if plaintext.len() > MAX_PLAINTEXT_LENGTH {
            return Err(TlsError::RecordError(
                "plaintext exceeds maximum fragment length".into(),
            ));
        }

        let mut inner = build_inner_plaintext(content_type, plaintext, 0)?;
        let ciphertext_len = inner.len() + self.tag_len;

        if ciphertext_len > MAX_CIPHERTEXT_LENGTH {
            return Err(TlsError::RecordError(
                "ciphertext would exceed maximum length".into(),
            ));
        }

        let nonce = build_nonce_from_iv_seq(&self.iv, self.seq);
        let aad = build_aad(ciphertext_len as u16);
        let ciphertext = self.aead.encrypt(&nonce, &aad, &inner)?;
        inner.zeroize();

        if self.seq == u64::MAX {
            return Err(TlsError::RecordError("sequence number overflow".into()));
        }
        self.seq += 1;

        Ok(Record {
            content_type: ContentType::ApplicationData,
            version: TLS13_LEGACY_VERSION,
            fragment: ciphertext,
        })
    }

    /// Current write sequence number.
    pub fn sequence_number(&self) -> u64 {
        self.seq
    }
}

/// Decrypts TLS 1.3 records.
///
/// Holds a read AEAD instance, the read IV, and a 64-bit sequence number.
pub struct RecordDecryptor {
    aead: Box<dyn TlsAead>,
    iv: Vec<u8>,
    seq: u64,
    tag_len: usize,
}

impl Drop for RecordDecryptor {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

impl RecordDecryptor {
    /// Create a new decryptor from traffic keys and cipher suite.
    pub fn new(suite: CipherSuite, keys: &TrafficKeys) -> Result<Self, TlsError> {
        let aead = create_aead(suite, &keys.key)?;
        let tag_len = aead.tag_size();
        Ok(Self {
            aead,
            iv: keys.iv.clone(),
            seq: 0,
            tag_len,
        })
    }

    /// Decrypt a TLS 1.3 ciphertext record.
    ///
    /// The record MUST have content_type == ApplicationData.
    /// Returns (actual_content_type, plaintext) after stripping inner
    /// plaintext framing and padding. Increments the sequence number.
    pub fn decrypt_record(&mut self, record: &Record) -> Result<(ContentType, Vec<u8>), TlsError> {
        if record.content_type != ContentType::ApplicationData {
            return Err(TlsError::RecordError(
                "expected ApplicationData for encrypted record".into(),
            ));
        }

        if record.fragment.len() < self.tag_len + 1 {
            return Err(TlsError::RecordError("encrypted record too short".into()));
        }

        if record.fragment.len() > MAX_CIPHERTEXT_LENGTH {
            return Err(TlsError::RecordError("record overflow".into()));
        }

        let nonce = build_nonce_from_iv_seq(&self.iv, self.seq);
        let aad = build_aad(record.fragment.len() as u16);
        let inner = self
            .aead
            .decrypt(&nonce, &aad, &record.fragment)
            .map_err(|_| TlsError::RecordError("bad record MAC".into()))?;

        let (ct, plaintext_slice) = parse_inner_plaintext(&inner)?;

        if plaintext_slice.len() > MAX_PLAINTEXT_LENGTH {
            return Err(TlsError::RecordError(
                "decrypted plaintext exceeds maximum length".into(),
            ));
        }

        if self.seq == u64::MAX {
            return Err(TlsError::RecordError("sequence number overflow".into()));
        }
        self.seq += 1;

        Ok((ct, plaintext_slice.to_vec()))
    }

    /// Current read sequence number.
    pub fn sequence_number(&self) -> u64 {
        self.seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypt::traffic_keys::TrafficKeys;

    fn make_keys_128() -> TrafficKeys {
        TrafficKeys {
            key: vec![0x42u8; 16],
            iv: vec![0xABu8; 12],
        }
    }

    fn make_keys_256() -> TrafficKeys {
        TrafficKeys {
            key: vec![0x42u8; 32],
            iv: vec![0xCDu8; 12],
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_aes128gcm() {
        let keys = make_keys_128();
        let suite = CipherSuite::TLS_AES_128_GCM_SHA256;
        let mut enc = RecordEncryptor::new(suite, &keys).unwrap();
        let mut dec = RecordDecryptor::new(suite, &keys).unwrap();

        let plaintext = b"hello TLS 1.3";
        let record = enc
            .encrypt_record(ContentType::Handshake, plaintext)
            .unwrap();

        assert_eq!(record.content_type, ContentType::ApplicationData);
        assert_eq!(record.version, TLS13_LEGACY_VERSION);
        // ciphertext = inner_plaintext(13 + 1) + tag(16) = 30
        assert_eq!(record.fragment.len(), plaintext.len() + 1 + 16);

        let (ct, pt) = dec.decrypt_record(&record).unwrap();
        assert_eq!(ct, ContentType::Handshake);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_chacha20() {
        let keys = make_keys_256();
        let suite = CipherSuite::TLS_CHACHA20_POLY1305_SHA256;
        let mut enc = RecordEncryptor::new(suite, &keys).unwrap();
        let mut dec = RecordDecryptor::new(suite, &keys).unwrap();

        let plaintext = b"hello ChaCha20-Poly1305 record layer";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        assert_eq!(record.content_type, ContentType::ApplicationData);

        let (ct, pt) = dec.decrypt_record(&record).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_content_type_hiding() {
        let keys = make_keys_128();
        let suite = CipherSuite::TLS_AES_128_GCM_SHA256;
        let mut enc = RecordEncryptor::new(suite, &keys).unwrap();
        let mut dec = RecordDecryptor::new(suite, &keys).unwrap();

        let types = [
            ContentType::Alert,
            ContentType::Handshake,
            ContentType::ApplicationData,
        ];

        for &inner_type in &types {
            let record = enc.encrypt_record(inner_type, b"test data").unwrap();
            // All encrypted records appear as ApplicationData on the wire
            assert_eq!(record.content_type, ContentType::ApplicationData);
            let (ct, pt) = dec.decrypt_record(&record).unwrap();
            assert_eq!(ct, inner_type);
            assert_eq!(pt, b"test data");
        }
    }

    #[test]
    fn test_padding_handling() {
        // Build inner plaintext with padding
        let inner = build_inner_plaintext(ContentType::Handshake, b"data", 10).unwrap();
        // Expected: b"data" + [22] + [0; 10] = 15 bytes
        assert_eq!(inner.len(), 4 + 1 + 10);
        assert_eq!(&inner[0..4], b"data");
        assert_eq!(inner[4], ContentType::Handshake as u8);
        assert!(inner[5..].iter().all(|&b| b == 0));

        // Parse should recover the content type and content
        let (ct, content) = parse_inner_plaintext(&inner).unwrap();
        assert_eq!(ct, ContentType::Handshake);
        assert_eq!(content, b"data");
    }

    #[test]
    fn test_sequence_number_increment() {
        let keys = make_keys_128();
        let suite = CipherSuite::TLS_AES_128_GCM_SHA256;
        let mut enc = RecordEncryptor::new(suite, &keys).unwrap();
        let mut dec = RecordDecryptor::new(suite, &keys).unwrap();

        assert_eq!(enc.sequence_number(), 0);
        assert_eq!(dec.sequence_number(), 0);

        for i in 0..3u64 {
            let record = enc.encrypt_record(ContentType::Handshake, b"msg").unwrap();
            assert_eq!(enc.sequence_number(), i + 1);
            dec.decrypt_record(&record).unwrap();
            assert_eq!(dec.sequence_number(), i + 1);
        }
    }

    #[test]
    fn test_nonce_construction() {
        // iv = [0x01, 0x02, ..., 0x0C], seq = 0
        let iv: Vec<u8> = (1..=12).collect();

        // seq = 0 → nonce == iv (XOR with all zeros)
        let nonce0 = build_nonce_from_iv_seq(&iv, 0);
        assert_eq!(nonce0, <[u8; 12]>::try_from(iv.as_slice()).unwrap());

        // seq = 1 → last byte XORed with 1
        let nonce1 = build_nonce_from_iv_seq(&iv, 1);
        assert_eq!(nonce1[..11], iv[..11]);
        assert_eq!(nonce1[11], iv[11] ^ 1); // 0x0C ^ 0x01 = 0x0D

        // seq = 0x0102030405060708
        let seq: u64 = 0x0102030405060708;
        let nonce = build_nonce_from_iv_seq(&iv, seq);
        // padded_seq = [0,0,0,0, 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08]
        // nonce[i] = iv[i] ^ padded_seq[i]
        let expected: Vec<u8> = iv
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                let pad = if i < 4 { 0 } else { seq.to_be_bytes()[i - 4] };
                v ^ pad
            })
            .collect();
        assert_eq!(nonce.to_vec(), expected);
    }

    #[test]
    fn test_aad_construction() {
        let aad = build_aad(100);
        assert_eq!(aad, [0x17, 0x03, 0x03, 0x00, 0x64]);

        let aad2 = build_aad(16384);
        assert_eq!(aad2, [0x17, 0x03, 0x03, 0x40, 0x00]);
    }

    #[test]
    fn test_max_record_size_enforcement() {
        let keys = make_keys_128();
        let suite = CipherSuite::TLS_AES_128_GCM_SHA256;
        let mut enc = RecordEncryptor::new(suite, &keys).unwrap();

        // Exactly MAX_PLAINTEXT_LENGTH should succeed
        let data = vec![0xAA; MAX_PLAINTEXT_LENGTH];
        assert!(enc
            .encrypt_record(ContentType::ApplicationData, &data)
            .is_ok());

        // MAX_PLAINTEXT_LENGTH + 1 should fail
        let too_big = vec![0xAA; MAX_PLAINTEXT_LENGTH + 1];
        assert!(enc
            .encrypt_record(ContentType::ApplicationData, &too_big)
            .is_err());
    }

    #[test]
    fn test_ciphertext_too_large() {
        let keys = make_keys_128();
        let suite = CipherSuite::TLS_AES_128_GCM_SHA256;
        let mut dec = RecordDecryptor::new(suite, &keys).unwrap();

        let record = Record {
            content_type: ContentType::ApplicationData,
            version: TLS13_LEGACY_VERSION,
            fragment: vec![0xFF; MAX_CIPHERTEXT_LENGTH + 1],
        };
        assert!(dec.decrypt_record(&record).is_err());
    }

    #[test]
    fn test_plaintext_mode() {
        use crate::record::RecordLayer;

        let mut rl = RecordLayer::new();
        assert!(!rl.is_encrypting());
        assert!(!rl.is_decrypting());

        // seal_record without encryption → plaintext record
        let wire = rl
            .seal_record(ContentType::Handshake, b"client hello")
            .unwrap();

        // Verify wire format: header(5) + body(12)
        assert_eq!(wire.len(), 5 + 12);
        assert_eq!(wire[0], ContentType::Handshake as u8);

        // open_record without decryption → plaintext passthrough
        let (ct, pt, consumed) = rl.open_record(&wire).unwrap();
        assert_eq!(ct, ContentType::Handshake);
        assert_eq!(pt, b"client hello");
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn test_key_change_mid_stream() {
        let keys_a = TrafficKeys {
            key: vec![0x11u8; 16],
            iv: vec![0xAAu8; 12],
        };
        let keys_b = TrafficKeys {
            key: vec![0x22u8; 16],
            iv: vec![0xBBu8; 12],
        };
        let suite = CipherSuite::TLS_AES_128_GCM_SHA256;

        let mut enc = RecordEncryptor::new(suite, &keys_a).unwrap();
        let mut dec_a = RecordDecryptor::new(suite, &keys_a).unwrap();
        let mut dec_b = RecordDecryptor::new(suite, &keys_b).unwrap();

        // Encrypt 2 records with key A
        let r1 = enc.encrypt_record(ContentType::Handshake, b"msg1").unwrap();
        let r2 = enc.encrypt_record(ContentType::Handshake, b"msg2").unwrap();
        assert_eq!(enc.sequence_number(), 2);

        // Decrypt with key A works
        dec_a.decrypt_record(&r1).unwrap();
        dec_a.decrypt_record(&r2).unwrap();

        // Switch encryptor to key B → seq resets
        enc = RecordEncryptor::new(suite, &keys_b).unwrap();
        assert_eq!(enc.sequence_number(), 0);

        let r3 = enc
            .encrypt_record(ContentType::ApplicationData, b"msg3")
            .unwrap();

        // Decrypt r3 with key B works
        let (ct, pt) = dec_b.decrypt_record(&r3).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(pt, b"msg3");

        // Decrypt r3 with key A should fail (wrong key)
        let mut dec_a2 = RecordDecryptor::new(suite, &keys_a).unwrap();
        assert!(dec_a2.decrypt_record(&r3).is_err());
    }

    #[test]
    fn test_decrypt_tampered_record() {
        let keys = make_keys_128();
        let suite = CipherSuite::TLS_AES_128_GCM_SHA256;
        let mut enc = RecordEncryptor::new(suite, &keys).unwrap();
        let mut dec = RecordDecryptor::new(suite, &keys).unwrap();

        let record = enc
            .encrypt_record(ContentType::Handshake, b"secret data")
            .unwrap();

        // Tamper: flip one bit in the ciphertext
        let mut tampered = record.clone();
        tampered.fragment[0] ^= 0x01;

        let result = dec.decrypt_record(&tampered);
        assert!(result.is_err());
    }
}
