//! TLS 1.2 AEAD record encryption with explicit nonce (RFC 5246 §6.2.3.3).
//!
//! For GCM cipher suites, the nonce is `fixed_iv(4) || explicit_nonce(8)`.
//! The explicit nonce is sent with each record (prepended to ciphertext).
//! AAD is 13 bytes: `seq_num(8) || type(1) || version(2) || plaintext_length(2)`.

use crate::crypt::aead::{create_aead, TlsAead};
use crate::record::{ContentType, Record};
use crate::CipherSuite;
use hitls_types::TlsError;
use zeroize::Zeroize;

use super::encryption::{MAX_CIPHERTEXT_LENGTH, MAX_PLAINTEXT_LENGTH};

/// TLS 1.2 record version (0x0303).
pub const TLS12_VERSION: u16 = 0x0303;

/// Explicit nonce length for GCM (8 bytes).
const EXPLICIT_NONCE_LEN: usize = 8;

/// Build the TLS 1.2 GCM nonce: fixed_iv(4) || explicit_nonce(8).
fn build_nonce_tls12(fixed_iv: &[u8], explicit_nonce: &[u8; EXPLICIT_NONCE_LEN]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(fixed_iv);
    nonce[4..12].copy_from_slice(explicit_nonce);
    nonce
}

/// Build the TLS 1.2 AAD (13 bytes):
/// `seq_num(8) || content_type(1) || version(2) || plaintext_length(2)`
fn build_aad_tls12(seq: u64, content_type: ContentType, plaintext_len: u16) -> [u8; 13] {
    let seq_bytes = seq.to_be_bytes();
    let len_bytes = plaintext_len.to_be_bytes();
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&seq_bytes);
    aad[8] = content_type as u8;
    aad[9] = 0x03; // version high
    aad[10] = 0x03; // version low
    aad[11] = len_bytes[0];
    aad[12] = len_bytes[1];
    aad
}

/// Encrypts TLS 1.2 GCM records.
///
/// The record fragment format is: `explicit_nonce(8) || ciphertext || tag(16)`.
pub struct RecordEncryptor12 {
    aead: Box<dyn TlsAead>,
    fixed_iv: Vec<u8>,
    seq: u64,
}

impl Drop for RecordEncryptor12 {
    fn drop(&mut self) {
        self.fixed_iv.zeroize();
    }
}

impl RecordEncryptor12 {
    /// Create a new TLS 1.2 GCM encryptor.
    ///
    /// `key` is the write key, `fixed_iv` is the 4-byte IV from the key block.
    /// The cipher suite determines which AEAD algorithm to use.
    pub fn new(suite: CipherSuite, key: &[u8], fixed_iv: Vec<u8>) -> Result<Self, TlsError> {
        let aead = create_aead(suite, key)?;
        Ok(Self {
            aead,
            fixed_iv,
            seq: 0,
        })
    }

    /// Encrypt a plaintext record.
    ///
    /// Returns a Record where fragment = `explicit_nonce(8) || ciphertext || tag(16)`.
    /// The content type is NOT hidden (unlike TLS 1.3).
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

        // Use sequence number as explicit nonce
        let explicit_nonce = self.seq.to_be_bytes();
        let nonce = build_nonce_tls12(&self.fixed_iv, &explicit_nonce);
        let aad = build_aad_tls12(self.seq, content_type, plaintext.len() as u16);

        let ciphertext = self.aead.encrypt(&nonce, &aad, plaintext)?;

        // Fragment = explicit_nonce || ciphertext (includes tag)
        let mut fragment = Vec::with_capacity(EXPLICIT_NONCE_LEN + ciphertext.len());
        fragment.extend_from_slice(&explicit_nonce);
        fragment.extend_from_slice(&ciphertext);

        if self.seq == u64::MAX {
            return Err(TlsError::RecordError("sequence number overflow".into()));
        }
        self.seq += 1;

        Ok(Record {
            content_type,
            version: TLS12_VERSION,
            fragment,
        })
    }

    /// Current write sequence number.
    pub fn sequence_number(&self) -> u64 {
        self.seq
    }
}

/// Decrypts TLS 1.2 GCM records.
pub struct RecordDecryptor12 {
    aead: Box<dyn TlsAead>,
    fixed_iv: Vec<u8>,
    seq: u64,
    tag_len: usize,
}

impl Drop for RecordDecryptor12 {
    fn drop(&mut self) {
        self.fixed_iv.zeroize();
    }
}

impl RecordDecryptor12 {
    /// Create a new TLS 1.2 GCM decryptor.
    pub fn new(suite: CipherSuite, key: &[u8], fixed_iv: Vec<u8>) -> Result<Self, TlsError> {
        let aead = create_aead(suite, key)?;
        let tag_len = aead.tag_size();
        Ok(Self {
            aead,
            fixed_iv,
            seq: 0,
            tag_len,
        })
    }

    /// Decrypt a TLS 1.2 GCM record.
    ///
    /// The fragment must contain: `explicit_nonce(8) || ciphertext || tag(16)`.
    /// Returns the plaintext. The content type comes from the record header.
    pub fn decrypt_record(&mut self, record: &Record) -> Result<Vec<u8>, TlsError> {
        if record.fragment.len() < EXPLICIT_NONCE_LEN + self.tag_len {
            return Err(TlsError::RecordError("encrypted record too short".into()));
        }

        if record.fragment.len() > MAX_CIPHERTEXT_LENGTH {
            return Err(TlsError::RecordError("record overflow".into()));
        }

        // Extract explicit nonce and ciphertext+tag
        let explicit_nonce: [u8; EXPLICIT_NONCE_LEN] =
            record.fragment[..EXPLICIT_NONCE_LEN].try_into().unwrap();
        let ciphertext_with_tag = &record.fragment[EXPLICIT_NONCE_LEN..];

        let plaintext_len = ciphertext_with_tag.len() - self.tag_len;
        let nonce = build_nonce_tls12(&self.fixed_iv, &explicit_nonce);
        let aad = build_aad_tls12(self.seq, record.content_type, plaintext_len as u16);

        let plaintext = self
            .aead
            .decrypt(&nonce, &aad, ciphertext_with_tag)
            .map_err(|_| TlsError::RecordError("bad record MAC".into()))?;

        if plaintext.len() > MAX_PLAINTEXT_LENGTH {
            return Err(TlsError::RecordError(
                "decrypted plaintext exceeds maximum length".into(),
            ));
        }

        if self.seq == u64::MAX {
            return Err(TlsError::RecordError("sequence number overflow".into()));
        }
        self.seq += 1;

        Ok(plaintext)
    }

    /// Current read sequence number.
    pub fn sequence_number(&self) -> u64 {
        self.seq
    }
}

/// Map a TLS 1.2 cipher suite to the underlying AEAD cipher suite for `create_aead`.
///
/// TLS 1.2 ECDHE_*_WITH_AES_128_GCM_* uses the same AES-128-GCM as TLS 1.3's
/// TLS_AES_128_GCM_SHA256; similarly for AES-256-GCM.
pub fn tls12_suite_to_aead_suite(suite: CipherSuite) -> Result<CipherSuite, TlsError> {
    match suite {
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        | CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256
        | CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        | CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256
        | CipherSuite::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
        | CipherSuite::TLS_RSA_PSK_WITH_AES_128_GCM_SHA256
        | CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 => {
            Ok(CipherSuite::TLS_AES_128_GCM_SHA256)
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        | CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384
        | CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        | CipherSuite::TLS_PSK_WITH_AES_256_GCM_SHA384
        | CipherSuite::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
        | CipherSuite::TLS_RSA_PSK_WITH_AES_256_GCM_SHA384
        | CipherSuite::TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 => {
            Ok(CipherSuite::TLS_AES_256_GCM_SHA384)
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        | CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        | CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        | CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256
        | CipherSuite::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256
        | CipherSuite::TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256
        | CipherSuite::TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => {
            Ok(CipherSuite::TLS_CHACHA20_POLY1305_SHA256)
        }
        // AES-CCM suites (RFC 6655 / RFC 7251, 16-byte tag): map to TLS 1.3 AES-128-CCM.
        // AesCcmAead accepts both 128-bit and 256-bit keys; key size comes from key material.
        CipherSuite::TLS_RSA_WITH_AES_128_CCM
        | CipherSuite::TLS_RSA_WITH_AES_256_CCM
        | CipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM
        | CipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM
        | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM
        | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM
        | CipherSuite::TLS_PSK_WITH_AES_128_CCM
        | CipherSuite::TLS_PSK_WITH_AES_256_CCM
        | CipherSuite::TLS_DHE_PSK_WITH_AES_128_CCM
        | CipherSuite::TLS_DHE_PSK_WITH_AES_256_CCM
        | CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 => {
            Ok(CipherSuite::TLS_AES_128_CCM_SHA256)
        }
        // AES-CCM_8 suites (RFC 6655 / RFC 7251, 8-byte tag): map to TLS 1.3 AES-128-CCM_8.
        CipherSuite::TLS_RSA_WITH_AES_128_CCM_8
        | CipherSuite::TLS_RSA_WITH_AES_256_CCM_8
        | CipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM_8
        | CipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM_8
        | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
        | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
        | CipherSuite::TLS_PSK_WITH_AES_128_CCM_8
        | CipherSuite::TLS_PSK_WITH_AES_256_CCM_8
        | CipherSuite::TLS_DHE_PSK_WITH_AES_128_CCM_8
        | CipherSuite::TLS_DHE_PSK_WITH_AES_256_CCM_8
        | CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 => {
            Ok(CipherSuite::TLS_AES_128_CCM_8_SHA256)
        }
        _ => Err(TlsError::NoSharedCipherSuite),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_keys_128() -> (Vec<u8>, Vec<u8>) {
        (vec![0x42u8; 16], vec![0xABu8; 4])
    }

    fn make_keys_256() -> (Vec<u8>, Vec<u8>) {
        (vec![0x42u8; 32], vec![0xCDu8; 4])
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_aes128gcm_tls12() {
        let (key, iv) = make_keys_128();
        let aead_suite = CipherSuite::TLS_AES_128_GCM_SHA256;
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv.clone()).unwrap();
        let mut dec = RecordDecryptor12::new(aead_suite, &key, iv).unwrap();

        let plaintext = b"hello TLS 1.2 GCM";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        // TLS 1.2: content type is actual type, not ApplicationData wrapper
        assert_eq!(record.content_type, ContentType::ApplicationData);
        assert_eq!(record.version, TLS12_VERSION);
        // fragment = explicit_nonce(8) + plaintext(17) + tag(16) = 41
        assert_eq!(record.fragment.len(), 8 + plaintext.len() + 16);

        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_aes256gcm_tls12() {
        let (key, iv) = make_keys_256();
        let aead_suite = CipherSuite::TLS_AES_256_GCM_SHA384;
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv.clone()).unwrap();
        let mut dec = RecordDecryptor12::new(aead_suite, &key, iv).unwrap();

        let plaintext = b"hello TLS 1.2 AES-256-GCM";
        let record = enc
            .encrypt_record(ContentType::Handshake, plaintext)
            .unwrap();

        assert_eq!(record.content_type, ContentType::Handshake);
        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_nonce_construction_tls12() {
        let fixed_iv = [0x01, 0x02, 0x03, 0x04];
        let explicit_nonce: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let nonce = build_nonce_tls12(&fixed_iv, &explicit_nonce);
        assert_eq!(
            nonce,
            [0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
        );
    }

    #[test]
    fn test_aad_construction_tls12() {
        let aad = build_aad_tls12(42, ContentType::ApplicationData, 100);
        // seq_num(8) = 0x000000000000002A
        assert_eq!(&aad[..8], &[0, 0, 0, 0, 0, 0, 0, 42]);
        // content_type(1) = 23
        assert_eq!(aad[8], 23);
        // version(2) = 0x0303
        assert_eq!(&aad[9..11], &[0x03, 0x03]);
        // length(2) = 100
        assert_eq!(&aad[11..13], &[0x00, 0x64]);
    }

    #[test]
    fn test_sequence_number_as_explicit_nonce() {
        let (key, iv) = make_keys_128();
        let aead_suite = CipherSuite::TLS_AES_128_GCM_SHA256;
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv).unwrap();

        assert_eq!(enc.sequence_number(), 0);

        let record0 = enc
            .encrypt_record(ContentType::ApplicationData, b"msg0")
            .unwrap();
        // First 8 bytes of fragment should be seq=0
        assert_eq!(&record0.fragment[..8], &[0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(enc.sequence_number(), 1);

        let record1 = enc
            .encrypt_record(ContentType::ApplicationData, b"msg1")
            .unwrap();
        // First 8 bytes of fragment should be seq=1
        assert_eq!(&record1.fragment[..8], &[0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(enc.sequence_number(), 2);
    }

    #[test]
    fn test_decrypt_tampered_record_tls12() {
        let (key, iv) = make_keys_128();
        let aead_suite = CipherSuite::TLS_AES_128_GCM_SHA256;
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv.clone()).unwrap();
        let mut dec = RecordDecryptor12::new(aead_suite, &key, iv).unwrap();

        let record = enc
            .encrypt_record(ContentType::Handshake, b"secret")
            .unwrap();

        // Tamper with ciphertext (after explicit nonce)
        let mut tampered = record.clone();
        tampered.fragment[10] ^= 0x01;
        assert!(dec.decrypt_record(&tampered).is_err());
    }

    #[test]
    fn test_multiple_records_tls12() {
        let (key, iv) = make_keys_128();
        let aead_suite = CipherSuite::TLS_AES_128_GCM_SHA256;
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv.clone()).unwrap();
        let mut dec = RecordDecryptor12::new(aead_suite, &key, iv).unwrap();

        for i in 0..5 {
            let msg = format!("message {i}");
            let record = enc
                .encrypt_record(ContentType::ApplicationData, msg.as_bytes())
                .unwrap();
            let decrypted = dec.decrypt_record(&record).unwrap();
            assert_eq!(decrypted, msg.as_bytes());
        }
        assert_eq!(enc.sequence_number(), 5);
        assert_eq!(dec.sequence_number(), 5);
    }

    #[test]
    fn test_tls12_suite_to_aead_suite() {
        assert_eq!(
            tls12_suite_to_aead_suite(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256).unwrap(),
            CipherSuite::TLS_AES_128_GCM_SHA256
        );
        assert_eq!(
            tls12_suite_to_aead_suite(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
                .unwrap(),
            CipherSuite::TLS_AES_256_GCM_SHA384
        );
        assert!(tls12_suite_to_aead_suite(CipherSuite::TLS_AES_128_GCM_SHA256).is_err());
    }

    #[test]
    fn test_chacha20_tls12_suite_mapping() {
        assert_eq!(
            tls12_suite_to_aead_suite(CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
                .unwrap(),
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256
        );
        assert_eq!(
            tls12_suite_to_aead_suite(CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
                .unwrap(),
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256
        );
    }

    #[test]
    fn test_chacha20_tls12_encrypt_decrypt_roundtrip() {
        let key = vec![0x42u8; 32]; // ChaCha20 uses 256-bit key
        let iv = vec![0xABu8; 4]; // 4-byte fixed IV
        let aead_suite = CipherSuite::TLS_CHACHA20_POLY1305_SHA256;
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv.clone()).unwrap();
        let mut dec = RecordDecryptor12::new(aead_suite, &key, iv).unwrap();

        let plaintext = b"hello TLS 1.2 ChaCha20-Poly1305";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        assert_eq!(record.content_type, ContentType::ApplicationData);
        assert_eq!(record.version, TLS12_VERSION);
        // fragment = explicit_nonce(8) + plaintext(31) + tag(16) = 55
        assert_eq!(record.fragment.len(), 8 + plaintext.len() + 16);

        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ccm128_tls12_encrypt_decrypt_roundtrip() {
        let (key, iv) = make_keys_128();
        let aead_suite = tls12_suite_to_aead_suite(CipherSuite::TLS_RSA_WITH_AES_128_CCM).unwrap();
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv.clone()).unwrap();
        let mut dec = RecordDecryptor12::new(aead_suite, &key, iv).unwrap();

        let plaintext = b"hello TLS 1.2 AES-128-CCM";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        assert_eq!(record.content_type, ContentType::ApplicationData);
        assert_eq!(record.version, TLS12_VERSION);
        // fragment = explicit_nonce(8) + plaintext(25) + tag(16) = 49
        assert_eq!(record.fragment.len(), 8 + plaintext.len() + 16);

        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ccm256_tls12_encrypt_decrypt_roundtrip() {
        let (key, iv) = make_keys_256();
        let aead_suite =
            tls12_suite_to_aead_suite(CipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM).unwrap();
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv.clone()).unwrap();
        let mut dec = RecordDecryptor12::new(aead_suite, &key, iv).unwrap();

        let plaintext = b"hello TLS 1.2 AES-256-CCM";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        assert_eq!(record.content_type, ContentType::ApplicationData);
        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ccm_tls12_suite_mapping() {
        // AES-128-CCM suites map to TLS_AES_128_CCM_SHA256
        assert_eq!(
            tls12_suite_to_aead_suite(CipherSuite::TLS_RSA_WITH_AES_128_CCM).unwrap(),
            CipherSuite::TLS_AES_128_CCM_SHA256
        );
        assert_eq!(
            tls12_suite_to_aead_suite(CipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM).unwrap(),
            CipherSuite::TLS_AES_128_CCM_SHA256
        );
        assert_eq!(
            tls12_suite_to_aead_suite(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM).unwrap(),
            CipherSuite::TLS_AES_128_CCM_SHA256
        );
        // AES-256-CCM suites also map to TLS_AES_128_CCM_SHA256 (key size from key material)
        assert_eq!(
            tls12_suite_to_aead_suite(CipherSuite::TLS_RSA_WITH_AES_256_CCM).unwrap(),
            CipherSuite::TLS_AES_128_CCM_SHA256
        );
        assert_eq!(
            tls12_suite_to_aead_suite(CipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM).unwrap(),
            CipherSuite::TLS_AES_128_CCM_SHA256
        );
        assert_eq!(
            tls12_suite_to_aead_suite(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM).unwrap(),
            CipherSuite::TLS_AES_128_CCM_SHA256
        );
    }

    #[test]
    fn test_ccm_tls12_multiple_records() {
        let (key, iv) = make_keys_128();
        let aead_suite =
            tls12_suite_to_aead_suite(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM).unwrap();
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv.clone()).unwrap();
        let mut dec = RecordDecryptor12::new(aead_suite, &key, iv).unwrap();

        for i in 0..5 {
            let msg = format!("CCM message {i}");
            let record = enc
                .encrypt_record(ContentType::ApplicationData, msg.as_bytes())
                .unwrap();
            let decrypted = dec.decrypt_record(&record).unwrap();
            assert_eq!(decrypted, msg.as_bytes());
        }
        assert_eq!(enc.sequence_number(), 5);
        assert_eq!(dec.sequence_number(), 5);
    }

    #[test]
    fn test_ccm_tls12_tampered_record() {
        let (key, iv) = make_keys_128();
        let aead_suite = tls12_suite_to_aead_suite(CipherSuite::TLS_RSA_WITH_AES_128_CCM).unwrap();
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv.clone()).unwrap();
        let mut dec = RecordDecryptor12::new(aead_suite, &key, iv).unwrap();

        let record = enc
            .encrypt_record(ContentType::Handshake, b"secret CCM data")
            .unwrap();

        let mut tampered = record.clone();
        tampered.fragment[10] ^= 0x01;
        assert!(dec.decrypt_record(&tampered).is_err());
    }

    #[test]
    fn test_ccm8_tls12_suite_mapping() {
        // CCM_8 suites map to TLS_AES_128_CCM_8_SHA256
        assert_eq!(
            tls12_suite_to_aead_suite(CipherSuite::TLS_RSA_WITH_AES_128_CCM_8).unwrap(),
            CipherSuite::TLS_AES_128_CCM_8_SHA256
        );
        assert_eq!(
            tls12_suite_to_aead_suite(CipherSuite::TLS_RSA_WITH_AES_256_CCM_8).unwrap(),
            CipherSuite::TLS_AES_128_CCM_8_SHA256
        );
    }

    #[test]
    fn test_ccm8_128_tls12_encrypt_decrypt_roundtrip() {
        let (key, iv) = make_keys_128();
        let aead_suite =
            tls12_suite_to_aead_suite(CipherSuite::TLS_RSA_WITH_AES_128_CCM_8).unwrap();
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv.clone()).unwrap();
        let mut dec = RecordDecryptor12::new(aead_suite, &key, iv).unwrap();

        let plaintext = b"hello TLS 1.2 AES-128-CCM_8";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        assert_eq!(record.content_type, ContentType::ApplicationData);
        assert_eq!(record.version, TLS12_VERSION);
        // fragment = explicit_nonce(8) + plaintext(27) + tag(8) = 43
        assert_eq!(record.fragment.len(), 8 + plaintext.len() + 8);

        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ccm8_256_tls12_encrypt_decrypt_roundtrip() {
        let (key, iv) = make_keys_256();
        let aead_suite =
            tls12_suite_to_aead_suite(CipherSuite::TLS_RSA_WITH_AES_256_CCM_8).unwrap();
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv.clone()).unwrap();
        let mut dec = RecordDecryptor12::new(aead_suite, &key, iv).unwrap();

        let plaintext = b"hello TLS 1.2 AES-256-CCM_8";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        // fragment = explicit_nonce(8) + plaintext(27) + tag(8) = 43
        assert_eq!(record.fragment.len(), 8 + plaintext.len() + 8);

        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_psk_ccm_tls12_suite_mapping() {
        // PSK+CCM suites map to TLS_AES_128_CCM_SHA256 (16-byte tag)
        assert_eq!(
            tls12_suite_to_aead_suite(CipherSuite::TLS_PSK_WITH_AES_256_CCM).unwrap(),
            CipherSuite::TLS_AES_128_CCM_SHA256
        );
        assert_eq!(
            tls12_suite_to_aead_suite(CipherSuite::TLS_DHE_PSK_WITH_AES_128_CCM).unwrap(),
            CipherSuite::TLS_AES_128_CCM_SHA256
        );
        assert_eq!(
            tls12_suite_to_aead_suite(CipherSuite::TLS_DHE_PSK_WITH_AES_256_CCM).unwrap(),
            CipherSuite::TLS_AES_128_CCM_SHA256
        );
        assert_eq!(
            tls12_suite_to_aead_suite(CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256).unwrap(),
            CipherSuite::TLS_AES_128_CCM_SHA256
        );
    }

    #[test]
    fn test_psk_ccm_tls12_encrypt_decrypt_roundtrip() {
        // Simulate PSK+CCM with AES-256 key (TLS_PSK_WITH_AES_256_CCM)
        let (key, iv) = make_keys_256();
        let aead_suite = tls12_suite_to_aead_suite(CipherSuite::TLS_PSK_WITH_AES_256_CCM).unwrap();
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv.clone()).unwrap();
        let mut dec = RecordDecryptor12::new(aead_suite, &key, iv).unwrap();

        let plaintext = b"hello TLS 1.2 PSK AES-256-CCM";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        // fragment = explicit_nonce(8) + plaintext(29) + tag(16) = 53
        assert_eq!(record.fragment.len(), 8 + plaintext.len() + 16);

        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ccm8_tls12_tampered_record() {
        let (key, iv) = make_keys_128();
        let aead_suite =
            tls12_suite_to_aead_suite(CipherSuite::TLS_RSA_WITH_AES_128_CCM_8).unwrap();
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv.clone()).unwrap();
        let mut dec = RecordDecryptor12::new(aead_suite, &key, iv).unwrap();

        let record = enc
            .encrypt_record(ContentType::Handshake, b"secret CCM_8 data")
            .unwrap();

        let mut tampered = record.clone();
        tampered.fragment[10] ^= 0x01;
        assert!(dec.decrypt_record(&tampered).is_err());
    }

    #[test]
    fn test_ecdhe_psk_gcm_tls12_suite_mapping() {
        // ECDHE_PSK GCM suites map to corresponding TLS 1.3 AES-GCM
        assert_eq!(
            tls12_suite_to_aead_suite(CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256).unwrap(),
            CipherSuite::TLS_AES_128_GCM_SHA256
        );
        assert_eq!(
            tls12_suite_to_aead_suite(CipherSuite::TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384).unwrap(),
            CipherSuite::TLS_AES_256_GCM_SHA384
        );
    }

    #[test]
    fn test_ecdhe_psk_gcm128_tls12_encrypt_decrypt_roundtrip() {
        let (key, iv) = make_keys_128();
        let aead_suite =
            tls12_suite_to_aead_suite(CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256).unwrap();
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv.clone()).unwrap();
        let mut dec = RecordDecryptor12::new(aead_suite, &key, iv).unwrap();

        let plaintext = b"hello TLS 1.2 ECDHE_PSK AES-128-GCM";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        assert_eq!(record.content_type, ContentType::ApplicationData);
        assert_eq!(record.version, TLS12_VERSION);
        // fragment = explicit_nonce(8) + plaintext(36) + tag(16) = 60
        assert_eq!(record.fragment.len(), 8 + plaintext.len() + 16);

        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ecdhe_psk_gcm256_tls12_encrypt_decrypt_roundtrip() {
        let (key, iv) = make_keys_256();
        let aead_suite =
            tls12_suite_to_aead_suite(CipherSuite::TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384).unwrap();
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv.clone()).unwrap();
        let mut dec = RecordDecryptor12::new(aead_suite, &key, iv).unwrap();

        let plaintext = b"hello TLS 1.2 ECDHE_PSK AES-256-GCM";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        assert_eq!(record.content_type, ContentType::ApplicationData);
        // fragment = explicit_nonce(8) + plaintext(36) + tag(16) = 60
        assert_eq!(record.fragment.len(), 8 + plaintext.len() + 16);

        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // --- Phase 65: PSK CCM completion + CCM_8 authentication cipher suites ---

    #[test]
    fn test_phase65_ccm_ccm8_suite_mapping() {
        // PSK CCM (16-byte tag) maps to TLS_AES_128_CCM_SHA256
        assert_eq!(
            tls12_suite_to_aead_suite(CipherSuite::TLS_PSK_WITH_AES_128_CCM).unwrap(),
            CipherSuite::TLS_AES_128_CCM_SHA256
        );

        // All CCM_8 suites map to TLS_AES_128_CCM_8_SHA256
        let ccm8_suites = [
            CipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM_8,
            CipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM_8,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
            CipherSuite::TLS_PSK_WITH_AES_128_CCM_8,
            CipherSuite::TLS_PSK_WITH_AES_256_CCM_8,
            CipherSuite::TLS_DHE_PSK_WITH_AES_128_CCM_8,
            CipherSuite::TLS_DHE_PSK_WITH_AES_256_CCM_8,
            CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256,
        ];
        for suite in ccm8_suites {
            assert_eq!(
                tls12_suite_to_aead_suite(suite).unwrap(),
                CipherSuite::TLS_AES_128_CCM_8_SHA256,
                "CCM_8 mapping failed for suite 0x{:04X}",
                suite.0
            );
        }
    }

    #[test]
    fn test_phase65_psk_ccm128_encrypt_decrypt_roundtrip() {
        let (key, iv) = make_keys_128();
        let aead_suite = tls12_suite_to_aead_suite(CipherSuite::TLS_PSK_WITH_AES_128_CCM).unwrap();
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv.clone()).unwrap();
        let mut dec = RecordDecryptor12::new(aead_suite, &key, iv).unwrap();

        let plaintext = b"hello TLS 1.2 PSK AES-128-CCM";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        assert_eq!(record.content_type, ContentType::ApplicationData);
        // fragment = explicit_nonce(8) + plaintext(29) + tag(16) = 53
        assert_eq!(record.fragment.len(), 8 + plaintext.len() + 16);

        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_phase65_psk_ccm8_128_encrypt_decrypt_roundtrip() {
        let (key, iv) = make_keys_128();
        let aead_suite =
            tls12_suite_to_aead_suite(CipherSuite::TLS_PSK_WITH_AES_128_CCM_8).unwrap();
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv.clone()).unwrap();
        let mut dec = RecordDecryptor12::new(aead_suite, &key, iv).unwrap();

        let plaintext = b"hello TLS 1.2 PSK AES-128-CCM_8";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        assert_eq!(record.content_type, ContentType::ApplicationData);
        // fragment = explicit_nonce(8) + plaintext(31) + tag(8) = 47
        assert_eq!(record.fragment.len(), 8 + plaintext.len() + 8);

        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_phase65_dhe_rsa_ccm8_256_encrypt_decrypt_roundtrip() {
        let (key, iv) = make_keys_256();
        let aead_suite =
            tls12_suite_to_aead_suite(CipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM_8).unwrap();
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv.clone()).unwrap();
        let mut dec = RecordDecryptor12::new(aead_suite, &key, iv).unwrap();

        let plaintext = b"hello TLS 1.2 DHE_RSA AES-256-CCM_8";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        // fragment = explicit_nonce(8) + plaintext(35) + tag(8) = 51
        assert_eq!(record.fragment.len(), 8 + plaintext.len() + 8);

        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_phase65_ecdhe_ecdsa_ccm8_128_encrypt_decrypt_roundtrip() {
        let (key, iv) = make_keys_128();
        let aead_suite =
            tls12_suite_to_aead_suite(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8).unwrap();
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv.clone()).unwrap();
        let mut dec = RecordDecryptor12::new(aead_suite, &key, iv).unwrap();

        let plaintext = b"hello TLS 1.2 ECDHE_ECDSA AES-128-CCM_8";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        // fragment = explicit_nonce(8) + plaintext(40) + tag(8) = 56
        assert_eq!(record.fragment.len(), 8 + plaintext.len() + 8);

        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_phase65_ccm8_psk_tampered_record() {
        let (key, iv) = make_keys_128();
        let aead_suite =
            tls12_suite_to_aead_suite(CipherSuite::TLS_PSK_WITH_AES_128_CCM_8).unwrap();
        let mut enc = RecordEncryptor12::new(aead_suite, &key, iv.clone()).unwrap();
        let mut dec = RecordDecryptor12::new(aead_suite, &key, iv).unwrap();

        let record = enc
            .encrypt_record(ContentType::Handshake, b"secret CCM_8 PSK data")
            .unwrap();

        let mut tampered = record.clone();
        tampered.fragment[10] ^= 0x01;
        assert!(dec.decrypt_record(&tampered).is_err());
    }

    #[test]
    fn test_phase65_params_lookup_psk_ccm() {
        use crate::crypt::Tls12CipherSuiteParams;

        // PSK CCM (16-byte tag)
        let p = Tls12CipherSuiteParams::from_suite(CipherSuite::TLS_PSK_WITH_AES_128_CCM).unwrap();
        assert!(!p.is_cbc);
        assert_eq!(p.key_len, 16);
        assert_eq!(p.hash_len, 32);
        assert_eq!(p.tag_len, 16);
        assert_eq!(p.fixed_iv_len, 4);
        assert_eq!(p.record_iv_len, 8);

        // PSK CCM_8 (8-byte tag)
        for (suite, key_len) in [
            (CipherSuite::TLS_PSK_WITH_AES_128_CCM_8, 16),
            (CipherSuite::TLS_PSK_WITH_AES_256_CCM_8, 32),
        ] {
            let p = Tls12CipherSuiteParams::from_suite(suite).unwrap();
            assert!(!p.is_cbc);
            assert_eq!(p.key_len, key_len);
            assert_eq!(p.tag_len, 8);
            assert_eq!(p.hash_len, 32);
        }
    }

    #[test]
    fn test_phase65_params_lookup_dhe_psk_ccm8() {
        use crate::crypt::Tls12CipherSuiteParams;

        for (suite, key_len) in [
            (CipherSuite::TLS_DHE_PSK_WITH_AES_128_CCM_8, 16),
            (CipherSuite::TLS_DHE_PSK_WITH_AES_256_CCM_8, 32),
        ] {
            let p = Tls12CipherSuiteParams::from_suite(suite).unwrap();
            assert!(!p.is_cbc);
            assert_eq!(p.key_len, key_len);
            assert_eq!(p.tag_len, 8);
            assert_eq!(p.hash_len, 32);
            assert_eq!(p.fixed_iv_len, 4);
            assert_eq!(p.record_iv_len, 8);
        }
    }

    #[test]
    fn test_phase65_params_lookup_ecdhe_psk_ccm8() {
        use crate::crypt::Tls12CipherSuiteParams;

        let p = Tls12CipherSuiteParams::from_suite(
            CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256,
        )
        .unwrap();
        assert!(!p.is_cbc);
        assert_eq!(p.key_len, 16);
        assert_eq!(p.tag_len, 8);
        assert_eq!(p.hash_len, 32);
    }

    #[test]
    fn test_phase65_params_lookup_dhe_rsa_ccm8() {
        use crate::crypt::Tls12CipherSuiteParams;

        for (suite, key_len) in [
            (CipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM_8, 16),
            (CipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM_8, 32),
        ] {
            let p = Tls12CipherSuiteParams::from_suite(suite).unwrap();
            assert!(!p.is_cbc);
            assert_eq!(p.key_len, key_len);
            assert_eq!(p.tag_len, 8);
            assert_eq!(p.hash_len, 32);
        }
    }

    #[test]
    fn test_phase65_params_lookup_ecdhe_ecdsa_ccm8() {
        use crate::crypt::Tls12CipherSuiteParams;

        for (suite, key_len) in [
            (CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, 16),
            (CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8, 32),
        ] {
            let p = Tls12CipherSuiteParams::from_suite(suite).unwrap();
            assert!(!p.is_cbc);
            assert_eq!(p.key_len, key_len);
            assert_eq!(p.tag_len, 8);
            assert_eq!(p.hash_len, 32);
        }
    }

    #[test]
    fn test_psk_cbc_sha256_sha384_params_lookup() {
        use crate::crypt::Tls12CipherSuiteParams;

        // PSK CBC-SHA256 suites
        for suite in [
            CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA256,
            CipherSuite::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
            CipherSuite::TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
        ] {
            let p = Tls12CipherSuiteParams::from_suite(suite).unwrap();
            assert!(p.is_cbc);
            assert_eq!(p.key_len, 16);
            assert_eq!(p.hash_len, 32);
            assert_eq!(p.mac_key_len, 32);
            assert_eq!(p.mac_len, 32);
        }

        // PSK CBC-SHA384 suites
        for suite in [
            CipherSuite::TLS_PSK_WITH_AES_256_CBC_SHA384,
            CipherSuite::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
            CipherSuite::TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
        ] {
            let p = Tls12CipherSuiteParams::from_suite(suite).unwrap();
            assert!(p.is_cbc);
            assert_eq!(p.key_len, 32);
            assert_eq!(p.hash_len, 48);
            assert_eq!(p.mac_key_len, 48);
            assert_eq!(p.mac_len, 48);
        }
    }

    #[test]
    fn test_ecdhe_psk_gcm_params_lookup() {
        use crate::crypt::Tls12CipherSuiteParams;

        let p128 =
            Tls12CipherSuiteParams::from_suite(CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256)
                .unwrap();
        assert!(!p128.is_cbc);
        assert_eq!(p128.key_len, 16);
        assert_eq!(p128.hash_len, 32);
        assert_eq!(p128.tag_len, 16);
        assert_eq!(p128.fixed_iv_len, 4);
        assert_eq!(p128.record_iv_len, 8);

        let p256 =
            Tls12CipherSuiteParams::from_suite(CipherSuite::TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384)
                .unwrap();
        assert!(!p256.is_cbc);
        assert_eq!(p256.key_len, 32);
        assert_eq!(p256.hash_len, 48);
        assert_eq!(p256.tag_len, 16);
    }
}
