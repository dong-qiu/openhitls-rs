//! DTLS 1.2 AEAD record encryption with epoch-aware nonce and AAD (RFC 6347).
//!
//! The nonce is `fixed_iv(4) || explicit_nonce(8)` where explicit_nonce = `epoch(2) || seq(6)`.
//! The AAD is 13 bytes: `epoch(2) || seq_num(6) || type(1) || version(2) || plaintext_length(2)`.
//! The record fragment is: `explicit_nonce(8) || ciphertext || tag(16)`.

use super::dtls::{DtlsRecord, DTLS12_VERSION};
use super::encryption::MAX_PLAINTEXT_LENGTH;
use super::ContentType;
use crate::crypt::aead::{create_aead, TlsAead};
use crate::record::encryption12::tls12_suite_to_aead_suite;
use crate::CipherSuite;
use hitls_types::TlsError;
use zeroize::Zeroize;

/// Explicit nonce length (8 bytes: epoch(2) + seq(6)).
const EXPLICIT_NONCE_LEN: usize = 8;

/// Build the DTLS 1.2 explicit nonce (8 bytes): `epoch(2) || seq(6)`.
fn build_explicit_nonce(epoch: u16, seq: u64) -> [u8; EXPLICIT_NONCE_LEN] {
    let mut nonce = [0u8; EXPLICIT_NONCE_LEN];
    nonce[..2].copy_from_slice(&epoch.to_be_bytes());
    let seq_bytes = seq.to_be_bytes();
    nonce[2..8].copy_from_slice(&seq_bytes[2..8]); // lower 6 bytes of seq
    nonce
}

/// Build the DTLS 1.2 GCM nonce (12 bytes): `fixed_iv(4) || explicit_nonce(8)`.
fn build_nonce_dtls12(fixed_iv: &[u8], epoch: u16, seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(fixed_iv);
    nonce[4..12].copy_from_slice(&build_explicit_nonce(epoch, seq));
    nonce
}

/// Build the DTLS 1.2 AAD (13 bytes):
/// `epoch(2) || seq_num(6) || content_type(1) || version(2) || plaintext_length(2)`
fn build_aad_dtls12(
    epoch: u16,
    seq: u64,
    content_type: ContentType,
    plaintext_len: u16,
) -> [u8; 13] {
    let mut aad = [0u8; 13];
    aad[..2].copy_from_slice(&epoch.to_be_bytes());
    let seq_bytes = seq.to_be_bytes();
    aad[2..8].copy_from_slice(&seq_bytes[2..8]);
    aad[8] = content_type as u8;
    aad[9] = (DTLS12_VERSION >> 8) as u8;
    aad[10] = (DTLS12_VERSION & 0xFF) as u8;
    aad[11..13].copy_from_slice(&plaintext_len.to_be_bytes());
    aad
}

/// DTLS 1.2 record encryptor (epoch-aware).
///
/// Unlike the TLS 1.2 encryptor, the caller provides epoch and sequence number
/// from `EpochState`, since these appear in the DTLS record header.
pub struct DtlsRecordEncryptor12 {
    aead: Box<dyn TlsAead>,
    fixed_iv: Vec<u8>,
}

impl Drop for DtlsRecordEncryptor12 {
    fn drop(&mut self) {
        self.fixed_iv.zeroize();
    }
}

impl DtlsRecordEncryptor12 {
    /// Create a new DTLS 1.2 GCM encryptor.
    pub fn new(suite: CipherSuite, key: &[u8], fixed_iv: Vec<u8>) -> Result<Self, TlsError> {
        let aead_suite = tls12_suite_to_aead_suite(suite)?;
        let aead = create_aead(aead_suite, key)?;
        Ok(Self { aead, fixed_iv })
    }

    /// Encrypt a plaintext and return a DTLS record.
    ///
    /// The fragment contains `explicit_nonce(8) || ciphertext || tag(16)`.
    pub fn encrypt_record(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
        epoch: u16,
        seq: u64,
    ) -> Result<DtlsRecord, TlsError> {
        if plaintext.len() > MAX_PLAINTEXT_LENGTH {
            return Err(TlsError::RecordError(
                "plaintext exceeds maximum fragment length".into(),
            ));
        }

        let explicit_nonce = build_explicit_nonce(epoch, seq);
        let nonce = build_nonce_dtls12(&self.fixed_iv, epoch, seq);
        let aad = build_aad_dtls12(epoch, seq, content_type, plaintext.len() as u16);

        let ciphertext = self.aead.encrypt(&nonce, &aad, plaintext)?;

        let mut fragment = Vec::with_capacity(EXPLICIT_NONCE_LEN + ciphertext.len());
        fragment.extend_from_slice(&explicit_nonce);
        fragment.extend_from_slice(&ciphertext);

        Ok(DtlsRecord {
            content_type,
            version: DTLS12_VERSION,
            epoch,
            sequence_number: seq,
            fragment,
        })
    }
}

/// DTLS 1.2 record decryptor (epoch-aware).
pub struct DtlsRecordDecryptor12 {
    aead: Box<dyn TlsAead>,
    fixed_iv: Vec<u8>,
    tag_len: usize,
}

impl Drop for DtlsRecordDecryptor12 {
    fn drop(&mut self) {
        self.fixed_iv.zeroize();
    }
}

impl DtlsRecordDecryptor12 {
    /// Create a new DTLS 1.2 GCM decryptor.
    pub fn new(suite: CipherSuite, key: &[u8], fixed_iv: Vec<u8>) -> Result<Self, TlsError> {
        let aead_suite = tls12_suite_to_aead_suite(suite)?;
        let aead = create_aead(aead_suite, key)?;
        let tag_len = aead.tag_size();
        Ok(Self {
            aead,
            fixed_iv,
            tag_len,
        })
    }

    /// Decrypt a DTLS record.
    ///
    /// Epoch and sequence number come from the record header.
    pub fn decrypt_record(&mut self, record: &DtlsRecord) -> Result<Vec<u8>, TlsError> {
        if record.fragment.len() < EXPLICIT_NONCE_LEN + self.tag_len {
            return Err(TlsError::RecordError(
                "DTLS encrypted record too short".into(),
            ));
        }

        let ciphertext_with_tag = &record.fragment[EXPLICIT_NONCE_LEN..];
        let plaintext_len = ciphertext_with_tag.len() - self.tag_len;

        let nonce = build_nonce_dtls12(&self.fixed_iv, record.epoch, record.sequence_number);
        let aad = build_aad_dtls12(
            record.epoch,
            record.sequence_number,
            record.content_type,
            plaintext_len as u16,
        );

        let plaintext = self
            .aead
            .decrypt(&nonce, &aad, ciphertext_with_tag)
            .map_err(|_| TlsError::RecordError("DTLS bad record MAC".into()))?;

        if plaintext.len() > MAX_PLAINTEXT_LENGTH {
            return Err(TlsError::RecordError(
                "decrypted plaintext exceeds maximum length".into(),
            ));
        }

        Ok(plaintext)
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
    fn test_encrypt_decrypt_roundtrip_aes128_dtls12() {
        let (key, iv) = make_keys_128();
        let suite = CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
        let mut enc = DtlsRecordEncryptor12::new(suite, &key, iv.clone()).unwrap();
        let mut dec = DtlsRecordDecryptor12::new(suite, &key, iv).unwrap();

        let plaintext = b"hello DTLS 1.2 GCM";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext, 0, 0)
            .unwrap();

        assert_eq!(record.content_type, ContentType::ApplicationData);
        assert_eq!(record.version, DTLS12_VERSION);
        assert_eq!(record.epoch, 0);
        assert_eq!(record.sequence_number, 0);
        // fragment = explicit_nonce(8) + plaintext(18) + tag(16) = 42
        assert_eq!(record.fragment.len(), 8 + plaintext.len() + 16);

        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_aes256_dtls12() {
        let (key, iv) = make_keys_256();
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
        let mut enc = DtlsRecordEncryptor12::new(suite, &key, iv.clone()).unwrap();
        let mut dec = DtlsRecordDecryptor12::new(suite, &key, iv).unwrap();

        let plaintext = b"hello DTLS 1.2 AES-256-GCM";
        let record = enc
            .encrypt_record(ContentType::Handshake, plaintext, 1, 5)
            .unwrap();

        assert_eq!(record.epoch, 1);
        assert_eq!(record.sequence_number, 5);
        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aad_construction_dtls12() {
        let aad = build_aad_dtls12(1, 42, ContentType::ApplicationData, 100);
        // epoch(2)
        assert_eq!(&aad[..2], &[0x00, 0x01]);
        // seq(6) = 42
        assert_eq!(&aad[2..8], &[0x00, 0x00, 0x00, 0x00, 0x00, 42]);
        // content_type(1) = 23
        assert_eq!(aad[8], 23);
        // version(2) = 0xFEFD
        assert_eq!(&aad[9..11], &[0xFE, 0xFD]);
        // length(2) = 100
        assert_eq!(&aad[11..13], &[0x00, 0x64]);
    }

    #[test]
    fn test_nonce_construction_dtls12() {
        let fixed_iv = [0x01, 0x02, 0x03, 0x04];
        let nonce = build_nonce_dtls12(&fixed_iv, 1, 0x0A0B0C0D0E0F);
        assert_eq!(
            nonce,
            [
                0x01, 0x02, 0x03, 0x04, // fixed_iv
                0x00, 0x01, // epoch
                0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F // seq (lower 6 bytes)
            ]
        );
    }

    #[test]
    fn test_decrypt_tampered_record_dtls12() {
        let (key, iv) = make_keys_128();
        let suite = CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
        let mut enc = DtlsRecordEncryptor12::new(suite, &key, iv.clone()).unwrap();
        let mut dec = DtlsRecordDecryptor12::new(suite, &key, iv).unwrap();

        let record = enc
            .encrypt_record(ContentType::Handshake, b"secret", 0, 0)
            .unwrap();

        let mut tampered = record.clone();
        tampered.fragment[10] ^= 0x01;
        assert!(dec.decrypt_record(&tampered).is_err());
    }

    #[test]
    fn test_different_epochs_different_ciphertexts() {
        let (key, iv) = make_keys_128();
        let suite = CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
        let mut enc = DtlsRecordEncryptor12::new(suite, &key, iv).unwrap();

        let plaintext = b"same message";
        let r0 = enc
            .encrypt_record(ContentType::ApplicationData, plaintext, 0, 0)
            .unwrap();
        let r1 = enc
            .encrypt_record(ContentType::ApplicationData, plaintext, 1, 0)
            .unwrap();

        // Different epochs → different explicit nonce → different ciphertext
        assert_ne!(r0.fragment, r1.fragment);
    }
}
