//! DTLS 1.3 AEAD record encryption (RFC 9147 §4).
//!
//! Uses TLS 1.3-style nonce (iv XOR seq) and inner plaintext (content || type || padding),
//! but with a 13-byte AAD matching the DTLSPlaintext header format.

use super::dtls13::{build_aad_dtls13, serialize_dtls13_record, Dtls13EpochState, Dtls13Record};
use super::encryption::MAX_PLAINTEXT_LENGTH;
use super::ContentType;
use crate::crypt::aead::{create_aead, TlsAead};
use crate::crypt::traffic_keys::TrafficKeys;
use crate::CipherSuite;
use hitls_types::TlsError;
use zeroize::Zeroize;

/// AEAD nonce size (always 12).
const NONCE_LEN: usize = 12;

/// AEAD tag size.
const TAG_LEN: usize = 16;

/// Build per-record nonce: `iv XOR pad_left(seq, 12)` (same as TLS 1.3).
fn build_nonce(iv: &[u8], seq: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    let seq_bytes = seq.to_be_bytes();
    nonce[4..12].copy_from_slice(&seq_bytes);
    for i in 0..NONCE_LEN {
        nonce[i] ^= iv[i];
    }
    nonce
}

/// Build inner plaintext: `content || content_type(1) || zeros[padding]`.
fn build_inner_plaintext(content_type: ContentType, plaintext: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(plaintext.len() + 1);
    inner.extend_from_slice(plaintext);
    inner.push(content_type as u8);
    inner
}

/// Extract content type from inner plaintext (last non-zero byte).
fn parse_inner_plaintext(inner: &[u8]) -> Result<(ContentType, Vec<u8>), TlsError> {
    // Find the last non-zero byte (content type)
    let ct_pos = inner
        .iter()
        .rposition(|&b| b != 0)
        .ok_or_else(|| TlsError::RecordError("DTLS 1.3: empty inner plaintext".into()))?;
    let ct = match inner[ct_pos] {
        20 => ContentType::ChangeCipherSpec,
        21 => ContentType::Alert,
        22 => ContentType::Handshake,
        23 => ContentType::ApplicationData,
        _ => {
            return Err(TlsError::RecordError(
                "DTLS 1.3: invalid inner content type".into(),
            ))
        }
    };
    Ok((ct, inner[..ct_pos].to_vec()))
}

/// DTLS 1.3 record encryptor.
pub struct Dtls13RecordEncryptor {
    aead: Box<dyn TlsAead>,
    iv: Vec<u8>,
}

impl Drop for Dtls13RecordEncryptor {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

impl Dtls13RecordEncryptor {
    pub fn new(suite: CipherSuite, keys: &TrafficKeys) -> Result<Self, TlsError> {
        let aead = create_aead(suite, &keys.key)?;
        Ok(Self {
            aead,
            iv: keys.iv.clone(),
        })
    }

    /// Encrypt a plaintext record and return the serialized DTLS record bytes.
    pub fn encrypt_record(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
        epoch_state: &mut Dtls13EpochState,
    ) -> Result<Vec<u8>, TlsError> {
        if plaintext.len() > MAX_PLAINTEXT_LENGTH {
            return Err(TlsError::RecordError(
                "DTLS 1.3: plaintext too large".into(),
            ));
        }

        let epoch = epoch_state.epoch();
        let seq = epoch_state.next_write_seq()?;

        let inner = build_inner_plaintext(content_type, plaintext);
        let nonce = build_nonce(&self.iv, seq);

        // AAD uses the ciphertext length (inner + tag)
        let ct_len = (inner.len() + TAG_LEN) as u16;
        let aad = build_aad_dtls13(ContentType::ApplicationData, epoch, seq, ct_len);

        let ciphertext = self
            .aead
            .encrypt(&nonce, &aad, &inner)
            .map_err(|e| TlsError::RecordError(format!("DTLS 1.3 encrypt: {e}")))?;

        let record = Dtls13Record {
            content_type: ContentType::ApplicationData,
            epoch,
            sequence_number: seq,
            fragment: ciphertext,
        };
        Ok(serialize_dtls13_record(&record))
    }
}

/// DTLS 1.3 record decryptor.
pub struct Dtls13RecordDecryptor {
    aead: Box<dyn TlsAead>,
    iv: Vec<u8>,
}

impl Drop for Dtls13RecordDecryptor {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

impl Dtls13RecordDecryptor {
    pub fn new(suite: CipherSuite, keys: &TrafficKeys) -> Result<Self, TlsError> {
        let aead = create_aead(suite, &keys.key)?;
        Ok(Self {
            aead,
            iv: keys.iv.clone(),
        })
    }

    /// Decrypt a DTLS 1.3 record. Returns (content_type, plaintext).
    pub fn decrypt_record(
        &mut self,
        record: &Dtls13Record,
    ) -> Result<(ContentType, Vec<u8>), TlsError> {
        if record.fragment.len() < TAG_LEN {
            return Err(TlsError::RecordError(
                "DTLS 1.3: ciphertext too short".into(),
            ));
        }

        let nonce = build_nonce(&self.iv, record.sequence_number);

        let aad = build_aad_dtls13(
            ContentType::ApplicationData,
            record.epoch,
            record.sequence_number,
            record.fragment.len() as u16,
        );

        let inner = self
            .aead
            .decrypt(&nonce, &aad, &record.fragment)
            .map_err(|_| {
                TlsError::RecordError("DTLS 1.3 decrypt: authentication failed".into())
            })?;

        parse_inner_plaintext(&inner)
    }
}

/// Serialize a plaintext (unencrypted) DTLS 1.3 record.
pub fn seal_plaintext_dtls13(
    content_type: ContentType,
    plaintext: &[u8],
    epoch_state: &mut Dtls13EpochState,
) -> Result<Vec<u8>, TlsError> {
    let seq = epoch_state.next_write_seq()?;
    let record = Dtls13Record {
        content_type,
        epoch: epoch_state.epoch(),
        sequence_number: seq,
        fragment: plaintext.to_vec(),
    };
    Ok(serialize_dtls13_record(&record))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let keys = TrafficKeys {
            key: vec![0x42; 16],
            iv: vec![0x43; 12],
        };
        let mut enc =
            Dtls13RecordEncryptor::new(CipherSuite::TLS_AES_128_GCM_SHA256, &keys).unwrap();
        let mut dec =
            Dtls13RecordDecryptor::new(CipherSuite::TLS_AES_128_GCM_SHA256, &keys).unwrap();

        let mut epoch = Dtls13EpochState::new(3); // application epoch
        let plaintext = b"hello DTLS 1.3";
        let sealed = enc
            .encrypt_record(ContentType::ApplicationData, plaintext, &mut epoch)
            .unwrap();

        // Parse the sealed record
        let (record, _) = super::super::dtls13::parse_dtls13_record(&sealed).unwrap();
        assert_eq!(record.content_type, ContentType::ApplicationData);
        assert_eq!(record.epoch, 3);

        let (ct, pt) = dec.decrypt_record(&record).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_content_type_hiding() {
        let keys = TrafficKeys {
            key: vec![0x44; 16],
            iv: vec![0x45; 12],
        };
        let mut enc =
            Dtls13RecordEncryptor::new(CipherSuite::TLS_AES_128_GCM_SHA256, &keys).unwrap();
        let mut dec =
            Dtls13RecordDecryptor::new(CipherSuite::TLS_AES_128_GCM_SHA256, &keys).unwrap();

        let mut epoch = Dtls13EpochState::new(2);

        // Handshake content should appear as ApplicationData on wire
        let sealed = enc
            .encrypt_record(ContentType::Handshake, b"hs data", &mut epoch)
            .unwrap();
        let (record, _) = super::super::dtls13::parse_dtls13_record(&sealed).unwrap();
        assert_eq!(record.content_type, ContentType::ApplicationData);

        let (ct, pt) = dec.decrypt_record(&record).unwrap();
        assert_eq!(ct, ContentType::Handshake);
        assert_eq!(pt, b"hs data");
    }

    #[test]
    fn test_multiple_records_sequence() {
        let keys = TrafficKeys {
            key: vec![0x46; 32],
            iv: vec![0x47; 12],
        };
        let mut enc =
            Dtls13RecordEncryptor::new(CipherSuite::TLS_AES_256_GCM_SHA384, &keys).unwrap();
        let mut dec =
            Dtls13RecordDecryptor::new(CipherSuite::TLS_AES_256_GCM_SHA384, &keys).unwrap();
        let mut epoch = Dtls13EpochState::new(3);

        for i in 0u8..5 {
            let msg = vec![i; 20];
            let sealed = enc
                .encrypt_record(ContentType::ApplicationData, &msg, &mut epoch)
                .unwrap();
            let (record, _) = super::super::dtls13::parse_dtls13_record(&sealed).unwrap();
            assert_eq!(record.sequence_number, i as u64);
            let (_, pt) = dec.decrypt_record(&record).unwrap();
            assert_eq!(pt, msg);
        }
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let keys = TrafficKeys {
            key: vec![0x48; 16],
            iv: vec![0x49; 12],
        };
        let mut enc =
            Dtls13RecordEncryptor::new(CipherSuite::TLS_AES_128_GCM_SHA256, &keys).unwrap();
        let mut dec =
            Dtls13RecordDecryptor::new(CipherSuite::TLS_AES_128_GCM_SHA256, &keys).unwrap();
        let mut epoch = Dtls13EpochState::new(3);

        let sealed = enc
            .encrypt_record(ContentType::ApplicationData, b"secret", &mut epoch)
            .unwrap();
        let (mut record, _) = super::super::dtls13::parse_dtls13_record(&sealed).unwrap();
        record.fragment[0] ^= 0xFF; // tamper
        assert!(dec.decrypt_record(&record).is_err());
    }

    #[test]
    fn test_seal_plaintext() {
        let mut epoch = Dtls13EpochState::new(0);
        let data = b"ClientHello data";
        let sealed = seal_plaintext_dtls13(ContentType::Handshake, data, &mut epoch).unwrap();
        let (record, _) = super::super::dtls13::parse_dtls13_record(&sealed).unwrap();
        assert_eq!(record.content_type, ContentType::Handshake);
        assert_eq!(record.epoch, 0);
        assert_eq!(record.sequence_number, 0);
        assert_eq!(record.fragment, data);
    }

    #[test]
    fn test_chacha20_poly1305_roundtrip() {
        let keys = TrafficKeys {
            key: vec![0x50; 32],
            iv: vec![0x51; 12],
        };
        let mut enc =
            Dtls13RecordEncryptor::new(CipherSuite::TLS_CHACHA20_POLY1305_SHA256, &keys).unwrap();
        let mut dec =
            Dtls13RecordDecryptor::new(CipherSuite::TLS_CHACHA20_POLY1305_SHA256, &keys).unwrap();
        let mut epoch = Dtls13EpochState::new(3);

        let sealed = enc
            .encrypt_record(ContentType::ApplicationData, b"chacha20 test", &mut epoch)
            .unwrap();
        let (record, _) = super::super::dtls13::parse_dtls13_record(&sealed).unwrap();
        let (ct, pt) = dec.decrypt_record(&record).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(pt, b"chacha20 test");
    }
}
