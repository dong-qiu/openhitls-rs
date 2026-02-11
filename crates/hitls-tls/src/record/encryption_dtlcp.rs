//! DTLCP record encryption (DTLS record layer + TLCP crypto).
//!
//! GCM: SM4-GCM with DTLS-style nonce (fixed_iv(4) || epoch(2) || seq(6))
//!      and AAD (epoch(2) || seq(6) || type(1) || version_0x0101(2) || len(2)).
//! CBC: SM4-CBC MAC-then-encrypt with HMAC-SM3, epoch/seq in MAC computation.

use super::dtls::DtlsRecord;
use super::encryption::{MAX_CIPHERTEXT_LENGTH, MAX_PLAINTEXT_LENGTH};
use super::ContentType;
use crate::crypt::aead::{create_sm4_gcm_aead, TlsAead};
use hitls_types::TlsError;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// DTLCP record version (same as TLCP).
pub const DTLCP_VERSION: u16 = 0x0101;

/// GCM explicit nonce length (epoch(2) + seq(6)).
const EXPLICIT_NONCE_LEN: usize = 8;

/// SM3 MAC output size (32 bytes).
const SM3_MAC_SIZE: usize = 32;

/// SM4 block size (16 bytes).
const SM4_BLOCK_SIZE: usize = 16;

// ─── Nonce / AAD Helpers ──────────────────────────────────

/// Build explicit nonce (8 bytes): `epoch(2) || seq(6)`.
fn build_explicit_nonce(epoch: u16, seq: u64) -> [u8; EXPLICIT_NONCE_LEN] {
    let mut nonce = [0u8; EXPLICIT_NONCE_LEN];
    nonce[..2].copy_from_slice(&epoch.to_be_bytes());
    let seq_bytes = seq.to_be_bytes();
    nonce[2..8].copy_from_slice(&seq_bytes[2..8]);
    nonce
}

/// Build GCM nonce (12 bytes): `fixed_iv(4) || epoch(2) || seq(6)`.
fn build_nonce_dtlcp(fixed_iv: &[u8], epoch: u16, seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(fixed_iv);
    nonce[4..12].copy_from_slice(&build_explicit_nonce(epoch, seq));
    nonce
}

/// Build DTLCP AAD (13 bytes):
/// `epoch(2) || seq(6) || type(1) || version_0x0101(2) || plaintext_len(2)`
fn build_aad_dtlcp(
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
    aad[9..11].copy_from_slice(&DTLCP_VERSION.to_be_bytes());
    aad[11..13].copy_from_slice(&plaintext_len.to_be_bytes());
    aad
}

/// Compute HMAC-SM3 MAC for DTLCP CBC records.
///
/// MAC = HMAC-SM3(mac_key, epoch(2) || seq(6) || type(1) || version(2) || len(2) || fragment)
fn compute_dtlcp_cbc_mac(
    mac_key: &[u8],
    epoch: u16,
    seq: u64,
    content_type: ContentType,
    fragment: &[u8],
) -> Result<Vec<u8>, TlsError> {
    use hitls_crypto::hmac::Hmac;
    use hitls_crypto::sm3::Sm3;

    let mut hmac =
        Hmac::new(|| Box::new(Sm3::new()) as Box<_>, mac_key).map_err(TlsError::CryptoError)?;

    hmac.update(&epoch.to_be_bytes())
        .map_err(TlsError::CryptoError)?;
    let seq_bytes = seq.to_be_bytes();
    hmac.update(&seq_bytes[2..8])
        .map_err(TlsError::CryptoError)?;
    hmac.update(&[content_type as u8])
        .map_err(TlsError::CryptoError)?;
    hmac.update(&DTLCP_VERSION.to_be_bytes())
        .map_err(TlsError::CryptoError)?;
    hmac.update(&(fragment.len() as u16).to_be_bytes())
        .map_err(TlsError::CryptoError)?;
    hmac.update(fragment).map_err(TlsError::CryptoError)?;

    let mut mac = vec![0u8; SM3_MAC_SIZE];
    hmac.finish(&mut mac).map_err(TlsError::CryptoError)?;
    Ok(mac)
}

/// Build TLS-style padding for CBC.
fn build_tls_padding(data_len: usize) -> Vec<u8> {
    let padding_length = (SM4_BLOCK_SIZE - ((data_len + 1) % SM4_BLOCK_SIZE)) % SM4_BLOCK_SIZE;
    vec![padding_length as u8; padding_length + 1]
}

/// Raw SM4-CBC encrypt in-place.
fn sm4_cbc_encrypt_raw(key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), TlsError> {
    let cipher = hitls_crypto::sm4::Sm4Key::new(key).map_err(TlsError::CryptoError)?;
    let mut prev = [0u8; SM4_BLOCK_SIZE];
    prev.copy_from_slice(iv);
    for chunk in data.chunks_mut(SM4_BLOCK_SIZE) {
        for i in 0..SM4_BLOCK_SIZE {
            chunk[i] ^= prev[i];
        }
        cipher.encrypt_block(chunk).map_err(TlsError::CryptoError)?;
        prev.copy_from_slice(chunk);
    }
    Ok(())
}

/// Raw SM4-CBC decrypt in-place.
fn sm4_cbc_decrypt_raw(key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), TlsError> {
    let cipher = hitls_crypto::sm4::Sm4Key::new(key).map_err(TlsError::CryptoError)?;
    let mut prev = [0u8; SM4_BLOCK_SIZE];
    prev.copy_from_slice(iv);
    for chunk in data.chunks_mut(SM4_BLOCK_SIZE) {
        let ct_copy: [u8; SM4_BLOCK_SIZE] = chunk.try_into().unwrap();
        cipher.decrypt_block(chunk).map_err(TlsError::CryptoError)?;
        for i in 0..SM4_BLOCK_SIZE {
            chunk[i] ^= prev[i];
        }
        prev = ct_copy;
    }
    Ok(())
}

// ─── GCM Encryptor / Decryptor ───────────────────────────

/// DTLCP GCM record encryptor.
pub struct DtlcpRecordEncryptorGcm {
    aead: Box<dyn TlsAead>,
    fixed_iv: Vec<u8>,
}

impl Drop for DtlcpRecordEncryptorGcm {
    fn drop(&mut self) {
        self.fixed_iv.zeroize();
    }
}

impl DtlcpRecordEncryptorGcm {
    pub fn new(key: &[u8], fixed_iv: Vec<u8>) -> Result<Self, TlsError> {
        let aead = create_sm4_gcm_aead(key)?;
        Ok(Self { aead, fixed_iv })
    }

    /// Encrypt a record. Fragment = `explicit_nonce(8) || ciphertext || tag(16)`.
    pub fn encrypt_record(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
        epoch: u16,
        seq: u64,
    ) -> Result<DtlsRecord, TlsError> {
        if plaintext.len() > MAX_PLAINTEXT_LENGTH {
            return Err(TlsError::RecordError("plaintext too large".into()));
        }
        let explicit_nonce = build_explicit_nonce(epoch, seq);
        let nonce = build_nonce_dtlcp(&self.fixed_iv, epoch, seq);
        let aad = build_aad_dtlcp(epoch, seq, content_type, plaintext.len() as u16);
        let ciphertext = self.aead.encrypt(&nonce, &aad, plaintext)?;
        let mut fragment = Vec::with_capacity(EXPLICIT_NONCE_LEN + ciphertext.len());
        fragment.extend_from_slice(&explicit_nonce);
        fragment.extend_from_slice(&ciphertext);
        Ok(DtlsRecord {
            content_type,
            version: DTLCP_VERSION,
            epoch,
            sequence_number: seq,
            fragment,
        })
    }
}

/// DTLCP GCM record decryptor.
pub struct DtlcpRecordDecryptorGcm {
    aead: Box<dyn TlsAead>,
    fixed_iv: Vec<u8>,
    tag_len: usize,
}

impl Drop for DtlcpRecordDecryptorGcm {
    fn drop(&mut self) {
        self.fixed_iv.zeroize();
    }
}

impl DtlcpRecordDecryptorGcm {
    pub fn new(key: &[u8], fixed_iv: Vec<u8>) -> Result<Self, TlsError> {
        let aead = create_sm4_gcm_aead(key)?;
        let tag_len = aead.tag_size();
        Ok(Self {
            aead,
            fixed_iv,
            tag_len,
        })
    }

    /// Decrypt a DTLCP record.
    pub fn decrypt_record(&mut self, record: &DtlsRecord) -> Result<Vec<u8>, TlsError> {
        if record.fragment.len() < EXPLICIT_NONCE_LEN + self.tag_len {
            return Err(TlsError::RecordError("DTLCP record too short".into()));
        }
        let ciphertext_with_tag = &record.fragment[EXPLICIT_NONCE_LEN..];
        let plaintext_len = ciphertext_with_tag.len() - self.tag_len;
        let nonce = build_nonce_dtlcp(&self.fixed_iv, record.epoch, record.sequence_number);
        let aad = build_aad_dtlcp(
            record.epoch,
            record.sequence_number,
            record.content_type,
            plaintext_len as u16,
        );
        let plaintext = self
            .aead
            .decrypt(&nonce, &aad, ciphertext_with_tag)
            .map_err(|_| TlsError::RecordError("DTLCP bad record MAC".into()))?;
        if plaintext.len() > MAX_PLAINTEXT_LENGTH {
            return Err(TlsError::RecordError("decrypted plaintext too large".into()));
        }
        Ok(plaintext)
    }
}

// ─── CBC Encryptor / Decryptor ───────────────────────────

/// DTLCP CBC MAC-then-encrypt record encryptor.
pub struct DtlcpRecordEncryptorCbc {
    enc_key: Vec<u8>,
    mac_key: Vec<u8>,
}

impl Drop for DtlcpRecordEncryptorCbc {
    fn drop(&mut self) {
        self.enc_key.zeroize();
        self.mac_key.zeroize();
    }
}

impl DtlcpRecordEncryptorCbc {
    pub fn new(enc_key: Vec<u8>, mac_key: Vec<u8>) -> Self {
        Self { enc_key, mac_key }
    }

    /// Encrypt a record. Fragment = `IV(16) || encrypted(plaintext || MAC(32) || padding)`.
    pub fn encrypt_record(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
        epoch: u16,
        seq: u64,
    ) -> Result<DtlsRecord, TlsError> {
        if plaintext.len() > MAX_PLAINTEXT_LENGTH {
            return Err(TlsError::RecordError("plaintext too large".into()));
        }
        let mac = compute_dtlcp_cbc_mac(&self.mac_key, epoch, seq, content_type, plaintext)?;
        let data_len = plaintext.len() + SM3_MAC_SIZE;
        let padding = build_tls_padding(data_len);
        let mut encrypt_data = Vec::with_capacity(data_len + padding.len());
        encrypt_data.extend_from_slice(plaintext);
        encrypt_data.extend_from_slice(&mac);
        encrypt_data.extend_from_slice(&padding);

        let mut iv = [0u8; SM4_BLOCK_SIZE];
        getrandom::getrandom(&mut iv)
            .map_err(|_| TlsError::RecordError("RNG failed".into()))?;
        sm4_cbc_encrypt_raw(&self.enc_key, &iv, &mut encrypt_data)?;

        let mut fragment = Vec::with_capacity(SM4_BLOCK_SIZE + encrypt_data.len());
        fragment.extend_from_slice(&iv);
        fragment.extend_from_slice(&encrypt_data);

        Ok(DtlsRecord {
            content_type,
            version: DTLCP_VERSION,
            epoch,
            sequence_number: seq,
            fragment,
        })
    }
}

/// DTLCP CBC record decryptor.
pub struct DtlcpRecordDecryptorCbc {
    enc_key: Vec<u8>,
    mac_key: Vec<u8>,
}

impl Drop for DtlcpRecordDecryptorCbc {
    fn drop(&mut self) {
        self.enc_key.zeroize();
        self.mac_key.zeroize();
    }
}

impl DtlcpRecordDecryptorCbc {
    pub fn new(enc_key: Vec<u8>, mac_key: Vec<u8>) -> Self {
        Self { enc_key, mac_key }
    }

    /// Decrypt a DTLCP CBC record.
    pub fn decrypt_record(
        &mut self,
        record: &DtlsRecord,
    ) -> Result<Vec<u8>, TlsError> {
        let fragment = &record.fragment;
        if fragment.len() < SM4_BLOCK_SIZE + SM4_BLOCK_SIZE * 3 {
            return Err(TlsError::RecordError("CBC record too short".into()));
        }
        if fragment.len() > MAX_CIPHERTEXT_LENGTH {
            return Err(TlsError::RecordError("record overflow".into()));
        }
        let iv = &fragment[..SM4_BLOCK_SIZE];
        let encrypted = &fragment[SM4_BLOCK_SIZE..];
        if encrypted.len() % SM4_BLOCK_SIZE != 0 {
            return Err(TlsError::RecordError("CBC not block-aligned".into()));
        }
        let mut decrypted = encrypted.to_vec();
        sm4_cbc_decrypt_raw(&self.enc_key, iv, &mut decrypted)?;

        let padding_length = decrypted[decrypted.len() - 1] as usize;
        let total_overhead = padding_length + 1 + SM3_MAC_SIZE;
        let good_length = if total_overhead <= decrypted.len() { 1u8 } else { 0u8 };

        let pad_start = decrypted.len().saturating_sub(padding_length + 1);
        let mut pad_ok = good_length;
        for &b in &decrypted[pad_start..] {
            pad_ok &= b.ct_eq(&(padding_length as u8)).unwrap_u8();
        }

        let content_len = if good_length == 1 {
            decrypted.len() - total_overhead
        } else {
            0
        };

        let expected_mac = compute_dtlcp_cbc_mac(
            &self.mac_key,
            record.epoch,
            record.sequence_number,
            record.content_type,
            &decrypted[..content_len],
        )?;

        let mac_slice = if good_length == 1 {
            &decrypted[content_len..content_len + SM3_MAC_SIZE]
        } else {
            &decrypted[..SM3_MAC_SIZE]
        };
        let mac_ok = mac_slice.ct_eq(expected_mac.as_slice()).unwrap_u8();

        if pad_ok & mac_ok != 1 {
            return Err(TlsError::RecordError("bad record MAC".into()));
        }

        let plaintext = decrypted[..content_len].to_vec();
        if plaintext.len() > MAX_PLAINTEXT_LENGTH {
            return Err(TlsError::RecordError("decrypted plaintext too large".into()));
        }
        Ok(plaintext)
    }
}

// ─── Dispatch Enum ────────────────────────────────────────

/// DTLCP encryptor (dispatches CBC vs GCM).
pub enum DtlcpEncryptor {
    Gcm(DtlcpRecordEncryptorGcm),
    Cbc(DtlcpRecordEncryptorCbc),
}

impl DtlcpEncryptor {
    pub fn encrypt_record(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
        epoch: u16,
        seq: u64,
    ) -> Result<DtlsRecord, TlsError> {
        match self {
            Self::Gcm(e) => e.encrypt_record(content_type, plaintext, epoch, seq),
            Self::Cbc(e) => e.encrypt_record(content_type, plaintext, epoch, seq),
        }
    }
}

/// DTLCP decryptor (dispatches CBC vs GCM).
pub enum DtlcpDecryptor {
    Gcm(DtlcpRecordDecryptorGcm),
    Cbc(DtlcpRecordDecryptorCbc),
}

impl DtlcpDecryptor {
    pub fn decrypt_record(&mut self, record: &DtlsRecord) -> Result<Vec<u8>, TlsError> {
        match self {
            Self::Gcm(e) => e.decrypt_record(record),
            Self::Cbc(e) => e.decrypt_record(record),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dtlcp_gcm_encrypt_decrypt() {
        let key = [0x42u8; 16];
        let iv = vec![0x01, 0x02, 0x03, 0x04];
        let mut enc = DtlcpRecordEncryptorGcm::new(&key, iv.clone()).unwrap();
        let mut dec = DtlcpRecordDecryptorGcm::new(&key, iv).unwrap();

        let plaintext = b"hello DTLCP GCM";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext, 1, 42)
            .unwrap();
        assert_eq!(record.version, DTLCP_VERSION);
        assert_eq!(record.epoch, 1);
        assert_eq!(record.sequence_number, 42);

        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dtlcp_cbc_encrypt_decrypt() {
        let enc_key = vec![0x42u8; 16];
        let mac_key = vec![0x99u8; 32];
        let mut encryptor =
            DtlcpRecordEncryptorCbc::new(enc_key.clone(), mac_key.clone());
        let mut decryptor =
            DtlcpRecordDecryptorCbc::new(enc_key, mac_key);

        let plaintext = b"hello DTLCP CBC";
        let record = encryptor
            .encrypt_record(ContentType::ApplicationData, plaintext, 1, 0)
            .unwrap();
        assert_eq!(record.version, DTLCP_VERSION);

        let decrypted = decryptor.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dtlcp_gcm_tampered_ciphertext() {
        let key = [0x42u8; 16];
        let iv = vec![0x01, 0x02, 0x03, 0x04];
        let mut enc = DtlcpRecordEncryptorGcm::new(&key, iv.clone()).unwrap();
        let mut dec = DtlcpRecordDecryptorGcm::new(&key, iv).unwrap();

        let mut record = enc
            .encrypt_record(ContentType::ApplicationData, b"test", 0, 0)
            .unwrap();
        // Tamper with ciphertext
        if let Some(byte) = record.fragment.get_mut(10) {
            *byte ^= 0xFF;
        }
        assert!(dec.decrypt_record(&record).is_err());
    }

    #[test]
    fn test_dtlcp_cbc_tampered_mac() {
        let enc_key = vec![0x42u8; 16];
        let mac_key = vec![0x99u8; 32];
        let mut encryptor = DtlcpRecordEncryptorCbc::new(enc_key.clone(), mac_key.clone());
        let mut decryptor = DtlcpRecordDecryptorCbc::new(enc_key, vec![0xAAu8; 32]); // wrong key

        let record = encryptor
            .encrypt_record(ContentType::ApplicationData, b"test", 0, 0)
            .unwrap();
        assert!(decryptor.decrypt_record(&record).is_err());
    }

    #[test]
    fn test_dtlcp_dispatch_enum() {
        let key = [0x42u8; 16];
        let iv = vec![0x01, 0x02, 0x03, 0x04];
        let mut enc = DtlcpEncryptor::Gcm(DtlcpRecordEncryptorGcm::new(&key, iv.clone()).unwrap());
        let mut dec = DtlcpDecryptor::Gcm(DtlcpRecordDecryptorGcm::new(&key, iv).unwrap());

        let record = enc
            .encrypt_record(ContentType::ApplicationData, b"dispatch", 1, 5)
            .unwrap();
        let plain = dec.decrypt_record(&record).unwrap();
        assert_eq!(plain, b"dispatch");
    }

    #[test]
    fn test_aad_format() {
        let aad = build_aad_dtlcp(1, 42, ContentType::ApplicationData, 100);
        assert_eq!(aad[0..2], 1u16.to_be_bytes());
        assert_eq!(aad[8], ContentType::ApplicationData as u8);
        assert_eq!(aad[9..11], DTLCP_VERSION.to_be_bytes());
        assert_eq!(aad[11..13], 100u16.to_be_bytes());
    }
}
