//! TLCP (GM/T 0024) record encryption.
//!
//! CBC suites: MAC-then-encrypt with HMAC-SM3 + SM4-CBC.
//! GCM suites: SM4-GCM AEAD (same pattern as TLS 1.2 AES-GCM).

use crate::crypt::aead::{create_sm4_gcm_aead, TlsAead};
use crate::record::{ContentType, Record};
use hitls_types::TlsError;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::encryption::{MAX_CIPHERTEXT_LENGTH, MAX_PLAINTEXT_LENGTH};

/// TLCP record version (0x0101).
pub const TLCP_VERSION: u16 = 0x0101;

/// SM3 MAC output size (32 bytes).
const SM3_MAC_SIZE: usize = 32;

/// SM4 block size (16 bytes).
const SM4_BLOCK_SIZE: usize = 16;

/// GCM explicit nonce length (8 bytes).
const GCM_EXPLICIT_NONCE_LEN: usize = 8;

// ─── Helpers ──────────────────────────────────────────────

/// Compute HMAC-SM3 MAC for TLCP CBC records.
///
/// MAC = HMAC-SM3(mac_key, seq(8) || type(1) || version(2) || length(2) || fragment)
fn compute_cbc_mac(
    mac_key: &[u8],
    seq: u64,
    content_type: ContentType,
    fragment: &[u8],
) -> Result<Vec<u8>, TlsError> {
    use hitls_crypto::hmac::Hmac;
    use hitls_crypto::sm3::Sm3;

    let mut hmac =
        Hmac::new(|| Box::new(Sm3::new()) as Box<_>, mac_key).map_err(TlsError::CryptoError)?;

    hmac.update(&seq.to_be_bytes())
        .map_err(TlsError::CryptoError)?;
    hmac.update(&[content_type as u8])
        .map_err(TlsError::CryptoError)?;
    hmac.update(&TLCP_VERSION.to_be_bytes())
        .map_err(TlsError::CryptoError)?;
    hmac.update(&(fragment.len() as u16).to_be_bytes())
        .map_err(TlsError::CryptoError)?;
    hmac.update(fragment).map_err(TlsError::CryptoError)?;

    let mut mac = vec![0u8; SM3_MAC_SIZE];
    hmac.finish(&mut mac).map_err(TlsError::CryptoError)?;
    Ok(mac)
}

/// Build TLS-style padding for CBC.
///
/// padding_length = (block_size - ((data_len + 1) % block_size)) % block_size
/// Total padding = padding_length + 1 bytes, all set to padding_length.
fn build_tls_padding(data_len: usize) -> Vec<u8> {
    let padding_length = (SM4_BLOCK_SIZE - ((data_len + 1) % SM4_BLOCK_SIZE)) % SM4_BLOCK_SIZE;
    vec![padding_length as u8; padding_length + 1]
}

/// Raw SM4-CBC encrypt in-place (no padding; data must be block-aligned).
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

/// Raw SM4-CBC decrypt in-place (no padding removal).
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

/// Build TLCP AAD (13 bytes, same layout as TLS 1.2 but version = 0x0101).
fn build_aad_tlcp(seq: u64, content_type: ContentType, plaintext_len: u16) -> [u8; 13] {
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&seq.to_be_bytes());
    aad[8] = content_type as u8;
    aad[9..11].copy_from_slice(&TLCP_VERSION.to_be_bytes());
    aad[11..13].copy_from_slice(&plaintext_len.to_be_bytes());
    aad
}

/// Build GCM nonce: fixed_iv(4) || explicit_nonce(8).
fn build_nonce_tlcp(fixed_iv: &[u8], explicit_nonce: &[u8; GCM_EXPLICIT_NONCE_LEN]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(fixed_iv);
    nonce[4..12].copy_from_slice(explicit_nonce);
    nonce
}

// ─── CBC MAC-then-encrypt ─────────────────────────────────

/// TLCP CBC MAC-then-encrypt record encryptor.
pub struct RecordEncryptorTlcpCbc {
    enc_key: Vec<u8>,
    mac_key: Vec<u8>,
    seq: u64,
}

impl Drop for RecordEncryptorTlcpCbc {
    fn drop(&mut self) {
        self.enc_key.zeroize();
        self.mac_key.zeroize();
    }
}

impl RecordEncryptorTlcpCbc {
    pub fn new(enc_key: Vec<u8>, mac_key: Vec<u8>) -> Self {
        Self {
            enc_key,
            mac_key,
            seq: 0,
        }
    }

    /// Encrypt a record with MAC-then-encrypt.
    ///
    /// Record fragment = explicit_IV(16) || encrypted(plaintext || MAC(32) || padding)
    pub fn encrypt_record(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
    ) -> Result<Record, TlsError> {
        if plaintext.len() > MAX_PLAINTEXT_LENGTH {
            return Err(TlsError::RecordError("plaintext exceeds maximum".into()));
        }

        // Compute MAC over plaintext
        let mac = compute_cbc_mac(&self.mac_key, self.seq, content_type, plaintext)?;

        // Build: plaintext || MAC || TLS-padding
        let data_len = plaintext.len() + SM3_MAC_SIZE;
        let padding = build_tls_padding(data_len);
        let mut encrypt_data = Vec::with_capacity(data_len + padding.len());
        encrypt_data.extend_from_slice(plaintext);
        encrypt_data.extend_from_slice(&mac);
        encrypt_data.extend_from_slice(&padding);

        // Generate random explicit IV
        let mut iv = [0u8; SM4_BLOCK_SIZE];
        getrandom::getrandom(&mut iv).map_err(|_| TlsError::RecordError("RNG failed".into()))?;

        // Encrypt in-place
        sm4_cbc_encrypt_raw(&self.enc_key, &iv, &mut encrypt_data)?;

        // Fragment = explicit_IV || ciphertext
        let mut fragment = Vec::with_capacity(SM4_BLOCK_SIZE + encrypt_data.len());
        fragment.extend_from_slice(&iv);
        fragment.extend_from_slice(&encrypt_data);

        if self.seq == u64::MAX {
            return Err(TlsError::RecordError("sequence number overflow".into()));
        }
        self.seq += 1;

        Ok(Record {
            content_type,
            version: TLCP_VERSION,
            fragment,
        })
    }

    pub fn sequence_number(&self) -> u64 {
        self.seq
    }
}

// ─── CBC Decryptor ────────────────────────────────────────

/// TLCP CBC record decryptor.
pub struct RecordDecryptorTlcpCbc {
    enc_key: Vec<u8>,
    mac_key: Vec<u8>,
    seq: u64,
}

impl Drop for RecordDecryptorTlcpCbc {
    fn drop(&mut self) {
        self.enc_key.zeroize();
        self.mac_key.zeroize();
    }
}

impl RecordDecryptorTlcpCbc {
    pub fn new(enc_key: Vec<u8>, mac_key: Vec<u8>) -> Self {
        Self {
            enc_key,
            mac_key,
            seq: 0,
        }
    }

    /// Decrypt a TLCP CBC record.
    ///
    /// Fragment = explicit_IV(16) || encrypted(plaintext || MAC(32) || padding)
    pub fn decrypt_record(&mut self, record: &Record) -> Result<Vec<u8>, TlsError> {
        let fragment = &record.fragment;

        // Minimum: IV(16) + one block of encrypted data (16)
        // Actually need at least: IV + enough for MAC(32) + 1 byte padding = IV + 48
        if fragment.len() < SM4_BLOCK_SIZE + SM4_BLOCK_SIZE * 3 {
            return Err(TlsError::RecordError("CBC record too short".into()));
        }
        if fragment.len() > MAX_CIPHERTEXT_LENGTH {
            return Err(TlsError::RecordError("record overflow".into()));
        }

        let iv = &fragment[..SM4_BLOCK_SIZE];
        let encrypted = &fragment[SM4_BLOCK_SIZE..];

        if encrypted.len() % SM4_BLOCK_SIZE != 0 {
            return Err(TlsError::RecordError(
                "CBC ciphertext not block-aligned".into(),
            ));
        }

        let mut decrypted = encrypted.to_vec();
        sm4_cbc_decrypt_raw(&self.enc_key, iv, &mut decrypted)?;

        // Read padding length from last byte
        let padding_length = decrypted[decrypted.len() - 1] as usize;

        // Check: padding_length + 1 + MAC_SIZE must fit
        let total_overhead = padding_length + 1 + SM3_MAC_SIZE;
        let good_length = if total_overhead <= decrypted.len() {
            1u8
        } else {
            0u8
        };

        // Verify all padding bytes (constant-time)
        let pad_start = decrypted.len().saturating_sub(padding_length + 1);
        let mut pad_ok = good_length;
        for &b in &decrypted[pad_start..] {
            pad_ok &= b.ct_eq(&(padding_length as u8)).unwrap_u8();
        }

        // Compute content length
        let content_len = if good_length == 1 {
            decrypted.len() - total_overhead
        } else {
            0
        };

        // Compute expected MAC
        let expected_mac = compute_cbc_mac(
            &self.mac_key,
            self.seq,
            record.content_type,
            &decrypted[..content_len],
        )?;

        // Compare received MAC (constant-time)
        let mac_slice = if good_length == 1 {
            &decrypted[content_len..content_len + SM3_MAC_SIZE]
        } else {
            // Dummy comparison against first SM3_MAC_SIZE bytes
            &decrypted[..SM3_MAC_SIZE]
        };
        let mac_ok = mac_slice.ct_eq(expected_mac.as_slice()).unwrap_u8();

        if pad_ok & mac_ok != 1 {
            return Err(TlsError::RecordError("bad record MAC".into()));
        }

        let plaintext = decrypted[..content_len].to_vec();

        if plaintext.len() > MAX_PLAINTEXT_LENGTH {
            return Err(TlsError::RecordError(
                "decrypted plaintext too large".into(),
            ));
        }

        if self.seq == u64::MAX {
            return Err(TlsError::RecordError("sequence number overflow".into()));
        }
        self.seq += 1;

        Ok(plaintext)
    }

    pub fn sequence_number(&self) -> u64 {
        self.seq
    }
}

// ─── GCM AEAD ─────────────────────────────────────────────

/// TLCP GCM record encryptor (SM4-GCM).
pub struct RecordEncryptorTlcpGcm {
    aead: Box<dyn TlsAead>,
    fixed_iv: Vec<u8>,
    seq: u64,
}

impl Drop for RecordEncryptorTlcpGcm {
    fn drop(&mut self) {
        self.fixed_iv.zeroize();
    }
}

impl RecordEncryptorTlcpGcm {
    pub fn new(key: &[u8], fixed_iv: Vec<u8>) -> Result<Self, TlsError> {
        let aead = create_sm4_gcm_aead(key)?;
        Ok(Self {
            aead,
            fixed_iv,
            seq: 0,
        })
    }

    /// Encrypt a record with SM4-GCM.
    ///
    /// Record fragment = explicit_nonce(8) || ciphertext || tag(16).
    pub fn encrypt_record(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
    ) -> Result<Record, TlsError> {
        if plaintext.len() > MAX_PLAINTEXT_LENGTH {
            return Err(TlsError::RecordError("plaintext exceeds maximum".into()));
        }

        let explicit_nonce = self.seq.to_be_bytes();
        let nonce = build_nonce_tlcp(&self.fixed_iv, &explicit_nonce);
        let aad = build_aad_tlcp(self.seq, content_type, plaintext.len() as u16);

        let ciphertext = self.aead.encrypt(&nonce, &aad, plaintext)?;

        let mut fragment = Vec::with_capacity(GCM_EXPLICIT_NONCE_LEN + ciphertext.len());
        fragment.extend_from_slice(&explicit_nonce);
        fragment.extend_from_slice(&ciphertext);

        if self.seq == u64::MAX {
            return Err(TlsError::RecordError("sequence number overflow".into()));
        }
        self.seq += 1;

        Ok(Record {
            content_type,
            version: TLCP_VERSION,
            fragment,
        })
    }

    pub fn sequence_number(&self) -> u64 {
        self.seq
    }
}

/// TLCP GCM record decryptor (SM4-GCM).
pub struct RecordDecryptorTlcpGcm {
    aead: Box<dyn TlsAead>,
    fixed_iv: Vec<u8>,
    seq: u64,
    tag_len: usize,
}

impl Drop for RecordDecryptorTlcpGcm {
    fn drop(&mut self) {
        self.fixed_iv.zeroize();
    }
}

impl RecordDecryptorTlcpGcm {
    pub fn new(key: &[u8], fixed_iv: Vec<u8>) -> Result<Self, TlsError> {
        let aead = create_sm4_gcm_aead(key)?;
        let tag_len = aead.tag_size();
        Ok(Self {
            aead,
            fixed_iv,
            seq: 0,
            tag_len,
        })
    }

    /// Decrypt a TLCP GCM record.
    ///
    /// Fragment = explicit_nonce(8) || ciphertext || tag(16).
    pub fn decrypt_record(&mut self, record: &Record) -> Result<Vec<u8>, TlsError> {
        if record.fragment.len() < GCM_EXPLICIT_NONCE_LEN + self.tag_len {
            return Err(TlsError::RecordError("encrypted record too short".into()));
        }
        if record.fragment.len() > MAX_CIPHERTEXT_LENGTH {
            return Err(TlsError::RecordError("record overflow".into()));
        }

        let explicit_nonce: [u8; GCM_EXPLICIT_NONCE_LEN] = record.fragment
            [..GCM_EXPLICIT_NONCE_LEN]
            .try_into()
            .unwrap();
        let ciphertext_with_tag = &record.fragment[GCM_EXPLICIT_NONCE_LEN..];

        let plaintext_len = ciphertext_with_tag.len() - self.tag_len;
        let nonce = build_nonce_tlcp(&self.fixed_iv, &explicit_nonce);
        let aad = build_aad_tlcp(self.seq, record.content_type, plaintext_len as u16);

        let plaintext = self
            .aead
            .decrypt(&nonce, &aad, ciphertext_with_tag)
            .map_err(|_| TlsError::RecordError("bad record MAC".into()))?;

        if plaintext.len() > MAX_PLAINTEXT_LENGTH {
            return Err(TlsError::RecordError(
                "decrypted plaintext too large".into(),
            ));
        }

        if self.seq == u64::MAX {
            return Err(TlsError::RecordError("sequence number overflow".into()));
        }
        self.seq += 1;

        Ok(plaintext)
    }

    pub fn sequence_number(&self) -> u64 {
        self.seq
    }
}

// ─── Unified TLCP Encryptor/Decryptor ─────────────────────

/// Unified TLCP record encryptor (dispatches CBC vs GCM).
pub enum TlcpEncryptor {
    Cbc(RecordEncryptorTlcpCbc),
    Gcm(RecordEncryptorTlcpGcm),
}

impl TlcpEncryptor {
    pub fn encrypt_record(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
    ) -> Result<Record, TlsError> {
        match self {
            Self::Cbc(e) => e.encrypt_record(content_type, plaintext),
            Self::Gcm(e) => e.encrypt_record(content_type, plaintext),
        }
    }
}

/// Unified TLCP record decryptor (dispatches CBC vs GCM).
pub enum TlcpDecryptor {
    Cbc(RecordDecryptorTlcpCbc),
    Gcm(RecordDecryptorTlcpGcm),
}

impl TlcpDecryptor {
    pub fn decrypt_record(&mut self, record: &Record) -> Result<Vec<u8>, TlsError> {
        match self {
            Self::Cbc(d) => d.decrypt_record(record),
            Self::Gcm(d) => d.decrypt_record(record),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbc_mac_then_encrypt_roundtrip() {
        let enc_key = vec![0x42u8; 16];
        let mac_key = vec![0xABu8; 32];

        let mut enc = RecordEncryptorTlcpCbc::new(enc_key.clone(), mac_key.clone());
        let mut dec = RecordDecryptorTlcpCbc::new(enc_key, mac_key);

        let plaintext = b"hello TLCP CBC MAC-then-encrypt";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        assert_eq!(record.content_type, ContentType::ApplicationData);
        assert_eq!(record.version, TLCP_VERSION);
        // Fragment = IV(16) + encrypted(31 + 32 + padding)
        // 31 + 32 = 63, need 64 → padding_length = 0, total padding = 1 → 64 bytes
        assert_eq!(record.fragment.len(), 16 + 64);

        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cbc_tampered_mac_detected() {
        let enc_key = vec![0x42u8; 16];
        let mac_key = vec![0xABu8; 32];

        let mut enc = RecordEncryptorTlcpCbc::new(enc_key.clone(), mac_key.clone());
        // Use different mac_key for decryption → MAC mismatch
        let mut dec = RecordDecryptorTlcpCbc::new(enc_key, vec![0xCDu8; 32]);

        let record = enc
            .encrypt_record(ContentType::ApplicationData, b"secret")
            .unwrap();
        assert!(dec.decrypt_record(&record).is_err());
    }

    #[test]
    fn test_cbc_tampered_ciphertext_detected() {
        let enc_key = vec![0x42u8; 16];
        let mac_key = vec![0xABu8; 32];

        let mut enc = RecordEncryptorTlcpCbc::new(enc_key.clone(), mac_key.clone());
        let mut dec = RecordDecryptorTlcpCbc::new(enc_key, mac_key);

        let mut record = enc
            .encrypt_record(ContentType::ApplicationData, b"secret data")
            .unwrap();

        // Tamper with encrypted data (after IV)
        record.fragment[20] ^= 0x01;
        assert!(dec.decrypt_record(&record).is_err());
    }

    #[test]
    fn test_cbc_empty_plaintext() {
        let enc_key = vec![0x42u8; 16];
        let mac_key = vec![0xABu8; 32];

        let mut enc = RecordEncryptorTlcpCbc::new(enc_key.clone(), mac_key.clone());
        let mut dec = RecordDecryptorTlcpCbc::new(enc_key, mac_key);

        let record = enc
            .encrypt_record(ContentType::ApplicationData, b"")
            .unwrap();

        // IV(16) + encrypted(MAC(32) + padding(16)) = 16 + 48 = 64
        assert_eq!(record.fragment.len(), 64);

        let decrypted = dec.decrypt_record(&record).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_gcm_tlcp_encrypt_decrypt_roundtrip() {
        let key = vec![0x42u8; 16];
        let iv = vec![0xABu8; 4];

        let mut enc = RecordEncryptorTlcpGcm::new(&key, iv.clone()).unwrap();
        let mut dec = RecordDecryptorTlcpGcm::new(&key, iv).unwrap();

        let plaintext = b"hello TLCP GCM";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        assert_eq!(record.version, TLCP_VERSION);
        // Fragment = explicit_nonce(8) + ciphertext(14) + tag(16) = 38
        assert_eq!(record.fragment.len(), 8 + plaintext.len() + 16);

        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_gcm_tlcp_tampered_tag() {
        let key = vec![0x42u8; 16];
        let iv = vec![0xABu8; 4];

        let mut enc = RecordEncryptorTlcpGcm::new(&key, iv.clone()).unwrap();
        let mut dec = RecordDecryptorTlcpGcm::new(&key, iv).unwrap();

        let mut record = enc
            .encrypt_record(ContentType::ApplicationData, b"secret")
            .unwrap();

        // Tamper with tag (last byte)
        let len = record.fragment.len();
        record.fragment[len - 1] ^= 0x01;
        assert!(dec.decrypt_record(&record).is_err());
    }

    #[test]
    fn test_aad_version_0x0101() {
        let aad = build_aad_tlcp(0, ContentType::ApplicationData, 100);
        // Version should be 0x0101
        assert_eq!(aad[9], 0x01);
        assert_eq!(aad[10], 0x01);
    }

    #[test]
    fn test_multiple_records_seq_increment() {
        let enc_key = vec![0x42u8; 16];
        let mac_key = vec![0xABu8; 32];

        let mut enc = RecordEncryptorTlcpCbc::new(enc_key.clone(), mac_key.clone());
        let mut dec = RecordDecryptorTlcpCbc::new(enc_key, mac_key);

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
}
