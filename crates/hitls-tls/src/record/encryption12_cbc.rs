//! TLS 1.2 CBC MAC-then-encrypt record encryption (RFC 5246 §6.2.3.1).
//!
//! Record fragment = explicit_IV(16) || encrypted(plaintext || MAC || padding)
//! MAC = HMAC(mac_key, seq(8) || type(1) || version(2) || length(2) || plaintext)
//! Padding uses TLS scheme: all padding bytes = pad_len, last byte = pad_len.

use crate::record::{ContentType, Record};
use hitls_crypto::hmac::Hmac;
use hitls_crypto::provider::Digest;
use hitls_types::TlsError;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::encryption::{MAX_CIPHERTEXT_LENGTH, MAX_PLAINTEXT_LENGTH};

/// TLS 1.2 record version (0x0303).
const TLS12_VERSION: u16 = 0x0303;

/// AES block size (16 bytes).
const AES_BLOCK_SIZE: usize = 16;

/// Create an HMAC instance for the given MAC length.
/// 20 → HMAC-SHA1, 32 → HMAC-SHA256, 48 → HMAC-SHA384.
fn create_hmac(mac_len: usize, mac_key: &[u8]) -> Result<Hmac, TlsError> {
    match mac_len {
        20 => Hmac::new(
            || Box::new(hitls_crypto::sha1::Sha1::new()) as Box<dyn Digest>,
            mac_key,
        ),
        32 => Hmac::new(
            || Box::new(hitls_crypto::sha2::Sha256::new()) as Box<dyn Digest>,
            mac_key,
        ),
        48 => Hmac::new(
            || Box::new(hitls_crypto::sha2::Sha384::new()) as Box<dyn Digest>,
            mac_key,
        ),
        _ => {
            return Err(TlsError::RecordError(format!(
                "unsupported MAC length: {mac_len}"
            )))
        }
    }
    .map_err(TlsError::CryptoError)
}

/// Compute HMAC MAC for TLS 1.2 CBC records.
///
/// MAC = HMAC(mac_key, seq(8) || type(1) || version(2) || length(2) || plaintext)
fn compute_cbc_mac(
    mac_len: usize,
    mac_key: &[u8],
    seq: u64,
    content_type: ContentType,
    fragment: &[u8],
) -> Result<Vec<u8>, TlsError> {
    let mut hmac = create_hmac(mac_len, mac_key)?;

    hmac.update(&seq.to_be_bytes())
        .map_err(TlsError::CryptoError)?;
    hmac.update(&[content_type as u8])
        .map_err(TlsError::CryptoError)?;
    hmac.update(&TLS12_VERSION.to_be_bytes())
        .map_err(TlsError::CryptoError)?;
    hmac.update(&(fragment.len() as u16).to_be_bytes())
        .map_err(TlsError::CryptoError)?;
    hmac.update(fragment).map_err(TlsError::CryptoError)?;

    let mut mac = vec![0u8; mac_len];
    hmac.finish(&mut mac).map_err(TlsError::CryptoError)?;
    Ok(mac)
}

/// Build TLS-style padding for CBC (RFC 5246 §6.2.3.2).
///
/// padding_length = (block_size - ((data_len + 1) % block_size)) % block_size
/// Total padding = padding_length + 1 bytes, all set to padding_length.
fn build_tls_padding(data_len: usize) -> Vec<u8> {
    let padding_length = (AES_BLOCK_SIZE - ((data_len + 1) % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;
    vec![padding_length as u8; padding_length + 1]
}

/// AES-CBC encrypt in-place (data must be block-aligned).
fn aes_cbc_encrypt_raw(key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), TlsError> {
    use hitls_crypto::aes::AesKey;

    let cipher = AesKey::new(key).map_err(TlsError::CryptoError)?;
    let mut prev = [0u8; AES_BLOCK_SIZE];
    prev.copy_from_slice(iv);

    for chunk in data.chunks_mut(AES_BLOCK_SIZE) {
        for i in 0..AES_BLOCK_SIZE {
            chunk[i] ^= prev[i];
        }
        cipher.encrypt_block(chunk).map_err(TlsError::CryptoError)?;
        prev.copy_from_slice(chunk);
    }
    Ok(())
}

/// AES-CBC decrypt in-place (no padding removal).
fn aes_cbc_decrypt_raw(key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), TlsError> {
    use hitls_crypto::aes::AesKey;

    let cipher = AesKey::new(key).map_err(TlsError::CryptoError)?;
    let mut prev = [0u8; AES_BLOCK_SIZE];
    prev.copy_from_slice(iv);

    for chunk in data.chunks_mut(AES_BLOCK_SIZE) {
        let ct_copy: [u8; AES_BLOCK_SIZE] = chunk.try_into().unwrap();
        cipher.decrypt_block(chunk).map_err(TlsError::CryptoError)?;
        for i in 0..AES_BLOCK_SIZE {
            chunk[i] ^= prev[i];
        }
        prev = ct_copy;
    }
    Ok(())
}

/// TLS 1.2 CBC MAC-then-encrypt record encryptor.
pub struct RecordEncryptor12Cbc {
    enc_key: Vec<u8>,
    mac_key: Vec<u8>,
    mac_len: usize,
    seq: u64,
}

impl Drop for RecordEncryptor12Cbc {
    fn drop(&mut self) {
        self.enc_key.zeroize();
        self.mac_key.zeroize();
    }
}

impl RecordEncryptor12Cbc {
    pub fn new(enc_key: Vec<u8>, mac_key: Vec<u8>, mac_len: usize) -> Self {
        Self {
            enc_key,
            mac_key,
            mac_len,
            seq: 0,
        }
    }

    /// Encrypt a record with MAC-then-encrypt.
    ///
    /// Record fragment = explicit_IV(16) || encrypted(plaintext || MAC || padding)
    pub fn encrypt_record(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
    ) -> Result<Record, TlsError> {
        if plaintext.len() > MAX_PLAINTEXT_LENGTH {
            return Err(TlsError::RecordError("plaintext exceeds maximum".into()));
        }

        // Compute MAC over plaintext
        let mac = compute_cbc_mac(
            self.mac_len,
            &self.mac_key,
            self.seq,
            content_type,
            plaintext,
        )?;

        // Build: plaintext || MAC || TLS-padding
        let data_len = plaintext.len() + self.mac_len;
        let padding = build_tls_padding(data_len);
        let mut encrypt_data = Vec::with_capacity(data_len + padding.len());
        encrypt_data.extend_from_slice(plaintext);
        encrypt_data.extend_from_slice(&mac);
        encrypt_data.extend_from_slice(&padding);

        // Generate random explicit IV
        let mut iv = [0u8; AES_BLOCK_SIZE];
        getrandom::getrandom(&mut iv).map_err(|_| TlsError::RecordError("RNG failed".into()))?;

        // Encrypt in-place
        aes_cbc_encrypt_raw(&self.enc_key, &iv, &mut encrypt_data)?;

        // Fragment = explicit_IV || ciphertext
        let mut fragment = Vec::with_capacity(AES_BLOCK_SIZE + encrypt_data.len());
        fragment.extend_from_slice(&iv);
        fragment.extend_from_slice(&encrypt_data);

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

    pub fn sequence_number(&self) -> u64 {
        self.seq
    }
}

/// TLS 1.2 CBC record decryptor.
pub struct RecordDecryptor12Cbc {
    enc_key: Vec<u8>,
    mac_key: Vec<u8>,
    mac_len: usize,
    seq: u64,
}

impl Drop for RecordDecryptor12Cbc {
    fn drop(&mut self) {
        self.enc_key.zeroize();
        self.mac_key.zeroize();
    }
}

impl RecordDecryptor12Cbc {
    pub fn new(enc_key: Vec<u8>, mac_key: Vec<u8>, mac_len: usize) -> Self {
        Self {
            enc_key,
            mac_key,
            mac_len,
            seq: 0,
        }
    }

    /// Decrypt a TLS 1.2 CBC record.
    ///
    /// Fragment = explicit_IV(16) || encrypted(plaintext || MAC || padding)
    ///
    /// Uses constant-time padding and MAC validation to avoid padding oracle.
    pub fn decrypt_record(&mut self, record: &Record) -> Result<Vec<u8>, TlsError> {
        let fragment = &record.fragment;

        // Minimum: IV(16) + at least one block (mac + padding)
        let min_encrypted_len = (self.mac_len + 1).div_ceil(AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        if fragment.len() < AES_BLOCK_SIZE + min_encrypted_len {
            return Err(TlsError::RecordError("CBC record too short".into()));
        }
        if fragment.len() > MAX_CIPHERTEXT_LENGTH {
            return Err(TlsError::RecordError("record overflow".into()));
        }

        let iv = &fragment[..AES_BLOCK_SIZE];
        let encrypted = &fragment[AES_BLOCK_SIZE..];

        if encrypted.len() % AES_BLOCK_SIZE != 0 {
            return Err(TlsError::RecordError(
                "CBC ciphertext not block-aligned".into(),
            ));
        }

        let mut decrypted = encrypted.to_vec();
        aes_cbc_decrypt_raw(&self.enc_key, iv, &mut decrypted)?;

        // Read padding length from last byte
        let padding_length = decrypted[decrypted.len() - 1] as usize;

        // Check: padding_length + 1 + mac_len must fit
        let total_overhead = padding_length + 1 + self.mac_len;
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

        // Compute expected MAC (always compute to avoid timing leak)
        let expected_mac = compute_cbc_mac(
            self.mac_len,
            &self.mac_key,
            self.seq,
            record.content_type,
            &decrypted[..content_len],
        )?;

        // Compare received MAC (constant-time)
        let mac_slice = if good_length == 1 && content_len + self.mac_len <= decrypted.len() {
            &decrypted[content_len..content_len + self.mac_len]
        } else {
            // Dummy comparison against first mac_len bytes
            &decrypted[..self.mac_len]
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

// ===========================================================================
// Encrypt-Then-MAC (RFC 7366)
// ===========================================================================

/// TLS 1.2 Encrypt-Then-MAC record encryptor (RFC 7366).
///
/// Reverses the order: encrypt plaintext+padding first, then MAC over the ciphertext.
/// This eliminates padding oracle attacks.
pub struct RecordEncryptor12EtM {
    enc_key: Vec<u8>,
    mac_key: Vec<u8>,
    mac_len: usize,
    seq: u64,
}

impl Drop for RecordEncryptor12EtM {
    fn drop(&mut self) {
        self.enc_key.zeroize();
        self.mac_key.zeroize();
    }
}

impl RecordEncryptor12EtM {
    pub fn new(enc_key: Vec<u8>, mac_key: Vec<u8>, mac_len: usize) -> Self {
        Self {
            enc_key,
            mac_key,
            mac_len,
            seq: 0,
        }
    }

    /// Encrypt a record with Encrypt-Then-MAC.
    ///
    /// 1. Pad plaintext with TLS padding
    /// 2. Generate random IV, encrypt plaintext||padding with AES-CBC
    /// 3. Compute MAC over seq || type || version || length(IV+ciphertext) || IV || ciphertext
    /// 4. Fragment = IV || ciphertext || MAC
    pub fn encrypt_record(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
    ) -> Result<Record, TlsError> {
        if plaintext.len() > MAX_PLAINTEXT_LENGTH {
            return Err(TlsError::RecordError("plaintext exceeds maximum".into()));
        }

        // Pad plaintext
        let padding = build_tls_padding(plaintext.len());
        let mut encrypt_data = Vec::with_capacity(plaintext.len() + padding.len());
        encrypt_data.extend_from_slice(plaintext);
        encrypt_data.extend_from_slice(&padding);

        // Generate random explicit IV
        let mut iv = [0u8; AES_BLOCK_SIZE];
        getrandom::getrandom(&mut iv).map_err(|_| TlsError::RecordError("RNG failed".into()))?;

        // Encrypt in-place
        aes_cbc_encrypt_raw(&self.enc_key, &iv, &mut encrypt_data)?;

        // Compute MAC over: seq(8) || type(1) || version(2) || length(2) || IV || ciphertext
        // length = len(IV + ciphertext), i.e., the ciphertext portion before MAC
        let adjusted_len = (AES_BLOCK_SIZE + encrypt_data.len()) as u16;
        let mut hmac = create_hmac(self.mac_len, &self.mac_key)?;
        hmac.update(&self.seq.to_be_bytes())
            .map_err(TlsError::CryptoError)?;
        hmac.update(&[content_type as u8])
            .map_err(TlsError::CryptoError)?;
        hmac.update(&TLS12_VERSION.to_be_bytes())
            .map_err(TlsError::CryptoError)?;
        hmac.update(&adjusted_len.to_be_bytes())
            .map_err(TlsError::CryptoError)?;
        hmac.update(&iv).map_err(TlsError::CryptoError)?;
        hmac.update(&encrypt_data).map_err(TlsError::CryptoError)?;
        let mut mac = vec![0u8; self.mac_len];
        hmac.finish(&mut mac).map_err(TlsError::CryptoError)?;

        // Fragment = IV || ciphertext || MAC
        let mut fragment = Vec::with_capacity(AES_BLOCK_SIZE + encrypt_data.len() + self.mac_len);
        fragment.extend_from_slice(&iv);
        fragment.extend_from_slice(&encrypt_data);
        fragment.extend_from_slice(&mac);

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

    pub fn sequence_number(&self) -> u64 {
        self.seq
    }
}

/// TLS 1.2 Encrypt-Then-MAC record decryptor (RFC 7366).
pub struct RecordDecryptor12EtM {
    enc_key: Vec<u8>,
    mac_key: Vec<u8>,
    mac_len: usize,
    seq: u64,
}

impl Drop for RecordDecryptor12EtM {
    fn drop(&mut self) {
        self.enc_key.zeroize();
        self.mac_key.zeroize();
    }
}

impl RecordDecryptor12EtM {
    pub fn new(enc_key: Vec<u8>, mac_key: Vec<u8>, mac_len: usize) -> Self {
        Self {
            enc_key,
            mac_key,
            mac_len,
            seq: 0,
        }
    }

    /// Decrypt a TLS 1.2 Encrypt-Then-MAC record.
    ///
    /// 1. Split fragment: IV(16) || ciphertext(N) || MAC(mac_len)
    /// 2. Verify MAC over seq || type || version || length(IV+ciphertext) || IV || ciphertext
    /// 3. Decrypt ciphertext with AES-CBC
    /// 4. Remove TLS padding
    pub fn decrypt_record(&mut self, record: &Record) -> Result<Vec<u8>, TlsError> {
        let fragment = &record.fragment;

        // Minimum: IV(16) + one block + MAC
        let min_len = AES_BLOCK_SIZE + AES_BLOCK_SIZE + self.mac_len;
        if fragment.len() < min_len {
            return Err(TlsError::RecordError("ETM record too short".into()));
        }
        if fragment.len() > MAX_CIPHERTEXT_LENGTH {
            return Err(TlsError::RecordError("record overflow".into()));
        }

        // Split: IV || ciphertext || MAC
        let mac_start = fragment.len() - self.mac_len;
        let iv = &fragment[..AES_BLOCK_SIZE];
        let ciphertext = &fragment[AES_BLOCK_SIZE..mac_start];
        let received_mac = &fragment[mac_start..];

        if ciphertext.len() % AES_BLOCK_SIZE != 0 {
            return Err(TlsError::RecordError(
                "ETM ciphertext not block-aligned".into(),
            ));
        }

        // Verify MAC FIRST (this is the key security property of ETM)
        let adjusted_len = (AES_BLOCK_SIZE + ciphertext.len()) as u16;
        let mut hmac = create_hmac(self.mac_len, &self.mac_key)?;
        hmac.update(&self.seq.to_be_bytes())
            .map_err(TlsError::CryptoError)?;
        hmac.update(&[record.content_type as u8])
            .map_err(TlsError::CryptoError)?;
        hmac.update(&TLS12_VERSION.to_be_bytes())
            .map_err(TlsError::CryptoError)?;
        hmac.update(&adjusted_len.to_be_bytes())
            .map_err(TlsError::CryptoError)?;
        hmac.update(iv).map_err(TlsError::CryptoError)?;
        hmac.update(ciphertext).map_err(TlsError::CryptoError)?;
        let mut expected_mac = vec![0u8; self.mac_len];
        hmac.finish(&mut expected_mac)
            .map_err(TlsError::CryptoError)?;

        if !bool::from(received_mac.ct_eq(&expected_mac)) {
            return Err(TlsError::RecordError("bad record MAC".into()));
        }

        // MAC verified — now decrypt
        let mut decrypted = ciphertext.to_vec();
        aes_cbc_decrypt_raw(&self.enc_key, iv, &mut decrypted)?;

        // Remove TLS padding (since MAC was already verified, padding errors
        // can't be used as an oracle)
        if decrypted.is_empty() {
            return Err(TlsError::RecordError("empty decrypted data".into()));
        }
        let padding_length = decrypted[decrypted.len() - 1] as usize;
        let total_padding = padding_length + 1;
        if total_padding > decrypted.len() {
            return Err(TlsError::RecordError("invalid padding".into()));
        }

        // Verify padding bytes
        for &b in &decrypted[decrypted.len() - total_padding..] {
            if b != padding_length as u8 {
                return Err(TlsError::RecordError("invalid padding".into()));
            }
        }

        let plaintext_len = decrypted.len() - total_padding;
        let plaintext = decrypted[..plaintext_len].to_vec();

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbc_sha1_encrypt_decrypt_roundtrip() {
        let enc_key = vec![0x42u8; 16]; // AES-128
        let mac_key = vec![0xABu8; 20]; // HMAC-SHA1 key

        let mut enc = RecordEncryptor12Cbc::new(enc_key.clone(), mac_key.clone(), 20);
        let mut dec = RecordDecryptor12Cbc::new(enc_key, mac_key, 20);

        let plaintext = b"hello TLS 1.2 CBC-SHA";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        assert_eq!(record.content_type, ContentType::ApplicationData);
        assert_eq!(record.version, TLS12_VERSION);

        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cbc_sha256_encrypt_decrypt_roundtrip() {
        let enc_key = vec![0x42u8; 16]; // AES-128
        let mac_key = vec![0xABu8; 32]; // HMAC-SHA256 key

        let mut enc = RecordEncryptor12Cbc::new(enc_key.clone(), mac_key.clone(), 32);
        let mut dec = RecordDecryptor12Cbc::new(enc_key, mac_key, 32);

        let plaintext = b"hello TLS 1.2 CBC-SHA256";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();
        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cbc_sha384_encrypt_decrypt_roundtrip() {
        let enc_key = vec![0x42u8; 32]; // AES-256
        let mac_key = vec![0xABu8; 48]; // HMAC-SHA384 key

        let mut enc = RecordEncryptor12Cbc::new(enc_key.clone(), mac_key.clone(), 48);
        let mut dec = RecordDecryptor12Cbc::new(enc_key, mac_key, 48);

        let plaintext = b"hello TLS 1.2 CBC-SHA384";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();
        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cbc_tampered_mac_detected() {
        let enc_key = vec![0x42u8; 16];
        let mac_key = vec![0xABu8; 20];

        let mut enc = RecordEncryptor12Cbc::new(enc_key.clone(), mac_key.clone(), 20);
        // Different MAC key → MAC mismatch
        let mut dec = RecordDecryptor12Cbc::new(enc_key, vec![0xCDu8; 20], 20);

        let record = enc
            .encrypt_record(ContentType::ApplicationData, b"secret")
            .unwrap();
        assert!(dec.decrypt_record(&record).is_err());
    }

    #[test]
    fn test_cbc_tampered_ciphertext_detected() {
        let enc_key = vec![0x42u8; 16];
        let mac_key = vec![0xABu8; 32];

        let mut enc = RecordEncryptor12Cbc::new(enc_key.clone(), mac_key.clone(), 32);
        let mut dec = RecordDecryptor12Cbc::new(enc_key, mac_key, 32);

        let mut record = enc
            .encrypt_record(ContentType::ApplicationData, b"secret data")
            .unwrap();

        // Tamper with encrypted data (after IV)
        record.fragment[20] ^= 0x01;
        assert!(dec.decrypt_record(&record).is_err());
    }

    #[test]
    fn test_cbc_multiple_records_seq() {
        let enc_key = vec![0x42u8; 16];
        let mac_key = vec![0xABu8; 20];

        let mut enc = RecordEncryptor12Cbc::new(enc_key.clone(), mac_key.clone(), 20);
        let mut dec = RecordDecryptor12Cbc::new(enc_key, mac_key, 20);

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

    // ETM tests

    #[test]
    fn test_etm_encrypt_decrypt_roundtrip() {
        let enc_key = vec![0x42u8; 16]; // AES-128
        let mac_key = vec![0xABu8; 32]; // HMAC-SHA256

        let mut enc = RecordEncryptor12EtM::new(enc_key.clone(), mac_key.clone(), 32);
        let mut dec = RecordDecryptor12EtM::new(enc_key, mac_key, 32);

        let plaintext = b"hello TLS 1.2 ETM";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();

        assert_eq!(record.content_type, ContentType::ApplicationData);
        assert_eq!(record.version, TLS12_VERSION);

        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_etm_sha1_roundtrip() {
        let enc_key = vec![0x42u8; 16];
        let mac_key = vec![0xABu8; 20]; // HMAC-SHA1

        let mut enc = RecordEncryptor12EtM::new(enc_key.clone(), mac_key.clone(), 20);
        let mut dec = RecordDecryptor12EtM::new(enc_key, mac_key, 20);

        let plaintext = b"hello ETM SHA1";
        let record = enc
            .encrypt_record(ContentType::ApplicationData, plaintext)
            .unwrap();
        let decrypted = dec.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_etm_tampered_mac_detected() {
        let enc_key = vec![0x42u8; 16];
        let mac_key = vec![0xABu8; 32];

        let mut enc = RecordEncryptor12EtM::new(enc_key.clone(), mac_key.clone(), 32);
        let mut dec = RecordDecryptor12EtM::new(enc_key, mac_key, 32);

        let mut record = enc
            .encrypt_record(ContentType::ApplicationData, b"secret")
            .unwrap();

        // Tamper with MAC (last byte)
        let last = record.fragment.len() - 1;
        record.fragment[last] ^= 0x01;
        assert!(dec.decrypt_record(&record).is_err());
    }

    #[test]
    fn test_etm_tampered_ciphertext_detected() {
        let enc_key = vec![0x42u8; 16];
        let mac_key = vec![0xABu8; 32];

        let mut enc = RecordEncryptor12EtM::new(enc_key.clone(), mac_key.clone(), 32);
        let mut dec = RecordDecryptor12EtM::new(enc_key, mac_key, 32);

        let mut record = enc
            .encrypt_record(ContentType::ApplicationData, b"secret data")
            .unwrap();

        // Tamper with ciphertext (byte after IV, before MAC)
        record.fragment[20] ^= 0x01;
        assert!(dec.decrypt_record(&record).is_err());
    }

    #[test]
    fn test_etm_multiple_records_seq() {
        let enc_key = vec![0x42u8; 16];
        let mac_key = vec![0xABu8; 32];

        let mut enc = RecordEncryptor12EtM::new(enc_key.clone(), mac_key.clone(), 32);
        let mut dec = RecordDecryptor12EtM::new(enc_key, mac_key, 32);

        for i in 0..5 {
            let msg = format!("ETM message {i}");
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
