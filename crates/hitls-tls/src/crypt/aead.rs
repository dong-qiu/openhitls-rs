//! TLS AEAD cipher abstraction.
//!
//! Wraps AES-GCM and ChaCha20-Poly1305 behind a common trait.

use crate::CipherSuite;
use hitls_types::TlsError;

/// Trait for TLS record-layer AEAD operations.
pub trait TlsAead: Send + Sync {
    /// Encrypt plaintext with AEAD. Returns `ciphertext || tag`.
    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TlsError>;

    /// Decrypt `ciphertext || tag` with AEAD. Returns plaintext.
    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, TlsError>;

    /// Tag size in bytes.
    fn tag_size(&self) -> usize;
}

/// AES-GCM AEAD (128-bit or 256-bit key).
/// Stores pre-expanded AES key and GHASH table to avoid per-record key expansion.
pub struct AesGcmAead {
    cipher: hitls_crypto::aes::AesKey,
    table: hitls_crypto::modes::gcm::GhashTable,
}

impl AesGcmAead {
    pub fn new(key: &[u8]) -> Result<Self, TlsError> {
        if key.len() != 16 && key.len() != 32 {
            return Err(TlsError::HandshakeFailed(
                "AES-GCM: invalid key length".into(),
            ));
        }
        let cipher = hitls_crypto::aes::AesKey::new(key).map_err(TlsError::CryptoError)?;
        let table = hitls_crypto::modes::gcm::GhashTable::from_cipher(&cipher)
            .map_err(TlsError::CryptoError)?;
        Ok(Self { cipher, table })
    }
}

impl TlsAead for AesGcmAead {
    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        hitls_crypto::modes::gcm::gcm_encrypt_with_aes(
            &self.cipher,
            &self.table,
            nonce,
            aad,
            plaintext,
        )
        .map_err(TlsError::CryptoError)
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        hitls_crypto::modes::gcm::gcm_decrypt_with_aes(
            &self.cipher,
            &self.table,
            nonce,
            aad,
            ciphertext_with_tag,
        )
        .map_err(TlsError::CryptoError)
    }

    fn tag_size(&self) -> usize {
        16
    }
}

/// AES-CCM AEAD (128-bit or 256-bit key, 16-byte tag).
/// Stores pre-expanded AES key to avoid per-record key expansion.
pub struct AesCcmAead {
    cipher: hitls_crypto::aes::AesKey,
}

impl AesCcmAead {
    pub fn new(key: &[u8]) -> Result<Self, TlsError> {
        if key.len() != 16 && key.len() != 32 {
            return Err(TlsError::HandshakeFailed(
                "AES-CCM: invalid key length".into(),
            ));
        }
        let cipher = hitls_crypto::aes::AesKey::new(key).map_err(TlsError::CryptoError)?;
        Ok(Self { cipher })
    }
}

impl TlsAead for AesCcmAead {
    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        hitls_crypto::modes::ccm::ccm_encrypt_with_key(&self.cipher, nonce, aad, plaintext, 16)
            .map_err(TlsError::CryptoError)
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        hitls_crypto::modes::ccm::ccm_decrypt_with_key(
            &self.cipher,
            nonce,
            aad,
            ciphertext_with_tag,
            16,
        )
        .map_err(TlsError::CryptoError)
    }

    fn tag_size(&self) -> usize {
        16
    }
}

/// AES-CCM_8 AEAD (128-bit or 256-bit key, 8-byte tag).
/// Stores pre-expanded AES key to avoid per-record key expansion.
pub struct AesCcm8Aead {
    cipher: hitls_crypto::aes::AesKey,
}

impl AesCcm8Aead {
    pub fn new(key: &[u8]) -> Result<Self, TlsError> {
        if key.len() != 16 && key.len() != 32 {
            return Err(TlsError::HandshakeFailed(
                "AES-CCM_8: invalid key length".into(),
            ));
        }
        let cipher = hitls_crypto::aes::AesKey::new(key).map_err(TlsError::CryptoError)?;
        Ok(Self { cipher })
    }
}

impl TlsAead for AesCcm8Aead {
    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        hitls_crypto::modes::ccm::ccm_encrypt_with_key(&self.cipher, nonce, aad, plaintext, 8)
            .map_err(TlsError::CryptoError)
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        hitls_crypto::modes::ccm::ccm_decrypt_with_key(
            &self.cipher,
            nonce,
            aad,
            ciphertext_with_tag,
            8,
        )
        .map_err(TlsError::CryptoError)
    }

    fn tag_size(&self) -> usize {
        8
    }
}

/// ChaCha20-Poly1305 AEAD.
pub struct ChaCha20Poly1305Aead {
    inner: hitls_crypto::chacha20::ChaCha20Poly1305,
}

impl ChaCha20Poly1305Aead {
    pub fn new(key: &[u8]) -> Result<Self, TlsError> {
        let inner =
            hitls_crypto::chacha20::ChaCha20Poly1305::new(key).map_err(TlsError::CryptoError)?;
        Ok(Self { inner })
    }
}

impl TlsAead for ChaCha20Poly1305Aead {
    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        self.inner
            .encrypt(nonce, aad, plaintext)
            .map_err(TlsError::CryptoError)
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        self.inner
            .decrypt(nonce, aad, ciphertext_with_tag)
            .map_err(TlsError::CryptoError)
    }

    fn tag_size(&self) -> usize {
        16
    }
}

/// SM4-GCM AEAD (128-bit key only).
/// Stores pre-expanded SM4 key and GHASH table to avoid per-record key expansion.
#[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
pub struct Sm4GcmAead {
    cipher: hitls_crypto::sm4::Sm4Key,
    table: hitls_crypto::modes::gcm::GhashTable,
}

#[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
impl Sm4GcmAead {
    pub fn new(key: &[u8]) -> Result<Self, TlsError> {
        if key.len() != 16 {
            return Err(TlsError::HandshakeFailed(
                "SM4-GCM: key must be 16 bytes".into(),
            ));
        }
        let cipher = hitls_crypto::sm4::Sm4Key::new(key).map_err(TlsError::CryptoError)?;
        let table = hitls_crypto::modes::gcm::GhashTable::from_cipher(&cipher)
            .map_err(TlsError::CryptoError)?;
        Ok(Self { cipher, table })
    }
}

#[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
impl TlsAead for Sm4GcmAead {
    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        hitls_crypto::modes::gcm::gcm_encrypt_with(&self.cipher, &self.table, nonce, aad, plaintext)
            .map_err(TlsError::CryptoError)
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        hitls_crypto::modes::gcm::gcm_decrypt_with(
            &self.cipher,
            &self.table,
            nonce,
            aad,
            ciphertext_with_tag,
        )
        .map_err(TlsError::CryptoError)
    }

    fn tag_size(&self) -> usize {
        16
    }
}

/// SM4-CCM AEAD (128-bit key only).
/// Stores pre-expanded SM4 key to avoid per-record key expansion.
#[cfg(feature = "sm_tls13")]
pub struct Sm4CcmAead {
    cipher: hitls_crypto::sm4::Sm4Key,
}

#[cfg(feature = "sm_tls13")]
impl Sm4CcmAead {
    pub fn new(key: &[u8]) -> Result<Self, TlsError> {
        if key.len() != 16 {
            return Err(TlsError::HandshakeFailed(
                "SM4-CCM: key must be 16 bytes".into(),
            ));
        }
        let cipher = hitls_crypto::sm4::Sm4Key::new(key).map_err(TlsError::CryptoError)?;
        Ok(Self { cipher })
    }
}

#[cfg(feature = "sm_tls13")]
impl TlsAead for Sm4CcmAead {
    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        hitls_crypto::modes::ccm::sm4_ccm_encrypt_with_key(&self.cipher, nonce, aad, plaintext, 16)
            .map_err(TlsError::CryptoError)
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        hitls_crypto::modes::ccm::sm4_ccm_decrypt_with_key(
            &self.cipher,
            nonce,
            aad,
            ciphertext_with_tag,
            16,
        )
        .map_err(TlsError::CryptoError)
    }

    fn tag_size(&self) -> usize {
        16
    }
}

/// Enum-dispatched AEAD — eliminates `Box<dyn TlsAead>` vtable indirection and heap allocation.
pub enum TlsAeadImpl {
    AesGcm(AesGcmAead),
    AesCcm(AesCcmAead),
    AesCcm8(AesCcm8Aead),
    ChaCha20Poly1305(ChaCha20Poly1305Aead),
    #[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
    Sm4Gcm(Sm4GcmAead),
    #[cfg(feature = "sm_tls13")]
    Sm4Ccm(Sm4CcmAead),
}

impl TlsAeadImpl {
    #[inline]
    pub fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        match self {
            Self::AesGcm(a) => a.encrypt(nonce, aad, plaintext),
            Self::AesCcm(a) => a.encrypt(nonce, aad, plaintext),
            Self::AesCcm8(a) => a.encrypt(nonce, aad, plaintext),
            Self::ChaCha20Poly1305(a) => a.encrypt(nonce, aad, plaintext),
            #[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
            Self::Sm4Gcm(a) => a.encrypt(nonce, aad, plaintext),
            #[cfg(feature = "sm_tls13")]
            Self::Sm4Ccm(a) => a.encrypt(nonce, aad, plaintext),
        }
    }

    #[inline]
    pub fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        match self {
            Self::AesGcm(a) => a.decrypt(nonce, aad, ciphertext_with_tag),
            Self::AesCcm(a) => a.decrypt(nonce, aad, ciphertext_with_tag),
            Self::AesCcm8(a) => a.decrypt(nonce, aad, ciphertext_with_tag),
            Self::ChaCha20Poly1305(a) => a.decrypt(nonce, aad, ciphertext_with_tag),
            #[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
            Self::Sm4Gcm(a) => a.decrypt(nonce, aad, ciphertext_with_tag),
            #[cfg(feature = "sm_tls13")]
            Self::Sm4Ccm(a) => a.decrypt(nonce, aad, ciphertext_with_tag),
        }
    }

    #[inline]
    pub fn tag_size(&self) -> usize {
        match self {
            Self::AesGcm(a) => a.tag_size(),
            Self::AesCcm(a) => a.tag_size(),
            Self::AesCcm8(a) => a.tag_size(),
            Self::ChaCha20Poly1305(a) => a.tag_size(),
            #[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
            Self::Sm4Gcm(a) => a.tag_size(),
            #[cfg(feature = "sm_tls13")]
            Self::Sm4Ccm(a) => a.tag_size(),
        }
    }
}

/// Create a TlsAeadImpl instance for the given cipher suite and key.
pub fn create_aead(suite: CipherSuite, key: &[u8]) -> Result<TlsAeadImpl, TlsError> {
    match suite {
        CipherSuite::TLS_AES_128_GCM_SHA256 | CipherSuite::TLS_AES_256_GCM_SHA384 => {
            Ok(TlsAeadImpl::AesGcm(AesGcmAead::new(key)?))
        }
        CipherSuite::TLS_AES_128_CCM_SHA256 => Ok(TlsAeadImpl::AesCcm(AesCcmAead::new(key)?)),
        CipherSuite::TLS_AES_128_CCM_8_SHA256 => Ok(TlsAeadImpl::AesCcm8(AesCcm8Aead::new(key)?)),
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => Ok(TlsAeadImpl::ChaCha20Poly1305(
            ChaCha20Poly1305Aead::new(key)?,
        )),
        #[cfg(feature = "sm_tls13")]
        CipherSuite::TLS_SM4_GCM_SM3 => Ok(TlsAeadImpl::Sm4Gcm(Sm4GcmAead::new(key)?)),
        #[cfg(feature = "sm_tls13")]
        CipherSuite::TLS_SM4_CCM_SM3 => Ok(TlsAeadImpl::Sm4Ccm(Sm4CcmAead::new(key)?)),
        _ => Err(TlsError::NoSharedCipherSuite),
    }
}

/// Create an SM4-GCM AEAD instance.
#[cfg(feature = "tlcp")]
pub fn create_sm4_gcm_aead(key: &[u8]) -> Result<TlsAeadImpl, TlsError> {
    Ok(TlsAeadImpl::Sm4Gcm(Sm4GcmAead::new(key)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_aead_roundtrip() {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello TLS 1.3";

        let aead = create_aead(CipherSuite::TLS_AES_128_GCM_SHA256, &key).unwrap();
        let ct = aead.encrypt(&nonce, aad, plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len() + aead.tag_size());

        let pt = aead.decrypt(&nonce, aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_chacha20_poly1305_aead_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello ChaCha20";

        let aead = create_aead(CipherSuite::TLS_CHACHA20_POLY1305_SHA256, &key).unwrap();
        let ct = aead.encrypt(&nonce, aad, plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len() + aead.tag_size());

        let pt = aead.decrypt(&nonce, aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aes_ccm_aead_128_roundtrip() {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello AES-CCM-128";

        let aead = create_aead(CipherSuite::TLS_AES_128_CCM_SHA256, &key).unwrap();
        let ct = aead.encrypt(&nonce, aad, plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len() + aead.tag_size());

        let pt = aead.decrypt(&nonce, aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aes_ccm_aead_256_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello AES-CCM-256";

        let aead = AesCcmAead::new(&key).unwrap();
        let ct = aead.encrypt(&nonce, aad, plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len() + aead.tag_size());

        let pt = aead.decrypt(&nonce, aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aes_ccm_aead_tampered() {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let aad = b"additional data";

        let aead = AesCcmAead::new(&key).unwrap();
        let mut ct = aead.encrypt(&nonce, aad, b"secret").unwrap();
        ct[0] ^= 0x01; // tamper
        assert!(aead.decrypt(&nonce, aad, &ct).is_err());
    }

    #[cfg(feature = "sm_tls13")]
    #[test]
    fn test_sm4_gcm_aead_roundtrip() {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello SM4-GCM TLS 1.3";

        let aead = create_aead(CipherSuite::TLS_SM4_GCM_SM3, &key).unwrap();
        let ct = aead.encrypt(&nonce, aad, plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len() + aead.tag_size());

        let pt = aead.decrypt(&nonce, aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aes_ccm8_aead_128_roundtrip() {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello AES-CCM_8-128";

        let aead = create_aead(CipherSuite::TLS_AES_128_CCM_8_SHA256, &key).unwrap();
        assert_eq!(aead.tag_size(), 8);
        let ct = aead.encrypt(&nonce, aad, plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len() + 8);

        let pt = aead.decrypt(&nonce, aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aes_ccm8_aead_256_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello AES-CCM_8-256";

        let aead = AesCcm8Aead::new(&key).unwrap();
        assert_eq!(aead.tag_size(), 8);
        let ct = aead.encrypt(&nonce, aad, plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len() + 8);

        let pt = aead.decrypt(&nonce, aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aes_ccm8_aead_tampered() {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let aad = b"additional data";

        let aead = AesCcm8Aead::new(&key).unwrap();
        let mut ct = aead.encrypt(&nonce, aad, b"secret").unwrap();
        ct[0] ^= 0x01; // tamper
        assert!(aead.decrypt(&nonce, aad, &ct).is_err());
    }

    #[test]
    fn test_ccm8_vs_ccm16_different_output() {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let aad = b"aad";
        let plaintext = b"same plaintext";

        let aead16 = AesCcmAead::new(&key).unwrap();
        let aead8 = AesCcm8Aead::new(&key).unwrap();

        let ct16 = aead16.encrypt(&nonce, aad, plaintext).unwrap();
        let ct8 = aead8.encrypt(&nonce, aad, plaintext).unwrap();

        assert_eq!(ct16.len(), plaintext.len() + 16);
        assert_eq!(ct8.len(), plaintext.len() + 8);
        // Ciphertext portions may differ due to CCM tag length affecting encryption
        assert_ne!(ct16.len(), ct8.len());
    }

    #[cfg(feature = "sm_tls13")]
    #[test]
    fn test_sm4_ccm_aead_roundtrip() {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let aad = b"additional data";
        let plaintext = b"hello SM4-CCM TLS 1.3";

        let aead = create_aead(CipherSuite::TLS_SM4_CCM_SM3, &key).unwrap();
        let ct = aead.encrypt(&nonce, aad, plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len() + aead.tag_size());

        let pt = aead.decrypt(&nonce, aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aes_gcm_aead_invalid_key_length() {
        // Only 16 and 32-byte keys are valid for AES-GCM
        assert!(AesGcmAead::new(&[0x42u8; 0]).is_err());
        assert!(AesGcmAead::new(&[0x42u8; 8]).is_err());
        assert!(AesGcmAead::new(&[0x42u8; 24]).is_err());
        assert!(AesGcmAead::new(&[0x42u8; 48]).is_err());
        // Valid key lengths should succeed
        assert!(AesGcmAead::new(&[0x42u8; 16]).is_ok());
        assert!(AesGcmAead::new(&[0x42u8; 32]).is_ok());
    }

    #[test]
    fn test_aes_ccm_aead_invalid_key_length() {
        assert!(AesCcmAead::new(&[0x42u8; 0]).is_err());
        assert!(AesCcmAead::new(&[0x42u8; 8]).is_err());
        assert!(AesCcmAead::new(&[0x42u8; 24]).is_err());
        // Valid
        assert!(AesCcmAead::new(&[0x42u8; 16]).is_ok());
        assert!(AesCcmAead::new(&[0x42u8; 32]).is_ok());
    }

    #[test]
    fn test_aes_ccm8_aead_invalid_key_length() {
        assert!(AesCcm8Aead::new(&[0x42u8; 0]).is_err());
        assert!(AesCcm8Aead::new(&[0x42u8; 12]).is_err());
        assert!(AesCcm8Aead::new(&[0x42u8; 24]).is_err());
        // Valid
        assert!(AesCcm8Aead::new(&[0x42u8; 16]).is_ok());
        assert!(AesCcm8Aead::new(&[0x42u8; 32]).is_ok());
    }

    #[test]
    fn test_aead_tag_size_consistency() {
        let gcm = AesGcmAead::new(&[0x42u8; 16]).unwrap();
        assert_eq!(gcm.tag_size(), 16);

        let ccm = AesCcmAead::new(&[0x42u8; 16]).unwrap();
        assert_eq!(ccm.tag_size(), 16);

        let ccm8 = AesCcm8Aead::new(&[0x42u8; 16]).unwrap();
        assert_eq!(ccm8.tag_size(), 8);

        let chacha = ChaCha20Poly1305Aead::new(&[0x42u8; 32]).unwrap();
        assert_eq!(chacha.tag_size(), 16);
    }

    #[test]
    fn test_aes_gcm_decrypt_wrong_nonce() {
        let key = [0x42u8; 16];
        let nonce1 = [0x01u8; 12];
        let nonce2 = [0x02u8; 12];
        let aad = b"aad";
        let plaintext = b"test data";

        let aead = AesGcmAead::new(&key).unwrap();
        let ct = aead.encrypt(&nonce1, aad, plaintext).unwrap();
        // Decrypting with wrong nonce should fail
        assert!(aead.decrypt(&nonce2, aad, &ct).is_err());
    }

    #[test]
    fn test_aes_gcm_wrong_aad_fails() {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let plaintext = b"secret message";

        let aead = AesGcmAead::new(&key).unwrap();
        let ct = aead.encrypt(&nonce, b"hello", plaintext).unwrap();

        // Decrypting with different AAD should fail
        assert!(aead.decrypt(&nonce, b"world", &ct).is_err());
    }

    #[test]
    fn test_chacha20_wrong_aad_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"secret message";

        let aead = ChaCha20Poly1305Aead::new(&key).unwrap();
        let ct = aead.encrypt(&nonce, b"hello", plaintext).unwrap();

        // Decrypting with different AAD should fail
        assert!(aead.decrypt(&nonce, b"world", &ct).is_err());
    }

    #[test]
    fn test_aes_gcm_empty_plaintext_roundtrip() {
        let key = [0x42u8; 16];
        let nonce = [0x01u8; 12];
        let aad = b"additional data";

        let aead = AesGcmAead::new(&key).unwrap();
        let ct = aead.encrypt(&nonce, aad, b"").unwrap();

        // Ciphertext for empty plaintext is exactly the tag
        assert_eq!(ct.len(), aead.tag_size());

        let pt = aead.decrypt(&nonce, aad, &ct).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn test_create_aead_unsupported_suite() {
        let key = [0x42u8; 16];
        // Use an obviously unsupported cipher suite value
        let result = create_aead(CipherSuite(0xFFFF), &key);
        assert!(
            matches!(result, Err(TlsError::NoSharedCipherSuite)),
            "expected NoSharedCipherSuite for unsupported suite"
        );
    }

    #[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
    #[test]
    fn test_sm4_gcm_invalid_key_length() {
        // 15 bytes — too short
        assert!(Sm4GcmAead::new(&[0u8; 15]).is_err());
        // 17 bytes — too long
        assert!(Sm4GcmAead::new(&[0u8; 17]).is_err());
        // 0 bytes — empty
        assert!(Sm4GcmAead::new(&[]).is_err());
        // 16 bytes — valid
        assert!(Sm4GcmAead::new(&[0u8; 16]).is_ok());
    }
}
