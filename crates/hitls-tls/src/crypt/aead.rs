//! TLS AEAD cipher abstraction.
//!
//! Wraps AES-GCM and ChaCha20-Poly1305 behind a common trait.

use crate::CipherSuite;
use hitls_types::TlsError;
use zeroize::Zeroize;

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
pub struct AesGcmAead {
    key: Vec<u8>,
}

impl AesGcmAead {
    pub fn new(key: &[u8]) -> Result<Self, TlsError> {
        if key.len() != 16 && key.len() != 32 {
            return Err(TlsError::HandshakeFailed(
                "AES-GCM: invalid key length".into(),
            ));
        }
        Ok(Self { key: key.to_vec() })
    }
}

impl Drop for AesGcmAead {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl TlsAead for AesGcmAead {
    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        hitls_crypto::modes::gcm::gcm_encrypt(&self.key, nonce, aad, plaintext)
            .map_err(TlsError::CryptoError)
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        hitls_crypto::modes::gcm::gcm_decrypt(&self.key, nonce, aad, ciphertext_with_tag)
            .map_err(TlsError::CryptoError)
    }

    fn tag_size(&self) -> usize {
        16
    }
}

/// AES-CCM AEAD (128-bit or 256-bit key, 16-byte tag).
pub struct AesCcmAead {
    key: Vec<u8>,
}

impl AesCcmAead {
    pub fn new(key: &[u8]) -> Result<Self, TlsError> {
        if key.len() != 16 && key.len() != 32 {
            return Err(TlsError::HandshakeFailed(
                "AES-CCM: invalid key length".into(),
            ));
        }
        Ok(Self { key: key.to_vec() })
    }
}

impl Drop for AesCcmAead {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl TlsAead for AesCcmAead {
    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        hitls_crypto::modes::ccm::ccm_encrypt(&self.key, nonce, aad, plaintext, 16)
            .map_err(TlsError::CryptoError)
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        hitls_crypto::modes::ccm::ccm_decrypt(&self.key, nonce, aad, ciphertext_with_tag, 16)
            .map_err(TlsError::CryptoError)
    }

    fn tag_size(&self) -> usize {
        16
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
#[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
pub struct Sm4GcmAead {
    key: Vec<u8>,
}

#[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
impl Sm4GcmAead {
    pub fn new(key: &[u8]) -> Result<Self, TlsError> {
        if key.len() != 16 {
            return Err(TlsError::HandshakeFailed(
                "SM4-GCM: key must be 16 bytes".into(),
            ));
        }
        Ok(Self { key: key.to_vec() })
    }
}

#[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
impl Drop for Sm4GcmAead {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
impl TlsAead for Sm4GcmAead {
    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        hitls_crypto::modes::gcm::sm4_gcm_encrypt(&self.key, nonce, aad, plaintext)
            .map_err(TlsError::CryptoError)
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        hitls_crypto::modes::gcm::sm4_gcm_decrypt(&self.key, nonce, aad, ciphertext_with_tag)
            .map_err(TlsError::CryptoError)
    }

    fn tag_size(&self) -> usize {
        16
    }
}

/// SM4-CCM AEAD (128-bit key only).
#[cfg(feature = "sm_tls13")]
pub struct Sm4CcmAead {
    key: Vec<u8>,
}

#[cfg(feature = "sm_tls13")]
impl Sm4CcmAead {
    pub fn new(key: &[u8]) -> Result<Self, TlsError> {
        if key.len() != 16 {
            return Err(TlsError::HandshakeFailed(
                "SM4-CCM: key must be 16 bytes".into(),
            ));
        }
        Ok(Self { key: key.to_vec() })
    }
}

#[cfg(feature = "sm_tls13")]
impl Drop for Sm4CcmAead {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(feature = "sm_tls13")]
impl TlsAead for Sm4CcmAead {
    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        hitls_crypto::modes::ccm::sm4_ccm_encrypt(&self.key, nonce, aad, plaintext, 16)
            .map_err(TlsError::CryptoError)
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        hitls_crypto::modes::ccm::sm4_ccm_decrypt(&self.key, nonce, aad, ciphertext_with_tag, 16)
            .map_err(TlsError::CryptoError)
    }

    fn tag_size(&self) -> usize {
        16
    }
}

/// Create a TlsAead instance for the given cipher suite and key.
pub fn create_aead(suite: CipherSuite, key: &[u8]) -> Result<Box<dyn TlsAead>, TlsError> {
    match suite {
        CipherSuite::TLS_AES_128_GCM_SHA256 | CipherSuite::TLS_AES_256_GCM_SHA384 => {
            Ok(Box::new(AesGcmAead::new(key)?))
        }
        CipherSuite::TLS_AES_128_CCM_SHA256 => Ok(Box::new(AesCcmAead::new(key)?)),
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => Ok(Box::new(ChaCha20Poly1305Aead::new(key)?)),
        #[cfg(feature = "sm_tls13")]
        CipherSuite::TLS_SM4_GCM_SM3 => Ok(Box::new(Sm4GcmAead::new(key)?)),
        #[cfg(feature = "sm_tls13")]
        CipherSuite::TLS_SM4_CCM_SM3 => Ok(Box::new(Sm4CcmAead::new(key)?)),
        _ => Err(TlsError::NoSharedCipherSuite),
    }
}

/// Create an SM4-GCM AEAD instance.
#[cfg(feature = "tlcp")]
pub fn create_sm4_gcm_aead(key: &[u8]) -> Result<Box<dyn TlsAead>, TlsError> {
    Ok(Box::new(Sm4GcmAead::new(key)?))
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
}
