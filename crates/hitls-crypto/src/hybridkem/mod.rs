//! Hybrid KEM combining X25519 + ML-KEM-768.
//!
//! Provides security against both classical and quantum adversaries
//! by combining an ECDH key exchange with a post-quantum KEM.
//! The shared secret is SHA-256(ss_classical || ss_pq).

use crate::mlkem::MlKemKeyPair;
use crate::sha2::Sha256;
use crate::x25519::{X25519PrivateKey, X25519PublicKey, X25519_KEY_SIZE};
use hitls_types::CryptoError;
use zeroize::Zeroize;

/// A hybrid KEM key pair combining X25519 and ML-KEM-768.
pub struct HybridKemKeyPair {
    /// Raw X25519 private key bytes (pre-clamping).
    x25519_sk_bytes: [u8; X25519_KEY_SIZE],
    /// X25519 public key bytes.
    x25519_pk: [u8; X25519_KEY_SIZE],
    /// ML-KEM-768 key pair.
    mlkem: MlKemKeyPair,
}

impl HybridKemKeyPair {
    /// Generate a new hybrid KEM key pair (X25519 + ML-KEM-768).
    pub fn generate() -> Result<Self, CryptoError> {
        // X25519 key pair
        let mut x25519_sk_bytes = [0u8; 32];
        getrandom::getrandom(&mut x25519_sk_bytes).map_err(|_| CryptoError::BnRandGenFail)?;
        let sk = X25519PrivateKey::new(&x25519_sk_bytes)?;
        let pk = sk.public_key();

        // ML-KEM-768 key pair
        let mlkem = MlKemKeyPair::generate(768)?;

        Ok(Self {
            x25519_sk_bytes,
            x25519_pk: *pk.as_bytes(),
            mlkem,
        })
    }

    /// Return the combined public key bytes: X25519 pk (32 bytes) || ML-KEM-768 ek.
    pub fn public_key(&self) -> Vec<u8> {
        let mlkem_ek = self.mlkem.encapsulation_key();
        let mut pk = Vec::with_capacity(X25519_KEY_SIZE + mlkem_ek.len());
        pk.extend_from_slice(&self.x25519_pk);
        pk.extend_from_slice(mlkem_ek);
        pk
    }

    /// Encapsulate: produce a shared secret and hybrid ciphertext.
    ///
    /// Uses the public keys stored in this key pair.
    /// Returns `(shared_secret, ciphertext)` where:
    /// - `shared_secret` is 32 bytes (SHA-256 of combined secrets)
    /// - `ciphertext` is X25519 ephemeral pk (32 bytes) || ML-KEM ciphertext
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        // X25519 ephemeral DH
        let sk_e = X25519PrivateKey::generate()?;
        let pk_e = sk_e.public_key();
        let pk_r = X25519PublicKey::new(&self.x25519_pk)?;
        let ss_c = sk_e.diffie_hellman(&pk_r)?;

        // ML-KEM-768 encapsulation
        let (ss_pq, ct_pq) = self.mlkem.encapsulate()?;

        // Combined ciphertext: pk_e || ct_pq
        let mut ct = Vec::with_capacity(X25519_KEY_SIZE + ct_pq.len());
        ct.extend_from_slice(pk_e.as_bytes());
        ct.extend_from_slice(&ct_pq);

        // Combined shared secret: SHA-256(ss_c || ss_pq)
        let ss = combine_secrets(&ss_c, &ss_pq)?;
        Ok((ss, ct))
    }

    /// Decapsulate: recover the shared secret from a hybrid ciphertext.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() <= X25519_KEY_SIZE {
            return Err(CryptoError::InvalidArg);
        }

        // Parse: ephemeral X25519 pk (32 bytes) || ML-KEM ciphertext
        let (pk_e_bytes, ct_pq) = ciphertext.split_at(X25519_KEY_SIZE);

        // X25519 key agreement
        let sk_r = X25519PrivateKey::new(&self.x25519_sk_bytes)?;
        let pk_e = X25519PublicKey::new(pk_e_bytes)?;
        let ss_c = sk_r.diffie_hellman(&pk_e)?;

        // ML-KEM-768 decapsulation
        let ss_pq = self.mlkem.decapsulate(ct_pq)?;

        // Combined shared secret: SHA-256(ss_c || ss_pq)
        combine_secrets(&ss_c, &ss_pq)
    }
}

impl Drop for HybridKemKeyPair {
    fn drop(&mut self) {
        self.x25519_sk_bytes.zeroize();
    }
}

/// Combine two shared secrets: SHA-256(ss1 || ss2).
fn combine_secrets(ss1: &[u8], ss2: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut hasher = Sha256::new();
    hasher.update(ss1)?;
    hasher.update(ss2)?;
    let hash = hasher.finish()?;
    Ok(hash.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_roundtrip() {
        let kp = HybridKemKeyPair::generate().unwrap();
        let (ss_enc, ct) = kp.encapsulate().unwrap();
        let ss_dec = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss_enc, ss_dec);
        assert_eq!(ss_enc.len(), 32);
    }

    #[test]
    fn test_hybrid_kem_public_key_length() {
        let kp = HybridKemKeyPair::generate().unwrap();
        let pk = kp.public_key();
        // X25519 pk (32) + ML-KEM-768 ek (1184)
        assert_eq!(pk.len(), 32 + 1184);
    }

    #[test]
    fn test_hybrid_kem_tampered_ciphertext() {
        let kp = HybridKemKeyPair::generate().unwrap();
        let (ss_enc, mut ct) = kp.encapsulate().unwrap();

        // Tamper with the ML-KEM portion (after X25519 pk)
        ct[40] ^= 0xff;
        let ss_dec = kp.decapsulate(&ct).unwrap();
        // ML-KEM uses implicit rejection, so decapsulation succeeds
        // but produces a different shared secret
        assert_ne!(ss_enc, ss_dec);
    }

    #[test]
    fn test_hybrid_kem_invalid_ciphertext_length() {
        let kp = HybridKemKeyPair::generate().unwrap();
        // Too short — must be > 32 bytes
        assert!(kp.decapsulate(&[0u8; 32]).is_err());
        assert!(kp.decapsulate(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_hybrid_kem_cross_key_decapsulation() {
        let kp1 = HybridKemKeyPair::generate().unwrap();
        let kp2 = HybridKemKeyPair::generate().unwrap();

        let (ss1, ct) = kp1.encapsulate().unwrap();
        // Decapsulate with wrong key — ML-KEM uses implicit rejection,
        // so decapsulation succeeds but produces a different shared secret
        let ss2 = kp2.decapsulate(&ct).unwrap();
        assert_ne!(
            ss1, ss2,
            "cross-key decapsulation should produce different shared secret"
        );
    }

    #[test]
    fn test_hybrid_kem_ciphertext_length() {
        let kp = HybridKemKeyPair::generate().unwrap();
        let (_, ct) = kp.encapsulate().unwrap();
        // X25519 ephemeral pk (32) + ML-KEM-768 ciphertext (1088) = 1120
        assert_eq!(
            ct.len(),
            32 + 1088,
            "hybrid ciphertext should be 1120 bytes"
        );
    }

    #[test]
    fn test_hybrid_kem_multiple_encapsulations_differ() {
        let kp = HybridKemKeyPair::generate().unwrap();
        let (ss1, ct1) = kp.encapsulate().unwrap();
        let (ss2, ct2) = kp.encapsulate().unwrap();
        // Each encapsulation uses fresh randomness
        assert_ne!(ct1, ct2, "ciphertexts should differ");
        assert_ne!(ss1, ss2, "shared secrets should differ");
    }
}
