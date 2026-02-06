//! SM2 elliptic curve public-key cryptography.
//!
//! SM2 is a Chinese national standard (GB/T 32918) for elliptic curve
//! cryptography. It supports digital signatures, key exchange, and
//! public-key encryption, all based on the SM2 recommended curve over
//! a 256-bit prime field.

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// An SM2 key pair for signing, verification, encryption, and key exchange.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Sm2KeyPair {
    /// The private scalar d (big-endian bytes).
    private_key: Vec<u8>,
    /// The public point Q encoded in uncompressed form.
    public_key: Vec<u8>,
}

impl Sm2KeyPair {
    /// Generate a new SM2 key pair.
    pub fn generate() -> Result<Self, CryptoError> {
        todo!("SM2 key generation not yet implemented")
    }

    /// Create an SM2 key pair from existing private key bytes.
    pub fn from_private_key(private_key: &[u8]) -> Result<Self, CryptoError> {
        todo!("SM2 key pair from private key not yet implemented")
    }

    /// Sign a message digest using SM2 digital signature.
    pub fn sign(&self, user_id: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        todo!("SM2 signing not yet implemented")
    }

    /// Verify an SM2 signature against a message.
    pub fn verify(
        &self,
        user_id: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        todo!("SM2 verification not yet implemented")
    }

    /// Encrypt data using SM2 public-key encryption.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        todo!("SM2 encryption not yet implemented")
    }

    /// Decrypt data using SM2 private-key decryption.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        todo!("SM2 decryption not yet implemented")
    }

    /// Return the public key in uncompressed point encoding.
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }
}
