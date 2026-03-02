//! Trait-based provider mechanism for cryptographic algorithms.
//!
//! These traits define the abstract interfaces that all algorithm
//! implementations must satisfy. This replaces the C function pointer
//! tables with Rust's trait system for zero-cost static dispatch.

use hitls_types::CryptoError;

/// A hash / message digest algorithm.
pub trait Digest: Send + Sync {
    /// The output size in bytes.
    fn output_size(&self) -> usize;

    /// The internal block size in bytes.
    fn block_size(&self) -> usize;

    /// Feed data into the hash state.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError>;

    /// Finalize the hash and write the digest to `out`.
    /// The length of `out` must be at least `output_size()`.
    fn finish(&mut self, out: &mut [u8]) -> Result<(), CryptoError>;

    /// Reset the hash state to process a new message.
    fn reset(&mut self);
}

/// A convenience wrapper trait for creating digest instances.
pub trait HashAlgorithm: Send + Sync {
    /// Create a new digest context.
    fn new_digest(&self) -> Box<dyn Digest>;

    /// One-shot hash computation.
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut ctx = self.new_digest();
        ctx.update(data)?;
        let mut out = vec![0u8; ctx.output_size()];
        ctx.finish(&mut out)?;
        Ok(out)
    }
}

/// A block cipher (e.g., AES, SM4).
pub trait BlockCipher: Send + Sync {
    /// Block size in bytes.
    fn block_size(&self) -> usize;

    /// Key size in bytes.
    fn key_size(&self) -> usize;

    /// Set the encryption key.
    fn set_encrypt_key(&mut self, key: &[u8]) -> Result<(), CryptoError>;

    /// Set the decryption key.
    fn set_decrypt_key(&mut self, key: &[u8]) -> Result<(), CryptoError>;

    /// Encrypt a single block in-place.
    fn encrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError>;

    /// Decrypt a single block in-place.
    fn decrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError>;
}

/// An Authenticated Encryption with Associated Data (AEAD) algorithm.
pub trait Aead: Send + Sync {
    /// The length of the authentication tag in bytes.
    fn tag_size(&self) -> usize;

    /// The expected nonce size in bytes.
    fn nonce_size(&self) -> usize;

    /// The key size in bytes.
    fn key_size(&self) -> usize;

    /// Set the key.
    fn set_key(&mut self, key: &[u8]) -> Result<(), CryptoError>;

    /// Encrypt plaintext with AEAD.
    ///
    /// Returns ciphertext || tag.
    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Decrypt ciphertext with AEAD.
    ///
    /// `ciphertext` should include the appended tag.
    fn decrypt(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// A Message Authentication Code (MAC) algorithm.
pub trait Mac: Send + Sync {
    /// The output size of the MAC in bytes.
    fn output_size(&self) -> usize;

    /// Initialize the MAC with a key.
    fn init(&mut self, key: &[u8]) -> Result<(), CryptoError>;

    /// Feed data into the MAC computation.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError>;

    /// Finalize and write the MAC value to `out`.
    fn finish(&mut self, out: &mut [u8]) -> Result<(), CryptoError>;

    /// Reset the MAC state for reuse with the same key.
    fn reset(&mut self);
}

/// A Key Derivation Function (KDF).
pub trait Kdf: Send + Sync {
    /// Derive key material.
    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError>;
}

/// A digital signature algorithm.
pub trait Signer: Send + Sync {
    /// Sign a message (or its hash), returning the signature.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// A signature verifier.
pub trait Verifier: Send + Sync {
    /// Verify a signature against a message (or its hash).
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;
}

/// A Key Encapsulation Mechanism (KEM).
pub trait Kem: Send + Sync {
    /// Generate a shared secret and ciphertext.
    fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;

    /// Recover the shared secret from ciphertext.
    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// A key agreement / key exchange protocol.
pub trait KeyAgreement: Send + Sync {
    /// Compute the shared secret from the peer's public key.
    fn compute_shared_secret(&self, peer_public_key: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

#[cfg(all(test, feature = "sha2"))]
mod tests {
    use super::*;

    /// Test HashAlgorithm::hash() default implementation via SHA-256.
    #[test]
    fn test_hash_algorithm_default_impl() {
        use crate::sha2::Sha256;

        struct Sha256Factory;
        impl HashAlgorithm for Sha256Factory {
            fn new_digest(&self) -> Box<dyn Digest> {
                Box::new(Sha256::new())
            }
        }

        let factory = Sha256Factory;
        let result = factory.hash(b"abc").unwrap();
        assert_eq!(result.len(), 32);
        // NIST SHA-256("abc") known answer
        assert_eq!(
            &result[..4],
            &[0xba, 0x78, 0x16, 0xbf],
            "SHA-256(abc) prefix"
        );
    }

    /// Test Digest trait output_size/block_size via SHA-256.
    #[test]
    fn test_digest_trait_output_size() {
        use crate::sha2::Sha256;

        let d: Box<dyn Digest> = Box::new(Sha256::new());
        assert_eq!(d.output_size(), 32);
        assert_eq!(d.block_size(), 64);
    }

    /// Test Digest reset+update+finish cycle.
    #[test]
    fn test_digest_trait_reset() {
        use crate::sha2::Sha256;

        let mut d: Box<dyn Digest> = Box::new(Sha256::new());
        d.update(b"first").unwrap();
        let mut out1 = [0u8; 32];
        d.finish(&mut out1).unwrap();

        d.reset();
        d.update(b"first").unwrap();
        let mut out2 = [0u8; 32];
        d.finish(&mut out2).unwrap();

        assert_eq!(out1, out2, "reset should produce same result");
    }
}
