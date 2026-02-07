//! ECDH (Elliptic Curve Diffie-Hellman) key agreement.
//!
//! Provides ECDH key pair generation and shared secret computation as
//! defined in NIST SP 800-56A. Operates over NIST P-256 and P-384 curves.

use hitls_bignum::BigNum;
use hitls_types::{CryptoError, EccCurveId};
use zeroize::Zeroize;

use crate::ecc::{EcGroup, EcPoint};

/// An ECDH key pair for key agreement.
#[derive(Clone)]
pub struct EcdhKeyPair {
    group: EcGroup,
    /// The private scalar d (1 <= d < n).
    private_key: BigNum,
    /// The public point Q = d*G.
    public_key: EcPoint,
}

impl Drop for EcdhKeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl EcdhKeyPair {
    /// Generate a new ECDH key pair for the given curve.
    pub fn generate(curve_id: EccCurveId) -> Result<Self, CryptoError> {
        let group = EcGroup::new(curve_id)?;
        let n = group.order();

        // Generate random d in [1, n-1]
        let d = BigNum::random_range(n)?;
        let d = if d.is_zero() { BigNum::from_u64(1) } else { d };

        let q = group.scalar_mul_base(&d)?;

        Ok(EcdhKeyPair {
            group,
            private_key: d,
            public_key: q,
        })
    }

    /// Create an ECDH key pair from existing private key bytes.
    pub fn from_private_key(curve_id: EccCurveId, private_key: &[u8]) -> Result<Self, CryptoError> {
        let group = EcGroup::new(curve_id)?;
        let d = BigNum::from_bytes_be(private_key);

        if d.is_zero() || d >= *group.order() {
            return Err(CryptoError::EccInvalidPrivateKey);
        }

        let q = group.scalar_mul_base(&d)?;

        Ok(EcdhKeyPair {
            group,
            private_key: d,
            public_key: q,
        })
    }

    /// Compute the shared secret from the peer's public key.
    ///
    /// Returns the x-coordinate of the shared point d*Q_peer.
    pub fn compute_shared_secret(&self, peer_public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let peer_point = EcPoint::from_uncompressed(&self.group, peer_public_key)?;

        let shared_point = self.group.scalar_mul(&self.private_key, &peer_point)?;

        if shared_point.is_infinity() {
            return Err(CryptoError::EccPointAtInfinity);
        }

        shared_point.x().to_bytes_be_padded(self.group.field_size())
    }

    /// Return the public key in uncompressed point encoding.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        self.public_key.to_uncompressed(&self.group)
    }

    /// Return a reference to the public point.
    pub fn public_key(&self) -> &EcPoint {
        &self.public_key
    }

    /// Return the curve identifier.
    pub fn curve_id(&self) -> EccCurveId {
        self.group.curve_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh_p256_shared_secret() {
        let alice = EcdhKeyPair::generate(EccCurveId::NistP256).unwrap();
        let bob = EcdhKeyPair::generate(EccCurveId::NistP256).unwrap();

        let alice_pub = alice.public_key_bytes().unwrap();
        let bob_pub = bob.public_key_bytes().unwrap();

        let secret_alice = alice.compute_shared_secret(&bob_pub).unwrap();
        let secret_bob = bob.compute_shared_secret(&alice_pub).unwrap();

        assert_eq!(secret_alice, secret_bob);
        assert_eq!(secret_alice.len(), 32); // P-256 field size
    }

    #[test]
    fn test_ecdh_p384_shared_secret() {
        let alice = EcdhKeyPair::generate(EccCurveId::NistP384).unwrap();
        let bob = EcdhKeyPair::generate(EccCurveId::NistP384).unwrap();

        let alice_pub = alice.public_key_bytes().unwrap();
        let bob_pub = bob.public_key_bytes().unwrap();

        let secret_alice = alice.compute_shared_secret(&bob_pub).unwrap();
        let secret_bob = bob.compute_shared_secret(&alice_pub).unwrap();

        assert_eq!(secret_alice, secret_bob);
        assert_eq!(secret_alice.len(), 48); // P-384 field size
    }

    #[test]
    fn test_ecdh_from_private_key() {
        let original = EcdhKeyPair::generate(EccCurveId::NistP256).unwrap();
        let pub_bytes = original.public_key_bytes().unwrap();

        // Re-derive from the same private key should give the same public key
        let prv_bytes = original.private_key.to_bytes_be();
        let restored = EcdhKeyPair::from_private_key(EccCurveId::NistP256, &prv_bytes).unwrap();
        let restored_pub = restored.public_key_bytes().unwrap();

        assert_eq!(pub_bytes, restored_pub);
    }
}
