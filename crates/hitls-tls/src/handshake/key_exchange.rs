//! TLS 1.3 ephemeral key exchange (X25519, SECP256R1).

use crate::crypt::NamedGroup;
use hitls_crypto::ecdh::EcdhKeyPair;
use hitls_crypto::x25519::{X25519PrivateKey, X25519PublicKey};
use hitls_types::TlsError;

/// Inner key exchange state (variant per named group).
enum KeyExchangeInner {
    X25519(X25519PrivateKey),
    EcdhP256(Box<EcdhKeyPair>),
}

/// Ephemeral key exchange state for a TLS handshake.
pub struct KeyExchange {
    group: NamedGroup,
    inner: KeyExchangeInner,
    public_key_bytes: Vec<u8>,
}

impl KeyExchange {
    /// Generate a new ephemeral keypair for the given named group.
    ///
    /// Supports X25519 and SECP256R1.
    pub fn generate(group: NamedGroup) -> Result<Self, TlsError> {
        match group {
            NamedGroup::X25519 => {
                let private_key = X25519PrivateKey::generate().map_err(TlsError::CryptoError)?;
                let public_key = private_key.public_key();
                let public_key_bytes = public_key.as_bytes().to_vec();
                Ok(Self {
                    group,
                    inner: KeyExchangeInner::X25519(private_key),
                    public_key_bytes,
                })
            }
            NamedGroup::SECP256R1 => {
                let kp = EcdhKeyPair::generate(hitls_types::EccCurveId::NistP256)
                    .map_err(TlsError::CryptoError)?;
                let public_key_bytes = kp.public_key_bytes().map_err(TlsError::CryptoError)?;
                Ok(Self {
                    group,
                    inner: KeyExchangeInner::EcdhP256(Box::new(kp)),
                    public_key_bytes,
                })
            }
            _ => Err(TlsError::HandshakeFailed(format!(
                "unsupported named group: {:?}",
                group
            ))),
        }
    }

    /// The named group for this key exchange.
    pub fn group(&self) -> NamedGroup {
        self.group
    }

    /// The public key bytes to include in the key_share extension.
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key_bytes
    }

    /// Compute the shared secret from the peer's public key.
    pub fn compute_shared_secret(&self, peer_public: &[u8]) -> Result<Vec<u8>, TlsError> {
        match &self.inner {
            KeyExchangeInner::X25519(private_key) => {
                let peer_key = X25519PublicKey::new(peer_public).map_err(TlsError::CryptoError)?;
                private_key
                    .diffie_hellman(&peer_key)
                    .map_err(TlsError::CryptoError)
            }
            KeyExchangeInner::EcdhP256(kp) => kp
                .compute_shared_secret(peer_public)
                .map_err(TlsError::CryptoError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange_x25519() {
        let kx = KeyExchange::generate(NamedGroup::X25519).unwrap();
        assert_eq!(kx.group(), NamedGroup::X25519);
        assert_eq!(kx.public_key_bytes().len(), 32);

        // Generate a peer and compute shared secret both ways
        let peer = KeyExchange::generate(NamedGroup::X25519).unwrap();
        let shared1 = kx.compute_shared_secret(peer.public_key_bytes()).unwrap();
        let shared2 = peer.compute_shared_secret(kx.public_key_bytes()).unwrap();
        assert_eq!(shared1, shared2);
        assert_eq!(shared1.len(), 32);
    }

    #[test]
    fn test_key_exchange_secp256r1() {
        let kx = KeyExchange::generate(NamedGroup::SECP256R1).unwrap();
        assert_eq!(kx.group(), NamedGroup::SECP256R1);
        // P-256 uncompressed point: 0x04 || x(32) || y(32) = 65 bytes
        assert_eq!(kx.public_key_bytes().len(), 65);

        let peer = KeyExchange::generate(NamedGroup::SECP256R1).unwrap();
        let shared1 = kx.compute_shared_secret(peer.public_key_bytes()).unwrap();
        let shared2 = peer.compute_shared_secret(kx.public_key_bytes()).unwrap();
        assert_eq!(shared1, shared2);
        assert_eq!(shared1.len(), 32); // P-256 field size
    }

    #[test]
    fn test_unsupported_group() {
        assert!(KeyExchange::generate(NamedGroup::X448).is_err());
    }
}
