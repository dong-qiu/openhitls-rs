//! TLS 1.3 ephemeral key exchange (X25519, X448, SECP256R1, X25519MLKEM768).

use crate::crypt::NamedGroup;
use hitls_crypto::ecdh::EcdhKeyPair;
use hitls_crypto::mlkem::MlKemKeyPair;
use hitls_crypto::x25519::{X25519PrivateKey, X25519PublicKey};
use hitls_crypto::x448::{X448PrivateKey, X448PublicKey};
use hitls_types::TlsError;

/// Inner key exchange state (variant per named group).
enum KeyExchangeInner {
    X25519(X25519PrivateKey),
    X448(X448PrivateKey),
    EcdhP256(Box<EcdhKeyPair>),
    #[cfg(feature = "tlcp")]
    EcdhSm2(Box<EcdhKeyPair>),
    HybridX25519MlKem768 {
        mlkem: MlKemKeyPair,
        x25519_sk: X25519PrivateKey,
    },
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
            NamedGroup::X448 => {
                let private_key = X448PrivateKey::generate().map_err(TlsError::CryptoError)?;
                let public_key = private_key.public_key();
                let public_key_bytes = public_key.as_bytes().to_vec();
                Ok(Self {
                    group,
                    inner: KeyExchangeInner::X448(private_key),
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
            #[cfg(feature = "tlcp")]
            NamedGroup::SM2P256 => {
                let kp = EcdhKeyPair::generate(hitls_types::EccCurveId::Sm2Prime256)
                    .map_err(TlsError::CryptoError)?;
                let public_key_bytes = kp.public_key_bytes().map_err(TlsError::CryptoError)?;
                Ok(Self {
                    group,
                    inner: KeyExchangeInner::EcdhSm2(Box::new(kp)),
                    public_key_bytes,
                })
            }
            NamedGroup::X25519_MLKEM768 => {
                let mlkem = MlKemKeyPair::generate(768).map_err(TlsError::CryptoError)?;
                let x25519_sk = X25519PrivateKey::generate().map_err(TlsError::CryptoError)?;
                let x25519_pk = x25519_sk.public_key();
                // Wire format: mlkem_ek(1184) || x25519_pk(32) = 1216 bytes
                let mut public_key_bytes = mlkem.encapsulation_key().to_vec();
                public_key_bytes.extend_from_slice(x25519_pk.as_bytes());
                Ok(Self {
                    group,
                    inner: KeyExchangeInner::HybridX25519MlKem768 { mlkem, x25519_sk },
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
            KeyExchangeInner::X448(private_key) => {
                let peer_key = X448PublicKey::new(peer_public).map_err(TlsError::CryptoError)?;
                private_key
                    .diffie_hellman(&peer_key)
                    .map_err(TlsError::CryptoError)
            }
            KeyExchangeInner::EcdhP256(kp) => kp
                .compute_shared_secret(peer_public)
                .map_err(TlsError::CryptoError),
            #[cfg(feature = "tlcp")]
            KeyExchangeInner::EcdhSm2(kp) => kp
                .compute_shared_secret(peer_public)
                .map_err(TlsError::CryptoError),
            KeyExchangeInner::HybridX25519MlKem768 { mlkem, x25519_sk } => {
                // peer_public = mlkem_ct(1088) || x25519_eph_pk(32) = 1120 bytes
                if peer_public.len() != 1120 {
                    return Err(TlsError::HandshakeFailed(
                        "invalid hybrid KEM ciphertext length".into(),
                    ));
                }
                let mlkem_ct = &peer_public[..1088];
                let x25519_pk_bytes = &peer_public[1088..1120];
                let mlkem_ss = mlkem.decapsulate(mlkem_ct).map_err(TlsError::CryptoError)?;
                let x25519_pk =
                    X25519PublicKey::new(x25519_pk_bytes).map_err(TlsError::CryptoError)?;
                let x25519_ss = x25519_sk
                    .diffie_hellman(&x25519_pk)
                    .map_err(TlsError::CryptoError)?;
                // Shared secret: mlkem_ss(32) || x25519_ss(32) = 64 bytes
                let mut shared_secret = mlkem_ss;
                shared_secret.extend_from_slice(&x25519_ss);
                Ok(shared_secret)
            }
        }
    }

    /// Server-side KEM encapsulation for hybrid groups.
    ///
    /// Returns `(shared_secret, ciphertext_for_key_share)`.
    pub fn encapsulate(
        group: NamedGroup,
        peer_public_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
        match group {
            NamedGroup::X25519_MLKEM768 => {
                // peer_public_key = mlkem_ek(1184) || x25519_pk(32) = 1216 bytes
                if peer_public_key.len() != 1216 {
                    return Err(TlsError::HandshakeFailed(
                        "invalid hybrid KEM public key length".into(),
                    ));
                }
                let mlkem_ek = &peer_public_key[..1184];
                let x25519_pk_bytes = &peer_public_key[1184..1216];

                // ML-KEM encapsulate to peer's encapsulation key
                let mlkem_kp = MlKemKeyPair::from_encapsulation_key(768, mlkem_ek)
                    .map_err(TlsError::CryptoError)?;
                let (mlkem_ss, mlkem_ct) = mlkem_kp.encapsulate().map_err(TlsError::CryptoError)?;

                // X25519 ephemeral DH
                let x25519_eph_sk = X25519PrivateKey::generate().map_err(TlsError::CryptoError)?;
                let x25519_eph_pk = x25519_eph_sk.public_key();
                let x25519_pk =
                    X25519PublicKey::new(x25519_pk_bytes).map_err(TlsError::CryptoError)?;
                let x25519_ss = x25519_eph_sk
                    .diffie_hellman(&x25519_pk)
                    .map_err(TlsError::CryptoError)?;

                // Ciphertext: mlkem_ct(1088) || x25519_eph_pk(32) = 1120 bytes
                let mut ciphertext = mlkem_ct;
                ciphertext.extend_from_slice(x25519_eph_pk.as_bytes());

                // Shared secret: mlkem_ss(32) || x25519_ss(32) = 64 bytes
                let mut shared_secret = mlkem_ss;
                shared_secret.extend_from_slice(&x25519_ss);

                Ok((shared_secret, ciphertext))
            }
            _ => Err(TlsError::HandshakeFailed("not a KEM group".into())),
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
    fn test_key_exchange_x448() {
        let kx = KeyExchange::generate(NamedGroup::X448).unwrap();
        assert_eq!(kx.group(), NamedGroup::X448);
        assert_eq!(kx.public_key_bytes().len(), 56);

        let peer = KeyExchange::generate(NamedGroup::X448).unwrap();
        let shared1 = kx.compute_shared_secret(peer.public_key_bytes()).unwrap();
        let shared2 = peer.compute_shared_secret(kx.public_key_bytes()).unwrap();
        assert_eq!(shared1, shared2);
        assert_eq!(shared1.len(), 56);
    }

    #[test]
    fn test_unsupported_group() {
        assert!(KeyExchange::generate(NamedGroup(0x9999)).is_err());
    }

    #[cfg(feature = "tlcp")]
    #[test]
    fn test_key_exchange_sm2() {
        let kx = KeyExchange::generate(NamedGroup::SM2P256).unwrap();
        assert_eq!(kx.group(), NamedGroup::SM2P256);
        // SM2 uncompressed point: 0x04 || x(32) || y(32) = 65 bytes
        assert_eq!(kx.public_key_bytes().len(), 65);

        let peer = KeyExchange::generate(NamedGroup::SM2P256).unwrap();
        let shared1 = kx.compute_shared_secret(peer.public_key_bytes()).unwrap();
        let shared2 = peer.compute_shared_secret(kx.public_key_bytes()).unwrap();
        assert_eq!(shared1, shared2);
        assert_eq!(shared1.len(), 32); // SM2 field size
    }

    #[test]
    fn test_key_exchange_hybrid_kem() {
        let kx = KeyExchange::generate(NamedGroup::X25519_MLKEM768).unwrap();
        assert_eq!(kx.group(), NamedGroup::X25519_MLKEM768);
        // mlkem768_ek(1184) || x25519_pk(32) = 1216 bytes
        assert_eq!(kx.public_key_bytes().len(), 1216);
    }

    #[test]
    fn test_key_exchange_hybrid_kem_roundtrip() {
        // Client generates key pair
        let client_kx = KeyExchange::generate(NamedGroup::X25519_MLKEM768).unwrap();
        assert_eq!(client_kx.public_key_bytes().len(), 1216);

        // Server encapsulates to client's public key
        let (server_ss, ciphertext) =
            KeyExchange::encapsulate(NamedGroup::X25519_MLKEM768, client_kx.public_key_bytes())
                .unwrap();
        assert_eq!(ciphertext.len(), 1120); // mlkem_ct(1088) || x25519_eph_pk(32)
        assert_eq!(server_ss.len(), 64); // mlkem_ss(32) || x25519_ss(32)

        // Client decapsulates server's ciphertext
        let client_ss = client_kx.compute_shared_secret(&ciphertext).unwrap();
        assert_eq!(client_ss.len(), 64);

        // Shared secrets must match
        assert_eq!(client_ss, server_ss);
    }

    #[test]
    fn test_key_exchange_hybrid_kem_encapsulate_bad_length() {
        assert!(KeyExchange::encapsulate(NamedGroup::X25519_MLKEM768, &[0u8; 100]).is_err());
    }
}
