//! Key material and enumeration types for TLS configuration.

pub use hitls_types::EccCurveId;
use zeroize::Zeroize;

/// Max fragment length values (RFC 6066 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxFragmentLength {
    Bits512 = 1,
    Bits1024 = 2,
    Bits2048 = 3,
    Bits4096 = 4,
}

impl MaxFragmentLength {
    pub fn to_size(self) -> usize {
        match self {
            Self::Bits512 => 512,
            Self::Bits1024 => 1024,
            Self::Bits2048 => 2048,
            Self::Bits4096 => 4096,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Bits512),
            2 => Some(Self::Bits1024),
            3 => Some(Self::Bits2048),
            4 => Some(Self::Bits4096),
            _ => None,
        }
    }
}

/// Server private key material for CertificateVerify signing.
#[derive(Debug, Clone)]
pub enum ServerPrivateKey {
    /// Ed25519 32-byte seed.
    Ed25519(Vec<u8>),
    /// Ed448 57-byte seed.
    Ed448(Vec<u8>),
    /// ECDSA private key bytes + curve identifier.
    Ecdsa {
        curve_id: EccCurveId,
        private_key: Vec<u8>,
    },
    /// RSA private key components (all big-endian).
    Rsa {
        n: Vec<u8>,
        d: Vec<u8>,
        e: Vec<u8>,
        p: Vec<u8>,
        q: Vec<u8>,
    },
    /// DSA private key with domain parameters.
    Dsa {
        /// DER-encoded DSAParameters (SEQUENCE { INTEGER p, INTEGER q, INTEGER g }).
        params_der: Vec<u8>,
        /// Private key x as big-endian bytes.
        private_key: Vec<u8>,
    },
    /// SM2 private key bytes (big-endian scalar on the SM2 curve).
    #[cfg(feature = "tlcp")]
    Sm2 { private_key: Vec<u8> },
}

impl Drop for ServerPrivateKey {
    fn drop(&mut self) {
        match self {
            ServerPrivateKey::Ed25519(seed) => seed.zeroize(),
            ServerPrivateKey::Ed448(seed) => seed.zeroize(),
            ServerPrivateKey::Ecdsa { private_key, .. } => private_key.zeroize(),
            ServerPrivateKey::Rsa { d, p, q, .. } => {
                d.zeroize();
                p.zeroize();
                q.zeroize();
            }
            ServerPrivateKey::Dsa { private_key, .. } => private_key.zeroize(),
            #[cfg(feature = "tlcp")]
            ServerPrivateKey::Sm2 { private_key } => private_key.zeroize(),
        }
    }
}

/// Action to take after the SNI callback processes a hostname.
#[derive(Clone)]
pub enum SniAction {
    /// Accept the connection with the current config.
    Accept,
    /// Accept the connection with a different config (e.g., different certificate).
    AcceptWithConfig(Box<super::TlsConfig>),
    /// Reject the connection with unrecognized_name alert.
    Reject,
    /// Ignore the SNI extension (clear the server name).
    Ignore,
}
