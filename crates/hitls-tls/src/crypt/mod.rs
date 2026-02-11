//! TLS cryptographic operations wrapper.
//!
//! Bridges the TLS protocol with the underlying `hitls-crypto` primitives.

pub mod aead;
pub mod hkdf;
pub mod key_schedule;
pub mod key_schedule12;
pub mod keylog;
pub mod prf;
pub mod traffic_keys;
pub mod transcript;

use crate::CipherSuite;
use hitls_crypto::provider::Digest;
use hitls_crypto::sha1::Sha1;
use hitls_crypto::sha2::{Sha256, Sha384};
#[cfg(feature = "tlcp")]
use hitls_crypto::sm3::Sm3;
use hitls_types::TlsError;

/// A factory closure that creates fresh Digest instances.
pub type HashFactory = Box<dyn Fn() -> Box<dyn Digest> + Send + Sync>;

/// Parameters associated with a TLS 1.3 cipher suite.
#[derive(Debug, Clone)]
pub struct CipherSuiteParams {
    /// The cipher suite identifier.
    pub suite: CipherSuite,
    /// Hash output size in bytes (32 for SHA-256, 48 for SHA-384).
    pub hash_len: usize,
    /// AEAD key length in bytes.
    pub key_len: usize,
    /// AEAD IV/nonce length in bytes (always 12 for TLS 1.3).
    pub iv_len: usize,
    /// AEAD tag length in bytes (always 16).
    pub tag_len: usize,
}

impl CipherSuiteParams {
    /// Look up parameters for a TLS 1.3 cipher suite.
    pub fn from_suite(suite: CipherSuite) -> Result<Self, TlsError> {
        match suite {
            CipherSuite::TLS_AES_128_GCM_SHA256 => Ok(Self {
                suite,
                hash_len: 32,
                key_len: 16,
                iv_len: 12,
                tag_len: 16,
            }),
            CipherSuite::TLS_AES_256_GCM_SHA384 => Ok(Self {
                suite,
                hash_len: 48,
                key_len: 32,
                iv_len: 12,
                tag_len: 16,
            }),
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => Ok(Self {
                suite,
                hash_len: 32,
                key_len: 32,
                iv_len: 12,
                tag_len: 16,
            }),
            _ => Err(TlsError::NoSharedCipherSuite),
        }
    }

    /// Create a HashFactory for this cipher suite's hash algorithm.
    pub fn hash_factory(&self) -> HashFactory {
        match self.hash_len {
            48 => Box::new(|| Box::new(Sha384::new()) as Box<dyn Digest>),
            _ => Box::new(|| Box::new(Sha256::new()) as Box<dyn Digest>),
        }
    }
}

/// TLS named group identifiers (for key exchange).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamedGroup(pub u16);

impl NamedGroup {
    // Elliptic curves
    pub const SECP256R1: Self = Self(0x0017);
    pub const SECP384R1: Self = Self(0x0018);
    pub const SECP521R1: Self = Self(0x0019);
    pub const X25519: Self = Self(0x001D);
    pub const X448: Self = Self(0x001E);
    // Finite field DH
    pub const FFDHE2048: Self = Self(0x0100);
    pub const FFDHE3072: Self = Self(0x0101);
    pub const FFDHE4096: Self = Self(0x0102);
    // Post-quantum (draft)
    pub const X25519_MLKEM768: Self = Self(0x6399);
    // TLCP SM2 curve
    pub const SM2P256: Self = Self(0x0041);

    /// Returns true if this group uses KEM (encapsulate/decapsulate) instead of DH.
    pub fn is_kem(&self) -> bool {
        matches!(*self, NamedGroup::X25519_MLKEM768)
    }
}

/// TLS signature scheme identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureScheme(pub u16);

impl SignatureScheme {
    pub const RSA_PKCS1_SHA256: Self = Self(0x0401);
    pub const RSA_PKCS1_SHA384: Self = Self(0x0501);
    pub const RSA_PKCS1_SHA512: Self = Self(0x0601);
    pub const ECDSA_SECP256R1_SHA256: Self = Self(0x0403);
    pub const ECDSA_SECP384R1_SHA384: Self = Self(0x0503);
    pub const ECDSA_SECP521R1_SHA512: Self = Self(0x0603);
    pub const RSA_PSS_RSAE_SHA256: Self = Self(0x0804);
    pub const RSA_PSS_RSAE_SHA384: Self = Self(0x0805);
    pub const RSA_PSS_RSAE_SHA512: Self = Self(0x0806);
    pub const ED25519: Self = Self(0x0807);
    pub const SM2_SM3: Self = Self(0x0708);
}

/// TLS 1.2 / TLCP key exchange algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeAlg {
    Ecdhe,
    /// Static RSA key exchange (client encrypts PMS with server's RSA cert key).
    Rsa,
    /// Ephemeral Diffie-Hellman key exchange (server sends DH params in SKE).
    Dhe,
    /// Plain PSK key exchange (RFC 4279) — no certificates, identity-based.
    Psk,
    /// DHE_PSK key exchange (RFC 4279) — DH + PSK, no certificates.
    DhePsk,
    /// RSA_PSK key exchange (RFC 4279) — RSA encryption + PSK, server has certificate.
    RsaPsk,
    /// ECDHE_PSK key exchange (RFC 5489) — ECDH + PSK, no certificates.
    EcdhePsk,
    /// TLCP ECC static key exchange (SM2 encryption of premaster secret).
    #[cfg(feature = "tlcp")]
    Ecc,
}

impl KeyExchangeAlg {
    /// Returns true if this is any PSK-based key exchange.
    pub fn is_psk(&self) -> bool {
        matches!(
            self,
            Self::Psk | Self::DhePsk | Self::RsaPsk | Self::EcdhePsk
        )
    }

    /// Returns true if the server should send a Certificate message.
    pub fn requires_certificate(&self) -> bool {
        !matches!(self, Self::Psk | Self::DhePsk | Self::EcdhePsk)
    }
}

/// TLS 1.2 / TLCP authentication algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthAlg {
    Rsa,
    Ecdsa,
    /// PSK-based authentication (no certificate signatures).
    Psk,
    #[cfg(feature = "tlcp")]
    Sm2,
}

/// Parameters associated with a TLS 1.2 cipher suite.
#[derive(Debug, Clone)]
pub struct Tls12CipherSuiteParams {
    /// The cipher suite identifier.
    pub suite: CipherSuite,
    /// Key exchange algorithm.
    pub kx_alg: KeyExchangeAlg,
    /// Authentication algorithm.
    pub auth_alg: AuthAlg,
    /// PRF hash output size in bytes (32 for SHA-256, 48 for SHA-384).
    pub hash_len: usize,
    /// Encryption key length in bytes (16 or 32).
    pub key_len: usize,
    /// Fixed IV length from key_block (4 for GCM/ChaCha20, 16 for CBC).
    pub fixed_iv_len: usize,
    /// Explicit nonce length sent with each record (8 for GCM/ChaCha20, 0 for CBC).
    pub record_iv_len: usize,
    /// AEAD tag length in bytes (16 for GCM/ChaCha20, 0 for CBC).
    pub tag_len: usize,
    /// MAC key length (0 for AEAD, 20 for HMAC-SHA1, 32 for SHA-256, 48 for SHA-384).
    pub mac_key_len: usize,
    /// MAC output length (0 for AEAD, 20 for SHA-1, 32 for SHA-256, 48 for SHA-384).
    pub mac_len: usize,
    /// true = CBC MAC-then-encrypt, false = AEAD (GCM/ChaCha20).
    pub is_cbc: bool,
}

impl Tls12CipherSuiteParams {
    /// Look up parameters for a TLS 1.2 cipher suite.
    pub fn from_suite(suite: CipherSuite) -> Result<Self, TlsError> {
        match suite {
            // --- ECDHE-GCM suites ---
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Ecdhe,
                auth_alg: AuthAlg::Rsa,
                hash_len: 32,
                key_len: 16,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Ecdhe,
                auth_alg: AuthAlg::Rsa,
                hash_len: 48,
                key_len: 32,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Ecdhe,
                auth_alg: AuthAlg::Ecdsa,
                hash_len: 32,
                key_len: 16,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Ecdhe,
                auth_alg: AuthAlg::Ecdsa,
                hash_len: 48,
                key_len: 32,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            // --- ECDHE-CBC-SHA suites (PRF=SHA-256, MAC=HMAC-SHA1) ---
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Ecdhe,
                auth_alg: AuthAlg::Rsa,
                hash_len: 32,
                key_len: 16,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 20,
                mac_len: 20,
                is_cbc: true,
            }),
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Ecdhe,
                auth_alg: AuthAlg::Rsa,
                hash_len: 32,
                key_len: 32,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 20,
                mac_len: 20,
                is_cbc: true,
            }),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Ecdhe,
                auth_alg: AuthAlg::Ecdsa,
                hash_len: 32,
                key_len: 16,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 20,
                mac_len: 20,
                is_cbc: true,
            }),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Ecdhe,
                auth_alg: AuthAlg::Ecdsa,
                hash_len: 32,
                key_len: 32,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 20,
                mac_len: 20,
                is_cbc: true,
            }),
            // --- ECDHE-CBC-SHA256 suites (PRF=SHA-256, MAC=HMAC-SHA256) ---
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Ecdhe,
                auth_alg: AuthAlg::Rsa,
                hash_len: 32,
                key_len: 16,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 32,
                mac_len: 32,
                is_cbc: true,
            }),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Ecdhe,
                auth_alg: AuthAlg::Ecdsa,
                hash_len: 32,
                key_len: 16,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 32,
                mac_len: 32,
                is_cbc: true,
            }),
            // --- ECDHE-CBC-SHA384 suites (PRF=SHA-384, MAC=HMAC-SHA384) ---
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Ecdhe,
                auth_alg: AuthAlg::Rsa,
                hash_len: 48,
                key_len: 32,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 48,
                mac_len: 48,
                is_cbc: true,
            }),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Ecdhe,
                auth_alg: AuthAlg::Ecdsa,
                hash_len: 48,
                key_len: 32,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 48,
                mac_len: 48,
                is_cbc: true,
            }),
            // --- ECDHE-ChaCha20-Poly1305 suites (PRF=SHA-256, AEAD) ---
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Ecdhe,
                auth_alg: AuthAlg::Rsa,
                hash_len: 32,
                key_len: 32,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Ecdhe,
                auth_alg: AuthAlg::Ecdsa,
                hash_len: 32,
                key_len: 32,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            // --- RSA static KX GCM suites ---
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Rsa,
                auth_alg: AuthAlg::Rsa,
                hash_len: 32,
                key_len: 16,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Rsa,
                auth_alg: AuthAlg::Rsa,
                hash_len: 48,
                key_len: 32,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            // --- RSA static KX CBC suites ---
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Rsa,
                auth_alg: AuthAlg::Rsa,
                hash_len: 32,
                key_len: 16,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 20,
                mac_len: 20,
                is_cbc: true,
            }),
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Rsa,
                auth_alg: AuthAlg::Rsa,
                hash_len: 32,
                key_len: 32,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 20,
                mac_len: 20,
                is_cbc: true,
            }),
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Rsa,
                auth_alg: AuthAlg::Rsa,
                hash_len: 32,
                key_len: 16,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 32,
                mac_len: 32,
                is_cbc: true,
            }),
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Rsa,
                auth_alg: AuthAlg::Rsa,
                hash_len: 32,
                key_len: 32,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 32,
                mac_len: 32,
                is_cbc: true,
            }),
            // --- DHE_RSA GCM suites ---
            CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Dhe,
                auth_alg: AuthAlg::Rsa,
                hash_len: 32,
                key_len: 16,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Dhe,
                auth_alg: AuthAlg::Rsa,
                hash_len: 48,
                key_len: 32,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            // --- DHE_RSA CBC suites ---
            CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Dhe,
                auth_alg: AuthAlg::Rsa,
                hash_len: 32,
                key_len: 16,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 20,
                mac_len: 20,
                is_cbc: true,
            }),
            CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Dhe,
                auth_alg: AuthAlg::Rsa,
                hash_len: 32,
                key_len: 32,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 20,
                mac_len: 20,
                is_cbc: true,
            }),
            CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Dhe,
                auth_alg: AuthAlg::Rsa,
                hash_len: 32,
                key_len: 16,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 32,
                mac_len: 32,
                is_cbc: true,
            }),
            CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Dhe,
                auth_alg: AuthAlg::Rsa,
                hash_len: 32,
                key_len: 32,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 32,
                mac_len: 32,
                is_cbc: true,
            }),
            // --- DHE_RSA ChaCha20-Poly1305 suite ---
            CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Dhe,
                auth_alg: AuthAlg::Rsa,
                hash_len: 32,
                key_len: 32,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            // --- Plain PSK GCM suites ---
            CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Psk,
                auth_alg: AuthAlg::Psk,
                hash_len: 32,
                key_len: 16,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            CipherSuite::TLS_PSK_WITH_AES_256_GCM_SHA384 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Psk,
                auth_alg: AuthAlg::Psk,
                hash_len: 48,
                key_len: 32,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            // --- Plain PSK CBC suites ---
            CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Psk,
                auth_alg: AuthAlg::Psk,
                hash_len: 32,
                key_len: 16,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 20,
                mac_len: 20,
                is_cbc: true,
            }),
            CipherSuite::TLS_PSK_WITH_AES_256_CBC_SHA => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Psk,
                auth_alg: AuthAlg::Psk,
                hash_len: 32,
                key_len: 32,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 20,
                mac_len: 20,
                is_cbc: true,
            }),
            // --- Plain PSK ChaCha20-Poly1305 ---
            CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Psk,
                auth_alg: AuthAlg::Psk,
                hash_len: 32,
                key_len: 32,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            // --- DHE_PSK GCM suites ---
            CipherSuite::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::DhePsk,
                auth_alg: AuthAlg::Psk,
                hash_len: 32,
                key_len: 16,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            CipherSuite::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::DhePsk,
                auth_alg: AuthAlg::Psk,
                hash_len: 48,
                key_len: 32,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            // --- DHE_PSK CBC suites ---
            CipherSuite::TLS_DHE_PSK_WITH_AES_128_CBC_SHA => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::DhePsk,
                auth_alg: AuthAlg::Psk,
                hash_len: 32,
                key_len: 16,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 20,
                mac_len: 20,
                is_cbc: true,
            }),
            CipherSuite::TLS_DHE_PSK_WITH_AES_256_CBC_SHA => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::DhePsk,
                auth_alg: AuthAlg::Psk,
                hash_len: 32,
                key_len: 32,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 20,
                mac_len: 20,
                is_cbc: true,
            }),
            // --- DHE_PSK ChaCha20-Poly1305 ---
            CipherSuite::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::DhePsk,
                auth_alg: AuthAlg::Psk,
                hash_len: 32,
                key_len: 32,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            // --- RSA_PSK GCM suites ---
            CipherSuite::TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::RsaPsk,
                auth_alg: AuthAlg::Rsa,
                hash_len: 32,
                key_len: 16,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            CipherSuite::TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::RsaPsk,
                auth_alg: AuthAlg::Rsa,
                hash_len: 48,
                key_len: 32,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            // --- RSA_PSK CBC suites ---
            CipherSuite::TLS_RSA_PSK_WITH_AES_128_CBC_SHA => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::RsaPsk,
                auth_alg: AuthAlg::Rsa,
                hash_len: 32,
                key_len: 16,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 20,
                mac_len: 20,
                is_cbc: true,
            }),
            CipherSuite::TLS_RSA_PSK_WITH_AES_256_CBC_SHA => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::RsaPsk,
                auth_alg: AuthAlg::Rsa,
                hash_len: 32,
                key_len: 32,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 20,
                mac_len: 20,
                is_cbc: true,
            }),
            // --- RSA_PSK ChaCha20-Poly1305 ---
            CipherSuite::TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::RsaPsk,
                auth_alg: AuthAlg::Rsa,
                hash_len: 32,
                key_len: 32,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            // --- ECDHE_PSK CBC suites ---
            CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::EcdhePsk,
                auth_alg: AuthAlg::Psk,
                hash_len: 32,
                key_len: 16,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 20,
                mac_len: 20,
                is_cbc: true,
            }),
            CipherSuite::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::EcdhePsk,
                auth_alg: AuthAlg::Psk,
                hash_len: 32,
                key_len: 32,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 20,
                mac_len: 20,
                is_cbc: true,
            }),
            CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::EcdhePsk,
                auth_alg: AuthAlg::Psk,
                hash_len: 32,
                key_len: 16,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 32,
                mac_len: 32,
                is_cbc: true,
            }),
            CipherSuite::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::EcdhePsk,
                auth_alg: AuthAlg::Psk,
                hash_len: 48,
                key_len: 32,
                fixed_iv_len: 16,
                record_iv_len: 0,
                tag_len: 0,
                mac_key_len: 48,
                mac_len: 48,
                is_cbc: true,
            }),
            // --- ECDHE_PSK ChaCha20-Poly1305 ---
            CipherSuite::TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::EcdhePsk,
                auth_alg: AuthAlg::Psk,
                hash_len: 32,
                key_len: 32,
                fixed_iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
                mac_key_len: 0,
                mac_len: 0,
                is_cbc: false,
            }),
            _ => Err(TlsError::NoSharedCipherSuite),
        }
    }

    /// Create a HashFactory for this cipher suite's PRF hash algorithm.
    pub fn hash_factory(&self) -> HashFactory {
        match self.hash_len {
            48 => Box::new(|| Box::new(Sha384::new()) as Box<dyn Digest>),
            _ => Box::new(|| Box::new(Sha256::new()) as Box<dyn Digest>),
        }
    }

    /// Create a HashFactory for the MAC hash algorithm (CBC suites only).
    /// Returns SHA-1 for mac_len=20, SHA-256 for mac_len=32, SHA-384 for mac_len=48.
    pub fn mac_hash_factory(&self) -> HashFactory {
        match self.mac_len {
            20 => Box::new(|| Box::new(Sha1::new()) as Box<dyn Digest>),
            48 => Box::new(|| Box::new(Sha384::new()) as Box<dyn Digest>),
            _ => Box::new(|| Box::new(Sha256::new()) as Box<dyn Digest>),
        }
    }

    /// Total key material needed from the key block.
    /// CBC: 2*mac_key + 2*enc_key + 2*iv. AEAD: 2*enc_key + 2*fixed_iv.
    pub fn key_block_len(&self) -> usize {
        2 * self.mac_key_len + 2 * self.key_len + 2 * self.fixed_iv_len
    }
}

/// Returns true if the cipher suite is a TLS 1.2 suite.
pub fn is_tls12_suite(suite: CipherSuite) -> bool {
    Tls12CipherSuiteParams::from_suite(suite).is_ok()
}

/// Returns true if the cipher suite is a TLS 1.3 suite.
pub fn is_tls13_suite(suite: CipherSuite) -> bool {
    CipherSuiteParams::from_suite(suite).is_ok()
}

/// Parameters associated with a TLCP cipher suite (GM/T 0024).
///
/// TLCP uses SM4 (16-byte key) and SM3 (32-byte hash) exclusively.
/// CBC suites use MAC-then-encrypt with HMAC-SM3.
/// GCM suites use SM4-GCM AEAD.
#[cfg(feature = "tlcp")]
#[derive(Debug, Clone)]
pub struct TlcpCipherSuiteParams {
    /// The cipher suite identifier.
    pub suite: CipherSuite,
    /// Key exchange algorithm: Ecdhe (forward secrecy) or Ecc (static).
    pub kx_alg: KeyExchangeAlg,
    /// true = SM4-CBC + HMAC-SM3, false = SM4-GCM AEAD.
    pub is_cbc: bool,
    /// SM4 encryption key length (always 16).
    pub enc_key_len: usize,
    /// MAC key length: 32 for CBC (HMAC-SM3), 0 for GCM.
    pub mac_key_len: usize,
    /// IV length: 16 for CBC, 4 (fixed portion) for GCM.
    pub iv_len: usize,
    /// Explicit nonce length per record: 0 for CBC (IV is random per record),
    /// 8 for GCM.
    pub record_iv_len: usize,
    /// Tag/MAC output length: 32 for CBC (HMAC-SM3), 16 for GCM.
    pub tag_len: usize,
}

#[cfg(feature = "tlcp")]
impl TlcpCipherSuiteParams {
    /// Look up parameters for a TLCP cipher suite.
    pub fn from_suite(suite: CipherSuite) -> Result<Self, TlsError> {
        match suite {
            CipherSuite::ECDHE_SM4_CBC_SM3 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Ecdhe,
                is_cbc: true,
                enc_key_len: 16,
                mac_key_len: 32,
                iv_len: 16,
                record_iv_len: 0,
                tag_len: 32,
            }),
            CipherSuite::ECC_SM4_CBC_SM3 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Ecc,
                is_cbc: true,
                enc_key_len: 16,
                mac_key_len: 32,
                iv_len: 16,
                record_iv_len: 0,
                tag_len: 32,
            }),
            CipherSuite::ECDHE_SM4_GCM_SM3 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Ecdhe,
                is_cbc: false,
                enc_key_len: 16,
                mac_key_len: 0,
                iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
            }),
            CipherSuite::ECC_SM4_GCM_SM3 => Ok(Self {
                suite,
                kx_alg: KeyExchangeAlg::Ecc,
                is_cbc: false,
                enc_key_len: 16,
                mac_key_len: 0,
                iv_len: 4,
                record_iv_len: 8,
                tag_len: 16,
            }),
            _ => Err(TlsError::NoSharedCipherSuite),
        }
    }

    /// Create a HashFactory for SM3 (always SM3 for TLCP).
    pub fn hash_factory(&self) -> HashFactory {
        Box::new(|| Box::new(Sm3::new()) as Box<dyn Digest>)
    }

    /// SM3 hash output length (always 32).
    pub fn hash_len(&self) -> usize {
        32
    }

    /// Total key material needed from the key block.
    ///
    /// CBC: 2×32 (MAC) + 2×16 (enc key) + 2×16 (IV) = 128 bytes.
    /// GCM: 2×16 (enc key) + 2×4 (fixed IV) = 40 bytes.
    pub fn key_block_len(&self) -> usize {
        2 * self.mac_key_len + 2 * self.enc_key_len + 2 * self.iv_len
    }
}

/// Returns true if the cipher suite is a TLCP suite.
#[cfg(feature = "tlcp")]
pub fn is_tlcp_suite(suite: CipherSuite) -> bool {
    TlcpCipherSuiteParams::from_suite(suite).is_ok()
}

#[cfg(test)]
#[cfg(feature = "tlcp")]
mod tests_tlcp {
    use super::*;

    #[test]
    fn test_tlcp_cipher_suite_params_ecdhe_cbc() {
        let params = TlcpCipherSuiteParams::from_suite(CipherSuite::ECDHE_SM4_CBC_SM3).unwrap();
        assert_eq!(params.kx_alg, KeyExchangeAlg::Ecdhe);
        assert!(params.is_cbc);
        assert_eq!(params.enc_key_len, 16);
        assert_eq!(params.mac_key_len, 32);
        assert_eq!(params.iv_len, 16);
        assert_eq!(params.tag_len, 32);
        assert_eq!(params.key_block_len(), 128);
        assert_eq!(params.hash_len(), 32);
    }

    #[test]
    fn test_tlcp_cipher_suite_params_ecc_gcm() {
        let params = TlcpCipherSuiteParams::from_suite(CipherSuite::ECC_SM4_GCM_SM3).unwrap();
        assert_eq!(params.kx_alg, KeyExchangeAlg::Ecc);
        assert!(!params.is_cbc);
        assert_eq!(params.enc_key_len, 16);
        assert_eq!(params.mac_key_len, 0);
        assert_eq!(params.iv_len, 4);
        assert_eq!(params.record_iv_len, 8);
        assert_eq!(params.tag_len, 16);
        assert_eq!(params.key_block_len(), 40);
    }

    #[test]
    fn test_tlcp_key_block_cbc_sizes() {
        // CBC: 2*32 + 2*16 + 2*16 = 128
        let cbc = TlcpCipherSuiteParams::from_suite(CipherSuite::ECC_SM4_CBC_SM3).unwrap();
        assert_eq!(cbc.key_block_len(), 128);
    }

    #[test]
    fn test_tlcp_key_block_gcm_sizes() {
        // GCM: 2*0 + 2*16 + 2*4 = 40
        let gcm = TlcpCipherSuiteParams::from_suite(CipherSuite::ECDHE_SM4_GCM_SM3).unwrap();
        assert_eq!(gcm.key_block_len(), 40);
    }

    #[test]
    fn test_tlcp_sm3_hash_factory() {
        let params = TlcpCipherSuiteParams::from_suite(CipherSuite::ECDHE_SM4_CBC_SM3).unwrap();
        let factory = params.hash_factory();
        let mut hasher = factory();
        hasher.update(b"abc").unwrap();
        let mut digest = vec![0u8; 32];
        hasher.finish(&mut digest).unwrap();
        assert_eq!(digest.len(), 32);
        // SM3("abc") known value
        let expected = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
        let got: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn test_is_tlcp_suite() {
        assert!(is_tlcp_suite(CipherSuite::ECDHE_SM4_CBC_SM3));
        assert!(is_tlcp_suite(CipherSuite::ECC_SM4_CBC_SM3));
        assert!(is_tlcp_suite(CipherSuite::ECDHE_SM4_GCM_SM3));
        assert!(is_tlcp_suite(CipherSuite::ECC_SM4_GCM_SM3));
        assert!(!is_tlcp_suite(CipherSuite::TLS_AES_128_GCM_SHA256));
    }
}
