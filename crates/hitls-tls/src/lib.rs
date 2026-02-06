#![forbid(unsafe_code)]
#![doc = "TLS protocol implementation for openHiTLS."]

pub mod alert;
pub mod config;
pub mod crypt;
pub mod extensions;
pub mod handshake;
pub mod record;
pub mod session;

use hitls_types::TlsError;

/// TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersion {
    Tls12,
    Tls13,
    Dtls12,
    Tlcp,
}

/// TLS cipher suite identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CipherSuite(pub u16);

impl CipherSuite {
    // TLS 1.3 cipher suites
    pub const TLS_AES_128_GCM_SHA256: Self = Self(0x1301);
    pub const TLS_AES_256_GCM_SHA384: Self = Self(0x1302);
    pub const TLS_CHACHA20_POLY1305_SHA256: Self = Self(0x1303);
    pub const TLS_AES_128_CCM_SHA256: Self = Self(0x1304);

    // TLS 1.2 cipher suites (representative)
    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: Self = Self(0xC02F);
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: Self = Self(0xC030);
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: Self = Self(0xC02B);
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: Self = Self(0xC02C);
}

/// The role of a TLS endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsRole {
    Client,
    Server,
}

/// A synchronous TLS connection.
pub trait TlsConnection {
    /// Perform the TLS handshake.
    fn handshake(&mut self) -> Result<(), TlsError>;
    /// Read decrypted data into `buf`.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError>;
    /// Write data to be encrypted and sent.
    fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError>;
    /// Shut down the TLS connection gracefully.
    fn shutdown(&mut self) -> Result<(), TlsError>;
    /// Get the negotiated TLS version.
    fn version(&self) -> Option<TlsVersion>;
    /// Get the negotiated cipher suite.
    fn cipher_suite(&self) -> Option<CipherSuite>;
}
