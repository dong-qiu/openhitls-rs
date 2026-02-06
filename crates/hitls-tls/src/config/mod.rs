//! TLS configuration with builder pattern.

use crate::{CipherSuite, TlsRole, TlsVersion};

/// TLS configuration.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Minimum supported TLS version.
    pub min_version: TlsVersion,
    /// Maximum supported TLS version.
    pub max_version: TlsVersion,
    /// Enabled cipher suites (in preference order).
    pub cipher_suites: Vec<CipherSuite>,
    /// The role (client or server).
    pub role: TlsRole,
    /// Enable session resumption.
    pub session_resumption: bool,
    /// ALPN protocols (in preference order).
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Server name for SNI extension.
    pub server_name: Option<String>,
}

impl TlsConfig {
    /// Create a builder for TLS configuration.
    pub fn builder() -> TlsConfigBuilder {
        TlsConfigBuilder::default()
    }
}

/// Builder for `TlsConfig`.
#[derive(Debug)]
pub struct TlsConfigBuilder {
    min_version: TlsVersion,
    max_version: TlsVersion,
    cipher_suites: Vec<CipherSuite>,
    role: TlsRole,
    session_resumption: bool,
    alpn_protocols: Vec<Vec<u8>>,
    server_name: Option<String>,
}

impl Default for TlsConfigBuilder {
    fn default() -> Self {
        Self {
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
            cipher_suites: vec![
                CipherSuite::TLS_AES_256_GCM_SHA384,
                CipherSuite::TLS_AES_128_GCM_SHA256,
                CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
            ],
            role: TlsRole::Client,
            session_resumption: true,
            alpn_protocols: Vec::new(),
            server_name: None,
        }
    }
}

impl TlsConfigBuilder {
    pub fn min_version(mut self, version: TlsVersion) -> Self {
        self.min_version = version;
        self
    }

    pub fn max_version(mut self, version: TlsVersion) -> Self {
        self.max_version = version;
        self
    }

    pub fn cipher_suites(mut self, suites: &[CipherSuite]) -> Self {
        self.cipher_suites = suites.to_vec();
        self
    }

    pub fn role(mut self, role: TlsRole) -> Self {
        self.role = role;
        self
    }

    pub fn session_resumption(mut self, enabled: bool) -> Self {
        self.session_resumption = enabled;
        self
    }

    pub fn alpn(mut self, protocols: &[&[u8]]) -> Self {
        self.alpn_protocols = protocols.iter().map(|p| p.to_vec()).collect();
        self
    }

    pub fn server_name(mut self, name: &str) -> Self {
        self.server_name = Some(name.to_string());
        self
    }

    pub fn build(self) -> TlsConfig {
        TlsConfig {
            min_version: self.min_version,
            max_version: self.max_version,
            cipher_suites: self.cipher_suites,
            role: self.role,
            session_resumption: self.session_resumption,
            alpn_protocols: self.alpn_protocols,
            server_name: self.server_name,
        }
    }
}
