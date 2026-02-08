//! TLS configuration with builder pattern.

use crate::crypt::{NamedGroup, SignatureScheme};
use crate::session::TlsSession;
use crate::{CipherSuite, TlsRole, TlsVersion};
use hitls_types::EccCurveId;
use zeroize::Zeroize;

/// Server private key material for CertificateVerify signing.
#[derive(Debug, Clone)]
pub enum ServerPrivateKey {
    /// Ed25519 32-byte seed.
    Ed25519(Vec<u8>),
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
}

impl Drop for ServerPrivateKey {
    fn drop(&mut self) {
        match self {
            ServerPrivateKey::Ed25519(seed) => seed.zeroize(),
            ServerPrivateKey::Ecdsa { private_key, .. } => private_key.zeroize(),
            ServerPrivateKey::Rsa { d, p, q, .. } => {
                d.zeroize();
                p.zeroize();
                q.zeroize();
            }
        }
    }
}

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
    /// Supported signature algorithms (in preference order).
    pub signature_algorithms: Vec<SignatureScheme>,
    /// Supported named groups for key exchange.
    pub supported_groups: Vec<NamedGroup>,
    /// Whether to verify the peer's certificate.
    pub verify_peer: bool,
    /// Trusted CA certificates (DER-encoded).
    pub trusted_certs: Vec<Vec<u8>>,
    /// Server certificate chain (DER-encoded, leaf first).
    pub certificate_chain: Vec<Vec<u8>>,
    /// Server private key for CertificateVerify signing.
    pub private_key: Option<ServerPrivateKey>,
    /// Ticket encryption key (32 bytes) for server-side NewSessionTicket generation.
    pub ticket_key: Option<Vec<u8>>,
    /// Session to resume via PSK (client-side).
    pub resumption_session: Option<TlsSession>,
    /// Maximum early data size (0 = disabled, for both client and server).
    pub max_early_data_size: u32,
    /// Client certificate chain (DER-encoded, leaf first) for post-handshake auth.
    pub client_certificate_chain: Vec<Vec<u8>>,
    /// Client private key for post-handshake CertificateVerify signing.
    pub client_private_key: Option<ServerPrivateKey>,
    /// Whether to offer post-handshake authentication (client-side).
    pub post_handshake_auth: bool,
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
    signature_algorithms: Vec<SignatureScheme>,
    supported_groups: Vec<NamedGroup>,
    verify_peer: bool,
    trusted_certs: Vec<Vec<u8>>,
    certificate_chain: Vec<Vec<u8>>,
    private_key: Option<ServerPrivateKey>,
    ticket_key: Option<Vec<u8>>,
    resumption_session: Option<TlsSession>,
    max_early_data_size: u32,
    client_certificate_chain: Vec<Vec<u8>>,
    client_private_key: Option<ServerPrivateKey>,
    post_handshake_auth: bool,
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
            signature_algorithms: vec![
                SignatureScheme::RSA_PSS_RSAE_SHA256,
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                SignatureScheme::ED25519,
            ],
            supported_groups: vec![NamedGroup::X25519],
            verify_peer: true,
            trusted_certs: Vec::new(),
            certificate_chain: Vec::new(),
            private_key: None,
            ticket_key: None,
            resumption_session: None,
            max_early_data_size: 0,
            client_certificate_chain: Vec::new(),
            client_private_key: None,
            post_handshake_auth: false,
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

    pub fn signature_algorithms(mut self, schemes: &[SignatureScheme]) -> Self {
        self.signature_algorithms = schemes.to_vec();
        self
    }

    pub fn supported_groups(mut self, groups: &[NamedGroup]) -> Self {
        self.supported_groups = groups.to_vec();
        self
    }

    pub fn verify_peer(mut self, verify: bool) -> Self {
        self.verify_peer = verify;
        self
    }

    pub fn trusted_cert(mut self, der_cert: Vec<u8>) -> Self {
        self.trusted_certs.push(der_cert);
        self
    }

    pub fn certificate_chain(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.certificate_chain = certs;
        self
    }

    pub fn private_key(mut self, key: ServerPrivateKey) -> Self {
        self.private_key = Some(key);
        self
    }

    pub fn ticket_key(mut self, key: Vec<u8>) -> Self {
        self.ticket_key = Some(key);
        self
    }

    pub fn resumption_session(mut self, session: TlsSession) -> Self {
        self.resumption_session = Some(session);
        self
    }

    pub fn max_early_data_size(mut self, size: u32) -> Self {
        self.max_early_data_size = size;
        self
    }

    pub fn client_certificate_chain(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.client_certificate_chain = certs;
        self
    }

    pub fn client_private_key(mut self, key: ServerPrivateKey) -> Self {
        self.client_private_key = Some(key);
        self
    }

    pub fn post_handshake_auth(mut self, enabled: bool) -> Self {
        self.post_handshake_auth = enabled;
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
            signature_algorithms: self.signature_algorithms,
            supported_groups: self.supported_groups,
            verify_peer: self.verify_peer,
            trusted_certs: self.trusted_certs,
            certificate_chain: self.certificate_chain,
            private_key: self.private_key,
            ticket_key: self.ticket_key,
            resumption_session: self.resumption_session,
            max_early_data_size: self.max_early_data_size,
            client_certificate_chain: self.client_certificate_chain,
            client_private_key: self.client_private_key,
            post_handshake_auth: self.post_handshake_auth,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder_defaults() {
        let config = TlsConfig::builder().build();
        assert_eq!(config.role, TlsRole::Client);
        assert_eq!(config.max_version, TlsVersion::Tls13);
        assert!(config.verify_peer);
        assert!(!config.signature_algorithms.is_empty());
        assert!(!config.supported_groups.is_empty());
        assert_eq!(config.supported_groups[0], NamedGroup::X25519);
    }

    #[test]
    fn test_config_builder_server_defaults() {
        let config = TlsConfig::builder().role(TlsRole::Server).build();
        assert_eq!(config.role, TlsRole::Server);
        assert!(config.certificate_chain.is_empty());
        assert!(config.private_key.is_none());
    }

    #[test]
    fn test_config_builder_with_server_cert() {
        let config = TlsConfig::builder()
            .role(TlsRole::Server)
            .certificate_chain(vec![vec![0x30, 0x82, 0x01, 0x00]])
            .private_key(ServerPrivateKey::Ed25519(vec![0x42; 32]))
            .build();
        assert_eq!(config.certificate_chain.len(), 1);
        assert!(config.private_key.is_some());
        match config.private_key.as_ref().unwrap() {
            ServerPrivateKey::Ed25519(seed) => assert_eq!(seed.len(), 32),
            _ => panic!("expected Ed25519"),
        }
    }

    #[test]
    fn test_config_builder_new_fields() {
        let config = TlsConfig::builder()
            .signature_algorithms(&[SignatureScheme::ED25519])
            .supported_groups(&[NamedGroup::X25519, NamedGroup::SECP256R1])
            .verify_peer(false)
            .trusted_cert(vec![0x30, 0x82])
            .server_name("example.com")
            .build();

        assert_eq!(config.signature_algorithms.len(), 1);
        assert_eq!(config.signature_algorithms[0], SignatureScheme::ED25519);
        assert_eq!(config.supported_groups.len(), 2);
        assert!(!config.verify_peer);
        assert_eq!(config.trusted_certs.len(), 1);
        assert_eq!(config.server_name.as_deref(), Some("example.com"));
    }
}
