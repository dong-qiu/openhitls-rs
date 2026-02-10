//! TLS configuration with builder pattern.

use std::fmt;
use std::sync::Arc;

use crate::crypt::{NamedGroup, SignatureScheme};
use crate::handshake::codec::CertCompressionAlgorithm;
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
    /// SM2 private key bytes (big-endian scalar on the SM2 curve).
    #[cfg(feature = "tlcp")]
    Sm2 { private_key: Vec<u8> },
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
            #[cfg(feature = "tlcp")]
            ServerPrivateKey::Sm2 { private_key } => private_key.zeroize(),
        }
    }
}

/// Server callback for PSK lookup: given a PSK identity, return the PSK value or None.
pub type PskServerCallback = Arc<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync>;

/// TLS configuration.
#[derive(Clone)]
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
    /// Server: request client certificate during TLS 1.2 handshake (mTLS).
    pub verify_client_cert: bool,
    /// Server: reject handshake if client provides no certificate (requires verify_client_cert).
    pub require_client_cert: bool,
    /// Enable Extended Master Secret extension (RFC 7627). Default: true.
    pub enable_extended_master_secret: bool,
    /// Enable Encrypt-Then-MAC extension (RFC 7366, CBC suites only). Default: true.
    pub enable_encrypt_then_mac: bool,
    /// Certificate compression algorithms to offer/accept (RFC 8879).
    /// Empty means disabled.
    pub cert_compression_algos: Vec<CertCompressionAlgorithm>,
    /// Pre-shared key value for TLS 1.2 PSK cipher suites (RFC 4279).
    pub psk: Option<Vec<u8>>,
    /// PSK identity (client: identity to send in CKE; server: for simple matching).
    pub psk_identity: Option<Vec<u8>>,
    /// PSK identity hint (server: sent in SKE to help client select correct PSK).
    pub psk_identity_hint: Option<Vec<u8>>,
    /// Server PSK callback: look up PSK by identity. Returns None if unknown.
    pub psk_server_callback: Option<PskServerCallback>,
    /// TLCP encryption certificate chain (DER-encoded, leaf first).
    /// TLCP uses double certificates: a signing cert + an encryption cert.
    #[cfg(feature = "tlcp")]
    pub tlcp_enc_certificate_chain: Vec<Vec<u8>>,
    /// TLCP encryption private key (SM2).
    #[cfg(feature = "tlcp")]
    pub tlcp_enc_private_key: Option<ServerPrivateKey>,
}

impl fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfig")
            .field("min_version", &self.min_version)
            .field("max_version", &self.max_version)
            .field("cipher_suites", &self.cipher_suites)
            .field("role", &self.role)
            .field("verify_peer", &self.verify_peer)
            .field(
                "psk",
                &self.psk.as_ref().map(|p| format!("[{} bytes]", p.len())),
            )
            .field("psk_identity", &self.psk_identity)
            .field(
                "psk_server_callback",
                &self.psk_server_callback.as_ref().map(|_| "<callback>"),
            )
            .finish_non_exhaustive()
    }
}

impl TlsConfig {
    /// Create a builder for TLS configuration.
    pub fn builder() -> TlsConfigBuilder {
        TlsConfigBuilder::default()
    }
}

/// Builder for `TlsConfig`.
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
    verify_client_cert: bool,
    require_client_cert: bool,
    enable_extended_master_secret: bool,
    enable_encrypt_then_mac: bool,
    cert_compression_algos: Vec<CertCompressionAlgorithm>,
    psk: Option<Vec<u8>>,
    psk_identity: Option<Vec<u8>>,
    psk_identity_hint: Option<Vec<u8>>,
    psk_server_callback: Option<PskServerCallback>,
    #[cfg(feature = "tlcp")]
    tlcp_enc_certificate_chain: Vec<Vec<u8>>,
    #[cfg(feature = "tlcp")]
    tlcp_enc_private_key: Option<ServerPrivateKey>,
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
            verify_client_cert: false,
            require_client_cert: false,
            enable_extended_master_secret: true,
            enable_encrypt_then_mac: true,
            cert_compression_algos: Vec::new(),
            psk: None,
            psk_identity: None,
            psk_identity_hint: None,
            psk_server_callback: None,
            #[cfg(feature = "tlcp")]
            tlcp_enc_certificate_chain: Vec::new(),
            #[cfg(feature = "tlcp")]
            tlcp_enc_private_key: None,
        }
    }
}

impl fmt::Debug for TlsConfigBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfigBuilder")
            .field("role", &self.role)
            .field("cipher_suites", &self.cipher_suites)
            .finish_non_exhaustive()
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

    pub fn verify_client_cert(mut self, enabled: bool) -> Self {
        self.verify_client_cert = enabled;
        self
    }

    pub fn require_client_cert(mut self, required: bool) -> Self {
        self.require_client_cert = required;
        self
    }

    pub fn enable_extended_master_secret(mut self, enabled: bool) -> Self {
        self.enable_extended_master_secret = enabled;
        self
    }

    pub fn enable_encrypt_then_mac(mut self, enabled: bool) -> Self {
        self.enable_encrypt_then_mac = enabled;
        self
    }

    pub fn cert_compression(mut self, algos: Vec<CertCompressionAlgorithm>) -> Self {
        self.cert_compression_algos = algos;
        self
    }

    pub fn psk(mut self, key: Vec<u8>) -> Self {
        self.psk = Some(key);
        self
    }

    pub fn psk_identity(mut self, identity: Vec<u8>) -> Self {
        self.psk_identity = Some(identity);
        self
    }

    pub fn psk_identity_hint(mut self, hint: Vec<u8>) -> Self {
        self.psk_identity_hint = Some(hint);
        self
    }

    pub fn psk_server_callback(mut self, cb: PskServerCallback) -> Self {
        self.psk_server_callback = Some(cb);
        self
    }

    #[cfg(feature = "tlcp")]
    pub fn tlcp_enc_certificate_chain(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.tlcp_enc_certificate_chain = certs;
        self
    }

    #[cfg(feature = "tlcp")]
    pub fn tlcp_enc_private_key(mut self, key: ServerPrivateKey) -> Self {
        self.tlcp_enc_private_key = Some(key);
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
            verify_client_cert: self.verify_client_cert,
            require_client_cert: self.require_client_cert,
            enable_extended_master_secret: self.enable_extended_master_secret,
            enable_encrypt_then_mac: self.enable_encrypt_then_mac,
            cert_compression_algos: self.cert_compression_algos,
            psk: self.psk,
            psk_identity: self.psk_identity,
            psk_identity_hint: self.psk_identity_hint,
            psk_server_callback: self.psk_server_callback,
            #[cfg(feature = "tlcp")]
            tlcp_enc_certificate_chain: self.tlcp_enc_certificate_chain,
            #[cfg(feature = "tlcp")]
            tlcp_enc_private_key: self.tlcp_enc_private_key,
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

    #[test]
    fn test_config_builder_mtls_defaults() {
        let config = TlsConfig::builder().build();
        assert!(!config.verify_client_cert);
        assert!(!config.require_client_cert);
    }

    #[test]
    fn test_config_builder_with_mtls() {
        let config = TlsConfig::builder()
            .role(TlsRole::Server)
            .verify_client_cert(true)
            .require_client_cert(true)
            .build();
        assert!(config.verify_client_cert);
        assert!(config.require_client_cert);
    }
}
