//! TLS configuration with builder pattern.

use std::fmt;
use std::sync::Arc;

use crate::crypt::{NamedGroup, SignatureScheme};
use crate::extensions::CustomExtension;
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

/// Server callback for PSK lookup: given a PSK identity, return the PSK value or None.
pub type PskServerCallback = Arc<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync>;

/// Callback for NSS key log format output (SSLKEYLOGFILE-compatible).
///
/// Called with a pre-formatted line: `<label> <client_random_hex> <secret_hex>`.
/// The callback should append the line (plus a newline) to a log file or buffer.
pub type KeyLogCallback = Arc<dyn Fn(&str) + Send + Sync>;

/// Callback for custom certificate verification.
///
/// Called with verification info after chain and hostname checks. The callback can
/// override the default result: returning `Ok(())` accepts the certificate even if
/// default checks failed, and returning `Err(reason)` rejects it.
pub type CertVerifyCallback =
    Arc<dyn Fn(&crate::cert_verify::CertVerifyInfo) -> Result<(), String> + Send + Sync>;

/// Callback for server-side SNI-based configuration selection.
///
/// Called with the client's requested hostname. Returns an action to take.
pub type SniCallback = Arc<dyn Fn(&str) -> SniAction + Send + Sync>;

/// Action to take after the SNI callback processes a hostname.
#[derive(Clone)]
pub enum SniAction {
    /// Accept the connection with the current config.
    Accept,
    /// Accept the connection with a different config (e.g., different certificate).
    AcceptWithConfig(Box<TlsConfig>),
    /// Reject the connection with unrecognized_name alert.
    Reject,
    /// Ignore the SNI extension (clear the server name).
    Ignore,
}

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
    /// Record size limit (RFC 8449). 0 = disabled (use default 16384).
    /// Valid range: 64..=16384 (TLS 1.2) or 64..=16385 (TLS 1.3).
    pub record_size_limit: u16,
    /// Whether to send Fallback SCSV (RFC 7507) in ClientHello.
    pub send_fallback_scsv: bool,
    /// Allow TLS 1.2 renegotiation (RFC 5746). Default: false.
    pub allow_renegotiation: bool,
    /// Enable OCSP stapling: client offers status_request, server provides stapled response.
    pub enable_ocsp_stapling: bool,
    /// Raw DER-encoded OCSP response for server-side stapling.
    pub ocsp_staple: Option<Vec<u8>>,
    /// Enable SCT (RFC 6962): client offers, server provides.
    pub enable_sct: bool,
    /// Raw SCT list bytes for server to provide in Certificate entries.
    pub sct_list: Option<Vec<u8>>,
    /// TLCP encryption certificate chain (DER-encoded, leaf first).
    /// TLCP uses double certificates: a signing cert + an encryption cert.
    #[cfg(feature = "tlcp")]
    pub tlcp_enc_certificate_chain: Vec<Vec<u8>>,
    /// TLCP encryption private key (SM2).
    #[cfg(feature = "tlcp")]
    pub tlcp_enc_private_key: Option<ServerPrivateKey>,
    /// Key log callback for NSS key log format (SSLKEYLOGFILE-compatible).
    pub key_log_callback: Option<KeyLogCallback>,
    /// Custom certificate verification callback.
    pub cert_verify_callback: Option<CertVerifyCallback>,
    /// Server-side SNI callback for hostname-based configuration selection.
    pub sni_callback: Option<SniCallback>,
    /// Whether to verify the server's hostname against the certificate.
    /// Only effective when `verify_peer` is true and `server_name` is set.
    /// Default: true.
    pub verify_hostname: bool,
    /// Registered custom extensions.
    pub custom_extensions: Vec<CustomExtension>,
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
            .field(
                "key_log_callback",
                &self.key_log_callback.as_ref().map(|_| "<callback>"),
            )
            .field(
                "cert_verify_callback",
                &self.cert_verify_callback.as_ref().map(|_| "<callback>"),
            )
            .field(
                "sni_callback",
                &self.sni_callback.as_ref().map(|_| "<callback>"),
            )
            .field("verify_hostname", &self.verify_hostname)
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
    record_size_limit: u16,
    send_fallback_scsv: bool,
    allow_renegotiation: bool,
    enable_ocsp_stapling: bool,
    ocsp_staple: Option<Vec<u8>>,
    enable_sct: bool,
    sct_list: Option<Vec<u8>>,
    #[cfg(feature = "tlcp")]
    tlcp_enc_certificate_chain: Vec<Vec<u8>>,
    #[cfg(feature = "tlcp")]
    tlcp_enc_private_key: Option<ServerPrivateKey>,
    key_log_callback: Option<KeyLogCallback>,
    cert_verify_callback: Option<CertVerifyCallback>,
    sni_callback: Option<SniCallback>,
    verify_hostname: bool,
    custom_extensions: Vec<CustomExtension>,
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
            record_size_limit: 0,
            send_fallback_scsv: false,
            allow_renegotiation: false,
            enable_ocsp_stapling: false,
            ocsp_staple: None,
            enable_sct: false,
            sct_list: None,
            #[cfg(feature = "tlcp")]
            tlcp_enc_certificate_chain: Vec::new(),
            #[cfg(feature = "tlcp")]
            tlcp_enc_private_key: None,
            key_log_callback: None,
            cert_verify_callback: None,
            sni_callback: None,
            verify_hostname: true,
            custom_extensions: Vec::new(),
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

    pub fn record_size_limit(mut self, limit: u16) -> Self {
        self.record_size_limit = limit;
        self
    }

    pub fn send_fallback_scsv(mut self, enabled: bool) -> Self {
        self.send_fallback_scsv = enabled;
        self
    }

    pub fn allow_renegotiation(mut self, enabled: bool) -> Self {
        self.allow_renegotiation = enabled;
        self
    }

    pub fn enable_ocsp_stapling(mut self, enabled: bool) -> Self {
        self.enable_ocsp_stapling = enabled;
        self
    }

    pub fn ocsp_staple(mut self, staple: Vec<u8>) -> Self {
        self.ocsp_staple = Some(staple);
        self
    }

    pub fn enable_sct(mut self, enabled: bool) -> Self {
        self.enable_sct = enabled;
        self
    }

    pub fn sct_list(mut self, sct: Vec<u8>) -> Self {
        self.sct_list = Some(sct);
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

    pub fn key_log(mut self, cb: KeyLogCallback) -> Self {
        self.key_log_callback = Some(cb);
        self
    }

    pub fn cert_verify_callback(mut self, cb: CertVerifyCallback) -> Self {
        self.cert_verify_callback = Some(cb);
        self
    }

    pub fn sni_callback(mut self, cb: SniCallback) -> Self {
        self.sni_callback = Some(cb);
        self
    }

    pub fn verify_hostname(mut self, enabled: bool) -> Self {
        self.verify_hostname = enabled;
        self
    }

    pub fn custom_extension(mut self, ext: CustomExtension) -> Self {
        self.custom_extensions.push(ext);
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
            record_size_limit: self.record_size_limit,
            send_fallback_scsv: self.send_fallback_scsv,
            allow_renegotiation: self.allow_renegotiation,
            enable_ocsp_stapling: self.enable_ocsp_stapling,
            ocsp_staple: self.ocsp_staple,
            enable_sct: self.enable_sct,
            sct_list: self.sct_list,
            #[cfg(feature = "tlcp")]
            tlcp_enc_certificate_chain: self.tlcp_enc_certificate_chain,
            #[cfg(feature = "tlcp")]
            tlcp_enc_private_key: self.tlcp_enc_private_key,
            key_log_callback: self.key_log_callback,
            cert_verify_callback: self.cert_verify_callback,
            sni_callback: self.sni_callback,
            verify_hostname: self.verify_hostname,
            custom_extensions: self.custom_extensions,
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

    #[test]
    fn test_config_builder_version_range() {
        let config = TlsConfig::builder()
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .build();
        assert_eq!(config.min_version, TlsVersion::Tls12);
        assert_eq!(config.max_version, TlsVersion::Tls12);
    }

    #[test]
    fn test_config_builder_alpn() {
        let config = TlsConfig::builder().alpn(&[b"h2", b"http/1.1"]).build();
        assert_eq!(config.alpn_protocols.len(), 2);
        assert_eq!(config.alpn_protocols[0], b"h2");
        assert_eq!(config.alpn_protocols[1], b"http/1.1");
    }

    #[test]
    fn test_config_builder_cipher_suites() {
        let config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_AES_128_GCM_SHA256])
            .build();
        assert_eq!(config.cipher_suites.len(), 1);
        assert_eq!(config.cipher_suites[0], CipherSuite::TLS_AES_128_GCM_SHA256);
    }

    #[test]
    fn test_config_builder_session_resumption() {
        // Default: enabled
        let config = TlsConfig::builder().build();
        assert!(config.session_resumption);

        // Disabled
        let config2 = TlsConfig::builder().session_resumption(false).build();
        assert!(!config2.session_resumption);
    }

    #[test]
    fn test_config_builder_psk() {
        let config = TlsConfig::builder()
            .psk(vec![0xAA; 32])
            .psk_identity(b"client1".to_vec())
            .psk_identity_hint(b"server hint".to_vec())
            .build();
        assert_eq!(config.psk.as_ref().unwrap().len(), 32);
        assert_eq!(config.psk_identity.as_ref().unwrap(), b"client1");
        assert_eq!(config.psk_identity_hint.as_ref().unwrap(), b"server hint");
    }

    #[test]
    fn test_config_builder_ems_etm_defaults() {
        let config = TlsConfig::builder().build();
        assert!(config.enable_extended_master_secret);
        assert!(config.enable_encrypt_then_mac);
    }

    #[test]
    fn test_config_builder_disable_ems_etm() {
        let config = TlsConfig::builder()
            .enable_extended_master_secret(false)
            .enable_encrypt_then_mac(false)
            .build();
        assert!(!config.enable_extended_master_secret);
        assert!(!config.enable_encrypt_then_mac);
    }

    #[test]
    fn test_config_builder_record_size_limit() {
        let config = TlsConfig::builder().record_size_limit(1024).build();
        assert_eq!(config.record_size_limit, 1024);

        let default = TlsConfig::builder().build();
        assert_eq!(default.record_size_limit, 0); // disabled
    }

    #[test]
    fn test_config_builder_fallback_scsv() {
        let config = TlsConfig::builder().send_fallback_scsv(true).build();
        assert!(config.send_fallback_scsv);

        let default = TlsConfig::builder().build();
        assert!(!default.send_fallback_scsv);
    }

    #[test]
    fn test_allow_renegotiation_config() {
        // Default: disabled
        let default = TlsConfig::builder().build();
        assert!(!default.allow_renegotiation);

        // Enabled
        let config = TlsConfig::builder().allow_renegotiation(true).build();
        assert!(config.allow_renegotiation);
    }

    #[test]
    fn test_config_builder_ocsp_sct() {
        let config = TlsConfig::builder()
            .enable_ocsp_stapling(true)
            .ocsp_staple(vec![0x30, 0x82])
            .enable_sct(true)
            .sct_list(vec![0x00, 0x10])
            .build();
        assert!(config.enable_ocsp_stapling);
        assert!(config.ocsp_staple.is_some());
        assert!(config.enable_sct);
        assert!(config.sct_list.is_some());
    }

    #[test]
    fn test_config_builder_post_handshake_auth() {
        let config = TlsConfig::builder()
            .post_handshake_auth(true)
            .client_certificate_chain(vec![vec![0x30]])
            .client_private_key(ServerPrivateKey::Ed25519(vec![0x42; 32]))
            .build();
        assert!(config.post_handshake_auth);
        assert_eq!(config.client_certificate_chain.len(), 1);
        assert!(config.client_private_key.is_some());
    }

    #[test]
    fn test_config_builder_early_data() {
        let config = TlsConfig::builder().max_early_data_size(16384).build();
        assert_eq!(config.max_early_data_size, 16384);

        let default = TlsConfig::builder().build();
        assert_eq!(default.max_early_data_size, 0);
    }

    #[test]
    fn test_config_builder_ticket_key() {
        let config = TlsConfig::builder().ticket_key(vec![0x42; 32]).build();
        assert_eq!(config.ticket_key.as_ref().unwrap().len(), 32);
    }

    #[test]
    fn test_config_debug_format() {
        let config = TlsConfig::builder().psk(vec![0xAA; 16]).build();
        let debug = format!("{config:?}");
        assert!(debug.contains("TlsConfig"));
        // PSK should show length, not raw bytes
        assert!(debug.contains("16 bytes"));
        assert!(!debug.contains("0xAA"));
    }

    #[test]
    fn test_config_builder_debug_format() {
        let builder = TlsConfig::builder();
        let debug = format!("{builder:?}");
        assert!(debug.contains("TlsConfigBuilder"));
        assert!(debug.contains("Client"));
    }

    #[test]
    fn test_config_builder_psk_server_callback() {
        let cb: PskServerCallback = Arc::new(|identity| {
            if identity == b"client1" {
                Some(vec![0xAA; 32])
            } else {
                None
            }
        });
        let config = TlsConfig::builder().psk_server_callback(cb).build();
        assert!(config.psk_server_callback.is_some());
        // Test the callback
        let result = (config.psk_server_callback.as_ref().unwrap())(b"client1");
        assert!(result.is_some());
        let result2 = (config.psk_server_callback.as_ref().unwrap())(b"unknown");
        assert!(result2.is_none());
    }
}
