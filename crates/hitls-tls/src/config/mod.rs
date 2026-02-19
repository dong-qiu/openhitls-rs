//! TLS configuration with builder pattern.

use std::fmt;
use std::sync::{Arc, Mutex};

use crate::crypt::{NamedGroup, SignatureScheme};
use crate::extensions::CustomExtension;
use crate::handshake::codec::CertCompressionAlgorithm;
use crate::handshake::extensions_codec::TrustedAuthority;
use crate::session::{SessionCache, TlsSession};
use crate::{CipherSuite, TlsRole, TlsVersion};
use hitls_types::EccCurveId;
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

/// Server callback for PSK lookup: given a PSK identity, return the PSK value or None.
pub type PskServerCallback = Arc<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync>;

/// Protocol message observation callback (debugging/auditing).
///
/// Called for every TLS protocol message sent or received.
/// Parameters: `(is_outgoing, tls_version, content_type, message_bytes)`.
/// - `is_outgoing`: true when sending, false when receiving
/// - `tls_version`: TLS version as u16 (e.g. 0x0303 for TLS 1.2)
/// - `content_type`: record content type (20=CCS, 21=alert, 22=handshake, 23=application)
/// - `message_bytes`: raw message payload
pub type MsgCallback = Arc<dyn Fn(bool, u16, u8, &[u8]) + Send + Sync>;

/// State change / alert notification callback.
///
/// Called on handshake state transitions and alert events.
/// Parameters: `(event_type, value)`.
/// Event types: handshake state changes, alert notifications, etc.
pub type InfoCallback = Arc<dyn Fn(i32, i32) + Send + Sync>;

/// TLS 1.3 record padding callback.
///
/// Called before encrypting a TLS 1.3 record to determine additional padding.
/// Parameters: `(content_type, plaintext_length)`.
/// Returns: desired total padding length (0 = no extra padding).
pub type RecordPaddingCallback = Arc<dyn Fn(u8, usize) -> usize + Send + Sync>;

/// Temporary DH key generation callback.
///
/// Called on server to generate ephemeral DH parameters.
/// Parameters: `(is_export, key_bits)`.
/// Returns: DH parameters as DER bytes, or None to use defaults.
pub type DhTmpCallback = Arc<dyn Fn(bool, u32) -> Option<Vec<u8>> + Send + Sync>;

/// DTLS cookie generation callback.
///
/// Called on DTLS server to generate a HelloVerifyRequest cookie.
/// Parameters: `(client_hello_data)` — opaque client identification data.
/// Returns: generated cookie bytes.
pub type CookieGenCallback = Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

/// DTLS cookie verification callback.
///
/// Called on DTLS server to verify a cookie from the client's second ClientHello.
/// Parameters: `(client_hello_data, cookie)`.
/// Returns: true if cookie is valid.
pub type CookieVerifyCallback = Arc<dyn Fn(&[u8], &[u8]) -> bool + Send + Sync>;

/// Information extracted from a ClientHello message for the callback.
#[derive(Debug, Clone)]
pub struct ClientHelloInfo {
    /// Client-offered cipher suites.
    pub cipher_suites: Vec<u16>,
    /// Client-offered TLS versions.
    pub supported_versions: Vec<u16>,
    /// Server name from SNI extension, if present.
    pub server_name: Option<String>,
    /// Client-offered ALPN protocols.
    pub alpn_protocols: Vec<Vec<u8>>,
}

/// Action to take after the ClientHello callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientHelloAction {
    /// Continue the handshake normally.
    Success,
    /// Suspend the handshake (e.g., for async processing).
    Retry,
    /// Abort the handshake and send the specified alert.
    Failed(u8),
}

/// ClientHello observation/processing callback (server-side).
///
/// Called when the server receives a ClientHello, before continuing the handshake.
/// Returns an action: continue, retry (suspend), or fail (abort with alert).
pub type ClientHelloCallback = Arc<dyn Fn(&ClientHelloInfo) -> ClientHelloAction + Send + Sync>;

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
    /// Server-side session cache for session ID-based resumption.
    /// Shared across connections via `Arc<Mutex<..>>`.
    pub session_cache: Option<Arc<Mutex<dyn SessionCache>>>,
    /// Whether to use server preference order for cipher suite negotiation.
    /// Default: true (server preference). When false, client preference is used.
    pub cipher_server_preference: bool,
    /// Max fragment length (RFC 6066). None = disabled (use default 16384).
    pub max_fragment_length: Option<MaxFragmentLength>,
    /// Signature algorithms for certificates (RFC 8446 §4.2.3).
    /// Empty = not sent (server uses signature_algorithms instead).
    pub signature_algorithms_cert: Vec<SignatureScheme>,
    /// Certificate authorities (RFC 8446 §4.2.4).
    /// DER-encoded Distinguished Names to send in ClientHello.
    /// Empty = not sent.
    pub certificate_authorities: Vec<Vec<u8>>,
    /// Target ClientHello size for PADDING extension (RFC 7685).
    /// 0 = disabled.
    pub padding_target: u16,
    /// OID filters for TLS 1.3 CertificateRequest (RFC 8446 §4.2.5).
    /// Each entry is (OID DER bytes, certificate extension values).
    /// Empty = not sent.
    pub oid_filters: Vec<(Vec<u8>, Vec<u8>)>,
    /// Heartbeat extension mode (RFC 6520).
    /// 0 = disabled (default), 1 = peer_allowed_to_send, 2 = peer_not_allowed_to_send.
    pub heartbeat_mode: u8,
    /// Enable GREASE (RFC 8701) in ClientHello.
    /// When true, injects random GREASE values into cipher suites, extensions,
    /// supported_versions, supported_groups, signature_algorithms, key_share.
    pub grease: bool,
    /// Trusted CA keys for ClientHello (RFC 6066 §6).
    /// Empty = not sent.
    pub trusted_ca_keys: Vec<TrustedAuthority>,
    /// SRTP protection profiles for USE_SRTP extension (RFC 5764).
    /// Empty = not sent.
    pub srtp_profiles: Vec<u16>,
    /// Enable OCSP multi-stapling via STATUS_REQUEST_V2 (RFC 6961).
    pub enable_ocsp_multi_stapling: bool,
    /// Protocol message observation callback (debugging/auditing).
    pub msg_callback: Option<MsgCallback>,
    /// State change / alert notification callback.
    pub info_callback: Option<InfoCallback>,
    /// TLS 1.3 record padding callback.
    pub record_padding_callback: Option<RecordPaddingCallback>,
    /// Temporary DH key generation callback (server-side).
    pub dh_tmp_callback: Option<DhTmpCallback>,
    /// DTLS cookie generation callback (server-side).
    pub cookie_gen_callback: Option<CookieGenCallback>,
    /// DTLS cookie verification callback (server-side).
    pub cookie_verify_callback: Option<CookieVerifyCallback>,
    /// ClientHello observation/processing callback (server-side).
    pub client_hello_callback: Option<ClientHelloCallback>,
    /// Enable DTLS flight-based transmission (default: true).
    /// When true, handshake messages are buffered and sent together as a flight.
    pub flight_transmit_enable: bool,
    /// Maximum consecutive empty records allowed before fatal alert (default: 32).
    /// Acts as DoS protection — resets to 0 on each non-empty record.
    pub empty_records_limit: u32,
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
            .field(
                "session_cache",
                &self.session_cache.as_ref().map(|_| "<cache>"),
            )
            .field("cipher_server_preference", &self.cipher_server_preference)
            .field(
                "msg_callback",
                &self.msg_callback.as_ref().map(|_| "<callback>"),
            )
            .field(
                "info_callback",
                &self.info_callback.as_ref().map(|_| "<callback>"),
            )
            .field(
                "record_padding_callback",
                &self.record_padding_callback.as_ref().map(|_| "<callback>"),
            )
            .field(
                "dh_tmp_callback",
                &self.dh_tmp_callback.as_ref().map(|_| "<callback>"),
            )
            .field(
                "cookie_gen_callback",
                &self.cookie_gen_callback.as_ref().map(|_| "<callback>"),
            )
            .field(
                "cookie_verify_callback",
                &self.cookie_verify_callback.as_ref().map(|_| "<callback>"),
            )
            .field(
                "client_hello_callback",
                &self.client_hello_callback.as_ref().map(|_| "<callback>"),
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
    session_cache: Option<Arc<Mutex<dyn SessionCache>>>,
    cipher_server_preference: bool,
    max_fragment_length: Option<MaxFragmentLength>,
    signature_algorithms_cert: Vec<SignatureScheme>,
    certificate_authorities: Vec<Vec<u8>>,
    padding_target: u16,
    oid_filters: Vec<(Vec<u8>, Vec<u8>)>,
    heartbeat_mode: u8,
    grease: bool,
    trusted_ca_keys: Vec<TrustedAuthority>,
    srtp_profiles: Vec<u16>,
    enable_ocsp_multi_stapling: bool,
    msg_callback: Option<MsgCallback>,
    info_callback: Option<InfoCallback>,
    record_padding_callback: Option<RecordPaddingCallback>,
    dh_tmp_callback: Option<DhTmpCallback>,
    cookie_gen_callback: Option<CookieGenCallback>,
    cookie_verify_callback: Option<CookieVerifyCallback>,
    client_hello_callback: Option<ClientHelloCallback>,
    flight_transmit_enable: bool,
    empty_records_limit: u32,
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
            session_cache: None,
            cipher_server_preference: true,
            max_fragment_length: None,
            signature_algorithms_cert: Vec::new(),
            certificate_authorities: Vec::new(),
            padding_target: 0,
            oid_filters: Vec::new(),
            heartbeat_mode: 0,
            grease: false,
            trusted_ca_keys: Vec::new(),
            srtp_profiles: Vec::new(),
            enable_ocsp_multi_stapling: false,
            msg_callback: None,
            info_callback: None,
            record_padding_callback: None,
            dh_tmp_callback: None,
            cookie_gen_callback: None,
            cookie_verify_callback: None,
            client_hello_callback: None,
            flight_transmit_enable: true,
            empty_records_limit: 32,
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

    pub fn session_cache(mut self, cache: Arc<Mutex<dyn SessionCache>>) -> Self {
        self.session_cache = Some(cache);
        self
    }

    pub fn cipher_server_preference(mut self, enabled: bool) -> Self {
        self.cipher_server_preference = enabled;
        self
    }

    pub fn max_fragment_length(mut self, mfl: MaxFragmentLength) -> Self {
        self.max_fragment_length = Some(mfl);
        self
    }

    pub fn signature_algorithms_cert(mut self, schemes: &[SignatureScheme]) -> Self {
        self.signature_algorithms_cert = schemes.to_vec();
        self
    }

    pub fn certificate_authorities(mut self, dns: Vec<Vec<u8>>) -> Self {
        self.certificate_authorities = dns;
        self
    }

    pub fn padding_target(mut self, target: u16) -> Self {
        self.padding_target = target;
        self
    }

    pub fn oid_filters(mut self, filters: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
        self.oid_filters = filters;
        self
    }

    pub fn heartbeat_mode(mut self, mode: u8) -> Self {
        self.heartbeat_mode = mode;
        self
    }

    pub fn grease(mut self, enabled: bool) -> Self {
        self.grease = enabled;
        self
    }

    pub fn trusted_ca_keys(mut self, authorities: Vec<TrustedAuthority>) -> Self {
        self.trusted_ca_keys = authorities;
        self
    }

    pub fn srtp_profiles(mut self, profiles: Vec<u16>) -> Self {
        self.srtp_profiles = profiles;
        self
    }

    pub fn enable_ocsp_multi_stapling(mut self, enabled: bool) -> Self {
        self.enable_ocsp_multi_stapling = enabled;
        self
    }

    pub fn msg_callback(mut self, cb: MsgCallback) -> Self {
        self.msg_callback = Some(cb);
        self
    }

    pub fn info_callback(mut self, cb: InfoCallback) -> Self {
        self.info_callback = Some(cb);
        self
    }

    pub fn record_padding_callback(mut self, cb: RecordPaddingCallback) -> Self {
        self.record_padding_callback = Some(cb);
        self
    }

    pub fn dh_tmp_callback(mut self, cb: DhTmpCallback) -> Self {
        self.dh_tmp_callback = Some(cb);
        self
    }

    pub fn cookie_gen_callback(mut self, cb: CookieGenCallback) -> Self {
        self.cookie_gen_callback = Some(cb);
        self
    }

    pub fn cookie_verify_callback(mut self, cb: CookieVerifyCallback) -> Self {
        self.cookie_verify_callback = Some(cb);
        self
    }

    pub fn client_hello_callback(mut self, cb: ClientHelloCallback) -> Self {
        self.client_hello_callback = Some(cb);
        self
    }

    pub fn flight_transmit_enable(mut self, enabled: bool) -> Self {
        self.flight_transmit_enable = enabled;
        self
    }

    pub fn empty_records_limit(mut self, limit: u32) -> Self {
        self.empty_records_limit = limit;
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
            session_cache: self.session_cache,
            cipher_server_preference: self.cipher_server_preference,
            max_fragment_length: self.max_fragment_length,
            signature_algorithms_cert: self.signature_algorithms_cert,
            certificate_authorities: self.certificate_authorities,
            padding_target: self.padding_target,
            oid_filters: self.oid_filters,
            heartbeat_mode: self.heartbeat_mode,
            grease: self.grease,
            trusted_ca_keys: self.trusted_ca_keys,
            srtp_profiles: self.srtp_profiles,
            enable_ocsp_multi_stapling: self.enable_ocsp_multi_stapling,
            msg_callback: self.msg_callback,
            info_callback: self.info_callback,
            record_padding_callback: self.record_padding_callback,
            dh_tmp_callback: self.dh_tmp_callback,
            cookie_gen_callback: self.cookie_gen_callback,
            cookie_verify_callback: self.cookie_verify_callback,
            client_hello_callback: self.client_hello_callback,
            flight_transmit_enable: self.flight_transmit_enable,
            empty_records_limit: self.empty_records_limit,
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

    #[test]
    fn test_config_session_cache() {
        use crate::session::InMemorySessionCache;
        use std::sync::Mutex;

        let cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));
        let config = TlsConfig::builder().session_cache(cache.clone()).build();
        assert!(config.session_cache.is_some());
    }

    #[test]
    fn test_config_cipher_server_preference() {
        // Default: true
        let config = TlsConfig::builder().build();
        assert!(config.cipher_server_preference);

        // Disabled
        let config2 = TlsConfig::builder().cipher_server_preference(false).build();
        assert!(!config2.cipher_server_preference);
    }

    #[test]
    fn test_config_max_fragment_length() {
        // Default: None
        let config = TlsConfig::builder().build();
        assert!(config.max_fragment_length.is_none());

        // Set MFL
        let config2 = TlsConfig::builder()
            .max_fragment_length(MaxFragmentLength::Bits2048)
            .build();
        assert_eq!(
            config2.max_fragment_length,
            Some(MaxFragmentLength::Bits2048)
        );
    }

    #[test]
    fn test_config_signature_algorithms_cert() {
        // Default: empty
        let config = TlsConfig::builder().build();
        assert!(config.signature_algorithms_cert.is_empty());

        // Set sig_algs_cert
        let config2 = TlsConfig::builder()
            .signature_algorithms_cert(&[
                SignatureScheme::RSA_PSS_RSAE_SHA256,
                SignatureScheme::ECDSA_SECP256R1_SHA256,
            ])
            .build();
        assert_eq!(config2.signature_algorithms_cert.len(), 2);
        assert_eq!(
            config2.signature_algorithms_cert[0],
            SignatureScheme::RSA_PSS_RSAE_SHA256
        );
    }

    #[test]
    fn test_config_certificate_authorities() {
        // Default: empty
        let config = TlsConfig::builder().build();
        assert!(config.certificate_authorities.is_empty());

        // Set certificate_authorities
        let dn = vec![0x30, 0x0A, 0x31, 0x08];
        let config2 = TlsConfig::builder()
            .certificate_authorities(vec![dn.clone()])
            .build();
        assert_eq!(config2.certificate_authorities.len(), 1);
        assert_eq!(config2.certificate_authorities[0], dn);
    }

    #[test]
    fn test_mfl_size_values() {
        assert_eq!(MaxFragmentLength::Bits512.to_size(), 512);
        assert_eq!(MaxFragmentLength::Bits1024.to_size(), 1024);
        assert_eq!(MaxFragmentLength::Bits2048.to_size(), 2048);
        assert_eq!(MaxFragmentLength::Bits4096.to_size(), 4096);

        assert_eq!(
            MaxFragmentLength::from_u8(1),
            Some(MaxFragmentLength::Bits512)
        );
        assert_eq!(
            MaxFragmentLength::from_u8(2),
            Some(MaxFragmentLength::Bits1024)
        );
        assert_eq!(
            MaxFragmentLength::from_u8(3),
            Some(MaxFragmentLength::Bits2048)
        );
        assert_eq!(
            MaxFragmentLength::from_u8(4),
            Some(MaxFragmentLength::Bits4096)
        );
        assert_eq!(MaxFragmentLength::from_u8(0), None);
        assert_eq!(MaxFragmentLength::from_u8(5), None);
    }

    #[test]
    fn test_config_padding_target() {
        // Default: 0 (disabled)
        let config = TlsConfig::builder().build();
        assert_eq!(config.padding_target, 0);

        // Set padding target
        let config2 = TlsConfig::builder().padding_target(512).build();
        assert_eq!(config2.padding_target, 512);
    }

    #[test]
    fn test_config_heartbeat_mode() {
        // Default: 0 (disabled)
        let config = TlsConfig::builder().build();
        assert_eq!(config.heartbeat_mode, 0);

        // Set mode 1 (peer_allowed_to_send)
        let config2 = TlsConfig::builder().heartbeat_mode(1).build();
        assert_eq!(config2.heartbeat_mode, 1);

        // Set mode 2 (peer_not_allowed_to_send)
        let config3 = TlsConfig::builder().heartbeat_mode(2).build();
        assert_eq!(config3.heartbeat_mode, 2);
    }

    #[test]
    fn test_config_grease() {
        // Default: false
        let config = TlsConfig::builder().build();
        assert!(!config.grease);

        // Enabled
        let config2 = TlsConfig::builder().grease(true).build();
        assert!(config2.grease);
    }

    #[test]
    fn test_config_oid_filters() {
        // Default: empty
        let config = TlsConfig::builder().build();
        assert!(config.oid_filters.is_empty());

        // Set OID filters
        let oid = vec![0x55, 0x1D, 0x25];
        let values = vec![0x30, 0x0A];
        let config2 = TlsConfig::builder()
            .oid_filters(vec![(oid.clone(), values.clone())])
            .build();
        assert_eq!(config2.oid_filters.len(), 1);
        assert_eq!(config2.oid_filters[0].0, oid);
        assert_eq!(config2.oid_filters[0].1, values);
    }

    // -------------------------------------------------------
    // Testing-Phase 76 — F2: Config builder callback tests
    // -------------------------------------------------------

    #[test]
    fn test_config_cert_verify_callback() {
        use crate::cert_verify::CertVerifyInfo;
        use std::sync::Arc;
        let cb: CertVerifyCallback = Arc::new(|_info: &CertVerifyInfo| Ok(()));
        let config = TlsConfig::builder().cert_verify_callback(cb).build();
        assert!(
            config.cert_verify_callback.is_some(),
            "cert_verify_callback should be set"
        );
    }

    #[test]
    fn test_config_sni_callback() {
        use std::sync::Arc;
        let cb: SniCallback = Arc::new(|_hostname: &str| SniAction::Accept);
        let config = TlsConfig::builder().sni_callback(cb).build();
        assert!(config.sni_callback.is_some(), "sni_callback should be set");
    }

    #[test]
    fn test_config_key_log_callback() {
        use std::sync::Arc;
        let logged = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let l = logged.clone();
        let cb: KeyLogCallback = Arc::new(move |line: &str| {
            l.lock().unwrap().push(line.to_string());
        });
        let config = TlsConfig::builder().key_log(cb).build();
        assert!(
            config.key_log_callback.is_some(),
            "key_log_callback should be set"
        );
        // Invoke it and verify it works
        (config.key_log_callback.as_ref().unwrap())("test line");
        assert_eq!(logged.lock().unwrap().as_slice(), &["test line"]);
    }

    #[test]
    fn test_config_verify_hostname_toggle() {
        // Default: verify_hostname = true
        let config_default = TlsConfig::builder().build();
        assert!(
            config_default.verify_hostname,
            "verify_hostname should default to true"
        );

        // Explicitly disable
        let config_off = TlsConfig::builder().verify_hostname(false).build();
        assert!(
            !config_off.verify_hostname,
            "verify_hostname(false) should disable it"
        );

        // Re-enable
        let config_on = TlsConfig::builder().verify_hostname(true).build();
        assert!(
            config_on.verify_hostname,
            "verify_hostname(true) should enable it"
        );
    }

    #[test]
    fn test_config_trusted_cert_accumulates() {
        let der1 = vec![0x30, 0x00]; // minimal fake DER
        let der2 = vec![0x30, 0x01, 0x00];
        let config = TlsConfig::builder()
            .trusted_cert(der1.clone())
            .trusted_cert(der2.clone())
            .build();
        assert_eq!(config.trusted_certs.len(), 2);
        assert_eq!(config.trusted_certs[0], der1);
        assert_eq!(config.trusted_certs[1], der2);
    }

    #[test]
    fn test_config_sni_action_variants() {
        // Verify all SniAction variants can be constructed and cloned
        let _accept = SniAction::Accept;
        let _reject = SniAction::Reject;
        let _ignore = SniAction::Ignore;
        let inner = TlsConfig::builder().build();
        let _with_config = SniAction::AcceptWithConfig(Box::new(inner));
    }

    #[test]
    fn test_config_debug_includes_callbacks() {
        use crate::cert_verify::CertVerifyInfo;
        use std::sync::Arc;
        let cb: CertVerifyCallback = Arc::new(|_: &CertVerifyInfo| Ok(()));
        let config = TlsConfig::builder().cert_verify_callback(cb).build();
        let s = format!("{config:?}");
        // Debug output should show "<callback>" placeholder for the callback field
        assert!(
            s.contains("cert_verify_callback"),
            "debug should include cert_verify_callback field"
        );
    }

    // -------------------------------------------------------
    // Phase 77 — F1: 7 TLS callback config tests
    // -------------------------------------------------------

    #[test]
    fn test_config_msg_callback() {
        use std::sync::{Arc, Mutex};
        let log = Arc::new(Mutex::new(Vec::<(bool, u16, u8, Vec<u8>)>::new()));
        let l = log.clone();
        let cb: MsgCallback = Arc::new(move |out, ver, ct, data| {
            l.lock().unwrap().push((out, ver, ct, data.to_vec()));
        });
        let config = TlsConfig::builder().msg_callback(cb).build();
        assert!(config.msg_callback.is_some());
        // Invoke
        (config.msg_callback.as_ref().unwrap())(true, 0x0303, 22, &[1, 2, 3]);
        let entries = log.lock().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], (true, 0x0303, 22, vec![1, 2, 3]));
    }

    #[test]
    fn test_config_info_callback() {
        use std::sync::{Arc, Mutex};
        let events = Arc::new(Mutex::new(Vec::<(i32, i32)>::new()));
        let e = events.clone();
        let cb: InfoCallback = Arc::new(move |event_type, value| {
            e.lock().unwrap().push((event_type, value));
        });
        let config = TlsConfig::builder().info_callback(cb).build();
        assert!(config.info_callback.is_some());
        (config.info_callback.as_ref().unwrap())(1, 42);
        assert_eq!(events.lock().unwrap().as_slice(), &[(1, 42)]);
    }

    #[test]
    fn test_config_record_padding_callback() {
        let cb: RecordPaddingCallback = Arc::new(|_ct, len| {
            // Pad to next multiple of 256
            let pad = 256 - (len % 256);
            if pad == 256 {
                0
            } else {
                pad
            }
        });
        let config = TlsConfig::builder().record_padding_callback(cb).build();
        assert!(config.record_padding_callback.is_some());
        let padding = (config.record_padding_callback.as_ref().unwrap())(23, 100);
        assert_eq!(padding, 156); // 256 - 100
    }

    #[test]
    fn test_config_dh_tmp_callback() {
        let cb: DhTmpCallback = Arc::new(|is_export, key_bits| {
            if is_export {
                None
            } else {
                Some(vec![0xAA; (key_bits / 8) as usize])
            }
        });
        let config = TlsConfig::builder().dh_tmp_callback(cb).build();
        assert!(config.dh_tmp_callback.is_some());
        let result = (config.dh_tmp_callback.as_ref().unwrap())(false, 2048);
        assert_eq!(result.unwrap().len(), 256);
        let result2 = (config.dh_tmp_callback.as_ref().unwrap())(true, 512);
        assert!(result2.is_none());
    }

    #[test]
    fn test_config_cookie_gen_callback() {
        let cb: CookieGenCallback = Arc::new(|client_data| {
            let mut cookie = vec![0xFF; 32];
            for (i, &b) in client_data.iter().take(32).enumerate() {
                cookie[i] ^= b;
            }
            cookie
        });
        let config = TlsConfig::builder().cookie_gen_callback(cb).build();
        assert!(config.cookie_gen_callback.is_some());
        let cookie = (config.cookie_gen_callback.as_ref().unwrap())(&[0x42; 10]);
        assert_eq!(cookie.len(), 32);
    }

    #[test]
    fn test_config_cookie_verify_callback() {
        let cb: CookieVerifyCallback =
            Arc::new(|_client_data, cookie| cookie.len() == 32 && cookie[0] != 0);
        let config = TlsConfig::builder().cookie_verify_callback(cb).build();
        assert!(config.cookie_verify_callback.is_some());
        assert!((config.cookie_verify_callback.as_ref().unwrap())(
            &[],
            &[1u8; 32]
        ));
        assert!(!(config.cookie_verify_callback.as_ref().unwrap())(
            &[],
            &[0u8; 32]
        ));
    }

    #[test]
    fn test_config_client_hello_callback() {
        let cb: ClientHelloCallback = Arc::new(|info| {
            if info.server_name.as_deref() == Some("blocked.com") {
                ClientHelloAction::Failed(112) // unrecognized_name
            } else {
                ClientHelloAction::Success
            }
        });
        let config = TlsConfig::builder().client_hello_callback(cb).build();
        assert!(config.client_hello_callback.is_some());
        let info_ok = ClientHelloInfo {
            cipher_suites: vec![0x1301],
            supported_versions: vec![0x0304],
            server_name: Some("example.com".to_string()),
            alpn_protocols: vec![],
        };
        assert_eq!(
            (config.client_hello_callback.as_ref().unwrap())(&info_ok),
            ClientHelloAction::Success
        );
        let info_bad = ClientHelloInfo {
            cipher_suites: vec![0x1301],
            supported_versions: vec![0x0304],
            server_name: Some("blocked.com".to_string()),
            alpn_protocols: vec![],
        };
        assert_eq!(
            (config.client_hello_callback.as_ref().unwrap())(&info_bad),
            ClientHelloAction::Failed(112)
        );
    }

    #[test]
    fn test_config_callbacks_default_none() {
        let config = TlsConfig::builder().build();
        assert!(config.msg_callback.is_none());
        assert!(config.info_callback.is_none());
        assert!(config.record_padding_callback.is_none());
        assert!(config.dh_tmp_callback.is_none());
        assert!(config.cookie_gen_callback.is_none());
        assert!(config.cookie_verify_callback.is_none());
        assert!(config.client_hello_callback.is_none());
    }

    #[test]
    fn test_client_hello_info_debug() {
        let info = ClientHelloInfo {
            cipher_suites: vec![0x1301, 0x1302],
            supported_versions: vec![0x0304],
            server_name: Some("test.com".to_string()),
            alpn_protocols: vec![b"h2".to_vec()],
        };
        let s = format!("{info:?}");
        assert!(s.contains("test.com"));
        assert!(s.contains("ClientHelloInfo"));
    }

    #[test]
    fn test_client_hello_action_variants() {
        assert_eq!(ClientHelloAction::Success, ClientHelloAction::Success);
        assert_eq!(ClientHelloAction::Retry, ClientHelloAction::Retry);
        assert_eq!(ClientHelloAction::Failed(80), ClientHelloAction::Failed(80));
        assert_ne!(ClientHelloAction::Success, ClientHelloAction::Retry);
        assert_ne!(ClientHelloAction::Failed(80), ClientHelloAction::Failed(90));
    }

    // -------------------------------------------------------
    // Phase 78 — Config builder tests for new extension fields
    // -------------------------------------------------------

    #[test]
    fn test_config_trusted_ca_keys() {
        use crate::handshake::extensions_codec::TrustedAuthority;
        // Default: empty
        let config = TlsConfig::builder().build();
        assert!(config.trusted_ca_keys.is_empty());

        // Set trusted CA keys
        let authorities = vec![
            TrustedAuthority {
                identifier_type: 1,
                data: vec![0xAA; 20],
            },
            TrustedAuthority {
                identifier_type: 3,
                data: vec![0xBB; 20],
            },
        ];
        let config2 = TlsConfig::builder().trusted_ca_keys(authorities).build();
        assert_eq!(config2.trusted_ca_keys.len(), 2);
        assert_eq!(config2.trusted_ca_keys[0].identifier_type, 1);
    }

    #[test]
    fn test_config_srtp_profiles() {
        // Default: empty
        let config = TlsConfig::builder().build();
        assert!(config.srtp_profiles.is_empty());

        // Set SRTP profiles
        let config2 = TlsConfig::builder()
            .srtp_profiles(vec![0x0001, 0x0007])
            .build();
        assert_eq!(config2.srtp_profiles, vec![0x0001, 0x0007]);
    }

    #[test]
    fn test_config_ocsp_multi_stapling() {
        // Default: disabled
        let config = TlsConfig::builder().build();
        assert!(!config.enable_ocsp_multi_stapling);

        // Enabled
        let config2 = TlsConfig::builder()
            .enable_ocsp_multi_stapling(true)
            .build();
        assert!(config2.enable_ocsp_multi_stapling);
    }

    #[test]
    fn test_config_flight_transmit_enable() {
        // Default: enabled
        let config = TlsConfig::builder().build();
        assert!(config.flight_transmit_enable);

        // Disabled
        let config2 = TlsConfig::builder().flight_transmit_enable(false).build();
        assert!(!config2.flight_transmit_enable);
    }

    #[test]
    fn test_config_empty_records_limit() {
        // Default: 32
        let config = TlsConfig::builder().build();
        assert_eq!(config.empty_records_limit, 32);

        // Custom
        let config2 = TlsConfig::builder().empty_records_limit(100).build();
        assert_eq!(config2.empty_records_limit, 100);

        // Zero (disallow all empty records)
        let config3 = TlsConfig::builder().empty_records_limit(0).build();
        assert_eq!(config3.empty_records_limit, 0);
    }
}
