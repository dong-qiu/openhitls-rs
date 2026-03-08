//! TLS callback type definitions.
//!
//! Defines all callback type aliases used by [`TlsConfig`](super::TlsConfig) for
//! customizing TLS behavior: PSK lookup, message observation, record padding,
//! DTLS cookies, SNI handling, certificate verification, and more.

use std::sync::Arc;

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

/// Callback for client-side OCSP stapling verification.
///
/// Called with the DER-encoded OCSP response and the server certificate chain
/// (DER-encoded, leaf first). Returns `Ok(())` to accept, `Err(reason)` to reject.
/// If no callback is set, the stapled OCSP response is stored but not validated.
pub type OcspStaplingCallback = Arc<dyn Fn(&[u8], &[Vec<u8>]) -> Result<(), String> + Send + Sync>;

/// Callback for server-side SNI-based configuration selection.
///
/// Called with the client's requested hostname. Returns an action to take.
pub type SniCallback = Arc<dyn Fn(&str) -> super::SniAction + Send + Sync>;

/// Result from the ticket key callback containing the key material.
#[derive(Clone)]
pub struct TicketKeyResult {
    /// 16-byte key name for ticket identification.
    pub key_name: [u8; 16],
    /// Encryption key (typically 32 bytes for AES-256).
    pub key: Vec<u8>,
    /// Initialization vector (typically 16 bytes).
    pub iv: Vec<u8>,
}

/// Ticket key callback for custom session ticket encryption key management.
///
/// Enables key rotation: the callback provides keying material for encrypting
/// (is_encrypt=true) or decrypting (is_encrypt=false) session tickets.
/// The `ticket_name` parameter is the first 16 bytes of the ticket (key name).
/// Returns `None` to reject (e.g., expired key).
pub type TicketKeyCallback = Arc<dyn Fn(&[u8], bool) -> Option<TicketKeyResult> + Send + Sync>;

/// Security callback for filtering cipher suites, groups, and signature algorithms.
///
/// Called during handshake to approve each algorithm against a security policy.
/// Parameters: `(op, level, id)`:
/// - `op`: 0=CipherSuite, 1=NamedGroup, 2=SignatureAlgorithm, 3=Version
/// - `level`: security level from config
/// - `id`: algorithm identifier (cipher suite u16, group u16, sigalg u16, version u16)
///
/// Returns true to allow, false to reject.
pub type SecurityCallback = Arc<dyn Fn(u32, u32, u16) -> bool + Send + Sync>;
