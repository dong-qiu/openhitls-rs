//! Connection information snapshot.
//!
//! After a TLS handshake completes, callers can query negotiated parameters
//! via the [`ConnectionInfo`] struct returned by `connection_info()`.

use crate::crypt::NamedGroup;
use crate::CipherSuite;

/// Snapshot of negotiated connection parameters after handshake.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// The negotiated cipher suite.
    pub cipher_suite: CipherSuite,
    /// Peer certificates (DER-encoded, leaf first).
    pub peer_certificates: Vec<Vec<u8>>,
    /// Negotiated ALPN protocol (if any).
    pub alpn_protocol: Option<Vec<u8>>,
    /// Server name (SNI) used in this connection.
    pub server_name: Option<String>,
    /// Negotiated key exchange group (if applicable).
    pub negotiated_group: Option<NamedGroup>,
    /// Whether this connection was resumed from a previous session.
    pub session_resumed: bool,
    /// Peer's Finished verify_data.
    pub peer_verify_data: Vec<u8>,
    /// Local Finished verify_data.
    pub local_verify_data: Vec<u8>,
}
