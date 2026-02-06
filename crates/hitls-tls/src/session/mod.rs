//! TLS session management and resumption.

use crate::CipherSuite;

/// A TLS session that can be used for resumption.
#[derive(Debug, Clone)]
pub struct TlsSession {
    /// Session identifier.
    pub id: Vec<u8>,
    /// The negotiated cipher suite.
    pub cipher_suite: CipherSuite,
    /// Resumption master secret (TLS 1.3) or master secret (TLS 1.2).
    pub master_secret: Vec<u8>,
    /// ALPN protocol negotiated in this session.
    pub alpn_protocol: Option<Vec<u8>>,
    /// Session ticket (TLS 1.3 NewSessionTicket).
    pub ticket: Option<Vec<u8>>,
    /// Ticket lifetime in seconds.
    pub ticket_lifetime: u32,
    /// Maximum early data size (TLS 1.3 0-RTT).
    pub max_early_data: u32,
}

/// Session cache for storing and retrieving sessions.
pub trait SessionCache: Send + Sync {
    /// Store a session.
    fn put(&mut self, key: &[u8], session: TlsSession);
    /// Retrieve a session.
    fn get(&self, key: &[u8]) -> Option<&TlsSession>;
    /// Remove a session.
    fn remove(&mut self, key: &[u8]);
}
