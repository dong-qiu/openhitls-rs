//! TLS session management and resumption.

use crate::CipherSuite;
use std::collections::HashMap;
use zeroize::Zeroize;

/// A TLS session that can be used for resumption.
#[derive(Debug, Clone)]
pub struct TlsSession {
    /// Session identifier.
    pub id: Vec<u8>,
    /// The negotiated cipher suite.
    pub cipher_suite: CipherSuite,
    /// Resumption master secret (TLS 1.3).
    pub master_secret: Vec<u8>,
    /// ALPN protocol negotiated in this session.
    pub alpn_protocol: Option<Vec<u8>>,
    /// Session ticket (TLS 1.3 NewSessionTicket).
    pub ticket: Option<Vec<u8>>,
    /// Ticket lifetime in seconds.
    pub ticket_lifetime: u32,
    /// Maximum early data size (TLS 1.3 0-RTT).
    pub max_early_data: u32,
    /// Ticket age add value (for obfuscating ticket age).
    pub ticket_age_add: u32,
    /// Ticket nonce used for PSK derivation.
    pub ticket_nonce: Vec<u8>,
    /// Timestamp when the session was created (seconds since UNIX epoch).
    pub created_at: u64,
    /// Pre-shared key derived from resumption_master_secret + ticket_nonce.
    pub psk: Vec<u8>,
}

impl Drop for TlsSession {
    fn drop(&mut self) {
        self.master_secret.zeroize();
        self.psk.zeroize();
    }
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

/// In-memory session cache with a maximum size limit.
pub struct InMemorySessionCache {
    sessions: HashMap<Vec<u8>, TlsSession>,
    max_size: usize,
}

impl InMemorySessionCache {
    /// Create a new cache with the given maximum number of sessions.
    pub fn new(max_size: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            max_size,
        }
    }

    /// Number of sessions in the cache.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

impl SessionCache for InMemorySessionCache {
    fn put(&mut self, key: &[u8], session: TlsSession) {
        if self.sessions.len() >= self.max_size && !self.sessions.contains_key(key) {
            // Evict first entry (simple eviction)
            if let Some(first_key) = self.sessions.keys().next().cloned() {
                self.sessions.remove(&first_key);
            }
        }
        self.sessions.insert(key.to_vec(), session);
    }

    fn get(&self, key: &[u8]) -> Option<&TlsSession> {
        self.sessions.get(key)
    }

    fn remove(&mut self, key: &[u8]) {
        self.sessions.remove(key);
    }
}
