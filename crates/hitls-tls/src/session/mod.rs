//! TLS session management and resumption.

use crate::CipherSuite;
use hitls_types::TlsError;
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
    /// Whether the Extended Master Secret extension (RFC 7627) was used.
    pub extended_master_secret: bool,
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

// ---------------------------------------------------------------------------
// Session ticket encryption/decryption (RFC 5077)
// ---------------------------------------------------------------------------

/// Encode TlsSession to bytes for ticket encryption.
///
/// Format: `cipher_suite(2) || ms_len(2) || master_secret(var) || created_at(8) || lifetime(4) || ems(1)`
pub fn encode_session_state(session: &TlsSession) -> Vec<u8> {
    let mut data = Vec::with_capacity(2 + 2 + session.master_secret.len() + 8 + 4 + 1);
    data.extend_from_slice(&session.cipher_suite.0.to_be_bytes());
    data.extend_from_slice(&(session.master_secret.len() as u16).to_be_bytes());
    data.extend_from_slice(&session.master_secret);
    data.extend_from_slice(&session.created_at.to_be_bytes());
    data.extend_from_slice(&session.ticket_lifetime.to_be_bytes());
    data.push(if session.extended_master_secret { 1 } else { 0 });
    data
}

/// Decode TlsSession from bytes after ticket decryption.
pub fn decode_session_state(data: &[u8]) -> Result<TlsSession, TlsError> {
    if data.len() < 2 + 2 {
        return Err(TlsError::HandshakeFailed("session state: too short".into()));
    }
    let cipher_suite = CipherSuite(u16::from_be_bytes([data[0], data[1]]));
    let ms_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 4 + ms_len + 8 + 4 {
        return Err(TlsError::HandshakeFailed("session state: truncated".into()));
    }
    let master_secret = data[4..4 + ms_len].to_vec();
    let offset = 4 + ms_len;
    let created_at = u64::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]);
    let lifetime = u32::from_be_bytes([
        data[offset + 8],
        data[offset + 9],
        data[offset + 10],
        data[offset + 11],
    ]);
    // EMS flag: optional trailing byte for backwards compatibility
    let ems = if data.len() > offset + 12 {
        data[offset + 12] != 0
    } else {
        false
    };

    Ok(TlsSession {
        id: Vec::new(),
        cipher_suite,
        master_secret,
        alpn_protocol: None,
        ticket: None,
        ticket_lifetime: lifetime,
        max_early_data: 0,
        ticket_age_add: 0,
        ticket_nonce: Vec::new(),
        created_at,
        psk: Vec::new(),
        extended_master_secret: ems,
    })
}

/// Encrypt session state into an opaque ticket using AES-256-GCM.
///
/// Format: `nonce(12) || ciphertext+tag(variable)`
///
/// `ticket_key` must be 32 bytes (AES-256).
pub fn encrypt_session_ticket(
    ticket_key: &[u8],
    session: &TlsSession,
) -> Result<Vec<u8>, TlsError> {
    if ticket_key.len() != 32 {
        return Err(TlsError::HandshakeFailed(
            "ticket_key must be 32 bytes".into(),
        ));
    }
    let plaintext = encode_session_state(session);
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| TlsError::HandshakeFailed(format!("getrandom: {e}")))?;

    let ct_tag = hitls_crypto::modes::gcm::gcm_encrypt(ticket_key, &nonce, &[], &plaintext)
        .map_err(TlsError::CryptoError)?;

    let mut ticket = Vec::with_capacity(12 + ct_tag.len());
    ticket.extend_from_slice(&nonce);
    ticket.extend_from_slice(&ct_tag);
    Ok(ticket)
}

/// Decrypt opaque ticket back to session state.
///
/// Returns `None` if decryption fails (graceful degradation to full handshake).
pub fn decrypt_session_ticket(ticket_key: &[u8], ticket: &[u8]) -> Option<TlsSession> {
    if ticket_key.len() != 32 || ticket.len() < 12 + 16 {
        return None;
    }
    let nonce = &ticket[..12];
    let ct_tag = &ticket[12..];

    let plaintext = hitls_crypto::modes::gcm::gcm_decrypt(ticket_key, nonce, &[], ct_tag).ok()?;
    decode_session_state(&plaintext).ok()
}
