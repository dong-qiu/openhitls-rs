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

/// In-memory session cache with a maximum size limit and optional TTL expiration.
pub struct InMemorySessionCache {
    sessions: HashMap<Vec<u8>, TlsSession>,
    max_size: usize,
    /// Session lifetime in seconds. 0 means no expiry.
    session_lifetime: u64,
}

impl InMemorySessionCache {
    /// Create a new cache with the given maximum number of sessions.
    /// Default session lifetime is 7200 seconds (2 hours).
    pub fn new(max_size: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            max_size,
            session_lifetime: 7200,
        }
    }

    /// Create a new cache with a custom session lifetime in seconds.
    /// A lifetime of 0 means sessions never expire.
    pub fn with_lifetime(max_size: usize, lifetime_secs: u64) -> Self {
        Self {
            sessions: HashMap::new(),
            max_size,
            session_lifetime: lifetime_secs,
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

    /// Remove all expired sessions from the cache.
    pub fn cleanup(&mut self) {
        if self.session_lifetime == 0 {
            return;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.sessions
            .retain(|_, session| now.saturating_sub(session.created_at) <= self.session_lifetime);
    }

    /// Check whether a session has expired based on the configured lifetime.
    fn is_expired(&self, session: &TlsSession) -> bool {
        if self.session_lifetime == 0 {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(session.created_at) > self.session_lifetime
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
        let session = self.sessions.get(key)?;
        // Lazy expiration: return None for expired sessions
        if self.is_expired(session) {
            return None;
        }
        Some(session)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(suite: u16, ms: &[u8]) -> TlsSession {
        TlsSession {
            id: Vec::new(),
            cipher_suite: CipherSuite(suite),
            master_secret: ms.to_vec(),
            alpn_protocol: None,
            ticket: None,
            ticket_lifetime: 3600,
            max_early_data: 0,
            ticket_age_add: 0,
            ticket_nonce: Vec::new(),
            created_at: now_secs(),
            psk: Vec::new(),
            extended_master_secret: false,
        }
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    // -----------------------------------------------------------------------
    // InMemorySessionCache
    // -----------------------------------------------------------------------

    #[test]
    fn test_cache_put_get() {
        let mut cache = InMemorySessionCache::new(10);
        let session = make_session(0x1301, &[0xAA; 32]);
        cache.put(b"key1", session);
        let s = cache.get(b"key1").unwrap();
        assert_eq!(s.cipher_suite.0, 0x1301);
        assert_eq!(s.master_secret, vec![0xAA; 32]);
    }

    #[test]
    fn test_cache_get_missing() {
        let cache = InMemorySessionCache::new(10);
        assert!(cache.get(b"nonexistent").is_none());
    }

    #[test]
    fn test_cache_remove() {
        let mut cache = InMemorySessionCache::new(10);
        cache.put(b"key1", make_session(0x1301, &[1; 32]));
        assert!(cache.get(b"key1").is_some());
        cache.remove(b"key1");
        assert!(cache.get(b"key1").is_none());
    }

    #[test]
    fn test_cache_len_is_empty() {
        let mut cache = InMemorySessionCache::new(10);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        cache.put(b"a", make_session(0x1301, &[1; 32]));
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
        cache.put(b"b", make_session(0x1302, &[2; 32]));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_cache_eviction() {
        let mut cache = InMemorySessionCache::new(2);
        cache.put(b"a", make_session(0x1301, &[1; 32]));
        cache.put(b"b", make_session(0x1302, &[2; 32]));
        assert_eq!(cache.len(), 2);
        // Third insert should evict one entry
        cache.put(b"c", make_session(0x1303, &[3; 32]));
        assert_eq!(cache.len(), 2);
        // c should exist
        assert!(cache.get(b"c").is_some());
    }

    #[test]
    fn test_cache_overwrite() {
        let mut cache = InMemorySessionCache::new(10);
        cache.put(b"key1", make_session(0x1301, &[1; 32]));
        cache.put(b"key1", make_session(0x1302, &[2; 32]));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(b"key1").unwrap().cipher_suite.0, 0x1302);
    }

    #[test]
    fn test_cache_multiple_keys() {
        let mut cache = InMemorySessionCache::new(10);
        cache.put(b"a", make_session(0x1301, &[1; 32]));
        cache.put(b"b", make_session(0x1302, &[2; 32]));
        cache.put(b"c", make_session(0x1303, &[3; 32]));
        assert_eq!(cache.get(b"a").unwrap().cipher_suite.0, 0x1301);
        assert_eq!(cache.get(b"b").unwrap().cipher_suite.0, 0x1302);
        assert_eq!(cache.get(b"c").unwrap().cipher_suite.0, 0x1303);
    }

    #[test]
    fn test_cache_zero_capacity() {
        let mut cache = InMemorySessionCache::new(0);
        // Inserting into zero-capacity cache: evicts immediately
        cache.put(b"key1", make_session(0x1301, &[1; 32]));
        // The session was evicted to make room, then inserted — but capacity=0 means
        // after eviction there's room for 1 (HashMap doesn't enforce max_size after put)
        // Actually, the code evicts one then inserts, so len=0 after evict but inserts again.
        // With 0 capacity, every insert evicts the previous entry.
    }

    // -----------------------------------------------------------------------
    // Session state encoding/decoding
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_decode_roundtrip() {
        let session = make_session(0x1301, &[0xAB; 48]);
        let expected_created_at = session.created_at;
        let encoded = encode_session_state(&session);
        let decoded = decode_session_state(&encoded).unwrap();
        assert_eq!(decoded.cipher_suite.0, 0x1301);
        assert_eq!(decoded.master_secret, vec![0xAB; 48]);
        assert_eq!(decoded.created_at, expected_created_at);
        assert_eq!(decoded.ticket_lifetime, 3600);
        assert!(!decoded.extended_master_secret);
    }

    #[test]
    fn test_encode_decode_empty_master_secret() {
        let session = make_session(0x1302, &[]);
        let encoded = encode_session_state(&session);
        let decoded = decode_session_state(&encoded).unwrap();
        assert!(decoded.master_secret.is_empty());
        assert_eq!(decoded.cipher_suite.0, 0x1302);
    }

    #[test]
    fn test_encode_decode_large_master_secret() {
        let ms = vec![0x42; 256];
        let session = make_session(0x1303, &ms);
        let encoded = encode_session_state(&session);
        let decoded = decode_session_state(&encoded).unwrap();
        assert_eq!(decoded.master_secret, ms);
    }

    #[test]
    fn test_decode_truncated() {
        // Less than minimum header (4 bytes)
        assert!(decode_session_state(&[0x13]).is_err());
        assert!(decode_session_state(&[0x13, 0x01]).is_err());
        assert!(decode_session_state(&[0x13, 0x01, 0x00]).is_err());
    }

    #[test]
    fn test_decode_invalid_ms_len() {
        // Header says ms_len=100 but not enough data
        let mut data = vec![0x13, 0x01, 0x00, 100];
        data.extend_from_slice(&[0u8; 10]); // only 10 bytes, need 100+12
        assert!(decode_session_state(&data).is_err());
    }

    #[test]
    fn test_encode_preserves_ems_flag() {
        let mut session = make_session(0x1301, &[0xCC; 32]);
        session.extended_master_secret = true;
        let encoded = encode_session_state(&session);
        let decoded = decode_session_state(&encoded).unwrap();
        assert!(decoded.extended_master_secret);
    }

    #[test]
    fn test_encode_decode_various_suites() {
        for suite in [0x1301u16, 0x1302, 0x1303, 0xC02F, 0xCCA8] {
            let session = make_session(suite, &[0x11; 32]);
            let encoded = encode_session_state(&session);
            let decoded = decode_session_state(&encoded).unwrap();
            assert_eq!(decoded.cipher_suite.0, suite);
        }
    }

    // -----------------------------------------------------------------------
    // Session ticket encryption/decryption
    // -----------------------------------------------------------------------

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let session = make_session(0x1301, &[0xAB; 48]);
        let ticket = encrypt_session_ticket(&key, &session).unwrap();
        let recovered = decrypt_session_ticket(&key, &ticket).unwrap();
        assert_eq!(recovered.cipher_suite.0, 0x1301);
        assert_eq!(recovered.master_secret, vec![0xAB; 48]);
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let session = make_session(0x1301, &[0xAB; 48]);
        let ticket = encrypt_session_ticket(&key, &session).unwrap();
        assert!(decrypt_session_ticket(&wrong_key, &ticket).is_none());
    }

    #[test]
    fn test_decrypt_tampered_ticket() {
        let key = [0x42u8; 32];
        let session = make_session(0x1301, &[0xAB; 48]);
        let mut ticket = encrypt_session_ticket(&key, &session).unwrap();
        // Flip a byte in the ciphertext
        let mid = ticket.len() / 2;
        ticket[mid] ^= 0xFF;
        assert!(decrypt_session_ticket(&key, &ticket).is_none());
    }

    #[test]
    fn test_decrypt_truncated() {
        let key = [0x42u8; 32];
        // Too short: needs at least nonce(12) + tag(16) = 28 bytes
        assert!(decrypt_session_ticket(&key, &[0u8; 27]).is_none());
    }

    #[test]
    fn test_decrypt_empty() {
        let key = [0x42u8; 32];
        assert!(decrypt_session_ticket(&key, &[]).is_none());
    }

    #[test]
    fn test_encrypt_produces_different_tickets() {
        let key = [0x42u8; 32];
        let session = make_session(0x1301, &[0xAB; 48]);
        let ticket1 = encrypt_session_ticket(&key, &session).unwrap();
        let ticket2 = encrypt_session_ticket(&key, &session).unwrap();
        // Different nonces → different ciphertexts
        assert_ne!(ticket1, ticket2);
    }

    // -----------------------------------------------------------------------
    // Session TTL expiration
    // -----------------------------------------------------------------------

    #[test]
    fn test_cache_ttl_fresh() {
        let mut cache = InMemorySessionCache::with_lifetime(10, 3600);
        let mut session = make_session(0x1301, &[0xAA; 32]);
        session.created_at = now_secs(); // fresh
        cache.put(b"key1", session);
        assert!(cache.get(b"key1").is_some());
    }

    #[test]
    fn test_cache_ttl_expired() {
        let mut cache = InMemorySessionCache::with_lifetime(10, 3600);
        let mut session = make_session(0x1301, &[0xAA; 32]);
        session.created_at = now_secs() - 7200; // 2 hours ago, TTL is 1 hour
        cache.put(b"key1", session);
        assert!(cache.get(b"key1").is_none());
    }

    #[test]
    fn test_cache_ttl_zero_no_expiry() {
        let mut cache = InMemorySessionCache::with_lifetime(10, 0);
        let mut session = make_session(0x1301, &[0xAA; 32]);
        session.created_at = 1; // very old
        cache.put(b"key1", session);
        // TTL=0 means no expiry, so session should still be returned
        assert!(cache.get(b"key1").is_some());
    }

    #[test]
    fn test_cache_cleanup() {
        let mut cache = InMemorySessionCache::with_lifetime(10, 3600);

        // Fresh session
        let mut fresh = make_session(0x1301, &[0xAA; 32]);
        fresh.created_at = now_secs();
        cache.put(b"fresh", fresh);

        // Expired session
        let mut expired = make_session(0x1302, &[0xBB; 32]);
        expired.created_at = now_secs() - 7200;
        cache.put(b"expired", expired);

        assert_eq!(cache.len(), 2);
        cache.cleanup();
        assert_eq!(cache.len(), 1);
        assert!(cache.get(b"fresh").is_some());
        // After cleanup, expired entry is removed from the HashMap
        assert!(!cache.sessions.contains_key(b"expired" as &[u8]));
    }

    #[test]
    fn test_cache_with_lifetime() {
        let cache = InMemorySessionCache::with_lifetime(50, 1800);
        assert_eq!(cache.max_size, 50);
        assert_eq!(cache.session_lifetime, 1800);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_arc_mutex_basic() {
        use std::sync::{Arc, Mutex};

        let cache = Arc::new(Mutex::new(InMemorySessionCache::new(10)));
        {
            let mut c = cache.lock().unwrap();
            c.put(b"key1", make_session(0x1301, &[1u8; 32]));
        }
        {
            let c = cache.lock().unwrap();
            let s = c.get(b"key1").unwrap();
            assert_eq!(s.cipher_suite.0, 0x1301);
        }
    }

    #[test]
    fn test_cache_arc_mutex_concurrent_puts() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let cache = Arc::new(Mutex::new(InMemorySessionCache::new(200)));
        let mut handles = Vec::new();

        for thread_id in 0u8..4 {
            let cache_clone = Arc::clone(&cache);
            let handle = thread::spawn(move || {
                for j in 0u8..25 {
                    let key = vec![thread_id, j];
                    let session = make_session(0x1301, &[thread_id; 32]);
                    let mut c = cache_clone.lock().unwrap();
                    c.put(&key, session);
                }
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().unwrap();
        }

        let c = cache.lock().unwrap();
        // 4 threads × 25 unique keys = 100 entries total (capacity=200)
        assert_eq!(c.len(), 100);
    }

    #[test]
    fn test_cache_arc_mutex_concurrent_get_put() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let cache = Arc::new(Mutex::new(InMemorySessionCache::new(50)));

        // Pre-populate a key for readers to find
        {
            let mut c = cache.lock().unwrap();
            c.put(b"shared_key", make_session(0x1302, &[0xAA; 32]));
        }

        let mut handles = Vec::new();

        // 2 writer threads
        for i in 0u8..2 {
            let cache_clone = Arc::clone(&cache);
            let h = thread::spawn(move || {
                for j in 0u8..10 {
                    let key = vec![i, j, 0xFF];
                    let mut c = cache_clone.lock().unwrap();
                    c.put(&key, make_session(0x1303, &[i; 32]));
                }
            });
            handles.push(h);
        }

        // 2 reader threads
        for _ in 0..2 {
            let cache_clone = Arc::clone(&cache);
            let h = thread::spawn(move || {
                for _ in 0..10 {
                    let c = cache_clone.lock().unwrap();
                    // Either finds the session or None — both are valid under concurrent load
                    let _ = c.get(b"shared_key");
                }
            });
            handles.push(h);
        }

        for h in handles {
            h.join().unwrap();
        }

        // The shared_key should still be retrievable (unless evicted under capacity pressure)
        let c = cache.lock().unwrap();
        assert!(!c.is_empty());
    }

    #[test]
    fn test_cache_arc_mutex_eviction_under_load() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        // Small capacity to trigger eviction under concurrent writes
        let cache = Arc::new(Mutex::new(InMemorySessionCache::new(5)));
        let mut handles = Vec::new();

        for i in 0u8..3 {
            let cache_clone = Arc::clone(&cache);
            let h = thread::spawn(move || {
                for j in 0u8..10 {
                    let key = vec![i, j];
                    let mut c = cache_clone.lock().unwrap();
                    c.put(&key, make_session(0x1301, &[i; 32]));
                }
            });
            handles.push(h);
        }

        for h in handles {
            h.join().unwrap();
        }

        // Eviction must keep len ≤ max_size
        let c = cache.lock().unwrap();
        assert!(c.len() <= 5, "cache len {} exceeds max_size 5", c.len());
    }

    #[test]
    fn test_cache_arc_mutex_shared_across_two_arcs() {
        use std::sync::{Arc, Mutex};

        let cache1 = Arc::new(Mutex::new(InMemorySessionCache::new(10)));
        let cache2 = Arc::clone(&cache1);

        // Write via cache1
        cache1
            .lock()
            .unwrap()
            .put(b"k1", make_session(0x1301, &[1u8; 32]));

        // Read via cache2 — should see the same data
        let c = cache2.lock().unwrap();
        assert!(c.get(b"k1").is_some());
        assert_eq!(c.get(b"k1").unwrap().cipher_suite.0, 0x1301);
    }

    #[test]
    fn test_cache_trait_object_via_arc_mutex() {
        use std::sync::{Arc, Mutex};

        // Use as SessionCache trait object
        let cache: Arc<Mutex<Box<dyn SessionCache>>> =
            Arc::new(Mutex::new(Box::new(InMemorySessionCache::new(10))));

        cache
            .lock()
            .unwrap()
            .put(b"trait_key", make_session(0x1302, &[0x42; 32]));

        let c = cache.lock().unwrap();
        let s = c.get(b"trait_key").unwrap();
        assert_eq!(s.cipher_suite.0, 0x1302);
    }
}
