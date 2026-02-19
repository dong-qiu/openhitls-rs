//! Transcript hash for TLS 1.3 handshake messages.
//!
//! Maintains a running hash over all handshake messages in order.

use hitls_crypto::provider::Digest;
use hitls_types::TlsError;

/// Running transcript hash over handshake messages.
///
/// Uses a message buffer + replay approach: `current_hash()` creates a fresh
/// hasher, replays all buffered data, and finishes to get the intermediate hash.
/// The live hasher is never finalized, so `update()` continues to work.
pub struct TranscriptHash {
    factory: Box<dyn Fn() -> Box<dyn Digest> + Send + Sync>,
    message_buffer: Vec<u8>,
    hash_len: usize,
}

impl TranscriptHash {
    /// Create a new TranscriptHash with the given hash factory.
    pub fn new(factory: impl Fn() -> Box<dyn Digest> + Send + Sync + 'static) -> Self {
        let hash_len = factory().output_size();
        Self {
            factory: Box::new(factory),
            message_buffer: Vec::new(),
            hash_len,
        }
    }

    /// Feed handshake message data into the transcript.
    pub fn update(&mut self, data: &[u8]) -> Result<(), TlsError> {
        self.message_buffer.extend_from_slice(data);
        Ok(())
    }

    /// Get the current transcript hash without consuming the state.
    ///
    /// Creates a fresh hasher, replays all buffered messages, and finishes.
    pub fn current_hash(&self) -> Result<Vec<u8>, TlsError> {
        let mut hasher = (self.factory)();
        hasher
            .update(&self.message_buffer)
            .map_err(TlsError::CryptoError)?;
        let mut out = vec![0u8; self.hash_len];
        hasher.finish(&mut out).map_err(TlsError::CryptoError)?;
        Ok(out)
    }

    /// Get the hash of an empty message sequence: Hash("").
    ///
    /// Needed for `Derive-Secret(secret, "derived", "")`.
    pub fn empty_hash(&self) -> Result<Vec<u8>, TlsError> {
        let mut hasher = (self.factory)();
        let mut out = vec![0u8; self.hash_len];
        hasher.finish(&mut out).map_err(TlsError::CryptoError)?;
        Ok(out)
    }

    /// Hash output size in bytes.
    pub fn hash_len(&self) -> usize {
        self.hash_len
    }

    /// Replace the transcript with a synthetic `message_hash` construct (RFC 8446 §4.4.1).
    ///
    /// Used when processing HelloRetryRequest: the transcript up to this point
    /// is replaced with `HandshakeType::MessageHash(254) || 0 || 0 || Hash.length || Hash(messages)`.
    pub fn replace_with_message_hash(&mut self) -> Result<(), TlsError> {
        let hash = self.current_hash()?;
        let mut synthetic = Vec::with_capacity(4 + hash.len());
        synthetic.push(254); // HandshakeType::MessageHash
        synthetic.push(0);
        synthetic.push(0);
        synthetic.push(hash.len() as u8);
        synthetic.extend_from_slice(&hash);
        self.message_buffer = synthetic;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_crypto::sha2::Sha256;

    fn sha256_factory() -> Box<dyn Digest> {
        Box::new(Sha256::new())
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_transcript_empty_hash() {
        let th = TranscriptHash::new(sha256_factory);
        let empty = th.empty_hash().unwrap();
        assert_eq!(
            to_hex(&empty),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_transcript_incremental() {
        let mut th = TranscriptHash::new(sha256_factory);
        th.update(b"hello").unwrap();
        let h1 = th.current_hash().unwrap();

        // current_hash() should be non-destructive
        let h2 = th.current_hash().unwrap();
        assert_eq!(h1, h2);

        // After more data, the hash should change
        th.update(b" world").unwrap();
        let h3 = th.current_hash().unwrap();
        assert_ne!(h1, h3);

        // h3 should equal SHA-256("hello world")
        let expected = hitls_crypto::sha2::Sha256::digest(b"hello world").unwrap();
        assert_eq!(h3, expected.to_vec());
    }

    #[test]
    fn test_transcript_replace_with_message_hash() {
        let mut th = TranscriptHash::new(sha256_factory);
        th.update(b"ClientHello").unwrap();
        th.update(b"ServerHello").unwrap();
        let hash_before = th.current_hash().unwrap();

        th.replace_with_message_hash().unwrap();
        let hash_after = th.current_hash().unwrap();

        // After replacement, hash must differ (different message buffer)
        assert_ne!(hash_before, hash_after);

        // The buffer starts with byte 254 (MessageHash handshake type)
        // and the length field equals hash_len (32 for SHA-256)
        assert_eq!(th.hash_len(), 32);
    }

    fn sha384_factory() -> Box<dyn Digest> {
        Box::new(hitls_crypto::sha2::Sha384::new())
    }

    #[test]
    fn test_transcript_sha384() {
        let th = TranscriptHash::new(sha384_factory);
        assert_eq!(th.hash_len(), 48);

        // SHA-384("") known value
        let empty = th.empty_hash().unwrap();
        assert_eq!(
            to_hex(&empty),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[test]
    fn test_transcript_hash_len_sha256() {
        let th = TranscriptHash::new(sha256_factory);
        assert_eq!(th.hash_len(), 32);
    }

    #[test]
    fn test_transcript_empty_update() {
        let mut th = TranscriptHash::new(sha256_factory);
        th.update(b"").unwrap();
        let h = th.current_hash().unwrap();
        let empty = th.empty_hash().unwrap();
        // Hashing empty data should equal the empty hash
        assert_eq!(h, empty);
    }

    #[test]
    fn test_transcript_binary_data() {
        let mut th = TranscriptHash::new(sha256_factory);
        // Feed raw binary data including null bytes and high bytes
        let data: Vec<u8> = (0..=255).collect();
        th.update(&data).unwrap();
        let h = th.current_hash().unwrap();
        assert_eq!(h.len(), 32);

        // Verify against direct SHA-256
        let expected = Sha256::digest(&data).unwrap();
        assert_eq!(h, expected.to_vec());
    }

    #[test]
    fn test_transcript_double_replace_message_hash() {
        let mut th = TranscriptHash::new(sha256_factory);
        th.update(b"ClientHello1").unwrap();
        th.update(b"ServerHello+HRR").unwrap();
        th.replace_with_message_hash().unwrap();
        let h1 = th.current_hash().unwrap();

        // Add second ClientHello, then replace again (simulates double HRR scenario)
        th.update(b"ClientHello2").unwrap();
        th.replace_with_message_hash().unwrap();
        let h2 = th.current_hash().unwrap();

        // The two hashes must differ (different buffer content)
        assert_ne!(h1, h2);
        assert_eq!(h2.len(), 32);
    }

    #[test]
    fn test_transcript_current_hash_fresh() {
        // current_hash on a freshly created transcript should equal empty_hash
        let th = TranscriptHash::new(sha256_factory);
        let current = th.current_hash().unwrap();
        let empty = th.empty_hash().unwrap();
        assert_eq!(current, empty);
    }

    #[test]
    fn test_transcript_update_after_replace() {
        let mut th = TranscriptHash::new(sha256_factory);
        th.update(b"msg1").unwrap();
        th.replace_with_message_hash().unwrap();
        let h_after_replace = th.current_hash().unwrap();

        // Adding more data after replacement should change the hash
        th.update(b"msg2").unwrap();
        let h_after_update = th.current_hash().unwrap();
        assert_ne!(h_after_replace, h_after_update);
        assert_eq!(h_after_update.len(), 32);
    }
}
