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
}
