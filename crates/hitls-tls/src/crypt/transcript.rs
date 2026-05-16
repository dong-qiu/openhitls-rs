//! Transcript hash for TLS 1.3 handshake messages.
//!
//! Maintains a running hash over all handshake messages in order.

use super::{DigestVariant, HashAlgId};
use hitls_crypto::provider::Digest;
use hitls_types::TlsError;

/// Stack-allocated hash output (max 64 bytes, no heap allocation).
///
/// Implements `Deref<Target=[u8]>` so it can be used wherever `&[u8]` is expected
/// (function arguments, `extend_from_slice`, `.len()`, etc.) with zero caller changes.
#[derive(Debug)]
pub struct HashOutput {
    buf: [u8; 64],
    len: usize,
}

impl HashOutput {
    fn new(len: usize) -> Self {
        Self {
            buf: [0u8; 64],
            len,
        }
    }
}

impl std::ops::Deref for HashOutput {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl PartialEq for HashOutput {
    fn eq(&self, other: &HashOutput) -> bool {
        self.buf[..self.len] == other.buf[..other.len]
    }
}

impl PartialEq<Vec<u8>> for HashOutput {
    fn eq(&self, other: &Vec<u8>) -> bool {
        &self.buf[..self.len] == other.as_slice()
    }
}

impl PartialEq<[u8]> for HashOutput {
    fn eq(&self, other: &[u8]) -> bool {
        &self.buf[..self.len] == other
    }
}

/// Running transcript hash over handshake messages.
///
/// Uses a message buffer + replay approach: `current_hash()` creates a fresh
/// hasher, replays all buffered data, and finishes to get the intermediate hash.
/// The live hasher is never finalized, so `update()` continues to work.
///
/// `Clone` (Phase I97) snapshots the buffered messages — used to retain the
/// completed handshake transcript so post-handshake CertificateVerify
/// (RFC 8446 §4.4.1 / §4.6.2) can continue it.
#[derive(Clone)]
pub struct TranscriptHash {
    alg: HashAlgId,
    message_buffer: Vec<u8>,
    hash_len: usize,
}

impl TranscriptHash {
    /// Create a new TranscriptHash with the given hash algorithm.
    pub fn new(alg: HashAlgId) -> Self {
        let hash_len = DigestVariant::output_size_for(alg);
        Self {
            alg,
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
    /// Returns a stack-allocated `HashOutput` (no heap allocation).
    pub fn current_hash(&self) -> Result<HashOutput, TlsError> {
        let mut hasher = DigestVariant::new(self.alg);
        hasher
            .update(&self.message_buffer)
            .map_err(TlsError::CryptoError)?;
        let mut out = HashOutput::new(self.hash_len);
        hasher
            .finish(&mut out.buf[..self.hash_len])
            .map_err(TlsError::CryptoError)?;
        Ok(out)
    }

    /// Get the hash of an empty message sequence: Hash("").
    ///
    /// Needed for `Derive-Secret(secret, "derived", "")`.
    pub fn empty_hash(&self) -> Result<HashOutput, TlsError> {
        let mut hasher = DigestVariant::new(self.alg);
        let mut out = HashOutput::new(self.hash_len);
        hasher
            .finish(&mut out.buf[..self.hash_len])
            .map_err(TlsError::CryptoError)?;
        Ok(out)
    }

    /// Hash output size in bytes.
    pub fn hash_len(&self) -> usize {
        self.hash_len
    }

    /// Raw buffered handshake message bytes. Used by the TLS 1.2
    /// CertificateVerify path to re-hash the transcript with the
    /// CV-scheme's hash algorithm (which may differ from the PRF
    /// hash this transcript is configured with) — RFC 5246 §7.4.8.
    pub fn message_bytes(&self) -> &[u8] {
        &self.message_buffer
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
    use hitls_utils::hex::to_hex;

    #[test]
    fn test_transcript_empty_hash() {
        let th = TranscriptHash::new(HashAlgId::Sha256);
        let empty = th.empty_hash().unwrap();
        assert_eq!(
            to_hex(&empty),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_transcript_incremental() {
        let mut th = TranscriptHash::new(HashAlgId::Sha256);
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
        let expected = Sha256::digest(b"hello world").unwrap();
        assert_eq!(h3, expected.to_vec());
    }

    #[test]
    fn test_transcript_clone_independence() {
        // Phase I97 — `request_client_auth` clones the retained handshake
        // transcript as a post-handshake baseline. The clone must (a)
        // reproduce the baseline hash exactly and (b) be independent —
        // updating one clone must not affect the original or siblings.
        let mut base = TranscriptHash::new(HashAlgId::Sha256);
        base.update(b"ClientHello..server..client-Finished")
            .unwrap();
        let baseline = base.current_hash().unwrap();

        let mut clone_a = base.clone();
        let mut clone_b = base.clone();
        // (a) a fresh clone reproduces the baseline.
        assert_eq!(clone_a.current_hash().unwrap(), baseline);

        // (b) extending clone_a leaves base and clone_b untouched.
        clone_a.update(b"CertificateRequest||Certificate").unwrap();
        assert_ne!(clone_a.current_hash().unwrap(), baseline);
        assert_eq!(base.current_hash().unwrap(), baseline);
        assert_eq!(clone_b.current_hash().unwrap(), baseline);

        // The same continuation on an independent clone yields the same
        // hash — i.e. two post-handshake auths off one baseline agree.
        clone_b.update(b"CertificateRequest||Certificate").unwrap();
        assert_eq!(
            clone_a.current_hash().unwrap(),
            clone_b.current_hash().unwrap()
        );
    }

    #[test]
    fn test_transcript_replace_with_message_hash() {
        let mut th = TranscriptHash::new(HashAlgId::Sha256);
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

    #[test]
    fn test_transcript_sha384() {
        let th = TranscriptHash::new(HashAlgId::Sha384);
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
        let th = TranscriptHash::new(HashAlgId::Sha256);
        assert_eq!(th.hash_len(), 32);
    }

    #[test]
    fn test_transcript_empty_update() {
        let mut th = TranscriptHash::new(HashAlgId::Sha256);
        th.update(b"").unwrap();
        let h = th.current_hash().unwrap();
        let empty = th.empty_hash().unwrap();
        // Hashing empty data should equal the empty hash
        assert_eq!(h, empty);
    }

    #[test]
    fn test_transcript_binary_data() {
        let mut th = TranscriptHash::new(HashAlgId::Sha256);
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
        let mut th = TranscriptHash::new(HashAlgId::Sha256);
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
        let th = TranscriptHash::new(HashAlgId::Sha256);
        let current = th.current_hash().unwrap();
        let empty = th.empty_hash().unwrap();
        assert_eq!(current, empty);
    }

    #[test]
    fn test_transcript_update_after_replace() {
        let mut th = TranscriptHash::new(HashAlgId::Sha256);
        th.update(b"msg1").unwrap();
        th.replace_with_message_hash().unwrap();
        let h_after_replace = th.current_hash().unwrap();

        // Adding more data after replacement should change the hash
        th.update(b"msg2").unwrap();
        let h_after_update = th.current_hash().unwrap();
        assert_ne!(h_after_replace, h_after_update);
        assert_eq!(h_after_update.len(), 32);
    }

    // ===== Phase T112: SM3 transcript hash tests =====

    #[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
    #[test]
    fn test_transcript_sm3_empty_hash() {
        // GM/T 0004-2012: SM3("") known value
        let th = TranscriptHash::new(HashAlgId::Sm3);
        let empty = th.empty_hash().unwrap();
        assert_eq!(
            to_hex(&empty),
            "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
        );
    }

    #[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
    #[test]
    fn test_transcript_sm3_incremental() {
        let mut th = TranscriptHash::new(HashAlgId::Sm3);
        th.update(b"abc").unwrap();
        let h1 = th.current_hash().unwrap();

        // SM3("abc") known value from GM/T 0004-2012
        assert_eq!(
            to_hex(&h1),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        );

        // current_hash() should be non-destructive
        let h2 = th.current_hash().unwrap();
        assert_eq!(h1, h2);

        // After more data, the hash should change
        th.update(b"def").unwrap();
        let h3 = th.current_hash().unwrap();
        assert_ne!(h1, h3);
        assert_eq!(h3.len(), 32);
    }

    #[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
    #[test]
    fn test_transcript_sm3_hash_len() {
        let th = TranscriptHash::new(HashAlgId::Sm3);
        assert_eq!(th.hash_len(), 32);

        // empty_hash() output should be exactly 32 bytes
        let empty = th.empty_hash().unwrap();
        assert_eq!(empty.len(), 32);
    }
}
