//! DTLS handshake message fragmentation and reassembly (RFC 6347 §4.2.3).
//!
//! Large handshake messages must be fragmented to fit within the DTLS MTU.
//! Each fragment has its own 12-byte DTLS handshake header with
//! `fragment_offset` and `fragment_length` fields.

use std::collections::HashMap;

use super::codec_dtls::{DtlsHandshakeHeader, DTLS_HS_HEADER_LEN};
use super::HandshakeType;
use hitls_types::TlsError;

/// Default DTLS MTU (conservative for UDP over IPv4/IPv6).
pub const DEFAULT_MTU: usize = 1200;

/// Fragment a handshake message body into MTU-sized DTLS handshake fragments.
///
/// Each returned `Vec<u8>` is a complete DTLS handshake message (12-byte header + fragment body).
/// If the message fits in a single fragment, returns a single-element vector.
pub fn fragment_handshake(
    msg_type: HandshakeType,
    body: &[u8],
    message_seq: u16,
    max_fragment_payload: usize,
) -> Vec<Vec<u8>> {
    let total_length = body.len() as u32;

    if body.len() <= max_fragment_payload {
        // Single fragment
        let msg = build_fragment(msg_type, total_length, message_seq, 0, body);
        return vec![msg];
    }

    let mut fragments = Vec::new();
    let mut offset = 0usize;

    while offset < body.len() {
        let end = std::cmp::min(offset + max_fragment_payload, body.len());
        let chunk = &body[offset..end];
        let msg = build_fragment(msg_type, total_length, message_seq, offset as u32, chunk);
        fragments.push(msg);
        offset = end;
    }

    fragments
}

fn build_fragment(
    msg_type: HandshakeType,
    total_length: u32,
    message_seq: u16,
    fragment_offset: u32,
    fragment_data: &[u8],
) -> Vec<u8> {
    let fragment_length = fragment_data.len() as u32;
    let mut out = Vec::with_capacity(DTLS_HS_HEADER_LEN + fragment_data.len());
    out.push(msg_type as u8);
    push_u24(&mut out, total_length);
    out.extend_from_slice(&message_seq.to_be_bytes());
    push_u24(&mut out, fragment_offset);
    push_u24(&mut out, fragment_length);
    out.extend_from_slice(fragment_data);
    out
}

fn push_u24(buf: &mut Vec<u8>, val: u32) {
    buf.push((val >> 16) as u8);
    buf.push((val >> 8) as u8);
    buf.push(val as u8);
}

/// Tracks reassembly state for a single handshake message.
pub struct ReassemblyBuffer {
    msg_type: HandshakeType,
    message_seq: u16,
    total_length: usize,
    buffer: Vec<u8>,
    received: Vec<bool>,
}

impl ReassemblyBuffer {
    /// Create a new reassembly buffer for a message of known total length.
    pub fn new(msg_type: HandshakeType, message_seq: u16, total_length: usize) -> Self {
        Self {
            msg_type,
            message_seq,
            total_length,
            buffer: vec![0u8; total_length],
            received: vec![false; total_length],
        }
    }

    /// Insert a fragment. Returns `true` if the message is now complete.
    pub fn insert_fragment(&mut self, offset: usize, data: &[u8]) -> Result<bool, TlsError> {
        if offset + data.len() > self.total_length {
            return Err(TlsError::HandshakeFailed(
                "fragment exceeds total message length".into(),
            ));
        }
        self.buffer[offset..offset + data.len()].copy_from_slice(data);
        for i in offset..offset + data.len() {
            self.received[i] = true;
        }
        Ok(self.is_complete())
    }

    /// Check if all bytes have been received.
    pub fn is_complete(&self) -> bool {
        // Empty messages (like ServerHelloDone) are always complete
        self.total_length == 0 || self.received.iter().all(|&r| r)
    }

    /// Get the reassembled message body (only valid if complete).
    pub fn message_body(&self) -> Option<&[u8]> {
        if self.is_complete() {
            Some(&self.buffer)
        } else {
            None
        }
    }

    /// Get the full DTLS handshake message (12-byte header + body) once complete.
    pub fn dtls_message(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }
        let msg = build_fragment(
            self.msg_type,
            self.total_length as u32,
            self.message_seq,
            0,
            &self.buffer,
        );
        Some(msg)
    }
}

/// Manages reassembly for multiple concurrent handshake messages.
pub struct ReassemblyManager {
    buffers: HashMap<u16, ReassemblyBuffer>,
    next_expected_seq: u16,
}

impl ReassemblyManager {
    pub fn new() -> Self {
        Self {
            buffers: HashMap::new(),
            next_expected_seq: 0,
        }
    }

    /// Process an incoming DTLS handshake fragment.
    ///
    /// Returns `Some(reassembled_dtls_message)` when a message with
    /// `message_seq == next_expected_seq` is complete. Otherwise returns `None`.
    pub fn process_fragment(
        &mut self,
        header: &DtlsHandshakeHeader,
        fragment_body: &[u8],
    ) -> Result<Option<Vec<u8>>, TlsError> {
        // Ignore old messages
        if header.message_seq < self.next_expected_seq {
            return Ok(None);
        }

        let buf = self.buffers.entry(header.message_seq).or_insert_with(|| {
            ReassemblyBuffer::new(header.msg_type, header.message_seq, header.length as usize)
        });

        buf.insert_fragment(header.fragment_offset as usize, fragment_body)?;

        // Check if the next expected message is complete
        if header.message_seq == self.next_expected_seq {
            if let Some(buf) = self.buffers.get(&self.next_expected_seq) {
                if buf.is_complete() {
                    let msg = buf.dtls_message().unwrap();
                    self.buffers.remove(&self.next_expected_seq);
                    self.next_expected_seq += 1;
                    return Ok(Some(msg));
                }
            }
        }

        Ok(None)
    }

    /// Reset for a new handshake.
    pub fn reset(&mut self) {
        self.buffers.clear();
        self.next_expected_seq = 0;
    }
}

impl Default for ReassemblyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::codec_dtls::parse_dtls_handshake_header;

    #[test]
    fn test_fragment_small_message_no_split() {
        let body = b"small msg";
        let fragments = fragment_handshake(HandshakeType::Finished, body, 5, 1000);
        assert_eq!(fragments.len(), 1);

        let (hdr, data, _) = parse_dtls_handshake_header(&fragments[0]).unwrap();
        assert_eq!(hdr.msg_type, HandshakeType::Finished);
        assert_eq!(hdr.message_seq, 5);
        assert_eq!(hdr.fragment_offset, 0);
        assert_eq!(hdr.fragment_length, body.len() as u32);
        assert_eq!(hdr.length, body.len() as u32);
        assert_eq!(data, body);
    }

    #[test]
    fn test_fragment_large_message_multiple_chunks() {
        let body = vec![0xAA; 3000];
        let max_frag = 1000;
        let fragments = fragment_handshake(HandshakeType::Certificate, &body, 2, max_frag);
        assert_eq!(fragments.len(), 3);

        // Verify each fragment
        let mut reassembled = vec![0u8; 3000];
        for frag in &fragments {
            let (hdr, data, _) = parse_dtls_handshake_header(frag).unwrap();
            assert_eq!(hdr.msg_type, HandshakeType::Certificate);
            assert_eq!(hdr.length, 3000);
            assert_eq!(hdr.message_seq, 2);
            let off = hdr.fragment_offset as usize;
            reassembled[off..off + data.len()].copy_from_slice(data);
        }
        assert_eq!(reassembled, body);
    }

    #[test]
    fn test_fragment_exact_boundary() {
        let body = vec![0xBB; 100];
        let fragments = fragment_handshake(HandshakeType::Finished, &body, 0, 100);
        // Exactly fits in one fragment
        assert_eq!(fragments.len(), 1);

        let fragments = fragment_handshake(HandshakeType::Finished, &body, 0, 50);
        // Exactly splits into 2
        assert_eq!(fragments.len(), 2);
    }

    #[test]
    fn test_reassembly_single_fragment() {
        let body = b"complete";
        let mut buf = ReassemblyBuffer::new(HandshakeType::Finished, 0, body.len());
        let complete = buf.insert_fragment(0, body).unwrap();
        assert!(complete);
        assert_eq!(buf.message_body().unwrap(), body);
    }

    #[test]
    fn test_reassembly_multiple_in_order() {
        let body = b"ABCDEFGHIJ"; // 10 bytes
        let mut buf = ReassemblyBuffer::new(HandshakeType::Certificate, 0, 10);

        assert!(!buf.insert_fragment(0, &body[0..4]).unwrap()); // "ABCD"
        assert!(!buf.insert_fragment(4, &body[4..7]).unwrap()); // "EFG"
        assert!(buf.insert_fragment(7, &body[7..10]).unwrap()); // "HIJ"
        assert_eq!(buf.message_body().unwrap(), body.as_slice());
    }

    #[test]
    fn test_reassembly_out_of_order() {
        let body = b"0123456789";
        let mut buf = ReassemblyBuffer::new(HandshakeType::Certificate, 0, 10);

        assert!(!buf.insert_fragment(7, &body[7..10]).unwrap()); // last chunk first
        assert!(!buf.insert_fragment(0, &body[0..4]).unwrap()); // first chunk
        assert!(buf.insert_fragment(4, &body[4..7]).unwrap()); // middle chunk
        assert_eq!(buf.message_body().unwrap(), body.as_slice());
    }

    #[test]
    fn test_reassembly_duplicate_fragment() {
        let body = b"hello";
        let mut buf = ReassemblyBuffer::new(HandshakeType::Finished, 0, 5);
        assert!(!buf.insert_fragment(0, &body[0..3]).unwrap());
        // Duplicate first fragment — no error
        assert!(!buf.insert_fragment(0, &body[0..3]).unwrap());
        assert!(buf.insert_fragment(3, &body[3..5]).unwrap());
        assert_eq!(buf.message_body().unwrap(), body.as_slice());
    }
}
