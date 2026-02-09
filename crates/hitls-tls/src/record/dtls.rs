//! DTLS 1.2 record layer (RFC 6347 §4.1).
//!
//! DTLS record header is 13 bytes:
//! `content_type(1) || version(2) || epoch(2) || sequence_number(6) || length(2)`

use super::ContentType;
use hitls_types::TlsError;

/// DTLS record header length: 13 bytes.
pub const DTLS_RECORD_HEADER_LEN: usize = 13;

/// DTLS 1.2 version wire value.
pub const DTLS12_VERSION: u16 = 0xFEFD;

/// Maximum 48-bit sequence number.
const MAX_SEQ_48: u64 = (1u64 << 48) - 1;

/// A parsed DTLS record.
#[derive(Debug, Clone)]
pub struct DtlsRecord {
    pub content_type: ContentType,
    pub version: u16,
    pub epoch: u16,
    pub sequence_number: u64, // 48-bit, stored in lower 48 bits
    pub fragment: Vec<u8>,
}

/// Parse a DTLS record from bytes.
///
/// Returns `(record, bytes_consumed)`.
pub fn parse_dtls_record(data: &[u8]) -> Result<(DtlsRecord, usize), TlsError> {
    if data.len() < DTLS_RECORD_HEADER_LEN {
        return Err(TlsError::RecordError(
            "incomplete DTLS record header".into(),
        ));
    }

    let content_type = match data[0] {
        20 => ContentType::ChangeCipherSpec,
        21 => ContentType::Alert,
        22 => ContentType::Handshake,
        23 => ContentType::ApplicationData,
        _ => return Err(TlsError::RecordError("unknown content type".into())),
    };

    let version = u16::from_be_bytes([data[1], data[2]]);
    let epoch = u16::from_be_bytes([data[3], data[4]]);

    // 48-bit sequence number in bytes 5..11
    let mut seq_bytes = [0u8; 8];
    seq_bytes[2..8].copy_from_slice(&data[5..11]);
    let sequence_number = u64::from_be_bytes(seq_bytes);

    let length = u16::from_be_bytes([data[11], data[12]]) as usize;

    let total = DTLS_RECORD_HEADER_LEN + length;
    if data.len() < total {
        return Err(TlsError::RecordError("incomplete DTLS record body".into()));
    }

    let fragment = data[DTLS_RECORD_HEADER_LEN..total].to_vec();

    Ok((
        DtlsRecord {
            content_type,
            version,
            epoch,
            sequence_number,
            fragment,
        },
        total,
    ))
}

/// Serialize a DTLS record to bytes.
pub fn serialize_dtls_record(record: &DtlsRecord) -> Vec<u8> {
    let len = record.fragment.len() as u16;
    let mut buf = Vec::with_capacity(DTLS_RECORD_HEADER_LEN + record.fragment.len());

    buf.push(record.content_type as u8);
    buf.extend_from_slice(&record.version.to_be_bytes());
    buf.extend_from_slice(&record.epoch.to_be_bytes());

    // 48-bit sequence number → 6 bytes
    let seq_bytes = record.sequence_number.to_be_bytes();
    buf.extend_from_slice(&seq_bytes[2..8]); // lower 6 bytes

    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&record.fragment);
    buf
}

/// Epoch and sequence number state for DTLS record layer.
///
/// Epoch increments when the cipher state changes (after CCS).
/// Sequence number is 48-bit and resets to 0 on epoch change.
pub struct EpochState {
    pub epoch: u16,
    pub write_seq: u64,
}

impl EpochState {
    pub fn new() -> Self {
        Self {
            epoch: 0,
            write_seq: 0,
        }
    }

    /// Advance to the next epoch. Resets sequence number to 0.
    pub fn next_epoch(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.write_seq = 0;
    }

    /// Get the next write sequence number and increment.
    pub fn next_write_seq(&mut self) -> Result<u64, TlsError> {
        if self.write_seq > MAX_SEQ_48 {
            return Err(TlsError::RecordError(
                "DTLS sequence number overflow".into(),
            ));
        }
        let seq = self.write_seq;
        self.write_seq += 1;
        Ok(seq)
    }
}

impl Default for EpochState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dtls_record_valid() {
        // Build a valid DTLS record: Handshake, version=0xFEFD, epoch=0, seq=1, body="hello"
        let mut data = vec![
            22, // Handshake
            0xFE, 0xFD, // DTLS 1.2
            0x00, 0x00, // epoch=0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // seq=1
            0x00, 0x05, // length=5
        ];
        data.extend_from_slice(b"hello");

        let (record, consumed) = parse_dtls_record(&data).unwrap();
        assert_eq!(record.content_type, ContentType::Handshake);
        assert_eq!(record.version, DTLS12_VERSION);
        assert_eq!(record.epoch, 0);
        assert_eq!(record.sequence_number, 1);
        assert_eq!(record.fragment, b"hello");
        assert_eq!(consumed, 18);
    }

    #[test]
    fn test_parse_dtls_record_too_short() {
        let data = vec![22, 0xFE, 0xFD, 0x00]; // only 4 bytes
        assert!(parse_dtls_record(&data).is_err());
    }

    #[test]
    fn test_serialize_dtls_record_roundtrip() {
        let record = DtlsRecord {
            content_type: ContentType::ApplicationData,
            version: DTLS12_VERSION,
            epoch: 1,
            sequence_number: 42,
            fragment: b"test data".to_vec(),
        };

        let bytes = serialize_dtls_record(&record);
        let (parsed, consumed) = parse_dtls_record(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.content_type, ContentType::ApplicationData);
        assert_eq!(parsed.version, DTLS12_VERSION);
        assert_eq!(parsed.epoch, 1);
        assert_eq!(parsed.sequence_number, 42);
        assert_eq!(parsed.fragment, b"test data");
    }

    #[test]
    fn test_dtls_record_epoch_and_seq_encoding() {
        let record = DtlsRecord {
            content_type: ContentType::Handshake,
            version: DTLS12_VERSION,
            epoch: 0x0102,
            sequence_number: 0x030405060708,
            fragment: vec![0xAA],
        };

        let bytes = serialize_dtls_record(&record);
        // Header: type(1) + version(2) + epoch(2) + seq(6) + length(2) = 13
        assert_eq!(bytes.len(), 14); // 13 header + 1 body
        assert_eq!(&bytes[3..5], &[0x01, 0x02]); // epoch
        assert_eq!(&bytes[5..11], &[0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // seq
        assert_eq!(&bytes[11..13], &[0x00, 0x01]); // length
        assert_eq!(bytes[13], 0xAA); // body
    }

    #[test]
    fn test_epoch_state_initial() {
        let state = EpochState::new();
        assert_eq!(state.epoch, 0);
        assert_eq!(state.write_seq, 0);
    }

    #[test]
    fn test_epoch_state_next_epoch_resets_seq() {
        let mut state = EpochState::new();
        state.write_seq = 100;
        state.next_epoch();
        assert_eq!(state.epoch, 1);
        assert_eq!(state.write_seq, 0);

        state.write_seq = 200;
        state.next_epoch();
        assert_eq!(state.epoch, 2);
        assert_eq!(state.write_seq, 0);
    }

    #[test]
    fn test_epoch_state_seq_overflow() {
        let mut state = EpochState::new();
        // Set to max 48-bit value
        state.write_seq = (1u64 << 48) - 1;
        // This should succeed (returns the max value)
        let seq = state.next_write_seq().unwrap();
        assert_eq!(seq, (1u64 << 48) - 1);

        // Next call should fail (overflow)
        assert!(state.next_write_seq().is_err());
    }
}
