//! DTLS 1.3 record layer (RFC 9147).
//!
//! Header formats:
//! - DTLSPlaintext (13 bytes): used for initial unencrypted messages (epoch 0)
//! - DTLSCiphertext (unified header): compact format for encrypted records
//!
//! We use the full DTLSPlaintext format for both plaintext and ciphertext records
//! for simplicity. The AAD for AEAD always uses the 13-byte DTLSPlaintext layout.

use super::ContentType;
use hitls_types::TlsError;

/// DTLS 1.3 legacy record version on the wire: {254, 253} = 0xFEFD.
pub const DTLS13_LEGACY_VERSION: u16 = 0xFEFD;

/// Maximum DTLS 1.3 epoch value (3 = application data).
pub const EPOCH_INITIAL: u16 = 0;
pub const EPOCH_HANDSHAKE: u16 = 2;
pub const EPOCH_APPLICATION: u16 = 3;

/// Maximum 48-bit sequence number.
const MAX_SEQ: u64 = (1u64 << 48) - 1;

/// DTLS 1.3 epoch + sequence state for one direction (read or write).
#[derive(Debug, Clone)]
pub struct Dtls13EpochState {
    epoch: u16,
    write_seq: u64,
}

impl Dtls13EpochState {
    pub fn new(epoch: u16) -> Self {
        Self {
            epoch,
            write_seq: 0,
        }
    }

    pub fn epoch(&self) -> u16 {
        self.epoch
    }

    pub fn set_epoch(&mut self, epoch: u16) {
        self.epoch = epoch;
        self.write_seq = 0;
    }

    /// Get next write sequence number and increment.
    pub fn next_write_seq(&mut self) -> Result<u64, TlsError> {
        if self.write_seq > MAX_SEQ {
            return Err(TlsError::RecordError(
                "DTLS 1.3 sequence number overflow".into(),
            ));
        }
        let seq = self.write_seq;
        self.write_seq += 1;
        Ok(seq)
    }
}

/// A parsed DTLS 1.3 record (DTLSPlaintext format).
#[derive(Debug, Clone)]
pub struct Dtls13Record {
    pub content_type: ContentType,
    pub epoch: u16,
    pub sequence_number: u64,
    pub fragment: Vec<u8>,
}

/// Parse a DTLS 1.3 record in DTLSPlaintext format (13-byte header).
///
/// Layout: content_type(1) || version(2) || epoch(2) || sequence_number(6) || length(2) || fragment
pub fn parse_dtls13_record(data: &[u8]) -> Result<(Dtls13Record, usize), TlsError> {
    if data.len() < 13 {
        return Err(TlsError::RecordError(
            "DTLS 1.3: incomplete record header".into(),
        ));
    }

    let content_type = match data[0] {
        20 => ContentType::ChangeCipherSpec,
        21 => ContentType::Alert,
        22 => ContentType::Handshake,
        23 => ContentType::ApplicationData,
        _ => {
            return Err(TlsError::RecordError(
                "DTLS 1.3: unknown content type".into(),
            ))
        }
    };

    let epoch = u16::from_be_bytes([data[3], data[4]]);
    let seq = u64::from_be_bytes([0, 0, data[5], data[6], data[7], data[8], data[9], data[10]]);
    let length = u16::from_be_bytes([data[11], data[12]]) as usize;

    if data.len() < 13 + length {
        return Err(TlsError::RecordError(
            "DTLS 1.3: incomplete record body".into(),
        ));
    }

    let fragment = data[13..13 + length].to_vec();
    Ok((
        Dtls13Record {
            content_type,
            epoch,
            sequence_number: seq,
            fragment,
        },
        13 + length,
    ))
}

/// Serialize a DTLS 1.3 record in DTLSPlaintext format (13-byte header).
pub fn serialize_dtls13_record(record: &Dtls13Record) -> Vec<u8> {
    let len = record.fragment.len() as u16;
    let mut buf = Vec::with_capacity(13 + record.fragment.len());
    buf.push(record.content_type as u8);
    buf.extend_from_slice(&DTLS13_LEGACY_VERSION.to_be_bytes());
    buf.extend_from_slice(&record.epoch.to_be_bytes());
    // 6-byte sequence number
    let seq_bytes = record.sequence_number.to_be_bytes();
    buf.extend_from_slice(&seq_bytes[2..8]);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&record.fragment);
    buf
}

/// Build the 13-byte AAD for DTLS 1.3 AEAD encryption.
///
/// AAD = content_type(1) || legacy_version(2) || epoch(2) || sequence(6) || plaintext_length(2)
pub fn build_aad_dtls13(
    content_type: ContentType,
    epoch: u16,
    sequence_number: u64,
    plaintext_length: u16,
) -> [u8; 13] {
    let mut aad = [0u8; 13];
    aad[0] = content_type as u8;
    aad[1..3].copy_from_slice(&DTLS13_LEGACY_VERSION.to_be_bytes());
    aad[3..5].copy_from_slice(&epoch.to_be_bytes());
    let seq_bytes = sequence_number.to_be_bytes();
    aad[5..11].copy_from_slice(&seq_bytes[2..8]);
    aad[11..13].copy_from_slice(&plaintext_length.to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_state_basic() {
        let mut state = Dtls13EpochState::new(EPOCH_INITIAL);
        assert_eq!(state.epoch(), 0);
        assert_eq!(state.next_write_seq().unwrap(), 0);
        assert_eq!(state.next_write_seq().unwrap(), 1);
        assert_eq!(state.next_write_seq().unwrap(), 2);
    }

    #[test]
    fn test_epoch_state_set_epoch_resets_seq() {
        let mut state = Dtls13EpochState::new(EPOCH_INITIAL);
        state.next_write_seq().unwrap();
        state.next_write_seq().unwrap();
        state.set_epoch(EPOCH_HANDSHAKE);
        assert_eq!(state.epoch(), 2);
        assert_eq!(state.next_write_seq().unwrap(), 0);
    }

    #[test]
    fn test_parse_serialize_roundtrip() {
        let record = Dtls13Record {
            content_type: ContentType::Handshake,
            epoch: 0,
            sequence_number: 42,
            fragment: vec![0x01, 0x02, 0x03, 0x04, 0x05],
        };
        let bytes = serialize_dtls13_record(&record);
        assert_eq!(bytes.len(), 13 + 5);

        let (parsed, consumed) = parse_dtls13_record(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.content_type, ContentType::Handshake);
        assert_eq!(parsed.epoch, 0);
        assert_eq!(parsed.sequence_number, 42);
        assert_eq!(parsed.fragment, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn test_parse_incomplete_header() {
        assert!(parse_dtls13_record(&[]).is_err());
        assert!(parse_dtls13_record(&[22; 12]).is_err());
    }

    #[test]
    fn test_parse_incomplete_body() {
        // Header says 100 bytes but body is empty
        let mut data = vec![
            22, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        data.extend_from_slice(&100u16.to_be_bytes());
        assert!(parse_dtls13_record(&data).is_err());
    }

    #[test]
    fn test_build_aad() {
        let aad = build_aad_dtls13(ContentType::ApplicationData, 3, 42, 100);
        assert_eq!(aad[0], 23); // ApplicationData
        assert_eq!(&aad[1..3], &[0xFE, 0xFD]); // version
        assert_eq!(&aad[3..5], &[0x00, 0x03]); // epoch
        assert_eq!(aad[10], 42); // low byte of seq
        assert_eq!(&aad[11..13], &[0x00, 100]); // length
    }

    #[test]
    fn test_epoch_constants() {
        assert_eq!(EPOCH_INITIAL, 0);
        assert_eq!(EPOCH_HANDSHAKE, 2);
        assert_eq!(EPOCH_APPLICATION, 3);
    }
}
