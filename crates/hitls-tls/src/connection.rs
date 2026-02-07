//! Synchronous TLS connection wrapping a `Read + Write` transport.

use std::io::{Read, Write};

use crate::config::TlsConfig;
use crate::handshake::client::ClientHandshake;
use crate::handshake::codec::parse_handshake_header;
use crate::handshake::HandshakeState;
use crate::record::{ContentType, RecordLayer};
use crate::{CipherSuite, TlsConnection, TlsError, TlsVersion};

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    Handshaking,
    Connected,
    Closed,
    Error,
}

/// A synchronous TLS 1.3 client connection.
pub struct TlsClientConnection<S: Read + Write> {
    stream: S,
    config: TlsConfig,
    record_layer: RecordLayer,
    state: ConnectionState,
    negotiated_suite: Option<CipherSuite>,
    negotiated_version: Option<TlsVersion>,
    /// Buffer for reading records from the stream.
    read_buf: Vec<u8>,
    /// Buffered decrypted application data.
    app_data_buf: Vec<u8>,
}

impl<S: Read + Write> TlsClientConnection<S> {
    /// Create a new TLS client connection wrapping the given stream.
    pub fn new(stream: S, config: TlsConfig) -> Self {
        Self {
            stream,
            config,
            record_layer: RecordLayer::new(),
            state: ConnectionState::Handshaking,
            negotiated_suite: None,
            negotiated_version: None,
            read_buf: Vec::with_capacity(16 * 1024),
            app_data_buf: Vec::new(),
        }
    }

    /// Read at least `min_bytes` from the stream into read_buf.
    fn fill_buf(&mut self, min_bytes: usize) -> Result<(), TlsError> {
        while self.read_buf.len() < min_bytes {
            let mut tmp = [0u8; 16384];
            let n = self
                .stream
                .read(&mut tmp)
                .map_err(|e| TlsError::RecordError(format!("read error: {e}")))?;
            if n == 0 {
                return Err(TlsError::RecordError("unexpected EOF".into()));
            }
            self.read_buf.extend_from_slice(&tmp[..n]);
        }
        Ok(())
    }

    /// Read a single record from the stream.
    /// Returns (content_type, plaintext).
    fn read_record(&mut self) -> Result<(ContentType, Vec<u8>), TlsError> {
        // Need at least 5 bytes for the record header
        self.fill_buf(5)?;

        // Peek at the length to know how many bytes we need
        let length = u16::from_be_bytes([self.read_buf[3], self.read_buf[4]]) as usize;
        self.fill_buf(5 + length)?;

        let (ct, plaintext, consumed) = self.record_layer.open_record(&self.read_buf)?;
        self.read_buf.drain(..consumed);

        Ok((ct, plaintext))
    }

    /// Run the TLS 1.3 client handshake.
    fn do_handshake(&mut self) -> Result<(), TlsError> {
        let mut hs = ClientHandshake::new(self.config.clone());

        // Step 1: Build and send ClientHello
        let ch_msg = hs.build_client_hello()?;
        let ch_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &ch_msg)?;
        self.stream
            .write_all(&ch_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Step 2: Read ServerHello (plaintext record)
        let (ct, sh_data) = self.read_record()?;
        if ct != ContentType::Handshake {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Handshake, got {ct:?}"
            )));
        }

        // Parse handshake header to get the full ServerHello message
        let (hs_type, _, sh_total) = parse_handshake_header(&sh_data)?;
        if hs_type != crate::handshake::HandshakeType::ServerHello {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ServerHello, got {hs_type:?}"
            )));
        }
        let sh_msg = &sh_data[..sh_total];

        let sh_actions = hs.process_server_hello(sh_msg)?;

        // Activate handshake encryption
        self.record_layer
            .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)?;
        self.record_layer
            .activate_write_encryption(sh_actions.suite, &sh_actions.client_hs_keys)?;

        // Step 3-6: Read encrypted handshake messages
        // Multiple messages may be packed in one record
        let mut hs_buffer: Vec<u8> = Vec::new();

        loop {
            // If we have data in the buffer, try to parse a handshake message
            while hs_buffer.len() >= 4 {
                let msg_len = ((hs_buffer[1] as usize) << 16)
                    | ((hs_buffer[2] as usize) << 8)
                    | (hs_buffer[3] as usize);
                let total = 4 + msg_len;
                if hs_buffer.len() < total {
                    break; // need more data
                }

                let msg_data = hs_buffer[..total].to_vec();
                hs_buffer.drain(..total);

                // Dispatch based on current state
                match hs.state() {
                    HandshakeState::WaitEncryptedExtensions => {
                        hs.process_encrypted_extensions(&msg_data)?;
                    }
                    HandshakeState::WaitCertCertReq => {
                        hs.process_certificate(&msg_data)?;
                    }
                    HandshakeState::WaitCertVerify => {
                        hs.process_certificate_verify(&msg_data)?;
                    }
                    HandshakeState::WaitFinished => {
                        let fin_actions = hs.process_finished(&msg_data)?;

                        // Send client Finished (encrypted with handshake keys)
                        let fin_record = self.record_layer.seal_record(
                            ContentType::Handshake,
                            &fin_actions.client_finished_msg,
                        )?;
                        self.stream
                            .write_all(&fin_record)
                            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

                        // Activate application keys
                        self.record_layer.activate_read_decryption(
                            fin_actions.suite,
                            &fin_actions.server_app_keys,
                        )?;
                        self.record_layer.activate_write_encryption(
                            fin_actions.suite,
                            &fin_actions.client_app_keys,
                        )?;

                        self.negotiated_suite = Some(fin_actions.suite);
                        self.negotiated_version = Some(TlsVersion::Tls13);
                        self.state = ConnectionState::Connected;
                        return Ok(());
                    }
                    _ => {
                        return Err(TlsError::HandshakeFailed(format!(
                            "unexpected state: {:?}",
                            hs.state()
                        )));
                    }
                }
            }

            // Read another encrypted record
            let (ct, plaintext) = self.read_record()?;
            match ct {
                ContentType::Handshake => {
                    hs_buffer.extend_from_slice(&plaintext);
                }
                ContentType::Alert => {
                    return Err(TlsError::HandshakeFailed(
                        "received alert during handshake".into(),
                    ));
                }
                _ => {
                    return Err(TlsError::HandshakeFailed(format!(
                        "unexpected content type during handshake: {ct:?}"
                    )));
                }
            }
        }
    }
}

impl<S: Read + Write> TlsConnection for TlsClientConnection<S> {
    fn handshake(&mut self) -> Result<(), TlsError> {
        if self.state != ConnectionState::Handshaking {
            return Err(TlsError::HandshakeFailed(
                "handshake already completed or failed".into(),
            ));
        }
        match self.do_handshake() {
            Ok(()) => Ok(()),
            Err(e) => {
                self.state = ConnectionState::Error;
                Err(e)
            }
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if self.state != ConnectionState::Connected {
            return Err(TlsError::RecordError(
                "not connected (handshake not done)".into(),
            ));
        }

        // Return buffered data first
        if !self.app_data_buf.is_empty() {
            let n = std::cmp::min(buf.len(), self.app_data_buf.len());
            buf[..n].copy_from_slice(&self.app_data_buf[..n]);
            self.app_data_buf.drain(..n);
            return Ok(n);
        }

        // Read a record
        let (ct, plaintext) = self.read_record()?;
        match ct {
            ContentType::ApplicationData => {
                let n = std::cmp::min(buf.len(), plaintext.len());
                buf[..n].copy_from_slice(&plaintext[..n]);
                if plaintext.len() > n {
                    self.app_data_buf.extend_from_slice(&plaintext[n..]);
                }
                Ok(n)
            }
            ContentType::Alert => {
                // close_notify or error
                self.state = ConnectionState::Closed;
                Ok(0)
            }
            _ => Err(TlsError::RecordError(format!(
                "unexpected content type: {ct:?}"
            ))),
        }
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        if self.state != ConnectionState::Connected {
            return Err(TlsError::RecordError(
                "not connected (handshake not done)".into(),
            ));
        }

        let record = self
            .record_layer
            .seal_record(ContentType::ApplicationData, buf)?;
        self.stream
            .write_all(&record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        Ok(buf.len())
    }

    fn shutdown(&mut self) -> Result<(), TlsError> {
        if self.state == ConnectionState::Closed {
            return Ok(());
        }

        // Send close_notify alert: [level=warning(1), description=close_notify(0)]
        let alert_data = [1u8, 0u8];
        let record = self
            .record_layer
            .seal_record(ContentType::Alert, &alert_data)?;
        let _ = self.stream.write_all(&record);
        self.state = ConnectionState::Closed;
        Ok(())
    }

    fn version(&self) -> Option<TlsVersion> {
        self.negotiated_version
    }

    fn cipher_suite(&self) -> Option<CipherSuite> {
        self.negotiated_suite
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_connection_creation() {
        let stream = Cursor::new(Vec::<u8>::new());
        let config = TlsConfig::builder().build();
        let conn = TlsClientConnection::new(stream, config);
        assert_eq!(conn.state, ConnectionState::Handshaking);
        assert!(conn.version().is_none());
        assert!(conn.cipher_suite().is_none());
    }
}
