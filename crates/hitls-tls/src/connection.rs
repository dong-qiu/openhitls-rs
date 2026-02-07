//! Synchronous TLS connection wrapping a `Read + Write` transport.

use std::io::{Read, Write};

use crate::config::TlsConfig;
use crate::handshake::client::ClientHandshake;
use crate::handshake::codec::parse_handshake_header;
use crate::handshake::server::ServerHandshake;
use crate::handshake::{HandshakeState, HandshakeType};
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

// ===========================================================================
// TLS Server Connection
// ===========================================================================

/// A synchronous TLS 1.3 server connection.
pub struct TlsServerConnection<S: Read + Write> {
    stream: S,
    config: TlsConfig,
    record_layer: RecordLayer,
    state: ConnectionState,
    negotiated_suite: Option<CipherSuite>,
    negotiated_version: Option<TlsVersion>,
    read_buf: Vec<u8>,
    app_data_buf: Vec<u8>,
}

impl<S: Read + Write> TlsServerConnection<S> {
    /// Create a new TLS server connection wrapping the given stream.
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
    fn read_record(&mut self) -> Result<(ContentType, Vec<u8>), TlsError> {
        self.fill_buf(5)?;
        let length = u16::from_be_bytes([self.read_buf[3], self.read_buf[4]]) as usize;
        self.fill_buf(5 + length)?;
        let (ct, plaintext, consumed) = self.record_layer.open_record(&self.read_buf)?;
        self.read_buf.drain(..consumed);
        Ok((ct, plaintext))
    }

    /// Run the TLS 1.3 server handshake.
    fn do_handshake(&mut self) -> Result<(), TlsError> {
        let mut hs = ServerHandshake::new(self.config.clone());

        // Step 1: Read ClientHello (plaintext record)
        let (ct, ch_data) = self.read_record()?;
        if ct != ContentType::Handshake {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Handshake, got {ct:?}"
            )));
        }

        let (hs_type, _, ch_total) = parse_handshake_header(&ch_data)?;
        if hs_type != HandshakeType::ClientHello {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ClientHello, got {hs_type:?}"
            )));
        }
        let ch_msg = &ch_data[..ch_total];

        // Step 2: Process ClientHello → get all server flight messages + keys
        let actions = hs.process_client_hello(ch_msg)?;

        // Step 3: Send ServerHello as plaintext record
        let sh_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &actions.server_hello_msg)?;
        self.stream
            .write_all(&sh_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Step 4: Activate handshake encryption
        self.record_layer
            .activate_write_encryption(actions.suite, &actions.server_hs_keys)?;
        self.record_layer
            .activate_read_decryption(actions.suite, &actions.client_hs_keys)?;

        // Step 5: Send EE, Certificate, CertificateVerify, Finished as encrypted records
        for msg in &[
            &actions.encrypted_extensions_msg,
            &actions.certificate_msg,
            &actions.certificate_verify_msg,
            &actions.server_finished_msg,
        ] {
            let record = self.record_layer.seal_record(ContentType::Handshake, msg)?;
            self.stream
                .write_all(&record)
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // Step 6: Read client Finished (encrypted)
        let (ct, fin_data) = self.read_record()?;
        if ct != ContentType::Handshake {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Handshake for client Finished, got {ct:?}"
            )));
        }

        let (hs_type, _, fin_total) = parse_handshake_header(&fin_data)?;
        if hs_type != HandshakeType::Finished {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Finished, got {hs_type:?}"
            )));
        }
        let fin_msg = &fin_data[..fin_total];

        // Step 7: Verify client Finished
        let _fin_actions = hs.process_client_finished(fin_msg)?;

        // Step 8: Activate application keys
        self.record_layer
            .activate_read_decryption(actions.suite, &actions.client_app_keys)?;
        self.record_layer
            .activate_write_encryption(actions.suite, &actions.server_app_keys)?;

        self.negotiated_suite = Some(actions.suite);
        self.negotiated_version = Some(TlsVersion::Tls13);
        self.state = ConnectionState::Connected;
        Ok(())
    }
}

impl<S: Read + Write> TlsConnection for TlsServerConnection<S> {
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

        if !self.app_data_buf.is_empty() {
            let n = std::cmp::min(buf.len(), self.app_data_buf.len());
            buf[..n].copy_from_slice(&self.app_data_buf[..n]);
            self.app_data_buf.drain(..n);
            return Ok(n);
        }

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

    /// Helper: generate Ed25519 server keypair and a minimal self-signed DER cert.
    /// Returns (seed, public_key_bytes, fake_der_cert).
    fn make_ed25519_server_identity() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let seed = vec![0x42; 32];
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(&seed).unwrap();
        let pub_key_bytes = kp.public_key().to_vec();
        // We use a fake DER cert since we'll disable peer verification.
        // In a real scenario, this would be a proper self-signed X.509 cert.
        let fake_cert = vec![0x30, 0x82, 0x01, 0x00];
        (seed, pub_key_bytes, fake_cert)
    }

    /// Run a full client-server handshake step by step using the state machines
    /// and record layers directly (no I/O transport needed).
    #[test]
    fn test_full_handshake_state_machine_roundtrip() {
        use crate::config::ServerPrivateKey;
        use crate::handshake::client::ClientHandshake;
        use crate::handshake::codec::parse_handshake_header;
        use crate::handshake::server::ServerHandshake;
        use crate::handshake::HandshakeState;
        use crate::record::{ContentType, RecordLayer};

        let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();

        let client_config = TlsConfig::builder()
            .server_name("test.example.com")
            .verify_peer(false) // disable cert chain validation for this test
            .build();

        let server_config = TlsConfig::builder()
            .role(crate::TlsRole::Server)
            .certificate_chain(vec![fake_cert])
            .private_key(ServerPrivateKey::Ed25519(seed))
            .verify_peer(false)
            .build();

        // --- Client builds ClientHello ---
        let mut client_hs = ClientHandshake::new(client_config);
        let mut client_rl = RecordLayer::new();
        let ch_msg = client_hs.build_client_hello().unwrap();
        assert_eq!(client_hs.state(), HandshakeState::WaitServerHello);
        let ch_record = client_rl
            .seal_record(ContentType::Handshake, &ch_msg)
            .unwrap();

        // --- Server receives ClientHello, produces flight ---
        let mut server_rl = RecordLayer::new();
        let (ct, ch_plaintext, _) = server_rl.open_record(&ch_record).unwrap();
        assert_eq!(ct, ContentType::Handshake);

        let (hs_type, _, ch_total) = parse_handshake_header(&ch_plaintext).unwrap();
        assert_eq!(hs_type, crate::handshake::HandshakeType::ClientHello);

        let mut server_hs = ServerHandshake::new(server_config);
        let actions = server_hs
            .process_client_hello(&ch_plaintext[..ch_total])
            .unwrap();
        assert_eq!(server_hs.state(), HandshakeState::WaitClientFinished);

        // --- Server sends ServerHello (plaintext) ---
        let sh_record = server_rl
            .seal_record(ContentType::Handshake, &actions.server_hello_msg)
            .unwrap();

        // Activate server HS encryption
        server_rl
            .activate_write_encryption(actions.suite, &actions.server_hs_keys)
            .unwrap();
        server_rl
            .activate_read_decryption(actions.suite, &actions.client_hs_keys)
            .unwrap();

        // Send encrypted flight: EE, Certificate, CertificateVerify, Finished
        let ee_record = server_rl
            .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
            .unwrap();
        let cert_record = server_rl
            .seal_record(ContentType::Handshake, &actions.certificate_msg)
            .unwrap();
        let cv_record = server_rl
            .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
            .unwrap();
        let sfin_record = server_rl
            .seal_record(ContentType::Handshake, &actions.server_finished_msg)
            .unwrap();

        // --- Client processes ServerHello ---
        let (ct, sh_plaintext, _) = client_rl.open_record(&sh_record).unwrap();
        assert_eq!(ct, ContentType::Handshake);
        let (_, _, sh_total) = parse_handshake_header(&sh_plaintext).unwrap();
        let sh_actions = client_hs
            .process_server_hello(&sh_plaintext[..sh_total])
            .unwrap();
        assert_eq!(client_hs.state(), HandshakeState::WaitEncryptedExtensions);

        // Activate client HS decryption/encryption
        client_rl
            .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)
            .unwrap();
        client_rl
            .activate_write_encryption(sh_actions.suite, &sh_actions.client_hs_keys)
            .unwrap();

        // --- Client processes encrypted flight ---
        // EE
        let (ct, ee_plain, _) = client_rl.open_record(&ee_record).unwrap();
        assert_eq!(ct, ContentType::Handshake);
        let (_, _, ee_total) = parse_handshake_header(&ee_plain).unwrap();
        client_hs
            .process_encrypted_extensions(&ee_plain[..ee_total])
            .unwrap();

        // Certificate
        let (ct, cert_plain, _) = client_rl.open_record(&cert_record).unwrap();
        assert_eq!(ct, ContentType::Handshake);
        let (_, _, cert_total) = parse_handshake_header(&cert_plain).unwrap();
        client_hs
            .process_certificate(&cert_plain[..cert_total])
            .unwrap();

        // CertificateVerify
        let (ct, cv_plain, _) = client_rl.open_record(&cv_record).unwrap();
        assert_eq!(ct, ContentType::Handshake);
        let (_, _, cv_total) = parse_handshake_header(&cv_plain).unwrap();
        client_hs
            .process_certificate_verify(&cv_plain[..cv_total])
            .unwrap();

        // Finished
        let (ct, fin_plain, _) = client_rl.open_record(&sfin_record).unwrap();
        assert_eq!(ct, ContentType::Handshake);
        let (_, _, fin_total) = parse_handshake_header(&fin_plain).unwrap();
        let fin_actions = client_hs.process_finished(&fin_plain[..fin_total]).unwrap();
        assert_eq!(client_hs.state(), HandshakeState::Connected);

        // --- Client sends client Finished ---
        let cfin_record = client_rl
            .seal_record(ContentType::Handshake, &fin_actions.client_finished_msg)
            .unwrap();

        // --- Server receives client Finished ---
        let (ct, cfin_plain, _) = server_rl.open_record(&cfin_record).unwrap();
        assert_eq!(ct, ContentType::Handshake);
        let (_, _, cfin_total) = parse_handshake_header(&cfin_plain).unwrap();
        let _cfin_actions = server_hs
            .process_client_finished(&cfin_plain[..cfin_total])
            .unwrap();
        assert_eq!(server_hs.state(), HandshakeState::Connected);

        // Both sides are connected!
        assert_eq!(fin_actions.suite, actions.suite);
    }

    /// Full handshake + bidirectional application data exchange.
    #[test]
    fn test_full_handshake_with_app_data() {
        use crate::config::ServerPrivateKey;
        use crate::handshake::client::ClientHandshake;
        use crate::handshake::codec::parse_handshake_header;
        use crate::handshake::server::ServerHandshake;
        use crate::record::{ContentType, RecordLayer};

        let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();

        let client_config = TlsConfig::builder().verify_peer(false).build();
        let server_config = TlsConfig::builder()
            .role(crate::TlsRole::Server)
            .certificate_chain(vec![fake_cert])
            .private_key(ServerPrivateKey::Ed25519(seed))
            .build();

        let mut client_hs = ClientHandshake::new(client_config);
        let mut client_rl = RecordLayer::new();
        let mut server_hs = ServerHandshake::new(server_config);
        let mut server_rl = RecordLayer::new();

        // --- Handshake (abbreviated, same flow as above) ---
        let ch_msg = client_hs.build_client_hello().unwrap();
        let ch_record = client_rl
            .seal_record(ContentType::Handshake, &ch_msg)
            .unwrap();

        let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
        let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
        let actions = server_hs
            .process_client_hello(&ch_data[..ch_total])
            .unwrap();

        let sh_record = server_rl
            .seal_record(ContentType::Handshake, &actions.server_hello_msg)
            .unwrap();
        server_rl
            .activate_write_encryption(actions.suite, &actions.server_hs_keys)
            .unwrap();
        server_rl
            .activate_read_decryption(actions.suite, &actions.client_hs_keys)
            .unwrap();

        let ee_rec = server_rl
            .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
            .unwrap();
        let cert_rec = server_rl
            .seal_record(ContentType::Handshake, &actions.certificate_msg)
            .unwrap();
        let cv_rec = server_rl
            .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
            .unwrap();
        let sfin_rec = server_rl
            .seal_record(ContentType::Handshake, &actions.server_finished_msg)
            .unwrap();

        // Client side
        let (_, sh_data, _) = client_rl.open_record(&sh_record).unwrap();
        let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
        let sh_actions = client_hs
            .process_server_hello(&sh_data[..sh_total])
            .unwrap();
        client_rl
            .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)
            .unwrap();
        client_rl
            .activate_write_encryption(sh_actions.suite, &sh_actions.client_hs_keys)
            .unwrap();

        for rec in [&ee_rec, &cert_rec, &cv_rec] {
            let (_, data, _) = client_rl.open_record(rec).unwrap();
            let (_, _, total) = parse_handshake_header(&data).unwrap();
            let msg = &data[..total];
            match client_hs.state() {
                crate::handshake::HandshakeState::WaitEncryptedExtensions => {
                    client_hs.process_encrypted_extensions(msg).unwrap();
                }
                crate::handshake::HandshakeState::WaitCertCertReq => {
                    client_hs.process_certificate(msg).unwrap();
                }
                crate::handshake::HandshakeState::WaitCertVerify => {
                    client_hs.process_certificate_verify(msg).unwrap();
                }
                s => panic!("unexpected state: {s:?}"),
            }
        }

        let (_, fin_data, _) = client_rl.open_record(&sfin_rec).unwrap();
        let (_, _, fin_total) = parse_handshake_header(&fin_data).unwrap();
        let fin_actions = client_hs.process_finished(&fin_data[..fin_total]).unwrap();

        let cfin_record = client_rl
            .seal_record(ContentType::Handshake, &fin_actions.client_finished_msg)
            .unwrap();

        let (_, cfin_data, _) = server_rl.open_record(&cfin_record).unwrap();
        let (_, _, cfin_total) = parse_handshake_header(&cfin_data).unwrap();
        server_hs
            .process_client_finished(&cfin_data[..cfin_total])
            .unwrap();

        // --- Activate application keys ---
        client_rl
            .activate_write_encryption(fin_actions.suite, &fin_actions.client_app_keys)
            .unwrap();
        client_rl
            .activate_read_decryption(fin_actions.suite, &fin_actions.server_app_keys)
            .unwrap();
        server_rl
            .activate_write_encryption(actions.suite, &actions.server_app_keys)
            .unwrap();
        server_rl
            .activate_read_decryption(actions.suite, &actions.client_app_keys)
            .unwrap();

        // --- Exchange application data ---
        // Client → Server
        let client_msg = b"Hello from client!";
        let c2s_record = client_rl
            .seal_record(ContentType::ApplicationData, client_msg)
            .unwrap();
        let (ct, c2s_plain, _) = server_rl.open_record(&c2s_record).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(&c2s_plain, client_msg);

        // Server → Client
        let server_msg = b"Hello from server!";
        let s2c_record = server_rl
            .seal_record(ContentType::ApplicationData, server_msg)
            .unwrap();
        let (ct, s2c_plain, _) = client_rl.open_record(&s2c_record).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(&s2c_plain, server_msg);
    }

    /// Test cipher suite negotiation: server picks first preference from its list.
    #[test]
    fn test_handshake_cipher_suite_negotiation() {
        use crate::config::ServerPrivateKey;
        use crate::handshake::client::ClientHandshake;
        use crate::handshake::codec::parse_handshake_header;
        use crate::handshake::server::ServerHandshake;
        use crate::record::{ContentType, RecordLayer};

        let (seed, _, fake_cert) = make_ed25519_server_identity();

        // Client offers AES_256_GCM first, AES_128_GCM second
        let client_config = TlsConfig::builder()
            .cipher_suites(&[
                CipherSuite::TLS_AES_256_GCM_SHA384,
                CipherSuite::TLS_AES_128_GCM_SHA256,
            ])
            .verify_peer(false)
            .build();

        // Server prefers AES_128_GCM first
        let server_config = TlsConfig::builder()
            .role(crate::TlsRole::Server)
            .cipher_suites(&[
                CipherSuite::TLS_AES_128_GCM_SHA256,
                CipherSuite::TLS_AES_256_GCM_SHA384,
            ])
            .certificate_chain(vec![fake_cert])
            .private_key(ServerPrivateKey::Ed25519(seed))
            .build();

        let mut client_hs = ClientHandshake::new(client_config);
        let mut client_rl = RecordLayer::new();
        let ch_msg = client_hs.build_client_hello().unwrap();
        let ch_record = client_rl
            .seal_record(ContentType::Handshake, &ch_msg)
            .unwrap();

        let mut server_rl = RecordLayer::new();
        let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
        let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();

        let mut server_hs = ServerHandshake::new(server_config);
        let actions = server_hs
            .process_client_hello(&ch_data[..ch_total])
            .unwrap();

        // Server should have selected AES_128_GCM (its first preference)
        assert_eq!(actions.suite, CipherSuite::TLS_AES_128_GCM_SHA256);
    }

    /// Test that handshake fails when there's no shared cipher suite.
    #[test]
    fn test_handshake_no_shared_cipher_suite() {
        use crate::config::ServerPrivateKey;
        use crate::handshake::client::ClientHandshake;
        use crate::handshake::codec::parse_handshake_header;
        use crate::handshake::server::ServerHandshake;
        use crate::record::{ContentType, RecordLayer};

        let (seed, _, fake_cert) = make_ed25519_server_identity();

        // Client only offers AES_256_GCM
        let client_config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_AES_256_GCM_SHA384])
            .verify_peer(false)
            .build();

        // Server only offers ChaCha20
        let server_config = TlsConfig::builder()
            .role(crate::TlsRole::Server)
            .cipher_suites(&[CipherSuite::TLS_CHACHA20_POLY1305_SHA256])
            .certificate_chain(vec![fake_cert])
            .private_key(ServerPrivateKey::Ed25519(seed))
            .build();

        let mut client_hs = ClientHandshake::new(client_config);
        let mut client_rl = RecordLayer::new();
        let ch_msg = client_hs.build_client_hello().unwrap();
        let ch_record = client_rl
            .seal_record(ContentType::Handshake, &ch_msg)
            .unwrap();

        let mut server_rl = RecordLayer::new();
        let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
        let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();

        let mut server_hs = ServerHandshake::new(server_config);
        let result = server_hs.process_client_hello(&ch_data[..ch_total]);
        assert!(result.is_err());
    }

    #[test]
    fn test_server_connection_creation() {
        let stream = Cursor::new(Vec::<u8>::new());
        let config = TlsConfig::builder().role(crate::TlsRole::Server).build();
        let conn = TlsServerConnection::new(stream, config);
        assert_eq!(conn.state, ConnectionState::Handshaking);
        assert!(conn.version().is_none());
        assert!(conn.cipher_suite().is_none());
    }
}
