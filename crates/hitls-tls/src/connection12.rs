//! Synchronous TLS 1.2 connection wrapping a `Read + Write` transport.
//!
//! Provides `Tls12ClientConnection` and `Tls12ServerConnection` implementing
//! the `TlsConnection` trait for TLS 1.2 ECDHE-GCM cipher suites.

use std::io::{Read, Write};

use crate::config::TlsConfig;
use crate::handshake::client12::Tls12ClientHandshake;
use crate::handshake::codec::{decode_server_hello, parse_handshake_header};
use crate::handshake::codec12::{
    decode_certificate12, decode_certificate_request12, decode_server_key_exchange,
};
use crate::handshake::server12::{ServerHelloResult, Tls12ServerHandshake};
use crate::handshake::HandshakeType;
use crate::record::{ContentType, RecordLayer};
use crate::session::TlsSession;
use crate::{CipherSuite, TlsConnection, TlsError, TlsVersion};
use zeroize::Zeroize;

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    Handshaking,
    Connected,
    Closed,
    Error,
}

// ===========================================================================
// TLS 1.2 Client Connection
// ===========================================================================

/// A synchronous TLS 1.2 client connection.
pub struct Tls12ClientConnection<S: Read + Write> {
    stream: S,
    config: TlsConfig,
    record_layer: RecordLayer,
    state: ConnectionState,
    negotiated_suite: Option<CipherSuite>,
    /// Buffer for reading records from the stream.
    read_buf: Vec<u8>,
    /// Buffered decrypted application data.
    app_data_buf: Vec<u8>,
    /// Session state for resumption (populated after handshake).
    session: Option<TlsSession>,
}

impl<S: Read + Write> Tls12ClientConnection<S> {
    /// Create a new TLS 1.2 client connection wrapping the given stream.
    pub fn new(stream: S, config: TlsConfig) -> Self {
        Self {
            stream,
            config,
            record_layer: RecordLayer::new(),
            state: ConnectionState::Handshaking,
            negotiated_suite: None,
            read_buf: Vec::with_capacity(16 * 1024),
            app_data_buf: Vec::new(),
            session: None,
        }
    }

    /// Take the session state (with ticket if applicable) for later resumption.
    pub fn take_session(&mut self) -> Option<TlsSession> {
        self.session.take()
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

    /// Read a handshake message from the stream.
    /// Returns (handshake_type, full_message_bytes_including_header).
    fn read_handshake_msg(&mut self) -> Result<(HandshakeType, Vec<u8>), TlsError> {
        let (ct, data) = self.read_record()?;
        if ct != ContentType::Handshake {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Handshake, got {ct:?}"
            )));
        }
        let (hs_type, _, total) = parse_handshake_header(&data)?;
        Ok((hs_type, data[..total].to_vec()))
    }

    /// Run the TLS 1.2 client handshake.
    fn do_handshake(&mut self) -> Result<(), TlsError> {
        let mut hs = Tls12ClientHandshake::new(self.config.clone());

        // 1. Build and send ClientHello
        let ch_msg = hs.build_client_hello()?;
        let ch_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &ch_msg)?;
        self.stream
            .write_all(&ch_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 2. Read ServerHello
        let (hs_type, sh_data) = self.read_handshake_msg()?;
        if hs_type != HandshakeType::ServerHello {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ServerHello, got {hs_type:?}"
            )));
        }
        let (_, sh_body, _) = parse_handshake_header(&sh_data)?;
        let sh = decode_server_hello(sh_body)?;
        let suite = hs.process_server_hello(&sh_data, &sh)?;

        // Check for abbreviated handshake (session resumption)
        if hs.is_abbreviated() {
            return self.do_client_abbreviated(&mut hs, suite);
        }

        // 3. Read Certificate
        let (hs_type, cert_data) = self.read_handshake_msg()?;
        if hs_type != HandshakeType::Certificate {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Certificate, got {hs_type:?}"
            )));
        }
        let (_, cert_body, _) = parse_handshake_header(&cert_data)?;
        let cert12 = decode_certificate12(cert_body)?;
        hs.process_certificate(&cert_data, &cert12.certificate_list)?;

        // 4. Read ServerKeyExchange
        let (hs_type, ske_data) = self.read_handshake_msg()?;
        if hs_type != HandshakeType::ServerKeyExchange {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ServerKeyExchange, got {hs_type:?}"
            )));
        }
        let (_, ske_body, _) = parse_handshake_header(&ske_data)?;
        let ske = decode_server_key_exchange(ske_body)?;
        hs.process_server_key_exchange(&ske_data, &ske)?;

        // 5. Read CertificateRequest (optional) or ServerHelloDone
        let (hs_type, next_data) = self.read_handshake_msg()?;
        let shd_data = if hs_type == HandshakeType::CertificateRequest {
            let (_, cr_body, _) = parse_handshake_header(&next_data)?;
            let cr = decode_certificate_request12(cr_body)?;
            hs.process_certificate_request(&next_data, &cr)?;
            // Now read the actual ServerHelloDone
            let (hs_type, shd_data) = self.read_handshake_msg()?;
            if hs_type != HandshakeType::ServerHelloDone {
                return Err(TlsError::HandshakeFailed(format!(
                    "expected ServerHelloDone, got {hs_type:?}"
                )));
            }
            shd_data
        } else if hs_type == HandshakeType::ServerHelloDone {
            next_data
        } else {
            return Err(TlsError::HandshakeFailed(format!(
                "expected CertificateRequest or ServerHelloDone, got {hs_type:?}"
            )));
        };

        // 6. Process ServerHelloDone → generates client flight
        let mut flight = hs.process_server_hello_done(&shd_data)?;

        // 7. Send client Certificate (if mTLS requested)
        if let Some(ref cert_msg) = flight.client_certificate {
            let cert_record = self
                .record_layer
                .seal_record(ContentType::Handshake, cert_msg)?;
            self.stream
                .write_all(&cert_record)
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // 8. Send ClientKeyExchange (plaintext)
        let cke_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &flight.client_key_exchange)?;
        self.stream
            .write_all(&cke_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 9. Send CertificateVerify (if mTLS with client cert)
        if let Some(ref cv_msg) = flight.certificate_verify {
            let cv_record = self
                .record_layer
                .seal_record(ContentType::Handshake, cv_msg)?;
            self.stream
                .write_all(&cv_record)
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // 10. Send ChangeCipherSpec
        let ccs_record = self
            .record_layer
            .seal_record(ContentType::ChangeCipherSpec, &[0x01])?;
        self.stream
            .write_all(&ccs_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 9. Activate write encryption
        if flight.is_cbc {
            self.record_layer.activate_write_encryption12_cbc(
                flight.client_write_key.clone(),
                flight.client_write_mac_key.clone(),
                flight.mac_len,
            );
        } else {
            self.record_layer.activate_write_encryption12(
                suite,
                &flight.client_write_key,
                flight.client_write_iv.clone(),
            )?;
        }

        // 10. Send Finished (encrypted)
        let fin_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &flight.finished)?;
        self.stream
            .write_all(&fin_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 11. Read NewSessionTicket (optional) then server ChangeCipherSpec
        loop {
            let (ct, data) = self.read_record()?;
            match ct {
                ContentType::Handshake => {
                    // May be a NewSessionTicket (plaintext, before CCS)
                    let (hs_type, _, total) = parse_handshake_header(&data)?;
                    if hs_type == HandshakeType::NewSessionTicket {
                        let body = &data[4..total];
                        hs.process_new_session_ticket(body)?;
                    } else {
                        return Err(TlsError::HandshakeFailed(format!(
                            "expected NewSessionTicket or CCS, got {hs_type:?}"
                        )));
                    }
                }
                ContentType::ChangeCipherSpec => {
                    hs.process_change_cipher_spec()?;
                    break;
                }
                _ => {
                    return Err(TlsError::HandshakeFailed(format!(
                        "expected ChangeCipherSpec, got {ct:?}"
                    )));
                }
            }
        }

        // 12. Activate read decryption
        if flight.is_cbc {
            self.record_layer.activate_read_decryption12_cbc(
                flight.server_write_key.clone(),
                flight.server_write_mac_key.clone(),
                flight.mac_len,
            );
        } else {
            self.record_layer.activate_read_decryption12(
                suite,
                &flight.server_write_key,
                flight.server_write_iv.clone(),
            )?;
        }

        // 13. Read server Finished (encrypted)
        let (hs_type, fin_data) = self.read_handshake_msg()?;
        if hs_type != HandshakeType::Finished {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Finished, got {hs_type:?}"
            )));
        }
        hs.process_finished(&fin_data, &flight.master_secret)?;

        // Build session state for later resumption
        self.session = Some(TlsSession {
            id: Vec::new(),
            cipher_suite: suite,
            master_secret: flight.master_secret.clone(),
            alpn_protocol: None,
            ticket: hs.received_ticket().map(|t| t.to_vec()),
            ticket_lifetime: hs.received_ticket_lifetime(),
            max_early_data: 0,
            ticket_age_add: 0,
            ticket_nonce: Vec::new(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            psk: Vec::new(),
        });

        // Zeroize secrets
        flight.master_secret.zeroize();
        flight.client_write_key.zeroize();
        flight.server_write_key.zeroize();

        self.negotiated_suite = Some(suite);
        self.state = ConnectionState::Connected;
        Ok(())
    }

    /// Abbreviated handshake path (client side, session resumption via ticket or ID).
    fn do_client_abbreviated(
        &mut self,
        hs: &mut Tls12ClientHandshake,
        suite: CipherSuite,
    ) -> Result<(), TlsError> {
        let mut keys = hs
            .take_abbreviated_keys()
            .ok_or_else(|| TlsError::HandshakeFailed("no abbreviated keys".into()))?;

        // 1. Read optional NewSessionTicket then CCS from server
        loop {
            let (ct, data) = self.read_record()?;
            match ct {
                ContentType::Handshake => {
                    let (hs_type, _, total) = parse_handshake_header(&data)?;
                    if hs_type == HandshakeType::NewSessionTicket {
                        let body = &data[4..total];
                        hs.process_new_session_ticket(body)?;
                    } else {
                        return Err(TlsError::HandshakeFailed(format!(
                            "expected NewSessionTicket or CCS, got {hs_type:?}"
                        )));
                    }
                }
                ContentType::ChangeCipherSpec => {
                    hs.process_change_cipher_spec()?;
                    break;
                }
                _ => {
                    return Err(TlsError::HandshakeFailed(format!(
                        "expected CCS, got {ct:?}"
                    )));
                }
            }
        }

        // 2. Activate read decryption (server write key)
        if keys.is_cbc {
            self.record_layer.activate_read_decryption12_cbc(
                keys.server_write_key.clone(),
                keys.server_write_mac_key.clone(),
                keys.mac_len,
            );
        } else {
            self.record_layer.activate_read_decryption12(
                suite,
                &keys.server_write_key,
                keys.server_write_iv.clone(),
            )?;
        }

        // 3. Read server Finished (encrypted)
        let (hs_type, fin_data) = self.read_handshake_msg()?;
        if hs_type != HandshakeType::Finished {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Finished, got {hs_type:?}"
            )));
        }
        let client_finished = hs.process_abbreviated_server_finished(&fin_data)?;

        // 4. Send CCS
        let ccs_record = self
            .record_layer
            .seal_record(ContentType::ChangeCipherSpec, &[0x01])?;
        self.stream
            .write_all(&ccs_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 5. Activate write encryption (client write key)
        if keys.is_cbc {
            self.record_layer.activate_write_encryption12_cbc(
                keys.client_write_key.clone(),
                keys.client_write_mac_key.clone(),
                keys.mac_len,
            );
        } else {
            self.record_layer.activate_write_encryption12(
                suite,
                &keys.client_write_key,
                keys.client_write_iv.clone(),
            )?;
        }

        // 6. Send client Finished (encrypted)
        let fin_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &client_finished)?;
        self.stream
            .write_all(&fin_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Build session state for later resumption
        self.session = Some(TlsSession {
            id: Vec::new(),
            cipher_suite: suite,
            master_secret: keys.master_secret.clone(),
            alpn_protocol: None,
            ticket: hs.received_ticket().map(|t| t.to_vec()),
            ticket_lifetime: hs.received_ticket_lifetime(),
            max_early_data: 0,
            ticket_age_add: 0,
            ticket_nonce: Vec::new(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            psk: Vec::new(),
        });

        // Zeroize secrets
        keys.master_secret.zeroize();
        keys.client_write_key.zeroize();
        keys.server_write_key.zeroize();

        self.negotiated_suite = Some(suite);
        self.state = ConnectionState::Connected;
        Ok(())
    }
}

impl<S: Read + Write> TlsConnection for Tls12ClientConnection<S> {
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
        let alert_data = [1u8, 0u8]; // close_notify
        let record = self
            .record_layer
            .seal_record(ContentType::Alert, &alert_data)?;
        let _ = self.stream.write_all(&record);
        self.state = ConnectionState::Closed;
        Ok(())
    }

    fn version(&self) -> Option<TlsVersion> {
        if self.state == ConnectionState::Connected {
            Some(TlsVersion::Tls12)
        } else {
            None
        }
    }

    fn cipher_suite(&self) -> Option<CipherSuite> {
        self.negotiated_suite
    }
}

// ===========================================================================
// TLS 1.2 Server Connection
// ===========================================================================

/// A synchronous TLS 1.2 server connection.
pub struct Tls12ServerConnection<S: Read + Write> {
    stream: S,
    config: TlsConfig,
    record_layer: RecordLayer,
    state: ConnectionState,
    negotiated_suite: Option<CipherSuite>,
    /// Buffer for reading records from the stream.
    read_buf: Vec<u8>,
    /// Buffered decrypted application data.
    app_data_buf: Vec<u8>,
    /// Session state for session ticket issuance.
    session: Option<TlsSession>,
}

impl<S: Read + Write> Tls12ServerConnection<S> {
    /// Create a new TLS 1.2 server connection wrapping the given stream.
    pub fn new(stream: S, config: TlsConfig) -> Self {
        Self {
            stream,
            config,
            record_layer: RecordLayer::new(),
            state: ConnectionState::Handshaking,
            negotiated_suite: None,
            read_buf: Vec::with_capacity(16 * 1024),
            app_data_buf: Vec::new(),
            session: None,
        }
    }

    /// Take the session state (for session caching on server side).
    pub fn take_session(&mut self) -> Option<TlsSession> {
        self.session.take()
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

    /// Read a handshake message from the stream.
    fn read_handshake_msg(&mut self) -> Result<(HandshakeType, Vec<u8>), TlsError> {
        let (ct, data) = self.read_record()?;
        if ct != ContentType::Handshake {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Handshake, got {ct:?}"
            )));
        }
        let (hs_type, _, total) = parse_handshake_header(&data)?;
        Ok((hs_type, data[..total].to_vec()))
    }

    /// Run the TLS 1.2 server handshake.
    fn do_handshake(&mut self) -> Result<(), TlsError> {
        let mut hs = Tls12ServerHandshake::new(self.config.clone());

        // 1. Read ClientHello
        let (hs_type, ch_data) = self.read_handshake_msg()?;
        if hs_type != HandshakeType::ClientHello {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ClientHello, got {hs_type:?}"
            )));
        }

        // 2. Process ClientHello (with ticket support, no session ID cache)
        let result = hs.process_client_hello_resumable(&ch_data, None)?;

        match result {
            ServerHelloResult::Full(flight) => {
                self.do_full_handshake(&mut hs, flight)?;
            }
            ServerHelloResult::Abbreviated(abbr) => {
                self.do_abbreviated_handshake(&mut hs, abbr)?;
            }
        }

        Ok(())
    }

    /// Full handshake path (with optional NewSessionTicket).
    fn do_full_handshake(
        &mut self,
        hs: &mut Tls12ServerHandshake,
        flight: crate::handshake::server12::ServerFlightResult,
    ) -> Result<(), TlsError> {
        let suite = flight.suite;

        // 3. Send ServerHello
        let sh_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &flight.server_hello)?;
        self.stream
            .write_all(&sh_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 4. Send Certificate
        let cert_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &flight.certificate)?;
        self.stream
            .write_all(&cert_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 5. Send ServerKeyExchange
        let ske_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &flight.server_key_exchange)?;
        self.stream
            .write_all(&ske_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 6. Send CertificateRequest (if mTLS enabled)
        if let Some(ref cr_msg) = flight.certificate_request {
            let cr_record = self
                .record_layer
                .seal_record(ContentType::Handshake, cr_msg)?;
            self.stream
                .write_all(&cr_record)
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // 7. Send ServerHelloDone
        let shd_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &flight.server_hello_done)?;
        self.stream
            .write_all(&shd_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 8. Read client Certificate (if mTLS)
        if flight.certificate_request.is_some() {
            let (hs_type, cert_data) = self.read_handshake_msg()?;
            if hs_type != HandshakeType::Certificate {
                return Err(TlsError::HandshakeFailed(format!(
                    "expected client Certificate, got {hs_type:?}"
                )));
            }
            hs.process_client_certificate(&cert_data)?;
        }

        // 9. Read ClientKeyExchange
        let (hs_type, cke_data) = self.read_handshake_msg()?;
        if hs_type != HandshakeType::ClientKeyExchange {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ClientKeyExchange, got {hs_type:?}"
            )));
        }
        let mut keys = hs.process_client_key_exchange(&cke_data)?;

        // 10. Read client CertificateVerify (if client sent certs)
        if hs.state() == crate::handshake::server12::Tls12ServerState::WaitClientCertificateVerify {
            let (hs_type, cv_data) = self.read_handshake_msg()?;
            if hs_type != HandshakeType::CertificateVerify {
                return Err(TlsError::HandshakeFailed(format!(
                    "expected CertificateVerify, got {hs_type:?}"
                )));
            }
            hs.process_client_certificate_verify(&cv_data)?;
        }

        // 11. Read ChangeCipherSpec from client
        let (ct, _ccs_data) = self.read_record()?;
        if ct != ContentType::ChangeCipherSpec {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ChangeCipherSpec, got {ct:?}"
            )));
        }
        hs.process_change_cipher_spec()?;

        // 12. Activate read decryption (client write key)
        if keys.is_cbc {
            self.record_layer.activate_read_decryption12_cbc(
                keys.client_write_key.clone(),
                keys.client_write_mac_key.clone(),
                keys.mac_len,
            );
        } else {
            self.record_layer.activate_read_decryption12(
                suite,
                &keys.client_write_key,
                keys.client_write_iv.clone(),
            )?;
        }

        // 13. Read client Finished (encrypted)
        let (hs_type, fin_data) = self.read_handshake_msg()?;
        if hs_type != HandshakeType::Finished {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Finished, got {hs_type:?}"
            )));
        }
        let server_fin = hs.process_finished(&fin_data)?;

        // 14. Send NewSessionTicket (plaintext, before CCS) if ticket_key configured
        if let Some(nst_msg) = hs.build_new_session_ticket(suite, 3600)? {
            let nst_record = self
                .record_layer
                .seal_record(ContentType::Handshake, &nst_msg)?;
            self.stream
                .write_all(&nst_record)
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // 15. Send ChangeCipherSpec
        let ccs_record = self
            .record_layer
            .seal_record(ContentType::ChangeCipherSpec, &[0x01])?;
        self.stream
            .write_all(&ccs_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 16. Activate write encryption (server write key)
        if keys.is_cbc {
            self.record_layer.activate_write_encryption12_cbc(
                keys.server_write_key.clone(),
                keys.server_write_mac_key.clone(),
                keys.mac_len,
            );
        } else {
            self.record_layer.activate_write_encryption12(
                suite,
                &keys.server_write_key,
                keys.server_write_iv.clone(),
            )?;
        }

        // 17. Send server Finished (encrypted)
        let sfin_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &server_fin.finished)?;
        self.stream
            .write_all(&sfin_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Zeroize secrets
        keys.master_secret.zeroize();
        keys.client_write_key.zeroize();
        keys.server_write_key.zeroize();

        self.negotiated_suite = Some(suite);
        self.state = ConnectionState::Connected;
        Ok(())
    }

    /// Abbreviated handshake path (session ticket or session ID resumption).
    fn do_abbreviated_handshake(
        &mut self,
        hs: &mut Tls12ServerHandshake,
        mut abbr: crate::handshake::server12::AbbreviatedServerResult,
    ) -> Result<(), TlsError> {
        let suite = abbr.suite;

        // 1. Send ServerHello (echoes session_id)
        let sh_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &abbr.server_hello)?;
        self.stream
            .write_all(&sh_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 2. Send NewSessionTicket (plaintext) if ticket_key configured
        if let Some(nst_msg) = hs.build_new_session_ticket(suite, 3600)? {
            let nst_record = self
                .record_layer
                .seal_record(ContentType::Handshake, &nst_msg)?;
            self.stream
                .write_all(&nst_record)
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // 3. Send CCS
        let ccs_record = self
            .record_layer
            .seal_record(ContentType::ChangeCipherSpec, &[0x01])?;
        self.stream
            .write_all(&ccs_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 4. Activate write encryption (server write key)
        if abbr.is_cbc {
            self.record_layer.activate_write_encryption12_cbc(
                abbr.server_write_key.clone(),
                abbr.server_write_mac_key.clone(),
                abbr.mac_len,
            );
        } else {
            self.record_layer.activate_write_encryption12(
                suite,
                &abbr.server_write_key,
                abbr.server_write_iv.clone(),
            )?;
        }

        // 5. Send server Finished (encrypted)
        let sfin_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &abbr.finished)?;
        self.stream
            .write_all(&sfin_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 6. Read client CCS
        let (ct, _ccs_data) = self.read_record()?;
        if ct != ContentType::ChangeCipherSpec {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ChangeCipherSpec, got {ct:?}"
            )));
        }
        hs.process_change_cipher_spec()?;

        // 7. Activate read decryption (client write key)
        if abbr.is_cbc {
            self.record_layer.activate_read_decryption12_cbc(
                abbr.client_write_key.clone(),
                abbr.client_write_mac_key.clone(),
                abbr.mac_len,
            );
        } else {
            self.record_layer.activate_read_decryption12(
                suite,
                &abbr.client_write_key,
                abbr.client_write_iv.clone(),
            )?;
        }

        // 8. Read client Finished (encrypted)
        let (hs_type, fin_data) = self.read_handshake_msg()?;
        if hs_type != HandshakeType::Finished {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Finished, got {hs_type:?}"
            )));
        }
        hs.process_abbreviated_finished(&fin_data)?;

        // Zeroize secrets
        abbr.master_secret.zeroize();
        abbr.client_write_key.zeroize();
        abbr.server_write_key.zeroize();

        self.negotiated_suite = Some(suite);
        self.state = ConnectionState::Connected;
        Ok(())
    }
}

impl<S: Read + Write> TlsConnection for Tls12ServerConnection<S> {
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
        let alert_data = [1u8, 0u8]; // close_notify
        let record = self
            .record_layer
            .seal_record(ContentType::Alert, &alert_data)?;
        let _ = self.stream.write_all(&record);
        self.state = ConnectionState::Closed;
        Ok(())
    }

    fn version(&self) -> Option<TlsVersion> {
        if self.state == ConnectionState::Connected {
            Some(TlsVersion::Tls12)
        } else {
            None
        }
    }

    fn cipher_suite(&self) -> Option<CipherSuite> {
        self.negotiated_suite
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerPrivateKey;
    use crate::crypt::NamedGroup;
    use crate::crypt::SignatureScheme;
    use crate::handshake::client12::Tls12ClientState;
    use crate::handshake::server12::{ServerHelloResult, Tls12ServerState};
    use crate::session::{InMemorySessionCache, SessionCache, TlsSession};
    use std::io::Cursor;

    #[test]
    fn test_tls12_client_connection_creation() {
        let stream = Cursor::new(Vec::<u8>::new());
        let config = TlsConfig::builder().build();
        let conn = Tls12ClientConnection::new(stream, config);
        assert_eq!(conn.state, ConnectionState::Handshaking);
        assert!(conn.version().is_none());
        assert!(conn.cipher_suite().is_none());
    }

    #[test]
    fn test_tls12_server_connection_creation() {
        let stream = Cursor::new(Vec::<u8>::new());
        let config = TlsConfig::builder().build();
        let conn = Tls12ServerConnection::new(stream, config);
        assert_eq!(conn.state, ConnectionState::Handshaking);
        assert!(conn.version().is_none());
        assert!(conn.cipher_suite().is_none());
    }

    /// In-process full TLS 1.2 handshake using a pipe-like transport.
    /// Uses ECDSA P-256 + SECP256R1 key exchange + AES-128-GCM.
    #[test]
    fn test_tls12_connection_full_handshake() {
        // Create ECDSA P-256 key pair for the server
        let ecdsa_private = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let fake_cert = vec![0x30, 0x82, 0x01, 0x00];

        let client_config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                SignatureScheme::RSA_PSS_RSAE_SHA256,
            ])
            .verify_peer(false)
            .build();

        let server_config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .certificate_chain(vec![fake_cert])
            .private_key(ServerPrivateKey::Ecdsa {
                curve_id: hitls_types::EccCurveId::NistP256,
                private_key: ecdsa_private,
            })
            .verify_peer(false)
            .build();

        // Use a shared byte buffer as in-process transport.
        // Client writes → server reads, server writes → client reads.
        // We'll drive this step by step using intermediate buffers.
        let mut client_to_server = Vec::new();
        let mut server_to_client = Vec::new();

        // --- Client side ---
        let mut client_hs = Tls12ClientHandshake::new(client_config);
        let mut client_rl = RecordLayer::new();

        // --- Server side ---
        let mut server_hs = Tls12ServerHandshake::new(server_config);
        let mut server_rl = RecordLayer::new();

        // 1. Client → ClientHello
        let ch_msg = client_hs.build_client_hello().unwrap();
        let ch_record = client_rl
            .seal_record(ContentType::Handshake, &ch_msg)
            .unwrap();
        client_to_server.extend_from_slice(&ch_record);

        // 2. Server processes ClientHello
        let (ct, ch_plain, consumed) = server_rl.open_record(&client_to_server).unwrap();
        client_to_server.drain(..consumed);
        assert_eq!(ct, ContentType::Handshake);
        let (_, _, ch_total) = parse_handshake_header(&ch_plain).unwrap();
        let flight = server_hs
            .process_client_hello(&ch_plain[..ch_total])
            .unwrap();
        let suite = flight.suite;

        // 3. Server → ServerHello + Certificate + SKE + SHD
        for msg in [
            &flight.server_hello,
            &flight.certificate,
            &flight.server_key_exchange,
            &flight.server_hello_done,
        ] {
            let rec = server_rl.seal_record(ContentType::Handshake, msg).unwrap();
            server_to_client.extend_from_slice(&rec);
        }

        // 4. Client processes server flight
        // ServerHello
        let (ct, sh_plain, consumed) = client_rl.open_record(&server_to_client).unwrap();
        server_to_client.drain(..consumed);
        assert_eq!(ct, ContentType::Handshake);
        let (_, sh_body, sh_total) = parse_handshake_header(&sh_plain).unwrap();
        let sh = decode_server_hello(sh_body).unwrap();
        client_hs
            .process_server_hello(&sh_plain[..sh_total], &sh)
            .unwrap();

        // Certificate
        let (ct, cert_plain, consumed) = client_rl.open_record(&server_to_client).unwrap();
        server_to_client.drain(..consumed);
        assert_eq!(ct, ContentType::Handshake);
        let (_, cert_body, cert_total) = parse_handshake_header(&cert_plain).unwrap();
        let cert12 = decode_certificate12(cert_body).unwrap();
        client_hs
            .process_certificate(&cert_plain[..cert_total], &cert12.certificate_list)
            .unwrap();

        // ServerKeyExchange
        let (ct, ske_plain, consumed) = client_rl.open_record(&server_to_client).unwrap();
        server_to_client.drain(..consumed);
        assert_eq!(ct, ContentType::Handshake);
        let (_, ske_body, ske_total) = parse_handshake_header(&ske_plain).unwrap();
        let ske = decode_server_key_exchange(ske_body).unwrap();
        client_hs
            .process_server_key_exchange(&ske_plain[..ske_total], &ske)
            .unwrap();

        // ServerHelloDone
        let (ct, shd_plain, consumed) = client_rl.open_record(&server_to_client).unwrap();
        server_to_client.drain(..consumed);
        assert_eq!(ct, ContentType::Handshake);
        let (_, _, shd_total) = parse_handshake_header(&shd_plain).unwrap();

        // 5. Client produces flight
        let mut cflight = client_hs
            .process_server_hello_done(&shd_plain[..shd_total])
            .unwrap();

        // 6. Client → CKE + CCS + Finished
        let cke_record = client_rl
            .seal_record(ContentType::Handshake, &cflight.client_key_exchange)
            .unwrap();
        client_to_server.extend_from_slice(&cke_record);

        let ccs_record = client_rl
            .seal_record(ContentType::ChangeCipherSpec, &[0x01])
            .unwrap();
        client_to_server.extend_from_slice(&ccs_record);

        // Activate client write encryption
        client_rl
            .activate_write_encryption12(
                suite,
                &cflight.client_write_key,
                cflight.client_write_iv.clone(),
            )
            .unwrap();

        let fin_record = client_rl
            .seal_record(ContentType::Handshake, &cflight.finished)
            .unwrap();
        client_to_server.extend_from_slice(&fin_record);

        // 7. Server processes CKE
        let (ct, cke_plain, consumed) = server_rl.open_record(&client_to_server).unwrap();
        client_to_server.drain(..consumed);
        assert_eq!(ct, ContentType::Handshake);
        let (_, _, cke_total) = parse_handshake_header(&cke_plain).unwrap();
        let mut keys = server_hs
            .process_client_key_exchange(&cke_plain[..cke_total])
            .unwrap();

        // 8. Server processes CCS
        let (ct, _, consumed) = server_rl.open_record(&client_to_server).unwrap();
        client_to_server.drain(..consumed);
        assert_eq!(ct, ContentType::ChangeCipherSpec);
        server_hs.process_change_cipher_spec().unwrap();

        // 9. Activate server read decryption
        server_rl
            .activate_read_decryption12(suite, &keys.client_write_key, keys.client_write_iv.clone())
            .unwrap();

        // 10. Server processes client Finished
        let (ct, fin_plain, consumed) = server_rl.open_record(&client_to_server).unwrap();
        client_to_server.drain(..consumed);
        assert_eq!(ct, ContentType::Handshake);
        let (_, _, fin_total) = parse_handshake_header(&fin_plain).unwrap();
        let server_fin = server_hs.process_finished(&fin_plain[..fin_total]).unwrap();

        // 11. Server → CCS + Finished
        let ccs_record = server_rl
            .seal_record(ContentType::ChangeCipherSpec, &[0x01])
            .unwrap();
        server_to_client.extend_from_slice(&ccs_record);

        server_rl
            .activate_write_encryption12(
                suite,
                &keys.server_write_key,
                keys.server_write_iv.clone(),
            )
            .unwrap();

        let sfin_record = server_rl
            .seal_record(ContentType::Handshake, &server_fin.finished)
            .unwrap();
        server_to_client.extend_from_slice(&sfin_record);

        // 12. Client processes server CCS
        let (ct, _, consumed) = client_rl.open_record(&server_to_client).unwrap();
        server_to_client.drain(..consumed);
        assert_eq!(ct, ContentType::ChangeCipherSpec);
        client_hs.process_change_cipher_spec().unwrap();

        // Activate client read decryption
        client_rl
            .activate_read_decryption12(
                suite,
                &cflight.server_write_key,
                cflight.server_write_iv.clone(),
            )
            .unwrap();

        // 13. Client processes server Finished
        let (ct, sfin_plain, consumed) = client_rl.open_record(&server_to_client).unwrap();
        server_to_client.drain(..consumed);
        assert_eq!(ct, ContentType::Handshake);
        let (_, _, sfin_total) = parse_handshake_header(&sfin_plain).unwrap();
        client_hs
            .process_finished(&sfin_plain[..sfin_total], &cflight.master_secret)
            .unwrap();

        // Both should be connected
        assert_eq!(client_hs.state(), Tls12ClientState::Connected);
        assert_eq!(server_hs.state(), Tls12ServerState::Connected);

        // 14. Exchange application data
        let app_msg = b"Hello from client over TLS 1.2!";
        let app_record = client_rl
            .seal_record(ContentType::ApplicationData, app_msg)
            .unwrap();

        let (ct, app_plain, _) = server_rl.open_record(&app_record).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(app_plain, app_msg);

        let reply = b"Hello from server over TLS 1.2!";
        let reply_record = server_rl
            .seal_record(ContentType::ApplicationData, reply)
            .unwrap();

        let (ct, reply_plain, _) = client_rl.open_record(&reply_record).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(reply_plain, reply);

        // Zeroize
        cflight.master_secret.zeroize();
        keys.master_secret.zeroize();
    }

    /// Helper: run a full in-process TLS 1.2 handshake + app data exchange.
    fn run_tls12_handshake(
        suite: CipherSuite,
        client_alpn: &[&[u8]],
        server_alpn: &[&[u8]],
    ) -> (
        crate::handshake::client12::Tls12ClientState,
        crate::handshake::server12::Tls12ServerState,
        Option<Vec<u8>>, // server negotiated ALPN
    ) {
        let ecdsa_private = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let fake_cert = vec![0x30, 0x82, 0x01, 0x00];

        let client_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .verify_peer(false)
            .alpn(client_alpn)
            .build();

        let server_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .certificate_chain(vec![fake_cert])
            .private_key(ServerPrivateKey::Ecdsa {
                curve_id: hitls_types::EccCurveId::NistP256,
                private_key: ecdsa_private,
            })
            .verify_peer(false)
            .alpn(server_alpn)
            .build();

        let mut c2s = Vec::new();
        let mut s2c = Vec::new();

        let mut client_hs = Tls12ClientHandshake::new(client_config);
        let mut client_rl = RecordLayer::new();
        let mut server_hs = Tls12ServerHandshake::new(server_config);
        let mut server_rl = RecordLayer::new();

        // 1. Client → CH
        let ch_msg = client_hs.build_client_hello().unwrap();
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::Handshake, &ch_msg)
                .unwrap(),
        );

        // 2. Server ← CH → SH + Cert + SKE + SHD
        let (_, ch_plain, consumed) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..consumed);
        let (_, _, ch_total) = parse_handshake_header(&ch_plain).unwrap();
        let flight = server_hs
            .process_client_hello(&ch_plain[..ch_total])
            .unwrap();
        let suite_neg = flight.suite;
        for msg in [
            &flight.server_hello,
            &flight.certificate,
            &flight.server_key_exchange,
            &flight.server_hello_done,
        ] {
            s2c.extend_from_slice(&server_rl.seal_record(ContentType::Handshake, msg).unwrap());
        }

        // 3. Client processes server flight
        // SH
        let (_, sh_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        let (_, sh_body, sh_total) = parse_handshake_header(&sh_plain).unwrap();
        let sh = decode_server_hello(sh_body).unwrap();
        client_hs
            .process_server_hello(&sh_plain[..sh_total], &sh)
            .unwrap();

        // Cert
        let (_, cert_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        let (_, cert_body, cert_total) = parse_handshake_header(&cert_plain).unwrap();
        let cert12 = decode_certificate12(cert_body).unwrap();
        client_hs
            .process_certificate(&cert_plain[..cert_total], &cert12.certificate_list)
            .unwrap();

        // SKE
        let (_, ske_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        let (_, ske_body, ske_total) = parse_handshake_header(&ske_plain).unwrap();
        let ske = decode_server_key_exchange(ske_body).unwrap();
        client_hs
            .process_server_key_exchange(&ske_plain[..ske_total], &ske)
            .unwrap();

        // SHD
        let (_, shd_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        let (_, _, shd_total) = parse_handshake_header(&shd_plain).unwrap();

        // 4. Client flight: CKE + CCS + Finished
        let cflight = client_hs
            .process_server_hello_done(&shd_plain[..shd_total])
            .unwrap();
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::Handshake, &cflight.client_key_exchange)
                .unwrap(),
        );
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::ChangeCipherSpec, &[0x01])
                .unwrap(),
        );

        // Activate client write
        if cflight.is_cbc {
            client_rl.activate_write_encryption12_cbc(
                cflight.client_write_key.clone(),
                cflight.client_write_mac_key.clone(),
                cflight.mac_len,
            );
        } else {
            client_rl
                .activate_write_encryption12(
                    suite_neg,
                    &cflight.client_write_key,
                    cflight.client_write_iv.clone(),
                )
                .unwrap();
        }
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::Handshake, &cflight.finished)
                .unwrap(),
        );

        // 5. Server processes CKE + CCS + Finished
        let (_, cke_plain, consumed) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..consumed);
        let (_, _, cke_total) = parse_handshake_header(&cke_plain).unwrap();
        let keys = server_hs
            .process_client_key_exchange(&cke_plain[..cke_total])
            .unwrap();

        let (ct, _, consumed) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..consumed);
        assert_eq!(ct, ContentType::ChangeCipherSpec);
        server_hs.process_change_cipher_spec().unwrap();

        // Activate server read
        if keys.is_cbc {
            server_rl.activate_read_decryption12_cbc(
                keys.client_write_key.clone(),
                keys.client_write_mac_key.clone(),
                keys.mac_len,
            );
        } else {
            server_rl
                .activate_read_decryption12(
                    suite_neg,
                    &keys.client_write_key,
                    keys.client_write_iv.clone(),
                )
                .unwrap();
        }

        let (_, fin_plain, consumed) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..consumed);
        let (_, _, fin_total) = parse_handshake_header(&fin_plain).unwrap();
        let server_fin = server_hs.process_finished(&fin_plain[..fin_total]).unwrap();

        // 6. Server → CCS + Finished
        s2c.extend_from_slice(
            &server_rl
                .seal_record(ContentType::ChangeCipherSpec, &[0x01])
                .unwrap(),
        );
        if keys.is_cbc {
            server_rl.activate_write_encryption12_cbc(
                keys.server_write_key.clone(),
                keys.server_write_mac_key.clone(),
                keys.mac_len,
            );
        } else {
            server_rl
                .activate_write_encryption12(
                    suite_neg,
                    &keys.server_write_key,
                    keys.server_write_iv.clone(),
                )
                .unwrap();
        }
        s2c.extend_from_slice(
            &server_rl
                .seal_record(ContentType::Handshake, &server_fin.finished)
                .unwrap(),
        );

        // 7. Client processes CCS + Finished
        let (ct, _, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        assert_eq!(ct, ContentType::ChangeCipherSpec);
        client_hs.process_change_cipher_spec().unwrap();

        if cflight.is_cbc {
            client_rl.activate_read_decryption12_cbc(
                cflight.server_write_key.clone(),
                cflight.server_write_mac_key.clone(),
                cflight.mac_len,
            );
        } else {
            client_rl
                .activate_read_decryption12(
                    suite_neg,
                    &cflight.server_write_key,
                    cflight.server_write_iv.clone(),
                )
                .unwrap();
        }

        let (_, sfin_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        let (_, _, sfin_total) = parse_handshake_header(&sfin_plain).unwrap();
        client_hs
            .process_finished(&sfin_plain[..sfin_total], &cflight.master_secret)
            .unwrap();

        // 8. App data exchange
        let app_msg = b"Hello from client!";
        let app_record = client_rl
            .seal_record(ContentType::ApplicationData, app_msg)
            .unwrap();
        let (ct, app_plain, _) = server_rl.open_record(&app_record).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(app_plain, app_msg);

        let reply = b"Hello from server!";
        let reply_record = server_rl
            .seal_record(ContentType::ApplicationData, reply)
            .unwrap();
        let (ct, reply_plain, _) = client_rl.open_record(&reply_record).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(reply_plain, reply);

        let negotiated = server_hs.negotiated_alpn().map(|v| v.to_vec());
        (client_hs.state(), server_hs.state(), negotiated)
    }

    #[test]
    fn test_tls12_cbc_sha_full_handshake() {
        let (cs, ss, _) =
            run_tls12_handshake(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, &[], &[]);
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_cbc_sha256_full_handshake() {
        let (cs, ss, _) = run_tls12_handshake(
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            &[],
            &[],
        );
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_cbc_sha384_full_handshake() {
        let (cs, ss, _) = run_tls12_handshake(
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
            &[],
            &[],
        );
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_chacha20_full_handshake() {
        let (cs, ss, _) = run_tls12_handshake(
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            &[],
            &[],
        );
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_alpn_negotiation() {
        let (cs, ss, alpn) = run_tls12_handshake(
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            &[b"h2", b"http/1.1"],
            &[b"h2"],
        );
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
        assert_eq!(alpn.as_deref(), Some(b"h2".as_slice()));
    }

    #[test]
    fn test_tls12_alpn_no_match() {
        let (cs, ss, alpn) = run_tls12_handshake(
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            &[b"h2"],
            &[b"grpc"],
        );
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
        // No common protocol → no ALPN selected
        assert!(alpn.is_none());
    }

    /// Helper: generate a self-signed ECDSA P-256 cert + key for testing.
    fn make_ecdsa_cert_and_key(cn: &str, private_key_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let kp = hitls_crypto::ecdsa::EcdsaKeyPair::from_private_key(
            hitls_types::EccCurveId::NistP256,
            private_key_bytes,
        )
        .unwrap();
        let sk = hitls_pki::x509::SigningKey::Ecdsa {
            curve_id: hitls_types::EccCurveId::NistP256,
            key_pair: kp,
        };
        let dn = hitls_pki::x509::DistinguishedName {
            entries: vec![("CN".to_string(), cn.to_string())],
        };
        let cert =
            hitls_pki::x509::CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000)
                .unwrap();
        (cert.to_der(), private_key_bytes.to_vec())
    }

    /// Run a full in-process TLS 1.2 handshake with mTLS (client certificate auth).
    fn run_tls12_mtls_handshake(
        require_client_cert: bool,
        provide_client_cert: bool,
    ) -> Result<
        (
            crate::handshake::client12::Tls12ClientState,
            crate::handshake::server12::Tls12ServerState,
        ),
        TlsError,
    > {
        // Server ECDSA key
        let server_key_bytes = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let (server_cert_der, _) = make_ecdsa_cert_and_key("Server", &server_key_bytes);

        // Client ECDSA key (different from server)
        let client_key_bytes = vec![
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
            0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
            0x3D, 0x3E, 0x3F, 0x40,
        ];
        let (client_cert_der, _) = make_ecdsa_cert_and_key("Client", &client_key_bytes);

        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

        let mut client_builder = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .verify_peer(false);

        if provide_client_cert {
            client_builder = client_builder
                .client_certificate_chain(vec![client_cert_der])
                .client_private_key(ServerPrivateKey::Ecdsa {
                    curve_id: hitls_types::EccCurveId::NistP256,
                    private_key: client_key_bytes,
                });
        }
        let client_config = client_builder.build();

        let server_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .certificate_chain(vec![server_cert_der])
            .private_key(ServerPrivateKey::Ecdsa {
                curve_id: hitls_types::EccCurveId::NistP256,
                private_key: server_key_bytes,
            })
            .verify_peer(false)
            .verify_client_cert(true)
            .require_client_cert(require_client_cert)
            .build();

        let mut c2s = Vec::new();
        let mut s2c = Vec::new();

        let mut client_hs = crate::handshake::client12::Tls12ClientHandshake::new(client_config);
        let mut client_rl = RecordLayer::new();
        let mut server_hs = Tls12ServerHandshake::new(server_config);
        let mut server_rl = RecordLayer::new();

        // 1. Client → CH
        let ch_msg = client_hs.build_client_hello()?;
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::Handshake, &ch_msg)
                .unwrap(),
        );

        // 2. Server ← CH → SH + Cert + SKE + CertReq + SHD
        let (_, ch_plain, consumed) = server_rl.open_record(&c2s)?;
        c2s.drain(..consumed);
        let (_, _, ch_total) = parse_handshake_header(&ch_plain)?;
        let flight = server_hs.process_client_hello(&ch_plain[..ch_total])?;

        // Server sends: SH, Cert, SKE, CertReq, SHD
        for msg in [
            &flight.server_hello,
            &flight.certificate,
            &flight.server_key_exchange,
        ] {
            s2c.extend_from_slice(&server_rl.seal_record(ContentType::Handshake, msg).unwrap());
        }
        if let Some(ref cr_msg) = flight.certificate_request {
            s2c.extend_from_slice(
                &server_rl
                    .seal_record(ContentType::Handshake, cr_msg)
                    .unwrap(),
            );
        }
        s2c.extend_from_slice(
            &server_rl
                .seal_record(ContentType::Handshake, &flight.server_hello_done)
                .unwrap(),
        );

        // 3. Client processes server flight
        // SH
        let (_, sh_plain, consumed) = client_rl.open_record(&s2c)?;
        s2c.drain(..consumed);
        let (_, sh_body, sh_total) = parse_handshake_header(&sh_plain)?;
        let sh = crate::handshake::codec::decode_server_hello(sh_body)?;
        client_hs.process_server_hello(&sh_plain[..sh_total], &sh)?;

        // Cert
        let (_, cert_plain, consumed) = client_rl.open_record(&s2c)?;
        s2c.drain(..consumed);
        let (_, cert_body, cert_total) = parse_handshake_header(&cert_plain)?;
        let cert12 = decode_certificate12(cert_body)?;
        client_hs.process_certificate(&cert_plain[..cert_total], &cert12.certificate_list)?;

        // SKE
        let (_, ske_plain, consumed) = client_rl.open_record(&s2c)?;
        s2c.drain(..consumed);
        let (_, ske_body, ske_total) = parse_handshake_header(&ske_plain)?;
        let ske = decode_server_key_exchange(ske_body)?;
        client_hs.process_server_key_exchange(&ske_plain[..ske_total], &ske)?;

        // CertReq
        let (_, cr_plain, consumed) = client_rl.open_record(&s2c)?;
        s2c.drain(..consumed);
        let (ht, cr_body, cr_total) = parse_handshake_header(&cr_plain)?;
        assert_eq!(ht, HandshakeType::CertificateRequest);
        let cr = decode_certificate_request12(cr_body)?;
        client_hs.process_certificate_request(&cr_plain[..cr_total], &cr)?;

        // SHD
        let (_, shd_plain, consumed) = client_rl.open_record(&s2c)?;
        s2c.drain(..consumed);
        let (_, _, shd_total) = parse_handshake_header(&shd_plain)?;

        // 4. Client flight: [ClientCert] + CKE + [CertVerify] + CCS + Finished
        let cflight = client_hs.process_server_hello_done(&shd_plain[..shd_total])?;

        // Send client Certificate (if present)
        if let Some(ref cert_msg) = cflight.client_certificate {
            c2s.extend_from_slice(
                &client_rl
                    .seal_record(ContentType::Handshake, cert_msg)
                    .unwrap(),
            );
        }

        // Send CKE
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::Handshake, &cflight.client_key_exchange)
                .unwrap(),
        );

        // Send CertificateVerify (if present)
        if let Some(ref cv_msg) = cflight.certificate_verify {
            c2s.extend_from_slice(
                &client_rl
                    .seal_record(ContentType::Handshake, cv_msg)
                    .unwrap(),
            );
        }

        // CCS
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::ChangeCipherSpec, &[0x01])
                .unwrap(),
        );

        // Activate client write encryption
        client_rl
            .activate_write_encryption12(
                suite,
                &cflight.client_write_key,
                cflight.client_write_iv.clone(),
            )
            .unwrap();

        // Finished (encrypted)
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::Handshake, &cflight.finished)
                .unwrap(),
        );

        // 5. Server processes client flight
        // Client Certificate
        let (_, client_cert_plain, consumed) = server_rl.open_record(&c2s)?;
        c2s.drain(..consumed);
        let (_, _, ccert_total) = parse_handshake_header(&client_cert_plain)?;
        server_hs.process_client_certificate(&client_cert_plain[..ccert_total])?;

        // CKE
        let (_, cke_plain, consumed) = server_rl.open_record(&c2s)?;
        c2s.drain(..consumed);
        let (_, _, cke_total) = parse_handshake_header(&cke_plain)?;
        let keys = server_hs.process_client_key_exchange(&cke_plain[..cke_total])?;

        // CertificateVerify (if client sent certs)
        if server_hs.state() == Tls12ServerState::WaitClientCertificateVerify {
            let (_, cv_plain, consumed) = server_rl.open_record(&c2s)?;
            c2s.drain(..consumed);
            let (_, _, cv_total) = parse_handshake_header(&cv_plain)?;
            server_hs.process_client_certificate_verify(&cv_plain[..cv_total])?;
        }

        // CCS
        let (ct, _, consumed) = server_rl.open_record(&c2s)?;
        c2s.drain(..consumed);
        assert_eq!(ct, ContentType::ChangeCipherSpec);
        server_hs.process_change_cipher_spec()?;

        // Activate server read
        server_rl
            .activate_read_decryption12(suite, &keys.client_write_key, keys.client_write_iv.clone())
            .unwrap();

        // Client Finished
        let (_, fin_plain, consumed) = server_rl.open_record(&c2s)?;
        c2s.drain(..consumed);
        let (_, _, fin_total) = parse_handshake_header(&fin_plain)?;
        let server_fin = server_hs.process_finished(&fin_plain[..fin_total])?;

        // 6. Server → CCS + Finished
        s2c.extend_from_slice(
            &server_rl
                .seal_record(ContentType::ChangeCipherSpec, &[0x01])
                .unwrap(),
        );
        server_rl
            .activate_write_encryption12(
                suite,
                &keys.server_write_key,
                keys.server_write_iv.clone(),
            )
            .unwrap();
        s2c.extend_from_slice(
            &server_rl
                .seal_record(ContentType::Handshake, &server_fin.finished)
                .unwrap(),
        );

        // 7. Client processes CCS + Finished
        let (ct, _, consumed) = client_rl.open_record(&s2c)?;
        s2c.drain(..consumed);
        assert_eq!(ct, ContentType::ChangeCipherSpec);
        client_hs.process_change_cipher_spec()?;

        client_rl
            .activate_read_decryption12(
                suite,
                &cflight.server_write_key,
                cflight.server_write_iv.clone(),
            )
            .unwrap();

        let (_, sfin_plain, consumed) = client_rl.open_record(&s2c)?;
        s2c.drain(..consumed);
        let (_, _, sfin_total) = parse_handshake_header(&sfin_plain)?;
        client_hs.process_finished(&sfin_plain[..sfin_total], &cflight.master_secret)?;

        // 8. App data exchange
        let app_msg = b"Hello mTLS!";
        let app_record = client_rl
            .seal_record(ContentType::ApplicationData, app_msg)
            .unwrap();
        let (ct, app_plain, _) = server_rl.open_record(&app_record)?;
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(app_plain, app_msg);

        Ok((client_hs.state(), server_hs.state()))
    }

    #[test]
    fn test_tls12_mtls_full_handshake() {
        let (cs, ss) = run_tls12_mtls_handshake(true, true).unwrap();
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_mtls_optional_no_cert() {
        // Server requests but doesn't require; client provides no cert
        let (cs, ss) = run_tls12_mtls_handshake(false, false).unwrap();
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_mtls_required_no_cert() {
        // Server requires client cert; client provides none → should fail
        let result = run_tls12_mtls_handshake(true, false);
        assert!(result.is_err());
    }

    // =========================================================================
    // Session Resumption helpers + tests
    // =========================================================================

    /// Helper: Run a full TLS 1.2 handshake and return the session for caching.
    fn run_full_handshake_get_session(suite: CipherSuite) -> TlsSession {
        let ecdsa_private = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let fake_cert = vec![0x30, 0x82, 0x01, 0x00];

        let client_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .verify_peer(false)
            .build();

        let server_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .certificate_chain(vec![fake_cert])
            .private_key(ServerPrivateKey::Ecdsa {
                curve_id: hitls_types::EccCurveId::NistP256,
                private_key: ecdsa_private,
            })
            .verify_peer(false)
            .build();

        let mut c2s = Vec::new();
        let mut s2c = Vec::new();
        let mut client_hs = Tls12ClientHandshake::new(client_config);
        let mut client_rl = RecordLayer::new();
        let mut server_hs = Tls12ServerHandshake::new(server_config);
        let mut server_rl = RecordLayer::new();

        // 1. Client → CH
        let ch_msg = client_hs.build_client_hello().unwrap();
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::Handshake, &ch_msg)
                .unwrap(),
        );

        // 2. Server ← CH → SH + Cert + SKE + SHD
        let (_, ch_plain, consumed) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..consumed);
        let (_, _, ch_total) = parse_handshake_header(&ch_plain).unwrap();
        let flight = server_hs
            .process_client_hello(&ch_plain[..ch_total])
            .unwrap();
        let suite_neg = flight.suite;
        for msg in [
            &flight.server_hello,
            &flight.certificate,
            &flight.server_key_exchange,
            &flight.server_hello_done,
        ] {
            s2c.extend_from_slice(&server_rl.seal_record(ContentType::Handshake, msg).unwrap());
        }

        // 3. Client processes SH + Cert + SKE + SHD
        let (_, sh_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        let (_, sh_body, sh_total) = parse_handshake_header(&sh_plain).unwrap();
        let sh = decode_server_hello(sh_body).unwrap();
        client_hs
            .process_server_hello(&sh_plain[..sh_total], &sh)
            .unwrap();

        let (_, cert_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        let (_, cert_body, cert_total) = parse_handshake_header(&cert_plain).unwrap();
        let cert12 = decode_certificate12(cert_body).unwrap();
        client_hs
            .process_certificate(&cert_plain[..cert_total], &cert12.certificate_list)
            .unwrap();

        let (_, ske_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        let (_, ske_body, ske_total) = parse_handshake_header(&ske_plain).unwrap();
        let ske = decode_server_key_exchange(ske_body).unwrap();
        client_hs
            .process_server_key_exchange(&ske_plain[..ske_total], &ske)
            .unwrap();

        let (_, shd_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        let (_, _, shd_total) = parse_handshake_header(&shd_plain).unwrap();

        // 4. Client flight: CKE + CCS + Finished
        let cflight = client_hs
            .process_server_hello_done(&shd_plain[..shd_total])
            .unwrap();
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::Handshake, &cflight.client_key_exchange)
                .unwrap(),
        );
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::ChangeCipherSpec, &[0x01])
                .unwrap(),
        );
        if cflight.is_cbc {
            client_rl.activate_write_encryption12_cbc(
                cflight.client_write_key.clone(),
                cflight.client_write_mac_key.clone(),
                cflight.mac_len,
            );
        } else {
            client_rl
                .activate_write_encryption12(
                    suite_neg,
                    &cflight.client_write_key,
                    cflight.client_write_iv.clone(),
                )
                .unwrap();
        }
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::Handshake, &cflight.finished)
                .unwrap(),
        );

        // 5. Server processes CKE + CCS + Finished
        let (_, cke_plain, consumed) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..consumed);
        let (_, _, cke_total) = parse_handshake_header(&cke_plain).unwrap();
        let keys = server_hs
            .process_client_key_exchange(&cke_plain[..cke_total])
            .unwrap();

        let (ct, _, consumed) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..consumed);
        assert_eq!(ct, ContentType::ChangeCipherSpec);
        server_hs.process_change_cipher_spec().unwrap();

        if keys.is_cbc {
            server_rl.activate_read_decryption12_cbc(
                keys.client_write_key.clone(),
                keys.client_write_mac_key.clone(),
                keys.mac_len,
            );
        } else {
            server_rl
                .activate_read_decryption12(
                    suite_neg,
                    &keys.client_write_key,
                    keys.client_write_iv.clone(),
                )
                .unwrap();
        }

        let (_, fin_plain, consumed) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..consumed);
        let (_, _, fin_total) = parse_handshake_header(&fin_plain).unwrap();
        let server_fin = server_hs.process_finished(&fin_plain[..fin_total]).unwrap();

        // 6. Server → CCS + Finished
        s2c.extend_from_slice(
            &server_rl
                .seal_record(ContentType::ChangeCipherSpec, &[0x01])
                .unwrap(),
        );
        if keys.is_cbc {
            server_rl.activate_write_encryption12_cbc(
                keys.server_write_key.clone(),
                keys.server_write_mac_key.clone(),
                keys.mac_len,
            );
        } else {
            server_rl
                .activate_write_encryption12(
                    suite_neg,
                    &keys.server_write_key,
                    keys.server_write_iv.clone(),
                )
                .unwrap();
        }
        s2c.extend_from_slice(
            &server_rl
                .seal_record(ContentType::Handshake, &server_fin.finished)
                .unwrap(),
        );

        // 7. Client processes CCS + Finished
        let (ct, _, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        assert_eq!(ct, ContentType::ChangeCipherSpec);
        client_hs.process_change_cipher_spec().unwrap();

        if cflight.is_cbc {
            client_rl.activate_read_decryption12_cbc(
                cflight.server_write_key.clone(),
                cflight.server_write_mac_key.clone(),
                cflight.mac_len,
            );
        } else {
            client_rl
                .activate_read_decryption12(
                    suite_neg,
                    &cflight.server_write_key,
                    cflight.server_write_iv.clone(),
                )
                .unwrap();
        }

        let (_, sfin_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        let (_, _, sfin_total) = parse_handshake_header(&sfin_plain).unwrap();
        client_hs
            .process_finished(&sfin_plain[..sfin_total], &cflight.master_secret)
            .unwrap();

        assert_eq!(client_hs.state(), Tls12ClientState::Connected);
        assert_eq!(server_hs.state(), Tls12ServerState::Connected);

        // Build session from server's assigned session_id + master_secret
        TlsSession {
            id: server_hs.session_id().to_vec(),
            cipher_suite: suite_neg,
            master_secret: server_hs.master_secret_ref().to_vec(),
            alpn_protocol: None,
            ticket: None,
            ticket_lifetime: 0,
            max_early_data: 0,
            ticket_age_add: 0,
            ticket_nonce: Vec::new(),
            created_at: 0,
            psk: Vec::new(),
        }
    }

    /// Helper: Run an abbreviated TLS 1.2 handshake using a cached session.
    ///
    /// The caller is responsible for populating `cache` with the session before
    /// calling this function. `cached_session` is used for the client config
    /// (to send the cached session_id in ClientHello).
    ///
    /// Returns (client_state, server_state) on success, or TlsError.
    fn run_abbreviated_handshake(
        suite: CipherSuite,
        cached_session: TlsSession,
        cache: &mut InMemorySessionCache,
    ) -> Result<(Tls12ClientState, Tls12ServerState), TlsError> {
        let ecdsa_private = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let fake_cert = vec![0x30, 0x82, 0x01, 0x00];

        // Client config: set resumption_session to cached session
        let client_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .verify_peer(false)
            .session_resumption(true)
            .resumption_session(cached_session)
            .build();

        // Server config: same as always
        let server_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .certificate_chain(vec![fake_cert])
            .private_key(ServerPrivateKey::Ecdsa {
                curve_id: hitls_types::EccCurveId::NistP256,
                private_key: ecdsa_private,
            })
            .verify_peer(false)
            .build();

        let mut c2s = Vec::new();
        let mut s2c = Vec::new();
        let mut client_hs = Tls12ClientHandshake::new(client_config);
        let mut client_rl = RecordLayer::new();
        let mut server_hs = Tls12ServerHandshake::new(server_config);
        let mut server_rl = RecordLayer::new();

        // 1. Client → CH (with cached session_id)
        let ch_msg = client_hs.build_client_hello()?;
        c2s.extend_from_slice(&client_rl.seal_record(ContentType::Handshake, &ch_msg)?);

        // 2. Server processes CH with cache → should return Abbreviated
        let (_, ch_plain, consumed) = server_rl.open_record(&c2s)?;
        c2s.drain(..consumed);
        let (_, _, ch_total) = parse_handshake_header(&ch_plain)?;
        let result = server_hs.process_client_hello_resumable(
            &ch_plain[..ch_total],
            Some(cache as &dyn SessionCache),
        )?;

        match result {
            ServerHelloResult::Abbreviated(mut abbr) => {
                // Abbreviated path: Server sends SH → CCS → Finished

                // 3. Server → SH (plaintext)
                s2c.extend_from_slice(
                    &server_rl.seal_record(ContentType::Handshake, &abbr.server_hello)?,
                );

                // 4. Server → CCS
                s2c.extend_from_slice(
                    &server_rl.seal_record(ContentType::ChangeCipherSpec, &[0x01])?,
                );

                // 5. Activate server write encryption
                if abbr.is_cbc {
                    server_rl.activate_write_encryption12_cbc(
                        abbr.server_write_key.clone(),
                        abbr.server_write_mac_key.clone(),
                        abbr.mac_len,
                    );
                } else {
                    server_rl.activate_write_encryption12(
                        abbr.suite,
                        &abbr.server_write_key,
                        abbr.server_write_iv.clone(),
                    )?;
                }

                // 6. Server → Finished (encrypted)
                s2c.extend_from_slice(
                    &server_rl.seal_record(ContentType::Handshake, &abbr.finished)?,
                );

                // 7. Client processes SH → detects abbreviated
                let (_, sh_plain, consumed) = client_rl.open_record(&s2c)?;
                s2c.drain(..consumed);
                let (_, sh_body, sh_total) = parse_handshake_header(&sh_plain)?;
                let sh = decode_server_hello(sh_body)?;
                client_hs.process_server_hello(&sh_plain[..sh_total], &sh)?;

                assert!(client_hs.is_abbreviated());
                let keys = client_hs.take_abbreviated_keys().unwrap();

                // 8. Client processes CCS
                let (ct, _, consumed) = client_rl.open_record(&s2c)?;
                s2c.drain(..consumed);
                assert_eq!(ct, ContentType::ChangeCipherSpec);
                client_hs.process_change_cipher_spec()?;

                // 9. Activate client read decryption (server write key)
                if keys.is_cbc {
                    client_rl.activate_read_decryption12_cbc(
                        keys.server_write_key.clone(),
                        keys.server_write_mac_key.clone(),
                        keys.mac_len,
                    );
                } else {
                    client_rl.activate_read_decryption12(
                        keys.suite,
                        &keys.server_write_key,
                        keys.server_write_iv.clone(),
                    )?;
                }

                // 10. Client reads server Finished (encrypted) → returns client Finished
                let (_, sfin_plain, consumed) = client_rl.open_record(&s2c)?;
                s2c.drain(..consumed);
                let (_, _, sfin_total) = parse_handshake_header(&sfin_plain)?;
                let client_finished_msg =
                    client_hs.process_abbreviated_server_finished(&sfin_plain[..sfin_total])?;

                // 11. Client → CCS
                c2s.extend_from_slice(
                    &client_rl.seal_record(ContentType::ChangeCipherSpec, &[0x01])?,
                );

                // 12. Activate client write encryption
                if keys.is_cbc {
                    client_rl.activate_write_encryption12_cbc(
                        keys.client_write_key.clone(),
                        keys.client_write_mac_key.clone(),
                        keys.mac_len,
                    );
                } else {
                    client_rl.activate_write_encryption12(
                        keys.suite,
                        &keys.client_write_key,
                        keys.client_write_iv.clone(),
                    )?;
                }

                // 13. Client → Finished (encrypted)
                c2s.extend_from_slice(
                    &client_rl.seal_record(ContentType::Handshake, &client_finished_msg)?,
                );

                // 14. Server processes client CCS
                let (ct, _, consumed) = server_rl.open_record(&c2s)?;
                c2s.drain(..consumed);
                assert_eq!(ct, ContentType::ChangeCipherSpec);
                server_hs.process_change_cipher_spec()?;

                // 15. Activate server read decryption (client write key)
                if abbr.is_cbc {
                    server_rl.activate_read_decryption12_cbc(
                        abbr.client_write_key.clone(),
                        abbr.client_write_mac_key.clone(),
                        abbr.mac_len,
                    );
                } else {
                    server_rl.activate_read_decryption12(
                        abbr.suite,
                        &abbr.client_write_key,
                        abbr.client_write_iv.clone(),
                    )?;
                }

                // 16. Server processes client Finished (encrypted)
                let (_, cfin_plain, consumed) = server_rl.open_record(&c2s)?;
                c2s.drain(..consumed);
                let (_, _, cfin_total) = parse_handshake_header(&cfin_plain)?;
                server_hs.process_abbreviated_finished(&cfin_plain[..cfin_total])?;

                // 17. Exchange app data to verify connection works
                let app_msg = b"Hello abbreviated!";
                let app_record = client_rl.seal_record(ContentType::ApplicationData, app_msg)?;
                let (ct, app_plain, _) = server_rl.open_record(&app_record)?;
                assert_eq!(ct, ContentType::ApplicationData);
                assert_eq!(app_plain, app_msg);

                let reply = b"Hello back!";
                let reply_record = server_rl.seal_record(ContentType::ApplicationData, reply)?;
                let (ct, reply_plain, _) = client_rl.open_record(&reply_record)?;
                assert_eq!(ct, ContentType::ApplicationData);
                assert_eq!(reply_plain, reply);

                // Zeroize
                abbr.master_secret.zeroize();

                Ok((client_hs.state(), server_hs.state()))
            }
            ServerHelloResult::Full(_flight) => {
                // Not an abbreviated handshake — return error for tests that expect resumption
                Err(TlsError::HandshakeFailed(
                    "expected abbreviated handshake but got full".into(),
                ))
            }
        }
    }

    #[test]
    fn test_tls12_session_resumption_roundtrip() {
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

        // Step 1: Full handshake → get session
        let session = run_full_handshake_get_session(suite);
        assert!(!session.id.is_empty());
        assert_eq!(session.cipher_suite, suite);

        // Step 2: Abbreviated handshake using cached session
        let mut cache = InMemorySessionCache::new(10);
        let sid = session.id.clone();
        cache.put(&sid, session.clone());
        let (cs, ss) = run_abbreviated_handshake(suite, session, &mut cache).unwrap();
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_session_resumption_cbc_suite() {
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA;

        let session = run_full_handshake_get_session(suite);
        assert!(!session.id.is_empty());

        let mut cache = InMemorySessionCache::new(10);
        let sid = session.id.clone();
        cache.put(&sid, session.clone());
        let (cs, ss) = run_abbreviated_handshake(suite, session, &mut cache).unwrap();
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_session_resumption_sha384() {
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;

        let session = run_full_handshake_get_session(suite);
        assert!(!session.id.is_empty());

        let mut cache = InMemorySessionCache::new(10);
        let sid = session.id.clone();
        cache.put(&sid, session.clone());
        let (cs, ss) = run_abbreviated_handshake(suite, session, &mut cache).unwrap();
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_mtls_then_resumption() {
        // Step 1: Full handshake with mTLS
        let (cs, ss) = run_tls12_mtls_handshake(false, true).unwrap();
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);

        // Step 2: Abbreviated handshake (no mTLS needed for resumption)
        // Use a fresh session from a GCM suite full handshake
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let session = run_full_handshake_get_session(suite);

        let mut cache = InMemorySessionCache::new(10);
        let sid = session.id.clone();
        cache.put(&sid, session.clone());
        let (cs, ss) = run_abbreviated_handshake(suite, session, &mut cache).unwrap();
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    // =========================================================================
    // Session Ticket helpers + tests
    // =========================================================================

    /// Helper: Run a full TLS 1.2 handshake with ticket_key configured on server.
    /// Returns the TlsSession (with ticket) from the handshake.
    fn run_full_handshake_with_ticket(suite: CipherSuite, ticket_key: Vec<u8>) -> TlsSession {
        use crate::handshake::codec12::decode_new_session_ticket12;

        let ecdsa_private = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let fake_cert = vec![0x30, 0x82, 0x01, 0x00];

        let client_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .verify_peer(false)
            .session_resumption(true)
            .build();

        let server_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .certificate_chain(vec![fake_cert])
            .private_key(ServerPrivateKey::Ecdsa {
                curve_id: hitls_types::EccCurveId::NistP256,
                private_key: ecdsa_private,
            })
            .verify_peer(false)
            .ticket_key(ticket_key)
            .build();

        let mut c2s = Vec::new();
        let mut s2c = Vec::new();
        let mut client_hs = Tls12ClientHandshake::new(client_config);
        let mut client_rl = RecordLayer::new();
        let mut server_hs = Tls12ServerHandshake::new(server_config);
        let mut server_rl = RecordLayer::new();

        // 1. Client → CH (with empty SessionTicket extension)
        let ch_msg = client_hs.build_client_hello().unwrap();
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::Handshake, &ch_msg)
                .unwrap(),
        );

        // 2. Server processes CH (should include empty SessionTicket ext in SH)
        let (_, ch_plain, consumed) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..consumed);
        let (_, _, ch_total) = parse_handshake_header(&ch_plain).unwrap();
        let flight = server_hs
            .process_client_hello(&ch_plain[..ch_total])
            .unwrap();
        let suite_neg = flight.suite;
        for msg in [
            &flight.server_hello,
            &flight.certificate,
            &flight.server_key_exchange,
            &flight.server_hello_done,
        ] {
            s2c.extend_from_slice(&server_rl.seal_record(ContentType::Handshake, msg).unwrap());
        }

        // 3. Client processes SH + Cert + SKE + SHD
        let (_, sh_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        let (_, sh_body, sh_total) = parse_handshake_header(&sh_plain).unwrap();
        let sh = decode_server_hello(sh_body).unwrap();
        client_hs
            .process_server_hello(&sh_plain[..sh_total], &sh)
            .unwrap();

        let (_, cert_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        let (_, cert_body, cert_total) = parse_handshake_header(&cert_plain).unwrap();
        let cert12 = decode_certificate12(cert_body).unwrap();
        client_hs
            .process_certificate(&cert_plain[..cert_total], &cert12.certificate_list)
            .unwrap();

        let (_, ske_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        let (_, ske_body, ske_total) = parse_handshake_header(&ske_plain).unwrap();
        let ske = decode_server_key_exchange(ske_body).unwrap();
        client_hs
            .process_server_key_exchange(&ske_plain[..ske_total], &ske)
            .unwrap();

        let (_, shd_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        let (_, _, shd_total) = parse_handshake_header(&shd_plain).unwrap();

        // 4. Client flight: CKE + CCS + Finished
        let cflight = client_hs
            .process_server_hello_done(&shd_plain[..shd_total])
            .unwrap();
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::Handshake, &cflight.client_key_exchange)
                .unwrap(),
        );
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::ChangeCipherSpec, &[0x01])
                .unwrap(),
        );
        client_rl
            .activate_write_encryption12(
                suite_neg,
                &cflight.client_write_key,
                cflight.client_write_iv.clone(),
            )
            .unwrap();
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::Handshake, &cflight.finished)
                .unwrap(),
        );

        // 5. Server processes CKE + CCS + Finished
        let (_, cke_plain, consumed) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..consumed);
        let (_, _, cke_total) = parse_handshake_header(&cke_plain).unwrap();
        let keys = server_hs
            .process_client_key_exchange(&cke_plain[..cke_total])
            .unwrap();

        let (ct, _, consumed) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..consumed);
        assert_eq!(ct, ContentType::ChangeCipherSpec);
        server_hs.process_change_cipher_spec().unwrap();

        server_rl
            .activate_read_decryption12(
                suite_neg,
                &keys.client_write_key,
                keys.client_write_iv.clone(),
            )
            .unwrap();

        let (_, fin_plain, consumed) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..consumed);
        let (_, _, fin_total) = parse_handshake_header(&fin_plain).unwrap();
        let server_fin = server_hs.process_finished(&fin_plain[..fin_total]).unwrap();

        // 6. Server → NewSessionTicket + CCS + Finished
        let nst_msg = server_hs
            .build_new_session_ticket(suite_neg, 3600)
            .unwrap()
            .expect("should produce a ticket");
        s2c.extend_from_slice(
            &server_rl
                .seal_record(ContentType::Handshake, &nst_msg)
                .unwrap(),
        );
        s2c.extend_from_slice(
            &server_rl
                .seal_record(ContentType::ChangeCipherSpec, &[0x01])
                .unwrap(),
        );
        server_rl
            .activate_write_encryption12(
                suite_neg,
                &keys.server_write_key,
                keys.server_write_iv.clone(),
            )
            .unwrap();
        s2c.extend_from_slice(
            &server_rl
                .seal_record(ContentType::Handshake, &server_fin.finished)
                .unwrap(),
        );

        // 7. Client processes NewSessionTicket + CCS + Finished
        let (ct, nst_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        assert_eq!(ct, ContentType::Handshake);
        let (hs_type, _, nst_total) = parse_handshake_header(&nst_plain).unwrap();
        assert_eq!(hs_type, HandshakeType::NewSessionTicket);
        let nst_body = &nst_plain[4..nst_total];
        let (lifetime, ticket_data) = decode_new_session_ticket12(nst_body).unwrap();
        client_hs.process_new_session_ticket(nst_body).unwrap();

        let (ct, _, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        assert_eq!(ct, ContentType::ChangeCipherSpec);
        client_hs.process_change_cipher_spec().unwrap();

        client_rl
            .activate_read_decryption12(
                suite_neg,
                &cflight.server_write_key,
                cflight.server_write_iv.clone(),
            )
            .unwrap();

        let (_, sfin_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        let (_, _, sfin_total) = parse_handshake_header(&sfin_plain).unwrap();
        client_hs
            .process_finished(&sfin_plain[..sfin_total], &cflight.master_secret)
            .unwrap();

        assert_eq!(client_hs.state(), Tls12ClientState::Connected);
        assert_eq!(server_hs.state(), Tls12ServerState::Connected);

        // Build session with ticket for resumption
        TlsSession {
            id: Vec::new(), // ticket-based, no session ID needed
            cipher_suite: suite_neg,
            master_secret: cflight.master_secret.clone(),
            alpn_protocol: None,
            ticket: Some(ticket_data),
            ticket_lifetime: lifetime,
            max_early_data: 0,
            ticket_age_add: 0,
            ticket_nonce: Vec::new(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            psk: Vec::new(),
        }
    }

    /// Helper: Run an abbreviated handshake using a session ticket (no session ID cache).
    fn run_ticket_abbreviated_handshake(
        suite: CipherSuite,
        ticket_key: Vec<u8>,
        cached_session: TlsSession,
    ) -> Result<(Tls12ClientState, Tls12ServerState), TlsError> {
        let ecdsa_private = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let fake_cert = vec![0x30, 0x82, 0x01, 0x00];

        let client_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .verify_peer(false)
            .session_resumption(true)
            .resumption_session(cached_session)
            .build();

        let server_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .certificate_chain(vec![fake_cert])
            .private_key(ServerPrivateKey::Ecdsa {
                curve_id: hitls_types::EccCurveId::NistP256,
                private_key: ecdsa_private,
            })
            .verify_peer(false)
            .ticket_key(ticket_key)
            .build();

        let mut c2s = Vec::new();
        let mut s2c = Vec::new();
        let mut client_hs = Tls12ClientHandshake::new(client_config);
        let mut client_rl = RecordLayer::new();
        let mut server_hs = Tls12ServerHandshake::new(server_config);
        let mut server_rl = RecordLayer::new();

        // 1. Client → CH (with ticket in SessionTicket extension)
        let ch_msg = client_hs.build_client_hello()?;
        c2s.extend_from_slice(&client_rl.seal_record(ContentType::Handshake, &ch_msg)?);

        // 2. Server processes CH with ticket (no session cache needed)
        let (_, ch_plain, consumed) = server_rl.open_record(&c2s)?;
        c2s.drain(..consumed);
        let (_, _, ch_total) = parse_handshake_header(&ch_plain)?;
        let result = server_hs.process_client_hello_resumable(&ch_plain[..ch_total], None)?;

        match result {
            ServerHelloResult::Abbreviated(mut abbr) => {
                // Server → SH + (optional NST) + CCS + Finished
                s2c.extend_from_slice(
                    &server_rl.seal_record(ContentType::Handshake, &abbr.server_hello)?,
                );

                // Optionally send NST (new ticket for the new session)
                if let Some(nst_msg) = server_hs.build_new_session_ticket(abbr.suite, 3600)? {
                    s2c.extend_from_slice(
                        &server_rl.seal_record(ContentType::Handshake, &nst_msg)?,
                    );
                }

                s2c.extend_from_slice(
                    &server_rl.seal_record(ContentType::ChangeCipherSpec, &[0x01])?,
                );
                server_rl.activate_write_encryption12(
                    abbr.suite,
                    &abbr.server_write_key,
                    abbr.server_write_iv.clone(),
                )?;
                s2c.extend_from_slice(
                    &server_rl.seal_record(ContentType::Handshake, &abbr.finished)?,
                );

                // Client processes SH
                let (_, sh_plain, consumed) = client_rl.open_record(&s2c)?;
                s2c.drain(..consumed);
                let (_, sh_body, sh_total) = parse_handshake_header(&sh_plain)?;
                let sh = decode_server_hello(sh_body)?;
                client_hs.process_server_hello(&sh_plain[..sh_total], &sh)?;

                assert!(client_hs.is_abbreviated());
                let keys = client_hs.take_abbreviated_keys().unwrap();

                // Client processes optional NST then CCS
                loop {
                    let (ct, data, consumed) = client_rl.open_record(&s2c)?;
                    s2c.drain(..consumed);
                    match ct {
                        ContentType::Handshake => {
                            let (hs_type, _, total) = parse_handshake_header(&data)?;
                            if hs_type == HandshakeType::NewSessionTicket {
                                let body = &data[4..total];
                                client_hs.process_new_session_ticket(body)?;
                            } else {
                                return Err(TlsError::HandshakeFailed(format!(
                                    "unexpected {hs_type:?}"
                                )));
                            }
                        }
                        ContentType::ChangeCipherSpec => {
                            client_hs.process_change_cipher_spec()?;
                            break;
                        }
                        _ => {
                            return Err(TlsError::HandshakeFailed(format!("unexpected {ct:?}")));
                        }
                    }
                }

                // Activate client read decryption
                client_rl.activate_read_decryption12(
                    keys.suite,
                    &keys.server_write_key,
                    keys.server_write_iv.clone(),
                )?;

                // Client reads server Finished
                let (_, sfin_plain, consumed) = client_rl.open_record(&s2c)?;
                s2c.drain(..consumed);
                let (_, _, sfin_total) = parse_handshake_header(&sfin_plain)?;
                let client_finished_msg =
                    client_hs.process_abbreviated_server_finished(&sfin_plain[..sfin_total])?;

                // Client → CCS + Finished
                c2s.extend_from_slice(
                    &client_rl.seal_record(ContentType::ChangeCipherSpec, &[0x01])?,
                );
                client_rl.activate_write_encryption12(
                    keys.suite,
                    &keys.client_write_key,
                    keys.client_write_iv.clone(),
                )?;
                c2s.extend_from_slice(
                    &client_rl.seal_record(ContentType::Handshake, &client_finished_msg)?,
                );

                // Server processes client CCS + Finished
                let (ct, _, consumed) = server_rl.open_record(&c2s)?;
                c2s.drain(..consumed);
                assert_eq!(ct, ContentType::ChangeCipherSpec);
                server_hs.process_change_cipher_spec()?;

                server_rl.activate_read_decryption12(
                    abbr.suite,
                    &abbr.client_write_key,
                    abbr.client_write_iv.clone(),
                )?;

                let (_, cfin_plain, consumed) = server_rl.open_record(&c2s)?;
                c2s.drain(..consumed);
                let (_, _, cfin_total) = parse_handshake_header(&cfin_plain)?;
                server_hs.process_abbreviated_finished(&cfin_plain[..cfin_total])?;

                // Verify app data works
                let app_msg = b"Hello ticket resumption!";
                let app_record = client_rl.seal_record(ContentType::ApplicationData, app_msg)?;
                let (ct, app_plain, _) = server_rl.open_record(&app_record)?;
                assert_eq!(ct, ContentType::ApplicationData);
                assert_eq!(app_plain, app_msg);

                abbr.master_secret.zeroize();

                Ok((client_hs.state(), server_hs.state()))
            }
            ServerHelloResult::Full(_flight) => Err(TlsError::HandshakeFailed(
                "expected abbreviated handshake but got full".into(),
            )),
        }
    }

    #[test]
    fn test_tls12_session_ticket_full_handshake() {
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let ticket_key = vec![0xAB; 32];

        let session = run_full_handshake_with_ticket(suite, ticket_key);
        assert!(session.ticket.is_some());
        assert!(!session.ticket.as_ref().unwrap().is_empty());
        assert_eq!(session.ticket_lifetime, 3600);
        assert_eq!(session.cipher_suite, suite);
        assert!(!session.master_secret.is_empty());
    }

    #[test]
    fn test_tls12_session_ticket_resumption() {
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let ticket_key = vec![0xAB; 32];

        // Step 1: Full handshake → get session with ticket
        let session = run_full_handshake_with_ticket(suite, ticket_key.clone());
        assert!(session.ticket.is_some());

        // Step 2: Abbreviated handshake using ticket
        let (cs, ss) = run_ticket_abbreviated_handshake(suite, ticket_key, session).unwrap();
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_session_ticket_invalid_ticket() {
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let ticket_key = vec![0xAB; 32];

        // Create a session with a corrupted ticket
        let mut session = run_full_handshake_with_ticket(suite, ticket_key.clone());
        // Corrupt the ticket data
        if let Some(ref mut ticket) = session.ticket {
            for b in ticket.iter_mut() {
                *b ^= 0xFF;
            }
        }

        // Abbreviated should fail → server falls back to full handshake
        let result = run_ticket_abbreviated_handshake(suite, ticket_key, session);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("expected abbreviated"));
    }

    #[test]
    fn test_tls12_session_ticket_wrong_key() {
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let ticket_key = vec![0xAB; 32];

        // Full handshake with original key
        let session = run_full_handshake_with_ticket(suite, ticket_key);
        assert!(session.ticket.is_some());

        // Try resumption with a different ticket key → decryption fails → full handshake
        let different_key = vec![0xCD; 32];
        let result = run_ticket_abbreviated_handshake(suite, different_key, session);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("expected abbreviated"));
    }

    #[test]
    fn test_tls12_session_ticket_take_session() {
        // Use Cursor-based connection to verify take_session works
        let stream = Cursor::new(Vec::<u8>::new());
        let config = TlsConfig::builder().build();
        let mut conn = Tls12ClientConnection::new(stream, config);

        // Before handshake, no session
        assert!(conn.take_session().is_none());

        // Manually set a session (simulating post-handshake state)
        conn.session = Some(TlsSession {
            id: Vec::new(),
            cipher_suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            master_secret: vec![0x42; 48],
            alpn_protocol: None,
            ticket: Some(vec![0xDE; 100]),
            ticket_lifetime: 3600,
            max_early_data: 0,
            ticket_age_add: 0,
            ticket_nonce: Vec::new(),
            created_at: 0,
            psk: Vec::new(),
        });

        let session = conn.take_session().unwrap();
        assert!(session.ticket.is_some());
        assert_eq!(session.ticket.as_ref().unwrap().len(), 100);
        assert_eq!(session.ticket_lifetime, 3600);

        // After take, session is gone
        assert!(conn.take_session().is_none());

        // Same for server
        let stream = Cursor::new(Vec::<u8>::new());
        let config = TlsConfig::builder().build();
        let mut srv = Tls12ServerConnection::new(stream, config);
        assert!(srv.take_session().is_none());
    }

    #[test]
    fn test_tls12_session_expired_fallback() {
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

        // Get a valid session from full handshake
        let session = run_full_handshake_get_session(suite);
        assert!(!session.id.is_empty());

        // Create a tiny cache (max 1 entry) and add the session
        let mut cache = InMemorySessionCache::new(1);
        let session_id = session.id.clone();
        cache.put(&session_id, session.clone());
        assert_eq!(cache.len(), 1);

        // Evict the session by adding a different one
        let other_session = TlsSession {
            id: vec![0xFF; 32],
            cipher_suite: suite,
            master_secret: vec![0xAA; 48],
            alpn_protocol: None,
            ticket: None,
            ticket_lifetime: 0,
            max_early_data: 0,
            ticket_age_add: 0,
            ticket_nonce: Vec::new(),
            created_at: 0,
            psk: Vec::new(),
        };
        cache.put(&[0xFF; 32], other_session);
        // Original session should be evicted
        assert!(cache.get(&session_id).is_none());

        // Now try to resume — should fall back to full handshake (not abbreviated)
        // Since run_abbreviated_handshake returns Err for full fallback,
        // this should fail.
        let result = run_abbreviated_handshake(suite, session, &mut cache);
        assert!(result.is_err());
        // The error message confirms it fell back to full handshake
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("expected abbreviated"));
    }
}
