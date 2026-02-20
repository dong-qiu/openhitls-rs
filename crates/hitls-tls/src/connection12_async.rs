//! Asynchronous TLS 1.2 connection wrapping an `AsyncRead + AsyncWrite` transport.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::alert::{AlertDescription, AlertLevel};
use crate::config::TlsConfig;
use crate::connection_info::ConnectionInfo;
use crate::crypt::{KeyExchangeAlg, NamedGroup};
use crate::handshake::client12::Tls12ClientHandshake;
use crate::handshake::codec::{decode_server_hello, parse_handshake_header};
use crate::handshake::codec12::{
    decode_certificate12, decode_certificate_request12, decode_server_key_exchange,
    decode_server_key_exchange_dhe, decode_server_key_exchange_dhe_anon,
    decode_server_key_exchange_dhe_psk, decode_server_key_exchange_ecdhe_anon,
    decode_server_key_exchange_ecdhe_psk, decode_server_key_exchange_psk_hint,
};
use crate::handshake::server12::{ServerHelloResult, Tls12ServerHandshake};
use crate::handshake::HandshakeType;
use crate::record::{ContentType, RecordLayer};
use crate::session::TlsSession;
use crate::{AsyncTlsConnection, CipherSuite, TlsError, TlsVersion};
use zeroize::Zeroize;

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    Handshaking,
    Connected,
    Renegotiating,
    Closed,
    Error,
}

// ===========================================================================
// Async TLS 1.2 Client Connection
// ===========================================================================

/// An asynchronous TLS 1.2 client connection.
pub struct AsyncTls12ClientConnection<S: AsyncRead + AsyncWrite + Unpin> {
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
    /// Client verify_data from last handshake (for renegotiation).
    client_verify_data: Vec<u8>,
    /// Server verify_data from last handshake (for renegotiation).
    server_verify_data: Vec<u8>,
    /// Peer certificates (DER-encoded, leaf first).
    peer_certificates: Vec<Vec<u8>>,
    /// Negotiated ALPN protocol (if any).
    negotiated_alpn: Option<Vec<u8>>,
    /// Server name used for this connection.
    server_name_used: Option<String>,
    /// Negotiated key exchange group (if applicable).
    negotiated_group: Option<NamedGroup>,
    /// Whether this connection was resumed from a previous session.
    session_resumed: bool,
    /// Whether we have sent close_notify.
    sent_close_notify: bool,
    /// Whether we have received close_notify.
    received_close_notify: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncTls12ClientConnection<S> {
    /// Create a new async TLS 1.2 client connection wrapping the given stream.
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
            client_verify_data: Vec::new(),
            server_verify_data: Vec::new(),
            peer_certificates: Vec::new(),
            negotiated_alpn: None,
            server_name_used: None,
            negotiated_group: None,
            session_resumed: false,
            sent_close_notify: false,
            received_close_notify: false,
        }
    }

    /// Take the session state (with ticket if applicable) for later resumption.
    pub fn take_session(&mut self) -> Option<TlsSession> {
        self.session.take()
    }

    /// Get a snapshot of the negotiated connection parameters.
    /// Returns `None` if the handshake has not completed.
    pub fn connection_info(&self) -> Option<ConnectionInfo> {
        self.negotiated_suite.map(|suite| ConnectionInfo {
            cipher_suite: suite,
            peer_certificates: self.peer_certificates.clone(),
            alpn_protocol: self.negotiated_alpn.clone(),
            server_name: self.server_name_used.clone(),
            negotiated_group: self.negotiated_group,
            session_resumed: self.session_resumed,
            peer_verify_data: self.server_verify_data.clone(),
            local_verify_data: self.client_verify_data.clone(),
        })
    }

    /// Get the peer's certificate chain (DER-encoded, leaf first).
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.peer_certificates
    }

    /// Get the negotiated ALPN protocol (if any).
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
    }

    /// Get the server name (SNI) used for this connection.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name_used.as_deref()
    }

    /// Get the negotiated key exchange group (if applicable).
    pub fn negotiated_group(&self) -> Option<NamedGroup> {
        self.negotiated_group
    }

    /// Whether this connection was resumed from a previous session.
    pub fn is_session_resumed(&self) -> bool {
        self.session_resumed
    }

    /// Get the peer's Finished verify_data.
    pub fn peer_verify_data(&self) -> &[u8] {
        &self.server_verify_data
    }

    /// Get the local Finished verify_data.
    pub fn local_verify_data(&self) -> &[u8] {
        &self.client_verify_data
    }

    /// Read at least `min_bytes` from the stream into read_buf.
    async fn fill_buf(&mut self, min_bytes: usize) -> Result<(), TlsError> {
        while self.read_buf.len() < min_bytes {
            let mut tmp = [0u8; 16384];
            let n = self
                .stream
                .read(&mut tmp)
                .await
                .map_err(|e| TlsError::RecordError(format!("read error: {e}")))?;
            if n == 0 {
                return Err(TlsError::RecordError("unexpected EOF".into()));
            }
            self.read_buf.extend_from_slice(&tmp[..n]);
        }
        Ok(())
    }

    /// Read a single record from the stream.
    async fn read_record(&mut self) -> Result<(ContentType, Vec<u8>), TlsError> {
        self.fill_buf(5).await?;
        let length = u16::from_be_bytes([self.read_buf[3], self.read_buf[4]]) as usize;
        self.fill_buf(5 + length).await?;
        let (ct, plaintext, consumed) = self.record_layer.open_record(&self.read_buf)?;
        self.read_buf.drain(..consumed);
        Ok((ct, plaintext))
    }

    /// Read a handshake message from the stream.
    /// Returns (handshake_type, full_message_bytes_including_header).
    async fn read_handshake_msg(&mut self) -> Result<(HandshakeType, Vec<u8>), TlsError> {
        let (ct, data) = self.read_record().await?;
        if ct != ContentType::Handshake {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Handshake, got {ct:?}"
            )));
        }
        let (hs_type, _, total) = parse_handshake_header(&data)?;
        Ok((hs_type, data[..total].to_vec()))
    }

    /// Run the TLS 1.2 client handshake.
    async fn do_handshake(&mut self) -> Result<(), TlsError> {
        // Auto-lookup: if no explicit resumption_session, check cache
        if self.config.resumption_session.is_none() && self.config.session_resumption {
            if let (Some(ref cache_mutex), Some(ref server_name)) =
                (&self.config.session_cache, &self.config.server_name)
            {
                if let Ok(cache) = cache_mutex.lock() {
                    if let Some(cached) = cache.get(server_name.as_bytes()) {
                        self.config.resumption_session = Some(cached.clone());
                    }
                }
            }
        }

        let mut hs = Tls12ClientHandshake::new(self.config.clone());

        // 1. Build and send ClientHello
        let ch_msg = hs.build_client_hello()?;
        let ch_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &ch_msg)?;
        self.stream
            .write_all(&ch_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 2. Read ServerHello
        let (hs_type, sh_data) = self.read_handshake_msg().await?;
        if hs_type != HandshakeType::ServerHello {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ServerHello, got {hs_type:?}"
            )));
        }
        let (_, sh_body, _) = parse_handshake_header(&sh_data)?;
        let sh = decode_server_hello(sh_body)?;
        let suite = hs.process_server_hello(&sh_data, &sh)?;

        // Apply negotiated max fragment length (RFC 6066) — lower priority than RSL
        if let Some(mfl) = hs.negotiated_max_fragment_length() {
            self.record_layer.max_fragment_size = mfl.to_size();
        }

        // Apply peer's record size limit (TLS 1.2: no adjustment) — overrides MFL
        if let Some(limit) = hs.peer_record_size_limit() {
            self.record_layer.max_fragment_size = limit as usize;
        }

        // Check for abbreviated handshake (session resumption)
        if hs.is_abbreviated() {
            return self.do_client_abbreviated(&mut hs, suite).await;
        }

        // 3. Read Certificate (only for KX that requires it)
        let (hs_type, next_data) = if hs.kx_alg().requires_certificate() {
            let (hs_type, cert_data) = self.read_handshake_msg().await?;
            if hs_type != HandshakeType::Certificate {
                return Err(TlsError::HandshakeFailed(format!(
                    "expected Certificate, got {hs_type:?}"
                )));
            }
            let (_, cert_body, _) = parse_handshake_header(&cert_data)?;
            let cert12 = decode_certificate12(cert_body)?;
            hs.process_certificate(&cert_data, &cert12.certificate_list)?;
            self.read_handshake_msg().await?
        } else {
            self.read_handshake_msg().await?
        };

        // 4. Read ServerKeyExchange or skip
        let (hs_type, next_data) = if hs_type == HandshakeType::ServerKeyExchange {
            let (_, ske_body, _) = parse_handshake_header(&next_data)?;
            match hs.kx_alg() {
                KeyExchangeAlg::Ecdhe => {
                    let ske = decode_server_key_exchange(ske_body)?;
                    hs.process_server_key_exchange(&next_data, &ske)?;
                }
                KeyExchangeAlg::Dhe => {
                    let ske = decode_server_key_exchange_dhe(ske_body)?;
                    hs.process_server_key_exchange_dhe(&next_data, &ske)?;
                }
                KeyExchangeAlg::Psk | KeyExchangeAlg::RsaPsk => {
                    let ske = decode_server_key_exchange_psk_hint(ske_body)?;
                    hs.process_server_key_exchange_psk_hint(&next_data, &ske)?;
                }
                KeyExchangeAlg::DhePsk => {
                    let ske = decode_server_key_exchange_dhe_psk(ske_body)?;
                    hs.process_server_key_exchange_dhe_psk(&next_data, &ske)?;
                }
                KeyExchangeAlg::EcdhePsk => {
                    let ske = decode_server_key_exchange_ecdhe_psk(ske_body)?;
                    hs.process_server_key_exchange_ecdhe_psk(&next_data, &ske)?;
                }
                KeyExchangeAlg::DheAnon => {
                    let ske = decode_server_key_exchange_dhe_anon(ske_body)?;
                    hs.process_server_key_exchange_dhe_anon(&next_data, &ske)?;
                }
                KeyExchangeAlg::EcdheAnon => {
                    let ske = decode_server_key_exchange_ecdhe_anon(ske_body)?;
                    hs.process_server_key_exchange_ecdhe_anon(&next_data, &ske)?;
                }
                KeyExchangeAlg::Rsa => {
                    return Err(TlsError::HandshakeFailed(
                        "unexpected ServerKeyExchange for RSA key exchange".into(),
                    ));
                }
                #[cfg(feature = "tlcp")]
                KeyExchangeAlg::Ecc => {
                    return Err(TlsError::HandshakeFailed(
                        "ECC not supported in TLS 1.2".into(),
                    ));
                }
            }
            // Read the next message after SKE
            self.read_handshake_msg().await?
        } else {
            // No SKE — must be RSA or plain PSK key exchange
            if hs.kx_alg() != KeyExchangeAlg::Rsa
                && hs.kx_alg() != KeyExchangeAlg::Psk
                && hs.kx_alg() != KeyExchangeAlg::RsaPsk
            {
                return Err(TlsError::HandshakeFailed(format!(
                    "expected ServerKeyExchange for {:?}, got {hs_type:?}",
                    hs.kx_alg()
                )));
            }
            (hs_type, next_data)
        };

        // 5. Read CertificateRequest (optional) or ServerHelloDone
        let shd_data = if hs_type == HandshakeType::CertificateRequest {
            let (_, cr_body, _) = parse_handshake_header(&next_data)?;
            let cr = decode_certificate_request12(cr_body)?;
            hs.process_certificate_request(&next_data, &cr)?;
            // Now read the actual ServerHelloDone
            let (hs_type, shd_data) = self.read_handshake_msg().await?;
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

        // 6. Process ServerHelloDone -> generates client flight
        let mut flight = hs.process_server_hello_done(&shd_data)?;

        // 7. Send client Certificate (if mTLS requested)
        if let Some(ref cert_msg) = flight.client_certificate {
            let cert_record = self
                .record_layer
                .seal_record(ContentType::Handshake, cert_msg)?;
            self.stream
                .write_all(&cert_record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // 8. Send ClientKeyExchange (plaintext)
        let cke_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &flight.client_key_exchange)?;
        self.stream
            .write_all(&cke_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 9. Send CertificateVerify (if mTLS with client cert)
        if let Some(ref cv_msg) = flight.certificate_verify {
            let cv_record = self
                .record_layer
                .seal_record(ContentType::Handshake, cv_msg)?;
            self.stream
                .write_all(&cv_record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // 10. Send ChangeCipherSpec
        let ccs_record = self
            .record_layer
            .seal_record(ContentType::ChangeCipherSpec, &[0x01])?;
        self.stream
            .write_all(&ccs_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 9. Activate write encryption
        if flight.is_cbc && hs.use_encrypt_then_mac() {
            self.record_layer.activate_write_encryption12_etm(
                flight.client_write_key.clone(),
                flight.client_write_mac_key.clone(),
                flight.mac_len,
            );
        } else if flight.is_cbc {
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
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 11. Read NewSessionTicket (optional) then server ChangeCipherSpec
        loop {
            let (ct, data) = self.read_record().await?;
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
        if flight.is_cbc && hs.use_encrypt_then_mac() {
            self.record_layer.activate_read_decryption12_etm(
                flight.server_write_key.clone(),
                flight.server_write_mac_key.clone(),
                flight.mac_len,
            );
        } else if flight.is_cbc {
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
        let (hs_type, fin_data) = self.read_handshake_msg().await?;
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
            extended_master_secret: hs.use_extended_master_secret(),
        });

        // Auto-store in client session cache
        if let (Some(ref cache_mutex), Some(ref server_name)) =
            (&self.config.session_cache, &self.config.server_name)
        {
            if let Ok(mut cache) = cache_mutex.lock() {
                if let Some(ref session) = self.session {
                    cache.put(server_name.as_bytes(), session.clone());
                }
            }
        }

        // Zeroize secrets
        flight.master_secret.zeroize();
        flight.client_write_key.zeroize();
        flight.server_write_key.zeroize();

        self.negotiated_suite = Some(suite);
        self.client_verify_data = hs.client_verify_data().to_vec();
        self.server_verify_data = hs.server_verify_data().to_vec();
        self.peer_certificates = hs.server_certs().to_vec();
        self.negotiated_alpn = hs.negotiated_alpn().map(|a| a.to_vec());
        self.server_name_used = self.config.server_name.clone();
        let nc = hs.server_named_curve();
        if nc != 0 {
            self.negotiated_group = Some(NamedGroup(nc));
        }
        self.session_resumed = false;
        self.state = ConnectionState::Connected;
        Ok(())
    }

    /// Abbreviated handshake path (client side, session resumption via ticket or ID).
    async fn do_client_abbreviated(
        &mut self,
        hs: &mut Tls12ClientHandshake,
        suite: CipherSuite,
    ) -> Result<(), TlsError> {
        let mut keys = hs
            .take_abbreviated_keys()
            .ok_or_else(|| TlsError::HandshakeFailed("no abbreviated keys".into()))?;

        // 1. Read optional NewSessionTicket then CCS from server
        loop {
            let (ct, data) = self.read_record().await?;
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
        if keys.is_cbc && hs.use_encrypt_then_mac() {
            self.record_layer.activate_read_decryption12_etm(
                keys.server_write_key.clone(),
                keys.server_write_mac_key.clone(),
                keys.mac_len,
            );
        } else if keys.is_cbc {
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
        let (hs_type, fin_data) = self.read_handshake_msg().await?;
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
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 5. Activate write encryption (client write key)
        if keys.is_cbc && hs.use_encrypt_then_mac() {
            self.record_layer.activate_write_encryption12_etm(
                keys.client_write_key.clone(),
                keys.client_write_mac_key.clone(),
                keys.mac_len,
            );
        } else if keys.is_cbc {
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
            .await
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
            extended_master_secret: hs.use_extended_master_secret(),
        });

        // Auto-store in client session cache
        if let (Some(ref cache_mutex), Some(ref server_name)) =
            (&self.config.session_cache, &self.config.server_name)
        {
            if let Ok(mut cache) = cache_mutex.lock() {
                if let Some(ref session) = self.session {
                    cache.put(server_name.as_bytes(), session.clone());
                }
            }
        }

        // Zeroize secrets
        keys.master_secret.zeroize();
        keys.client_write_key.zeroize();
        keys.server_write_key.zeroize();

        self.negotiated_suite = Some(suite);
        self.client_verify_data = hs.client_verify_data().to_vec();
        self.server_verify_data = hs.server_verify_data().to_vec();
        self.negotiated_alpn = hs.negotiated_alpn().map(|a| a.to_vec());
        self.server_name_used = self.config.server_name.clone();
        self.session_resumed = true;
        self.state = ConnectionState::Connected;
        Ok(())
    }

    /// Perform client-side renegotiation (RFC 5746).
    ///
    /// Creates a new handshake, sets verify_data for renegotiation_info,
    /// runs the full handshake over the encrypted connection, and re-keys.
    async fn do_renegotiation(&mut self) -> Result<(), TlsError> {
        self.state = ConnectionState::Renegotiating;

        let mut hs = Tls12ClientHandshake::new(self.config.clone());
        // Set previous verify_data for RFC 5746
        hs.setup_renegotiation(
            std::mem::take(&mut self.client_verify_data),
            std::mem::take(&mut self.server_verify_data),
        );

        // Build and send ClientHello (over encrypted connection)
        let ch_msg = hs.build_client_hello()?;
        let ch_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &ch_msg)?;
        self.stream
            .write_all(&ch_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Read ServerHello
        let (hs_type, sh_data) = self.read_handshake_msg().await?;
        if hs_type != HandshakeType::ServerHello {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ServerHello, got {hs_type:?}"
            )));
        }
        let (_, sh_body, _) = parse_handshake_header(&sh_data)?;
        let sh = decode_server_hello(sh_body)?;
        let suite = hs.process_server_hello(&sh_data, &sh)?;

        // Renegotiation always does full handshake (no abbreviation)
        if hs.is_abbreviated() {
            return Err(TlsError::HandshakeFailed(
                "unexpected session resumption during renegotiation".into(),
            ));
        }

        // Read Certificate (only for KX that requires it)
        let (hs_type, next_data) = if hs.kx_alg().requires_certificate() {
            let (hs_type, cert_data) = self.read_handshake_msg().await?;
            if hs_type != HandshakeType::Certificate {
                return Err(TlsError::HandshakeFailed(format!(
                    "expected Certificate, got {hs_type:?}"
                )));
            }
            let (_, cert_body, _) = parse_handshake_header(&cert_data)?;
            let cert12 = decode_certificate12(cert_body)?;
            hs.process_certificate(&cert_data, &cert12.certificate_list)?;
            self.read_handshake_msg().await?
        } else {
            self.read_handshake_msg().await?
        };

        // Handle optional CertificateStatus
        let (hs_type, next_data) = if hs_type == HandshakeType::CertificateStatus {
            self.read_handshake_msg().await?
        } else {
            (hs_type, next_data)
        };

        // Read ServerKeyExchange or skip
        let (hs_type, next_data) = if hs_type == HandshakeType::ServerKeyExchange {
            let (_, ske_body, _) = parse_handshake_header(&next_data)?;
            match hs.kx_alg() {
                KeyExchangeAlg::Ecdhe => {
                    let ske = decode_server_key_exchange(ske_body)?;
                    hs.process_server_key_exchange(&next_data, &ske)?;
                }
                KeyExchangeAlg::Dhe => {
                    let ske = decode_server_key_exchange_dhe(ske_body)?;
                    hs.process_server_key_exchange_dhe(&next_data, &ske)?;
                }
                KeyExchangeAlg::Psk | KeyExchangeAlg::RsaPsk => {
                    let ske = decode_server_key_exchange_psk_hint(ske_body)?;
                    hs.process_server_key_exchange_psk_hint(&next_data, &ske)?;
                }
                KeyExchangeAlg::DhePsk => {
                    let ske = decode_server_key_exchange_dhe_psk(ske_body)?;
                    hs.process_server_key_exchange_dhe_psk(&next_data, &ske)?;
                }
                KeyExchangeAlg::EcdhePsk => {
                    let ske = decode_server_key_exchange_ecdhe_psk(ske_body)?;
                    hs.process_server_key_exchange_ecdhe_psk(&next_data, &ske)?;
                }
                KeyExchangeAlg::DheAnon => {
                    let ske = decode_server_key_exchange_dhe_anon(ske_body)?;
                    hs.process_server_key_exchange_dhe_anon(&next_data, &ske)?;
                }
                KeyExchangeAlg::EcdheAnon => {
                    let ske = decode_server_key_exchange_ecdhe_anon(ske_body)?;
                    hs.process_server_key_exchange_ecdhe_anon(&next_data, &ske)?;
                }
                _ => {
                    return Err(TlsError::HandshakeFailed(
                        "unexpected ServerKeyExchange for this key exchange".into(),
                    ));
                }
            }
            self.read_handshake_msg().await?
        } else {
            if hs.kx_alg() != KeyExchangeAlg::Rsa
                && hs.kx_alg() != KeyExchangeAlg::Psk
                && hs.kx_alg() != KeyExchangeAlg::RsaPsk
            {
                return Err(TlsError::HandshakeFailed(format!(
                    "expected ServerKeyExchange for {:?}, got {hs_type:?}",
                    hs.kx_alg()
                )));
            }
            (hs_type, next_data)
        };

        // Read CertificateRequest (optional) or ServerHelloDone
        let shd_data = if hs_type == HandshakeType::CertificateRequest {
            let (_, cr_body, _) = parse_handshake_header(&next_data)?;
            let cr = decode_certificate_request12(cr_body)?;
            hs.process_certificate_request(&next_data, &cr)?;
            let (hs_type, shd_data) = self.read_handshake_msg().await?;
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

        // Process ServerHelloDone
        let mut flight = hs.process_server_hello_done(&shd_data)?;

        // Send client Certificate (if mTLS requested)
        if let Some(ref cert_msg) = flight.client_certificate {
            let cert_record = self
                .record_layer
                .seal_record(ContentType::Handshake, cert_msg)?;
            self.stream
                .write_all(&cert_record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // Send ClientKeyExchange
        let cke_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &flight.client_key_exchange)?;
        self.stream
            .write_all(&cke_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Send CertificateVerify (if mTLS)
        if let Some(ref cv_msg) = flight.certificate_verify {
            let cv_record = self
                .record_layer
                .seal_record(ContentType::Handshake, cv_msg)?;
            self.stream
                .write_all(&cv_record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // Send ChangeCipherSpec
        let ccs_record = self
            .record_layer
            .seal_record(ContentType::ChangeCipherSpec, &[0x01])?;
        self.stream
            .write_all(&ccs_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Activate write encryption (re-key)
        if flight.is_cbc && hs.use_encrypt_then_mac() {
            self.record_layer.activate_write_encryption12_etm(
                flight.client_write_key.clone(),
                flight.client_write_mac_key.clone(),
                flight.mac_len,
            );
        } else if flight.is_cbc {
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

        // Send Finished (encrypted with new keys)
        let fin_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &flight.finished)?;
        self.stream
            .write_all(&fin_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Read NewSessionTicket (optional) then server ChangeCipherSpec
        loop {
            let (ct, data) = self.read_record().await?;
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
                        "expected ChangeCipherSpec, got {ct:?}"
                    )));
                }
            }
        }

        // Activate read decryption (re-key)
        if flight.is_cbc && hs.use_encrypt_then_mac() {
            self.record_layer.activate_read_decryption12_etm(
                flight.server_write_key.clone(),
                flight.server_write_mac_key.clone(),
                flight.mac_len,
            );
        } else if flight.is_cbc {
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

        // Read server Finished (encrypted with new keys)
        let (hs_type, fin_data) = self.read_handshake_msg().await?;
        if hs_type != HandshakeType::Finished {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Finished, got {hs_type:?}"
            )));
        }
        hs.process_finished(&fin_data, &flight.master_secret)?;

        // Zeroize secrets
        flight.master_secret.zeroize();
        flight.client_write_key.zeroize();
        flight.server_write_key.zeroize();

        self.negotiated_suite = Some(suite);
        self.client_verify_data = hs.client_verify_data().to_vec();
        self.server_verify_data = hs.server_verify_data().to_vec();
        self.peer_certificates = hs.server_certs().to_vec();
        self.negotiated_alpn = hs.negotiated_alpn().map(|a| a.to_vec());
        self.server_name_used = self.config.server_name.clone();
        let nc = hs.server_named_curve();
        if nc != 0 {
            self.negotiated_group = Some(NamedGroup(nc));
        }
        self.state = ConnectionState::Connected;
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncTlsConnection for AsyncTls12ClientConnection<S> {
    async fn handshake(&mut self) -> Result<(), TlsError> {
        if self.state != ConnectionState::Handshaking {
            return Err(TlsError::HandshakeFailed(
                "handshake already completed or failed".into(),
            ));
        }
        match self.do_handshake().await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.state = ConnectionState::Error;
                Err(e)
            }
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if self.state != ConnectionState::Connected {
            return Err(TlsError::RecordError(
                "not connected (handshake not done)".into(),
            ));
        }

        loop {
            // Return buffered data first
            if !self.app_data_buf.is_empty() {
                let n = std::cmp::min(buf.len(), self.app_data_buf.len());
                buf[..n].copy_from_slice(&self.app_data_buf[..n]);
                self.app_data_buf.drain(..n);
                return Ok(n);
            }

            let (ct, plaintext) = self.read_record().await?;
            match ct {
                ContentType::ApplicationData => {
                    let n = std::cmp::min(buf.len(), plaintext.len());
                    buf[..n].copy_from_slice(&plaintext[..n]);
                    if plaintext.len() > n {
                        self.app_data_buf.extend_from_slice(&plaintext[n..]);
                    }
                    return Ok(n);
                }
                ContentType::Alert => {
                    if plaintext.len() >= 2 && plaintext[1] == 0 {
                        // close_notify
                        self.received_close_notify = true;
                    }
                    self.state = ConnectionState::Closed;
                    return Ok(0);
                }
                ContentType::Handshake => {
                    // Check for HelloRequest (type 0)
                    if plaintext.len() >= 4 && plaintext[0] == 0x00 {
                        if !self.config.allow_renegotiation {
                            // Send warning alert no_renegotiation and continue
                            let alert_data = [
                                AlertLevel::Warning as u8,
                                AlertDescription::NoRenegotiation as u8,
                            ];
                            let record = self
                                .record_layer
                                .seal_record(ContentType::Alert, &alert_data)?;
                            let _ = self.stream.write_all(&record).await;
                            continue;
                        }
                        // Perform renegotiation
                        self.do_renegotiation().await?;
                        continue;
                    }
                    return Err(TlsError::RecordError(
                        "unexpected handshake message during application data".into(),
                    ));
                }
                _ => {
                    return Err(TlsError::RecordError(format!(
                        "unexpected content type: {ct:?}"
                    )));
                }
            }
        }
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        if self.state != ConnectionState::Connected {
            return Err(TlsError::RecordError(
                "not connected (handshake not done)".into(),
            ));
        }

        if buf.is_empty() {
            return Ok(0);
        }

        let max_frag = self.record_layer.max_fragment_size;
        let mut offset = 0;
        while offset < buf.len() {
            let end = std::cmp::min(offset + max_frag, buf.len());
            let record = self
                .record_layer
                .seal_record(ContentType::ApplicationData, &buf[offset..end])?;
            self.stream
                .write_all(&record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
            offset = end;
        }
        Ok(buf.len())
    }

    async fn shutdown(&mut self) -> Result<(), TlsError> {
        if self.state == ConnectionState::Closed {
            return Ok(());
        }
        if !self.config.quiet_shutdown && !self.sent_close_notify {
            let alert_data = [1u8, 0u8]; // close_notify
            let record = self
                .record_layer
                .seal_record(ContentType::Alert, &alert_data)?;
            let _ = self.stream.write_all(&record).await;
            self.sent_close_notify = true;
        }
        self.state = ConnectionState::Closed;
        Ok(())
    }

    fn version(&self) -> Option<TlsVersion> {
        if self.state == ConnectionState::Connected || self.state == ConnectionState::Closed {
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
// Async TLS 1.2 Server Connection
// ===========================================================================

/// An asynchronous TLS 1.2 server connection.
pub struct AsyncTls12ServerConnection<S: AsyncRead + AsyncWrite + Unpin> {
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
    /// Client verify_data from last handshake (for renegotiation).
    client_verify_data: Vec<u8>,
    /// Server verify_data from last handshake (for renegotiation).
    server_verify_data: Vec<u8>,
    /// Peer certificates (DER-encoded, leaf first).
    peer_certificates: Vec<Vec<u8>>,
    /// Negotiated ALPN protocol (if any).
    negotiated_alpn: Option<Vec<u8>>,
    /// Client's SNI hostname.
    client_server_name: Option<String>,
    /// Negotiated key exchange group (if applicable).
    negotiated_group: Option<NamedGroup>,
    /// Whether this connection was resumed from a previous session.
    session_resumed: bool,
    /// Whether we have sent close_notify.
    sent_close_notify: bool,
    /// Whether we have received close_notify.
    received_close_notify: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncTls12ServerConnection<S> {
    /// Create a new async TLS 1.2 server connection wrapping the given stream.
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
            client_verify_data: Vec::new(),
            server_verify_data: Vec::new(),
            peer_certificates: Vec::new(),
            negotiated_alpn: None,
            client_server_name: None,
            negotiated_group: None,
            session_resumed: false,
            sent_close_notify: false,
            received_close_notify: false,
        }
    }

    /// Take the session state (for session caching on server side).
    pub fn take_session(&mut self) -> Option<TlsSession> {
        self.session.take()
    }

    /// Get a snapshot of the negotiated connection parameters.
    /// Returns `None` if the handshake has not completed.
    pub fn connection_info(&self) -> Option<ConnectionInfo> {
        self.negotiated_suite.map(|suite| ConnectionInfo {
            cipher_suite: suite,
            peer_certificates: self.peer_certificates.clone(),
            alpn_protocol: self.negotiated_alpn.clone(),
            server_name: self.client_server_name.clone(),
            negotiated_group: self.negotiated_group,
            session_resumed: self.session_resumed,
            peer_verify_data: self.client_verify_data.clone(),
            local_verify_data: self.server_verify_data.clone(),
        })
    }

    /// Get the peer's certificate chain (DER-encoded, leaf first).
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.peer_certificates
    }

    /// Get the negotiated ALPN protocol (if any).
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
    }

    /// Get the client's SNI hostname.
    pub fn server_name(&self) -> Option<&str> {
        self.client_server_name.as_deref()
    }

    /// Get the negotiated key exchange group (if applicable).
    pub fn negotiated_group(&self) -> Option<NamedGroup> {
        self.negotiated_group
    }

    /// Whether this connection was resumed from a previous session.
    pub fn is_session_resumed(&self) -> bool {
        self.session_resumed
    }

    /// Get the peer's Finished verify_data.
    pub fn peer_verify_data(&self) -> &[u8] {
        &self.client_verify_data
    }

    /// Get the local Finished verify_data.
    pub fn local_verify_data(&self) -> &[u8] {
        &self.server_verify_data
    }

    /// Read at least `min_bytes` from the stream into read_buf.
    async fn fill_buf(&mut self, min_bytes: usize) -> Result<(), TlsError> {
        while self.read_buf.len() < min_bytes {
            let mut tmp = [0u8; 16384];
            let n = self
                .stream
                .read(&mut tmp)
                .await
                .map_err(|e| TlsError::RecordError(format!("read error: {e}")))?;
            if n == 0 {
                return Err(TlsError::RecordError("unexpected EOF".into()));
            }
            self.read_buf.extend_from_slice(&tmp[..n]);
        }
        Ok(())
    }

    /// Read a single record from the stream.
    async fn read_record(&mut self) -> Result<(ContentType, Vec<u8>), TlsError> {
        self.fill_buf(5).await?;
        let length = u16::from_be_bytes([self.read_buf[3], self.read_buf[4]]) as usize;
        self.fill_buf(5 + length).await?;
        let (ct, plaintext, consumed) = self.record_layer.open_record(&self.read_buf)?;
        self.read_buf.drain(..consumed);
        Ok((ct, plaintext))
    }

    /// Read a handshake message from the stream.
    async fn read_handshake_msg(&mut self) -> Result<(HandshakeType, Vec<u8>), TlsError> {
        let (ct, data) = self.read_record().await?;
        if ct != ContentType::Handshake {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Handshake, got {ct:?}"
            )));
        }
        let (hs_type, _, total) = parse_handshake_header(&data)?;
        Ok((hs_type, data[..total].to_vec()))
    }

    /// Run the TLS 1.2 server handshake.
    async fn do_handshake(&mut self) -> Result<(), TlsError> {
        let mut hs = Tls12ServerHandshake::new(self.config.clone());

        // 1. Read ClientHello
        let (hs_type, ch_data) = self.read_handshake_msg().await?;
        if hs_type != HandshakeType::ClientHello {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ClientHello, got {hs_type:?}"
            )));
        }

        // 2. Process ClientHello (with ticket support + session ID cache)
        // Use a block to ensure MutexGuard is dropped before any .await
        let result = {
            let cache_ref = self
                .config
                .session_cache
                .as_ref()
                .map(|c| c.lock().unwrap());
            hs.process_client_hello_resumable(
                &ch_data,
                cache_ref
                    .as_deref()
                    .map(|c| c as &dyn crate::session::SessionCache),
            )?
        };

        // Apply client's max fragment length (RFC 6066) — lower priority than RSL
        if let Some(mfl) = hs.client_max_fragment_length() {
            self.record_layer.max_fragment_size = mfl.to_size();
        }

        // Apply client's record size limit (TLS 1.2: no adjustment) — overrides MFL
        if let Some(limit) = hs.client_record_size_limit() {
            self.record_layer.max_fragment_size = limit as usize;
        }

        match result {
            ServerHelloResult::Full(flight) => {
                self.do_full_handshake(&mut hs, flight).await?;
            }
            ServerHelloResult::Abbreviated(abbr) => {
                self.do_abbreviated_handshake(&mut hs, abbr).await?;
            }
        }

        Ok(())
    }

    /// Full handshake path (with optional NewSessionTicket).
    async fn do_full_handshake(
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
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 4. Send Certificate (if present -- PSK suites skip this)
        if let Some(ref cert_msg) = flight.certificate {
            let cert_record = self
                .record_layer
                .seal_record(ContentType::Handshake, cert_msg)?;
            self.stream
                .write_all(&cert_record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // 4b. Send CertificateStatus (if OCSP stapling, RFC 6066)
        if let Some(ref cs_msg) = flight.certificate_status {
            let cs_record = self
                .record_layer
                .seal_record(ContentType::Handshake, cs_msg)?;
            self.stream
                .write_all(&cs_record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // 5. Send ServerKeyExchange (if present -- not sent for RSA key exchange)
        if let Some(ref ske_msg) = flight.server_key_exchange {
            let ske_record = self
                .record_layer
                .seal_record(ContentType::Handshake, ske_msg)?;
            self.stream
                .write_all(&ske_record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // 6. Send CertificateRequest (if mTLS enabled)
        if let Some(ref cr_msg) = flight.certificate_request {
            let cr_record = self
                .record_layer
                .seal_record(ContentType::Handshake, cr_msg)?;
            self.stream
                .write_all(&cr_record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // 7. Send ServerHelloDone
        let shd_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &flight.server_hello_done)?;
        self.stream
            .write_all(&shd_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 8. Read client Certificate (if mTLS)
        if flight.certificate_request.is_some() {
            let (hs_type, cert_data) = self.read_handshake_msg().await?;
            if hs_type != HandshakeType::Certificate {
                return Err(TlsError::HandshakeFailed(format!(
                    "expected client Certificate, got {hs_type:?}"
                )));
            }
            hs.process_client_certificate(&cert_data)?;
        }

        // 9. Read ClientKeyExchange
        let (hs_type, cke_data) = self.read_handshake_msg().await?;
        if hs_type != HandshakeType::ClientKeyExchange {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ClientKeyExchange, got {hs_type:?}"
            )));
        }
        let mut keys = hs.process_client_key_exchange(&cke_data)?;

        // 10. Read client CertificateVerify (if client sent certs)
        if hs.state() == crate::handshake::server12::Tls12ServerState::WaitClientCertificateVerify {
            let (hs_type, cv_data) = self.read_handshake_msg().await?;
            if hs_type != HandshakeType::CertificateVerify {
                return Err(TlsError::HandshakeFailed(format!(
                    "expected CertificateVerify, got {hs_type:?}"
                )));
            }
            hs.process_client_certificate_verify(&cv_data)?;
        }

        // 11. Read ChangeCipherSpec from client
        let (ct, _ccs_data) = self.read_record().await?;
        if ct != ContentType::ChangeCipherSpec {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ChangeCipherSpec, got {ct:?}"
            )));
        }
        hs.process_change_cipher_spec()?;

        // 12. Activate read decryption (client write key)
        if keys.is_cbc && hs.use_encrypt_then_mac() {
            self.record_layer.activate_read_decryption12_etm(
                keys.client_write_key.clone(),
                keys.client_write_mac_key.clone(),
                keys.mac_len,
            );
        } else if keys.is_cbc {
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
        let (hs_type, fin_data) = self.read_handshake_msg().await?;
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
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // 15. Send ChangeCipherSpec
        let ccs_record = self
            .record_layer
            .seal_record(ContentType::ChangeCipherSpec, &[0x01])?;
        self.stream
            .write_all(&ccs_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 16. Activate write encryption (server write key)
        if keys.is_cbc && hs.use_encrypt_then_mac() {
            self.record_layer.activate_write_encryption12_etm(
                keys.server_write_key.clone(),
                keys.server_write_mac_key.clone(),
                keys.mac_len,
            );
        } else if keys.is_cbc {
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
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Store session in cache before zeroizing master secret
        if let Some(ref cache_mutex) = self.config.session_cache {
            let session_id = hs.session_id();
            if !session_id.is_empty() {
                if let Ok(mut cache) = cache_mutex.lock() {
                    let session = crate::session::TlsSession {
                        id: session_id.to_vec(),
                        cipher_suite: suite,
                        master_secret: keys.master_secret.clone(),
                        alpn_protocol: hs.negotiated_alpn().map(|a| a.to_vec()),
                        ticket: None,
                        ticket_lifetime: 7200,
                        max_early_data: 0,
                        ticket_age_add: 0,
                        ticket_nonce: Vec::new(),
                        created_at: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        psk: Vec::new(),
                        extended_master_secret: hs.use_extended_master_secret(),
                    };
                    let sid = session.id.clone();
                    cache.put(&sid, session);
                }
            }
        }

        // Zeroize secrets
        keys.master_secret.zeroize();
        keys.client_write_key.zeroize();
        keys.server_write_key.zeroize();

        self.negotiated_suite = Some(suite);
        self.client_verify_data = hs.client_verify_data().to_vec();
        self.server_verify_data = hs.server_verify_data().to_vec();
        self.peer_certificates = hs.client_certs().to_vec();
        self.negotiated_alpn = hs.negotiated_alpn().map(|a| a.to_vec());
        self.client_server_name = hs.client_server_name().map(|s| s.to_string());
        self.session_resumed = false;
        self.state = ConnectionState::Connected;
        Ok(())
    }

    /// Abbreviated handshake path (session ticket or session ID resumption).
    async fn do_abbreviated_handshake(
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
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 2. Send NewSessionTicket (plaintext) if ticket_key configured
        if let Some(nst_msg) = hs.build_new_session_ticket(suite, 3600)? {
            let nst_record = self
                .record_layer
                .seal_record(ContentType::Handshake, &nst_msg)?;
            self.stream
                .write_all(&nst_record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // 3. Send CCS
        let ccs_record = self
            .record_layer
            .seal_record(ContentType::ChangeCipherSpec, &[0x01])?;
        self.stream
            .write_all(&ccs_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 4. Activate write encryption (server write key)
        if abbr.is_cbc && hs.use_encrypt_then_mac() {
            self.record_layer.activate_write_encryption12_etm(
                abbr.server_write_key.clone(),
                abbr.server_write_mac_key.clone(),
                abbr.mac_len,
            );
        } else if abbr.is_cbc {
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
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 6. Read client CCS
        let (ct, _ccs_data) = self.read_record().await?;
        if ct != ContentType::ChangeCipherSpec {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ChangeCipherSpec, got {ct:?}"
            )));
        }
        hs.process_change_cipher_spec()?;

        // 7. Activate read decryption (client write key)
        if abbr.is_cbc && hs.use_encrypt_then_mac() {
            self.record_layer.activate_read_decryption12_etm(
                abbr.client_write_key.clone(),
                abbr.client_write_mac_key.clone(),
                abbr.mac_len,
            );
        } else if abbr.is_cbc {
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
        let (hs_type, fin_data) = self.read_handshake_msg().await?;
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
        self.client_verify_data = hs.client_verify_data().to_vec();
        self.server_verify_data = hs.server_verify_data().to_vec();
        self.negotiated_alpn = hs.negotiated_alpn().map(|a| a.to_vec());
        self.client_server_name = hs.client_server_name().map(|s| s.to_string());
        self.session_resumed = true;
        self.state = ConnectionState::Connected;
        Ok(())
    }

    /// Initiate server-side renegotiation (RFC 5746).
    ///
    /// Sends a HelloRequest and sets state to Renegotiating.
    /// The actual renegotiation handshake happens when the client responds
    /// with a ClientHello, processed by the server's `read()`.
    pub async fn initiate_renegotiation(&mut self) -> Result<(), TlsError> {
        if self.state != ConnectionState::Connected {
            return Err(TlsError::HandshakeFailed(
                "cannot renegotiate: not connected".into(),
            ));
        }
        if !self.config.allow_renegotiation {
            return Err(TlsError::HandshakeFailed(
                "renegotiation not allowed by config".into(),
            ));
        }

        // Send HelloRequest
        let hr = Tls12ServerHandshake::build_hello_request();
        let record = self.record_layer.seal_record(ContentType::Handshake, &hr)?;
        self.stream
            .write_all(&record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        self.state = ConnectionState::Renegotiating;
        Ok(())
    }

    /// Perform server-side renegotiation with the received ClientHello.
    async fn do_server_renegotiation(&mut self, ch_data: Vec<u8>) -> Result<(), TlsError> {
        let mut hs = Tls12ServerHandshake::new(self.config.clone());
        hs.setup_renegotiation(
            std::mem::take(&mut self.client_verify_data),
            std::mem::take(&mut self.server_verify_data),
        );

        // Use a block to ensure MutexGuard is dropped before any .await
        let result = {
            let cache_ref = self
                .config
                .session_cache
                .as_ref()
                .map(|c| c.lock().unwrap());
            hs.process_client_hello_resumable(
                &ch_data,
                cache_ref
                    .as_deref()
                    .map(|c| c as &dyn crate::session::SessionCache),
            )?
        };

        match result {
            ServerHelloResult::Full(flight) => {
                self.do_server_renego_full(&mut hs, flight).await?;
            }
            ServerHelloResult::Abbreviated(_) => {
                return Err(TlsError::HandshakeFailed(
                    "unexpected session resumption during renegotiation".into(),
                ));
            }
        }

        Ok(())
    }

    /// Full handshake path for renegotiation (reuses same logic as initial).
    async fn do_server_renego_full(
        &mut self,
        hs: &mut Tls12ServerHandshake,
        flight: crate::handshake::server12::ServerFlightResult,
    ) -> Result<(), TlsError> {
        let suite = flight.suite;

        // Send ServerHello
        let sh_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &flight.server_hello)?;
        self.stream
            .write_all(&sh_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Send Certificate (if present)
        if let Some(ref cert_msg) = flight.certificate {
            let cert_record = self
                .record_layer
                .seal_record(ContentType::Handshake, cert_msg)?;
            self.stream
                .write_all(&cert_record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // Send CertificateStatus (if OCSP stapling)
        if let Some(ref cs_msg) = flight.certificate_status {
            let cs_record = self
                .record_layer
                .seal_record(ContentType::Handshake, cs_msg)?;
            self.stream
                .write_all(&cs_record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // Send ServerKeyExchange (if present)
        if let Some(ref ske_msg) = flight.server_key_exchange {
            let ske_record = self
                .record_layer
                .seal_record(ContentType::Handshake, ske_msg)?;
            self.stream
                .write_all(&ske_record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // Send CertificateRequest (if mTLS enabled)
        if let Some(ref cr_msg) = flight.certificate_request {
            let cr_record = self
                .record_layer
                .seal_record(ContentType::Handshake, cr_msg)?;
            self.stream
                .write_all(&cr_record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // Send ServerHelloDone
        let shd_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &flight.server_hello_done)?;
        self.stream
            .write_all(&shd_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Read client Certificate (if mTLS)
        if flight.certificate_request.is_some() {
            let (hs_type, cert_data) = self.read_handshake_msg().await?;
            if hs_type != HandshakeType::Certificate {
                return Err(TlsError::HandshakeFailed(format!(
                    "expected client Certificate, got {hs_type:?}"
                )));
            }
            hs.process_client_certificate(&cert_data)?;
        }

        // Read ClientKeyExchange
        let (hs_type, cke_data) = self.read_handshake_msg().await?;
        if hs_type != HandshakeType::ClientKeyExchange {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ClientKeyExchange, got {hs_type:?}"
            )));
        }
        let mut keys = hs.process_client_key_exchange(&cke_data)?;

        // Read client CertificateVerify (if client sent certs)
        if hs.state() == crate::handshake::server12::Tls12ServerState::WaitClientCertificateVerify {
            let (hs_type, cv_data) = self.read_handshake_msg().await?;
            if hs_type != HandshakeType::CertificateVerify {
                return Err(TlsError::HandshakeFailed(format!(
                    "expected CertificateVerify, got {hs_type:?}"
                )));
            }
            hs.process_client_certificate_verify(&cv_data)?;
        }

        // Read ChangeCipherSpec from client
        let (ct, _ccs_data) = self.read_record().await?;
        if ct != ContentType::ChangeCipherSpec {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ChangeCipherSpec, got {ct:?}"
            )));
        }
        hs.process_change_cipher_spec()?;

        // Activate read decryption (re-key with client write key)
        if keys.is_cbc && hs.use_encrypt_then_mac() {
            self.record_layer.activate_read_decryption12_etm(
                keys.client_write_key.clone(),
                keys.client_write_mac_key.clone(),
                keys.mac_len,
            );
        } else if keys.is_cbc {
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

        // Read client Finished (encrypted with new keys)
        let (hs_type, fin_data) = self.read_handshake_msg().await?;
        if hs_type != HandshakeType::Finished {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Finished, got {hs_type:?}"
            )));
        }
        let server_fin = hs.process_finished(&fin_data)?;

        // Send ChangeCipherSpec
        let ccs_record = self
            .record_layer
            .seal_record(ContentType::ChangeCipherSpec, &[0x01])?;
        self.stream
            .write_all(&ccs_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Activate write encryption (re-key with server write key)
        if keys.is_cbc && hs.use_encrypt_then_mac() {
            self.record_layer.activate_write_encryption12_etm(
                keys.server_write_key.clone(),
                keys.server_write_mac_key.clone(),
                keys.mac_len,
            );
        } else if keys.is_cbc {
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

        // Send server Finished (encrypted with new keys)
        let sfin_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &server_fin.finished)?;
        self.stream
            .write_all(&sfin_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Store session in cache before zeroizing master secret
        if let Some(ref cache_mutex) = self.config.session_cache {
            let session_id = hs.session_id();
            if !session_id.is_empty() {
                if let Ok(mut cache) = cache_mutex.lock() {
                    let session = crate::session::TlsSession {
                        id: session_id.to_vec(),
                        cipher_suite: suite,
                        master_secret: keys.master_secret.clone(),
                        alpn_protocol: hs.negotiated_alpn().map(|a| a.to_vec()),
                        ticket: None,
                        ticket_lifetime: 7200,
                        max_early_data: 0,
                        ticket_age_add: 0,
                        ticket_nonce: Vec::new(),
                        created_at: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        psk: Vec::new(),
                        extended_master_secret: hs.use_extended_master_secret(),
                    };
                    let sid = session.id.clone();
                    cache.put(&sid, session);
                }
            }
        }

        // Zeroize secrets
        keys.master_secret.zeroize();
        keys.client_write_key.zeroize();
        keys.server_write_key.zeroize();

        self.negotiated_suite = Some(suite);
        self.client_verify_data = hs.client_verify_data().to_vec();
        self.server_verify_data = hs.server_verify_data().to_vec();
        self.peer_certificates = hs.client_certs().to_vec();
        self.negotiated_alpn = hs.negotiated_alpn().map(|a| a.to_vec());
        self.client_server_name = hs.client_server_name().map(|s| s.to_string());
        self.state = ConnectionState::Connected;
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncTlsConnection for AsyncTls12ServerConnection<S> {
    async fn handshake(&mut self) -> Result<(), TlsError> {
        if self.state != ConnectionState::Handshaking {
            return Err(TlsError::HandshakeFailed(
                "handshake already completed or failed".into(),
            ));
        }
        match self.do_handshake().await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.state = ConnectionState::Error;
                Err(e)
            }
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if self.state != ConnectionState::Connected && self.state != ConnectionState::Renegotiating
        {
            return Err(TlsError::RecordError(
                "not connected (handshake not done)".into(),
            ));
        }

        loop {
            // Only return buffered data when Connected (not during renegotiation)
            if self.state == ConnectionState::Connected && !self.app_data_buf.is_empty() {
                let n = std::cmp::min(buf.len(), self.app_data_buf.len());
                buf[..n].copy_from_slice(&self.app_data_buf[..n]);
                self.app_data_buf.drain(..n);
                return Ok(n);
            }

            let (ct, plaintext) = self.read_record().await?;
            match ct {
                ContentType::ApplicationData => {
                    if self.state == ConnectionState::Renegotiating {
                        // Buffer app data during renegotiation
                        self.app_data_buf.extend_from_slice(&plaintext);
                        continue;
                    }
                    let n = std::cmp::min(buf.len(), plaintext.len());
                    buf[..n].copy_from_slice(&plaintext[..n]);
                    if plaintext.len() > n {
                        self.app_data_buf.extend_from_slice(&plaintext[n..]);
                    }
                    return Ok(n);
                }
                ContentType::Alert => {
                    // Check for no_renegotiation warning during renegotiation
                    if self.state == ConnectionState::Renegotiating
                        && plaintext.len() >= 2
                        && plaintext[0] == AlertLevel::Warning as u8
                        && plaintext[1] == AlertDescription::NoRenegotiation as u8
                    {
                        // Client refused renegotiation -- go back to Connected
                        self.state = ConnectionState::Connected;
                        continue;
                    }
                    if plaintext.len() >= 2 && plaintext[1] == 0 {
                        // close_notify
                        self.received_close_notify = true;
                    }
                    self.state = ConnectionState::Closed;
                    return Ok(0);
                }
                ContentType::Handshake => {
                    if self.state == ConnectionState::Renegotiating {
                        // Expecting ClientHello during renegotiation
                        let (hs_type, _, total) = parse_handshake_header(&plaintext)?;
                        if hs_type == HandshakeType::ClientHello {
                            let ch_data = plaintext[..total].to_vec();
                            self.do_server_renegotiation(ch_data).await?;
                            continue;
                        }
                        return Err(TlsError::HandshakeFailed(format!(
                            "expected ClientHello during renegotiation, got {hs_type:?}"
                        )));
                    }
                    return Err(TlsError::RecordError(format!(
                        "unexpected content type: {ct:?}"
                    )));
                }
                _ => {
                    return Err(TlsError::RecordError(format!(
                        "unexpected content type: {ct:?}"
                    )));
                }
            }
        }
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        if self.state != ConnectionState::Connected {
            return Err(TlsError::RecordError(
                "not connected (handshake not done)".into(),
            ));
        }

        if buf.is_empty() {
            return Ok(0);
        }

        let max_frag = self.record_layer.max_fragment_size;
        let mut offset = 0;
        while offset < buf.len() {
            let end = std::cmp::min(offset + max_frag, buf.len());
            let record = self
                .record_layer
                .seal_record(ContentType::ApplicationData, &buf[offset..end])?;
            self.stream
                .write_all(&record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
            offset = end;
        }
        Ok(buf.len())
    }

    async fn shutdown(&mut self) -> Result<(), TlsError> {
        if self.state == ConnectionState::Closed {
            return Ok(());
        }
        if !self.config.quiet_shutdown && !self.sent_close_notify {
            let alert_data = [1u8, 0u8]; // close_notify
            let record = self
                .record_layer
                .seal_record(ContentType::Alert, &alert_data)?;
            let _ = self.stream.write_all(&record).await;
            self.sent_close_notify = true;
        }
        self.state = ConnectionState::Closed;
        Ok(())
    }

    fn version(&self) -> Option<TlsVersion> {
        if self.state == ConnectionState::Connected || self.state == ConnectionState::Closed {
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
    use crate::config::{ServerPrivateKey, TlsConfig};
    use crate::crypt::NamedGroup;
    use crate::crypt::SignatureScheme;
    use crate::CipherSuite;

    fn ecdsa_private_key() -> Vec<u8> {
        vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ]
    }

    fn make_configs(suite: CipherSuite) -> (TlsConfig, TlsConfig) {
        let key_bytes = ecdsa_private_key();
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
                private_key: key_bytes,
            })
            .verify_peer(false)
            .build();

        (client_config, server_config)
    }

    #[tokio::test]
    async fn test_async_tls12_new_connection_state() {
        let (client_config, _) = make_configs(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        let (client_stream, _server_stream) = tokio::io::duplex(16 * 1024);
        let conn = AsyncTls12ClientConnection::new(client_stream, client_config);

        assert_eq!(conn.version(), None);
        assert_eq!(conn.cipher_suite(), None);
    }

    #[tokio::test]
    async fn test_async_tls12_read_before_handshake() {
        let (_, server_config) = make_configs(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        let (_, server_stream) = tokio::io::duplex(16 * 1024);
        let mut conn = AsyncTls12ServerConnection::new(server_stream, server_config);

        let mut buf = [0u8; 16];
        let result = conn.read(&mut buf).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_async_tls12_write_before_handshake() {
        let (client_config, _) = make_configs(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        let (client_stream, _) = tokio::io::duplex(16 * 1024);
        let mut conn = AsyncTls12ClientConnection::new(client_stream, client_config);

        let result = conn.write(b"hello").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_async_tls12_full_handshake_and_data() {
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let (client_config, server_config) = make_configs(suite);

        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncTls12ClientConnection::new(client_stream, client_config);
        let mut server = AsyncTls12ServerConnection::new(server_stream, server_config);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        assert_eq!(client.version(), Some(TlsVersion::Tls12));
        assert_eq!(server.version(), Some(TlsVersion::Tls12));
        assert_eq!(client.cipher_suite(), Some(suite));
        assert_eq!(server.cipher_suite(), Some(suite));

        // Client → Server
        let msg = b"Hello from client";
        client.write(msg).await.unwrap();
        let mut buf = [0u8; 256];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg);

        // Server → Client
        let reply = b"Hello from server";
        server.write(reply).await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], reply);
    }

    #[tokio::test]
    async fn test_async_tls12_double_handshake_fails() {
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let (client_config, server_config) = make_configs(suite);

        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncTls12ClientConnection::new(client_stream, client_config);
        let mut server = AsyncTls12ServerConnection::new(server_stream, server_config);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        assert!(client.handshake().await.is_err());
        assert!(server.handshake().await.is_err());
    }

    #[tokio::test]
    async fn test_async_tls12_shutdown() {
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let (client_config, server_config) = make_configs(suite);

        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncTls12ClientConnection::new(client_stream, client_config);
        let mut server = AsyncTls12ServerConnection::new(server_stream, server_config);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        client.shutdown().await.unwrap();
        // Double shutdown should be OK
        client.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_async_tls12_chacha20_handshake() {
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
        let (client_config, server_config) = make_configs(suite);

        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncTls12ClientConnection::new(client_stream, client_config);
        let mut server = AsyncTls12ServerConnection::new(server_stream, server_config);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        assert_eq!(client.cipher_suite(), Some(suite));

        let data = b"ChaCha20-Poly1305 test data";
        client.write(data).await.unwrap();
        let mut buf = [0u8; 256];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], data);
    }

    #[tokio::test]
    async fn test_async_tls12_server_new_state() {
        let (_, server_config) = make_configs(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        let (_, server_stream) = tokio::io::duplex(16 * 1024);
        let conn = AsyncTls12ServerConnection::new(server_stream, server_config);

        assert_eq!(conn.version(), None);
        assert_eq!(conn.cipher_suite(), None);
    }

    #[tokio::test]
    async fn test_async_tls12_take_session() {
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let (client_config, server_config) = make_configs(suite);

        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncTls12ClientConnection::new(client_stream, client_config);
        let mut server = AsyncTls12ServerConnection::new(server_stream, server_config);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        let session = client.take_session();
        assert!(session.is_some());
        let session = session.unwrap();
        assert_eq!(session.cipher_suite, suite);

        // Second take returns None
        assert!(client.take_session().is_none());
    }

    #[tokio::test]
    async fn test_async_tls12_client_accessors_before_handshake() {
        let (client_config, _) = make_configs(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        let (client_stream, _) = tokio::io::duplex(16 * 1024);
        let conn = AsyncTls12ClientConnection::new(client_stream, client_config);

        assert!(conn.connection_info().is_none());
        assert!(conn.peer_certificates().is_empty());
        assert!(conn.alpn_protocol().is_none());
        assert!(conn.server_name().is_none());
        assert!(conn.negotiated_group().is_none());
        assert!(!conn.is_session_resumed());
        assert!(conn.peer_verify_data().is_empty());
        assert!(conn.local_verify_data().is_empty());
    }

    #[tokio::test]
    async fn test_async_tls12_server_accessors_before_handshake() {
        let (_, server_config) = make_configs(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        let (_, server_stream) = tokio::io::duplex(16 * 1024);
        let conn = AsyncTls12ServerConnection::new(server_stream, server_config);

        assert!(conn.connection_info().is_none());
        assert!(conn.peer_certificates().is_empty());
        assert!(conn.alpn_protocol().is_none());
        assert!(conn.server_name().is_none());
        assert!(conn.negotiated_group().is_none());
        assert!(!conn.is_session_resumed());
        assert!(conn.peer_verify_data().is_empty());
        assert!(conn.local_verify_data().is_empty());
    }

    #[tokio::test]
    async fn test_async_tls12_connection_info_after_handshake() {
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let (client_config, server_config) = make_configs(suite);

        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncTls12ClientConnection::new(client_stream, client_config);
        let mut server = AsyncTls12ServerConnection::new(server_stream, server_config);

        let (c, s) = tokio::join!(client.handshake(), server.handshake());
        c.unwrap();
        s.unwrap();

        let info = client.connection_info().unwrap();
        assert_eq!(info.cipher_suite, suite);
        assert!(!info.session_resumed);
    }

    #[tokio::test]
    async fn test_async_tls12_large_payload() {
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let (client_config, server_config) = make_configs(suite);

        let (client_stream, server_stream) = tokio::io::duplex(128 * 1024);
        let mut client = AsyncTls12ClientConnection::new(client_stream, client_config);
        let mut server = AsyncTls12ServerConnection::new(server_stream, server_config);

        let (c, s) = tokio::join!(client.handshake(), server.handshake());
        c.unwrap();
        s.unwrap();

        let data = vec![0xABu8; 32 * 1024];
        client.write(&data).await.unwrap();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0;
        while total < data.len() {
            let n = server.read(&mut buf[total..]).await.unwrap();
            assert!(n > 0);
            total += n;
        }
        assert_eq!(&buf[..total], &data[..]);
    }

    #[tokio::test]
    async fn test_async_tls12_cbc_cipher_suite() {
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256;
        let (client_config, server_config) = make_configs(suite);

        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncTls12ClientConnection::new(client_stream, client_config);
        let mut server = AsyncTls12ServerConnection::new(server_stream, server_config);

        let (c, s) = tokio::join!(client.handshake(), server.handshake());
        c.unwrap();
        s.unwrap();

        assert_eq!(client.cipher_suite(), Some(suite));

        let msg = b"CBC cipher suite test";
        client.write(msg).await.unwrap();
        let mut buf = [0u8; 256];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg);
    }

    // -------------------------------------------------------
    // Testing-Phase 88: async TLS 1.2 additional tests
    // -------------------------------------------------------

    #[tokio::test]
    async fn test_async_tls12_multi_message_exchange() {
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let (client_config, server_config) = make_configs(suite);

        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncTls12ClientConnection::new(client_stream, client_config);
        let mut server = AsyncTls12ServerConnection::new(server_stream, server_config);

        let (c, s) = tokio::join!(client.handshake(), server.handshake());
        c.unwrap();
        s.unwrap();

        // Multiple round-trip exchanges
        for i in 0..5 {
            let msg = format!("async-tls12-msg-{i}");
            client.write(msg.as_bytes()).await.unwrap();
            let mut buf = [0u8; 256];
            let n = server.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());

            let reply = format!("async-tls12-reply-{i}");
            server.write(reply.as_bytes()).await.unwrap();
            let n = client.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], reply.as_bytes());
        }
    }

    #[tokio::test]
    async fn test_async_tls12_verify_data_after_handshake() {
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let (client_config, server_config) = make_configs(suite);

        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncTls12ClientConnection::new(client_stream, client_config);
        let mut server = AsyncTls12ServerConnection::new(server_stream, server_config);

        let (c, s) = tokio::join!(client.handshake(), server.handshake());
        c.unwrap();
        s.unwrap();

        // After handshake, verify_data should be populated (12 bytes for TLS 1.2)
        assert!(!client.peer_verify_data().is_empty());
        assert!(!client.local_verify_data().is_empty());
        assert!(!server.peer_verify_data().is_empty());
        assert!(!server.local_verify_data().is_empty());

        // Client's peer verify_data = server's local verify_data
        assert_eq!(client.peer_verify_data(), server.local_verify_data());
        // Client's local verify_data = server's peer verify_data
        assert_eq!(client.local_verify_data(), server.peer_verify_data());
    }

    #[tokio::test]
    async fn test_async_tls12_negotiated_group_after_handshake() {
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let (client_config, server_config) = make_configs(suite);

        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncTls12ClientConnection::new(client_stream, client_config);
        let mut server = AsyncTls12ServerConnection::new(server_stream, server_config);

        let (c, s) = tokio::join!(client.handshake(), server.handshake());
        c.unwrap();
        s.unwrap();

        // ECDHE suite should have a negotiated group
        assert_eq!(client.negotiated_group(), Some(NamedGroup::SECP256R1));
    }

    #[tokio::test]
    async fn test_async_tls12_server_connection_info_after_handshake() {
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let (client_config, server_config) = make_configs(suite);

        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncTls12ClientConnection::new(client_stream, client_config);
        let mut server = AsyncTls12ServerConnection::new(server_stream, server_config);

        let (c, s) = tokio::join!(client.handshake(), server.handshake());
        c.unwrap();
        s.unwrap();

        // Server connection info
        let server_info = server.connection_info().unwrap();
        assert_eq!(server_info.cipher_suite, suite);
        assert!(!server_info.session_resumed);
        // Verify data should be present in connection info
        assert!(!server_info.peer_verify_data.is_empty());
        assert!(!server_info.local_verify_data.is_empty());
    }
}
