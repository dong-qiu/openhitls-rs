//! Asynchronous DTLS 1.2 connection wrapping an `AsyncRead + AsyncWrite` transport.
//!
//! Provides `AsyncDtls12ClientConnection` and `AsyncDtls12ServerConnection` with
//! full handshake (including cookie exchange), abbreviated handshake (session
//! resumption), async read/write/shutdown, anti-replay, and epoch management.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::TlsConfig;
use crate::connection_info::ConnectionInfo;
use crate::crypt::NamedGroup;
use crate::handshake::client_dtls12::{Dtls12ClientHandshake, Dtls12ClientState};
use crate::handshake::codec::{decode_server_hello, parse_handshake_header};
use crate::handshake::codec12::{
    decode_certificate12, decode_server_key_exchange, encode_change_cipher_spec,
};
use crate::handshake::codec_dtls::{dtls_to_tls_handshake, parse_dtls_handshake_header};
use crate::handshake::server_dtls12::{
    Dtls12ServerHandshake, Dtls12ServerState, DtlsServerHelloResult,
};
use crate::handshake::HandshakeType;
use crate::record::anti_replay::AntiReplayWindow;
use crate::record::dtls::{
    parse_dtls_record, serialize_dtls_record, DtlsRecord, EpochState, DTLS12_VERSION,
    DTLS_RECORD_HEADER_LEN,
};
use crate::record::encryption_dtls12::{DtlsRecordDecryptor12, DtlsRecordEncryptor12};
use crate::record::ContentType;
use crate::session::TlsSession;
use crate::{AsyncTlsConnection, CipherSuite, TlsError, TlsVersion};
use zeroize::Zeroize;

/// Connection state for async DTLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DtlsConnectionState {
    Handshaking,
    Connected,
    Closed,
    Error,
}

// ===========================================================================
// Async DTLS 1.2 Client Connection
// ===========================================================================

/// An asynchronous DTLS 1.2 client connection.
pub struct AsyncDtls12ClientConnection<S: AsyncRead + AsyncWrite + Unpin> {
    stream: S,
    config: TlsConfig,
    write_epoch: EpochState,
    read_epoch: EpochState,
    encryptor: Option<DtlsRecordEncryptor12>,
    decryptor: Option<DtlsRecordDecryptor12>,
    anti_replay: AntiReplayWindow,
    state: DtlsConnectionState,
    negotiated_suite: Option<CipherSuite>,
    read_buf: Vec<u8>,
    app_data_buf: Vec<u8>,
    peer_certificates: Vec<Vec<u8>>,
    negotiated_alpn: Option<Vec<u8>>,
    server_name_used: Option<String>,
    negotiated_group: Option<NamedGroup>,
    session_resumed: bool,
    sent_close_notify: bool,
    received_close_notify: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncDtls12ClientConnection<S> {
    /// Create a new async DTLS 1.2 client connection wrapping the given stream.
    pub fn new(stream: S, config: TlsConfig) -> Self {
        Self {
            stream,
            config,
            write_epoch: EpochState::new(),
            read_epoch: EpochState::new(),
            encryptor: None,
            decryptor: None,
            anti_replay: AntiReplayWindow::new(),
            state: DtlsConnectionState::Handshaking,
            negotiated_suite: None,
            read_buf: Vec::with_capacity(16 * 1024),
            app_data_buf: Vec::new(),
            peer_certificates: Vec::new(),
            negotiated_alpn: None,
            server_name_used: None,
            negotiated_group: None,
            session_resumed: false,
            sent_close_notify: false,
            received_close_notify: false,
        }
    }

    /// Take the session state for later resumption.
    pub fn take_session(&mut self) -> Option<TlsSession> {
        None // DTLS 1.2 sessions are stored in the cache, not individually
    }

    /// Get a snapshot of the negotiated connection parameters.
    pub fn connection_info(&self) -> Option<ConnectionInfo> {
        self.negotiated_suite.map(|suite| ConnectionInfo {
            cipher_suite: suite,
            peer_certificates: self.peer_certificates.clone(),
            alpn_protocol: self.negotiated_alpn.clone(),
            server_name: self.server_name_used.clone(),
            negotiated_group: self.negotiated_group,
            session_resumed: self.session_resumed,
            peer_verify_data: Vec::new(),
            local_verify_data: Vec::new(),
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

    // -----------------------------------------------------------------------
    // I/O helpers
    // -----------------------------------------------------------------------

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

    /// Read a single DTLS record from the stream.
    async fn read_dtls_record(&mut self) -> Result<DtlsRecord, TlsError> {
        // Read at least the DTLS header (13 bytes)
        self.fill_buf(DTLS_RECORD_HEADER_LEN).await?;
        let length = u16::from_be_bytes([self.read_buf[11], self.read_buf[12]]) as usize;
        self.fill_buf(DTLS_RECORD_HEADER_LEN + length).await?;
        let (record, consumed) = parse_dtls_record(&self.read_buf)?;
        self.read_buf.drain(..consumed);
        Ok(record)
    }

    /// Write a DTLS record (plaintext) to the stream.
    async fn write_dtls_record(&mut self, record: &DtlsRecord) -> Result<(), TlsError> {
        let bytes = serialize_dtls_record(record);
        self.stream
            .write_all(&bytes)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))
    }

    /// Wrap a handshake message in a DTLS record and send it.
    async fn send_handshake(&mut self, hs_msg: &[u8]) -> Result<(), TlsError> {
        let seq = self.write_epoch.next_write_seq()?;
        let record = DtlsRecord {
            content_type: ContentType::Handshake,
            version: DTLS12_VERSION,
            epoch: self.write_epoch.epoch,
            sequence_number: seq,
            fragment: hs_msg.to_vec(),
        };
        self.write_dtls_record(&record).await
    }

    /// Send a ChangeCipherSpec record.
    async fn send_ccs(&mut self) -> Result<(), TlsError> {
        let seq = self.write_epoch.next_write_seq()?;
        let record = DtlsRecord {
            content_type: ContentType::ChangeCipherSpec,
            version: DTLS12_VERSION,
            epoch: self.write_epoch.epoch,
            sequence_number: seq,
            fragment: encode_change_cipher_spec(),
        };
        self.write_dtls_record(&record).await
    }

    /// Encrypt and send a handshake message.
    async fn send_encrypted_handshake(&mut self, hs_msg: &[u8]) -> Result<(), TlsError> {
        let enc = self
            .encryptor
            .as_mut()
            .ok_or_else(|| TlsError::RecordError("no encryptor".into()))?;
        let seq = self.write_epoch.next_write_seq()?;
        let record =
            enc.encrypt_record(ContentType::Handshake, hs_msg, self.write_epoch.epoch, seq)?;
        self.write_dtls_record(&record).await
    }

    /// Encrypt and send application data.
    async fn send_encrypted_app_data(&mut self, data: &[u8]) -> Result<(), TlsError> {
        let enc = self
            .encryptor
            .as_mut()
            .ok_or_else(|| TlsError::RecordError("no encryptor".into()))?;
        let seq = self.write_epoch.next_write_seq()?;
        let record = enc.encrypt_record(
            ContentType::ApplicationData,
            data,
            self.write_epoch.epoch,
            seq,
        )?;
        self.write_dtls_record(&record).await
    }

    /// Encrypt and send an alert.
    async fn send_encrypted_alert(&mut self, level: u8, desc: u8) -> Result<(), TlsError> {
        let alert_data = vec![level, desc];
        let enc = self
            .encryptor
            .as_mut()
            .ok_or_else(|| TlsError::RecordError("no encryptor".into()))?;
        let seq = self.write_epoch.next_write_seq()?;
        let record =
            enc.encrypt_record(ContentType::Alert, &alert_data, self.write_epoch.epoch, seq)?;
        self.write_dtls_record(&record).await
    }

    // -----------------------------------------------------------------------
    // Handshake
    // -----------------------------------------------------------------------

    async fn do_handshake(&mut self) -> Result<(), TlsError> {
        // Auto-lookup session from cache
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

        self.server_name_used = self.config.server_name.clone();

        let mut client_hs = Dtls12ClientHandshake::new(self.config.clone());

        // === Flight 1: Client → ClientHello ===
        let ch_msg = client_hs.build_client_hello()?;
        self.send_handshake(&ch_msg).await?;

        // === Read first server message (ServerHello or HelloVerifyRequest) ===
        let record = self.read_dtls_record().await?;
        let hs_msg = record.fragment;

        // Check if it's a HelloVerifyRequest (handshake type 3)
        let (header, _, _) = parse_dtls_handshake_header(&hs_msg)?;

        let hs_msg = if header.msg_type == HandshakeType::HelloVerifyRequest {
            // Process HVR and resend CH with cookie
            let ch2_msg = client_hs.process_hello_verify_request(&hs_msg)?;
            self.send_handshake(&ch2_msg).await?;

            // Read ServerHello after cookie exchange
            let record2 = self.read_dtls_record().await?;
            record2.fragment
        } else {
            hs_msg
        };

        // === Process ServerHello ===
        let sh_tls = dtls_to_tls_handshake(&hs_msg)?;
        let (_, sh_body, _) = parse_handshake_header(&sh_tls)?;
        let sh = decode_server_hello(sh_body)?;
        client_hs.process_server_hello(&hs_msg, &sh)?;

        let suite = sh.cipher_suite;
        let server_session_id = sh.legacy_session_id.clone();
        self.negotiated_suite = Some(suite);

        // Check for abbreviated handshake (session resumption)
        if client_hs.is_abbreviated() {
            return self
                .do_client_abbreviated(&mut client_hs, suite, &server_session_id)
                .await;
        }

        // === Full handshake path ===
        self.do_client_full(&mut client_hs, suite, &server_session_id)
            .await
    }

    async fn do_client_full(
        &mut self,
        client_hs: &mut Dtls12ClientHandshake,
        suite: CipherSuite,
        server_session_id: &[u8],
    ) -> Result<(), TlsError> {
        // === Read Certificate ===
        let cert_record = self.read_dtls_record().await?;
        let cert_tls = dtls_to_tls_handshake(&cert_record.fragment)?;
        let (_, cert_body, _) = parse_handshake_header(&cert_tls)?;
        let cert12 = decode_certificate12(cert_body)?;
        client_hs.process_certificate(&cert_record.fragment, &cert12.certificate_list)?;
        self.peer_certificates = cert12.certificate_list;

        // === Read ServerKeyExchange ===
        let ske_record = self.read_dtls_record().await?;
        let ske_tls = dtls_to_tls_handshake(&ske_record.fragment)?;
        let (_, ske_body, _) = parse_handshake_header(&ske_tls)?;
        let ske = decode_server_key_exchange(ske_body)?;
        client_hs.process_server_key_exchange(&ske_record.fragment, &ske)?;

        // === Read ServerHelloDone ===
        let shd_record = self.read_dtls_record().await?;

        // === Process ServerHelloDone → client flight (CKE + CCS + Finished) ===
        let mut cflight = client_hs.process_server_hello_done(&shd_record.fragment)?;

        // Send ClientKeyExchange (plaintext, epoch 0)
        self.send_handshake(&cflight.client_key_exchange).await?;

        // Send CCS (epoch 0)
        self.send_ccs().await?;

        // Bump client write epoch (0 → 1)
        self.write_epoch.next_epoch();
        self.encryptor = Some(DtlsRecordEncryptor12::new(
            suite,
            &cflight.client_write_key,
            cflight.client_write_iv.clone(),
        )?);

        // Send Finished (encrypted, epoch 1)
        self.send_encrypted_handshake(&cflight.finished).await?;

        // === Read server CCS ===
        let ccs_record = self.read_dtls_record().await?;
        if ccs_record.content_type != ContentType::ChangeCipherSpec {
            return Err(TlsError::HandshakeFailed(
                "expected ChangeCipherSpec".into(),
            ));
        }
        client_hs.process_change_cipher_spec()?;

        // Bump client read epoch (0 → 1)
        self.read_epoch.next_epoch();
        self.decryptor = Some(DtlsRecordDecryptor12::new(
            suite,
            &cflight.server_write_key,
            cflight.server_write_iv.clone(),
        )?);

        // === Read server Finished (encrypted) ===
        let sfin_record = self.read_dtls_record().await?;
        let sfin_plain = self
            .decryptor
            .as_mut()
            .unwrap()
            .decrypt_record(&sfin_record)?;

        let (sfin_header, _, _) = parse_dtls_handshake_header(&sfin_plain)?;
        if sfin_header.msg_type != HandshakeType::Finished {
            return Err(TlsError::HandshakeFailed("expected Finished".into()));
        }
        client_hs.process_finished(&sfin_plain, &cflight.master_secret)?;

        // === Handshake complete ===
        assert_eq!(client_hs.state(), Dtls12ClientState::Connected);
        self.state = DtlsConnectionState::Connected;

        // Auto-store session in cache
        store_client_session_async(
            &self.config,
            server_session_id,
            suite,
            &cflight.master_secret,
        );

        // Zeroize key material
        cflight.master_secret.zeroize();
        cflight.client_write_key.zeroize();
        cflight.server_write_key.zeroize();

        Ok(())
    }

    async fn do_client_abbreviated(
        &mut self,
        client_hs: &mut Dtls12ClientHandshake,
        suite: CipherSuite,
        server_session_id: &[u8],
    ) -> Result<(), TlsError> {
        let mut client_keys = client_hs
            .take_abbreviated_keys()
            .ok_or_else(|| TlsError::HandshakeFailed("no abbreviated keys".into()))?;

        // === Read server CCS ===
        let ccs_record = self.read_dtls_record().await?;
        if ccs_record.content_type != ContentType::ChangeCipherSpec {
            return Err(TlsError::HandshakeFailed(
                "expected ChangeCipherSpec".into(),
            ));
        }
        client_hs.process_change_cipher_spec()?;

        // Bump client read epoch (0 → 1)
        self.read_epoch.next_epoch();
        self.decryptor = Some(DtlsRecordDecryptor12::new(
            suite,
            &client_keys.server_write_key,
            client_keys.server_write_iv.clone(),
        )?);

        // === Read server Finished (encrypted) ===
        let sfin_record = self.read_dtls_record().await?;
        let sfin_plain = self
            .decryptor
            .as_mut()
            .unwrap()
            .decrypt_record(&sfin_record)?;

        let (sfin_header, _, _) = parse_dtls_handshake_header(&sfin_plain)?;
        if sfin_header.msg_type != HandshakeType::Finished {
            return Err(TlsError::HandshakeFailed("expected Finished".into()));
        }

        let client_finished = client_hs
            .process_abbreviated_server_finished(&sfin_plain, &client_keys.master_secret)?;

        // === Client sends CCS + Finished ===
        self.send_ccs().await?;

        // Bump client write epoch (0 → 1)
        self.write_epoch.next_epoch();
        self.encryptor = Some(DtlsRecordEncryptor12::new(
            suite,
            &client_keys.client_write_key,
            client_keys.client_write_iv.clone(),
        )?);

        self.send_encrypted_handshake(&client_finished).await?;

        // === Handshake complete ===
        assert_eq!(client_hs.state(), Dtls12ClientState::Connected);
        self.state = DtlsConnectionState::Connected;
        self.session_resumed = true;

        // Auto-store session in cache
        store_client_session_async(
            &self.config,
            server_session_id,
            suite,
            &client_keys.master_secret,
        );

        // Zeroize
        client_keys.master_secret.zeroize();
        client_keys.client_write_key.zeroize();
        client_keys.server_write_key.zeroize();

        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncTlsConnection for AsyncDtls12ClientConnection<S> {
    async fn handshake(&mut self) -> Result<(), TlsError> {
        if self.state != DtlsConnectionState::Handshaking {
            return Err(TlsError::HandshakeFailed(
                "handshake already completed or failed".into(),
            ));
        }
        match self.do_handshake().await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.state = DtlsConnectionState::Error;
                Err(e)
            }
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if self.state != DtlsConnectionState::Connected {
            return Err(TlsError::RecordError("not connected".into()));
        }
        if buf.is_empty() {
            return Ok(0);
        }

        // Return buffered app data first
        if !self.app_data_buf.is_empty() {
            let n = buf.len().min(self.app_data_buf.len());
            buf[..n].copy_from_slice(&self.app_data_buf[..n]);
            self.app_data_buf.drain(..n);
            return Ok(n);
        }

        // Read and decrypt a DTLS record
        loop {
            let record = self.read_dtls_record().await?;

            match record.content_type {
                ContentType::ApplicationData => {
                    // Anti-replay check
                    if !self.anti_replay.check(record.sequence_number) {
                        continue; // silently drop replayed records
                    }

                    let dec = self
                        .decryptor
                        .as_mut()
                        .ok_or_else(|| TlsError::RecordError("no decryptor".into()))?;
                    let plaintext = dec.decrypt_record(&record)?;
                    self.anti_replay.accept(record.sequence_number);

                    let n = buf.len().min(plaintext.len());
                    buf[..n].copy_from_slice(&plaintext[..n]);
                    if plaintext.len() > n {
                        self.app_data_buf.extend_from_slice(&plaintext[n..]);
                    }
                    return Ok(n);
                }
                ContentType::Alert => {
                    // Try to decrypt if we have a decryptor
                    let alert_data = if let Some(ref mut dec) = self.decryptor {
                        dec.decrypt_record(&record).unwrap_or(record.fragment)
                    } else {
                        record.fragment
                    };
                    if alert_data.len() >= 2 && alert_data[1] == 0 {
                        // close_notify
                        self.received_close_notify = true;
                        self.state = DtlsConnectionState::Closed;
                        return Ok(0);
                    }
                    return Err(TlsError::AlertReceived(format!(
                        "alert: level={} desc={}",
                        alert_data.first().unwrap_or(&0),
                        alert_data.get(1).unwrap_or(&0)
                    )));
                }
                _ => {
                    // Ignore unexpected record types during connected state
                    continue;
                }
            }
        }
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        if self.state != DtlsConnectionState::Connected {
            return Err(TlsError::RecordError("not connected".into()));
        }
        if buf.is_empty() {
            return Ok(0);
        }

        // Split into fragments if needed (default max 16384)
        let max_frag = 16384;
        let mut total = 0;
        for chunk in buf.chunks(max_frag) {
            self.send_encrypted_app_data(chunk).await?;
            total += chunk.len();
        }
        Ok(total)
    }

    async fn shutdown(&mut self) -> Result<(), TlsError> {
        if self.state == DtlsConnectionState::Closed {
            return Ok(());
        }
        if self.state != DtlsConnectionState::Connected {
            return Err(TlsError::RecordError("not connected".into()));
        }

        // Send close_notify alert
        self.send_encrypted_alert(1, 0).await?;
        self.sent_close_notify = true;
        self.state = DtlsConnectionState::Closed;
        Ok(())
    }

    fn version(&self) -> Option<TlsVersion> {
        if self.state == DtlsConnectionState::Connected || self.state == DtlsConnectionState::Closed
        {
            Some(TlsVersion::Dtls12)
        } else {
            None
        }
    }

    fn cipher_suite(&self) -> Option<CipherSuite> {
        self.negotiated_suite
    }
}

// ===========================================================================
// Async DTLS 1.2 Server Connection
// ===========================================================================

/// An asynchronous DTLS 1.2 server connection.
pub struct AsyncDtls12ServerConnection<S: AsyncRead + AsyncWrite + Unpin> {
    stream: S,
    config: TlsConfig,
    write_epoch: EpochState,
    read_epoch: EpochState,
    encryptor: Option<DtlsRecordEncryptor12>,
    decryptor: Option<DtlsRecordDecryptor12>,
    anti_replay: AntiReplayWindow,
    state: DtlsConnectionState,
    negotiated_suite: Option<CipherSuite>,
    read_buf: Vec<u8>,
    app_data_buf: Vec<u8>,
    peer_certificates: Vec<Vec<u8>>,
    negotiated_alpn: Option<Vec<u8>>,
    client_server_name: Option<String>,
    negotiated_group: Option<NamedGroup>,
    session_resumed: bool,
    sent_close_notify: bool,
    received_close_notify: bool,
    enable_cookie: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncDtls12ServerConnection<S> {
    /// Create a new async DTLS 1.2 server connection.
    pub fn new(stream: S, config: TlsConfig, enable_cookie: bool) -> Self {
        Self {
            stream,
            config,
            write_epoch: EpochState::new(),
            read_epoch: EpochState::new(),
            encryptor: None,
            decryptor: None,
            anti_replay: AntiReplayWindow::new(),
            state: DtlsConnectionState::Handshaking,
            negotiated_suite: None,
            read_buf: Vec::with_capacity(16 * 1024),
            app_data_buf: Vec::new(),
            peer_certificates: Vec::new(),
            negotiated_alpn: None,
            client_server_name: None,
            negotiated_group: None,
            session_resumed: false,
            sent_close_notify: false,
            received_close_notify: false,
            enable_cookie,
        }
    }

    /// Get a snapshot of the negotiated connection parameters.
    pub fn connection_info(&self) -> Option<ConnectionInfo> {
        self.negotiated_suite.map(|suite| ConnectionInfo {
            cipher_suite: suite,
            peer_certificates: self.peer_certificates.clone(),
            alpn_protocol: self.negotiated_alpn.clone(),
            server_name: self.client_server_name.clone(),
            negotiated_group: self.negotiated_group,
            session_resumed: self.session_resumed,
            peer_verify_data: Vec::new(),
            local_verify_data: Vec::new(),
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

    /// Get the client's requested server name (SNI).
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

    // -----------------------------------------------------------------------
    // I/O helpers
    // -----------------------------------------------------------------------

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

    async fn read_dtls_record(&mut self) -> Result<DtlsRecord, TlsError> {
        self.fill_buf(DTLS_RECORD_HEADER_LEN).await?;
        let length = u16::from_be_bytes([self.read_buf[11], self.read_buf[12]]) as usize;
        self.fill_buf(DTLS_RECORD_HEADER_LEN + length).await?;
        let (record, consumed) = parse_dtls_record(&self.read_buf)?;
        self.read_buf.drain(..consumed);
        Ok(record)
    }

    async fn write_dtls_record(&mut self, record: &DtlsRecord) -> Result<(), TlsError> {
        let bytes = serialize_dtls_record(record);
        self.stream
            .write_all(&bytes)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))
    }

    async fn send_handshake(&mut self, hs_msg: &[u8]) -> Result<(), TlsError> {
        let seq = self.write_epoch.next_write_seq()?;
        let record = DtlsRecord {
            content_type: ContentType::Handshake,
            version: DTLS12_VERSION,
            epoch: self.write_epoch.epoch,
            sequence_number: seq,
            fragment: hs_msg.to_vec(),
        };
        self.write_dtls_record(&record).await
    }

    async fn send_ccs(&mut self) -> Result<(), TlsError> {
        let seq = self.write_epoch.next_write_seq()?;
        let record = DtlsRecord {
            content_type: ContentType::ChangeCipherSpec,
            version: DTLS12_VERSION,
            epoch: self.write_epoch.epoch,
            sequence_number: seq,
            fragment: encode_change_cipher_spec(),
        };
        self.write_dtls_record(&record).await
    }

    async fn send_encrypted_handshake(&mut self, hs_msg: &[u8]) -> Result<(), TlsError> {
        let enc = self
            .encryptor
            .as_mut()
            .ok_or_else(|| TlsError::RecordError("no encryptor".into()))?;
        let seq = self.write_epoch.next_write_seq()?;
        let record =
            enc.encrypt_record(ContentType::Handshake, hs_msg, self.write_epoch.epoch, seq)?;
        self.write_dtls_record(&record).await
    }

    async fn send_encrypted_app_data(&mut self, data: &[u8]) -> Result<(), TlsError> {
        let enc = self
            .encryptor
            .as_mut()
            .ok_or_else(|| TlsError::RecordError("no encryptor".into()))?;
        let seq = self.write_epoch.next_write_seq()?;
        let record = enc.encrypt_record(
            ContentType::ApplicationData,
            data,
            self.write_epoch.epoch,
            seq,
        )?;
        self.write_dtls_record(&record).await
    }

    async fn send_encrypted_alert(&mut self, level: u8, desc: u8) -> Result<(), TlsError> {
        let alert_data = vec![level, desc];
        let enc = self
            .encryptor
            .as_mut()
            .ok_or_else(|| TlsError::RecordError("no encryptor".into()))?;
        let seq = self.write_epoch.next_write_seq()?;
        let record =
            enc.encrypt_record(ContentType::Alert, &alert_data, self.write_epoch.epoch, seq)?;
        self.write_dtls_record(&record).await
    }

    // -----------------------------------------------------------------------
    // Handshake
    // -----------------------------------------------------------------------

    async fn do_handshake(&mut self) -> Result<(), TlsError> {
        let mut server_hs = Dtls12ServerHandshake::new(self.config.clone(), self.enable_cookie);

        // === Read ClientHello ===
        let ch_record = self.read_dtls_record().await?;
        let ch_hs_msg = ch_record.fragment;

        let result = server_hs.process_client_hello(&ch_hs_msg)?;

        let server_result = match result {
            Ok(r) => r,
            Err(hvr_result) => {
                // Send HelloVerifyRequest
                self.send_handshake(&hvr_result.hello_verify_request)
                    .await?;

                // Read ClientHello with cookie
                let ch2_record = self.read_dtls_record().await?;
                server_hs.process_client_hello_with_cookie(&ch2_record.fragment)?
            }
        };

        match server_result {
            DtlsServerHelloResult::Full(flight) => {
                self.do_server_full(&mut server_hs, flight).await
            }
            DtlsServerHelloResult::Abbreviated(mut abbr) => {
                self.do_server_abbreviated(&mut server_hs, &mut abbr).await
            }
        }
    }

    async fn do_server_full(
        &mut self,
        server_hs: &mut Dtls12ServerHandshake,
        flight: crate::handshake::server_dtls12::DtlsServerFlightResult,
    ) -> Result<(), TlsError> {
        let suite = flight.suite;
        self.negotiated_suite = Some(suite);

        // === Send SH + Cert + SKE + SHD ===
        for msg in [
            &flight.server_hello,
            &flight.certificate,
            &flight.server_key_exchange,
            &flight.server_hello_done,
        ] {
            self.send_handshake(msg).await?;
        }

        // === Read ClientKeyExchange ===
        let cke_record = self.read_dtls_record().await?;
        let mut keys = server_hs.process_client_key_exchange(&cke_record.fragment)?;

        // === Read CCS ===
        let ccs_record = self.read_dtls_record().await?;
        if ccs_record.content_type != ContentType::ChangeCipherSpec {
            return Err(TlsError::HandshakeFailed(
                "expected ChangeCipherSpec".into(),
            ));
        }
        server_hs.process_change_cipher_spec()?;

        // Bump server read epoch (0 → 1)
        self.read_epoch.next_epoch();
        let mut server_dec = DtlsRecordDecryptor12::new(
            suite,
            &keys.client_write_key,
            keys.client_write_iv.clone(),
        )?;

        // === Read client Finished (encrypted) ===
        let fin_record = self.read_dtls_record().await?;
        let fin_plain = server_dec.decrypt_record(&fin_record)?;

        let (fin_header, _, _) = parse_dtls_handshake_header(&fin_plain)?;
        if fin_header.msg_type != HandshakeType::Finished {
            return Err(TlsError::HandshakeFailed("expected Finished".into()));
        }
        let server_fin_result = server_hs.process_finished(&fin_plain)?;

        // === Send server CCS + Finished ===
        self.send_ccs().await?;

        // Bump server write epoch (0 → 1)
        self.write_epoch.next_epoch();
        self.encryptor = Some(DtlsRecordEncryptor12::new(
            suite,
            &keys.server_write_key,
            keys.server_write_iv.clone(),
        )?);

        self.send_encrypted_handshake(&server_fin_result.finished)
            .await?;

        // === Handshake complete ===
        assert_eq!(server_hs.state(), Dtls12ServerState::Connected);
        self.decryptor = Some(server_dec);
        self.state = DtlsConnectionState::Connected;

        // Auto-store session in cache
        store_server_session_async(&self.config, server_hs, suite, &keys.master_secret);

        // Zeroize
        keys.master_secret.zeroize();
        keys.client_write_key.zeroize();
        keys.server_write_key.zeroize();

        Ok(())
    }

    async fn do_server_abbreviated(
        &mut self,
        server_hs: &mut Dtls12ServerHandshake,
        abbr: &mut crate::handshake::server_dtls12::DtlsAbbreviatedServerResult,
    ) -> Result<(), TlsError> {
        let suite = abbr.suite;
        self.negotiated_suite = Some(suite);

        // === Server sends SH (plaintext) ===
        self.send_handshake(&abbr.server_hello).await?;

        // === Server sends CCS (plaintext) ===
        self.send_ccs().await?;

        // === Server sends Finished (encrypted, epoch 1) ===
        self.write_epoch.next_epoch();
        self.encryptor = Some(DtlsRecordEncryptor12::new(
            suite,
            &abbr.server_write_key,
            abbr.server_write_iv.clone(),
        )?);

        self.send_encrypted_handshake(&abbr.finished).await?;

        // === Read client CCS ===
        let ccs_record = self.read_dtls_record().await?;
        if ccs_record.content_type != ContentType::ChangeCipherSpec {
            return Err(TlsError::HandshakeFailed(
                "expected ChangeCipherSpec".into(),
            ));
        }

        // Bump server read epoch (0 → 1)
        self.read_epoch.next_epoch();
        self.decryptor = Some(DtlsRecordDecryptor12::new(
            suite,
            &abbr.client_write_key,
            abbr.client_write_iv.clone(),
        )?);

        // === Read client Finished (encrypted) ===
        let cfin_record = self.read_dtls_record().await?;
        let cfin_plain = self
            .decryptor
            .as_mut()
            .unwrap()
            .decrypt_record(&cfin_record)?;

        let (cfin_header, _, _) = parse_dtls_handshake_header(&cfin_plain)?;
        if cfin_header.msg_type != HandshakeType::Finished {
            return Err(TlsError::HandshakeFailed("expected Finished".into()));
        }
        server_hs.process_abbreviated_finished(&cfin_plain)?;

        // === Handshake complete ===
        assert_eq!(server_hs.state(), Dtls12ServerState::Connected);
        self.state = DtlsConnectionState::Connected;
        self.session_resumed = true;

        // Auto-store session
        store_server_session_async(&self.config, server_hs, suite, &abbr.master_secret);

        // Zeroize
        abbr.master_secret.zeroize();
        abbr.client_write_key.zeroize();
        abbr.server_write_key.zeroize();

        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncTlsConnection for AsyncDtls12ServerConnection<S> {
    async fn handshake(&mut self) -> Result<(), TlsError> {
        if self.state != DtlsConnectionState::Handshaking {
            return Err(TlsError::HandshakeFailed(
                "handshake already completed or failed".into(),
            ));
        }
        match self.do_handshake().await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.state = DtlsConnectionState::Error;
                Err(e)
            }
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if self.state != DtlsConnectionState::Connected {
            return Err(TlsError::RecordError("not connected".into()));
        }
        if buf.is_empty() {
            return Ok(0);
        }

        // Return buffered app data first
        if !self.app_data_buf.is_empty() {
            let n = buf.len().min(self.app_data_buf.len());
            buf[..n].copy_from_slice(&self.app_data_buf[..n]);
            self.app_data_buf.drain(..n);
            return Ok(n);
        }

        loop {
            let record = self.read_dtls_record().await?;

            match record.content_type {
                ContentType::ApplicationData => {
                    if !self.anti_replay.check(record.sequence_number) {
                        continue;
                    }

                    let dec = self
                        .decryptor
                        .as_mut()
                        .ok_or_else(|| TlsError::RecordError("no decryptor".into()))?;
                    let plaintext = dec.decrypt_record(&record)?;
                    self.anti_replay.accept(record.sequence_number);

                    let n = buf.len().min(plaintext.len());
                    buf[..n].copy_from_slice(&plaintext[..n]);
                    if plaintext.len() > n {
                        self.app_data_buf.extend_from_slice(&plaintext[n..]);
                    }
                    return Ok(n);
                }
                ContentType::Alert => {
                    let alert_data = if let Some(ref mut dec) = self.decryptor {
                        dec.decrypt_record(&record).unwrap_or(record.fragment)
                    } else {
                        record.fragment
                    };
                    if alert_data.len() >= 2 && alert_data[1] == 0 {
                        self.received_close_notify = true;
                        self.state = DtlsConnectionState::Closed;
                        return Ok(0);
                    }
                    return Err(TlsError::AlertReceived(format!(
                        "alert: level={} desc={}",
                        alert_data.first().unwrap_or(&0),
                        alert_data.get(1).unwrap_or(&0)
                    )));
                }
                _ => {
                    continue;
                }
            }
        }
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        if self.state != DtlsConnectionState::Connected {
            return Err(TlsError::RecordError("not connected".into()));
        }
        if buf.is_empty() {
            return Ok(0);
        }

        let max_frag = 16384;
        let mut total = 0;
        for chunk in buf.chunks(max_frag) {
            self.send_encrypted_app_data(chunk).await?;
            total += chunk.len();
        }
        Ok(total)
    }

    async fn shutdown(&mut self) -> Result<(), TlsError> {
        if self.state == DtlsConnectionState::Closed {
            return Ok(());
        }
        if self.state != DtlsConnectionState::Connected {
            return Err(TlsError::RecordError("not connected".into()));
        }

        self.send_encrypted_alert(1, 0).await?;
        self.sent_close_notify = true;
        self.state = DtlsConnectionState::Closed;
        Ok(())
    }

    fn version(&self) -> Option<TlsVersion> {
        if self.state == DtlsConnectionState::Connected || self.state == DtlsConnectionState::Closed
        {
            Some(TlsVersion::Dtls12)
        } else {
            None
        }
    }

    fn cipher_suite(&self) -> Option<CipherSuite> {
        self.negotiated_suite
    }
}

// ===========================================================================
// Session cache helpers (synchronous lock, never held across .await)
// ===========================================================================

fn store_client_session_async(
    config: &TlsConfig,
    session_id: &[u8],
    suite: CipherSuite,
    master_secret: &[u8],
) {
    if let (Some(ref cache), Some(ref name)) = (&config.session_cache, &config.server_name) {
        if let Ok(mut c) = cache.lock() {
            let session = TlsSession {
                id: session_id.to_vec(),
                cipher_suite: suite,
                master_secret: master_secret.to_vec(),
                alpn_protocol: None,
                ticket: None,
                ticket_lifetime: 0,
                max_early_data: 0,
                ticket_age_add: 0,
                ticket_nonce: Vec::new(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                psk: Vec::new(),
                extended_master_secret: false,
            };
            c.put(name.as_bytes(), session);
        }
    }
}

fn store_server_session_async(
    config: &TlsConfig,
    server_hs: &Dtls12ServerHandshake,
    suite: CipherSuite,
    master_secret: &[u8],
) {
    if let Some(ref cache) = config.session_cache {
        let sid = server_hs.session_id();
        if !sid.is_empty() {
            if let Ok(mut c) = cache.lock() {
                let session = TlsSession {
                    id: sid.to_vec(),
                    cipher_suite: suite,
                    master_secret: master_secret.to_vec(),
                    alpn_protocol: None,
                    ticket: None,
                    ticket_lifetime: 0,
                    max_early_data: 0,
                    ticket_age_add: 0,
                    ticket_nonce: Vec::new(),
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    psk: Vec::new(),
                    extended_master_secret: false,
                };
                c.put(sid, session);
            }
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerPrivateKey;
    use crate::crypt::{NamedGroup, SignatureScheme};
    use crate::session::{InMemorySessionCache, SessionCache};
    use std::sync::{Arc, Mutex};

    fn client_config() -> TlsConfig {
        TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                SignatureScheme::RSA_PSS_RSAE_SHA256,
            ])
            .verify_peer(false)
            .build()
    }

    fn server_config() -> TlsConfig {
        let ecdsa_private = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let fake_cert = vec![0x30, 0x82, 0x01, 0x00];

        TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .certificate_chain(vec![fake_cert])
            .private_key(ServerPrivateKey::Ecdsa {
                curve_id: hitls_types::EccCurveId::NistP256,
                private_key: ecdsa_private,
            })
            .verify_peer(false)
            .build()
    }

    fn client_config_with_cache(cache: Arc<Mutex<InMemorySessionCache>>) -> TlsConfig {
        TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                SignatureScheme::RSA_PSS_RSAE_SHA256,
            ])
            .verify_peer(false)
            .server_name("test.dtls.async")
            .session_cache(cache)
            .build()
    }

    fn server_config_with_cache(cache: Arc<Mutex<InMemorySessionCache>>) -> TlsConfig {
        let ecdsa_private = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let fake_cert = vec![0x30, 0x82, 0x01, 0x00];

        TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .certificate_chain(vec![fake_cert])
            .private_key(ServerPrivateKey::Ecdsa {
                curve_id: hitls_types::EccCurveId::NistP256,
                private_key: ecdsa_private,
            })
            .verify_peer(false)
            .session_cache(cache)
            .build()
    }

    #[tokio::test]
    async fn test_async_dtls12_read_before_handshake() {
        let (client_stream, _server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncDtls12ClientConnection::new(client_stream, client_config());
        let mut buf = [0u8; 16];
        let err = client.read(&mut buf).await.unwrap_err();
        match err {
            TlsError::RecordError(msg) => assert!(msg.contains("not connected")),
            _ => panic!("expected RecordError, got {err:?}"),
        }
    }

    #[tokio::test]
    async fn test_async_dtls12_write_before_handshake() {
        let (client_stream, _server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncDtls12ClientConnection::new(client_stream, client_config());
        let err = client.write(b"hello").await.unwrap_err();
        match err {
            TlsError::RecordError(msg) => assert!(msg.contains("not connected")),
            _ => panic!("expected RecordError, got {err:?}"),
        }
    }

    #[tokio::test]
    async fn test_async_dtls12_full_handshake() {
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncDtls12ClientConnection::new(client_stream, client_config());
        let mut server = AsyncDtls12ServerConnection::new(server_stream, server_config(), false);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        // Exchange app data
        let msg = b"Hello from async DTLS client!";
        client.write(msg).await.unwrap();
        let mut buf = [0u8; 256];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg);

        let reply = b"Hello from async DTLS server!";
        server.write(reply).await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], reply);
    }

    #[tokio::test]
    async fn test_async_dtls12_version_check() {
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncDtls12ClientConnection::new(client_stream, client_config());
        let mut server = AsyncDtls12ServerConnection::new(server_stream, server_config(), false);

        // Before handshake
        assert_eq!(client.version(), None);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        // After handshake
        assert_eq!(client.version(), Some(TlsVersion::Dtls12));
        assert_eq!(server.version(), Some(TlsVersion::Dtls12));
    }

    #[tokio::test]
    async fn test_async_dtls12_cipher_suite() {
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncDtls12ClientConnection::new(client_stream, client_config());
        let mut server = AsyncDtls12ServerConnection::new(server_stream, server_config(), false);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        assert_eq!(
            client.cipher_suite(),
            Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
        );
        assert_eq!(client.cipher_suite(), server.cipher_suite());
    }

    #[tokio::test]
    async fn test_async_dtls12_connection_info() {
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncDtls12ClientConnection::new(client_stream, client_config());
        let mut server = AsyncDtls12ServerConnection::new(server_stream, server_config(), false);

        // Before handshake
        assert!(client.connection_info().is_none());

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        let info = client.connection_info().unwrap();
        assert_eq!(
            info.cipher_suite,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        );
        assert!(!info.session_resumed);
    }

    #[tokio::test]
    async fn test_async_dtls12_shutdown() {
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncDtls12ClientConnection::new(client_stream, client_config());
        let mut server = AsyncDtls12ServerConnection::new(server_stream, server_config(), false);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        // Shutdown client
        client.shutdown().await.unwrap();
        assert_eq!(client.version(), Some(TlsVersion::Dtls12)); // version still available after close

        // Double shutdown is OK
        client.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_async_dtls12_large_payload() {
        let (client_stream, server_stream) = tokio::io::duplex(128 * 1024);
        let mut client = AsyncDtls12ClientConnection::new(client_stream, client_config());
        let mut server = AsyncDtls12ServerConnection::new(server_stream, server_config(), false);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        // Send 32 KB
        let payload = vec![0xAB; 32 * 1024];
        client.write(&payload).await.unwrap();

        let mut received = Vec::new();
        let mut buf = [0u8; 16384];
        while received.len() < payload.len() {
            let n = server.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn test_async_dtls12_abbreviated_handshake() {
        let client_cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));
        let server_cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));

        // First: full handshake to populate caches
        {
            let (cs, ss) = tokio::io::duplex(64 * 1024);
            let mut c = AsyncDtls12ClientConnection::new(
                cs,
                client_config_with_cache(client_cache.clone()),
            );
            let mut s = AsyncDtls12ServerConnection::new(
                ss,
                server_config_with_cache(server_cache.clone()),
                false,
            );
            let (cr, sr) = tokio::join!(c.handshake(), s.handshake());
            cr.unwrap();
            sr.unwrap();
            assert!(!c.is_session_resumed());

            // Verify session cached
            let cache = client_cache.lock().unwrap();
            assert!(cache.get(b"test.dtls.async").is_some());
        }

        // Second: abbreviated handshake using cached session
        {
            let (cs, ss) = tokio::io::duplex(64 * 1024);
            let mut c = AsyncDtls12ClientConnection::new(
                cs,
                client_config_with_cache(client_cache.clone()),
            );
            let mut s = AsyncDtls12ServerConnection::new(
                ss,
                server_config_with_cache(server_cache.clone()),
                false,
            );
            let (cr, sr) = tokio::join!(c.handshake(), s.handshake());
            cr.unwrap();
            sr.unwrap();

            // Verify app data works after abbreviated handshake
            let msg = b"abbreviated test";
            c.write(msg).await.unwrap();
            let mut buf = [0u8; 256];
            let n = s.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg);
        }
    }

    #[tokio::test]
    async fn test_async_dtls12_session_resumed() {
        let client_cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));
        let server_cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));

        // Full handshake first
        {
            let (cs, ss) = tokio::io::duplex(64 * 1024);
            let mut c = AsyncDtls12ClientConnection::new(
                cs,
                client_config_with_cache(client_cache.clone()),
            );
            let mut s = AsyncDtls12ServerConnection::new(
                ss,
                server_config_with_cache(server_cache.clone()),
                false,
            );
            let (cr, sr) = tokio::join!(c.handshake(), s.handshake());
            cr.unwrap();
            sr.unwrap();
        }

        // Abbreviated handshake — check session_resumed flag
        {
            let (cs, ss) = tokio::io::duplex(64 * 1024);
            let mut c = AsyncDtls12ClientConnection::new(
                cs,
                client_config_with_cache(client_cache.clone()),
            );
            let mut s = AsyncDtls12ServerConnection::new(
                ss,
                server_config_with_cache(server_cache.clone()),
                false,
            );
            let (cr, sr) = tokio::join!(c.handshake(), s.handshake());
            cr.unwrap();
            sr.unwrap();

            assert!(c.is_session_resumed());
            assert!(s.is_session_resumed());
        }
    }

    // -------------------------------------------------------
    // Testing-Phase 78 — H3: Async DTLS 1.2 cookie mode + edge cases
    // -------------------------------------------------------

    #[tokio::test]
    async fn test_async_dtls12_with_cookie_mode() {
        // Server enables cookie (HelloVerifyRequest flow)
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncDtls12ClientConnection::new(client_stream, client_config());
        let mut server = AsyncDtls12ServerConnection::new(server_stream, server_config(), true); // cookie=true

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        assert_eq!(client.version(), Some(TlsVersion::Dtls12));
        assert_eq!(server.version(), Some(TlsVersion::Dtls12));

        // Data exchange after cookie-based handshake
        let msg = b"cookie-mode-ok";
        client.write(msg).await.unwrap();
        let mut buf = [0u8; 64];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg);
    }

    #[tokio::test]
    async fn test_async_dtls12_multi_message_exchange() {
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncDtls12ClientConnection::new(client_stream, client_config());
        let mut server = AsyncDtls12ServerConnection::new(server_stream, server_config(), false);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        // Multiple round-trips
        for i in 0..5 {
            let msg = format!("msg-{i}");
            client.write(msg.as_bytes()).await.unwrap();
            let mut buf = [0u8; 64];
            let n = server.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());

            let reply = format!("ack-{i}");
            server.write(reply.as_bytes()).await.unwrap();
            let n = client.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], reply.as_bytes());
        }
    }

    #[tokio::test]
    async fn test_async_dtls12_cookie_mode_abbreviated() {
        // Cookie mode + session resumption
        let client_cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));
        let server_cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));

        // 1st: Full handshake with cookie
        {
            let (cs, ss) = tokio::io::duplex(64 * 1024);
            let mut c = AsyncDtls12ClientConnection::new(
                cs,
                client_config_with_cache(client_cache.clone()),
            );
            let mut s = AsyncDtls12ServerConnection::new(
                ss,
                server_config_with_cache(server_cache.clone()),
                true, // cookie enabled
            );
            let (cr, sr) = tokio::join!(c.handshake(), s.handshake());
            cr.unwrap();
            sr.unwrap();
            assert!(!c.is_session_resumed());
        }

        // 2nd: Abbreviated handshake with cookie
        {
            let (cs, ss) = tokio::io::duplex(64 * 1024);
            let mut c = AsyncDtls12ClientConnection::new(
                cs,
                client_config_with_cache(client_cache.clone()),
            );
            let mut s = AsyncDtls12ServerConnection::new(
                ss,
                server_config_with_cache(server_cache.clone()),
                true,
            );
            let (cr, sr) = tokio::join!(c.handshake(), s.handshake());
            cr.unwrap();
            sr.unwrap();
            assert!(c.is_session_resumed());
            assert!(s.is_session_resumed());
        }
    }
}
