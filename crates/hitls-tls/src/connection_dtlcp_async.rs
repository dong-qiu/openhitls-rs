//! Asynchronous DTLCP connection wrapping an `AsyncRead + AsyncWrite` transport.
//!
//! DTLCP = DTLS record layer + TLCP handshake (SM2/SM3/SM4).
//! Provides `AsyncDtlcpClientConnection` and `AsyncDtlcpServerConnection` with
//! full handshake (including cookie exchange), async read/write/shutdown,
//! anti-replay, and epoch management.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::TlsConfig;
use crate::connection_info::ConnectionInfo;
use crate::handshake::client_dtlcp::DtlcpClientHandshake;
use crate::handshake::codec::{decode_server_hello, parse_handshake_header};
use crate::handshake::codec_dtls::{dtls_to_tls_handshake, parse_dtls_handshake_header};
use crate::handshake::codec_tlcp::decode_tlcp_certificate;
use crate::handshake::server_dtlcp::DtlcpServerHandshake;
use crate::handshake::HandshakeType;
use crate::record::anti_replay::AntiReplayWindow;
use crate::record::dtls::{
    parse_dtls_record, serialize_dtls_record, DtlsRecord, EpochState, DTLS_RECORD_HEADER_LEN,
};
use crate::record::encryption_dtlcp::{
    DtlcpDecryptor, DtlcpEncryptor, DtlcpRecordDecryptorCbc, DtlcpRecordDecryptorGcm,
    DtlcpRecordEncryptorCbc, DtlcpRecordEncryptorGcm, DTLCP_VERSION,
};
use crate::record::ContentType;
use crate::{AsyncTlsConnection, CipherSuite, TlsError, TlsVersion};
use zeroize::Zeroize;

use crate::handshake::codec12::encode_change_cipher_spec;

/// Connection state for async DTLCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DtlcpConnectionState {
    Handshaking,
    Connected,
    Closed,
    Error,
}

// ===========================================================================
// Helpers: create encryptor/decryptor based on CBC vs GCM
// ===========================================================================

fn create_dtlcp_encryptor(
    suite: CipherSuite,
    enc_key: &[u8],
    mac_key: &[u8],
    iv: &[u8],
) -> Result<DtlcpEncryptor, TlsError> {
    let is_cbc = matches!(
        suite,
        CipherSuite::ECDHE_SM4_CBC_SM3 | CipherSuite::ECC_SM4_CBC_SM3
    );
    if is_cbc {
        Ok(DtlcpEncryptor::Cbc(DtlcpRecordEncryptorCbc::new(
            enc_key.to_vec(),
            mac_key,
        )?))
    } else {
        Ok(DtlcpEncryptor::Gcm(DtlcpRecordEncryptorGcm::new(
            enc_key,
            iv.to_vec(),
        )?))
    }
}

fn create_dtlcp_decryptor(
    suite: CipherSuite,
    enc_key: &[u8],
    mac_key: &[u8],
    iv: &[u8],
) -> Result<DtlcpDecryptor, TlsError> {
    let is_cbc = matches!(
        suite,
        CipherSuite::ECDHE_SM4_CBC_SM3 | CipherSuite::ECC_SM4_CBC_SM3
    );
    if is_cbc {
        Ok(DtlcpDecryptor::Cbc(DtlcpRecordDecryptorCbc::new(
            enc_key.to_vec(),
            mac_key,
        )?))
    } else {
        Ok(DtlcpDecryptor::Gcm(DtlcpRecordDecryptorGcm::new(
            enc_key,
            iv.to_vec(),
        )?))
    }
}

// ===========================================================================
// Async DTLCP Client Connection
// ===========================================================================

/// An asynchronous DTLCP client connection.
pub struct AsyncDtlcpClientConnection<S: AsyncRead + AsyncWrite + Unpin> {
    stream: S,
    config: TlsConfig,
    write_epoch: EpochState,
    read_epoch: EpochState,
    encryptor: Option<DtlcpEncryptor>,
    decryptor: Option<DtlcpDecryptor>,
    anti_replay: AntiReplayWindow,
    state: DtlcpConnectionState,
    negotiated_suite: Option<CipherSuite>,
    read_buf: Vec<u8>,
    app_data_buf: Vec<u8>,
    sent_close_notify: bool,
    received_close_notify: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncDtlcpClientConnection<S> {
    /// Create a new async DTLCP client connection wrapping the given stream.
    pub fn new(stream: S, config: TlsConfig) -> Self {
        Self {
            stream,
            config,
            write_epoch: EpochState::new(),
            read_epoch: EpochState::new(),
            encryptor: None,
            decryptor: None,
            anti_replay: AntiReplayWindow::new(),
            state: DtlcpConnectionState::Handshaking,
            negotiated_suite: None,
            read_buf: Vec::with_capacity(16 * 1024),
            app_data_buf: Vec::new(),
            sent_close_notify: false,
            received_close_notify: false,
        }
    }

    /// Get a snapshot of the negotiated connection parameters.
    pub fn connection_info(&self) -> Option<ConnectionInfo> {
        self.negotiated_suite.map(|suite| ConnectionInfo {
            cipher_suite: suite,
            peer_certificates: Vec::new(),
            alpn_protocol: None,
            server_name: None,
            negotiated_group: None,
            session_resumed: false,
            peer_verify_data: Vec::new(),
            local_verify_data: Vec::new(),
        })
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
            version: DTLCP_VERSION,
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
            version: DTLCP_VERSION,
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
        let mut client_hs = DtlcpClientHandshake::new(self.config.clone());

        // === Flight 1: Client → ClientHello ===
        let ch_msg = client_hs.build_client_hello()?;
        self.send_handshake(&ch_msg).await?;

        // === Read first server message (ServerHello or HelloVerifyRequest) ===
        let record = self.read_dtls_record().await?;
        let hs_msg = record.fragment;

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
        self.negotiated_suite = Some(suite);

        // === Read Certificate (double cert) ===
        let cert_record = self.read_dtls_record().await?;
        let cert_tls = dtls_to_tls_handshake(&cert_record.fragment)?;
        let (_, cert_body, _) = parse_handshake_header(&cert_tls)?;
        let cert_msg = decode_tlcp_certificate(cert_body)?;
        client_hs.process_certificate(&cert_record.fragment, &cert_msg)?;

        // === Read ServerKeyExchange ===
        let ske_record = self.read_dtls_record().await?;
        let ske_tls = dtls_to_tls_handshake(&ske_record.fragment)?;
        let (_, ske_body, _) = parse_handshake_header(&ske_tls)?;
        client_hs.process_server_key_exchange(&ske_record.fragment, ske_body)?;

        // === Read ServerHelloDone ===
        let shd_record = self.read_dtls_record().await?;

        // === Process ServerHelloDone → client flight ===
        let mut cflight = client_hs.process_server_hello_done(&shd_record.fragment)?;

        // Send ClientKeyExchange (plaintext, epoch 0)
        self.send_handshake(&cflight.client_key_exchange).await?;

        // Send CCS (epoch 0)
        self.send_ccs().await?;

        // Bump client write epoch (0 → 1)
        self.write_epoch.next_epoch();
        self.encryptor = Some(create_dtlcp_encryptor(
            suite,
            &cflight.client_write_key,
            &cflight.client_write_mac_key,
            &cflight.client_write_iv,
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
        self.decryptor = Some(create_dtlcp_decryptor(
            suite,
            &cflight.server_write_key,
            &cflight.server_write_mac_key,
            &cflight.server_write_iv,
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
        self.state = DtlcpConnectionState::Connected;

        // Zeroize key material
        cflight.master_secret.zeroize();
        cflight.client_write_key.zeroize();
        cflight.server_write_key.zeroize();
        cflight.client_write_mac_key.zeroize();
        cflight.server_write_mac_key.zeroize();

        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncTlsConnection for AsyncDtlcpClientConnection<S> {
    async fn handshake(&mut self) -> Result<(), TlsError> {
        if self.state != DtlcpConnectionState::Handshaking {
            return Err(TlsError::HandshakeFailed(
                "handshake already completed or failed".into(),
            ));
        }
        match self.do_handshake().await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.state = DtlcpConnectionState::Error;
                Err(e)
            }
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if self.state != DtlcpConnectionState::Connected {
            return Err(TlsError::RecordError("not connected".into()));
        }
        if buf.is_empty() {
            return Ok(0);
        }

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
                    let alert_data = if let Some(ref mut dec) = self.decryptor {
                        dec.decrypt_record(&record).unwrap_or(record.fragment)
                    } else {
                        record.fragment
                    };
                    if alert_data.len() >= 2 && alert_data[1] == 0 {
                        self.received_close_notify = true;
                        self.state = DtlcpConnectionState::Closed;
                        return Ok(0);
                    }
                    return Err(TlsError::AlertReceived(format!(
                        "alert: level={} desc={}",
                        alert_data.first().unwrap_or(&0),
                        alert_data.get(1).unwrap_or(&0)
                    )));
                }
                _ => {
                    continue; // ignore unexpected record types
                }
            }
        }
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        if self.state != DtlcpConnectionState::Connected {
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
        if self.state == DtlcpConnectionState::Closed {
            return Ok(());
        }
        if self.state != DtlcpConnectionState::Connected {
            return Err(TlsError::RecordError("not connected".into()));
        }

        if !self.config.quiet_shutdown {
            self.send_encrypted_alert(1, 0).await?;
            self.sent_close_notify = true;
        }
        self.state = DtlcpConnectionState::Closed;
        Ok(())
    }

    fn version(&self) -> Option<TlsVersion> {
        if self.state == DtlcpConnectionState::Connected
            || self.state == DtlcpConnectionState::Closed
        {
            Some(TlsVersion::Dtlcp)
        } else {
            None
        }
    }

    fn cipher_suite(&self) -> Option<CipherSuite> {
        self.negotiated_suite
    }
}

// ===========================================================================
// Async DTLCP Server Connection
// ===========================================================================

/// An asynchronous DTLCP server connection.
pub struct AsyncDtlcpServerConnection<S: AsyncRead + AsyncWrite + Unpin> {
    stream: S,
    config: TlsConfig,
    write_epoch: EpochState,
    read_epoch: EpochState,
    encryptor: Option<DtlcpEncryptor>,
    decryptor: Option<DtlcpDecryptor>,
    anti_replay: AntiReplayWindow,
    state: DtlcpConnectionState,
    negotiated_suite: Option<CipherSuite>,
    read_buf: Vec<u8>,
    app_data_buf: Vec<u8>,
    sent_close_notify: bool,
    received_close_notify: bool,
    enable_cookie: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncDtlcpServerConnection<S> {
    /// Create a new async DTLCP server connection.
    pub fn new(stream: S, config: TlsConfig, enable_cookie: bool) -> Self {
        Self {
            stream,
            config,
            write_epoch: EpochState::new(),
            read_epoch: EpochState::new(),
            encryptor: None,
            decryptor: None,
            anti_replay: AntiReplayWindow::new(),
            state: DtlcpConnectionState::Handshaking,
            negotiated_suite: None,
            read_buf: Vec::with_capacity(16 * 1024),
            app_data_buf: Vec::new(),
            sent_close_notify: false,
            received_close_notify: false,
            enable_cookie,
        }
    }

    /// Get a snapshot of the negotiated connection parameters.
    pub fn connection_info(&self) -> Option<ConnectionInfo> {
        self.negotiated_suite.map(|suite| ConnectionInfo {
            cipher_suite: suite,
            peer_certificates: Vec::new(),
            alpn_protocol: None,
            server_name: None,
            negotiated_group: None,
            session_resumed: false,
            peer_verify_data: Vec::new(),
            local_verify_data: Vec::new(),
        })
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
            version: DTLCP_VERSION,
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
            version: DTLCP_VERSION,
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
        let mut server_hs = DtlcpServerHandshake::new(self.config.clone(), self.enable_cookie);

        // === Read ClientHello ===
        let ch_record = self.read_dtls_record().await?;
        let ch_hs_msg = ch_record.fragment;

        let result = server_hs.process_client_hello(&ch_hs_msg)?;

        let flight = match result {
            Ok(flight) => flight,
            Err(hvr_result) => {
                // Send HelloVerifyRequest
                self.send_handshake(&hvr_result.hello_verify_request)
                    .await?;

                // Read ClientHello with cookie
                let ch2_record = self.read_dtls_record().await?;
                server_hs.process_client_hello_with_cookie(&ch2_record.fragment)?
            }
        };

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
        let server_dec = create_dtlcp_decryptor(
            suite,
            &keys.client_write_key,
            &keys.client_write_mac_key,
            &keys.client_write_iv,
        )?;
        self.decryptor = Some(server_dec);

        // === Read client Finished (encrypted) ===
        let fin_record = self.read_dtls_record().await?;
        let fin_plain = self
            .decryptor
            .as_mut()
            .unwrap()
            .decrypt_record(&fin_record)?;

        let (fin_header, _, _) = parse_dtls_handshake_header(&fin_plain)?;
        if fin_header.msg_type != HandshakeType::Finished {
            return Err(TlsError::HandshakeFailed("expected Finished".into()));
        }
        let server_fin_result = server_hs.process_finished(&fin_plain)?;

        // === Send server CCS + Finished ===
        self.send_ccs().await?;

        // Bump server write epoch (0 → 1)
        self.write_epoch.next_epoch();
        self.encryptor = Some(create_dtlcp_encryptor(
            suite,
            &keys.server_write_key,
            &keys.server_write_mac_key,
            &keys.server_write_iv,
        )?);

        self.send_encrypted_handshake(&server_fin_result.finished)
            .await?;

        // === Handshake complete ===
        self.state = DtlcpConnectionState::Connected;

        // Zeroize
        keys.master_secret.zeroize();
        keys.client_write_key.zeroize();
        keys.server_write_key.zeroize();
        keys.client_write_mac_key.zeroize();
        keys.server_write_mac_key.zeroize();

        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncTlsConnection for AsyncDtlcpServerConnection<S> {
    async fn handshake(&mut self) -> Result<(), TlsError> {
        if self.state != DtlcpConnectionState::Handshaking {
            return Err(TlsError::HandshakeFailed(
                "handshake already completed or failed".into(),
            ));
        }
        match self.do_handshake().await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.state = DtlcpConnectionState::Error;
                Err(e)
            }
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if self.state != DtlcpConnectionState::Connected {
            return Err(TlsError::RecordError("not connected".into()));
        }
        if buf.is_empty() {
            return Ok(0);
        }

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
                        self.state = DtlcpConnectionState::Closed;
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
        if self.state != DtlcpConnectionState::Connected {
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
        if self.state == DtlcpConnectionState::Closed {
            return Ok(());
        }
        if self.state != DtlcpConnectionState::Connected {
            return Err(TlsError::RecordError("not connected".into()));
        }

        if !self.config.quiet_shutdown {
            self.send_encrypted_alert(1, 0).await?;
            self.sent_close_notify = true;
        }
        self.state = DtlcpConnectionState::Closed;
        Ok(())
    }

    fn version(&self) -> Option<TlsVersion> {
        if self.state == DtlcpConnectionState::Connected
            || self.state == DtlcpConnectionState::Closed
        {
            Some(TlsVersion::Dtlcp)
        } else {
            None
        }
    }

    fn cipher_suite(&self) -> Option<CipherSuite> {
        self.negotiated_suite
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerPrivateKey;
    use crate::crypt::SignatureScheme;

    fn create_test_sm2_certs() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        use hitls_crypto::sm2::Sm2KeyPair;
        use hitls_pki::x509::{
            CertificateBuilder, DistinguishedName, SigningKey, SubjectPublicKeyInfo,
        };
        use hitls_utils::oid::known;

        let sign_kp = Sm2KeyPair::generate().unwrap();
        let sign_pubkey = sign_kp.public_key_bytes().unwrap();
        let sign_privkey = sign_kp.private_key_bytes().unwrap();

        let enc_kp = Sm2KeyPair::generate().unwrap();
        let enc_pubkey = enc_kp.public_key_bytes().unwrap();
        let enc_privkey = enc_kp.private_key_bytes().unwrap();

        let sign_spki = SubjectPublicKeyInfo {
            algorithm_oid: known::ec_public_key().to_der_value(),
            algorithm_params: Some(known::sm2_curve().to_der_value()),
            public_key: sign_pubkey,
        };
        let sign_sk = SigningKey::Sm2(sign_kp);
        let sign_dn = DistinguishedName {
            entries: vec![("CN".to_string(), "Async DTLCP Sign".to_string())],
        };
        let sign_cert = CertificateBuilder::new()
            .serial_number(&[0x01])
            .issuer(sign_dn.clone())
            .subject(sign_dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(sign_spki)
            .build(&sign_sk)
            .unwrap();

        let enc_spki = SubjectPublicKeyInfo {
            algorithm_oid: known::ec_public_key().to_der_value(),
            algorithm_params: Some(known::sm2_curve().to_der_value()),
            public_key: enc_pubkey,
        };
        let enc_sk = SigningKey::Sm2(enc_kp);
        let enc_dn = DistinguishedName {
            entries: vec![("CN".to_string(), "Async DTLCP Enc".to_string())],
        };
        let enc_cert = CertificateBuilder::new()
            .serial_number(&[0x02])
            .issuer(enc_dn.clone())
            .subject(enc_dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(enc_spki)
            .build(&enc_sk)
            .unwrap();

        (sign_privkey, sign_cert.raw, enc_privkey, enc_cert.raw)
    }

    fn build_dtlcp_configs(suite: CipherSuite) -> (TlsConfig, TlsConfig) {
        let (sign_privkey, sign_cert, enc_privkey, enc_cert) = create_test_sm2_certs();

        let client_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .signature_algorithms(&[SignatureScheme::SM2_SM3])
            .verify_peer(false)
            .build();

        let server_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .signature_algorithms(&[SignatureScheme::SM2_SM3])
            .certificate_chain(vec![sign_cert])
            .private_key(ServerPrivateKey::Sm2 {
                private_key: sign_privkey,
            })
            .tlcp_enc_certificate_chain(vec![enc_cert])
            .tlcp_enc_private_key(ServerPrivateKey::Sm2 {
                private_key: enc_privkey,
            })
            .verify_peer(false)
            .build();

        (client_config, server_config)
    }

    #[tokio::test]
    async fn test_async_dtlcp_read_before_handshake() {
        let (client_stream, _server_stream) = tokio::io::duplex(64 * 1024);
        let config = build_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3).0;
        let mut client = AsyncDtlcpClientConnection::new(client_stream, config);
        let mut buf = [0u8; 16];
        let err = client.read(&mut buf).await.unwrap_err();
        match err {
            TlsError::RecordError(msg) => assert!(msg.contains("not connected")),
            _ => panic!("expected RecordError, got {err:?}"),
        }
    }

    #[tokio::test]
    async fn test_async_dtlcp_full_handshake_and_data() {
        let (client_config, server_config) = build_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncDtlcpClientConnection::new(client_stream, client_config);
        let mut server = AsyncDtlcpServerConnection::new(server_stream, server_config, false);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        // Client -> Server
        let msg = b"Hello from async DTLCP client!";
        client.write(msg).await.unwrap();
        let mut buf = [0u8; 256];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg);

        // Server -> Client
        let reply = b"Hello from async DTLCP server!";
        server.write(reply).await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], reply);
    }

    #[tokio::test]
    async fn test_async_dtlcp_with_cookie() {
        let (client_config, server_config) = build_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncDtlcpClientConnection::new(client_stream, client_config);
        let mut server = AsyncDtlcpServerConnection::new(server_stream, server_config, true);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        assert_eq!(client.version(), Some(TlsVersion::Dtlcp));
        assert_eq!(server.version(), Some(TlsVersion::Dtlcp));

        // Verify data exchange after cookie handshake
        let msg = b"Cookie exchange data";
        client.write(msg).await.unwrap();
        let mut buf = [0u8; 256];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg);
    }

    #[tokio::test]
    async fn test_async_dtlcp_shutdown() {
        let (client_config, server_config) = build_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncDtlcpClientConnection::new(client_stream, client_config);
        let mut server = AsyncDtlcpServerConnection::new(server_stream, server_config, false);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        // Shutdown client
        client.shutdown().await.unwrap();
        assert_eq!(client.version(), Some(TlsVersion::Dtlcp));

        // Double shutdown is OK
        client.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_async_dtlcp_connection_info() {
        let (client_config, server_config) = build_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncDtlcpClientConnection::new(client_stream, client_config);
        let mut server = AsyncDtlcpServerConnection::new(server_stream, server_config, false);

        // Before handshake
        assert!(client.connection_info().is_none());
        assert_eq!(client.version(), None);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        assert_eq!(client.version(), Some(TlsVersion::Dtlcp));
        assert_eq!(server.version(), Some(TlsVersion::Dtlcp));
        assert_eq!(client.cipher_suite(), Some(CipherSuite::ECDHE_SM4_GCM_SM3));

        let info = client.connection_info().unwrap();
        assert_eq!(info.cipher_suite, CipherSuite::ECDHE_SM4_GCM_SM3);

        let sinfo = server.connection_info().unwrap();
        assert_eq!(sinfo.cipher_suite, CipherSuite::ECDHE_SM4_GCM_SM3);
    }

    #[tokio::test]
    async fn test_async_dtlcp_bidirectional() {
        let (client_config, server_config) = build_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncDtlcpClientConnection::new(client_stream, client_config);
        let mut server = AsyncDtlcpServerConnection::new(server_stream, server_config, false);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        // Multiple bidirectional messages
        for i in 0..10 {
            let msg = format!("DTLCP async message {i}");
            client.write(msg.as_bytes()).await.unwrap();
            let mut buf = [0u8; 256];
            let n = server.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());

            let reply = format!("DTLCP async reply {i}");
            server.write(reply.as_bytes()).await.unwrap();
            let n = client.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], reply.as_bytes());
        }
    }

    #[tokio::test]
    async fn test_async_dtlcp_large_payload() {
        let (client_config, server_config) = build_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let (client_stream, server_stream) = tokio::io::duplex(128 * 1024);
        let mut client = AsyncDtlcpClientConnection::new(client_stream, client_config);
        let mut server = AsyncDtlcpServerConnection::new(server_stream, server_config, false);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        // Send 32 KB
        let payload = vec![0xCD; 32 * 1024];
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
    async fn test_async_dtlcp_write_before_handshake() {
        let (client_stream, _server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncDtlcpClientConnection::new(
            client_stream,
            build_dtlcp_configs(CipherSuite::ECDHE_SM4_CBC_SM3).0,
        );
        let result = client.write(b"data").await;
        assert!(result.is_err(), "write before handshake should fail");
    }

    #[tokio::test]
    async fn test_async_dtlcp_shutdown_before_connected_fails() {
        let (client_config, _server_config) =
            build_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let (cs, _ss) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncDtlcpClientConnection::new(cs, client_config);
        // DTLCP requires Connected state for shutdown
        let result = client.shutdown().await;
        assert!(result.is_err(), "DTLCP shutdown before handshake should fail");
    }
}
