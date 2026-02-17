//! Asynchronous TLS 1.3 connection wrapping an `AsyncRead + AsyncWrite` transport.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::TlsConfig;
use crate::connection_info::ConnectionInfo;
use crate::crypt::key_schedule::KeySchedule;
use crate::crypt::traffic_keys::TrafficKeys;
use crate::crypt::{CipherSuiteParams, NamedGroup};
use crate::handshake::client::{ClientHandshake, ServerHelloResult};
use crate::handshake::codec::{
    decode_certificate_request, decode_key_update, encode_certificate, encode_certificate_verify,
    encode_finished, encode_key_update, parse_handshake_header, CertificateEntry, CertificateMsg,
    CertificateVerifyMsg, KeyUpdateMsg, KeyUpdateRequest,
};
use crate::handshake::server::{ClientHelloResult, ServerHandshake};
use crate::handshake::{HandshakeState, HandshakeType};
use crate::record::{ContentType, RecordLayer};
use crate::session::TlsSession;
use crate::{AsyncTlsConnection, CipherSuite, TlsError, TlsVersion};
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
// Async TLS 1.3 Client Connection
// ===========================================================================

/// An asynchronous TLS 1.3 client connection.
pub struct AsyncTlsClientConnection<S: AsyncRead + AsyncWrite + Unpin> {
    stream: S,
    config: TlsConfig,
    record_layer: RecordLayer,
    state: ConnectionState,
    negotiated_suite: Option<CipherSuite>,
    negotiated_version: Option<TlsVersion>,
    read_buf: Vec<u8>,
    app_data_buf: Vec<u8>,
    cipher_params: Option<CipherSuiteParams>,
    client_app_secret: Vec<u8>,
    server_app_secret: Vec<u8>,
    resumption_master_secret: Vec<u8>,
    client_hs: Option<ClientHandshake>,
    received_session: Option<TlsSession>,
    early_data_queue: Vec<u8>,
    early_data_accepted: bool,
    peer_certificates: Vec<Vec<u8>>,
    negotiated_alpn: Option<Vec<u8>>,
    server_name_used: Option<String>,
    negotiated_group: Option<NamedGroup>,
    session_resumed: bool,
    sent_close_notify: bool,
    received_close_notify: bool,
    /// Counter for consecutive KeyUpdate messages without application data.
    key_update_recv_count: u32,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Drop for AsyncTlsClientConnection<S> {
    fn drop(&mut self) {
        self.client_app_secret.zeroize();
        self.server_app_secret.zeroize();
        self.resumption_master_secret.zeroize();
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncTlsClientConnection<S> {
    /// Create a new async TLS client connection wrapping the given stream.
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
            cipher_params: None,
            client_app_secret: Vec::new(),
            server_app_secret: Vec::new(),
            resumption_master_secret: Vec::new(),
            client_hs: None,
            received_session: None,
            early_data_queue: Vec::new(),
            early_data_accepted: false,
            peer_certificates: Vec::new(),
            negotiated_alpn: None,
            server_name_used: None,
            negotiated_group: None,
            session_resumed: false,
            sent_close_notify: false,
            received_close_notify: false,
            key_update_recv_count: 0,
        }
    }

    /// Take the received session (from NewSessionTicket) for future resumption.
    pub fn take_session(&mut self) -> Option<TlsSession> {
        self.received_session.take()
    }

    /// Queue early data to be sent during the 0-RTT phase.
    pub fn queue_early_data(&mut self, data: &[u8]) {
        self.early_data_queue.extend_from_slice(data);
    }

    /// Whether the server accepted 0-RTT early data.
    pub fn early_data_accepted(&self) -> bool {
        self.early_data_accepted
    }

    /// Return a snapshot of negotiated connection parameters, or `None` if
    /// the handshake has not completed yet.
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

    /// Peer certificates (DER-encoded, leaf first).
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.peer_certificates
    }

    /// Negotiated ALPN protocol (if any).
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
    }

    /// Server name (SNI) used in this connection.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name_used.as_deref()
    }

    /// Negotiated key exchange group (if applicable).
    pub fn negotiated_group(&self) -> Option<NamedGroup> {
        self.negotiated_group
    }

    /// Whether this connection was resumed from a previous session.
    pub fn is_session_resumed(&self) -> bool {
        self.session_resumed
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

    /// Initiate a key update (RFC 8446 §4.6.3).
    pub async fn key_update(&mut self, request_response: bool) -> Result<(), TlsError> {
        if self.state != ConnectionState::Connected {
            return Err(TlsError::HandshakeFailed(
                "key_update: not connected".into(),
            ));
        }
        let params = self
            .cipher_params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher params".into()))?
            .clone();
        let ku = KeyUpdateMsg {
            request_update: if request_response {
                KeyUpdateRequest::UpdateRequested
            } else {
                KeyUpdateRequest::UpdateNotRequested
            },
        };
        let ku_msg = encode_key_update(&ku);
        let record = self
            .record_layer
            .seal_record(ContentType::Handshake, &ku_msg)?;
        self.stream
            .write_all(&record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        let ks = KeySchedule::new(params.clone());
        let new_secret = ks.update_traffic_secret(&self.client_app_secret)?;
        let new_keys = TrafficKeys::derive(&params, &new_secret)?;
        self.record_layer
            .activate_write_encryption(params.suite, &new_keys)?;
        self.client_app_secret.zeroize();
        self.client_app_secret = new_secret;
        Ok(())
    }

    /// Handle a received KeyUpdate message.
    async fn handle_key_update(&mut self, body: &[u8]) -> Result<(), TlsError> {
        self.key_update_recv_count += 1;
        if self.key_update_recv_count > 128 {
            return Err(TlsError::HandshakeFailed(
                "too many consecutive KeyUpdate messages without application data".into(),
            ));
        }
        let ku = decode_key_update(body)?;
        let params = self
            .cipher_params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher params".into()))?
            .clone();
        let ks = KeySchedule::new(params.clone());
        let new_secret = ks.update_traffic_secret(&self.server_app_secret)?;
        let new_keys = TrafficKeys::derive(&params, &new_secret)?;
        self.record_layer
            .activate_read_decryption(params.suite, &new_keys)?;
        self.server_app_secret.zeroize();
        self.server_app_secret = new_secret;
        if ku.request_update == KeyUpdateRequest::UpdateRequested {
            self.key_update(false).await?;
        }
        Ok(())
    }

    /// Handle post-handshake CertificateRequest (simplified).
    async fn handle_post_hs_cert_request(
        &mut self,
        body: &[u8],
        full_msg: &[u8],
    ) -> Result<(), TlsError> {
        use crate::handshake::signing::{select_signature_scheme, sign_certificate_verify};

        if !self.config.post_handshake_auth {
            return Err(TlsError::HandshakeFailed(
                "received CertificateRequest but post_handshake_auth not offered".into(),
            ));
        }

        let cr = decode_certificate_request(body)?;
        let sig_algs_ext = cr
            .extensions
            .iter()
            .find(|e| e.extension_type == crate::extensions::ExtensionType::SIGNATURE_ALGORITHMS)
            .ok_or_else(|| {
                TlsError::HandshakeFailed("CertificateRequest missing signature_algorithms".into())
            })?;
        let server_sig_algs =
            crate::handshake::extensions_codec::parse_signature_algorithms_ch(&sig_algs_ext.data)?;

        let params = self
            .cipher_params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher params".into()))?
            .clone();
        let factory = params.hash_factory();
        let ks = KeySchedule::new(params.clone());

        let mut hasher = (*factory)();
        hasher.update(full_msg).map_err(TlsError::CryptoError)?;
        let mut cr_hash = vec![0u8; params.hash_len];
        hasher.finish(&mut cr_hash).map_err(TlsError::CryptoError)?;

        let cert_msg = if self.config.client_certificate_chain.is_empty() {
            CertificateMsg {
                certificate_request_context: cr.certificate_request_context.clone(),
                certificate_list: vec![],
            }
        } else {
            CertificateMsg {
                certificate_request_context: cr.certificate_request_context.clone(),
                certificate_list: self
                    .config
                    .client_certificate_chain
                    .iter()
                    .map(|cert_der| CertificateEntry {
                        cert_data: cert_der.clone(),
                        extensions: vec![],
                    })
                    .collect(),
            }
        };
        let cert_encoded = encode_certificate(&cert_msg);

        let mut hasher2 = (*factory)();
        hasher2.update(full_msg).map_err(TlsError::CryptoError)?;
        hasher2
            .update(&cert_encoded)
            .map_err(TlsError::CryptoError)?;

        let cert_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &cert_encoded)?;
        self.stream
            .write_all(&cert_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        if let Some(ref client_key) = self.config.client_private_key {
            let scheme = select_signature_scheme(client_key, &server_sig_algs)?;

            let mut cv_hash = vec![0u8; params.hash_len];
            let mut hasher3 = (*factory)();
            hasher3.update(full_msg).map_err(TlsError::CryptoError)?;
            hasher3
                .update(&cert_encoded)
                .map_err(TlsError::CryptoError)?;
            hasher3
                .finish(&mut cv_hash)
                .map_err(TlsError::CryptoError)?;

            let signature = sign_certificate_verify(client_key, scheme, &cv_hash, false)?;
            let cv_msg = encode_certificate_verify(&CertificateVerifyMsg {
                algorithm: scheme,
                signature,
            });

            let cv_record = self
                .record_layer
                .seal_record(ContentType::Handshake, &cv_msg)?;
            self.stream
                .write_all(&cv_record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

            let finished_key = ks.derive_finished_key(&self.client_app_secret)?;
            let mut fin_hash = vec![0u8; params.hash_len];
            let mut hasher4 = (*factory)();
            hasher4.update(full_msg).map_err(TlsError::CryptoError)?;
            hasher4
                .update(&cert_encoded)
                .map_err(TlsError::CryptoError)?;
            hasher4.update(&cv_msg).map_err(TlsError::CryptoError)?;
            hasher4
                .finish(&mut fin_hash)
                .map_err(TlsError::CryptoError)?;

            let verify_data = ks.compute_finished_verify_data(&finished_key, &fin_hash)?;
            let fin_msg = encode_finished(&verify_data);

            let fin_record = self
                .record_layer
                .seal_record(ContentType::Handshake, &fin_msg)?;
            self.stream
                .write_all(&fin_record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        Ok(())
    }

    /// Run the TLS 1.3 client handshake.
    async fn do_handshake(&mut self) -> Result<(), TlsError> {
        // Auto-lookup: if no explicit resumption_session, check cache
        if self.config.resumption_session.is_none() {
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

        let mut hs = ClientHandshake::new(self.config.clone());

        // Build and send ClientHello
        let ch_msg = hs.build_client_hello()?;
        let ch_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &ch_msg)?;
        self.stream
            .write_all(&ch_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 0-RTT early data
        let offered_early_data = hs.offered_early_data();
        if offered_early_data && !self.early_data_queue.is_empty() {
            let params = CipherSuiteParams::from_suite(
                self.config
                    .resumption_session
                    .as_ref()
                    .map(|s| s.cipher_suite)
                    .unwrap_or(CipherSuite::TLS_AES_128_GCM_SHA256),
            )?;
            let early_keys = TrafficKeys::derive(&params, hs.early_traffic_secret())?;
            self.record_layer
                .activate_write_encryption(params.suite, &early_keys)?;
            let early_data = std::mem::take(&mut self.early_data_queue);
            let early_record = self
                .record_layer
                .seal_record(ContentType::ApplicationData, &early_data)?;
            self.stream
                .write_all(&early_record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // Read ServerHello (may be HRR)
        let sh_actions = self.read_and_process_server_hello(&mut hs).await?;

        // Activate handshake read decryption
        self.record_layer
            .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)?;

        let hs_write_suite = sh_actions.suite;
        let hs_write_keys = sh_actions.client_hs_keys;
        if !offered_early_data {
            self.record_layer
                .activate_write_encryption(hs_write_suite, &hs_write_keys)?;
        }

        // Read encrypted handshake flight
        self.process_encrypted_flight(&mut hs, offered_early_data, hs_write_suite, &hs_write_keys)
            .await?;

        self.client_hs = Some(hs);
        Ok(())
    }

    /// Read ServerHello, handle HRR if needed.
    async fn read_and_process_server_hello(
        &mut self,
        hs: &mut ClientHandshake,
    ) -> Result<crate::handshake::client::ServerHelloActions, TlsError> {
        let (ct, sh_data) = self.read_record().await?;
        if ct != ContentType::Handshake {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Handshake, got {ct:?}"
            )));
        }

        let (hs_type, _, sh_total) = parse_handshake_header(&sh_data)?;
        if hs_type != HandshakeType::ServerHello {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ServerHello, got {hs_type:?}"
            )));
        }
        let sh_msg = &sh_data[..sh_total];

        match hs.process_server_hello(sh_msg)? {
            ServerHelloResult::Actions(actions) => Ok(actions),
            ServerHelloResult::RetryNeeded(retry) => {
                let ch2_msg = hs.build_client_hello_retry(&retry)?;
                let ch2_record = self
                    .record_layer
                    .seal_record(ContentType::Handshake, &ch2_msg)?;
                self.stream
                    .write_all(&ch2_record)
                    .await
                    .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

                let (ct2, sh2_data) = self.read_record().await?;
                if ct2 != ContentType::Handshake {
                    return Err(TlsError::HandshakeFailed(format!(
                        "expected Handshake after HRR, got {ct2:?}"
                    )));
                }
                let (hs_type2, _, sh2_total) = parse_handshake_header(&sh2_data)?;
                if hs_type2 != HandshakeType::ServerHello {
                    return Err(TlsError::HandshakeFailed(format!(
                        "expected ServerHello after HRR, got {hs_type2:?}"
                    )));
                }
                let sh2_msg = &sh2_data[..sh2_total];

                match hs.process_server_hello(sh2_msg)? {
                    ServerHelloResult::Actions(actions) => Ok(actions),
                    ServerHelloResult::RetryNeeded(_) => Err(TlsError::HandshakeFailed(
                        "received second HelloRetryRequest".into(),
                    )),
                }
            }
        }
    }

    /// Process the encrypted handshake flight (EE, Cert, CV, Finished).
    async fn process_encrypted_flight(
        &mut self,
        hs: &mut ClientHandshake,
        offered_early_data: bool,
        hs_write_suite: CipherSuite,
        hs_write_keys: &TrafficKeys,
    ) -> Result<(), TlsError> {
        let mut hs_buffer: Vec<u8> = Vec::new();

        loop {
            while hs_buffer.len() >= 4 {
                let msg_len = ((hs_buffer[1] as usize) << 16)
                    | ((hs_buffer[2] as usize) << 8)
                    | (hs_buffer[3] as usize);
                let total = 4 + msg_len;
                if hs_buffer.len() < total {
                    break;
                }

                let msg_data = hs_buffer[..total].to_vec();
                hs_buffer.drain(..total);

                match hs.state() {
                    HandshakeState::WaitEncryptedExtensions => {
                        hs.process_encrypted_extensions(&msg_data)?;
                        if let Some(limit) = hs.peer_record_size_limit() {
                            self.record_layer.max_fragment_size = limit as usize;
                        }
                    }
                    HandshakeState::WaitCertCertReq => {
                        #[cfg(feature = "cert-compression")]
                        if !msg_data.is_empty()
                            && msg_data[0] == HandshakeType::CompressedCertificate as u8
                        {
                            hs.process_compressed_certificate(&msg_data)?;
                        } else {
                            hs.process_certificate(&msg_data)?;
                        }
                        #[cfg(not(feature = "cert-compression"))]
                        hs.process_certificate(&msg_data)?;
                    }
                    HandshakeState::WaitCertVerify => {
                        hs.process_certificate_verify(&msg_data)?;
                    }
                    HandshakeState::WaitFinished => {
                        let fin_actions = hs.process_finished(&msg_data)?;

                        if let Some(ref eoed_msg) = fin_actions.end_of_early_data_msg {
                            let eoed_record = self
                                .record_layer
                                .seal_record(ContentType::Handshake, eoed_msg)?;
                            self.stream
                                .write_all(&eoed_record)
                                .await
                                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
                            self.early_data_accepted = true;
                        }

                        if offered_early_data {
                            self.record_layer
                                .activate_write_encryption(hs_write_suite, hs_write_keys)?;
                        }

                        let fin_record = self.record_layer.seal_record(
                            ContentType::Handshake,
                            &fin_actions.client_finished_msg,
                        )?;
                        self.stream
                            .write_all(&fin_record)
                            .await
                            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

                        self.record_layer.activate_read_decryption(
                            fin_actions.suite,
                            &fin_actions.server_app_keys,
                        )?;
                        self.record_layer.activate_write_encryption(
                            fin_actions.suite,
                            &fin_actions.client_app_keys,
                        )?;

                        self.cipher_params = Some(fin_actions.cipher_params);
                        self.client_app_secret = fin_actions.client_app_secret;
                        self.server_app_secret = fin_actions.server_app_secret;
                        self.resumption_master_secret = fin_actions.resumption_master_secret;

                        self.negotiated_suite = Some(fin_actions.suite);
                        self.negotiated_version = Some(TlsVersion::Tls13);
                        self.peer_certificates = hs.server_certs().to_vec();
                        self.negotiated_alpn = hs.negotiated_alpn().map(|a| a.to_vec());
                        self.server_name_used = self.config.server_name.clone();
                        self.negotiated_group = hs.negotiated_group();
                        self.session_resumed = hs.is_psk_mode();
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

            let (ct, plaintext) = self.read_record().await?;
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

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncTlsConnection for AsyncTlsClientConnection<S> {
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

        if !self.app_data_buf.is_empty() {
            let n = std::cmp::min(buf.len(), self.app_data_buf.len());
            buf[..n].copy_from_slice(&self.app_data_buf[..n]);
            self.app_data_buf.drain(..n);
            return Ok(n);
        }

        loop {
            let (ct, plaintext) = self.read_record().await?;
            match ct {
                ContentType::ApplicationData => {
                    self.key_update_recv_count = 0;
                    let n = std::cmp::min(buf.len(), plaintext.len());
                    buf[..n].copy_from_slice(&plaintext[..n]);
                    if plaintext.len() > n {
                        self.app_data_buf.extend_from_slice(&plaintext[n..]);
                    }
                    return Ok(n);
                }
                ContentType::Handshake => {
                    let (hs_type, body, total) = parse_handshake_header(&plaintext)?;
                    match hs_type {
                        HandshakeType::KeyUpdate => {
                            self.handle_key_update(body).await?;
                            continue;
                        }
                        HandshakeType::NewSessionTicket => {
                            if let Some(ref hs) = self.client_hs {
                                if let Ok(session) = hs.process_new_session_ticket(
                                    &plaintext[..total],
                                    &self.resumption_master_secret,
                                ) {
                                    // Auto-store in session cache
                                    if let (Some(ref cache_mutex), Some(ref server_name)) =
                                        (&self.config.session_cache, &self.config.server_name)
                                    {
                                        if let Ok(mut cache) = cache_mutex.lock() {
                                            cache.put(server_name.as_bytes(), session.clone());
                                        }
                                    }
                                    self.received_session = Some(session);
                                }
                            }
                            continue;
                        }
                        HandshakeType::CertificateRequest => {
                            let body_owned = body.to_vec();
                            let full_msg_owned = plaintext[..total].to_vec();
                            self.handle_post_hs_cert_request(&body_owned, &full_msg_owned)
                                .await?;
                            continue;
                        }
                        _ => {
                            return Err(TlsError::HandshakeFailed(format!(
                                "unexpected post-handshake message: {hs_type:?}"
                            )));
                        }
                    }
                }
                ContentType::Alert => {
                    if plaintext.len() >= 2 && plaintext[1] == 0 {
                        self.received_close_notify = true;
                    }
                    self.state = ConnectionState::Closed;
                    return Ok(0);
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
        if !self.sent_close_notify {
            let alert_data = [1u8, 0u8];
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
        match self.state {
            ConnectionState::Connected | ConnectionState::Closed => self.negotiated_version,
            _ => self.negotiated_version,
        }
    }

    fn cipher_suite(&self) -> Option<CipherSuite> {
        self.negotiated_suite
    }
}

// ===========================================================================
// Async TLS 1.3 Server Connection
// ===========================================================================

/// An asynchronous TLS 1.3 server connection.
pub struct AsyncTlsServerConnection<S: AsyncRead + AsyncWrite + Unpin> {
    stream: S,
    config: TlsConfig,
    record_layer: RecordLayer,
    state: ConnectionState,
    negotiated_suite: Option<CipherSuite>,
    negotiated_version: Option<TlsVersion>,
    read_buf: Vec<u8>,
    app_data_buf: Vec<u8>,
    cipher_params: Option<CipherSuiteParams>,
    client_app_secret: Vec<u8>,
    server_app_secret: Vec<u8>,
    peer_certificates: Vec<Vec<u8>>,
    negotiated_alpn: Option<Vec<u8>>,
    client_server_name: Option<String>,
    negotiated_group: Option<NamedGroup>,
    session_resumed: bool,
    sent_close_notify: bool,
    received_close_notify: bool,
    /// Counter for consecutive KeyUpdate messages without application data.
    key_update_recv_count: u32,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Drop for AsyncTlsServerConnection<S> {
    fn drop(&mut self) {
        self.client_app_secret.zeroize();
        self.server_app_secret.zeroize();
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncTlsServerConnection<S> {
    /// Create a new async TLS server connection wrapping the given stream.
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
            cipher_params: None,
            client_app_secret: Vec::new(),
            server_app_secret: Vec::new(),
            peer_certificates: Vec::new(),
            negotiated_alpn: None,
            client_server_name: None,
            negotiated_group: None,
            session_resumed: false,
            sent_close_notify: false,
            received_close_notify: false,
            key_update_recv_count: 0,
        }
    }

    /// Return a snapshot of negotiated connection parameters, or `None` if
    /// the handshake has not completed yet.
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

    /// Peer certificates (DER-encoded, leaf first).
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.peer_certificates
    }

    /// Negotiated ALPN protocol (if any).
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
    }

    /// Client server name (SNI) used in this connection.
    pub fn server_name(&self) -> Option<&str> {
        self.client_server_name.as_deref()
    }

    /// Negotiated key exchange group (if applicable).
    pub fn negotiated_group(&self) -> Option<NamedGroup> {
        self.negotiated_group
    }

    /// Whether this connection was resumed from a previous session.
    pub fn is_session_resumed(&self) -> bool {
        self.session_resumed
    }

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

    async fn read_record(&mut self) -> Result<(ContentType, Vec<u8>), TlsError> {
        self.fill_buf(5).await?;
        let length = u16::from_be_bytes([self.read_buf[3], self.read_buf[4]]) as usize;
        self.fill_buf(5 + length).await?;
        let (ct, plaintext, consumed) = self.record_layer.open_record(&self.read_buf)?;
        self.read_buf.drain(..consumed);
        Ok((ct, plaintext))
    }

    pub async fn key_update(&mut self, request_response: bool) -> Result<(), TlsError> {
        if self.state != ConnectionState::Connected {
            return Err(TlsError::HandshakeFailed(
                "key_update: not connected".into(),
            ));
        }
        let params = self
            .cipher_params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher params".into()))?
            .clone();
        let ku = KeyUpdateMsg {
            request_update: if request_response {
                KeyUpdateRequest::UpdateRequested
            } else {
                KeyUpdateRequest::UpdateNotRequested
            },
        };
        let ku_msg = encode_key_update(&ku);
        let record = self
            .record_layer
            .seal_record(ContentType::Handshake, &ku_msg)?;
        self.stream
            .write_all(&record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        let ks = KeySchedule::new(params.clone());
        let new_secret = ks.update_traffic_secret(&self.server_app_secret)?;
        let new_keys = TrafficKeys::derive(&params, &new_secret)?;
        self.record_layer
            .activate_write_encryption(params.suite, &new_keys)?;
        self.server_app_secret.zeroize();
        self.server_app_secret = new_secret;
        Ok(())
    }

    async fn handle_key_update(&mut self, body: &[u8]) -> Result<(), TlsError> {
        self.key_update_recv_count += 1;
        if self.key_update_recv_count > 128 {
            return Err(TlsError::HandshakeFailed(
                "too many consecutive KeyUpdate messages without application data".into(),
            ));
        }
        let ku = decode_key_update(body)?;
        let params = self
            .cipher_params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher params".into()))?
            .clone();
        let ks = KeySchedule::new(params.clone());
        let new_secret = ks.update_traffic_secret(&self.client_app_secret)?;
        let new_keys = TrafficKeys::derive(&params, &new_secret)?;
        self.record_layer
            .activate_read_decryption(params.suite, &new_keys)?;
        self.client_app_secret.zeroize();
        self.client_app_secret = new_secret;
        if ku.request_update == KeyUpdateRequest::UpdateRequested {
            self.key_update(false).await?;
        }
        Ok(())
    }

    /// Run the TLS 1.3 server handshake.
    async fn do_handshake(&mut self) -> Result<(), TlsError> {
        let mut hs = ServerHandshake::new(self.config.clone());

        // Read ClientHello
        let (ct, ch_data) = self.read_record().await?;
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

        // Process ClientHello (may result in HRR)
        let actions = match hs.process_client_hello(ch_msg)? {
            ClientHelloResult::Actions(actions) => *actions,
            ClientHelloResult::HelloRetryRequest(hrr_actions) => {
                let hrr_record = self
                    .record_layer
                    .seal_record(ContentType::Handshake, &hrr_actions.hrr_msg)?;
                self.stream
                    .write_all(&hrr_record)
                    .await
                    .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

                let (ct2, ch2_data) = self.read_record().await?;
                if ct2 != ContentType::Handshake {
                    return Err(TlsError::HandshakeFailed(format!(
                        "expected Handshake after HRR, got {ct2:?}"
                    )));
                }
                let (hs_type2, _, ch2_total) = parse_handshake_header(&ch2_data)?;
                if hs_type2 != HandshakeType::ClientHello {
                    return Err(TlsError::HandshakeFailed(format!(
                        "expected ClientHello after HRR, got {hs_type2:?}"
                    )));
                }
                let ch2_msg = &ch2_data[..ch2_total];
                hs.process_client_hello_retry(ch2_msg)?
            }
        };

        if let Some(limit) = hs.client_record_size_limit() {
            self.record_layer.max_fragment_size = limit.saturating_sub(1) as usize;
        }

        // Send ServerHello
        let sh_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &actions.server_hello_msg)?;
        self.stream
            .write_all(&sh_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Activate handshake encryption
        self.record_layer
            .activate_write_encryption(actions.suite, &actions.server_hs_keys)?;

        if actions.early_data_accepted {
            if let Some(ref early_keys) = actions.early_read_keys {
                self.record_layer
                    .activate_read_decryption(actions.suite, early_keys)?;
            }
        } else {
            self.record_layer
                .activate_read_decryption(actions.suite, &actions.client_hs_keys)?;
        }

        // Send EE, [Certificate, CertificateVerify], Finished
        let ee_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)?;
        self.stream
            .write_all(&ee_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        if !actions.psk_mode {
            for msg in &[&actions.certificate_msg, &actions.certificate_verify_msg] {
                let record = self.record_layer.seal_record(ContentType::Handshake, msg)?;
                self.stream
                    .write_all(&record)
                    .await
                    .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
            }
        }

        let sfin_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &actions.server_finished_msg)?;
        self.stream
            .write_all(&sfin_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 0-RTT early data
        if actions.early_data_accepted {
            loop {
                let (ct, data) = self.read_record().await?;
                match ct {
                    ContentType::ApplicationData => {
                        self.app_data_buf.extend_from_slice(&data);
                    }
                    ContentType::Handshake => {
                        let (hs_type, _, total) = parse_handshake_header(&data)?;
                        if hs_type == HandshakeType::EndOfEarlyData {
                            hs.process_end_of_early_data(&data[..total])?;
                            break;
                        } else {
                            return Err(TlsError::HandshakeFailed(format!(
                                "expected EndOfEarlyData, got {hs_type:?}"
                            )));
                        }
                    }
                    _ => {
                        return Err(TlsError::HandshakeFailed(format!(
                            "unexpected content type during 0-RTT: {ct:?}"
                        )));
                    }
                }
            }
            self.record_layer
                .activate_read_decryption(actions.suite, &actions.client_hs_keys)?;
        }

        // Read client Finished
        let (ct, fin_data) = self.read_record().await?;
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

        let fin_actions = hs.process_client_finished(fin_msg)?;

        // Activate application keys
        self.record_layer
            .activate_read_decryption(actions.suite, &actions.client_app_keys)?;
        self.record_layer
            .activate_write_encryption(actions.suite, &actions.server_app_keys)?;

        // Send NewSessionTicket(s)
        for nst_msg in &fin_actions.new_session_ticket_msgs {
            let nst_record = self
                .record_layer
                .seal_record(ContentType::Handshake, nst_msg)?;
            self.stream
                .write_all(&nst_record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        self.cipher_params = Some(actions.cipher_params);
        self.client_app_secret = actions.client_app_secret;
        self.server_app_secret = actions.server_app_secret;

        self.negotiated_suite = Some(actions.suite);
        self.negotiated_version = Some(TlsVersion::Tls13);
        self.peer_certificates = hs.client_certs().to_vec();
        self.negotiated_alpn = hs.negotiated_alpn().map(|a| a.to_vec());
        self.client_server_name = hs.client_server_name().map(|s| s.to_string());
        self.negotiated_group = hs.negotiated_group();
        self.state = ConnectionState::Connected;
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncTlsConnection for AsyncTlsServerConnection<S> {
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

        if !self.app_data_buf.is_empty() {
            let n = std::cmp::min(buf.len(), self.app_data_buf.len());
            buf[..n].copy_from_slice(&self.app_data_buf[..n]);
            self.app_data_buf.drain(..n);
            return Ok(n);
        }

        loop {
            let (ct, plaintext) = self.read_record().await?;
            match ct {
                ContentType::ApplicationData => {
                    self.key_update_recv_count = 0;
                    let n = std::cmp::min(buf.len(), plaintext.len());
                    buf[..n].copy_from_slice(&plaintext[..n]);
                    if plaintext.len() > n {
                        self.app_data_buf.extend_from_slice(&plaintext[n..]);
                    }
                    return Ok(n);
                }
                ContentType::Handshake => {
                    let (hs_type, body, _) = parse_handshake_header(&plaintext)?;
                    match hs_type {
                        HandshakeType::KeyUpdate => {
                            self.handle_key_update(body).await?;
                            continue;
                        }
                        _ => {
                            return Err(TlsError::HandshakeFailed(format!(
                                "unexpected post-handshake message: {hs_type:?}"
                            )));
                        }
                    }
                }
                ContentType::Alert => {
                    if plaintext.len() >= 2 && plaintext[1] == 0 {
                        self.received_close_notify = true;
                    }
                    self.state = ConnectionState::Closed;
                    return Ok(0);
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
        if !self.sent_close_notify {
            let alert_data = [1u8, 0u8];
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
        match self.state {
            ConnectionState::Connected | ConnectionState::Closed => self.negotiated_version,
            _ => self.negotiated_version,
        }
    }

    fn cipher_suite(&self) -> Option<CipherSuite> {
        self.negotiated_suite
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_async_client_creation() {
        let (client, _server) = tokio::io::duplex(16 * 1024);
        let config = TlsConfig::builder().build();
        let conn = AsyncTlsClientConnection::new(client, config);
        assert_eq!(conn.state, ConnectionState::Handshaking);
        assert!(conn.version().is_none());
        assert!(conn.cipher_suite().is_none());
    }

    #[test]
    fn test_async_server_creation() {
        let (_client, server) = tokio::io::duplex(16 * 1024);
        let config = TlsConfig::builder().build();
        let conn = AsyncTlsServerConnection::new(server, config);
        assert_eq!(conn.state, ConnectionState::Handshaking);
        assert!(conn.version().is_none());
        assert!(conn.cipher_suite().is_none());
    }
}
