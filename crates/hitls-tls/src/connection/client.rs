use std::io::{Read, Write};

use super::ConnectionState;
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
use crate::handshake::{HandshakeState, HandshakeType};
use crate::record::{ContentType, RecordLayer};
use crate::session::TlsSession;
use crate::{CipherSuite, TlsConnection, TlsError, TlsVersion};
use zeroize::Zeroize;

/// A synchronous TLS 1.3 client connection.
pub struct TlsClientConnection<S: Read + Write> {
    stream: S,
    config: TlsConfig,
    record_layer: RecordLayer,
    pub(super) state: ConnectionState,
    negotiated_suite: Option<CipherSuite>,
    negotiated_version: Option<TlsVersion>,
    /// Buffer for reading records from the stream.
    read_buf: Vec<u8>,
    /// Buffered decrypted application data.
    app_data_buf: Vec<u8>,
    /// Cipher suite parameters (for key updates).
    pub(super) cipher_params: Option<CipherSuiteParams>,
    /// Client application traffic secret (for key updates).
    pub(super) client_app_secret: Vec<u8>,
    /// Server application traffic secret (for key updates).
    pub(super) server_app_secret: Vec<u8>,
    /// Resumption master secret (for processing NewSessionTicket).
    resumption_master_secret: Vec<u8>,
    /// Exporter master secret (for RFC 5705 / RFC 8446 §7.5 key material export).
    exporter_master_secret: Vec<u8>,
    /// Early exporter master secret (for 0-RTT key material export, empty if no PSK).
    pub(super) early_exporter_master_secret: Vec<u8>,
    /// Client handshake state (kept for processing post-handshake messages).
    client_hs: Option<ClientHandshake>,
    /// Received session from NewSessionTicket (for resumption).
    received_session: Option<TlsSession>,
    /// Early data to send during 0-RTT (queued before handshake).
    pub(super) early_data_queue: Vec<u8>,
    /// Whether early data was accepted by the server in this connection.
    early_data_accepted: bool,
    /// Peer certificates (DER-encoded, leaf first).
    peer_certificates: Vec<Vec<u8>>,
    /// Negotiated ALPN protocol (if any).
    negotiated_alpn: Option<Vec<u8>>,
    /// Server name (SNI) used in this connection.
    server_name_used: Option<String>,
    /// Negotiated key exchange group (if applicable).
    negotiated_group: Option<NamedGroup>,
    /// Whether this connection was resumed from a previous session.
    session_resumed: bool,
    /// Whether we have sent close_notify.
    sent_close_notify: bool,
    /// Whether we have received close_notify.
    received_close_notify: bool,
    /// Counter for consecutive KeyUpdate messages without application data.
    pub(super) key_update_recv_count: u32,
}

impl<S: Read + Write> Drop for TlsClientConnection<S> {
    fn drop(&mut self) {
        self.client_app_secret.zeroize();
        self.server_app_secret.zeroize();
        self.resumption_master_secret.zeroize();
        self.exporter_master_secret.zeroize();
        self.early_exporter_master_secret.zeroize();
    }
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
            cipher_params: None,
            client_app_secret: Vec::new(),
            server_app_secret: Vec::new(),
            resumption_master_secret: Vec::new(),
            exporter_master_secret: Vec::new(),
            early_exporter_master_secret: Vec::new(),
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

    /// Queue early data to be sent during the 0-RTT phase of the handshake.
    /// Must be called before `handshake()`. The data will be sent if the server
    /// accepts 0-RTT; otherwise it is discarded.
    pub fn queue_early_data(&mut self, data: &[u8]) {
        self.early_data_queue.extend_from_slice(data);
    }

    /// Whether the server accepted 0-RTT early data in this connection.
    pub fn early_data_accepted(&self) -> bool {
        self.early_data_accepted
    }

    /// Export keying material per RFC 8446 §7.5 / RFC 5705.
    ///
    /// Derives `length` bytes of key material from the TLS session using the
    /// given label and optional context. Must only be called after the handshake
    /// completes.
    pub fn export_keying_material(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
        length: usize,
    ) -> Result<Vec<u8>, TlsError> {
        if self.state != ConnectionState::Connected {
            return Err(TlsError::HandshakeFailed(
                "export_keying_material: not connected".into(),
            ));
        }
        let params = self
            .cipher_params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher params".into()))?;
        let factory = params.hash_factory();
        crate::crypt::export::tls13_export_keying_material(
            &*factory,
            &self.exporter_master_secret,
            label,
            context,
            length,
        )
    }

    /// Export early keying material per RFC 8446 §7.5 (0-RTT context).
    ///
    /// Uses the early exporter master secret derived during PSK-based handshakes.
    /// Returns an error if no PSK was offered (empty early exporter master secret).
    pub fn export_early_keying_material(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
        length: usize,
    ) -> Result<Vec<u8>, TlsError> {
        if self.early_exporter_master_secret.is_empty() {
            return Err(TlsError::HandshakeFailed(
                "export_early_keying_material: no early exporter master secret (no PSK offered)"
                    .into(),
            ));
        }
        let params = self
            .cipher_params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher params".into()))?;
        let factory = params.hash_factory();
        crate::crypt::export::tls13_export_early_keying_material(
            &*factory,
            &self.early_exporter_master_secret,
            label,
            context,
            length,
        )
    }

    /// Return a snapshot of the negotiated connection parameters.
    ///
    /// Returns `None` if no cipher suite has been negotiated yet (i.e. before
    /// the handshake completes).
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

    /// Initiate a key update (RFC 8446 §4.6.3).
    ///
    /// Sends a KeyUpdate message and updates the write encryption key.
    /// If `request_response` is true, the peer must respond with its own KeyUpdate.
    pub fn key_update(&mut self, request_response: bool) -> Result<(), TlsError> {
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
        // Encode and send KeyUpdate with old write key
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
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        // Update write key (client_app_secret)
        let ks = KeySchedule::new(params.clone());
        let new_secret = ks.update_traffic_secret(&self.client_app_secret)?;
        let new_keys = TrafficKeys::derive(&params, &new_secret)?;
        self.record_layer
            .activate_write_encryption(params.suite, &new_keys)?;
        self.client_app_secret.zeroize();
        self.client_app_secret = new_secret;
        Ok(())
    }

    /// Handle a received KeyUpdate message (updates read key, optionally responds).
    fn handle_key_update(&mut self, body: &[u8]) -> Result<(), TlsError> {
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
        // Update read key (server_app_secret)
        let ks = KeySchedule::new(params.clone());
        let new_secret = ks.update_traffic_secret(&self.server_app_secret)?;
        let new_keys = TrafficKeys::derive(&params, &new_secret)?;
        self.record_layer
            .activate_read_decryption(params.suite, &new_keys)?;
        self.server_app_secret.zeroize();
        self.server_app_secret = new_secret;
        // If requested, respond with our own KeyUpdate
        if ku.request_update == KeyUpdateRequest::UpdateRequested {
            self.key_update(false)?;
        }
        Ok(())
    }

    /// Handle a post-handshake CertificateRequest from the server (RFC 8446 §4.6.2).
    ///
    /// Responds with Certificate + CertificateVerify + Finished.
    pub(super) fn handle_post_hs_cert_request(
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

        // Extract signature_algorithms from CertificateRequest extensions
        let sig_algs_ext = cr
            .extensions
            .iter()
            .find(|e| e.extension_type == crate::extensions::ExtensionType::SIGNATURE_ALGORITHMS)
            .ok_or_else(|| {
                TlsError::HandshakeFailed("CertificateRequest missing signature_algorithms".into())
            })?;
        let server_sig_algs =
            crate::handshake::extensions_codec::parse_signature_algorithms_ch(&sig_algs_ext.data)?;

        // Build a transcript for this post-handshake exchange.
        // Per RFC 8446 §4.4.2, the handshake context for post-HS auth is:
        //   Hash(Handshake Context) || CertificateRequest
        // We use the cipher suite's hash. The "Handshake Context" is approximated
        // by the application traffic transcript hash which we don't fully track post-HS.
        // Instead, we create a fresh transcript containing just CertificateRequest.
        let params = self
            .cipher_params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher params".into()))?
            .clone();
        let factory = params.hash_factory();
        let ks = KeySchedule::new(params.clone());

        // Compute transcript hash over CertificateRequest message
        let mut hasher = (*factory)();
        hasher.update(full_msg).map_err(TlsError::CryptoError)?;
        let mut cr_hash = vec![0u8; params.hash_len];
        hasher.finish(&mut cr_hash).map_err(TlsError::CryptoError)?;

        // Build Certificate message
        let cert_msg = if self.config.client_certificate_chain.is_empty() {
            // Send empty Certificate (no client cert available)
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

        // Update transcript with Certificate
        let mut hasher2 = (*factory)();
        hasher2.update(full_msg).map_err(TlsError::CryptoError)?;
        hasher2
            .update(&cert_encoded)
            .map_err(TlsError::CryptoError)?;

        // Send Certificate
        let cert_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &cert_encoded)?;
        self.stream
            .write_all(&cert_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        if let Some(ref client_key) = self.config.client_private_key {
            // Build and send CertificateVerify
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
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

            // Build and send Finished
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
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        Ok(())
    }

    /// Run the TLS 1.3 client handshake.
    fn do_handshake(&mut self) -> Result<(), TlsError> {
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

        // Step 1: Build and send ClientHello
        let ch_msg = hs.build_client_hello()?;
        let ch_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &ch_msg)?;
        self.stream
            .write_all(&ch_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Step 1b: If offering 0-RTT, activate early write key and send queued data
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

            // Send queued early data
            let early_data = std::mem::take(&mut self.early_data_queue);
            let early_record = self
                .record_layer
                .seal_record(ContentType::ApplicationData, &early_data)?;
            self.stream
                .write_all(&early_record)
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // Step 2: Read ServerHello (plaintext record) — may be HRR
        let sh_actions = self.read_and_process_server_hello(&mut hs)?;

        // Activate handshake read decryption
        self.record_layer
            .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)?;

        // For 0-RTT, defer HS write activation until after EOED
        let hs_write_suite = sh_actions.suite;
        let hs_write_keys = sh_actions.client_hs_keys;
        if !offered_early_data {
            self.record_layer
                .activate_write_encryption(hs_write_suite, &hs_write_keys)?;
        }

        // Step 3-6: Read encrypted handshake messages
        self.process_encrypted_flight(&mut hs, offered_early_data, hs_write_suite, &hs_write_keys)?;

        // Keep the handshake state for processing post-handshake messages (NST)
        self.client_hs = Some(hs);
        Ok(())
    }

    /// Read ServerHello, handle HRR if needed, return handshake encryption keys.
    fn read_and_process_server_hello(
        &mut self,
        hs: &mut ClientHandshake,
    ) -> Result<crate::handshake::client::ServerHelloActions, TlsError> {
        let (ct, sh_data) = self.read_record()?;
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
                // Build and send retried ClientHello
                let ch2_msg = hs.build_client_hello_retry(&retry)?;
                let ch2_record = self
                    .record_layer
                    .seal_record(ContentType::Handshake, &ch2_msg)?;
                self.stream
                    .write_all(&ch2_record)
                    .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

                // Read real ServerHello
                let (ct2, sh2_data) = self.read_record()?;
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
    fn process_encrypted_flight(
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
                        // Apply peer's record size limit (TLS 1.3)
                        if let Some(limit) = hs.peer_record_size_limit() {
                            self.record_layer.max_fragment_size = limit as usize;
                        }
                    }
                    HandshakeState::WaitCertCertReq => {
                        // Check message type: Certificate (11) or CompressedCertificate (25)
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

                        // If 0-RTT was accepted, send EOED with early key then switch
                        if let Some(ref eoed_msg) = fin_actions.end_of_early_data_msg {
                            let eoed_record = self
                                .record_layer
                                .seal_record(ContentType::Handshake, eoed_msg)?;
                            self.stream
                                .write_all(&eoed_record)
                                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
                            self.early_data_accepted = true;
                        }

                        // If we offered early data, now switch write to HS keys
                        if offered_early_data {
                            self.record_layer
                                .activate_write_encryption(hs_write_suite, hs_write_keys)?;
                        }

                        // Send client Finished with HS write key
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
                        // Wire record padding callback (TLS 1.3)
                        if let Some(ref cb) = self.config.record_padding_callback {
                            self.record_layer.set_record_padding_callback(cb.clone());
                        }

                        self.cipher_params = Some(fin_actions.cipher_params);
                        self.client_app_secret = fin_actions.client_app_secret;
                        self.server_app_secret = fin_actions.server_app_secret;
                        self.resumption_master_secret = fin_actions.resumption_master_secret;
                        self.exporter_master_secret = fin_actions.exporter_master_secret;
                        self.early_exporter_master_secret =
                            fin_actions.early_exporter_master_secret;

                        self.negotiated_suite = Some(fin_actions.suite);
                        self.negotiated_version = Some(TlsVersion::Tls13);

                        // Populate connection info from handshake state
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

        loop {
            let (ct, plaintext) = self.read_record()?;
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
                    // Post-handshake message (e.g., KeyUpdate, NewSessionTicket)
                    let (hs_type, body, total) = parse_handshake_header(&plaintext)?;
                    match hs_type {
                        HandshakeType::KeyUpdate => {
                            self.handle_key_update(body)?;
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
                            self.handle_post_hs_cert_request(body, &plaintext[..total])?;
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

    fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
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
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
            offset = end;
        }
        Ok(buf.len())
    }

    fn shutdown(&mut self) -> Result<(), TlsError> {
        if self.state == ConnectionState::Closed {
            return Ok(());
        }

        if !self.config.quiet_shutdown && !self.sent_close_notify {
            let alert_data = [1u8, 0u8];
            let record = self
                .record_layer
                .seal_record(ContentType::Alert, &alert_data)?;
            let _ = self.stream.write_all(&record);
            self.sent_close_notify = true;
        }
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
