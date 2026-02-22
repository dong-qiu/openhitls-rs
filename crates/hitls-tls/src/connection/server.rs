use std::io::{Read, Write};

use super::ConnectionState;
use crate::config::TlsConfig;
use crate::connection_info::ConnectionInfo;
use crate::crypt::key_schedule::KeySchedule;
use crate::crypt::traffic_keys::TrafficKeys;
use crate::crypt::{CipherSuiteParams, NamedGroup};
use crate::handshake::codec::{
    decode_certificate, decode_certificate_verify, decode_finished, decode_key_update,
    encode_certificate_request, encode_key_update, parse_handshake_header, CertificateRequestMsg,
    KeyUpdateMsg, KeyUpdateRequest,
};
use crate::handshake::server::{ClientHelloResult, ServerHandshake};
use crate::handshake::HandshakeType;
use crate::record::{ContentType, RecordLayer};
use crate::{CipherSuite, TlsConnection, TlsError, TlsVersion};
use zeroize::Zeroize;

/// A synchronous TLS 1.3 server connection.
pub struct TlsServerConnection<S: Read + Write> {
    stream: S,
    config: TlsConfig,
    record_layer: RecordLayer,
    pub(super) state: ConnectionState,
    negotiated_suite: Option<CipherSuite>,
    negotiated_version: Option<TlsVersion>,
    read_buf: Vec<u8>,
    app_data_buf: Vec<u8>,
    /// Cipher suite parameters (for key updates).
    cipher_params: Option<CipherSuiteParams>,
    /// Client application traffic secret (for key updates).
    client_app_secret: Vec<u8>,
    /// Server application traffic secret (for key updates).
    server_app_secret: Vec<u8>,
    /// Exporter master secret (for RFC 5705 / RFC 8446 §7.5 key material export).
    exporter_master_secret: Vec<u8>,
    /// Early exporter master secret (for 0-RTT key material export, empty if no PSK).
    early_exporter_master_secret: Vec<u8>,
    /// Peer certificates (DER-encoded, leaf first).
    peer_certificates: Vec<Vec<u8>>,
    /// Negotiated ALPN protocol (if any).
    negotiated_alpn: Option<Vec<u8>>,
    /// Client server name (SNI) received from the client.
    client_server_name: Option<String>,
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

impl<S: Read + Write> Drop for TlsServerConnection<S> {
    fn drop(&mut self) {
        self.client_app_secret.zeroize();
        self.server_app_secret.zeroize();
        self.exporter_master_secret.zeroize();
        self.early_exporter_master_secret.zeroize();
    }
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
            cipher_params: None,
            client_app_secret: Vec::new(),
            server_app_secret: Vec::new(),
            exporter_master_secret: Vec::new(),
            early_exporter_master_secret: Vec::new(),
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

    /// Client server name (SNI) received from the client.
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
        // Update write key (server_app_secret for server)
        let ks = KeySchedule::new(params.clone());
        let new_secret = ks.update_traffic_secret(&self.server_app_secret)?;
        let new_keys = TrafficKeys::derive(&params, &new_secret)?;
        self.record_layer
            .activate_write_encryption(params.suite, &new_keys)?;
        self.server_app_secret.zeroize();
        self.server_app_secret = new_secret;
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
        // Update read key (client_app_secret for server)
        let ks = KeySchedule::new(params.clone());
        let new_secret = ks.update_traffic_secret(&self.client_app_secret)?;
        let new_keys = TrafficKeys::derive(&params, &new_secret)?;
        self.record_layer
            .activate_read_decryption(params.suite, &new_keys)?;
        self.client_app_secret.zeroize();
        self.client_app_secret = new_secret;
        // If requested, respond with our own KeyUpdate
        if ku.request_update == KeyUpdateRequest::UpdateRequested {
            self.key_update(false)?;
        }
        Ok(())
    }

    /// Request post-handshake client authentication (RFC 8446 §4.6.2).
    ///
    /// Sends a CertificateRequest message and reads the client's
    /// Certificate + CertificateVerify + Finished response.
    /// Returns the client's certificate chain (DER-encoded certs), which
    /// may be empty if the client has no certificate.
    pub fn request_client_auth(&mut self) -> Result<Vec<Vec<u8>>, TlsError> {
        use crate::crypt::SignatureScheme;
        use crate::handshake::extensions_codec::build_signature_algorithms;
        use crate::handshake::verify::verify_certificate_verify;

        if self.state != ConnectionState::Connected {
            return Err(TlsError::HandshakeFailed(
                "request_client_auth: not connected".into(),
            ));
        }

        let params = self
            .cipher_params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher params".into()))?
            .clone();
        let factory = params.hash_factory();
        let ks = KeySchedule::new(params.clone());

        // Generate random context for this request
        let mut context = vec![0u8; 8];
        getrandom::getrandom(&mut context)
            .map_err(|e| TlsError::HandshakeFailed(format!("random error: {e}")))?;

        // Build CertificateRequest with signature_algorithms extension
        let sig_algs = vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            SignatureScheme::ECDSA_SECP384R1_SHA384,
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PSS_RSAE_SHA384,
            SignatureScheme::RSA_PSS_RSAE_SHA512,
        ];
        let mut cr_exts = vec![build_signature_algorithms(&sig_algs)];
        if !self.config.oid_filters.is_empty() {
            cr_exts.push(crate::handshake::extensions_codec::build_oid_filters(
                &self.config.oid_filters,
            ));
        }
        let cr = CertificateRequestMsg {
            certificate_request_context: context.clone(),
            extensions: cr_exts,
        };
        let cr_msg = encode_certificate_request(&cr);

        // Send CertificateRequest
        let cr_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &cr_msg)?;
        self.stream
            .write_all(&cr_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Start transcript for this post-HS exchange (just the CertificateRequest)
        let mut hasher = (*factory)();
        hasher.update(&cr_msg).map_err(TlsError::CryptoError)?;

        // Read client Certificate
        let (ct, cert_data) = self.read_record()?;
        if ct != ContentType::Handshake {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Handshake (Certificate), got {ct:?}"
            )));
        }
        let (hs_type, cert_body, cert_total) = parse_handshake_header(&cert_data)?;
        if hs_type != HandshakeType::Certificate {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Certificate, got {hs_type:?}"
            )));
        }
        let cert_msg_data = &cert_data[..cert_total];
        let cert_msg = decode_certificate(cert_body)?;

        // Verify context matches
        if cert_msg.certificate_request_context != context {
            return Err(TlsError::HandshakeFailed(
                "certificate_request_context mismatch".into(),
            ));
        }

        let client_certs: Vec<Vec<u8>> = cert_msg
            .certificate_list
            .iter()
            .map(|e| e.cert_data.clone())
            .collect();

        // Update transcript with Certificate
        hasher
            .update(cert_msg_data)
            .map_err(TlsError::CryptoError)?;

        if client_certs.is_empty() {
            // Client sent empty Certificate — no CertificateVerify expected.
            // Read Finished.
            let mut fin_hash_buf = vec![0u8; params.hash_len];
            let mut hasher_fin = (*factory)();
            hasher_fin.update(&cr_msg).map_err(TlsError::CryptoError)?;
            hasher_fin
                .update(cert_msg_data)
                .map_err(TlsError::CryptoError)?;
            hasher_fin
                .finish(&mut fin_hash_buf)
                .map_err(TlsError::CryptoError)?;

            let (ct3, fin_data) = self.read_record()?;
            if ct3 != ContentType::Handshake {
                return Err(TlsError::HandshakeFailed(format!(
                    "expected Handshake (Finished), got {ct3:?}"
                )));
            }
            let (hs_type3, fin_body, _) = parse_handshake_header(&fin_data)?;
            if hs_type3 != HandshakeType::Finished {
                return Err(TlsError::HandshakeFailed(format!(
                    "expected Finished, got {hs_type3:?}"
                )));
            }
            let fin_msg = decode_finished(fin_body, params.hash_len)?;

            // Verify Finished
            let finished_key = ks.derive_finished_key(&self.client_app_secret)?;
            let expected = ks.compute_finished_verify_data(&finished_key, &fin_hash_buf)?;
            if fin_msg.verify_data != expected {
                return Err(TlsError::HandshakeFailed(
                    "post-HS client Finished verification failed".into(),
                ));
            }

            return Ok(client_certs);
        }

        // Read CertificateVerify
        let (ct2, cv_data) = self.read_record()?;
        if ct2 != ContentType::Handshake {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Handshake (CertificateVerify), got {ct2:?}"
            )));
        }
        let (hs_type2, cv_body, cv_total) = parse_handshake_header(&cv_data)?;
        if hs_type2 != HandshakeType::CertificateVerify {
            return Err(TlsError::HandshakeFailed(format!(
                "expected CertificateVerify, got {hs_type2:?}"
            )));
        }
        let cv_msg_data = &cv_data[..cv_total];
        let cv_msg = decode_certificate_verify(cv_body)?;

        // Verify CertificateVerify signature against transcript hash
        let mut cv_hash = vec![0u8; params.hash_len];
        let mut hasher_cv = (*factory)();
        hasher_cv.update(&cr_msg).map_err(TlsError::CryptoError)?;
        hasher_cv
            .update(cert_msg_data)
            .map_err(TlsError::CryptoError)?;
        hasher_cv
            .finish(&mut cv_hash)
            .map_err(TlsError::CryptoError)?;

        // Parse the first client cert to verify the signature
        let client_cert = hitls_pki::x509::Certificate::from_der(&client_certs[0])
            .map_err(|e| TlsError::HandshakeFailed(format!("client cert parse: {e}")))?;
        verify_certificate_verify(
            &client_cert,
            cv_msg.algorithm,
            &cv_msg.signature,
            &cv_hash,
            false, // client CertificateVerify
        )?;

        // Update transcript with CertificateVerify, then compute hash for Finished
        hasher
            .update(cert_msg_data)
            .map_err(TlsError::CryptoError)?;
        // We need a fresh hasher for the Finished hash that includes CR+Cert+CV
        let mut fin_hash_buf = vec![0u8; params.hash_len];
        let mut hasher_fin = (*factory)();
        hasher_fin.update(&cr_msg).map_err(TlsError::CryptoError)?;
        hasher_fin
            .update(cert_msg_data)
            .map_err(TlsError::CryptoError)?;
        hasher_fin
            .update(cv_msg_data)
            .map_err(TlsError::CryptoError)?;
        hasher_fin
            .finish(&mut fin_hash_buf)
            .map_err(TlsError::CryptoError)?;

        // Read Finished
        let (ct3, fin_data) = self.read_record()?;
        if ct3 != ContentType::Handshake {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Handshake (Finished), got {ct3:?}"
            )));
        }
        let (hs_type3, fin_body, _) = parse_handshake_header(&fin_data)?;
        if hs_type3 != HandshakeType::Finished {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Finished, got {hs_type3:?}"
            )));
        }
        let fin_msg = decode_finished(fin_body, params.hash_len)?;

        // Verify Finished
        let finished_key = ks.derive_finished_key(&self.client_app_secret)?;
        let expected = ks.compute_finished_verify_data(&finished_key, &fin_hash_buf)?;
        if fin_msg.verify_data != expected {
            return Err(TlsError::HandshakeFailed(
                "post-HS client Finished verification failed".into(),
            ));
        }

        Ok(client_certs)
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

        // Step 2: Process ClientHello — may result in HRR
        let actions = match hs.process_client_hello(ch_msg)? {
            ClientHelloResult::Actions(actions) => *actions,
            ClientHelloResult::HelloRetryRequest(hrr_actions) => {
                // Send HRR as plaintext
                let hrr_record = self
                    .record_layer
                    .seal_record(ContentType::Handshake, &hrr_actions.hrr_msg)?;
                self.stream
                    .write_all(&hrr_record)
                    .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

                // Read retried ClientHello
                let (ct2, ch2_data) = self.read_record()?;
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

        // Apply client's record size limit (TLS 1.3: subtract 1 for content type)
        if let Some(limit) = hs.client_record_size_limit() {
            self.record_layer.max_fragment_size = limit.saturating_sub(1) as usize;
        }

        // Step 3: Send ServerHello as plaintext record
        let sh_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &actions.server_hello_msg)?;
        self.stream
            .write_all(&sh_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Step 4: Activate handshake write encryption
        self.record_layer
            .activate_write_encryption(actions.suite, &actions.server_hs_keys)?;

        // Step 4b: If 0-RTT accepted, activate early read decryption first
        if actions.early_data_accepted {
            if let Some(ref early_keys) = actions.early_read_keys {
                self.record_layer
                    .activate_read_decryption(actions.suite, early_keys)?;
            }
        } else {
            self.record_layer
                .activate_read_decryption(actions.suite, &actions.client_hs_keys)?;
        }

        // Step 5: Send EE, [Certificate, CertificateVerify], Finished as encrypted records
        let ee_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)?;
        self.stream
            .write_all(&ee_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        if !actions.psk_mode {
            for msg in &[&actions.certificate_msg, &actions.certificate_verify_msg] {
                let record = self.record_layer.seal_record(ContentType::Handshake, msg)?;
                self.stream
                    .write_all(&record)
                    .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
            }
        }

        let sfin_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &actions.server_finished_msg)?;
        self.stream
            .write_all(&sfin_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Step 5b: If 0-RTT accepted, read early data + EndOfEarlyData
        if actions.early_data_accepted {
            loop {
                let (ct, data) = self.read_record()?;
                match ct {
                    ContentType::ApplicationData => {
                        // Buffer early data for later retrieval
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
            // Switch read to HS keys for client Finished
            self.record_layer
                .activate_read_decryption(actions.suite, &actions.client_hs_keys)?;
        }

        // Step 6: Read client Finished (encrypted with HS keys)
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
        let fin_actions = hs.process_client_finished(fin_msg)?;

        // Step 8: Activate application keys
        self.record_layer
            .activate_read_decryption(actions.suite, &actions.client_app_keys)?;
        self.record_layer
            .activate_write_encryption(actions.suite, &actions.server_app_keys)?;
        // Wire record padding callback (TLS 1.3)
        if let Some(ref cb) = self.config.record_padding_callback {
            self.record_layer.set_record_padding_callback(cb.clone());
        }

        // Step 9: Send NewSessionTicket(s) if generated
        for nst_msg in &fin_actions.new_session_ticket_msgs {
            let nst_record = self
                .record_layer
                .seal_record(ContentType::Handshake, nst_msg)?;
            self.stream
                .write_all(&nst_record)
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // Save secrets for key updates and export
        self.cipher_params = Some(actions.cipher_params);
        self.client_app_secret = actions.client_app_secret;
        self.server_app_secret = actions.server_app_secret;
        self.exporter_master_secret = actions.exporter_master_secret;
        self.early_exporter_master_secret = actions.early_exporter_master_secret;

        self.negotiated_suite = Some(actions.suite);
        self.negotiated_version = Some(TlsVersion::Tls13);

        // Populate connection info from handshake state
        self.peer_certificates = hs.client_certs().to_vec();
        self.negotiated_alpn = hs.negotiated_alpn().map(|a| a.to_vec());
        self.client_server_name = hs.client_server_name().map(|s| s.to_string());
        self.negotiated_group = hs.negotiated_group();

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
                    // Post-handshake message (e.g., KeyUpdate)
                    let (hs_type, body, _) = parse_handshake_header(&plaintext)?;
                    match hs_type {
                        HandshakeType::KeyUpdate => {
                            self.handle_key_update(body)?;
                            continue; // read next record
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
