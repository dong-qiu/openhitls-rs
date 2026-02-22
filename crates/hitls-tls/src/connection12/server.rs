use std::io::{Read, Write};

use super::ConnectionState;
use crate::alert::{AlertDescription, AlertLevel};
use crate::config::TlsConfig;
use crate::connection_info::ConnectionInfo;
use crate::crypt::NamedGroup;
use crate::handshake::codec::parse_handshake_header;
use crate::handshake::server12::{ServerHelloResult, Tls12ServerHandshake};
use crate::handshake::HandshakeType;
use crate::record::{ContentType, RecordLayer};
use crate::session::TlsSession;
use crate::{CipherSuite, TlsConnection, TlsError, TlsVersion};
use zeroize::Zeroize;

/// A synchronous TLS 1.2 server connection.
pub struct Tls12ServerConnection<S: Read + Write> {
    stream: S,
    config: TlsConfig,
    record_layer: RecordLayer,
    pub(super) state: ConnectionState,
    negotiated_suite: Option<CipherSuite>,
    /// Buffer for reading records from the stream.
    read_buf: Vec<u8>,
    /// Buffered decrypted application data.
    app_data_buf: Vec<u8>,
    /// Session state for session ticket issuance.
    session: Option<TlsSession>,
    /// Master secret (for RFC 5705 key material export).
    export_master_secret: Vec<u8>,
    /// Client random (for RFC 5705 key material export).
    export_client_random: [u8; 32],
    /// Server random (for RFC 5705 key material export).
    export_server_random: [u8; 32],
    /// PRF hash length (for determining hash factory).
    export_hash_len: usize,
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
    pub(super) received_close_notify: bool,
}

impl<S: Read + Write> Drop for Tls12ServerConnection<S> {
    fn drop(&mut self) {
        self.export_master_secret.zeroize();
    }
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
            export_master_secret: Vec::new(),
            export_client_random: [0u8; 32],
            export_server_random: [0u8; 32],
            export_hash_len: 0,
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

    /// Export keying material per RFC 5705.
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
        let factory =
            crate::crypt::Tls12CipherSuiteParams::hash_factory_for_len(self.export_hash_len);
        crate::crypt::export::tls12_export_keying_material(
            &*factory,
            &self.export_master_secret,
            &self.export_client_random,
            &self.export_server_random,
            label,
            context,
            length,
        )
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

        // 2. Process ClientHello (with ticket support + session ID cache)
        let cache_ref = self
            .config
            .session_cache
            .as_ref()
            .map(|c| c.lock().unwrap());
        let result = hs.process_client_hello_resumable(
            &ch_data,
            cache_ref
                .as_deref()
                .map(|c| c as &dyn crate::session::SessionCache),
        )?;
        drop(cache_ref);

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

        // 4. Send Certificate (if present — PSK suites skip this)
        if let Some(ref cert_msg) = flight.certificate {
            let cert_record = self
                .record_layer
                .seal_record(ContentType::Handshake, cert_msg)?;
            self.stream
                .write_all(&cert_record)
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // 4b. Send CertificateStatus (if OCSP stapling, RFC 6066)
        if let Some(ref cs_msg) = flight.certificate_status {
            let cs_record = self
                .record_layer
                .seal_record(ContentType::Handshake, cs_msg)?;
            self.stream
                .write_all(&cs_record)
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // 5. Send ServerKeyExchange (if present — not sent for RSA key exchange)
        if let Some(ref ske_msg) = flight.server_key_exchange {
            let ske_record = self
                .record_layer
                .seal_record(ContentType::Handshake, ske_msg)?;
            self.stream
                .write_all(&ske_record)
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

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
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Store export parameters (before zeroizing master_secret)
        self.export_master_secret = keys.master_secret.clone();
        self.export_client_random = *hs.client_random();
        self.export_server_random = *hs.server_random();
        if let Ok(p) = crate::crypt::Tls12CipherSuiteParams::from_suite(suite) {
            self.export_hash_len = p.hash_len;
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

        // Store session in cache for session ID-based resumption
        if let Some(ref cache_mutex) = self.config.session_cache {
            let session_id = hs.session_id();
            if !session_id.is_empty() {
                if let Ok(mut cache) = cache_mutex.lock() {
                    let session = TlsSession {
                        id: session_id.to_vec(),
                        cipher_suite: suite,
                        master_secret: self.export_master_secret.clone(),
                        alpn_protocol: self.negotiated_alpn.clone(),
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
        let (hs_type, fin_data) = self.read_handshake_msg()?;
        if hs_type != HandshakeType::Finished {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Finished, got {hs_type:?}"
            )));
        }
        hs.process_abbreviated_finished(&fin_data)?;

        // Store export parameters (before zeroizing master_secret)
        self.export_master_secret = abbr.master_secret.clone();
        self.export_client_random = *hs.client_random();
        self.export_server_random = *hs.server_random();
        if let Ok(p) = crate::crypt::Tls12CipherSuiteParams::from_suite(suite) {
            self.export_hash_len = p.hash_len;
        }

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
    pub fn initiate_renegotiation(&mut self) -> Result<(), TlsError> {
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
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        self.state = ConnectionState::Renegotiating;
        Ok(())
    }

    /// Perform server-side renegotiation with the received ClientHello.
    fn do_server_renegotiation(&mut self, ch_data: Vec<u8>) -> Result<(), TlsError> {
        let mut hs = Tls12ServerHandshake::new(self.config.clone());
        hs.setup_renegotiation(
            std::mem::take(&mut self.client_verify_data),
            std::mem::take(&mut self.server_verify_data),
        );

        let cache_ref = self
            .config
            .session_cache
            .as_ref()
            .map(|c| c.lock().unwrap());
        let result = hs.process_client_hello_resumable(
            &ch_data,
            cache_ref
                .as_deref()
                .map(|c| c as &dyn crate::session::SessionCache),
        )?;
        drop(cache_ref);

        match result {
            ServerHelloResult::Full(flight) => {
                self.do_server_renego_full(&mut hs, flight)?;
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
    fn do_server_renego_full(
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
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Send Certificate (if present)
        if let Some(ref cert_msg) = flight.certificate {
            let cert_record = self
                .record_layer
                .seal_record(ContentType::Handshake, cert_msg)?;
            self.stream
                .write_all(&cert_record)
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // Send CertificateStatus (if OCSP stapling)
        if let Some(ref cs_msg) = flight.certificate_status {
            let cs_record = self
                .record_layer
                .seal_record(ContentType::Handshake, cs_msg)?;
            self.stream
                .write_all(&cs_record)
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // Send ServerKeyExchange (if present)
        if let Some(ref ske_msg) = flight.server_key_exchange {
            let ske_record = self
                .record_layer
                .seal_record(ContentType::Handshake, ske_msg)?;
            self.stream
                .write_all(&ske_record)
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // Send CertificateRequest (if mTLS enabled)
        if let Some(ref cr_msg) = flight.certificate_request {
            let cr_record = self
                .record_layer
                .seal_record(ContentType::Handshake, cr_msg)?;
            self.stream
                .write_all(&cr_record)
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // Send ServerHelloDone
        let shd_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &flight.server_hello_done)?;
        self.stream
            .write_all(&shd_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Read client Certificate (if mTLS)
        if flight.certificate_request.is_some() {
            let (hs_type, cert_data) = self.read_handshake_msg()?;
            if hs_type != HandshakeType::Certificate {
                return Err(TlsError::HandshakeFailed(format!(
                    "expected client Certificate, got {hs_type:?}"
                )));
            }
            hs.process_client_certificate(&cert_data)?;
        }

        // Read ClientKeyExchange
        let (hs_type, cke_data) = self.read_handshake_msg()?;
        if hs_type != HandshakeType::ClientKeyExchange {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ClientKeyExchange, got {hs_type:?}"
            )));
        }
        let mut keys = hs.process_client_key_exchange(&cke_data)?;

        // Read client CertificateVerify (if client sent certs)
        if hs.state() == crate::handshake::server12::Tls12ServerState::WaitClientCertificateVerify {
            let (hs_type, cv_data) = self.read_handshake_msg()?;
            if hs_type != HandshakeType::CertificateVerify {
                return Err(TlsError::HandshakeFailed(format!(
                    "expected CertificateVerify, got {hs_type:?}"
                )));
            }
            hs.process_client_certificate_verify(&cv_data)?;
        }

        // Read ChangeCipherSpec from client
        let (ct, _ccs_data) = self.read_record()?;
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
        let (hs_type, fin_data) = self.read_handshake_msg()?;
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
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Update export parameters
        self.export_master_secret = keys.master_secret.clone();
        self.export_client_random = *hs.client_random();
        self.export_server_random = *hs.server_random();
        if let Ok(p) = crate::crypt::Tls12CipherSuiteParams::from_suite(suite) {
            self.export_hash_len = p.hash_len;
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

        // Store session in cache for session ID-based resumption
        if let Some(ref cache_mutex) = self.config.session_cache {
            let session_id = hs.session_id();
            if !session_id.is_empty() {
                if let Ok(mut cache) = cache_mutex.lock() {
                    let session = TlsSession {
                        id: session_id.to_vec(),
                        cipher_suite: suite,
                        master_secret: self.export_master_secret.clone(),
                        alpn_protocol: self.negotiated_alpn.clone(),
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

            let (ct, plaintext) = self.read_record()?;
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
                        // Client refused renegotiation — go back to Connected
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
                            self.do_server_renegotiation(ch_data)?;
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
            let alert_data = [1u8, 0u8]; // close_notify
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
