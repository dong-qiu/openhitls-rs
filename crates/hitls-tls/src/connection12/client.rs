use std::io::{Read, Write};

use super::ConnectionState;
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
use crate::handshake::HandshakeType;
use crate::record::{ContentType, RecordLayer};
use crate::session::TlsSession;
use crate::{CipherSuite, TlsConnection, TlsError, TlsVersion};
use zeroize::Zeroize;

/// A synchronous TLS 1.2 client connection.
pub struct Tls12ClientConnection<S: Read + Write> {
    stream: S,
    config: TlsConfig,
    pub(super) record_layer: RecordLayer,
    pub(super) state: ConnectionState,
    negotiated_suite: Option<CipherSuite>,
    /// Buffer for reading records from the stream.
    read_buf: Vec<u8>,
    /// Buffered decrypted application data.
    app_data_buf: Vec<u8>,
    /// Session state for resumption (populated after handshake).
    pub(super) session: Option<TlsSession>,
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
    /// Server name used for this connection.
    server_name_used: Option<String>,
    /// Negotiated key exchange group (if applicable).
    negotiated_group: Option<NamedGroup>,
    /// Whether this connection was resumed from a previous session.
    session_resumed: bool,
    /// Whether we have sent close_notify.
    pub(super) sent_close_notify: bool,
    /// Whether we have received close_notify.
    pub(super) received_close_notify: bool,
}

impl<S: Read + Write> Drop for Tls12ClientConnection<S> {
    fn drop(&mut self) {
        self.export_master_secret.zeroize();
    }
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
            export_master_secret: Vec::new(),
            export_client_random: [0u8; 32],
            export_server_random: [0u8; 32],
            export_hash_len: 0,
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

    /// Export keying material per RFC 5705.
    ///
    /// Derives `length` bytes of key material from the TLS 1.2 session using
    /// the PRF, the given label, and optional context. Must only be called
    /// after the handshake completes.
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
        let alg = match self.export_hash_len {
            48 => crate::crypt::HashAlgId::Sha384,
            _ => crate::crypt::HashAlgId::Sha256,
        };
        crate::crypt::export::tls12_export_keying_material(
            alg,
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
            return self.do_client_abbreviated(&mut hs, suite);
        }

        // 3. Read Certificate (only for KX that requires it)
        let (hs_type, next_data) = if hs.kx_alg().requires_certificate() {
            let (hs_type, cert_data) = self.read_handshake_msg()?;
            if hs_type != HandshakeType::Certificate {
                return Err(TlsError::HandshakeFailed(format!(
                    "expected Certificate, got {hs_type:?}"
                )));
            }
            let (_, cert_body, _) = parse_handshake_header(&cert_data)?;
            let cert12 = decode_certificate12(cert_body)?;
            hs.process_certificate(&cert_data, &cert12.certificate_list)?;
            self.read_handshake_msg()?
        } else {
            self.read_handshake_msg()?
        };

        // 3b. Handle optional CertificateStatus (RFC 6066, OCSP stapling)
        let (hs_type, next_data) = if hs_type == HandshakeType::CertificateStatus {
            // CertificateStatus is added to transcript but contents are not used
            // by the handshake — just available for the application.
            // Read next message after CertificateStatus
            self.read_handshake_msg()?
        } else {
            (hs_type, next_data)
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
            self.read_handshake_msg()?
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

        // Store export parameters (before zeroizing master_secret)
        self.export_master_secret = flight.master_secret.clone();
        self.export_client_random = *hs.client_random();
        self.export_server_random = *hs.server_random();
        if let Ok(p) = crate::crypt::Tls12CipherSuiteParams::from_suite(suite) {
            self.export_hash_len = p.hash_len;
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
    fn do_renegotiation(&mut self) -> Result<(), TlsError> {
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
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Run the rest of the handshake — reuse the same logic as do_handshake
        // but hs is already set up for renegotiation.

        // Read ServerHello
        let (hs_type, sh_data) = self.read_handshake_msg()?;
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
            let (hs_type, cert_data) = self.read_handshake_msg()?;
            if hs_type != HandshakeType::Certificate {
                return Err(TlsError::HandshakeFailed(format!(
                    "expected Certificate, got {hs_type:?}"
                )));
            }
            let (_, cert_body, _) = parse_handshake_header(&cert_data)?;
            let cert12 = decode_certificate12(cert_body)?;
            hs.process_certificate(&cert_data, &cert12.certificate_list)?;
            self.read_handshake_msg()?
        } else {
            self.read_handshake_msg()?
        };

        // Handle optional CertificateStatus
        let (hs_type, next_data) = if hs_type == HandshakeType::CertificateStatus {
            self.read_handshake_msg()?
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
            self.read_handshake_msg()?
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

        // Process ServerHelloDone
        let mut flight = hs.process_server_hello_done(&shd_data)?;

        // Send client Certificate (if mTLS requested)
        if let Some(ref cert_msg) = flight.client_certificate {
            let cert_record = self
                .record_layer
                .seal_record(ContentType::Handshake, cert_msg)?;
            self.stream
                .write_all(&cert_record)
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // Send ClientKeyExchange
        let cke_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &flight.client_key_exchange)?;
        self.stream
            .write_all(&cke_record)
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Send CertificateVerify (if mTLS)
        if let Some(ref cv_msg) = flight.certificate_verify {
            let cv_record = self
                .record_layer
                .seal_record(ContentType::Handshake, cv_msg)?;
            self.stream
                .write_all(&cv_record)
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
        }

        // Send ChangeCipherSpec
        let ccs_record = self
            .record_layer
            .seal_record(ContentType::ChangeCipherSpec, &[0x01])?;
        self.stream
            .write_all(&ccs_record)
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
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Read NewSessionTicket (optional) then server ChangeCipherSpec
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
        let (hs_type, fin_data) = self.read_handshake_msg()?;
        if hs_type != HandshakeType::Finished {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Finished, got {hs_type:?}"
            )));
        }
        hs.process_finished(&fin_data, &flight.master_secret)?;

        // Update export parameters
        self.export_master_secret = flight.master_secret.clone();
        self.export_client_random = *hs.client_random();
        self.export_server_random = *hs.server_random();
        if let Ok(p) = crate::crypt::Tls12CipherSuiteParams::from_suite(suite) {
            self.export_hash_len = p.hash_len;
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

        loop {
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
                            let _ = self.stream.write_all(&record);
                            continue;
                        }
                        // Perform renegotiation
                        self.do_renegotiation()?;
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
