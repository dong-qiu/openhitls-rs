//! Synchronous TLS 1.2 connection wrapping a `Read + Write` transport.
//!
//! Provides `Tls12ClientConnection` and `Tls12ServerConnection` implementing
//! the `TlsConnection` trait for TLS 1.2 ECDHE-GCM cipher suites.

use std::io::{Read, Write};

use crate::alert::{AlertDescription, AlertLevel};
use crate::config::TlsConfig;
use crate::crypt::KeyExchangeAlg;
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
use crate::{CipherSuite, TlsConnection, TlsError, TlsVersion};
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

        // Apply peer's record size limit (TLS 1.2: no adjustment)
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

        // Apply client's record size limit (TLS 1.2: no adjustment)
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

        let result = hs.process_client_hello_resumable(&ch_data, None)?;

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
            flight.certificate.as_ref().unwrap(),
            flight.server_key_exchange.as_ref().unwrap(),
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
            flight.certificate.as_ref().unwrap(),
            flight.server_key_exchange.as_ref().unwrap(),
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
            flight.certificate.as_ref().unwrap(),
            flight.server_key_exchange.as_ref().unwrap(),
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
            flight.certificate.as_ref().unwrap(),
            flight.server_key_exchange.as_ref().unwrap(),
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
        if cflight.is_cbc && client_hs.use_encrypt_then_mac() {
            client_rl.activate_write_encryption12_etm(
                cflight.client_write_key.clone(),
                cflight.client_write_mac_key.clone(),
                cflight.mac_len,
            );
        } else if cflight.is_cbc {
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

        if keys.is_cbc && server_hs.use_encrypt_then_mac() {
            server_rl.activate_read_decryption12_etm(
                keys.client_write_key.clone(),
                keys.client_write_mac_key.clone(),
                keys.mac_len,
            );
        } else if keys.is_cbc {
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
        let server_etm = server_hs.use_encrypt_then_mac();

        // 6. Server → CCS + Finished
        s2c.extend_from_slice(
            &server_rl
                .seal_record(ContentType::ChangeCipherSpec, &[0x01])
                .unwrap(),
        );
        activate_write_cbc_or_etm(
            &mut server_rl,
            suite_neg,
            keys.is_cbc,
            server_etm,
            &keys.server_write_key,
            &keys.server_write_mac_key,
            keys.mac_len,
            keys.server_write_iv.clone(),
        );
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
        let client_etm = client_hs.use_encrypt_then_mac();

        activate_read_cbc_or_etm(
            &mut client_rl,
            suite_neg,
            cflight.is_cbc,
            client_etm,
            &cflight.server_write_key,
            &cflight.server_write_mac_key,
            cflight.mac_len,
            cflight.server_write_iv.clone(),
        );

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
            extended_master_secret: client_hs.use_extended_master_secret(),
        }
    }

    // Activate CBC/ETM/AEAD encryption on the given record layer (helper for test fns).
    #[allow(clippy::too_many_arguments)]
    fn activate_write_cbc_or_etm(
        rl: &mut RecordLayer,
        suite: CipherSuite,
        is_cbc: bool,
        use_etm: bool,
        write_key: &[u8],
        mac_key: &[u8],
        mac_len: usize,
        iv: Vec<u8>,
    ) {
        if is_cbc && use_etm {
            rl.activate_write_encryption12_etm(write_key.to_vec(), mac_key.to_vec(), mac_len);
        } else if is_cbc {
            rl.activate_write_encryption12_cbc(write_key.to_vec(), mac_key.to_vec(), mac_len);
        } else {
            rl.activate_write_encryption12(suite, write_key, iv)
                .unwrap();
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn activate_read_cbc_or_etm(
        rl: &mut RecordLayer,
        suite: CipherSuite,
        is_cbc: bool,
        use_etm: bool,
        write_key: &[u8],
        mac_key: &[u8],
        mac_len: usize,
        iv: Vec<u8>,
    ) {
        if is_cbc && use_etm {
            rl.activate_read_decryption12_etm(write_key.to_vec(), mac_key.to_vec(), mac_len);
        } else if is_cbc {
            rl.activate_read_decryption12_cbc(write_key.to_vec(), mac_key.to_vec(), mac_len);
        } else {
            rl.activate_read_decryption12(suite, write_key, iv).unwrap();
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
                let server_etm = server_hs.use_encrypt_then_mac();

                // 3. Server → SH (plaintext)
                s2c.extend_from_slice(
                    &server_rl.seal_record(ContentType::Handshake, &abbr.server_hello)?,
                );

                // 4. Server → CCS
                s2c.extend_from_slice(
                    &server_rl.seal_record(ContentType::ChangeCipherSpec, &[0x01])?,
                );

                // 5. Activate server write encryption
                activate_write_cbc_or_etm(
                    &mut server_rl,
                    abbr.suite,
                    abbr.is_cbc,
                    server_etm,
                    &abbr.server_write_key,
                    &abbr.server_write_mac_key,
                    abbr.mac_len,
                    abbr.server_write_iv.clone(),
                );

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
                let client_etm = client_hs.use_encrypt_then_mac();

                // 8. Client processes CCS
                let (ct, _, consumed) = client_rl.open_record(&s2c)?;
                s2c.drain(..consumed);
                assert_eq!(ct, ContentType::ChangeCipherSpec);
                client_hs.process_change_cipher_spec()?;

                // 9. Activate client read decryption (server write key)
                activate_read_cbc_or_etm(
                    &mut client_rl,
                    keys.suite,
                    keys.is_cbc,
                    client_etm,
                    &keys.server_write_key,
                    &keys.server_write_mac_key,
                    keys.mac_len,
                    keys.server_write_iv.clone(),
                );

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
                activate_write_cbc_or_etm(
                    &mut client_rl,
                    keys.suite,
                    keys.is_cbc,
                    client_etm,
                    &keys.client_write_key,
                    &keys.client_write_mac_key,
                    keys.mac_len,
                    keys.client_write_iv.clone(),
                );

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
                activate_read_cbc_or_etm(
                    &mut server_rl,
                    abbr.suite,
                    abbr.is_cbc,
                    server_etm,
                    &abbr.client_write_key,
                    &abbr.client_write_mac_key,
                    abbr.mac_len,
                    abbr.client_write_iv.clone(),
                );

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
            flight.certificate.as_ref().unwrap(),
            flight.server_key_exchange.as_ref().unwrap(),
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
            extended_master_secret: client_hs.use_extended_master_secret(),
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
            extended_master_secret: false,
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
            extended_master_secret: false,
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

    // =========================================================================
    // Phase 35: EMS + ETM + Renegotiation Info tests
    // =========================================================================

    /// Helper: run a full handshake with custom configs, returning handshake structs.
    fn run_ems_etm_handshake(
        suite: CipherSuite,
        client_ems: bool,
        server_ems: bool,
        client_etm: bool,
        server_etm: bool,
    ) -> (Tls12ClientHandshake, Tls12ServerHandshake) {
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
            .enable_extended_master_secret(client_ems)
            .enable_encrypt_then_mac(client_etm)
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
            .enable_extended_master_secret(server_ems)
            .enable_encrypt_then_mac(server_etm)
            .build();

        let mut c2s = Vec::new();
        let mut s2c = Vec::new();
        let mut client_hs = Tls12ClientHandshake::new(client_config);
        let mut client_rl = RecordLayer::new();
        let mut server_hs = Tls12ServerHandshake::new(server_config);
        let mut server_rl = RecordLayer::new();

        // CH
        let ch_msg = client_hs.build_client_hello().unwrap();
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::Handshake, &ch_msg)
                .unwrap(),
        );

        // Server processes CH
        let (_, ch_plain, consumed) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..consumed);
        let (_, _, ch_total) = parse_handshake_header(&ch_plain).unwrap();
        let flight = server_hs
            .process_client_hello(&ch_plain[..ch_total])
            .unwrap();

        // SH + Cert + SKE + SHD
        for msg in [
            &flight.server_hello,
            flight.certificate.as_ref().unwrap(),
            flight.server_key_exchange.as_ref().unwrap(),
            &flight.server_hello_done,
        ] {
            s2c.extend_from_slice(&server_rl.seal_record(ContentType::Handshake, msg).unwrap());
        }

        // Client processes SH
        let (_, sh_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        let (_, sh_body, sh_total) = parse_handshake_header(&sh_plain).unwrap();
        let sh = decode_server_hello(sh_body).unwrap();
        client_hs
            .process_server_hello(&sh_plain[..sh_total], &sh)
            .unwrap();

        // Client processes Cert
        let (_, cert_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        let (_, cert_body, cert_total) = parse_handshake_header(&cert_plain).unwrap();
        let cert12 = decode_certificate12(cert_body).unwrap();
        client_hs
            .process_certificate(&cert_plain[..cert_total], &cert12.certificate_list)
            .unwrap();

        // Client processes SKE
        let (_, ske_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        let (_, ske_body, ske_total) = parse_handshake_header(&ske_plain).unwrap();
        let ske = decode_server_key_exchange(ske_body).unwrap();
        client_hs
            .process_server_key_exchange(&ske_plain[..ske_total], &ske)
            .unwrap();

        // Client processes SHD + builds CKE + CCS + Finished
        let (_, shd_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        let (_, _, shd_total) = parse_handshake_header(&shd_plain).unwrap();
        let cflight = client_hs
            .process_server_hello_done(&shd_plain[..shd_total])
            .unwrap();

        // Client sends CKE + CCS + Finished
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

        let params = crate::crypt::Tls12CipherSuiteParams::from_suite(flight.suite).unwrap();
        if cflight.is_cbc && client_hs.use_encrypt_then_mac() {
            client_rl.activate_write_encryption12_etm(
                cflight.client_write_key.clone(),
                cflight.client_write_mac_key.clone(),
                cflight.mac_len,
            );
        } else if cflight.is_cbc {
            client_rl.activate_write_encryption12_cbc(
                cflight.client_write_key.clone(),
                cflight.client_write_mac_key.clone(),
                cflight.mac_len,
            );
        } else {
            client_rl
                .activate_write_encryption12(
                    flight.suite,
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

        // Server processes CKE
        let (_, cke_plain, consumed) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..consumed);
        let (_, _, cke_total) = parse_handshake_header(&cke_plain).unwrap();
        let keys = server_hs
            .process_client_key_exchange(&cke_plain[..cke_total])
            .unwrap();

        // Server processes CCS
        let (ct, _, consumed) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..consumed);
        assert_eq!(ct, ContentType::ChangeCipherSpec);
        server_hs.process_change_cipher_spec().unwrap();

        // Server read decryption
        if keys.is_cbc && server_hs.use_encrypt_then_mac() {
            server_rl.activate_read_decryption12_etm(
                keys.client_write_key.clone(),
                keys.client_write_mac_key.clone(),
                keys.mac_len,
            );
        } else if keys.is_cbc {
            server_rl.activate_read_decryption12_cbc(
                keys.client_write_key.clone(),
                keys.client_write_mac_key.clone(),
                keys.mac_len,
            );
        } else {
            server_rl
                .activate_read_decryption12(
                    flight.suite,
                    &keys.client_write_key,
                    keys.client_write_iv.clone(),
                )
                .unwrap();
        }

        // Server processes client Finished + builds server Finished
        let (_, fin_plain, consumed) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..consumed);
        let (_, _, fin_total) = parse_handshake_header(&fin_plain).unwrap();
        let server_fin = server_hs.process_finished(&fin_plain[..fin_total]).unwrap();

        // Server sends CCS + Finished
        s2c.extend_from_slice(
            &server_rl
                .seal_record(ContentType::ChangeCipherSpec, &[0x01])
                .unwrap(),
        );
        if keys.is_cbc && server_hs.use_encrypt_then_mac() {
            server_rl.activate_write_encryption12_etm(
                keys.server_write_key.clone(),
                keys.server_write_mac_key.clone(),
                keys.mac_len,
            );
        } else if keys.is_cbc {
            server_rl.activate_write_encryption12_cbc(
                keys.server_write_key.clone(),
                keys.server_write_mac_key.clone(),
                keys.mac_len,
            );
        } else {
            server_rl
                .activate_write_encryption12(
                    flight.suite,
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

        // Client processes CCS + server Finished
        let (ct, _, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        assert_eq!(ct, ContentType::ChangeCipherSpec);
        client_hs.process_change_cipher_spec().unwrap();

        if cflight.is_cbc && client_hs.use_encrypt_then_mac() {
            client_rl.activate_read_decryption12_etm(
                cflight.server_write_key.clone(),
                cflight.server_write_mac_key.clone(),
                cflight.mac_len,
            );
        } else if cflight.is_cbc {
            client_rl.activate_read_decryption12_cbc(
                cflight.server_write_key.clone(),
                cflight.server_write_mac_key.clone(),
                cflight.mac_len,
            );
        } else {
            client_rl
                .activate_read_decryption12(
                    flight.suite,
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

        // Verify both connected
        assert_eq!(client_hs.state(), Tls12ClientState::Connected);
        assert_eq!(server_hs.state(), Tls12ServerState::Connected);

        // Verify data exchange works (if encrypted)
        let app_data = b"Hello EMS/ETM test!";
        let encrypted = client_rl
            .seal_record(ContentType::ApplicationData, app_data)
            .unwrap();
        let (ct, decrypted, _) = server_rl.open_record(&encrypted).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(decrypted, app_data);

        let _ = params; // suppress unused warning
        (client_hs, server_hs)
    }

    #[test]
    fn test_tls12_ems_full_handshake() {
        // Both enable EMS → EMS negotiated
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let (client_hs, server_hs) = run_ems_etm_handshake(suite, true, true, false, false);
        assert!(client_hs.use_extended_master_secret());
        assert!(server_hs.use_extended_master_secret());
        // Verify_data stored
        assert_eq!(client_hs.client_verify_data().len(), 12);
        assert_eq!(client_hs.server_verify_data().len(), 12);
        assert_eq!(server_hs.client_verify_data().len(), 12);
        assert_eq!(server_hs.server_verify_data().len(), 12);
    }

    #[test]
    fn test_tls12_ems_client_only() {
        // Client enables EMS but server disables → not negotiated
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let (client_hs, server_hs) = run_ems_etm_handshake(suite, true, false, false, false);
        assert!(!client_hs.use_extended_master_secret());
        assert!(!server_hs.use_extended_master_secret());
    }

    #[test]
    fn test_tls12_ems_server_only() {
        // Server enables EMS but client doesn't offer → not negotiated
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let (client_hs, server_hs) = run_ems_etm_handshake(suite, false, true, false, false);
        assert!(!client_hs.use_extended_master_secret());
        assert!(!server_hs.use_extended_master_secret());
    }

    #[test]
    fn test_tls12_etm_cbc_roundtrip() {
        // ETM with CBC cipher suite
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA;
        let (client_hs, server_hs) = run_ems_etm_handshake(suite, false, false, true, true);
        assert!(client_hs.use_encrypt_then_mac());
        assert!(server_hs.use_encrypt_then_mac());
    }

    #[test]
    fn test_tls12_etm_only_with_cbc() {
        // ETM with AEAD suite → not negotiated (ETM only applies to CBC)
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let (client_hs, server_hs) = run_ems_etm_handshake(suite, false, false, true, true);
        assert!(!client_hs.use_encrypt_then_mac());
        assert!(!server_hs.use_encrypt_then_mac());
    }

    #[test]
    fn test_tls12_ems_etm_combined() {
        // Both EMS and ETM with CBC suite
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA;
        let (client_hs, server_hs) = run_ems_etm_handshake(suite, true, true, true, true);
        assert!(client_hs.use_extended_master_secret());
        assert!(server_hs.use_extended_master_secret());
        assert!(client_hs.use_encrypt_then_mac());
        assert!(server_hs.use_encrypt_then_mac());
    }

    #[test]
    fn test_tls12_renegotiation_info_validated() {
        // Verify initial handshake validates renegotiation_info (both sides check empty)
        // This test just confirms the handshake succeeds with renegotiation_info present
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let (client_hs, server_hs) = run_ems_etm_handshake(suite, true, true, false, false);
        assert_eq!(client_hs.state(), Tls12ClientState::Connected);
        assert_eq!(server_hs.state(), Tls12ServerState::Connected);
        // Verify_data is 12 bytes (used for renegotiation_info in future renegotiations)
        assert_eq!(client_hs.client_verify_data().len(), 12);
        assert_eq!(client_hs.server_verify_data().len(), 12);
    }

    #[test]
    fn test_tls12_ems_session_resumption_with_ticket() {
        // Full handshake with EMS → get ticket → resume → both should negotiate EMS
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let ticket_key = vec![0xAB; 32];

        // Step 1: Full handshake with EMS + ticket
        let session = run_full_handshake_with_ticket(suite, ticket_key.clone());
        assert!(session.ticket.is_some());
        assert!(session.extended_master_secret); // EMS was negotiated

        // Step 2: Abbreviated handshake with the EMS session
        let (cs, ss) = run_ticket_abbreviated_handshake(suite, ticket_key, session).unwrap();
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    // =======================================================================
    // RSA / DHE key exchange helpers and tests (Phase 36)
    // =======================================================================

    /// Generate an RSA 2048 server identity (cert DER + ServerPrivateKey).
    fn make_rsa_cert_and_key() -> (Vec<u8>, ServerPrivateKey) {
        use hitls_crypto::rsa::RsaPrivateKey;
        use hitls_pki::x509::{CertificateBuilder, DistinguishedName, SigningKey};

        let rsa = RsaPrivateKey::generate(2048).unwrap();
        let (n, d, e) = (rsa.n_bytes(), rsa.d_bytes(), rsa.e_bytes());
        let (p, q) = (rsa.p_bytes(), rsa.q_bytes());
        let sk = SigningKey::Rsa(rsa);
        let dn = DistinguishedName {
            entries: vec![("CN".into(), "TestRSA".into())],
        };
        let cert = CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000).unwrap();
        (cert.to_der(), ServerPrivateKey::Rsa { n, d, e, p, q })
    }

    /// Run a full TLS 1.2 handshake with RSA or DHE key exchange (in-process).
    ///
    /// Works for RSA static KX (no SKE), DHE_RSA (DHE SKE), and ECDHE_RSA (ECDHE SKE).
    /// Uses a real RSA certificate so that RSA encryption and signature verification work.
    fn run_tls12_rsa_or_dhe_handshake(
        suite: CipherSuite,
        groups: &[NamedGroup],
    ) -> (Tls12ClientState, Tls12ServerState) {
        let (cert_der, server_key) = make_rsa_cert_and_key();

        let sig_algs = [
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PSS_RSAE_SHA384,
            SignatureScheme::RSA_PKCS1_SHA384,
        ];

        let client_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .build();

        let server_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(vec![cert_der])
            .private_key(server_key)
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

        // 2. Server ← CH → server flight
        let (_, ch_plain, consumed) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..consumed);
        let (_, _, ch_total) = parse_handshake_header(&ch_plain).unwrap();
        let flight = server_hs
            .process_client_hello(&ch_plain[..ch_total])
            .unwrap();
        let suite_neg = flight.suite;

        // Server sends: SH, Cert, [SKE], SHD
        for msg in [&flight.server_hello, flight.certificate.as_ref().unwrap()] {
            s2c.extend_from_slice(&server_rl.seal_record(ContentType::Handshake, msg).unwrap());
        }
        if let Some(ref ske_msg) = flight.server_key_exchange {
            s2c.extend_from_slice(
                &server_rl
                    .seal_record(ContentType::Handshake, ske_msg)
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

        // SKE (optional — only for ECDHE/DHE)
        if flight.server_key_exchange.is_some() {
            let (_, ske_plain, consumed) = client_rl.open_record(&s2c).unwrap();
            s2c.drain(..consumed);
            let (_, ske_body, ske_total) = parse_handshake_header(&ske_plain).unwrap();
            match client_hs.kx_alg() {
                KeyExchangeAlg::Ecdhe => {
                    let ske = decode_server_key_exchange(ske_body).unwrap();
                    client_hs
                        .process_server_key_exchange(&ske_plain[..ske_total], &ske)
                        .unwrap();
                }
                KeyExchangeAlg::Dhe => {
                    let ske = decode_server_key_exchange_dhe(ske_body).unwrap();
                    client_hs
                        .process_server_key_exchange_dhe(&ske_plain[..ske_total], &ske)
                        .unwrap();
                }
                _ => panic!("unexpected kx_alg for SKE"),
            }
        }

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

        // Activate client write encryption
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

        // 8. App data exchange
        let app_msg = b"RSA/DHE works!";
        let app_record = client_rl
            .seal_record(ContentType::ApplicationData, app_msg)
            .unwrap();
        let (ct, app_plain, _) = server_rl.open_record(&app_record).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(app_plain, app_msg);

        let reply = b"Confirmed!";
        let reply_record = server_rl
            .seal_record(ContentType::ApplicationData, reply)
            .unwrap();
        let (ct, reply_plain, _) = client_rl.open_record(&reply_record).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(reply_plain, reply);

        (client_hs.state(), server_hs.state())
    }

    #[test]
    fn test_tls12_rsa_gcm_handshake() {
        let (cs, ss) = run_tls12_rsa_or_dhe_handshake(
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            &[], // RSA KX doesn't need groups
        );
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_rsa_cbc_handshake() {
        let (cs, ss) =
            run_tls12_rsa_or_dhe_handshake(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256, &[]);
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_dhe_gcm_handshake() {
        let (cs, ss) = run_tls12_rsa_or_dhe_handshake(
            CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            &[NamedGroup::FFDHE2048],
        );
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_dhe_cbc_handshake() {
        let (cs, ss) = run_tls12_rsa_or_dhe_handshake(
            CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            &[NamedGroup::FFDHE2048],
        );
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_dhe_chacha20_handshake() {
        let (cs, ss) = run_tls12_rsa_or_dhe_handshake(
            CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            &[NamedGroup::FFDHE2048],
        );
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_ecdhe_rsa_gcm_handshake() {
        let (cs, ss) = run_tls12_rsa_or_dhe_handshake(
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            &[NamedGroup::SECP256R1],
        );
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_ems_mismatch_fallback() {
        // Session without EMS, but new handshake negotiates EMS → should NOT resume
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let ticket_key = vec![0xAB; 32];

        // Create a session manually with extended_master_secret: false
        // but with a valid ticket encrypted by a server that had EMS disabled

        // Encrypt a session ticket with EMS=false
        let non_ems_session = TlsSession {
            id: Vec::new(),
            cipher_suite: suite,
            master_secret: vec![0x42; 48],
            alpn_protocol: None,
            ticket: None,
            ticket_lifetime: 3600,
            max_early_data: 0,
            ticket_age_add: 0,
            ticket_nonce: Vec::new(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            psk: Vec::new(),
            extended_master_secret: false,
        };
        let ticket_data =
            crate::session::encrypt_session_ticket(&ticket_key, &non_ems_session).unwrap();

        // Build a resumption session with the non-EMS ticket
        let resumption_session = TlsSession {
            id: Vec::new(),
            cipher_suite: suite,
            master_secret: vec![0x42; 48],
            alpn_protocol: None,
            ticket: Some(ticket_data),
            ticket_lifetime: 3600,
            max_early_data: 0,
            ticket_age_add: 0,
            ticket_nonce: Vec::new(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            psk: Vec::new(),
            extended_master_secret: false,
        };

        // Client sends EMS extension (default true), but cached session has EMS=false
        // Server decrypts ticket → EMS=false, but client offers EMS
        // Server check: session.ems(false) == client_has_ems(true) → false, so skip
        // Falls back to full handshake → test expects abbreviated but gets full
        let result = run_ticket_abbreviated_handshake(suite, ticket_key, resumption_session);
        // Should fail because the test helper expects abbreviated
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("expected abbreviated"));
    }

    // ===== PSK handshake test helper =====

    /// Run a full TLS 1.2 PSK handshake (in-process).
    ///
    /// Supports PSK, DHE_PSK, ECDHE_PSK, and RSA_PSK families.
    /// For RSA_PSK, an RSA certificate is generated and used.
    fn run_tls12_psk_handshake(
        suite: CipherSuite,
        groups: &[NamedGroup],
    ) -> (Tls12ClientState, Tls12ServerState) {
        let psk = b"test-pre-shared-key-32-bytes!!!!".to_vec(); // 32 bytes
        let psk_identity = b"client-identity".to_vec();

        let params =
            crate::crypt::Tls12CipherSuiteParams::from_suite(suite).expect("unknown suite");
        let needs_cert = params.kx_alg.requires_certificate();

        let sig_algs = [
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ];

        let client_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .psk(psk.clone())
            .psk_identity(psk_identity.clone())
            .build();

        let server_config = if needs_cert {
            let (cert_der, server_key) = make_rsa_cert_and_key();
            TlsConfig::builder()
                .cipher_suites(&[suite])
                .supported_groups(groups)
                .signature_algorithms(&sig_algs)
                .verify_peer(false)
                .psk(psk.clone())
                .psk_identity_hint(b"server-hint".to_vec())
                .certificate_chain(vec![cert_der])
                .private_key(server_key)
                .build()
        } else {
            TlsConfig::builder()
                .cipher_suites(&[suite])
                .supported_groups(groups)
                .signature_algorithms(&sig_algs)
                .verify_peer(false)
                .psk(psk.clone())
                .psk_identity_hint(b"server-hint".to_vec())
                .build()
        };

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

        // 2. Server ← CH → server flight
        let (_, ch_plain, consumed) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..consumed);
        let (_, _, ch_total) = parse_handshake_header(&ch_plain).unwrap();
        let flight = server_hs
            .process_client_hello(&ch_plain[..ch_total])
            .unwrap();
        let suite_neg = flight.suite;

        // Server sends: SH, [Cert], [SKE], SHD
        s2c.extend_from_slice(
            &server_rl
                .seal_record(ContentType::Handshake, &flight.server_hello)
                .unwrap(),
        );
        if let Some(ref cert_msg) = flight.certificate {
            s2c.extend_from_slice(
                &server_rl
                    .seal_record(ContentType::Handshake, cert_msg)
                    .unwrap(),
            );
        }
        if let Some(ref ske_msg) = flight.server_key_exchange {
            s2c.extend_from_slice(
                &server_rl
                    .seal_record(ContentType::Handshake, ske_msg)
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
        let (_, sh_plain, consumed) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..consumed);
        let (_, sh_body, sh_total) = parse_handshake_header(&sh_plain).unwrap();
        let sh = decode_server_hello(sh_body).unwrap();
        client_hs
            .process_server_hello(&sh_plain[..sh_total], &sh)
            .unwrap();

        // Cert (only for RSA_PSK)
        if needs_cert {
            let (_, cert_plain, consumed) = client_rl.open_record(&s2c).unwrap();
            s2c.drain(..consumed);
            let (_, cert_body, cert_total) = parse_handshake_header(&cert_plain).unwrap();
            let cert12 = decode_certificate12(cert_body).unwrap();
            client_hs
                .process_certificate(&cert_plain[..cert_total], &cert12.certificate_list)
                .unwrap();
        }

        // SKE (optional)
        if flight.server_key_exchange.is_some() {
            let (_, ske_plain, consumed) = client_rl.open_record(&s2c).unwrap();
            s2c.drain(..consumed);
            let (_, ske_body, ske_total) = parse_handshake_header(&ske_plain).unwrap();
            match client_hs.kx_alg() {
                KeyExchangeAlg::Psk | KeyExchangeAlg::RsaPsk => {
                    let ske = decode_server_key_exchange_psk_hint(ske_body).unwrap();
                    client_hs
                        .process_server_key_exchange_psk_hint(&ske_plain[..ske_total], &ske)
                        .unwrap();
                }
                KeyExchangeAlg::DhePsk => {
                    let ske = decode_server_key_exchange_dhe_psk(ske_body).unwrap();
                    client_hs
                        .process_server_key_exchange_dhe_psk(&ske_plain[..ske_total], &ske)
                        .unwrap();
                }
                KeyExchangeAlg::EcdhePsk => {
                    let ske = decode_server_key_exchange_ecdhe_psk(ske_body).unwrap();
                    client_hs
                        .process_server_key_exchange_ecdhe_psk(&ske_plain[..ske_total], &ske)
                        .unwrap();
                }
                _ => panic!("unexpected kx_alg {:?} for PSK SKE", client_hs.kx_alg()),
            }
        }

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

        // Activate client write encryption
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

        // 8. App data exchange
        let app_msg = b"PSK works!";
        let app_record = client_rl
            .seal_record(ContentType::ApplicationData, app_msg)
            .unwrap();
        let (ct, app_plain, _) = server_rl.open_record(&app_record).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(app_plain, app_msg);

        let reply = b"Confirmed!";
        let reply_record = server_rl
            .seal_record(ContentType::ApplicationData, reply)
            .unwrap();
        let (ct, reply_plain, _) = client_rl.open_record(&reply_record).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(reply_plain, reply);

        (client_hs.state(), server_hs.state())
    }

    #[test]
    fn test_tls12_psk_gcm_handshake() {
        let (cs, ss) = run_tls12_psk_handshake(CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256, &[]);
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_psk_cbc_handshake() {
        let (cs, ss) = run_tls12_psk_handshake(CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA, &[]);
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_dhe_psk_gcm_handshake() {
        let (cs, ss) = run_tls12_psk_handshake(
            CipherSuite::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
            &[NamedGroup::FFDHE2048],
        );
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_ecdhe_psk_cbc_handshake() {
        let (cs, ss) = run_tls12_psk_handshake(
            CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
            &[NamedGroup::SECP256R1],
        );
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_rsa_psk_gcm_handshake() {
        let (cs, ss) =
            run_tls12_psk_handshake(CipherSuite::TLS_RSA_PSK_WITH_AES_128_GCM_SHA256, &[]);
        assert_eq!(cs, Tls12ClientState::Connected);
        assert_eq!(ss, Tls12ServerState::Connected);
    }

    #[test]
    fn test_tls12_fallback_scsv_accepted() {
        // Client sends Fallback SCSV, server max_version is TLS 1.2 → accepted
        let ecdsa_private = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let fake_cert = vec![0x30, 0x82, 0x01, 0x00];
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

        let client_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .verify_peer(false)
            .send_fallback_scsv(true)
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
            .max_version(TlsVersion::Tls12) // server only supports TLS 1.2
            .build();

        let mut client_hs = Tls12ClientHandshake::new(client_config);
        let mut server_hs = Tls12ServerHandshake::new(server_config);
        let mut client_rl = RecordLayer::new();
        let mut server_rl = RecordLayer::new();

        let ch_msg = client_hs.build_client_hello().unwrap();
        let ch_record = client_rl
            .seal_record(ContentType::Handshake, &ch_msg)
            .unwrap();
        let (_, ch_plain, _) = server_rl.open_record(&ch_record).unwrap();
        let (_, _, ch_total) = parse_handshake_header(&ch_plain).unwrap();

        // Server should accept (max_version == TLS 1.2, no downgrade)
        let result = server_hs.process_client_hello(&ch_plain[..ch_total]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_tls12_fallback_scsv_rejected() {
        // Client sends Fallback SCSV, server max_version is TLS 1.3 → rejected
        let ecdsa_private = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let fake_cert = vec![0x30, 0x82, 0x01, 0x00];
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

        let client_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .verify_peer(false)
            .send_fallback_scsv(true)
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
            .max_version(TlsVersion::Tls13) // server supports TLS 1.3 → downgrade detected
            .build();

        let mut client_hs = Tls12ClientHandshake::new(client_config);
        let mut server_hs = Tls12ServerHandshake::new(server_config);
        let mut client_rl = RecordLayer::new();
        let mut server_rl = RecordLayer::new();

        let ch_msg = client_hs.build_client_hello().unwrap();
        let ch_record = client_rl
            .seal_record(ContentType::Handshake, &ch_msg)
            .unwrap();
        let (_, ch_plain, _) = server_rl.open_record(&ch_record).unwrap();
        let (_, _, ch_total) = parse_handshake_header(&ch_plain).unwrap();

        // Server should reject (inappropriate fallback)
        let result = server_hs.process_client_hello(&ch_plain[..ch_total]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("inappropriate fallback"));
    }

    #[test]
    fn test_tls12_record_size_limit() {
        let ecdsa_private = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let fake_cert = vec![0x30, 0x82, 0x01, 0x00];
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

        let client_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .verify_peer(false)
            .record_size_limit(2048)
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
            .record_size_limit(2048)
            .max_version(TlsVersion::Tls12)
            .build();

        let mut client_hs = Tls12ClientHandshake::new(client_config);
        let mut server_hs = Tls12ServerHandshake::new(server_config);
        let mut client_rl = RecordLayer::new();
        let mut server_rl = RecordLayer::new();

        // 1. Client → CH
        let ch_msg = client_hs.build_client_hello().unwrap();
        let ch_record = client_rl
            .seal_record(ContentType::Handshake, &ch_msg)
            .unwrap();

        // 2. Server ← CH
        let (_, ch_plain, _) = server_rl.open_record(&ch_record).unwrap();
        let (_, _, ch_total) = parse_handshake_header(&ch_plain).unwrap();
        let flight = server_hs
            .process_client_hello(&ch_plain[..ch_total])
            .unwrap();

        // Server should have client's RSL
        assert_eq!(server_hs.client_record_size_limit(), Some(2048));

        // Apply client's RSL to server record layer (TLS 1.2: no adjustment)
        if let Some(limit) = server_hs.client_record_size_limit() {
            server_rl.max_fragment_size = limit as usize;
        }

        // 3. Server → SH
        let sh_record = server_rl
            .seal_record(ContentType::Handshake, &flight.server_hello)
            .unwrap();

        // 4. Client ← SH
        let (_, sh_plain, _) = client_rl.open_record(&sh_record).unwrap();
        let (_, sh_body, sh_total) = parse_handshake_header(&sh_plain).unwrap();
        let sh = decode_server_hello(sh_body).unwrap();
        client_hs
            .process_server_hello(&sh_plain[..sh_total], &sh)
            .unwrap();

        // Client should have peer's RSL
        assert_eq!(client_hs.peer_record_size_limit(), Some(2048));

        // Apply to client record layer
        if let Some(limit) = client_hs.peer_record_size_limit() {
            client_rl.max_fragment_size = limit as usize;
        }

        // Verify caps
        assert_eq!(server_rl.max_fragment_size, 2048);
        assert_eq!(client_rl.max_fragment_size, 2048);

        // Large plaintext should be rejected
        let large = vec![0x42u8; 2049];
        assert!(server_rl
            .seal_record(ContentType::ApplicationData, &large)
            .is_err());

        // Exactly 2048 should work
        let ok = vec![0x42u8; 2048];
        assert!(server_rl
            .seal_record(ContentType::ApplicationData, &ok)
            .is_ok());
    }

    // ======================================================================
    // Renegotiation tests (RFC 5746)
    // ======================================================================

    /// Helper: create ECDSA server identity for renegotiation tests.
    fn make_renego_configs(allow_renegotiation: bool) -> (TlsConfig, TlsConfig) {
        let ecdsa_private = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let fake_cert = vec![0x30, 0x82, 0x01, 0x00];

        let client_config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .verify_peer(false)
            .allow_renegotiation(allow_renegotiation)
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
            .allow_renegotiation(allow_renegotiation)
            .build();

        (client_config, server_config)
    }

    /// Full renegotiation roundtrip: handshake → app data → server initiates
    /// renegotiation → client re-handshakes → app data works with new keys.
    #[test]
    fn test_full_renegotiation_roundtrip() {
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let (client_config, server_config) = make_renego_configs(true);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            assert_eq!(conn.state, ConnectionState::Connected);

            // Exchange some data before renegotiation
            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"before renego");
            conn.write(b"ack before").unwrap();

            // Initiate renegotiation
            conn.initiate_renegotiation().unwrap();
            assert_eq!(conn.state, ConnectionState::Renegotiating);

            // Read triggers the renegotiation processing (ClientHello arrives)
            let n = conn.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"after renego");
            assert_eq!(conn.state, ConnectionState::Connected);

            conn.write(b"ack after").unwrap();
            conn.shutdown().unwrap();
        });

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        // Exchange data before renegotiation
        conn.write(b"before renego").unwrap();
        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ack before");

        // Now read triggers HelloRequest handling → performs renegotiation
        conn.write(b"after renego").unwrap();
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ack after");

        conn.shutdown().unwrap();
        server_handle.join().unwrap();
    }

    /// When allow_renegotiation=false, client sends no_renegotiation warning
    /// and connection continues.
    #[test]
    fn test_renegotiation_disabled_rejects() {
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let (client_config, mut server_config) = make_renego_configs(false);
        // Server needs renegotiation enabled to initiate, but client has it disabled
        server_config.allow_renegotiation = true;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            conn.handshake().unwrap();

            // Initiate renegotiation
            conn.initiate_renegotiation().unwrap();
            assert_eq!(conn.state, ConnectionState::Renegotiating);

            // Read should receive the no_renegotiation alert and go back to Connected
            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).unwrap();
            assert_eq!(conn.state, ConnectionState::Connected);
            assert_eq!(&buf[..n], b"still works");

            conn.write(b"confirmed").unwrap();
            conn.shutdown().unwrap();
        });

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        // Client read triggers HelloRequest → sends no_renegotiation → continues reading
        // The write + read after should still work on the existing connection
        conn.write(b"still works").unwrap();
        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"confirmed");

        conn.shutdown().unwrap();
        server_handle.join().unwrap();
    }

    /// Renegotiation always does full handshake even if ticket available.
    #[test]
    fn test_renegotiation_no_session_resumption() {
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let ecdsa_private = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let fake_cert = vec![0x30, 0x82, 0x01, 0x00];

        // Enable session tickets AND renegotiation
        let ticket_key = vec![0xAA; 32];
        let client_config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .verify_peer(false)
            .session_resumption(true)
            .allow_renegotiation(true)
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
            .ticket_key(ticket_key)
            .allow_renegotiation(true)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            conn.handshake().unwrap();

            // Read app data, then trigger renegotiation
            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"ping");

            conn.initiate_renegotiation().unwrap();

            // Read triggers ClientHello processing (full handshake, not resumption)
            let n = conn.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"ping2");

            conn.write(b"pong2").unwrap();
            conn.shutdown().unwrap();
        });

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        conn.write(b"ping").unwrap();

        // This write+read will trigger renegotiation when HelloRequest arrives
        conn.write(b"ping2").unwrap();
        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"pong2");

        conn.shutdown().unwrap();
        server_handle.join().unwrap();
    }
}
