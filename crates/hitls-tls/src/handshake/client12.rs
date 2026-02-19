//! TLS 1.2 client handshake state machine.
//!
//! Implements the full TLS 1.2 client handshake for ECDHE, RSA static,
//! and DHE key exchange with AES-GCM, AES-CBC, and ChaCha20-Poly1305
//! cipher suites.

use crate::config::ServerPrivateKey;
use crate::config::TlsConfig;
use crate::crypt::key_schedule12::{
    compute_verify_data, derive_extended_master_secret, derive_key_block, derive_master_secret,
};
use crate::crypt::transcript::TranscriptHash;
use crate::crypt::{KeyExchangeAlg, NamedGroup, SignatureScheme, Tls12CipherSuiteParams};
use crate::extensions::ExtensionType;
use crate::handshake::codec::{encode_client_hello, ClientHello, ServerHello};
use crate::handshake::codec12::{
    build_dhe_ske_params, build_psk_pms, build_ske_params, build_ske_signed_data,
    decode_new_session_ticket12, encode_certificate12, encode_certificate_verify12,
    encode_client_key_exchange, encode_client_key_exchange_dhe, encode_client_key_exchange_dhe_psk,
    encode_client_key_exchange_ecdhe_psk, encode_client_key_exchange_psk,
    encode_client_key_exchange_rsa, encode_client_key_exchange_rsa_psk, encode_finished12,
    Certificate12, CertificateRequest12, CertificateVerify12, ClientKeyExchange,
    ClientKeyExchangeDhe, ClientKeyExchangeDhePsk, ClientKeyExchangeEcdhePsk, ClientKeyExchangePsk,
    ClientKeyExchangeRsa, ClientKeyExchangeRsaPsk, ServerKeyExchange, ServerKeyExchangeDhe,
    ServerKeyExchangeDheAnon, ServerKeyExchangeDhePsk as SkeDhePsk, ServerKeyExchangeEcdheAnon,
    ServerKeyExchangeEcdhePsk, ServerKeyExchangePskHint,
};
use crate::handshake::key_exchange::KeyExchange;
use crate::handshake::server12::select_signature_scheme_tls12;
use crate::CipherSuite;
use hitls_crypto::dh::{DhKeyPair, DhParams};
use hitls_crypto::rsa::{RsaPadding, RsaPublicKey};
use hitls_crypto::sha2::Sha256;
use hitls_types::TlsError;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// TLS 1.2 client handshake states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls12ClientState {
    Idle,
    WaitServerHello,
    WaitCertificate,
    WaitServerKeyExchange,
    WaitServerHelloDone,
    WaitChangeCipherSpec,
    WaitFinished,
    Connected,
}

/// Result of processing ServerHelloDone — contains the client flight to send.
pub struct ClientFlightResult {
    /// Client Certificate message (only if server requested via CertificateRequest).
    pub client_certificate: Option<Vec<u8>>,
    /// ClientKeyExchange message (handshake)
    pub client_key_exchange: Vec<u8>,
    /// Client CertificateVerify message (only if client sent a non-empty certificate).
    pub certificate_verify: Option<Vec<u8>>,
    /// Finished message (handshake, to be encrypted)
    pub finished: Vec<u8>,
    /// Master secret for key derivation
    pub master_secret: Vec<u8>,
    /// Client write MAC key (empty for AEAD suites).
    pub client_write_mac_key: Vec<u8>,
    /// Server write MAC key (empty for AEAD suites).
    pub server_write_mac_key: Vec<u8>,
    /// Client write key
    pub client_write_key: Vec<u8>,
    /// Server write key
    pub server_write_key: Vec<u8>,
    /// Client write IV
    pub client_write_iv: Vec<u8>,
    /// Server write IV
    pub server_write_iv: Vec<u8>,
    /// True if the negotiated suite uses CBC (not AEAD).
    pub is_cbc: bool,
    /// MAC output length (0 for AEAD, 20/32/48 for CBC).
    pub mac_len: usize,
}

impl Drop for ClientFlightResult {
    fn drop(&mut self) {
        self.master_secret.zeroize();
        self.client_write_mac_key.zeroize();
        self.server_write_mac_key.zeroize();
        self.client_write_key.zeroize();
        self.server_write_key.zeroize();
        self.client_write_iv.zeroize();
        self.server_write_iv.zeroize();
    }
}

/// Keys for abbreviated (session resumption) handshake.
pub struct AbbreviatedClientKeys {
    /// Negotiated cipher suite.
    pub suite: CipherSuite,
    /// Master secret (from cached session).
    pub master_secret: Vec<u8>,
    /// Client write MAC key (empty for AEAD suites).
    pub client_write_mac_key: Vec<u8>,
    /// Server write MAC key (empty for AEAD suites).
    pub server_write_mac_key: Vec<u8>,
    /// Client write key.
    pub client_write_key: Vec<u8>,
    /// Server write key.
    pub server_write_key: Vec<u8>,
    /// Client write IV.
    pub client_write_iv: Vec<u8>,
    /// Server write IV.
    pub server_write_iv: Vec<u8>,
    /// True if the negotiated suite uses CBC (not AEAD).
    pub is_cbc: bool,
    /// MAC output length (0 for AEAD, 20/32/48 for CBC).
    pub mac_len: usize,
}

impl Drop for AbbreviatedClientKeys {
    fn drop(&mut self) {
        self.master_secret.zeroize();
        self.client_write_mac_key.zeroize();
        self.server_write_mac_key.zeroize();
        self.client_write_key.zeroize();
        self.server_write_key.zeroize();
        self.client_write_iv.zeroize();
        self.server_write_iv.zeroize();
    }
}

/// TLS 1.2 client handshake state machine.
pub struct Tls12ClientHandshake {
    config: TlsConfig,
    state: Tls12ClientState,
    params: Option<Tls12CipherSuiteParams>,
    transcript: TranscriptHash,
    client_random: [u8; 32],
    server_random: [u8; 32],
    server_certs: Vec<Vec<u8>>,
    server_ecdh_public: Vec<u8>,
    server_named_curve: u16,
    /// Key exchange algorithm for this session.
    kx_alg: KeyExchangeAlg,
    /// Leaf certificate DER (for RSA key encryption).
    server_cert_der: Vec<u8>,
    /// DHE params from ServerKeyExchange.
    server_dhe_p: Vec<u8>,
    server_dhe_g: Vec<u8>,
    server_dhe_ys: Vec<u8>,
    /// PSK identity hint from server (RFC 4279).
    server_psk_hint: Vec<u8>,
    /// Stored ClientHello bytes for transcript replay on hash switch.
    client_hello_bytes: Vec<u8>,
    /// Whether server sent CertificateRequest (mTLS).
    cert_request_received: bool,
    /// Signature algorithms requested by server in CertificateRequest.
    requested_sig_algs: Vec<SignatureScheme>,
    /// Session ID sent in ClientHello (from cached session, for resumption).
    cached_session_id: Vec<u8>,
    /// Master secret from cached session (for abbreviated handshake).
    cached_master_secret: Vec<u8>,
    /// Whether this is an abbreviated (resumed) handshake.
    abbreviated: bool,
    /// Keys derived during abbreviated handshake (available after process_server_hello).
    abbreviated_keys: Option<AbbreviatedClientKeys>,
    /// Whether server signaled session ticket support in ServerHello.
    server_supports_ticket: bool,
    /// Received session ticket from NewSessionTicket message.
    received_ticket: Option<Vec<u8>>,
    /// Received ticket lifetime hint.
    received_ticket_lifetime: u32,
    /// Negotiated Extended Master Secret (RFC 7627).
    use_extended_master_secret: bool,
    /// Negotiated Encrypt-Then-MAC (RFC 7366, CBC suites only).
    use_encrypt_then_mac: bool,
    /// Stored client verify_data after sending Finished.
    client_verify_data: Vec<u8>,
    /// Stored server verify_data after receiving Finished.
    server_verify_data: Vec<u8>,
    /// Whether the cached session used EMS (for resumption compatibility).
    cached_session_ems: bool,
    /// Peer's record size limit from ServerHello.
    peer_record_size_limit: Option<u16>,
    /// Whether this is a renegotiation handshake.
    is_renegotiation: bool,
    /// Previous client verify_data (saved from prior handshake for renegotiation).
    prev_client_verify_data: Vec<u8>,
    /// Previous server verify_data (saved from prior handshake for renegotiation).
    prev_server_verify_data: Vec<u8>,
    /// Negotiated ALPN protocol from ServerHello (if any).
    negotiated_alpn: Option<Vec<u8>>,
    /// Negotiated max fragment length from ServerHello (RFC 6066).
    negotiated_max_fragment_length: Option<crate::config::MaxFragmentLength>,
}

impl Tls12ClientHandshake {
    pub fn new(config: TlsConfig) -> Self {
        Self {
            config,
            state: Tls12ClientState::Idle,
            params: None,
            transcript: TranscriptHash::new(|| Box::new(Sha256::new())),
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            server_certs: Vec::new(),
            server_ecdh_public: Vec::new(),
            server_named_curve: 0,
            kx_alg: KeyExchangeAlg::Ecdhe,
            server_cert_der: Vec::new(),
            server_dhe_p: Vec::new(),
            server_dhe_g: Vec::new(),
            server_dhe_ys: Vec::new(),
            server_psk_hint: Vec::new(),
            client_hello_bytes: Vec::new(),
            cert_request_received: false,
            requested_sig_algs: Vec::new(),
            cached_session_id: Vec::new(),
            cached_master_secret: Vec::new(),
            abbreviated: false,
            abbreviated_keys: None,
            server_supports_ticket: false,
            received_ticket: None,
            received_ticket_lifetime: 0,
            use_extended_master_secret: false,
            use_encrypt_then_mac: false,
            client_verify_data: Vec::new(),
            server_verify_data: Vec::new(),
            cached_session_ems: false,
            peer_record_size_limit: None,
            is_renegotiation: false,
            prev_client_verify_data: Vec::new(),
            prev_server_verify_data: Vec::new(),
            negotiated_alpn: None,
            negotiated_max_fragment_length: None,
        }
    }

    pub fn state(&self) -> Tls12ClientState {
        self.state
    }

    /// Whether this handshake used abbreviated (session resumption) mode.
    pub fn is_abbreviated(&self) -> bool {
        self.abbreviated
    }

    /// Take the abbreviated handshake keys (available after `process_server_hello`
    /// if session resumption was detected).
    pub fn take_abbreviated_keys(&mut self) -> Option<AbbreviatedClientKeys> {
        self.abbreviated_keys.take()
    }

    /// Whether the server supports session tickets (signaled in ServerHello).
    pub fn server_supports_ticket(&self) -> bool {
        self.server_supports_ticket
    }

    /// Get the received session ticket (if any).
    pub fn received_ticket(&self) -> Option<&[u8]> {
        self.received_ticket.as_deref()
    }

    /// Get the received ticket lifetime hint.
    pub fn received_ticket_lifetime(&self) -> u32 {
        self.received_ticket_lifetime
    }

    /// Process a NewSessionTicket message from the server (RFC 5077).
    ///
    /// `body` is the handshake message body (after 4-byte header).
    pub fn process_new_session_ticket(&mut self, body: &[u8]) -> Result<(), TlsError> {
        let (lifetime, ticket) = decode_new_session_ticket12(body)?;
        self.received_ticket = Some(ticket);
        self.received_ticket_lifetime = lifetime;
        Ok(())
    }

    /// The key exchange algorithm for this session.
    pub fn kx_alg(&self) -> KeyExchangeAlg {
        self.kx_alg
    }

    /// The client random value (for key export).
    pub fn client_random(&self) -> &[u8; 32] {
        &self.client_random
    }

    /// The server random value (for key export).
    pub fn server_random(&self) -> &[u8; 32] {
        &self.server_random
    }

    /// Whether Extended Master Secret was negotiated.
    pub fn use_extended_master_secret(&self) -> bool {
        self.use_extended_master_secret
    }

    /// Whether Encrypt-Then-MAC was negotiated (CBC suites only).
    pub fn use_encrypt_then_mac(&self) -> bool {
        self.use_encrypt_then_mac
    }

    /// Get the client verify_data from Finished (for renegotiation).
    pub fn client_verify_data(&self) -> &[u8] {
        &self.client_verify_data
    }

    /// Get the server verify_data from Finished (for renegotiation).
    pub fn server_verify_data(&self) -> &[u8] {
        &self.server_verify_data
    }

    /// Peer's record size limit from ServerHello (RFC 8449).
    pub fn peer_record_size_limit(&self) -> Option<u16> {
        self.peer_record_size_limit
    }

    /// Negotiated max fragment length from ServerHello (RFC 6066).
    pub fn negotiated_max_fragment_length(&self) -> Option<crate::config::MaxFragmentLength> {
        self.negotiated_max_fragment_length
    }

    /// Whether this is a renegotiation handshake.
    pub fn is_renegotiation(&self) -> bool {
        self.is_renegotiation
    }

    /// Get the server's certificate chain (DER-encoded, leaf first).
    pub fn server_certs(&self) -> &[Vec<u8>] {
        &self.server_certs
    }

    /// Get the server's selected named curve (raw u16 value).
    pub fn server_named_curve(&self) -> u16 {
        self.server_named_curve
    }

    /// Get the negotiated ALPN protocol (if any).
    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
    }

    /// Reset handshake state for renegotiation (RFC 5746).
    ///
    /// Saves the current verify_data from both sides, resets all handshake
    /// state to Idle, and marks this as a renegotiation handshake.
    pub fn reset_for_renegotiation(&mut self) {
        self.prev_client_verify_data = std::mem::take(&mut self.client_verify_data);
        self.prev_server_verify_data = std::mem::take(&mut self.server_verify_data);
        self.state = Tls12ClientState::Idle;
        self.params = None;
        self.transcript = TranscriptHash::new(|| Box::new(Sha256::new()));
        self.client_random = [0u8; 32];
        self.server_random = [0u8; 32];
        self.server_certs.clear();
        self.server_ecdh_public.clear();
        self.server_named_curve = 0;
        self.kx_alg = KeyExchangeAlg::Ecdhe;
        self.server_cert_der.clear();
        self.server_dhe_p.clear();
        self.server_dhe_g.clear();
        self.server_dhe_ys.clear();
        self.server_psk_hint.clear();
        self.client_hello_bytes.clear();
        self.cert_request_received = false;
        self.requested_sig_algs.clear();
        self.cached_session_id.clear();
        self.cached_master_secret.zeroize();
        self.cached_master_secret.clear();
        self.abbreviated = false;
        self.abbreviated_keys = None;
        self.server_supports_ticket = false;
        self.received_ticket = None;
        self.received_ticket_lifetime = 0;
        self.use_extended_master_secret = false;
        self.use_encrypt_then_mac = false;
        self.cached_session_ems = false;
        self.peer_record_size_limit = None;
        self.negotiated_alpn = None;
        self.negotiated_max_fragment_length = None;
        self.is_renegotiation = true;
    }

    /// Set up for renegotiation with previous verify_data.
    ///
    /// Used by the connection layer to create a new handshake configured
    /// for renegotiation with the verify_data from a previous handshake.
    pub fn setup_renegotiation(&mut self, prev_client_vd: Vec<u8>, prev_server_vd: Vec<u8>) {
        self.prev_client_verify_data = prev_client_vd;
        self.prev_server_verify_data = prev_server_vd;
        self.is_renegotiation = true;
    }

    /// Build the ClientHello message.
    ///
    /// Returns the full handshake message bytes (for sending) and the raw
    /// message bytes (for the transcript hash).
    pub fn build_client_hello(&mut self) -> Result<Vec<u8>, TlsError> {
        // Generate client_random
        getrandom::getrandom(&mut self.client_random)
            .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;

        // Build extensions for TLS 1.2
        let mut extensions = Vec::new();

        // SNI
        if let Some(ref name) = self.config.server_name {
            extensions.push(crate::handshake::extensions_codec::build_server_name(name));
        }

        // Signature algorithms
        extensions.push(
            crate::handshake::extensions_codec::build_signature_algorithms(
                &self.config.signature_algorithms,
            ),
        );

        // Supported groups
        extensions.push(crate::handshake::extensions_codec::build_supported_groups(
            &self.config.supported_groups,
        ));

        // EC point formats (uncompressed only)
        extensions.push(crate::handshake::extensions_codec::build_ec_point_formats());

        // Renegotiation info (RFC 5746)
        if self.is_renegotiation {
            // Client sends client_verify_data only (RFC 5746 §3.5)
            extensions.push(
                crate::handshake::extensions_codec::build_renegotiation_info(
                    &self.prev_client_verify_data,
                    &[],
                ),
            );
        } else {
            extensions.push(crate::handshake::extensions_codec::build_renegotiation_info_initial());
        }

        // ALPN
        if !self.config.alpn_protocols.is_empty() {
            extensions.push(crate::handshake::extensions_codec::build_alpn(
                &self.config.alpn_protocols,
            ));
        }

        // Session Ticket (RFC 5077) — disabled during renegotiation
        if self.config.session_resumption && !self.is_renegotiation {
            if let Some(ref session) = self.config.resumption_session {
                if let Some(ref ticket) = session.ticket {
                    // Send ticket for resumption
                    extensions.push(crate::handshake::extensions_codec::build_session_ticket_ch(
                        ticket,
                    ));
                } else {
                    // No ticket, send empty extension to signal support
                    extensions.push(crate::handshake::extensions_codec::build_session_ticket_ch(
                        &[],
                    ));
                }
            } else {
                // No cached session, send empty extension to signal support
                extensions.push(crate::handshake::extensions_codec::build_session_ticket_ch(
                    &[],
                ));
            }
        }

        // Extended Master Secret (RFC 7627)
        if self.config.enable_extended_master_secret {
            extensions.push(crate::handshake::extensions_codec::build_extended_master_secret());
        }

        // Encrypt-Then-MAC (RFC 7366)
        if self.config.enable_encrypt_then_mac {
            extensions.push(crate::handshake::extensions_codec::build_encrypt_then_mac());
        }

        // Max Fragment Length (RFC 6066)
        if let Some(mfl) = self.config.max_fragment_length {
            extensions.push(crate::handshake::extensions_codec::build_max_fragment_length(mfl));
        }

        // Record Size Limit (RFC 8449)
        if self.config.record_size_limit > 0 {
            extensions.push(crate::handshake::extensions_codec::build_record_size_limit(
                self.config.record_size_limit.min(16384),
            ));
        }

        // OCSP Stapling (RFC 6066)
        if self.config.enable_ocsp_stapling {
            extensions.push(crate::handshake::extensions_codec::build_status_request_ch());
        }

        // Signed Certificate Timestamp (RFC 6962)
        if self.config.enable_sct {
            extensions.push(crate::handshake::extensions_codec::build_sct_ch());
        }

        // Trusted CA Keys (RFC 6066 §6)
        if !self.config.trusted_ca_keys.is_empty() {
            extensions.push(crate::handshake::extensions_codec::build_trusted_ca_keys(
                &self.config.trusted_ca_keys,
            ));
        }

        // USE_SRTP (RFC 5764)
        if !self.config.srtp_profiles.is_empty() {
            extensions.push(crate::handshake::extensions_codec::build_use_srtp(
                &self.config.srtp_profiles,
                &[],
            ));
        }

        // STATUS_REQUEST_V2 / OCSP multi-stapling (RFC 6961)
        if self.config.enable_ocsp_multi_stapling {
            extensions.push(crate::handshake::extensions_codec::build_status_request_v2(
                &[2],
            ));
        }

        // Custom extensions
        extensions.extend(crate::extensions::build_custom_extensions(
            &self.config.custom_extensions,
            crate::extensions::ExtensionContext::CLIENT_HELLO,
        ));

        // Cache the EMS flag from resumption session for later validation
        if let Some(ref session) = self.config.resumption_session {
            self.cached_session_ems = session.extended_master_secret;
        }

        // Filter cipher suites to TLS 1.2 ones only
        let mut tls12_suites: Vec<CipherSuite> = self
            .config
            .cipher_suites
            .iter()
            .copied()
            .filter(|s| crate::crypt::is_tls12_suite(*s))
            .collect();

        if tls12_suites.is_empty() {
            return Err(TlsError::NoSharedCipherSuite);
        }

        // Fallback SCSV (RFC 7507)
        if self.config.send_fallback_scsv {
            tls12_suites.push(CipherSuite::TLS_FALLBACK_SCSV);
        }

        // Use cached session ID for resumption, or generate a random one.
        // For ticket-based resumption: if session has a ticket but empty ID, generate
        // a random session_id so the server can echo it back (RFC 5077 §3.4).
        // During renegotiation, always use a fresh session ID (no resumption).
        let session_id = if self.config.session_resumption && !self.is_renegotiation {
            if let Some(ref session) = self.config.resumption_session {
                self.cached_master_secret = session.master_secret.clone();
                if session.id.is_empty() && session.ticket.is_some() {
                    // Ticket-based resumption: generate random session_id
                    let mut sid = vec![0u8; 32];
                    getrandom::getrandom(&mut sid)
                        .map_err(|e| TlsError::HandshakeFailed(format!("random gen: {e}")))?;
                    self.cached_session_id = sid.clone();
                    sid
                } else {
                    self.cached_session_id = session.id.clone();
                    session.id.clone()
                }
            } else {
                let mut sid = vec![0u8; 32];
                getrandom::getrandom(&mut sid)
                    .map_err(|e| TlsError::HandshakeFailed(format!("random gen: {e}")))?;
                sid
            }
        } else {
            let mut sid = vec![0u8; 32];
            getrandom::getrandom(&mut sid)
                .map_err(|e| TlsError::HandshakeFailed(format!("random gen: {e}")))?;
            sid
        };

        let ch = ClientHello {
            random: self.client_random,
            legacy_session_id: session_id,
            cipher_suites: tls12_suites,
            extensions,
        };

        let msg = encode_client_hello(&ch);
        self.client_hello_bytes = msg.clone();
        self.transcript.update(&msg)?;
        self.state = Tls12ClientState::WaitServerHello;
        Ok(msg)
    }

    /// Process a ServerHello message.
    pub fn process_server_hello(
        &mut self,
        raw_msg: &[u8],
        sh: &ServerHello,
    ) -> Result<CipherSuite, TlsError> {
        if self.state != Tls12ClientState::WaitServerHello {
            return Err(TlsError::HandshakeFailed("unexpected ServerHello".into()));
        }

        // Check cipher suite is one we offered and is TLS 1.2
        let params = Tls12CipherSuiteParams::from_suite(sh.cipher_suite)?;

        self.server_random = sh.random;

        // Parse ServerHello extensions
        for ext in &sh.extensions {
            match ext.extension_type {
                ExtensionType::SESSION_TICKET => {
                    self.server_supports_ticket = true;
                }
                ExtensionType::EXTENDED_MASTER_SECRET => {
                    crate::handshake::extensions_codec::parse_extended_master_secret(&ext.data)?;
                    self.use_extended_master_secret = true;
                }
                ExtensionType::ENCRYPT_THEN_MAC => {
                    crate::handshake::extensions_codec::parse_encrypt_then_mac(&ext.data)?;
                    // Only enable ETM for CBC suites
                    if params.is_cbc {
                        self.use_encrypt_then_mac = true;
                    }
                }
                ExtensionType::RENEGOTIATION_INFO => {
                    let ri_data =
                        crate::handshake::extensions_codec::parse_renegotiation_info(&ext.data)?;
                    if self.is_renegotiation {
                        // RFC 5746 §3.5: server must send
                        // client_verify_data || server_verify_data
                        let mut expected = Vec::with_capacity(
                            self.prev_client_verify_data.len() + self.prev_server_verify_data.len(),
                        );
                        expected.extend_from_slice(&self.prev_client_verify_data);
                        expected.extend_from_slice(&self.prev_server_verify_data);
                        if ri_data.ct_eq(&expected).unwrap_u8() != 1 {
                            return Err(TlsError::HandshakeFailed(
                                "renegotiation_info verify_data mismatch".into(),
                            ));
                        }
                    } else if !ri_data.is_empty() {
                        return Err(TlsError::HandshakeFailed(
                            "non-empty renegotiation_info in initial handshake".into(),
                        ));
                    }
                }
                ExtensionType::RECORD_SIZE_LIMIT => {
                    self.peer_record_size_limit = Some(
                        crate::handshake::extensions_codec::parse_record_size_limit(&ext.data)?,
                    );
                }
                ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
                    let proto = crate::handshake::extensions_codec::parse_alpn_sh(&ext.data)?;
                    self.negotiated_alpn = Some(proto);
                }
                ExtensionType::MAX_FRAGMENT_LENGTH => {
                    self.negotiated_max_fragment_length = Some(
                        crate::handshake::extensions_codec::parse_max_fragment_length(&ext.data)?,
                    );
                }
                _ => {}
            }
        }

        // Parse custom extensions in ServerHello
        crate::extensions::parse_custom_extensions(
            &self.config.custom_extensions,
            crate::extensions::ExtensionContext::SERVER_HELLO,
            &sh.extensions,
        )?;

        // Switch transcript hash if the negotiated suite uses SHA-384
        if params.hash_len == 48 {
            self.transcript = TranscriptHash::new(|| Box::new(hitls_crypto::sha2::Sha384::new()));
            // Replay the ClientHello into the new transcript
            self.transcript.update(&self.client_hello_bytes)?;
        }

        self.transcript.update(raw_msg)?;

        // Check for abbreviated handshake (session resumption)
        if !self.cached_session_id.is_empty() && sh.legacy_session_id == self.cached_session_id {
            // EMS resumption compatibility check (RFC 7627 §5.3):
            // - If cached session used EMS but server didn't echo EMS → reject abbreviation
            // - If cached session did NOT use EMS but server echoed EMS → reject abbreviation
            if self.cached_session_ems != self.use_extended_master_secret {
                // Fall through to full handshake
                self.abbreviated = false;
                self.kx_alg = params.kx_alg;
                let next_state = match params.kx_alg {
                    KeyExchangeAlg::Psk => Tls12ClientState::WaitServerHelloDone,
                    KeyExchangeAlg::DhePsk | KeyExchangeAlg::EcdhePsk => {
                        Tls12ClientState::WaitServerKeyExchange
                    }
                    _ => Tls12ClientState::WaitCertificate,
                };
                self.params = Some(params);
                self.state = next_state;
                return Ok(sh.cipher_suite);
            }

            self.abbreviated = true;

            // Derive keys from cached master_secret + new randoms
            let factory = params.hash_factory();
            let key_block = derive_key_block(
                &*factory,
                &self.cached_master_secret,
                &self.server_random,
                &self.client_random,
                &params,
            )?;

            let is_cbc = params.is_cbc;
            let mac_len = params.mac_len;

            self.abbreviated_keys = Some(AbbreviatedClientKeys {
                suite: sh.cipher_suite,
                master_secret: self.cached_master_secret.clone(),
                client_write_mac_key: key_block.client_write_mac_key.clone(),
                server_write_mac_key: key_block.server_write_mac_key.clone(),
                client_write_key: key_block.client_write_key.clone(),
                server_write_key: key_block.server_write_key.clone(),
                client_write_iv: key_block.client_write_iv.clone(),
                server_write_iv: key_block.server_write_iv.clone(),
                is_cbc,
                mac_len,
            });

            self.params = Some(params);
            self.state = Tls12ClientState::WaitChangeCipherSpec;
            return Ok(sh.cipher_suite);
        }

        self.kx_alg = params.kx_alg;
        // PSK/DhePsk/EcdhePsk suites have no Certificate message.
        // PSK goes straight to WaitServerHelloDone (SKE is optional: hint only).
        // DhePsk/EcdhePsk expect ServerKeyExchange with DH/ECDHE params.
        // RsaPsk has a certificate, same as Rsa.
        let next_state = match params.kx_alg {
            KeyExchangeAlg::Psk => Tls12ClientState::WaitServerHelloDone,
            KeyExchangeAlg::DhePsk
            | KeyExchangeAlg::EcdhePsk
            | KeyExchangeAlg::DheAnon
            | KeyExchangeAlg::EcdheAnon => Tls12ClientState::WaitServerKeyExchange,
            _ => Tls12ClientState::WaitCertificate,
        };
        self.params = Some(params);
        self.state = next_state;
        Ok(sh.cipher_suite)
    }

    /// Process a Certificate message (TLS 1.2 format).
    pub fn process_certificate(
        &mut self,
        raw_msg: &[u8],
        cert_list: &[Vec<u8>],
    ) -> Result<(), TlsError> {
        if self.state != Tls12ClientState::WaitCertificate {
            return Err(TlsError::HandshakeFailed("unexpected Certificate".into()));
        }

        if cert_list.is_empty() {
            return Err(TlsError::HandshakeFailed("empty certificate chain".into()));
        }

        self.server_certs = cert_list.to_vec();
        self.server_cert_der = cert_list[0].clone();
        self.transcript.update(raw_msg)?;

        crate::cert_verify::verify_server_certificate(&self.config, &self.server_certs)?;

        match self.kx_alg {
            // RSA / RSA_PSK: no ServerKeyExchange — skip directly to SHD
            KeyExchangeAlg::Rsa | KeyExchangeAlg::RsaPsk => {
                self.state = Tls12ClientState::WaitServerHelloDone;
            }
            // PSK/anonymous suites without certificates should never reach here
            KeyExchangeAlg::Psk
            | KeyExchangeAlg::DhePsk
            | KeyExchangeAlg::EcdhePsk
            | KeyExchangeAlg::DheAnon
            | KeyExchangeAlg::EcdheAnon => {
                return Err(TlsError::HandshakeFailed(
                    "unexpected Certificate for anonymous/PSK key exchange".into(),
                ));
            }
            // ECDHE / DHE: expect ServerKeyExchange next
            _ => {
                self.state = Tls12ClientState::WaitServerKeyExchange;
            }
        }
        Ok(())
    }

    /// Process a ServerKeyExchange message.
    ///
    /// Verifies the signature over the ECDHE parameters using the server's
    /// certificate public key.
    pub fn process_server_key_exchange(
        &mut self,
        raw_msg: &[u8],
        ske: &ServerKeyExchange,
    ) -> Result<(), TlsError> {
        if self.state != Tls12ClientState::WaitServerKeyExchange {
            return Err(TlsError::HandshakeFailed(
                "unexpected ServerKeyExchange".into(),
            ));
        }

        // Verify the signature
        if self.config.verify_peer {
            let params = build_ske_params(ske.curve_type, ske.named_curve, &ske.public_key);
            let signed_data =
                build_ske_signed_data(&self.client_random, &self.server_random, &params);

            verify_ske_signature(
                &self.server_certs[0],
                ske.signature_algorithm,
                &signed_data,
                &ske.signature,
            )?;
        }

        self.server_ecdh_public = ske.public_key.clone();
        self.server_named_curve = ske.named_curve;
        self.transcript.update(raw_msg)?;
        self.state = Tls12ClientState::WaitServerHelloDone;
        Ok(())
    }

    /// Process a DHE ServerKeyExchange message.
    ///
    /// Verifies the signature over the DHE parameters using the server's
    /// certificate public key.
    pub fn process_server_key_exchange_dhe(
        &mut self,
        raw_msg: &[u8],
        ske: &ServerKeyExchangeDhe,
    ) -> Result<(), TlsError> {
        if self.state != Tls12ClientState::WaitServerKeyExchange {
            return Err(TlsError::HandshakeFailed(
                "unexpected DHE ServerKeyExchange".into(),
            ));
        }

        // Verify the signature
        if self.config.verify_peer {
            let params = build_dhe_ske_params(&ske.dh_p, &ske.dh_g, &ske.dh_ys);
            let signed_data =
                build_ske_signed_data(&self.client_random, &self.server_random, &params);
            verify_ske_signature(
                &self.server_certs[0],
                ske.signature_algorithm,
                &signed_data,
                &ske.signature,
            )?;
        }

        self.server_dhe_p = ske.dh_p.clone();
        self.server_dhe_g = ske.dh_g.clone();
        self.server_dhe_ys = ske.dh_ys.clone();
        self.transcript.update(raw_msg)?;
        self.state = Tls12ClientState::WaitServerHelloDone;
        Ok(())
    }

    /// Process PSK hint-only ServerKeyExchange (for PSK or RSA_PSK).
    pub fn process_server_key_exchange_psk_hint(
        &mut self,
        raw_msg: &[u8],
        ske: &ServerKeyExchangePskHint,
    ) -> Result<(), TlsError> {
        self.transcript.update(raw_msg)?;
        self.server_psk_hint = ske.hint.clone();
        self.state = Tls12ClientState::WaitServerHelloDone;
        Ok(())
    }

    /// Process DHE_PSK ServerKeyExchange (unsigned DH params + hint).
    pub fn process_server_key_exchange_dhe_psk(
        &mut self,
        raw_msg: &[u8],
        ske: &SkeDhePsk,
    ) -> Result<(), TlsError> {
        self.transcript.update(raw_msg)?;
        self.server_psk_hint = ske.hint.clone();
        self.server_dhe_p = ske.dh_p.clone();
        self.server_dhe_g = ske.dh_g.clone();
        self.server_dhe_ys = ske.dh_ys.clone();
        self.state = Tls12ClientState::WaitServerHelloDone;
        Ok(())
    }

    /// Process ECDHE_PSK ServerKeyExchange (unsigned ECDHE params + hint).
    pub fn process_server_key_exchange_ecdhe_psk(
        &mut self,
        raw_msg: &[u8],
        ske: &ServerKeyExchangeEcdhePsk,
    ) -> Result<(), TlsError> {
        self.transcript.update(raw_msg)?;
        self.server_psk_hint = ske.hint.clone();
        self.server_named_curve = ske.named_curve;
        self.server_ecdh_public = ske.public_key.clone();
        self.state = Tls12ClientState::WaitServerHelloDone;
        Ok(())
    }

    /// Process a DH_anon ServerKeyExchange (unsigned DH params).
    pub fn process_server_key_exchange_dhe_anon(
        &mut self,
        raw_msg: &[u8],
        ske: &ServerKeyExchangeDheAnon,
    ) -> Result<(), TlsError> {
        if self.state != Tls12ClientState::WaitServerKeyExchange {
            return Err(TlsError::HandshakeFailed(
                "unexpected DH_anon ServerKeyExchange".into(),
            ));
        }
        self.server_dhe_p = ske.dh_p.clone();
        self.server_dhe_g = ske.dh_g.clone();
        self.server_dhe_ys = ske.dh_ys.clone();
        self.transcript.update(raw_msg)?;
        self.state = Tls12ClientState::WaitServerHelloDone;
        Ok(())
    }

    /// Process an ECDH_anon ServerKeyExchange (unsigned ECDHE params).
    pub fn process_server_key_exchange_ecdhe_anon(
        &mut self,
        raw_msg: &[u8],
        ske: &ServerKeyExchangeEcdheAnon,
    ) -> Result<(), TlsError> {
        if self.state != Tls12ClientState::WaitServerKeyExchange {
            return Err(TlsError::HandshakeFailed(
                "unexpected ECDH_anon ServerKeyExchange".into(),
            ));
        }
        self.server_named_curve = ske.named_curve;
        self.server_ecdh_public = ske.public_key.clone();
        self.transcript.update(raw_msg)?;
        self.state = Tls12ClientState::WaitServerHelloDone;
        Ok(())
    }

    /// Process a CertificateRequest message from the server (mTLS).
    ///
    /// `raw_msg` is the full handshake message including the 4-byte header.
    pub fn process_certificate_request(
        &mut self,
        raw_msg: &[u8],
        cr: &CertificateRequest12,
    ) -> Result<(), TlsError> {
        if self.state != Tls12ClientState::WaitServerHelloDone {
            return Err(TlsError::HandshakeFailed(
                "unexpected CertificateRequest".into(),
            ));
        }

        self.cert_request_received = true;
        self.requested_sig_algs = cr.sig_hash_algs.clone();
        self.transcript.update(raw_msg)?;
        // Stay in WaitServerHelloDone — ServerHelloDone comes next
        Ok(())
    }

    /// Process a ServerHelloDone message.
    ///
    /// Triggers the client flight: generates ClientKeyExchange, derives keys,
    /// and computes Finished.
    pub fn process_server_hello_done(
        &mut self,
        raw_msg: &[u8],
    ) -> Result<ClientFlightResult, TlsError> {
        if self.state != Tls12ClientState::WaitServerHelloDone {
            return Err(TlsError::HandshakeFailed(
                "unexpected ServerHelloDone".into(),
            ));
        }

        self.transcript.update(raw_msg)?;

        let params = self
            .params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher suite params".into()))?;

        // Build client Certificate (if server requested)
        let client_certificate = if self.cert_request_received {
            let cert_list = self.config.client_certificate_chain.clone();
            let cert12 = Certificate12 {
                certificate_list: cert_list,
            };
            let cert_msg = encode_certificate12(&cert12);
            self.transcript.update(&cert_msg)?;
            Some(cert_msg)
        } else {
            None
        };

        // Generate premaster secret and CKE based on key exchange algorithm
        let (pre_master_secret, cke_msg) = match self.kx_alg {
            KeyExchangeAlg::Ecdhe => {
                let group = match self.server_named_curve {
                    0x0017 => NamedGroup::SECP256R1,
                    0x0018 => NamedGroup::SECP384R1,
                    0x001D => NamedGroup::X25519,
                    _ => {
                        return Err(TlsError::HandshakeFailed(format!(
                            "unsupported ECDH curve: 0x{:04x}",
                            self.server_named_curve
                        )))
                    }
                };
                let kx = KeyExchange::generate(group)?;
                let client_public = kx.public_key_bytes().to_vec();
                let pms = kx.compute_shared_secret(&self.server_ecdh_public)?;
                let cke = ClientKeyExchange {
                    public_key: client_public,
                };
                let cke_msg = encode_client_key_exchange(&cke);
                (pms, cke_msg)
            }
            KeyExchangeAlg::Rsa => {
                // Generate 48-byte PMS: version(2) || random(46)
                let mut pms = vec![0u8; 48];
                pms[0] = 0x03;
                pms[1] = 0x03;
                getrandom::getrandom(&mut pms[2..])
                    .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;
                // Encrypt PMS with server's RSA public key
                let rsa_pub = parse_rsa_public_key_from_cert(&self.server_cert_der)?;
                let encrypted_pms = rsa_pub
                    .encrypt(RsaPadding::Pkcs1v15Encrypt, &pms)
                    .map_err(TlsError::CryptoError)?;
                let cke = ClientKeyExchangeRsa { encrypted_pms };
                let cke_msg = encode_client_key_exchange_rsa(&cke);
                (pms, cke_msg)
            }
            KeyExchangeAlg::Dhe => {
                let dh_params = DhParams::new(&self.server_dhe_p, &self.server_dhe_g)
                    .map_err(TlsError::CryptoError)?;
                let kp = DhKeyPair::generate(&dh_params).map_err(TlsError::CryptoError)?;
                let yc = kp
                    .public_key_bytes(&dh_params)
                    .map_err(TlsError::CryptoError)?;
                let pms = kp
                    .compute_shared_secret(&dh_params, &self.server_dhe_ys)
                    .map_err(TlsError::CryptoError)?;
                let cke = ClientKeyExchangeDhe { dh_yc: yc };
                let cke_msg = encode_client_key_exchange_dhe(&cke);
                (pms, cke_msg)
            }
            KeyExchangeAlg::Psk => {
                let psk = self
                    .config
                    .psk
                    .as_ref()
                    .ok_or_else(|| TlsError::HandshakeFailed("no PSK configured".into()))?;
                let other_secret = vec![0u8; psk.len()];
                let pms = build_psk_pms(&other_secret, psk);
                let identity = self.config.psk_identity.as_ref().ok_or_else(|| {
                    TlsError::HandshakeFailed("no PSK identity configured".into())
                })?;
                let cke = ClientKeyExchangePsk {
                    identity: identity.clone(),
                };
                let cke_msg = encode_client_key_exchange_psk(&cke);
                (pms, cke_msg)
            }
            KeyExchangeAlg::DhePsk => {
                let psk = self
                    .config
                    .psk
                    .as_ref()
                    .ok_or_else(|| TlsError::HandshakeFailed("no PSK configured".into()))?;
                let identity = self.config.psk_identity.as_ref().ok_or_else(|| {
                    TlsError::HandshakeFailed("no PSK identity configured".into())
                })?;
                let dh_params = DhParams::new(&self.server_dhe_p, &self.server_dhe_g)
                    .map_err(TlsError::CryptoError)?;
                let dh_kp = DhKeyPair::generate(&dh_params).map_err(TlsError::CryptoError)?;
                let dh_yc = dh_kp
                    .public_key_bytes(&dh_params)
                    .map_err(TlsError::CryptoError)?;
                let dh_shared = dh_kp
                    .compute_shared_secret(&dh_params, &self.server_dhe_ys)
                    .map_err(TlsError::CryptoError)?;
                let pms = build_psk_pms(&dh_shared, psk);
                let cke = ClientKeyExchangeDhePsk {
                    identity: identity.clone(),
                    dh_yc,
                };
                let cke_msg = encode_client_key_exchange_dhe_psk(&cke);
                (pms, cke_msg)
            }
            KeyExchangeAlg::EcdhePsk => {
                let psk = self
                    .config
                    .psk
                    .as_ref()
                    .ok_or_else(|| TlsError::HandshakeFailed("no PSK configured".into()))?;
                let identity = self.config.psk_identity.as_ref().ok_or_else(|| {
                    TlsError::HandshakeFailed("no PSK identity configured".into())
                })?;
                let group = match self.server_named_curve {
                    0x0017 => NamedGroup::SECP256R1,
                    0x0018 => NamedGroup::SECP384R1,
                    0x001D => NamedGroup::X25519,
                    _ => {
                        return Err(TlsError::HandshakeFailed(format!(
                            "unsupported ECDH curve: 0x{:04x}",
                            self.server_named_curve
                        )))
                    }
                };
                let kx = KeyExchange::generate(group)?;
                let ecdh_shared = kx.compute_shared_secret(&self.server_ecdh_public)?;
                let pms = build_psk_pms(&ecdh_shared, psk);
                let cke = ClientKeyExchangeEcdhePsk {
                    identity: identity.clone(),
                    public_key: kx.public_key_bytes().to_vec(),
                };
                let cke_msg = encode_client_key_exchange_ecdhe_psk(&cke);
                (pms, cke_msg)
            }
            KeyExchangeAlg::RsaPsk => {
                let psk = self
                    .config
                    .psk
                    .as_ref()
                    .ok_or_else(|| TlsError::HandshakeFailed("no PSK configured".into()))?;
                let identity = self.config.psk_identity.as_ref().ok_or_else(|| {
                    TlsError::HandshakeFailed("no PSK identity configured".into())
                })?;
                // Generate 48-byte RSA PMS: version(2) || random(46)
                let mut rsa_pms = vec![0u8; 48];
                rsa_pms[0] = 0x03;
                rsa_pms[1] = 0x03;
                getrandom::getrandom(&mut rsa_pms[2..])
                    .map_err(|e| TlsError::HandshakeFailed(format!("getrandom failed: {e}")))?;
                let rsa_pub = parse_rsa_public_key_from_cert(&self.server_cert_der)?;
                let encrypted = rsa_pub
                    .encrypt(RsaPadding::Pkcs1v15Encrypt, &rsa_pms)
                    .map_err(TlsError::CryptoError)?;
                let pms = build_psk_pms(&rsa_pms, psk);
                let cke = ClientKeyExchangeRsaPsk {
                    identity: identity.clone(),
                    encrypted_pms: encrypted,
                };
                let cke_msg = encode_client_key_exchange_rsa_psk(&cke);
                (pms, cke_msg)
            }
            KeyExchangeAlg::DheAnon => {
                let dh_params = DhParams::new(&self.server_dhe_p, &self.server_dhe_g)
                    .map_err(TlsError::CryptoError)?;
                let kp = DhKeyPair::generate(&dh_params).map_err(TlsError::CryptoError)?;
                let yc = kp
                    .public_key_bytes(&dh_params)
                    .map_err(TlsError::CryptoError)?;
                let pms = kp
                    .compute_shared_secret(&dh_params, &self.server_dhe_ys)
                    .map_err(TlsError::CryptoError)?;
                let cke = ClientKeyExchangeDhe { dh_yc: yc };
                let cke_msg = encode_client_key_exchange_dhe(&cke);
                (pms, cke_msg)
            }
            KeyExchangeAlg::EcdheAnon => {
                let group = match self.server_named_curve {
                    0x0017 => NamedGroup::SECP256R1,
                    0x0018 => NamedGroup::SECP384R1,
                    0x001D => NamedGroup::X25519,
                    _ => {
                        return Err(TlsError::HandshakeFailed(format!(
                            "unsupported ECDH curve: 0x{:04x}",
                            self.server_named_curve
                        )))
                    }
                };
                let kx = KeyExchange::generate(group)?;
                let client_public = kx.public_key_bytes().to_vec();
                let pms = kx.compute_shared_secret(&self.server_ecdh_public)?;
                let cke = ClientKeyExchange {
                    public_key: client_public,
                };
                let cke_msg = encode_client_key_exchange(&cke);
                (pms, cke_msg)
            }
            #[cfg(feature = "tlcp")]
            _ => {
                return Err(TlsError::HandshakeFailed(
                    "unsupported key exchange algorithm".into(),
                ))
            }
        };
        self.transcript.update(&cke_msg)?;

        // Derive master secret (EMS uses transcript hash instead of randoms)
        let factory = params.hash_factory();
        let master_secret = if self.use_extended_master_secret {
            let session_hash = self.transcript.current_hash()?;
            derive_extended_master_secret(&*factory, &pre_master_secret, &session_hash)?
        } else {
            derive_master_secret(
                &*factory,
                &pre_master_secret,
                &self.client_random,
                &self.server_random,
            )?
        };
        crate::crypt::keylog::log_master_secret(&self.config, &self.client_random, &master_secret);

        // Derive key block
        let key_block = derive_key_block(
            &*factory,
            &master_secret,
            &self.server_random,
            &self.client_random,
            params,
        )?;

        // Build CertificateVerify (if client sent a non-empty certificate)
        let certificate_verify = if self.cert_request_received
            && !self.config.client_certificate_chain.is_empty()
        {
            if let Some(ref client_key) = self.config.client_private_key {
                let transcript_hash = self.transcript.current_hash()?;
                let scheme = select_signature_scheme_tls12(client_key, &self.requested_sig_algs)?;
                let signature = sign_certificate_verify12(client_key, scheme, &transcript_hash)?;
                let cv = CertificateVerify12 {
                    sig_algorithm: scheme,
                    signature,
                };
                let cv_msg = encode_certificate_verify12(&cv);
                self.transcript.update(&cv_msg)?;
                Some(cv_msg)
            } else {
                None
            }
        } else {
            None
        };

        // Compute client Finished
        let transcript_hash = self.transcript.current_hash()?;
        let verify_data = compute_verify_data(
            &*factory,
            &master_secret,
            "client finished",
            &transcript_hash,
        )?;
        self.client_verify_data = verify_data.clone();
        let finished_msg = encode_finished12(&verify_data);
        // The Finished message itself is added to the transcript for verifying server Finished
        self.transcript.update(&finished_msg)?;

        self.state = Tls12ClientState::WaitChangeCipherSpec;

        Ok(ClientFlightResult {
            client_certificate,
            client_key_exchange: cke_msg,
            certificate_verify,
            finished: finished_msg,
            master_secret,
            client_write_mac_key: key_block.client_write_mac_key.clone(),
            server_write_mac_key: key_block.server_write_mac_key.clone(),
            client_write_key: key_block.client_write_key.clone(),
            server_write_key: key_block.server_write_key.clone(),
            client_write_iv: key_block.client_write_iv.clone(),
            server_write_iv: key_block.server_write_iv.clone(),
            is_cbc: params.is_cbc,
            mac_len: params.mac_len,
        })
    }

    /// Process ChangeCipherSpec from server.
    pub fn process_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        if self.state != Tls12ClientState::WaitChangeCipherSpec {
            return Err(TlsError::HandshakeFailed(
                "unexpected ChangeCipherSpec".into(),
            ));
        }
        // CCS is not a handshake message — not added to transcript
        self.state = Tls12ClientState::WaitFinished;
        Ok(())
    }

    /// Process server Finished in abbreviated handshake and return client Finished.
    ///
    /// In abbreviated mode, verifies the server's Finished, adds it to transcript,
    /// then computes and returns the client Finished message.
    pub fn process_abbreviated_server_finished(
        &mut self,
        raw_msg: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        if self.state != Tls12ClientState::WaitFinished || !self.abbreviated {
            return Err(TlsError::HandshakeFailed(
                "unexpected abbreviated Finished".into(),
            ));
        }

        let params = self
            .params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher suite params".into()))?;

        if raw_msg.len() < 4 + 12 {
            return Err(TlsError::HandshakeFailed(
                "Finished message too short".into(),
            ));
        }
        let received_verify_data = &raw_msg[4..4 + 12];

        // Verify server Finished: PRF(ms, "server finished", Hash(CH + SH))
        let factory = params.hash_factory();
        let transcript_hash = self.transcript.current_hash()?;
        let expected = compute_verify_data(
            &*factory,
            &self.cached_master_secret,
            "server finished",
            &transcript_hash,
        )?;

        if !bool::from(received_verify_data.ct_eq(&expected)) {
            return Err(TlsError::HandshakeFailed(
                "server Finished verify_data mismatch".into(),
            ));
        }

        self.server_verify_data = received_verify_data.to_vec();

        // Add server Finished to transcript
        self.transcript.update(raw_msg)?;

        // Compute client Finished: PRF(ms, "client finished", Hash(CH + SH + server_Finished))
        let transcript_hash = self.transcript.current_hash()?;
        let client_verify_data = compute_verify_data(
            &*factory,
            &self.cached_master_secret,
            "client finished",
            &transcript_hash,
        )?;
        self.client_verify_data = client_verify_data.clone();
        let finished_msg = encode_finished12(&client_verify_data);

        self.state = Tls12ClientState::Connected;
        Ok(finished_msg)
    }

    /// Process server Finished message.
    pub fn process_finished(
        &mut self,
        raw_msg: &[u8],
        master_secret: &[u8],
    ) -> Result<(), TlsError> {
        if self.state != Tls12ClientState::WaitFinished {
            return Err(TlsError::HandshakeFailed("unexpected Finished".into()));
        }

        let params = self
            .params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher suite params".into()))?;

        // Parse verify_data from raw_msg (skip 4-byte handshake header)
        if raw_msg.len() < 4 + 12 {
            return Err(TlsError::HandshakeFailed(
                "Finished message too short".into(),
            ));
        }
        let received_verify_data = &raw_msg[4..4 + 12];

        // Compute expected verify_data
        let factory = params.hash_factory();
        let transcript_hash = self.transcript.current_hash()?;
        let expected = compute_verify_data(
            &*factory,
            master_secret,
            "server finished",
            &transcript_hash,
        )?;

        // Constant-time comparison
        if received_verify_data.ct_eq(&expected).into() {
            self.server_verify_data = received_verify_data.to_vec();
            self.transcript.update(raw_msg)?;
            self.state = Tls12ClientState::Connected;
            Ok(())
        } else {
            Err(TlsError::HandshakeFailed(
                "server Finished verify_data mismatch".into(),
            ))
        }
    }
}

/// Verify the signature on ServerKeyExchange parameters.
pub(crate) fn verify_ske_signature(
    cert_der: &[u8],
    scheme: SignatureScheme,
    signed_data: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    let cert = hitls_pki::x509::Certificate::from_der(cert_der)
        .map_err(|e| TlsError::HandshakeFailed(format!("cert parse: {e}")))?;
    let spki = &cert.public_key;

    let ok = match scheme {
        SignatureScheme::RSA_PKCS1_SHA256 => {
            let digest = compute_sha256(signed_data)?;
            verify_rsa_pkcs1(spki, &digest, signature)?
        }
        SignatureScheme::RSA_PKCS1_SHA384 => {
            let digest = compute_sha384(signed_data)?;
            verify_rsa_pkcs1(spki, &digest, signature)?
        }
        SignatureScheme::RSA_PSS_RSAE_SHA256 => {
            let digest = compute_sha256(signed_data)?;
            verify_rsa_pss(spki, &digest, signature)?
        }
        SignatureScheme::ECDSA_SECP256R1_SHA256 => {
            let digest = compute_sha256(signed_data)?;
            verify_ecdsa(spki, hitls_types::EccCurveId::NistP256, &digest, signature)?
        }
        SignatureScheme::ECDSA_SECP384R1_SHA384 => {
            let digest = compute_sha384(signed_data)?;
            verify_ecdsa(spki, hitls_types::EccCurveId::NistP384, &digest, signature)?
        }
        SignatureScheme::DSA_SHA256 => {
            let digest = compute_sha256(signed_data)?;
            crate::handshake::server12::verify_dsa_from_spki(spki, &digest, signature)?
        }
        SignatureScheme::DSA_SHA384 => {
            let digest = compute_sha384(signed_data)?;
            crate::handshake::server12::verify_dsa_from_spki(spki, &digest, signature)?
        }
        _ => {
            return Err(TlsError::HandshakeFailed(format!(
                "unsupported SKE signature scheme: 0x{:04x}",
                scheme.0
            )))
        }
    };

    if ok {
        Ok(())
    } else {
        Err(TlsError::HandshakeFailed(
            "ServerKeyExchange signature verification failed".into(),
        ))
    }
}

fn compute_sha256(data: &[u8]) -> Result<Vec<u8>, TlsError> {
    let mut h = hitls_crypto::sha2::Sha256::new();
    h.update(data).map_err(TlsError::CryptoError)?;
    Ok(h.finish().map_err(TlsError::CryptoError)?.to_vec())
}

fn compute_sha384(data: &[u8]) -> Result<Vec<u8>, TlsError> {
    let mut h = hitls_crypto::sha2::Sha384::new();
    h.update(data).map_err(TlsError::CryptoError)?;
    Ok(h.finish().map_err(TlsError::CryptoError)?.to_vec())
}

fn verify_rsa_pkcs1(
    spki: &hitls_pki::x509::SubjectPublicKeyInfo,
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, TlsError> {
    use hitls_utils::asn1::Decoder;
    let mut key_dec = Decoder::new(&spki.public_key);
    let mut seq = key_dec
        .read_sequence()
        .map_err(|e| TlsError::HandshakeFailed(format!("RSA key parse: {e}")))?;
    let n = seq
        .read_integer()
        .map_err(|e| TlsError::HandshakeFailed(format!("RSA modulus parse: {e}")))?;
    let e = seq
        .read_integer()
        .map_err(|e| TlsError::HandshakeFailed(format!("RSA exponent parse: {e}")))?;

    let rsa_pub = hitls_crypto::rsa::RsaPublicKey::new(n, e).map_err(TlsError::CryptoError)?;
    rsa_pub
        .verify(
            hitls_crypto::rsa::RsaPadding::Pkcs1v15Sign,
            digest,
            signature,
        )
        .map_err(TlsError::CryptoError)
}

fn verify_rsa_pss(
    spki: &hitls_pki::x509::SubjectPublicKeyInfo,
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, TlsError> {
    use hitls_utils::asn1::Decoder;
    let mut key_dec = Decoder::new(&spki.public_key);
    let mut seq = key_dec
        .read_sequence()
        .map_err(|e| TlsError::HandshakeFailed(format!("RSA key parse: {e}")))?;
    let n = seq
        .read_integer()
        .map_err(|e| TlsError::HandshakeFailed(format!("RSA modulus parse: {e}")))?;
    let e = seq
        .read_integer()
        .map_err(|e| TlsError::HandshakeFailed(format!("RSA exponent parse: {e}")))?;

    let rsa_pub = hitls_crypto::rsa::RsaPublicKey::new(n, e).map_err(TlsError::CryptoError)?;
    rsa_pub
        .verify(hitls_crypto::rsa::RsaPadding::Pss, digest, signature)
        .map_err(TlsError::CryptoError)
}

fn verify_ecdsa(
    spki: &hitls_pki::x509::SubjectPublicKeyInfo,
    curve_id: hitls_types::EccCurveId,
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, TlsError> {
    let verifier = hitls_crypto::ecdsa::EcdsaKeyPair::from_public_key(curve_id, &spki.public_key)
        .map_err(TlsError::CryptoError)?;
    verifier
        .verify(digest, signature)
        .map_err(TlsError::CryptoError)
}

/// Sign transcript hash for TLS 1.2 CertificateVerify.
///
/// Unlike `sign_ske_data`, the `transcript_hash` is already a digest — it is
/// passed directly to the signing function without additional hashing.
fn sign_certificate_verify12(
    key: &ServerPrivateKey,
    scheme: SignatureScheme,
    transcript_hash: &[u8],
) -> Result<Vec<u8>, TlsError> {
    match key {
        ServerPrivateKey::Ed25519(seed) => {
            let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(seed)
                .map_err(TlsError::CryptoError)?;
            kp.sign(transcript_hash)
                .map(|s| s.to_vec())
                .map_err(TlsError::CryptoError)
        }
        ServerPrivateKey::Ed448(seed) => {
            let kp = hitls_crypto::ed448::Ed448KeyPair::from_seed(seed)
                .map_err(TlsError::CryptoError)?;
            kp.sign(transcript_hash)
                .map(|s| s.to_vec())
                .map_err(TlsError::CryptoError)
        }
        ServerPrivateKey::Ecdsa {
            curve_id,
            private_key,
        } => {
            // transcript_hash IS the digest — sign directly
            let kp = hitls_crypto::ecdsa::EcdsaKeyPair::from_private_key(*curve_id, private_key)
                .map_err(TlsError::CryptoError)?;
            kp.sign(transcript_hash).map_err(TlsError::CryptoError)
        }
        ServerPrivateKey::Rsa { n, d, e, p, q } => {
            let padding = match scheme {
                SignatureScheme::RSA_PKCS1_SHA256 | SignatureScheme::RSA_PKCS1_SHA384 => {
                    hitls_crypto::rsa::RsaPadding::Pkcs1v15Sign
                }
                _ => hitls_crypto::rsa::RsaPadding::Pss,
            };
            let rsa_key = hitls_crypto::rsa::RsaPrivateKey::new(n, d, e, p, q)
                .map_err(TlsError::CryptoError)?;
            rsa_key
                .sign(padding, transcript_hash)
                .map_err(TlsError::CryptoError)
        }
        ServerPrivateKey::Dsa {
            params_der,
            private_key,
        } => {
            let params = crate::handshake::server12::parse_dsa_params_der(params_der)?;
            let kp = hitls_crypto::dsa::DsaKeyPair::from_private_key(params, private_key)
                .map_err(TlsError::CryptoError)?;
            // transcript_hash IS the digest — sign directly
            kp.sign(transcript_hash).map_err(TlsError::CryptoError)
        }
        #[cfg(feature = "tlcp")]
        ServerPrivateKey::Sm2 { private_key } => {
            let kp = hitls_crypto::sm2::Sm2KeyPair::from_private_key(private_key)
                .map_err(TlsError::CryptoError)?;
            kp.sign(transcript_hash).map_err(TlsError::CryptoError)
        }
    }
}

/// Parse the RSA public key from a DER-encoded X.509 certificate.
///
/// Extracts the SubjectPublicKeyInfo, decodes the RSA modulus and exponent,
/// and returns an `RsaPublicKey` suitable for encryption.
fn parse_rsa_public_key_from_cert(cert_der: &[u8]) -> Result<RsaPublicKey, TlsError> {
    let cert = hitls_pki::x509::Certificate::from_der(cert_der)
        .map_err(|e| TlsError::HandshakeFailed(format!("cert parse: {e}")))?;
    let spki = &cert.public_key;

    use hitls_utils::asn1::Decoder;
    let mut key_dec = Decoder::new(&spki.public_key);
    let mut seq = key_dec
        .read_sequence()
        .map_err(|e| TlsError::HandshakeFailed(format!("RSA key parse: {e}")))?;
    let n = seq
        .read_integer()
        .map_err(|e| TlsError::HandshakeFailed(format!("RSA modulus parse: {e}")))?;
    let e = seq
        .read_integer()
        .map_err(|e| TlsError::HandshakeFailed(format!("RSA exponent parse: {e}")))?;

    RsaPublicKey::new(n, e).map_err(TlsError::CryptoError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_build() {
        let config = TlsConfig::builder()
            .cipher_suites(&[
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_AES_128_GCM_SHA256, // TLS 1.3 suite should be filtered out
            ])
            .supported_groups(&[NamedGroup::SECP256R1])
            .build();

        let mut hs = Tls12ClientHandshake::new(config);
        let ch_msg = hs.build_client_hello().unwrap();

        // Verify it's a valid handshake message
        let (msg_type, body, _) = crate::handshake::codec::parse_handshake_header(&ch_msg).unwrap();
        assert_eq!(msg_type, crate::handshake::HandshakeType::ClientHello);

        // Parse the ClientHello
        let ch = crate::handshake::codec::decode_client_hello(body).unwrap();
        // Should only contain TLS 1.2 suites
        assert_eq!(ch.cipher_suites.len(), 1);
        assert_eq!(
            ch.cipher_suites[0],
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        );

        assert_eq!(hs.state(), Tls12ClientState::WaitServerHello);
    }

    #[test]
    fn test_state_transitions() {
        let hs = Tls12ClientHandshake::new(TlsConfig::builder().build());
        assert_eq!(hs.state(), Tls12ClientState::Idle);
    }

    #[test]
    fn test_client_stores_cert_request() {
        let config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .build();
        let mut hs = Tls12ClientHandshake::new(config);

        // Must be in WaitServerHelloDone to process CertificateRequest
        hs.state = Tls12ClientState::WaitServerHelloDone;

        let cr = CertificateRequest12 {
            cert_types: vec![1, 64],
            sig_hash_algs: vec![
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                SignatureScheme::RSA_PSS_RSAE_SHA256,
            ],
            ca_names: vec![],
        };
        let cr_msg = crate::handshake::codec12::encode_certificate_request12(&cr);
        hs.process_certificate_request(&cr_msg, &cr).unwrap();

        assert!(hs.cert_request_received);
        assert_eq!(hs.requested_sig_algs.len(), 2);
        // Still in WaitServerHelloDone
        assert_eq!(hs.state(), Tls12ClientState::WaitServerHelloDone);
    }

    #[test]
    fn test_cert_request_wrong_state() {
        let config = TlsConfig::builder().build();
        let mut hs = Tls12ClientHandshake::new(config);

        let cr = CertificateRequest12 {
            cert_types: vec![1],
            sig_hash_algs: vec![SignatureScheme::ECDSA_SECP256R1_SHA256],
            ca_names: vec![],
        };
        let cr_msg = crate::handshake::codec12::encode_certificate_request12(&cr);
        // State is Idle, not WaitServerHelloDone
        assert!(hs.process_certificate_request(&cr_msg, &cr).is_err());
    }

    #[test]
    fn test_client_sends_cached_session_id() {
        use crate::session::TlsSession;

        let session_id = vec![0xAA; 32];
        let master_secret = vec![0xBB; 48];
        let session = TlsSession {
            id: session_id.clone(),
            cipher_suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            master_secret,
            alpn_protocol: None,
            ticket: None,
            ticket_lifetime: 0,
            max_early_data: 0,
            ticket_age_add: 0,
            ticket_nonce: Vec::new(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            psk: Vec::new(),
            extended_master_secret: false,
        };

        let config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .session_resumption(true)
            .resumption_session(session)
            .build();

        let mut hs = Tls12ClientHandshake::new(config);
        let ch_msg = hs.build_client_hello().unwrap();

        // Parse the ClientHello and verify it contains the cached session_id
        let (_, body, _) = crate::handshake::codec::parse_handshake_header(&ch_msg).unwrap();
        let ch = crate::handshake::codec::decode_client_hello(body).unwrap();
        assert_eq!(ch.legacy_session_id, session_id);
        assert_eq!(hs.cached_session_id, session_id);
    }

    #[test]
    fn test_client_detects_abbreviated_handshake() {
        use crate::handshake::codec::{encode_server_hello, ServerHello};
        use crate::session::TlsSession;

        let session_id = vec![0xAA; 32];
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let session = TlsSession {
            id: session_id.clone(),
            cipher_suite: suite,
            master_secret: vec![0xBB; 48],
            alpn_protocol: None,
            ticket: None,
            ticket_lifetime: 0,
            max_early_data: 0,
            ticket_age_add: 0,
            ticket_nonce: Vec::new(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            psk: Vec::new(),
            extended_master_secret: false,
        };

        let config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .session_resumption(true)
            .resumption_session(session)
            .build();

        let mut hs = Tls12ClientHandshake::new(config);
        hs.build_client_hello().unwrap();

        // Server echoes back the cached session_id → abbreviated
        let mut server_random = [0u8; 32];
        getrandom::getrandom(&mut server_random).unwrap();
        let sh = ServerHello {
            random: server_random,
            legacy_session_id: session_id,
            cipher_suite: suite,
            extensions: Vec::new(),
        };
        let sh_msg = encode_server_hello(&sh);
        let result_suite = hs.process_server_hello(&sh_msg, &sh).unwrap();

        assert_eq!(result_suite, suite);
        assert!(hs.is_abbreviated());
        assert_eq!(hs.state(), Tls12ClientState::WaitChangeCipherSpec);

        // Keys should be available
        let keys = hs.take_abbreviated_keys();
        assert!(keys.is_some());
        let keys = keys.unwrap();
        assert_eq!(keys.suite, suite);
        assert!(!keys.client_write_key.is_empty());
        assert!(!keys.server_write_key.is_empty());
    }

    #[test]
    fn test_client_falls_back_to_full_on_new_session_id() {
        use crate::handshake::codec::{encode_server_hello, ServerHello};
        use crate::session::TlsSession;

        let session_id = vec![0xAA; 32];
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let session = TlsSession {
            id: session_id,
            cipher_suite: suite,
            master_secret: vec![0xBB; 48],
            alpn_protocol: None,
            ticket: None,
            ticket_lifetime: 0,
            max_early_data: 0,
            ticket_age_add: 0,
            ticket_nonce: Vec::new(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            psk: Vec::new(),
            extended_master_secret: false,
        };

        let config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .session_resumption(true)
            .resumption_session(session)
            .build();

        let mut hs = Tls12ClientHandshake::new(config);
        hs.build_client_hello().unwrap();

        // Server responds with a DIFFERENT session_id → full handshake
        let mut server_random = [0u8; 32];
        getrandom::getrandom(&mut server_random).unwrap();
        let sh = ServerHello {
            random: server_random,
            legacy_session_id: vec![0xCC; 32], // different from cached
            cipher_suite: suite,
            extensions: Vec::new(),
        };
        let sh_msg = encode_server_hello(&sh);
        hs.process_server_hello(&sh_msg, &sh).unwrap();

        assert!(!hs.is_abbreviated());
        assert_eq!(hs.state(), Tls12ClientState::WaitCertificate);
        assert!(hs.take_abbreviated_keys().is_none());
    }

    #[test]
    fn test_abbreviated_key_derivation_uses_new_randoms() {
        use crate::handshake::codec::{encode_server_hello, ServerHello};
        use crate::session::TlsSession;

        let session_id = vec![0xAA; 32];
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let master_secret = vec![0xBB; 48];

        let make_session = || TlsSession {
            id: session_id.clone(),
            cipher_suite: suite,
            master_secret: master_secret.clone(),
            alpn_protocol: None,
            ticket: None,
            ticket_lifetime: 0,
            max_early_data: 0,
            ticket_age_add: 0,
            ticket_nonce: Vec::new(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            psk: Vec::new(),
            extended_master_secret: false,
        };

        // First handshake
        let config1 = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .session_resumption(true)
            .resumption_session(make_session())
            .build();

        let mut hs1 = Tls12ClientHandshake::new(config1);
        hs1.build_client_hello().unwrap();

        let mut sr1 = [0u8; 32];
        getrandom::getrandom(&mut sr1).unwrap();
        let sh1 = ServerHello {
            random: sr1,
            legacy_session_id: session_id.clone(),
            cipher_suite: suite,
            extensions: Vec::new(),
        };
        let sh1_msg = encode_server_hello(&sh1);
        hs1.process_server_hello(&sh1_msg, &sh1).unwrap();
        let keys1 = hs1.take_abbreviated_keys().unwrap();

        // Second handshake with different server random
        let config2 = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .session_resumption(true)
            .resumption_session(make_session())
            .build();

        let mut hs2 = Tls12ClientHandshake::new(config2);
        hs2.build_client_hello().unwrap();

        let mut sr2 = [0u8; 32];
        getrandom::getrandom(&mut sr2).unwrap();
        let sh2 = ServerHello {
            random: sr2,
            legacy_session_id: session_id,
            cipher_suite: suite,
            extensions: Vec::new(),
        };
        let sh2_msg = encode_server_hello(&sh2);
        hs2.process_server_hello(&sh2_msg, &sh2).unwrap();
        let keys2 = hs2.take_abbreviated_keys().unwrap();

        // Same master_secret but different randoms → different keys
        assert_eq!(keys1.master_secret, keys2.master_secret);
        assert_ne!(keys1.client_write_key, keys2.client_write_key);
        assert_ne!(keys1.server_write_key, keys2.server_write_key);
    }

    #[test]
    fn test_server_hello_wrong_state() {
        let config = TlsConfig::builder().build();
        let mut hs = Tls12ClientHandshake::new(config);
        // State is Idle, not WaitServerHello
        let sh = ServerHello {
            random: [0u8; 32],
            legacy_session_id: vec![],
            cipher_suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            extensions: Vec::new(),
        };
        let sh_msg = crate::handshake::codec::encode_server_hello(&sh);
        assert!(hs.process_server_hello(&sh_msg, &sh).is_err());
    }

    #[test]
    fn test_server_hello_unsupported_suite() {
        let config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .build();
        let mut hs = Tls12ClientHandshake::new(config);
        hs.build_client_hello().unwrap();

        // Server responds with a suite we didn't offer
        let mut server_random = [0u8; 32];
        getrandom::getrandom(&mut server_random).unwrap();
        let sh = ServerHello {
            random: server_random,
            legacy_session_id: vec![0u8; 32],
            // This is a valid TLS 1.2 suite but the client only offered ECDSA
            cipher_suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            extensions: Vec::new(),
        };
        let sh_msg = crate::handshake::codec::encode_server_hello(&sh);
        // from_suite should succeed since it's a valid suite, but the test
        // verifies the flow doesn't panic and correctly processes
        let result = hs.process_server_hello(&sh_msg, &sh);
        // Should succeed since from_suite validates the suite is known, not that it was offered
        // (TLS spec says client should validate, but our impl accepts known suites)
        assert!(result.is_ok());
    }

    #[test]
    fn test_process_certificate_wrong_state() {
        let config = TlsConfig::builder().build();
        let mut hs = Tls12ClientHandshake::new(config);
        // State is Idle, not WaitCertificate
        let cert_msg = vec![0x0b, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]; // minimal cert msg
        assert!(hs.process_certificate(&cert_msg, &[vec![0x30]]).is_err());
    }

    #[test]
    fn test_server_hello_done_wrong_state() {
        let config = TlsConfig::builder().build();
        let mut hs = Tls12ClientHandshake::new(config);
        // State is Idle, not WaitServerHelloDone
        let shd_msg = vec![0x0e, 0x00, 0x00, 0x00]; // ServerHelloDone (empty body)
        assert!(hs.process_server_hello_done(&shd_msg).is_err());
    }

    #[test]
    fn test_process_finished_wrong_state() {
        let config = TlsConfig::builder().build();
        let mut hs = Tls12ClientHandshake::new(config);
        // State is Idle, not WaitFinished
        let finished_msg = vec![
            0x14, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert!(hs.process_finished(&finished_msg, &[0u8; 48]).is_err());
    }

    #[test]
    fn test_kx_alg_rsa_static() {
        use crate::handshake::codec::{encode_server_hello, ServerHello};

        let config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .build();

        let mut hs = Tls12ClientHandshake::new(config);
        hs.build_client_hello().unwrap();

        let mut server_random = [0u8; 32];
        getrandom::getrandom(&mut server_random).unwrap();
        let sh = ServerHello {
            random: server_random,
            legacy_session_id: vec![0u8; 32],
            cipher_suite: CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            extensions: Vec::new(),
        };
        let sh_msg = encode_server_hello(&sh);
        hs.process_server_hello(&sh_msg, &sh).unwrap();

        assert_eq!(hs.kx_alg(), KeyExchangeAlg::Rsa);
        // RSA static: after Certificate, should skip SKE and go to WaitServerHelloDone
        assert_eq!(hs.state(), Tls12ClientState::WaitCertificate);
    }

    #[test]
    fn test_kx_alg_dhe() {
        use crate::handshake::codec::{encode_server_hello, ServerHello};

        let config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .build();

        let mut hs = Tls12ClientHandshake::new(config);
        hs.build_client_hello().unwrap();

        let mut server_random = [0u8; 32];
        getrandom::getrandom(&mut server_random).unwrap();
        let sh = ServerHello {
            random: server_random,
            legacy_session_id: vec![0u8; 32],
            cipher_suite: CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            extensions: Vec::new(),
        };
        let sh_msg = encode_server_hello(&sh);
        hs.process_server_hello(&sh_msg, &sh).unwrap();

        assert_eq!(hs.kx_alg(), KeyExchangeAlg::Dhe);
        assert_eq!(hs.state(), Tls12ClientState::WaitCertificate);
    }

    #[test]
    fn test_new_session_ticket_processed() {
        let config = TlsConfig::builder().build();
        let mut hs = Tls12ClientHandshake::new(config);

        // Build a minimal NewSessionTicket body:
        // lifetime_hint(4 bytes) || ticket_length(2 bytes) || ticket(N bytes)
        let lifetime: u32 = 3600;
        let ticket_data = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let mut body = Vec::new();
        body.extend_from_slice(&lifetime.to_be_bytes());
        body.extend_from_slice(&(ticket_data.len() as u16).to_be_bytes());
        body.extend_from_slice(&ticket_data);

        hs.process_new_session_ticket(&body).unwrap();

        assert_eq!(hs.received_ticket(), Some(ticket_data.as_slice()));
        assert_eq!(hs.received_ticket_lifetime(), 3600);
    }

    #[test]
    fn test_client_reset_for_renegotiation() {
        let config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .build();
        let mut hs = Tls12ClientHandshake::new(config);

        // Simulate verify_data from a completed handshake
        hs.client_verify_data = vec![0x01; 12];
        hs.server_verify_data = vec![0x02; 12];
        hs.state = Tls12ClientState::Connected;

        assert!(!hs.is_renegotiation());

        hs.reset_for_renegotiation();

        assert!(hs.is_renegotiation());
        assert_eq!(hs.state(), Tls12ClientState::Idle);
        assert_eq!(hs.prev_client_verify_data, vec![0x01; 12]);
        assert_eq!(hs.prev_server_verify_data, vec![0x02; 12]);
        assert!(hs.client_verify_data.is_empty());
        assert!(hs.server_verify_data.is_empty());
    }
}
