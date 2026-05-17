//! TLS 1.2 server handshake state machine.
//!
//! Implements the ECDHE-GCM handshake for TLS 1.2 servers.

use crate::config::{ServerPrivateKey, SniAction, TlsConfig};
use crate::crypt::key_schedule12::{
    compute_verify_data, derive_extended_master_secret, derive_key_block, derive_master_secret,
};
use crate::crypt::transcript::TranscriptHash;
use crate::crypt::{
    is_tls12_suite, HashAlgId, KeyExchangeAlg, NamedGroup, SignatureScheme, Tls12CipherSuiteParams,
};
use crate::extensions::ExtensionType;
use crate::handshake::codec::{decode_client_hello, encode_server_hello, ClientHello, ServerHello};
use crate::handshake::codec12::{
    build_dhe_ske_params, build_psk_pms, build_ske_params, build_ske_signed_data,
    decode_certificate12, decode_certificate_verify12, decode_client_key_exchange,
    decode_client_key_exchange_dhe, decode_client_key_exchange_dhe_psk,
    decode_client_key_exchange_ecdhe_psk, decode_client_key_exchange_psk,
    decode_client_key_exchange_rsa, decode_client_key_exchange_rsa_psk, encode_certificate12,
    encode_certificate_request12, encode_finished12, encode_new_session_ticket12,
    encode_server_hello_done, encode_server_key_exchange, encode_server_key_exchange_dhe,
    encode_server_key_exchange_dhe_anon, encode_server_key_exchange_dhe_psk,
    encode_server_key_exchange_ecdhe_anon, encode_server_key_exchange_ecdhe_psk,
    encode_server_key_exchange_psk_hint, Certificate12, CertificateRequest12, ServerKeyExchange,
    ServerKeyExchangeDhe, ServerKeyExchangeDheAnon, ServerKeyExchangeDhePsk,
    ServerKeyExchangeEcdheAnon, ServerKeyExchangeEcdhePsk, ServerKeyExchangePskHint,
};
use crate::handshake::extensions_codec::{
    build_ec_point_formats, build_encrypt_then_mac, build_extended_master_secret,
    build_max_fragment_length, build_record_size_limit, build_renegotiation_info,
    build_renegotiation_info_initial, build_session_ticket_sh, parse_alpn_ch,
    parse_ec_point_formats, parse_encrypt_then_mac, parse_extended_master_secret,
    parse_max_fragment_length, parse_record_size_limit, parse_renegotiation_info,
    parse_server_name, parse_session_ticket_ch, parse_signature_algorithms_ch,
    parse_supported_groups_ch,
};
use crate::handshake::key_exchange::KeyExchange;
use crate::session::{decrypt_session_ticket, encrypt_session_ticket, SessionCache, TlsSession};
use crate::{CipherSuite, TlsVersion};
use hitls_crypto::dh::{DhKeyPair, DhParams};
use hitls_crypto::rsa::{RsaPadding, RsaPrivateKey as CryptoRsaPrivateKey};
use hitls_types::{DhParamId, EccCurveId, TlsError};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// TLS 1.2 server handshake states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls12ServerState {
    Idle,
    WaitClientCertificate,
    WaitClientKeyExchange,
    WaitClientCertificateVerify,
    WaitChangeCipherSpec,
    WaitFinished,
    Connected,
}

/// Server flight result after processing ClientHello.
#[derive(Debug)]
pub struct ServerFlightResult {
    /// ServerHello handshake message.
    pub server_hello: Vec<u8>,
    /// Certificate handshake message (None for PSK suites without certificates).
    pub certificate: Option<Vec<u8>>,
    /// CertificateStatus message (RFC 6066, OCSP stapling — None if not requested or no staple).
    pub certificate_status: Option<Vec<u8>>,
    /// ServerKeyExchange handshake message (None for RSA static key exchange).
    pub server_key_exchange: Option<Vec<u8>>,
    /// CertificateRequest message (only if mTLS is enabled).
    pub certificate_request: Option<Vec<u8>>,
    /// ServerHelloDone handshake message.
    pub server_hello_done: Vec<u8>,
    /// Negotiated cipher suite.
    pub suite: CipherSuite,
    /// Server-assigned session ID for session caching.
    pub session_id: Vec<u8>,
}

/// Result from abbreviated handshake (session resumption).
pub struct AbbreviatedServerResult {
    /// ServerHello handshake message.
    pub server_hello: Vec<u8>,
    /// Optional NewSessionTicket message (RFC 5077). When `Some`, the server
    /// must send this **before** ChangeCipherSpec and the server Finished —
    /// the message has already been folded into the handshake transcript.
    pub new_session_ticket: Option<Vec<u8>>,
    /// Server Finished message (to be sent after CCS, before reading client flight).
    pub finished: Vec<u8>,
    /// Negotiated cipher suite.
    pub suite: CipherSuite,
    /// Session ID (echoed from client's cached session).
    pub session_id: Vec<u8>,
    /// Master secret (48 bytes, from cached session).
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

impl Drop for AbbreviatedServerResult {
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

/// Result of processing ClientHello — either full or abbreviated handshake.
pub enum ServerHelloResult {
    /// Full handshake (Certificate + SKE + SHD etc.)
    Full(ServerFlightResult),
    /// Abbreviated handshake (session resumption).
    Abbreviated(AbbreviatedServerResult),
}

/// Keys derived after client key exchange.
pub struct Tls12DerivedKeys {
    /// Master secret (48 bytes).
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

impl Drop for Tls12DerivedKeys {
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

/// Server finished result.
pub struct ServerFinishedResult {
    /// Optional NewSessionTicket message (RFC 5077). When `Some`, the server
    /// must send this **before** ChangeCipherSpec and the server Finished —
    /// the message has already been folded into the handshake transcript.
    pub new_session_ticket: Option<Vec<u8>>,
    /// Server Finished message.
    pub finished: Vec<u8>,
}

/// TLS 1.2 server handshake state machine.
pub struct Tls12ServerHandshake {
    config: TlsConfig,
    state: Tls12ServerState,
    params: Option<Tls12CipherSuiteParams>,
    transcript: TranscriptHash,
    client_random: [u8; 32],
    server_random: [u8; 32],
    ephemeral_key: Option<KeyExchange>,
    kx_alg: KeyExchangeAlg,
    dhe_params: Option<DhParams>,
    dhe_key_pair: Option<DhKeyPair>,
    master_secret: Vec<u8>,
    client_sig_algs: Vec<SignatureScheme>,
    /// Negotiated ALPN protocol (if any).
    negotiated_alpn: Option<Vec<u8>>,
    /// Client SNI hostname (if sent).
    client_server_name: Option<String>,
    /// Client certificates (DER-encoded, leaf first) for mTLS.
    client_certs: Vec<Vec<u8>>,
    /// Server-assigned session ID.
    session_id: Vec<u8>,
    /// Whether this is an abbreviated (resumed) handshake.
    abbreviated: bool,
    /// Negotiated Extended Master Secret (RFC 7627).
    use_extended_master_secret: bool,
    /// Negotiated Encrypt-Then-MAC (RFC 7366, CBC suites only).
    use_encrypt_then_mac: bool,
    /// Stored client verify_data after receiving Finished.
    client_verify_data: Vec<u8>,
    /// Stored server verify_data after sending Finished.
    server_verify_data: Vec<u8>,
    /// Whether the client offered EMS in ClientHello.
    client_offered_ems: bool,
    /// Whether the client offered ETM in ClientHello.
    client_offered_etm: bool,
    /// Whether the client offered `ec_point_formats` in ClientHello
    /// (RFC 4492 §5.1.2 / RFC 8422 §5.1.2 — echoed in ServerHello when
    /// an ECC cipher suite is negotiated).
    client_offered_ec_point_formats: bool,
    /// Client's record size limit from ClientHello (RFC 8449).
    client_record_size_limit: Option<u16>,
    /// Whether the client sent the status_request extension (OCSP stapling).
    client_wants_ocsp: bool,
    /// Whether the client sent the signed_certificate_timestamp extension.
    client_wants_sct: bool,
    /// Whether this is a renegotiation handshake.
    is_renegotiation: bool,
    /// Previous client verify_data (saved from prior handshake for renegotiation).
    prev_client_verify_data: Vec<u8>,
    /// Previous server verify_data (saved from prior handshake for renegotiation).
    prev_server_verify_data: Vec<u8>,
    /// Client-offered max fragment length (RFC 6066).
    client_max_fragment_length: Option<crate::config::MaxFragmentLength>,
}

impl Drop for Tls12ServerHandshake {
    fn drop(&mut self) {
        self.master_secret.zeroize();
    }
}

impl Tls12ServerHandshake {
    pub fn new(config: TlsConfig) -> Self {
        Self {
            config,
            state: Tls12ServerState::Idle,
            params: None,
            transcript: TranscriptHash::new(HashAlgId::Sha256),
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            ephemeral_key: None,
            kx_alg: KeyExchangeAlg::Ecdhe,
            dhe_params: None,
            dhe_key_pair: None,
            master_secret: Vec::new(),
            client_sig_algs: Vec::new(),
            negotiated_alpn: None,
            client_server_name: None,
            client_certs: Vec::new(),
            session_id: Vec::new(),
            abbreviated: false,
            use_extended_master_secret: false,
            use_encrypt_then_mac: false,
            client_verify_data: Vec::new(),
            server_verify_data: Vec::new(),
            client_offered_ems: false,
            client_offered_etm: false,
            client_offered_ec_point_formats: false,
            client_record_size_limit: None,
            client_wants_ocsp: false,
            client_wants_sct: false,
            is_renegotiation: false,
            prev_client_verify_data: Vec::new(),
            prev_server_verify_data: Vec::new(),
            client_max_fragment_length: None,
        }
    }

    pub fn state(&self) -> Tls12ServerState {
        self.state
    }

    /// Get the negotiated key exchange algorithm.
    pub fn kx_alg(&self) -> KeyExchangeAlg {
        self.kx_alg
    }

    /// Get the negotiated ALPN protocol (if any).
    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
    }

    /// Get the client's SNI hostname (if sent).
    pub fn client_server_name(&self) -> Option<&str> {
        self.client_server_name.as_deref()
    }

    /// Get the server-assigned session ID.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Get a reference to the master secret (for session caching after handshake).
    pub fn master_secret_ref(&self) -> &[u8] {
        &self.master_secret
    }

    /// The client random value (for key export).
    pub fn client_random(&self) -> &[u8; 32] {
        &self.client_random
    }

    /// The server random value (for key export).
    pub fn server_random(&self) -> &[u8; 32] {
        &self.server_random
    }

    /// Whether this handshake used abbreviated (session resumption) mode.
    pub fn is_abbreviated(&self) -> bool {
        self.abbreviated
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

    /// Client's record size limit from ClientHello (RFC 8449).
    pub fn client_record_size_limit(&self) -> Option<u16> {
        self.client_record_size_limit
    }

    /// Client-offered max fragment length from ClientHello (RFC 6066).
    pub fn client_max_fragment_length(&self) -> Option<crate::config::MaxFragmentLength> {
        self.client_max_fragment_length
    }

    /// Whether this is a renegotiation handshake.
    pub fn is_renegotiation(&self) -> bool {
        self.is_renegotiation
    }

    /// Get the client's certificate chain (DER-encoded, leaf first) for mTLS.
    pub fn client_certs(&self) -> &[Vec<u8>] {
        &self.client_certs
    }

    /// Reset handshake state for renegotiation (RFC 5746).
    ///
    /// Saves the current verify_data from both sides, resets all handshake
    /// state to Idle, and marks this as a renegotiation handshake.
    pub fn reset_for_renegotiation(&mut self) {
        self.prev_client_verify_data = std::mem::take(&mut self.client_verify_data);
        self.prev_server_verify_data = std::mem::take(&mut self.server_verify_data);
        self.state = Tls12ServerState::Idle;
        self.params = None;
        self.transcript = TranscriptHash::new(HashAlgId::Sha256);
        self.client_random = [0u8; 32];
        self.server_random = [0u8; 32];
        self.ephemeral_key = None;
        self.kx_alg = KeyExchangeAlg::Ecdhe;
        self.dhe_params = None;
        self.dhe_key_pair = None;
        self.master_secret.zeroize();
        self.master_secret.clear();
        self.client_sig_algs.clear();
        self.negotiated_alpn = None;
        self.client_server_name = None;
        self.client_certs.clear();
        self.session_id.clear();
        self.abbreviated = false;
        self.use_extended_master_secret = false;
        self.use_encrypt_then_mac = false;
        self.client_offered_ems = false;
        self.client_offered_etm = false;
        self.client_offered_ec_point_formats = false;
        self.client_record_size_limit = None;
        self.client_wants_ocsp = false;
        self.client_wants_sct = false;
        self.client_max_fragment_length = None;
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

    /// Build a HelloRequest message (RFC 5246 §7.4.1.1).
    pub fn build_hello_request() -> Vec<u8> {
        crate::handshake::codec::encode_hello_request()
    }

    /// Build an encrypted NewSessionTicket message and fold it into the
    /// handshake transcript (RFC 5077 §3.5: NST is hashed into the transcript
    /// used to compute server Finished).
    ///
    /// Returns the wrapped handshake message, or `None` if `ticket_key` is
    /// not configured. Call this **before** computing server Finished.
    fn build_and_record_new_session_ticket(
        &mut self,
        suite: CipherSuite,
        master_secret: &[u8],
        use_ems: bool,
        lifetime: u32,
    ) -> Result<Option<Vec<u8>>, TlsError> {
        let Some(ticket_key) = self.config.ticket_key.as_ref() else {
            return Ok(None);
        };
        if master_secret.is_empty() {
            return Err(TlsError::HandshakeFailed(
                "master_secret not available for ticket".into(),
            ));
        }
        let session = TlsSession {
            id: Vec::new(),
            cipher_suite: suite,
            master_secret: master_secret.to_vec(),
            alpn_protocol: self.negotiated_alpn.clone(),
            ticket: None,
            ticket_lifetime: lifetime,
            max_early_data: 0,
            ticket_age_add: 0,
            ticket_nonce: Vec::new(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            psk: Vec::new(),
            extended_master_secret: use_ems,
        };
        let ticket = encrypt_session_ticket(ticket_key, &session)?;
        let msg = encode_new_session_ticket12(lifetime, &ticket);
        self.transcript.update(&msg)?;
        Ok(Some(msg))
    }

    /// Process ClientHello and build the full server flight.
    ///
    /// `msg_data` is the full handshake message including the 4-byte header.
    /// Returns ServerHello + Certificate + ServerKeyExchange + ServerHelloDone.
    pub fn process_client_hello(
        &mut self,
        msg_data: &[u8],
    ) -> Result<ServerFlightResult, TlsError> {
        if self.state != Tls12ServerState::Idle {
            return Err(TlsError::HandshakeFailed("unexpected ClientHello".into()));
        }

        // Parse ClientHello (skip 4-byte handshake header)
        let body = get_body(msg_data)?;
        let ch = decode_client_hello(body)?;
        self.client_random = ch.random;

        // Parse extensions
        let mut client_groups = Vec::new();
        let mut client_alpn_protocols = Vec::new();
        for ext in &ch.extensions {
            match ext.extension_type {
                ExtensionType::SIGNATURE_ALGORITHMS => {
                    self.client_sig_algs = parse_signature_algorithms_ch(&ext.data)?;
                }
                ExtensionType::SUPPORTED_GROUPS => {
                    client_groups = parse_supported_groups_ch(&ext.data)?;
                }
                ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
                    client_alpn_protocols = parse_alpn_ch(&ext.data)?;
                }
                ExtensionType::SERVER_NAME => {
                    self.client_server_name = Some(parse_server_name(&ext.data)?);
                }
                ExtensionType::EXTENDED_MASTER_SECRET => {
                    parse_extended_master_secret(&ext.data)?;
                    self.client_offered_ems = true;
                }
                ExtensionType::ENCRYPT_THEN_MAC => {
                    parse_encrypt_then_mac(&ext.data)?;
                    self.client_offered_etm = true;
                }
                ExtensionType::EC_POINT_FORMATS => {
                    // RFC 8422 §5.1.2 — validate the list (it MUST
                    // contain `uncompressed`); we only need the
                    // offered/not-offered flag for the ServerHello echo.
                    parse_ec_point_formats(&ext.data)?;
                    self.client_offered_ec_point_formats = true;
                }
                ExtensionType::RENEGOTIATION_INFO => {
                    let ri_data = parse_renegotiation_info(&ext.data)?;
                    if self.is_renegotiation {
                        // RFC 5746 §3.7: client must send client_verify_data
                        if ri_data.ct_eq(&self.prev_client_verify_data).unwrap_u8() != 1 {
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
                    self.client_record_size_limit = Some(parse_record_size_limit(&ext.data)?);
                }
                ExtensionType::STATUS_REQUEST => {
                    self.client_wants_ocsp = true;
                }
                ExtensionType::SIGNED_CERTIFICATE_TIMESTAMP => {
                    self.client_wants_sct = true;
                }
                ExtensionType::MAX_FRAGMENT_LENGTH => {
                    self.client_max_fragment_length = Some(parse_max_fragment_length(&ext.data)?);
                }
                _ => {} // ignore other extensions
            }
        }

        // Parse custom extensions from ClientHello
        crate::extensions::parse_custom_extensions(
            &self.config.custom_extensions,
            crate::extensions::ExtensionContext::CLIENT_HELLO,
            &ch.extensions,
        )?;

        // SNI callback (server-side hostname-based config selection)
        if let (Some(ref sni_cb), Some(ref hostname)) =
            (&self.config.sni_callback, &self.client_server_name)
        {
            match sni_cb(hostname) {
                SniAction::Accept => {}
                SniAction::AcceptWithConfig(new_config) => {
                    self.config = *new_config;
                }
                SniAction::Reject => {
                    return Err(TlsError::HandshakeFailed("unrecognized_name".into()));
                }
                SniAction::Ignore => {
                    self.client_server_name = None;
                }
            }
        }

        // ClientHello callback (server-side observation/processing)
        if let Some(ref ch_cb) = self.config.client_hello_callback {
            let info = crate::config::ClientHelloInfo {
                cipher_suites: ch.cipher_suites.iter().map(|cs| cs.0).collect(),
                supported_versions: vec![0x0303], // TLS 1.2
                server_name: self.client_server_name.clone(),
                alpn_protocols: client_alpn_protocols.clone(),
            };
            match ch_cb(&info) {
                crate::config::ClientHelloAction::Success => {}
                crate::config::ClientHelloAction::Retry => {
                    return Err(TlsError::HandshakeFailed(
                        "client_hello_callback: retry requested".into(),
                    ));
                }
                crate::config::ClientHelloAction::Failed(alert) => {
                    return Err(TlsError::HandshakeFailed(format!(
                        "client_hello_callback: rejected (alert {})",
                        alert
                    )));
                }
            }
        }

        // Fallback SCSV (RFC 7507) detection
        if ch.cipher_suites.contains(&CipherSuite::TLS_FALLBACK_SCSV) {
            // If server supports a higher version than TLS 1.2, reject
            if self.config.max_version == TlsVersion::Tls13 {
                return Err(TlsError::HandshakeFailed(
                    "inappropriate fallback: server supports higher version".into(),
                ));
            }
        }

        // Negotiate ALPN
        if !client_alpn_protocols.is_empty() && !self.config.alpn_protocols.is_empty() {
            for server_proto in &self.config.alpn_protocols {
                if client_alpn_protocols.contains(server_proto) {
                    self.negotiated_alpn = Some(server_proto.clone());
                    break;
                }
            }
        }

        // Negotiate cipher suite
        let suite = negotiate_cipher_suite(&ch, &self.config)?;
        let params = Tls12CipherSuiteParams::from_suite(suite)?;

        // Switch transcript hash if needed
        if params.hash_len == 48 {
            self.transcript = TranscriptHash::new(HashAlgId::Sha384);
        }

        // Add full ClientHello (including header) to transcript
        self.transcript.update(msg_data)?;

        // Generate server random
        getrandom::fill(&mut self.server_random)
            .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;

        // Generate server-assigned session_id (32 bytes) for session caching
        let mut session_id = vec![0u8; 32];
        getrandom::fill(&mut session_id)
            .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;
        self.session_id = session_id;

        // Store key exchange algorithm
        self.kx_alg = params.kx_alg;

        // Negotiate EMS based on three-state policy (RFC 7627):
        // - Forbid: never echo, even if client offered
        // - Prefer: echo iff client offered (default)
        // - Force:  reject the handshake if the client did not offer
        match self.config.ems_mode {
            crate::config::EmsMode::Forbid => {}
            crate::config::EmsMode::Prefer => {
                if self.client_offered_ems {
                    self.use_extended_master_secret = true;
                }
            }
            crate::config::EmsMode::Force => {
                if !self.client_offered_ems {
                    return Err(TlsError::HandshakeFailed(
                        "EMS required by EmsMode::Force but client did not advertise it".into(),
                    ));
                }
                self.use_extended_master_secret = true;
            }
        }

        // Negotiate ETM: echo if client offered, config enables, AND suite is CBC
        if self.client_offered_etm && self.config.enable_encrypt_then_mac && params.is_cbc {
            self.use_encrypt_then_mac = true;
        }

        // Build ServerHello extensions
        let mut sh_extensions = Vec::new();
        // Renegotiation info (RFC 5746): always include in ServerHello
        if self.is_renegotiation {
            sh_extensions.push(build_renegotiation_info(
                &self.prev_client_verify_data,
                &self.prev_server_verify_data,
            ));
        } else {
            sh_extensions.push(build_renegotiation_info_initial());
        }
        if let Some(ref alpn) = self.negotiated_alpn {
            sh_extensions.push(crate::handshake::extensions_codec::build_alpn_selected(
                alpn,
            ));
        }
        // Signal session ticket support if ticket_key is configured
        if self.config.ticket_key.is_some() {
            sh_extensions.push(build_session_ticket_sh());
        }
        // Echo EMS extension
        if self.use_extended_master_secret {
            sh_extensions.push(build_extended_master_secret());
        }
        // Echo ETM extension
        if self.use_encrypt_then_mac {
            sh_extensions.push(build_encrypt_then_mac());
        }
        // Echo ec_point_formats (RFC 8422 §5.1.2): when the client
        // offered it and an ECC (ECDHE) cipher suite is negotiated, the
        // ServerHello carries `ec_point_formats` listing `uncompressed`.
        // tlsfuzzer's ECC scripts (`ExpectServerHello` with
        // `ec_point_formats`) require this; omitting it aborts the
        // handshake at the client.
        if self.client_offered_ec_point_formats
            && matches!(
                params.kx_alg,
                KeyExchangeAlg::Ecdhe | KeyExchangeAlg::EcdhePsk | KeyExchangeAlg::EcdheAnon
            )
        {
            sh_extensions.push(build_ec_point_formats());
        }
        // Echo Record Size Limit (RFC 8449) if client offered and config enables it
        if self.client_record_size_limit.is_some() && self.config.record_size_limit > 0 {
            sh_extensions.push(build_record_size_limit(
                self.config.record_size_limit.min(16384),
            ));
        }
        // Echo Max Fragment Length (RFC 6066) if client offered
        if let Some(mfl) = self.client_max_fragment_length {
            sh_extensions.push(build_max_fragment_length(mfl));
        }

        // Custom extensions for ServerHello
        sh_extensions.extend(crate::extensions::build_custom_extensions(
            &self.config.custom_extensions,
            crate::extensions::ExtensionContext::SERVER_HELLO,
        ));

        // Build ServerHello
        let sh = ServerHello {
            random: self.server_random,
            legacy_session_id: self.session_id.clone(),
            cipher_suite: suite,
            extensions: sh_extensions,
        };
        let sh_msg = encode_server_hello(&sh);
        self.transcript.update(&sh_msg)?;

        // Build Certificate (only for non-PSK key exchanges that require certificates)
        let cert_msg = if params.kx_alg.requires_certificate() {
            let cert12 = Certificate12 {
                certificate_list: self.config.certificate_chain.clone(),
            };
            let msg = encode_certificate12(&cert12);
            self.transcript.update(&msg)?;
            Some(msg)
        } else {
            None
        };

        // Build CertificateStatus (RFC 6066 — OCSP stapling)
        let cert_status_msg = if self.client_wants_ocsp {
            if let Some(ref ocsp_response) = self.config.ocsp_staple {
                let msg = crate::handshake::codec12::encode_certificate_status12(ocsp_response);
                self.transcript.update(&msg)?;
                Some(msg)
            } else {
                None
            }
        } else {
            None
        };

        // Build ServerKeyExchange (depends on key exchange algorithm)
        let ske_msg_opt = match params.kx_alg {
            KeyExchangeAlg::Rsa => {
                // RSA static key exchange: no ServerKeyExchange message
                None
            }
            KeyExchangeAlg::Dhe => {
                // DHE key exchange: negotiate FFDHE group, generate DH key pair
                let group = negotiate_ffdhe_group(&client_groups, &self.config.supported_groups)?;
                let dh_param_id = named_group_to_dh_param_id(group)?;
                let dh_params = DhParams::from_group(dh_param_id).map_err(TlsError::CryptoError)?;
                let dh_kp = DhKeyPair::generate(&dh_params).map_err(TlsError::CryptoError)?;
                let dh_ys = dh_kp
                    .public_key_bytes(&dh_params)
                    .map_err(TlsError::CryptoError)?;
                let dh_p = dh_params.p_bytes();
                let dh_g = dh_params.g_bytes();

                let ske_params = build_dhe_ske_params(&dh_p, &dh_g, &dh_ys);
                let signed_data =
                    build_ske_signed_data(&self.client_random, &self.server_random, &ske_params);

                let private_key = self.config.private_key.as_ref().ok_or_else(|| {
                    TlsError::HandshakeFailed("no server private key configured".into())
                })?;
                let sig_scheme = select_signature_scheme_tls12(private_key, &self.client_sig_algs)?;
                let signature = sign_ske_data(private_key, sig_scheme, &signed_data)?;

                let ske = ServerKeyExchangeDhe {
                    dh_p,
                    dh_g,
                    dh_ys,
                    signature_algorithm: sig_scheme,
                    signature,
                };
                let ske_msg = encode_server_key_exchange_dhe(&ske);
                self.transcript.update(&ske_msg)?;

                self.dhe_params = Some(dh_params);
                self.dhe_key_pair = Some(dh_kp);

                Some(ske_msg)
            }
            KeyExchangeAlg::Ecdhe => {
                // ECDHE key exchange: negotiate EC group, generate ephemeral key
                let group = negotiate_group(&client_groups, &self.config.supported_groups)?;
                let kx = KeyExchange::generate(group)?;
                let server_public = kx.public_key_bytes().to_vec();

                let named_curve = group.0;
                let ske_params = build_ske_params(3, named_curve, &server_public);
                let signed_data =
                    build_ske_signed_data(&self.client_random, &self.server_random, &ske_params);

                let private_key = self.config.private_key.as_ref().ok_or_else(|| {
                    TlsError::HandshakeFailed("no server private key configured".into())
                })?;
                let sig_scheme = select_signature_scheme_tls12(private_key, &self.client_sig_algs)?;
                let signature = sign_ske_data(private_key, sig_scheme, &signed_data)?;

                let ske = ServerKeyExchange {
                    curve_type: 3,
                    named_curve,
                    public_key: server_public,
                    signature_algorithm: sig_scheme,
                    signature,
                };
                let ske_msg = encode_server_key_exchange(&ske);
                self.transcript.update(&ske_msg)?;

                self.ephemeral_key = Some(kx);

                Some(ske_msg)
            }
            KeyExchangeAlg::Psk | KeyExchangeAlg::RsaPsk => {
                // Optional: send hint-only SKE if hint is configured
                if let Some(ref hint) = self.config.psk_identity_hint {
                    let ske = ServerKeyExchangePskHint { hint: hint.clone() };
                    let ske_msg = encode_server_key_exchange_psk_hint(&ske);
                    self.transcript.update(&ske_msg)?;
                    Some(ske_msg)
                } else {
                    None
                }
            }
            KeyExchangeAlg::DhePsk => {
                let group = negotiate_ffdhe_group(&client_groups, &self.config.supported_groups)?;
                let dh_param_id = named_group_to_dh_param_id(group)?;
                let dh_params = DhParams::from_group(dh_param_id).map_err(TlsError::CryptoError)?;
                let dh_kp = DhKeyPair::generate(&dh_params).map_err(TlsError::CryptoError)?;
                let dh_ys = dh_kp
                    .public_key_bytes(&dh_params)
                    .map_err(TlsError::CryptoError)?;
                let hint = self.config.psk_identity_hint.clone().unwrap_or_default();
                let ske = ServerKeyExchangeDhePsk {
                    hint,
                    dh_p: dh_params.p_bytes(),
                    dh_g: dh_params.g_bytes(),
                    dh_ys,
                };
                let ske_msg = encode_server_key_exchange_dhe_psk(&ske);
                self.transcript.update(&ske_msg)?;
                self.dhe_params = Some(dh_params);
                self.dhe_key_pair = Some(dh_kp);
                Some(ske_msg)
            }
            KeyExchangeAlg::EcdhePsk => {
                let group = negotiate_group(&client_groups, &self.config.supported_groups)?;
                let kx = KeyExchange::generate(group)?;
                let hint = self.config.psk_identity_hint.clone().unwrap_or_default();
                let ske = ServerKeyExchangeEcdhePsk {
                    hint,
                    named_curve: group.0,
                    public_key: kx.public_key_bytes().to_vec(),
                };
                let ske_msg = encode_server_key_exchange_ecdhe_psk(&ske);
                self.transcript.update(&ske_msg)?;
                self.ephemeral_key = Some(kx);
                Some(ske_msg)
            }
            KeyExchangeAlg::DheAnon => {
                let group = negotiate_ffdhe_group(&client_groups, &self.config.supported_groups)?;
                let dh_param_id = named_group_to_dh_param_id(group)?;
                let dh_params = DhParams::from_group(dh_param_id).map_err(TlsError::CryptoError)?;
                let dh_kp = DhKeyPair::generate(&dh_params).map_err(TlsError::CryptoError)?;
                let dh_ys = dh_kp
                    .public_key_bytes(&dh_params)
                    .map_err(TlsError::CryptoError)?;
                let ske = ServerKeyExchangeDheAnon {
                    dh_p: dh_params.p_bytes(),
                    dh_g: dh_params.g_bytes(),
                    dh_ys,
                };
                let ske_msg = encode_server_key_exchange_dhe_anon(&ske);
                self.transcript.update(&ske_msg)?;
                self.dhe_params = Some(dh_params);
                self.dhe_key_pair = Some(dh_kp);
                Some(ske_msg)
            }
            KeyExchangeAlg::EcdheAnon => {
                let group = negotiate_group(&client_groups, &self.config.supported_groups)?;
                let kx = KeyExchange::generate(group)?;
                let ske = ServerKeyExchangeEcdheAnon {
                    named_curve: group.0,
                    public_key: kx.public_key_bytes().to_vec(),
                };
                let ske_msg = encode_server_key_exchange_ecdhe_anon(&ske);
                self.transcript.update(&ske_msg)?;
                self.ephemeral_key = Some(kx);
                Some(ske_msg)
            }
            #[cfg(feature = "tlcp")]
            KeyExchangeAlg::Ecc => {
                return Err(TlsError::HandshakeFailed(
                    "ECC static key exchange not supported in TLS 1.2 server".into(),
                ));
            }
        };

        // Build CertificateRequest (if mTLS is enabled and KX requires certificates)
        let certificate_request =
            if self.config.verify_client_cert && params.kx_alg.requires_certificate() {
                // Phase T118 — advertise the comprehensive 18-item set of
                // signature schemes our TLS 1.2 server can accept for
                // client authentication (RFC 5246 §7.4.4 — `supported_
                // signature_algorithms`). Mirrors the T102 TLS 1.3 CR
                // list exactly: Edwards → ECDSA strong→weak → RSA-PSS
                // strong→weak → RSA-PKCS#1 strong→weak. This matches
                // tlsfuzzer's `test-certificate-request.py` 18-item
                // `sigalgs` expectation (closes the last mTLS-12 XFAIL
                // `check sigalgs in cert request`).
                //
                // We INTENTIONALLY include `rsa_pkcs1_*` (legacy) and
                // SHA-1 / SHA-224 codepoints even though CV-side
                // refusal still applies — the CR sigalgs extension
                // legitimately gates both the CV signature scheme AND
                // the cert-chain signature scheme; PKCS#1 / SHA-1 /
                // SHA-224 remain valid for cert-chain signatures.
                //
                // We do NOT use `self.config.signature_algorithms` here
                // because that field is the CLIENT-side offer-list
                // (what we'll sign with as a client); the SERVER's CR
                // list is what we'll ACCEPT from the client and is
                // intentionally broader.
                let cr_sig_algs = vec![
                    SignatureScheme::ED25519,
                    SignatureScheme::ED448,
                    SignatureScheme::ECDSA_SECP521R1_SHA512,
                    SignatureScheme::ECDSA_SECP384R1_SHA384,
                    SignatureScheme::ECDSA_SECP256R1_SHA256,
                    SignatureScheme::ECDSA_SHA224,
                    SignatureScheme::ECDSA_SHA1,
                    SignatureScheme::RSA_PSS_RSAE_SHA512,
                    SignatureScheme::RSA_PSS_PSS_SHA512,
                    SignatureScheme::RSA_PSS_RSAE_SHA384,
                    SignatureScheme::RSA_PSS_PSS_SHA384,
                    SignatureScheme::RSA_PSS_RSAE_SHA256,
                    SignatureScheme::RSA_PSS_PSS_SHA256,
                    SignatureScheme::RSA_PKCS1_SHA512,
                    SignatureScheme::RSA_PKCS1_SHA384,
                    SignatureScheme::RSA_PKCS1_SHA256,
                    SignatureScheme::RSA_PKCS1_SHA224,
                    SignatureScheme::RSA_PKCS1_SHA1,
                ];
                let cr = CertificateRequest12 {
                    cert_types: vec![1, 64], // rsa_sign, ecdsa_sign
                    sig_hash_algs: cr_sig_algs,
                    ca_names: vec![],
                };
                let cr_msg = encode_certificate_request12(&cr);
                self.transcript.update(&cr_msg)?;
                Some(cr_msg)
            } else {
                None
            };

        // Build ServerHelloDone
        let shd_msg = encode_server_hello_done();
        self.transcript.update(&shd_msg)?;

        self.params = Some(params);
        self.state = if self.config.verify_client_cert && certificate_request.is_some() {
            Tls12ServerState::WaitClientCertificate
        } else {
            Tls12ServerState::WaitClientKeyExchange
        };

        Ok(ServerFlightResult {
            server_hello: sh_msg,
            certificate: cert_msg,
            certificate_status: cert_status_msg,
            server_key_exchange: ske_msg_opt,
            certificate_request,
            server_hello_done: shd_msg,
            suite,
            session_id: self.session_id.clone(),
        })
    }

    /// Process ClientHello with optional session cache lookup and ticket support.
    ///
    /// Priority: (1) session ticket resumption, (2) session ID cache, (3) full handshake.
    pub fn process_client_hello_resumable(
        &mut self,
        msg_data: &[u8],
        session_cache: Option<&dyn SessionCache>,
    ) -> Result<ServerHelloResult, TlsError> {
        if self.state != Tls12ServerState::Idle {
            return Err(TlsError::HandshakeFailed("unexpected ClientHello".into()));
        }

        // Parse ClientHello to check session_id and extensions
        let body = get_body(msg_data)?;
        let ch = decode_client_hello(body)?;

        // Check for EMS extension in CH (needed for resumption compatibility checks)
        let client_has_ems = ch
            .extensions
            .iter()
            .any(|ext| ext.extension_type == ExtensionType::EXTENDED_MASTER_SECRET);

        // (1) Try session ticket resumption
        if let Some(ref ticket_key) = self.config.ticket_key {
            for ext in &ch.extensions {
                if ext.extension_type == ExtensionType::SESSION_TICKET {
                    let ticket_data = parse_session_ticket_ch(&ext.data)?;
                    if !ticket_data.is_empty() {
                        if let Some(session) = decrypt_session_ticket(ticket_key, &ticket_data) {
                            // EMS resumption check (RFC 7627 §5.3):
                            // session EMS flag must match client's EMS offer
                            if session.extended_master_secret == client_has_ems
                                && ch.cipher_suites.contains(&session.cipher_suite)
                                && self.config.cipher_suites.contains(&session.cipher_suite)
                                && is_tls12_suite(session.cipher_suite)
                            {
                                let cached_suite = session.cipher_suite;
                                let cached_ms = session.master_secret.clone();
                                let cached_ems = session.extended_master_secret;
                                // Use the client's session_id so client detects abbreviation
                                let sid = ch.legacy_session_id.clone();

                                return self
                                    .do_abbreviated(
                                        msg_data,
                                        &ch,
                                        cached_suite,
                                        &cached_ms,
                                        sid,
                                        cached_ems,
                                    )
                                    .map(ServerHelloResult::Abbreviated);
                            }
                        }
                    }
                    break;
                }
            }
        }

        // (2) Try session ID cache resumption
        if let Some(cache) = session_cache {
            if !ch.legacy_session_id.is_empty() {
                if let Some(session) = cache.get(&ch.legacy_session_id) {
                    // EMS resumption check (RFC 7627 §5.3):
                    // session EMS flag must match client's EMS offer
                    if session.extended_master_secret == client_has_ems
                        && ch.cipher_suites.contains(&session.cipher_suite)
                        && self.config.cipher_suites.contains(&session.cipher_suite)
                        && is_tls12_suite(session.cipher_suite)
                    {
                        let cached_suite = session.cipher_suite;
                        let cached_ms = session.master_secret.clone();
                        let cached_ems = session.extended_master_secret;
                        let sid = ch.legacy_session_id.clone();

                        return self
                            .do_abbreviated(
                                msg_data,
                                &ch,
                                cached_suite,
                                &cached_ms,
                                sid,
                                cached_ems,
                            )
                            .map(ServerHelloResult::Abbreviated);
                    }
                }
            }
        }

        // (3) Fall back to full handshake
        self.process_client_hello(msg_data)
            .map(ServerHelloResult::Full)
    }

    /// Perform abbreviated handshake (session resumption).
    ///
    /// Builds ServerHello + server Finished, derives keys from cached master_secret
    /// with new randoms. Server sends CCS + Finished FIRST (before client).
    fn do_abbreviated(
        &mut self,
        msg_data: &[u8],
        ch: &ClientHello,
        suite: CipherSuite,
        cached_master_secret: &[u8],
        session_id: Vec<u8>,
        cached_ems: bool,
    ) -> Result<AbbreviatedServerResult, TlsError> {
        let params = Tls12CipherSuiteParams::from_suite(suite)?;

        // Set EMS flag from cached session for abbreviated handshake
        self.use_extended_master_secret = cached_ems;

        // Check if client offered ETM and suite is CBC
        let mut client_offered_etm_here = false;
        for ext in &ch.extensions {
            if ext.extension_type == ExtensionType::ENCRYPT_THEN_MAC {
                client_offered_etm_here = true;
                break;
            }
        }
        if client_offered_etm_here && self.config.enable_encrypt_then_mac && params.is_cbc {
            self.use_encrypt_then_mac = true;
        }

        // Switch transcript hash if the resumed suite uses SHA-384
        if params.hash_len == 48 {
            self.transcript = TranscriptHash::new(HashAlgId::Sha384);
        }

        self.client_random = ch.random;

        // Generate server random
        getrandom::fill(&mut self.server_random)
            .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;

        // Add full ClientHello to transcript
        self.transcript.update(msg_data)?;

        // Build ServerHello echoing the cached session_id
        let mut sh_extensions = Vec::new();
        // Renegotiation info (RFC 5746)
        if self.is_renegotiation {
            sh_extensions.push(build_renegotiation_info(
                &self.prev_client_verify_data,
                &self.prev_server_verify_data,
            ));
        } else {
            sh_extensions.push(build_renegotiation_info_initial());
        }
        if self.config.ticket_key.is_some() {
            sh_extensions.push(build_session_ticket_sh());
        }
        // Echo EMS extension for abbreviated handshake
        if self.use_extended_master_secret {
            sh_extensions.push(build_extended_master_secret());
        }
        // Echo ETM extension for abbreviated handshake
        if self.use_encrypt_then_mac {
            sh_extensions.push(build_encrypt_then_mac());
        }
        let sh = ServerHello {
            random: self.server_random,
            legacy_session_id: session_id.clone(),
            cipher_suite: suite,
            extensions: sh_extensions,
        };
        let sh_msg = encode_server_hello(&sh);
        self.transcript.update(&sh_msg)?;

        // Derive key block from cached master_secret + new randoms
        let alg = params.hash_alg_id();
        let key_block = derive_key_block(
            alg,
            cached_master_secret,
            &self.server_random,
            &self.client_random,
            &params,
        )?;

        // Build NewSessionTicket BEFORE computing server Finished (RFC 5077 §3.5):
        // the abbreviated flow sends [NST]?, CCS, SFin, so SFin's transcript
        // covers CH + SH + (optional NST).
        let new_session_ticket = self.build_and_record_new_session_ticket(
            suite,
            cached_master_secret,
            cached_ems,
            3600,
        )?;

        // Compute server Finished: PRF(ms, "server finished", Hash(CH + SH [+ NST]))
        let transcript_hash = self.transcript.current_hash()?;
        let server_verify_data = compute_verify_data(
            alg,
            cached_master_secret,
            "server finished",
            &transcript_hash,
        )?;
        self.server_verify_data = server_verify_data.clone();
        let finished_msg = encode_finished12(&server_verify_data);

        // Add server Finished to transcript (for client Finished verification)
        self.transcript.update(&finished_msg)?;

        // Store state for later verification
        self.session_id = session_id.clone();
        self.master_secret = cached_master_secret.to_vec();
        self.abbreviated = true;

        // Extract Copy fields before moving params
        let is_cbc = params.is_cbc;
        let mac_len = params.mac_len;

        let result = AbbreviatedServerResult {
            server_hello: sh_msg,
            new_session_ticket,
            finished: finished_msg,
            suite,
            session_id,
            master_secret: cached_master_secret.to_vec(),
            client_write_mac_key: key_block.client_write_mac_key.clone(),
            server_write_mac_key: key_block.server_write_mac_key.clone(),
            client_write_key: key_block.client_write_key.clone(),
            server_write_key: key_block.server_write_key.clone(),
            client_write_iv: key_block.client_write_iv.clone(),
            server_write_iv: key_block.server_write_iv.clone(),
            is_cbc,
            mac_len,
        };

        self.params = Some(params);
        self.state = Tls12ServerState::WaitChangeCipherSpec;

        Ok(result)
    }

    /// Process client Finished in abbreviated (session resumption) handshake.
    ///
    /// In abbreviated mode, server Finished was already sent. This method only
    /// verifies the client's Finished message.
    pub fn process_abbreviated_finished(&mut self, msg_data: &[u8]) -> Result<(), TlsError> {
        if self.state != Tls12ServerState::WaitFinished {
            return Err(TlsError::HandshakeFailed("unexpected Finished".into()));
        }

        let params = self
            .params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher suite params".into()))?;

        if msg_data.len() < 4 + 12 {
            return Err(TlsError::HandshakeFailed("Finished too short".into()));
        }
        let received_verify_data = &msg_data[4..4 + 12];

        // Transcript contains CH + SH + server_Finished at this point
        let transcript_hash = self.transcript.current_hash()?;
        let expected = compute_verify_data(
            params.hash_alg_id(),
            &self.master_secret,
            "client finished",
            &transcript_hash,
        )?;

        if !bool::from(received_verify_data.ct_eq(&expected)) {
            return Err(TlsError::HandshakeFailed(
                "client Finished verify_data mismatch".into(),
            ));
        }

        self.client_verify_data = received_verify_data.to_vec();
        self.state = Tls12ServerState::Connected;
        Ok(())
    }

    /// Process client Certificate message (mTLS).
    ///
    /// `msg_data` is the full handshake message including the 4-byte header.
    pub fn process_client_certificate(&mut self, msg_data: &[u8]) -> Result<(), TlsError> {
        if self.state != Tls12ServerState::WaitClientCertificate {
            return Err(TlsError::HandshakeFailed(
                "unexpected client Certificate".into(),
            ));
        }

        self.transcript.update(msg_data)?;

        let body = get_body(msg_data)?;
        let cert12 = decode_certificate12(body)?;

        if cert12.certificate_list.is_empty() && self.config.require_client_cert {
            return Err(TlsError::HandshakeFailed(
                "client certificate required but not provided".into(),
            ));
        }

        self.client_certs = cert12.certificate_list;
        self.state = Tls12ServerState::WaitClientKeyExchange;
        Ok(())
    }

    /// Process ClientKeyExchange and derive keys.
    ///
    /// `msg_data` is the full handshake message including the 4-byte header.
    pub fn process_client_key_exchange(
        &mut self,
        msg_data: &[u8],
    ) -> Result<Tls12DerivedKeys, TlsError> {
        if self.state != Tls12ServerState::WaitClientKeyExchange {
            return Err(TlsError::HandshakeFailed(
                "unexpected ClientKeyExchange".into(),
            ));
        }

        self.transcript.update(msg_data)?;

        let body = get_body(msg_data)?;

        // Compute pre-master secret based on key exchange algorithm
        let pre_master_secret = match self.kx_alg {
            KeyExchangeAlg::Ecdhe => {
                let cke = decode_client_key_exchange(body)?;
                let kx = self
                    .ephemeral_key
                    .take()
                    .ok_or_else(|| TlsError::HandshakeFailed("no ephemeral key".into()))?;
                kx.compute_shared_secret(&cke.public_key)?
            }
            KeyExchangeAlg::Rsa => {
                let cke = decode_client_key_exchange_rsa(body)?;
                let private_key = self.config.private_key.as_ref().ok_or_else(|| {
                    TlsError::HandshakeFailed("no server private key configured".into())
                })?;
                let ServerPrivateKey::Rsa { n, d, e, p, q } = private_key else {
                    return Err(TlsError::HandshakeFailed(
                        "RSA key exchange requires RSA private key".into(),
                    ));
                };
                let rsa_key =
                    CryptoRsaPrivateKey::new(n, d, e, p, q).map_err(TlsError::CryptoError)?;

                // Bleichenbacher protection: generate random PMS first, then
                // overwrite only if decryption succeeds and version bytes match.
                let mut random_pms = vec![0u8; 48];
                getrandom::fill(&mut random_pms)
                    .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;
                // Set version bytes for the random fallback PMS (TLS 1.2 = 0x0303)
                random_pms[0] = 0x03;
                random_pms[1] = 0x03;

                match rsa_key.decrypt(RsaPadding::Pkcs1v15Encrypt, &cke.encrypted_pms) {
                    Ok(ref decrypted)
                        if decrypted.len() == 48
                            && decrypted[0] == 0x03
                            && decrypted[1] == 0x03 =>
                    {
                        decrypted.clone()
                    }
                    _ => {
                        // Decryption failed, wrong length, or wrong version:
                        // use random PMS to prevent Bleichenbacher oracle
                        random_pms
                    }
                }
            }
            KeyExchangeAlg::Dhe => {
                let cke = decode_client_key_exchange_dhe(body)?;
                let dh_kp = self
                    .dhe_key_pair
                    .take()
                    .ok_or_else(|| TlsError::HandshakeFailed("no DHE key pair".into()))?;
                let dh_params = self
                    .dhe_params
                    .take()
                    .ok_or_else(|| TlsError::HandshakeFailed("no DHE params".into()))?;
                dh_kp
                    .compute_shared_secret(&dh_params, &cke.dh_yc)
                    .map_err(TlsError::CryptoError)?
            }
            KeyExchangeAlg::Psk => {
                let cke = decode_client_key_exchange_psk(body)?;
                let psk = self.resolve_psk(&cke.identity)?;
                let other_secret = vec![0u8; psk.len()];
                build_psk_pms(&other_secret, &psk)
            }
            KeyExchangeAlg::DhePsk => {
                let cke = decode_client_key_exchange_dhe_psk(body)?;
                let psk = self.resolve_psk(&cke.identity)?;
                let dh_kp = self.dhe_key_pair.take().ok_or_else(|| {
                    TlsError::HandshakeFailed("no DHE key pair for DHE_PSK".into())
                })?;
                let dh_params = self
                    .dhe_params
                    .take()
                    .ok_or_else(|| TlsError::HandshakeFailed("no DHE params for DHE_PSK".into()))?;
                let dh_shared = dh_kp
                    .compute_shared_secret(&dh_params, &cke.dh_yc)
                    .map_err(TlsError::CryptoError)?;
                build_psk_pms(&dh_shared, &psk)
            }
            KeyExchangeAlg::EcdhePsk => {
                let cke = decode_client_key_exchange_ecdhe_psk(body)?;
                let psk = self.resolve_psk(&cke.identity)?;
                let kx = self.ephemeral_key.take().ok_or_else(|| {
                    TlsError::HandshakeFailed("no ECDHE key for ECDHE_PSK".into())
                })?;
                let ecdh_shared = kx.compute_shared_secret(&cke.public_key)?;
                build_psk_pms(&ecdh_shared, &psk)
            }
            KeyExchangeAlg::RsaPsk => {
                let cke = decode_client_key_exchange_rsa_psk(body)?;
                let psk = self.resolve_psk(&cke.identity)?;
                // Decrypt RSA PMS with Bleichenbacher protection (same as RSA)
                let rsa_key = match &self.config.private_key {
                    Some(ServerPrivateKey::Rsa { n, d, e, p, q }) => {
                        CryptoRsaPrivateKey::new(n, d, e, p, q).map_err(TlsError::CryptoError)?
                    }
                    _ => {
                        return Err(TlsError::HandshakeFailed(
                            "no RSA private key for RSA_PSK".into(),
                        ))
                    }
                };
                let mut fallback_pms = vec![0u8; 48];
                fallback_pms[0] = 0x03;
                fallback_pms[1] = 0x03;
                getrandom::fill(&mut fallback_pms[2..])
                    .map_err(|e| TlsError::HandshakeFailed(format!("getrandom: {e}")))?;
                let rsa_pms = match rsa_key.decrypt(RsaPadding::Pkcs1v15Encrypt, &cke.encrypted_pms)
                {
                    Ok(decrypted) if decrypted.len() == 48 => {
                        let version_ok =
                            bool::from(decrypted[0].ct_eq(&0x03) & decrypted[1].ct_eq(&0x03));
                        if version_ok {
                            decrypted
                        } else {
                            fallback_pms
                        }
                    }
                    _ => fallback_pms,
                };
                build_psk_pms(&rsa_pms, &psk)
            }
            KeyExchangeAlg::DheAnon => {
                let cke = decode_client_key_exchange_dhe(body)?;
                let dh_kp = self.dhe_key_pair.take().ok_or_else(|| {
                    TlsError::HandshakeFailed("no DHE key pair for DH_anon".into())
                })?;
                let dh_params = self
                    .dhe_params
                    .take()
                    .ok_or_else(|| TlsError::HandshakeFailed("no DHE params for DH_anon".into()))?;
                dh_kp
                    .compute_shared_secret(&dh_params, &cke.dh_yc)
                    .map_err(TlsError::CryptoError)?
            }
            KeyExchangeAlg::EcdheAnon => {
                let cke = decode_client_key_exchange(body)?;
                let kx = self.ephemeral_key.take().ok_or_else(|| {
                    TlsError::HandshakeFailed("no ECDHE key for ECDH_anon".into())
                })?;
                kx.compute_shared_secret(&cke.public_key)?
            }
            #[cfg(feature = "tlcp")]
            KeyExchangeAlg::Ecc => {
                return Err(TlsError::HandshakeFailed(
                    "ECC static key exchange not supported in TLS 1.2 server".into(),
                ));
            }
        };

        let params = self
            .params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher suite params".into()))?;

        // Derive master secret (EMS uses transcript hash instead of randoms)
        let alg = params.hash_alg_id();
        let master_secret = if self.use_extended_master_secret {
            let session_hash = self.transcript.current_hash()?;
            derive_extended_master_secret(alg, &pre_master_secret, &session_hash)?
        } else {
            derive_master_secret(
                alg,
                &pre_master_secret,
                &self.client_random,
                &self.server_random,
            )?
        };
        crate::crypt::keylog::log_master_secret(&self.config, &self.client_random, &master_secret);

        let key_block = derive_key_block(
            alg,
            &master_secret,
            &self.server_random,
            &self.client_random,
            params,
        )?;

        self.master_secret = master_secret.clone();
        self.state = if !self.client_certs.is_empty() {
            Tls12ServerState::WaitClientCertificateVerify
        } else {
            Tls12ServerState::WaitChangeCipherSpec
        };

        Ok(Tls12DerivedKeys {
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

    /// Process client CertificateVerify message (mTLS).
    ///
    /// Verifies the client's signature over the transcript hash using
    /// the client's certificate public key.
    ///
    /// `msg_data` is the full handshake message including the 4-byte header.
    pub fn process_client_certificate_verify(&mut self, msg_data: &[u8]) -> Result<(), TlsError> {
        if self.state != Tls12ServerState::WaitClientCertificateVerify {
            return Err(TlsError::HandshakeFailed(
                "unexpected CertificateVerify".into(),
            ));
        }

        let body = get_body(msg_data)?;
        let cv = decode_certificate_verify12(body)?;

        if self.client_certs.is_empty() {
            return Err(TlsError::HandshakeFailed(
                "no client certificate for CertificateVerify".into(),
            ));
        }

        // Phase T118 — compute the CV transcript digest using the
        // scheme-specific hash (RFC 5246 §7.4.8: the CV hash MUST be
        // the one named in `SignatureAndHashAlgorithm`, not the PRF
        // hash). Pre-T118 we always used `transcript.current_hash()`
        // which is the PRF hash — only worked when CV hash == PRF hash.
        // Now that the CR list advertises 18 schemes (T118), the
        // client may pick rsa_pss_rsae_sha512 etc. and we MUST hash
        // with SHA-512 even when the PRF is SHA-256.
        let transcript_msgs = self.transcript.message_bytes();
        let transcript_hash = cv_transcript_digest(cv.sig_algorithm, transcript_msgs)?;

        verify_cv12_signature(
            &self.client_certs[0],
            cv.sig_algorithm,
            &transcript_hash,
            &cv.signature,
        )?;

        self.transcript.update(msg_data)?;
        self.state = Tls12ServerState::WaitChangeCipherSpec;
        Ok(())
    }

    /// Process ChangeCipherSpec from client.
    pub fn process_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        if self.state != Tls12ServerState::WaitChangeCipherSpec {
            return Err(TlsError::HandshakeFailed(
                "unexpected ChangeCipherSpec".into(),
            ));
        }
        // CCS is not a handshake message — not added to transcript
        self.state = Tls12ServerState::WaitFinished;
        Ok(())
    }

    /// Process client Finished and build server CCS + Finished.
    ///
    /// `msg_data` is the full handshake message including the 4-byte header.
    pub fn process_finished(&mut self, msg_data: &[u8]) -> Result<ServerFinishedResult, TlsError> {
        if self.state != Tls12ServerState::WaitFinished {
            return Err(TlsError::HandshakeFailed("unexpected Finished".into()));
        }

        let params = self
            .params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher suite params".into()))?;

        // Verify client Finished (verify_data is in the body, after 4-byte header)
        if msg_data.len() < 4 + 12 {
            return Err(TlsError::HandshakeFailed("Finished too short".into()));
        }
        let received_verify_data = &msg_data[4..4 + 12];

        let alg = params.hash_alg_id();
        let transcript_hash = self.transcript.current_hash()?;
        let expected = compute_verify_data(
            alg,
            &self.master_secret,
            "client finished",
            &transcript_hash,
        )?;

        if !bool::from(received_verify_data.ct_eq(&expected)) {
            return Err(TlsError::HandshakeFailed(
                "client Finished verify_data mismatch".into(),
            ));
        }

        self.client_verify_data = received_verify_data.to_vec();

        // Add client Finished to transcript
        self.transcript.update(msg_data)?;

        // Build NewSessionTicket BEFORE computing server Finished. RFC 5077 §3.5
        // requires NST to be in the transcript hashed for server Finished. The
        // helper updates `self.transcript` internally; cloning master_secret
        // satisfies the borrow checker.
        let suite = params.suite;
        let master_secret = self.master_secret.clone();
        let use_ems = self.use_extended_master_secret;
        let new_session_ticket =
            self.build_and_record_new_session_ticket(suite, &master_secret, use_ems, 3600)?;

        // Compute server Finished over the (possibly NST-extended) transcript.
        let transcript_hash = self.transcript.current_hash()?;
        let server_verify_data = compute_verify_data(
            alg,
            &self.master_secret,
            "server finished",
            &transcript_hash,
        )?;
        self.server_verify_data = server_verify_data.clone();
        let finished_msg = encode_finished12(&server_verify_data);

        self.state = Tls12ServerState::Connected;

        Ok(ServerFinishedResult {
            new_session_ticket,
            finished: finished_msg,
        })
    }

    /// Resolve PSK from config: try callback first, then fall back to static PSK.
    fn resolve_psk(&self, identity: &[u8]) -> Result<Vec<u8>, TlsError> {
        if let Some(ref cb) = self.config.psk_server_callback {
            cb(identity).ok_or_else(|| TlsError::HandshakeFailed("PSK identity not found".into()))
        } else if let Some(ref psk) = self.config.psk {
            Ok(psk.clone())
        } else {
            Err(TlsError::HandshakeFailed("no PSK configured".into()))
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Negotiate a TLS 1.2 cipher suite between client and server.
pub(crate) fn negotiate_cipher_suite(
    ch: &ClientHello,
    config: &TlsConfig,
) -> Result<CipherSuite, TlsError> {
    if config.cipher_server_preference {
        // Server preference order (default)
        for server_suite in &config.cipher_suites {
            if !is_tls12_suite(*server_suite) {
                continue;
            }
            if ch.cipher_suites.contains(server_suite) {
                return Ok(*server_suite);
            }
        }
    } else {
        // Client preference order
        for client_suite in &ch.cipher_suites {
            if !is_tls12_suite(*client_suite) {
                continue;
            }
            if config.cipher_suites.contains(client_suite) {
                return Ok(*client_suite);
            }
        }
    }
    Err(TlsError::NoSharedCipherSuite)
}

/// Negotiate a named group for ECDHE.
pub(crate) fn negotiate_group(
    client_groups: &[NamedGroup],
    server_groups: &[NamedGroup],
) -> Result<NamedGroup, TlsError> {
    for sg in server_groups {
        if client_groups.contains(sg) {
            return Ok(*sg);
        }
    }
    Err(TlsError::HandshakeFailed("no common ECDHE group".into()))
}

/// Negotiate a named group for DHE (FFDHE groups only).
pub(crate) fn negotiate_ffdhe_group(
    client_groups: &[NamedGroup],
    server_groups: &[NamedGroup],
) -> Result<NamedGroup, TlsError> {
    for sg in server_groups {
        if is_ffdhe_group(*sg) && client_groups.contains(sg) {
            return Ok(*sg);
        }
    }
    // If no FFDHE group was negotiated via supported_groups extension,
    // default to FFDHE2048 (server choice per RFC 7919).
    Ok(NamedGroup::FFDHE2048)
}

/// Check if a NamedGroup is an FFDHE group.
fn is_ffdhe_group(g: NamedGroup) -> bool {
    matches!(
        g,
        NamedGroup::FFDHE2048
            | NamedGroup::FFDHE3072
            | NamedGroup::FFDHE4096
            | NamedGroup::FFDHE6144
            | NamedGroup::FFDHE8192
    )
}

/// Map a NamedGroup to a DhParamId for RFC 7919 groups.
fn named_group_to_dh_param_id(group: NamedGroup) -> Result<DhParamId, TlsError> {
    match group {
        NamedGroup::FFDHE2048 => Ok(DhParamId::Rfc7919_2048),
        NamedGroup::FFDHE3072 => Ok(DhParamId::Rfc7919_3072),
        NamedGroup::FFDHE4096 => Ok(DhParamId::Rfc7919_4096),
        NamedGroup::FFDHE6144 => Ok(DhParamId::Rfc7919_6144),
        NamedGroup::FFDHE8192 => Ok(DhParamId::Rfc7919_8192),
        _ => Err(TlsError::HandshakeFailed(format!(
            "unsupported FFDHE group: 0x{:04x}",
            group.0
        ))),
    }
}

/// Select a signature scheme for TLS 1.2 ServerKeyExchange.
///
/// Unlike TLS 1.3 which only uses PSS, TLS 1.2 also supports PKCS#1v1.5.
pub(crate) fn select_signature_scheme_tls12(
    key: &ServerPrivateKey,
    client_schemes: &[SignatureScheme],
) -> Result<SignatureScheme, TlsError> {
    let candidates: &[SignatureScheme] = match key {
        ServerPrivateKey::Ed25519(_) => &[SignatureScheme::ED25519],
        ServerPrivateKey::Ed448(_) => &[SignatureScheme::ED448],
        ServerPrivateKey::Ecdsa { curve_id, .. } => match *curve_id {
            EccCurveId::NistP256 => &[SignatureScheme::ECDSA_SECP256R1_SHA256],
            EccCurveId::NistP384 => &[SignatureScheme::ECDSA_SECP384R1_SHA384],
            EccCurveId::NistP521 => &[SignatureScheme::ECDSA_SECP521R1_SHA512],
            _ => {
                return Err(TlsError::HandshakeFailed(
                    "unsupported ECDSA curve for signing".into(),
                ))
            }
        },
        ServerPrivateKey::Rsa { .. } => &[
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PSS_RSAE_SHA384,
            SignatureScheme::RSA_PKCS1_SHA384,
        ],
        ServerPrivateKey::Dsa { .. } => &[SignatureScheme::DSA_SHA256, SignatureScheme::DSA_SHA384],
        #[cfg(feature = "tlcp")]
        ServerPrivateKey::Sm2 { .. } => &[SignatureScheme::SM2_SM3],
    };

    // RFC 5246 §7.4.1.4.1 — the `signature_algorithms` extension is
    // OPTIONAL in a TLS 1.2 ClientHello. When the client omits it, the
    // RFC requires the server to "behave as if the client had sent the
    // value {sha1,rsa}" (or {sha1,ecdsa} / {sha1,dsa} for those key
    // exchanges). This is enforced strictly by peers: tlslite-ng /
    // tlsfuzzer reject any other ServerKeyExchange signature algorithm
    // with "Server selected invalid signature algorithm", so we must
    // honour the literal `{sha1,*}` default — SHA-1 here is confined to
    // this one legacy-compatibility path, reached only when a client
    // explicitly signals it supports nothing beyond the TLS 1.2
    // mandatory-to-implement floor. Without this the server rejects
    // every such client with "no common signature scheme".
    if client_schemes.is_empty() {
        return Ok(match key {
            ServerPrivateKey::Rsa { .. } => SignatureScheme::RSA_PKCS1_SHA1,
            ServerPrivateKey::Ecdsa { .. } => SignatureScheme::ECDSA_SHA1,
            // Ed25519 / Ed448 / DSA / SM2 keep their single scheme: a
            // TLS-1.2 client that omits signature_algorithms predates
            // EdDSA entirely, and our `s-server` advertises no DSA
            // suites, so this combination is degenerate. The
            // `candidates` match above already errored for an
            // unsupported ECDSA curve, so this slice is non-empty.
            _ => candidates[0],
        });
    }

    for candidate in candidates {
        if client_schemes.contains(candidate) {
            return Ok(*candidate);
        }
    }

    Err(TlsError::HandshakeFailed(
        "no common signature scheme".into(),
    ))
}

/// Sign ServerKeyExchange data using the server's private key.
///
/// The signed data is `client_random || server_random || server_key_exchange_params`.
/// Unlike TLS 1.3, there is no "64 spaces" prefix — the data is hashed directly.
pub(crate) fn sign_ske_data(
    key: &ServerPrivateKey,
    scheme: SignatureScheme,
    signed_data: &[u8],
) -> Result<Vec<u8>, TlsError> {
    match key {
        ServerPrivateKey::Ed25519(seed) => {
            let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(seed)
                .map_err(TlsError::CryptoError)?;
            kp.sign(signed_data)
                .map(|s| s.to_vec())
                .map_err(TlsError::CryptoError)
        }
        ServerPrivateKey::Ed448(seed) => {
            let kp = hitls_crypto::ed448::Ed448KeyPair::from_seed(seed)
                .map_err(TlsError::CryptoError)?;
            kp.sign(signed_data)
                .map(|s| s.to_vec())
                .map_err(TlsError::CryptoError)
        }
        ServerPrivateKey::Ecdsa {
            curve_id,
            private_key,
        } => {
            let digest = match scheme {
                // ECDSA_SHA1: RFC 5246 §7.4.1.4.1 default when the
                // client omits signature_algorithms (legacy path only).
                SignatureScheme::ECDSA_SHA1 => compute_sha1(signed_data)?,
                SignatureScheme::ECDSA_SECP256R1_SHA256 => compute_sha256(signed_data)?,
                SignatureScheme::ECDSA_SECP384R1_SHA384 => compute_sha384(signed_data)?,
                SignatureScheme::ECDSA_SECP521R1_SHA512 => compute_sha512(signed_data)?,
                _ => return Err(TlsError::HandshakeFailed("ECDSA scheme mismatch".into())),
            };
            let kp = hitls_crypto::ecdsa::EcdsaKeyPair::from_private_key(*curve_id, private_key)
                .map_err(TlsError::CryptoError)?;
            kp.sign(&digest).map_err(TlsError::CryptoError)
        }
        ServerPrivateKey::Rsa { n, d, e, p, q } => {
            let digest = match scheme {
                // RSA_PKCS1_SHA1: RFC 5246 §7.4.1.4.1 default when the
                // client omits signature_algorithms (legacy path only).
                SignatureScheme::RSA_PKCS1_SHA1 => compute_sha1(signed_data)?,
                SignatureScheme::RSA_PKCS1_SHA256 | SignatureScheme::RSA_PSS_RSAE_SHA256 => {
                    compute_sha256(signed_data)?
                }
                SignatureScheme::RSA_PKCS1_SHA384 | SignatureScheme::RSA_PSS_RSAE_SHA384 => {
                    compute_sha384(signed_data)?
                }
                _ => return Err(TlsError::HandshakeFailed("RSA scheme mismatch".into())),
            };
            let padding = match scheme {
                SignatureScheme::RSA_PKCS1_SHA1
                | SignatureScheme::RSA_PKCS1_SHA256
                | SignatureScheme::RSA_PKCS1_SHA384 => hitls_crypto::rsa::RsaPadding::Pkcs1v15Sign,
                _ => hitls_crypto::rsa::RsaPadding::Pss,
            };
            let rsa_key = hitls_crypto::rsa::RsaPrivateKey::new(n, d, e, p, q)
                .map_err(TlsError::CryptoError)?;
            rsa_key
                .sign(padding, &digest)
                .map_err(TlsError::CryptoError)
        }
        ServerPrivateKey::Dsa {
            params_der,
            private_key,
        } => {
            let digest = match scheme {
                SignatureScheme::DSA_SHA256 => compute_sha256(signed_data)?,
                SignatureScheme::DSA_SHA384 => compute_sha384(signed_data)?,
                _ => return Err(TlsError::HandshakeFailed("DSA scheme mismatch".into())),
            };
            let params = parse_dsa_params_der(params_der)?;
            let kp = hitls_crypto::dsa::DsaKeyPair::from_private_key(params, private_key)
                .map_err(TlsError::CryptoError)?;
            kp.sign(&digest).map_err(TlsError::CryptoError)
        }
        #[cfg(feature = "tlcp")]
        ServerPrivateKey::Sm2 { private_key } => {
            let kp = hitls_crypto::sm2::Sm2KeyPair::from_private_key(private_key)
                .map_err(TlsError::CryptoError)?;
            kp.sign(signed_data).map_err(TlsError::CryptoError)
        }
    }
}

/// Strip the 4-byte handshake header from a full handshake message.
fn get_body(msg_data: &[u8]) -> Result<&[u8], TlsError> {
    // Phase T91 — see server.rs `get_body` for rationale.
    if msg_data.len() < 4 {
        return Err(TlsError::HandshakeFailed(
            "handshake message too short (decode_error)".into(),
        ));
    }
    Ok(&msg_data[4..])
}

fn compute_sha1(data: &[u8]) -> Result<Vec<u8>, TlsError> {
    let mut h = hitls_crypto::sha1::Sha1::new();
    h.update(data).map_err(TlsError::CryptoError)?;
    Ok(h.finish().map_err(TlsError::CryptoError)?.to_vec())
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

fn compute_sha512(data: &[u8]) -> Result<Vec<u8>, TlsError> {
    let mut h = hitls_crypto::sha2::Sha512::new();
    h.update(data).map_err(TlsError::CryptoError)?;
    Ok(h.finish().map_err(TlsError::CryptoError)?.to_vec())
}

/// Parse DER-encoded DSAParameters (SEQUENCE { INTEGER p, INTEGER q, INTEGER g }).
pub(crate) fn parse_dsa_params_der(
    params_der: &[u8],
) -> Result<hitls_crypto::dsa::DsaParams, TlsError> {
    use hitls_utils::asn1::Decoder;

    // Strip leading zero bytes (unsigned big-endian representation)
    fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        &bytes[start..]
    }

    let mut dec = Decoder::new(params_der);
    let mut seq = dec
        .read_sequence()
        .map_err(|e| TlsError::HandshakeFailed(format!("DSA params parse: {e}")))?;
    let p = seq
        .read_integer()
        .map_err(|e| TlsError::HandshakeFailed(format!("DSA p parse: {e}")))?;
    let q = seq
        .read_integer()
        .map_err(|e| TlsError::HandshakeFailed(format!("DSA q parse: {e}")))?;
    let g = seq
        .read_integer()
        .map_err(|e| TlsError::HandshakeFailed(format!("DSA g parse: {e}")))?;
    let p = strip_leading_zeros(p);
    let q = strip_leading_zeros(q);
    let g = strip_leading_zeros(g);
    hitls_crypto::dsa::DsaParams::new(p, q, g).map_err(TlsError::CryptoError)
}

/// Verify a DSA signature using the public key from an SPKI.
///
/// The SPKI's algorithm_params contains DER-encoded DSAParameters (p, q, g)
/// and the public_key contains the DER-encoded INTEGER y.
pub(crate) fn verify_dsa_from_spki(
    spki: &hitls_pki::x509::SubjectPublicKeyInfo,
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, TlsError> {
    use hitls_utils::asn1::Decoder;

    fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        &bytes[start..]
    }

    let params_der = spki
        .algorithm_params
        .as_ref()
        .ok_or_else(|| TlsError::HandshakeFailed("DSA SPKI missing algorithm params".into()))?;
    let params = parse_dsa_params_der(params_der)?;
    // Parse the public key y from DER INTEGER
    let mut key_dec = Decoder::new(&spki.public_key);
    let y = key_dec
        .read_integer()
        .map_err(|e| TlsError::HandshakeFailed(format!("DSA public key parse: {e}")))?;
    let y = strip_leading_zeros(y);
    let kp =
        hitls_crypto::dsa::DsaKeyPair::from_public_key(params, y).map_err(TlsError::CryptoError)?;
    kp.verify(digest, signature).map_err(TlsError::CryptoError)
}

/// Phase T118 — hash the TLS 1.2 transcript bytes using the hash
/// algorithm dictated by the CV `SignatureAndHashAlgorithm` (RFC 5246
/// §7.4.8). This is required because the CV hash is independent of
/// the PRF hash: e.g. a `rsa_pss_rsae_sha512` CV needs a SHA-512
/// digest even when the cipher suite's PRF is SHA-256.
///
/// For ED25519 / ED448 — Edwards signatures bind the raw message, not
/// a digest, so we return the message bytes unchanged and let the
/// caller pass them through to the EdDSA verifier.
fn cv_transcript_digest(
    scheme: SignatureScheme,
    transcript_msgs: &[u8],
) -> Result<Vec<u8>, TlsError> {
    use hitls_crypto::sha1::Sha1;
    use hitls_crypto::sha2::{Sha256, Sha384, Sha512};

    // Edwards: no pre-hash, pass raw transcript bytes through.
    if scheme == SignatureScheme::ED25519 || scheme == SignatureScheme::ED448 {
        return Ok(transcript_msgs.to_vec());
    }

    // Decode hash byte from the SignatureAndHashAlgorithm wire form
    // (high byte = hash, low byte = signature). RFC 5246 §7.4.1.4.1
    // HashAlgorithm enum:
    //   0 = none, 1 = md5, 2 = sha1, 3 = sha224, 4 = sha256,
    //   5 = sha384, 6 = sha512, 8 = Intrinsic (RFC 8422).
    //
    // The PSS schemes 0x0804..=0x0806 encode the hash via the high
    // byte too (0x08 = "Intrinsic"-style namespace; the LOW byte
    // 0x04/0x05/0x06 maps to sha256/sha384/sha512).
    let hash_byte = ((scheme.0 >> 8) & 0xff) as u8;
    let sig_byte = (scheme.0 & 0xff) as u8;

    match (hash_byte, sig_byte) {
        (0x08, 0x04) => {
            let mut h = Sha256::new();
            h.update(transcript_msgs).map_err(TlsError::CryptoError)?;
            Ok(h.finish().map_err(TlsError::CryptoError)?.to_vec())
        }
        (0x08, 0x05) => {
            let mut h = Sha384::new();
            h.update(transcript_msgs).map_err(TlsError::CryptoError)?;
            Ok(h.finish().map_err(TlsError::CryptoError)?.to_vec())
        }
        (0x08, 0x06) => {
            let mut h = Sha512::new();
            h.update(transcript_msgs).map_err(TlsError::CryptoError)?;
            Ok(h.finish().map_err(TlsError::CryptoError)?.to_vec())
        }
        (2, _) => {
            let mut h = Sha1::new();
            h.update(transcript_msgs).map_err(TlsError::CryptoError)?;
            Ok(h.finish().map_err(TlsError::CryptoError)?.to_vec())
        }
        (4, _) => {
            let mut h = Sha256::new();
            h.update(transcript_msgs).map_err(TlsError::CryptoError)?;
            Ok(h.finish().map_err(TlsError::CryptoError)?.to_vec())
        }
        (5, _) => {
            let mut h = Sha384::new();
            h.update(transcript_msgs).map_err(TlsError::CryptoError)?;
            Ok(h.finish().map_err(TlsError::CryptoError)?.to_vec())
        }
        (6, _) => {
            let mut h = Sha512::new();
            h.update(transcript_msgs).map_err(TlsError::CryptoError)?;
            Ok(h.finish().map_err(TlsError::CryptoError)?.to_vec())
        }
        _ => Err(TlsError::HandshakeFailed(format!(
            "unsupported CV hash algorithm in scheme 0x{:04x}",
            scheme.0
        ))),
    }
}

/// Verify a TLS 1.2 CertificateVerify signature.
///
/// `transcript_hash` is already a hash digest computed by
/// `cv_transcript_digest` using the hash algorithm dictated by the
/// CV scheme — it is NOT re-hashed before verification.
fn verify_cv12_signature(
    cert_der: &[u8],
    scheme: SignatureScheme,
    transcript_hash: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    let cert = hitls_pki::x509::Certificate::from_der(cert_der)
        .map_err(|e| TlsError::HandshakeFailed(format!("client cert parse: {e}")))?;
    let spki = &cert.public_key;

    // Phase T108 — RFC 5246 §7.2.2 / RFC 8446 §6.2: crypto-layer
    // errors during CV signature verification (malformed / too-short
    // signature bytes, RSA decryption math errors, etc.) are
    // `decrypt_error` (50) per spec, not the catch-all `internal_error`.
    // Coerce here so the alert mapper routes correctly without
    // needing per-call-site wording in the underlying primitive.
    let map_verify_err = |e: TlsError| -> TlsError {
        match e {
            TlsError::CryptoError(_) => TlsError::HandshakeFailed(
                "client CertificateVerify signature verification failed \
                 (crypto-layer error — RFC 5246 §7.2.2: decrypt_error)"
                    .into(),
            ),
            other => other,
        }
    };

    let ok = match scheme {
        // Phase T118 — RSA-PKCS#1v1.5 across SHA-1/256/384/512.
        // verify(Pkcs1v15Sign, digest, sig) auto-detects the inner
        // DigestInfo hash OID against `digest`'s length, so a single
        // arm covers all four lengths.
        SignatureScheme::RSA_PKCS1_SHA1
        | SignatureScheme::RSA_PKCS1_SHA256
        | SignatureScheme::RSA_PKCS1_SHA384
        | SignatureScheme::RSA_PKCS1_SHA512 => verify_cv_rsa(
            spki,
            hitls_crypto::rsa::RsaPadding::Pkcs1v15Sign,
            transcript_hash,
            signature,
        )
        .map_err(map_verify_err)?,
        // Phase T118 — RSA-PSS SHA-256/384/512. Use the explicit-hash
        // `verify_pss(digest, sig, alg)` entry point (the legacy
        // `verify(Pss, ...)` API is SHA-256 only).
        SignatureScheme::RSA_PSS_RSAE_SHA256 => verify_cv_rsa_pss(
            spki,
            transcript_hash,
            signature,
            hitls_crypto::rsa::RsaHashAlg::Sha256,
        )
        .map_err(map_verify_err)?,
        SignatureScheme::RSA_PSS_RSAE_SHA384 => verify_cv_rsa_pss(
            spki,
            transcript_hash,
            signature,
            hitls_crypto::rsa::RsaHashAlg::Sha384,
        )
        .map_err(map_verify_err)?,
        SignatureScheme::RSA_PSS_RSAE_SHA512 => verify_cv_rsa_pss(
            spki,
            transcript_hash,
            signature,
            hitls_crypto::rsa::RsaHashAlg::Sha512,
        )
        .map_err(map_verify_err)?,
        SignatureScheme::ECDSA_SECP256R1_SHA256 => {
            let verifier = hitls_crypto::ecdsa::EcdsaKeyPair::from_public_key(
                hitls_types::EccCurveId::NistP256,
                &spki.public_key,
            )
            .map_err(TlsError::CryptoError)
            .map_err(map_verify_err)?;
            verifier
                .verify(transcript_hash, signature)
                .map_err(TlsError::CryptoError)
                .map_err(map_verify_err)?
        }
        SignatureScheme::ECDSA_SECP384R1_SHA384 => {
            let verifier = hitls_crypto::ecdsa::EcdsaKeyPair::from_public_key(
                hitls_types::EccCurveId::NistP384,
                &spki.public_key,
            )
            .map_err(TlsError::CryptoError)
            .map_err(map_verify_err)?;
            verifier
                .verify(transcript_hash, signature)
                .map_err(TlsError::CryptoError)
                .map_err(map_verify_err)?
        }
        // Phase T118 — ECDSA P-521 with SHA-512. Same call shape as
        // P-256 / P-384; the SPKI parser figures out the curve from
        // the AlgorithmIdentifier OID.
        SignatureScheme::ECDSA_SECP521R1_SHA512 => {
            let verifier = hitls_crypto::ecdsa::EcdsaKeyPair::from_public_key(
                hitls_types::EccCurveId::NistP521,
                &spki.public_key,
            )
            .map_err(TlsError::CryptoError)
            .map_err(map_verify_err)?;
            verifier
                .verify(transcript_hash, signature)
                .map_err(TlsError::CryptoError)
                .map_err(map_verify_err)?
        }
        SignatureScheme::DSA_SHA256 | SignatureScheme::DSA_SHA384 => {
            verify_dsa_from_spki(spki, transcript_hash, signature).map_err(map_verify_err)?
        }
        // Phase T118 — Ed25519: signature is over the raw message,
        // not a digest. `cv_transcript_digest` returns the buffer
        // unchanged for Edwards schemes, so `transcript_hash` here
        // is actually the raw transcript bytes.
        SignatureScheme::ED25519 => {
            let verifier = hitls_crypto::ed25519::Ed25519KeyPair::from_public_key(&spki.public_key)
                .map_err(TlsError::CryptoError)
                .map_err(map_verify_err)?;
            verifier
                .verify(transcript_hash, signature)
                .map_err(TlsError::CryptoError)
                .map_err(map_verify_err)?
        }
        _ => {
            return Err(TlsError::HandshakeFailed(format!(
                "unsupported CertificateVerify scheme: 0x{:04x}",
                scheme.0
            )))
        }
    };

    if ok {
        Ok(())
    } else {
        // Phase T108 — RFC 5246 §7.2.2 / RFC 8446 §6.2: a CertificateVerify
        // signature failure is a `decrypt_error` (50), not the catch-all
        // `internal_error`. Embed the substring so `tls_error_to_alert`
        // maps it correctly (same fix pattern as T99 for the TLS 1.3
        // verify path).
        Err(TlsError::HandshakeFailed(
            "client CertificateVerify signature verification failed \
             (RFC 5246 §7.2.2 — alert: decrypt_error)"
                .into(),
        ))
    }
}

fn verify_cv_rsa(
    spki: &hitls_pki::x509::SubjectPublicKeyInfo,
    padding: hitls_crypto::rsa::RsaPadding,
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
        .verify(padding, digest, signature)
        .map_err(TlsError::CryptoError)
}

/// Phase T118 — RSA-PSS verify with an explicit hash algorithm.
/// The legacy `RsaPublicKey::verify(Pss, ...)` API is SHA-256 only;
/// for SHA-384/SHA-512 PSS variants the caller must use
/// `verify_pss(digest, sig, alg)` instead.
fn verify_cv_rsa_pss(
    spki: &hitls_pki::x509::SubjectPublicKeyInfo,
    digest: &[u8],
    signature: &[u8],
    alg: hitls_crypto::rsa::RsaHashAlg,
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
        .verify_pss(digest, signature, alg)
        .map_err(TlsError::CryptoError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerPrivateKey;
    use crate::crypt::NamedGroup;
    use crate::handshake::codec::parse_handshake_header;
    use crate::handshake::HandshakeType;

    fn make_server_config() -> TlsConfig {
        // Use Ed25519 for simplicity in tests
        let seed = vec![0x42u8; 32];
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(&seed).unwrap();
        let pub_key = kp.public_key().to_vec();

        // Create a minimal self-signed cert (just for test, not a real X.509)
        // We'll use a simple DER-encoded cert for testing
        let cert_der = create_test_ed25519_cert(&seed, &pub_key);

        TlsConfig::builder()
            .cipher_suites(&[
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            ])
            .supported_groups(&[NamedGroup::SECP256R1, NamedGroup::X25519])
            .signature_algorithms(&[
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                SignatureScheme::RSA_PSS_RSAE_SHA256,
            ])
            .certificate_chain(vec![cert_der])
            .private_key(ServerPrivateKey::Ed25519(seed))
            .build()
    }

    /// Create a minimal test certificate (not for real use).
    fn create_test_ed25519_cert(_seed: &[u8], _pub_key: &[u8]) -> Vec<u8> {
        // For unit tests, we just need some DER bytes.
        // The SKE signature verification tests use verify_peer=false.
        vec![0x30, 0x02, 0x05, 0x00]
    }

    fn build_test_client_hello(suites: &[CipherSuite]) -> Vec<u8> {
        use crate::handshake::codec::encode_client_hello;
        use crate::handshake::extensions_codec::*;

        let mut random = [0u8; 32];
        getrandom::fill(&mut random).unwrap();

        let extensions = vec![
            build_signature_algorithms(&[
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                SignatureScheme::RSA_PSS_RSAE_SHA256,
            ]),
            build_supported_groups(&[NamedGroup::SECP256R1, NamedGroup::X25519]),
            build_ec_point_formats(),
            build_renegotiation_info_initial(),
        ];

        let ch = ClientHello {
            random,
            legacy_session_id: vec![0u8; 32],
            cipher_suites: suites.to_vec(),
            extensions,
        };

        encode_client_hello(&ch)
    }

    #[test]
    fn test_server_state_initial() {
        let config = make_server_config();
        let hs = Tls12ServerHandshake::new(config);
        assert_eq!(hs.state(), Tls12ServerState::Idle);
    }

    #[test]
    fn test_negotiate_cipher_suite_basic() {
        let ch = ClientHello {
            random: [0u8; 32],
            legacy_session_id: vec![],
            cipher_suites: vec![
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            ],
            extensions: vec![],
        };
        let config = make_server_config();
        let suite = negotiate_cipher_suite(&ch, &config).unwrap();
        // Server preference order has RSA first
        assert_eq!(suite, CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    }

    #[test]
    fn test_negotiate_cipher_suite_no_match() {
        let ch = ClientHello {
            random: [0u8; 32],
            legacy_session_id: vec![],
            cipher_suites: vec![CipherSuite::TLS_AES_128_GCM_SHA256], // TLS 1.3 only
            extensions: vec![],
        };
        let config = make_server_config();
        assert!(negotiate_cipher_suite(&ch, &config).is_err());
    }

    #[test]
    fn test_negotiate_group() {
        let client = vec![NamedGroup::X25519, NamedGroup::SECP256R1];
        let server = vec![NamedGroup::SECP256R1, NamedGroup::X25519];
        let group = negotiate_group(&client, &server).unwrap();
        // Server preference: SECP256R1 first
        assert_eq!(group, NamedGroup::SECP256R1);
    }

    #[test]
    fn test_select_signature_scheme_tls12_rsa() {
        let key = ServerPrivateKey::Rsa {
            n: vec![0x01],
            d: vec![0x02],
            e: vec![0x03],
            p: vec![0x04],
            q: vec![0x05],
        };
        let client_schemes = vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PSS_RSAE_SHA256,
        ];
        // Should prefer PSS over PKCS#1v1.5
        let scheme = select_signature_scheme_tls12(&key, &client_schemes).unwrap();
        assert_eq!(scheme, SignatureScheme::RSA_PSS_RSAE_SHA256);
    }

    #[test]
    fn test_select_signature_scheme_tls12_pkcs1_fallback() {
        let key = ServerPrivateKey::Rsa {
            n: vec![0x01],
            d: vec![0x02],
            e: vec![0x03],
            p: vec![0x04],
            q: vec![0x05],
        };
        let client_schemes = vec![SignatureScheme::RSA_PKCS1_SHA256];
        let scheme = select_signature_scheme_tls12(&key, &client_schemes).unwrap();
        assert_eq!(scheme, SignatureScheme::RSA_PKCS1_SHA256);
    }

    #[test]
    fn test_select_signature_scheme_tls12_empty_rsa() {
        // Phase I101 — RFC 5246 §7.4.1.4.1: an empty client-scheme list
        // (no `signature_algorithms` extension) must NOT error; the RSA
        // fallback is the literal `{sha1,rsa}` default the RFC mandates
        // (and tlslite-ng / tlsfuzzer strictly enforce).
        let key = ServerPrivateKey::Rsa {
            n: vec![0x01],
            d: vec![0x02],
            e: vec![0x03],
            p: vec![0x04],
            q: vec![0x05],
        };
        let scheme = select_signature_scheme_tls12(&key, &[]).unwrap();
        assert_eq!(scheme, SignatureScheme::RSA_PKCS1_SHA1);
    }

    #[test]
    fn test_select_signature_scheme_tls12_empty_ecdsa() {
        // Phase I101 — the ECDSA no-extension fallback is `{sha1,ecdsa}`
        // for every curve (RFC 5246 §7.4.1.4.1).
        for curve in [
            EccCurveId::NistP256,
            EccCurveId::NistP384,
            EccCurveId::NistP521,
        ] {
            let key = ServerPrivateKey::Ecdsa {
                curve_id: curve,
                private_key: vec![0x01],
            };
            let scheme = select_signature_scheme_tls12(&key, &[]).unwrap();
            assert_eq!(scheme, SignatureScheme::ECDSA_SHA1);
        }
    }

    #[test]
    fn test_process_client_hello_generates_server_flight() {
        let mut config = make_server_config();
        // Use Ed25519, client supports it
        config.verify_peer = false;

        let mut hs = Tls12ServerHandshake::new(config);

        let ch_msg = build_test_client_hello(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]);

        // Pass the full handshake message (including 4-byte header)
        let result = hs.process_client_hello(&ch_msg).unwrap();

        // Verify all four messages are present
        let (ht, _, _) = parse_handshake_header(&result.server_hello).unwrap();
        assert_eq!(ht, HandshakeType::ServerHello);

        let cert_data = result
            .certificate
            .as_ref()
            .expect("ECDHE should have Certificate");
        let (ht, _, _) = parse_handshake_header(cert_data).unwrap();
        assert_eq!(ht, HandshakeType::Certificate);

        let ske_data = result
            .server_key_exchange
            .as_ref()
            .expect("ECDHE should have SKE");
        let (ht, _, _) = parse_handshake_header(ske_data).unwrap();
        assert_eq!(ht, HandshakeType::ServerKeyExchange);

        let (ht, _, _) = parse_handshake_header(&result.server_hello_done).unwrap();
        assert_eq!(ht, HandshakeType::ServerHelloDone);

        assert_eq!(hs.state(), Tls12ServerState::WaitClientKeyExchange);
        assert!(result.certificate_request.is_none());
    }

    #[test]
    fn test_server_sends_cert_request_when_mtls_enabled() {
        let mut config = make_server_config();
        config.verify_client_cert = true;

        let mut hs = Tls12ServerHandshake::new(config);
        let ch_msg = build_test_client_hello(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]);
        let result = hs.process_client_hello(&ch_msg).unwrap();

        assert!(result.certificate_request.is_some());
        let cr_data = result.certificate_request.unwrap();
        let (ht, _, _) = parse_handshake_header(&cr_data).unwrap();
        assert_eq!(ht, HandshakeType::CertificateRequest);
        assert_eq!(hs.state(), Tls12ServerState::WaitClientCertificate);
    }

    #[test]
    fn test_server_cert_request_advertises_comprehensive_sigalgs() {
        // Phase T118 — RFC 5246 §7.4.4 + RFC 8446 §4.2.3 / §4.3.2:
        // the TLS 1.2 server CertificateRequest's `supported_
        // signature_algorithms` MUST list every scheme we will
        // accept from the client (CV + cert-chain signatures).
        // tlsfuzzer's `test-certificate-request.py` (conversation
        // `check sigalgs in cert request`) hardcodes the canonical
        // 18-item list — assert exact match.
        let mut config = make_server_config();
        config.verify_client_cert = true;

        let mut hs = Tls12ServerHandshake::new(config);
        let ch_msg = build_test_client_hello(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]);
        let result = hs.process_client_hello(&ch_msg).unwrap();

        let cr_data = result.certificate_request.expect("CR present");
        let (_ht, cr_body, _total) = parse_handshake_header(&cr_data).unwrap();
        let cr = crate::handshake::codec12::decode_certificate_request12(cr_body).unwrap();

        let expected = vec![
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            SignatureScheme::ECDSA_SECP521R1_SHA512,
            SignatureScheme::ECDSA_SECP384R1_SHA384,
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            SignatureScheme::ECDSA_SHA224,
            SignatureScheme::ECDSA_SHA1,
            SignatureScheme::RSA_PSS_RSAE_SHA512,
            SignatureScheme::RSA_PSS_PSS_SHA512,
            SignatureScheme::RSA_PSS_RSAE_SHA384,
            SignatureScheme::RSA_PSS_PSS_SHA384,
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PSS_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA224,
            SignatureScheme::RSA_PKCS1_SHA1,
        ];
        assert_eq!(cr.sig_hash_algs, expected);
        assert_eq!(cr.cert_types, vec![1, 64]);
    }

    #[test]
    fn test_server_no_cert_request_when_disabled() {
        let config = make_server_config();
        let mut hs = Tls12ServerHandshake::new(config);
        let ch_msg = build_test_client_hello(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]);
        let result = hs.process_client_hello(&ch_msg).unwrap();

        assert!(result.certificate_request.is_none());
        assert_eq!(hs.state(), Tls12ServerState::WaitClientKeyExchange);
    }

    #[test]
    fn test_server_rejects_empty_cert_when_required() {
        let mut config = make_server_config();
        config.verify_client_cert = true;
        config.require_client_cert = true;

        let mut hs = Tls12ServerHandshake::new(config);
        let ch_msg = build_test_client_hello(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]);
        hs.process_client_hello(&ch_msg).unwrap();

        // Send empty client certificate
        let empty_cert = Certificate12 {
            certificate_list: vec![],
        };
        let empty_cert_msg = encode_certificate12(&empty_cert);
        let result = hs.process_client_certificate(&empty_cert_msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_server_accepts_empty_cert_when_optional() {
        let mut config = make_server_config();
        config.verify_client_cert = true;
        config.require_client_cert = false;

        let mut hs = Tls12ServerHandshake::new(config);
        let ch_msg = build_test_client_hello(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]);
        hs.process_client_hello(&ch_msg).unwrap();

        // Send empty client certificate
        let empty_cert = Certificate12 {
            certificate_list: vec![],
        };
        let empty_cert_msg = encode_certificate12(&empty_cert);
        hs.process_client_certificate(&empty_cert_msg).unwrap();
        assert_eq!(hs.state(), Tls12ServerState::WaitClientKeyExchange);
    }

    #[test]
    fn test_server_detects_cached_session_abbreviated() {
        use crate::session::{InMemorySessionCache, TlsSession};

        let config = make_server_config();
        let suite = CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;

        // Create a cached session
        let session_id = vec![0xAA; 32];
        let master_secret = vec![0xBB; 48];
        let session = TlsSession {
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

        let mut cache = InMemorySessionCache::new(16);
        cache.put(&session_id, session);

        let mut hs = Tls12ServerHandshake::new(config);

        // Build a ClientHello with the cached session_id
        let ch_msg = build_test_client_hello_with_session_id(&[suite], &session_id);

        let result = hs
            .process_client_hello_resumable(&ch_msg, Some(&cache))
            .unwrap();

        match result {
            ServerHelloResult::Abbreviated(ref abbr) => {
                assert_eq!(abbr.suite, suite);
                assert_eq!(abbr.session_id, session_id);
                assert_eq!(abbr.master_secret, master_secret);
                assert!(!abbr.client_write_key.is_empty());
                assert!(!abbr.server_write_key.is_empty());
            }
            ServerHelloResult::Full(_) => panic!("expected abbreviated handshake"),
        }
        assert!(hs.is_abbreviated());
        assert_eq!(hs.state(), Tls12ServerState::WaitChangeCipherSpec);
    }

    #[test]
    fn test_server_unknown_session_full_handshake() {
        use crate::session::InMemorySessionCache;

        let config = make_server_config();
        let suite = CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;

        // Empty cache — no sessions
        let cache = InMemorySessionCache::new(16);
        let mut hs = Tls12ServerHandshake::new(config);

        // Build a ClientHello with a session_id not in cache
        let ch_msg = build_test_client_hello_with_session_id(&[suite], &[0xCC; 32]);

        let result = hs
            .process_client_hello_resumable(&ch_msg, Some(&cache))
            .unwrap();

        match result {
            ServerHelloResult::Full(ref flight) => {
                assert_eq!(flight.suite, suite);
                assert!(!flight.session_id.is_empty());
            }
            ServerHelloResult::Abbreviated(_) => panic!("expected full handshake"),
        }
        assert!(!hs.is_abbreviated());
        assert_eq!(hs.state(), Tls12ServerState::WaitClientKeyExchange);
    }

    #[test]
    fn test_server_session_suite_mismatch_full_handshake() {
        use crate::session::{InMemorySessionCache, TlsSession};

        let config = make_server_config();

        // Cache a session with a different cipher suite than what client offers
        let session_id = vec![0xDD; 32];
        let session = TlsSession {
            id: session_id.clone(),
            cipher_suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
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

        let mut cache = InMemorySessionCache::new(16);
        cache.put(&session_id, session);

        let mut hs = Tls12ServerHandshake::new(config);

        // Client offers only AES-128-GCM, but cached session uses AES-256-GCM
        let ch_msg = build_test_client_hello_with_session_id(
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            &session_id,
        );

        let result = hs
            .process_client_hello_resumable(&ch_msg, Some(&cache))
            .unwrap();

        match result {
            ServerHelloResult::Full(ref flight) => {
                assert_eq!(
                    flight.suite,
                    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                );
            }
            ServerHelloResult::Abbreviated(_) => panic!("expected full handshake"),
        }
        assert!(!hs.is_abbreviated());
    }

    /// Build a ClientHello with a specific session_id for session resumption tests.
    fn build_test_client_hello_with_session_id(
        suites: &[CipherSuite],
        session_id: &[u8],
    ) -> Vec<u8> {
        use crate::handshake::codec::encode_client_hello;
        use crate::handshake::extensions_codec::*;

        let mut random = [0u8; 32];
        getrandom::fill(&mut random).unwrap();

        let extensions = vec![
            build_signature_algorithms(&[
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                SignatureScheme::RSA_PSS_RSAE_SHA256,
            ]),
            build_supported_groups(&[NamedGroup::SECP256R1, NamedGroup::X25519]),
            build_ec_point_formats(),
            build_renegotiation_info_initial(),
        ];

        let ch = ClientHello {
            random,
            legacy_session_id: session_id.to_vec(),
            cipher_suites: suites.to_vec(),
            extensions,
        };

        encode_client_hello(&ch)
    }

    /// Build a ClientHello with optional STATUS_REQUEST and SCT extensions.
    fn build_test_client_hello_with_ocsp(
        suites: &[CipherSuite],
        include_status_request: bool,
        include_sct: bool,
    ) -> Vec<u8> {
        use crate::handshake::codec::encode_client_hello;
        use crate::handshake::extensions_codec::*;

        let mut random = [0u8; 32];
        getrandom::fill(&mut random).unwrap();

        let mut extensions = vec![
            build_signature_algorithms(&[
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                SignatureScheme::RSA_PSS_RSAE_SHA256,
            ]),
            build_supported_groups(&[NamedGroup::SECP256R1, NamedGroup::X25519]),
            build_ec_point_formats(),
            build_renegotiation_info_initial(),
        ];
        if include_status_request {
            extensions.push(build_status_request_ch());
        }
        if include_sct {
            extensions.push(build_sct_ch());
        }

        let ch = ClientHello {
            random,
            legacy_session_id: vec![0u8; 32],
            cipher_suites: suites.to_vec(),
            extensions,
        };

        encode_client_hello(&ch)
    }

    #[test]
    fn test_server_ocsp_stapling_when_requested_and_configured() {
        let fake_ocsp_response = vec![0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB];
        let config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1, NamedGroup::X25519])
            .signature_algorithms(&[
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                SignatureScheme::RSA_PSS_RSAE_SHA256,
            ])
            .certificate_chain(vec![vec![0x30, 0x02, 0x05, 0x00]])
            .private_key(ServerPrivateKey::Ed25519(vec![0x42u8; 32]))
            .ocsp_staple(fake_ocsp_response.clone())
            .build();

        let mut hs = Tls12ServerHandshake::new(config);
        let ch = build_test_client_hello_with_ocsp(
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            true,
            false,
        );
        let result = hs.process_client_hello(&ch).unwrap();

        // CertificateStatus should be present
        let cs = result
            .certificate_status
            .as_ref()
            .expect("CertificateStatus should be present");
        let (ht, body, _) = parse_handshake_header(cs).unwrap();
        assert_eq!(ht, HandshakeType::CertificateStatus);

        let ocsp = crate::handshake::codec12::decode_certificate_status12(body).unwrap();
        assert_eq!(ocsp, fake_ocsp_response);
    }

    #[test]
    fn test_server_no_ocsp_when_not_requested() {
        let config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1, NamedGroup::X25519])
            .signature_algorithms(&[
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                SignatureScheme::RSA_PSS_RSAE_SHA256,
            ])
            .certificate_chain(vec![vec![0x30, 0x02, 0x05, 0x00]])
            .private_key(ServerPrivateKey::Ed25519(vec![0x42u8; 32]))
            .ocsp_staple(vec![0x30, 0x02, 0x05, 0x00])
            .build();

        let mut hs = Tls12ServerHandshake::new(config);
        // Client does NOT include STATUS_REQUEST extension
        let ch = build_test_client_hello_with_ocsp(
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            false,
            false,
        );
        let result = hs.process_client_hello(&ch).unwrap();

        // No CertificateStatus since client didn't request it
        assert!(result.certificate_status.is_none());
    }

    #[test]
    fn test_server_no_ocsp_when_no_staple_configured() {
        let config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1, NamedGroup::X25519])
            .signature_algorithms(&[
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                SignatureScheme::RSA_PSS_RSAE_SHA256,
            ])
            .certificate_chain(vec![vec![0x30, 0x02, 0x05, 0x00]])
            .private_key(ServerPrivateKey::Ed25519(vec![0x42u8; 32]))
            // No ocsp_staple configured
            .build();

        let mut hs = Tls12ServerHandshake::new(config);
        // Client requests OCSP stapling but server has no staple
        let ch = build_test_client_hello_with_ocsp(
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            true,
            false,
        );
        let result = hs.process_client_hello(&ch).unwrap();

        // No CertificateStatus since server has no OCSP staple
        assert!(result.certificate_status.is_none());
    }

    #[test]
    fn test_server_flight_order_with_ocsp() {
        let fake_ocsp = vec![0xDE, 0xAD];
        let config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1, NamedGroup::X25519])
            .signature_algorithms(&[
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                SignatureScheme::RSA_PSS_RSAE_SHA256,
            ])
            .certificate_chain(vec![vec![0x30, 0x02, 0x05, 0x00]])
            .private_key(ServerPrivateKey::Ed25519(vec![0x42u8; 32]))
            .ocsp_staple(fake_ocsp)
            .build();

        let mut hs = Tls12ServerHandshake::new(config);
        let ch = build_test_client_hello_with_ocsp(
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            true,
            false,
        );
        let result = hs.process_client_hello(&ch).unwrap();

        // Verify complete flight: SH, Cert, CertificateStatus, SKE, SHD
        let (ht, _, _) = parse_handshake_header(&result.server_hello).unwrap();
        assert_eq!(ht, HandshakeType::ServerHello);

        let (ht, _, _) = parse_handshake_header(result.certificate.as_ref().unwrap()).unwrap();
        assert_eq!(ht, HandshakeType::Certificate);

        let (ht, _, _) =
            parse_handshake_header(result.certificate_status.as_ref().unwrap()).unwrap();
        assert_eq!(ht, HandshakeType::CertificateStatus);

        let (ht, _, _) =
            parse_handshake_header(result.server_key_exchange.as_ref().unwrap()).unwrap();
        assert_eq!(ht, HandshakeType::ServerKeyExchange);

        let (ht, _, _) = parse_handshake_header(&result.server_hello_done).unwrap();
        assert_eq!(ht, HandshakeType::ServerHelloDone);
    }

    #[test]
    fn test_server12_cke_wrong_state_idle() {
        let config = make_server_config();
        let mut hs = Tls12ServerHandshake::new(config);
        // CKE from Idle → error
        assert!(hs
            .process_client_key_exchange(&[16, 0, 0, 4, 0, 0, 0, 0])
            .is_err());
    }

    #[test]
    fn test_server12_ccs_wrong_state_idle() {
        let config = make_server_config();
        let mut hs = Tls12ServerHandshake::new(config);
        // CCS from Idle → error
        assert!(hs.process_change_cipher_spec().is_err());
    }

    #[test]
    fn test_server12_finished_wrong_state_idle() {
        let config = make_server_config();
        let mut hs = Tls12ServerHandshake::new(config);
        // Finished from Idle → error
        assert!(hs
            .process_finished(&[20, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            .is_err());
    }

    #[test]
    fn test_server12_cert_wrong_state_idle() {
        let config = make_server_config();
        let mut hs = Tls12ServerHandshake::new(config);
        // Client Certificate from Idle → error
        assert!(hs
            .process_client_certificate(&[11, 0, 0, 3, 0, 0, 0])
            .is_err());
    }

    #[test]
    fn test_server12_accessor_methods() {
        let config = make_server_config();
        let hs = Tls12ServerHandshake::new(config);
        assert_eq!(hs.state(), Tls12ServerState::Idle);
        assert!(!hs.is_abbreviated());
    }

    #[test]
    fn test_server_reset_for_renegotiation() {
        let config = make_server_config();
        let mut hs = Tls12ServerHandshake::new(config);

        // Simulate verify_data from a completed handshake
        hs.client_verify_data = vec![0x03; 12];
        hs.server_verify_data = vec![0x04; 12];
        hs.state = Tls12ServerState::Connected;

        assert!(!hs.is_renegotiation());

        hs.reset_for_renegotiation();

        assert!(hs.is_renegotiation());
        assert_eq!(hs.state(), Tls12ServerState::Idle);
        assert_eq!(hs.prev_client_verify_data, vec![0x03; 12]);
        assert_eq!(hs.prev_server_verify_data, vec![0x04; 12]);
        assert!(hs.client_verify_data.is_empty());
        assert!(hs.server_verify_data.is_empty());
    }

    #[test]
    fn test_server_build_hello_request() {
        let hr = Tls12ServerHandshake::build_hello_request();
        assert_eq!(hr, vec![0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_cipher_server_preference_default() {
        // Server preference: server's first matching suite wins
        let ch = ClientHello {
            random: [0u8; 32],
            legacy_session_id: vec![],
            cipher_suites: vec![
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ],
            extensions: vec![],
        };
        let config = TlsConfig::builder()
            .role(crate::TlsRole::Server)
            .cipher_suites(&[
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            ])
            .build();
        // Server preference: RSA first in server list
        let suite = negotiate_cipher_suite(&ch, &config).unwrap();
        assert_eq!(suite, CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    }

    #[test]
    fn test_server12_abbreviated_finished_wrong_state_idle() {
        let config = make_server_config();
        let mut hs = Tls12ServerHandshake::new(config);
        // Abbreviated Finished from Idle → error
        assert!(hs
            .process_abbreviated_finished(&[20, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            .is_err());
    }

    #[test]
    fn test_server12_cert_verify_wrong_state_idle() {
        let config = make_server_config();
        let mut hs = Tls12ServerHandshake::new(config);
        // CertificateVerify from Idle → error
        assert!(hs
            .process_client_certificate_verify(&[15, 0, 0, 4, 0x08, 0x04, 0x00, 0x00])
            .is_err());
    }

    #[test]
    fn test_server12_build_new_session_ticket_no_key() {
        let config = make_server_config();
        let mut hs = Tls12ServerHandshake::new(config);
        // No ticket_key configured → returns Ok(None) regardless of master_secret.
        let result = hs
            .build_and_record_new_session_ticket(
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                &[0xAB; 48],
                false,
                3600,
            )
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_server12_build_new_session_ticket_with_key_no_master_secret() {
        let config = TlsConfig::builder()
            .role(crate::TlsRole::Server)
            .certificate_chain(vec![vec![0x30, 0x02, 0x05, 0x00]])
            .private_key(ServerPrivateKey::Ed25519(vec![0x42u8; 32]))
            .cipher_suites(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256])
            .ticket_key(vec![0xAA; 48])
            .build();
        let mut hs = Tls12ServerHandshake::new(config);
        // ticket_key configured but caller passed empty master_secret → error
        let result = hs.build_and_record_new_session_ticket(
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            &[],
            false,
            3600,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_cipher_client_preference() {
        // Client preference: client's first matching suite wins
        let ch = ClientHello {
            random: [0u8; 32],
            legacy_session_id: vec![],
            cipher_suites: vec![
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ],
            extensions: vec![],
        };
        let config = TlsConfig::builder()
            .role(crate::TlsRole::Server)
            .cipher_suites(&[
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            ])
            .cipher_server_preference(false)
            .build();
        // Client preference: ECDSA first in client list
        let suite = negotiate_cipher_suite(&ch, &config).unwrap();
        assert_eq!(suite, CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    }
}
