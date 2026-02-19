//! TLS 1.3 server handshake state machine.
//!
//! Implements the server side of the 1-RTT handshake:
//! ClientHello → ServerHello + {EE} + {Certificate} + {CertificateVerify} + {Finished}
//! → client {Finished}

use crate::config::{SniAction, TlsConfig};
use crate::crypt::hkdf::{hkdf_expand, hmac_hash};
use crate::crypt::key_schedule::KeySchedule;
use crate::crypt::traffic_keys::TrafficKeys;
use crate::crypt::transcript::TranscriptHash;
use crate::crypt::{CipherSuiteParams, HashFactory, NamedGroup, SignatureScheme};
use crate::extensions::ExtensionType;
use crate::CipherSuite;
use hitls_crypto::sha2::Sha256;
use hitls_types::TlsError;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

#[cfg(feature = "cert-compression")]
use super::codec::{
    compress_certificate_body, encode_compressed_certificate, CompressedCertificateMsg,
};
use super::codec::{
    decode_client_hello, decode_finished, encode_certificate, encode_certificate_verify,
    encode_encrypted_extensions, encode_finished, encode_new_session_ticket, encode_server_hello,
    CertCompressionAlgorithm, CertificateEntry, CertificateMsg, CertificateVerifyMsg,
    EncryptedExtensions, NewSessionTicketMsg, ServerHello, HELLO_RETRY_REQUEST_RANDOM,
};
use super::extensions_codec::{
    build_alpn_selected, build_early_data_ee, build_early_data_nst, build_key_share_hrr,
    build_key_share_sh, build_pre_shared_key_sh, build_record_size_limit, build_sct_cert_entry,
    build_status_request_cert_entry, build_supported_versions_sh, parse_alpn_ch,
    parse_certificate_authorities, parse_compress_certificate, parse_key_share_ch,
    parse_pre_shared_key_ch, parse_psk_key_exchange_modes, parse_record_size_limit,
    parse_server_name, parse_signature_algorithms_cert, parse_signature_algorithms_ch,
    parse_status_request_ch, parse_supported_groups_ch, parse_supported_versions_ch,
};
use super::key_exchange::KeyExchange;
use super::signing::{select_signature_scheme, sign_certificate_verify};
use super::HandshakeState;

/// Result from processing ClientHello.
pub struct ClientHelloActions {
    /// Raw ServerHello handshake message bytes (sent as plaintext record).
    pub server_hello_msg: Vec<u8>,
    /// Raw EncryptedExtensions handshake message bytes.
    pub encrypted_extensions_msg: Vec<u8>,
    /// Raw Certificate handshake message bytes.
    pub certificate_msg: Vec<u8>,
    /// Raw CertificateVerify handshake message bytes.
    pub certificate_verify_msg: Vec<u8>,
    /// Raw server Finished handshake message bytes.
    pub server_finished_msg: Vec<u8>,
    /// Server handshake traffic keys (for encrypting EE, Cert, CV, Finished).
    pub server_hs_keys: TrafficKeys,
    /// Client handshake traffic keys (for decrypting client Finished).
    pub client_hs_keys: TrafficKeys,
    /// Server application traffic keys.
    pub server_app_keys: TrafficKeys,
    /// Client application traffic keys.
    pub client_app_keys: TrafficKeys,
    /// The negotiated cipher suite.
    pub suite: CipherSuite,
    /// Raw client application traffic secret (for key updates).
    pub client_app_secret: Vec<u8>,
    /// Raw server application traffic secret (for key updates).
    pub server_app_secret: Vec<u8>,
    /// Cipher suite parameters (for key updates).
    pub cipher_params: CipherSuiteParams,
    /// Whether this handshake used PSK (skipped cert/CV).
    pub psk_mode: bool,
    /// Exporter master secret (for RFC 5705 / RFC 8446 §7.5 key material export).
    pub exporter_master_secret: Vec<u8>,
    /// Early exporter master secret (for export_early_keying_material, empty if no PSK).
    pub early_exporter_master_secret: Vec<u8>,
    /// Whether 0-RTT early data was accepted.
    pub early_data_accepted: bool,
    /// Client early traffic keys (for reading 0-RTT data, if accepted).
    pub early_read_keys: Option<TrafficKeys>,
}

/// Result from processing ClientHello: either full handshake or HRR needed.
pub enum ClientHelloResult {
    /// Normal handshake — all server flight messages and keys ready.
    Actions(Box<ClientHelloActions>),
    /// HelloRetryRequest needed — send HRR, then read retried ClientHello.
    HelloRetryRequest(HelloRetryRequestActions),
}

/// Actions when a HelloRetryRequest is needed.
pub struct HelloRetryRequestActions {
    /// Raw HRR ServerHello message bytes (sent as plaintext record).
    pub hrr_msg: Vec<u8>,
    /// The negotiated cipher suite.
    pub suite: CipherSuite,
}

/// Result from processing client Finished.
pub struct ClientFinishedActions {
    /// The negotiated cipher suite.
    pub suite: CipherSuite,
    /// NewSessionTicket messages to send (post-handshake, encrypted).
    pub new_session_ticket_msgs: Vec<Vec<u8>>,
    /// Resumption master secret (for client-side PSK derivation in tests).
    pub resumption_master_secret: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Ticket encryption helpers
// ---------------------------------------------------------------------------

/// Encrypt session data into a ticket.
///
/// Format: nonce(12) || ciphertext(XOR-encrypted) || hmac(hash_len).
/// Plaintext: psk_len(2) || psk || suite(2) || created_at(8) || age_add(4).
pub(crate) fn encrypt_ticket(
    factory: &HashFactory,
    ticket_key: &[u8],
    psk: &[u8],
    suite: CipherSuite,
    created_at: u64,
    age_add: u32,
) -> Result<Vec<u8>, TlsError> {
    // Build plaintext
    let mut plaintext = Vec::with_capacity(2 + psk.len() + 14);
    plaintext.extend_from_slice(&(psk.len() as u16).to_be_bytes());
    plaintext.extend_from_slice(psk);
    plaintext.extend_from_slice(&suite.0.to_be_bytes());
    plaintext.extend_from_slice(&created_at.to_be_bytes());
    plaintext.extend_from_slice(&age_add.to_be_bytes());

    // Generate random nonce
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce)
        .map_err(|_| TlsError::HandshakeFailed("ticket nonce gen failed".into()))?;

    // Derive key stream
    let key_stream = hkdf_expand(&**factory, ticket_key, &nonce, plaintext.len())?;

    // XOR encrypt
    let ciphertext: Vec<u8> = plaintext
        .iter()
        .zip(key_stream.iter())
        .map(|(p, k)| p ^ k)
        .collect();

    // HMAC for authentication
    let mut mac_input = Vec::with_capacity(12 + ciphertext.len());
    mac_input.extend_from_slice(&nonce);
    mac_input.extend_from_slice(&ciphertext);
    let mac = hmac_hash(&**factory, ticket_key, &mac_input)?;

    let mut ticket = Vec::with_capacity(12 + ciphertext.len() + mac.len());
    ticket.extend_from_slice(&nonce);
    ticket.extend_from_slice(&ciphertext);
    ticket.extend_from_slice(&mac);
    Ok(ticket)
}

/// Decrypt a ticket to recover (psk, suite, created_at, age_add).
pub(crate) fn decrypt_ticket(
    factory: &HashFactory,
    ticket_key: &[u8],
    ticket: &[u8],
) -> Result<(Vec<u8>, CipherSuite, u64, u32), TlsError> {
    let mac_len = (*factory)().output_size();
    if ticket.len() < 12 + mac_len {
        return Err(TlsError::HandshakeFailed("ticket too short".into()));
    }

    let nonce = &ticket[..12];
    let ciphertext = &ticket[12..ticket.len() - mac_len];
    let mac = &ticket[ticket.len() - mac_len..];

    // Verify MAC
    let mut mac_input = Vec::with_capacity(12 + ciphertext.len());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(ciphertext);
    let expected_mac = hmac_hash(&**factory, ticket_key, &mac_input)?;

    if !bool::from(mac.ct_eq(&expected_mac)) {
        return Err(TlsError::HandshakeFailed(
            "ticket MAC verification failed".into(),
        ));
    }

    // Derive key stream and decrypt
    let key_stream = hkdf_expand(&**factory, ticket_key, nonce, ciphertext.len())?;
    let plaintext: Vec<u8> = ciphertext
        .iter()
        .zip(key_stream.iter())
        .map(|(c, k)| c ^ k)
        .collect();

    // Parse plaintext: psk_len(2) || psk || suite(2) || created_at(8) || age_add(4)
    if plaintext.len() < 16 {
        return Err(TlsError::HandshakeFailed(
            "ticket plaintext too short".into(),
        ));
    }
    let psk_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
    if plaintext.len() < 2 + psk_len + 14 {
        return Err(TlsError::HandshakeFailed(
            "ticket plaintext invalid length".into(),
        ));
    }
    let psk = plaintext[2..2 + psk_len].to_vec();
    let pos = 2 + psk_len;
    let suite = CipherSuite(u16::from_be_bytes([plaintext[pos], plaintext[pos + 1]]));
    let created_at = u64::from_be_bytes([
        plaintext[pos + 2],
        plaintext[pos + 3],
        plaintext[pos + 4],
        plaintext[pos + 5],
        plaintext[pos + 6],
        plaintext[pos + 7],
        plaintext[pos + 8],
        plaintext[pos + 9],
    ]);
    let age_add = u32::from_be_bytes([
        plaintext[pos + 10],
        plaintext[pos + 11],
        plaintext[pos + 12],
        plaintext[pos + 13],
    ]);

    Ok((psk, suite, created_at, age_add))
}

/// Server handshake state machine.
pub struct ServerHandshake {
    config: TlsConfig,
    state: HandshakeState,
    key_schedule: Option<KeySchedule>,
    transcript: TranscriptHash,
    params: Option<CipherSuiteParams>,
    negotiated_suite: Option<CipherSuite>,
    /// Client handshake traffic secret (for verifying client Finished).
    client_hs_secret: Vec<u8>,
    /// Server handshake traffic secret (for server finished key).
    server_hs_secret: Vec<u8>,
    /// Client-offered certificate compression algorithms.
    client_cert_compression_algos: Vec<CertCompressionAlgorithm>,
    /// Client's record size limit from ClientHello.
    client_record_size_limit: Option<u16>,
    /// Whether client requested OCSP stapling.
    client_wants_ocsp: bool,
    /// Whether client requested SCT.
    client_wants_sct: bool,
    /// Client random (stored for key logging).
    client_random: [u8; 32],
    /// Negotiated ALPN protocol (if any).
    negotiated_alpn: Option<Vec<u8>>,
    /// Client SNI hostname (if sent).
    client_server_name: Option<String>,
    /// Negotiated key exchange group.
    negotiated_group: Option<NamedGroup>,
    /// Client certificates (DER-encoded, leaf first) for post-handshake auth.
    client_certs: Vec<Vec<u8>>,
    /// Client-offered signature algorithms for certificates (RFC 8446 §4.2.3).
    client_sig_algs_cert: Vec<SignatureScheme>,
    /// Certificate authorities received from client (RFC 8446 §4.2.4).
    client_certificate_authorities: Vec<Vec<u8>>,
}

impl Drop for ServerHandshake {
    fn drop(&mut self) {
        self.client_hs_secret.zeroize();
        self.server_hs_secret.zeroize();
    }
}

impl ServerHandshake {
    /// Create a new server handshake.
    pub fn new(config: TlsConfig) -> Self {
        let transcript = TranscriptHash::new(|| Box::new(Sha256::new()));
        Self {
            config,
            state: HandshakeState::WaitClientHello,
            key_schedule: None,
            transcript,
            params: None,
            negotiated_suite: None,
            client_hs_secret: Vec::new(),
            server_hs_secret: Vec::new(),
            client_cert_compression_algos: Vec::new(),
            client_record_size_limit: None,
            client_wants_ocsp: false,
            client_wants_sct: false,
            client_random: [0u8; 32],
            negotiated_alpn: None,
            client_server_name: None,
            negotiated_group: None,
            client_certs: Vec::new(),
            client_sig_algs_cert: Vec::new(),
            client_certificate_authorities: Vec::new(),
        }
    }

    /// Current handshake state.
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// The client's record size limit (for capping outgoing records).
    pub fn client_record_size_limit(&self) -> Option<u16> {
        self.client_record_size_limit
    }

    /// Get the negotiated ALPN protocol (if any).
    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
    }

    /// Get the client's SNI hostname (if sent).
    pub fn client_server_name(&self) -> Option<&str> {
        self.client_server_name.as_deref()
    }

    /// Get the negotiated key exchange group (if any).
    pub fn negotiated_group(&self) -> Option<NamedGroup> {
        self.negotiated_group
    }

    /// Get the client's certificate chain (DER-encoded, leaf first).
    pub fn client_certs(&self) -> &[Vec<u8>] {
        &self.client_certs
    }

    /// Client-offered signature algorithms for certificates (RFC 8446 §4.2.3).
    pub fn client_sig_algs_cert(&self) -> &[SignatureScheme] {
        &self.client_sig_algs_cert
    }

    /// Certificate authorities received from client's ClientHello.
    pub fn client_certificate_authorities(&self) -> &[Vec<u8>] {
        &self.client_certificate_authorities
    }

    /// Process a ClientHello message.
    ///
    /// Returns either the full server flight (normal handshake) or a
    /// HelloRetryRequest if the client's key_share doesn't match any server group.
    ///
    /// `msg_data` is the full handshake message including the 4-byte header.
    pub fn process_client_hello(&mut self, msg_data: &[u8]) -> Result<ClientHelloResult, TlsError> {
        if self.state != HandshakeState::WaitClientHello {
            return Err(TlsError::HandshakeFailed(
                "process_client_hello: wrong state".into(),
            ));
        }

        let body = get_body(msg_data)?;
        let ch = decode_client_hello(body)?;
        self.client_random = ch.random;

        // --- Parse extensions ---

        // supported_versions: verify client offers TLS 1.3
        let versions_ext = ch
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::SUPPORTED_VERSIONS)
            .ok_or_else(|| {
                TlsError::HandshakeFailed("missing supported_versions in ClientHello".into())
            })?;
        let versions = parse_supported_versions_ch(&versions_ext.data)?;
        if !versions.contains(&0x0304) {
            return Err(TlsError::HandshakeFailed(
                "client does not support TLS 1.3".into(),
            ));
        }

        // signature_algorithms
        let sig_alg_ext = ch
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::SIGNATURE_ALGORITHMS)
            .ok_or_else(|| {
                TlsError::HandshakeFailed("missing signature_algorithms in ClientHello".into())
            })?;
        let client_sig_algs = parse_signature_algorithms_ch(&sig_alg_ext.data)?;

        // signature_algorithms_cert (RFC 8446 §4.2.3) — optional
        if let Some(sac_ext) = ch
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::SIGNATURE_ALGORITHMS_CERT)
        {
            self.client_sig_algs_cert = parse_signature_algorithms_cert(&sac_ext.data)?;
        }

        // certificate_authorities (RFC 8446 §4.2.4) — optional
        if let Some(ca_ext) = ch
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::CERTIFICATE_AUTHORITIES)
        {
            self.client_certificate_authorities = parse_certificate_authorities(&ca_ext.data)?;
        }

        // key_share
        let ks_ext = ch
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::KEY_SHARE)
            .ok_or_else(|| TlsError::HandshakeFailed("missing key_share in ClientHello".into()))?;
        let client_key_shares = parse_key_share_ch(&ks_ext.data)?;

        // supported_groups (optional for normal path, required for HRR)
        let client_groups = ch
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::SUPPORTED_GROUPS)
            .map(|e| parse_supported_groups_ch(&e.data))
            .transpose()?;

        // compress_certificate (RFC 8879)
        let client_cert_compression = ch
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::COMPRESS_CERTIFICATE)
            .map(|e| parse_compress_certificate(&e.data))
            .transpose()?
            .unwrap_or_default();
        self.client_cert_compression_algos = client_cert_compression;

        // record_size_limit (RFC 8449)
        if let Some(rsl_ext) = ch
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::RECORD_SIZE_LIMIT)
        {
            self.client_record_size_limit = Some(parse_record_size_limit(&rsl_ext.data)?);
        }

        // status_request (OCSP stapling, RFC 6066)
        if let Some(sr_ext) = ch
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::STATUS_REQUEST)
        {
            if parse_status_request_ch(&sr_ext.data).unwrap_or(false) {
                self.client_wants_ocsp = true;
            }
        }

        // signed_certificate_timestamp (SCT, RFC 6962)
        if ch
            .extensions
            .iter()
            .any(|e| e.extension_type == ExtensionType::SIGNED_CERTIFICATE_TIMESTAMP)
        {
            self.client_wants_sct = true;
        }

        // ALPN (RFC 7301)
        if let Some(alpn_ext) = ch
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
        {
            let client_alpn_protocols = parse_alpn_ch(&alpn_ext.data)?;
            // Server preference order
            for server_proto in &self.config.alpn_protocols {
                if client_alpn_protocols.contains(server_proto) {
                    self.negotiated_alpn = Some(server_proto.clone());
                    break;
                }
            }
        }

        // SNI (RFC 6066)
        if let Some(sni_ext) = ch
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::SERVER_NAME)
        {
            self.client_server_name = Some(parse_server_name(&sni_ext.data)?);
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
                supported_versions: versions.clone(),
                server_name: self.client_server_name.clone(),
                alpn_protocols: Vec::new(),
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

        // --- Select cipher suite ---
        let suite = if self.config.cipher_server_preference {
            // Server preference (default)
            self.config
                .cipher_suites
                .iter()
                .find(|s| ch.cipher_suites.contains(s))
                .copied()
        } else {
            // Client preference
            ch.cipher_suites
                .iter()
                .find(|s| self.config.cipher_suites.contains(s))
                .copied()
        }
        .ok_or(TlsError::NoSharedCipherSuite)?;

        let params = CipherSuiteParams::from_suite(suite)?;

        // If SHA-384, re-init transcript
        if params.hash_len == 48 {
            self.transcript = TranscriptHash::new(|| Box::new(hitls_crypto::sha2::Sha384::new()));
        }

        // --- Check for PSK ---
        let psk_ext = ch
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::PRE_SHARED_KEY);
        let psk_modes_ext = ch
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::PSK_KEY_EXCHANGE_MODES);

        let mut verified_psk: Option<Vec<u8>> = None;
        if let (Some(psk_e), Some(modes_e)) = (psk_ext, psk_modes_ext) {
            // Verify client supports psk_dhe_ke mode (1)
            let modes = parse_psk_key_exchange_modes(&modes_e.data)?;
            if modes.contains(&0x01) {
                if let Some(ref ticket_key) = self.config.ticket_key {
                    let (identities, binders) = parse_pre_shared_key_ch(&psk_e.data)?;
                    if let Some(((identity, _age), binder)) =
                        identities.first().zip(binders.first())
                    {
                        // Try to decrypt ticket
                        let factory = params.hash_factory();
                        if let Ok((psk, ticket_suite, _created_at, _age_add)) =
                            decrypt_ticket(&factory, ticket_key, identity)
                        {
                            // Verify the ticket's cipher suite matches
                            if ticket_suite == suite {
                                // Verify binder
                                if verify_binder(&params, &psk, msg_data, binder)? {
                                    verified_psk = Some(psk);
                                }
                            }
                        }
                    }
                }
            }
        }

        // --- Find matching key_share ---
        // Try each of the server's preferred groups against client key_shares
        let matched_share = self
            .config
            .supported_groups
            .iter()
            .find_map(|server_group| {
                client_key_shares
                    .iter()
                    .find(|(g, _)| g == server_group)
                    .map(|(g, k)| (*g, k.clone()))
            });

        if let Some((client_group, client_pub_key)) = matched_share {
            // --- Normal handshake path (with or without PSK) ---
            self.build_server_flight(
                msg_data,
                &ch,
                suite,
                params,
                client_group,
                &client_pub_key,
                &client_sig_algs,
                verified_psk,
            )
            .map(|a| ClientHelloResult::Actions(Box::new(a)))
        } else {
            // --- HelloRetryRequest path ---
            // Find a common group between server's groups and client's supported_groups
            let client_groups = client_groups.ok_or_else(|| {
                TlsError::HandshakeFailed(
                    "no matching key_share and no supported_groups extension".into(),
                )
            })?;

            let selected_group = self
                .config
                .supported_groups
                .iter()
                .find(|g| client_groups.contains(g))
                .copied()
                .ok_or_else(|| TlsError::HandshakeFailed("no common named group for HRR".into()))?;

            // Feed CH to transcript, then replace with message_hash
            self.transcript.update(msg_data)?;
            self.transcript.replace_with_message_hash()?;

            // Build HRR ServerHello
            let hrr = ServerHello {
                random: HELLO_RETRY_REQUEST_RANDOM,
                legacy_session_id: ch.legacy_session_id.clone(),
                cipher_suite: suite,
                extensions: vec![
                    build_supported_versions_sh(),
                    build_key_share_hrr(selected_group),
                ],
            };
            let hrr_msg = encode_server_hello(&hrr);

            // Feed HRR to transcript
            self.transcript.update(&hrr_msg)?;

            // Save state
            self.params = Some(params);
            self.negotiated_suite = Some(suite);
            self.state = HandshakeState::WaitClientHelloRetry;

            Ok(ClientHelloResult::HelloRetryRequest(
                HelloRetryRequestActions { hrr_msg, suite },
            ))
        }
    }

    /// Process a retried ClientHello (after HelloRetryRequest).
    ///
    /// The transcript already contains MessageHash + HRR.
    /// `msg_data` is the full handshake message including the 4-byte header.
    pub fn process_client_hello_retry(
        &mut self,
        msg_data: &[u8],
    ) -> Result<ClientHelloActions, TlsError> {
        if self.state != HandshakeState::WaitClientHelloRetry {
            return Err(TlsError::HandshakeFailed(
                "process_client_hello_retry: wrong state".into(),
            ));
        }

        let body = get_body(msg_data)?;
        let ch = decode_client_hello(body)?;

        // Parse extensions again
        let sig_alg_ext = ch
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::SIGNATURE_ALGORITHMS)
            .ok_or_else(|| {
                TlsError::HandshakeFailed("missing signature_algorithms in retried CH".into())
            })?;
        let client_sig_algs = parse_signature_algorithms_ch(&sig_alg_ext.data)?;

        let ks_ext = ch
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::KEY_SHARE)
            .ok_or_else(|| TlsError::HandshakeFailed("missing key_share in retried CH".into()))?;
        let client_key_shares = parse_key_share_ch(&ks_ext.data)?;

        // Re-parse compress_certificate from retried CH
        let client_cert_compression = ch
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::COMPRESS_CERTIFICATE)
            .map(|e| parse_compress_certificate(&e.data))
            .transpose()?
            .unwrap_or_default();
        self.client_cert_compression_algos = client_cert_compression;

        let suite = self
            .negotiated_suite
            .ok_or_else(|| TlsError::HandshakeFailed("no negotiated suite after HRR".into()))?;
        let params = self
            .params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no params after HRR".into()))?
            .clone();

        // Find matching key_share (should succeed now)
        let matched_share = self
            .config
            .supported_groups
            .iter()
            .find_map(|server_group| {
                client_key_shares
                    .iter()
                    .find(|(g, _)| g == server_group)
                    .map(|(g, k)| (*g, k.clone()))
            });

        let (client_group, client_pub_key) = matched_share.ok_or_else(|| {
            TlsError::HandshakeFailed("no matching key_share in retried CH".into())
        })?;

        self.build_server_flight(
            msg_data,
            &ch,
            suite,
            params,
            client_group,
            &client_pub_key,
            &client_sig_algs,
            None, // No PSK on HRR retry
        )
    }

    /// Build the server flight (SH + EE + [Cert + CV] + Finished) and derive all keys.
    ///
    /// Used by both normal and HRR paths after a matching key_share is found.
    /// If `verified_psk` is Some, PSK mode is used (skip Certificate + CertificateVerify).
    #[allow(clippy::too_many_arguments)]
    fn build_server_flight(
        &mut self,
        msg_data: &[u8],
        ch: &super::codec::ClientHello,
        suite: CipherSuite,
        params: CipherSuiteParams,
        client_group: NamedGroup,
        client_pub_key: &[u8],
        client_sig_algs: &[crate::crypt::SignatureScheme],
        verified_psk: Option<Vec<u8>>,
    ) -> Result<ClientHelloActions, TlsError> {
        let psk_mode = verified_psk.is_some();
        self.negotiated_group = Some(client_group);

        // Check if client offered early_data and server can accept it
        let client_offered_early_data = ch
            .extensions
            .iter()
            .any(|e| e.extension_type == ExtensionType::EARLY_DATA);
        let accept_early_data =
            psk_mode && client_offered_early_data && self.config.max_early_data_size > 0;

        // Feed ClientHello to transcript
        self.transcript.update(msg_data)?;

        // Key schedule — derive early secret before anything else
        let mut ks = KeySchedule::new(params.clone());
        ks.derive_early_secret(verified_psk.as_deref())?;

        // Derive early traffic keys for 0-RTT BEFORE feeding SH to transcript
        // (early traffic secret = Derive-Secret(ES, "c e traffic", Hash(CH)))
        let early_read_keys = if accept_early_data {
            let ch_transcript = self.transcript.current_hash()?;
            let early_secret = ks.derive_early_traffic_secret(&ch_transcript)?;
            crate::crypt::keylog::log_key(
                &self.config,
                "CLIENT_EARLY_TRAFFIC_SECRET",
                &self.client_random,
                &early_secret,
            );
            Some(TrafficKeys::derive(&params, &early_secret)?)
        } else {
            None
        };

        // Derive early exporter master secret (requires EarlySecret stage)
        let early_exporter_master_secret = if verified_psk.is_some() {
            let ch_hash = self.transcript.current_hash()?;
            ks.derive_early_exporter_master_secret(&ch_hash)?
        } else {
            Vec::new()
        };

        // Key exchange: KEM (encapsulate) or DH (generate + compute)
        let (shared_secret, server_key_share_bytes) = if client_group.is_kem() {
            KeyExchange::encapsulate(client_group, client_pub_key)?
        } else {
            let server_kx = KeyExchange::generate(client_group)?;
            let ss = server_kx.compute_shared_secret(client_pub_key)?;
            (ss, server_kx.public_key_bytes().to_vec())
        };

        // Build ServerHello
        let mut random = [0u8; 32];
        getrandom::getrandom(&mut random)
            .map_err(|_| TlsError::HandshakeFailed("random generation failed".into()))?;

        let mut sh_extensions = vec![
            build_supported_versions_sh(),
            build_key_share_sh(client_group, &server_key_share_bytes),
        ];
        if psk_mode {
            sh_extensions.push(build_pre_shared_key_sh(0));
        }

        let sh = ServerHello {
            random,
            legacy_session_id: ch.legacy_session_id.clone(),
            cipher_suite: suite,
            extensions: sh_extensions,
        };
        let server_hello_msg = encode_server_hello(&sh);
        self.transcript.update(&server_hello_msg)?;

        ks.derive_handshake_secret(&shared_secret)?;

        let transcript_hash = self.transcript.current_hash()?;
        let (client_hs_secret, server_hs_secret) =
            ks.derive_handshake_traffic_secrets(&transcript_hash)?;
        crate::crypt::keylog::log_key(
            &self.config,
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            &self.client_random,
            &client_hs_secret,
        );
        crate::crypt::keylog::log_key(
            &self.config,
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            &self.client_random,
            &server_hs_secret,
        );

        let server_hs_keys = TrafficKeys::derive(&params, &server_hs_secret)?;
        let client_hs_keys = TrafficKeys::derive(&params, &client_hs_secret)?;

        // Build EncryptedExtensions
        let mut ee_extensions = Vec::new();
        if accept_early_data {
            ee_extensions.push(build_early_data_ee());
        }
        if self.client_record_size_limit.is_some() && self.config.record_size_limit > 0 {
            ee_extensions.push(build_record_size_limit(
                self.config.record_size_limit.min(16385),
            ));
        }
        // ALPN in EncryptedExtensions (RFC 8446 §4.2)
        if let Some(ref proto) = self.negotiated_alpn {
            ee_extensions.push(build_alpn_selected(proto));
        }
        // Custom extensions for EncryptedExtensions
        ee_extensions.extend(crate::extensions::build_custom_extensions(
            &self.config.custom_extensions,
            crate::extensions::ExtensionContext::ENCRYPTED_EXTENSIONS,
        ));

        let ee = EncryptedExtensions {
            extensions: ee_extensions,
        };
        let encrypted_extensions_msg = encode_encrypted_extensions(&ee);
        self.transcript.update(&encrypted_extensions_msg)?;

        // Certificate + CertificateVerify (skip in PSK mode)
        let mut certificate_msg = Vec::new();
        let mut certificate_verify_msg = Vec::new();
        if !psk_mode {
            let cert_msg = CertificateMsg {
                certificate_request_context: vec![],
                certificate_list: self
                    .config
                    .certificate_chain
                    .iter()
                    .enumerate()
                    .map(|(i, cert_der)| {
                        let mut cert_extensions = Vec::new();
                        if i == 0 {
                            // Leaf certificate: add OCSP/SCT extensions
                            if self.client_wants_ocsp {
                                if let Some(ref ocsp) = self.config.ocsp_staple {
                                    cert_extensions.push(build_status_request_cert_entry(ocsp));
                                }
                            }
                            if self.client_wants_sct {
                                if let Some(ref sct) = self.config.sct_list {
                                    cert_extensions.push(build_sct_cert_entry(sct));
                                }
                            }
                        }
                        CertificateEntry {
                            cert_data: cert_der.clone(),
                            extensions: cert_extensions,
                        }
                    })
                    .collect(),
            };
            // Try certificate compression if both sides support it
            #[cfg(feature = "cert-compression")]
            {
                let negotiated_algo = self
                    .config
                    .cert_compression_algos
                    .iter()
                    .find(|a| self.client_cert_compression_algos.contains(a))
                    .copied();
                if let Some(algo) = negotiated_algo {
                    // Encode the uncompressed Certificate body (without handshake header)
                    let uncompressed = encode_certificate(&cert_msg);
                    let cert_body = &uncompressed[4..]; // skip 4-byte handshake header
                    let compressed_data = compress_certificate_body(cert_body)?;
                    let compressed_msg = CompressedCertificateMsg {
                        algorithm: algo,
                        uncompressed_length: cert_body.len() as u32,
                        compressed_data,
                    };
                    certificate_msg = encode_compressed_certificate(&compressed_msg);
                } else {
                    certificate_msg = encode_certificate(&cert_msg);
                }
            }
            #[cfg(not(feature = "cert-compression"))]
            {
                certificate_msg = encode_certificate(&cert_msg);
            }
            self.transcript.update(&certificate_msg)?;

            let private_key = self.config.private_key.as_ref().ok_or_else(|| {
                TlsError::HandshakeFailed("no server private key configured".into())
            })?;
            let sig_scheme = select_signature_scheme(private_key, client_sig_algs)?;
            let cv_transcript_hash = self.transcript.current_hash()?;
            let signature =
                sign_certificate_verify(private_key, sig_scheme, &cv_transcript_hash, true)?;

            let cv = CertificateVerifyMsg {
                algorithm: sig_scheme,
                signature,
            };
            certificate_verify_msg = encode_certificate_verify(&cv);
            self.transcript.update(&certificate_verify_msg)?;
        }

        // Build server Finished
        let server_finished_key = ks.derive_finished_key(&server_hs_secret)?;
        let finished_transcript = self.transcript.current_hash()?;
        let server_verify_data =
            ks.compute_finished_verify_data(&server_finished_key, &finished_transcript)?;
        let server_finished_msg = encode_finished(&server_verify_data);
        self.transcript.update(&server_finished_msg)?;

        // Derive application keys
        ks.derive_master_secret()?;
        let transcript_hash_sf = self.transcript.current_hash()?;
        let (client_app_secret, server_app_secret) =
            ks.derive_app_traffic_secrets(&transcript_hash_sf)?;
        crate::crypt::keylog::log_key(
            &self.config,
            "CLIENT_TRAFFIC_SECRET_0",
            &self.client_random,
            &client_app_secret,
        );
        crate::crypt::keylog::log_key(
            &self.config,
            "SERVER_TRAFFIC_SECRET_0",
            &self.client_random,
            &server_app_secret,
        );
        let server_app_keys = TrafficKeys::derive(&params, &server_app_secret)?;
        let client_app_keys = TrafficKeys::derive(&params, &client_app_secret)?;

        // Derive exporter master secret (RFC 8446 §7.5)
        let exporter_master_secret = ks.derive_exporter_master_secret(&transcript_hash_sf)?;
        crate::crypt::keylog::log_key(
            &self.config,
            "EXPORTER_SECRET",
            &self.client_random,
            &exporter_master_secret,
        );

        // Save state
        self.client_hs_secret = client_hs_secret;
        self.server_hs_secret = server_hs_secret;
        self.key_schedule = Some(ks);
        self.params = Some(params.clone());
        self.negotiated_suite = Some(suite);
        self.state = HandshakeState::WaitClientFinished;

        Ok(ClientHelloActions {
            server_hello_msg,
            encrypted_extensions_msg,
            certificate_msg,
            certificate_verify_msg,
            server_finished_msg,
            server_hs_keys,
            client_hs_keys,
            server_app_keys,
            client_app_keys,
            suite,
            client_app_secret,
            server_app_secret,
            cipher_params: params,
            exporter_master_secret,
            early_exporter_master_secret,
            psk_mode,
            early_data_accepted: accept_early_data,
            early_read_keys,
        })
    }

    /// Process an EndOfEarlyData message (adds to transcript).
    ///
    /// `msg_data` is the full handshake message including the 4-byte header.
    pub fn process_end_of_early_data(&mut self, msg_data: &[u8]) -> Result<(), TlsError> {
        self.transcript.update(msg_data)?;
        Ok(())
    }

    /// Process the client's Finished message.
    ///
    /// `msg_data` is the full handshake message including the 4-byte header.
    pub fn process_client_finished(
        &mut self,
        msg_data: &[u8],
    ) -> Result<ClientFinishedActions, TlsError> {
        if self.state != HandshakeState::WaitClientFinished {
            return Err(TlsError::HandshakeFailed(
                "process_client_finished: wrong state".into(),
            ));
        }

        let params = self
            .params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher suite params".into()))?
            .clone();
        let ks = self
            .key_schedule
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no key schedule".into()))?;

        let body = get_body(msg_data)?;
        let fin = decode_finished(body, params.hash_len)?;

        // Derive client finished key and verify
        let client_finished_key = ks.derive_finished_key(&self.client_hs_secret)?;
        // Transcript hash is everything up to (but not including) client Finished.
        // At this point, the transcript contains CH..server_Finished.
        let transcript_hash = self.transcript.current_hash()?;
        let expected = ks.compute_finished_verify_data(&client_finished_key, &transcript_hash)?;

        if !bool::from(fin.verify_data.ct_eq(&expected)) {
            return Err(TlsError::HandshakeFailed(
                "client Finished verify_data mismatch".into(),
            ));
        }

        // Feed client Finished to transcript
        self.transcript.update(msg_data)?;

        let suite = self
            .negotiated_suite
            .ok_or_else(|| TlsError::HandshakeFailed("no negotiated suite".into()))?;

        // Derive resumption master secret
        let transcript_hash_cf = self.transcript.current_hash()?;
        let resumption_master_secret = ks.derive_resumption_master_secret(&transcript_hash_cf)?;

        // Generate NewSessionTicket(s) if ticket_key is configured
        let mut new_session_ticket_msgs = Vec::new();
        if let Some(ref ticket_key) = self.config.ticket_key {
            let factory = params.hash_factory();

            // Generate ticket nonce and age_add
            let mut nonce_bytes = [0u8; 8];
            getrandom::getrandom(&mut nonce_bytes)
                .map_err(|_| TlsError::HandshakeFailed("nonce gen failed".into()))?;
            let mut age_add_bytes = [0u8; 4];
            getrandom::getrandom(&mut age_add_bytes)
                .map_err(|_| TlsError::HandshakeFailed("age_add gen failed".into()))?;
            let age_add = u32::from_be_bytes(age_add_bytes);

            // Derive PSK from resumption_master_secret + nonce
            let psk = ks.derive_resumption_psk(&resumption_master_secret, &nonce_bytes)?;

            // Get current time
            let created_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Encrypt ticket
            let ticket_data =
                encrypt_ticket(&factory, ticket_key, &psk, suite, created_at, age_add)?;

            let mut nst_extensions = Vec::new();
            if self.config.max_early_data_size > 0 {
                nst_extensions.push(build_early_data_nst(self.config.max_early_data_size));
            }
            let nst = NewSessionTicketMsg {
                ticket_lifetime: 3600, // 1 hour
                ticket_age_add: age_add,
                ticket_nonce: nonce_bytes.to_vec(),
                ticket: ticket_data,
                extensions: nst_extensions,
            };
            new_session_ticket_msgs.push(encode_new_session_ticket(&nst));
        }

        self.state = HandshakeState::Connected;
        Ok(ClientFinishedActions {
            suite,
            new_session_ticket_msgs,
            resumption_master_secret,
        })
    }
}

/// Verify a PSK binder against the truncated ClientHello.
///
/// The binder is computed as:
///   binder = HMAC(finished_key, Hash(truncated_CH))
/// where truncated_CH = full CH without the binder value(s).
fn verify_binder(
    params: &CipherSuiteParams,
    psk: &[u8],
    ch_msg: &[u8],
    binder: &[u8],
) -> Result<bool, TlsError> {
    // The binder size at the end of CH: 2 (binders list len) + 1 (binder entry len) + hash_len
    let binder_tail_size = 2 + 1 + params.hash_len;
    if ch_msg.len() <= binder_tail_size {
        return Ok(false);
    }
    let truncated_ch = &ch_msg[..ch_msg.len() - binder_tail_size];

    // Set up temporary key schedule for binder verification
    let mut ks = KeySchedule::new(params.clone());
    ks.derive_early_secret(Some(psk))?;
    let binder_key = ks.derive_binder_key(false)?; // resumption binder
    let finished_key = ks.derive_finished_key(&binder_key)?;

    // Hash the truncated CH
    let factory = params.hash_factory();
    let mut hasher = (*factory)();
    hasher.update(truncated_ch).map_err(TlsError::CryptoError)?;
    let mut hash = vec![0u8; params.hash_len];
    hasher.finish(&mut hash).map_err(TlsError::CryptoError)?;

    // Compute expected binder
    let expected = ks.compute_finished_verify_data(&finished_key, &hash)?;

    Ok(bool::from(binder.ct_eq(&expected)))
}

/// Extract handshake body from message data (skip 4-byte header).
fn get_body(msg_data: &[u8]) -> Result<&[u8], TlsError> {
    if msg_data.len() <= 4 {
        return Err(TlsError::HandshakeFailed(
            "handshake message too short".into(),
        ));
    }
    Ok(&msg_data[4..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerPrivateKey;
    use crate::TlsRole;

    fn make_server_config() -> TlsConfig {
        TlsConfig::builder()
            .role(TlsRole::Server)
            .certificate_chain(vec![vec![0x30, 0x82, 0x01, 0x00]]) // fake DER
            .private_key(ServerPrivateKey::Ed25519(vec![0x42; 32]))
            .verify_peer(false)
            .build()
    }

    #[test]
    fn test_server_handshake_init() {
        let config = make_server_config();
        let hs = ServerHandshake::new(config);
        assert_eq!(hs.state(), HandshakeState::WaitClientHello);
    }

    #[test]
    fn test_server_process_invalid_state() {
        let config = make_server_config();
        let mut hs = ServerHandshake::new(config);
        // Can't process client Finished before ClientHello
        let dummy = vec![20u8, 0, 0, 32, 0, 0, 0, 0];
        assert!(hs.process_client_finished(&dummy).is_err());
    }

    #[test]
    fn test_server_rejects_missing_supported_versions() {
        let config = make_server_config();
        let mut hs = ServerHandshake::new(config);

        // Build a minimal ClientHello without supported_versions
        use crate::handshake::codec::encode_client_hello;
        use crate::handshake::codec::ClientHello;
        use crate::handshake::extensions_codec::{
            build_key_share_ch, build_signature_algorithms, build_supported_groups,
        };

        let ch = ClientHello {
            random: [0xAA; 32],
            legacy_session_id: vec![],
            cipher_suites: vec![CipherSuite::TLS_AES_128_GCM_SHA256],
            extensions: vec![
                build_supported_groups(&[NamedGroup::X25519]),
                build_signature_algorithms(&[crate::crypt::SignatureScheme::ED25519]),
                build_key_share_ch(NamedGroup::X25519, &[0x55; 32]),
            ],
        };
        let msg = encode_client_hello(&ch);

        let result = hs.process_client_hello(&msg);
        match result {
            Err(e) => {
                let err_msg = format!("{e}");
                assert!(
                    err_msg.contains("supported_versions"),
                    "unexpected error: {err_msg}"
                );
            }
            Ok(_) => panic!("expected error for missing supported_versions"),
        }
    }

    /// Build a valid TLS 1.3 ClientHello message for server testing.
    fn build_valid_ch(suites: &[CipherSuite], group: NamedGroup, ks_data: &[u8]) -> Vec<u8> {
        use crate::handshake::extensions_codec::{
            build_key_share_ch, build_signature_algorithms, build_supported_groups,
            build_supported_versions_ch,
        };
        let ch = super::super::codec::ClientHello {
            random: [0xBB; 32],
            legacy_session_id: vec![],
            cipher_suites: suites.to_vec(),
            extensions: vec![
                build_supported_versions_ch(),
                build_supported_groups(&[group]),
                build_signature_algorithms(&[crate::crypt::SignatureScheme::ED25519]),
                build_key_share_ch(group, ks_data),
            ],
        };
        super::super::codec::encode_client_hello(&ch)
    }

    #[test]
    fn test_server_accepts_valid_client_hello() {
        let config = make_server_config();
        let mut hs = ServerHandshake::new(config);
        let msg = build_valid_ch(
            &[CipherSuite::TLS_AES_128_GCM_SHA256],
            NamedGroup::X25519,
            &[0x55; 32],
        );
        let result = hs.process_client_hello(&msg);
        assert!(result.is_ok(), "valid CH should succeed");
    }

    #[test]
    fn test_server_rejects_empty_cipher_suites() {
        let config = make_server_config();
        let mut hs = ServerHandshake::new(config);
        let msg = build_valid_ch(&[], NamedGroup::X25519, &[0x55; 32]);
        let result = hs.process_client_hello(&msg);
        assert!(result.is_err(), "empty cipher suites should be rejected");
    }

    #[test]
    fn test_server_rejects_no_key_share() {
        use crate::handshake::extensions_codec::{
            build_signature_algorithms, build_supported_groups, build_supported_versions_ch,
        };
        let config = make_server_config();
        let mut hs = ServerHandshake::new(config);
        // Build CH without key_share extension
        let ch = super::super::codec::ClientHello {
            random: [0xCC; 32],
            legacy_session_id: vec![],
            cipher_suites: vec![CipherSuite::TLS_AES_128_GCM_SHA256],
            extensions: vec![
                build_supported_versions_ch(),
                build_supported_groups(&[NamedGroup::X25519]),
                build_signature_algorithms(&[crate::crypt::SignatureScheme::ED25519]),
                // no key_share
            ],
        };
        let msg = super::super::codec::encode_client_hello(&ch);
        let result = hs.process_client_hello(&msg);
        // Should either error or trigger HRR
        match result {
            Ok(ClientHelloResult::HelloRetryRequest(_)) => {} // acceptable
            Err(_) => {}                                      // acceptable
            Ok(ClientHelloResult::Actions(_)) => {
                panic!("should not succeed without key_share")
            }
        }
    }

    #[test]
    fn test_server_triggers_hrr_wrong_group() {
        use crate::handshake::extensions_codec::{
            build_key_share_ch, build_signature_algorithms, build_supported_groups,
            build_supported_versions_ch,
        };
        // Server only supports X25519, but client offers secp256r1
        let config = TlsConfig::builder()
            .role(crate::TlsRole::Server)
            .certificate_chain(vec![vec![0x30, 0x82, 0x01, 0x00]])
            .private_key(ServerPrivateKey::Ed25519(vec![0x42; 32]))
            .verify_peer(false)
            .supported_groups(&[NamedGroup::X25519])
            .build();
        let mut hs = ServerHandshake::new(config);

        let ch = super::super::codec::ClientHello {
            random: [0xDD; 32],
            legacy_session_id: vec![],
            cipher_suites: vec![CipherSuite::TLS_AES_128_GCM_SHA256],
            extensions: vec![
                build_supported_versions_ch(),
                build_supported_groups(&[NamedGroup::SECP256R1, NamedGroup::X25519]),
                build_signature_algorithms(&[crate::crypt::SignatureScheme::ED25519]),
                // Key share only offers secp256r1 — X25519 not included
                build_key_share_ch(NamedGroup::SECP256R1, &[0x04; 65]),
            ],
        };
        let msg = super::super::codec::encode_client_hello(&ch);
        let result = hs.process_client_hello(&msg);
        match result {
            Ok(ClientHelloResult::HelloRetryRequest(hrr)) => {
                assert_eq!(hrr.suite, CipherSuite::TLS_AES_128_GCM_SHA256);
            }
            _other => panic!("expected HRR"),
        }
    }

    #[test]
    fn test_server_hrr_then_retry() {
        use crate::handshake::extensions_codec::{
            build_key_share_ch, build_signature_algorithms, build_supported_groups,
            build_supported_versions_ch,
        };
        let config = TlsConfig::builder()
            .role(crate::TlsRole::Server)
            .certificate_chain(vec![vec![0x30, 0x82, 0x01, 0x00]])
            .private_key(ServerPrivateKey::Ed25519(vec![0x42; 32]))
            .verify_peer(false)
            .supported_groups(&[NamedGroup::X25519])
            .build();
        let mut hs = ServerHandshake::new(config);

        // First CH: wrong group key share
        let ch1 = super::super::codec::ClientHello {
            random: [0xEE; 32],
            legacy_session_id: vec![],
            cipher_suites: vec![CipherSuite::TLS_AES_128_GCM_SHA256],
            extensions: vec![
                build_supported_versions_ch(),
                build_supported_groups(&[NamedGroup::SECP256R1, NamedGroup::X25519]),
                build_signature_algorithms(&[crate::crypt::SignatureScheme::ED25519]),
                build_key_share_ch(NamedGroup::SECP256R1, &[0x04; 65]),
            ],
        };
        let msg1 = super::super::codec::encode_client_hello(&ch1);
        let result1 = hs.process_client_hello(&msg1);
        assert!(matches!(
            result1,
            Ok(ClientHelloResult::HelloRetryRequest(_))
        ));

        // Second CH: correct group
        let ch2 = super::super::codec::ClientHello {
            random: [0xEE; 32],
            legacy_session_id: vec![],
            cipher_suites: vec![CipherSuite::TLS_AES_128_GCM_SHA256],
            extensions: vec![
                build_supported_versions_ch(),
                build_supported_groups(&[NamedGroup::SECP256R1, NamedGroup::X25519]),
                build_signature_algorithms(&[crate::crypt::SignatureScheme::ED25519]),
                build_key_share_ch(NamedGroup::X25519, &[0x55; 32]),
            ],
        };
        let msg2 = super::super::codec::encode_client_hello(&ch2);
        let result2 = hs.process_client_hello_retry(&msg2);
        assert!(result2.is_ok(), "retried CH should succeed");
    }

    #[test]
    fn test_server_no_supported_groups_still_works() {
        use crate::handshake::extensions_codec::{
            build_key_share_ch, build_signature_algorithms, build_supported_versions_ch,
        };
        let config = make_server_config();
        let mut hs = ServerHandshake::new(config);
        // CH without supported_groups extension but with a valid key_share
        let ch = super::super::codec::ClientHello {
            random: [0xFF; 32],
            legacy_session_id: vec![],
            cipher_suites: vec![CipherSuite::TLS_AES_128_GCM_SHA256],
            extensions: vec![
                build_supported_versions_ch(),
                build_signature_algorithms(&[crate::crypt::SignatureScheme::ED25519]),
                build_key_share_ch(NamedGroup::X25519, &[0x55; 32]),
            ],
        };
        let msg = super::super::codec::encode_client_hello(&ch);
        let result = hs.process_client_hello(&msg);
        // Server can proceed if a usable key_share is found
        assert!(
            result.is_ok(),
            "should work with key_share even without supported_groups"
        );
    }

    #[test]
    fn test_server_chacha20_suite() {
        let config = TlsConfig::builder()
            .role(crate::TlsRole::Server)
            .certificate_chain(vec![vec![0x30, 0x82, 0x01, 0x00]])
            .private_key(ServerPrivateKey::Ed25519(vec![0x42; 32]))
            .cipher_suites(&[CipherSuite::TLS_CHACHA20_POLY1305_SHA256])
            .verify_peer(false)
            .build();
        let mut hs = ServerHandshake::new(config);
        let msg = build_valid_ch(
            &[CipherSuite::TLS_CHACHA20_POLY1305_SHA256],
            NamedGroup::X25519,
            &[0x55; 32],
        );
        let result = hs.process_client_hello(&msg);
        match result {
            Ok(ClientHelloResult::Actions(a)) => {
                assert_eq!(a.suite, CipherSuite::TLS_CHACHA20_POLY1305_SHA256);
            }
            _other => panic!("expected Actions with CHA CHA20"),
        }
    }

    #[test]
    fn test_server_aes256_gcm_suite() {
        let config = TlsConfig::builder()
            .role(crate::TlsRole::Server)
            .certificate_chain(vec![vec![0x30, 0x82, 0x01, 0x00]])
            .private_key(ServerPrivateKey::Ed25519(vec![0x42; 32]))
            .cipher_suites(&[CipherSuite::TLS_AES_256_GCM_SHA384])
            .verify_peer(false)
            .build();
        let mut hs = ServerHandshake::new(config);
        let msg = build_valid_ch(
            &[CipherSuite::TLS_AES_256_GCM_SHA384],
            NamedGroup::X25519,
            &[0x55; 32],
        );
        let result = hs.process_client_hello(&msg);
        match result {
            Ok(ClientHelloResult::Actions(a)) => {
                assert_eq!(a.suite, CipherSuite::TLS_AES_256_GCM_SHA384);
            }
            _other => panic!("expected Actions with AES-256-GCM"),
        }
    }

    #[test]
    fn test_cipher_client_preference_tls13() {
        // Server supports AES-256-GCM first, client wants AES-128-GCM first
        let config = TlsConfig::builder()
            .role(crate::TlsRole::Server)
            .certificate_chain(vec![vec![0x30, 0x82, 0x01, 0x00]])
            .private_key(ServerPrivateKey::Ed25519(vec![0x42; 32]))
            .cipher_suites(&[
                CipherSuite::TLS_AES_256_GCM_SHA384,
                CipherSuite::TLS_AES_128_GCM_SHA256,
            ])
            .cipher_server_preference(false)
            .verify_peer(false)
            .build();
        let mut hs = ServerHandshake::new(config);
        // Client offers AES-128-GCM first, AES-256-GCM second
        let msg = build_valid_ch(
            &[
                CipherSuite::TLS_AES_128_GCM_SHA256,
                CipherSuite::TLS_AES_256_GCM_SHA384,
            ],
            NamedGroup::X25519,
            &[0x55; 32],
        );
        let result = hs.process_client_hello(&msg);
        match result {
            Ok(ClientHelloResult::Actions(a)) => {
                // Client preference: AES-128-GCM wins
                assert_eq!(a.suite, CipherSuite::TLS_AES_128_GCM_SHA256);
            }
            _other => panic!("expected Actions"),
        }
    }

    #[test]
    fn test_server_double_ch_rejected() {
        let config = make_server_config();
        let mut hs = ServerHandshake::new(config);
        let msg = build_valid_ch(
            &[CipherSuite::TLS_AES_128_GCM_SHA256],
            NamedGroup::X25519,
            &[0x55; 32],
        );
        // First CH should succeed
        let _ = hs.process_client_hello(&msg).unwrap();
        // Second CH should fail (wrong state)
        let result = hs.process_client_hello(&msg);
        assert!(result.is_err(), "second CH should be rejected");
    }

    #[test]
    fn test_server_process_finished_correct() {
        let config = make_server_config();
        let mut hs = ServerHandshake::new(config);
        let msg = build_valid_ch(
            &[CipherSuite::TLS_AES_128_GCM_SHA256],
            NamedGroup::X25519,
            &[0x55; 32],
        );
        let _actions = match hs.process_client_hello(&msg).unwrap() {
            ClientHelloResult::Actions(a) => a,
            _ => panic!("expected Actions"),
        };
        // After processing CH, server should be in WaitClientFinished state
        assert_eq!(hs.state(), HandshakeState::WaitClientFinished);
    }

    #[test]
    fn test_server_process_finished_wrong() {
        let config = make_server_config();
        let mut hs = ServerHandshake::new(config);
        let msg = build_valid_ch(
            &[CipherSuite::TLS_AES_128_GCM_SHA256],
            NamedGroup::X25519,
            &[0x55; 32],
        );
        let _ = hs.process_client_hello(&msg).unwrap();

        // Build a Finished with wrong verify_data
        let wrong_verify = vec![0xDE; 32];
        let mut fin_msg = vec![20u8]; // HandshakeType::Finished
        let len = wrong_verify.len() as u32;
        fin_msg.push((len >> 16) as u8);
        fin_msg.push((len >> 8) as u8);
        fin_msg.push(len as u8);
        fin_msg.extend_from_slice(&wrong_verify);

        let result = hs.process_client_finished(&fin_msg);
        assert!(result.is_err(), "wrong verify_data should fail");
    }

    #[test]
    fn test_server_rejects_unsupported_version() {
        use crate::handshake::extensions_codec::{
            build_key_share_ch, build_signature_algorithms, build_supported_groups,
        };
        let config = make_server_config();
        let mut hs = ServerHandshake::new(config);

        // Build CH with only TLS 1.2 in supported_versions
        let mut sv_data = vec![0x02]; // list length = 2
        sv_data.extend_from_slice(&0x0303u16.to_be_bytes()); // TLS 1.2
        let sv_ext = crate::extensions::Extension {
            extension_type: crate::extensions::ExtensionType::SUPPORTED_VERSIONS,
            data: sv_data,
        };

        let ch = super::super::codec::ClientHello {
            random: [0x11; 32],
            legacy_session_id: vec![],
            cipher_suites: vec![CipherSuite::TLS_AES_128_GCM_SHA256],
            extensions: vec![
                sv_ext,
                build_supported_groups(&[NamedGroup::X25519]),
                build_signature_algorithms(&[crate::crypt::SignatureScheme::ED25519]),
                build_key_share_ch(NamedGroup::X25519, &[0x55; 32]),
            ],
        };
        let msg = super::super::codec::encode_client_hello(&ch);
        let result = hs.process_client_hello(&msg);
        assert!(
            result.is_err(),
            "TLS 1.2 only should be rejected by 1.3 server"
        );
    }

    #[test]
    fn test_tls13_server_parses_sig_algs_cert() {
        use super::super::extensions_codec::{
            build_key_share_ch, build_signature_algorithms, build_signature_algorithms_cert,
            build_supported_groups, build_supported_versions_ch,
        };
        use crate::crypt::SignatureScheme;

        let server_config = TlsConfig::builder()
            .role(crate::TlsRole::Server)
            .certificate_chain(vec![vec![0x30, 0x82, 0x01, 0x00]])
            .private_key(crate::config::ServerPrivateKey::Ed25519(vec![0x42; 32]))
            .verify_peer(false)
            .build();
        let mut hs = ServerHandshake::new(server_config);

        // Build a ClientHello with signature_algorithms_cert
        let ch = super::super::codec::ClientHello {
            random: [0x42; 32],
            legacy_session_id: vec![],
            cipher_suites: vec![CipherSuite::TLS_AES_128_GCM_SHA256],
            extensions: vec![
                build_supported_versions_ch(),
                build_supported_groups(&[NamedGroup::X25519]),
                build_signature_algorithms(&[SignatureScheme::ED25519]),
                build_signature_algorithms_cert(&[
                    SignatureScheme::RSA_PSS_RSAE_SHA256,
                    SignatureScheme::ECDSA_SECP256R1_SHA256,
                ]),
                build_key_share_ch(NamedGroup::X25519, &[0x55; 32]),
            ],
        };
        let msg = super::super::codec::encode_client_hello(&ch);
        let _result = hs.process_client_hello(&msg);
        // The server should have parsed sig_algs_cert
        assert_eq!(hs.client_sig_algs_cert().len(), 2);
        assert_eq!(
            hs.client_sig_algs_cert()[0],
            SignatureScheme::RSA_PSS_RSAE_SHA256
        );
        assert_eq!(
            hs.client_sig_algs_cert()[1],
            SignatureScheme::ECDSA_SECP256R1_SHA256
        );
    }

    #[test]
    fn test_tls13_sig_algs_cert_empty_default() {
        let server_config = TlsConfig::builder()
            .role(crate::TlsRole::Server)
            .verify_peer(false)
            .build();
        let hs = ServerHandshake::new(server_config);
        // No sig_algs_cert by default
        assert!(hs.client_sig_algs_cert().is_empty());
    }

    #[test]
    fn test_tls13_server_parses_certificate_authorities() {
        use super::super::extensions_codec::{
            build_certificate_authorities, build_key_share_ch, build_signature_algorithms,
            build_supported_groups, build_supported_versions_ch,
        };
        use crate::crypt::SignatureScheme;

        let server_config = TlsConfig::builder()
            .role(crate::TlsRole::Server)
            .certificate_chain(vec![vec![0x30, 0x82, 0x01, 0x00]])
            .private_key(crate::config::ServerPrivateKey::Ed25519(vec![0x42; 32]))
            .verify_peer(false)
            .build();
        let mut hs = ServerHandshake::new(server_config);

        // Build a ClientHello with certificate_authorities extension
        let dn1 = vec![0x30, 0x06, 0x31, 0x04, 0x30, 0x02, 0x06, 0x00];
        let dn2 = vec![0x30, 0x03, 0x31, 0x01, 0x00];
        let ch = super::super::codec::ClientHello {
            random: [0x42; 32],
            legacy_session_id: vec![],
            cipher_suites: vec![CipherSuite::TLS_AES_128_GCM_SHA256],
            extensions: vec![
                build_supported_versions_ch(),
                build_supported_groups(&[NamedGroup::X25519]),
                build_signature_algorithms(&[SignatureScheme::ED25519]),
                build_key_share_ch(NamedGroup::X25519, &[0x55; 32]),
                build_certificate_authorities(&[dn1.clone(), dn2.clone()]),
            ],
        };
        let msg = super::super::codec::encode_client_hello(&ch);
        let _result = hs.process_client_hello(&msg);

        // Server should have parsed the certificate_authorities
        let cas = hs.client_certificate_authorities();
        assert_eq!(cas.len(), 2);
        assert_eq!(cas[0], dn1);
        assert_eq!(cas[1], dn2);
    }

    #[test]
    fn test_tls13_certificate_authorities_empty_default() {
        let server_config = TlsConfig::builder()
            .role(crate::TlsRole::Server)
            .verify_peer(false)
            .build();
        let hs = ServerHandshake::new(server_config);
        // No certificate_authorities by default
        assert!(hs.client_certificate_authorities().is_empty());
    }

    #[test]
    fn test_server_secp256r1_key_share() {
        // Test with SECP256R1 key share (65-byte uncompressed point)
        let config = TlsConfig::builder()
            .role(crate::TlsRole::Server)
            .certificate_chain(vec![vec![0x30, 0x82, 0x01, 0x00]])
            .private_key(ServerPrivateKey::Ed25519(vec![0x42; 32]))
            .supported_groups(&[NamedGroup::SECP256R1])
            .verify_peer(false)
            .build();
        let mut hs = ServerHandshake::new(config);
        // Use a plausible (but not real) 65-byte uncompressed public key for P-256
        let msg = build_valid_ch(
            &[CipherSuite::TLS_AES_128_GCM_SHA256],
            NamedGroup::SECP256R1,
            &[0x04; 65],
        );
        let result = hs.process_client_hello(&msg);
        // Should either produce an error (due to invalid point) or succeed
        // The server should at least parse the ClientHello correctly
        match result {
            Ok(ClientHelloResult::Actions(a)) => {
                assert_eq!(a.suite, CipherSuite::TLS_AES_128_GCM_SHA256);
            }
            // Invalid point → handshake error is also acceptable
            Err(_) => {}
            Ok(ClientHelloResult::HelloRetryRequest(_)) => {
                panic!("should not HRR when key share group matches")
            }
        }
    }

    #[test]
    fn test_server_no_common_cipher_suite() {
        // Server only supports AES-256, client only offers AES-128
        let config = TlsConfig::builder()
            .role(crate::TlsRole::Server)
            .certificate_chain(vec![vec![0x30, 0x82, 0x01, 0x00]])
            .private_key(ServerPrivateKey::Ed25519(vec![0x42; 32]))
            .cipher_suites(&[CipherSuite::TLS_AES_256_GCM_SHA384])
            .verify_peer(false)
            .build();
        let mut hs = ServerHandshake::new(config);
        let msg = build_valid_ch(
            &[CipherSuite::TLS_CHACHA20_POLY1305_SHA256],
            NamedGroup::X25519,
            &[0x55; 32],
        );
        let result = hs.process_client_hello(&msg);
        assert!(result.is_err(), "no common suite should be rejected");
    }

    #[test]
    fn test_server_cipher_server_preference_default() {
        // Default is server preference: server's first matching suite wins
        let config = TlsConfig::builder()
            .role(crate::TlsRole::Server)
            .certificate_chain(vec![vec![0x30, 0x82, 0x01, 0x00]])
            .private_key(ServerPrivateKey::Ed25519(vec![0x42; 32]))
            .cipher_suites(&[
                CipherSuite::TLS_AES_256_GCM_SHA384,
                CipherSuite::TLS_AES_128_GCM_SHA256,
            ])
            .verify_peer(false)
            .build();
        let mut hs = ServerHandshake::new(config);
        // Client offers AES-128 first
        let msg = build_valid_ch(
            &[
                CipherSuite::TLS_AES_128_GCM_SHA256,
                CipherSuite::TLS_AES_256_GCM_SHA384,
            ],
            NamedGroup::X25519,
            &[0x55; 32],
        );
        let result = hs.process_client_hello(&msg);
        match result {
            Ok(ClientHelloResult::Actions(a)) => {
                // Server preference: AES-256-GCM wins (server's first)
                assert_eq!(a.suite, CipherSuite::TLS_AES_256_GCM_SHA384);
            }
            _other => panic!("expected Actions"),
        }
    }

    #[test]
    fn test_server_client_hello_retry_then_wrong_group_still_fails() {
        use crate::handshake::extensions_codec::{
            build_key_share_ch, build_signature_algorithms, build_supported_groups,
            build_supported_versions_ch,
        };
        // Server only supports X25519
        let config = TlsConfig::builder()
            .role(crate::TlsRole::Server)
            .certificate_chain(vec![vec![0x30, 0x82, 0x01, 0x00]])
            .private_key(ServerPrivateKey::Ed25519(vec![0x42; 32]))
            .verify_peer(false)
            .supported_groups(&[NamedGroup::X25519])
            .build();
        let mut hs = ServerHandshake::new(config);

        // First CH: wrong group → HRR
        let ch1 = super::super::codec::ClientHello {
            random: [0xEE; 32],
            legacy_session_id: vec![],
            cipher_suites: vec![CipherSuite::TLS_AES_128_GCM_SHA256],
            extensions: vec![
                build_supported_versions_ch(),
                build_supported_groups(&[NamedGroup::SECP256R1, NamedGroup::X25519]),
                build_signature_algorithms(&[crate::crypt::SignatureScheme::ED25519]),
                build_key_share_ch(NamedGroup::SECP256R1, &[0x04; 65]),
            ],
        };
        let msg1 = super::super::codec::encode_client_hello(&ch1);
        let result1 = hs.process_client_hello(&msg1);
        assert!(matches!(
            result1,
            Ok(ClientHelloResult::HelloRetryRequest(_))
        ));

        // Second CH: STILL wrong group → error
        let ch2 = super::super::codec::ClientHello {
            random: [0xEE; 32],
            legacy_session_id: vec![],
            cipher_suites: vec![CipherSuite::TLS_AES_128_GCM_SHA256],
            extensions: vec![
                build_supported_versions_ch(),
                build_supported_groups(&[NamedGroup::SECP256R1, NamedGroup::X25519]),
                build_signature_algorithms(&[crate::crypt::SignatureScheme::ED25519]),
                build_key_share_ch(NamedGroup::SECP256R1, &[0x04; 65]), // still wrong!
            ],
        };
        let msg2 = super::super::codec::encode_client_hello(&ch2);
        let result2 = hs.process_client_hello_retry(&msg2);
        // Should fail since client didn't fix the group
        assert!(result2.is_err());
    }
}
