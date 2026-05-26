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
use crate::crypt::{CipherSuiteParams, HashAlgId, NamedGroup, SignatureScheme};
use crate::extensions::ExtensionType;
use crate::CipherSuite;
use hitls_crypto::provider::Digest;
use hitls_types::TlsError;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

#[cfg(feature = "cert-compression")]
use super::codec::{
    compress_certificate_body, encode_compressed_certificate, CompressedCertificateMsg,
};
use super::codec::{
    decode_client_hello, decode_finished, encode_certificate, encode_certificate_request,
    encode_certificate_verify, encode_encrypted_extensions, encode_finished,
    encode_new_session_ticket, encode_server_hello, CertCompressionAlgorithm, CertificateEntry,
    CertificateMsg, CertificateRequestMsg, CertificateVerifyMsg, EncryptedExtensions,
    NewSessionTicketMsg, ServerHello, HELLO_RETRY_REQUEST_RANDOM,
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
use super::signing::sign_certificate_verify;
use super::HandshakeState;

/// Result from processing ClientHello.
pub struct ClientHelloActions {
    /// Raw ServerHello handshake message bytes (sent as plaintext record).
    pub server_hello_msg: Vec<u8>,
    /// Raw EncryptedExtensions handshake message bytes.
    pub encrypted_extensions_msg: Vec<u8>,
    /// Raw CertificateRequest handshake message bytes (Phase T97).
    /// Empty when mTLS is not enabled (`config.verify_client_cert == false`)
    /// or in PSK mode. When non-empty it is sent immediately after
    /// EncryptedExtensions per RFC 8446 §4.3.2.
    pub certificate_request_msg: Vec<u8>,
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
    alg: HashAlgId,
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
    getrandom::fill(&mut nonce)
        .map_err(|_| TlsError::HandshakeFailed("ticket nonce gen failed".into()))?;

    // Derive key stream
    let key_stream = hkdf_expand(alg, ticket_key, &nonce, plaintext.len())?;

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
    let (mac, mac_len) = hmac_hash(alg, ticket_key, &mac_input)?;

    let mut ticket = Vec::with_capacity(12 + ciphertext.len() + mac_len);
    ticket.extend_from_slice(&nonce);
    ticket.extend_from_slice(&ciphertext);
    ticket.extend_from_slice(&mac[..mac_len]);
    Ok(ticket)
}

/// Decrypt a ticket to recover (psk, suite, created_at, age_add).
pub(crate) fn decrypt_ticket(
    alg: HashAlgId,
    ticket_key: &[u8],
    ticket: &[u8],
) -> Result<(Vec<u8>, CipherSuite, u64, u32), TlsError> {
    let mac_len = crate::crypt::DigestVariant::output_size_for(alg);
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
    let (expected_mac, expected_mac_len) = hmac_hash(alg, ticket_key, &mac_input)?;

    if !bool::from(mac.ct_eq(&expected_mac[..expected_mac_len])) {
        return Err(TlsError::HandshakeFailed(
            "ticket MAC verification failed".into(),
        ));
    }

    // Derive key stream and decrypt
    let key_stream = hkdf_expand(alg, ticket_key, nonce, ciphertext.len())?;
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
    /// Phase I95: ECH-accept state across HRR. `true` once `try_unwrap_ech`
    /// has successfully recovered an inner CH on the initial CH; the
    /// retried CH MUST also offer ECH (downgrade-protection) and the
    /// server unwraps it the same way.
    #[cfg(feature = "ech")]
    ech_accepted_on_initial: bool,
    /// Phase T97: in-handshake mTLS flag — `true` when the server
    /// emitted a CertificateRequest in the EE-flight and is waiting
    /// for the client's Certificate / CertificateVerify before the
    /// client Finished. Used by the do-handshake macro to know
    /// whether to read those messages.
    pub expecting_client_cert: bool,
    /// Phase T106 — client's ClientHello carried the `early_data`
    /// extension. Used by the do-handshake macro to enter "skip
    /// rejected early data" mode in two places (per RFC 8446
    /// §4.2.10): tolerating non-Handshake records between CH1 and
    /// CH2 after HRR, and tolerating AEAD-decrypt failures between
    /// server Finished and client Finished. The flag is set
    /// regardless of whether we actually accept early data
    /// (`early_data_accepted` covers the accept side; this flag
    /// covers the reject-but-tolerate side).
    pub client_offered_early_data: bool,
}

struct ServerFlightParams<'a> {
    msg_data: &'a [u8],
    ch: &'a super::codec::ClientHello,
    suite: CipherSuite,
    params: CipherSuiteParams,
    client_group: NamedGroup,
    client_pub_key: &'a [u8],
    client_sig_algs: &'a [crate::crypt::SignatureScheme],
    verified_psk: Option<Vec<u8>>,
    /// Phase T120 — `psk_ke` (RFC 8446 §4.2.9 mode 0): PSK resumption
    /// without (EC)DHE. When true, no `key_share` is sent in the
    /// ServerHello and the Handshake Secret is extracted over a
    /// Hash.length zero string instead of an ECDHE shared secret.
    psk_ke: bool,
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
        let transcript = TranscriptHash::new(HashAlgId::Sha256);
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
            #[cfg(feature = "ech")]
            ech_accepted_on_initial: false,
            expecting_client_cert: false,
            client_offered_early_data: false,
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

        // Phase I93/I94/I95: ECH split-CH unwrap. If `ech_keypairs` is
        // configured and the outer CH carries an `encrypted_client_hello`
        // extension whose `config_id` matches one of our published
        // configs, decrypt to recover the inner CH and process THAT
        // instead. config_id mismatch is treated as GREASE (process
        // outer); config_id match with decrypt failure is a hard error.
        // On ECH accept, set `ech_accepted_on_initial = true` so a
        // subsequent retried CH (after HRR) can enforce continuity
        // (Phase I95: downgrade-protection).
        #[cfg(feature = "ech")]
        let _inner_storage;
        #[cfg(feature = "ech")]
        let msg_data: &[u8] = if !self.config.ech_keypairs.is_empty() {
            match Self::try_unwrap_ech(msg_data, &self.config.ech_keypairs)? {
                Some(inner) => {
                    _inner_storage = inner;
                    self.ech_accepted_on_initial = true;
                    &_inner_storage[..]
                }
                None => msg_data,
            }
        } else {
            msg_data
        };

        let body = get_body(msg_data)?;
        let ch = decode_client_hello(body)?;
        self.client_random = ch.random;

        // Phase T106 — surface the offered-but-not-necessarily-accepted
        // early_data state on the handshake EARLY (before HRR vs
        // full-flight branching) so the do-handshake macro can enter
        // "skip rejected early data" mode in both code paths
        // (RFC 8446 §4.2.10).
        self.client_offered_early_data = ch
            .extensions
            .iter()
            .any(|e| e.extension_type == ExtensionType::EARLY_DATA);

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

        // signature_algorithms — RFC 8446 §4.2.3: required for cert-based
        // authentication; MAY be omitted for PSK-only resumption (the
        // PSK binder + chosen ticket suite supply the auth). Phase T109
        // makes the extraction tolerant; the non-PSK build path below
        // re-checks that client_sig_algs is non-empty before invoking
        // `select_signature_scheme_for_cert`.
        let client_sig_algs = match ch
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::SIGNATURE_ALGORITHMS)
        {
            Some(ext) => parse_signature_algorithms_ch(&ext.data)?,
            None => Vec::new(),
        };

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
            self.transcript = TranscriptHash::new(HashAlgId::Sha384);
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
        // Phase T120 — `psk_ke` (PSK without (EC)DHE); set below.
        let mut psk_ke = false;
        if let (Some(psk_e), Some(modes_e)) = (psk_ext, psk_modes_ext) {
            // RFC 8446 §4.2.9 — the client advertises its supported PSK
            // key exchange modes. `psk_dhe_ke` (1) is preferred (forward
            // secrecy); `psk_ke` (0) — PSK without (EC)DHE — is taken
            // only when the client offers it alone (Phase T120).
            let modes = parse_psk_key_exchange_modes(&modes_e.data)?;
            if modes.contains(&0x01) || modes.contains(&0x00) {
                let (identities, binders) = parse_pre_shared_key_ch(&psk_e.data)?;
                if let Some(((identity, _age), binder)) = identities.first().zip(binders.first()) {
                    // Path 1 — resumption: decrypt the ticket from
                    // `identity` using the configured ticket_key.
                    if let Some(ref ticket_key) = self.config.ticket_key {
                        if let Ok((psk, ticket_suite, _created_at, _age_add)) =
                            decrypt_ticket(params.hash_alg_id(), ticket_key, identity)
                        {
                            // RFC 8446 §4.2.11: the ticket binds the
                            // PSK to a cipher suite; reject mismatches.
                            if ticket_suite == suite
                                && verify_binder(&params, &psk, msg_data, binder, false)?
                            {
                                verified_psk = Some(psk);
                            }
                        }
                    }
                    // Path 2 — external PSK (Phase T119): when no ticket
                    // matched, fall back to the out-of-band PSK configured
                    // on `TlsConfig` (`--psk` / `--psk-identity` on the
                    // CLI). Per RFC 8446 §4.2.11.2 the binder uses the
                    // `"ext binder"` label. The external PSK length must
                    // equal the negotiated suite's hash output (§4.2.11);
                    // otherwise the binder check fails and we silently
                    // fall through to non-PSK handshake.
                    if verified_psk.is_none() {
                        if let (Some(ref cfg_id), Some(ref cfg_psk)) =
                            (&self.config.psk_identity, &self.config.psk)
                        {
                            if identity == cfg_id
                                && cfg_psk.len() == params.hash_len
                                && verify_binder(&params, cfg_psk, msg_data, binder, true)?
                            {
                                verified_psk = Some(cfg_psk.clone());
                            }
                        }
                    }
                }
            }
            // Phase T120 — once a PSK is verified, fall to `psk_ke` when
            // the client did not also offer `psk_dhe_ke`.
            if verified_psk.is_some() && !modes.contains(&0x01) {
                psk_ke = true;
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
            self.build_server_flight(ServerFlightParams {
                msg_data,
                ch: &ch,
                suite,
                params,
                client_group,
                client_pub_key: &client_pub_key,
                client_sig_algs: &client_sig_algs,
                verified_psk,
                psk_ke,
            })
            .map(|a| ClientHelloResult::Actions(Box::new(a)))
        } else {
            // --- HelloRetryRequest path ---
            // Find a common group between server's groups and client's supported_groups
            let client_groups = client_groups.ok_or_else(|| {
                TlsError::HandshakeFailed(
                    "no matching key_share and no supported_groups extension".into(),
                )
            })?;

            // RFC 8446 §4.2.7: the client's `supported_groups` are ordered
            // from most preferred to least preferred. For HRR we honour the
            // client's order (matching OpenSSL / BoringSSL / Go behaviour),
            // not our own — picking the first client-preferred group that we
            // actually support. This is what tlsfuzzer / typical
            // client-driven interop checks assume.
            let selected_group = client_groups
                .iter()
                .find(|g| self.config.supported_groups.contains(g))
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

        // Phase I95: HRR-with-ECH unwrap. The retried CH must follow the
        // same ECH discipline as the initial CH:
        //   - If ECH was accepted on the initial CH (ech_accepted_on_initial
        //     == true), the retried CH MUST also offer ECH and decrypt
        //     successfully — otherwise an attacker could downgrade the
        //     handshake by stripping the ECH ext on CH2.
        //   - If ECH was NOT accepted on initial (config_id mismatch /
        //     no ECH), the retried CH is processed as outer (no special
        //     enforcement on CH2).
        // The cookie carried in HRR.cookie already binds CH2 to the inner
        // CH1 transcript, so swapping msg_data → inner here lets the
        // existing transcript machinery do the right thing.
        #[cfg(feature = "ech")]
        let _inner_storage;
        #[cfg(feature = "ech")]
        let msg_data: &[u8] = if !self.config.ech_keypairs.is_empty() {
            match Self::try_unwrap_ech(msg_data, &self.config.ech_keypairs)? {
                Some(inner) => {
                    _inner_storage = inner;
                    &_inner_storage[..]
                }
                None => {
                    if self.ech_accepted_on_initial {
                        return Err(TlsError::HandshakeFailed(
                            "ECH downgrade after HRR: initial CH was \
                             ECH-accepted but retried CH carries no \
                             matching ECH offer"
                                .into(),
                        ));
                    }
                    msg_data
                }
            }
        } else if self.ech_accepted_on_initial {
            return Err(TlsError::HandshakeFailed(
                "ECH state lost between initial CH and retry — \
                 server config no longer has ech_keypairs"
                    .into(),
            ));
        } else {
            msg_data
        };

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

        self.build_server_flight(ServerFlightParams {
            msg_data,
            ch: &ch,
            suite,
            params,
            client_group,
            client_pub_key: &client_pub_key,
            client_sig_algs: &client_sig_algs,
            verified_psk: None, // No PSK on HRR retry
            psk_ke: false,      // psk_ke needs a verified PSK
        })
    }

    /// Build the server flight (SH + EE + [Cert + CV] + Finished) and derive all keys.
    ///
    /// Used by both normal and HRR paths after a matching key_share is found.
    /// If `verified_psk` is Some, PSK mode is used (skip Certificate + CertificateVerify).
    fn build_server_flight(
        &mut self,
        p: ServerFlightParams<'_>,
    ) -> Result<ClientHelloActions, TlsError> {
        let psk_mode = p.verified_psk.is_some();
        self.negotiated_group = Some(p.client_group);

        // Check if client offered early_data and server can accept it
        let client_offered_early_data =
            p.ch.extensions
                .iter()
                .any(|e| e.extension_type == ExtensionType::EARLY_DATA);
        let accept_early_data =
            psk_mode && client_offered_early_data && self.config.max_early_data_size > 0;

        // Feed ClientHello to transcript
        self.transcript.update(p.msg_data)?;

        // Key schedule — derive early secret before anything else
        let mut ks = KeySchedule::new(p.params.clone());
        ks.derive_early_secret(p.verified_psk.as_deref())?;

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
            Some(TrafficKeys::derive(&p.params, &early_secret)?)
        } else {
            None
        };

        // Derive early exporter master secret (requires EarlySecret stage)
        let early_exporter_master_secret = if p.verified_psk.is_some() {
            let ch_hash = self.transcript.current_hash()?;
            ks.derive_early_exporter_master_secret(&ch_hash)?
        } else {
            Vec::new()
        };

        // Key exchange. Phase T120 — `psk_ke` (PSK without (EC)DHE):
        // no key_share is sent and the Handshake Secret is extracted
        // over a Hash.length zero string (RFC 8446 §4.2.9 / §7.1).
        let (shared_secret, server_key_share_bytes) = if p.psk_ke {
            (vec![0u8; p.params.hash_len], Vec::new())
        } else if p.client_group.is_kem() {
            // The peer's KEM key_share is attacker-controlled input; a
            // malformed/invalid encapsulation value is `illegal_parameter`
            // (RFC 8446 §4.2.8.2), not `internal_error`.
            KeyExchange::encapsulate(p.client_group, p.client_pub_key)
                .map_err(|e| TlsError::HandshakeFailed(format!("invalid key_share: {e}")))?
        } else {
            let server_kx = KeyExchange::generate(p.client_group)?;
            // `compute_shared_secret` consumes the client's key_share. A
            // malformed peer public value (wrong length, point not on the
            // curve, point at infinity, low-order / all-zero X25519/X448
            // result, …) is a peer-input error → `illegal_parameter`
            // (RFC 8446 §4.2.8.2), never `internal_error`.
            let ss = server_kx
                .compute_shared_secret(p.client_pub_key)
                .map_err(|e| TlsError::HandshakeFailed(format!("invalid key_share: {e}")))?;
            (ss, server_kx.public_key_bytes().to_vec())
        };

        // Build ServerHello
        let mut random = [0u8; 32];
        getrandom::fill(&mut random)
            .map_err(|_| TlsError::HandshakeFailed("random generation failed".into()))?;

        let mut sh_extensions = vec![build_supported_versions_sh()];
        // psk_ke (RFC 8446 §4.2.9) sends no key_share.
        if !p.psk_ke {
            sh_extensions.push(build_key_share_sh(p.client_group, &server_key_share_bytes));
        }
        if psk_mode {
            sh_extensions.push(build_pre_shared_key_sh(0));
        }

        let sh = ServerHello {
            random,
            legacy_session_id: p.ch.legacy_session_id.clone(),
            cipher_suite: p.suite,
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

        let server_hs_keys = TrafficKeys::derive(&p.params, &server_hs_secret)?;
        let client_hs_keys = TrafficKeys::derive(&p.params, &client_hs_secret)?;

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

        // Phase T97 — CertificateRequest for in-handshake mTLS
        // (RFC 8446 §4.3.2). Skipped in PSK mode (no cert auth) and
        // when the server config doesn't ask for client cert.
        let certificate_request_msg = if !psk_mode && self.config.verify_client_cert {
            // Phase T102 — advertise the comprehensive set of
            // signature schemes our server can accept for client
            // authentication (RFC 8446 §4.3.2). Order mirrors the
            // IANA SignatureScheme registry-by-strength convention
            // tlsfuzzer's `test-tls13-certificate-request.py`
            // hardcodes (Edwards → ECDSA strong→weak → RSA-PSS
            // strong→weak → RSA-PKCS#1 strong→weak); this is also
            // the order common stacks (OpenSSL, NSS) emit.
            //
            // We INTENTIONALLY include `rsa_pkcs1_*` and the SHA-1
            // / SHA-224 codepoints even though `verify_certificate_
            // verify` rejects them in CertificateVerify per
            // RFC 8446 §4.4.3. The CR sigalgs extension gates BOTH
            // the CV signature scheme AND the cert-chain signature
            // scheme; rsa_pkcs1_* and SHA-1/224 remain valid for
            // certificate-chain signatures (§4.2.3) so advertising
            // them is correct. Per-scheme refusal still applies to
            // CV via `is_pkcs1_or_legacy_hash`.
            //
            // Empty context for in-handshake CR (post-handshake CR
            // uses a non-empty random context — that path is
            // separate, see `tls13_client_handle_post_hs_cert_request_body!`).
            let cr_sig_algs = [
                crate::crypt::SignatureScheme::ED25519,
                crate::crypt::SignatureScheme::ED448,
                crate::crypt::SignatureScheme::ECDSA_SECP521R1_SHA512,
                crate::crypt::SignatureScheme::ECDSA_SECP384R1_SHA384,
                crate::crypt::SignatureScheme::ECDSA_SECP256R1_SHA256,
                crate::crypt::SignatureScheme::ECDSA_SHA224,
                crate::crypt::SignatureScheme::ECDSA_SHA1,
                crate::crypt::SignatureScheme::RSA_PSS_RSAE_SHA512,
                crate::crypt::SignatureScheme::RSA_PSS_PSS_SHA512,
                crate::crypt::SignatureScheme::RSA_PSS_RSAE_SHA384,
                crate::crypt::SignatureScheme::RSA_PSS_PSS_SHA384,
                crate::crypt::SignatureScheme::RSA_PSS_RSAE_SHA256,
                crate::crypt::SignatureScheme::RSA_PSS_PSS_SHA256,
                crate::crypt::SignatureScheme::RSA_PKCS1_SHA512,
                crate::crypt::SignatureScheme::RSA_PKCS1_SHA384,
                crate::crypt::SignatureScheme::RSA_PKCS1_SHA256,
                crate::crypt::SignatureScheme::RSA_PKCS1_SHA224,
                crate::crypt::SignatureScheme::RSA_PKCS1_SHA1,
            ];
            let cr_extensions =
                vec![crate::handshake::extensions_codec::build_signature_algorithms(&cr_sig_algs)];
            let cr = CertificateRequestMsg {
                certificate_request_context: vec![],
                extensions: cr_extensions,
            };
            let cr_msg = encode_certificate_request(&cr);
            self.transcript.update(&cr_msg)?;
            self.expecting_client_cert = true;
            cr_msg
        } else {
            Vec::new()
        };

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
            // Phase T109 — cert-based auth requires the client's
            // `signature_algorithms`. PSK-only handshakes can omit it
            // (the binder + suite supply auth), but if we reach this
            // branch we're about to sign CertificateVerify, so the
            // extension MUST be present (RFC 8446 §4.2.3).
            if p.client_sig_algs.is_empty() {
                return Err(TlsError::HandshakeFailed(
                    "missing signature_algorithms in ClientHello \
                     (required for certificate-based authentication, \
                     RFC 8446 §4.2.3 — alert: missing_extension)"
                        .into(),
                ));
            }
            // Phase T107 — when our cert uses the `id-RSASSA-PSS`
            // SPKI OID, advertise `rsa_pss_pss_*` instead of
            // `rsa_pss_rsae_*` per RFC 5756 / RFC 8446 §4.2.3.
            let sig_scheme = super::signing::select_signature_scheme_for_cert(
                private_key,
                p.client_sig_algs,
                self.config.server_cert_is_rsa_pss,
            )?;
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
        let server_app_keys = TrafficKeys::derive(&p.params, &server_app_secret)?;
        let client_app_keys = TrafficKeys::derive(&p.params, &client_app_secret)?;

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
        self.params = Some(p.params.clone());
        self.negotiated_suite = Some(p.suite);
        self.state = HandshakeState::WaitClientFinished;

        Ok(ClientHelloActions {
            server_hello_msg,
            encrypted_extensions_msg,
            certificate_request_msg,
            certificate_msg,
            certificate_verify_msg,
            server_finished_msg,
            server_hs_keys,
            client_hs_keys,
            server_app_keys,
            client_app_keys,
            suite: p.suite,
            client_app_secret,
            server_app_secret,
            cipher_params: p.params,
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
    /// Phase T97 — process the client's in-handshake Certificate message
    /// (RFC 8446 §4.4.2). Updates the transcript and stores the parsed
    /// chain in `client_certs` for subsequent CertificateVerify
    /// signature checking.
    pub fn process_client_certificate(&mut self, msg_data: &[u8]) -> Result<(), TlsError> {
        if !self.expecting_client_cert {
            return Err(TlsError::HandshakeFailed(
                "process_client_certificate: not expecting client cert".into(),
            ));
        }
        // Add to transcript before parsing — transcript hashes the wire bytes.
        self.transcript.update(msg_data)?;
        let body = get_body(msg_data)?;
        let cert_msg = crate::handshake::codec::decode_certificate(body)?;
        // Empty client cert chain is permitted by RFC 8446 §4.4.2 (client
        // signals "no cert"); the macro handles `require_client_cert`.
        self.client_certs = cert_msg
            .certificate_list
            .into_iter()
            .map(|e| e.cert_data)
            .collect();
        Ok(())
    }

    /// Phase T97 — was the most recent `process_client_certificate`
    /// call a non-empty Certificate? Used to decide whether to also
    /// expect a CertificateVerify.
    pub fn client_sent_certificates(&self) -> bool {
        !self.client_certs.is_empty()
    }

    /// Phase T97 — process the client's in-handshake CertificateVerify
    /// message (RFC 8446 §4.4.3). Verifies the signature against the
    /// leaf cert from the previously-processed Certificate message,
    /// over the transcript hash up to (but not including) this CV.
    /// Then optionally validates the cert chain against
    /// `config.trusted_certs` if `verify_client_cert == true`.
    pub fn process_client_certificate_verify(&mut self, msg_data: &[u8]) -> Result<(), TlsError> {
        if self.client_certs.is_empty() {
            return Err(TlsError::HandshakeFailed(
                "process_client_certificate_verify: no client cert to verify against".into(),
            ));
        }
        // Snapshot transcript BEFORE adding CV to it (signature is over
        // the transcript up to and INCLUDING the client Certificate but
        // NOT the CertificateVerify, per RFC 8446 §4.4.3).
        let transcript_hash = self.transcript.current_hash()?;

        let body = get_body(msg_data)?;
        let cv = crate::handshake::codec::decode_certificate_verify(body)?;

        // Parse the leaf cert and verify the signature using the same
        // helper TLS 1.3 client uses for server CertificateVerify.
        let leaf = hitls_pki::x509::Certificate::from_der(&self.client_certs[0])
            .map_err(|e| TlsError::HandshakeFailed(format!("client leaf cert parse: {e}")))?;
        crate::handshake::verify::verify_certificate_verify(
            &leaf,
            cv.algorithm,
            &cv.signature,
            &transcript_hash,
            false, // is_server == false for client CertificateVerify
        )?;

        // After signature OK, add CV to transcript.
        self.transcript.update(msg_data)?;

        // Optional chain validation against trusted_certs.
        if self.config.verify_client_cert && !self.config.trusted_certs.is_empty() {
            let intermediates: Vec<hitls_pki::x509::Certificate> = self
                .client_certs
                .iter()
                .skip(1) // leaf is `cert` arg below
                .map(|der| hitls_pki::x509::Certificate::from_der(der))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| TlsError::HandshakeFailed(format!("client chain parse: {e}")))?;
            let mut verifier = hitls_pki::x509::verify::CertificateVerifier::new();
            for ta_der in &self.config.trusted_certs {
                let ta = hitls_pki::x509::Certificate::from_der(ta_der)
                    .map_err(|e| TlsError::HandshakeFailed(format!("trust anchor parse: {e}")))?;
                verifier.add_trusted_cert(ta);
            }
            verifier.verify_cert(&leaf, &intermediates).map_err(|e| {
                TlsError::HandshakeFailed(format!("client cert chain verify failed: {e}"))
            })?;
        }
        Ok(())
    }

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
            // Generate ticket nonce and age_add
            let mut nonce_bytes = [0u8; 8];
            getrandom::fill(&mut nonce_bytes)
                .map_err(|_| TlsError::HandshakeFailed("nonce gen failed".into()))?;
            let mut age_add_bytes = [0u8; 4];
            getrandom::fill(&mut age_add_bytes)
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
            let ticket_data = encrypt_ticket(
                params.hash_alg_id(),
                ticket_key,
                &psk,
                suite,
                created_at,
                age_add,
            )?;

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

    /// Phase I97 — snapshot the completed handshake transcript
    /// (ClientHello … client Finished) for post-handshake use.
    ///
    /// RFC 8446 §4.4.1 requires a post-handshake CertificateVerify to be
    /// computed over the main-handshake transcript continued with the
    /// post-handshake CertificateRequest + Certificate. The connection
    /// retains this clone so [`request_client_auth`] can seed its hash
    /// from it. Call **after** `process_client_finished`, which feeds the
    /// client Finished into the transcript.
    ///
    /// [`request_client_auth`]: crate::connection::TlsServerConnection::request_client_auth
    pub fn transcript_clone(&self) -> TranscriptHash {
        self.transcript.clone()
    }

    /// Test-only accessor (Phase I93 e2e tests verify that the recovered
    /// inner CH's random — not the outer wire random — landed in the
    /// handshake context). Gated on `feature = "ech"` because the only
    /// caller is the ECH split-CH end-to-end test, which itself only
    /// compiles when ECH is enabled — without the gate, `--no-default-features`
    /// flags this as dead code.
    #[cfg(all(test, feature = "ech"))]
    pub(crate) fn client_random_for_test(&self) -> &[u8; 32] {
        &self.client_random
    }

    /// Phase I93/I94 helper. Inspect an outer ClientHello message for an
    /// `encrypted_client_hello` extension. If present and its `config_id`
    /// matches one of `keypairs`, attempt HPKE-decryption to recover the
    /// inner CH bytes (full handshake message). Return values:
    ///
    /// - `Ok(None)`: no ECH ext at all, OR config_id mismatch (treated as
    ///   GREASE — the caller falls back to processing the outer CH).
    /// - `Ok(Some(inner))`: ECH accepted; caller should process `inner`.
    /// - `Err(...)`: config_id matched but HPKE-decryption failed (wrong
    ///   sk, AAD mismatch from outer-CH tampering, AEAD tag failure, …).
    ///   This is a hard handshake error; the caller MUST NOT silently
    ///   fall back, otherwise an attacker who flips one byte of the
    ///   outer CH could force outer-CH processing and defeat ECH's
    ///   privacy.
    ///
    /// **AAD (Phase I94)**: this implementation uses the draft-ietf-tls-esni
    /// `ClientHelloOuterAAD` — the outer CH bytes with the ECH ext's
    /// `payload` (=ciphertext) replaced by zeros of the same length.
    /// `enc` is left as the real value. Reconstructed by replacing the
    /// real ECH ext data with a placeholder version (zeroed payload),
    /// then re-encoding the outer CH. The encoding must be byte-
    /// identical to the client's AAD; this works because both sides
    /// use the same `encode_client_hello` and the placeholder ECH ext
    /// has the same total length as the real one.
    #[cfg(feature = "ech")]
    fn try_unwrap_ech(
        outer_msg: &[u8],
        keypairs: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<Option<Vec<u8>>, TlsError> {
        let body = get_body(outer_msg)?;
        let outer_decoded = decode_client_hello(body)?;

        let ech_ext_idx = outer_decoded
            .extensions
            .iter()
            .position(|e| e.extension_type == ExtensionType::ENCRYPTED_CLIENT_HELLO);
        let Some(ech_ext_idx) = ech_ext_idx else {
            return Ok(None); // no ECH offered
        };
        let ech_hello =
            crate::ech::parse_ech_client_hello(&outer_decoded.extensions[ech_ext_idx].data)?;

        // Find the keypair whose ECHConfig parses to a matching config_id.
        // We re-parse on every CH to keep the config field free of ech-feature
        // dependencies; for production servers with many configs a parse
        // cache could be added in a future P-phase.
        let matching = keypairs.iter().find_map(|(cfg_bytes, sk_bytes)| {
            let mut wire = Vec::with_capacity(2 + cfg_bytes.len());
            wire.extend_from_slice(&(cfg_bytes.len() as u16).to_be_bytes());
            wire.extend_from_slice(cfg_bytes);
            crate::ech::parse_ech_config_list(&wire)
                .ok()
                .and_then(|cfgs| {
                    cfgs.into_iter()
                        .find(|c| c.config_id == ech_hello.config_id)
                        .map(|c| (c, sk_bytes.clone()))
                })
        });

        let Some((config, sk)) = matching else {
            // config_id is unknown — treat as GREASE (RFC: "the server
            // SHOULD ignore the extension if config_id does not match").
            return Ok(None);
        };

        // Reconstruct ClientHelloOuterAAD: replace the real ECH ext data
        // with a placeholder where the payload (ciphertext) is zeroed,
        // keeping enc as the real value. Then re-encode.
        let mut placeholder_extensions = outer_decoded.extensions.clone();
        let placeholder_ech = crate::ech::EchClientHello {
            ech_type: ech_hello.ech_type,
            cipher_suite: ech_hello.cipher_suite,
            config_id: ech_hello.config_id,
            enc: ech_hello.enc.clone(),
            payload: vec![0u8; ech_hello.payload.len()],
        };
        placeholder_extensions[ech_ext_idx] = crate::extensions::Extension {
            extension_type: ExtensionType::ENCRYPTED_CLIENT_HELLO,
            data: crate::ech::encode_ech_client_hello(&placeholder_ech),
        };
        let placeholder_outer = crate::handshake::codec::ClientHello {
            random: outer_decoded.random,
            legacy_session_id: outer_decoded.legacy_session_id.clone(),
            cipher_suites: outer_decoded.cipher_suites.clone(),
            extensions: placeholder_extensions,
        };
        let aad = crate::handshake::codec::encode_client_hello(&placeholder_outer);

        // Real ECH attempt — decrypt or fail loud. AAD mismatch (outer
        // CH tampering) propagates as an HPKE-Open AEAD-tag failure.
        let mut ctx =
            crate::ech::ech_setup_recipient(&config, ech_hello.cipher_suite, &ech_hello.enc, &sk)?;
        let inner = ctx
            .open(&aad, &ech_hello.payload)
            .map_err(|e| TlsError::HandshakeFailed(format!("ECH HPKE open: {e}")))?;
        Ok(Some(inner))
    }
}

/// Verify a PSK binder against the truncated ClientHello (RFC 8446 §4.2.11.2).
///
/// The binder is `HMAC(finished_key, Hash(truncated_CH))`, where
/// `truncated_CH` is the full CH with the trailing binders list stripped.
/// `external` selects the binder-key label: `"res binder"` for tickets
/// (resumption) vs `"ext binder"` for out-of-band PSKs configured via
/// `config.psk` / `config.psk_identity` (Phase T119). Both run the same
/// HKDF chain off the early secret, only the label differs.
fn verify_binder(
    params: &CipherSuiteParams,
    psk: &[u8],
    ch_msg: &[u8],
    binder: &[u8],
    external: bool,
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
    let binder_key = ks.derive_binder_key(external)?;
    let finished_key = ks.derive_finished_key(&binder_key)?;

    // Hash the truncated CH
    let mut hasher = crate::crypt::DigestVariant::new(params.hash_alg_id());
    hasher.update(truncated_ch).map_err(TlsError::CryptoError)?;
    let mut hash = [0u8; 64];
    hasher
        .finish(&mut hash[..params.hash_len])
        .map_err(TlsError::CryptoError)?;

    // Compute expected binder
    let expected = ks.compute_finished_verify_data(&finished_key, &hash[..params.hash_len])?;

    Ok(bool::from(binder.ct_eq(&expected)))
}

/// Extract handshake body from message data (skip 4-byte header).
fn get_body(msg_data: &[u8]) -> Result<&[u8], TlsError> {
    // Phase T91 — must be at least the 4-byte header. Zero-length
    // bodies are valid for some message types (EndOfEarlyData,
    // ServerHelloDone in 1.2) so the per-message decoder enforces
    // its own length contract from here. This used to be `<= 4`,
    // which folded "header-only" into "too short" and produced a
    // generic `handshake_failure` for malformed Finished etc.
    // instead of the more specific `decode_error`.
    if msg_data.len() < 4 {
        return Err(TlsError::HandshakeFailed(
            "handshake message too short (decode_error)".into(),
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
            .certificate_chain(vec![vec![0x30, 0x02, 0x05, 0x00]]) // fake DER
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
        use crate::handshake::codec::encode_client_hello;
        use crate::handshake::codec::ClientHello;
        use crate::handshake::extensions_codec::{
            build_key_share_ch, build_signature_algorithms, build_supported_groups,
        };

        let config = make_server_config();
        let mut hs = ServerHandshake::new(config);

        // Build a minimal ClientHello without supported_versions

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
            .certificate_chain(vec![vec![0x30, 0x02, 0x05, 0x00]])
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
            .certificate_chain(vec![vec![0x30, 0x02, 0x05, 0x00]])
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
            .certificate_chain(vec![vec![0x30, 0x02, 0x05, 0x00]])
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
            .certificate_chain(vec![vec![0x30, 0x02, 0x05, 0x00]])
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
            .certificate_chain(vec![vec![0x30, 0x02, 0x05, 0x00]])
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
        let ClientHelloResult::Actions(_actions) = hs.process_client_hello(&msg).unwrap() else {
            panic!("expected Actions");
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
            .certificate_chain(vec![vec![0x30, 0x02, 0x05, 0x00]])
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
            .certificate_chain(vec![vec![0x30, 0x02, 0x05, 0x00]])
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
            .certificate_chain(vec![vec![0x30, 0x02, 0x05, 0x00]])
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
            .certificate_chain(vec![vec![0x30, 0x02, 0x05, 0x00]])
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
            .certificate_chain(vec![vec![0x30, 0x02, 0x05, 0x00]])
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
    fn test_server_accessors_after_init() {
        let config = make_server_config();
        let hs = ServerHandshake::new(config);
        assert_eq!(hs.state(), HandshakeState::WaitClientHello);
        assert!(hs.client_record_size_limit().is_none());
        assert!(hs.negotiated_alpn().is_none());
        assert!(hs.client_server_name().is_none());
        assert!(hs.negotiated_group().is_none());
        assert!(hs.client_certs().is_empty());
    }

    #[test]
    fn test_server_process_client_finished_wrong_state_wait_ch() {
        let config = make_server_config();
        let mut hs = ServerHandshake::new(config);
        // Finished from WaitClientHello → error
        assert!(hs
            .process_client_finished(&[20, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            .is_err());
    }

    #[test]
    fn test_server_process_client_hello_retry_wrong_state() {
        let config = make_server_config();
        let mut hs = ServerHandshake::new(config);
        // process_client_hello_retry from WaitClientHello (without prior HRR) → error
        assert!(hs
            .process_client_hello_retry(&[1, 0, 0, 4, 0, 0, 0, 0])
            .is_err());
    }

    #[test]
    fn test_server_rejects_tls12_only_supported_versions() {
        use crate::extensions::Extension;
        use crate::handshake::codec::{encode_client_hello, ClientHello};
        use crate::handshake::extensions_codec::{
            build_key_share_ch, build_signature_algorithms, build_supported_groups,
        };
        let config = make_server_config();
        let mut hs = ServerHandshake::new(config);

        // ClientHello with supported_versions that does NOT include TLS 1.3
        let sv_ext = Extension {
            extension_type: ExtensionType::SUPPORTED_VERSIONS,
            data: vec![2, 0x03, 0x03], // only TLS 1.2
        };

        let ch = ClientHello {
            random: [0xBB; 32],
            legacy_session_id: vec![],
            cipher_suites: vec![CipherSuite::TLS_AES_128_GCM_SHA256],
            extensions: vec![
                sv_ext,
                build_supported_groups(&[NamedGroup::X25519]),
                build_signature_algorithms(&[crate::crypt::SignatureScheme::ED25519]),
                build_key_share_ch(NamedGroup::X25519, &[0x04; 32]),
            ],
        };
        let msg = encode_client_hello(&ch);
        assert!(hs.process_client_hello(&msg).is_err());
    }

    #[test]
    fn test_server_alpn_no_match_returns_none() {
        let config = make_server_config();
        let hs = ServerHandshake::new(config);
        // Without processing any CH, negotiated_alpn is None
        assert!(hs.negotiated_alpn().is_none());
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
            .certificate_chain(vec![vec![0x30, 0x02, 0x05, 0x00]])
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

    // ===================================================================
    // Phase T82 — PSK binder verification negative tests (RFC 8446 §4.2.11.2)
    //
    // verify_binder rejects tampered binders, wrong PSK, mismatched hash
    // length, and truncated ClientHello messages. These tests exercise
    // each rejection path directly against verify_binder.
    // ===================================================================

    /// Construct a synthetic ClientHello-shaped byte stream and the matching
    /// binder for a given PSK + cipher suite, returning (ch_msg, binder).
    ///
    /// `ch_msg` ends with the canonical binders tail
    /// (2 binders_len || 1 binder_entry_len || hash_len binder bytes), so
    /// `verify_binder` will strip exactly the same bytes when truncating.
    fn forge_ch_with_binder(
        psk: &[u8],
        suite: CipherSuite,
        ch_prefix: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let params = CipherSuiteParams::from_suite(suite).unwrap();
        let hash_len = params.hash_len;

        // Compute binder = HMAC(finished_key, Hash(truncated_CH))
        let mut ks = KeySchedule::new(params.clone());
        ks.derive_early_secret(Some(psk)).unwrap();
        let binder_key = ks.derive_binder_key(false).unwrap();
        let finished_key = ks.derive_finished_key(&binder_key).unwrap();

        let mut hasher = crate::crypt::DigestVariant::new(params.hash_alg_id());
        hasher.update(ch_prefix).unwrap();
        let mut hash = [0u8; 64];
        hasher.finish(&mut hash[..hash_len]).unwrap();
        let binder = ks
            .compute_finished_verify_data(&finished_key, &hash[..hash_len])
            .unwrap();

        // Append binders tail: binders_list_len(2) || binder_len(1) || binder
        let binders_list_len = 1 + hash_len;
        let mut ch_msg = ch_prefix.to_vec();
        ch_msg.extend_from_slice(&(binders_list_len as u16).to_be_bytes());
        ch_msg.push(hash_len as u8);
        ch_msg.extend_from_slice(&binder);

        (ch_msg, binder)
    }

    #[test]
    fn test_verify_binder_accepts_correct_binder() {
        let psk = vec![0x42; 32];
        let suite = CipherSuite::TLS_AES_128_GCM_SHA256;
        let (ch_msg, binder) = forge_ch_with_binder(&psk, suite, b"truncated CH bytes");
        let params = CipherSuiteParams::from_suite(suite).unwrap();

        assert!(verify_binder(&params, &psk, &ch_msg, &binder, false).unwrap());
    }

    #[test]
    fn test_verify_binder_rejects_tampered_binder() {
        let psk = vec![0x42; 32];
        let suite = CipherSuite::TLS_AES_128_GCM_SHA256;
        let (ch_msg, mut binder) = forge_ch_with_binder(&psk, suite, b"truncated CH bytes");
        let params = CipherSuiteParams::from_suite(suite).unwrap();

        // Flip one bit in the binder — must be rejected (replay-protection core).
        binder[0] ^= 0x01;
        assert!(!verify_binder(&params, &psk, &ch_msg, &binder, false).unwrap());
    }

    #[test]
    fn test_verify_binder_rejects_wrong_psk() {
        let psk_real = vec![0x42; 32];
        let psk_attacker = vec![0xAA; 32];
        let suite = CipherSuite::TLS_AES_128_GCM_SHA256;
        let (ch_msg, binder) = forge_ch_with_binder(&psk_real, suite, b"truncated CH bytes");
        let params = CipherSuiteParams::from_suite(suite).unwrap();

        // Same CH, but verifier uses a different PSK → finished_key differs → mismatch.
        assert!(!verify_binder(&params, &psk_attacker, &ch_msg, &binder, false).unwrap());
    }

    #[test]
    fn test_verify_binder_rejects_wrong_hash_len() {
        // Forge with SHA-256 (32-byte binder), verify with SHA-384 params (48-byte expected).
        let psk = vec![0x42; 32];
        let (ch_msg, binder) = forge_ch_with_binder(
            &psk,
            CipherSuite::TLS_AES_128_GCM_SHA256,
            b"x".repeat(80).as_slice(),
        );
        let params_wrong =
            CipherSuiteParams::from_suite(CipherSuite::TLS_AES_256_GCM_SHA384).unwrap();

        // verify_binder will strip 2 + 1 + 48 = 51 bytes from CH and compute
        // SHA-384 over the resulting prefix. Even ignoring the binder length
        // mismatch, the hash domain differs → must reject.
        let result = verify_binder(&params_wrong, &psk, &ch_msg, &binder, false).unwrap();
        assert!(!result, "SHA-384 verifier must not accept SHA-256 binder");
    }

    #[test]
    fn test_verify_binder_rejects_truncated_ch() {
        let psk = vec![0x42; 32];
        let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
        // binder_tail_size = 2 + 1 + 32 = 35. ch_msg of exactly 35 bytes leaves
        // an empty truncated_CH, which the implementation rejects with Ok(false).
        let ch_msg = vec![0u8; 35];
        let binder = vec![0u8; 32];
        assert!(!verify_binder(&params, &psk, &ch_msg, &binder, false).unwrap());

        // Strictly shorter than the tail → also Ok(false).
        let short_ch = vec![0u8; 10];
        assert!(!verify_binder(&params, &psk, &short_ch, &binder, false).unwrap());
    }

    #[test]
    fn test_verify_binder_rejects_modified_truncated_ch() {
        // Forge a binder over CH prefix `original`, then call verify_binder
        // with a tampered prefix. Since the binder is HMAC-bound to the
        // truncated CH bytes, any modification must propagate to a mismatch.
        let psk = vec![0x42; 32];
        let suite = CipherSuite::TLS_AES_128_GCM_SHA256;
        let prefix = b"original CH prefix bytes used in transcript".to_vec();
        let (mut ch_msg, binder) = forge_ch_with_binder(&psk, suite, &prefix);
        let params = CipherSuiteParams::from_suite(suite).unwrap();

        // Sanity: unmodified accepts.
        assert!(verify_binder(&params, &psk, &ch_msg, &binder, false).unwrap());

        // Flip one byte inside the truncated portion — must reject.
        ch_msg[5] ^= 0x80;
        assert!(!verify_binder(&params, &psk, &ch_msg, &binder, false).unwrap());
    }

    /// Phase T119 — external-PSK binder path (RFC 8446 §4.2.11.2 `"ext binder"`
    /// label). Forge a binder using the external label, then verify with
    /// `external=true` (accepts) and `external=false` (rejects, because the
    /// labels differ).
    #[test]
    fn test_verify_binder_external_label() {
        let psk = vec![0xCD; 32];
        let suite = CipherSuite::TLS_AES_128_GCM_SHA256;
        let params = CipherSuiteParams::from_suite(suite).unwrap();
        let hash_len = params.hash_len;

        // Forge a binder using the EXTERNAL label.
        let prefix = b"external psk CH prefix";
        let mut ks = KeySchedule::new(params.clone());
        ks.derive_early_secret(Some(&psk)).unwrap();
        let binder_key = ks.derive_binder_key(true).unwrap();
        let finished_key = ks.derive_finished_key(&binder_key).unwrap();
        let mut hasher = crate::crypt::DigestVariant::new(params.hash_alg_id());
        hasher.update(prefix).unwrap();
        let mut hash = [0u8; 64];
        hasher.finish(&mut hash[..hash_len]).unwrap();
        let binder = ks
            .compute_finished_verify_data(&finished_key, &hash[..hash_len])
            .unwrap();

        let mut ch_msg = prefix.to_vec();
        ch_msg.extend_from_slice(&((1 + hash_len) as u16).to_be_bytes());
        ch_msg.push(hash_len as u8);
        ch_msg.extend_from_slice(&binder);

        // Correct label accepts; resumption label rejects (mixing the two
        // would let a ticket binder be reused as an external-PSK binder).
        assert!(verify_binder(&params, &psk, &ch_msg, &binder, true).unwrap());
        assert!(!verify_binder(&params, &psk, &ch_msg, &binder, false).unwrap());
    }
}
