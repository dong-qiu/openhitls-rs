//! TLS 1.3 client handshake state machine.
//!
//! Implements the client side of the 1-RTT handshake:
//! ClientHello → ServerHello → {EncryptedExtensions} → {Certificate} →
//! {CertificateVerify} → {Finished} → client {Finished}

use crate::config::TlsConfig;
use crate::crypt::key_schedule::KeySchedule;
use crate::crypt::traffic_keys::TrafficKeys;
use crate::crypt::transcript::TranscriptHash;
use crate::crypt::{CipherSuiteParams, NamedGroup};
use crate::extensions::ExtensionType;
use crate::CipherSuite;
use hitls_crypto::sha2::Sha256;
use hitls_types::TlsError;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::codec::{
    decode_certificate, decode_certificate_verify, decode_encrypted_extensions, decode_finished,
    decode_new_session_ticket, decode_server_hello, encode_client_hello, encode_end_of_early_data,
    encode_finished, CertCompressionAlgorithm, ClientHello, HELLO_RETRY_REQUEST_RANDOM,
};
#[cfg(feature = "cert-compression")]
use super::codec::{decode_compressed_certificate, decompress_certificate_body};
use super::extensions_codec::{
    build_alpn, build_certificate_authorities, build_compress_certificate, build_cookie,
    build_early_data_ch, build_grease_extension, build_heartbeat, build_key_share_ch,
    build_key_share_ch_grease, build_padding, build_post_handshake_auth, build_pre_shared_key_ch,
    build_psk_key_exchange_modes, build_record_size_limit, build_sct_ch, build_server_name,
    build_signature_algorithms, build_signature_algorithms_cert, build_signature_algorithms_grease,
    build_status_request_ch, build_status_request_v2, build_supported_groups,
    build_supported_groups_grease, build_supported_versions_ch, build_supported_versions_ch_grease,
    build_trusted_ca_keys, build_use_srtp, grease_value, parse_alpn_sh, parse_cookie,
    parse_key_share_hrr, parse_key_share_sh, parse_pre_shared_key_sh, parse_record_size_limit,
    parse_status_request_cert_entry, parse_supported_versions_sh,
};
use super::key_exchange::KeyExchange;
use super::verify::verify_certificate_verify;
use super::HandshakeState;

use crate::session::TlsSession;

/// Result from processing ServerHello: either normal or HRR.
pub enum ServerHelloResult {
    /// Normal ServerHello — activate handshake encryption.
    Actions(ServerHelloActions),
    /// HelloRetryRequest — need to send a new ClientHello.
    RetryNeeded(RetryActions),
}

/// Actions to take after processing ServerHello.
pub struct ServerHelloActions {
    pub server_hs_keys: TrafficKeys,
    pub client_hs_keys: TrafficKeys,
    pub suite: CipherSuite,
}

/// Info for building the retried ClientHello after HRR.
pub struct RetryActions {
    /// The group the server selected for key exchange.
    pub selected_group: NamedGroup,
    /// Cookie from the HRR (if present).
    pub cookie: Option<Vec<u8>>,
    /// The negotiated cipher suite.
    pub suite: CipherSuite,
}

/// Actions to take after processing server Finished.
pub struct FinishedActions {
    /// Encoded client Finished handshake message (header + body).
    pub client_finished_msg: Vec<u8>,
    pub client_app_keys: TrafficKeys,
    pub server_app_keys: TrafficKeys,
    pub suite: CipherSuite,
    /// Raw client application traffic secret (for key updates).
    pub client_app_secret: Vec<u8>,
    /// Raw server application traffic secret (for key updates).
    pub server_app_secret: Vec<u8>,
    /// Cipher suite parameters (for key updates).
    pub cipher_params: CipherSuiteParams,
    /// Resumption master secret (for deriving PSKs from NewSessionTickets).
    pub resumption_master_secret: Vec<u8>,
    /// Exporter master secret (for RFC 5705 / RFC 8446 §7.5 key material export).
    pub exporter_master_secret: Vec<u8>,
    /// Early exporter master secret (for export_early_keying_material, empty if no PSK).
    pub early_exporter_master_secret: Vec<u8>,
    /// EndOfEarlyData message to send (if 0-RTT was accepted).
    /// Must be sent encrypted with 0-RTT write key before switching to HS write key.
    pub end_of_early_data_msg: Option<Vec<u8>>,
}

/// Client handshake state machine.
pub struct ClientHandshake {
    config: TlsConfig,
    state: HandshakeState,
    key_exchange: Option<KeyExchange>,
    key_schedule: Option<KeySchedule>,
    transcript: TranscriptHash,
    params: Option<CipherSuiteParams>,
    negotiated_suite: Option<CipherSuite>,
    server_certs: Vec<Vec<u8>>,
    /// The raw ClientHello handshake message bytes (for transcript).
    client_hello_msg: Vec<u8>,
    /// Client handshake traffic secret (for finished key).
    client_hs_secret: Vec<u8>,
    /// Server handshake traffic secret (for finished key).
    server_hs_secret: Vec<u8>,
    /// Whether a HelloRetryRequest has been processed.
    hrr_done: bool,
    /// PSK for session resumption (stored during build_client_hello).
    psk: Option<Vec<u8>>,
    /// Whether PSK mode was accepted by the server.
    psk_mode: bool,
    /// Whether we offered 0-RTT early data in the ClientHello.
    offered_early_data: bool,
    /// Whether the server accepted 0-RTT early data.
    early_data_accepted: bool,
    /// Client early traffic secret (for 0-RTT encryption).
    early_traffic_secret: Vec<u8>,
    /// Offered certificate compression algorithms.
    cert_compression_algos: Vec<CertCompressionAlgorithm>,
    /// Peer's record size limit from EncryptedExtensions (adjusted for TLS 1.3).
    peer_record_size_limit: Option<u16>,
    /// OCSP response received from server Certificate entry.
    ocsp_response: Option<Vec<u8>>,
    /// SCT data received from server Certificate entry.
    sct_data: Option<Vec<u8>>,
    /// Client random (for key logging).
    client_random: [u8; 32],
    /// Negotiated ALPN protocol from EncryptedExtensions (if any).
    negotiated_alpn: Option<Vec<u8>>,
    /// Negotiated key exchange group from ServerHello key_share.
    negotiated_group: Option<NamedGroup>,
    /// Early exporter master secret (RFC 8446 §7.5, derived when PSK is offered).
    early_exporter_master_secret: Vec<u8>,
}

impl Drop for ClientHandshake {
    fn drop(&mut self) {
        self.client_hs_secret.zeroize();
        self.server_hs_secret.zeroize();
        self.early_traffic_secret.zeroize();
        if let Some(ref mut psk) = self.psk {
            psk.zeroize();
        }
        self.early_exporter_master_secret.zeroize();
    }
}

impl ClientHandshake {
    /// Create a new client handshake.
    pub fn new(config: TlsConfig) -> Self {
        // Start with SHA-256 transcript (we'll re-initialize if the server
        // selects SHA-384, but TLS_AES_128_GCM_SHA256 is most common).
        let transcript = TranscriptHash::new(|| Box::new(Sha256::new()));
        Self {
            config,
            state: HandshakeState::Idle,
            key_exchange: None,
            key_schedule: None,
            transcript,
            params: None,
            negotiated_suite: None,
            server_certs: Vec::new(),
            client_hello_msg: Vec::new(),
            client_hs_secret: Vec::new(),
            server_hs_secret: Vec::new(),
            hrr_done: false,
            psk: None,
            psk_mode: false,
            offered_early_data: false,
            early_data_accepted: false,
            early_traffic_secret: Vec::new(),
            cert_compression_algos: Vec::new(),
            peer_record_size_limit: None,
            ocsp_response: None,
            sct_data: None,
            client_random: [0u8; 32],
            negotiated_alpn: None,
            negotiated_group: None,
            early_exporter_master_secret: Vec::new(),
        }
    }

    /// Current handshake state.
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// Whether 0-RTT early data was offered in the ClientHello.
    pub fn offered_early_data(&self) -> bool {
        self.offered_early_data
    }

    /// Whether the server accepted 0-RTT early data.
    pub fn early_data_accepted(&self) -> bool {
        self.early_data_accepted
    }

    /// The client early traffic secret (for 0-RTT encryption).
    /// Only valid if `offered_early_data()` is true.
    pub fn early_traffic_secret(&self) -> &[u8] {
        &self.early_traffic_secret
    }

    /// The peer's negotiated record size limit (adjusted for TLS 1.3).
    pub fn peer_record_size_limit(&self) -> Option<u16> {
        self.peer_record_size_limit
    }

    /// OCSP response received from server's Certificate entry.
    pub fn ocsp_response(&self) -> Option<&[u8]> {
        self.ocsp_response.as_deref()
    }

    /// SCT data received from server's Certificate entry.
    pub fn sct_data(&self) -> Option<&[u8]> {
        self.sct_data.as_deref()
    }

    /// Get the server's certificate chain (DER-encoded, leaf first).
    pub fn server_certs(&self) -> &[Vec<u8>] {
        &self.server_certs
    }

    /// Get the negotiated ALPN protocol (if any).
    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
    }

    /// Get the negotiated key exchange group (if any).
    pub fn negotiated_group(&self) -> Option<NamedGroup> {
        self.negotiated_group
    }

    /// Whether PSK mode was used (session resumed via PSK).
    pub fn is_psk_mode(&self) -> bool {
        self.psk_mode
    }

    /// Build the ClientHello handshake message.
    /// Returns the raw handshake message bytes (to be sent in a Handshake record).
    pub fn build_client_hello(&mut self) -> Result<Vec<u8>, TlsError> {
        if self.state != HandshakeState::Idle {
            return Err(TlsError::HandshakeFailed(
                "build_client_hello: wrong state".into(),
            ));
        }

        // Generate ephemeral key
        let group = self
            .config
            .supported_groups
            .first()
            .copied()
            .unwrap_or(NamedGroup::X25519);
        let kx = KeyExchange::generate(group)?;

        // Generate random
        let mut random = [0u8; 32];
        getrandom::getrandom(&mut random)
            .map_err(|_| TlsError::HandshakeFailed("random generation failed".into()))?;
        self.client_random = random;

        // Build extensions (with optional GREASE injection)
        let grease_enabled = self.config.grease;
        let mut extensions = if grease_enabled {
            vec![
                build_supported_versions_ch_grease(grease_value()),
                build_supported_groups_grease(&self.config.supported_groups, grease_value()),
                build_signature_algorithms_grease(
                    &self.config.signature_algorithms,
                    grease_value(),
                ),
                build_key_share_ch_grease(group, kx.public_key_bytes(), grease_value()),
            ]
        } else {
            vec![
                build_supported_versions_ch(),
                build_supported_groups(&self.config.supported_groups),
                build_signature_algorithms(&self.config.signature_algorithms),
                build_key_share_ch(group, kx.public_key_bytes()),
            ]
        };
        if !self.config.signature_algorithms_cert.is_empty() {
            extensions.push(build_signature_algorithms_cert(
                &self.config.signature_algorithms_cert,
            ));
        }
        if !self.config.certificate_authorities.is_empty() {
            extensions.push(build_certificate_authorities(
                &self.config.certificate_authorities,
            ));
        }
        if let Some(ref name) = self.config.server_name {
            extensions.push(build_server_name(name));
        }
        if self.config.post_handshake_auth {
            extensions.push(build_post_handshake_auth());
        }
        if !self.config.cert_compression_algos.is_empty() {
            extensions.push(build_compress_certificate(
                &self.config.cert_compression_algos,
            ));
            self.cert_compression_algos = self.config.cert_compression_algos.clone();
        }
        if self.config.record_size_limit > 0 {
            extensions.push(build_record_size_limit(
                self.config.record_size_limit.min(16385),
            ));
        }
        if self.config.enable_ocsp_stapling {
            extensions.push(build_status_request_ch());
        }
        if self.config.enable_sct {
            extensions.push(build_sct_ch());
        }

        // ALPN
        if !self.config.alpn_protocols.is_empty() {
            extensions.push(build_alpn(&self.config.alpn_protocols));
        }

        // Heartbeat extension (RFC 6520)
        if self.config.heartbeat_mode > 0 {
            extensions.push(build_heartbeat(self.config.heartbeat_mode));
        }

        // Trusted CA Keys (RFC 6066 §6)
        if !self.config.trusted_ca_keys.is_empty() {
            extensions.push(build_trusted_ca_keys(&self.config.trusted_ca_keys));
        }

        // USE_SRTP (RFC 5764)
        if !self.config.srtp_profiles.is_empty() {
            extensions.push(build_use_srtp(&self.config.srtp_profiles, &[]));
        }

        // STATUS_REQUEST_V2 / OCSP multi-stapling (RFC 6961)
        if self.config.enable_ocsp_multi_stapling {
            extensions.push(build_status_request_v2(&[2])); // ocsp_multi(2)
        }

        // Custom extensions
        extensions.extend(crate::extensions::build_custom_extensions(
            &self.config.custom_extensions,
            crate::extensions::ExtensionContext::CLIENT_HELLO,
        ));

        // GREASE empty extension (RFC 8701)
        if grease_enabled {
            extensions.push(build_grease_extension());
        }

        // PADDING extension (RFC 7685) — added before PSK (which MUST be last)
        if self.config.padding_target > 0 {
            // Compute current ClientHello encoded size estimate:
            // type(1) + length(3) + version(2) + random(32) + session_id_len(1) +
            // suites_len(2) + suites(2*N) + comp_len(1) + comp(1) + ext_len(2) + extensions
            let suites_size = 2 * self.config.cipher_suites.len();
            let ext_size: usize = extensions
                .iter()
                .map(|e| 4 + e.data.len()) // type(2) + length(2) + data
                .sum();
            let ch_size = 1 + 3 + 2 + 32 + 1 + 2 + suites_size + 1 + 1 + 2 + ext_size;
            let target = self.config.padding_target as usize;
            if ch_size + 4 < target {
                // Need (target - ch_size) more bytes total. The PADDING extension itself
                // takes 4 bytes overhead (type + length), so padding_data = needed - 4.
                let needed = target - ch_size;
                if needed > 4 {
                    extensions.push(build_padding(needed - 4));
                }
            }
        }

        // PSK extensions (pre_shared_key MUST be last)
        let has_psk = self.config.resumption_session.is_some();
        let offer_early_data = has_psk
            && self
                .config
                .resumption_session
                .as_ref()
                .is_some_and(|s| s.max_early_data > 0);
        if has_psk {
            extensions.push(build_psk_key_exchange_modes());
        }
        if offer_early_data {
            extensions.push(build_early_data_ch());
        }

        // Build cipher suites (with optional GREASE prepend)
        let mut cipher_suites = self.config.cipher_suites.clone();
        if grease_enabled {
            cipher_suites.insert(0, CipherSuite(grease_value()));
        }

        let ch = ClientHello {
            random,
            legacy_session_id: vec![],
            cipher_suites,
            extensions,
        };

        let mut msg = encode_client_hello(&ch);

        // If we have a resumption session, append PSK extension with binder
        if let Some(ref session) = self.config.resumption_session {
            let psk = session.psk.clone();
            let ticket = session.ticket.clone().unwrap_or_default();
            let age_add = session.ticket_age_add;

            // Compute obfuscated ticket age
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let real_age_ms = now.saturating_sub(session.created_at) * 1000;
            let obfuscated_age = (real_age_ms as u32).wrapping_add(age_add);

            // Determine hash length from the session's cipher suite
            let params = CipherSuiteParams::from_suite(session.cipher_suite)?;
            let hash_len = params.hash_len;

            // Build pre_shared_key extension with placeholder binder
            let placeholder_binder = vec![0u8; hash_len];
            let psk_ext =
                build_pre_shared_key_ch(&[(ticket, obfuscated_age)], &[placeholder_binder]);

            // Append the PSK extension to the CH message
            // The CH message format: type(1) || len(3) || body
            // body: version(2) || random(32) || session_id_len(1) || session_id ||
            //       suites_len(2) || suites || comp_len(1) || comp || ext_len(2) || extensions...
            // We need to:
            // 1. Encode the extension
            // 2. Append it to the extensions block
            // 3. Update the extensions length and the handshake message length
            let ext_data = {
                let mut buf = Vec::new();
                buf.extend_from_slice(&psk_ext.extension_type.0.to_be_bytes());
                buf.extend_from_slice(&(psk_ext.data.len() as u16).to_be_bytes());
                buf.extend_from_slice(&psk_ext.data);
                buf
            };

            // Update extensions length (last 2 bytes before extensions start)
            // Find extensions_len position: it's at msg[4 + body_offset]
            // Easier approach: update the raw bytes
            // Current msg length before adding PSK ext
            let old_msg_len = msg.len();

            // Append extension bytes
            msg.extend_from_slice(&ext_data);

            // Update handshake message length (bytes 1..4, 3 bytes big-endian)
            let new_body_len = msg.len() - 4;
            msg[1] = ((new_body_len >> 16) & 0xFF) as u8;
            msg[2] = ((new_body_len >> 8) & 0xFF) as u8;
            msg[3] = (new_body_len & 0xFF) as u8;

            // Update extensions length
            // Extensions length is a 2-byte field right before the first extension
            // We need to find it. In the CH body (starting at msg[4]):
            // version(2) + random(32) + session_id_len(1) + session_id +
            // suites_len(2) + suites + comp_len(1) + comp + ext_len(2) + extensions
            let body = &msg[4..];
            let mut pos = 2 + 32; // version + random
            let sid_len = body[pos] as usize;
            pos += 1 + sid_len;
            let suites_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
            pos += 2 + suites_len;
            let comp_len = body[pos] as usize;
            pos += 1 + comp_len;
            // pos now points to extensions_length (2 bytes)
            let ext_len_pos = 4 + pos; // absolute position in msg
            let old_ext_len = u16::from_be_bytes([msg[ext_len_pos], msg[ext_len_pos + 1]]) as usize;
            let new_ext_len = old_ext_len + ext_data.len();
            msg[ext_len_pos] = ((new_ext_len >> 8) & 0xFF) as u8;
            msg[ext_len_pos + 1] = (new_ext_len & 0xFF) as u8;

            // Now compute the binder
            // Truncated CH = msg minus the binder tail (2 + 1 + hash_len bytes)
            let binder_tail_size = 2 + 1 + hash_len;
            let truncated_ch = &msg[..msg.len() - binder_tail_size];

            // Set up temp KeySchedule for binder computation
            let mut ks = KeySchedule::new(params.clone());
            ks.derive_early_secret(Some(&psk))?;
            let binder_key = ks.derive_binder_key(false)?;
            let finished_key = ks.derive_finished_key(&binder_key)?;

            // Hash truncated CH
            let factory = params.hash_factory();
            let mut hasher = (*factory)();
            hasher.update(truncated_ch).map_err(TlsError::CryptoError)?;
            let mut hash = vec![0u8; hash_len];
            hasher.finish(&mut hash).map_err(TlsError::CryptoError)?;

            // Compute binder
            let binder = ks.compute_finished_verify_data(&finished_key, &hash)?;

            // Write binder into msg (replacing placeholder)
            let binder_start = msg.len() - hash_len;
            msg[binder_start..].copy_from_slice(&binder);

            // Store PSK for later use in process_server_hello
            self.psk = Some(psk);

            // Derive early exporter master secret (RFC 8446 §7.5)
            // Hash the full CH (with real binder) for the transcript
            {
                let mut eems_hasher = (*factory)();
                eems_hasher.update(&msg).map_err(TlsError::CryptoError)?;
                let mut eems_hash = vec![0u8; hash_len];
                eems_hasher
                    .finish(&mut eems_hash)
                    .map_err(TlsError::CryptoError)?;
                self.early_exporter_master_secret =
                    ks.derive_early_exporter_master_secret(&eems_hash)?;
            }

            // Derive early traffic secret for 0-RTT if offering early data
            if offer_early_data {
                // Hash the full CH (with real binder) for the early traffic secret
                let mut ch_hasher = (*factory)();
                ch_hasher.update(&msg).map_err(TlsError::CryptoError)?;
                let mut ch_hash = vec![0u8; hash_len];
                ch_hasher
                    .finish(&mut ch_hash)
                    .map_err(TlsError::CryptoError)?;
                self.early_traffic_secret = ks.derive_early_traffic_secret(&ch_hash)?;
                crate::crypt::keylog::log_key(
                    &self.config,
                    "CLIENT_EARLY_TRAFFIC_SECRET",
                    &self.client_random,
                    &self.early_traffic_secret,
                );
                self.offered_early_data = true;
            }

            let _ = old_msg_len; // suppress unused warning
        }

        self.client_hello_msg = msg.clone();
        self.key_exchange = Some(kx);
        self.state = HandshakeState::WaitServerHello;

        Ok(msg)
    }

    /// Process a ServerHello message (or HelloRetryRequest).
    ///
    /// `msg_data` is the full handshake message including the 4-byte header.
    /// Returns either handshake actions or a retry request.
    pub fn process_server_hello(&mut self, msg_data: &[u8]) -> Result<ServerHelloResult, TlsError> {
        if self.state != HandshakeState::WaitServerHello {
            return Err(TlsError::HandshakeFailed(
                "process_server_hello: wrong state".into(),
            ));
        }

        let body = get_body(msg_data)?;
        let sh = decode_server_hello(body)?;

        // Check supported_versions extension for TLS 1.3
        let version_ext = sh
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::SUPPORTED_VERSIONS)
            .ok_or_else(|| {
                TlsError::HandshakeFailed(
                    "missing supported_versions extension in ServerHello".into(),
                )
            })?;
        let version = parse_supported_versions_sh(&version_ext.data)?;
        if version != 0x0304 {
            return Err(TlsError::HandshakeFailed(format!(
                "unsupported TLS version: 0x{version:04x}"
            )));
        }

        // Negotiate cipher suite
        let suite = sh.cipher_suite;
        if !self.config.cipher_suites.contains(&suite) {
            return Err(TlsError::NoSharedCipherSuite);
        }

        // Detect HelloRetryRequest by magic random
        if sh.random == HELLO_RETRY_REQUEST_RANDOM {
            return self.process_hello_retry_request(msg_data, &sh, suite);
        }

        let params = CipherSuiteParams::from_suite(suite)?;

        // If the cipher suite uses SHA-384, re-initialize the transcript
        if params.hash_len == 48 && !self.hrr_done {
            self.transcript = TranscriptHash::new(|| Box::new(hitls_crypto::sha2::Sha384::new()));
        }

        // Feed ClientHello + ServerHello to transcript
        // (If HRR already done, transcript already contains MessageHash + HRR + CH2,
        //  so we only feed CH on the first time.)
        if !self.hrr_done {
            self.transcript.update(&self.client_hello_msg)?;
        }
        self.transcript.update(msg_data)?;

        // Extract key_share from ServerHello
        let ks_ext = sh
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::KEY_SHARE)
            .ok_or_else(|| TlsError::HandshakeFailed("missing key_share in ServerHello".into()))?;
        let (server_group, server_pub_key) = parse_key_share_sh(&ks_ext.data)?;
        self.negotiated_group = Some(server_group);

        // Verify group matches
        let kx = self
            .key_exchange
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no key exchange state".into()))?;
        if server_group != kx.group() {
            return Err(TlsError::HandshakeFailed(
                "server key_share group mismatch".into(),
            ));
        }

        // Compute shared secret
        let shared_secret = kx.compute_shared_secret(&server_pub_key)?;

        // Check for pre_shared_key extension in ServerHello
        let psk_selected = sh
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::PRE_SHARED_KEY)
            .map(|e| parse_pre_shared_key_sh(&e.data))
            .transpose()?;
        if let Some(idx) = psk_selected {
            if idx != 0 {
                return Err(TlsError::HandshakeFailed(
                    "server selected unexpected PSK identity".into(),
                ));
            }
            if self.psk.is_none() {
                return Err(TlsError::HandshakeFailed(
                    "server accepted PSK but we didn't offer one".into(),
                ));
            }
            self.psk_mode = true;
        }

        // Parse custom extensions in ServerHello
        crate::extensions::parse_custom_extensions(
            &self.config.custom_extensions,
            crate::extensions::ExtensionContext::SERVER_HELLO,
            &sh.extensions,
        )?;

        // Key schedule: Early Secret → Handshake Secret
        let mut ks = KeySchedule::new(params.clone());
        ks.derive_early_secret(self.psk.as_deref())?;

        // Derive early exporter master secret before advancing to handshake stage
        // (requires EarlySecret stage; uses Hash(ClientHello) as transcript)
        if self.psk.is_some() {
            let ch_hash = self.transcript.current_hash()?;
            self.early_exporter_master_secret = ks.derive_early_exporter_master_secret(&ch_hash)?;
        }

        ks.derive_handshake_secret(&shared_secret)?;

        // Derive handshake traffic secrets
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

        // Derive traffic keys
        let server_hs_keys = TrafficKeys::derive(&params, &server_hs_secret)?;
        let client_hs_keys = TrafficKeys::derive(&params, &client_hs_secret)?;

        // Save secrets for later (finished key derivation)
        self.client_hs_secret = client_hs_secret;
        self.server_hs_secret = server_hs_secret;
        self.key_schedule = Some(ks);
        self.params = Some(params);
        self.negotiated_suite = Some(suite);
        self.state = HandshakeState::WaitEncryptedExtensions;

        Ok(ServerHelloResult::Actions(ServerHelloActions {
            server_hs_keys,
            client_hs_keys,
            suite,
        }))
    }

    /// Handle a HelloRetryRequest (ServerHello with magic random).
    fn process_hello_retry_request(
        &mut self,
        msg_data: &[u8],
        sh: &super::codec::ServerHello,
        suite: CipherSuite,
    ) -> Result<ServerHelloResult, TlsError> {
        if self.hrr_done {
            return Err(TlsError::HandshakeFailed(
                "received second HelloRetryRequest".into(),
            ));
        }

        let params = CipherSuiteParams::from_suite(suite)?;

        // Re-init transcript if SHA-384
        if params.hash_len == 48 {
            self.transcript = TranscriptHash::new(|| Box::new(hitls_crypto::sha2::Sha384::new()));
        }

        // Feed original CH to transcript, then replace with message_hash
        self.transcript.update(&self.client_hello_msg)?;
        self.transcript.replace_with_message_hash()?;

        // Feed HRR to transcript
        self.transcript.update(msg_data)?;

        // Extract selected group from key_share extension
        let ks_ext = sh
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::KEY_SHARE)
            .ok_or_else(|| TlsError::HandshakeFailed("missing key_share in HRR".into()))?;
        let selected_group = parse_key_share_hrr(&ks_ext.data)?;

        // Extract cookie if present
        let cookie = sh
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::COOKIE)
            .map(|e| parse_cookie(&e.data))
            .transpose()?;

        // Save state
        self.params = Some(params);
        self.negotiated_suite = Some(suite);
        self.hrr_done = true;

        Ok(ServerHelloResult::RetryNeeded(RetryActions {
            selected_group,
            cookie,
            suite,
        }))
    }

    /// Build a retried ClientHello after HelloRetryRequest.
    ///
    /// Generates a new key exchange for the selected group and builds a new ClientHello.
    pub fn build_client_hello_retry(&mut self, retry: &RetryActions) -> Result<Vec<u8>, TlsError> {
        // Generate new key exchange for the selected group
        let kx = KeyExchange::generate(retry.selected_group)?;

        let mut random = [0u8; 32];
        getrandom::getrandom(&mut random)
            .map_err(|_| TlsError::HandshakeFailed("random generation failed".into()))?;

        let mut extensions = vec![
            build_supported_versions_ch(),
            build_supported_groups(&self.config.supported_groups),
            build_signature_algorithms(&self.config.signature_algorithms),
            build_key_share_ch(retry.selected_group, kx.public_key_bytes()),
        ];
        if !self.config.signature_algorithms_cert.is_empty() {
            extensions.push(build_signature_algorithms_cert(
                &self.config.signature_algorithms_cert,
            ));
        }
        if let Some(ref name) = self.config.server_name {
            extensions.push(build_server_name(name));
        }
        if let Some(ref cookie) = retry.cookie {
            extensions.push(build_cookie(cookie));
        }
        if !self.cert_compression_algos.is_empty() {
            extensions.push(build_compress_certificate(&self.cert_compression_algos));
        }
        if self.config.record_size_limit > 0 {
            extensions.push(build_record_size_limit(
                self.config.record_size_limit.min(16385),
            ));
        }
        if self.config.enable_ocsp_stapling {
            extensions.push(build_status_request_ch());
        }
        if self.config.enable_sct {
            extensions.push(build_sct_ch());
        }
        if !self.config.alpn_protocols.is_empty() {
            extensions.push(build_alpn(&self.config.alpn_protocols));
        }

        let ch = ClientHello {
            random,
            legacy_session_id: vec![],
            cipher_suites: self.config.cipher_suites.clone(),
            extensions,
        };

        let msg = encode_client_hello(&ch);
        self.transcript.update(&msg)?;
        self.key_exchange = Some(kx);
        self.state = HandshakeState::WaitServerHello;

        Ok(msg)
    }

    /// Process an EncryptedExtensions message.
    pub fn process_encrypted_extensions(&mut self, msg_data: &[u8]) -> Result<(), TlsError> {
        if self.state != HandshakeState::WaitEncryptedExtensions {
            return Err(TlsError::HandshakeFailed(
                "process_encrypted_extensions: wrong state".into(),
            ));
        }

        let body = get_body(msg_data)?;
        let ee = decode_encrypted_extensions(body)?;

        // Process extensions from EncryptedExtensions
        for ext in &ee.extensions {
            match ext.extension_type {
                ExtensionType::EARLY_DATA => {
                    if self.offered_early_data {
                        self.early_data_accepted = true;
                    }
                }
                ExtensionType::RECORD_SIZE_LIMIT => {
                    let peer_limit = parse_record_size_limit(&ext.data)?;
                    // TLS 1.3: subtract 1 for content type byte
                    self.peer_record_size_limit = Some(peer_limit.saturating_sub(1));
                }
                ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
                    let proto = parse_alpn_sh(&ext.data)?;
                    self.negotiated_alpn = Some(proto);
                }
                _ => {}
            }
        }

        // Parse custom extensions in EncryptedExtensions
        crate::extensions::parse_custom_extensions(
            &self.config.custom_extensions,
            crate::extensions::ExtensionContext::ENCRYPTED_EXTENSIONS,
            &ee.extensions,
        )?;

        self.transcript.update(msg_data)?;
        // In PSK mode, server skips Certificate + CertificateVerify
        if self.psk_mode {
            self.state = HandshakeState::WaitFinished;
        } else {
            self.state = HandshakeState::WaitCertCertReq;
        }
        Ok(())
    }

    /// Process a Certificate message.
    pub fn process_certificate(&mut self, msg_data: &[u8]) -> Result<(), TlsError> {
        if self.state != HandshakeState::WaitCertCertReq {
            return Err(TlsError::HandshakeFailed(
                "process_certificate: wrong state".into(),
            ));
        }

        let body = get_body(msg_data)?;
        let cert_msg = decode_certificate(body)?;

        if cert_msg.certificate_list.is_empty() {
            return Err(TlsError::HandshakeFailed("empty certificate list".into()));
        }

        // Store DER-encoded certificates
        self.server_certs = cert_msg
            .certificate_list
            .iter()
            .map(|e| e.cert_data.clone())
            .collect();

        // Extract OCSP/SCT from leaf certificate entry extensions
        if let Some(leaf_entry) = cert_msg.certificate_list.first() {
            for ext in &leaf_entry.extensions {
                match ext.extension_type {
                    ExtensionType::STATUS_REQUEST => {
                        self.ocsp_response = Some(parse_status_request_cert_entry(&ext.data)?);
                    }
                    ExtensionType::SIGNED_CERTIFICATE_TIMESTAMP => {
                        self.sct_data = Some(ext.data.clone());
                    }
                    _ => {}
                }
            }
        }

        self.transcript.update(msg_data)?;

        crate::cert_verify::verify_server_certificate(&self.config, &self.server_certs)?;

        self.state = HandshakeState::WaitCertVerify;
        Ok(())
    }

    /// Process a CompressedCertificate message (RFC 8879).
    #[cfg(feature = "cert-compression")]
    pub fn process_compressed_certificate(&mut self, msg_data: &[u8]) -> Result<(), TlsError> {
        if self.state != HandshakeState::WaitCertCertReq {
            return Err(TlsError::HandshakeFailed(
                "process_compressed_certificate: wrong state".into(),
            ));
        }

        let body = get_body(msg_data)?;
        let compressed_msg = decode_compressed_certificate(body)?;

        // Verify we offered this algorithm
        if !self
            .cert_compression_algos
            .contains(&compressed_msg.algorithm)
        {
            return Err(TlsError::HandshakeFailed(
                "server used cert compression algorithm we didn't offer".into(),
            ));
        }

        // Decompress to recover the original Certificate message body
        let cert_body = decompress_certificate_body(
            compressed_msg.algorithm,
            &compressed_msg.compressed_data,
            compressed_msg.uncompressed_length,
        )?;

        let cert_msg = decode_certificate(&cert_body)?;

        if cert_msg.certificate_list.is_empty() {
            return Err(TlsError::HandshakeFailed("empty certificate list".into()));
        }

        // Store DER-encoded certificates
        self.server_certs = cert_msg
            .certificate_list
            .iter()
            .map(|e| e.cert_data.clone())
            .collect();

        // RFC 8879 §4: transcript uses the CompressedCertificate message as-is
        self.transcript.update(msg_data)?;
        self.state = HandshakeState::WaitCertVerify;
        Ok(())
    }

    /// Process a CertificateVerify message.
    pub fn process_certificate_verify(&mut self, msg_data: &[u8]) -> Result<(), TlsError> {
        if self.state != HandshakeState::WaitCertVerify {
            return Err(TlsError::HandshakeFailed(
                "process_certificate_verify: wrong state".into(),
            ));
        }

        let body = get_body(msg_data)?;
        let cv = decode_certificate_verify(body)?;

        // Get transcript hash BEFORE this message (for signature verification)
        let transcript_hash = self.transcript.current_hash()?;

        // Parse the server's end-entity certificate
        if self.config.verify_peer {
            let cert_der = self
                .server_certs
                .first()
                .ok_or_else(|| TlsError::HandshakeFailed("no server certificate".into()))?;
            let cert = hitls_pki::x509::Certificate::from_der(cert_der)
                .map_err(|e| TlsError::HandshakeFailed(format!("cert parse error: {e}")))?;

            verify_certificate_verify(&cert, cv.algorithm, &cv.signature, &transcript_hash, true)?;
        }

        // Feed this message to the transcript
        self.transcript.update(msg_data)?;
        self.state = HandshakeState::WaitFinished;
        Ok(())
    }

    /// Process the server Finished message.
    ///
    /// Returns actions for activating application keys and sending client Finished.
    pub fn process_finished(&mut self, msg_data: &[u8]) -> Result<FinishedActions, TlsError> {
        if self.state != HandshakeState::WaitFinished {
            return Err(TlsError::HandshakeFailed(
                "process_finished: wrong state".into(),
            ));
        }

        let params = self
            .params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher suite params".into()))?
            .clone();
        let ks = self
            .key_schedule
            .as_mut()
            .ok_or_else(|| TlsError::HandshakeFailed("no key schedule".into()))?;

        let body = get_body(msg_data)?;
        let fin = decode_finished(body, params.hash_len)?;

        // Verify server Finished
        let server_finished_key = ks.derive_finished_key(&self.server_hs_secret)?;
        let transcript_hash = self.transcript.current_hash()?;
        let expected = ks.compute_finished_verify_data(&server_finished_key, &transcript_hash)?;

        if !bool::from(fin.verify_data.ct_eq(&expected)) {
            return Err(TlsError::HandshakeFailed(
                "server Finished verify_data mismatch".into(),
            ));
        }

        // Feed server Finished to transcript
        self.transcript.update(msg_data)?;

        // Derive Master Secret
        ks.derive_master_secret()?;

        // Derive application traffic secrets from Hash(CH..server Finished)
        // NOTE: EOED must NOT be in transcript yet (RFC 8446 §7.1)
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

        // Derive exporter master secret (RFC 8446 §7.5)
        let exporter_master_secret = ks.derive_exporter_master_secret(&transcript_hash_sf)?;
        crate::crypt::keylog::log_key(
            &self.config,
            "EXPORTER_SECRET",
            &self.client_random,
            &exporter_master_secret,
        );

        let suite = self
            .negotiated_suite
            .ok_or_else(|| TlsError::HandshakeFailed("no negotiated suite".into()))?;
        let client_app_keys = TrafficKeys::derive(&params, &client_app_secret)?;
        let server_app_keys = TrafficKeys::derive(&params, &server_app_secret)?;

        // If 0-RTT was accepted, add EndOfEarlyData to transcript AFTER app secrets
        // but BEFORE client Finished (RFC 8446 §4.4.4: client Finished context includes EOED)
        let eoed_msg = if self.early_data_accepted {
            let msg = encode_end_of_early_data();
            self.transcript.update(&msg)?;
            Some(msg)
        } else {
            None
        };

        // Build client Finished from Hash(CH..server Finished [.. EOED])
        let transcript_hash_for_cfin = self.transcript.current_hash()?;
        let client_finished_key = ks.derive_finished_key(&self.client_hs_secret)?;
        let client_verify_data =
            ks.compute_finished_verify_data(&client_finished_key, &transcript_hash_for_cfin)?;
        let client_finished_msg = encode_finished(&client_verify_data);

        // Feed client Finished to transcript (for resumption master secret)
        self.transcript.update(&client_finished_msg)?;

        // Derive resumption master secret
        let transcript_hash_cf = self.transcript.current_hash()?;
        let resumption_master_secret = ks.derive_resumption_master_secret(&transcript_hash_cf)?;

        self.state = HandshakeState::Connected;

        Ok(FinishedActions {
            client_finished_msg,
            client_app_keys,
            server_app_keys,
            suite,
            client_app_secret,
            server_app_secret,
            cipher_params: params,
            resumption_master_secret,
            exporter_master_secret,
            early_exporter_master_secret: std::mem::take(&mut self.early_exporter_master_secret),
            end_of_early_data_msg: eoed_msg,
        })
    }

    /// Process a NewSessionTicket message received post-handshake.
    ///
    /// Returns a `TlsSession` that can be stored for future resumption.
    pub fn process_new_session_ticket(
        &self,
        msg_data: &[u8],
        resumption_master_secret: &[u8],
    ) -> Result<TlsSession, TlsError> {
        let body = get_body(msg_data)?;
        let nst = decode_new_session_ticket(body)?;

        let params = self
            .params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher suite params".into()))?;
        let ks = KeySchedule::new(params.clone());

        // Derive PSK from resumption_master_secret + ticket_nonce
        let psk = ks.derive_resumption_psk(resumption_master_secret, &nst.ticket_nonce)?;

        let suite = self
            .negotiated_suite
            .ok_or_else(|| TlsError::HandshakeFailed("no negotiated suite".into()))?;

        // Extract max_early_data from NST extensions (early_data extension)
        let max_early_data = nst
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::EARLY_DATA)
            .and_then(|e| {
                if e.data.len() >= 4 {
                    Some(u32::from_be_bytes([
                        e.data[0], e.data[1], e.data[2], e.data[3],
                    ]))
                } else {
                    None
                }
            })
            .unwrap_or(0);

        Ok(TlsSession {
            id: nst.ticket.clone(),
            cipher_suite: suite,
            master_secret: resumption_master_secret.to_vec(),
            alpn_protocol: None,
            ticket: Some(nst.ticket),
            ticket_lifetime: nst.ticket_lifetime,
            max_early_data,
            ticket_age_add: nst.ticket_age_add,
            ticket_nonce: nst.ticket_nonce,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            psk,
            extended_master_secret: false,
        })
    }
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

    #[test]
    fn test_client_handshake_init() {
        let config = TlsConfig::builder().build();
        let hs = ClientHandshake::new(config);
        assert_eq!(hs.state(), HandshakeState::Idle);
    }

    #[test]
    fn test_client_hello_generation() {
        let config = TlsConfig::builder().server_name("example.com").build();
        let mut hs = ClientHandshake::new(config);

        let ch_msg = hs.build_client_hello().unwrap();
        assert_eq!(hs.state(), HandshakeState::WaitServerHello);

        // Verify it's a valid handshake message
        assert!(ch_msg.len() > 4);
        assert_eq!(ch_msg[0], 1); // ClientHello type

        // Cannot build ClientHello again
        assert!(hs.build_client_hello().is_err());
    }

    #[test]
    fn test_state_enforcement() {
        let config = TlsConfig::builder().build();
        let mut hs = ClientHandshake::new(config);

        // Can't process ServerHello before ClientHello
        assert!(hs.process_server_hello(&[2, 0, 0, 4, 0, 0, 0, 0]).is_err());

        // Can't process EncryptedExtensions from Idle
        assert!(hs
            .process_encrypted_extensions(&[8, 0, 0, 2, 0, 0])
            .is_err());

        // Can't process Certificate from Idle
        assert!(hs.process_certificate(&[11, 0, 0, 4, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn test_certificate_verify_wrong_state() {
        let config = TlsConfig::builder().build();
        let mut hs = ClientHandshake::new(config);
        // CertificateVerify from Idle → error
        assert!(hs
            .process_certificate_verify(&[15, 0, 0, 4, 0, 0, 0, 0])
            .is_err());
    }

    #[test]
    fn test_finished_wrong_state() {
        let config = TlsConfig::builder().build();
        let mut hs = ClientHandshake::new(config);
        // Finished from Idle → error
        assert!(hs
            .process_finished(&[
                20, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0
            ])
            .is_err());
    }

    #[cfg(feature = "cert-compression")]
    #[test]
    fn test_compressed_certificate_wrong_state() {
        let config = TlsConfig::builder().build();
        let mut hs = ClientHandshake::new(config);
        // CompressedCertificate from Idle → error
        assert!(hs
            .process_compressed_certificate(&[25, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0])
            .is_err());
    }

    #[test]
    fn test_new_session_ticket_wrong_state() {
        let config = TlsConfig::builder().build();
        let hs = ClientHandshake::new(config);
        // NST from Idle → error (no cipher suite params)
        assert!(hs
            .process_new_session_ticket(&[4, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[])
            .is_err());
    }

    #[test]
    fn test_client_hello_has_supported_versions() {
        let config = TlsConfig::builder().server_name("example.com").build();
        let mut hs = ClientHandshake::new(config);
        let ch_msg = hs.build_client_hello().unwrap();

        // Verify the CH bytes contain the supported_versions extension type (0x002B)
        let found = ch_msg.windows(2).any(|w| w[0] == 0x00 && w[1] == 0x2B);
        assert!(
            found,
            "ClientHello must contain supported_versions extension (0x002B)"
        );
    }

    /// Parse extension types from a raw ClientHello handshake message.
    /// Returns a list of (type_u16) for each extension found.
    fn parse_extension_types(ch_msg: &[u8]) -> Vec<u16> {
        // Skip handshake header: type(1) + length(3) = 4
        let mut pos = 4;
        // version(2) + random(32)
        pos += 2 + 32;
        if pos >= ch_msg.len() {
            return vec![];
        }
        // session_id
        let sid_len = ch_msg[pos] as usize;
        pos += 1 + sid_len;
        // cipher_suites
        if pos + 2 > ch_msg.len() {
            return vec![];
        }
        let suites_len = u16::from_be_bytes([ch_msg[pos], ch_msg[pos + 1]]) as usize;
        pos += 2 + suites_len;
        // compression_methods
        if pos >= ch_msg.len() {
            return vec![];
        }
        let comp_len = ch_msg[pos] as usize;
        pos += 1 + comp_len;
        // extensions_length
        if pos + 2 > ch_msg.len() {
            return vec![];
        }
        let ext_total = u16::from_be_bytes([ch_msg[pos], ch_msg[pos + 1]]) as usize;
        pos += 2;
        let ext_end = pos + ext_total;
        let mut types = Vec::new();
        while pos + 4 <= ext_end && pos + 4 <= ch_msg.len() {
            let etype = u16::from_be_bytes([ch_msg[pos], ch_msg[pos + 1]]);
            let elen = u16::from_be_bytes([ch_msg[pos + 2], ch_msg[pos + 3]]) as usize;
            types.push(etype);
            pos += 4 + elen;
        }
        types
    }

    #[test]
    fn test_padding_in_tls13_client_hello() {
        let config = TlsConfig::builder()
            .server_name("example.com")
            .padding_target(512)
            .build();
        let mut hs = ClientHandshake::new(config);
        let ch_msg = hs.build_client_hello().unwrap();

        // PADDING extension type is 21 (0x0015)
        let ext_types = parse_extension_types(&ch_msg);
        assert!(
            ext_types.contains(&21),
            "ClientHello should contain PADDING extension"
        );
        // The CH message should be close to the target size
        assert!(
            ch_msg.len() >= 508,
            "CH len {} should be near target 512",
            ch_msg.len()
        );
    }

    #[test]
    fn test_no_padding_when_disabled() {
        let config = TlsConfig::builder()
            .server_name("example.com")
            .padding_target(0)
            .build();
        let mut hs = ClientHandshake::new(config);
        let ch_msg = hs.build_client_hello().unwrap();

        // PADDING extension type is 21 (0x0015) — must NOT appear
        let ext_types = parse_extension_types(&ch_msg);
        assert!(
            !ext_types.contains(&21),
            "ClientHello should NOT contain PADDING extension when disabled"
        );
    }

    #[test]
    fn test_no_padding_when_already_large() {
        // Set a very small target that the CH already exceeds
        let config = TlsConfig::builder()
            .server_name("example.com")
            .padding_target(10)
            .build();
        let mut hs = ClientHandshake::new(config);
        let ch_msg = hs.build_client_hello().unwrap();

        // PADDING extension should NOT be present since CH already exceeds target
        let ext_types = parse_extension_types(&ch_msg);
        assert!(
            !ext_types.contains(&21),
            "ClientHello should NOT contain PADDING when already exceeding target"
        );
    }

    #[test]
    fn test_grease_in_client_hello() {
        use crate::handshake::extensions_codec::is_grease_value;

        let config = TlsConfig::builder().grease(true).build();
        let mut hs = ClientHandshake::new(config);
        let ch_msg = hs.build_client_hello().unwrap();

        // Parse the ClientHello to check for GREASE values
        // The CH starts with type(1) + length(3) + version(2) + random(32) +
        // session_id_len(1) + session_id + suites_len(2) + suites...
        let pos = 4; // skip type + length
        let _version = u16::from_be_bytes([ch_msg[pos], ch_msg[pos + 1]]);
        let sid_len = ch_msg[pos + 2 + 32] as usize;
        let suites_offset = pos + 2 + 32 + 1 + sid_len;
        let suites_len =
            u16::from_be_bytes([ch_msg[suites_offset], ch_msg[suites_offset + 1]]) as usize;

        // Check that at least one GREASE cipher suite exists (should be first)
        let first_suite =
            u16::from_be_bytes([ch_msg[suites_offset + 2], ch_msg[suites_offset + 3]]);
        assert!(
            is_grease_value(first_suite),
            "first cipher suite should be GREASE, got {first_suite:#06X}"
        );

        // Check that at least one GREASE extension type exists in the message
        // by scanning for any 2-byte window matching the GREASE pattern in extension area
        let comp_offset = suites_offset + 2 + suites_len;
        let _comp_len = ch_msg[comp_offset] as usize;
        let ext_offset = comp_offset + 1 + _comp_len;
        let ext_total_len =
            u16::from_be_bytes([ch_msg[ext_offset], ch_msg[ext_offset + 1]]) as usize;
        let ext_data = &ch_msg[ext_offset + 2..ext_offset + 2 + ext_total_len];

        // Scan for any extension with a GREASE type
        let mut found_grease_ext = false;
        let mut p = 0;
        while p + 4 <= ext_data.len() {
            let etype = u16::from_be_bytes([ext_data[p], ext_data[p + 1]]);
            let elen = u16::from_be_bytes([ext_data[p + 2], ext_data[p + 3]]) as usize;
            if is_grease_value(etype) {
                found_grease_ext = true;
                break;
            }
            p += 4 + elen;
        }
        assert!(
            found_grease_ext,
            "ClientHello should contain a GREASE extension"
        );
    }

    #[test]
    fn test_no_grease_when_disabled() {
        use crate::handshake::extensions_codec::is_grease_value;

        let config = TlsConfig::builder().grease(false).build();
        let mut hs = ClientHandshake::new(config);
        let ch_msg = hs.build_client_hello().unwrap();

        // Parse cipher suites — none should be GREASE
        let pos = 4;
        let sid_len = ch_msg[pos + 2 + 32] as usize;
        let suites_offset = pos + 2 + 32 + 1 + sid_len;
        let suites_len =
            u16::from_be_bytes([ch_msg[suites_offset], ch_msg[suites_offset + 1]]) as usize;
        let mut s = suites_offset + 2;
        while s + 2 <= suites_offset + 2 + suites_len {
            let suite = u16::from_be_bytes([ch_msg[s], ch_msg[s + 1]]);
            assert!(
                !is_grease_value(suite),
                "no GREASE cipher suite expected, found {suite:#06X}"
            );
            s += 2;
        }
    }

    #[test]
    fn test_client_hello_has_alpn_when_configured() {
        let config = TlsConfig::builder()
            .server_name("example.com")
            .alpn(&[b"h2", b"http/1.1"])
            .build();
        let mut hs = ClientHandshake::new(config);
        let ch_msg = hs.build_client_hello().unwrap();

        // ALPN extension type = 0x0010 (16)
        let has_alpn = ch_msg.windows(2).any(|w| w[0] == 0x00 && w[1] == 0x10);
        assert!(has_alpn, "ClientHello must contain ALPN extension (0x0010)");

        // "h2" is 2 bytes, so look for the h2 bytes in the raw message
        assert!(
            ch_msg.windows(2).any(|w| w == b"h2"),
            "ClientHello should contain 'h2' protocol"
        );
    }

    #[test]
    fn test_client_hello_has_sni_extension() {
        let config = TlsConfig::builder().server_name("test.example.com").build();
        let mut hs = ClientHandshake::new(config);
        let ch_msg = hs.build_client_hello().unwrap();

        // SNI extension type = 0x0000 (0)
        // Check that the hostname bytes appear in the message
        assert!(
            ch_msg.windows(16).any(|w| w == b"test.example.com"),
            "ClientHello should contain server_name 'test.example.com'"
        );
    }

    #[test]
    fn test_client_hello_signature_algorithms_cert() {
        let config = TlsConfig::builder()
            .server_name("example.com")
            .signature_algorithms_cert(&[
                crate::crypt::SignatureScheme::ECDSA_SECP256R1_SHA256,
                crate::crypt::SignatureScheme::RSA_PSS_RSAE_SHA256,
            ])
            .build();
        let mut hs = ClientHandshake::new(config);
        let ch_msg = hs.build_client_hello().unwrap();

        // signature_algorithms_cert extension type = 0x0032 (50)
        let has_sig_alg_cert = ch_msg.windows(2).any(|w| w[0] == 0x00 && w[1] == 0x32);
        assert!(
            has_sig_alg_cert,
            "ClientHello should contain signature_algorithms_cert (0x0032)"
        );
    }

    #[test]
    fn test_client_hello_certificate_authorities() {
        use hitls_pki::x509::{CertificateBuilder, DistinguishedName, SigningKey};
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".into(), "Test CA".into())],
        };
        let ca = CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_900_000_000).unwrap();

        let config = TlsConfig::builder()
            .server_name("example.com")
            .certificate_authorities(vec![ca.raw])
            .build();
        let mut hs = ClientHandshake::new(config);
        let ch_msg = hs.build_client_hello().unwrap();

        // certificate_authorities extension type = 0x002F (47)
        let has_ca = ch_msg.windows(2).any(|w| w[0] == 0x00 && w[1] == 0x2F);
        assert!(
            has_ca,
            "ClientHello should contain certificate_authorities (0x002F)"
        );
    }

    #[test]
    fn test_client_accessors_after_init() {
        let config = TlsConfig::builder().build();
        let hs = ClientHandshake::new(config);
        // All accessors should return safe defaults before handshake
        assert!(!hs.offered_early_data());
        assert!(!hs.early_data_accepted());
        assert!(hs.early_traffic_secret().is_empty());
        assert!(hs.peer_record_size_limit().is_none());
        assert!(hs.ocsp_response().is_none());
        assert!(hs.sct_data().is_none());
        assert!(hs.server_certs().is_empty());
        assert!(hs.negotiated_alpn().is_none());
        assert!(hs.negotiated_group().is_none());
        assert!(!hs.is_psk_mode());
    }

    #[test]
    fn test_client_hello_with_heartbeat_extension() {
        let config = TlsConfig::builder()
            .server_name("example.com")
            .heartbeat_mode(1)
            .build();
        let mut hs = ClientHandshake::new(config);
        let ch_msg = hs.build_client_hello().unwrap();

        // Heartbeat extension type = 0x000F (15)
        let ext_types = parse_extension_types(&ch_msg);
        assert!(
            ext_types.contains(&0x000F),
            "ClientHello should contain heartbeat extension (0x000F)"
        );
    }

    #[test]
    fn test_client_hello_default_has_supported_groups() {
        let config = TlsConfig::builder().server_name("example.com").build();
        let mut hs = ClientHandshake::new(config);
        let ch_msg = hs.build_client_hello().unwrap();

        // supported_groups extension type = 0x000A (10)
        let ext_types = parse_extension_types(&ch_msg);
        assert!(
            ext_types.contains(&0x000A),
            "ClientHello should contain supported_groups (0x000A)"
        );
    }

    #[test]
    fn test_client_new_session_ticket_no_params() {
        let config = TlsConfig::builder().build();
        let hs = ClientHandshake::new(config);
        // No params set (no handshake done) → error on NST processing
        let fake_nst = vec![4, 0, 0, 12, 0, 0, 0, 10, 0, 0, 0, 1, 0, 0, 1, 0x42];
        assert!(hs
            .process_new_session_ticket(&fake_nst, &[0u8; 48])
            .is_err());
    }

    #[test]
    fn test_client_process_finished_wrong_state_idle() {
        let config = TlsConfig::builder().build();
        let mut hs = ClientHandshake::new(config);
        // Finished from Idle → error
        assert!(hs
            .process_finished(&[20, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            .is_err());
    }

    // ===================================================================
    // 0-RTT Early Data offering tests (Testing-Phase 91)
    // ===================================================================

    /// Client without resumption_session should NOT offer early data.
    #[test]
    fn test_client_no_psk_no_early_data_offered() {
        let config = TlsConfig::builder().max_early_data_size(16384).build();
        let mut hs = ClientHandshake::new(config);
        let _ch = hs.build_client_hello().unwrap();
        assert!(
            !hs.offered_early_data(),
            "no resumption session → must not offer early data"
        );
        assert!(hs.early_traffic_secret().is_empty());
    }

    /// Client with session that has max_early_data=0 should NOT offer early data.
    #[test]
    fn test_client_session_zero_max_early_data_not_offered() {
        let session = crate::session::TlsSession {
            id: Vec::new(),
            cipher_suite: crate::CipherSuite::TLS_AES_128_GCM_SHA256,
            master_secret: vec![0x01; 32],
            alpn_protocol: None,
            ticket: Some(vec![0xAA; 16]),
            ticket_lifetime: 3600,
            max_early_data: 0, // zero → no early data
            ticket_age_add: 0,
            ticket_nonce: vec![0x01],
            created_at: 0,
            psk: vec![0x01; 32],
            extended_master_secret: false,
        };

        let config = TlsConfig::builder()
            .resumption_session(session)
            .max_early_data_size(16384)
            .build();
        let mut hs = ClientHandshake::new(config);
        let _ch = hs.build_client_hello().unwrap();
        assert!(
            !hs.offered_early_data(),
            "session.max_early_data=0 → must not offer early data"
        );
    }
}
