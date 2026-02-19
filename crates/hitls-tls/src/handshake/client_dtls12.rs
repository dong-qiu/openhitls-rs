//! DTLS 1.2 client handshake state machine.
//!
//! Mirrors the TLS 1.2 client handshake (client12.rs) but uses DTLS-specific
//! record framing, 12-byte handshake headers, cookie exchange, and
//! transcript hashing with TLS-format headers (RFC 6347 §4.2.6).

use crate::config::TlsConfig;
use crate::crypt::key_schedule12::{compute_verify_data, derive_key_block, derive_master_secret};
use crate::crypt::transcript::TranscriptHash;
use crate::crypt::{NamedGroup, Tls12CipherSuiteParams};
use crate::handshake::codec::ServerHello;
use crate::handshake::codec12::{build_ske_params, build_ske_signed_data, ServerKeyExchange};
use crate::handshake::codec_dtls::{
    dtls_to_tls_handshake, encode_dtls_client_hello_body, wrap_dtls_handshake_full,
};
use crate::handshake::key_exchange::KeyExchange;
use crate::handshake::HandshakeType;
use crate::CipherSuite;
use hitls_crypto::sha2::Sha256;
use hitls_types::TlsError;
use zeroize::Zeroize;

/// DTLS 1.2 client handshake states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dtls12ClientState {
    Idle,
    WaitHelloVerifyRequest,
    WaitServerHello,
    WaitCertificate,
    WaitServerKeyExchange,
    WaitServerHelloDone,
    WaitChangeCipherSpec,
    WaitFinished,
    Connected,
}

/// Result of processing ServerHelloDone — contains the client flight.
pub struct DtlsClientFlightResult {
    /// ClientKeyExchange DTLS handshake message.
    pub client_key_exchange: Vec<u8>,
    /// Finished DTLS handshake message.
    pub finished: Vec<u8>,
    /// Master secret.
    pub master_secret: Vec<u8>,
    /// Key material.
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
}

impl Drop for DtlsClientFlightResult {
    fn drop(&mut self) {
        self.master_secret.zeroize();
        self.client_write_key.zeroize();
        self.server_write_key.zeroize();
        self.client_write_iv.zeroize();
        self.server_write_iv.zeroize();
    }
}

/// Keys derived from a cached session for abbreviated handshake.
pub struct DtlsAbbreviatedClientKeys {
    pub suite: CipherSuite,
    pub master_secret: Vec<u8>,
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
}

impl Drop for DtlsAbbreviatedClientKeys {
    fn drop(&mut self) {
        self.master_secret.zeroize();
        self.client_write_key.zeroize();
        self.server_write_key.zeroize();
        self.client_write_iv.zeroize();
        self.server_write_iv.zeroize();
    }
}

/// DTLS 1.2 client handshake state machine.
pub struct Dtls12ClientHandshake {
    config: TlsConfig,
    state: Dtls12ClientState,
    params: Option<Tls12CipherSuiteParams>,
    transcript: TranscriptHash,
    client_random: [u8; 32],
    server_random: [u8; 32],
    server_certs: Vec<Vec<u8>>,
    server_ecdh_public: Vec<u8>,
    server_named_curve: u16,
    /// Next message_seq to assign to outgoing messages.
    message_seq: u16,
    /// Cookie from HelloVerifyRequest.
    cookie: Vec<u8>,
    /// Stored ClientHello body for transcript replay on hash switch.
    client_hello_tls_bytes: Vec<u8>,
    /// Cached session ID for abbreviated handshake.
    cached_session_id: Vec<u8>,
    /// Cached master secret for abbreviated handshake.
    cached_master_secret: Vec<u8>,
    /// Cached cipher suite for abbreviated handshake.
    cached_suite: CipherSuite,
    /// Whether this is an abbreviated (resumed) handshake.
    abbreviated: bool,
    /// Abbreviated keys (set when abbreviated == true after SH processing).
    abbreviated_keys: Option<DtlsAbbreviatedClientKeys>,
}

impl Dtls12ClientHandshake {
    pub fn new(config: TlsConfig) -> Self {
        Self {
            config,
            state: Dtls12ClientState::Idle,
            params: None,
            transcript: TranscriptHash::new(|| Box::new(Sha256::new())),
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            server_certs: Vec::new(),
            server_ecdh_public: Vec::new(),
            server_named_curve: 0,
            message_seq: 0,
            cookie: Vec::new(),
            client_hello_tls_bytes: Vec::new(),
            cached_session_id: Vec::new(),
            cached_master_secret: Vec::new(),
            cached_suite: CipherSuite(0),
            abbreviated: false,
            abbreviated_keys: None,
        }
    }

    pub fn state(&self) -> Dtls12ClientState {
        self.state
    }

    /// Build the initial ClientHello (DTLS format with empty cookie).
    ///
    /// Returns the DTLS handshake message (12-byte header + body).
    pub fn build_client_hello(&mut self) -> Result<Vec<u8>, TlsError> {
        self.build_client_hello_with_cookie(&[])
    }

    /// Build a ClientHello with the given cookie.
    fn build_client_hello_with_cookie(&mut self, cookie: &[u8]) -> Result<Vec<u8>, TlsError> {
        // Generate client_random (only on first call)
        if self.state == Dtls12ClientState::Idle {
            getrandom::getrandom(&mut self.client_random)
                .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;

            // Check session cache for resumption
            if let (Some(ref cache_mutex), Some(ref server_name)) =
                (&self.config.session_cache, &self.config.server_name)
            {
                if let Ok(cache) = cache_mutex.lock() {
                    if let Some(session) = cache.get(server_name.as_bytes()) {
                        if crate::crypt::is_tls12_suite(session.cipher_suite) {
                            self.cached_session_id = session.id.clone();
                            self.cached_master_secret = session.master_secret.clone();
                            self.cached_suite = session.cipher_suite;
                        }
                    }
                }
            }
        }

        // Build extensions
        let mut extensions = Vec::new();
        if let Some(ref name) = self.config.server_name {
            extensions.push(crate::handshake::extensions_codec::build_server_name(name));
        }
        extensions.push(
            crate::handshake::extensions_codec::build_signature_algorithms(
                &self.config.signature_algorithms,
            ),
        );
        extensions.push(crate::handshake::extensions_codec::build_supported_groups(
            &self.config.supported_groups,
        ));
        extensions.push(crate::handshake::extensions_codec::build_ec_point_formats());
        extensions.push(crate::handshake::extensions_codec::build_renegotiation_info_initial());

        // Filter cipher suites to TLS 1.2
        let tls12_suites: Vec<CipherSuite> = self
            .config
            .cipher_suites
            .iter()
            .copied()
            .filter(|s| crate::crypt::is_tls12_suite(*s))
            .collect();

        if tls12_suites.is_empty() {
            return Err(TlsError::NoSharedCipherSuite);
        }

        // Use cached session ID if available (for abbreviated handshake),
        // otherwise generate a random one.
        let session_id = if !self.cached_session_id.is_empty() {
            self.cached_session_id.clone()
        } else {
            let mut sid = vec![0u8; 32];
            getrandom::getrandom(&mut sid)
                .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;
            sid
        };

        let ch = crate::handshake::codec::ClientHello {
            random: self.client_random,
            legacy_session_id: session_id,
            cipher_suites: tls12_suites,
            extensions,
        };

        // Encode DTLS ClientHello body (with cookie field)
        let ch_body = encode_dtls_client_hello_body(&ch, cookie);

        // Wrap with DTLS handshake header
        let seq = self.message_seq;
        self.message_seq += 1;
        let dtls_msg = wrap_dtls_handshake_full(HandshakeType::ClientHello, &ch_body, seq);

        // Convert to TLS format for transcript
        let tls_msg = dtls_to_tls_handshake(&dtls_msg)?;
        self.client_hello_tls_bytes = tls_msg.clone();
        self.transcript.update(&tls_msg)?;

        self.state = if cookie.is_empty() {
            Dtls12ClientState::WaitHelloVerifyRequest
        } else {
            Dtls12ClientState::WaitServerHello
        };

        Ok(dtls_msg)
    }

    /// Process a HelloVerifyRequest. Returns a new ClientHello with the cookie.
    ///
    /// `raw_dtls_msg` is the DTLS handshake message (12-byte header + body).
    pub fn process_hello_verify_request(
        &mut self,
        raw_dtls_msg: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        if self.state != Dtls12ClientState::WaitHelloVerifyRequest
            && self.state != Dtls12ClientState::WaitServerHello
        {
            return Err(TlsError::HandshakeFailed(
                "unexpected HelloVerifyRequest".into(),
            ));
        }

        // Parse HVR body (skip 12-byte DTLS header)
        let body = dtls_get_body(raw_dtls_msg)?;
        let hvr = crate::handshake::codec_dtls::decode_hello_verify_request(body)?;
        self.cookie = hvr.cookie;

        // HVR is NOT added to the transcript (RFC 6347 §4.2.1)
        // Reset transcript for fresh start with the retried ClientHello
        self.transcript = TranscriptHash::new(|| Box::new(Sha256::new()));

        // Rebuild ClientHello with cookie
        self.build_client_hello_with_cookie(&self.cookie.clone())
    }

    /// Process a ServerHello message.
    ///
    /// `raw_dtls_msg` is the DTLS handshake message (12-byte header).
    pub fn process_server_hello(
        &mut self,
        raw_dtls_msg: &[u8],
        sh: &ServerHello,
    ) -> Result<CipherSuite, TlsError> {
        if self.state != Dtls12ClientState::WaitServerHello
            && self.state != Dtls12ClientState::WaitHelloVerifyRequest
        {
            return Err(TlsError::HandshakeFailed("unexpected ServerHello".into()));
        }

        let params = Tls12CipherSuiteParams::from_suite(sh.cipher_suite)?;
        self.server_random = sh.random;

        // Switch transcript hash if SHA-384 suite
        if params.hash_len == 48 {
            self.transcript = TranscriptHash::new(|| Box::new(hitls_crypto::sha2::Sha384::new()));
            self.transcript.update(&self.client_hello_tls_bytes)?;
        }

        self.params = Some(params.clone());

        // Add ServerHello to transcript in TLS format
        let tls_msg = dtls_to_tls_handshake(raw_dtls_msg)?;
        self.transcript.update(&tls_msg)?;

        // Check for abbreviated handshake (session resumption)
        if !self.cached_session_id.is_empty()
            && sh.legacy_session_id == self.cached_session_id
            && sh.cipher_suite == self.cached_suite
        {
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
            self.abbreviated_keys = Some(DtlsAbbreviatedClientKeys {
                suite: sh.cipher_suite,
                master_secret: self.cached_master_secret.clone(),
                client_write_key: key_block.client_write_key.clone(),
                server_write_key: key_block.server_write_key.clone(),
                client_write_iv: key_block.client_write_iv.clone(),
                server_write_iv: key_block.server_write_iv.clone(),
            });
            self.state = Dtls12ClientState::WaitChangeCipherSpec;
        } else {
            // Full handshake — clear cached state
            self.abbreviated = false;
            self.cached_session_id.clear();
            self.cached_master_secret.zeroize();
            self.state = Dtls12ClientState::WaitCertificate;
        }

        Ok(sh.cipher_suite)
    }

    /// Whether this is an abbreviated (resumed) handshake.
    pub fn is_abbreviated(&self) -> bool {
        self.abbreviated
    }

    /// Take the abbreviated keys (consumes them).
    pub fn take_abbreviated_keys(&mut self) -> Option<DtlsAbbreviatedClientKeys> {
        self.abbreviated_keys.take()
    }

    /// Process server Finished for abbreviated handshake.
    ///
    /// Verifies server Finished, computes client Finished, returns the client Finished message.
    pub fn process_abbreviated_server_finished(
        &mut self,
        raw_dtls_msg: &[u8],
        master_secret: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        if self.state != Dtls12ClientState::WaitFinished || !self.abbreviated {
            return Err(TlsError::HandshakeFailed(
                "unexpected abbreviated Finished".into(),
            ));
        }

        let params = self
            .params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher suite params".into()))?;

        // Convert to TLS format to extract verify_data
        let tls_msg = dtls_to_tls_handshake(raw_dtls_msg)?;
        if tls_msg.len() < 4 + 12 {
            return Err(TlsError::HandshakeFailed(
                "Finished message too short".into(),
            ));
        }
        let received_verify_data = &tls_msg[4..4 + 12];

        // Verify server Finished: PRF(ms, "server finished", Hash(CH + SH))
        let factory = params.hash_factory();
        let transcript_hash = self.transcript.current_hash()?;
        let expected = compute_verify_data(
            &*factory,
            master_secret,
            "server finished",
            &transcript_hash,
        )?;

        use subtle::ConstantTimeEq;
        if !bool::from(received_verify_data.ct_eq(&expected)) {
            return Err(TlsError::HandshakeFailed(
                "server Finished verify_data mismatch".into(),
            ));
        }

        // Add server Finished to transcript
        self.transcript.update(&tls_msg)?;

        // Compute client Finished: PRF(ms, "client finished", Hash(CH + SH + SF))
        let transcript_hash = self.transcript.current_hash()?;
        let client_verify_data = compute_verify_data(
            &*factory,
            master_secret,
            "client finished",
            &transcript_hash,
        )?;
        let finished_tls = crate::handshake::codec12::encode_finished12(&client_verify_data);

        let seq = self.message_seq;
        self.message_seq += 1;
        let finished_dtls =
            crate::handshake::codec_dtls::tls_to_dtls_handshake(&finished_tls, seq)?;

        self.state = Dtls12ClientState::Connected;
        Ok(finished_dtls)
    }

    /// Process a Certificate message.
    pub fn process_certificate(
        &mut self,
        raw_dtls_msg: &[u8],
        cert_list: &[Vec<u8>],
    ) -> Result<(), TlsError> {
        if self.state != Dtls12ClientState::WaitCertificate {
            return Err(TlsError::HandshakeFailed("unexpected Certificate".into()));
        }
        if cert_list.is_empty() {
            return Err(TlsError::HandshakeFailed("empty certificate chain".into()));
        }
        self.server_certs = cert_list.to_vec();
        let tls_msg = dtls_to_tls_handshake(raw_dtls_msg)?;
        self.transcript.update(&tls_msg)?;

        crate::cert_verify::verify_server_certificate(&self.config, &self.server_certs)?;

        self.state = Dtls12ClientState::WaitServerKeyExchange;
        Ok(())
    }

    /// Process a ServerKeyExchange message.
    pub fn process_server_key_exchange(
        &mut self,
        raw_dtls_msg: &[u8],
        ske: &ServerKeyExchange,
    ) -> Result<(), TlsError> {
        if self.state != Dtls12ClientState::WaitServerKeyExchange {
            return Err(TlsError::HandshakeFailed(
                "unexpected ServerKeyExchange".into(),
            ));
        }

        if self.config.verify_peer {
            let params = build_ske_params(ske.curve_type, ske.named_curve, &ske.public_key);
            let signed_data =
                build_ske_signed_data(&self.client_random, &self.server_random, &params);
            crate::handshake::client12::verify_ske_signature(
                &self.server_certs[0],
                ske.signature_algorithm,
                &signed_data,
                &ske.signature,
            )?;
        }

        self.server_ecdh_public = ske.public_key.clone();
        self.server_named_curve = ske.named_curve;
        let tls_msg = dtls_to_tls_handshake(raw_dtls_msg)?;
        self.transcript.update(&tls_msg)?;
        self.state = Dtls12ClientState::WaitServerHelloDone;
        Ok(())
    }

    /// Process a ServerHelloDone message.
    pub fn process_server_hello_done(
        &mut self,
        raw_dtls_msg: &[u8],
    ) -> Result<DtlsClientFlightResult, TlsError> {
        if self.state != Dtls12ClientState::WaitServerHelloDone {
            return Err(TlsError::HandshakeFailed(
                "unexpected ServerHelloDone".into(),
            ));
        }

        let tls_msg = dtls_to_tls_handshake(raw_dtls_msg)?;
        self.transcript.update(&tls_msg)?;

        let params = self
            .params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher suite params".into()))?;

        // Generate ephemeral key
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
        let pre_master_secret = kx.compute_shared_secret(&self.server_ecdh_public)?;

        // Build CKE (encode in TLS format, convert to DTLS)
        let cke = crate::handshake::codec12::ClientKeyExchange {
            public_key: client_public,
        };
        let cke_tls_msg = crate::handshake::codec12::encode_client_key_exchange(&cke);
        let seq = self.message_seq;
        self.message_seq += 1;
        let cke_dtls_msg = crate::handshake::codec_dtls::tls_to_dtls_handshake(&cke_tls_msg, seq)?;

        // Add CKE to transcript in TLS format
        self.transcript.update(&cke_tls_msg)?;

        // Derive keys
        let factory = params.hash_factory();
        let master_secret = derive_master_secret(
            &*factory,
            &pre_master_secret,
            &self.client_random,
            &self.server_random,
        )?;
        crate::crypt::keylog::log_master_secret(&self.config, &self.client_random, &master_secret);

        let key_block = derive_key_block(
            &*factory,
            &master_secret,
            &self.server_random,
            &self.client_random,
            params,
        )?;

        // Compute client Finished
        let transcript_hash = self.transcript.current_hash()?;
        let verify_data = compute_verify_data(
            &*factory,
            &master_secret,
            "client finished",
            &transcript_hash,
        )?;
        let finished_tls_msg = crate::handshake::codec12::encode_finished12(&verify_data);
        self.transcript.update(&finished_tls_msg)?;

        let seq = self.message_seq;
        self.message_seq += 1;
        let finished_dtls_msg =
            crate::handshake::codec_dtls::tls_to_dtls_handshake(&finished_tls_msg, seq)?;

        self.state = Dtls12ClientState::WaitChangeCipherSpec;

        Ok(DtlsClientFlightResult {
            client_key_exchange: cke_dtls_msg,
            finished: finished_dtls_msg,
            master_secret,
            client_write_key: key_block.client_write_key.clone(),
            server_write_key: key_block.server_write_key.clone(),
            client_write_iv: key_block.client_write_iv.clone(),
            server_write_iv: key_block.server_write_iv.clone(),
        })
    }

    /// Process ChangeCipherSpec from server.
    pub fn process_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        if self.state != Dtls12ClientState::WaitChangeCipherSpec {
            return Err(TlsError::HandshakeFailed(
                "unexpected ChangeCipherSpec".into(),
            ));
        }
        self.state = Dtls12ClientState::WaitFinished;
        Ok(())
    }

    /// Process server Finished message.
    pub fn process_finished(
        &mut self,
        raw_dtls_msg: &[u8],
        master_secret: &[u8],
    ) -> Result<(), TlsError> {
        if self.state != Dtls12ClientState::WaitFinished {
            return Err(TlsError::HandshakeFailed("unexpected Finished".into()));
        }

        let params = self
            .params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher suite params".into()))?;

        // Convert to TLS format to extract verify_data
        let tls_msg = dtls_to_tls_handshake(raw_dtls_msg)?;
        if tls_msg.len() < 4 + 12 {
            return Err(TlsError::HandshakeFailed(
                "Finished message too short".into(),
            ));
        }
        let received_verify_data = &tls_msg[4..4 + 12];

        let factory = params.hash_factory();
        let transcript_hash = self.transcript.current_hash()?;
        let expected = compute_verify_data(
            &*factory,
            master_secret,
            "server finished",
            &transcript_hash,
        )?;

        use subtle::ConstantTimeEq;
        if received_verify_data.ct_eq(&expected).into() {
            self.transcript.update(&tls_msg)?;
            self.state = Dtls12ClientState::Connected;
            Ok(())
        } else {
            Err(TlsError::HandshakeFailed(
                "server Finished verify_data mismatch".into(),
            ))
        }
    }
}

/// Strip the 12-byte DTLS handshake header to get the body.
fn dtls_get_body(msg: &[u8]) -> Result<&[u8], TlsError> {
    if msg.len() < 12 {
        return Err(TlsError::HandshakeFailed(
            "DTLS handshake message too short".into(),
        ));
    }
    Ok(&msg[12..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypt::NamedGroup;
    use crate::handshake::codec_dtls::parse_dtls_handshake_header;

    #[test]
    fn test_dtls12_client_build_hello() {
        let config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .build();

        let mut hs = Dtls12ClientHandshake::new(config);
        let ch_msg = hs.build_client_hello().unwrap();

        // Verify DTLS handshake header
        let (header, _body, _) = parse_dtls_handshake_header(&ch_msg).unwrap();
        assert_eq!(header.msg_type, HandshakeType::ClientHello);
        assert_eq!(header.message_seq, 0);
        assert_eq!(header.fragment_offset, 0);

        assert_eq!(hs.state(), Dtls12ClientState::WaitHelloVerifyRequest);
        assert_eq!(hs.message_seq, 1);
    }

    #[test]
    fn test_dtls12_client_state_transitions() {
        let hs = Dtls12ClientHandshake::new(TlsConfig::builder().build());
        assert_eq!(hs.state(), Dtls12ClientState::Idle);
    }

    #[test]
    fn test_dtls12_message_seq_tracking() {
        let config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .build();

        let mut hs = Dtls12ClientHandshake::new(config);
        let ch1 = hs.build_client_hello().unwrap();

        let (h1, _, _) = parse_dtls_handshake_header(&ch1).unwrap();
        assert_eq!(h1.message_seq, 0);
        assert_eq!(hs.message_seq, 1);
    }

    #[test]
    fn test_dtls12_client_hvr_processing() {
        use crate::handshake::codec_dtls::{
            encode_hello_verify_request, wrap_dtls_handshake_full, HelloVerifyRequest,
        };
        use crate::record::dtls::DTLS12_VERSION;

        let config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .build();

        let mut hs = Dtls12ClientHandshake::new(config);
        let _ch1 = hs.build_client_hello().unwrap();
        assert_eq!(hs.state(), Dtls12ClientState::WaitHelloVerifyRequest);

        // Construct a HelloVerifyRequest with a cookie
        let cookie = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let hvr = HelloVerifyRequest {
            server_version: DTLS12_VERSION,
            cookie: cookie.clone(),
        };
        let hvr_body = encode_hello_verify_request(&hvr);
        let hvr_msg = wrap_dtls_handshake_full(HandshakeType::HelloVerifyRequest, &hvr_body, 0);

        // Process HVR → should get a new ClientHello with the cookie
        let ch2 = hs.process_hello_verify_request(&hvr_msg).unwrap();

        // State should now be WaitServerHello
        assert_eq!(hs.state(), Dtls12ClientState::WaitServerHello);
        // The new CH should be a valid DTLS handshake message
        let (h2, _, _) = parse_dtls_handshake_header(&ch2).unwrap();
        assert_eq!(h2.msg_type, HandshakeType::ClientHello);
    }

    #[test]
    fn test_dtls12_client_hvr_wrong_state() {
        let config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .build();

        let mut hs = Dtls12ClientHandshake::new(config);
        // State is Idle — HVR should fail
        let hvr_msg = vec![
            0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xFE, 0xFD,
            0x00,
        ]; // minimal HVR
        assert!(hs.process_hello_verify_request(&hvr_msg).is_err());
    }

    #[test]
    fn test_dtls12_client_process_sh_wrong_state() {
        use crate::handshake::codec::ServerHello;

        let config = TlsConfig::builder().build();
        let mut hs = Dtls12ClientHandshake::new(config);
        // State is Idle, not WaitServerHello
        let sh = ServerHello {
            random: [0u8; 32],
            legacy_session_id: vec![],
            cipher_suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            extensions: Vec::new(),
        };
        // Wrap as DTLS
        let sh_tls = crate::handshake::codec::encode_server_hello(&sh);
        let sh_dtls = crate::handshake::codec_dtls::tls_to_dtls_handshake(&sh_tls, 0).unwrap();
        assert!(hs.process_server_hello(&sh_dtls, &sh).is_err());
    }

    #[test]
    fn test_dtls12_client_ccs_wrong_state() {
        let config = TlsConfig::builder().build();
        let mut hs = Dtls12ClientHandshake::new(config);
        // State is Idle, not WaitChangeCipherSpec
        assert!(hs.process_change_cipher_spec().is_err());
    }

    #[test]
    fn test_dtls12_client_detects_abbreviated() {
        use crate::session::{InMemorySessionCache, SessionCache, TlsSession};
        use std::sync::{Arc, Mutex};

        let session_id = vec![0xAA; 32];
        let master_secret = vec![0xBB; 48];
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

        let cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));
        {
            let mut c = cache.lock().unwrap();
            c.put(
                b"test.example.com",
                TlsSession {
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
                        .unwrap_or_default()
                        .as_secs(),
                    psk: Vec::new(),
                    extended_master_secret: false,
                },
            );
        }

        let config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .server_name("test.example.com")
            .session_cache(cache)
            .verify_peer(false)
            .build();

        let mut hs = Dtls12ClientHandshake::new(config);
        let _ch_msg = hs.build_client_hello().unwrap();
        assert!(!hs.is_abbreviated());

        // Server echoes back the cached session_id → abbreviated
        let sh = ServerHello {
            random: [0x11; 32],
            legacy_session_id: session_id,
            cipher_suite: suite,
            extensions: Vec::new(),
        };
        let sh_tls = crate::handshake::codec::encode_server_hello(&sh);
        let sh_dtls = crate::handshake::codec_dtls::tls_to_dtls_handshake(&sh_tls, 0).unwrap();
        hs.process_server_hello(&sh_dtls, &sh).unwrap();

        assert!(hs.is_abbreviated());
        assert_eq!(hs.state(), Dtls12ClientState::WaitChangeCipherSpec);
        assert!(hs.take_abbreviated_keys().is_some());
    }

    #[test]
    fn test_dtls12_client_process_cert_wrong_state() {
        let config = TlsConfig::builder().build();
        let mut hs = Dtls12ClientHandshake::new(config);
        // State is Idle, not WaitCertificate
        let fake_cert = wrap_dtls_handshake_full(
            HandshakeType::Certificate,
            &[0x00, 0x00, 0x03, 0x00, 0x00, 0x00],
            0,
        );
        assert!(hs.process_certificate(&fake_cert, &[vec![0x30]]).is_err());
    }

    #[test]
    fn test_dtls12_client_process_ske_wrong_state() {
        use crate::handshake::codec12::ServerKeyExchange;

        let config = TlsConfig::builder().build();
        let mut hs = Dtls12ClientHandshake::new(config);
        // State is Idle, not WaitServerKeyExchange
        let ske = ServerKeyExchange {
            curve_type: 3,
            named_curve: 0x0017,
            public_key: vec![0x04; 65],
            signature_algorithm: crate::crypt::SignatureScheme::ECDSA_SECP256R1_SHA256,
            signature: vec![0u8; 64],
        };
        let fake_ske = wrap_dtls_handshake_full(HandshakeType::ServerKeyExchange, &[0u8; 100], 0);
        assert!(hs.process_server_key_exchange(&fake_ske, &ske).is_err());
    }

    #[test]
    fn test_dtls12_client_process_shd_wrong_state() {
        let config = TlsConfig::builder().build();
        let mut hs = Dtls12ClientHandshake::new(config);
        // State is Idle, not WaitServerHelloDone
        let fake_shd = wrap_dtls_handshake_full(HandshakeType::ServerHelloDone, &[], 0);
        assert!(hs.process_server_hello_done(&fake_shd).is_err());
    }

    #[test]
    fn test_dtls12_client_process_finished_wrong_state() {
        let config = TlsConfig::builder().build();
        let mut hs = Dtls12ClientHandshake::new(config);
        // State is Idle, not WaitFinished
        let fake_fin = wrap_dtls_handshake_full(HandshakeType::Finished, &[0u8; 12], 0);
        assert!(hs.process_finished(&fake_fin, &[0u8; 48]).is_err());
    }

    #[test]
    fn test_dtls12_client_abbreviated_finished_wrong_state() {
        let config = TlsConfig::builder().build();
        let mut hs = Dtls12ClientHandshake::new(config);
        // State is Idle, not WaitFinished
        let fake_fin = wrap_dtls_handshake_full(HandshakeType::Finished, &[0u8; 12], 0);
        assert!(hs
            .process_abbreviated_server_finished(&fake_fin, &[0u8; 48])
            .is_err());
    }

    #[test]
    fn test_dtls12_client_non_abbreviated_when_session_id_differs() {
        use crate::session::{InMemorySessionCache, SessionCache, TlsSession};
        use std::sync::{Arc, Mutex};

        let session_id = vec![0xAA; 32];
        let master_secret = vec![0xBB; 48];
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

        let cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));
        {
            let mut c = cache.lock().unwrap();
            c.put(
                b"test.example.com",
                TlsSession {
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
                        .unwrap_or_default()
                        .as_secs(),
                    psk: Vec::new(),
                    extended_master_secret: false,
                },
            );
        }

        let config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .server_name("test.example.com")
            .session_cache(cache)
            .verify_peer(false)
            .build();

        let mut hs = Dtls12ClientHandshake::new(config);
        let _ch_msg = hs.build_client_hello().unwrap();

        // Server returns a DIFFERENT session_id → full handshake, not abbreviated
        let sh = crate::handshake::codec::ServerHello {
            random: [0x22; 32],
            legacy_session_id: vec![0xCC; 32], // different from cached
            cipher_suite: suite,
            extensions: Vec::new(),
        };
        let sh_tls = crate::handshake::codec::encode_server_hello(&sh);
        let sh_dtls = crate::handshake::codec_dtls::tls_to_dtls_handshake(&sh_tls, 0).unwrap();
        hs.process_server_hello(&sh_dtls, &sh).unwrap();

        assert!(!hs.is_abbreviated());
        assert_eq!(hs.state(), Dtls12ClientState::WaitCertificate);
    }

    #[test]
    fn test_dtls12_client_empty_cert_list_rejected() {
        let config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .verify_peer(false)
            .build();

        let mut hs = Dtls12ClientHandshake::new(config);
        let _ch = hs.build_client_hello().unwrap();

        // Process a ServerHello to advance to WaitCertificate
        let sh = crate::handshake::codec::ServerHello {
            random: [0x33; 32],
            legacy_session_id: vec![0u8; 32],
            cipher_suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            extensions: Vec::new(),
        };
        let sh_tls = crate::handshake::codec::encode_server_hello(&sh);
        let sh_dtls = crate::handshake::codec_dtls::tls_to_dtls_handshake(&sh_tls, 0).unwrap();
        hs.process_server_hello(&sh_dtls, &sh).unwrap();

        assert_eq!(hs.state(), Dtls12ClientState::WaitCertificate);

        // Process Certificate with empty cert list → error
        let cert_body = vec![0x00, 0x00, 0x00]; // empty certificate_list
        let cert_dtls = wrap_dtls_handshake_full(HandshakeType::Certificate, &cert_body, 1);
        let result = hs.process_certificate(&cert_dtls, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_dtls12_client_dtls_get_body_edge_cases() {
        // Too short
        assert!(dtls_get_body(&[0u8; 5]).is_err());
        // Exactly 12 bytes → empty body
        let body = dtls_get_body(&[0u8; 12]).unwrap();
        assert!(body.is_empty());
        // 13 bytes → 1-byte body
        let body = dtls_get_body(&[0u8; 13]).unwrap();
        assert_eq!(body.len(), 1);
    }
}
