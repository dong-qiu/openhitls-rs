//! DTLS 1.2 server handshake state machine.
//!
//! Mirrors the TLS 1.2 server handshake (server12.rs) but uses DTLS-specific
//! record framing, 12-byte handshake headers, cookie exchange, and
//! transcript hashing with TLS-format headers (RFC 6347 §4.2.6).

use crate::config::TlsConfig;
use crate::crypt::key_schedule12::{compute_verify_data, derive_key_block, derive_master_secret};
use crate::crypt::transcript::TranscriptHash;
use crate::crypt::{SignatureScheme, Tls12CipherSuiteParams};
use crate::extensions::ExtensionType;
use crate::handshake::codec::{encode_server_hello, ClientHello, ServerHello};
use crate::handshake::codec12::{
    build_ske_params, build_ske_signed_data, decode_client_key_exchange, encode_certificate12,
    encode_finished12, encode_server_key_exchange, Certificate12, ServerKeyExchange,
};
use crate::handshake::codec_dtls::{
    decode_dtls_client_hello, dtls_to_tls_handshake, encode_hello_verify_request,
    tls_to_dtls_handshake, wrap_dtls_handshake_full, HelloVerifyRequest,
};
use crate::handshake::extensions_codec::{
    parse_signature_algorithms_ch, parse_supported_groups_ch,
};
use crate::handshake::key_exchange::KeyExchange;
use crate::handshake::server12::{
    negotiate_cipher_suite, negotiate_group, select_signature_scheme_tls12, sign_ske_data,
};
use crate::handshake::HandshakeType;
use crate::record::dtls::DTLS12_VERSION;
use crate::CipherSuite;
use hitls_crypto::sha2::Sha256;
use hitls_types::TlsError;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// DTLS 1.2 server handshake states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dtls12ServerState {
    Idle,
    WaitClientHelloWithCookie,
    WaitClientKeyExchange,
    WaitChangeCipherSpec,
    WaitFinished,
    Connected,
}

/// Result from processing the initial ClientHello when cookie mode is enabled.
#[derive(Debug)]
pub struct DtlsHelloVerifyResult {
    /// HelloVerifyRequest DTLS handshake message.
    pub hello_verify_request: Vec<u8>,
}

/// Server flight result after processing ClientHello (with valid cookie or no-cookie mode).
#[derive(Debug)]
pub struct DtlsServerFlightResult {
    /// ServerHello DTLS handshake message.
    pub server_hello: Vec<u8>,
    /// Certificate DTLS handshake message.
    pub certificate: Vec<u8>,
    /// ServerKeyExchange DTLS handshake message.
    pub server_key_exchange: Vec<u8>,
    /// ServerHelloDone DTLS handshake message.
    pub server_hello_done: Vec<u8>,
    /// Negotiated cipher suite.
    pub suite: CipherSuite,
}

/// Keys derived after processing ClientKeyExchange.
pub struct DtlsDerivedKeys {
    pub master_secret: Vec<u8>,
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
}

impl Drop for DtlsDerivedKeys {
    fn drop(&mut self) {
        self.master_secret.zeroize();
        self.client_write_key.zeroize();
        self.server_write_key.zeroize();
        self.client_write_iv.zeroize();
        self.server_write_iv.zeroize();
    }
}

/// Server Finished result.
pub struct DtlsServerFinishedResult {
    /// Server Finished DTLS handshake message.
    pub finished: Vec<u8>,
}

/// DTLS 1.2 server handshake state machine.
pub struct Dtls12ServerHandshake {
    config: TlsConfig,
    state: Dtls12ServerState,
    params: Option<Tls12CipherSuiteParams>,
    transcript: TranscriptHash,
    client_random: [u8; 32],
    server_random: [u8; 32],
    ephemeral_key: Option<KeyExchange>,
    master_secret: Vec<u8>,
    client_sig_algs: Vec<SignatureScheme>,
    /// Next message_seq to assign to outgoing messages.
    message_seq: u16,
    /// Whether cookie exchange is enabled.
    enable_cookie: bool,
    /// Secret for computing cookies (HMAC-SHA256 based).
    cookie_secret: Vec<u8>,
    /// The expected cookie for the current handshake.
    expected_cookie: Vec<u8>,
}

impl Drop for Dtls12ServerHandshake {
    fn drop(&mut self) {
        self.master_secret.zeroize();
        self.cookie_secret.zeroize();
    }
}

impl Dtls12ServerHandshake {
    pub fn new(config: TlsConfig, enable_cookie: bool) -> Self {
        let mut cookie_secret = vec![0u8; 32];
        let _ = getrandom::getrandom(&mut cookie_secret);

        Self {
            config,
            state: Dtls12ServerState::Idle,
            params: None,
            transcript: TranscriptHash::new(|| Box::new(Sha256::new())),
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            ephemeral_key: None,
            master_secret: Vec::new(),
            client_sig_algs: Vec::new(),
            message_seq: 0,
            enable_cookie,
            cookie_secret,
            expected_cookie: Vec::new(),
        }
    }

    pub fn state(&self) -> Dtls12ServerState {
        self.state
    }

    /// Process the initial ClientHello.
    ///
    /// `raw_dtls_msg` is the DTLS handshake message (12-byte header + body).
    ///
    /// If cookie mode is enabled, returns `Ok(Err(hvr))` containing a HelloVerifyRequest.
    /// If cookie mode is disabled, returns `Ok(Ok(flight))` with the server flight.
    pub fn process_client_hello(
        &mut self,
        raw_dtls_msg: &[u8],
    ) -> Result<Result<DtlsServerFlightResult, DtlsHelloVerifyResult>, TlsError> {
        if self.state != Dtls12ServerState::Idle {
            return Err(TlsError::HandshakeFailed("unexpected ClientHello".into()));
        }

        // Parse DTLS ClientHello body (skip 12-byte header)
        let body = dtls_get_body(raw_dtls_msg)?;
        let (ch, cookie) = decode_dtls_client_hello(body)?;
        self.client_random = ch.random;

        if self.enable_cookie {
            if cookie.is_empty() {
                // First ClientHello without cookie — send HVR
                let computed_cookie = self.compute_cookie(&ch);
                self.expected_cookie = computed_cookie.clone();

                let hvr = HelloVerifyRequest {
                    server_version: DTLS12_VERSION,
                    cookie: computed_cookie,
                };
                let hvr_body = encode_hello_verify_request(&hvr);
                let seq = self.message_seq;
                self.message_seq += 1;
                let hvr_msg =
                    wrap_dtls_handshake_full(HandshakeType::HelloVerifyRequest, &hvr_body, seq);

                self.state = Dtls12ServerState::WaitClientHelloWithCookie;
                return Ok(Err(DtlsHelloVerifyResult {
                    hello_verify_request: hvr_msg,
                }));
            }
            // Has cookie — verify it
            if cookie != self.expected_cookie {
                return Err(TlsError::HandshakeFailed("cookie mismatch".into()));
            }
        }

        // Process ClientHello and build server flight
        self.build_server_flight(raw_dtls_msg, &ch).map(Ok)
    }

    /// Process a retried ClientHello (with cookie).
    ///
    /// Called when state is `WaitClientHelloWithCookie`.
    pub fn process_client_hello_with_cookie(
        &mut self,
        raw_dtls_msg: &[u8],
    ) -> Result<DtlsServerFlightResult, TlsError> {
        if self.state != Dtls12ServerState::WaitClientHelloWithCookie {
            return Err(TlsError::HandshakeFailed(
                "unexpected ClientHello with cookie".into(),
            ));
        }

        let body = dtls_get_body(raw_dtls_msg)?;
        let (ch, cookie) = decode_dtls_client_hello(body)?;
        self.client_random = ch.random;

        // Verify cookie
        if cookie != self.expected_cookie {
            return Err(TlsError::HandshakeFailed("cookie mismatch".into()));
        }

        self.build_server_flight(raw_dtls_msg, &ch)
    }

    /// Build the server flight: SH + Certificate + SKE + SHD.
    fn build_server_flight(
        &mut self,
        raw_dtls_msg: &[u8],
        ch: &ClientHello,
    ) -> Result<DtlsServerFlightResult, TlsError> {
        // Parse extensions
        let mut client_groups = Vec::new();
        for ext in &ch.extensions {
            match ext.extension_type {
                ExtensionType::SIGNATURE_ALGORITHMS => {
                    self.client_sig_algs = parse_signature_algorithms_ch(&ext.data)?;
                }
                ExtensionType::SUPPORTED_GROUPS => {
                    client_groups = parse_supported_groups_ch(&ext.data)?;
                }
                _ => {}
            }
        }

        // Negotiate cipher suite
        let suite = negotiate_cipher_suite(ch, &self.config)?;
        let params = Tls12CipherSuiteParams::from_suite(suite)?;

        // Switch transcript hash if SHA-384
        if params.hash_len == 48 {
            self.transcript = TranscriptHash::new(|| Box::new(hitls_crypto::sha2::Sha384::new()));
        }

        // Add ClientHello to transcript in TLS format
        let tls_ch = dtls_to_tls_handshake(raw_dtls_msg)?;
        self.transcript.update(&tls_ch)?;

        // Generate server random
        getrandom::getrandom(&mut self.server_random)
            .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;

        // Negotiate group
        let group = negotiate_group(&client_groups, &self.config.supported_groups)?;

        // Build ServerHello (TLS format, then convert to DTLS)
        let sh = ServerHello {
            random: self.server_random,
            legacy_session_id: ch.legacy_session_id.clone(),
            cipher_suite: suite,
            extensions: Vec::new(),
        };
        let sh_tls = encode_server_hello(&sh);
        let seq = self.message_seq;
        self.message_seq += 1;
        let sh_dtls = tls_to_dtls_handshake(&sh_tls, seq)?;
        self.transcript.update(&sh_tls)?;

        // Build Certificate (TLS format, then convert to DTLS)
        let cert12 = Certificate12 {
            certificate_list: self.config.certificate_chain.clone(),
        };
        let cert_tls = encode_certificate12(&cert12);
        let seq = self.message_seq;
        self.message_seq += 1;
        let cert_dtls = tls_to_dtls_handshake(&cert_tls, seq)?;
        self.transcript.update(&cert_tls)?;

        // Generate ephemeral ECDH key
        let kx = KeyExchange::generate(group)?;
        let server_public = kx.public_key_bytes().to_vec();

        // Build and sign ServerKeyExchange
        let named_curve = group.0;
        let ske_params = build_ske_params(3, named_curve, &server_public);
        let signed_data =
            build_ske_signed_data(&self.client_random, &self.server_random, &ske_params);

        let private_key =
            self.config.private_key.as_ref().ok_or_else(|| {
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
        let ske_tls = encode_server_key_exchange(&ske);
        let seq = self.message_seq;
        self.message_seq += 1;
        let ske_dtls = tls_to_dtls_handshake(&ske_tls, seq)?;
        self.transcript.update(&ske_tls)?;

        // Build ServerHelloDone
        let shd_tls = crate::handshake::codec12::encode_server_hello_done();
        let seq = self.message_seq;
        self.message_seq += 1;
        let shd_dtls = tls_to_dtls_handshake(&shd_tls, seq)?;
        self.transcript.update(&shd_tls)?;

        self.ephemeral_key = Some(kx);
        self.params = Some(params);
        self.state = Dtls12ServerState::WaitClientKeyExchange;

        Ok(DtlsServerFlightResult {
            server_hello: sh_dtls,
            certificate: cert_dtls,
            server_key_exchange: ske_dtls,
            server_hello_done: shd_dtls,
            suite,
        })
    }

    /// Process ClientKeyExchange and derive keys.
    ///
    /// `raw_dtls_msg` is the DTLS handshake message (12-byte header + body).
    pub fn process_client_key_exchange(
        &mut self,
        raw_dtls_msg: &[u8],
    ) -> Result<DtlsDerivedKeys, TlsError> {
        if self.state != Dtls12ServerState::WaitClientKeyExchange {
            return Err(TlsError::HandshakeFailed(
                "unexpected ClientKeyExchange".into(),
            ));
        }

        // Add to transcript in TLS format
        let tls_msg = dtls_to_tls_handshake(raw_dtls_msg)?;
        self.transcript.update(&tls_msg)?;

        // Decode CKE body (skip DTLS 12-byte header)
        let body = dtls_get_body(raw_dtls_msg)?;
        let cke = decode_client_key_exchange(body)?;

        let kx = self
            .ephemeral_key
            .take()
            .ok_or_else(|| TlsError::HandshakeFailed("no ephemeral key".into()))?;
        let pre_master_secret = kx.compute_shared_secret(&cke.public_key)?;

        let params = self
            .params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher suite params".into()))?;

        let factory = params.hash_factory();
        let master_secret = derive_master_secret(
            &*factory,
            &pre_master_secret,
            &self.client_random,
            &self.server_random,
        )?;

        let key_block = derive_key_block(
            &*factory,
            &master_secret,
            &self.server_random,
            &self.client_random,
            params,
        )?;

        self.master_secret = master_secret.clone();
        self.state = Dtls12ServerState::WaitChangeCipherSpec;

        Ok(DtlsDerivedKeys {
            master_secret,
            client_write_key: key_block.client_write_key.clone(),
            server_write_key: key_block.server_write_key.clone(),
            client_write_iv: key_block.client_write_iv.clone(),
            server_write_iv: key_block.server_write_iv.clone(),
        })
    }

    /// Process ChangeCipherSpec from client.
    pub fn process_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        if self.state != Dtls12ServerState::WaitChangeCipherSpec {
            return Err(TlsError::HandshakeFailed(
                "unexpected ChangeCipherSpec".into(),
            ));
        }
        self.state = Dtls12ServerState::WaitFinished;
        Ok(())
    }

    /// Process client Finished and build server Finished.
    ///
    /// `raw_dtls_msg` is the DTLS handshake message (12-byte header + body).
    pub fn process_finished(
        &mut self,
        raw_dtls_msg: &[u8],
    ) -> Result<DtlsServerFinishedResult, TlsError> {
        if self.state != Dtls12ServerState::WaitFinished {
            return Err(TlsError::HandshakeFailed("unexpected Finished".into()));
        }

        let params = self
            .params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher suite params".into()))?;

        // Convert to TLS format to get verify_data
        let tls_msg = dtls_to_tls_handshake(raw_dtls_msg)?;
        if tls_msg.len() < 4 + 12 {
            return Err(TlsError::HandshakeFailed("Finished too short".into()));
        }
        let received_verify_data = &tls_msg[4..4 + 12];

        // Verify client Finished
        let factory = params.hash_factory();
        let transcript_hash = self.transcript.current_hash()?;
        let expected = compute_verify_data(
            &*factory,
            &self.master_secret,
            "client finished",
            &transcript_hash,
        )?;

        if !bool::from(received_verify_data.ct_eq(&expected)) {
            return Err(TlsError::HandshakeFailed(
                "client Finished verify_data mismatch".into(),
            ));
        }

        // Add client Finished to transcript
        self.transcript.update(&tls_msg)?;

        // Compute server Finished
        let transcript_hash = self.transcript.current_hash()?;
        let server_verify_data = compute_verify_data(
            &*factory,
            &self.master_secret,
            "server finished",
            &transcript_hash,
        )?;
        let finished_tls = encode_finished12(&server_verify_data);
        let seq = self.message_seq;
        self.message_seq += 1;
        let finished_dtls = tls_to_dtls_handshake(&finished_tls, seq)?;

        self.state = Dtls12ServerState::Connected;

        Ok(DtlsServerFinishedResult {
            finished: finished_dtls,
        })
    }

    /// Compute a cookie from the ClientHello fields.
    ///
    /// Uses HMAC-SHA256(cookie_secret, client_random || cipher_suites_hash).
    fn compute_cookie(&self, ch: &ClientHello) -> Vec<u8> {
        use hitls_crypto::hmac::Hmac;
        use hitls_crypto::sha2::Sha256 as S256;

        // Hash the cipher suite list for a compact representation
        let mut suite_bytes = Vec::with_capacity(ch.cipher_suites.len() * 2);
        for s in &ch.cipher_suites {
            suite_bytes.extend_from_slice(&s.0.to_be_bytes());
        }

        let mut mac = Hmac::new(
            || -> Box<dyn hitls_crypto::hash::Digest> { Box::new(S256::new()) },
            &self.cookie_secret,
        )
        .unwrap();
        mac.update(&ch.random).unwrap();
        mac.update(&suite_bytes).unwrap();

        let mut out = vec![0u8; 32];
        mac.finish(&mut out).unwrap();
        // Truncate to 16 bytes for cookie (sufficient for DoS protection)
        out.truncate(16);
        out
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
    use crate::config::ServerPrivateKey;
    use crate::crypt::NamedGroup;
    use crate::handshake::codec_dtls::{
        encode_dtls_client_hello_body, parse_dtls_handshake_header,
    };

    fn make_dtls_server_config() -> TlsConfig {
        let seed = vec![0x42u8; 32];
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(&seed).unwrap();
        let _pub_key = kp.public_key().to_vec();

        // Minimal test cert (not real X.509)
        let cert_der = vec![0x30, 0x82, 0x01, 0x00];

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

    fn build_dtls_client_hello(suites: &[CipherSuite], cookie: &[u8]) -> Vec<u8> {
        let mut random = [0u8; 32];
        getrandom::getrandom(&mut random).unwrap();

        let extensions = vec![
            crate::handshake::extensions_codec::build_signature_algorithms(&[
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                SignatureScheme::RSA_PSS_RSAE_SHA256,
            ]),
            crate::handshake::extensions_codec::build_supported_groups(&[
                NamedGroup::SECP256R1,
                NamedGroup::X25519,
            ]),
            crate::handshake::extensions_codec::build_ec_point_formats(),
            crate::handshake::extensions_codec::build_renegotiation_info_initial(),
        ];

        let ch = ClientHello {
            random,
            legacy_session_id: vec![0u8; 32],
            cipher_suites: suites.to_vec(),
            extensions,
        };

        let body = encode_dtls_client_hello_body(&ch, cookie);
        wrap_dtls_handshake_full(HandshakeType::ClientHello, &body, 0)
    }

    #[test]
    fn test_dtls12_server_state_initial() {
        let config = make_dtls_server_config();
        let hs = Dtls12ServerHandshake::new(config, true);
        assert_eq!(hs.state(), Dtls12ServerState::Idle);
    }

    #[test]
    fn test_dtls12_server_no_cookie_mode() {
        let config = make_dtls_server_config();
        let mut hs = Dtls12ServerHandshake::new(config, false);

        let ch_msg =
            build_dtls_client_hello(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256], &[]);

        let result = hs.process_client_hello(&ch_msg).unwrap();
        // Should directly produce server flight (no HVR)
        let flight = result.unwrap();

        // Verify all messages have DTLS headers
        let (h, _, _) = parse_dtls_handshake_header(&flight.server_hello).unwrap();
        assert_eq!(h.msg_type, HandshakeType::ServerHello);

        let (h, _, _) = parse_dtls_handshake_header(&flight.certificate).unwrap();
        assert_eq!(h.msg_type, HandshakeType::Certificate);

        let (h, _, _) = parse_dtls_handshake_header(&flight.server_key_exchange).unwrap();
        assert_eq!(h.msg_type, HandshakeType::ServerKeyExchange);

        let (h, _, _) = parse_dtls_handshake_header(&flight.server_hello_done).unwrap();
        assert_eq!(h.msg_type, HandshakeType::ServerHelloDone);

        assert_eq!(hs.state(), Dtls12ServerState::WaitClientKeyExchange);
    }

    #[test]
    fn test_dtls12_hello_verify_request_flow() {
        let config = make_dtls_server_config();
        let mut hs = Dtls12ServerHandshake::new(config, true);

        // First ClientHello (no cookie)
        let ch_msg =
            build_dtls_client_hello(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256], &[]);

        let result = hs.process_client_hello(&ch_msg).unwrap();
        // Should get HVR, not flight
        let hvr_result = result.unwrap_err();

        let (h, _, _) = parse_dtls_handshake_header(&hvr_result.hello_verify_request).unwrap();
        assert_eq!(h.msg_type, HandshakeType::HelloVerifyRequest);
        assert_eq!(hs.state(), Dtls12ServerState::WaitClientHelloWithCookie);
    }
}
