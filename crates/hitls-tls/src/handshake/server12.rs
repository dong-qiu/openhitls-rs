//! TLS 1.2 server handshake state machine.
//!
//! Implements the ECDHE-GCM handshake for TLS 1.2 servers.

use crate::config::{ServerPrivateKey, TlsConfig};
use crate::crypt::key_schedule12::{compute_verify_data, derive_key_block, derive_master_secret};
use crate::crypt::transcript::TranscriptHash;
use crate::crypt::{is_tls12_suite, NamedGroup, SignatureScheme, Tls12CipherSuiteParams};
use crate::extensions::ExtensionType;
use crate::handshake::codec::{decode_client_hello, encode_server_hello, ClientHello, ServerHello};
use crate::handshake::codec12::{
    build_ske_params, build_ske_signed_data, decode_certificate12, decode_certificate_verify12,
    decode_client_key_exchange, encode_certificate12, encode_certificate_request12,
    encode_finished12, encode_server_hello_done, encode_server_key_exchange, Certificate12,
    CertificateRequest12, ServerKeyExchange,
};
use crate::handshake::extensions_codec::{
    parse_alpn_ch, parse_server_name, parse_signature_algorithms_ch, parse_supported_groups_ch,
};
use crate::handshake::key_exchange::KeyExchange;
use crate::session::SessionCache;
use crate::CipherSuite;
use hitls_crypto::sha2::Sha256;
use hitls_types::{EccCurveId, TlsError};
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
pub struct ServerFlightResult {
    /// ServerHello handshake message.
    pub server_hello: Vec<u8>,
    /// Certificate handshake message.
    pub certificate: Vec<u8>,
    /// ServerKeyExchange handshake message.
    pub server_key_exchange: Vec<u8>,
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
            transcript: TranscriptHash::new(|| Box::new(Sha256::new())),
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            ephemeral_key: None,
            master_secret: Vec::new(),
            client_sig_algs: Vec::new(),
            negotiated_alpn: None,
            client_server_name: None,
            client_certs: Vec::new(),
            session_id: Vec::new(),
            abbreviated: false,
        }
    }

    pub fn state(&self) -> Tls12ServerState {
        self.state
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

    /// Whether this handshake used abbreviated (session resumption) mode.
    pub fn is_abbreviated(&self) -> bool {
        self.abbreviated
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
                _ => {} // ignore other extensions
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
            self.transcript = TranscriptHash::new(|| Box::new(hitls_crypto::sha2::Sha384::new()));
        }

        // Add full ClientHello (including header) to transcript
        self.transcript.update(msg_data)?;

        // Generate server random
        getrandom::getrandom(&mut self.server_random)
            .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;

        // Generate server-assigned session_id (32 bytes) for session caching
        let mut session_id = vec![0u8; 32];
        getrandom::getrandom(&mut session_id)
            .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;
        self.session_id = session_id;

        // Negotiate group
        let group = negotiate_group(&client_groups, &self.config.supported_groups)?;

        // Build ServerHello extensions
        let mut sh_extensions = Vec::new();
        if let Some(ref alpn) = self.negotiated_alpn {
            sh_extensions.push(crate::handshake::extensions_codec::build_alpn_selected(
                alpn,
            ));
        }

        // Build ServerHello
        let sh = ServerHello {
            random: self.server_random,
            legacy_session_id: self.session_id.clone(),
            cipher_suite: suite,
            extensions: sh_extensions,
        };
        let sh_msg = encode_server_hello(&sh);
        self.transcript.update(&sh_msg)?;

        // Build Certificate
        let cert12 = Certificate12 {
            certificate_list: self.config.certificate_chain.clone(),
        };
        let cert_msg = encode_certificate12(&cert12);
        self.transcript.update(&cert_msg)?;

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
        let ske_msg = encode_server_key_exchange(&ske);
        self.transcript.update(&ske_msg)?;

        // Build CertificateRequest (if mTLS is enabled)
        let certificate_request = if self.config.verify_client_cert {
            let cr = CertificateRequest12 {
                cert_types: vec![1, 64], // rsa_sign, ecdsa_sign
                sig_hash_algs: self.config.signature_algorithms.clone(),
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

        self.ephemeral_key = Some(kx);
        self.params = Some(params);
        self.state = if self.config.verify_client_cert {
            Tls12ServerState::WaitClientCertificate
        } else {
            Tls12ServerState::WaitClientKeyExchange
        };

        Ok(ServerFlightResult {
            server_hello: sh_msg,
            certificate: cert_msg,
            server_key_exchange: ske_msg,
            certificate_request,
            server_hello_done: shd_msg,
            suite,
            session_id: self.session_id.clone(),
        })
    }

    /// Process ClientHello with optional session cache lookup.
    ///
    /// If the client's session_id matches a cached session and the cipher suite
    /// is acceptable, returns an abbreviated handshake result. Otherwise falls
    /// back to a full handshake via `process_client_hello()`.
    pub fn process_client_hello_resumable(
        &mut self,
        msg_data: &[u8],
        session_cache: Option<&dyn SessionCache>,
    ) -> Result<ServerHelloResult, TlsError> {
        if self.state != Tls12ServerState::Idle {
            return Err(TlsError::HandshakeFailed("unexpected ClientHello".into()));
        }

        // Parse ClientHello to check session_id
        let body = get_body(msg_data)?;
        let ch = decode_client_hello(body)?;

        // Try session resumption
        if let Some(cache) = session_cache {
            if !ch.legacy_session_id.is_empty() {
                if let Some(session) = cache.get(&ch.legacy_session_id) {
                    // Verify the cached cipher suite is offered by both sides
                    if ch.cipher_suites.contains(&session.cipher_suite)
                        && self.config.cipher_suites.contains(&session.cipher_suite)
                        && is_tls12_suite(session.cipher_suite)
                    {
                        let cached_suite = session.cipher_suite;
                        let cached_ms = session.master_secret.clone();
                        let sid = ch.legacy_session_id.clone();

                        return self
                            .do_abbreviated(msg_data, &ch, cached_suite, &cached_ms, sid)
                            .map(ServerHelloResult::Abbreviated);
                    }
                }
            }
        }

        // Fall back to full handshake
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
    ) -> Result<AbbreviatedServerResult, TlsError> {
        let params = Tls12CipherSuiteParams::from_suite(suite)?;

        // Switch transcript hash if the resumed suite uses SHA-384
        if params.hash_len == 48 {
            self.transcript = TranscriptHash::new(|| Box::new(hitls_crypto::sha2::Sha384::new()));
        }

        self.client_random = ch.random;

        // Generate server random
        getrandom::getrandom(&mut self.server_random)
            .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;

        // Add full ClientHello to transcript
        self.transcript.update(msg_data)?;

        // Build ServerHello echoing the cached session_id
        let sh = ServerHello {
            random: self.server_random,
            legacy_session_id: session_id.clone(),
            cipher_suite: suite,
            extensions: Vec::new(),
        };
        let sh_msg = encode_server_hello(&sh);
        self.transcript.update(&sh_msg)?;

        // Derive key block from cached master_secret + new randoms
        let factory = params.hash_factory();
        let key_block = derive_key_block(
            &*factory,
            cached_master_secret,
            &self.server_random,
            &self.client_random,
            &params,
        )?;

        // Compute server Finished: PRF(ms, "server finished", Hash(CH + SH))
        let transcript_hash = self.transcript.current_hash()?;
        let server_verify_data = compute_verify_data(
            &*factory,
            cached_master_secret,
            "server finished",
            &transcript_hash,
        )?;
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

        // Compute transcript hash BEFORE adding CertificateVerify to transcript
        let transcript_hash = self.transcript.current_hash()?;

        let body = get_body(msg_data)?;
        let cv = decode_certificate_verify12(body)?;

        if self.client_certs.is_empty() {
            return Err(TlsError::HandshakeFailed(
                "no client certificate for CertificateVerify".into(),
            ));
        }

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
        self.transcript.update(msg_data)?;

        // Compute server Finished
        let transcript_hash = self.transcript.current_hash()?;
        let server_verify_data = compute_verify_data(
            &*factory,
            &self.master_secret,
            "server finished",
            &transcript_hash,
        )?;
        let finished_msg = encode_finished12(&server_verify_data);

        self.state = Tls12ServerState::Connected;

        Ok(ServerFinishedResult {
            finished: finished_msg,
        })
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
    // Server preference order
    for server_suite in &config.cipher_suites {
        if !is_tls12_suite(*server_suite) {
            continue;
        }
        if ch.cipher_suites.contains(server_suite) {
            return Ok(*server_suite);
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

/// Select a signature scheme for TLS 1.2 ServerKeyExchange.
///
/// Unlike TLS 1.3 which only uses PSS, TLS 1.2 also supports PKCS#1v1.5.
pub(crate) fn select_signature_scheme_tls12(
    key: &ServerPrivateKey,
    client_schemes: &[SignatureScheme],
) -> Result<SignatureScheme, TlsError> {
    let candidates: &[SignatureScheme] = match key {
        ServerPrivateKey::Ed25519(_) => &[SignatureScheme::ED25519],
        ServerPrivateKey::Ecdsa { curve_id, .. } => match *curve_id {
            EccCurveId::NistP256 => &[SignatureScheme::ECDSA_SECP256R1_SHA256],
            EccCurveId::NistP384 => &[SignatureScheme::ECDSA_SECP384R1_SHA384],
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
        #[cfg(feature = "tlcp")]
        ServerPrivateKey::Sm2 { .. } => &[SignatureScheme::SM2_SM3],
    };

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
        ServerPrivateKey::Ecdsa {
            curve_id,
            private_key,
        } => {
            let digest = match scheme {
                SignatureScheme::ECDSA_SECP256R1_SHA256 => compute_sha256(signed_data)?,
                SignatureScheme::ECDSA_SECP384R1_SHA384 => compute_sha384(signed_data)?,
                _ => return Err(TlsError::HandshakeFailed("ECDSA scheme mismatch".into())),
            };
            let kp = hitls_crypto::ecdsa::EcdsaKeyPair::from_private_key(*curve_id, private_key)
                .map_err(TlsError::CryptoError)?;
            kp.sign(&digest).map_err(TlsError::CryptoError)
        }
        ServerPrivateKey::Rsa { n, d, e, p, q } => {
            let digest = match scheme {
                SignatureScheme::RSA_PKCS1_SHA256 | SignatureScheme::RSA_PSS_RSAE_SHA256 => {
                    compute_sha256(signed_data)?
                }
                SignatureScheme::RSA_PKCS1_SHA384 | SignatureScheme::RSA_PSS_RSAE_SHA384 => {
                    compute_sha384(signed_data)?
                }
                _ => return Err(TlsError::HandshakeFailed("RSA scheme mismatch".into())),
            };
            let padding = match scheme {
                SignatureScheme::RSA_PKCS1_SHA256 | SignatureScheme::RSA_PKCS1_SHA384 => {
                    hitls_crypto::rsa::RsaPadding::Pkcs1v15Sign
                }
                _ => hitls_crypto::rsa::RsaPadding::Pss,
            };
            let rsa_key = hitls_crypto::rsa::RsaPrivateKey::new(n, d, e, p, q)
                .map_err(TlsError::CryptoError)?;
            rsa_key
                .sign(padding, &digest)
                .map_err(TlsError::CryptoError)
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
    if msg_data.len() <= 4 {
        return Err(TlsError::HandshakeFailed(
            "handshake message too short".into(),
        ));
    }
    Ok(&msg_data[4..])
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

/// Verify a TLS 1.2 CertificateVerify signature.
///
/// Unlike SKE verification, `transcript_hash` is already a hash digest —
/// it is NOT re-hashed before verification.
fn verify_cv12_signature(
    cert_der: &[u8],
    scheme: SignatureScheme,
    transcript_hash: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    let cert = hitls_pki::x509::Certificate::from_der(cert_der)
        .map_err(|e| TlsError::HandshakeFailed(format!("client cert parse: {e}")))?;
    let spki = &cert.public_key;

    let ok = match scheme {
        SignatureScheme::RSA_PKCS1_SHA256 | SignatureScheme::RSA_PKCS1_SHA384 => verify_cv_rsa(
            spki,
            hitls_crypto::rsa::RsaPadding::Pkcs1v15Sign,
            transcript_hash,
            signature,
        )?,
        SignatureScheme::RSA_PSS_RSAE_SHA256 | SignatureScheme::RSA_PSS_RSAE_SHA384 => {
            verify_cv_rsa(
                spki,
                hitls_crypto::rsa::RsaPadding::Pss,
                transcript_hash,
                signature,
            )?
        }
        SignatureScheme::ECDSA_SECP256R1_SHA256 => {
            let verifier = hitls_crypto::ecdsa::EcdsaKeyPair::from_public_key(
                hitls_types::EccCurveId::NistP256,
                &spki.public_key,
            )
            .map_err(TlsError::CryptoError)?;
            verifier
                .verify(transcript_hash, signature)
                .map_err(TlsError::CryptoError)?
        }
        SignatureScheme::ECDSA_SECP384R1_SHA384 => {
            let verifier = hitls_crypto::ecdsa::EcdsaKeyPair::from_public_key(
                hitls_types::EccCurveId::NistP384,
                &spki.public_key,
            )
            .map_err(TlsError::CryptoError)?;
            verifier
                .verify(transcript_hash, signature)
                .map_err(TlsError::CryptoError)?
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
        Err(TlsError::HandshakeFailed(
            "client CertificateVerify signature verification failed".into(),
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
        vec![0x30, 0x82, 0x01, 0x00]
    }

    fn build_test_client_hello(suites: &[CipherSuite]) -> Vec<u8> {
        use crate::handshake::codec::encode_client_hello;
        use crate::handshake::extensions_codec::*;

        let mut random = [0u8; 32];
        getrandom::getrandom(&mut random).unwrap();

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

        let (ht, _, _) = parse_handshake_header(&result.certificate).unwrap();
        assert_eq!(ht, HandshakeType::Certificate);

        let (ht, _, _) = parse_handshake_header(&result.server_key_exchange).unwrap();
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
            created_at: 0,
            psk: Vec::new(),
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
            created_at: 0,
            psk: Vec::new(),
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
        getrandom::getrandom(&mut random).unwrap();

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
}
