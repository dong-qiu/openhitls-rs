//! DTLCP server handshake state machine.
//!
//! Combines DTLS record framing (12-byte handshake headers, cookie exchange,
//! transcript hashing with TLS-format headers) with TLCP crypto (SM2/SM3/SM4,
//! double certificates, ECDHE + ECC static key exchange).

use crate::config::{ServerPrivateKey, TlsConfig};
use crate::crypt::key_schedule12::{
    compute_verify_data, derive_master_secret, derive_tlcp_key_block,
};
use crate::crypt::transcript::TranscriptHash;
use crate::crypt::{KeyExchangeAlg, NamedGroup, SignatureScheme, TlcpCipherSuiteParams};
use crate::handshake::codec::{encode_server_hello, ClientHello, ServerHello};
use crate::handshake::codec12::{
    build_ske_params, build_ske_signed_data, decode_client_key_exchange, encode_finished12,
    encode_server_hello_done, encode_server_key_exchange, ServerKeyExchange,
};
use crate::handshake::codec_dtls::{
    decode_dtls_client_hello, dtls_to_tls_handshake, encode_hello_verify_request,
    tls_to_dtls_handshake, wrap_dtls_handshake_full, HelloVerifyRequest,
};
use crate::handshake::codec_tlcp::{
    build_ecc_ske_signed_data, decode_ecc_client_key_exchange, encode_ecc_server_key_exchange,
    encode_tlcp_certificate, EccServerKeyExchange, TlcpCertificateMessage,
};
use crate::handshake::key_exchange::KeyExchange;
use crate::handshake::HandshakeType;
use crate::record::encryption_dtlcp::DTLCP_VERSION;
use crate::CipherSuite;
use hitls_crypto::sm3::Sm3;
use hitls_types::TlsError;
use std::mem;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// DTLCP server handshake states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlcpServerState {
    Idle,
    WaitClientHelloWithCookie,
    WaitClientKeyExchange,
    WaitChangeCipherSpec,
    WaitFinished,
    Connected,
}

/// Result from processing the initial ClientHello when cookie mode is enabled.
#[derive(Debug)]
pub struct DtlcpHelloVerifyResult {
    /// HelloVerifyRequest DTLS handshake message.
    pub hello_verify_request: Vec<u8>,
}

/// Server flight result after processing ClientHello.
pub struct DtlcpServerFlightResult {
    /// ServerHello DTLS handshake message.
    pub server_hello: Vec<u8>,
    /// Certificate DTLS handshake message (double cert).
    pub certificate: Vec<u8>,
    /// ServerKeyExchange DTLS handshake message.
    pub server_key_exchange: Vec<u8>,
    /// ServerHelloDone DTLS handshake message.
    pub server_hello_done: Vec<u8>,
    /// Negotiated cipher suite.
    pub suite: CipherSuite,
}

/// Keys derived after processing ClientKeyExchange.
pub struct DtlcpDerivedKeys {
    pub master_secret: Vec<u8>,
    pub client_write_mac_key: Vec<u8>,
    pub server_write_mac_key: Vec<u8>,
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
}

impl Drop for DtlcpDerivedKeys {
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

/// Server Finished result.
pub struct DtlcpServerFinishedResult {
    /// Server Finished DTLS handshake message.
    pub finished: Vec<u8>,
}

/// DTLCP server handshake state machine.
pub struct DtlcpServerHandshake {
    config: TlsConfig,
    state: DtlcpServerState,
    params: Option<TlcpCipherSuiteParams>,
    transcript: TranscriptHash,
    client_random: [u8; 32],
    server_random: [u8; 32],
    is_ecc_static: bool,
    ecdh_keypair: Option<KeyExchange>,
    master_secret: Vec<u8>,
    /// Next message_seq to assign to outgoing messages.
    message_seq: u16,
    /// Whether cookie exchange is enabled.
    enable_cookie: bool,
    /// Secret for computing cookies (HMAC-SHA256 based).
    cookie_secret: Vec<u8>,
    /// The expected cookie for the current handshake.
    expected_cookie: Vec<u8>,
}

impl Drop for DtlcpServerHandshake {
    fn drop(&mut self) {
        self.master_secret.zeroize();
        self.cookie_secret.zeroize();
    }
}

impl DtlcpServerHandshake {
    pub fn new(config: TlsConfig, enable_cookie: bool) -> Self {
        let mut cookie_secret = vec![0u8; 32];
        let _ = getrandom::getrandom(&mut cookie_secret);

        Self {
            config,
            state: DtlcpServerState::Idle,
            params: None,
            transcript: TranscriptHash::new(|| Box::new(Sm3::new())),
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            is_ecc_static: false,
            ecdh_keypair: None,
            master_secret: Vec::new(),
            message_seq: 0,
            enable_cookie,
            cookie_secret,
            expected_cookie: Vec::new(),
        }
    }

    pub fn state(&self) -> DtlcpServerState {
        self.state
    }

    /// Process the initial ClientHello.
    ///
    /// If cookie mode is enabled, returns `Ok(Err(hvr))` containing a HelloVerifyRequest.
    /// If cookie mode is disabled, returns `Ok(Ok(flight))` with the server flight.
    pub fn process_client_hello(
        &mut self,
        raw_dtls_msg: &[u8],
    ) -> Result<Result<DtlcpServerFlightResult, DtlcpHelloVerifyResult>, TlsError> {
        if self.state != DtlcpServerState::Idle {
            return Err(TlsError::HandshakeFailed("unexpected ClientHello".into()));
        }

        // Parse DTLS ClientHello body (skip 12-byte header)
        let body = dtls_get_body(raw_dtls_msg)?;
        let (ch, cookie) = decode_dtls_client_hello(body)?;
        self.client_random = ch.random;

        if self.enable_cookie {
            if cookie.is_empty() {
                // First ClientHello without cookie -- send HVR
                let computed_cookie = self.compute_cookie(&ch);
                self.expected_cookie = computed_cookie.clone();

                let hvr = HelloVerifyRequest {
                    server_version: DTLCP_VERSION,
                    cookie: computed_cookie,
                };
                let hvr_body = encode_hello_verify_request(&hvr);
                let seq = self.message_seq;
                self.message_seq += 1;
                let hvr_msg =
                    wrap_dtls_handshake_full(HandshakeType::HelloVerifyRequest, &hvr_body, seq);

                self.state = DtlcpServerState::WaitClientHelloWithCookie;
                return Ok(Err(DtlcpHelloVerifyResult {
                    hello_verify_request: hvr_msg,
                }));
            }
            // Has cookie -- verify it
            if cookie != self.expected_cookie {
                return Err(TlsError::HandshakeFailed("cookie mismatch".into()));
            }
        }

        // Process ClientHello and build server flight
        self.build_server_flight(raw_dtls_msg, &ch).map(Ok)
    }

    /// Process a retried ClientHello (with cookie).
    pub fn process_client_hello_with_cookie(
        &mut self,
        raw_dtls_msg: &[u8],
    ) -> Result<DtlcpServerFlightResult, TlsError> {
        if self.state != DtlcpServerState::WaitClientHelloWithCookie {
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
    ) -> Result<DtlcpServerFlightResult, TlsError> {
        // Negotiate cipher suite (TLCP suites only)
        let suite = self.negotiate_suite(ch)?;
        let params = TlcpCipherSuiteParams::from_suite(suite)?;
        self.is_ecc_static = params.kx_alg == KeyExchangeAlg::Ecc;
        self.params = Some(params);

        // Add ClientHello to transcript in TLS format
        let tls_ch = dtls_to_tls_handshake(raw_dtls_msg)?;
        self.transcript.update(&tls_ch)?;

        // Generate server random
        getrandom::getrandom(&mut self.server_random)
            .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;

        // Build ServerHello (TLS format, then convert to DTLS)
        let mut session_id = vec![0u8; 32];
        getrandom::getrandom(&mut session_id)
            .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;

        let sh = ServerHello {
            random: self.server_random,
            legacy_session_id: session_id,
            cipher_suite: suite,
            extensions: Vec::new(),
        };
        let sh_tls = encode_server_hello(&sh);
        let seq = self.message_seq;
        self.message_seq += 1;
        let sh_dtls = tls_to_dtls_handshake(&sh_tls, seq)?;
        self.transcript.update(&sh_tls)?;

        // Build Certificate (double cert: sign chain + enc cert)
        let cert_msg = TlcpCertificateMessage {
            sign_chain: self.config.certificate_chain.clone(),
            enc_cert: self
                .config
                .tlcp_enc_certificate_chain
                .first()
                .cloned()
                .ok_or_else(|| {
                    TlsError::HandshakeFailed("no TLCP encryption certificate".into())
                })?,
        };
        let cert_tls = encode_tlcp_certificate(&cert_msg);
        let seq = self.message_seq;
        self.message_seq += 1;
        let cert_dtls = tls_to_dtls_handshake(&cert_tls, seq)?;
        self.transcript.update(&cert_tls)?;

        // Build ServerKeyExchange
        let ske_tls = self.build_server_key_exchange(&cert_msg.enc_cert)?;
        let seq = self.message_seq;
        self.message_seq += 1;
        let ske_dtls = tls_to_dtls_handshake(&ske_tls, seq)?;
        self.transcript.update(&ske_tls)?;

        // Build ServerHelloDone
        let shd_tls = encode_server_hello_done();
        let seq = self.message_seq;
        self.message_seq += 1;
        let shd_dtls = tls_to_dtls_handshake(&shd_tls, seq)?;
        self.transcript.update(&shd_tls)?;

        self.state = DtlcpServerState::WaitClientKeyExchange;

        Ok(DtlcpServerFlightResult {
            server_hello: sh_dtls,
            certificate: cert_dtls,
            server_key_exchange: ske_dtls,
            server_hello_done: shd_dtls,
            suite,
        })
    }

    /// Negotiate a TLCP cipher suite.
    fn negotiate_suite(&self, ch: &ClientHello) -> Result<CipherSuite, TlsError> {
        for &server_suite in &self.config.cipher_suites {
            if crate::crypt::is_tlcp_suite(server_suite)
                && ch.cipher_suites.contains(&server_suite)
            {
                return Ok(server_suite);
            }
        }
        Err(TlsError::NoSharedCipherSuite)
    }

    /// Build the ServerKeyExchange message (TLS format).
    fn build_server_key_exchange(&mut self, enc_cert_der: &[u8]) -> Result<Vec<u8>, TlsError> {
        let sign_key = self
            .config
            .private_key
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no signing private key".into()))?;

        if self.is_ecc_static {
            // ECC static: sign (client_random || server_random || enc_cert_der)
            let signed_data =
                build_ecc_ske_signed_data(&self.client_random, &self.server_random, enc_cert_der);
            let signature = sign_sm2(sign_key, &signed_data)?;

            let ske = EccServerKeyExchange {
                signature_algorithm: SignatureScheme::SM2_SM3,
                signature,
            };
            Ok(encode_ecc_server_key_exchange(&ske))
        } else {
            // ECDHE: generate ephemeral SM2 keypair
            let kx = KeyExchange::generate(NamedGroup::SM2P256)?;
            let public_key = kx.public_key_bytes().to_vec();

            let params = build_ske_params(3, 0x0041, &public_key);
            let signed_data =
                build_ske_signed_data(&self.client_random, &self.server_random, &params);
            let signature = sign_sm2(sign_key, &signed_data)?;

            let ske = ServerKeyExchange {
                curve_type: 3,
                named_curve: 0x0041,
                public_key,
                signature_algorithm: SignatureScheme::SM2_SM3,
                signature,
            };

            self.ecdh_keypair = Some(kx);
            Ok(encode_server_key_exchange(&ske))
        }
    }

    /// Process ClientKeyExchange and derive keys.
    pub fn process_client_key_exchange(
        &mut self,
        raw_dtls_msg: &[u8],
    ) -> Result<DtlcpDerivedKeys, TlsError> {
        if self.state != DtlcpServerState::WaitClientKeyExchange {
            return Err(TlsError::HandshakeFailed(
                "unexpected ClientKeyExchange".into(),
            ));
        }

        // Add to transcript in TLS format
        let tls_msg = dtls_to_tls_handshake(raw_dtls_msg)?;
        self.transcript.update(&tls_msg)?;

        // Decode CKE body (skip DTLS 12-byte header)
        let body = dtls_get_body(raw_dtls_msg)?;

        let params = self
            .params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher suite params".into()))?
            .clone();

        let pre_master_secret = if self.is_ecc_static {
            // ECC static: SM2-decrypt premaster secret
            let cke = decode_ecc_client_key_exchange(body)?;

            let enc_key = self
                .config
                .tlcp_enc_private_key
                .as_ref()
                .ok_or_else(|| TlsError::HandshakeFailed("no enc private key".into()))?;

            let private_key_bytes = match enc_key {
                ServerPrivateKey::Sm2 { private_key } => private_key,
                _ => {
                    return Err(TlsError::HandshakeFailed(
                        "enc private key must be SM2".into(),
                    ))
                }
            };

            let kp = hitls_crypto::sm2::Sm2KeyPair::from_private_key(private_key_bytes)
                .map_err(TlsError::CryptoError)?;
            kp.decrypt(&cke.encrypted_premaster)
                .map_err(TlsError::CryptoError)?
        } else {
            // ECDHE: compute shared secret
            let cke = decode_client_key_exchange(body)?;
            let kx = self
                .ecdh_keypair
                .as_ref()
                .ok_or_else(|| TlsError::HandshakeFailed("no ECDH keypair".into()))?;
            kx.compute_shared_secret(&cke.public_key)?
        };

        // Derive master secret and key block
        let factory = params.hash_factory();
        let master_secret = derive_master_secret(
            &*factory,
            &pre_master_secret,
            &self.client_random,
            &self.server_random,
        )?;
        crate::crypt::keylog::log_master_secret(&self.config, &self.client_random, &master_secret);

        let mut key_block = derive_tlcp_key_block(
            &*factory,
            &master_secret,
            &self.server_random,
            &self.client_random,
            &params,
        )?;

        self.master_secret = master_secret.clone();
        self.state = DtlcpServerState::WaitChangeCipherSpec;

        Ok(DtlcpDerivedKeys {
            master_secret,
            client_write_mac_key: mem::take(&mut key_block.client_write_mac_key),
            server_write_mac_key: mem::take(&mut key_block.server_write_mac_key),
            client_write_key: mem::take(&mut key_block.client_write_key),
            server_write_key: mem::take(&mut key_block.server_write_key),
            client_write_iv: mem::take(&mut key_block.client_write_iv),
            server_write_iv: mem::take(&mut key_block.server_write_iv),
        })
    }

    /// Process ChangeCipherSpec from client.
    pub fn process_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        if self.state != DtlcpServerState::WaitChangeCipherSpec {
            return Err(TlsError::HandshakeFailed(
                "unexpected ChangeCipherSpec".into(),
            ));
        }
        self.state = DtlcpServerState::WaitFinished;
        Ok(())
    }

    /// Process client Finished and build server Finished.
    pub fn process_finished(
        &mut self,
        raw_dtls_msg: &[u8],
    ) -> Result<DtlcpServerFinishedResult, TlsError> {
        if self.state != DtlcpServerState::WaitFinished {
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

        self.state = DtlcpServerState::Connected;

        Ok(DtlcpServerFinishedResult {
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

/// SM2 signing using the server's signing private key.
fn sign_sm2(key: &ServerPrivateKey, data: &[u8]) -> Result<Vec<u8>, TlsError> {
    match key {
        ServerPrivateKey::Sm2 { private_key } => {
            let kp = hitls_crypto::sm2::Sm2KeyPair::from_private_key(private_key)
                .map_err(TlsError::CryptoError)?;
            kp.sign(data).map_err(TlsError::CryptoError)
        }
        _ => Err(TlsError::HandshakeFailed(
            "DTLCP signing key must be SM2".into(),
        )),
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
    #[test]
    fn test_dtlcp_server_state_initial() {
        let config = TlsConfig::builder().build();
        let hs = DtlcpServerHandshake::new(config, true);
        assert_eq!(hs.state(), DtlcpServerState::Idle);
    }

    #[test]
    fn test_dtlcp_server_state_initial_no_cookie() {
        let config = TlsConfig::builder().build();
        let hs = DtlcpServerHandshake::new(config, false);
        assert_eq!(hs.state(), DtlcpServerState::Idle);
        assert!(!hs.enable_cookie);
    }
}
