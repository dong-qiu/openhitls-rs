//! DTLCP client handshake state machine.
//!
//! Combines DTLS record framing (12-byte handshake headers, cookie exchange,
//! transcript hashing with TLS-format headers) with TLCP crypto (SM2/SM3/SM4,
//! double certificates, ECDHE + ECC static key exchange).

use crate::config::TlsConfig;
use crate::crypt::key_schedule12::{
    compute_verify_data, derive_master_secret, derive_tlcp_key_block,
};
use crate::crypt::transcript::TranscriptHash;
use crate::crypt::{KeyExchangeAlg, NamedGroup, TlcpCipherSuiteParams};
use crate::handshake::codec::ServerHello;
use crate::handshake::codec12::{
    build_ske_params, build_ske_signed_data, encode_client_key_exchange, encode_finished12,
    ClientKeyExchange,
};
use crate::handshake::codec_dtls::{dtls_to_tls_handshake, wrap_dtls_handshake_full};
use crate::handshake::codec_tlcp::{
    build_ecc_ske_signed_data, decode_ecc_server_key_exchange, encode_ecc_client_key_exchange,
    EccClientKeyExchange, TlcpCertificateMessage,
};
use crate::handshake::key_exchange::KeyExchange;
use crate::handshake::HandshakeType;
use crate::record::encryption_dtlcp::DTLCP_VERSION;
use crate::CipherSuite;
use hitls_crypto::sm3::Sm3;
use hitls_types::TlsError;
use std::mem;
use zeroize::Zeroize;

/// DTLCP client handshake states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlcpClientState {
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

/// Result of processing ServerHelloDone -- contains the client flight.
pub struct DtlcpClientFlightResult {
    /// ClientKeyExchange DTLS handshake message.
    pub client_key_exchange: Vec<u8>,
    /// Finished DTLS handshake message.
    pub finished: Vec<u8>,
    /// Master secret.
    pub master_secret: Vec<u8>,
    /// Key material (CBC suites need MAC keys).
    pub client_write_mac_key: Vec<u8>,
    pub server_write_mac_key: Vec<u8>,
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
}

impl Drop for DtlcpClientFlightResult {
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

/// DTLCP client handshake state machine.
pub struct DtlcpClientHandshake {
    config: TlsConfig,
    state: DtlcpClientState,
    params: Option<TlcpCipherSuiteParams>,
    transcript: TranscriptHash,
    client_random: [u8; 32],
    server_random: [u8; 32],
    server_sign_certs: Vec<Vec<u8>>,
    server_enc_cert: Vec<u8>,
    server_ecdh_public: Vec<u8>,
    is_ecc_static: bool,
    /// Next message_seq to assign to outgoing messages.
    message_seq: u16,
    /// Cookie from HelloVerifyRequest.
    cookie: Vec<u8>,
    /// Stored ClientHello TLS bytes for transcript replay.
    client_hello_tls_bytes: Vec<u8>,
}

impl DtlcpClientHandshake {
    pub fn new(config: TlsConfig) -> Self {
        Self {
            config,
            state: DtlcpClientState::Idle,
            params: None,
            transcript: TranscriptHash::new(|| Box::new(Sm3::new())),
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            server_sign_certs: Vec::new(),
            server_enc_cert: Vec::new(),
            server_ecdh_public: Vec::new(),
            is_ecc_static: false,
            message_seq: 0,
            cookie: Vec::new(),
            client_hello_tls_bytes: Vec::new(),
        }
    }

    pub fn state(&self) -> DtlcpClientState {
        self.state
    }

    /// Build the initial ClientHello (DTLS format with empty cookie).
    pub fn build_client_hello(&mut self) -> Result<Vec<u8>, TlsError> {
        self.build_client_hello_with_cookie(&[])
    }

    /// Build a ClientHello with the given cookie.
    fn build_client_hello_with_cookie(&mut self, cookie: &[u8]) -> Result<Vec<u8>, TlsError> {
        // Generate client_random (only on first call)
        if self.state == DtlcpClientState::Idle {
            getrandom::getrandom(&mut self.client_random)
                .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;
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
        extensions.push(crate::handshake::extensions_codec::build_ec_point_formats());

        // Filter cipher suites to TLCP
        let tlcp_suites: Vec<CipherSuite> = self
            .config
            .cipher_suites
            .iter()
            .copied()
            .filter(|s| crate::crypt::is_tlcp_suite(*s))
            .collect();

        if tlcp_suites.is_empty() {
            return Err(TlsError::NoSharedCipherSuite);
        }

        let mut session_id = vec![0u8; 32];
        getrandom::getrandom(&mut session_id)
            .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;

        let ch = crate::handshake::codec::ClientHello {
            random: self.client_random,
            legacy_session_id: session_id,
            cipher_suites: tlcp_suites,
            extensions,
        };

        // Encode DTLCP ClientHello body (with cookie, version = 0x0101)
        let ch_body = encode_dtlcp_client_hello_body(&ch, cookie);

        // Wrap with DTLS handshake header
        let seq = self.message_seq;
        self.message_seq += 1;
        let dtls_msg = wrap_dtls_handshake_full(HandshakeType::ClientHello, &ch_body, seq);

        // Convert to TLS format for transcript
        let tls_msg = dtls_to_tls_handshake(&dtls_msg)?;
        self.client_hello_tls_bytes = tls_msg.clone();
        self.transcript.update(&tls_msg)?;

        self.state = if cookie.is_empty() {
            DtlcpClientState::WaitHelloVerifyRequest
        } else {
            DtlcpClientState::WaitServerHello
        };

        Ok(dtls_msg)
    }

    /// Process a HelloVerifyRequest. Returns a new ClientHello with the cookie.
    pub fn process_hello_verify_request(
        &mut self,
        raw_dtls_msg: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        if self.state != DtlcpClientState::WaitHelloVerifyRequest
            && self.state != DtlcpClientState::WaitServerHello
        {
            return Err(TlsError::HandshakeFailed(
                "unexpected HelloVerifyRequest".into(),
            ));
        }

        // Parse HVR body (skip 12-byte DTLS header)
        let body = dtls_get_body(raw_dtls_msg)?;
        let hvr = crate::handshake::codec_dtls::decode_hello_verify_request(body)?;
        self.cookie = hvr.cookie;

        // HVR is NOT added to the transcript (RFC 6347 S4.2.1)
        // Reset transcript for fresh start with the retried ClientHello
        self.transcript = TranscriptHash::new(|| Box::new(Sm3::new()));

        // Rebuild ClientHello with cookie
        self.build_client_hello_with_cookie(&self.cookie.clone())
    }

    /// Process a ServerHello message.
    pub fn process_server_hello(
        &mut self,
        raw_dtls_msg: &[u8],
        sh: &ServerHello,
    ) -> Result<CipherSuite, TlsError> {
        if self.state != DtlcpClientState::WaitServerHello
            && self.state != DtlcpClientState::WaitHelloVerifyRequest
        {
            return Err(TlsError::HandshakeFailed("unexpected ServerHello".into()));
        }

        let params = TlcpCipherSuiteParams::from_suite(sh.cipher_suite)?;
        self.is_ecc_static = params.kx_alg == KeyExchangeAlg::Ecc;
        self.server_random = sh.random;
        self.params = Some(params);

        // Add ServerHello to transcript in TLS format
        let tls_msg = dtls_to_tls_handshake(raw_dtls_msg)?;
        self.transcript.update(&tls_msg)?;
        self.state = DtlcpClientState::WaitCertificate;
        Ok(sh.cipher_suite)
    }

    /// Process a TLCP Certificate message (double cert: sign chain + enc cert).
    pub fn process_certificate(
        &mut self,
        raw_dtls_msg: &[u8],
        cert_msg: &TlcpCertificateMessage,
    ) -> Result<(), TlsError> {
        if self.state != DtlcpClientState::WaitCertificate {
            return Err(TlsError::HandshakeFailed("unexpected Certificate".into()));
        }

        self.server_sign_certs = cert_msg.sign_chain.clone();
        self.server_enc_cert = cert_msg.enc_cert.clone();

        let tls_msg = dtls_to_tls_handshake(raw_dtls_msg)?;
        self.transcript.update(&tls_msg)?;

        crate::cert_verify::verify_server_certificate(&self.config, &self.server_sign_certs)?;

        self.state = DtlcpClientState::WaitServerKeyExchange;
        Ok(())
    }

    /// Process ServerKeyExchange.
    ///
    /// For ECDHE: parse ephemeral SM2 pubkey + SM2-SM3 signature.
    /// For ECC: parse signature over (client_random || server_random || enc_cert_der).
    pub fn process_server_key_exchange(
        &mut self,
        raw_dtls_msg: &[u8],
        body: &[u8],
    ) -> Result<(), TlsError> {
        if self.state != DtlcpClientState::WaitServerKeyExchange {
            return Err(TlsError::HandshakeFailed(
                "unexpected ServerKeyExchange".into(),
            ));
        }

        if self.is_ecc_static {
            // ECC static: signature over enc cert
            let ske = decode_ecc_server_key_exchange(body)?;
            if self.config.verify_peer {
                let signed_data = build_ecc_ske_signed_data(
                    &self.client_random,
                    &self.server_random,
                    &self.server_enc_cert,
                );
                crate::handshake::client_tlcp::verify_sm2_signature(
                    &self.server_sign_certs[0],
                    &signed_data,
                    &ske.signature,
                )?;
            }
        } else {
            // ECDHE: ephemeral SM2 pubkey + signature
            let ske = crate::handshake::codec12::decode_server_key_exchange(body)?;
            if self.config.verify_peer {
                let params = build_ske_params(ske.curve_type, ske.named_curve, &ske.public_key);
                let signed_data =
                    build_ske_signed_data(&self.client_random, &self.server_random, &params);
                crate::handshake::client_tlcp::verify_sm2_signature(
                    &self.server_sign_certs[0],
                    &signed_data,
                    &ske.signature,
                )?;
            }
            self.server_ecdh_public =
                crate::handshake::codec12::decode_server_key_exchange(body)?.public_key;
        }

        let tls_msg = dtls_to_tls_handshake(raw_dtls_msg)?;
        self.transcript.update(&tls_msg)?;
        self.state = DtlcpClientState::WaitServerHelloDone;
        Ok(())
    }

    /// Process ServerHelloDone and generate the client flight.
    pub fn process_server_hello_done(
        &mut self,
        raw_dtls_msg: &[u8],
    ) -> Result<DtlcpClientFlightResult, TlsError> {
        if self.state != DtlcpClientState::WaitServerHelloDone {
            return Err(TlsError::HandshakeFailed(
                "unexpected ServerHelloDone".into(),
            ));
        }

        let tls_msg = dtls_to_tls_handshake(raw_dtls_msg)?;
        self.transcript.update(&tls_msg)?;

        let params = self
            .params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher suite params".into()))?
            .clone();

        let (pre_master_secret, cke_tls_msg) = if self.is_ecc_static {
            // ECC static: generate 48-byte PMS, SM2-encrypt with server enc cert pubkey
            let mut pms = vec![0u8; 48];
            // PMS format: version(2) || random(46), version = 0x0101
            pms[0] = 0x01;
            pms[1] = 0x01;
            getrandom::getrandom(&mut pms[2..])
                .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;

            let cert = hitls_pki::x509::Certificate::from_der(&self.server_enc_cert)
                .map_err(|e| TlsError::HandshakeFailed(format!("enc cert parse: {e}")))?;

            let enc_pubkey = &cert.public_key.public_key;
            let enc_kp = hitls_crypto::sm2::Sm2KeyPair::from_public_key(enc_pubkey)
                .map_err(TlsError::CryptoError)?;
            let encrypted = enc_kp.encrypt(&pms).map_err(TlsError::CryptoError)?;

            let cke = EccClientKeyExchange {
                encrypted_premaster: encrypted,
            };
            let cke_msg = encode_ecc_client_key_exchange(&cke);
            (pms, cke_msg)
        } else {
            // ECDHE: generate ephemeral SM2 key pair, compute shared secret
            let kx = KeyExchange::generate(NamedGroup::SM2P256)?;
            let client_public = kx.public_key_bytes().to_vec();
            let pre_master_secret = kx.compute_shared_secret(&self.server_ecdh_public)?;

            let cke = ClientKeyExchange {
                public_key: client_public,
            };
            let cke_msg = encode_client_key_exchange(&cke);
            (pre_master_secret, cke_msg)
        };

        // Convert CKE TLS msg to DTLS format
        let seq = self.message_seq;
        self.message_seq += 1;
        let cke_dtls_msg = crate::handshake::codec_dtls::tls_to_dtls_handshake(&cke_tls_msg, seq)?;

        // Add CKE to transcript in TLS format
        self.transcript.update(&cke_tls_msg)?;

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

        // Compute client Finished
        let transcript_hash = self.transcript.current_hash()?;
        let verify_data = compute_verify_data(
            &*factory,
            &master_secret,
            "client finished",
            &transcript_hash,
        )?;
        let finished_tls_msg = encode_finished12(&verify_data);
        self.transcript.update(&finished_tls_msg)?;

        let seq = self.message_seq;
        self.message_seq += 1;
        let finished_dtls_msg =
            crate::handshake::codec_dtls::tls_to_dtls_handshake(&finished_tls_msg, seq)?;

        self.state = DtlcpClientState::WaitChangeCipherSpec;

        Ok(DtlcpClientFlightResult {
            client_key_exchange: cke_dtls_msg,
            finished: finished_dtls_msg,
            master_secret,
            client_write_mac_key: mem::take(&mut key_block.client_write_mac_key),
            server_write_mac_key: mem::take(&mut key_block.server_write_mac_key),
            client_write_key: mem::take(&mut key_block.client_write_key),
            server_write_key: mem::take(&mut key_block.server_write_key),
            client_write_iv: mem::take(&mut key_block.client_write_iv),
            server_write_iv: mem::take(&mut key_block.server_write_iv),
        })
    }

    /// Process ChangeCipherSpec from server.
    pub fn process_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        if self.state != DtlcpClientState::WaitChangeCipherSpec {
            return Err(TlsError::HandshakeFailed(
                "unexpected ChangeCipherSpec".into(),
            ));
        }
        self.state = DtlcpClientState::WaitFinished;
        Ok(())
    }

    /// Process server Finished message.
    pub fn process_finished(
        &mut self,
        raw_dtls_msg: &[u8],
        master_secret: &[u8],
    ) -> Result<(), TlsError> {
        if self.state != DtlcpClientState::WaitFinished {
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
            self.state = DtlcpClientState::Connected;
            Ok(())
        } else {
            Err(TlsError::HandshakeFailed(
                "server Finished verify_data mismatch".into(),
            ))
        }
    }
}

/// Encode a DTLCP ClientHello body (with cookie field, version = 0x0101).
///
/// Same as `encode_dtls_client_hello_body` but uses DTLCP version (0x0101)
/// instead of DTLS 1.2 version (0xFEFD).
fn encode_dtlcp_client_hello_body(
    ch: &crate::handshake::codec::ClientHello,
    cookie: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(256);

    // legacy_version = 0x0101 (DTLCP)
    body.extend_from_slice(&DTLCP_VERSION.to_be_bytes());

    // random
    body.extend_from_slice(&ch.random);

    // legacy_session_id
    body.push(ch.legacy_session_id.len() as u8);
    body.extend_from_slice(&ch.legacy_session_id);

    // cookie (DTLS-specific)
    body.push(cookie.len() as u8);
    body.extend_from_slice(cookie);

    // cipher_suites
    let suites_len = (ch.cipher_suites.len() * 2) as u16;
    body.extend_from_slice(&suites_len.to_be_bytes());
    for s in &ch.cipher_suites {
        body.extend_from_slice(&s.0.to_be_bytes());
    }

    // legacy_compression_methods = {0}
    body.push(1);
    body.push(0);

    // extensions
    let ext_data = crate::handshake::codec::encode_extensions(&ch.extensions);
    body.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_data);

    body
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
    use crate::crypt::SignatureScheme;
    use crate::handshake::codec_dtls::parse_dtls_handshake_header;

    #[test]
    fn test_dtlcp_client_build_hello() {
        let config = TlsConfig::builder()
            .cipher_suites(&[
                CipherSuite::ECDHE_SM4_GCM_SM3,
                CipherSuite::ECC_SM4_CBC_SM3,
                CipherSuite::TLS_AES_128_GCM_SHA256, // should be filtered out
            ])
            .signature_algorithms(&[SignatureScheme::SM2_SM3])
            .build();

        let mut hs = DtlcpClientHandshake::new(config);
        let ch_msg = hs.build_client_hello().unwrap();

        // Verify DTLS handshake header
        let (header, _body, _) = parse_dtls_handshake_header(&ch_msg).unwrap();
        assert_eq!(header.msg_type, HandshakeType::ClientHello);
        assert_eq!(header.message_seq, 0);
        assert_eq!(header.fragment_offset, 0);

        assert_eq!(hs.state(), DtlcpClientState::WaitHelloVerifyRequest);
        assert_eq!(hs.message_seq, 1);
    }

    #[test]
    fn test_dtlcp_client_state_transitions() {
        let hs = DtlcpClientHandshake::new(TlsConfig::builder().build());
        assert_eq!(hs.state(), DtlcpClientState::Idle);
    }

    #[test]
    fn test_dtlcp_client_hello_version_is_0x0101() {
        let config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::ECDHE_SM4_GCM_SM3])
            .signature_algorithms(&[SignatureScheme::SM2_SM3])
            .build();

        let mut hs = DtlcpClientHandshake::new(config);
        let ch_msg = hs.build_client_hello().unwrap();

        // Body starts at offset 12 (DTLS header), first 2 bytes = version
        let body = &ch_msg[12..];
        let version = u16::from_be_bytes([body[0], body[1]]);
        assert_eq!(version, DTLCP_VERSION);
    }

    #[test]
    fn test_dtlcp_client_message_seq_tracking() {
        let config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::ECDHE_SM4_GCM_SM3])
            .signature_algorithms(&[SignatureScheme::SM2_SM3])
            .build();

        let mut hs = DtlcpClientHandshake::new(config);
        let ch1 = hs.build_client_hello().unwrap();

        let (h1, _, _) = parse_dtls_handshake_header(&ch1).unwrap();
        assert_eq!(h1.message_seq, 0);
        assert_eq!(hs.message_seq, 1);
    }

    #[test]
    fn test_dtlcp_client_no_tlcp_suites_error() {
        // Config with only TLS 1.3 suites → build_client_hello fails
        let config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_AES_128_GCM_SHA256])
            .signature_algorithms(&[SignatureScheme::SM2_SM3])
            .build();

        let mut hs = DtlcpClientHandshake::new(config);
        let result = hs.build_client_hello();
        assert!(result.is_err());
    }

    #[test]
    fn test_dtlcp_client_ccs_wrong_state_idle() {
        let config = TlsConfig::builder().build();
        let mut hs = DtlcpClientHandshake::new(config);
        let result = hs.process_change_cipher_spec();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unexpected ChangeCipherSpec"));
    }

    #[test]
    fn test_dtlcp_client_finished_wrong_state_idle() {
        let config = TlsConfig::builder().build();
        let mut hs = DtlcpClientHandshake::new(config);
        let fake_msg = vec![0u8; 20];
        let result = hs.process_finished(&fake_msg, &[0u8; 48]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unexpected Finished"));
    }

    #[test]
    fn test_dtlcp_client_server_hello_wrong_state_idle() {
        let config = TlsConfig::builder().build();
        let mut hs = DtlcpClientHandshake::new(config);
        let fake_msg = vec![0u8; 20];
        let sh = crate::handshake::codec::ServerHello {
            random: [0u8; 32],
            legacy_session_id: vec![0u8; 32],
            cipher_suite: CipherSuite::ECDHE_SM4_GCM_SM3,
            extensions: Vec::new(),
        };
        let result = hs.process_server_hello(&fake_msg, &sh);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unexpected ServerHello"));
    }

    #[test]
    fn test_dtlcp_client_dtls_get_body_too_short() {
        let short_msg = vec![0u8; 5];
        let result = dtls_get_body(&short_msg);
        assert!(result.is_err());

        let exact_msg = vec![0u8; 12];
        let body = dtls_get_body(&exact_msg).unwrap();
        assert!(body.is_empty());
    }
}
