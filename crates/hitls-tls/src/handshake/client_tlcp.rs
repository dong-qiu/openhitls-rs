//! TLCP (GM/T 0024) client handshake state machine.
//!
//! Supports both ECDHE (forward secrecy) and ECC (static) key exchange modes
//! with SM2/SM3/SM4 cipher suites.

use crate::config::TlsConfig;
use crate::crypt::key_schedule12::{
    compute_verify_data, derive_master_secret, derive_tlcp_key_block,
};
use crate::crypt::transcript::TranscriptHash;
use crate::crypt::{HashAlgId, KeyExchangeAlg, NamedGroup, TlcpCipherSuiteParams};
use crate::handshake::codec::{encode_client_hello, ClientHello, ServerHello};
use crate::handshake::codec12::{
    build_ske_params, build_ske_signed_data, encode_client_key_exchange, encode_finished12,
    ClientKeyExchange,
};
use crate::handshake::codec_tlcp::{
    build_ecc_ske_signed_data, decode_ecc_server_key_exchange, encode_ecc_client_key_exchange,
    EccClientKeyExchange, TlcpCertificateMessage,
};
use crate::handshake::key_exchange::KeyExchange;
use crate::CipherSuite;
use hitls_types::TlsError;
use std::mem;
use zeroize::Zeroize;

/// TLCP client handshake states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlcpClientState {
    Idle,
    WaitServerHello,
    WaitCertificate,
    WaitServerKeyExchange,
    WaitServerHelloDone,
    WaitChangeCipherSpec,
    WaitFinished,
    Connected,
}

/// Result of processing ServerHelloDone.
pub struct TlcpClientFlightResult {
    pub client_key_exchange: Vec<u8>,
    pub finished: Vec<u8>,
    pub master_secret: Vec<u8>,
    pub client_write_mac_key: Vec<u8>,
    pub server_write_mac_key: Vec<u8>,
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
}

impl Drop for TlcpClientFlightResult {
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

/// TLCP client handshake state machine.
pub struct TlcpClientHandshake {
    config: TlsConfig,
    state: TlcpClientState,
    params: Option<TlcpCipherSuiteParams>,
    transcript: TranscriptHash,
    client_random: [u8; 32],
    server_random: [u8; 32],
    server_sign_certs: Vec<Vec<u8>>,
    server_enc_cert: Vec<u8>,
    server_ecdh_public: Vec<u8>,
    is_ecc_static: bool,
}

impl TlcpClientHandshake {
    pub fn new(config: TlsConfig) -> Self {
        Self {
            config,
            state: TlcpClientState::Idle,
            params: None,
            transcript: TranscriptHash::new(HashAlgId::Sm3),
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            server_sign_certs: Vec::new(),
            server_enc_cert: Vec::new(),
            server_ecdh_public: Vec::new(),
            is_ecc_static: false,
        }
    }

    pub fn state(&self) -> TlcpClientState {
        self.state
    }

    /// Build the ClientHello message (version=0x0101, TLCP suites).
    pub fn build_client_hello(&mut self) -> Result<Vec<u8>, TlsError> {
        getrandom::getrandom(&mut self.client_random)
            .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;

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

        let ch = ClientHello {
            random: self.client_random,
            legacy_session_id: session_id,
            cipher_suites: tlcp_suites,
            extensions,
        };

        let msg = encode_client_hello(&ch);
        self.transcript.update(&msg)?;
        self.state = TlcpClientState::WaitServerHello;
        Ok(msg)
    }

    /// Process ServerHello.
    pub fn process_server_hello(
        &mut self,
        raw_msg: &[u8],
        sh: &ServerHello,
    ) -> Result<CipherSuite, TlsError> {
        if self.state != TlcpClientState::WaitServerHello {
            return Err(TlsError::HandshakeFailed("unexpected ServerHello".into()));
        }

        let params = TlcpCipherSuiteParams::from_suite(sh.cipher_suite)?;
        self.is_ecc_static = params.kx_alg == KeyExchangeAlg::Ecc;
        self.server_random = sh.random;
        self.params = Some(params);
        self.transcript.update(raw_msg)?;
        self.state = TlcpClientState::WaitCertificate;
        Ok(sh.cipher_suite)
    }

    /// Process TLCP Certificate (double cert: sign chain + enc cert).
    pub fn process_certificate(
        &mut self,
        raw_msg: &[u8],
        cert_msg: &TlcpCertificateMessage,
    ) -> Result<(), TlsError> {
        if self.state != TlcpClientState::WaitCertificate {
            return Err(TlsError::HandshakeFailed("unexpected Certificate".into()));
        }

        self.server_sign_certs = cert_msg.sign_chain.clone();
        self.server_enc_cert = cert_msg.enc_cert.clone();
        self.transcript.update(raw_msg)?;

        crate::cert_verify::verify_server_certificate(&self.config, &self.server_sign_certs)?;

        self.state = TlcpClientState::WaitServerKeyExchange;
        Ok(())
    }

    /// Process ServerKeyExchange.
    ///
    /// For ECDHE: parse ephemeral SM2 pubkey + SM2-SM3 signature.
    /// For ECC: parse signature over (client_random || server_random || enc_cert_der).
    pub fn process_server_key_exchange(
        &mut self,
        raw_msg: &[u8],
        body: &[u8],
    ) -> Result<(), TlsError> {
        if self.state != TlcpClientState::WaitServerKeyExchange {
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
                verify_sm2_signature(&self.server_sign_certs[0], &signed_data, &ske.signature)?;
            }
        } else {
            // ECDHE: ephemeral SM2 pubkey + signature
            let ske = crate::handshake::codec12::decode_server_key_exchange(body)?;
            if self.config.verify_peer {
                let params = build_ske_params(ske.curve_type, ske.named_curve, &ske.public_key);
                let signed_data =
                    build_ske_signed_data(&self.client_random, &self.server_random, &params);
                verify_sm2_signature(&self.server_sign_certs[0], &signed_data, &ske.signature)?;
            }
            self.server_ecdh_public =
                crate::handshake::codec12::decode_server_key_exchange(body)?.public_key;
        }

        self.transcript.update(raw_msg)?;
        self.state = TlcpClientState::WaitServerHelloDone;
        Ok(())
    }

    /// Process ServerHelloDone and generate client flight.
    pub fn process_server_hello_done(
        &mut self,
        raw_msg: &[u8],
    ) -> Result<TlcpClientFlightResult, TlsError> {
        if self.state != TlcpClientState::WaitServerHelloDone {
            return Err(TlsError::HandshakeFailed(
                "unexpected ServerHelloDone".into(),
            ));
        }

        self.transcript.update(raw_msg)?;

        let params = self
            .params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher suite params".into()))?
            .clone();

        let (pre_master_secret, cke_msg) = if self.is_ecc_static {
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

        self.transcript.update(&cke_msg)?;

        // Derive master secret and key block
        let alg = params.hash_alg_id();
        let master_secret = derive_master_secret(
            alg,
            &pre_master_secret,
            &self.client_random,
            &self.server_random,
        )?;
        crate::crypt::keylog::log_master_secret(&self.config, &self.client_random, &master_secret);

        let mut key_block = derive_tlcp_key_block(
            alg,
            &master_secret,
            &self.server_random,
            &self.client_random,
            &params,
        )?;

        // Compute client Finished
        let transcript_hash = self.transcript.current_hash()?;
        let verify_data =
            compute_verify_data(alg, &master_secret, "client finished", &transcript_hash)?;
        let finished_msg = encode_finished12(&verify_data);
        self.transcript.update(&finished_msg)?;

        self.state = TlcpClientState::WaitChangeCipherSpec;

        Ok(TlcpClientFlightResult {
            client_key_exchange: cke_msg,
            finished: finished_msg,
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
        if self.state != TlcpClientState::WaitChangeCipherSpec {
            return Err(TlsError::HandshakeFailed(
                "unexpected ChangeCipherSpec".into(),
            ));
        }
        self.state = TlcpClientState::WaitFinished;
        Ok(())
    }

    /// Process server Finished message.
    pub fn process_finished(
        &mut self,
        raw_msg: &[u8],
        master_secret: &[u8],
    ) -> Result<(), TlsError> {
        if self.state != TlcpClientState::WaitFinished {
            return Err(TlsError::HandshakeFailed("unexpected Finished".into()));
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

        let transcript_hash = self.transcript.current_hash()?;
        let expected = compute_verify_data(
            params.hash_alg_id(),
            master_secret,
            "server finished",
            &transcript_hash,
        )?;

        use subtle::ConstantTimeEq;
        if received_verify_data.ct_eq(&expected).into() {
            self.transcript.update(raw_msg)?;
            self.state = TlcpClientState::Connected;
            Ok(())
        } else {
            Err(TlsError::HandshakeFailed(
                "server Finished verify_data mismatch".into(),
            ))
        }
    }
}

/// Verify SM2-SM3 signature using the signing certificate.
pub(crate) fn verify_sm2_signature(
    cert_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    let cert = hitls_pki::x509::Certificate::from_der(cert_der)
        .map_err(|e| TlsError::HandshakeFailed(format!("cert parse: {e}")))?;

    let kp = hitls_crypto::sm2::Sm2KeyPair::from_public_key(&cert.public_key.public_key)
        .map_err(TlsError::CryptoError)?;

    let ok = kp
        .verify(message, signature)
        .map_err(TlsError::CryptoError)?;
    if ok {
        Ok(())
    } else {
        Err(TlsError::HandshakeFailed(
            "SM2 signature verification failed".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypt::SignatureScheme;

    #[test]
    fn test_tlcp_client_build_hello() {
        let config = TlsConfig::builder()
            .cipher_suites(&[
                CipherSuite::ECDHE_SM4_CBC_SM3,
                CipherSuite::ECC_SM4_GCM_SM3,
                CipherSuite::TLS_AES_128_GCM_SHA256, // should be filtered out
            ])
            .signature_algorithms(&[SignatureScheme::SM2_SM3])
            .build();

        let mut hs = TlcpClientHandshake::new(config);
        let ch_msg = hs.build_client_hello().unwrap();

        let (msg_type, body, _) = crate::handshake::codec::parse_handshake_header(&ch_msg).unwrap();
        assert_eq!(msg_type, crate::handshake::HandshakeType::ClientHello);

        let ch = crate::handshake::codec::decode_client_hello(body).unwrap();
        // Should only contain TLCP suites
        assert_eq!(ch.cipher_suites.len(), 2);
        assert_eq!(ch.cipher_suites[0], CipherSuite::ECDHE_SM4_CBC_SM3);
        assert_eq!(ch.cipher_suites[1], CipherSuite::ECC_SM4_GCM_SM3);

        assert_eq!(hs.state(), TlcpClientState::WaitServerHello);
    }

    #[test]
    fn test_tlcp_client_state_transitions() {
        let config = TlsConfig::builder().build();
        let hs = TlcpClientHandshake::new(config);
        assert_eq!(hs.state(), TlcpClientState::Idle);
    }

    #[test]
    fn test_tlcp_client_server_hello_wrong_state() {
        let config = TlsConfig::builder().build();
        let mut hs = TlcpClientHandshake::new(config);
        // ServerHello from Idle → error
        let sh = crate::handshake::codec::ServerHello {
            random: [0u8; 32],
            legacy_session_id: vec![],
            cipher_suite: CipherSuite::ECDHE_SM4_CBC_SM3,
            extensions: vec![],
        };
        let result = hs.process_server_hello(&[2, 0, 0, 4, 0, 0, 0, 0], &sh);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("unexpected ServerHello"), "{msg}");
    }

    #[test]
    fn test_tlcp_client_certificate_wrong_state() {
        let config = TlsConfig::builder().build();
        let mut hs = TlcpClientHandshake::new(config);
        let cert_msg = crate::handshake::codec_tlcp::TlcpCertificateMessage {
            sign_chain: vec![],
            enc_cert: vec![],
        };
        // Certificate from Idle → error
        let result = hs.process_certificate(&[11, 0, 0, 4, 0, 0, 0, 0], &cert_msg);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("unexpected Certificate"), "{msg}");
    }

    #[test]
    fn test_tlcp_client_ske_wrong_state() {
        let config = TlsConfig::builder().build();
        let mut hs = TlcpClientHandshake::new(config);
        // SKE from Idle → error
        let result = hs.process_server_key_exchange(&[12, 0, 0, 4], &[0, 0, 0, 0]);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("unexpected ServerKeyExchange"), "{msg}");
    }

    #[test]
    fn test_tlcp_client_shd_wrong_state() {
        let config = TlsConfig::builder().build();
        let mut hs = TlcpClientHandshake::new(config);
        // SHD from Idle → error
        let result = hs.process_server_hello_done(&[14, 0, 0, 0]);
        assert!(result.is_err());
        let msg = format!("{}", result.err().unwrap());
        assert!(msg.contains("unexpected ServerHelloDone"), "{msg}");
    }

    #[test]
    fn test_tlcp_client_ccs_wrong_state() {
        let config = TlsConfig::builder().build();
        let mut hs = TlcpClientHandshake::new(config);
        // CCS from Idle → error
        let result = hs.process_change_cipher_spec();
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("unexpected ChangeCipherSpec"), "{msg}");
    }

    #[test]
    fn test_tlcp_client_finished_wrong_state() {
        let config = TlsConfig::builder().build();
        let mut hs = TlcpClientHandshake::new(config);
        // Finished from Idle → error
        let result = hs.process_finished(
            &[20, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0u8; 48],
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("unexpected Finished"), "{msg}");
    }

    #[test]
    fn test_tlcp_client_no_tlcp_suites_error() {
        // Config with only TLS 1.3 suite → no TLCP suites → error on build_client_hello
        let config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_AES_128_GCM_SHA256])
            .build();
        let mut hs = TlcpClientHandshake::new(config);
        let result = hs.build_client_hello();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TlsError::NoSharedCipherSuite));
    }
}
