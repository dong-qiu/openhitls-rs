//! TLCP (GM/T 0024) server handshake state machine.
//!
//! Supports both ECDHE (forward secrecy) and ECC (static) key exchange modes
//! with SM2/SM3/SM4 cipher suites.

use crate::config::{ServerPrivateKey, TlsConfig};
use crate::crypt::key_schedule12::{
    compute_verify_data, derive_master_secret, derive_tlcp_key_block,
};
use crate::crypt::transcript::TranscriptHash;
use crate::crypt::{KeyExchangeAlg, NamedGroup, SignatureScheme, TlcpCipherSuiteParams};
use crate::handshake::codec::{decode_client_hello, encode_server_hello, ClientHello, ServerHello};
use crate::handshake::codec12::{
    build_ske_params, build_ske_signed_data, decode_client_key_exchange, encode_finished12,
    encode_server_hello_done, encode_server_key_exchange, ServerKeyExchange,
};
use crate::handshake::codec_tlcp::{
    build_ecc_ske_signed_data, decode_ecc_client_key_exchange, encode_ecc_server_key_exchange,
    encode_tlcp_certificate, EccServerKeyExchange, TlcpCertificateMessage,
};
use crate::handshake::key_exchange::KeyExchange;
use crate::CipherSuite;
use hitls_crypto::sm3::Sm3;
use hitls_types::TlsError;
use std::mem;
use zeroize::Zeroize;

/// TLCP server handshake states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlcpServerState {
    Idle,
    WaitClientKeyExchange,
    WaitChangeCipherSpec,
    WaitFinished,
    Connected,
}

/// Result of building the server flight.
pub struct TlcpServerFlightResult {
    pub server_hello: Vec<u8>,
    pub certificate: Vec<u8>,
    pub server_key_exchange: Vec<u8>,
    pub server_hello_done: Vec<u8>,
}

/// Result of processing ClientKeyExchange — contains derived keys and Finished.
pub struct TlcpServerKeysResult {
    pub master_secret: Vec<u8>,
    pub client_write_mac_key: Vec<u8>,
    pub server_write_mac_key: Vec<u8>,
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
}

impl Drop for TlcpServerKeysResult {
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

/// TLCP server handshake state machine.
pub struct TlcpServerHandshake {
    config: TlsConfig,
    state: TlcpServerState,
    params: Option<TlcpCipherSuiteParams>,
    transcript: TranscriptHash,
    client_random: [u8; 32],
    server_random: [u8; 32],
    is_ecc_static: bool,
    ecdh_keypair: Option<KeyExchange>,
}

impl TlcpServerHandshake {
    pub fn new(config: TlsConfig) -> Self {
        Self {
            config,
            state: TlcpServerState::Idle,
            params: None,
            transcript: TranscriptHash::new(|| Box::new(Sm3::new())),
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            is_ecc_static: false,
            ecdh_keypair: None,
        }
    }

    pub fn state(&self) -> TlcpServerState {
        self.state
    }

    /// Process ClientHello and build the server flight.
    pub fn process_client_hello(
        &mut self,
        raw_msg: &[u8],
    ) -> Result<(TlcpServerFlightResult, CipherSuite), TlsError> {
        if self.state != TlcpServerState::Idle {
            return Err(TlsError::HandshakeFailed("unexpected ClientHello".into()));
        }

        // Parse CH
        let (_, body, _) = crate::handshake::codec::parse_handshake_header(raw_msg)?;
        let ch = decode_client_hello(body)?;

        self.client_random = ch.random;
        self.transcript.update(raw_msg)?;

        // Negotiate cipher suite (prefer server order)
        let suite = self.negotiate_suite(&ch)?;
        let params = TlcpCipherSuiteParams::from_suite(suite)?;
        self.is_ecc_static = params.kx_alg == KeyExchangeAlg::Ecc;
        self.params = Some(params);

        // Generate server_random
        getrandom::getrandom(&mut self.server_random)
            .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;

        // Build ServerHello
        let mut session_id = vec![0u8; 32];
        getrandom::getrandom(&mut session_id)
            .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;

        let sh = ServerHello {
            random: self.server_random,
            legacy_session_id: session_id,
            cipher_suite: suite,
            extensions: Vec::new(),
        };
        let sh_msg = encode_server_hello(&sh);
        self.transcript.update(&sh_msg)?;

        // Build Certificate (double cert)
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
        let cert_data = encode_tlcp_certificate(&cert_msg);
        self.transcript.update(&cert_data)?;

        // Build ServerKeyExchange
        let ske_msg = self.build_server_key_exchange(&cert_msg.enc_cert)?;
        self.transcript.update(&ske_msg)?;

        // Build ServerHelloDone
        let shd_msg = encode_server_hello_done();
        self.transcript.update(&shd_msg)?;

        self.state = TlcpServerState::WaitClientKeyExchange;

        Ok((
            TlcpServerFlightResult {
                server_hello: sh_msg,
                certificate: cert_data,
                server_key_exchange: ske_msg,
                server_hello_done: shd_msg,
            },
            suite,
        ))
    }

    /// Negotiate a TLCP cipher suite.
    fn negotiate_suite(&self, ch: &ClientHello) -> Result<CipherSuite, TlsError> {
        for &server_suite in &self.config.cipher_suites {
            if crate::crypt::is_tlcp_suite(server_suite) && ch.cipher_suites.contains(&server_suite)
            {
                return Ok(server_suite);
            }
        }
        Err(TlsError::NoSharedCipherSuite)
    }

    /// Build the ServerKeyExchange message.
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
        raw_msg: &[u8],
        body: &[u8],
    ) -> Result<TlcpServerKeysResult, TlsError> {
        if self.state != TlcpServerState::WaitClientKeyExchange {
            return Err(TlsError::HandshakeFailed(
                "unexpected ClientKeyExchange".into(),
            ));
        }

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

        self.transcript.update(raw_msg)?;

        // Derive master secret and key block
        let factory = params.hash_factory();
        let master_secret = derive_master_secret(
            &*factory,
            &pre_master_secret,
            &self.client_random,
            &self.server_random,
        )?;

        let mut key_block = derive_tlcp_key_block(
            &*factory,
            &master_secret,
            &self.server_random,
            &self.client_random,
            &params,
        )?;

        self.state = TlcpServerState::WaitChangeCipherSpec;

        Ok(TlcpServerKeysResult {
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
        if self.state != TlcpServerState::WaitChangeCipherSpec {
            return Err(TlsError::HandshakeFailed(
                "unexpected ChangeCipherSpec".into(),
            ));
        }
        self.state = TlcpServerState::WaitFinished;
        Ok(())
    }

    /// Process client Finished and build server Finished.
    pub fn process_finished_and_build(
        &mut self,
        raw_msg: &[u8],
        master_secret: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        if self.state != TlcpServerState::WaitFinished {
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

        // Verify client Finished
        let factory = params.hash_factory();
        let transcript_hash = self.transcript.current_hash()?;
        let expected = compute_verify_data(
            &*factory,
            master_secret,
            "client finished",
            &transcript_hash,
        )?;

        use subtle::ConstantTimeEq;
        if !bool::from(received_verify_data.ct_eq(&expected)) {
            return Err(TlsError::HandshakeFailed(
                "client Finished verify_data mismatch".into(),
            ));
        }

        self.transcript.update(raw_msg)?;

        // Build server Finished
        let transcript_hash = self.transcript.current_hash()?;
        let server_verify_data = compute_verify_data(
            &*factory,
            master_secret,
            "server finished",
            &transcript_hash,
        )?;
        let finished_msg = encode_finished12(&server_verify_data);
        self.transcript.update(&finished_msg)?;

        self.state = TlcpServerState::Connected;

        Ok(finished_msg)
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
            "TLCP signing key must be SM2".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlcp_server_state_transitions() {
        let config = TlsConfig::builder().build();
        let hs = TlcpServerHandshake::new(config);
        assert_eq!(hs.state(), TlcpServerState::Idle);
    }
}
