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
    decode_server_hello, encode_client_hello, encode_finished, ClientHello,
};
use super::extensions_codec::{
    build_key_share_ch, build_server_name, build_signature_algorithms, build_supported_groups,
    build_supported_versions_ch, parse_key_share_sh, parse_supported_versions_sh,
};
use super::key_exchange::KeyExchange;
use super::verify::verify_certificate_verify;
use super::HandshakeState;

/// Actions to take after processing ServerHello.
pub struct ServerHelloActions {
    pub server_hs_keys: TrafficKeys,
    pub client_hs_keys: TrafficKeys,
    pub suite: CipherSuite,
}

/// Actions to take after processing server Finished.
pub struct FinishedActions {
    /// Encoded client Finished handshake message (header + body).
    pub client_finished_msg: Vec<u8>,
    pub client_app_keys: TrafficKeys,
    pub server_app_keys: TrafficKeys,
    pub suite: CipherSuite,
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
}

impl Drop for ClientHandshake {
    fn drop(&mut self) {
        self.client_hs_secret.zeroize();
        self.server_hs_secret.zeroize();
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
        }
    }

    /// Current handshake state.
    pub fn state(&self) -> HandshakeState {
        self.state
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

        // Build extensions
        let mut extensions = vec![
            build_supported_versions_ch(),
            build_supported_groups(&self.config.supported_groups),
            build_signature_algorithms(&self.config.signature_algorithms),
            build_key_share_ch(group, kx.public_key_bytes()),
        ];
        if let Some(ref name) = self.config.server_name {
            extensions.push(build_server_name(name));
        }

        let ch = ClientHello {
            random,
            legacy_session_id: vec![],
            cipher_suites: self.config.cipher_suites.clone(),
            extensions,
        };

        let msg = encode_client_hello(&ch);
        self.client_hello_msg = msg.clone();
        self.key_exchange = Some(kx);
        self.state = HandshakeState::WaitServerHello;

        Ok(msg)
    }

    /// Process a ServerHello message.
    ///
    /// `msg_data` is the full handshake message including the 4-byte header.
    /// Returns actions for the connection to activate handshake encryption.
    pub fn process_server_hello(
        &mut self,
        msg_data: &[u8],
    ) -> Result<ServerHelloActions, TlsError> {
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

        let params = CipherSuiteParams::from_suite(suite)?;

        // If the cipher suite uses SHA-384, re-initialize the transcript
        if params.hash_len == 48 {
            self.transcript = TranscriptHash::new(|| Box::new(hitls_crypto::sha2::Sha384::new()));
        }

        // Feed ClientHello + ServerHello to transcript
        self.transcript.update(&self.client_hello_msg)?;
        self.transcript.update(msg_data)?;

        // Extract key_share from ServerHello
        let ks_ext = sh
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::KEY_SHARE)
            .ok_or_else(|| TlsError::HandshakeFailed("missing key_share in ServerHello".into()))?;
        let (server_group, server_pub_key) = parse_key_share_sh(&ks_ext.data)?;

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

        // Key schedule: Early Secret → Handshake Secret
        let mut ks = KeySchedule::new(params.clone());
        ks.derive_early_secret(None)?;
        ks.derive_handshake_secret(&shared_secret)?;

        // Derive handshake traffic secrets
        let transcript_hash = self.transcript.current_hash()?;
        let (client_hs_secret, server_hs_secret) =
            ks.derive_handshake_traffic_secrets(&transcript_hash)?;

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

        Ok(ServerHelloActions {
            server_hs_keys,
            client_hs_keys,
            suite,
        })
    }

    /// Process an EncryptedExtensions message.
    pub fn process_encrypted_extensions(&mut self, msg_data: &[u8]) -> Result<(), TlsError> {
        if self.state != HandshakeState::WaitEncryptedExtensions {
            return Err(TlsError::HandshakeFailed(
                "process_encrypted_extensions: wrong state".into(),
            ));
        }

        let body = get_body(msg_data)?;
        let _ee = decode_encrypted_extensions(body)?;

        self.transcript.update(msg_data)?;
        self.state = HandshakeState::WaitCertCertReq;
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

            verify_certificate_verify(&cert, cv.algorithm, &cv.signature, &transcript_hash)?;
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

        // Derive application traffic secrets (transcript = CH..server Finished)
        let transcript_hash_sf = self.transcript.current_hash()?;
        let (client_app_secret, server_app_secret) =
            ks.derive_app_traffic_secrets(&transcript_hash_sf)?;

        let suite = self
            .negotiated_suite
            .ok_or_else(|| TlsError::HandshakeFailed("no negotiated suite".into()))?;
        let client_app_keys = TrafficKeys::derive(&params, &client_app_secret)?;
        let server_app_keys = TrafficKeys::derive(&params, &server_app_secret)?;

        // Build client Finished
        let client_finished_key = ks.derive_finished_key(&self.client_hs_secret)?;
        let client_verify_data =
            ks.compute_finished_verify_data(&client_finished_key, &transcript_hash_sf)?;
        let client_finished_msg = encode_finished(&client_verify_data);

        // Feed client Finished to transcript (for resumption master secret if needed)
        self.transcript.update(&client_finished_msg)?;

        self.state = HandshakeState::Connected;

        Ok(FinishedActions {
            client_finished_msg,
            client_app_keys,
            server_app_keys,
            suite,
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
}
