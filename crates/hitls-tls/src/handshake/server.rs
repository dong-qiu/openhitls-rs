//! TLS 1.3 server handshake state machine.
//!
//! Implements the server side of the 1-RTT handshake:
//! ClientHello → ServerHello + {EE} + {Certificate} + {CertificateVerify} + {Finished}
//! → client {Finished}

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
    decode_client_hello, decode_finished, encode_certificate, encode_certificate_verify,
    encode_encrypted_extensions, encode_finished, encode_server_hello, CertificateEntry,
    CertificateMsg, CertificateVerifyMsg, EncryptedExtensions, ServerHello,
};
use super::extensions_codec::{
    build_key_share_sh, build_supported_versions_sh, parse_key_share_ch,
    parse_signature_algorithms_ch, parse_supported_versions_ch,
};
use super::key_exchange::KeyExchange;
use super::signing::{select_signature_scheme, sign_certificate_verify};
use super::HandshakeState;

/// Result from processing ClientHello.
pub struct ClientHelloActions {
    /// Raw ServerHello handshake message bytes (sent as plaintext record).
    pub server_hello_msg: Vec<u8>,
    /// Raw EncryptedExtensions handshake message bytes.
    pub encrypted_extensions_msg: Vec<u8>,
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
}

/// Result from processing client Finished.
pub struct ClientFinishedActions {
    /// The negotiated cipher suite.
    pub suite: CipherSuite,
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
        let transcript = TranscriptHash::new(|| Box::new(Sha256::new()));
        Self {
            config,
            state: HandshakeState::WaitClientHello,
            key_schedule: None,
            transcript,
            params: None,
            negotiated_suite: None,
            client_hs_secret: Vec::new(),
            server_hs_secret: Vec::new(),
        }
    }

    /// Current handshake state.
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// Process a ClientHello message and produce the entire server flight.
    ///
    /// `msg_data` is the full handshake message including the 4-byte header.
    pub fn process_client_hello(
        &mut self,
        msg_data: &[u8],
    ) -> Result<ClientHelloActions, TlsError> {
        if self.state != HandshakeState::WaitClientHello {
            return Err(TlsError::HandshakeFailed(
                "process_client_hello: wrong state".into(),
            ));
        }

        let body = get_body(msg_data)?;
        let ch = decode_client_hello(body)?;

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

        // signature_algorithms
        let sig_alg_ext = ch
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::SIGNATURE_ALGORITHMS)
            .ok_or_else(|| {
                TlsError::HandshakeFailed("missing signature_algorithms in ClientHello".into())
            })?;
        let client_sig_algs = parse_signature_algorithms_ch(&sig_alg_ext.data)?;

        // key_share
        let ks_ext = ch
            .extensions
            .iter()
            .find(|e| e.extension_type == ExtensionType::KEY_SHARE)
            .ok_or_else(|| TlsError::HandshakeFailed("missing key_share in ClientHello".into()))?;
        let client_key_shares = parse_key_share_ch(&ks_ext.data)?;

        // --- Select cipher suite ---
        let suite = self
            .config
            .cipher_suites
            .iter()
            .find(|s| ch.cipher_suites.contains(s))
            .copied()
            .ok_or(TlsError::NoSharedCipherSuite)?;

        let params = CipherSuiteParams::from_suite(suite)?;

        // If SHA-384, re-init transcript
        if params.hash_len == 48 {
            self.transcript = TranscriptHash::new(|| Box::new(hitls_crypto::sha2::Sha384::new()));
        }

        // --- Find shared key exchange group ---
        // We prefer X25519. Find the client's key share for X25519.
        let (client_group, client_pub_key) = client_key_shares
            .iter()
            .find(|(g, _)| *g == NamedGroup::X25519)
            .ok_or_else(|| {
                TlsError::HandshakeFailed("no X25519 key share in ClientHello".into())
            })?;

        // --- Feed ClientHello to transcript ---
        self.transcript.update(msg_data)?;

        // --- Generate server ephemeral key ---
        let server_kx = KeyExchange::generate(*client_group)?;

        // --- Build ServerHello ---
        let mut random = [0u8; 32];
        getrandom::getrandom(&mut random)
            .map_err(|_| TlsError::HandshakeFailed("random generation failed".into()))?;

        let sh = ServerHello {
            random,
            legacy_session_id: ch.legacy_session_id.clone(),
            cipher_suite: suite,
            extensions: vec![
                build_supported_versions_sh(),
                build_key_share_sh(*client_group, server_kx.public_key_bytes()),
            ],
        };
        let server_hello_msg = encode_server_hello(&sh);

        // Feed ServerHello to transcript
        self.transcript.update(&server_hello_msg)?;

        // --- Compute shared secret ---
        let shared_secret = server_kx.compute_shared_secret(client_pub_key)?;

        // --- Key schedule ---
        let mut ks = KeySchedule::new(params.clone());
        ks.derive_early_secret(None)?;
        ks.derive_handshake_secret(&shared_secret)?;

        let transcript_hash = self.transcript.current_hash()?;
        let (client_hs_secret, server_hs_secret) =
            ks.derive_handshake_traffic_secrets(&transcript_hash)?;

        let server_hs_keys = TrafficKeys::derive(&params, &server_hs_secret)?;
        let client_hs_keys = TrafficKeys::derive(&params, &client_hs_secret)?;

        // --- Build EncryptedExtensions (empty) ---
        let ee = EncryptedExtensions { extensions: vec![] };
        let encrypted_extensions_msg = encode_encrypted_extensions(&ee);
        self.transcript.update(&encrypted_extensions_msg)?;

        // --- Build Certificate ---
        let cert_msg = CertificateMsg {
            certificate_request_context: vec![],
            certificate_list: self
                .config
                .certificate_chain
                .iter()
                .map(|cert_der| CertificateEntry {
                    cert_data: cert_der.clone(),
                    extensions: vec![],
                })
                .collect(),
        };
        let certificate_msg = encode_certificate(&cert_msg);
        self.transcript.update(&certificate_msg)?;

        // --- Build CertificateVerify ---
        let private_key =
            self.config.private_key.as_ref().ok_or_else(|| {
                TlsError::HandshakeFailed("no server private key configured".into())
            })?;
        let sig_scheme = select_signature_scheme(private_key, &client_sig_algs)?;
        let cv_transcript_hash = self.transcript.current_hash()?;
        let signature = sign_certificate_verify(private_key, sig_scheme, &cv_transcript_hash)?;

        let cv = CertificateVerifyMsg {
            algorithm: sig_scheme,
            signature,
        };
        let certificate_verify_msg = encode_certificate_verify(&cv);
        self.transcript.update(&certificate_verify_msg)?;

        // --- Build server Finished ---
        let server_finished_key = ks.derive_finished_key(&server_hs_secret)?;
        let finished_transcript = self.transcript.current_hash()?;
        let server_verify_data =
            ks.compute_finished_verify_data(&server_finished_key, &finished_transcript)?;
        let server_finished_msg = encode_finished(&server_verify_data);
        self.transcript.update(&server_finished_msg)?;

        // --- Derive application keys ---
        ks.derive_master_secret()?;
        let transcript_hash_sf = self.transcript.current_hash()?;
        let (client_app_secret, server_app_secret) =
            ks.derive_app_traffic_secrets(&transcript_hash_sf)?;
        let server_app_keys = TrafficKeys::derive(&params, &server_app_secret)?;
        let client_app_keys = TrafficKeys::derive(&params, &client_app_secret)?;

        // --- Save state ---
        self.client_hs_secret = client_hs_secret;
        self.server_hs_secret = server_hs_secret;
        self.key_schedule = Some(ks);
        self.params = Some(params);
        self.negotiated_suite = Some(suite);
        self.state = HandshakeState::WaitClientFinished;

        Ok(ClientHelloActions {
            server_hello_msg,
            encrypted_extensions_msg,
            certificate_msg,
            certificate_verify_msg,
            server_finished_msg,
            server_hs_keys,
            client_hs_keys,
            server_app_keys,
            client_app_keys,
            suite,
        })
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

        self.state = HandshakeState::Connected;
        Ok(ClientFinishedActions { suite })
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
    use crate::config::ServerPrivateKey;
    use crate::TlsRole;

    fn make_server_config() -> TlsConfig {
        TlsConfig::builder()
            .role(TlsRole::Server)
            .certificate_chain(vec![vec![0x30, 0x82, 0x01, 0x00]]) // fake DER
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
        let config = make_server_config();
        let mut hs = ServerHandshake::new(config);

        // Build a minimal ClientHello without supported_versions
        use crate::handshake::codec::encode_client_hello;
        use crate::handshake::codec::ClientHello;
        use crate::handshake::extensions_codec::{
            build_key_share_ch, build_signature_algorithms, build_supported_groups,
        };

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
}
