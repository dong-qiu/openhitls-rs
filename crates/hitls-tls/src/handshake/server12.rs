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
    build_ske_params, build_ske_signed_data, decode_client_key_exchange, encode_certificate12,
    encode_finished12, encode_server_hello_done, encode_server_key_exchange, Certificate12,
    ServerKeyExchange,
};
use crate::handshake::extensions_codec::{
    parse_signature_algorithms_ch, parse_supported_groups_ch,
};
use crate::handshake::key_exchange::KeyExchange;
use crate::CipherSuite;
use hitls_crypto::sha2::Sha256;
use hitls_types::{EccCurveId, TlsError};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// TLS 1.2 server handshake states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls12ServerState {
    Idle,
    WaitClientKeyExchange,
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
    /// ServerHelloDone handshake message.
    pub server_hello_done: Vec<u8>,
    /// Negotiated cipher suite.
    pub suite: CipherSuite,
}

/// Keys derived after client key exchange.
pub struct Tls12DerivedKeys {
    /// Master secret (48 bytes).
    pub master_secret: Vec<u8>,
    /// Client write key.
    pub client_write_key: Vec<u8>,
    /// Server write key.
    pub server_write_key: Vec<u8>,
    /// Client write IV (4 bytes for GCM).
    pub client_write_iv: Vec<u8>,
    /// Server write IV (4 bytes for GCM).
    pub server_write_iv: Vec<u8>,
}

impl Drop for Tls12DerivedKeys {
    fn drop(&mut self) {
        self.master_secret.zeroize();
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
        }
    }

    pub fn state(&self) -> Tls12ServerState {
        self.state
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
        for ext in &ch.extensions {
            match ext.extension_type {
                ExtensionType::SIGNATURE_ALGORITHMS => {
                    self.client_sig_algs = parse_signature_algorithms_ch(&ext.data)?;
                }
                ExtensionType::SUPPORTED_GROUPS => {
                    client_groups = parse_supported_groups_ch(&ext.data)?;
                }
                _ => {} // ignore other extensions
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

        // Negotiate group
        let group = negotiate_group(&client_groups, &self.config.supported_groups)?;

        // Build ServerHello
        let sh = ServerHello {
            random: self.server_random,
            legacy_session_id: ch.legacy_session_id.clone(),
            cipher_suite: suite,
            extensions: Vec::new(), // TLS 1.2 ServerHello: no extensions needed for ECDHE-GCM
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

        // Build ServerHelloDone
        let shd_msg = encode_server_hello_done();
        self.transcript.update(&shd_msg)?;

        self.ephemeral_key = Some(kx);
        self.params = Some(params);
        self.state = Tls12ServerState::WaitClientKeyExchange;

        Ok(ServerFlightResult {
            server_hello: sh_msg,
            certificate: cert_msg,
            server_key_exchange: ske_msg,
            server_hello_done: shd_msg,
            suite,
        })
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
        self.state = Tls12ServerState::WaitChangeCipherSpec;

        Ok(Tls12DerivedKeys {
            master_secret,
            client_write_key: key_block.client_write_key.clone(),
            server_write_key: key_block.server_write_key.clone(),
            client_write_iv: key_block.client_write_iv.clone(),
            server_write_iv: key_block.server_write_iv.clone(),
        })
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
fn negotiate_cipher_suite(ch: &ClientHello, config: &TlsConfig) -> Result<CipherSuite, TlsError> {
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
fn negotiate_group(
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
fn select_signature_scheme_tls12(
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
fn sign_ske_data(
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
    }
}
