//! TLS 1.2 client handshake state machine (ECDHE-GCM).
//!
//! Implements the full TLS 1.2 client handshake for ECDHE key exchange
//! with AES-GCM cipher suites.

use crate::config::TlsConfig;
use crate::crypt::key_schedule12::{compute_verify_data, derive_key_block, derive_master_secret};
use crate::crypt::transcript::TranscriptHash;
use crate::crypt::{NamedGroup, SignatureScheme, Tls12CipherSuiteParams};
use crate::handshake::codec::{encode_client_hello, ClientHello, ServerHello};
use crate::handshake::codec12::{
    build_ske_params, build_ske_signed_data, encode_client_key_exchange, encode_finished12,
    ClientKeyExchange, ServerKeyExchange,
};
use crate::handshake::key_exchange::KeyExchange;
use crate::CipherSuite;
use hitls_crypto::sha2::Sha256;
use hitls_types::TlsError;
use zeroize::Zeroize;

/// TLS 1.2 client handshake states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls12ClientState {
    Idle,
    WaitServerHello,
    WaitCertificate,
    WaitServerKeyExchange,
    WaitServerHelloDone,
    WaitChangeCipherSpec,
    WaitFinished,
    Connected,
}

/// Result of processing ServerHelloDone — contains the client flight to send.
pub struct ClientFlightResult {
    /// ClientKeyExchange message (handshake)
    pub client_key_exchange: Vec<u8>,
    /// Finished message (handshake, to be encrypted)
    pub finished: Vec<u8>,
    /// Master secret for key derivation
    pub master_secret: Vec<u8>,
    /// Client write key
    pub client_write_key: Vec<u8>,
    /// Server write key
    pub server_write_key: Vec<u8>,
    /// Client write IV (4 bytes for GCM)
    pub client_write_iv: Vec<u8>,
    /// Server write IV (4 bytes for GCM)
    pub server_write_iv: Vec<u8>,
}

impl Drop for ClientFlightResult {
    fn drop(&mut self) {
        self.master_secret.zeroize();
        self.client_write_key.zeroize();
        self.server_write_key.zeroize();
        self.client_write_iv.zeroize();
        self.server_write_iv.zeroize();
    }
}

/// TLS 1.2 client handshake state machine.
pub struct Tls12ClientHandshake {
    config: TlsConfig,
    state: Tls12ClientState,
    params: Option<Tls12CipherSuiteParams>,
    transcript: TranscriptHash,
    client_random: [u8; 32],
    server_random: [u8; 32],
    server_certs: Vec<Vec<u8>>,
    server_ecdh_public: Vec<u8>,
    server_named_curve: u16,
    /// Stored ClientHello bytes for transcript replay on hash switch.
    client_hello_bytes: Vec<u8>,
}

impl Tls12ClientHandshake {
    pub fn new(config: TlsConfig) -> Self {
        Self {
            config,
            state: Tls12ClientState::Idle,
            params: None,
            transcript: TranscriptHash::new(|| Box::new(Sha256::new())),
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            server_certs: Vec::new(),
            server_ecdh_public: Vec::new(),
            server_named_curve: 0,
            client_hello_bytes: Vec::new(),
        }
    }

    pub fn state(&self) -> Tls12ClientState {
        self.state
    }

    /// Build the ClientHello message.
    ///
    /// Returns the full handshake message bytes (for sending) and the raw
    /// message bytes (for the transcript hash).
    pub fn build_client_hello(&mut self) -> Result<Vec<u8>, TlsError> {
        // Generate client_random
        getrandom::getrandom(&mut self.client_random)
            .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;

        // Build extensions for TLS 1.2
        let mut extensions = Vec::new();

        // SNI
        if let Some(ref name) = self.config.server_name {
            extensions.push(crate::handshake::extensions_codec::build_server_name(name));
        }

        // Signature algorithms
        extensions.push(
            crate::handshake::extensions_codec::build_signature_algorithms(
                &self.config.signature_algorithms,
            ),
        );

        // Supported groups
        extensions.push(crate::handshake::extensions_codec::build_supported_groups(
            &self.config.supported_groups,
        ));

        // EC point formats (uncompressed only)
        extensions.push(crate::handshake::extensions_codec::build_ec_point_formats());

        // Renegotiation info (empty for initial handshake)
        extensions.push(crate::handshake::extensions_codec::build_renegotiation_info_initial());

        // Filter cipher suites to TLS 1.2 ones only
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

        // Generate a random session ID (32 bytes)
        let mut session_id = vec![0u8; 32];
        getrandom::getrandom(&mut session_id)
            .map_err(|e| TlsError::HandshakeFailed(format!("random gen failed: {e}")))?;

        let ch = ClientHello {
            random: self.client_random,
            legacy_session_id: session_id,
            cipher_suites: tls12_suites,
            extensions,
        };

        let msg = encode_client_hello(&ch);
        self.client_hello_bytes = msg.clone();
        self.transcript.update(&msg)?;
        self.state = Tls12ClientState::WaitServerHello;
        Ok(msg)
    }

    /// Process a ServerHello message.
    pub fn process_server_hello(
        &mut self,
        raw_msg: &[u8],
        sh: &ServerHello,
    ) -> Result<CipherSuite, TlsError> {
        if self.state != Tls12ClientState::WaitServerHello {
            return Err(TlsError::HandshakeFailed("unexpected ServerHello".into()));
        }

        // Check cipher suite is one we offered and is TLS 1.2
        let params = Tls12CipherSuiteParams::from_suite(sh.cipher_suite)?;

        self.server_random = sh.random;

        // Switch transcript hash if the negotiated suite uses SHA-384
        if params.hash_len == 48 {
            self.transcript = TranscriptHash::new(|| Box::new(hitls_crypto::sha2::Sha384::new()));
            // Replay the ClientHello into the new transcript
            self.transcript.update(&self.client_hello_bytes)?;
        }

        self.params = Some(params);
        self.transcript.update(raw_msg)?;
        self.state = Tls12ClientState::WaitCertificate;
        Ok(sh.cipher_suite)
    }

    /// Process a Certificate message (TLS 1.2 format).
    pub fn process_certificate(
        &mut self,
        raw_msg: &[u8],
        cert_list: &[Vec<u8>],
    ) -> Result<(), TlsError> {
        if self.state != Tls12ClientState::WaitCertificate {
            return Err(TlsError::HandshakeFailed("unexpected Certificate".into()));
        }

        if cert_list.is_empty() {
            return Err(TlsError::HandshakeFailed("empty certificate chain".into()));
        }

        self.server_certs = cert_list.to_vec();
        self.transcript.update(raw_msg)?;
        self.state = Tls12ClientState::WaitServerKeyExchange;
        Ok(())
    }

    /// Process a ServerKeyExchange message.
    ///
    /// Verifies the signature over the ECDHE parameters using the server's
    /// certificate public key.
    pub fn process_server_key_exchange(
        &mut self,
        raw_msg: &[u8],
        ske: &ServerKeyExchange,
    ) -> Result<(), TlsError> {
        if self.state != Tls12ClientState::WaitServerKeyExchange {
            return Err(TlsError::HandshakeFailed(
                "unexpected ServerKeyExchange".into(),
            ));
        }

        // Verify the signature
        if self.config.verify_peer {
            let params = build_ske_params(ske.curve_type, ske.named_curve, &ske.public_key);
            let signed_data =
                build_ske_signed_data(&self.client_random, &self.server_random, &params);

            verify_ske_signature(
                &self.server_certs[0],
                ske.signature_algorithm,
                &signed_data,
                &ske.signature,
            )?;
        }

        self.server_ecdh_public = ske.public_key.clone();
        self.server_named_curve = ske.named_curve;
        self.transcript.update(raw_msg)?;
        self.state = Tls12ClientState::WaitServerHelloDone;
        Ok(())
    }

    /// Process a ServerHelloDone message.
    ///
    /// Triggers the client flight: generates ClientKeyExchange, derives keys,
    /// and computes Finished.
    pub fn process_server_hello_done(
        &mut self,
        raw_msg: &[u8],
    ) -> Result<ClientFlightResult, TlsError> {
        if self.state != Tls12ClientState::WaitServerHelloDone {
            return Err(TlsError::HandshakeFailed(
                "unexpected ServerHelloDone".into(),
            ));
        }

        self.transcript.update(raw_msg)?;

        let params = self
            .params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher suite params".into()))?;

        // Generate ephemeral key pair matching server's curve
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

        // Compute ECDH shared secret (pre_master_secret)
        let pre_master_secret = kx.compute_shared_secret(&self.server_ecdh_public)?;

        // Build ClientKeyExchange message
        let cke = ClientKeyExchange {
            public_key: client_public,
        };
        let cke_msg = encode_client_key_exchange(&cke);
        self.transcript.update(&cke_msg)?;

        // Derive master secret
        let factory = params.hash_factory();
        let master_secret = derive_master_secret(
            &*factory,
            &pre_master_secret,
            &self.client_random,
            &self.server_random,
        )?;

        // Derive key block
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
        let finished_msg = encode_finished12(&verify_data);
        // The Finished message itself is added to the transcript for verifying server Finished
        self.transcript.update(&finished_msg)?;

        self.state = Tls12ClientState::WaitChangeCipherSpec;

        Ok(ClientFlightResult {
            client_key_exchange: cke_msg,
            finished: finished_msg,
            master_secret,
            client_write_key: key_block.client_write_key.clone(),
            server_write_key: key_block.server_write_key.clone(),
            client_write_iv: key_block.client_write_iv.clone(),
            server_write_iv: key_block.server_write_iv.clone(),
        })
    }

    /// Process ChangeCipherSpec from server.
    pub fn process_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        if self.state != Tls12ClientState::WaitChangeCipherSpec {
            return Err(TlsError::HandshakeFailed(
                "unexpected ChangeCipherSpec".into(),
            ));
        }
        // CCS is not a handshake message — not added to transcript
        self.state = Tls12ClientState::WaitFinished;
        Ok(())
    }

    /// Process server Finished message.
    pub fn process_finished(
        &mut self,
        raw_msg: &[u8],
        master_secret: &[u8],
    ) -> Result<(), TlsError> {
        if self.state != Tls12ClientState::WaitFinished {
            return Err(TlsError::HandshakeFailed("unexpected Finished".into()));
        }

        let params = self
            .params
            .as_ref()
            .ok_or_else(|| TlsError::HandshakeFailed("no cipher suite params".into()))?;

        // Parse verify_data from raw_msg (skip 4-byte handshake header)
        if raw_msg.len() < 4 + 12 {
            return Err(TlsError::HandshakeFailed(
                "Finished message too short".into(),
            ));
        }
        let received_verify_data = &raw_msg[4..4 + 12];

        // Compute expected verify_data
        let factory = params.hash_factory();
        let transcript_hash = self.transcript.current_hash()?;
        let expected = compute_verify_data(
            &*factory,
            master_secret,
            "server finished",
            &transcript_hash,
        )?;

        // Constant-time comparison
        use subtle::ConstantTimeEq;
        if received_verify_data.ct_eq(&expected).into() {
            self.transcript.update(raw_msg)?;
            self.state = Tls12ClientState::Connected;
            Ok(())
        } else {
            Err(TlsError::HandshakeFailed(
                "server Finished verify_data mismatch".into(),
            ))
        }
    }
}

/// Verify the signature on ServerKeyExchange parameters.
fn verify_ske_signature(
    cert_der: &[u8],
    scheme: SignatureScheme,
    signed_data: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    let cert = hitls_pki::x509::Certificate::from_der(cert_der)
        .map_err(|e| TlsError::HandshakeFailed(format!("cert parse: {e}")))?;
    let spki = &cert.public_key;

    let ok = match scheme {
        SignatureScheme::RSA_PKCS1_SHA256 => {
            let digest = compute_sha256(signed_data)?;
            verify_rsa_pkcs1(spki, &digest, signature)?
        }
        SignatureScheme::RSA_PKCS1_SHA384 => {
            let digest = compute_sha384(signed_data)?;
            verify_rsa_pkcs1(spki, &digest, signature)?
        }
        SignatureScheme::RSA_PSS_RSAE_SHA256 => {
            let digest = compute_sha256(signed_data)?;
            verify_rsa_pss(spki, &digest, signature)?
        }
        SignatureScheme::ECDSA_SECP256R1_SHA256 => {
            let digest = compute_sha256(signed_data)?;
            verify_ecdsa(spki, hitls_types::EccCurveId::NistP256, &digest, signature)?
        }
        SignatureScheme::ECDSA_SECP384R1_SHA384 => {
            let digest = compute_sha384(signed_data)?;
            verify_ecdsa(spki, hitls_types::EccCurveId::NistP384, &digest, signature)?
        }
        _ => {
            return Err(TlsError::HandshakeFailed(format!(
                "unsupported SKE signature scheme: 0x{:04x}",
                scheme.0
            )))
        }
    };

    if ok {
        Ok(())
    } else {
        Err(TlsError::HandshakeFailed(
            "ServerKeyExchange signature verification failed".into(),
        ))
    }
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

fn verify_rsa_pkcs1(
    spki: &hitls_pki::x509::SubjectPublicKeyInfo,
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
        .verify(
            hitls_crypto::rsa::RsaPadding::Pkcs1v15Sign,
            digest,
            signature,
        )
        .map_err(TlsError::CryptoError)
}

fn verify_rsa_pss(
    spki: &hitls_pki::x509::SubjectPublicKeyInfo,
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
        .verify(hitls_crypto::rsa::RsaPadding::Pss, digest, signature)
        .map_err(TlsError::CryptoError)
}

fn verify_ecdsa(
    spki: &hitls_pki::x509::SubjectPublicKeyInfo,
    curve_id: hitls_types::EccCurveId,
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, TlsError> {
    let verifier = hitls_crypto::ecdsa::EcdsaKeyPair::from_public_key(curve_id, &spki.public_key)
        .map_err(TlsError::CryptoError)?;
    verifier
        .verify(digest, signature)
        .map_err(TlsError::CryptoError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_build() {
        let config = TlsConfig::builder()
            .cipher_suites(&[
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_AES_128_GCM_SHA256, // TLS 1.3 suite should be filtered out
            ])
            .supported_groups(&[NamedGroup::SECP256R1])
            .build();

        let mut hs = Tls12ClientHandshake::new(config);
        let ch_msg = hs.build_client_hello().unwrap();

        // Verify it's a valid handshake message
        let (msg_type, body, _) = crate::handshake::codec::parse_handshake_header(&ch_msg).unwrap();
        assert_eq!(msg_type, crate::handshake::HandshakeType::ClientHello);

        // Parse the ClientHello
        let ch = crate::handshake::codec::decode_client_hello(body).unwrap();
        // Should only contain TLS 1.2 suites
        assert_eq!(ch.cipher_suites.len(), 1);
        assert_eq!(
            ch.cipher_suites[0],
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        );

        assert_eq!(hs.state(), Tls12ClientState::WaitServerHello);
    }

    #[test]
    fn test_state_transitions() {
        let hs = Tls12ClientHandshake::new(TlsConfig::builder().build());
        assert_eq!(hs.state(), Tls12ClientState::Idle);
    }
}
