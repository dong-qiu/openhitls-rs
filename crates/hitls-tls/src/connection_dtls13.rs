//! DTLS 1.3 connection layer (RFC 9147).
//!
//! Provides synchronous datagram-based DTLS 1.3 client and server connections.
//! Reuses TLS 1.3 handshake state machines and key schedule with DTLS record framing.

use crate::config::TlsConfig;
use crate::crypt::traffic_keys::TrafficKeys;
use crate::handshake::client::ClientHandshake;
use crate::handshake::codec::parse_handshake_header;
use crate::handshake::codec_dtls::{dtls_to_tls_handshake, tls_to_dtls_handshake};
use crate::handshake::server::{ClientHelloResult, ServerHandshake};
use crate::record::dtls13::{
    parse_dtls13_record, Dtls13EpochState, EPOCH_APPLICATION, EPOCH_HANDSHAKE, EPOCH_INITIAL,
};
use crate::record::encryption_dtls13::{
    seal_plaintext_dtls13, Dtls13RecordDecryptor, Dtls13RecordEncryptor,
};
use crate::record::ContentType;
use crate::{CipherSuite, TlsError, TlsVersion};
use zeroize::Zeroize;

/// DTLS 1.3 client connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dtls13State {
    Idle,
    Handshaking,
    Connected,
    Closed,
    Error,
}

/// A synchronous DTLS 1.3 client connection.
///
/// Operates on datagrams: call `handshake_write()` to get outgoing datagrams,
/// and `handshake_read()` to process incoming datagrams.
pub struct Dtls13ClientConnection {
    #[allow(dead_code)]
    config: TlsConfig,
    state: Dtls13State,
    hs: ClientHandshake,
    write_epoch: Dtls13EpochState,
    read_epoch: Dtls13EpochState,
    encryptor: Option<Dtls13RecordEncryptor>,
    decryptor: Option<Dtls13RecordDecryptor>,
    negotiated_suite: Option<CipherSuite>,
    /// Application traffic keys for key update.
    client_app_keys: TrafficKeys,
    server_app_keys: TrafficKeys,
    /// Message sequence counter for DTLS handshake fragmentation.
    write_msg_seq: u16,
}

impl Drop for Dtls13ClientConnection {
    fn drop(&mut self) {
        self.client_app_keys.key.zeroize();
        self.client_app_keys.iv.zeroize();
        self.server_app_keys.key.zeroize();
        self.server_app_keys.iv.zeroize();
    }
}

impl Dtls13ClientConnection {
    pub fn new(config: TlsConfig) -> Self {
        Self {
            hs: ClientHandshake::new(config.clone()),
            config,
            state: Dtls13State::Idle,
            write_epoch: Dtls13EpochState::new(EPOCH_INITIAL),
            read_epoch: Dtls13EpochState::new(EPOCH_INITIAL),
            encryptor: None,
            decryptor: None,
            negotiated_suite: None,
            client_app_keys: TrafficKeys {
                key: Vec::new(),
                iv: Vec::new(),
            },
            server_app_keys: TrafficKeys {
                key: Vec::new(),
                iv: Vec::new(),
            },
            write_msg_seq: 0,
        }
    }

    /// Negotiated protocol version (always DTLS 1.3 after handshake).
    pub fn version(&self) -> Option<TlsVersion> {
        if self.state == Dtls13State::Connected || self.state == Dtls13State::Closed {
            Some(TlsVersion::Dtls13)
        } else {
            None
        }
    }

    /// Begin the handshake: returns the ClientHello datagram to send.
    pub fn start_handshake(&mut self) -> Result<Vec<u8>, TlsError> {
        if self.state != Dtls13State::Idle {
            return Err(TlsError::HandshakeFailed(
                "DTLS 1.3: not in idle state".into(),
            ));
        }
        self.state = Dtls13State::Handshaking;

        let ch_msg = self.hs.build_client_hello()?;
        // Wrap in DTLS record (plaintext, epoch 0)
        let dtls_ch = tls_to_dtls_handshake(&ch_msg, self.next_msg_seq())?;
        seal_plaintext_dtls13(ContentType::Handshake, &dtls_ch, &mut self.write_epoch)
    }

    /// Process an incoming datagram during the handshake.
    /// Returns outgoing datagrams to send (may be empty if waiting for more data).
    pub fn process_datagram(&mut self, datagram: &[u8]) -> Result<Vec<Vec<u8>>, TlsError> {
        if self.state == Dtls13State::Error {
            return Err(TlsError::HandshakeFailed("DTLS 1.3: in error state".into()));
        }

        let mut outgoing = Vec::new();
        let mut offset = 0;

        while offset < datagram.len() {
            let remaining = &datagram[offset..];
            let (record, consumed) = match parse_dtls13_record(remaining) {
                Ok(r) => r,
                Err(_) => break,
            };
            offset += consumed;

            match self.state {
                Dtls13State::Handshaking => {
                    let msgs = self.process_handshake_record(&record)?;
                    outgoing.extend(msgs);
                }
                Dtls13State::Connected => {
                    // Application data will be handled by read()
                    break;
                }
                _ => break,
            }
        }

        Ok(outgoing)
    }

    /// Process a single record during the handshake.
    fn process_handshake_record(
        &mut self,
        record: &crate::record::dtls13::Dtls13Record,
    ) -> Result<Vec<Vec<u8>>, TlsError> {
        let mut outgoing = Vec::new();

        // Decrypt if we have a decryptor for this epoch
        let (content_type, fragment) = if record.epoch > 0 {
            if let Some(dec) = &mut self.decryptor {
                dec.decrypt_record(record)?
            } else {
                return Err(TlsError::HandshakeFailed(
                    "DTLS 1.3: no decryptor for encrypted epoch".into(),
                ));
            }
        } else {
            (record.content_type, record.fragment.clone())
        };

        if content_type != ContentType::Handshake {
            return Ok(outgoing);
        }

        // Convert DTLS handshake to TLS format for the TLS 1.3 state machine
        let tls_msg = dtls_to_tls_handshake(&fragment)?;
        let (_, _, total) = parse_handshake_header(&tls_msg)?;
        let msg_data = &tls_msg[..total];

        use crate::handshake::client::ServerHelloResult;
        use crate::handshake::HandshakeState;

        match self.hs.state() {
            HandshakeState::WaitServerHello => {
                match self.hs.process_server_hello(msg_data)? {
                    ServerHelloResult::Actions(actions) => {
                        let suite = actions.suite;
                        self.negotiated_suite = Some(suite);

                        // Activate handshake encryption
                        self.write_epoch.set_epoch(EPOCH_HANDSHAKE);
                        self.read_epoch.set_epoch(EPOCH_HANDSHAKE);

                        self.encryptor =
                            Some(Dtls13RecordEncryptor::new(suite, &actions.client_hs_keys)?);
                        self.decryptor =
                            Some(Dtls13RecordDecryptor::new(suite, &actions.server_hs_keys)?);
                    }
                    ServerHelloResult::RetryNeeded(_retry) => {
                        // Build new ClientHello with the server's selected group
                        let ch2_msg = self.hs.build_client_hello()?;
                        let dtls_ch2 = tls_to_dtls_handshake(&ch2_msg, self.next_msg_seq())?;
                        let record = seal_plaintext_dtls13(
                            ContentType::Handshake,
                            &dtls_ch2,
                            &mut self.write_epoch,
                        )?;
                        outgoing.push(record);
                    }
                }
            }
            HandshakeState::WaitEncryptedExtensions => {
                self.hs.process_encrypted_extensions(msg_data)?;
            }
            HandshakeState::WaitCertCertReq => {
                self.hs.process_certificate(msg_data)?;
            }
            HandshakeState::WaitCertVerify => {
                self.hs.process_certificate_verify(msg_data)?;
            }
            HandshakeState::WaitFinished => {
                let result = self.hs.process_finished(msg_data)?;

                // Send client Finished
                let dtls_fin =
                    tls_to_dtls_handshake(&result.client_finished_msg, self.next_msg_seq())?;
                let fin_record = self.encrypt_handshake(&dtls_fin)?;
                outgoing.push(fin_record);

                // Switch to application traffic keys
                self.write_epoch.set_epoch(EPOCH_APPLICATION);
                self.read_epoch.set_epoch(EPOCH_APPLICATION);

                let suite = self.negotiated_suite.unwrap();
                self.client_app_keys = TrafficKeys {
                    key: result.client_app_keys.key.clone(),
                    iv: result.client_app_keys.iv.clone(),
                };
                self.server_app_keys = TrafficKeys {
                    key: result.server_app_keys.key.clone(),
                    iv: result.server_app_keys.iv.clone(),
                };
                self.encryptor = Some(Dtls13RecordEncryptor::new(suite, &result.client_app_keys)?);
                self.decryptor = Some(Dtls13RecordDecryptor::new(suite, &result.server_app_keys)?);

                self.state = Dtls13State::Connected;
            }
            _ => {}
        }

        Ok(outgoing)
    }

    /// Encrypt a handshake message with the current encryptor.
    fn encrypt_handshake(&mut self, data: &[u8]) -> Result<Vec<u8>, TlsError> {
        if let Some(enc) = &mut self.encryptor {
            enc.encrypt_record(ContentType::Handshake, data, &mut self.write_epoch)
        } else {
            seal_plaintext_dtls13(ContentType::Handshake, data, &mut self.write_epoch)
        }
    }

    /// Encrypt application data and return the datagram to send.
    pub fn write(&mut self, data: &[u8]) -> Result<Vec<u8>, TlsError> {
        if self.state != Dtls13State::Connected {
            return Err(TlsError::HandshakeFailed("DTLS 1.3: not connected".into()));
        }
        let enc = self
            .encryptor
            .as_mut()
            .ok_or_else(|| TlsError::RecordError("DTLS 1.3: no encryptor".into()))?;
        enc.encrypt_record(ContentType::ApplicationData, data, &mut self.write_epoch)
    }

    /// Decrypt an incoming application data datagram.
    pub fn read(&mut self, datagram: &[u8]) -> Result<Vec<u8>, TlsError> {
        if self.state != Dtls13State::Connected {
            return Err(TlsError::HandshakeFailed("DTLS 1.3: not connected".into()));
        }
        let (record, _) = parse_dtls13_record(datagram)?;
        let dec = self
            .decryptor
            .as_mut()
            .ok_or_else(|| TlsError::RecordError("DTLS 1.3: no decryptor".into()))?;
        let (ct, pt) = dec.decrypt_record(&record)?;
        if ct != ContentType::ApplicationData {
            return Err(TlsError::RecordError(
                "DTLS 1.3: expected application data".into(),
            ));
        }
        Ok(pt)
    }

    /// Whether the connection is established.
    pub fn is_connected(&self) -> bool {
        self.state == Dtls13State::Connected
    }

    fn next_msg_seq(&mut self) -> u16 {
        let seq = self.write_msg_seq;
        self.write_msg_seq += 1;
        seq
    }
}

/// A synchronous DTLS 1.3 server connection.
pub struct Dtls13ServerConnection {
    #[allow(dead_code)]
    config: TlsConfig,
    state: Dtls13State,
    hs: ServerHandshake,
    write_epoch: Dtls13EpochState,
    read_epoch: Dtls13EpochState,
    encryptor: Option<Dtls13RecordEncryptor>,
    decryptor: Option<Dtls13RecordDecryptor>,
    negotiated_suite: Option<CipherSuite>,
    client_app_keys: TrafficKeys,
    server_app_keys: TrafficKeys,
    write_msg_seq: u16,
}

impl Drop for Dtls13ServerConnection {
    fn drop(&mut self) {
        self.client_app_keys.key.zeroize();
        self.client_app_keys.iv.zeroize();
        self.server_app_keys.key.zeroize();
        self.server_app_keys.iv.zeroize();
    }
}

impl Dtls13ServerConnection {
    pub fn new(config: TlsConfig) -> Self {
        Self {
            hs: ServerHandshake::new(config.clone()),
            config,
            state: Dtls13State::Idle,
            write_epoch: Dtls13EpochState::new(EPOCH_INITIAL),
            read_epoch: Dtls13EpochState::new(EPOCH_INITIAL),
            encryptor: None,
            decryptor: None,
            negotiated_suite: None,
            client_app_keys: TrafficKeys {
                key: Vec::new(),
                iv: Vec::new(),
            },
            server_app_keys: TrafficKeys {
                key: Vec::new(),
                iv: Vec::new(),
            },
            write_msg_seq: 0,
        }
    }

    /// Negotiated protocol version.
    pub fn version(&self) -> Option<TlsVersion> {
        if self.state == Dtls13State::Connected || self.state == Dtls13State::Closed {
            Some(TlsVersion::Dtls13)
        } else {
            None
        }
    }

    /// Process a ClientHello datagram. Returns outgoing datagrams (ServerHello flight).
    pub fn process_client_hello_datagram(
        &mut self,
        datagram: &[u8],
    ) -> Result<Vec<Vec<u8>>, TlsError> {
        let (record, _) = parse_dtls13_record(datagram)?;
        if record.content_type != ContentType::Handshake {
            return Err(TlsError::HandshakeFailed(
                "DTLS 1.3: expected handshake record".into(),
            ));
        }

        // Convert DTLS handshake to TLS format
        let tls_msg = dtls_to_tls_handshake(&record.fragment)?;
        let (_, _, total) = parse_handshake_header(&tls_msg)?;

        match self.hs.process_client_hello(&tls_msg[..total])? {
            ClientHelloResult::Actions(actions) => {
                let suite = actions.suite;
                self.negotiated_suite = Some(suite);
                self.state = Dtls13State::Handshaking;

                let mut outgoing = Vec::new();

                // ServerHello (plaintext, epoch 0)
                let dtls_sh =
                    tls_to_dtls_handshake(&actions.server_hello_msg, self.next_msg_seq())?;
                outgoing.push(seal_plaintext_dtls13(
                    ContentType::Handshake,
                    &dtls_sh,
                    &mut self.write_epoch,
                )?);

                // Activate handshake encryption
                self.write_epoch.set_epoch(EPOCH_HANDSHAKE);
                self.read_epoch.set_epoch(EPOCH_HANDSHAKE);
                self.encryptor = Some(Dtls13RecordEncryptor::new(suite, &actions.server_hs_keys)?);
                self.decryptor = Some(Dtls13RecordDecryptor::new(suite, &actions.client_hs_keys)?);

                // EncryptedExtensions (encrypted)
                let dtls_ee =
                    tls_to_dtls_handshake(&actions.encrypted_extensions_msg, self.next_msg_seq())?;
                outgoing.push(self.encrypt_handshake(&dtls_ee)?);

                // Certificate (encrypted)
                let dtls_cert =
                    tls_to_dtls_handshake(&actions.certificate_msg, self.next_msg_seq())?;
                outgoing.push(self.encrypt_handshake(&dtls_cert)?);

                // CertificateVerify (encrypted)
                let dtls_cv =
                    tls_to_dtls_handshake(&actions.certificate_verify_msg, self.next_msg_seq())?;
                outgoing.push(self.encrypt_handshake(&dtls_cv)?);

                // Server Finished (encrypted)
                let dtls_fin =
                    tls_to_dtls_handshake(&actions.server_finished_msg, self.next_msg_seq())?;
                outgoing.push(self.encrypt_handshake(&dtls_fin)?);

                // Store application keys for later activation
                self.client_app_keys = actions.client_app_keys;
                self.server_app_keys = actions.server_app_keys;

                Ok(outgoing)
            }
            ClientHelloResult::HelloRetryRequest(actions) => {
                let dtls_hrr = tls_to_dtls_handshake(&actions.hrr_msg, self.next_msg_seq())?;
                let record = seal_plaintext_dtls13(
                    ContentType::Handshake,
                    &dtls_hrr,
                    &mut self.write_epoch,
                )?;
                Ok(vec![record])
            }
        }
    }

    /// Process the client Finished datagram. Completes the handshake.
    pub fn process_client_finished_datagram(&mut self, datagram: &[u8]) -> Result<(), TlsError> {
        let (record, _) = parse_dtls13_record(datagram)?;

        let (_, fragment) = if let Some(dec) = &mut self.decryptor {
            dec.decrypt_record(&record)?
        } else {
            (record.content_type, record.fragment.clone())
        };

        let tls_msg = dtls_to_tls_handshake(&fragment)?;
        let (_, _, total) = parse_handshake_header(&tls_msg)?;
        self.hs.process_client_finished(&tls_msg[..total])?;

        // Switch to application traffic keys
        self.write_epoch.set_epoch(EPOCH_APPLICATION);
        self.read_epoch.set_epoch(EPOCH_APPLICATION);

        let suite = self.negotiated_suite.unwrap();
        self.encryptor = Some(Dtls13RecordEncryptor::new(suite, &self.server_app_keys)?);
        self.decryptor = Some(Dtls13RecordDecryptor::new(suite, &self.client_app_keys)?);

        self.state = Dtls13State::Connected;
        Ok(())
    }

    /// Encrypt application data.
    pub fn write(&mut self, data: &[u8]) -> Result<Vec<u8>, TlsError> {
        if self.state != Dtls13State::Connected {
            return Err(TlsError::HandshakeFailed("DTLS 1.3: not connected".into()));
        }
        let enc = self
            .encryptor
            .as_mut()
            .ok_or_else(|| TlsError::RecordError("DTLS 1.3: no encryptor".into()))?;
        enc.encrypt_record(ContentType::ApplicationData, data, &mut self.write_epoch)
    }

    /// Decrypt incoming application data.
    pub fn read(&mut self, datagram: &[u8]) -> Result<Vec<u8>, TlsError> {
        if self.state != Dtls13State::Connected {
            return Err(TlsError::HandshakeFailed("DTLS 1.3: not connected".into()));
        }
        let (record, _) = parse_dtls13_record(datagram)?;
        let dec = self
            .decryptor
            .as_mut()
            .ok_or_else(|| TlsError::RecordError("DTLS 1.3: no decryptor".into()))?;
        let (ct, pt) = dec.decrypt_record(&record)?;
        if ct != ContentType::ApplicationData {
            return Err(TlsError::RecordError(
                "DTLS 1.3: expected application data".into(),
            ));
        }
        Ok(pt)
    }

    /// Whether the connection is established.
    pub fn is_connected(&self) -> bool {
        self.state == Dtls13State::Connected
    }

    fn encrypt_handshake(&mut self, data: &[u8]) -> Result<Vec<u8>, TlsError> {
        if let Some(enc) = &mut self.encryptor {
            enc.encrypt_record(ContentType::Handshake, data, &mut self.write_epoch)
        } else {
            seal_plaintext_dtls13(ContentType::Handshake, data, &mut self.write_epoch)
        }
    }

    fn next_msg_seq(&mut self) -> u16 {
        let seq = self.write_msg_seq;
        self.write_msg_seq += 1;
        seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerPrivateKey;
    use crate::TlsRole;

    fn make_ed25519_identity() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use hitls_crypto::ed25519::Ed25519KeyPair;
        use hitls_pki::x509::{CertificateBuilder, DistinguishedName, SigningKey};
        let kp = Ed25519KeyPair::generate().unwrap();
        let seed = kp.seed().to_vec();
        let pub_key = kp.public_key().to_vec();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".into(), "dtls13.test".into())],
        };
        let cert = CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_900_000_000).unwrap();
        (seed, pub_key, cert.raw)
    }

    #[test]
    fn test_dtls13_version_before_handshake() {
        let config = TlsConfig::builder().verify_peer(false).build();
        let conn = Dtls13ClientConnection::new(config);
        assert_eq!(conn.version(), None);
        assert!(!conn.is_connected());
    }

    #[test]
    fn test_dtls13_client_server_handshake_and_data() {
        let (seed, _pub_key, cert) = make_ed25519_identity();

        let client_config = TlsConfig::builder().verify_peer(false).build();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .certificate_chain(vec![cert])
            .private_key(ServerPrivateKey::Ed25519(seed))
            .verify_peer(false)
            .build();

        let mut client = Dtls13ClientConnection::new(client_config);
        let mut server = Dtls13ServerConnection::new(server_config);

        // Client → Server: ClientHello
        let ch_datagram = client.start_handshake().unwrap();

        // Server processes ClientHello and returns flight (SH, EE, Cert, CV, Fin)
        let server_flight = server.process_client_hello_datagram(&ch_datagram).unwrap();
        assert!(
            server_flight.len() >= 5,
            "expected at least 5 datagrams in server flight"
        );

        // Client processes each server datagram
        // First datagram is ServerHello (plaintext)
        let client_responses = client.process_datagram(&server_flight[0]).unwrap();
        // After SH, client should have activated handshake keys — no response expected
        assert!(client_responses.is_empty() || client_responses.iter().all(|r| !r.is_empty()));

        // Process remaining encrypted datagrams (EE, Cert, CV, Fin)
        let mut client_fin_datagram = Vec::new();
        for dgram in &server_flight[1..] {
            let responses = client.process_datagram(dgram).unwrap();
            for r in responses {
                if !r.is_empty() {
                    client_fin_datagram = r;
                }
            }
        }

        // Client should now be connected
        assert!(client.is_connected());
        assert_eq!(client.version(), Some(TlsVersion::Dtls13));

        // Server processes client Finished
        server
            .process_client_finished_datagram(&client_fin_datagram)
            .unwrap();
        assert!(server.is_connected());
        assert_eq!(server.version(), Some(TlsVersion::Dtls13));

        // Bidirectional application data exchange
        let msg1 = b"hello from DTLS 1.3 client";
        let encrypted1 = client.write(msg1).unwrap();
        let decrypted1 = server.read(&encrypted1).unwrap();
        assert_eq!(decrypted1, msg1);

        let msg2 = b"hello from DTLS 1.3 server";
        let encrypted2 = server.write(msg2).unwrap();
        let decrypted2 = client.read(&encrypted2).unwrap();
        assert_eq!(decrypted2, msg2);
    }

    #[test]
    fn test_dtls13_write_before_connected_fails() {
        let config = TlsConfig::builder().verify_peer(false).build();
        let mut client = Dtls13ClientConnection::new(config);
        assert!(client.write(b"data").is_err());
    }

    #[test]
    fn test_dtls13_read_before_connected_fails() {
        let config = TlsConfig::builder().verify_peer(false).build();
        let mut client = Dtls13ClientConnection::new(config);
        assert!(client.read(&[]).is_err());
    }

    // ================================================================
    // Phase T87 — DTLS 1.3 deep coverage. Until T87 the file had
    // 4 tests (0.65/100L) covering only happy-path handshake and
    // pre-connection guards. These tests pin error paths, state
    // transitions, and parser robustness contracts that an attacker
    // could exploit without explicit verification.
    // ================================================================

    /// `start_handshake` from any state other than `Idle` must reject —
    /// otherwise a double-call would silently re-init the handshake
    /// state machine and lose the in-flight ClientHello.
    #[test]
    fn test_dtls13_double_start_handshake_rejected() {
        let config = TlsConfig::builder().verify_peer(false).build();
        let mut client = Dtls13ClientConnection::new(config);
        let _first = client.start_handshake().expect("first start succeeds");
        match client.start_handshake() {
            Err(TlsError::HandshakeFailed(msg)) => {
                assert!(
                    msg.contains("not in idle"),
                    "expected idle-state error, got: {msg}"
                );
            }
            other => panic!("expected HandshakeFailed, got {other:?}"),
        }
    }

    /// Server must reject a ClientHello datagram in the wrong state
    /// (e.g. after it already produced a flight). Pins the state guard
    /// against a peer replaying CHs to confuse the server.
    #[test]
    fn test_dtls13_server_double_client_hello_rejected() {
        let (seed, _pub_key, cert) = make_ed25519_identity();
        let client_config = TlsConfig::builder().verify_peer(false).build();
        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .certificate_chain(vec![cert])
            .private_key(ServerPrivateKey::Ed25519(seed))
            .verify_peer(false)
            .build();

        let mut client = Dtls13ClientConnection::new(client_config);
        let mut server = Dtls13ServerConnection::new(server_config);

        let ch = client.start_handshake().unwrap();
        let _ = server.process_client_hello_datagram(&ch).unwrap();

        // Second CH: must reject (server is past the initial state).
        let res = server.process_client_hello_datagram(&ch);
        assert!(
            res.is_err(),
            "second ClientHello must not be silently re-processed"
        );
    }

    /// Empty / sub-header datagrams to `process_datagram` must NOT
    /// panic. Network-level junk and adversarial truncation must be
    /// handled as soft errors / no-ops.
    #[test]
    fn test_dtls13_process_empty_or_truncated_datagram_does_not_panic() {
        let config = TlsConfig::builder().verify_peer(false).build();
        let mut client = Dtls13ClientConnection::new(config);
        // Drive into the Handshaking state (need a handshake started).
        let _ = client.start_handshake().unwrap();

        // Empty datagram: should produce no responses and not panic.
        let empty_result = client.process_datagram(&[]);
        assert!(empty_result.is_ok(), "empty datagram must be a no-op");
        assert!(empty_result.unwrap().is_empty());

        // 1-byte: parser rejects, returns Ok([]) (DTLS records discard
        // un-parseable bytes).
        let one_byte = client.process_datagram(&[0x16]);
        assert!(one_byte.is_ok());

        // 12 bytes (less than minimum DTLS 1.3 record): same.
        let twelve_bytes = client.process_datagram(&[0u8; 12]);
        assert!(twelve_bytes.is_ok());
    }

    /// `is_connected` lifecycle: false at construction, false after
    /// `start_handshake`, true only after the full handshake completes.
    /// Catches a regression where state transitions accidentally set
    /// `Connected` early.
    #[test]
    fn test_dtls13_is_connected_lifecycle() {
        let (seed, _pub_key, cert) = make_ed25519_identity();
        let client_config = TlsConfig::builder().verify_peer(false).build();
        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .certificate_chain(vec![cert])
            .private_key(ServerPrivateKey::Ed25519(seed))
            .verify_peer(false)
            .build();

        let mut client = Dtls13ClientConnection::new(client_config);
        let mut server = Dtls13ServerConnection::new(server_config);
        assert!(!client.is_connected(), "client: false at construction");
        assert!(!server.is_connected(), "server: false at construction");

        let ch = client.start_handshake().unwrap();
        assert!(
            !client.is_connected(),
            "client: false after start_handshake (still Handshaking)"
        );

        let server_flight = server.process_client_hello_datagram(&ch).unwrap();
        assert!(
            !server.is_connected(),
            "server: false after producing flight (waiting on client Finished)"
        );

        let _ = client.process_datagram(&server_flight[0]).unwrap();
        let mut client_fin = Vec::new();
        for d in &server_flight[1..] {
            for r in client.process_datagram(d).unwrap() {
                if !r.is_empty() {
                    client_fin = r;
                }
            }
        }
        assert!(client.is_connected(), "client: true after full handshake");
        assert!(!server.is_connected(), "server: still false until CFin");

        server
            .process_client_finished_datagram(&client_fin)
            .unwrap();
        assert!(server.is_connected(), "server: true after CFin");
    }

    /// Garbage application-data datagram via `read` after handshake
    /// must be a soft error, not a panic. Defends the application
    /// against attacker-injected malformed records on the connected
    /// socket.
    #[test]
    fn test_dtls13_read_garbage_after_connected_is_soft_error() {
        let (seed, _pub_key, cert) = make_ed25519_identity();
        let client_config = TlsConfig::builder().verify_peer(false).build();
        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .certificate_chain(vec![cert])
            .private_key(ServerPrivateKey::Ed25519(seed))
            .verify_peer(false)
            .build();

        let mut client = Dtls13ClientConnection::new(client_config);
        let mut server = Dtls13ServerConnection::new(server_config);
        let ch = client.start_handshake().unwrap();
        let server_flight = server.process_client_hello_datagram(&ch).unwrap();
        let _ = client.process_datagram(&server_flight[0]).unwrap();
        let mut client_fin = Vec::new();
        for d in &server_flight[1..] {
            for r in client.process_datagram(d).unwrap() {
                if !r.is_empty() {
                    client_fin = r;
                }
            }
        }
        server
            .process_client_finished_datagram(&client_fin)
            .unwrap();
        assert!(client.is_connected() && server.is_connected());

        // Now feed garbage to read. Either Err (parse / decrypt failure)
        // or Ok(empty) is acceptable; a panic is not.
        let garbage = vec![0xDEu8; 64];
        if let Ok(v) = client.read(&garbage) {
            assert!(v.is_empty(), "garbage must not surface as fake plaintext");
        }
    }

    /// `version()` returns `Some(Dtls13)` only post-handshake. Pre-
    /// handshake it must be `None` so a caller cannot mistake a
    /// half-open connection for a negotiated session.
    #[test]
    fn test_dtls13_server_version_lifecycle() {
        let (seed, _pub_key, cert) = make_ed25519_identity();
        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .certificate_chain(vec![cert])
            .private_key(ServerPrivateKey::Ed25519(seed))
            .verify_peer(false)
            .build();

        let server = Dtls13ServerConnection::new(server_config);
        assert_eq!(
            server.version(),
            None,
            "server version must be None pre-handshake"
        );
    }

    /// Server-side `process_client_finished_datagram` before any CH
    /// arrived must reject. Pins the state guard so a network attacker
    /// cannot inject a fake "Finished" datagram against a fresh server.
    #[test]
    fn test_dtls13_server_finished_without_client_hello_rejected() {
        let (seed, _pub_key, cert) = make_ed25519_identity();
        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .certificate_chain(vec![cert])
            .private_key(ServerPrivateKey::Ed25519(seed))
            .verify_peer(false)
            .build();
        let mut server = Dtls13ServerConnection::new(server_config);
        let res = server.process_client_finished_datagram(&[0u8; 32]);
        assert!(res.is_err(), "Finished without prior CH must reject");
    }

    /// Client `write` when not connected must reject — defends against
    /// app-level code accidentally sending plaintext to the network
    /// because it forgot to await the handshake.
    #[test]
    fn test_dtls13_server_write_before_connected_fails() {
        let (seed, _pub_key, cert) = make_ed25519_identity();
        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .certificate_chain(vec![cert])
            .private_key(ServerPrivateKey::Ed25519(seed))
            .verify_peer(false)
            .build();
        let mut server = Dtls13ServerConnection::new(server_config);
        assert!(
            server.write(b"premature").is_err(),
            "server.write before connect must reject"
        );
    }
}
