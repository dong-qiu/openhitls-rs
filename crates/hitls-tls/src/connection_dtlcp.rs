//! DTLCP connection types and in-memory handshake driver.
//!
//! DTLCP = DTLS record layer + TLCP handshake (SM2/SM3/SM4).
//! Uses epoch-aware encryption, anti-replay protection, and cookie exchange.

use crate::config::TlsConfig;
use crate::handshake::client_dtlcp::{DtlcpClientHandshake, DtlcpClientState};
use crate::handshake::codec::{decode_server_hello, ServerHello};
use crate::handshake::codec12::encode_change_cipher_spec;
use crate::handshake::codec_dtls::{dtls_to_tls_handshake, parse_dtls_handshake_header};
use crate::handshake::codec_tlcp::decode_tlcp_certificate;
use crate::handshake::server_dtlcp::{DtlcpServerHandshake, DtlcpServerState};
use crate::handshake::HandshakeType;
use crate::record::anti_replay::AntiReplayWindow;
use crate::record::dtls::{parse_dtls_record, serialize_dtls_record, DtlsRecord, EpochState};
use crate::record::encryption_dtlcp::{
    DtlcpDecryptor, DtlcpEncryptor, DtlcpRecordDecryptorCbc, DtlcpRecordDecryptorGcm,
    DtlcpRecordEncryptorCbc, DtlcpRecordEncryptorGcm, DTLCP_VERSION,
};
use crate::record::ContentType;
use crate::{CipherSuite, TlsError, TlsVersion};
use zeroize::Zeroize;

/// Connection state for DTLCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum DtlcpConnectionState {
    Handshaking,
    Connected,
    Closed,
    Error,
}

// ===========================================================================
// DTLCP Client Connection
// ===========================================================================

/// A DTLCP client connection.
pub struct DtlcpClientConnection {
    #[allow(dead_code)]
    config: TlsConfig,
    write_epoch: EpochState,
    #[allow(dead_code)]
    read_epoch: EpochState,
    encryptor: Option<DtlcpEncryptor>,
    decryptor: Option<DtlcpDecryptor>,
    anti_replay: AntiReplayWindow,
    state: DtlcpConnectionState,
    negotiated_suite: Option<CipherSuite>,
}

impl DtlcpClientConnection {
    pub fn new(config: TlsConfig) -> Self {
        Self {
            config,
            write_epoch: EpochState::new(),
            read_epoch: EpochState::new(),
            encryptor: None,
            decryptor: None,
            anti_replay: AntiReplayWindow::new(),
            state: DtlcpConnectionState::Handshaking,
            negotiated_suite: None,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.state == DtlcpConnectionState::Connected
    }

    pub fn version(&self) -> Option<TlsVersion> {
        if self.is_connected() {
            Some(TlsVersion::Dtlcp)
        } else {
            None
        }
    }

    pub fn cipher_suite(&self) -> Option<CipherSuite> {
        self.negotiated_suite
    }

    /// Seal an application data datagram for sending.
    pub fn seal_app_data(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        if !self.is_connected() {
            return Err(TlsError::RecordError("not connected".into()));
        }
        let enc = self
            .encryptor
            .as_mut()
            .ok_or_else(|| TlsError::RecordError("no encryptor".into()))?;
        let seq = self.write_epoch.next_write_seq()?;
        let record = enc.encrypt_record(
            ContentType::ApplicationData,
            plaintext,
            self.write_epoch.epoch,
            seq,
        )?;
        Ok(serialize_dtls_record(&record))
    }

    /// Open a received application data datagram.
    pub fn open_app_data(&mut self, datagram: &[u8]) -> Result<Vec<u8>, TlsError> {
        if !self.is_connected() {
            return Err(TlsError::RecordError("not connected".into()));
        }
        let (record, _) = parse_dtls_record(datagram)?;

        // Anti-replay check
        if !self.anti_replay.check(record.sequence_number) {
            return Err(TlsError::RecordError("replayed record".into()));
        }

        let dec = self
            .decryptor
            .as_mut()
            .ok_or_else(|| TlsError::RecordError("no decryptor".into()))?;
        let plaintext = dec.decrypt_record(&record)?;
        self.anti_replay.accept(record.sequence_number);
        Ok(plaintext)
    }
}

/// A DTLCP server connection.
pub struct DtlcpServerConnection {
    #[allow(dead_code)]
    config: TlsConfig,
    write_epoch: EpochState,
    #[allow(dead_code)]
    read_epoch: EpochState,
    encryptor: Option<DtlcpEncryptor>,
    decryptor: Option<DtlcpDecryptor>,
    anti_replay: AntiReplayWindow,
    state: DtlcpConnectionState,
    negotiated_suite: Option<CipherSuite>,
    #[allow(dead_code)]
    enable_cookie: bool,
}

impl DtlcpServerConnection {
    pub fn new(config: TlsConfig, enable_cookie: bool) -> Self {
        Self {
            config,
            write_epoch: EpochState::new(),
            read_epoch: EpochState::new(),
            encryptor: None,
            decryptor: None,
            anti_replay: AntiReplayWindow::new(),
            state: DtlcpConnectionState::Handshaking,
            negotiated_suite: None,
            enable_cookie,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.state == DtlcpConnectionState::Connected
    }

    pub fn version(&self) -> Option<TlsVersion> {
        if self.is_connected() {
            Some(TlsVersion::Dtlcp)
        } else {
            None
        }
    }

    pub fn cipher_suite(&self) -> Option<CipherSuite> {
        self.negotiated_suite
    }

    /// Seal an application data datagram for sending.
    pub fn seal_app_data(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        if !self.is_connected() {
            return Err(TlsError::RecordError("not connected".into()));
        }
        let enc = self
            .encryptor
            .as_mut()
            .ok_or_else(|| TlsError::RecordError("no encryptor".into()))?;
        let seq = self.write_epoch.next_write_seq()?;
        let record = enc.encrypt_record(
            ContentType::ApplicationData,
            plaintext,
            self.write_epoch.epoch,
            seq,
        )?;
        Ok(serialize_dtls_record(&record))
    }

    /// Open a received application data datagram.
    pub fn open_app_data(&mut self, datagram: &[u8]) -> Result<Vec<u8>, TlsError> {
        if !self.is_connected() {
            return Err(TlsError::RecordError("not connected".into()));
        }
        let (record, _) = parse_dtls_record(datagram)?;

        if !self.anti_replay.check(record.sequence_number) {
            return Err(TlsError::RecordError("replayed record".into()));
        }

        let dec = self
            .decryptor
            .as_mut()
            .ok_or_else(|| TlsError::RecordError("no decryptor".into()))?;
        let plaintext = dec.decrypt_record(&record)?;
        self.anti_replay.accept(record.sequence_number);
        Ok(plaintext)
    }
}

// ===========================================================================
// Helper: wrap a handshake message in a DTLCP record
// ===========================================================================

fn wrap_handshake_record(epoch: &mut EpochState, hs_msg: &[u8]) -> Result<Vec<u8>, TlsError> {
    let seq = epoch.next_write_seq()?;
    let record = DtlsRecord {
        content_type: ContentType::Handshake,
        version: DTLCP_VERSION,
        epoch: epoch.epoch,
        sequence_number: seq,
        fragment: hs_msg.to_vec(),
    };
    Ok(serialize_dtls_record(&record))
}

fn wrap_ccs_record(epoch: &mut EpochState) -> Result<Vec<u8>, TlsError> {
    let seq = epoch.next_write_seq()?;
    let record = DtlsRecord {
        content_type: ContentType::ChangeCipherSpec,
        version: DTLCP_VERSION,
        epoch: epoch.epoch,
        sequence_number: seq,
        fragment: encode_change_cipher_spec(),
    };
    Ok(serialize_dtls_record(&record))
}

fn wrap_encrypted_handshake_record(
    epoch: &mut EpochState,
    enc: &mut DtlcpEncryptor,
    hs_msg: &[u8],
) -> Result<Vec<u8>, TlsError> {
    let seq = epoch.next_write_seq()?;
    let record = enc.encrypt_record(ContentType::Handshake, hs_msg, epoch.epoch, seq)?;
    Ok(serialize_dtls_record(&record))
}

// ===========================================================================
// Create DTLCP encryptor/decryptor based on CBC vs GCM
// ===========================================================================

fn create_dtlcp_encryptor(
    suite: CipherSuite,
    enc_key: &[u8],
    mac_key: &[u8],
    iv: &[u8],
) -> Result<DtlcpEncryptor, TlsError> {
    let is_cbc = matches!(
        suite,
        CipherSuite::ECDHE_SM4_CBC_SM3 | CipherSuite::ECC_SM4_CBC_SM3
    );
    if is_cbc {
        Ok(DtlcpEncryptor::Cbc(DtlcpRecordEncryptorCbc::new(
            enc_key.to_vec(),
            mac_key.to_vec(),
        )))
    } else {
        Ok(DtlcpEncryptor::Gcm(DtlcpRecordEncryptorGcm::new(
            enc_key,
            iv.to_vec(),
        )?))
    }
}

fn create_dtlcp_decryptor(
    suite: CipherSuite,
    enc_key: &[u8],
    mac_key: &[u8],
    iv: &[u8],
) -> Result<DtlcpDecryptor, TlsError> {
    let is_cbc = matches!(
        suite,
        CipherSuite::ECDHE_SM4_CBC_SM3 | CipherSuite::ECC_SM4_CBC_SM3
    );
    if is_cbc {
        Ok(DtlcpDecryptor::Cbc(DtlcpRecordDecryptorCbc::new(
            enc_key.to_vec(),
            mac_key.to_vec(),
        )))
    } else {
        Ok(DtlcpDecryptor::Gcm(DtlcpRecordDecryptorGcm::new(
            enc_key,
            iv.to_vec(),
        )?))
    }
}

// ===========================================================================
// Full DTLCP handshake driver (for testing)
// ===========================================================================

/// Perform a full DTLCP handshake between client and server using byte buffers.
///
/// Returns `(client, server)` both in Connected state.
#[allow(clippy::type_complexity)]
pub fn dtlcp_handshake_in_memory(
    client_config: TlsConfig,
    server_config: TlsConfig,
    enable_cookie: bool,
) -> Result<(DtlcpClientConnection, DtlcpServerConnection), TlsError> {
    let mut client_conn = DtlcpClientConnection::new(client_config.clone());
    let mut server_conn = DtlcpServerConnection::new(server_config.clone(), enable_cookie);

    let mut client_hs = DtlcpClientHandshake::new(client_config);
    let mut server_hs = DtlcpServerHandshake::new(server_config, enable_cookie);

    // Buffers for datagrams
    let mut client_to_server: Vec<Vec<u8>> = Vec::new();
    let mut server_to_client: Vec<Vec<u8>> = Vec::new();

    // === Flight 1: Client -> ClientHello ===
    let ch_msg = client_hs.build_client_hello()?;
    let ch_datagram = wrap_handshake_record(&mut client_conn.write_epoch, &ch_msg)?;
    client_to_server.push(ch_datagram);

    // === Server receives ClientHello ===
    let ch_datagram = client_to_server.remove(0);
    let (record, _) = parse_dtls_record(&ch_datagram)?;
    let ch_hs_msg = record.fragment;

    let result = server_hs.process_client_hello(&ch_hs_msg)?;

    let flight = match result {
        Ok(flight) => flight,
        Err(hvr_result) => {
            // === Flight 2: Server -> HelloVerifyRequest ===
            let hvr_datagram = wrap_handshake_record(
                &mut server_conn.write_epoch,
                &hvr_result.hello_verify_request,
            )?;
            server_to_client.push(hvr_datagram);

            // === Client receives HVR ===
            let hvr_datagram = server_to_client.remove(0);
            let (record, _) = parse_dtls_record(&hvr_datagram)?;
            let hvr_hs_msg = record.fragment;
            let ch2_msg = client_hs.process_hello_verify_request(&hvr_hs_msg)?;

            // === Flight 3: Client -> ClientHello with cookie ===
            let ch2_datagram = wrap_handshake_record(&mut client_conn.write_epoch, &ch2_msg)?;
            client_to_server.push(ch2_datagram);

            // === Server receives CH2 ===
            let ch2_datagram = client_to_server.remove(0);
            let (record, _) = parse_dtls_record(&ch2_datagram)?;
            let ch2_hs_msg = record.fragment;
            server_hs.process_client_hello_with_cookie(&ch2_hs_msg)?
        }
    };

    let suite = flight.suite;

    // === Flight 4: Server -> SH + Cert + SKE + SHD ===
    for msg in [
        &flight.server_hello,
        &flight.certificate,
        &flight.server_key_exchange,
        &flight.server_hello_done,
    ] {
        let datagram = wrap_handshake_record(&mut server_conn.write_epoch, msg)?;
        server_to_client.push(datagram);
    }

    // === Client processes server flight ===
    // ServerHello
    let sh_datagram = server_to_client.remove(0);
    let (sh_record, _) = parse_dtls_record(&sh_datagram)?;
    let sh_hs_msg = &sh_record.fragment;
    let sh_tls = dtls_to_tls_handshake(sh_hs_msg)?;
    let (_, sh_body, _) = crate::handshake::codec::parse_handshake_header(&sh_tls)?;
    let sh: ServerHello = decode_server_hello(sh_body)?;
    client_hs.process_server_hello(sh_hs_msg, &sh)?;

    // Certificate (double cert)
    let cert_datagram = server_to_client.remove(0);
    let (cert_record, _) = parse_dtls_record(&cert_datagram)?;
    let cert_hs_msg = &cert_record.fragment;
    let cert_tls = dtls_to_tls_handshake(cert_hs_msg)?;
    let (_, cert_body, _) = crate::handshake::codec::parse_handshake_header(&cert_tls)?;
    let cert_msg = decode_tlcp_certificate(cert_body)?;
    client_hs.process_certificate(cert_hs_msg, &cert_msg)?;

    // ServerKeyExchange
    let ske_datagram = server_to_client.remove(0);
    let (ske_record, _) = parse_dtls_record(&ske_datagram)?;
    let ske_hs_msg = &ske_record.fragment;
    let ske_tls = dtls_to_tls_handshake(ske_hs_msg)?;
    let (_, ske_body, _) = crate::handshake::codec::parse_handshake_header(&ske_tls)?;
    client_hs.process_server_key_exchange(ske_hs_msg, ske_body)?;

    // ServerHelloDone
    let shd_datagram = server_to_client.remove(0);
    let (shd_record, _) = parse_dtls_record(&shd_datagram)?;
    let shd_hs_msg = &shd_record.fragment;

    // === Client produces flight: CKE + CCS + Finished ===
    let mut cflight = client_hs.process_server_hello_done(shd_hs_msg)?;

    // Send CKE (plaintext, epoch 0)
    let cke_datagram =
        wrap_handshake_record(&mut client_conn.write_epoch, &cflight.client_key_exchange)?;
    client_to_server.push(cke_datagram);

    // Send CCS (epoch 0)
    let ccs_datagram = wrap_ccs_record(&mut client_conn.write_epoch)?;
    client_to_server.push(ccs_datagram);

    // Bump client write epoch (0 -> 1)
    client_conn.write_epoch.next_epoch();
    let mut client_enc = create_dtlcp_encryptor(
        suite,
        &cflight.client_write_key,
        &cflight.client_write_mac_key,
        &cflight.client_write_iv,
    )?;

    // Send Finished (encrypted, epoch 1)
    let fin_datagram = wrap_encrypted_handshake_record(
        &mut client_conn.write_epoch,
        &mut client_enc,
        &cflight.finished,
    )?;
    client_to_server.push(fin_datagram);

    // === Server processes client flight ===
    // CKE
    let cke_datagram = client_to_server.remove(0);
    let (cke_record, _) = parse_dtls_record(&cke_datagram)?;
    let mut keys = server_hs.process_client_key_exchange(&cke_record.fragment)?;

    // CCS
    let ccs_datagram = client_to_server.remove(0);
    let (ccs_record, _) = parse_dtls_record(&ccs_datagram)?;
    assert_eq!(ccs_record.content_type, ContentType::ChangeCipherSpec);
    server_hs.process_change_cipher_spec()?;

    // Bump server read epoch (0 -> 1)
    server_conn.read_epoch.next_epoch();
    let mut server_dec = create_dtlcp_decryptor(
        suite,
        &keys.client_write_key,
        &keys.client_write_mac_key,
        &keys.client_write_iv,
    )?;

    // Client Finished (encrypted)
    let fin_datagram = client_to_server.remove(0);
    let (fin_record, _) = parse_dtls_record(&fin_datagram)?;
    let fin_plain = server_dec.decrypt_record(&fin_record)?;

    // Convert decrypted DTLS HS to proper format for process_finished
    let (fin_header, _, _) = parse_dtls_handshake_header(&fin_plain)?;
    assert_eq!(fin_header.msg_type, HandshakeType::Finished);
    let server_fin_result = server_hs.process_finished(&fin_plain)?;

    // === Server sends CCS + Finished ===
    let ccs_datagram = wrap_ccs_record(&mut server_conn.write_epoch)?;
    server_to_client.push(ccs_datagram);

    // Bump server write epoch (0 -> 1)
    server_conn.write_epoch.next_epoch();
    let mut server_enc = create_dtlcp_encryptor(
        suite,
        &keys.server_write_key,
        &keys.server_write_mac_key,
        &keys.server_write_iv,
    )?;

    let sfin_datagram = wrap_encrypted_handshake_record(
        &mut server_conn.write_epoch,
        &mut server_enc,
        &server_fin_result.finished,
    )?;
    server_to_client.push(sfin_datagram);

    // === Client processes server CCS + Finished ===
    let ccs_datagram = server_to_client.remove(0);
    let (ccs_record, _) = parse_dtls_record(&ccs_datagram)?;
    assert_eq!(ccs_record.content_type, ContentType::ChangeCipherSpec);
    client_hs.process_change_cipher_spec()?;

    // Bump client read epoch (0 -> 1)
    client_conn.read_epoch.next_epoch();
    let mut client_dec = create_dtlcp_decryptor(
        suite,
        &cflight.server_write_key,
        &cflight.server_write_mac_key,
        &cflight.server_write_iv,
    )?;

    // Server Finished (encrypted)
    let sfin_datagram = server_to_client.remove(0);
    let (sfin_record, _) = parse_dtls_record(&sfin_datagram)?;
    let sfin_plain = client_dec.decrypt_record(&sfin_record)?;

    let (sfin_header, _, _) = parse_dtls_handshake_header(&sfin_plain)?;
    assert_eq!(sfin_header.msg_type, HandshakeType::Finished);
    client_hs.process_finished(&sfin_plain, &cflight.master_secret)?;

    // === Handshake complete ===
    assert_eq!(client_hs.state(), DtlcpClientState::Connected);
    assert_eq!(server_hs.state(), DtlcpServerState::Connected);

    // Install application data keys
    client_conn.encryptor = Some(client_enc);
    client_conn.decryptor = Some(client_dec);
    client_conn.state = DtlcpConnectionState::Connected;
    client_conn.negotiated_suite = Some(suite);

    server_conn.encryptor = Some(server_enc);
    server_conn.decryptor = Some(server_dec);
    server_conn.state = DtlcpConnectionState::Connected;
    server_conn.negotiated_suite = Some(suite);

    // Zeroize key material
    cflight.master_secret.zeroize();
    cflight.client_write_key.zeroize();
    cflight.server_write_key.zeroize();
    cflight.client_write_mac_key.zeroize();
    cflight.server_write_mac_key.zeroize();
    keys.master_secret.zeroize();
    keys.client_write_key.zeroize();
    keys.server_write_key.zeroize();
    keys.client_write_mac_key.zeroize();
    keys.server_write_mac_key.zeroize();

    Ok((client_conn, server_conn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerPrivateKey;
    use crate::crypt::SignatureScheme;

    /// Create SM2 key pairs and self-signed certificates for testing.
    fn create_test_sm2_certs() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        use hitls_crypto::sm2::Sm2KeyPair;
        use hitls_pki::x509::{
            CertificateBuilder, DistinguishedName, SigningKey, SubjectPublicKeyInfo,
        };
        use hitls_utils::oid::known;

        // Generate sign key pair
        let sign_kp = Sm2KeyPair::generate().unwrap();
        let sign_pubkey = sign_kp.public_key_bytes().unwrap();
        let sign_privkey = sign_kp.private_key_bytes().unwrap();

        // Generate enc key pair
        let enc_kp = Sm2KeyPair::generate().unwrap();
        let enc_pubkey = enc_kp.public_key_bytes().unwrap();
        let enc_privkey = enc_kp.private_key_bytes().unwrap();

        // Build SM2 SPKI for sign cert
        let sign_spki = SubjectPublicKeyInfo {
            algorithm_oid: known::ec_public_key().to_der_value(),
            algorithm_params: Some(known::sm2_curve().to_der_value()),
            public_key: sign_pubkey,
        };

        let sign_sk = SigningKey::Sm2(sign_kp);
        let sign_dn = DistinguishedName {
            entries: vec![("CN".to_string(), "DTLCP Sign Test".to_string())],
        };
        let sign_cert = CertificateBuilder::new()
            .serial_number(&[0x01])
            .issuer(sign_dn.clone())
            .subject(sign_dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(sign_spki)
            .build(&sign_sk)
            .unwrap();

        // Build SM2 SPKI for enc cert
        let enc_spki = SubjectPublicKeyInfo {
            algorithm_oid: known::ec_public_key().to_der_value(),
            algorithm_params: Some(known::sm2_curve().to_der_value()),
            public_key: enc_pubkey,
        };

        let enc_sk = SigningKey::Sm2(enc_kp);
        let enc_dn = DistinguishedName {
            entries: vec![("CN".to_string(), "DTLCP Enc Test".to_string())],
        };
        let enc_cert = CertificateBuilder::new()
            .serial_number(&[0x02])
            .issuer(enc_dn.clone())
            .subject(enc_dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(enc_spki)
            .build(&enc_sk)
            .unwrap();

        (sign_privkey, sign_cert.raw, enc_privkey, enc_cert.raw)
    }

    /// Build client and server configs for DTLCP testing.
    fn build_dtlcp_configs(suite: CipherSuite) -> (TlsConfig, TlsConfig) {
        let (sign_privkey, sign_cert, enc_privkey, enc_cert) = create_test_sm2_certs();

        let client_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .signature_algorithms(&[SignatureScheme::SM2_SM3])
            .verify_peer(false) // Self-signed, skip chain validation
            .build();

        let server_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .signature_algorithms(&[SignatureScheme::SM2_SM3])
            .certificate_chain(vec![sign_cert])
            .private_key(ServerPrivateKey::Sm2 {
                private_key: sign_privkey,
            })
            .tlcp_enc_certificate_chain(vec![enc_cert])
            .tlcp_enc_private_key(ServerPrivateKey::Sm2 {
                private_key: enc_privkey,
            })
            .verify_peer(false)
            .build();

        (client_config, server_config)
    }

    // --- Connection creation tests ---

    #[test]
    fn test_dtlcp_client_connection_creation() {
        let (client_config, _) = build_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let conn = DtlcpClientConnection::new(client_config);
        assert!(!conn.is_connected());
        assert!(conn.version().is_none());
        assert!(conn.cipher_suite().is_none());
    }

    #[test]
    fn test_dtlcp_server_connection_creation() {
        let (_, server_config) = build_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let conn = DtlcpServerConnection::new(server_config, true);
        assert!(!conn.is_connected());
        assert!(conn.version().is_none());
        assert!(conn.cipher_suite().is_none());
    }

    // --- ECDHE GCM handshake tests ---

    #[test]
    fn test_dtlcp_handshake_ecdhe_gcm_no_cookie() {
        let (client_config, server_config) = build_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let (client, server) =
            dtlcp_handshake_in_memory(client_config, server_config, false).unwrap();

        assert!(client.is_connected());
        assert!(server.is_connected());
        assert_eq!(client.version(), Some(TlsVersion::Dtlcp));
        assert_eq!(server.version(), Some(TlsVersion::Dtlcp));
        assert_eq!(client.cipher_suite(), Some(CipherSuite::ECDHE_SM4_GCM_SM3));
        assert_eq!(client.cipher_suite(), server.cipher_suite());
    }

    #[test]
    fn test_dtlcp_handshake_ecdhe_gcm_with_cookie() {
        let (client_config, server_config) = build_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let (client, server) =
            dtlcp_handshake_in_memory(client_config, server_config, true).unwrap();

        assert!(client.is_connected());
        assert!(server.is_connected());
        assert_eq!(client.version(), Some(TlsVersion::Dtlcp));
    }

    // --- ECC static GCM handshake test ---

    #[test]
    fn test_dtlcp_handshake_ecc_gcm() {
        let (client_config, server_config) = build_dtlcp_configs(CipherSuite::ECC_SM4_GCM_SM3);
        let (client, server) =
            dtlcp_handshake_in_memory(client_config, server_config, false).unwrap();

        assert!(client.is_connected());
        assert!(server.is_connected());
        assert_eq!(client.cipher_suite(), Some(CipherSuite::ECC_SM4_GCM_SM3));
    }

    // --- CBC handshake test ---

    #[test]
    fn test_dtlcp_handshake_ecdhe_cbc() {
        let (client_config, server_config) = build_dtlcp_configs(CipherSuite::ECDHE_SM4_CBC_SM3);
        let (client, server) =
            dtlcp_handshake_in_memory(client_config, server_config, false).unwrap();

        assert!(client.is_connected());
        assert!(server.is_connected());
        assert_eq!(client.cipher_suite(), Some(CipherSuite::ECDHE_SM4_CBC_SM3));
    }

    // --- Application data exchange ---

    #[test]
    fn test_dtlcp_app_data_exchange() {
        let (client_config, server_config) = build_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let (mut client, mut server) =
            dtlcp_handshake_in_memory(client_config, server_config, false).unwrap();

        // Client -> Server
        let msg = b"Hello from DTLCP client!";
        let datagram = client.seal_app_data(msg).unwrap();
        let received = server.open_app_data(&datagram).unwrap();
        assert_eq!(received, msg);

        // Server -> Client
        let reply = b"Hello from DTLCP server!";
        let datagram = server.seal_app_data(reply).unwrap();
        let received = client.open_app_data(&datagram).unwrap();
        assert_eq!(received, reply);
    }

    #[test]
    fn test_dtlcp_app_data_exchange_cbc() {
        let (client_config, server_config) = build_dtlcp_configs(CipherSuite::ECDHE_SM4_CBC_SM3);
        let (mut client, mut server) =
            dtlcp_handshake_in_memory(client_config, server_config, false).unwrap();

        let msg = b"Hello from DTLCP CBC client!";
        let datagram = client.seal_app_data(msg).unwrap();
        let received = server.open_app_data(&datagram).unwrap();
        assert_eq!(received, msg);

        let reply = b"Hello from DTLCP CBC server!";
        let datagram = server.seal_app_data(reply).unwrap();
        let received = client.open_app_data(&datagram).unwrap();
        assert_eq!(received, reply);
    }

    // --- Anti-replay test ---

    #[test]
    fn test_dtlcp_anti_replay_rejection() {
        let (client_config, server_config) = build_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let (mut client, mut server) =
            dtlcp_handshake_in_memory(client_config, server_config, false).unwrap();

        let msg = b"test data";
        let datagram = client.seal_app_data(msg).unwrap();

        // First receive succeeds
        let received = server.open_app_data(&datagram).unwrap();
        assert_eq!(received, msg);

        // Replay should fail
        let result = server.open_app_data(&datagram);
        assert!(result.is_err());
    }

    // --- Multiple messages test ---

    #[test]
    fn test_dtlcp_multiple_messages() {
        let (client_config, server_config) = build_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let (mut client, mut server) =
            dtlcp_handshake_in_memory(client_config, server_config, false).unwrap();

        for i in 0..10 {
            let msg = format!("DTLCP message {i}");
            let datagram = client.seal_app_data(msg.as_bytes()).unwrap();
            let received = server.open_app_data(&datagram).unwrap();
            assert_eq!(received, msg.as_bytes());
        }

        for i in 0..10 {
            let msg = format!("DTLCP reply {i}");
            let datagram = server.seal_app_data(msg.as_bytes()).unwrap();
            let received = client.open_app_data(&datagram).unwrap();
            assert_eq!(received, msg.as_bytes());
        }
    }

    // --- ECC static CBC handshake test ---

    #[test]
    fn test_dtlcp_handshake_ecc_cbc() {
        let (client_config, server_config) = build_dtlcp_configs(CipherSuite::ECC_SM4_CBC_SM3);
        let (client, server) =
            dtlcp_handshake_in_memory(client_config, server_config, false).unwrap();

        assert!(client.is_connected());
        assert!(server.is_connected());
        assert_eq!(client.cipher_suite(), Some(CipherSuite::ECC_SM4_CBC_SM3));
    }
}
