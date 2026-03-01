//! Asynchronous TLCP (GM/T 0024) connection wrapping an `AsyncRead + AsyncWrite` transport.
//!
//! Provides `AsyncTlcpClientConnection` and `AsyncTlcpServerConnection` with
//! full TLCP handshake using SM2/SM3/SM4 cipher suites (both ECDHE and ECC static).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::TlsConfig;
use crate::connection_info::ConnectionInfo;
use crate::connection_tlcp::{activate_tlcp_read, activate_tlcp_write};
use crate::handshake::client_tlcp::TlcpClientHandshake;
use crate::handshake::codec::{decode_server_hello, parse_handshake_header};
use crate::handshake::codec_tlcp::decode_tlcp_certificate;
use crate::handshake::server_tlcp::TlcpServerHandshake;
use crate::handshake::HandshakeType;
use crate::record::{ContentType, RecordLayer};
use crate::{AsyncTlsConnection, CipherSuite, TlsError, TlsVersion};
use zeroize::Zeroize;

/// Connection state for async TLCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlcpConnectionState {
    Handshaking,
    Connected,
    Closed,
    Error,
}

// ===========================================================================
// Async TLCP Client Connection
// ===========================================================================

/// An asynchronous TLCP client connection.
pub struct AsyncTlcpClientConnection<S: AsyncRead + AsyncWrite + Unpin> {
    stream: S,
    config: TlsConfig,
    record_layer: RecordLayer,
    state: TlcpConnectionState,
    negotiated_suite: Option<CipherSuite>,
    read_buf: Vec<u8>,
    app_data_buf: Vec<u8>,
    sent_close_notify: bool,
    received_close_notify: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncTlcpClientConnection<S> {
    /// Create a new async TLCP client connection wrapping the given stream.
    pub fn new(stream: S, config: TlsConfig) -> Self {
        Self {
            stream,
            config,
            record_layer: RecordLayer::new(),
            state: TlcpConnectionState::Handshaking,
            negotiated_suite: None,
            read_buf: Vec::with_capacity(16 * 1024),
            app_data_buf: Vec::new(),
            sent_close_notify: false,
            received_close_notify: false,
        }
    }

    /// Get a snapshot of the negotiated connection parameters.
    pub fn connection_info(&self) -> Option<ConnectionInfo> {
        self.negotiated_suite.map(|suite| ConnectionInfo {
            cipher_suite: suite,
            peer_certificates: Vec::new(),
            alpn_protocol: None,
            server_name: None,
            negotiated_group: None,
            session_resumed: false,
            peer_verify_data: Vec::new(),
            local_verify_data: Vec::new(),
        })
    }

    async fn fill_buf(&mut self, min_bytes: usize) -> Result<(), TlsError> {
        fill_buf_body!(is_async, self, min_bytes)
    }

    async fn read_record(&mut self) -> Result<(ContentType, Vec<u8>), TlsError> {
        read_record_body!(is_async, self)
    }

    async fn read_handshake_msg(&mut self) -> Result<(HandshakeType, Vec<u8>), TlsError> {
        let (ct, data) = self.read_record().await?;
        if ct != ContentType::Handshake {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Handshake, got {ct:?}"
            )));
        }
        let (hs_type, _, total) = parse_handshake_header(&data)?;
        Ok((hs_type, data[..total].to_vec()))
    }

    /// Run the TLCP client handshake.
    async fn do_handshake(&mut self) -> Result<(), TlsError> {
        let mut hs = TlcpClientHandshake::new(self.config.clone());

        // 1. Build and send ClientHello
        let ch_msg = hs.build_client_hello()?;
        let ch_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &ch_msg)?;
        self.stream
            .write_all(&ch_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 2. Read ServerHello
        let (hs_type, sh_data) = self.read_handshake_msg().await?;
        if hs_type != HandshakeType::ServerHello {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ServerHello, got {hs_type:?}"
            )));
        }
        let (_, sh_body, _) = parse_handshake_header(&sh_data)?;
        let sh = decode_server_hello(sh_body)?;
        let suite = hs.process_server_hello(&sh_data, &sh)?;

        // 3. Read Certificate (double cert)
        let (hs_type, cert_data) = self.read_handshake_msg().await?;
        if hs_type != HandshakeType::Certificate {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Certificate, got {hs_type:?}"
            )));
        }
        let (_, cert_body, _) = parse_handshake_header(&cert_data)?;
        let cert_msg = decode_tlcp_certificate(cert_body)?;
        hs.process_certificate(&cert_data, &cert_msg)?;

        // 4. Read ServerKeyExchange
        let (hs_type, ske_data) = self.read_handshake_msg().await?;
        if hs_type != HandshakeType::ServerKeyExchange {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ServerKeyExchange, got {hs_type:?}"
            )));
        }
        let (_, ske_body, _) = parse_handshake_header(&ske_data)?;
        hs.process_server_key_exchange(&ske_data, ske_body)?;

        // 5. Read ServerHelloDone
        let (hs_type, shd_data) = self.read_handshake_msg().await?;
        if hs_type != HandshakeType::ServerHelloDone {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ServerHelloDone, got {hs_type:?}"
            )));
        }

        // 6. Process ServerHelloDone → client flight (CKE + CCS + Finished)
        let mut cflight = hs.process_server_hello_done(&shd_data)?;

        // 7. Send ClientKeyExchange (plaintext)
        let cke_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &cflight.client_key_exchange)?;
        self.stream
            .write_all(&cke_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 8. Send ChangeCipherSpec
        let ccs_record = self
            .record_layer
            .seal_record(ContentType::ChangeCipherSpec, &[0x01])?;
        self.stream
            .write_all(&ccs_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 9. Activate write encryption
        activate_tlcp_write(
            &mut self.record_layer,
            suite,
            &cflight.client_write_key,
            &cflight.client_write_mac_key,
            &cflight.client_write_iv,
        )?;

        // 10. Send Finished (encrypted)
        let fin_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &cflight.finished)?;
        self.stream
            .write_all(&fin_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 11. Read server ChangeCipherSpec
        let (ct, _) = self.read_record().await?;
        if ct != ContentType::ChangeCipherSpec {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ChangeCipherSpec, got {ct:?}"
            )));
        }
        hs.process_change_cipher_spec()?;

        // 12. Activate read decryption
        activate_tlcp_read(
            &mut self.record_layer,
            suite,
            &cflight.server_write_key,
            &cflight.server_write_mac_key,
            &cflight.server_write_iv,
        )?;

        // 13. Read server Finished (encrypted)
        let (hs_type, fin_data) = self.read_handshake_msg().await?;
        if hs_type != HandshakeType::Finished {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Finished, got {hs_type:?}"
            )));
        }
        hs.process_finished(&fin_data, &cflight.master_secret)?;

        // Zeroize secrets
        cflight.master_secret.zeroize();
        cflight.client_write_key.zeroize();
        cflight.server_write_key.zeroize();
        cflight.client_write_mac_key.zeroize();
        cflight.server_write_mac_key.zeroize();

        self.negotiated_suite = Some(suite);
        self.state = TlcpConnectionState::Connected;
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncTlsConnection for AsyncTlcpClientConnection<S> {
    async fn handshake(&mut self) -> Result<(), TlsError> {
        if self.state != TlcpConnectionState::Handshaking {
            return Err(TlsError::HandshakeFailed(
                "handshake already completed or failed".into(),
            ));
        }
        match self.do_handshake().await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.state = TlcpConnectionState::Error;
                Err(e)
            }
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if self.state != TlcpConnectionState::Connected {
            return Err(TlsError::RecordError(
                "not connected (handshake not done)".into(),
            ));
        }

        if !self.app_data_buf.is_empty() {
            let n = buf.len().min(self.app_data_buf.len());
            buf[..n].copy_from_slice(&self.app_data_buf[..n]);
            self.app_data_buf.drain(..n);
            return Ok(n);
        }

        loop {
            let (ct, plaintext) = self.read_record().await?;
            match ct {
                ContentType::ApplicationData => {
                    let n = buf.len().min(plaintext.len());
                    buf[..n].copy_from_slice(&plaintext[..n]);
                    if plaintext.len() > n {
                        self.app_data_buf.extend_from_slice(&plaintext[n..]);
                    }
                    return Ok(n);
                }
                ContentType::Alert => {
                    if plaintext.len() >= 2 && plaintext[1] == 0 {
                        self.received_close_notify = true;
                    }
                    self.state = TlcpConnectionState::Closed;
                    return Ok(0);
                }
                _ => {
                    // Ignore unexpected record types (e.g., stale handshake)
                    continue;
                }
            }
        }
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        if self.state != TlcpConnectionState::Connected {
            return Err(TlsError::RecordError(
                "not connected (handshake not done)".into(),
            ));
        }
        if buf.is_empty() {
            return Ok(0);
        }

        let max_frag = self.record_layer.max_fragment_size;
        let mut offset = 0;
        while offset < buf.len() {
            let end = std::cmp::min(offset + max_frag, buf.len());
            let record = self
                .record_layer
                .seal_record(ContentType::ApplicationData, &buf[offset..end])?;
            self.stream
                .write_all(&record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
            offset = end;
        }
        Ok(buf.len())
    }

    async fn shutdown(&mut self) -> Result<(), TlsError> {
        if self.state == TlcpConnectionState::Closed {
            return Ok(());
        }
        if !self.sent_close_notify {
            let alert_data = [1u8, 0u8]; // warning, close_notify
            let record = self
                .record_layer
                .seal_record(ContentType::Alert, &alert_data)?;
            let _ = self.stream.write_all(&record).await;
            self.sent_close_notify = true;
        }
        self.state = TlcpConnectionState::Closed;
        Ok(())
    }

    fn version(&self) -> Option<TlsVersion> {
        if self.state == TlcpConnectionState::Connected || self.state == TlcpConnectionState::Closed
        {
            Some(TlsVersion::Tlcp)
        } else {
            None
        }
    }

    fn cipher_suite(&self) -> Option<CipherSuite> {
        self.negotiated_suite
    }
}

// ===========================================================================
// Async TLCP Server Connection
// ===========================================================================

/// An asynchronous TLCP server connection.
pub struct AsyncTlcpServerConnection<S: AsyncRead + AsyncWrite + Unpin> {
    stream: S,
    config: TlsConfig,
    record_layer: RecordLayer,
    state: TlcpConnectionState,
    negotiated_suite: Option<CipherSuite>,
    read_buf: Vec<u8>,
    app_data_buf: Vec<u8>,
    sent_close_notify: bool,
    received_close_notify: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncTlcpServerConnection<S> {
    /// Create a new async TLCP server connection wrapping the given stream.
    pub fn new(stream: S, config: TlsConfig) -> Self {
        Self {
            stream,
            config,
            record_layer: RecordLayer::new(),
            state: TlcpConnectionState::Handshaking,
            negotiated_suite: None,
            read_buf: Vec::with_capacity(16 * 1024),
            app_data_buf: Vec::new(),
            sent_close_notify: false,
            received_close_notify: false,
        }
    }

    /// Get a snapshot of the negotiated connection parameters.
    pub fn connection_info(&self) -> Option<ConnectionInfo> {
        self.negotiated_suite.map(|suite| ConnectionInfo {
            cipher_suite: suite,
            peer_certificates: Vec::new(),
            alpn_protocol: None,
            server_name: None,
            negotiated_group: None,
            session_resumed: false,
            peer_verify_data: Vec::new(),
            local_verify_data: Vec::new(),
        })
    }

    async fn fill_buf(&mut self, min_bytes: usize) -> Result<(), TlsError> {
        fill_buf_body!(is_async, self, min_bytes)
    }

    async fn read_record(&mut self) -> Result<(ContentType, Vec<u8>), TlsError> {
        read_record_body!(is_async, self)
    }

    async fn read_handshake_msg(&mut self) -> Result<(HandshakeType, Vec<u8>), TlsError> {
        let (ct, data) = self.read_record().await?;
        if ct != ContentType::Handshake {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Handshake, got {ct:?}"
            )));
        }
        let (hs_type, _, total) = parse_handshake_header(&data)?;
        Ok((hs_type, data[..total].to_vec()))
    }

    /// Run the TLCP server handshake.
    async fn do_handshake(&mut self) -> Result<(), TlsError> {
        let mut hs = TlcpServerHandshake::new(self.config.clone());

        // 1. Read ClientHello
        let (hs_type, ch_data) = self.read_handshake_msg().await?;
        if hs_type != HandshakeType::ClientHello {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ClientHello, got {hs_type:?}"
            )));
        }

        // 2. Process ClientHello -> produces SH+Cert+SKE+SHD flight
        let (flight, suite) = hs.process_client_hello(&ch_data)?;

        // 3. Send ServerHello
        let sh_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &flight.server_hello)?;
        self.stream
            .write_all(&sh_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 4. Send Certificate (double cert)
        let cert_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &flight.certificate)?;
        self.stream
            .write_all(&cert_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 5. Send ServerKeyExchange
        let ske_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &flight.server_key_exchange)?;
        self.stream
            .write_all(&ske_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 6. Send ServerHelloDone
        let shd_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &flight.server_hello_done)?;
        self.stream
            .write_all(&shd_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 7. Read ClientKeyExchange
        let (hs_type, cke_data) = self.read_handshake_msg().await?;
        if hs_type != HandshakeType::ClientKeyExchange {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ClientKeyExchange, got {hs_type:?}"
            )));
        }
        let (_, cke_body, _) = parse_handshake_header(&cke_data)?;
        let mut skeys = hs.process_client_key_exchange(&cke_data, cke_body)?;

        // 8. Read ChangeCipherSpec from client
        let (ct, _) = self.read_record().await?;
        if ct != ContentType::ChangeCipherSpec {
            return Err(TlsError::HandshakeFailed(format!(
                "expected ChangeCipherSpec, got {ct:?}"
            )));
        }
        hs.process_change_cipher_spec()?;

        // 9. Activate read decryption (client write key)
        activate_tlcp_read(
            &mut self.record_layer,
            suite,
            &skeys.client_write_key,
            &skeys.client_write_mac_key,
            &skeys.client_write_iv,
        )?;

        // 10. Read client Finished (encrypted)
        let (hs_type, fin_data) = self.read_handshake_msg().await?;
        if hs_type != HandshakeType::Finished {
            return Err(TlsError::HandshakeFailed(format!(
                "expected Finished, got {hs_type:?}"
            )));
        }
        let server_fin = hs.process_finished_and_build(&fin_data, &skeys.master_secret)?;

        // 11. Send ChangeCipherSpec
        let ccs_record = self
            .record_layer
            .seal_record(ContentType::ChangeCipherSpec, &[0x01])?;
        self.stream
            .write_all(&ccs_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // 12. Activate write encryption (server write key)
        activate_tlcp_write(
            &mut self.record_layer,
            suite,
            &skeys.server_write_key,
            &skeys.server_write_mac_key,
            &skeys.server_write_iv,
        )?;

        // 13. Send server Finished (encrypted)
        let sfin_record = self
            .record_layer
            .seal_record(ContentType::Handshake, &server_fin)?;
        self.stream
            .write_all(&sfin_record)
            .await
            .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;

        // Zeroize secrets
        skeys.master_secret.zeroize();
        skeys.client_write_key.zeroize();
        skeys.server_write_key.zeroize();
        skeys.client_write_mac_key.zeroize();
        skeys.server_write_mac_key.zeroize();

        self.negotiated_suite = Some(suite);
        self.state = TlcpConnectionState::Connected;
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncTlsConnection for AsyncTlcpServerConnection<S> {
    async fn handshake(&mut self) -> Result<(), TlsError> {
        if self.state != TlcpConnectionState::Handshaking {
            return Err(TlsError::HandshakeFailed(
                "handshake already completed or failed".into(),
            ));
        }
        match self.do_handshake().await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.state = TlcpConnectionState::Error;
                Err(e)
            }
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if self.state != TlcpConnectionState::Connected {
            return Err(TlsError::RecordError(
                "not connected (handshake not done)".into(),
            ));
        }

        if !self.app_data_buf.is_empty() {
            let n = buf.len().min(self.app_data_buf.len());
            buf[..n].copy_from_slice(&self.app_data_buf[..n]);
            self.app_data_buf.drain(..n);
            return Ok(n);
        }

        loop {
            let (ct, plaintext) = self.read_record().await?;
            match ct {
                ContentType::ApplicationData => {
                    let n = buf.len().min(plaintext.len());
                    buf[..n].copy_from_slice(&plaintext[..n]);
                    if plaintext.len() > n {
                        self.app_data_buf.extend_from_slice(&plaintext[n..]);
                    }
                    return Ok(n);
                }
                ContentType::Alert => {
                    if plaintext.len() >= 2 && plaintext[1] == 0 {
                        self.received_close_notify = true;
                    }
                    self.state = TlcpConnectionState::Closed;
                    return Ok(0);
                }
                _ => {
                    // Ignore unexpected record types (e.g., stale handshake)
                    continue;
                }
            }
        }
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        if self.state != TlcpConnectionState::Connected {
            return Err(TlsError::RecordError(
                "not connected (handshake not done)".into(),
            ));
        }
        if buf.is_empty() {
            return Ok(0);
        }

        let max_frag = self.record_layer.max_fragment_size;
        let mut offset = 0;
        while offset < buf.len() {
            let end = std::cmp::min(offset + max_frag, buf.len());
            let record = self
                .record_layer
                .seal_record(ContentType::ApplicationData, &buf[offset..end])?;
            self.stream
                .write_all(&record)
                .await
                .map_err(|e| TlsError::RecordError(format!("write error: {e}")))?;
            offset = end;
        }
        Ok(buf.len())
    }

    async fn shutdown(&mut self) -> Result<(), TlsError> {
        if self.state == TlcpConnectionState::Closed {
            return Ok(());
        }
        if !self.sent_close_notify {
            let alert_data = [1u8, 0u8]; // warning, close_notify
            let record = self
                .record_layer
                .seal_record(ContentType::Alert, &alert_data)?;
            let _ = self.stream.write_all(&record).await;
            self.sent_close_notify = true;
        }
        self.state = TlcpConnectionState::Closed;
        Ok(())
    }

    fn version(&self) -> Option<TlsVersion> {
        if self.state == TlcpConnectionState::Connected || self.state == TlcpConnectionState::Closed
        {
            Some(TlsVersion::Tlcp)
        } else {
            None
        }
    }

    fn cipher_suite(&self) -> Option<CipherSuite> {
        self.negotiated_suite
    }
}

// ===========================================================================
// Tests
// ===========================================================================

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

        let sign_kp = Sm2KeyPair::generate().unwrap();
        let sign_pubkey = sign_kp.public_key_bytes().unwrap();
        let sign_privkey = sign_kp.private_key_bytes().unwrap();

        let enc_kp = Sm2KeyPair::generate().unwrap();
        let enc_pubkey = enc_kp.public_key_bytes().unwrap();
        let enc_privkey = enc_kp.private_key_bytes().unwrap();

        let sign_spki = SubjectPublicKeyInfo {
            algorithm_oid: known::ec_public_key().to_der_value(),
            algorithm_params: Some(known::sm2_curve().to_der_value()),
            public_key: sign_pubkey,
        };
        let sign_sk = SigningKey::Sm2(sign_kp);
        let sign_dn = DistinguishedName {
            entries: vec![("CN".to_string(), "Async TLCP Sign".to_string())],
        };
        let sign_cert = CertificateBuilder::new()
            .serial_number(&[0x01])
            .issuer(sign_dn.clone())
            .subject(sign_dn)
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(sign_spki)
            .build(&sign_sk)
            .unwrap();

        let enc_spki = SubjectPublicKeyInfo {
            algorithm_oid: known::ec_public_key().to_der_value(),
            algorithm_params: Some(known::sm2_curve().to_der_value()),
            public_key: enc_pubkey,
        };
        let enc_sk = SigningKey::Sm2(enc_kp);
        let enc_dn = DistinguishedName {
            entries: vec![("CN".to_string(), "Async TLCP Enc".to_string())],
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

    fn build_tlcp_configs(suite: CipherSuite) -> (TlsConfig, TlsConfig) {
        let (sign_privkey, sign_cert, enc_privkey, enc_cert) = create_test_sm2_certs();

        let client_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .signature_algorithms(&[SignatureScheme::SM2_SM3])
            .verify_peer(false)
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

    #[tokio::test]
    async fn test_async_tlcp_read_before_handshake() {
        let (client_stream, _server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncTlcpClientConnection::new(
            client_stream,
            build_tlcp_configs(CipherSuite::ECDHE_SM4_CBC_SM3).0,
        );
        let mut buf = [0u8; 16];
        let err = client.read(&mut buf).await.unwrap_err();
        match err {
            TlsError::RecordError(msg) => assert!(msg.contains("not connected")),
            _ => panic!("expected RecordError, got {err:?}"),
        }
    }

    #[tokio::test]
    async fn test_async_tlcp_full_handshake_and_data() {
        let (client_config, server_config) = build_tlcp_configs(CipherSuite::ECDHE_SM4_CBC_SM3);
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncTlcpClientConnection::new(client_stream, client_config);
        let mut server = AsyncTlcpServerConnection::new(server_stream, server_config);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        // Client -> Server
        let msg = b"Hello from async TLCP client!";
        client.write(msg).await.unwrap();
        let mut buf = [0u8; 256];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg);

        // Server -> Client
        let reply = b"Hello from async TLCP server!";
        server.write(reply).await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], reply);
    }

    #[tokio::test]
    async fn test_async_tlcp_gcm_handshake() {
        let (client_config, server_config) = build_tlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncTlcpClientConnection::new(client_stream, client_config);
        let mut server = AsyncTlcpServerConnection::new(server_stream, server_config);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        assert_eq!(client.cipher_suite(), Some(CipherSuite::ECDHE_SM4_GCM_SM3));
        assert_eq!(client.cipher_suite(), server.cipher_suite());

        // Verify data exchange
        let msg = b"GCM mode data";
        client.write(msg).await.unwrap();
        let mut buf = [0u8; 256];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg);
    }

    #[tokio::test]
    async fn test_async_tlcp_ecc_handshake() {
        let (client_config, server_config) = build_tlcp_configs(CipherSuite::ECC_SM4_GCM_SM3);
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncTlcpClientConnection::new(client_stream, client_config);
        let mut server = AsyncTlcpServerConnection::new(server_stream, server_config);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        assert_eq!(client.cipher_suite(), Some(CipherSuite::ECC_SM4_GCM_SM3));

        let msg = b"ECC static key exchange data";
        client.write(msg).await.unwrap();
        let mut buf = [0u8; 256];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg);
    }

    #[tokio::test]
    async fn test_async_tlcp_shutdown() {
        let (client_config, server_config) = build_tlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncTlcpClientConnection::new(client_stream, client_config);
        let mut server = AsyncTlcpServerConnection::new(server_stream, server_config);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        // Shutdown client
        client.shutdown().await.unwrap();
        assert_eq!(client.version(), Some(TlsVersion::Tlcp));

        // Double shutdown is OK
        client.shutdown().await.unwrap();

        // Shutdown server
        server.shutdown().await.unwrap();
        assert_eq!(server.version(), Some(TlsVersion::Tlcp));
    }

    #[tokio::test]
    async fn test_async_tlcp_connection_info() {
        let (client_config, server_config) = build_tlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncTlcpClientConnection::new(client_stream, client_config);
        let mut server = AsyncTlcpServerConnection::new(server_stream, server_config);

        // Before handshake
        assert!(client.connection_info().is_none());
        assert_eq!(client.version(), None);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        // After handshake
        assert_eq!(client.version(), Some(TlsVersion::Tlcp));
        assert_eq!(server.version(), Some(TlsVersion::Tlcp));

        let info = client.connection_info().unwrap();
        assert_eq!(info.cipher_suite, CipherSuite::ECDHE_SM4_GCM_SM3);

        let sinfo = server.connection_info().unwrap();
        assert_eq!(sinfo.cipher_suite, CipherSuite::ECDHE_SM4_GCM_SM3);
    }

    #[tokio::test]
    async fn test_async_tlcp_large_payload() {
        let (client_config, server_config) = build_tlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let (client_stream, server_stream) = tokio::io::duplex(128 * 1024);
        let mut client = AsyncTlcpClientConnection::new(client_stream, client_config);
        let mut server = AsyncTlcpServerConnection::new(server_stream, server_config);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        // Send 32 KB
        let payload = vec![0xAB; 32 * 1024];
        client.write(&payload).await.unwrap();

        let mut received = Vec::new();
        let mut buf = [0u8; 16384];
        while received.len() < payload.len() {
            let n = server.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn test_async_tlcp_multi_message() {
        let (client_config, server_config) = build_tlcp_configs(CipherSuite::ECDHE_SM4_CBC_SM3);
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let mut client = AsyncTlcpClientConnection::new(client_stream, client_config);
        let mut server = AsyncTlcpServerConnection::new(server_stream, server_config);

        let (c_res, s_res) = tokio::join!(client.handshake(), server.handshake());
        c_res.unwrap();
        s_res.unwrap();

        // Send multiple messages
        for i in 0..10 {
            let msg = format!("TLCP async message {i}");
            client.write(msg.as_bytes()).await.unwrap();
            let mut buf = [0u8; 256];
            let n = server.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
        }

        // Send in reverse direction
        for i in 0..10 {
            let msg = format!("TLCP async reply {i}");
            server.write(msg.as_bytes()).await.unwrap();
            let mut buf = [0u8; 256];
            let n = client.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
        }
    }
}
