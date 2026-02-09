//! TLCP (GM/T 0024) connection types and in-memory handshake driver.
//!
//! Supports all 4 TLCP cipher suites with both ECDHE and ECC static
//! key exchange modes over SM2/SM3/SM4.

#[cfg(test)]
mod tests {
    use crate::config::{ServerPrivateKey, TlsConfig};
    use crate::crypt::SignatureScheme;
    use crate::handshake::client_tlcp::{TlcpClientHandshake, TlcpClientState};
    use crate::handshake::codec::{decode_server_hello, parse_handshake_header};
    use crate::handshake::codec_tlcp::decode_tlcp_certificate;
    use crate::handshake::server_tlcp::{TlcpServerHandshake, TlcpServerState};
    use crate::record::encryption_tlcp::{
        RecordDecryptorTlcpCbc, RecordDecryptorTlcpGcm, RecordEncryptorTlcpCbc,
        RecordEncryptorTlcpGcm, TlcpDecryptor, TlcpEncryptor,
    };
    use crate::record::{ContentType, RecordLayer};
    use crate::CipherSuite;
    use zeroize::Zeroize;

    /// Create SM2 key pairs and self-signed certificates for testing.
    ///
    /// Returns (sign_private_key_bytes, sign_cert_der, enc_private_key_bytes, enc_cert_der).
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
            entries: vec![("CN".to_string(), "TLCP Sign Test".to_string())],
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
            entries: vec![("CN".to_string(), "TLCP Enc Test".to_string())],
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

    /// Build client and server configs for TLCP testing.
    fn build_tlcp_configs(suite: CipherSuite) -> (TlsConfig, TlsConfig) {
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

    /// Activate TLCP write encryption on a RecordLayer.
    fn activate_tlcp_write(
        rl: &mut RecordLayer,
        suite: CipherSuite,
        enc_key: &[u8],
        mac_key: &[u8],
        iv: &[u8],
    ) {
        let is_cbc = matches!(
            suite,
            CipherSuite::ECDHE_SM4_CBC_SM3 | CipherSuite::ECC_SM4_CBC_SM3
        );
        if is_cbc {
            rl.activate_write_encryption_tlcp(TlcpEncryptor::Cbc(RecordEncryptorTlcpCbc::new(
                enc_key.to_vec(),
                mac_key.to_vec(),
            )));
        } else {
            rl.activate_write_encryption_tlcp(TlcpEncryptor::Gcm(
                RecordEncryptorTlcpGcm::new(enc_key, iv.to_vec()).unwrap(),
            ));
        }
    }

    /// Activate TLCP read decryption on a RecordLayer.
    fn activate_tlcp_read(
        rl: &mut RecordLayer,
        suite: CipherSuite,
        enc_key: &[u8],
        mac_key: &[u8],
        iv: &[u8],
    ) {
        let is_cbc = matches!(
            suite,
            CipherSuite::ECDHE_SM4_CBC_SM3 | CipherSuite::ECC_SM4_CBC_SM3
        );
        if is_cbc {
            rl.activate_read_decryption_tlcp(TlcpDecryptor::Cbc(RecordDecryptorTlcpCbc::new(
                enc_key.to_vec(),
                mac_key.to_vec(),
            )));
        } else {
            rl.activate_read_decryption_tlcp(TlcpDecryptor::Gcm(
                RecordDecryptorTlcpGcm::new(enc_key, iv.to_vec()).unwrap(),
            ));
        }
    }

    /// Run a full TLCP handshake in-memory.
    fn do_tlcp_handshake(
        suite: CipherSuite,
    ) -> (RecordLayer, RecordLayer, TlcpClientState, TlcpServerState) {
        let (client_config, server_config) = build_tlcp_configs(suite);

        let mut client_hs = TlcpClientHandshake::new(client_config);
        let mut server_hs = TlcpServerHandshake::new(server_config);

        let mut client_rl = RecordLayer::new();
        let mut server_rl = RecordLayer::new();

        let mut client_to_server = Vec::new();
        let mut server_to_client = Vec::new();

        // 1. Client → ClientHello
        let ch_msg = client_hs.build_client_hello().unwrap();
        let ch_record = client_rl
            .seal_record(ContentType::Handshake, &ch_msg)
            .unwrap();
        client_to_server.extend_from_slice(&ch_record);

        // 2. Server processes ClientHello
        let (ct, ch_plain, consumed) = server_rl.open_record(&client_to_server).unwrap();
        client_to_server.drain(..consumed);
        assert_eq!(ct, ContentType::Handshake);
        let (_, _, ch_total) = parse_handshake_header(&ch_plain).unwrap();
        let (flight, negotiated_suite) = server_hs
            .process_client_hello(&ch_plain[..ch_total])
            .unwrap();
        assert_eq!(negotiated_suite, suite);

        // 3. Server → ServerHello + Certificate + SKE + SHD
        for msg in [
            &flight.server_hello,
            &flight.certificate,
            &flight.server_key_exchange,
            &flight.server_hello_done,
        ] {
            let rec = server_rl.seal_record(ContentType::Handshake, msg).unwrap();
            server_to_client.extend_from_slice(&rec);
        }

        // 4. Client processes ServerHello
        let (ct, sh_plain, consumed) = client_rl.open_record(&server_to_client).unwrap();
        server_to_client.drain(..consumed);
        assert_eq!(ct, ContentType::Handshake);
        let (_, sh_body, sh_total) = parse_handshake_header(&sh_plain).unwrap();
        let sh = decode_server_hello(sh_body).unwrap();
        client_hs
            .process_server_hello(&sh_plain[..sh_total], &sh)
            .unwrap();

        // 5. Client processes Certificate (double cert)
        let (ct, cert_plain, consumed) = client_rl.open_record(&server_to_client).unwrap();
        server_to_client.drain(..consumed);
        assert_eq!(ct, ContentType::Handshake);
        let (_, cert_body, cert_total) = parse_handshake_header(&cert_plain).unwrap();
        let cert_msg = decode_tlcp_certificate(cert_body).unwrap();
        client_hs
            .process_certificate(&cert_plain[..cert_total], &cert_msg)
            .unwrap();

        // 6. Client processes ServerKeyExchange
        let (ct, ske_plain, consumed) = client_rl.open_record(&server_to_client).unwrap();
        server_to_client.drain(..consumed);
        assert_eq!(ct, ContentType::Handshake);
        let (_, ske_body, ske_total) = parse_handshake_header(&ske_plain).unwrap();
        client_hs
            .process_server_key_exchange(&ske_plain[..ske_total], ske_body)
            .unwrap();

        // 7. Client processes ServerHelloDone
        let (ct, shd_plain, consumed) = client_rl.open_record(&server_to_client).unwrap();
        server_to_client.drain(..consumed);
        assert_eq!(ct, ContentType::Handshake);
        let (_, _, shd_total) = parse_handshake_header(&shd_plain).unwrap();
        let mut cflight = client_hs
            .process_server_hello_done(&shd_plain[..shd_total])
            .unwrap();

        // 8. Client → CKE (plaintext) + CCS + Finished (encrypted)
        let cke_record = client_rl
            .seal_record(ContentType::Handshake, &cflight.client_key_exchange)
            .unwrap();
        client_to_server.extend_from_slice(&cke_record);

        let ccs_record = client_rl
            .seal_record(ContentType::ChangeCipherSpec, &[0x01])
            .unwrap();
        client_to_server.extend_from_slice(&ccs_record);

        // Activate client write encryption
        activate_tlcp_write(
            &mut client_rl,
            suite,
            &cflight.client_write_key,
            &cflight.client_write_mac_key,
            &cflight.client_write_iv,
        );

        let fin_record = client_rl
            .seal_record(ContentType::Handshake, &cflight.finished)
            .unwrap();
        client_to_server.extend_from_slice(&fin_record);

        // 9. Server processes CKE
        let (ct, cke_plain, consumed) = server_rl.open_record(&client_to_server).unwrap();
        client_to_server.drain(..consumed);
        assert_eq!(ct, ContentType::Handshake);
        let (_, cke_body, cke_total) = parse_handshake_header(&cke_plain).unwrap();
        let mut skeys = server_hs
            .process_client_key_exchange(&cke_plain[..cke_total], cke_body)
            .unwrap();

        // 10. Server processes CCS
        let (ct, _, consumed) = server_rl.open_record(&client_to_server).unwrap();
        client_to_server.drain(..consumed);
        assert_eq!(ct, ContentType::ChangeCipherSpec);
        server_hs.process_change_cipher_spec().unwrap();

        // 11. Activate server read decryption (client write key)
        activate_tlcp_read(
            &mut server_rl,
            suite,
            &skeys.client_write_key,
            &skeys.client_write_mac_key,
            &skeys.client_write_iv,
        );

        // 12. Server processes client Finished (encrypted)
        let (ct, fin_plain, consumed) = server_rl.open_record(&client_to_server).unwrap();
        client_to_server.drain(..consumed);
        assert_eq!(ct, ContentType::Handshake);
        let (_, _, fin_total) = parse_handshake_header(&fin_plain).unwrap();
        let server_fin = server_hs
            .process_finished_and_build(&fin_plain[..fin_total], &skeys.master_secret)
            .unwrap();

        // 13. Server → CCS + Finished
        let ccs_record = server_rl
            .seal_record(ContentType::ChangeCipherSpec, &[0x01])
            .unwrap();
        server_to_client.extend_from_slice(&ccs_record);

        // Activate server write encryption
        activate_tlcp_write(
            &mut server_rl,
            suite,
            &skeys.server_write_key,
            &skeys.server_write_mac_key,
            &skeys.server_write_iv,
        );

        let sfin_record = server_rl
            .seal_record(ContentType::Handshake, &server_fin)
            .unwrap();
        server_to_client.extend_from_slice(&sfin_record);

        // 14. Client processes server CCS
        let (ct, _, consumed) = client_rl.open_record(&server_to_client).unwrap();
        server_to_client.drain(..consumed);
        assert_eq!(ct, ContentType::ChangeCipherSpec);
        client_hs.process_change_cipher_spec().unwrap();

        // Activate client read decryption
        activate_tlcp_read(
            &mut client_rl,
            suite,
            &cflight.server_write_key,
            &cflight.server_write_mac_key,
            &cflight.server_write_iv,
        );

        // 15. Client processes server Finished (encrypted)
        let (ct, sfin_plain, consumed) = client_rl.open_record(&server_to_client).unwrap();
        server_to_client.drain(..consumed);
        assert_eq!(ct, ContentType::Handshake);
        let (_, _, sfin_total) = parse_handshake_header(&sfin_plain).unwrap();
        client_hs
            .process_finished(&sfin_plain[..sfin_total], &cflight.master_secret)
            .unwrap();

        // Zeroize
        cflight.master_secret.zeroize();
        skeys.master_secret.zeroize();

        let cs = client_hs.state();
        let ss = server_hs.state();

        (client_rl, server_rl, cs, ss)
    }

    // ─── Full handshake tests ────────────────────────────────

    #[test]
    fn test_tlcp_ecdhe_cbc_full_handshake() {
        let (_, _, cs, ss) = do_tlcp_handshake(CipherSuite::ECDHE_SM4_CBC_SM3);
        assert_eq!(cs, TlcpClientState::Connected);
        assert_eq!(ss, TlcpServerState::Connected);
    }

    #[test]
    fn test_tlcp_ecdhe_gcm_full_handshake() {
        let (_, _, cs, ss) = do_tlcp_handshake(CipherSuite::ECDHE_SM4_GCM_SM3);
        assert_eq!(cs, TlcpClientState::Connected);
        assert_eq!(ss, TlcpServerState::Connected);
    }

    #[test]
    fn test_tlcp_ecc_cbc_full_handshake() {
        let (_, _, cs, ss) = do_tlcp_handshake(CipherSuite::ECC_SM4_CBC_SM3);
        assert_eq!(cs, TlcpClientState::Connected);
        assert_eq!(ss, TlcpServerState::Connected);
    }

    #[test]
    fn test_tlcp_ecc_gcm_full_handshake() {
        let (_, _, cs, ss) = do_tlcp_handshake(CipherSuite::ECC_SM4_GCM_SM3);
        assert_eq!(cs, TlcpClientState::Connected);
        assert_eq!(ss, TlcpServerState::Connected);
    }

    // ─── Application data tests ──────────────────────────────

    #[test]
    fn test_tlcp_app_data_exchange_cbc() {
        let (mut client_rl, mut server_rl, _, _) =
            do_tlcp_handshake(CipherSuite::ECDHE_SM4_CBC_SM3);

        let msg = b"Hello from TLCP client over SM4-CBC!";
        let record = client_rl
            .seal_record(ContentType::ApplicationData, msg)
            .unwrap();
        let (ct, plaintext, _) = server_rl.open_record(&record).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(plaintext, msg);

        let reply = b"Hello from TLCP server over SM4-CBC!";
        let record = server_rl
            .seal_record(ContentType::ApplicationData, reply)
            .unwrap();
        let (ct, plaintext, _) = client_rl.open_record(&record).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(plaintext, reply);
    }

    #[test]
    fn test_tlcp_app_data_exchange_gcm() {
        let (mut client_rl, mut server_rl, _, _) =
            do_tlcp_handshake(CipherSuite::ECDHE_SM4_GCM_SM3);

        let msg = b"Hello from TLCP client over SM4-GCM!";
        let record = client_rl
            .seal_record(ContentType::ApplicationData, msg)
            .unwrap();
        let (ct, plaintext, _) = server_rl.open_record(&record).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(plaintext, msg);

        let reply = b"Hello from TLCP server over SM4-GCM!";
        let record = server_rl
            .seal_record(ContentType::ApplicationData, reply)
            .unwrap();
        let (ct, plaintext, _) = client_rl.open_record(&record).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(plaintext, reply);
    }

    #[test]
    fn test_tlcp_ecc_app_data_exchange() {
        let (mut client_rl, mut server_rl, _, _) = do_tlcp_handshake(CipherSuite::ECC_SM4_GCM_SM3);

        let msg = b"ECC static mode application data!";
        let record = client_rl
            .seal_record(ContentType::ApplicationData, msg)
            .unwrap();
        let (ct, plaintext, _) = server_rl.open_record(&record).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn test_tlcp_multiple_app_data_records() {
        let (mut client_rl, mut server_rl, _, _) =
            do_tlcp_handshake(CipherSuite::ECDHE_SM4_CBC_SM3);

        for i in 0..10 {
            let msg = format!("TLCP message #{i}");
            let record = client_rl
                .seal_record(ContentType::ApplicationData, msg.as_bytes())
                .unwrap();
            let (ct, plaintext, _) = server_rl.open_record(&record).unwrap();
            assert_eq!(ct, ContentType::ApplicationData);
            assert_eq!(plaintext, msg.as_bytes());
        }
    }
}
