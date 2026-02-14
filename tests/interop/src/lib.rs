//! Integration tests for openHiTLS-rs.
//! Cross-crate roundtrip and interoperability tests.

#[cfg(test)]
mod tests {
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // -------------------------------------------------------
    // 1. RSA sign + ECDSA sign same message
    // -------------------------------------------------------
    #[test]
    fn test_rsa_and_ecdsa_sign_verify() {
        let message = b"cross-algorithm test message";

        // SHA-256 digest
        let digest = hitls_crypto::sha2::Sha256::digest(message).unwrap();

        // RSA PKCS#1v1.5 sign + verify
        let rsa_key = hitls_crypto::rsa::RsaPrivateKey::generate(2048).unwrap();
        let rsa_sig = rsa_key
            .sign(hitls_crypto::rsa::RsaPadding::Pkcs1v15Sign, &digest)
            .unwrap();
        let rsa_pub = rsa_key.public_key();
        let rsa_ok = rsa_pub
            .verify(
                hitls_crypto::rsa::RsaPadding::Pkcs1v15Sign,
                &digest,
                &rsa_sig,
            )
            .unwrap();
        assert!(rsa_ok, "RSA signature verification failed");

        // ECDSA P-256 sign + verify
        let ec_kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
        let ec_sig = ec_kp.sign(&digest).unwrap();
        let ec_ok = ec_kp.verify(&digest, &ec_sig).unwrap();
        assert!(ec_ok, "ECDSA signature verification failed");

        // Cross-check: ECDSA sig should fail on RSA pubkey (type mismatch via different API)
        // Just verify both sigs are valid and different
        assert_ne!(rsa_sig, ec_sig);
    }

    // -------------------------------------------------------
    // 2. AES-GCM encrypt + HMAC-SHA256 verify
    // -------------------------------------------------------
    #[test]
    fn test_aes_gcm_encrypt_hmac_verify() {
        let plaintext = b"encrypt-then-mac test";
        let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce = hex("000000000000000000000001");

        // AES-256-GCM encrypt (returns ct || tag)
        let ct_tag =
            hitls_crypto::modes::gcm::gcm_encrypt(&key, &nonce, b"aad", plaintext).unwrap();

        // Compute HMAC-SHA256 over ciphertext for integrity binding
        let hmac_key = hex("aabbccdd");
        let mac = hitls_crypto::hmac::Hmac::mac(
            || Box::new(hitls_crypto::sha2::Sha256::new()),
            &hmac_key,
            &ct_tag,
        )
        .unwrap();
        assert_eq!(mac.len(), 32);

        // Verify HMAC
        let mac2 = hitls_crypto::hmac::Hmac::mac(
            || Box::new(hitls_crypto::sha2::Sha256::new()),
            &hmac_key,
            &ct_tag,
        )
        .unwrap();
        assert_eq!(mac, mac2, "HMAC mismatch");

        // Decrypt
        let pt = hitls_crypto::modes::gcm::gcm_decrypt(&key, &nonce, b"aad", &ct_tag).unwrap();
        assert_eq!(pt, plaintext);
    }

    // -------------------------------------------------------
    // 3. PBKDF2 → AES key → encrypt → decrypt
    // -------------------------------------------------------
    #[test]
    fn test_pbkdf2_to_aes_roundtrip() {
        let password = b"correct horse battery staple";
        let salt = hex("0011223344556677");

        // Derive 32-byte key
        let key = hitls_crypto::pbkdf2::pbkdf2(password, &salt, 1000, 32).unwrap();
        assert_eq!(key.len(), 32);

        // Encrypt with derived key
        let plaintext = b"PBKDF2 derived key encryption test";
        let nonce = hex("000000000000000000000001");
        let ct = hitls_crypto::modes::gcm::gcm_encrypt(&key, &nonce, b"", plaintext).unwrap();

        // Decrypt
        let pt = hitls_crypto::modes::gcm::gcm_decrypt(&key, &nonce, b"", &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    // -------------------------------------------------------
    // 4. Ed25519 sign/verify with serialized keys
    // -------------------------------------------------------
    #[test]
    fn test_ed25519_sign_verify_serialized() {
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let message = b"Ed25519 serialization test";

        // Sign
        let sig = kp.sign(message).unwrap();

        // Get public key bytes
        let pk_bytes = kp.public_key().to_vec();

        // Reconstruct from public key bytes only
        let verifier = hitls_crypto::ed25519::Ed25519KeyPair::from_public_key(&pk_bytes).unwrap();
        let ok = verifier.verify(message, &sig).unwrap();
        assert!(ok, "Ed25519 verify failed with reconstructed public key");

        // Tampered message should fail
        let bad_ok = verifier.verify(b"wrong message", &sig).unwrap();
        assert!(!bad_ok, "Ed25519 verify should fail for wrong message");
    }

    // -------------------------------------------------------
    // 5. SM2 sign/verify + encrypt/decrypt
    // -------------------------------------------------------
    #[test]
    fn test_ecdsa_p384_sign_verify() {
        // P-384 ECDSA roundtrip
        let kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP384).unwrap();
        let digest = hitls_crypto::sha2::Sha384::digest(b"P-384 ECDSA test message").unwrap();
        let sig = kp.sign(&digest).unwrap();
        let ok = kp.verify(&digest, &sig).unwrap();
        assert!(ok, "P-384 ECDSA verification failed");

        // Wrong digest should fail
        let bad = kp.verify(&[0u8; 48], &sig).unwrap();
        assert!(!bad, "P-384 ECDSA should reject wrong digest");
    }

    // -------------------------------------------------------
    // 6. X.509 cert parse + signature verify
    // -------------------------------------------------------
    #[test]
    fn test_x509_parse_and_verify() {
        // Use the test certs from the C project
        let cert_dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testcode/testdata/tls/certificate/pem/rsa_sha256/"
        );

        let ca_pem_path = format!("{cert_dir}ca_cert.pem");
        let ee_pem_path = format!("{cert_dir}inter_cert.pem");

        // Try to load test certs; skip if not available
        let ca_pem = match std::fs::read_to_string(&ca_pem_path) {
            Ok(p) => p,
            Err(_) => {
                eprintln!("Skipping X.509 test: test certs not found at {ca_pem_path}");
                return;
            }
        };
        let ee_pem = std::fs::read_to_string(&ee_pem_path).unwrap();

        let ca = hitls_pki::x509::Certificate::from_pem(&ca_pem).unwrap();
        let ee = hitls_pki::x509::Certificate::from_pem(&ee_pem).unwrap();

        // CA should be self-signed
        assert!(ca.is_self_signed());

        // Verify ee cert was signed by CA
        let ok = ee.verify_signature(&ca).unwrap();
        assert!(ok, "EE cert signature verification failed");
    }

    // -------------------------------------------------------
    // 7. Certificate chain verification
    // -------------------------------------------------------
    #[test]
    fn test_x509_chain_verification() {
        let cert_dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testcode/testdata/tls/certificate/pem/rsa_sha256/"
        );

        let ca_pem_path = format!("{cert_dir}ca_cert.pem");
        let inter_pem_path = format!("{cert_dir}inter_cert.pem");
        let ee_pem_path = format!("{cert_dir}server_cert.pem");

        let ca_pem = match std::fs::read_to_string(&ca_pem_path) {
            Ok(p) => p,
            Err(_) => {
                eprintln!("Skipping chain test: test certs not found");
                return;
            }
        };
        let inter_pem = std::fs::read_to_string(&inter_pem_path).unwrap();
        let ee_pem = std::fs::read_to_string(&ee_pem_path).unwrap();

        let ca = hitls_pki::x509::Certificate::from_pem(&ca_pem).unwrap();
        let inter = hitls_pki::x509::Certificate::from_pem(&inter_pem).unwrap();
        let ee = hitls_pki::x509::Certificate::from_pem(&ee_pem).unwrap();

        let mut verifier = hitls_pki::x509::verify::CertificateVerifier::new();
        verifier.add_trusted_cert(ca);

        let chain = verifier.verify_cert(&ee, &[inter]).unwrap();
        assert!(chain.len() >= 2, "chain should have at least 2 certs");
    }

    // -------------------------------------------------------
    // 8. ML-KEM all parameter sets
    // -------------------------------------------------------
    #[test]
    fn test_mlkem_all_params() {
        for &ps in &[512u32, 768, 1024] {
            let kp = hitls_crypto::mlkem::MlKemKeyPair::generate(ps).unwrap();
            let (ss1, ct) = kp.encapsulate().unwrap();
            let ss2 = kp.decapsulate(&ct).unwrap();
            assert_eq!(ss1, ss2, "ML-KEM-{ps} shared secret mismatch");
        }
    }

    // -------------------------------------------------------
    // 9. ML-DSA sign/verify all param sets
    // -------------------------------------------------------
    #[test]
    fn test_mldsa_all_params() {
        for &ps in &[44u32, 65, 87] {
            let kp = hitls_crypto::mldsa::MlDsaKeyPair::generate(ps).unwrap();
            let msg = format!("ML-DSA-{ps} test message");
            let sig = kp.sign(msg.as_bytes()).unwrap();
            let ok = kp.verify(msg.as_bytes(), &sig).unwrap();
            assert!(ok, "ML-DSA-{ps} verification failed");
        }
    }

    // -------------------------------------------------------
    // 10. HybridKEM X25519+ML-KEM roundtrip
    // -------------------------------------------------------
    #[test]
    fn test_hybridkem_roundtrip() {
        let kp = hitls_crypto::hybridkem::HybridKemKeyPair::generate().unwrap();
        let (ss1, ct) = kp.encapsulate().unwrap();
        let ss2 = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2, "HybridKEM shared secret mismatch");

        // Different encapsulation should produce different ciphertext
        let (ss3, ct2) = kp.encapsulate().unwrap();
        assert_ne!(ct, ct2, "two encapsulations should differ");
        // But decapsulated shared secrets should match their own ct
        let ss4 = kp.decapsulate(&ct2).unwrap();
        assert_eq!(ss3, ss4);
    }

    // -------------------------------------------------------
    // 11. Ed25519 CA → CSR → signed cert → chain verification
    // -------------------------------------------------------
    #[test]
    fn test_ed25519_ca_chain_generation() {
        use hitls_pki::x509::{
            CertificateBuilder, CertificateRequestBuilder, DistinguishedName, SigningKey,
        };

        // Generate CA key + self-signed cert
        let ca_kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let ca_sk = SigningKey::Ed25519(ca_kp);
        let ca_dn = DistinguishedName {
            entries: vec![
                ("CN".to_string(), "Integration Test CA".to_string()),
                ("O".to_string(), "OpenHiTLS".to_string()),
            ],
        };
        let ca_cert =
            CertificateBuilder::self_signed(ca_dn, &ca_sk, 1_700_000_000, 1_800_000_000).unwrap();
        assert!(ca_cert.is_self_signed());
        assert!(ca_cert.is_ca());
        assert!(ca_cert.verify_signature(&ca_cert).unwrap());

        // Generate EE key + CSR
        let ee_kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let ee_sk = SigningKey::Ed25519(ee_kp);
        let ee_dn = DistinguishedName {
            entries: vec![("CN".to_string(), "server.example.com".to_string())],
        };
        let csr = CertificateRequestBuilder::new(ee_dn).build(&ee_sk).unwrap();
        assert!(csr.verify_signature().unwrap());

        // CA signs cert using CSR info
        let ee_cert = CertificateBuilder::new()
            .serial_number(&[0x02])
            .issuer(ca_cert.subject.clone())
            .subject(csr.subject.clone())
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(csr.public_key.clone())
            .build(&ca_sk)
            .unwrap();
        assert!(ee_cert.verify_signature(&ca_cert).unwrap());

        // Chain verification
        let mut verifier = hitls_pki::x509::verify::CertificateVerifier::new();
        verifier.add_trusted_cert(ca_cert);
        let chain = verifier.verify_cert(&ee_cert, &[]).unwrap();
        assert!(!chain.is_empty());
    }

    // -------------------------------------------------------
    // 12. ECDSA P-256 CA → cert → chain verification
    // -------------------------------------------------------
    #[test]
    fn test_ecdsa_ca_chain_generation() {
        use hitls_pki::x509::{CertificateBuilder, DistinguishedName, SigningKey};

        let ca_kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
        let ca_sk = SigningKey::Ecdsa {
            curve_id: hitls_types::EccCurveId::NistP256,
            key_pair: ca_kp,
        };
        let ca_dn = DistinguishedName {
            entries: vec![("CN".to_string(), "ECDSA CA".to_string())],
        };
        let ca_cert =
            CertificateBuilder::self_signed(ca_dn, &ca_sk, 1_700_000_000, 1_800_000_000).unwrap();
        assert!(ca_cert.is_self_signed());
        assert!(ca_cert.verify_signature(&ca_cert).unwrap());

        // Generate EE cert
        let ee_kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
        let ee_sk = SigningKey::Ecdsa {
            curve_id: hitls_types::EccCurveId::NistP256,
            key_pair: ee_kp,
        };
        let ee_spki = ee_sk.public_key_info().unwrap();
        let ee_cert = CertificateBuilder::new()
            .serial_number(&[0x03])
            .issuer(ca_cert.subject.clone())
            .subject(DistinguishedName {
                entries: vec![("CN".to_string(), "ecdsa.example.com".to_string())],
            })
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(ee_spki)
            .build(&ca_sk)
            .unwrap();
        assert!(ee_cert.verify_signature(&ca_cert).unwrap());
    }

    // -------------------------------------------------------
    // 13. TLS 1.2 ECDHE-ECDSA full handshake + app data
    // -------------------------------------------------------
    #[test]
    fn test_tls12_ecdhe_ecdsa_full_handshake() {
        use hitls_tls::config::{ServerPrivateKey, TlsConfig};
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::handshake::client12::Tls12ClientHandshake;
        use hitls_tls::handshake::codec::{decode_server_hello, parse_handshake_header};
        use hitls_tls::handshake::codec12::{decode_certificate12, decode_server_key_exchange};
        use hitls_tls::handshake::server12::Tls12ServerHandshake;
        use hitls_tls::record::{ContentType, RecordLayer};
        use hitls_tls::CipherSuite;

        let ecdsa_private = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let fake_cert = vec![0x30, 0x82, 0x01, 0x00];

        let client_config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .verify_peer(false)
            .build();

        let server_config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .certificate_chain(vec![fake_cert])
            .private_key(ServerPrivateKey::Ecdsa {
                curve_id: hitls_types::EccCurveId::NistP256,
                private_key: ecdsa_private,
            })
            .verify_peer(false)
            .build();

        let mut c2s = Vec::new();
        let mut s2c = Vec::new();
        let mut client_hs = Tls12ClientHandshake::new(client_config);
        let mut server_hs = Tls12ServerHandshake::new(server_config);
        let mut client_rl = RecordLayer::new();
        let mut server_rl = RecordLayer::new();

        // Client → CH
        let ch_msg = client_hs.build_client_hello().unwrap();
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::Handshake, &ch_msg)
                .unwrap(),
        );

        // Server processes CH, sends flight
        let (_, ch_plain, consumed) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..consumed);
        let (_, _, ch_total) = parse_handshake_header(&ch_plain).unwrap();
        let sflight = server_hs
            .process_client_hello(&ch_plain[..ch_total])
            .unwrap();
        let suite = sflight.suite;

        for msg in [
            &sflight.server_hello,
            sflight.certificate.as_ref().unwrap(),
            sflight.server_key_exchange.as_ref().unwrap(),
            &sflight.server_hello_done,
        ] {
            s2c.extend_from_slice(&server_rl.seal_record(ContentType::Handshake, msg).unwrap());
        }

        // Client processes server flight
        // SH
        let (_, data, c) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..c);
        let (_, body, total) = parse_handshake_header(&data).unwrap();
        let sh = decode_server_hello(body).unwrap();
        client_hs.process_server_hello(&data[..total], &sh).unwrap();
        // Cert
        let (_, data, c) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..c);
        let (_, body, total) = parse_handshake_header(&data).unwrap();
        let cert12 = decode_certificate12(body).unwrap();
        client_hs
            .process_certificate(&data[..total], &cert12.certificate_list)
            .unwrap();
        // SKE
        let (_, data, c) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..c);
        let (_, body, total) = parse_handshake_header(&data).unwrap();
        let ske = decode_server_key_exchange(body).unwrap();
        client_hs
            .process_server_key_exchange(&data[..total], &ske)
            .unwrap();
        // SHD
        let (_, data, c) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..c);
        let (_, _, total) = parse_handshake_header(&data).unwrap();
        let mut cflight = client_hs.process_server_hello_done(&data[..total]).unwrap();

        // Client → CKE + CCS + Finished
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::Handshake, &cflight.client_key_exchange)
                .unwrap(),
        );
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::ChangeCipherSpec, &[0x01])
                .unwrap(),
        );
        client_rl
            .activate_write_encryption12(
                suite,
                &cflight.client_write_key,
                cflight.client_write_iv.clone(),
            )
            .unwrap();
        c2s.extend_from_slice(
            &client_rl
                .seal_record(ContentType::Handshake, &cflight.finished)
                .unwrap(),
        );

        // Server processes CKE + CCS + Finished
        let (_, data, c) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..c);
        let (_, _, total) = parse_handshake_header(&data).unwrap();
        let mut keys = server_hs
            .process_client_key_exchange(&data[..total])
            .unwrap();

        let (ct, _, c) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..c);
        assert_eq!(ct, ContentType::ChangeCipherSpec);
        server_hs.process_change_cipher_spec().unwrap();

        server_rl
            .activate_read_decryption12(suite, &keys.client_write_key, keys.client_write_iv.clone())
            .unwrap();

        let (_, data, c) = server_rl.open_record(&c2s).unwrap();
        c2s.drain(..c);
        let (_, _, total) = parse_handshake_header(&data).unwrap();
        let sfin = server_hs.process_finished(&data[..total]).unwrap();

        // Server → CCS + Finished
        s2c.extend_from_slice(
            &server_rl
                .seal_record(ContentType::ChangeCipherSpec, &[0x01])
                .unwrap(),
        );
        server_rl
            .activate_write_encryption12(
                suite,
                &keys.server_write_key,
                keys.server_write_iv.clone(),
            )
            .unwrap();
        s2c.extend_from_slice(
            &server_rl
                .seal_record(ContentType::Handshake, &sfin.finished)
                .unwrap(),
        );

        // Client processes server CCS + Finished
        let (ct, _, c) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..c);
        assert_eq!(ct, ContentType::ChangeCipherSpec);
        client_hs.process_change_cipher_spec().unwrap();

        client_rl
            .activate_read_decryption12(
                suite,
                &cflight.server_write_key,
                cflight.server_write_iv.clone(),
            )
            .unwrap();

        let (_, data, c) = client_rl.open_record(&s2c).unwrap();
        s2c.drain(..c);
        let (_, _, total) = parse_handshake_header(&data).unwrap();
        client_hs
            .process_finished(&data[..total], &cflight.master_secret)
            .unwrap();

        // Both connected — exchange app data
        let msg = b"TLS 1.2 interop integration test!";
        let rec = client_rl
            .seal_record(ContentType::ApplicationData, msg)
            .unwrap();
        let (ct, plain, _) = server_rl.open_record(&rec).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(plain, msg);

        let reply = b"Server reply over TLS 1.2 GCM";
        let rec = server_rl
            .seal_record(ContentType::ApplicationData, reply)
            .unwrap();
        let (ct, plain, _) = client_rl.open_record(&rec).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(plain, reply);

        // Cleanup
        use zeroize::Zeroize;
        cflight.master_secret.zeroize();
        keys.master_secret.zeroize();
    }

    // -------------------------------------------------------
    // 14. CSR → cert pipeline with PEM roundtrip
    // -------------------------------------------------------
    #[test]
    fn test_csr_to_cert_pem_pipeline() {
        use hitls_pki::x509::{
            Certificate, CertificateBuilder, CertificateRequest, CertificateRequestBuilder,
            DistinguishedName, SigningKey,
        };

        // Generate CA
        let ca_kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let ca_sk = SigningKey::Ed25519(ca_kp);
        let ca_dn = DistinguishedName {
            entries: vec![("CN".to_string(), "Pipeline CA".to_string())],
        };
        let ca_cert =
            CertificateBuilder::self_signed(ca_dn, &ca_sk, 1_700_000_000, 1_800_000_000).unwrap();

        // Generate CSR as PEM
        let ee_kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let ee_sk = SigningKey::Ed25519(ee_kp);
        let csr_pem = CertificateRequestBuilder::new(DistinguishedName {
            entries: vec![("CN".to_string(), "pipeline.example.com".to_string())],
        })
        .build_pem(&ee_sk)
        .unwrap();

        // Parse CSR from PEM
        let csr = CertificateRequest::from_pem(&csr_pem).unwrap();
        assert!(csr.verify_signature().unwrap());

        // Sign cert
        let ee_cert = CertificateBuilder::new()
            .serial_number(&[0x99])
            .issuer(ca_cert.subject.clone())
            .subject(csr.subject.clone())
            .validity(1_700_000_000, 1_800_000_000)
            .subject_public_key(csr.public_key.clone())
            .build(&ca_sk)
            .unwrap();

        // PEM roundtrip
        let cert_pem = hitls_utils::pem::encode("CERTIFICATE", &ee_cert.raw);
        let parsed = Certificate::from_pem(&cert_pem).unwrap();
        assert_eq!(parsed.subject.get("CN"), Some("pipeline.example.com"));
        assert!(parsed.verify_signature(&ca_cert).unwrap());
    }

    // -------------------------------------------------------
    // TCP loopback helpers
    // -------------------------------------------------------

    /// Generate an Ed25519 server identity (cert DER chain + ServerPrivateKey).
    fn make_ed25519_server_identity() -> (Vec<Vec<u8>>, hitls_tls::config::ServerPrivateKey) {
        use hitls_pki::x509::{CertificateBuilder, DistinguishedName, SigningKey};
        let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let seed = kp.seed().to_vec();
        let sk = SigningKey::Ed25519(kp);
        let dn = DistinguishedName {
            entries: vec![("CN".into(), "localhost".into())],
        };
        let cert = CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000).unwrap();
        (
            vec![cert.raw],
            hitls_tls::config::ServerPrivateKey::Ed25519(seed),
        )
    }

    /// Generate an ECDSA P-256 server identity.
    fn make_ecdsa_server_identity() -> (Vec<Vec<u8>>, hitls_tls::config::ServerPrivateKey) {
        use hitls_pki::x509::{CertificateBuilder, DistinguishedName, SigningKey};
        use hitls_types::EccCurveId;
        let kp = hitls_crypto::ecdsa::EcdsaKeyPair::generate(EccCurveId::NistP256).unwrap();
        let priv_bytes = kp.private_key_bytes();
        let sk = SigningKey::Ecdsa {
            curve_id: EccCurveId::NistP256,
            key_pair: kp,
        };
        let dn = DistinguishedName {
            entries: vec![("CN".into(), "localhost".into())],
        };
        let cert = CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000).unwrap();
        (
            vec![cert.raw],
            hitls_tls::config::ServerPrivateKey::Ecdsa {
                curve_id: EccCurveId::NistP256,
                private_key: priv_bytes,
            },
        )
    }

    /// Generate an RSA 2048 server identity.
    fn make_rsa_server_identity() -> (Vec<Vec<u8>>, hitls_tls::config::ServerPrivateKey) {
        use hitls_pki::x509::{CertificateBuilder, DistinguishedName, SigningKey};
        let rsa = hitls_crypto::rsa::RsaPrivateKey::generate(2048).unwrap();
        let (n, d, e) = (rsa.n_bytes(), rsa.d_bytes(), rsa.e_bytes());
        let (p, q) = (rsa.p_bytes(), rsa.q_bytes());
        let sk = SigningKey::Rsa(rsa);
        let dn = DistinguishedName {
            entries: vec![("CN".into(), "localhost".into())],
        };
        let cert = CertificateBuilder::self_signed(dn, &sk, 1_700_000_000, 1_800_000_000).unwrap();
        (
            vec![cert.raw],
            hitls_tls::config::ServerPrivateKey::Rsa { n, d, e, p, q },
        )
    }

    // -------------------------------------------------------
    // 15. TCP loopback: TLS 1.3 Ed25519
    // -------------------------------------------------------
    #[test]
    fn test_tcp_tls13_loopback_ed25519() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();

            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"Hello from client!");

            conn.write(b"Hello from server!").unwrap();
            conn.shutdown().unwrap();
        });

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        assert_eq!(conn.version(), Some(TlsVersion::Tls13));

        conn.write(b"Hello from client!").unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"Hello from server!");

        conn.shutdown().unwrap();
        server_handle.join().unwrap();
    }

    // -------------------------------------------------------
    // 16. TCP loopback: TLS 1.2 ECDSA P-256
    // -------------------------------------------------------
    #[test]
    fn test_tcp_tls12_loopback_ecdsa() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ecdsa_server_identity();

        let suites = [CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
        let groups = [NamedGroup::SECP256R1];
        let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&suites)
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&suites)
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            conn.handshake().unwrap();

            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"TLS 1.2 works!");

            conn.write(b"TLS 1.2 confirmed!").unwrap();
            conn.shutdown().unwrap();
        });

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        assert_eq!(conn.version(), Some(TlsVersion::Tls12));

        conn.write(b"TLS 1.2 works!").unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"TLS 1.2 confirmed!");

        conn.shutdown().unwrap();
        server_handle.join().unwrap();
    }

    // -------------------------------------------------------
    // 17. TCP loopback: TLS 1.3 large payload (64 KB)
    // -------------------------------------------------------
    #[test]
    fn test_tcp_tls13_loopback_large_payload() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .build();

        let payload: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
        let payload_clone = payload.clone();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();

            // Read all 64 KB (may arrive across multiple TLS records)
            let mut received = Vec::new();
            while received.len() < 65536 {
                let mut buf = [0u8; 16384];
                let n = conn.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
            }
            assert_eq!(received, payload_clone);

            // Echo back in chunks
            let mut offset = 0;
            while offset < received.len() {
                let end = (offset + 16000).min(received.len());
                conn.write(&received[offset..end]).unwrap();
                offset = end;
            }
            conn.shutdown().unwrap();
        });

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        // Write in chunks (TLS max fragment = 16384)
        let mut offset = 0;
        while offset < payload.len() {
            let end = (offset + 16000).min(payload.len());
            conn.write(&payload[offset..end]).unwrap();
            offset = end;
        }

        let mut received = Vec::new();
        while received.len() < 65536 {
            let mut buf = [0u8; 16384];
            let n = conn.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        assert_eq!(received, payload);

        conn.shutdown().unwrap();
        server_handle.join().unwrap();
    }

    // -------------------------------------------------------
    // 18. TCP loopback: TLS 1.2 RSA
    // -------------------------------------------------------
    #[test]
    #[ignore] // RSA 2048 key generation is slow
    fn test_tcp_tls12_loopback_rsa() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_rsa_server_identity();

        let suites = [CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384];
        let groups = [NamedGroup::SECP256R1];
        let sig_algs = [
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ];

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&suites)
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&suites)
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            conn.handshake().unwrap();

            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"RSA over TCP!");

            conn.write(b"RSA confirmed!").unwrap();
            conn.shutdown().unwrap();
        });

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        conn.write(b"RSA over TCP!").unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"RSA confirmed!");

        conn.shutdown().unwrap();
        server_handle.join().unwrap();
    }

    // -------------------------------------------------------
    // 19. TCP loopback: TLS 1.3 multi-message echo
    // -------------------------------------------------------
    #[test]
    fn test_tcp_tls13_loopback_multi_message() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();

            for _ in 0..5 {
                let mut buf = [0u8; 256];
                let n = conn.read(&mut buf).unwrap();
                conn.write(&buf[..n]).unwrap();
            }
            conn.shutdown().unwrap();
        });

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        for i in 0..5u32 {
            let msg = format!("Message #{}", i + 1);
            conn.write(msg.as_bytes()).unwrap();

            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
        }

        conn.shutdown().unwrap();
        server_handle.join().unwrap();
    }

    // -------------------------------------------------------
    // 20. TCP loopback: TLS 1.2 session ticket resumption
    // -------------------------------------------------------
    #[test]
    fn test_tcp_tls12_session_ticket_loopback() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ecdsa_server_identity();
        let ticket_key = vec![0xAB; 32];

        let suites = [CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
        let groups = [NamedGroup::SECP256R1];
        let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

        // --- First connection: full handshake, get ticket ---
        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&suites)
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain.clone())
            .private_key(server_key.clone())
            .verify_peer(false)
            .ticket_key(ticket_key.clone())
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&suites)
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .session_resumption(true)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            conn.handshake().unwrap();

            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"Full handshake!");
            conn.write(b"Got it!").unwrap();
            conn.shutdown().unwrap();
        });

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        assert_eq!(conn.version(), Some(TlsVersion::Tls12));

        conn.write(b"Full handshake!").unwrap();
        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"Got it!");

        // Get the session with ticket for resumption
        let session = conn.take_session().unwrap();
        assert!(session.ticket.is_some(), "should have received a ticket");

        conn.shutdown().unwrap();
        server_handle.join().unwrap();

        // --- Second connection: ticket-based resumption ---
        let server_config2 = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&suites)
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .ticket_key(ticket_key)
            .build();

        let client_config2 = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&suites)
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .session_resumption(true)
            .resumption_session(session)
            .build();

        let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr2 = listener2.local_addr().unwrap();

        let server_handle2 = thread::spawn(move || {
            let (stream, _) = listener2.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config2);
            conn.handshake().unwrap();

            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"Resumed!");
            conn.write(b"Session ticket works!").unwrap();
            conn.shutdown().unwrap();
        });

        let stream2 = TcpStream::connect_timeout(&addr2, Duration::from_secs(5)).unwrap();
        stream2
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream2
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn2 = Tls12ClientConnection::new(stream2, client_config2);
        conn2.handshake().unwrap();
        assert_eq!(conn2.version(), Some(TlsVersion::Tls12));

        conn2.write(b"Resumed!").unwrap();
        let mut buf = [0u8; 256];
        let n = conn2.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"Session ticket works!");

        conn2.shutdown().unwrap();
        server_handle2.join().unwrap();
    }

    // -------------------------------------------------------
    // 21. TCP loopback: TLS 1.2 EMS + ETM over CBC cipher suite
    // -------------------------------------------------------
    #[test]
    fn test_tcp_tls12_ems_etm_loopback() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ecdsa_server_identity();

        // Use CBC suite so ETM applies
        let suites = [CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256];
        let groups = [NamedGroup::SECP256R1];
        let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&suites)
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .enable_extended_master_secret(true)
            .enable_encrypt_then_mac(true)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&suites)
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .enable_extended_master_secret(true)
            .enable_encrypt_then_mac(true)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            conn.handshake().unwrap();

            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"EMS+ETM CBC works!");

            conn.write(b"EMS+ETM confirmed!").unwrap();
            conn.shutdown().unwrap();
        });

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        assert_eq!(conn.version(), Some(TlsVersion::Tls12));

        conn.write(b"EMS+ETM CBC works!").unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"EMS+ETM confirmed!");

        conn.shutdown().unwrap();
        server_handle.join().unwrap();
    }

    // -------------------------------------------------------
    // 22. TCP loopback: TLS 1.2 RSA static key exchange
    // -------------------------------------------------------
    #[test]
    #[ignore] // RSA 2048 key generation is slow
    fn test_tcp_tls12_loopback_rsa_static() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::SignatureScheme;
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_rsa_server_identity();

        let suites = [CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256];
        let sig_algs = [
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ];

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&suites)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&suites)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            conn.handshake().unwrap();

            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"RSA static KX over TCP!");

            conn.write(b"RSA static confirmed!").unwrap();
            conn.shutdown().unwrap();
        });

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        assert_eq!(conn.version(), Some(TlsVersion::Tls12));
        assert_eq!(
            conn.cipher_suite(),
            Some(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256)
        );

        conn.write(b"RSA static KX over TCP!").unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"RSA static confirmed!");

        conn.shutdown().unwrap();
        server_handle.join().unwrap();
    }

    // -------------------------------------------------------
    // 23. TCP loopback: TLS 1.2 DHE_RSA key exchange
    // -------------------------------------------------------
    #[test]
    #[ignore] // RSA 2048 key generation is slow
    fn test_tcp_tls12_loopback_dhe_rsa() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_rsa_server_identity();

        let suites = [CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256];
        let groups = [NamedGroup::FFDHE2048];
        let sig_algs = [
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ];

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&suites)
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&suites)
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            conn.handshake().unwrap();

            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"DHE over TCP!");

            conn.write(b"DHE confirmed!").unwrap();
            conn.shutdown().unwrap();
        });

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        assert_eq!(conn.version(), Some(TlsVersion::Tls12));
        assert_eq!(
            conn.cipher_suite(),
            Some(CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256)
        );

        conn.write(b"DHE over TCP!").unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"DHE confirmed!");

        conn.shutdown().unwrap();
        server_handle.join().unwrap();
    }

    // -------------------------------------------------------
    // 24. Async TCP loopback: TLS 1.3 Ed25519
    // -------------------------------------------------------
    #[tokio::test]
    async fn test_async_tls13_loopback() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection_async::{AsyncTlsClientConnection, AsyncTlsServerConnection};
        use hitls_tls::{AsyncTlsConnection, TlsRole, TlsVersion};
        use tokio::net::TcpListener;

        let (cert_chain, server_key) = make_ed25519_server_identity();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = AsyncTlsServerConnection::new(stream, server_config);
            conn.handshake().await.unwrap();

            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"async hello from client!");

            conn.write(b"async hello from server!").await.unwrap();
            conn.shutdown().await.unwrap();
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut conn = AsyncTlsClientConnection::new(stream, client_config);
        conn.handshake().await.unwrap();

        assert_eq!(conn.version(), Some(TlsVersion::Tls13));

        conn.write(b"async hello from client!").await.unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"async hello from server!");

        conn.shutdown().await.unwrap();
        server_handle.await.unwrap();
    }

    // -------------------------------------------------------
    // 25. Async TCP loopback: TLS 1.2 ECDSA
    // -------------------------------------------------------
    #[tokio::test]
    async fn test_async_tls12_loopback() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12_async::{
            AsyncTls12ClientConnection, AsyncTls12ServerConnection,
        };
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{AsyncTlsConnection, CipherSuite, TlsRole, TlsVersion};
        use tokio::net::TcpListener;

        let (cert_chain, server_key) = make_ecdsa_server_identity();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .verify_peer(false)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = AsyncTls12ServerConnection::new(stream, server_config);
            conn.handshake().await.unwrap();

            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"async TLS 1.2 hello!");

            conn.write(b"async TLS 1.2 reply!").await.unwrap();
            conn.shutdown().await.unwrap();
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut conn = AsyncTls12ClientConnection::new(stream, client_config);
        conn.handshake().await.unwrap();

        assert_eq!(conn.version(), Some(TlsVersion::Tls12));
        assert_eq!(
            conn.cipher_suite(),
            Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
        );

        conn.write(b"async TLS 1.2 hello!").await.unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"async TLS 1.2 reply!");

        conn.shutdown().await.unwrap();
        server_handle.await.unwrap();
    }

    // -------------------------------------------------------
    // 26. Async TCP loopback: TLS 1.3 large payload
    // -------------------------------------------------------
    #[tokio::test]
    async fn test_async_tls13_large_payload() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection_async::{AsyncTlsClientConnection, AsyncTlsServerConnection};
        use hitls_tls::{AsyncTlsConnection, TlsRole, TlsVersion};
        use tokio::net::TcpListener;

        let (cert_chain, server_key) = make_ed25519_server_identity();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // 64KB payload — must be chunked since TLS max fragment is 16384
        let payload: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
        let payload_clone = payload.clone();

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = AsyncTlsServerConnection::new(stream, server_config);
            conn.handshake().await.unwrap();

            // Echo back everything
            let mut received = Vec::new();
            let mut buf = [0u8; 32768];
            while received.len() < payload_clone.len() {
                let n = conn.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
            }
            assert_eq!(received, payload_clone);

            // Send it back in chunks
            let mut offset = 0;
            while offset < received.len() {
                let end = std::cmp::min(offset + 16000, received.len());
                conn.write(&received[offset..end]).await.unwrap();
                offset = end;
            }
            conn.shutdown().await.unwrap();
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut conn = AsyncTlsClientConnection::new(stream, client_config);
        conn.handshake().await.unwrap();

        // Send in chunks
        let mut offset = 0;
        while offset < payload.len() {
            let end = std::cmp::min(offset + 16000, payload.len());
            conn.write(&payload[offset..end]).await.unwrap();
            offset = end;
        }

        // Receive echo
        let mut received = Vec::new();
        let mut buf = [0u8; 32768];
        while received.len() < payload.len() {
            let n = conn.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        assert_eq!(received, payload);

        conn.shutdown().await.unwrap();
        server_handle.await.unwrap();
    }

    // -------------------------------------------------------
    // DTLS 1.2 integration tests
    // -------------------------------------------------------

    fn make_dtls12_configs() -> (hitls_tls::config::TlsConfig, hitls_tls::config::TlsConfig) {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::CipherSuite;

        let (cert_chain, server_key) = make_ecdsa_server_identity();

        let client_config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .verify_peer(false)
            .build();

        let server_config = TlsConfig::builder()
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        (client_config, server_config)
    }

    #[test]
    fn test_dtls12_handshake_no_cookie() {
        use hitls_tls::connection_dtls12::dtls12_handshake_in_memory;
        use hitls_tls::TlsVersion;

        let (cc, sc) = make_dtls12_configs();
        let (client, server) = dtls12_handshake_in_memory(cc, sc, false).unwrap();
        assert_eq!(client.version(), Some(TlsVersion::Dtls12));
        assert_eq!(server.version(), Some(TlsVersion::Dtls12));
    }

    #[test]
    fn test_dtls12_handshake_with_cookie() {
        use hitls_tls::connection_dtls12::dtls12_handshake_in_memory;
        use hitls_tls::TlsVersion;

        let (cc, sc) = make_dtls12_configs();
        let (client, server) = dtls12_handshake_in_memory(cc, sc, true).unwrap();
        assert_eq!(client.version(), Some(TlsVersion::Dtls12));
        assert_eq!(server.version(), Some(TlsVersion::Dtls12));
    }

    #[test]
    fn test_dtls12_data_roundtrip() {
        use hitls_tls::connection_dtls12::dtls12_handshake_in_memory;

        let (cc, sc) = make_dtls12_configs();
        let (mut client, mut server) = dtls12_handshake_in_memory(cc, sc, false).unwrap();

        // Client -> Server
        let datagram = client.seal_app_data(b"Hello from DTLS client").unwrap();
        let pt = server.open_app_data(&datagram).unwrap();
        assert_eq!(pt, b"Hello from DTLS client");

        // Server -> Client
        let datagram = server.seal_app_data(b"Hello from DTLS server").unwrap();
        let pt = client.open_app_data(&datagram).unwrap();
        assert_eq!(pt, b"Hello from DTLS server");
    }

    #[test]
    fn test_dtls12_multiple_datagrams() {
        use hitls_tls::connection_dtls12::dtls12_handshake_in_memory;

        let (cc, sc) = make_dtls12_configs();
        let (mut client, mut server) = dtls12_handshake_in_memory(cc, sc, false).unwrap();

        for i in 0..20u32 {
            let msg = format!("DTLS message #{i}");
            let dg = client.seal_app_data(msg.as_bytes()).unwrap();
            let pt = server.open_app_data(&dg).unwrap();
            assert_eq!(pt, msg.as_bytes());

            let reply = format!("DTLS reply #{i}");
            let dg = server.seal_app_data(reply.as_bytes()).unwrap();
            let pt = client.open_app_data(&dg).unwrap();
            assert_eq!(pt, reply.as_bytes());
        }
    }

    #[test]
    fn test_dtls12_anti_replay() {
        use hitls_tls::connection_dtls12::dtls12_handshake_in_memory;

        let (cc, sc) = make_dtls12_configs();
        let (mut client, mut server) = dtls12_handshake_in_memory(cc, sc, false).unwrap();

        let datagram = client.seal_app_data(b"replay me").unwrap();
        // First open succeeds
        let pt = server.open_app_data(&datagram).unwrap();
        assert_eq!(pt, b"replay me");
        // Second open (replay) should fail
        let result = server.open_app_data(&datagram);
        assert!(result.is_err(), "replayed datagram should be rejected");
    }

    // -------------------------------------------------------
    // TLCP integration tests
    // -------------------------------------------------------

    fn make_sm2_tlcp_identity() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
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
            entries: vec![("CN".into(), "TLCP Sign".into())],
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
            entries: vec![("CN".into(), "TLCP Enc".into())],
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

    fn make_tlcp_configs(
        suite: hitls_tls::CipherSuite,
    ) -> (hitls_tls::config::TlsConfig, hitls_tls::config::TlsConfig) {
        use hitls_tls::config::{ServerPrivateKey, TlsConfig};
        use hitls_tls::crypt::SignatureScheme;

        let (sign_privkey, sign_cert, enc_privkey, enc_cert) = make_sm2_tlcp_identity();

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

    #[test]
    fn test_tlcp_ecdhe_gcm() {
        use hitls_tls::connection_tlcp::tlcp_handshake_in_memory;
        use hitls_tls::CipherSuite;

        let (cc, sc) = make_tlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let (mut client, mut server) = tlcp_handshake_in_memory(cc, sc).unwrap();

        let rec = client.seal_app_data(b"TLCP ECDHE GCM test").unwrap();
        let pt = server.open_app_data(&rec).unwrap();
        assert_eq!(pt, b"TLCP ECDHE GCM test");

        let rec = server.seal_app_data(b"TLCP server reply").unwrap();
        let pt = client.open_app_data(&rec).unwrap();
        assert_eq!(pt, b"TLCP server reply");
    }

    #[test]
    fn test_tlcp_ecdhe_cbc() {
        use hitls_tls::connection_tlcp::tlcp_handshake_in_memory;
        use hitls_tls::CipherSuite;

        let (cc, sc) = make_tlcp_configs(CipherSuite::ECDHE_SM4_CBC_SM3);
        let (mut client, mut server) = tlcp_handshake_in_memory(cc, sc).unwrap();

        let rec = client.seal_app_data(b"TLCP ECDHE CBC test").unwrap();
        let pt = server.open_app_data(&rec).unwrap();
        assert_eq!(pt, b"TLCP ECDHE CBC test");

        let rec = server.seal_app_data(b"CBC server reply").unwrap();
        let pt = client.open_app_data(&rec).unwrap();
        assert_eq!(pt, b"CBC server reply");
    }

    #[test]
    fn test_tlcp_ecc_gcm() {
        use hitls_tls::connection_tlcp::tlcp_handshake_in_memory;
        use hitls_tls::CipherSuite;

        let (cc, sc) = make_tlcp_configs(CipherSuite::ECC_SM4_GCM_SM3);
        let (mut client, mut server) = tlcp_handshake_in_memory(cc, sc).unwrap();

        let rec = client.seal_app_data(b"ECC GCM test").unwrap();
        let pt = server.open_app_data(&rec).unwrap();
        assert_eq!(pt, b"ECC GCM test");
    }

    #[test]
    fn test_tlcp_ecc_cbc() {
        use hitls_tls::connection_tlcp::tlcp_handshake_in_memory;
        use hitls_tls::CipherSuite;

        let (cc, sc) = make_tlcp_configs(CipherSuite::ECC_SM4_CBC_SM3);
        let (mut client, mut server) = tlcp_handshake_in_memory(cc, sc).unwrap();

        let rec = client.seal_app_data(b"ECC CBC test").unwrap();
        let pt = server.open_app_data(&rec).unwrap();
        assert_eq!(pt, b"ECC CBC test");
    }

    // -------------------------------------------------------
    // DTLCP integration tests
    // -------------------------------------------------------

    fn make_dtlcp_configs(
        suite: hitls_tls::CipherSuite,
    ) -> (hitls_tls::config::TlsConfig, hitls_tls::config::TlsConfig) {
        use hitls_tls::config::{ServerPrivateKey, TlsConfig};
        use hitls_tls::crypt::SignatureScheme;

        let (sign_privkey, sign_cert, enc_privkey, enc_cert) = make_sm2_tlcp_identity();

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

    #[test]
    fn test_dtlcp_ecdhe_gcm() {
        use hitls_tls::connection_dtlcp::dtlcp_handshake_in_memory;
        use hitls_tls::CipherSuite;

        let (cc, sc) = make_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let (mut client, mut server) = dtlcp_handshake_in_memory(cc, sc, false).unwrap();

        let dg = client.seal_app_data(b"DTLCP ECDHE GCM").unwrap();
        let pt = server.open_app_data(&dg).unwrap();
        assert_eq!(pt, b"DTLCP ECDHE GCM");

        let dg = server.seal_app_data(b"DTLCP reply").unwrap();
        let pt = client.open_app_data(&dg).unwrap();
        assert_eq!(pt, b"DTLCP reply");
    }

    #[test]
    fn test_dtlcp_ecdhe_cbc() {
        use hitls_tls::connection_dtlcp::dtlcp_handshake_in_memory;
        use hitls_tls::CipherSuite;

        let (cc, sc) = make_dtlcp_configs(CipherSuite::ECDHE_SM4_CBC_SM3);
        let (mut client, mut server) = dtlcp_handshake_in_memory(cc, sc, false).unwrap();

        let dg = client.seal_app_data(b"DTLCP ECDHE CBC").unwrap();
        let pt = server.open_app_data(&dg).unwrap();
        assert_eq!(pt, b"DTLCP ECDHE CBC");
    }

    #[test]
    fn test_dtlcp_with_cookie() {
        use hitls_tls::connection_dtlcp::dtlcp_handshake_in_memory;
        use hitls_tls::{CipherSuite, TlsVersion};

        let (cc, sc) = make_dtlcp_configs(CipherSuite::ECDHE_SM4_GCM_SM3);
        let (client, server) = dtlcp_handshake_in_memory(cc, sc, true).unwrap();
        assert_eq!(client.version(), Some(TlsVersion::Dtlcp));
        assert_eq!(server.version(), Some(TlsVersion::Dtlcp));
    }

    // -------------------------------------------------------
    // mTLS integration tests
    // -------------------------------------------------------

    #[test]
    fn test_tls12_mtls_loopback() {
        use hitls_tls::config::{ServerPrivateKey, TlsConfig};
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ecdsa_server_identity();

        // Also create a client ECDSA identity
        let client_kp =
            hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
        let client_priv = client_kp.private_key_bytes();
        let client_sk = hitls_pki::x509::SigningKey::Ecdsa {
            curve_id: hitls_types::EccCurveId::NistP256,
            key_pair: client_kp,
        };
        let client_dn = hitls_pki::x509::DistinguishedName {
            entries: vec![("CN".into(), "client".into())],
        };
        let client_cert = hitls_pki::x509::CertificateBuilder::self_signed(
            client_dn,
            &client_sk,
            1_700_000_000,
            1_800_000_000,
        )
        .unwrap();

        let suites = [CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
        let groups = [NamedGroup::SECP256R1];
        let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&suites)
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .verify_client_cert(true)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&suites)
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .client_certificate_chain(vec![client_cert.raw])
            .client_private_key(ServerPrivateKey::Ecdsa {
                curve_id: hitls_types::EccCurveId::NistP256,
                private_key: client_priv,
            })
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            conn.handshake().unwrap();

            let mut buf = [0u8; 256];
            let n = conn.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"mTLS client hello");
            conn.write(b"mTLS server reply").unwrap();
            conn.shutdown().unwrap();
        });

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        assert_eq!(conn.version(), Some(TlsVersion::Tls12));
        conn.write(b"mTLS client hello").unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"mTLS server reply");

        conn.shutdown().unwrap();
        server_handle.join().unwrap();
    }

    #[test]
    fn test_tls12_mtls_required_no_cert() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ecdsa_server_identity();

        let suites = [CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
        let groups = [NamedGroup::SECP256R1];
        let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&suites)
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .verify_client_cert(true)
            .require_client_cert(true)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&suites)
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            // No client cert provided
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            // Server should reject because client sends empty cert
            let result = conn.handshake();
            assert!(result.is_err(), "server should reject missing client cert");
        });

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        // Client handshake may also error out
        let _ = conn.handshake();

        server_handle.join().unwrap();
    }

    #[test]
    fn test_tls13_post_hs_auth_in_memory() {
        use hitls_tls::config::{ServerPrivateKey, TlsConfig};
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();

        // Create client Ed25519 identity
        let client_kp = hitls_crypto::ed25519::Ed25519KeyPair::generate().unwrap();
        let client_seed = client_kp.seed().to_vec();
        let client_sk = hitls_pki::x509::SigningKey::Ed25519(client_kp);
        let client_dn = hitls_pki::x509::DistinguishedName {
            entries: vec![("CN".into(), "post-hs-client".into())],
        };
        let client_cert = hitls_pki::x509::CertificateBuilder::self_signed(
            client_dn,
            &client_sk,
            1_700_000_000,
            1_800_000_000,
        )
        .unwrap();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .post_handshake_auth(true)
            .client_certificate_chain(vec![client_cert.raw])
            .client_private_key(ServerPrivateKey::Ed25519(client_seed))
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();

            // Request post-handshake client auth
            let certs = conn.request_client_auth().unwrap();
            assert!(!certs.is_empty(), "should receive client cert");

            conn.write(b"post-hs auth ok").unwrap();
            conn.shutdown().unwrap();
        });

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"post-hs auth ok");

        conn.shutdown().unwrap();
        server_handle.join().unwrap();
    }

    #[test]
    fn test_tls13_post_hs_auth_not_offered() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        // Client does NOT offer post_handshake_auth
        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .post_handshake_auth(false)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();

            // Request post-handshake auth — client didn't offer it
            // Server should still send CertificateRequest, but client will error
            let result = conn.request_client_auth();
            // This should fail because client didn't offer post_handshake_auth
            assert!(
                result.is_err(),
                "should fail when client didn't offer post-hs auth"
            );

            let _ = conn.shutdown();
        });

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        // Client reads — should get CertificateRequest and fail
        let mut buf = [0u8; 256];
        let _ = conn.read(&mut buf);

        let _ = conn.shutdown();
        server_handle.join().unwrap();
    }
}
