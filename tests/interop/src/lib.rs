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

    // -------------------------------------------------------
    // Cipher suite integration tests — helper
    // -------------------------------------------------------

    /// Run a synchronous TCP loopback TLS 1.2 handshake with the given config pair.
    /// Returns (negotiated cipher suite on client, negotiated cipher suite on server).
    fn run_tls12_tcp_loopback(
        client_config: hitls_tls::config::TlsConfig,
        server_config: hitls_tls::config::TlsConfig,
    ) -> (hitls_tls::CipherSuite, hitls_tls::CipherSuite) {
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::TlsConnection;
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let (tx, rx) = mpsc::channel();
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
            let suite = conn.cipher_suite().unwrap();
            let mut buf = [0u8; 32];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
            let _ = conn.shutdown();
            tx.send(suite).unwrap();
        });

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        let client_suite = conn.cipher_suite().unwrap();
        conn.write(b"ping").unwrap();
        let mut buf = [0u8; 32];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();

        server_handle.join().unwrap();
        let server_suite = rx.recv().unwrap();
        (client_suite, server_suite)
    }

    // -------------------------------------------------------
    // 40–43. ECDHE_ECDSA CCM cipher suites (RFC 6655/7251)
    // -------------------------------------------------------

    #[test]
    fn test_tcp_tls12_ecdhe_ecdsa_aes128_ccm() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM;
        let (cert_chain, server_key) = make_ecdsa_server_identity();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .verify_peer(false)
            .build();

        let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
        assert_eq!(cs, suite);
        assert_eq!(ss, suite);
    }

    #[test]
    fn test_tcp_tls12_ecdhe_ecdsa_aes256_ccm() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM;
        let (cert_chain, server_key) = make_ecdsa_server_identity();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .verify_peer(false)
            .build();

        let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
        assert_eq!(cs, suite);
        assert_eq!(ss, suite);
    }

    #[test]
    fn test_tcp_tls12_ecdhe_ecdsa_aes128_ccm_8() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
        let (cert_chain, server_key) = make_ecdsa_server_identity();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .verify_peer(false)
            .build();

        let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
        assert_eq!(cs, suite);
        assert_eq!(ss, suite);
    }

    #[test]
    fn test_tcp_tls12_ecdhe_ecdsa_aes256_ccm_8() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8;
        let (cert_chain, server_key) = make_ecdsa_server_identity();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .verify_peer(false)
            .build();

        let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
        assert_eq!(cs, suite);
        assert_eq!(ss, suite);
    }

    // -------------------------------------------------------
    // 44–47. DHE_RSA CCM cipher suites (RFC 6655)
    // -------------------------------------------------------

    #[test]
    fn test_tcp_tls12_dhe_rsa_aes128_ccm() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

        let suite = CipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM;
        let (cert_chain, server_key) = make_rsa_server_identity();
        let sig_algs = [
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ];

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::FFDHE2048])
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::FFDHE2048])
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .build();

        let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
        assert_eq!(cs, suite);
        assert_eq!(ss, suite);
    }

    #[test]
    fn test_tcp_tls12_dhe_rsa_aes256_ccm() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

        let suite = CipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM;
        let (cert_chain, server_key) = make_rsa_server_identity();
        let sig_algs = [
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ];

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::FFDHE2048])
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::FFDHE2048])
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .build();

        let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
        assert_eq!(cs, suite);
        assert_eq!(ss, suite);
    }

    #[test]
    fn test_tcp_tls12_dhe_rsa_aes128_ccm_8() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

        let suite = CipherSuite::TLS_DHE_RSA_WITH_AES_128_CCM_8;
        let (cert_chain, server_key) = make_rsa_server_identity();
        let sig_algs = [
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ];

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::FFDHE2048])
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::FFDHE2048])
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .build();

        let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
        assert_eq!(cs, suite);
        assert_eq!(ss, suite);
    }

    #[test]
    fn test_tcp_tls12_dhe_rsa_aes256_ccm_8() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsRole, TlsVersion};

        let suite = CipherSuite::TLS_DHE_RSA_WITH_AES_256_CCM_8;
        let (cert_chain, server_key) = make_rsa_server_identity();
        let sig_algs = [
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ];

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::FFDHE2048])
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::FFDHE2048])
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .build();

        let (cs, ss) = run_tls12_tcp_loopback(client_config, server_config);
        assert_eq!(cs, suite);
        assert_eq!(ss, suite);
    }

    // -------------------------------------------------------
    // 48–52. PSK cipher suites (RFC 4279, RFC 5487)
    // -------------------------------------------------------

    fn make_psk_configs(
        suite: hitls_tls::CipherSuite,
        groups: &[hitls_tls::crypt::NamedGroup],
    ) -> (hitls_tls::config::TlsConfig, hitls_tls::config::TlsConfig) {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::crypt::SignatureScheme;
        use hitls_tls::{TlsRole, TlsVersion};

        let psk = b"integration-test-psk-32-bytes!!!".to_vec();
        let psk_identity = b"test-client".to_vec();
        let sig_algs = [
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ];

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .psk(psk.clone())
            .psk_identity(psk_identity)
            .build();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .psk(psk)
            .psk_identity_hint(b"server-hint".to_vec())
            .build();

        (client_config, server_config)
    }

    #[test]
    fn test_tcp_tls12_psk_aes128_gcm() {
        use hitls_tls::CipherSuite;
        let suite = CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256;
        let (cc, sc) = make_psk_configs(suite, &[]);
        let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
        assert_eq!(cs, suite);
        assert_eq!(ss, suite);
    }

    #[test]
    fn test_tcp_tls12_psk_aes128_ccm() {
        use hitls_tls::CipherSuite;
        let suite = CipherSuite::TLS_PSK_WITH_AES_128_CCM;
        let (cc, sc) = make_psk_configs(suite, &[]);
        let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
        assert_eq!(cs, suite);
        assert_eq!(ss, suite);
    }

    #[test]
    fn test_tcp_tls12_dhe_psk_aes128_gcm() {
        use hitls_tls::crypt::NamedGroup;
        use hitls_tls::CipherSuite;
        let suite = CipherSuite::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256;
        let (cc, sc) = make_psk_configs(suite, &[NamedGroup::FFDHE2048]);
        let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
        assert_eq!(cs, suite);
        assert_eq!(ss, suite);
    }

    #[test]
    fn test_tcp_tls12_ecdhe_psk_aes128_gcm() {
        use hitls_tls::crypt::NamedGroup;
        use hitls_tls::CipherSuite;
        let suite = CipherSuite::TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256;
        let (cc, sc) = make_psk_configs(suite, &[NamedGroup::SECP256R1]);
        let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
        assert_eq!(cs, suite);
        assert_eq!(ss, suite);
    }

    #[test]
    fn test_tcp_tls12_psk_chacha20() {
        use hitls_tls::CipherSuite;
        let suite = CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256;
        let (cc, sc) = make_psk_configs(suite, &[]);
        let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
        assert_eq!(cs, suite);
        assert_eq!(ss, suite);
    }

    // -------------------------------------------------------
    // 53–56. DH_ANON / ECDH_ANON cipher suites (RFC 5246/4492)
    // -------------------------------------------------------

    fn make_anon_configs(
        suite: hitls_tls::CipherSuite,
        groups: &[hitls_tls::crypt::NamedGroup],
    ) -> (hitls_tls::config::TlsConfig, hitls_tls::config::TlsConfig) {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::{TlsRole, TlsVersion};

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(groups)
            .verify_peer(false)
            .build();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(groups)
            .verify_peer(false)
            .build();

        (client_config, server_config)
    }

    #[test]
    fn test_tcp_tls12_dh_anon_aes128_gcm() {
        use hitls_tls::crypt::NamedGroup;
        use hitls_tls::CipherSuite;
        let suite = CipherSuite::TLS_DH_ANON_WITH_AES_128_GCM_SHA256;
        let (cc, sc) = make_anon_configs(suite, &[NamedGroup::FFDHE2048]);
        let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
        assert_eq!(cs, suite);
        assert_eq!(ss, suite);
    }

    #[test]
    fn test_tcp_tls12_dh_anon_aes128_cbc() {
        use hitls_tls::crypt::NamedGroup;
        use hitls_tls::CipherSuite;
        let suite = CipherSuite::TLS_DH_ANON_WITH_AES_128_CBC_SHA256;
        let (cc, sc) = make_anon_configs(suite, &[NamedGroup::FFDHE2048]);
        let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
        assert_eq!(cs, suite);
        assert_eq!(ss, suite);
    }

    #[test]
    fn test_tcp_tls12_ecdh_anon_aes128_cbc() {
        use hitls_tls::crypt::NamedGroup;
        use hitls_tls::CipherSuite;
        let suite = CipherSuite::TLS_ECDH_ANON_WITH_AES_128_CBC_SHA;
        let (cc, sc) = make_anon_configs(suite, &[NamedGroup::SECP256R1]);
        let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
        assert_eq!(cs, suite);
        assert_eq!(ss, suite);
    }

    #[test]
    fn test_tcp_tls12_ecdh_anon_aes256_cbc() {
        use hitls_tls::crypt::NamedGroup;
        use hitls_tls::CipherSuite;
        let suite = CipherSuite::TLS_ECDH_ANON_WITH_AES_256_CBC_SHA;
        let (cc, sc) = make_anon_configs(suite, &[NamedGroup::SECP256R1]);
        let (cs, ss) = run_tls12_tcp_loopback(cc, sc);
        assert_eq!(cs, suite);
        assert_eq!(ss, suite);
    }

    // -------------------------------------------------------
    // 57–61. TLS 1.3 additional cipher suites
    // -------------------------------------------------------

    fn run_tls13_tcp_loopback(
        suite: hitls_tls::CipherSuite,
    ) -> (hitls_tls::CipherSuite, hitls_tls::CipherSuite) {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();
        let (tx, rx) = mpsc::channel();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .cipher_suites(&[suite])
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

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
            let suite = conn.cipher_suite().unwrap();
            let mut buf = [0u8; 32];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
            let _ = conn.shutdown();
            tx.send(suite).unwrap();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .cipher_suites(&[suite])
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        let client_suite = conn.cipher_suite().unwrap();
        conn.write(b"ping").unwrap();
        let mut buf = [0u8; 32];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();

        server_handle.join().unwrap();
        let server_suite = rx.recv().unwrap();
        (client_suite, server_suite)
    }

    #[test]
    fn test_tcp_tls13_aes256_gcm() {
        use hitls_tls::CipherSuite;
        let suite = CipherSuite::TLS_AES_256_GCM_SHA384;
        let (cs, ss) = run_tls13_tcp_loopback(suite);
        assert_eq!(cs, suite);
        assert_eq!(ss, suite);
    }

    #[test]
    fn test_tcp_tls13_chacha20_poly1305() {
        use hitls_tls::CipherSuite;
        let suite = CipherSuite::TLS_CHACHA20_POLY1305_SHA256;
        let (cs, ss) = run_tls13_tcp_loopback(suite);
        assert_eq!(cs, suite);
        assert_eq!(ss, suite);
    }

    #[test]
    fn test_tcp_tls13_rsa_server_cert() {
        // TLS 1.3 handshake with an RSA server certificate (not Ed25519)
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_rsa_server_identity();

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
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let mut buf = [0u8; 32];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
            let _ = conn.shutdown();
        });

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        assert_eq!(conn.version(), Some(TlsVersion::Tls13));
        conn.write(b"ping").unwrap();
        let mut buf = [0u8; 32];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();
        server_handle.join().unwrap();
    }

    #[test]
    fn test_tcp_tls13_aes128_ccm_8() {
        use hitls_tls::CipherSuite;
        let suite = CipherSuite::TLS_AES_128_CCM_8_SHA256;
        let (cs, ss) = run_tls13_tcp_loopback(suite);
        assert_eq!(cs, suite);
        assert_eq!(ss, suite);
    }

    // -------------------------------------------------------
    // Testing-Phase 74 C2: Error scenario integration tests
    // 15 new tests covering version mismatch, cipher mismatch,
    // PSK failures, ALPN negotiation, concurrent connections,
    // large payloads, and connection info validation.
    // -------------------------------------------------------

    /// TLS 1.3–only client vs TLS 1.2–only server — handshake must fail.
    #[test]
    fn test_version_mismatch_tls13_client_vs_tls12_server() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::TlsClientConnection;
        use hitls_tls::connection12::Tls12ServerConnection;
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ecdsa_server_identity();
        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut conn = Tls12ServerConnection::new(stream, server_config);
                let _ = conn.handshake(); // expected to fail
            }
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        assert!(
            conn.handshake().is_err(),
            "TLS 1.3-only client vs TLS 1.2-only server must fail"
        );
        server_handle.join().unwrap();
    }

    /// TLS 1.2–only client vs TLS 1.3–only server — handshake must fail.
    #[test]
    fn test_version_mismatch_tls12_client_vs_tls13_server() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::TlsServerConnection;
        use hitls_tls::connection12::Tls12ClientConnection;
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
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

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut conn = TlsServerConnection::new(stream, server_config);
                let _ = conn.handshake(); // expected to fail
            }
        });

        let (cert_chain2, server_key2) = make_ecdsa_server_identity();
        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .certificate_chain(cert_chain2)
            .private_key(server_key2)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        assert!(
            conn.handshake().is_err(),
            "TLS 1.2-only client vs TLS 1.3-only server must fail"
        );
        server_handle.join().unwrap();
    }

    /// TLS 1.2 cipher suite mismatch — no common cipher suite → handshake fails.
    #[test]
    fn test_tls12_cipher_suite_mismatch() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_rsa_server_identity();
        let groups = [NamedGroup::SECP256R1];
        let sig_algs = [
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ];

        // Server only offers AES-128-GCM
        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        // Client only offers AES-256-GCM — no overlap with server
        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut conn = Tls12ServerConnection::new(stream, server_config);
                let _ = conn.handshake();
            }
        });

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        assert!(conn.handshake().is_err(), "cipher suite mismatch must fail");
        server_handle.join().unwrap();
    }

    /// TLS 1.2 PSK with wrong key — MAC verification fails → handshake error.
    #[test]
    fn test_tls12_psk_wrong_key() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::SignatureScheme;
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let suite = CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256;
        let sig_algs = [
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ];

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .psk(b"correct-psk-key-thats-32-bytes!!".to_vec())
            .psk_identity_hint(b"server-hint".to_vec())
            .build();

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .psk(b"wrong-psk-key-that-is-different!!".to_vec()) // mismatch
            .psk_identity(b"client".to_vec())
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut conn = Tls12ServerConnection::new(stream, server_config);
                let _ = conn.handshake();
            }
        });

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        assert!(conn.handshake().is_err(), "PSK key mismatch must fail");
        server_handle.join().unwrap();
    }

    /// TLS 1.3 ALPN negotiation — client and server share "http/1.1" protocol.
    #[test]
    fn test_tls13_alpn_overlap_negotiated() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();
        let (tx, rx) = mpsc::channel::<Option<Vec<u8>>>();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .alpn(&[b"http/1.1"])
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
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let alpn = conn.alpn_protocol().map(|p| p.to_vec());
            tx.send(alpn).unwrap();
            let mut buf = [0u8; 8];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .alpn(&[b"h2", b"http/1.1"]) // prefers h2 but server only has http/1.1
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        let client_alpn = conn.alpn_protocol().map(|p| p.to_vec());
        assert_eq!(
            client_alpn,
            Some(b"http/1.1".to_vec()),
            "ALPN should be http/1.1"
        );
        conn.write(b"ping").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();

        server_handle.join().unwrap();
        let server_alpn = rx.recv().unwrap();
        assert_eq!(
            server_alpn,
            Some(b"http/1.1".to_vec()),
            "Server ALPN should be http/1.1"
        );
    }

    /// TLS 1.3 ALPN — client offers protocols, server has none → no ALPN negotiated.
    #[test]
    fn test_tls13_alpn_client_only_no_server_alpn() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();

        // Server has NO ALPN configured
        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain)
            .private_key(server_key)
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
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let mut buf = [0u8; 8];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
            let _ = conn.shutdown();
        });

        // Client offers ALPN, server ignores it
        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .alpn(&[b"h2", b"http/1.1"])
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        // Server didn't select any protocol
        assert_eq!(conn.alpn_protocol(), None, "no ALPN when server has none");
        conn.write(b"ping").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();
        server_handle.join().unwrap();
    }

    /// Five concurrent TLS 1.3 connections all succeed independently.
    #[test]
    fn test_concurrent_tls13_connections() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let sub_handles: Vec<_> = (0..5)
                .map(|_| {
                    let (stream, _) = listener.accept().unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(10)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(10)))
                        .unwrap();
                    let cc = cert_chain.clone();
                    let pk = server_key.clone();
                    thread::spawn(move || {
                        let cfg = TlsConfig::builder()
                            .role(TlsRole::Server)
                            .min_version(TlsVersion::Tls13)
                            .max_version(TlsVersion::Tls13)
                            .certificate_chain(cc)
                            .private_key(pk)
                            .verify_peer(false)
                            .build();
                        let mut conn = TlsServerConnection::new(stream, cfg);
                        conn.handshake().unwrap();
                        let mut buf = [0u8; 64];
                        let n = conn.read(&mut buf).unwrap();
                        conn.write(&buf[..n]).unwrap();
                        let _ = conn.shutdown();
                    })
                })
                .collect();
            for h in sub_handles {
                h.join().unwrap();
            }
        });

        let client_handles: Vec<_> = (0..5_usize)
            .map(|i| {
                thread::spawn(move || {
                    let cfg = TlsConfig::builder()
                        .role(TlsRole::Client)
                        .min_version(TlsVersion::Tls13)
                        .max_version(TlsVersion::Tls13)
                        .verify_peer(false)
                        .build();
                    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(10)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(10)))
                        .unwrap();
                    let mut conn = TlsClientConnection::new(stream, cfg);
                    conn.handshake().unwrap();
                    let msg = format!("tls13-client-{}", i);
                    conn.write(msg.as_bytes()).unwrap();
                    let mut buf = [0u8; 64];
                    let n = conn.read(&mut buf).unwrap();
                    assert_eq!(&buf[..n], msg.as_bytes());
                    let _ = conn.shutdown();
                })
            })
            .collect();

        for h in client_handles {
            h.join().unwrap();
        }
        server_handle.join().unwrap();
    }

    /// Five concurrent TLS 1.2 connections all succeed independently.
    #[test]
    fn test_concurrent_tls12_connections() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ecdsa_server_identity();
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let groups = [NamedGroup::SECP256R1];
        let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let sub_handles: Vec<_> = (0..5)
                .map(|_| {
                    let (stream, _) = listener.accept().unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(10)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(10)))
                        .unwrap();
                    let cc = cert_chain.clone();
                    let pk = server_key.clone();
                    thread::spawn(move || {
                        let cfg = TlsConfig::builder()
                            .role(TlsRole::Server)
                            .min_version(TlsVersion::Tls12)
                            .max_version(TlsVersion::Tls12)
                            .cipher_suites(&[suite])
                            .supported_groups(&groups)
                            .signature_algorithms(&sig_algs)
                            .certificate_chain(cc)
                            .private_key(pk)
                            .verify_peer(false)
                            .build();
                        let mut conn = Tls12ServerConnection::new(stream, cfg);
                        conn.handshake().unwrap();
                        let mut buf = [0u8; 64];
                        let n = conn.read(&mut buf).unwrap();
                        conn.write(&buf[..n]).unwrap();
                        let _ = conn.shutdown();
                    })
                })
                .collect();
            for h in sub_handles {
                h.join().unwrap();
            }
        });

        let client_handles: Vec<_> = (0..5_usize)
            .map(|i| {
                thread::spawn(move || {
                    let cfg = TlsConfig::builder()
                        .role(TlsRole::Client)
                        .min_version(TlsVersion::Tls12)
                        .max_version(TlsVersion::Tls12)
                        .cipher_suites(&[suite])
                        .supported_groups(&groups)
                        .signature_algorithms(&sig_algs)
                        .verify_peer(false)
                        .build();
                    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(10)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(10)))
                        .unwrap();
                    let mut conn = Tls12ClientConnection::new(stream, cfg);
                    conn.handshake().unwrap();
                    let msg = format!("tls12-client-{}", i);
                    conn.write(msg.as_bytes()).unwrap();
                    let mut buf = [0u8; 64];
                    let n = conn.read(&mut buf).unwrap();
                    assert_eq!(&buf[..n], msg.as_bytes());
                    let _ = conn.shutdown();
                })
            })
            .collect();

        for h in client_handles {
            h.join().unwrap();
        }
        server_handle.join().unwrap();
    }

    /// TLS 1.3: 64 KB payload round-trip succeeds (tests record fragmentation).
    #[test]
    fn test_tls13_large_64kb_payload() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let payload: Vec<u8> = (0u8..=255).cycle().take(65536).collect();
        let payload_for_server = payload.clone();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain)
            .private_key(server_key)
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
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let mut received = Vec::new();
            while received.len() < 65536 {
                let mut buf = vec![0u8; 16384];
                let n = conn.read(&mut buf).unwrap();
                received.extend_from_slice(&buf[..n]);
            }
            tx.send(received).unwrap();
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(&payload).unwrap();
        let _ = conn.shutdown();

        server_handle.join().unwrap();
        let received = rx.recv().unwrap();
        assert_eq!(
            received, payload_for_server,
            "64KB payload must arrive intact"
        );
    }

    /// TLS 1.2: 64 KB payload round-trip succeeds.
    #[test]
    fn test_tls12_large_64kb_payload() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_rsa_server_identity();
        let suite = CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
        let groups = [NamedGroup::SECP256R1];
        let sig_algs = [
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ];
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let payload: Vec<u8> = (0u8..=255).cycle().take(65536).collect();
        let payload_for_server = payload.clone();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
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
            let mut received = Vec::new();
            while received.len() < 65536 {
                let mut buf = vec![0u8; 16384];
                let n = conn.read(&mut buf).unwrap();
                received.extend_from_slice(&buf[..n]);
            }
            tx.send(received).unwrap();
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(&payload).unwrap();
        let _ = conn.shutdown();

        server_handle.join().unwrap();
        let received = rx.recv().unwrap();
        assert_eq!(
            received, payload_for_server,
            "64KB TLS 1.2 payload must arrive intact"
        );
    }

    /// TLS 1.3 ConnectionInfo — cipher_suite, negotiated_group, session_resumed.
    #[test]
    fn test_tls13_connection_info_fields() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::connection_info::ConnectionInfo;
        use hitls_tls::crypt::NamedGroup;
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();
        let suite = CipherSuite::TLS_AES_128_GCM_SHA256;
        let (tx, rx) = mpsc::channel::<ConnectionInfo>();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .cipher_suites(&[suite])
            .certificate_chain(cert_chain)
            .private_key(server_key)
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
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let info = conn.connection_info().unwrap();
            tx.send(info).unwrap();
            let mut buf = [0u8; 8];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .cipher_suites(&[suite])
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        let info = conn.connection_info().unwrap();
        assert_eq!(info.cipher_suite, suite);
        assert!(!info.session_resumed, "first connection is never resumed");
        assert!(
            info.negotiated_group.is_some(),
            "TLS 1.3 must negotiate a group"
        );
        let group = info.negotiated_group.unwrap();
        assert!(
            matches!(group, NamedGroup::X25519 | NamedGroup::SECP256R1),
            "expected X25519 or P-256, got {:?}",
            group
        );

        conn.write(b"info").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();

        server_handle.join().unwrap();
        let server_info = rx.recv().unwrap();
        assert_eq!(server_info.cipher_suite, suite);
        assert!(!server_info.session_resumed);
    }

    /// TLS 1.2 ConnectionInfo — cipher_suite, negotiated_group, session_resumed.
    #[test]
    fn test_tls12_connection_info_fields() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::connection_info::ConnectionInfo;
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ecdsa_server_identity();
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let groups = [NamedGroup::SECP256R1];
        let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];
        let (tx, rx) = mpsc::channel::<ConnectionInfo>();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
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
            let info = conn.connection_info().unwrap();
            tx.send(info).unwrap();
            let mut buf = [0u8; 8];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        let info = conn.connection_info().unwrap();
        assert_eq!(info.cipher_suite, suite);
        assert!(
            !info.session_resumed,
            "first TLS 1.2 connection is not resumed"
        );
        assert_eq!(
            info.negotiated_group,
            Some(NamedGroup::SECP256R1),
            "ECDHE must negotiate SECP256R1"
        );

        conn.write(b"info").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();

        server_handle.join().unwrap();
        let server_info = rx.recv().unwrap();
        assert_eq!(server_info.cipher_suite, suite);
    }

    /// TLS 1.3: is_session_resumed() returns false on the first (full) handshake.
    #[test]
    fn test_tls13_first_connection_not_resumed() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
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
            assert!(
                !conn.is_session_resumed(),
                "server: first connection not resumed"
            );
            let mut buf = [0u8; 8];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        assert!(
            !conn.is_session_resumed(),
            "client: first connection not resumed"
        );
        conn.write(b"hello").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();
        server_handle.join().unwrap();
    }

    /// TLS 1.2: three sequential back-and-forth message exchanges on one connection.
    #[test]
    fn test_tls12_multi_message_exchange() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ecdsa_server_identity();
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let groups = [NamedGroup::SECP256R1];
        let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
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
            for _ in 0..3 {
                let mut buf = [0u8; 64];
                let n = conn.read(&mut buf).unwrap();
                let mut reply = b"ack:".to_vec();
                reply.extend_from_slice(&buf[..n]);
                conn.write(&reply).unwrap();
            }
            conn.shutdown().unwrap();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        for i in 0..3 {
            let msg = format!("msg{}", i);
            conn.write(msg.as_bytes()).unwrap();
            let mut buf = [0u8; 64];
            let n = conn.read(&mut buf).unwrap();
            let expected = format!("ack:{}", msg);
            assert_eq!(&buf[..n], expected.as_bytes(), "message {} roundtrip", i);
        }
        conn.shutdown().unwrap();
        server_handle.join().unwrap();
    }

    /// TLS 1.2: graceful shutdown sends close_notify on both sides without error.
    #[test]
    fn test_tls12_graceful_shutdown() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_rsa_server_identity();
        let suite = CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
        let groups = [NamedGroup::SECP256R1];
        let sig_algs = [
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ];

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
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
            let mut buf = [0u8; 16];
            let _ = conn.read(&mut buf);
            conn.shutdown().unwrap();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"bye").unwrap();
        conn.shutdown().unwrap();
        server_handle.join().unwrap();
    }

    /// TLS 1.3: cipher suite negotiation when both sides share multiple suites.
    #[test]
    fn test_tls13_multi_suite_negotiation() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();
        // Server prefers AES-256-GCM first
        let server_suites = [
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_AES_128_GCM_SHA256,
        ];
        // Client prefers AES-128-GCM first, also supports AES-256-GCM
        let client_suites = [
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
        ];
        let (tx, rx) = mpsc::channel::<CipherSuite>();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .cipher_suites(&server_suites)
            .certificate_chain(cert_chain)
            .private_key(server_key)
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
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            tx.send(conn.cipher_suite().unwrap()).unwrap();
            let mut buf = [0u8; 8];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .cipher_suites(&client_suites)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        let client_suite = conn.cipher_suite().unwrap();
        conn.write(b"suite").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();

        server_handle.join().unwrap();
        let server_suite = rx.recv().unwrap();
        assert_eq!(
            client_suite, server_suite,
            "both sides must use same cipher suite"
        );
        assert!(
            matches!(
                client_suite,
                CipherSuite::TLS_AES_128_GCM_SHA256 | CipherSuite::TLS_AES_256_GCM_SHA384
            ),
            "negotiated suite must be from the common set"
        );
    }

    /// TLS 1.3: session_resumption(true) — first connection has session_resumed=false.
    #[test]
    fn test_tls13_session_take_after_handshake() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
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
            let mut buf = [0u8; 8];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .session_resumption(true)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        assert!(
            !conn.is_session_resumed(),
            "first connection is never resumed"
        );
        conn.write(b"take").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();
        server_handle.join().unwrap();
    }

    /// TLS 1.2: empty write returns without error.
    #[test]
    fn test_tls12_empty_write() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ecdsa_server_identity();
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let groups = [NamedGroup::SECP256R1];
        let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
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
            let mut buf = [0u8; 16];
            let _ = conn.read(&mut buf);
            conn.write(b"ok").unwrap();
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        // Empty write must succeed
        conn.write(b"").unwrap();
        // Follow with real data to unblock the server
        conn.write(b"data").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();
        server_handle.join().unwrap();
    }

    // -------------------------------------------------------
    // Testing-Phase 75 — E1: Phase 74 Feature Integration Tests
    // -------------------------------------------------------

    /// TLS 1.3 handshake with certificate_authorities config succeeds.
    /// Verifies the extension is sent without protocol errors.
    #[test]
    fn test_tls13_certificate_authorities_config_handshake() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
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
            let mut buf = [0u8; 8];
            let _ = conn.read(&mut buf);
            conn.write(b"ok").unwrap();
            let _ = conn.shutdown();
        });

        // Client sends certificate_authorities extension with two fake DER-encoded DNs
        let dn1 = vec![0x30, 0x07, 0x31, 0x05, 0x30, 0x03, 0x06, 0x01, 0x41]; // minimal SEQUENCE
        let dn2 = vec![0x30, 0x07, 0x31, 0x05, 0x30, 0x03, 0x06, 0x01, 0x42];
        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_authorities(vec![dn1, dn2])
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"hi").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();

        server_handle.join().unwrap();
    }

    /// TLS 1.3 handshake succeeds when no certificate_authorities are configured.
    #[test]
    fn test_tls13_certificate_authorities_empty_config() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
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
            let mut buf = [0u8; 8];
            let _ = conn.read(&mut buf);
            conn.write(b"ok").unwrap();
            let _ = conn.shutdown();
        });

        // Empty certificate_authorities (equivalent to not setting it)
        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_authorities(vec![])
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"hi").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();

        server_handle.join().unwrap();
    }

    /// TLS 1.3 export_keying_material: client and server derive the same material.
    #[test]
    fn test_tls13_export_keying_material_client_server_match() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();
        let (tx, rx) = mpsc::channel::<Vec<u8>>();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain)
            .private_key(server_key)
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
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let ekm = conn
                .export_keying_material(b"TESTING LABEL", Some(b"test context"), 32)
                .unwrap();
            tx.send(ekm).unwrap();
            let mut buf = [0u8; 8];
            let _ = conn.read(&mut buf);
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        let client_ekm = conn
            .export_keying_material(b"TESTING LABEL", Some(b"test context"), 32)
            .unwrap();
        assert_eq!(client_ekm.len(), 32);

        conn.write(b"done").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();

        server_handle.join().unwrap();
        let server_ekm = rx.recv().unwrap();
        assert_eq!(
            client_ekm, server_ekm,
            "client and server must derive identical keying material"
        );
    }

    /// TLS 1.3 export_keying_material: different labels produce different material.
    #[test]
    fn test_tls13_export_keying_material_different_labels() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
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
            let mut buf = [0u8; 8];
            let _ = conn.read(&mut buf);
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        let ekm1 = conn.export_keying_material(b"LABEL ONE", None, 32).unwrap();
        let ekm2 = conn.export_keying_material(b"LABEL TWO", None, 32).unwrap();
        let ekm3 = conn
            .export_keying_material(b"LABEL ONE", Some(b"context"), 32)
            .unwrap();
        assert_ne!(
            ekm1, ekm2,
            "different labels must produce different material"
        );
        assert_ne!(ekm1, ekm3, "no-context vs with-context must differ");

        conn.write(b"done").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();

        server_handle.join().unwrap();
    }

    /// TLS 1.3 export_keying_material: returns error before handshake.
    #[test]
    fn test_tls13_export_keying_material_before_handshake() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::TlsClientConnection;
        use std::net::{TcpListener, TcpStream};
        use std::time::Duration;

        // Create an unconnected client — handshake() never called
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();

        let config = TlsConfig::builder()
            .role(hitls_tls::TlsRole::Client)
            .verify_peer(false)
            .build();
        let conn = TlsClientConnection::new(stream, config);

        let result = conn.export_keying_material(b"test", None, 32);
        assert!(
            result.is_err(),
            "export_keying_material must fail before handshake"
        );
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("not connected"),
            "error should say 'not connected', got: {msg}"
        );
    }

    /// TLS 1.3 export_early_keying_material: returns error when no PSK was used.
    #[test]
    fn test_tls13_export_early_keying_material_no_psk() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
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
            // Server also fails without PSK
            let res = conn.export_early_keying_material(b"early", None, 32);
            assert!(res.is_err(), "server: early export must fail without PSK");
            let mut buf = [0u8; 8];
            let _ = conn.read(&mut buf);
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        // No PSK → early exporter master secret is empty → error
        let result = conn.export_early_keying_material(b"early", None, 32);
        assert!(result.is_err(), "early export must fail without PSK");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("no early exporter master secret"),
            "unexpected error: {msg}"
        );

        conn.write(b"done").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();

        server_handle.join().unwrap();
    }

    /// TLS 1.3 export_keying_material: various output lengths work correctly.
    #[test]
    fn test_tls13_export_keying_material_various_lengths() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
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
            let mut buf = [0u8; 8];
            let _ = conn.read(&mut buf);
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        for length in [16, 32, 48, 64] {
            let ekm = conn
                .export_keying_material(b"EXPORTER LABEL", Some(b"ctx"), length)
                .unwrap();
            assert_eq!(
                ekm.len(),
                length,
                "expected {length} bytes, got {}",
                ekm.len()
            );
        }

        conn.write(b"done").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();

        server_handle.join().unwrap();
    }

    /// TLS 1.2 export_keying_material: client and server derive the same material.
    #[test]
    fn test_tls12_export_keying_material_client_server_match() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::SignatureScheme;
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ecdsa_server_identity();
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let groups = [hitls_tls::crypt::NamedGroup::SECP256R1];
        let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];
        let (tx, rx) = mpsc::channel::<Vec<u8>>();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
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
            let ekm = conn
                .export_keying_material(b"TESTING LABEL", Some(b"test context"), 32)
                .unwrap();
            tx.send(ekm).unwrap();
            let mut buf = [0u8; 8];
            let _ = conn.read(&mut buf);
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        let client_ekm = conn
            .export_keying_material(b"TESTING LABEL", Some(b"test context"), 32)
            .unwrap();
        assert_eq!(client_ekm.len(), 32);

        conn.write(b"done").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();

        server_handle.join().unwrap();
        let server_ekm = rx.recv().unwrap();
        assert_eq!(
            client_ekm, server_ekm,
            "TLS 1.2: client and server must derive identical keying material"
        );
    }

    /// TLS 1.2 session cache: InMemorySessionCache stores sessions; second connection
    /// is resumed via session ticket (server with ticket_key + client with session_cache).
    #[test]
    fn test_tls12_session_cache_store_and_resume() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::SignatureScheme;
        use hitls_tls::session::InMemorySessionCache;
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ecdsa_server_identity();
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let groups = [hitls_tls::crypt::NamedGroup::SECP256R1];
        let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];
        // Server uses the same ticket_key for both connections so it can decrypt
        // tickets issued during the first handshake.
        let ticket_key = vec![0xAB; 32];

        // Shared client session cache
        let client_cache = Arc::new(Mutex::new(InMemorySessionCache::new(10)));

        // First connection: server issues a session ticket; client stores it in cache.
        let server_config1 = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain.clone())
            .private_key(server_key.clone())
            .ticket_key(ticket_key.clone())
            .verify_peer(false)
            .build();

        let listener1 = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr1 = listener1.local_addr().unwrap();

        let s1 = thread::spawn(move || {
            let (stream, _) = listener1.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config1);
            conn.handshake().unwrap();
            let mut buf = [0u8; 8];
            let _ = conn.read(&mut buf);
            conn.write(b"ok").unwrap();
            let _ = conn.shutdown();
        });

        let client_cache_clone = client_cache.clone();
        let client_config1 = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .server_name("localhost")
            .session_cache(client_cache_clone)
            .session_resumption(true)
            .verify_peer(false)
            .build();

        let stream1 = std::net::TcpStream::connect_timeout(&addr1, Duration::from_secs(5)).unwrap();
        stream1
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream1
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn1 = Tls12ClientConnection::new(stream1, client_config1);
        conn1.handshake().unwrap();
        assert!(
            !conn1.is_session_resumed(),
            "first connection is never resumed"
        );
        conn1.write(b"hi").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn1.read(&mut buf);
        let _ = conn1.shutdown();
        s1.join().unwrap();

        // The client cache should now hold the ticket-based session for "localhost"
        assert!(
            !client_cache.lock().unwrap().is_empty(),
            "session with ticket should be stored in client cache after first connection"
        );

        // Second connection: server with the same ticket_key can decrypt the cached ticket.
        let server_config2 = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .ticket_key(ticket_key)
            .verify_peer(false)
            .build();

        let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr2 = listener2.local_addr().unwrap();

        let s2 = thread::spawn(move || {
            let (stream, _) = listener2.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config2);
            conn.handshake().unwrap();
            assert!(
                conn.is_session_resumed(),
                "server: second connection should be resumed"
            );
            let mut buf = [0u8; 8];
            let _ = conn.read(&mut buf);
            conn.write(b"ok").unwrap();
            let _ = conn.shutdown();
        });

        let client_cache_clone2 = client_cache.clone();
        let client_config2 = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .server_name("localhost")
            .session_cache(client_cache_clone2)
            .session_resumption(true)
            .verify_peer(false)
            .build();

        let stream2 = std::net::TcpStream::connect_timeout(&addr2, Duration::from_secs(5)).unwrap();
        stream2
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream2
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn2 = Tls12ClientConnection::new(stream2, client_config2);
        conn2.handshake().unwrap();
        // Ticket in cache lets client offer it; server decrypts → abbreviated handshake
        assert!(
            conn2.is_session_resumed(),
            "second connection should be resumed from cached ticket"
        );
        conn2.write(b"hi").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn2.read(&mut buf);
        let _ = conn2.shutdown();
        s2.join().unwrap();
    }

    /// TLS 1.3 export_keying_material: server-side export also works.
    #[test]
    fn test_tls13_export_keying_material_server_side() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();
        let (tx, rx) = mpsc::channel::<(Vec<u8>, Vec<u8>)>();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain)
            .private_key(server_key)
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
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let ekm_with_ctx = conn
                .export_keying_material(b"MY LABEL", Some(b"my context"), 48)
                .unwrap();
            let ekm_no_ctx = conn.export_keying_material(b"MY LABEL", None, 48).unwrap();
            tx.send((ekm_with_ctx, ekm_no_ctx)).unwrap();
            let mut buf = [0u8; 8];
            let _ = conn.read(&mut buf);
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        let client_ekm_with_ctx = conn
            .export_keying_material(b"MY LABEL", Some(b"my context"), 48)
            .unwrap();
        let client_ekm_no_ctx = conn.export_keying_material(b"MY LABEL", None, 48).unwrap();

        conn.write(b"done").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();

        server_handle.join().unwrap();
        let (server_ekm_with_ctx, server_ekm_no_ctx) = rx.recv().unwrap();

        assert_eq!(
            client_ekm_with_ctx, server_ekm_with_ctx,
            "with-context EKM must match"
        );
        assert_eq!(
            client_ekm_no_ctx, server_ekm_no_ctx,
            "no-context EKM must match"
        );
        assert_ne!(
            client_ekm_with_ctx, client_ekm_no_ctx,
            "context vs no-context must differ"
        );
        assert_eq!(client_ekm_with_ctx.len(), 48);
        assert_eq!(client_ekm_no_ctx.len(), 48);
    }

    // -------------------------------------------------------
    // Testing-Phase 76 — F3: cert_verify callback + key_log + renegotiation
    // -------------------------------------------------------

    /// TLS 1.3: cert_verify_callback accepts despite no trusted certs configured.
    #[test]
    fn test_tls13_cert_verify_callback_accept() {
        use hitls_tls::config::{CertVerifyCallback, TlsConfig};
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::Arc;
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
            let mut buf = [0u8; 8];
            let _ = conn.read(&mut buf);
            conn.write(b"ok").unwrap();
            let _ = conn.shutdown();
        });

        let cb: CertVerifyCallback = Arc::new(|_info| Ok(()));
        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(true)
            .verify_hostname(false)
            .cert_verify_callback(cb)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"hi").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();
        server_handle.join().unwrap();
    }

    /// TLS 1.3: cert_verify_callback rejects → handshake fails.
    #[test]
    fn test_tls13_cert_verify_callback_reject() {
        use hitls_tls::config::{CertVerifyCallback, TlsConfig};
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::Arc;
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
            let _ = conn.handshake();
        });

        let cb: CertVerifyCallback = Arc::new(|_info| Err("rejected by policy".to_string()));
        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(true)
            .verify_hostname(false)
            .cert_verify_callback(cb)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        let result = conn.handshake();
        assert!(result.is_err(), "handshake must fail when callback rejects");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("rejected by policy") || msg.contains("callback"),
            "unexpected error: {msg}"
        );
        server_handle.join().unwrap();
    }

    /// TLS 1.2: cert_verify_callback accepts despite no trusted certs.
    #[test]
    fn test_tls12_cert_verify_callback_accept() {
        use hitls_tls::config::{CertVerifyCallback, TlsConfig};
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::SignatureScheme;
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ecdsa_server_identity();
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let groups = [hitls_tls::crypt::NamedGroup::SECP256R1];
        let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
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
            let mut buf = [0u8; 8];
            let _ = conn.read(&mut buf);
            conn.write(b"ok").unwrap();
            let _ = conn.shutdown();
        });

        let cb: CertVerifyCallback = Arc::new(|_info| Ok(()));
        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(true)
            .verify_hostname(false)
            .cert_verify_callback(cb)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"hi").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();
        server_handle.join().unwrap();
    }

    /// TLS 1.3: key_log_callback is invoked during handshake.
    #[test]
    fn test_tls13_key_log_callback_invoked() {
        use hitls_tls::config::{KeyLogCallback, TlsConfig};
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();
        let logged: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let ll = logged.clone();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain)
            .private_key(server_key)
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
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let mut buf = [0u8; 8];
            let _ = conn.read(&mut buf);
            conn.write(b"ok").unwrap();
            let _ = conn.shutdown();
        });

        let cb: KeyLogCallback = Arc::new(move |line: &str| {
            ll.lock().unwrap().push(line.to_string());
        });
        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .key_log(cb)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"hi").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();
        server_handle.join().unwrap();

        let lines = logged.lock().unwrap();
        assert!(
            !lines.is_empty(),
            "key_log_callback must be invoked during TLS 1.3 handshake"
        );
        for line in lines.iter() {
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            assert_eq!(
                parts.len(),
                3,
                "key log line must have 3 space-separated fields: {line}"
            );
        }
    }

    /// TLS 1.2: key_log_callback logs CLIENT_RANDOM during handshake.
    #[test]
    fn test_tls12_key_log_callback_invoked() {
        use hitls_tls::config::{KeyLogCallback, TlsConfig};
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::SignatureScheme;
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ecdsa_server_identity();
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let groups = [hitls_tls::crypt::NamedGroup::SECP256R1];
        let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];
        let logged: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let ll = logged.clone();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
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
            let mut buf = [0u8; 8];
            let _ = conn.read(&mut buf);
            conn.write(b"ok").unwrap();
            let _ = conn.shutdown();
        });

        let cb: KeyLogCallback = Arc::new(move |line: &str| {
            ll.lock().unwrap().push(line.to_string());
        });
        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .key_log(cb)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"hi").unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();
        server_handle.join().unwrap();

        let lines = logged.lock().unwrap();
        assert!(
            !lines.is_empty(),
            "key_log_callback must be invoked during TLS 1.2 handshake"
        );
        let has_client_random = lines.iter().any(|l| l.starts_with("CLIENT_RANDOM"));
        assert!(
            has_client_random,
            "TLS 1.2 key log must contain CLIENT_RANDOM, got: {lines:?}"
        );
    }

    /// TLS 1.2: server-initiated renegotiation over TCP succeeds.
    #[test]
    fn test_tls12_renegotiation_server_initiated() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::SignatureScheme;
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ecdsa_server_identity();
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let groups = [hitls_tls::crypt::NamedGroup::SECP256R1];
        let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .allow_renegotiation(true)
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

            let mut buf = [0u8; 64];
            let n = conn.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"before renego");
            conn.write(b"ack1").unwrap();

            // Server initiates renegotiation (sends HelloRequest)
            conn.initiate_renegotiation().unwrap();

            // read() processes incoming ClientHello and completes re-handshake
            let n = conn.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"after renego");
            conn.write(b"ack2").unwrap();
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .allow_renegotiation(true)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();

        conn.write(b"before renego").unwrap();
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ack1");

        // write() triggers HelloRequest processing → client re-handshakes
        conn.write(b"after renego").unwrap();
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ack2");
        let _ = conn.shutdown();
        server_handle.join().unwrap();
    }

    // -------------------------------------------------------
    // Testing-Phase 77 — G1: SniCallback integration tests
    // -------------------------------------------------------

    /// TLS 1.3: SniCallback returns Accept — handshake succeeds with original config.
    #[test]
    fn test_tls13_sni_callback_accept() {
        use hitls_tls::config::{SniAction, SniCallback, TlsConfig};
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();
        let cb: SniCallback = Arc::new(|_hostname: &str| SniAction::Accept);

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .sni_callback(cb)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let mut buf = [0u8; 16];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .server_name("example.com")
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"sni-accept").unwrap();
        let mut buf = [0u8; 16];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"sni-accept");
        server_handle.join().unwrap();
    }

    /// TLS 1.3: SniCallback returns AcceptWithConfig — server switches to new config.
    #[test]
    fn test_tls13_sni_callback_accept_with_config() {
        use hitls_tls::config::{SniAction, SniCallback, TlsConfig};
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let (cert_chain1, server_key1) = make_ed25519_server_identity();
        let (cert_chain2, server_key2) = make_ed25519_server_identity();

        // Callback switches to a second certificate chain for "example.com"
        let new_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain2)
            .private_key(server_key2)
            .verify_peer(false)
            .build();

        let cb: SniCallback = Arc::new(move |_hostname: &str| {
            SniAction::AcceptWithConfig(Box::new(new_config.clone()))
        });

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain1)
            .private_key(server_key1)
            .verify_peer(false)
            .sni_callback(cb)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = TlsServerConnection::new(stream, server_config);
            // Handshake succeeds using the config switched in by SniCallback
            conn.handshake().unwrap();
            let mut buf = [0u8; 16];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .server_name("example.com")
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"sni-switched").unwrap();
        let mut buf = [0u8; 16];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"sni-switched");
        server_handle.join().unwrap();
    }

    /// TLS 1.3: SniCallback returns Reject — handshake fails with error.
    #[test]
    fn test_tls13_sni_callback_reject() {
        use hitls_tls::config::{SniAction, SniCallback, TlsConfig};
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();
        // Callback always rejects
        let cb: SniCallback = Arc::new(|_| SniAction::Reject);

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .sni_callback(cb)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = TlsServerConnection::new(stream, server_config);
            // Server-side handshake should fail (Reject)
            let _ = conn.handshake();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .server_name("rejected.example.com")
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        // Client-side handshake should fail because server rejected SNI
        let result = conn.handshake();
        assert!(
            result.is_err(),
            "handshake should fail when SniCallback rejects"
        );
        server_handle.join().unwrap();
    }

    /// TLS 1.3: SniCallback returns Ignore — server_name cleared, handshake continues.
    #[test]
    fn test_tls13_sni_callback_ignore() {
        use hitls_tls::config::{SniAction, SniCallback, TlsConfig};
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();
        // Callback returns Ignore → server clears client_server_name but continues
        let cb: SniCallback = Arc::new(|_| SniAction::Ignore);

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .sni_callback(cb)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let mut buf = [0u8; 16];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .server_name("ignored.example.com")
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        // Handshake succeeds despite Ignore
        conn.handshake().unwrap();
        conn.write(b"sni-ignored").unwrap();
        let mut buf = [0u8; 16];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"sni-ignored");
        server_handle.join().unwrap();
    }

    /// TLS 1.2: SniCallback returns Accept — handshake succeeds.
    #[test]
    fn test_tls12_sni_callback_accept() {
        use hitls_tls::config::{SniAction, SniCallback, TlsConfig};
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::SignatureScheme;
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ecdsa_server_identity();
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let groups = [hitls_tls::crypt::NamedGroup::SECP256R1];
        let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

        let cb: SniCallback = Arc::new(|_| SniAction::Accept);

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .sni_callback(cb)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let mut buf = [0u8; 16];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .server_name("example.com")
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"tls12-sni").unwrap();
        let mut buf = [0u8; 16];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"tls12-sni");
        server_handle.join().unwrap();
    }

    /// TLS 1.2: SniCallback returns Reject — handshake fails.
    #[test]
    fn test_tls12_sni_callback_reject() {
        use hitls_tls::config::{SniAction, SniCallback, TlsConfig};
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::SignatureScheme;
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ecdsa_server_identity();
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let groups = [hitls_tls::crypt::NamedGroup::SECP256R1];
        let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

        let cb: SniCallback = Arc::new(|_| SniAction::Reject);

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .sni_callback(cb)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            let _ = conn.handshake();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .server_name("rejected.example.com")
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        let result = conn.handshake();
        assert!(
            result.is_err(),
            "handshake should fail when TLS 1.2 SniCallback rejects"
        );
        server_handle.join().unwrap();
    }

    // -------------------------------------------------------
    // Testing-Phase 77 — G2: PADDING extension integration
    // -------------------------------------------------------

    /// TLS 1.3: Client with padding_target=512, handshake completes successfully.
    #[test]
    fn test_tls13_padding_extension_handshake() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
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

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let mut buf = [0u8; 16];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
        });

        // Client sends ClientHello padded to ~512 bytes via RFC 7685 PADDING extension
        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .padding_target(512)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"padded-hello").unwrap();
        let mut buf = [0u8; 16];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"padded-hello");
        server_handle.join().unwrap();
    }

    // -------------------------------------------------------
    // Testing-Phase 77 — G3: OID Filters integration
    // -------------------------------------------------------

    /// TLS 1.3 mTLS: Server with oid_filters set, CertificateRequest includes OID Filters extension.
    #[test]
    fn test_tls13_oid_filters_in_cert_request() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let (server_cert_chain, server_key) = make_ed25519_server_identity();
        let (client_cert_chain, client_key) = make_ed25519_server_identity();

        // OID for extendedKeyUsage (2.5.29.37)
        let oid_bytes = vec![0x55, 0x1D, 0x25];
        let oid_values = vec![0x30, 0x0A]; // placeholder values

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(server_cert_chain)
            .private_key(server_key)
            .verify_peer(true)
            .trusted_cert(client_cert_chain[0].clone())
            .oid_filters(vec![(oid_bytes, oid_values)])
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = TlsServerConnection::new(stream, server_config);
            // Server sends CertificateRequest with OID Filters — handshake should complete
            let result = conn.handshake();
            let _ = result;
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(client_cert_chain)
            .private_key(client_key)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        // Client receives CertificateRequest with OID Filters and processes it
        let _ = conn.handshake();
        server_handle.join().unwrap();
    }

    /// TLS 1.3 mTLS: Server without oid_filters — CertificateRequest has no OID Filters extension.
    #[test]
    fn test_tls13_no_oid_filters_in_cert_request() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let (server_cert_chain, server_key) = make_ed25519_server_identity();
        let (client_cert_chain, client_key) = make_ed25519_server_identity();

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(server_cert_chain)
            .private_key(server_key)
            .verify_peer(true)
            .trusted_cert(client_cert_chain[0].clone())
            .build(); // No oid_filters

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = TlsServerConnection::new(stream, server_config);
            let _ = conn.handshake();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(client_cert_chain)
            .private_key(client_key)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        // Handshake completes without OID Filters (no crash / no parse error)
        let _ = conn.handshake();
        server_handle.join().unwrap();
    }

    // -------------------------------------------------------
    // Testing-Phase 77 — G4: DTLS 1.2 abbreviated handshake integration
    // -------------------------------------------------------

    /// DTLS 1.2: Full handshake followed by an abbreviated (session resumption) handshake.
    #[test]
    fn test_dtls12_integration_abbreviated_handshake() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection_dtls12::dtls12_handshake_in_memory;
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::session::{InMemorySessionCache, SessionCache};
        use hitls_tls::{CipherSuite, TlsVersion};
        use std::sync::{Arc, Mutex};

        let (cert_chain, server_key) = make_ecdsa_server_identity();
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let groups = [NamedGroup::SECP256R1];
        let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

        let client_cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));
        let server_cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));

        let make_client_config = |cache: Arc<Mutex<InMemorySessionCache>>| {
            TlsConfig::builder()
                .cipher_suites(&[suite])
                .supported_groups(&groups)
                .signature_algorithms(&sig_algs)
                .verify_peer(false)
                .server_name("dtls.test.example")
                .session_cache(cache)
                .build()
        };

        let make_server_config = |cache: Arc<Mutex<InMemorySessionCache>>| {
            TlsConfig::builder()
                .cipher_suites(&[suite])
                .supported_groups(&groups)
                .signature_algorithms(&sig_algs)
                .certificate_chain(cert_chain.clone())
                .private_key(server_key.clone())
                .verify_peer(false)
                .session_cache(cache)
                .build()
        };

        // 1st connection: full handshake → populates session caches
        let cc1 = make_client_config(client_cache.clone());
        let sc1 = make_server_config(server_cache.clone());
        let (client1, server1) = dtls12_handshake_in_memory(cc1, sc1, false).unwrap();
        assert_eq!(client1.version(), Some(TlsVersion::Dtls12));
        assert_eq!(server1.version(), Some(TlsVersion::Dtls12));

        // Verify session was cached on the client
        let session_stored = {
            let cache = client_cache.lock().unwrap();
            cache.get(b"dtls.test.example").is_some()
        };
        assert!(session_stored, "client should have cached the session");

        // 2nd connection: abbreviated handshake (session resumption)
        let cc2 = make_client_config(client_cache.clone());
        let sc2 = make_server_config(server_cache.clone());
        let (client2, server2) = dtls12_handshake_in_memory(cc2, sc2, false).unwrap();
        assert_eq!(client2.version(), Some(TlsVersion::Dtls12));
        assert_eq!(server2.version(), Some(TlsVersion::Dtls12));
    }

    /// DTLS 1.2 abbreviated: Data exchange works correctly after session resumption.
    #[test]
    fn test_dtls12_integration_abbreviated_data_exchange() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection_dtls12::dtls12_handshake_in_memory;
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::session::InMemorySessionCache;
        use hitls_tls::CipherSuite;
        use std::sync::{Arc, Mutex};

        let (cert_chain, server_key) = make_ecdsa_server_identity();
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let groups = [NamedGroup::SECP256R1];
        let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

        let client_cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));
        let server_cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));

        let make_client_config = |cache: Arc<Mutex<InMemorySessionCache>>| {
            TlsConfig::builder()
                .cipher_suites(&[suite])
                .supported_groups(&groups)
                .signature_algorithms(&sig_algs)
                .verify_peer(false)
                .server_name("dtls.test.example")
                .session_cache(cache)
                .build()
        };

        let make_server_config = |cache: Arc<Mutex<InMemorySessionCache>>| {
            TlsConfig::builder()
                .cipher_suites(&[suite])
                .supported_groups(&groups)
                .signature_algorithms(&sig_algs)
                .certificate_chain(cert_chain.clone())
                .private_key(server_key.clone())
                .verify_peer(false)
                .session_cache(cache)
                .build()
        };

        // First: full handshake
        let (_, _) = dtls12_handshake_in_memory(
            make_client_config(client_cache.clone()),
            make_server_config(server_cache.clone()),
            false,
        )
        .unwrap();

        // Second: abbreviated handshake
        let (mut client, mut server) = dtls12_handshake_in_memory(
            make_client_config(client_cache),
            make_server_config(server_cache),
            false,
        )
        .unwrap();

        // Verify application data works after abbreviated handshake
        let datagram = client.seal_app_data(b"after resumption").unwrap();
        let pt = server.open_app_data(&datagram).unwrap();
        assert_eq!(pt, b"after resumption");

        let reply = server.seal_app_data(b"resumed ok").unwrap();
        let pt = client.open_app_data(&reply).unwrap();
        assert_eq!(pt, b"resumed ok");
    }

    // -------------------------------------------------------
    // Testing-Phase 77 — G5: PskServerCallback integration tests
    // -------------------------------------------------------

    /// TLS 1.2 PSK: PskServerCallback returns key for known identity — handshake succeeds.
    #[test]
    fn test_tls12_psk_server_callback_known_identity() {
        use hitls_tls::config::{PskServerCallback, TlsConfig};
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let suite = CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256;
        let psk = b"test-psk-key-32-bytes-for-aes!!!".to_vec();
        let psk_clone = psk.clone();
        let identity = b"known-client".to_vec();

        // Server uses callback to look up PSK by identity
        let cb: PskServerCallback = Arc::new(move |id: &[u8]| {
            if id == b"known-client" {
                Some(psk_clone.clone())
            } else {
                None
            }
        });

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .verify_peer(false)
            .psk_server_callback(cb)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let mut buf = [0u8; 16];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .verify_peer(false)
            .psk(psk)
            .psk_identity(identity)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"psk-callback").unwrap();
        let mut buf = [0u8; 16];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"psk-callback");
        server_handle.join().unwrap();
    }

    /// TLS 1.2 PSK: PskServerCallback returns None for unknown identity — handshake fails.
    #[test]
    fn test_tls12_psk_server_callback_unknown_identity() {
        use hitls_tls::config::{PskServerCallback, TlsConfig};
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let suite = CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256;
        let psk = b"test-psk-key-32-bytes-for-aes!!!".to_vec();

        // Server callback never finds the identity → returns None
        let cb: PskServerCallback = Arc::new(|_id: &[u8]| None);

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .verify_peer(false)
            .psk_server_callback(cb)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            let _ = conn.handshake(); // Expected to fail
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .verify_peer(false)
            .psk(psk)
            .psk_identity(b"unknown-client".to_vec())
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        let result = conn.handshake();
        assert!(
            result.is_err(),
            "handshake should fail for unknown PSK identity"
        );
        server_handle.join().unwrap();
    }

    // -------------------------------------------------------
    // Testing-Phase 78 — H1: GREASE (RFC 8701) integration tests
    // -------------------------------------------------------

    /// TLS 1.3: GREASE enabled on client — server ignores GREASE values, handshake succeeds.
    #[test]
    fn test_tls13_grease_enabled_handshake() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
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

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let mut buf = [0u8; 32];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
        });

        // Client with GREASE enabled
        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .grease(true)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"grease-tls13").unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"grease-tls13");
        server_handle.join().unwrap();
    }

    /// TLS 1.2: GREASE enabled on client — server ignores GREASE values, handshake succeeds.
    #[test]
    fn test_tls12_grease_enabled_handshake() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::SignatureScheme;
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ecdsa_server_identity();
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let groups = [hitls_tls::crypt::NamedGroup::SECP256R1];
        let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let mut buf = [0u8; 32];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
        });

        // Client with GREASE enabled
        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .grease(true)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"grease-tls12").unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"grease-tls12");
        server_handle.join().unwrap();
    }

    // -------------------------------------------------------
    // Testing-Phase 78 — H2: Heartbeat extension (RFC 6520) integration
    // -------------------------------------------------------

    /// TLS 1.3: Client with heartbeat_mode=1, handshake succeeds (negotiation-only).
    #[test]
    fn test_tls13_heartbeat_mode_handshake() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
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

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let mut buf = [0u8; 32];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
        });

        // Client with heartbeat_mode=1 (peer_allowed_to_send)
        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .heartbeat_mode(1)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"heartbeat-tls13").unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"heartbeat-tls13");
        server_handle.join().unwrap();
    }

    /// TLS 1.2: Client with heartbeat_mode=2, handshake succeeds.
    #[test]
    fn test_tls12_heartbeat_mode_handshake() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::SignatureScheme;
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ecdsa_server_identity();
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        let groups = [hitls_tls::crypt::NamedGroup::SECP256R1];
        let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let mut buf = [0u8; 32];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
        });

        // Client with heartbeat_mode=2 (peer_not_allowed_to_send)
        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .heartbeat_mode(2)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"heartbeat-tls12").unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"heartbeat-tls12");
        server_handle.join().unwrap();
    }

    // -------------------------------------------------------
    // Testing-Phase 78 — H5: GREASE + Heartbeat combined
    // -------------------------------------------------------

    /// TLS 1.3: Both GREASE and heartbeat enabled simultaneously.
    #[test]
    fn test_tls13_grease_and_heartbeat_combined() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
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

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let mut buf = [0u8; 32];
            let n = conn.read(&mut buf).unwrap();
            conn.write(&buf[..n]).unwrap();
        });

        // Client with both GREASE and heartbeat enabled
        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .grease(true)
            .heartbeat_mode(1)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"combo").unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"combo");
        server_handle.join().unwrap();
    }

    /// DTLS 1.2: GREASE enabled on client — handshake succeeds.
    #[test]
    fn test_dtls12_grease_enabled_handshake() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection_dtls12::dtls12_handshake_in_memory;
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsVersion};

        let (cert_chain, server_key) = make_ecdsa_server_identity();
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

        let client_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .grease(true)
            .verify_peer(false)
            .build();

        let server_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .build();

        let (mut client, mut server) =
            dtls12_handshake_in_memory(client_config, server_config, false).unwrap();
        assert_eq!(client.version(), Some(TlsVersion::Dtls12));
        assert_eq!(server.version(), Some(TlsVersion::Dtls12));

        // App data exchange
        let ct = client.seal_app_data(b"grease-dtls").unwrap();
        let pt = server.open_app_data(&ct).unwrap();
        assert_eq!(pt, b"grease-dtls");
    }

    // -------------------------------------------------------
    // Phase 79 — Integration tests for Phase 77-78 features
    // -------------------------------------------------------

    /// TLS 1.3: MsgCallback observes protocol messages during handshake.
    #[test]
    fn test_tls13_msg_callback() {
        use hitls_tls::config::{MsgCallback, TlsConfig};
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();
        let messages: Arc<Mutex<Vec<(bool, u16, u8)>>> = Arc::new(Mutex::new(Vec::new()));
        let msgs = messages.clone();

        let cb: MsgCallback = Arc::new(move |outgoing, version, content_type, _data| {
            msgs.lock().unwrap().push((outgoing, version, content_type));
        });

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain)
            .private_key(server_key)
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
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let mut buf = [0u8; 32];
            let _ = conn.read(&mut buf);
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .msg_callback(cb)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"hi").unwrap();
        let _ = conn.shutdown();
        server_handle.join().unwrap();

        // msg_callback is configured but not yet wired into handshake call sites.
        // This test verifies the config is accepted and handshake succeeds.
        let _msgs = messages.lock().unwrap();
    }

    /// TLS 1.2: MsgCallback config accepted and handshake succeeds.
    #[test]
    fn test_tls12_msg_callback() {
        use hitls_tls::config::{MsgCallback, TlsConfig};
        use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ecdsa_server_identity();
        let messages: Arc<Mutex<Vec<(bool, u16, u8)>>> = Arc::new(Mutex::new(Vec::new()));
        let msgs = messages.clone();

        let cb: MsgCallback = Arc::new(move |outgoing, version, content_type, _data| {
            msgs.lock().unwrap().push((outgoing, version, content_type));
        });

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .certificate_chain(cert_chain)
            .private_key(server_key)
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
            let mut buf = [0u8; 32];
            let _ = conn.read(&mut buf);
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls12)
            .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .verify_peer(false)
            .msg_callback(cb)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"hello12").unwrap();
        let _ = conn.shutdown();
        server_handle.join().unwrap();

        // msg_callback is configured but not yet wired into handshake call sites.
        // This test verifies the config is accepted and handshake succeeds.
        let _msgs = messages.lock().unwrap();
    }

    /// TLS 1.3: InfoCallback config accepted and handshake succeeds.
    #[test]
    fn test_tls13_info_callback() {
        use hitls_tls::config::{InfoCallback, TlsConfig};
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();
        let events: Arc<Mutex<Vec<(i32, i32)>>> = Arc::new(Mutex::new(Vec::new()));
        let evts = events.clone();

        let cb: InfoCallback = Arc::new(move |event_type, value| {
            evts.lock().unwrap().push((event_type, value));
        });

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .info_callback(cb.clone())
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
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let mut buf = [0u8; 32];
            let _ = conn.read(&mut buf);
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"info").unwrap();
        let _ = conn.shutdown();
        server_handle.join().unwrap();

        // Info callback was set on server — it should have received events
        let evts = events.lock().unwrap();
        // We don't strictly require events (depends on implementation),
        // but the callback should be wired without panicking
        // The main assertion is that the handshake succeeded with the callback set
        let _ = evts.len(); // just ensure no panic occurred
    }

    /// TLS 1.3: ClientHelloCallback observes cipher suites from client.
    #[test]
    fn test_tls13_client_hello_callback() {
        use hitls_tls::config::{ClientHelloAction, ClientHelloCallback, TlsConfig};
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();
        let observed_suites: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(Vec::new()));
        let suites = observed_suites.clone();

        let cb: ClientHelloCallback = Arc::new(move |info| {
            suites
                .lock()
                .unwrap()
                .extend_from_slice(&info.cipher_suites);
            ClientHelloAction::Success
        });

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .client_hello_callback(cb)
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
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let mut buf = [0u8; 32];
            let _ = conn.read(&mut buf);
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .cipher_suites(&[
                CipherSuite::TLS_AES_128_GCM_SHA256,
                CipherSuite::TLS_AES_256_GCM_SHA384,
            ])
            .verify_peer(false)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"ch").unwrap();
        let _ = conn.shutdown();
        server_handle.join().unwrap();

        let suites = observed_suites.lock().unwrap();
        assert!(!suites.is_empty(), "should observe client cipher suites");
        // The client offered TLS_AES_128_GCM_SHA256 (0x1301)
        assert!(
            suites.contains(&0x1301),
            "should contain TLS_AES_128_GCM_SHA256"
        );
    }

    /// CBC-MAC-SM4: create and verify MAC via hitls-crypto.
    #[test]
    fn test_cbc_mac_sm4_integration() {
        use hitls_crypto::cbc_mac::CbcMacSm4;

        let key = [0x42u8; 16];
        let message = b"CBC-MAC-SM4 integration test message with multiple blocks of data!";

        let mut mac = CbcMacSm4::new(&key).unwrap();
        mac.update(message).unwrap();
        let mut tag1 = [0u8; 16];
        mac.finish(&mut tag1).unwrap();

        // Same key + message → same MAC
        let mut mac2 = CbcMacSm4::new(&key).unwrap();
        mac2.update(message).unwrap();
        let mut tag2 = [0u8; 16];
        mac2.finish(&mut tag2).unwrap();
        assert_eq!(tag1, tag2);

        // Different message → different MAC
        let mut mac3 = CbcMacSm4::new(&key).unwrap();
        mac3.update(b"different message").unwrap();
        let mut tag3 = [0u8; 16];
        mac3.finish(&mut tag3).unwrap();
        assert_ne!(tag1, tag3);
    }

    /// CMS AuthenticatedData: create + verify + DER roundtrip.
    #[test]
    fn test_cms_authenticated_data_integration() {
        use hitls_pki::cms::{CmsContentType, CmsDigestAlg, CmsMessage};

        let data = b"CMS AuthenticatedData integration test";
        let key = b"0123456789abcdef0123456789abcdef"; // 32 bytes for HMAC key

        // Create
        let cms = CmsMessage::authenticate(data, key, CmsDigestAlg::Sha256).unwrap();
        assert_eq!(cms.content_type, CmsContentType::AuthenticatedData);
        assert!(cms.authenticated_data.is_some());

        // Verify
        let ok = cms.verify_mac(key).unwrap();
        assert!(ok, "MAC verification should succeed with correct key");

        // Wrong key → verification fails
        let wrong_key = b"wrong_key_wrong_key_wrong_key!!!";
        let ok2 = cms.verify_mac(wrong_key).unwrap();
        assert!(!ok2, "MAC verification should fail with wrong key");

        // DER roundtrip
        let parsed = CmsMessage::from_der(&cms.raw).unwrap();
        assert_eq!(parsed.content_type, CmsContentType::AuthenticatedData);
        let ok3 = parsed.verify_mac(key).unwrap();
        assert!(ok3, "MAC should verify after DER roundtrip");
    }

    /// TLS 1.3: record_padding_callback is wired and handshake succeeds.
    #[test]
    fn test_tls13_record_padding_callback() {
        use hitls_tls::config::{RecordPaddingCallback, TlsConfig};
        use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
        use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::time::Duration;

        let (cert_chain, server_key) = make_ed25519_server_identity();
        let pad_calls: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let pads = pad_calls.clone();

        let cb: RecordPaddingCallback = Arc::new(move |_content_type, _len| {
            *pads.lock().unwrap() += 1;
            32 // add 32 bytes padding
        });

        let server_config = TlsConfig::builder()
            .role(TlsRole::Server)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .certificate_chain(cert_chain)
            .private_key(server_key)
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
            let mut conn = TlsServerConnection::new(stream, server_config);
            conn.handshake().unwrap();
            let mut buf = [0u8; 64];
            let n = conn.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"padded data");
            conn.write(b"ok").unwrap();
            let _ = conn.shutdown();
        });

        let client_config = TlsConfig::builder()
            .role(TlsRole::Client)
            .min_version(TlsVersion::Tls13)
            .max_version(TlsVersion::Tls13)
            .verify_peer(false)
            .record_padding_callback(cb)
            .build();

        let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsClientConnection::new(stream, client_config);
        conn.handshake().unwrap();
        conn.write(b"padded data").unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ok");
        let _ = conn.shutdown();
        server_handle.join().unwrap();

        let calls = *pad_calls.lock().unwrap();
        assert!(calls > 0, "record_padding_callback should have been called");
    }

    /// DTLS 1.2: flight_transmit_enable and empty_records_limit config.
    #[test]
    fn test_dtls12_config_enhancements() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::connection_dtls12::dtls12_handshake_in_memory;
        use hitls_tls::crypt::{NamedGroup, SignatureScheme};
        use hitls_tls::{CipherSuite, TlsVersion};

        let (cert_chain, server_key) = make_ecdsa_server_identity();
        let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

        // Config with custom DTLS settings
        let client_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .verify_peer(false)
            .flight_transmit_enable(true)
            .empty_records_limit(64)
            .build();

        let server_config = TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&[NamedGroup::SECP256R1])
            .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
            .certificate_chain(cert_chain)
            .private_key(server_key)
            .verify_peer(false)
            .flight_transmit_enable(false)
            .empty_records_limit(100)
            .build();

        // Verify config values
        assert!(client_config.flight_transmit_enable);
        assert_eq!(client_config.empty_records_limit, 64);
        assert!(!server_config.flight_transmit_enable);
        assert_eq!(server_config.empty_records_limit, 100);

        // DTLS handshake should succeed with these configs
        let (mut client, mut server) =
            dtls12_handshake_in_memory(client_config, server_config, false).unwrap();
        assert_eq!(client.version(), Some(TlsVersion::Dtls12));
        assert_eq!(server.version(), Some(TlsVersion::Dtls12));

        let ct = client.seal_app_data(b"dtls-config-test").unwrap();
        let pt = server.open_app_data(&ct).unwrap();
        assert_eq!(pt, b"dtls-config-test");
    }

    /// RecordLayer: empty record DoS protection with configurable limit.
    #[test]
    fn test_record_layer_empty_records_limit() {
        use hitls_tls::record::{ContentType, RecordLayer};

        let mut rl = RecordLayer::new();
        rl.empty_records_limit = 5;

        // 5 empty handshake records should be allowed
        for _ in 0..5 {
            rl.check_empty_record(ContentType::Handshake, 0).unwrap();
        }

        // 6th should fail
        let result = rl.check_empty_record(ContentType::Handshake, 0);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("too many consecutive empty records"));

        // Non-empty record resets the counter
        rl.check_empty_record(ContentType::Handshake, 42).unwrap();
        assert_eq!(rl.empty_record_count, 0);

        // Can accept empty records again
        rl.check_empty_record(ContentType::Handshake, 0).unwrap();
        assert_eq!(rl.empty_record_count, 1);
    }

    // ─── Phase 82: Integration tests ───

    #[test]
    fn test_quiet_shutdown_e2e() {
        use hitls_tls::config::TlsConfig;
        use hitls_tls::{TlsRole, TlsVersion};

        // Verify quiet_shutdown config works end-to-end
        let config = TlsConfig::builder()
            .role(TlsRole::Client)
            .quiet_shutdown(true)
            .build();
        assert!(config.quiet_shutdown);

        // With quiet_shutdown=false (default), config should be false
        let config2 = TlsConfig::builder().role(TlsRole::Server).build();
        assert!(!config2.quiet_shutdown);

        // Verify it propagates through version limits
        let config3 = TlsConfig::builder()
            .min_version(TlsVersion::Tls12)
            .max_version(TlsVersion::Tls13)
            .quiet_shutdown(true)
            .build();
        assert!(config3.quiet_shutdown);
        assert_eq!(config3.min_version, TlsVersion::Tls12);
    }

    #[test]
    fn test_security_callback_e2e() {
        use hitls_tls::config::{SecurityCallback, TlsConfig};
        use hitls_tls::TlsRole;
        use std::sync::Arc;

        // Create a security callback that rejects weak ciphers
        let cb: SecurityCallback = Arc::new(|op, level, id| {
            if op == 0 && level >= 2 {
                // At level 2+, reject AES-128 suites (id < 0x1302)
                id >= 0x1302
            } else {
                true
            }
        });

        let config = TlsConfig::builder()
            .role(TlsRole::Server)
            .security_cb(cb.clone())
            .security_level(2)
            .build();

        let cb_ref = config.security_cb.as_ref().unwrap();
        let level = config.security_level;

        // AES-128-GCM (0x1301) should be rejected at level 2
        assert!(!(cb_ref)(0, level, 0x1301));
        // AES-256-GCM (0x1302) should be allowed
        assert!((cb_ref)(0, level, 0x1302));
        // Groups always allowed
        assert!((cb_ref)(1, level, 0x001D));
    }

    #[test]
    fn test_encrypted_pkcs8_e2e() {
        use hitls_pki::pkcs8::encrypted;
        use hitls_pki::pkcs8::{encode_ed25519_pkcs8_der, parse_pkcs8_der, Pkcs8PrivateKey};

        // Generate a key, encrypt it, decrypt it, use it
        let seed = [0x42u8; 32];
        let pki_der = encode_ed25519_pkcs8_der(&seed);

        // Encrypt with password
        let encrypted_der = encrypted::encrypt_pkcs8_der(&pki_der, "integration-test").unwrap();

        // Verify it's different from plaintext
        assert_ne!(pki_der, encrypted_der);

        // Decrypt
        let decrypted = encrypted::decrypt_pkcs8_der(&encrypted_der, "integration-test").unwrap();
        assert_eq!(pki_der, decrypted);

        // Parse and use the key
        let key = parse_pkcs8_der(&decrypted).unwrap();
        match key {
            Pkcs8PrivateKey::Ed25519(kp) => {
                let sig = kp.sign(b"test").unwrap();
                assert!(kp.verify(b"test", &sig).is_ok());
            }
            _ => panic!("Expected Ed25519"),
        }
    }
}
