//! PKI, X.509, CMS, and codec-level integration tests.

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
    let Ok(ca_pem) = std::fs::read_to_string(&ca_pem_path) else {
        eprintln!("Skipping X.509 test: test certs not found at {ca_pem_path}");
        return;
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

#[test]
fn test_x509_chain_verification() {
    let cert_dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testcode/testdata/tls/certificate/pem/rsa_sha256/"
    );

    let ca_pem_path = format!("{cert_dir}ca_cert.pem");
    let inter_pem_path = format!("{cert_dir}inter_cert.pem");
    let ee_pem_path = format!("{cert_dir}server_cert.pem");

    let Ok(ca_pem) = std::fs::read_to_string(&ca_pem_path) else {
        eprintln!("Skipping chain test: test certs not found");
        return;
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
    use zeroize::Zeroize;

    let ecdsa_private = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
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

    // Client -> CH
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

    // Client -> CKE + CCS + Finished
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

    // Server -> CCS + Finished
    s2c.extend_from_slice(
        &server_rl
            .seal_record(ContentType::ChangeCipherSpec, &[0x01])
            .unwrap(),
    );
    server_rl
        .activate_write_encryption12(suite, &keys.server_write_key, keys.server_write_iv.clone())
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

    // Both connected -- exchange app data
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
    cflight.master_secret.zeroize();
    keys.master_secret.zeroize();
}

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

    // Same key + message -> same MAC
    let mut mac2 = CbcMacSm4::new(&key).unwrap();
    mac2.update(message).unwrap();
    let mut tag2 = [0u8; 16];
    mac2.finish(&mut tag2).unwrap();
    assert_eq!(tag1, tag2);

    // Different message -> different MAC
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

    // Wrong key -> verification fails
    let wrong_key = b"wrong_key_wrong_key_wrong_key!!!";
    let ok2 = cms.verify_mac(wrong_key).unwrap();
    assert!(!ok2, "MAC verification should fail with wrong key");

    // DER roundtrip
    let parsed = CmsMessage::from_der(&cms.raw).unwrap();
    assert_eq!(parsed.content_type, CmsContentType::AuthenticatedData);
    let ok3 = parsed.verify_mac(key).unwrap();
    assert!(ok3, "MAC should verify after DER roundtrip");
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

/// CRL end-to-end: CrlBuilder → sign → DER/PEM roundtrip → verify → revocation check.
#[test]
fn test_crl_builder_sign_parse_verify_roundtrip() {
    use hitls_pki::x509::{
        CertificateBuilder, CertificateRevocationList, CrlBuilder, DistinguishedName,
        RevocationReason, RevokedCertBuilder, SigningKey,
    };

    // 1. Create a self-signed RSA CA certificate
    let rsa_key = hitls_crypto::rsa::RsaPrivateKey::generate(2048).unwrap();
    let sk = SigningKey::Rsa(rsa_key);
    let ca_dn = DistinguishedName {
        entries: vec![
            ("C".into(), "CN".into()),
            ("O".into(), "Integration Test".into()),
            ("CN".into(), "CRL E2E Test CA".into()),
        ],
    };
    let ca_cert =
        CertificateBuilder::self_signed(ca_dn.clone(), &sk, 1_700_000_000, 1_800_000_000).unwrap();
    assert!(ca_cert.is_self_signed());
    assert!(ca_cert.is_ca());

    // 2. Build a CRL with multiple revoked certificates
    let serial_revoked = vec![0x01, 0x02, 0x03];
    let serial_compromised = vec![0x0A, 0x0B];
    let serial_not_revoked = vec![0xFF];

    let crl = CrlBuilder::new(ca_dn, 1_710_000_000)
        .next_update(1_720_000_000)
        .add_revoked(
            RevokedCertBuilder::new(&serial_revoked, 1_705_000_000)
                .reason(RevocationReason::CessationOfOperation),
        )
        .add_revoked(
            RevokedCertBuilder::new(&serial_compromised, 1_706_000_000)
                .reason(RevocationReason::KeyCompromise)
                .invalidity_date(1_704_000_000),
        )
        .add_crl_number(&[0x01])
        .build(&sk)
        .unwrap();

    // 3. DER roundtrip
    let der = crl.to_der();
    let parsed = CertificateRevocationList::from_der(&der).unwrap();
    assert_eq!(parsed.revoked_certs.len(), 2);
    assert_eq!(parsed.this_update, 1_710_000_000);
    assert_eq!(parsed.next_update, Some(1_720_000_000));

    // 4. PEM roundtrip
    let pem = crl.to_pem();
    let parsed_pem = CertificateRevocationList::from_pem(&pem).unwrap();
    assert_eq!(parsed_pem.revoked_certs.len(), 2);

    // 5. Verify CRL signature against the CA certificate
    assert!(parsed.verify_signature(&ca_cert).unwrap());

    // 6. Revocation status checks
    assert!(
        parsed.is_revoked(&serial_revoked).is_some(),
        "serial_revoked must be in CRL"
    );
    assert!(
        parsed.is_revoked(&serial_compromised).is_some(),
        "serial_compromised must be in CRL"
    );
    assert!(
        parsed.is_revoked(&serial_not_revoked).is_none(),
        "serial_not_revoked must NOT be in CRL"
    );

    // 7. Check revocation reason and invalidity date
    let entry = parsed.is_revoked(&serial_compromised).unwrap();
    assert_eq!(entry.reason, Some(RevocationReason::KeyCompromise));
    assert_eq!(entry.invalidity_date, Some(1_704_000_000));

    // 8. Check CRL number extension
    assert_eq!(parsed.crl_number(), Some(vec![0x01]));

    // 9. Cross-verify: wrong CA must fail
    let rsa_key2 = hitls_crypto::rsa::RsaPrivateKey::generate(2048).unwrap();
    let sk2 = SigningKey::Rsa(rsa_key2);
    let wrong_dn = DistinguishedName {
        entries: vec![("CN".into(), "Wrong CA".into())],
    };
    let wrong_ca =
        CertificateBuilder::self_signed(wrong_dn, &sk2, 1_700_000_000, 1_800_000_000).unwrap();
    let verify_wrong = parsed.verify_signature(&wrong_ca);
    assert!(
        verify_wrong.is_err() || !verify_wrong.unwrap(),
        "CRL signature must fail with wrong CA"
    );
}

/// HPKE end-to-end: X25519 base mode seal→open roundtrip.
#[test]
fn test_hpke_base_mode_seal_open_roundtrip() {
    use hitls_crypto::hpke::HpkeCtx;

    // Generate recipient X25519 key
    let sk_r = hitls_crypto::x25519::X25519PrivateKey::generate().unwrap();
    let pk_r_bytes = sk_r.public_key().as_bytes().to_vec();
    let sk_r_bytes = sk_r.to_bytes();

    let info = b"integration test info";
    let aad = b"associated data";
    let plaintext = b"Hello, HPKE integration test!";

    // Sender: setup + seal (default suite: X25519/SHA256/AES128-GCM)
    let (mut sender_ctx, enc): (HpkeCtx, Vec<u8>) =
        HpkeCtx::setup_sender(&pk_r_bytes, info).unwrap();
    let ciphertext: Vec<u8> = sender_ctx.seal(aad, plaintext).unwrap();

    // Recipient: setup + open
    let mut recipient_ctx = HpkeCtx::setup_recipient(&sk_r_bytes, &enc, info).unwrap();
    let decrypted = recipient_ctx.open(aad, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext, "HPKE seal/open roundtrip failed");

    // Tampered ciphertext must fail
    let mut bad_ct = ciphertext.clone();
    bad_ct[0] ^= 0xFF;
    let mut ctx2 = HpkeCtx::setup_recipient(&sk_r_bytes, &enc, info).unwrap();
    assert!(ctx2.open(aad, &bad_ct).is_err(), "tampered ct must fail");
}

/// XMSS-MT end-to-end: multi-tree sign→verify roundtrip.
#[test]
fn test_xmss_mt_sign_verify_roundtrip() {
    use hitls_types::XmssMtParamId;

    // Use the smallest multi-tree variant: SHA-256 h=20 d=4
    let param = XmssMtParamId::Sha2_20_4_256;
    let mut kp = hitls_crypto::xmss::XmssMtKeyPair::generate(param).unwrap();
    assert!(kp.remaining_signatures() > 0);

    let msg = b"XMSS-MT integration test message";
    let sig = kp.sign(msg).unwrap();

    // Verify
    assert!(kp.verify(msg, &sig).unwrap(), "XMSS-MT verify must pass");

    // Verify with wrong message must fail
    let result = kp.verify(b"wrong message", &sig);
    assert!(
        result.is_err() || !result.unwrap(),
        "XMSS-MT verify must fail with wrong message"
    );
}
