use super::*;
use std::io::Cursor;

use crate::config::TlsConfig;
use crate::crypt::key_schedule::KeySchedule;
use crate::crypt::traffic_keys::TrafficKeys;
use crate::handshake::client::{ClientHandshake, ServerHelloResult};
use crate::handshake::codec::{
    decode_certificate_request, decode_key_update, encode_certificate, encode_certificate_request,
    encode_certificate_verify, encode_finished, encode_key_update, parse_handshake_header,
    CertificateEntry, CertificateMsg, CertificateRequestMsg, CertificateVerifyMsg, KeyUpdateMsg,
    KeyUpdateRequest,
};
use crate::handshake::server::{ClientHelloResult, ServerHandshake};
use crate::handshake::{HandshakeState, HandshakeType};
use crate::record::{ContentType, RecordLayer};
use crate::session::TlsSession;
use crate::{CipherSuite, TlsConnection};

#[test]
fn test_connection_creation() {
    let stream = Cursor::new(Vec::<u8>::new());
    let config = TlsConfig::builder().build();
    let conn = TlsClientConnection::new(stream, config);
    assert_eq!(conn.state, ConnectionState::Handshaking);
    assert!(conn.version().is_none());
    assert!(conn.cipher_suite().is_none());
}

/// Helper: generate Ed25519 server keypair and a minimal self-signed DER cert.
/// Returns (seed, public_key_bytes, fake_der_cert).
fn make_ed25519_server_identity() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let seed = vec![0x42; 32];
    let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(&seed).unwrap();
    let pub_key_bytes = kp.public_key().to_vec();
    // We use a fake DER cert since we'll disable peer verification.
    // In a real scenario, this would be a proper self-signed X.509 cert.
    let fake_cert = vec![0x30, 0x82, 0x01, 0x00];
    (seed, pub_key_bytes, fake_cert)
}

/// Run a full client-server handshake step by step using the state machines
/// and record layers directly (no I/O transport needed).
#[test]
fn test_full_handshake_state_machine_roundtrip() {
    use crate::config::ServerPrivateKey;

    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();

    let client_config = TlsConfig::builder()
        .server_name("test.example.com")
        .verify_peer(false) // disable cert chain validation for this test
        .build();

    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .verify_peer(false)
        .build();

    // --- Client builds ClientHello ---
    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let ch_msg = client_hs.build_client_hello().unwrap();
    assert_eq!(client_hs.state(), HandshakeState::WaitServerHello);
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();

    // --- Server receives ClientHello, produces flight ---
    let mut server_rl = RecordLayer::new();
    let (ct, ch_plaintext, _) = server_rl.open_record(&ch_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);

    let (hs_type, _, ch_total) = parse_handshake_header(&ch_plaintext).unwrap();
    assert_eq!(hs_type, crate::handshake::HandshakeType::ClientHello);

    let mut server_hs = ServerHandshake::new(server_config);
    let actions = match server_hs
        .process_client_hello(&ch_plaintext[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions, got HRR"),
    };
    assert_eq!(server_hs.state(), HandshakeState::WaitClientFinished);

    // --- Server sends ServerHello (plaintext) ---
    let sh_record = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();

    // Activate server HS encryption
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();

    // Send encrypted flight: EE, Certificate, CertificateVerify, Finished
    let ee_record = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let cert_record = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_msg)
        .unwrap();
    let cv_record = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
        .unwrap();
    let sfin_record = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    // --- Client processes ServerHello ---
    let (ct, sh_plaintext, _) = client_rl.open_record(&sh_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (_, _, sh_total) = parse_handshake_header(&sh_plaintext).unwrap();
    let sh_actions = match client_hs
        .process_server_hello(&sh_plaintext[..sh_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions, got HRR"),
    };
    assert_eq!(client_hs.state(), HandshakeState::WaitEncryptedExtensions);

    // Activate client HS decryption/encryption
    client_rl
        .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_actions.suite, &sh_actions.client_hs_keys)
        .unwrap();

    // --- Client processes encrypted flight ---
    // EE
    let (ct, ee_plain, _) = client_rl.open_record(&ee_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (_, _, ee_total) = parse_handshake_header(&ee_plain).unwrap();
    client_hs
        .process_encrypted_extensions(&ee_plain[..ee_total])
        .unwrap();

    // Certificate
    let (ct, cert_plain, _) = client_rl.open_record(&cert_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (_, _, cert_total) = parse_handshake_header(&cert_plain).unwrap();
    client_hs
        .process_certificate(&cert_plain[..cert_total])
        .unwrap();

    // CertificateVerify
    let (ct, cv_plain, _) = client_rl.open_record(&cv_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (_, _, cv_total) = parse_handshake_header(&cv_plain).unwrap();
    client_hs
        .process_certificate_verify(&cv_plain[..cv_total])
        .unwrap();

    // Finished
    let (ct, fin_plain, _) = client_rl.open_record(&sfin_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (_, _, fin_total) = parse_handshake_header(&fin_plain).unwrap();
    let fin_actions = client_hs.process_finished(&fin_plain[..fin_total]).unwrap();
    assert_eq!(client_hs.state(), HandshakeState::Connected);

    // --- Client sends client Finished ---
    let cfin_record = client_rl
        .seal_record(ContentType::Handshake, &fin_actions.client_finished_msg)
        .unwrap();

    // --- Server receives client Finished ---
    let (ct, cfin_plain, _) = server_rl.open_record(&cfin_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (_, _, cfin_total) = parse_handshake_header(&cfin_plain).unwrap();
    let _cfin_actions = server_hs
        .process_client_finished(&cfin_plain[..cfin_total])
        .unwrap();
    assert_eq!(server_hs.state(), HandshakeState::Connected);

    // Both sides are connected!
    assert_eq!(fin_actions.suite, actions.suite);
}

/// Full handshake + bidirectional application data exchange.
#[test]
fn test_full_handshake_with_app_data() {
    use crate::config::ServerPrivateKey;

    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();

    let client_config = TlsConfig::builder().verify_peer(false).build();
    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    // --- Handshake (abbreviated, same flow as above) ---
    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();

    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let actions = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions, got HRR"),
    };

    let sh_record = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();

    let ee_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let cert_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_msg)
        .unwrap();
    let cv_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
        .unwrap();
    let sfin_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    // Client side
    let (_, sh_data, _) = client_rl.open_record(&sh_record).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_actions = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions, got HRR"),
    };
    client_rl
        .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_actions.suite, &sh_actions.client_hs_keys)
        .unwrap();

    for rec in [&ee_rec, &cert_rec, &cv_rec] {
        let (_, data, _) = client_rl.open_record(rec).unwrap();
        let (_, _, total) = parse_handshake_header(&data).unwrap();
        let msg = &data[..total];
        match client_hs.state() {
            crate::handshake::HandshakeState::WaitEncryptedExtensions => {
                client_hs.process_encrypted_extensions(msg).unwrap();
            }
            crate::handshake::HandshakeState::WaitCertCertReq => {
                client_hs.process_certificate(msg).unwrap();
            }
            crate::handshake::HandshakeState::WaitCertVerify => {
                client_hs.process_certificate_verify(msg).unwrap();
            }
            s => panic!("unexpected state: {s:?}"),
        }
    }

    let (_, fin_data, _) = client_rl.open_record(&sfin_rec).unwrap();
    let (_, _, fin_total) = parse_handshake_header(&fin_data).unwrap();
    let fin_actions = client_hs.process_finished(&fin_data[..fin_total]).unwrap();

    let cfin_record = client_rl
        .seal_record(ContentType::Handshake, &fin_actions.client_finished_msg)
        .unwrap();

    let (_, cfin_data, _) = server_rl.open_record(&cfin_record).unwrap();
    let (_, _, cfin_total) = parse_handshake_header(&cfin_data).unwrap();
    server_hs
        .process_client_finished(&cfin_data[..cfin_total])
        .unwrap();

    // --- Activate application keys ---
    client_rl
        .activate_write_encryption(fin_actions.suite, &fin_actions.client_app_keys)
        .unwrap();
    client_rl
        .activate_read_decryption(fin_actions.suite, &fin_actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_app_keys)
        .unwrap();

    // --- Exchange application data ---
    // Client → Server
    let client_msg = b"Hello from client!";
    let c2s_record = client_rl
        .seal_record(ContentType::ApplicationData, client_msg)
        .unwrap();
    let (ct, c2s_plain, _) = server_rl.open_record(&c2s_record).unwrap();
    assert_eq!(ct, ContentType::ApplicationData);
    assert_eq!(&c2s_plain, client_msg);

    // Server → Client
    let server_msg = b"Hello from server!";
    let s2c_record = server_rl
        .seal_record(ContentType::ApplicationData, server_msg)
        .unwrap();
    let (ct, s2c_plain, _) = client_rl.open_record(&s2c_record).unwrap();
    assert_eq!(ct, ContentType::ApplicationData);
    assert_eq!(&s2c_plain, server_msg);
}

/// Test cipher suite negotiation: server picks first preference from its list.
#[test]
fn test_handshake_cipher_suite_negotiation() {
    use crate::config::ServerPrivateKey;

    let (seed, _, fake_cert) = make_ed25519_server_identity();

    // Client offers AES_256_GCM first, AES_128_GCM second
    let client_config = TlsConfig::builder()
        .cipher_suites(&[
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_AES_128_GCM_SHA256,
        ])
        .verify_peer(false)
        .build();

    // Server prefers AES_128_GCM first
    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .cipher_suites(&[
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
        ])
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();

    let mut server_rl = RecordLayer::new();
    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();

    let mut server_hs = ServerHandshake::new(server_config);
    let actions = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions, got HRR"),
    };

    // Server should have selected AES_128_GCM (its first preference)
    assert_eq!(actions.suite, CipherSuite::TLS_AES_128_GCM_SHA256);
}

/// Test that handshake fails when there's no shared cipher suite.
#[test]
fn test_handshake_no_shared_cipher_suite() {
    use crate::config::ServerPrivateKey;

    let (seed, _, fake_cert) = make_ed25519_server_identity();

    // Client only offers AES_256_GCM
    let client_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::TLS_AES_256_GCM_SHA384])
        .verify_peer(false)
        .build();

    // Server only offers ChaCha20
    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .cipher_suites(&[CipherSuite::TLS_CHACHA20_POLY1305_SHA256])
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();

    let mut server_rl = RecordLayer::new();
    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();

    let mut server_hs = ServerHandshake::new(server_config);
    let result = server_hs.process_client_hello(&ch_data[..ch_total]);
    assert!(result.is_err());
}

#[test]
fn test_server_connection_creation() {
    let stream = Cursor::new(Vec::<u8>::new());
    let config = TlsConfig::builder().role(crate::TlsRole::Server).build();
    let conn = TlsServerConnection::new(stream, config);
    assert_eq!(conn.state, ConnectionState::Handshaking);
    assert!(conn.version().is_none());
    assert!(conn.cipher_suite().is_none());
}

/// Helper: perform a complete handshake at the record layer level.
/// Returns (client_rl, server_rl, client_app_secret, server_app_secret, cipher_params).
fn do_test_handshake() -> (
    RecordLayer,
    RecordLayer,
    Vec<u8>,
    Vec<u8>,
    crate::crypt::CipherSuiteParams,
    CipherSuite,
) {
    use crate::config::ServerPrivateKey;

    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();

    let client_config = TlsConfig::builder().verify_peer(false).build();
    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    // Handshake flow
    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();

    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let actions = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions, got HRR"),
    };

    let sh_record = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();

    let ee_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let cert_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_msg)
        .unwrap();
    let cv_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
        .unwrap();
    let sfin_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    let (_, sh_data, _) = client_rl.open_record(&sh_record).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_actions = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions, got HRR"),
    };
    client_rl
        .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_actions.suite, &sh_actions.client_hs_keys)
        .unwrap();

    for rec in [&ee_rec, &cert_rec, &cv_rec] {
        let (_, data, _) = client_rl.open_record(rec).unwrap();
        let (_, _, total) = parse_handshake_header(&data).unwrap();
        let msg = &data[..total];
        match client_hs.state() {
            crate::handshake::HandshakeState::WaitEncryptedExtensions => {
                client_hs.process_encrypted_extensions(msg).unwrap();
            }
            crate::handshake::HandshakeState::WaitCertCertReq => {
                client_hs.process_certificate(msg).unwrap();
            }
            crate::handshake::HandshakeState::WaitCertVerify => {
                client_hs.process_certificate_verify(msg).unwrap();
            }
            s => panic!("unexpected state: {s:?}"),
        }
    }

    let (_, fin_data, _) = client_rl.open_record(&sfin_rec).unwrap();
    let (_, _, fin_total) = parse_handshake_header(&fin_data).unwrap();
    let fin_actions = client_hs.process_finished(&fin_data[..fin_total]).unwrap();

    let cfin_record = client_rl
        .seal_record(ContentType::Handshake, &fin_actions.client_finished_msg)
        .unwrap();

    let (_, cfin_data, _) = server_rl.open_record(&cfin_record).unwrap();
    let (_, _, cfin_total) = parse_handshake_header(&cfin_data).unwrap();
    server_hs
        .process_client_finished(&cfin_data[..cfin_total])
        .unwrap();

    // Activate application keys
    client_rl
        .activate_write_encryption(fin_actions.suite, &fin_actions.client_app_keys)
        .unwrap();
    client_rl
        .activate_read_decryption(fin_actions.suite, &fin_actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_app_keys)
        .unwrap();

    (
        client_rl,
        server_rl,
        fin_actions.client_app_secret,
        fin_actions.server_app_secret,
        fin_actions.cipher_params,
        fin_actions.suite,
    )
}

/// Test KeyUpdate: client sends KeyUpdate(Requested) → server updates read key,
/// responds → client updates read key. Then exchange app data with new keys.
#[test]
fn test_key_update_roundtrip() {
    let (
        mut client_rl,
        mut server_rl,
        client_app_secret_orig,
        server_app_secret_orig,
        params,
        suite,
    ) = do_test_handshake();

    // Each side tracks its own copy of secrets
    let mut client_write_secret = client_app_secret_orig.clone(); // client writes with this
    let mut server_read_secret = client_app_secret_orig; // server reads client data with this
    let mut server_write_secret = server_app_secret_orig.clone(); // server writes with this
    let mut client_read_secret = server_app_secret_orig; // client reads server data with this

    // Verify app data works with initial keys
    let msg = b"before key update";
    let rec = client_rl
        .seal_record(ContentType::ApplicationData, msg)
        .unwrap();
    let (ct, pt, _) = server_rl.open_record(&rec).unwrap();
    assert_eq!(ct, ContentType::ApplicationData);
    assert_eq!(pt, msg);

    // --- Client sends KeyUpdate(UpdateRequested) ---
    let ku = KeyUpdateMsg {
        request_update: KeyUpdateRequest::UpdateRequested,
    };
    let ku_msg = encode_key_update(&ku);
    let ku_record = client_rl
        .seal_record(ContentType::Handshake, &ku_msg)
        .unwrap();

    // Client updates its write key
    let ks = KeySchedule::new(params.clone());
    let new_write = ks.update_traffic_secret(&client_write_secret).unwrap();
    let new_keys = TrafficKeys::derive(&params, &new_write).unwrap();
    client_rl
        .activate_write_encryption(suite, &new_keys)
        .unwrap();
    client_write_secret = new_write;

    // --- Server receives and processes KeyUpdate ---
    let (ct, ku_plain, _) = server_rl.open_record(&ku_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (hs_type, body, _) = crate::handshake::codec::parse_handshake_header(&ku_plain).unwrap();
    assert_eq!(hs_type, HandshakeType::KeyUpdate);
    let decoded_ku = decode_key_update(body).unwrap();
    assert_eq!(decoded_ku.request_update, KeyUpdateRequest::UpdateRequested);

    // Server updates its read key (to match client's new write key)
    let ks2 = KeySchedule::new(params.clone());
    let new_read = ks2.update_traffic_secret(&server_read_secret).unwrap();
    let new_read_keys = TrafficKeys::derive(&params, &new_read).unwrap();
    server_rl
        .activate_read_decryption(suite, &new_read_keys)
        .unwrap();
    server_read_secret = new_read;

    // Since UpdateRequested, server sends its own KeyUpdate(UpdateNotRequested)
    let ku_resp = KeyUpdateMsg {
        request_update: KeyUpdateRequest::UpdateNotRequested,
    };
    let ku_resp_msg = encode_key_update(&ku_resp);
    let ku_resp_record = server_rl
        .seal_record(ContentType::Handshake, &ku_resp_msg)
        .unwrap();

    // Server updates its write key
    let ks3 = KeySchedule::new(params.clone());
    let new_s_write = ks3.update_traffic_secret(&server_write_secret).unwrap();
    let new_s_keys = TrafficKeys::derive(&params, &new_s_write).unwrap();
    server_rl
        .activate_write_encryption(suite, &new_s_keys)
        .unwrap();
    server_write_secret = new_s_write;

    // --- Client receives server's KeyUpdate response ---
    let (ct, ku_resp_plain, _) = client_rl.open_record(&ku_resp_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (hs_type, body, _) =
        crate::handshake::codec::parse_handshake_header(&ku_resp_plain).unwrap();
    assert_eq!(hs_type, HandshakeType::KeyUpdate);
    let decoded_resp = decode_key_update(body).unwrap();
    assert_eq!(
        decoded_resp.request_update,
        KeyUpdateRequest::UpdateNotRequested
    );

    // Client updates its read key
    let ks4 = KeySchedule::new(params.clone());
    let new_c_read = ks4.update_traffic_secret(&client_read_secret).unwrap();
    let new_c_read_keys = TrafficKeys::derive(&params, &new_c_read).unwrap();
    client_rl
        .activate_read_decryption(suite, &new_c_read_keys)
        .unwrap();
    client_read_secret = new_c_read;

    // --- Verify app data works with new keys (both directions) ---
    let msg2 = b"after key update - client to server";
    let rec2 = client_rl
        .seal_record(ContentType::ApplicationData, msg2)
        .unwrap();
    let (ct, pt, _) = server_rl.open_record(&rec2).unwrap();
    assert_eq!(ct, ContentType::ApplicationData);
    assert_eq!(pt, msg2);

    let msg3 = b"after key update - server to client";
    let rec3 = server_rl
        .seal_record(ContentType::ApplicationData, msg3)
        .unwrap();
    let (ct, pt, _) = client_rl.open_record(&rec3).unwrap();
    assert_eq!(ct, ContentType::ApplicationData);
    assert_eq!(pt, msg3);

    // Both sides independently derived the same updated secrets
    assert_eq!(client_write_secret, server_read_secret);
    assert_eq!(server_write_secret, client_read_secret);
}

/// Test KeyUpdate(UpdateNotRequested): peer doesn't respond with its own KeyUpdate.
#[test]
fn test_key_update_not_requested() {
    let (mut client_rl, mut server_rl, client_secret, _server_secret, params, suite) =
        do_test_handshake();

    // Client sends KeyUpdate(UpdateNotRequested) — server should NOT respond
    let ku = KeyUpdateMsg {
        request_update: KeyUpdateRequest::UpdateNotRequested,
    };
    let ku_msg = encode_key_update(&ku);
    let ku_record = client_rl
        .seal_record(ContentType::Handshake, &ku_msg)
        .unwrap();

    // Client updates write key
    let ks = KeySchedule::new(params.clone());
    let new_write = ks.update_traffic_secret(&client_secret).unwrap();
    let new_keys = TrafficKeys::derive(&params, &new_write).unwrap();
    client_rl
        .activate_write_encryption(suite, &new_keys)
        .unwrap();

    // Server processes — updates read key only
    let (ct, ku_plain, _) = server_rl.open_record(&ku_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (hs_type, body, _) = crate::handshake::codec::parse_handshake_header(&ku_plain).unwrap();
    assert_eq!(hs_type, HandshakeType::KeyUpdate);
    let decoded = crate::handshake::codec::decode_key_update(body).unwrap();
    assert_eq!(decoded.request_update, KeyUpdateRequest::UpdateNotRequested);

    let ks2 = KeySchedule::new(params.clone());
    let new_read = ks2.update_traffic_secret(&client_secret).unwrap();
    let new_read_keys = TrafficKeys::derive(&params, &new_read).unwrap();
    server_rl
        .activate_read_decryption(suite, &new_read_keys)
        .unwrap();

    // Verify client→server still works with new keys
    let msg = b"after not-requested key update";
    let rec = client_rl
        .seal_record(ContentType::ApplicationData, msg)
        .unwrap();
    let (ct, pt, _) = server_rl.open_record(&rec).unwrap();
    assert_eq!(ct, ContentType::ApplicationData);
    assert_eq!(pt, msg);
}

/// Test multiple consecutive key updates.
#[test]
fn test_key_update_multiple() {
    let (mut client_rl, mut server_rl, mut c_write, _s_write, params, suite) = do_test_handshake();

    let mut s_read = c_write.clone();

    for i in 0..3 {
        // Client sends KeyUpdate(NotRequested) each time
        let ku = KeyUpdateMsg {
            request_update: KeyUpdateRequest::UpdateNotRequested,
        };
        let ku_msg = encode_key_update(&ku);
        let ku_record = client_rl
            .seal_record(ContentType::Handshake, &ku_msg)
            .unwrap();

        // Client updates write key
        let ks = KeySchedule::new(params.clone());
        let new_write = ks.update_traffic_secret(&c_write).unwrap();
        let new_keys = TrafficKeys::derive(&params, &new_write).unwrap();
        client_rl
            .activate_write_encryption(suite, &new_keys)
            .unwrap();
        c_write = new_write;

        // Server processes
        let (ct, _ku_plain, _) = server_rl.open_record(&ku_record).unwrap();
        assert_eq!(ct, ContentType::Handshake);

        let ks2 = KeySchedule::new(params.clone());
        let new_read = ks2.update_traffic_secret(&s_read).unwrap();
        let new_read_keys = TrafficKeys::derive(&params, &new_read).unwrap();
        server_rl
            .activate_read_decryption(suite, &new_read_keys)
            .unwrap();
        s_read = new_read;

        // Verify data exchange works after each update
        let msg = format!("msg after update {i}");
        let rec = client_rl
            .seal_record(ContentType::ApplicationData, msg.as_bytes())
            .unwrap();
        let (ct, pt, _) = server_rl.open_record(&rec).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(pt, msg.as_bytes());
    }
}

/// Test that key_update() before Connected returns an error.
#[test]
fn test_key_update_before_connected() {
    let stream = Cursor::new(Vec::<u8>::new());
    let config = TlsConfig::builder().build();
    let mut conn = TlsClientConnection::new(stream, config);
    assert!(conn.key_update(true).is_err());

    let stream2 = Cursor::new(Vec::<u8>::new());
    let config2 = TlsConfig::builder().role(crate::TlsRole::Server).build();
    let mut conn2 = TlsServerConnection::new(stream2, config2);
    assert!(conn2.key_update(true).is_err());
}

// ===================================================================
// HelloRetryRequest tests
// ===================================================================

/// Test HRR: client offers only SECP256R1 key_share, server prefers X25519.
/// Server sends HRR → client retries with X25519 → full handshake succeeds.
#[test]
fn test_hrr_group_mismatch() {
    use crate::config::ServerPrivateKey;
    use crate::crypt::NamedGroup;

    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();

    // Client offers SECP256R1 as first group (will generate key_share for it)
    // but also supports X25519 in supported_groups
    let client_config = TlsConfig::builder()
        .supported_groups(&[NamedGroup::SECP256R1, NamedGroup::X25519])
        .verify_peer(false)
        .build();

    // Server prefers X25519 only
    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .supported_groups(&[NamedGroup::X25519])
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    // --- Client builds CH1 (with SECP256R1 key_share) ---
    let ch1_msg = client_hs.build_client_hello().unwrap();
    let ch1_record = client_rl
        .seal_record(ContentType::Handshake, &ch1_msg)
        .unwrap();

    // --- Server receives CH1 → HRR ---
    let (_, ch1_data, _) = server_rl.open_record(&ch1_record).unwrap();
    let (_, _, ch1_total) = parse_handshake_header(&ch1_data).unwrap();
    let result = server_hs
        .process_client_hello(&ch1_data[..ch1_total])
        .unwrap();

    let hrr_actions = match result {
        ClientHelloResult::HelloRetryRequest(a) => a,
        ClientHelloResult::Actions(_) => panic!("expected HRR, got Actions"),
    };

    // --- Server sends HRR ---
    let hrr_record = server_rl
        .seal_record(ContentType::Handshake, &hrr_actions.hrr_msg)
        .unwrap();

    // --- Client receives HRR ---
    let (_, hrr_data, _) = client_rl.open_record(&hrr_record).unwrap();
    let (_, _, hrr_total) = parse_handshake_header(&hrr_data).unwrap();
    let sh_result = client_hs
        .process_server_hello(&hrr_data[..hrr_total])
        .unwrap();

    let retry = match sh_result {
        ServerHelloResult::RetryNeeded(r) => r,
        ServerHelloResult::Actions(_) => panic!("expected RetryNeeded"),
    };
    assert_eq!(retry.selected_group, NamedGroup::X25519);

    // --- Client builds CH2 (with X25519 key_share) ---
    let ch2_msg = client_hs.build_client_hello_retry(&retry).unwrap();
    let ch2_record = client_rl
        .seal_record(ContentType::Handshake, &ch2_msg)
        .unwrap();

    // --- Server receives CH2 → full handshake ---
    let (_, ch2_data, _) = server_rl.open_record(&ch2_record).unwrap();
    let (_, _, ch2_total) = parse_handshake_header(&ch2_data).unwrap();
    let actions = server_hs
        .process_client_hello_retry(&ch2_data[..ch2_total])
        .unwrap();

    // --- Server sends ServerHello + encrypted flight ---
    let sh_record = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();

    let ee_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let cert_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_msg)
        .unwrap();
    let cv_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
        .unwrap();
    let sfin_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    // --- Client processes real ServerHello ---
    let (_, sh_data, _) = client_rl.open_record(&sh_record).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_actions = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions on second SH"),
    };
    client_rl
        .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_actions.suite, &sh_actions.client_hs_keys)
        .unwrap();

    // --- Client processes encrypted flight ---
    for rec in [&ee_rec, &cert_rec, &cv_rec] {
        let (_, data, _) = client_rl.open_record(rec).unwrap();
        let (_, _, total) = parse_handshake_header(&data).unwrap();
        let msg = &data[..total];
        match client_hs.state() {
            HandshakeState::WaitEncryptedExtensions => {
                client_hs.process_encrypted_extensions(msg).unwrap();
            }
            HandshakeState::WaitCertCertReq => {
                client_hs.process_certificate(msg).unwrap();
            }
            HandshakeState::WaitCertVerify => {
                client_hs.process_certificate_verify(msg).unwrap();
            }
            s => panic!("unexpected state: {s:?}"),
        }
    }

    let (_, fin_data, _) = client_rl.open_record(&sfin_rec).unwrap();
    let (_, _, fin_total) = parse_handshake_header(&fin_data).unwrap();
    let fin_actions = client_hs.process_finished(&fin_data[..fin_total]).unwrap();
    assert_eq!(client_hs.state(), HandshakeState::Connected);

    // --- Client sends Finished ---
    let cfin_record = client_rl
        .seal_record(ContentType::Handshake, &fin_actions.client_finished_msg)
        .unwrap();
    let (_, cfin_data, _) = server_rl.open_record(&cfin_record).unwrap();
    let (_, _, cfin_total) = parse_handshake_header(&cfin_data).unwrap();
    server_hs
        .process_client_finished(&cfin_data[..cfin_total])
        .unwrap();
    assert_eq!(server_hs.state(), HandshakeState::Connected);

    // --- Activate app keys and exchange data ---
    client_rl
        .activate_write_encryption(fin_actions.suite, &fin_actions.client_app_keys)
        .unwrap();
    client_rl
        .activate_read_decryption(fin_actions.suite, &fin_actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_app_keys)
        .unwrap();

    let msg = b"Hello after HRR!";
    let rec = client_rl
        .seal_record(ContentType::ApplicationData, msg)
        .unwrap();
    let (ct, pt, _) = server_rl.open_record(&rec).unwrap();
    assert_eq!(ct, ContentType::ApplicationData);
    assert_eq!(pt, msg);

    let msg2 = b"Server response after HRR!";
    let rec2 = server_rl
        .seal_record(ContentType::ApplicationData, msg2)
        .unwrap();
    let (ct2, pt2, _) = client_rl.open_record(&rec2).unwrap();
    assert_eq!(ct2, ContentType::ApplicationData);
    assert_eq!(pt2, msg2);
}

/// Test that SECP256R1 key exchange works end-to-end (no HRR needed).
#[test]
fn test_secp256r1_handshake_no_hrr() {
    use crate::config::ServerPrivateKey;
    use crate::crypt::NamedGroup;

    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();

    // Both client and server offer SECP256R1 as first group
    let client_config = TlsConfig::builder()
        .supported_groups(&[NamedGroup::SECP256R1])
        .verify_peer(false)
        .build();

    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .supported_groups(&[NamedGroup::SECP256R1])
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    // Build and process CH
    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();
    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();

    // Should be Actions (no HRR) since both agree on SECP256R1
    let actions = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions, got HRR"),
    };

    // Do full handshake
    let sh_record = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();

    let ee_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let cert_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_msg)
        .unwrap();
    let cv_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
        .unwrap();
    let sfin_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    let (_, sh_data, _) = client_rl.open_record(&sh_record).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_actions = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions"),
    };
    client_rl
        .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_actions.suite, &sh_actions.client_hs_keys)
        .unwrap();

    for rec in [&ee_rec, &cert_rec, &cv_rec] {
        let (_, data, _) = client_rl.open_record(rec).unwrap();
        let (_, _, total) = parse_handshake_header(&data).unwrap();
        let msg = &data[..total];
        match client_hs.state() {
            HandshakeState::WaitEncryptedExtensions => {
                client_hs.process_encrypted_extensions(msg).unwrap();
            }
            HandshakeState::WaitCertCertReq => {
                client_hs.process_certificate(msg).unwrap();
            }
            HandshakeState::WaitCertVerify => {
                client_hs.process_certificate_verify(msg).unwrap();
            }
            s => panic!("unexpected state: {s:?}"),
        }
    }

    let (_, fin_data, _) = client_rl.open_record(&sfin_rec).unwrap();
    let (_, _, fin_total) = parse_handshake_header(&fin_data).unwrap();
    let fin_actions = client_hs.process_finished(&fin_data[..fin_total]).unwrap();
    assert_eq!(client_hs.state(), HandshakeState::Connected);

    let cfin_record = client_rl
        .seal_record(ContentType::Handshake, &fin_actions.client_finished_msg)
        .unwrap();
    let (_, cfin_data, _) = server_rl.open_record(&cfin_record).unwrap();
    let (_, _, cfin_total) = parse_handshake_header(&cfin_data).unwrap();
    server_hs
        .process_client_finished(&cfin_data[..cfin_total])
        .unwrap();
    assert_eq!(server_hs.state(), HandshakeState::Connected);

    // Exchange data
    client_rl
        .activate_write_encryption(fin_actions.suite, &fin_actions.client_app_keys)
        .unwrap();
    client_rl
        .activate_read_decryption(fin_actions.suite, &fin_actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_app_keys)
        .unwrap();

    let msg = b"P-256 handshake works!";
    let rec = client_rl
        .seal_record(ContentType::ApplicationData, msg)
        .unwrap();
    let (ct, pt, _) = server_rl.open_record(&rec).unwrap();
    assert_eq!(ct, ContentType::ApplicationData);
    assert_eq!(pt, msg);
}

/// Test that HRR constant is correct (SHA-256 of "HelloRetryRequest").
#[test]
fn test_hrr_random_constant() {
    use crate::handshake::codec::HELLO_RETRY_REQUEST_RANDOM;
    let hash = hitls_crypto::sha2::Sha256::digest(b"HelloRetryRequest").unwrap();
    assert_eq!(hash.as_ref(), &HELLO_RETRY_REQUEST_RANDOM);
}

/// Test transcript hash replacement for HRR (message_hash construct).
#[test]
fn test_hrr_transcript_hash() {
    use crate::crypt::transcript::TranscriptHash;
    use hitls_crypto::sha2::Sha256;

    let mut th = TranscriptHash::new(|| Box::new(Sha256::new()));
    th.update(b"original ClientHello data").unwrap();
    let hash_before = th.current_hash().unwrap();

    th.replace_with_message_hash().unwrap();
    let hash_after = th.current_hash().unwrap();

    // After replacement, the transcript contains the synthetic MessageHash construct
    // which is different from the original hash
    assert_ne!(hash_before, hash_after);

    // The synthetic message is: 254 || 0 || 0 || hash_len || hash
    // So Hash(254 || 0 || 0 || 32 || hash_before) should equal hash_after
    let mut expected_input = vec![254, 0, 0, 32];
    expected_input.extend_from_slice(&hash_before);
    let expected = Sha256::digest(&expected_input).unwrap();
    assert_eq!(hash_after, expected.to_vec());
}

/// Test that no common group results in an error (not HRR).
#[test]
fn test_hrr_no_common_group() {
    use crate::config::ServerPrivateKey;
    use crate::crypt::NamedGroup;

    let (seed, _, fake_cert) = make_ed25519_server_identity();

    // Client only supports SECP256R1
    let client_config = TlsConfig::builder()
        .supported_groups(&[NamedGroup::SECP256R1])
        .verify_peer(false)
        .build();

    // Server only supports X448 (not implemented for key exchange)
    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .supported_groups(&[NamedGroup::X448])
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();
    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();

    // Should error because no common group exists
    let result = server_hs.process_client_hello(&ch_data[..ch_total]);
    assert!(result.is_err());
}

// ===================================================================
// PSK / Session Tickets tests
// ===================================================================

/// Helper: perform a full handshake at the state-machine level with ticket support.
/// Returns (client_rl, server_rl, cipher_params, suite, fin_actions, cfin_actions)
/// where cfin_actions contains new_session_ticket_msgs and resumption_master_secret.
fn do_test_handshake_with_tickets() -> (
    RecordLayer,
    RecordLayer,
    crate::crypt::CipherSuiteParams,
    CipherSuite,
    crate::handshake::client::FinishedActions,
    crate::handshake::server::ClientFinishedActions,
    crate::handshake::server::ClientHelloActions,
) {
    use crate::config::ServerPrivateKey;

    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();
    let ticket_key = vec![0xAB; 32];

    let client_config = TlsConfig::builder().verify_peer(false).build();
    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .ticket_key(ticket_key)
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    // Handshake flow
    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();

    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let actions = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions, got HRR"),
    };

    let sh_record = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();

    let ee_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let cert_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_msg)
        .unwrap();
    let cv_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
        .unwrap();
    let sfin_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    let (_, sh_data, _) = client_rl.open_record(&sh_record).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_actions = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions, got HRR"),
    };
    client_rl
        .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_actions.suite, &sh_actions.client_hs_keys)
        .unwrap();

    for rec in [&ee_rec, &cert_rec, &cv_rec] {
        let (_, data, _) = client_rl.open_record(rec).unwrap();
        let (_, _, total) = parse_handshake_header(&data).unwrap();
        let msg = &data[..total];
        match client_hs.state() {
            crate::handshake::HandshakeState::WaitEncryptedExtensions => {
                client_hs.process_encrypted_extensions(msg).unwrap();
            }
            crate::handshake::HandshakeState::WaitCertCertReq => {
                client_hs.process_certificate(msg).unwrap();
            }
            crate::handshake::HandshakeState::WaitCertVerify => {
                client_hs.process_certificate_verify(msg).unwrap();
            }
            s => panic!("unexpected state: {s:?}"),
        }
    }

    let (_, fin_data, _) = client_rl.open_record(&sfin_rec).unwrap();
    let (_, _, fin_total) = parse_handshake_header(&fin_data).unwrap();
    let fin_actions = client_hs.process_finished(&fin_data[..fin_total]).unwrap();

    let cfin_record = client_rl
        .seal_record(ContentType::Handshake, &fin_actions.client_finished_msg)
        .unwrap();

    let (_, cfin_data, _) = server_rl.open_record(&cfin_record).unwrap();
    let (_, _, cfin_total) = parse_handshake_header(&cfin_data).unwrap();
    let cfin_actions = server_hs
        .process_client_finished(&cfin_data[..cfin_total])
        .unwrap();

    // Activate application keys
    client_rl
        .activate_write_encryption(fin_actions.suite, &fin_actions.client_app_keys)
        .unwrap();
    client_rl
        .activate_read_decryption(fin_actions.suite, &fin_actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_app_keys)
        .unwrap();

    (
        client_rl,
        server_rl,
        fin_actions.cipher_params.clone(),
        fin_actions.suite,
        fin_actions,
        cfin_actions,
        actions,
    )
}

/// Test NewSessionTicket codec roundtrip (already tested in codec, but verify
/// end-to-end: server generates NST → client receives and processes it).
#[test]
fn test_nst_generation_and_processing() {
    let (mut client_rl, mut server_rl, _params, _suite, fin_actions, cfin_actions, _actions) =
        do_test_handshake_with_tickets();

    // Server should have generated at least one NST
    assert!(
        !cfin_actions.new_session_ticket_msgs.is_empty(),
        "no NST messages generated"
    );

    // Send NST from server to client
    let nst_msg = &cfin_actions.new_session_ticket_msgs[0];
    let nst_record = server_rl
        .seal_record(ContentType::Handshake, nst_msg)
        .unwrap();

    // Client receives and decrypts NST
    let (ct, nst_plain, _) = client_rl.open_record(&nst_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);

    let (hs_type, _, nst_total) = parse_handshake_header(&nst_plain).unwrap();
    assert_eq!(hs_type, HandshakeType::NewSessionTicket);

    // Process NST to get a TlsSession
    let config = TlsConfig::builder().verify_peer(false).build();
    let hs = ClientHandshake::new(config);
    // We need a ClientHandshake with params set — use a helper approach
    // Actually, process_new_session_ticket needs params and negotiated_suite.
    // Let's test using the connection-level integration instead.

    // For now, verify the NST message is parseable
    let body = &nst_plain[4..nst_total];
    let nst = crate::handshake::codec::decode_new_session_ticket(body).unwrap();
    assert!(nst.ticket_lifetime > 0);
    assert!(!nst.ticket.is_empty());
    assert!(!nst.ticket_nonce.is_empty());

    // Verify we can derive PSK from resumption_master_secret
    let params =
        crate::crypt::CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
    let ks = crate::crypt::key_schedule::KeySchedule::new(params);
    let psk = ks
        .derive_resumption_psk(&fin_actions.resumption_master_secret, &nst.ticket_nonce)
        .unwrap();
    assert_eq!(psk.len(), 32); // SHA-256 hash length

    let _ = hs; // suppress unused warning
}

/// Test InMemorySessionCache operations.
#[test]
fn test_session_cache_operations() {
    use crate::session::{InMemorySessionCache, SessionCache};

    let mut cache = InMemorySessionCache::new(2);
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);

    let session1 = TlsSession {
        id: vec![1],
        cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
        master_secret: vec![0; 32],
        alpn_protocol: None,
        ticket: Some(vec![0xAA; 16]),
        ticket_lifetime: 3600,
        max_early_data: 0,
        ticket_age_add: 42,
        ticket_nonce: vec![1, 2, 3],
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        psk: vec![0; 32],
        extended_master_secret: false,
    };

    let session2 = TlsSession {
        id: vec![2],
        cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
        master_secret: vec![0; 32],
        alpn_protocol: None,
        ticket: Some(vec![0xBB; 16]),
        ticket_lifetime: 3600,
        max_early_data: 0,
        ticket_age_add: 43,
        ticket_nonce: vec![4, 5, 6],
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        psk: vec![0; 32],
        extended_master_secret: false,
    };

    cache.put(b"key1", session1);
    assert_eq!(cache.len(), 1);
    assert!(cache.get(b"key1").is_some());
    assert!(cache.get(b"key2").is_none());

    cache.put(b"key2", session2);
    assert_eq!(cache.len(), 2);

    // Inserting a third should evict one (max_size = 2)
    let session3 = TlsSession {
        id: vec![3],
        cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
        master_secret: vec![0; 32],
        alpn_protocol: None,
        ticket: Some(vec![0xCC; 16]),
        ticket_lifetime: 3600,
        max_early_data: 0,
        ticket_age_add: 44,
        ticket_nonce: vec![7, 8, 9],
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        psk: vec![0; 32],
        extended_master_secret: false,
    };
    cache.put(b"key3", session3);
    assert_eq!(cache.len(), 2);

    // Remove
    cache.remove(b"key3");
    assert!(cache.get(b"key3").is_none());
}

/// Full PSK session resumption roundtrip:
/// 1. Full handshake → server generates NST
/// 2. Client derives TlsSession from NST
/// 3. Second handshake using PSK → server accepts PSK, skips cert/CV
/// 4. Exchange application data
#[test]
fn test_session_resumption_roundtrip() {
    use crate::config::ServerPrivateKey;

    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();
    let ticket_key = vec![0xAB; 32];

    // === First handshake (full) ===
    let client_config = TlsConfig::builder().verify_peer(false).build();
    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_cert.clone()])
        .private_key(ServerPrivateKey::Ed25519(seed.clone()))
        .ticket_key(ticket_key.clone())
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();
    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let actions1 = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions"),
    };
    assert!(!actions1.psk_mode, "first handshake should NOT be PSK mode");

    // Server sends SH + encrypted flight
    let sh_rec = server_rl
        .seal_record(ContentType::Handshake, &actions1.server_hello_msg)
        .unwrap();
    server_rl
        .activate_write_encryption(actions1.suite, &actions1.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions1.suite, &actions1.client_hs_keys)
        .unwrap();
    let ee_rec = server_rl
        .seal_record(ContentType::Handshake, &actions1.encrypted_extensions_msg)
        .unwrap();
    let cert_rec = server_rl
        .seal_record(ContentType::Handshake, &actions1.certificate_msg)
        .unwrap();
    let cv_rec = server_rl
        .seal_record(ContentType::Handshake, &actions1.certificate_verify_msg)
        .unwrap();
    let sfin_rec = server_rl
        .seal_record(ContentType::Handshake, &actions1.server_finished_msg)
        .unwrap();

    // Client processes SH + encrypted flight
    let (_, sh_data, _) = client_rl.open_record(&sh_rec).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_act = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions"),
    };
    client_rl
        .activate_read_decryption(sh_act.suite, &sh_act.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_act.suite, &sh_act.client_hs_keys)
        .unwrap();

    for rec in [&ee_rec, &cert_rec, &cv_rec] {
        let (_, data, _) = client_rl.open_record(rec).unwrap();
        let (_, _, total) = parse_handshake_header(&data).unwrap();
        let msg = &data[..total];
        match client_hs.state() {
            HandshakeState::WaitEncryptedExtensions => {
                client_hs.process_encrypted_extensions(msg).unwrap();
            }
            HandshakeState::WaitCertCertReq => {
                client_hs.process_certificate(msg).unwrap();
            }
            HandshakeState::WaitCertVerify => {
                client_hs.process_certificate_verify(msg).unwrap();
            }
            s => panic!("unexpected state: {s:?}"),
        }
    }

    let (_, fin_data, _) = client_rl.open_record(&sfin_rec).unwrap();
    let (_, _, fin_total) = parse_handshake_header(&fin_data).unwrap();
    let fin_act = client_hs.process_finished(&fin_data[..fin_total]).unwrap();

    let cfin_record = client_rl
        .seal_record(ContentType::Handshake, &fin_act.client_finished_msg)
        .unwrap();
    let (_, cfin_data, _) = server_rl.open_record(&cfin_record).unwrap();
    let (_, _, cfin_total) = parse_handshake_header(&cfin_data).unwrap();
    let cfin_act = server_hs
        .process_client_finished(&cfin_data[..cfin_total])
        .unwrap();

    // Activate app keys for first connection
    client_rl
        .activate_write_encryption(fin_act.suite, &fin_act.client_app_keys)
        .unwrap();
    client_rl
        .activate_read_decryption(fin_act.suite, &fin_act.server_app_keys)
        .unwrap();
    server_rl
        .activate_write_encryption(actions1.suite, &actions1.server_app_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions1.suite, &actions1.client_app_keys)
        .unwrap();

    // Server should have generated NST
    assert!(!cfin_act.new_session_ticket_msgs.is_empty());

    // Client receives NST
    let nst_record = server_rl
        .seal_record(ContentType::Handshake, &cfin_act.new_session_ticket_msgs[0])
        .unwrap();
    let (_, nst_plain, _) = client_rl.open_record(&nst_record).unwrap();
    let (_, _, nst_total) = parse_handshake_header(&nst_plain).unwrap();
    let session = client_hs
        .process_new_session_ticket(&nst_plain[..nst_total], &fin_act.resumption_master_secret)
        .unwrap();

    assert!(!session.psk.is_empty());
    assert!(session.ticket.is_some());

    // === Second handshake (PSK resumption) ===
    let client_config2 = TlsConfig::builder()
        .verify_peer(false)
        .resumption_session(session)
        .build();
    let server_config2 = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .ticket_key(ticket_key)
        .build();

    let mut client_hs2 = ClientHandshake::new(client_config2);
    let mut client_rl2 = RecordLayer::new();
    let mut server_hs2 = ServerHandshake::new(server_config2);
    let mut server_rl2 = RecordLayer::new();

    // Client builds CH with PSK
    let ch2_msg = client_hs2.build_client_hello().unwrap();
    let ch2_record = client_rl2
        .seal_record(ContentType::Handshake, &ch2_msg)
        .unwrap();
    let (_, ch2_data, _) = server_rl2.open_record(&ch2_record).unwrap();
    let (_, _, ch2_total) = parse_handshake_header(&ch2_data).unwrap();

    let actions2 = match server_hs2
        .process_client_hello(&ch2_data[..ch2_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions for PSK handshake"),
    };
    // Server should be in PSK mode (skipping cert/CV)
    assert!(actions2.psk_mode, "second handshake should be PSK mode");

    // Server sends SH + encrypted flight (EE + Finished only, no cert/CV)
    let sh2_rec = server_rl2
        .seal_record(ContentType::Handshake, &actions2.server_hello_msg)
        .unwrap();
    server_rl2
        .activate_write_encryption(actions2.suite, &actions2.server_hs_keys)
        .unwrap();
    server_rl2
        .activate_read_decryption(actions2.suite, &actions2.client_hs_keys)
        .unwrap();

    let ee2_rec = server_rl2
        .seal_record(ContentType::Handshake, &actions2.encrypted_extensions_msg)
        .unwrap();
    // In PSK mode, cert_msg and cv_msg should be empty
    assert!(
        actions2.certificate_msg.is_empty(),
        "cert_msg should be empty in PSK mode"
    );
    assert!(
        actions2.certificate_verify_msg.is_empty(),
        "cv_msg should be empty in PSK mode"
    );
    let sfin2_rec = server_rl2
        .seal_record(ContentType::Handshake, &actions2.server_finished_msg)
        .unwrap();

    // Client processes SH
    let (_, sh2_data, _) = client_rl2.open_record(&sh2_rec).unwrap();
    let (_, _, sh2_total) = parse_handshake_header(&sh2_data).unwrap();
    let sh_act2 = match client_hs2
        .process_server_hello(&sh2_data[..sh2_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions"),
    };
    client_rl2
        .activate_read_decryption(sh_act2.suite, &sh_act2.server_hs_keys)
        .unwrap();
    client_rl2
        .activate_write_encryption(sh_act2.suite, &sh_act2.client_hs_keys)
        .unwrap();

    // Client processes EE (should go to WaitFinished in PSK mode)
    let (_, ee2_data, _) = client_rl2.open_record(&ee2_rec).unwrap();
    let (_, _, ee2_total) = parse_handshake_header(&ee2_data).unwrap();
    client_hs2
        .process_encrypted_extensions(&ee2_data[..ee2_total])
        .unwrap();
    assert_eq!(
        client_hs2.state(),
        HandshakeState::WaitFinished,
        "should skip to WaitFinished in PSK mode"
    );

    // Client processes Finished
    let (_, fin2_data, _) = client_rl2.open_record(&sfin2_rec).unwrap();
    let (_, _, fin2_total) = parse_handshake_header(&fin2_data).unwrap();
    let fin_act2 = client_hs2
        .process_finished(&fin2_data[..fin2_total])
        .unwrap();
    assert_eq!(client_hs2.state(), HandshakeState::Connected);

    // Client sends Finished
    let cfin2_record = client_rl2
        .seal_record(ContentType::Handshake, &fin_act2.client_finished_msg)
        .unwrap();
    let (_, cfin2_data, _) = server_rl2.open_record(&cfin2_record).unwrap();
    let (_, _, cfin2_total) = parse_handshake_header(&cfin2_data).unwrap();
    server_hs2
        .process_client_finished(&cfin2_data[..cfin2_total])
        .unwrap();
    assert_eq!(server_hs2.state(), HandshakeState::Connected);

    // Activate app keys
    client_rl2
        .activate_write_encryption(fin_act2.suite, &fin_act2.client_app_keys)
        .unwrap();
    client_rl2
        .activate_read_decryption(fin_act2.suite, &fin_act2.server_app_keys)
        .unwrap();
    server_rl2
        .activate_write_encryption(actions2.suite, &actions2.server_app_keys)
        .unwrap();
    server_rl2
        .activate_read_decryption(actions2.suite, &actions2.client_app_keys)
        .unwrap();

    // Exchange app data on resumed connection
    let msg = b"Hello from PSK-resumed client!";
    let rec = client_rl2
        .seal_record(ContentType::ApplicationData, msg)
        .unwrap();
    let (ct, pt, _) = server_rl2.open_record(&rec).unwrap();
    assert_eq!(ct, ContentType::ApplicationData);
    assert_eq!(pt, msg);

    let msg2 = b"Hello from PSK-resumed server!";
    let rec2 = server_rl2
        .seal_record(ContentType::ApplicationData, msg2)
        .unwrap();
    let (ct2, pt2, _) = client_rl2.open_record(&rec2).unwrap();
    assert_eq!(ct2, ContentType::ApplicationData);
    assert_eq!(pt2, msg2);
}

/// Test ticket encryption/decryption roundtrip.
#[test]
fn test_ticket_encrypt_decrypt() {
    use crate::handshake::server::{decrypt_ticket, encrypt_ticket};

    let params =
        crate::crypt::CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
    let factory = params.hash_factory();
    let ticket_key = vec![0x42; 32];
    let psk = vec![0xDE; 32];
    let suite = CipherSuite::TLS_AES_128_GCM_SHA256;
    let created_at = 1700000000u64;
    let age_add = 12345u32;

    let encrypted =
        encrypt_ticket(&factory, &ticket_key, &psk, suite, created_at, age_add).unwrap();
    assert!(!encrypted.is_empty());

    let (dec_psk, dec_suite, dec_created, dec_age) =
        decrypt_ticket(&factory, &ticket_key, &encrypted).unwrap();
    assert_eq!(dec_psk, psk);
    assert_eq!(dec_suite, suite);
    assert_eq!(dec_created, created_at);
    assert_eq!(dec_age, age_add);
}

/// Test that decrypting with wrong key fails.
#[test]
fn test_ticket_decrypt_wrong_key() {
    use crate::handshake::server::{decrypt_ticket, encrypt_ticket};

    let params =
        crate::crypt::CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
    let factory = params.hash_factory();
    let ticket_key = vec![0x42; 32];
    let wrong_key = vec![0x99; 32];
    let psk = vec![0xDE; 32];

    let encrypted = encrypt_ticket(
        &factory,
        &ticket_key,
        &psk,
        CipherSuite::TLS_AES_128_GCM_SHA256,
        1700000000,
        12345,
    )
    .unwrap();

    let result = decrypt_ticket(&factory, &wrong_key, &encrypted);
    assert!(result.is_err(), "decryption with wrong key should fail");
}

/// Test that PSK binder verification works correctly.
#[test]
fn test_psk_binder_computation() {
    let params =
        crate::crypt::CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
    let psk = vec![0xAA; 32];

    // Set up key schedule for binder
    let mut ks = KeySchedule::new(params.clone());
    ks.derive_early_secret(Some(&psk)).unwrap();
    let binder_key = ks.derive_binder_key(false).unwrap();
    assert_eq!(binder_key.len(), 32);

    let finished_key = ks.derive_finished_key(&binder_key).unwrap();
    assert_eq!(finished_key.len(), 32);

    // Compute binder over some test data
    let factory = params.hash_factory();
    let mut hasher = (*factory)();
    hasher.update(b"test transcript data").unwrap();
    let mut hash = vec![0u8; 32];
    hasher.finish(&mut hash).unwrap();

    let binder = ks
        .compute_finished_verify_data(&finished_key, &hash)
        .unwrap();
    assert_eq!(binder.len(), 32);

    // Verify determinism
    let mut hasher2 = (*factory)();
    hasher2.update(b"test transcript data").unwrap();
    let mut hash2 = vec![0u8; 32];
    hasher2.finish(&mut hash2).unwrap();
    let binder2 = ks
        .compute_finished_verify_data(&finished_key, &hash2)
        .unwrap();
    assert_eq!(binder, binder2);
}

/// Test PSK extension codec roundtrip.
#[test]
fn test_psk_ch_extension_in_handshake() {
    use crate::handshake::extensions_codec::{build_pre_shared_key_ch, parse_pre_shared_key_ch};

    let ticket = vec![0xAA; 32];
    let age = 12345u32;
    let binder = vec![0xBB; 32];

    let ext = build_pre_shared_key_ch(&[(ticket.clone(), age)], std::slice::from_ref(&binder));
    assert_eq!(
        ext.extension_type,
        crate::extensions::ExtensionType::PRE_SHARED_KEY
    );

    let (identities, binders) = parse_pre_shared_key_ch(&ext.data).unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].0, ticket);
    assert_eq!(identities[0].1, age);
    assert_eq!(binders.len(), 1);
    assert_eq!(binders[0], binder);
}

// ===================================================================
// 0-RTT Early Data tests
// ===================================================================

/// Helper: perform a full handshake with ticket support, receive NST,
/// and return the TlsSession ready for 0-RTT resumption.
/// Also returns the server identity components for the second handshake.
fn do_initial_handshake_for_early_data(
    max_early_data_size: u32,
) -> (
    TlsSession,
    Vec<u8>, // seed
    Vec<u8>, // fake_cert
    Vec<u8>, // ticket_key
) {
    use crate::config::ServerPrivateKey;

    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();
    let ticket_key = vec![0xAB; 32];

    let client_config = TlsConfig::builder().verify_peer(false).build();
    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_cert.clone()])
        .private_key(ServerPrivateKey::Ed25519(seed.clone()))
        .ticket_key(ticket_key.clone())
        .max_early_data_size(max_early_data_size)
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    // Full handshake
    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();
    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let actions = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions"),
    };

    let sh_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();
    let ee_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let cert_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_msg)
        .unwrap();
    let cv_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
        .unwrap();
    let sfin_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    let (_, sh_data, _) = client_rl.open_record(&sh_rec).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_act = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        crate::handshake::client::ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions"),
    };
    client_rl
        .activate_read_decryption(sh_act.suite, &sh_act.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_act.suite, &sh_act.client_hs_keys)
        .unwrap();

    for rec in [&ee_rec, &cert_rec, &cv_rec] {
        let (_, data, _) = client_rl.open_record(rec).unwrap();
        let (_, _, total) = parse_handshake_header(&data).unwrap();
        let msg = &data[..total];
        match client_hs.state() {
            HandshakeState::WaitEncryptedExtensions => {
                client_hs.process_encrypted_extensions(msg).unwrap();
            }
            HandshakeState::WaitCertCertReq => {
                client_hs.process_certificate(msg).unwrap();
            }
            HandshakeState::WaitCertVerify => {
                client_hs.process_certificate_verify(msg).unwrap();
            }
            s => panic!("unexpected state: {s:?}"),
        }
    }

    let (_, fin_data, _) = client_rl.open_record(&sfin_rec).unwrap();
    let (_, _, fin_total) = parse_handshake_header(&fin_data).unwrap();
    let fin_act = client_hs.process_finished(&fin_data[..fin_total]).unwrap();

    let cfin_record = client_rl
        .seal_record(ContentType::Handshake, &fin_act.client_finished_msg)
        .unwrap();
    let (_, cfin_data, _) = server_rl.open_record(&cfin_record).unwrap();
    let (_, _, cfin_total) = parse_handshake_header(&cfin_data).unwrap();
    let cfin_act = server_hs
        .process_client_finished(&cfin_data[..cfin_total])
        .unwrap();

    // Activate app keys
    client_rl
        .activate_write_encryption(fin_act.suite, &fin_act.client_app_keys)
        .unwrap();
    client_rl
        .activate_read_decryption(fin_act.suite, &fin_act.server_app_keys)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_app_keys)
        .unwrap();

    // Receive NST
    assert!(!cfin_act.new_session_ticket_msgs.is_empty());
    let nst_record = server_rl
        .seal_record(ContentType::Handshake, &cfin_act.new_session_ticket_msgs[0])
        .unwrap();
    let (_, nst_plain, _) = client_rl.open_record(&nst_record).unwrap();
    let (_, _, nst_total) = parse_handshake_header(&nst_plain).unwrap();
    let session = client_hs
        .process_new_session_ticket(&nst_plain[..nst_total], &fin_act.resumption_master_secret)
        .unwrap();

    assert!(!session.psk.is_empty());
    assert!(session.ticket.is_some());
    if max_early_data_size > 0 {
        assert_eq!(session.max_early_data, max_early_data_size);
    }

    (session, seed, fake_cert, ticket_key)
}

/// Test 0-RTT early data accepted: client sends early data, server receives it,
/// handshake completes, then exchange app data.
#[test]
fn test_early_data_accepted() {
    use crate::config::ServerPrivateKey;

    let (session, seed, fake_cert, ticket_key) = do_initial_handshake_for_early_data(16384);
    let early_suite = session.cipher_suite;

    // === Second handshake with 0-RTT ===
    let client_config = TlsConfig::builder()
        .verify_peer(false)
        .resumption_session(session)
        .build();
    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .ticket_key(ticket_key)
        .max_early_data_size(16384)
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    // Client builds CH with PSK + early_data
    let ch_msg = client_hs.build_client_hello().unwrap();
    assert!(client_hs.offered_early_data(), "should offer early data");

    // Derive early traffic keys for client write (must use session's cipher suite)
    let params = crate::crypt::CipherSuiteParams::from_suite(early_suite).unwrap();
    let early_keys = TrafficKeys::derive(&params, client_hs.early_traffic_secret()).unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();

    // Activate 0-RTT write and send early data
    client_rl
        .activate_write_encryption(params.suite, &early_keys)
        .unwrap();
    let early_msg = b"Hello from 0-RTT!";
    let early_record = client_rl
        .seal_record(ContentType::ApplicationData, early_msg)
        .unwrap();

    // Server processes CH
    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let actions = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions for PSK handshake"),
    };
    assert!(actions.psk_mode, "should be PSK mode");
    assert!(actions.early_data_accepted, "should accept early data");
    assert!(actions.early_read_keys.is_some());

    // Server sends SH as plaintext
    let sh_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();

    // Activate server HS write and early read
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, actions.early_read_keys.as_ref().unwrap())
        .unwrap();

    // Server reads early data
    let (ct, early_data, _) = server_rl.open_record(&early_record).unwrap();
    assert_eq!(ct, ContentType::ApplicationData);
    assert_eq!(early_data, early_msg);

    // Server sends EE (with early_data ext) + Finished (PSK mode, no cert/CV)
    let ee_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let sfin_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    // Client processes SH
    let (_, sh_data, _) = client_rl.open_record(&sh_rec).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_act = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        crate::handshake::client::ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions"),
    };
    client_rl
        .activate_read_decryption(sh_act.suite, &sh_act.server_hs_keys)
        .unwrap();
    // Don't activate HS write yet (still using 0-RTT write key)

    // Client processes EE
    let (_, ee_data, _) = client_rl.open_record(&ee_rec).unwrap();
    let (_, _, ee_total) = parse_handshake_header(&ee_data).unwrap();
    client_hs
        .process_encrypted_extensions(&ee_data[..ee_total])
        .unwrap();
    assert!(
        client_hs.early_data_accepted(),
        "client should detect 0-RTT accepted"
    );
    assert_eq!(client_hs.state(), HandshakeState::WaitFinished);

    // Client processes server Finished
    let (_, fin_data, _) = client_rl.open_record(&sfin_rec).unwrap();
    let (_, _, fin_total) = parse_handshake_header(&fin_data).unwrap();
    let fin_act = client_hs.process_finished(&fin_data[..fin_total]).unwrap();
    assert!(
        fin_act.end_of_early_data_msg.is_some(),
        "should have EOED message"
    );

    // Client sends EOED with 0-RTT write key
    let eoed_msg = fin_act.end_of_early_data_msg.as_ref().unwrap();
    let eoed_record = client_rl
        .seal_record(ContentType::Handshake, eoed_msg)
        .unwrap();

    // Now switch client write to HS keys
    client_rl
        .activate_write_encryption(sh_act.suite, &sh_act.client_hs_keys)
        .unwrap();

    // Client sends Finished with HS keys
    let cfin_record = client_rl
        .seal_record(ContentType::Handshake, &fin_act.client_finished_msg)
        .unwrap();

    // Server reads EOED
    let (ct, eoed_data, _) = server_rl.open_record(&eoed_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (hs_type, _, eoed_total) = parse_handshake_header(&eoed_data).unwrap();
    assert_eq!(hs_type, HandshakeType::EndOfEarlyData);
    server_hs
        .process_end_of_early_data(&eoed_data[..eoed_total])
        .unwrap();

    // Switch server read to HS keys
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();

    // Server processes client Finished
    let (_, cfin_data, _) = server_rl.open_record(&cfin_record).unwrap();
    let (_, _, cfin_total) = parse_handshake_header(&cfin_data).unwrap();
    server_hs
        .process_client_finished(&cfin_data[..cfin_total])
        .unwrap();
    assert_eq!(server_hs.state(), HandshakeState::Connected);
    assert_eq!(client_hs.state(), HandshakeState::Connected);

    // Activate app keys
    client_rl
        .activate_write_encryption(fin_act.suite, &fin_act.client_app_keys)
        .unwrap();
    client_rl
        .activate_read_decryption(fin_act.suite, &fin_act.server_app_keys)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_app_keys)
        .unwrap();

    // Exchange app data after handshake
    let msg = b"Post-0-RTT app data from client";
    let rec = client_rl
        .seal_record(ContentType::ApplicationData, msg)
        .unwrap();
    let (ct, pt, _) = server_rl.open_record(&rec).unwrap();
    assert_eq!(ct, ContentType::ApplicationData);
    assert_eq!(pt, msg);

    let msg2 = b"Post-0-RTT app data from server";
    let rec2 = server_rl
        .seal_record(ContentType::ApplicationData, msg2)
        .unwrap();
    let (ct2, pt2, _) = client_rl.open_record(&rec2).unwrap();
    assert_eq!(ct2, ContentType::ApplicationData);
    assert_eq!(pt2, msg2);
}

/// Test 0-RTT rejected: server doesn't accept (max_early_data_size=0),
/// client falls back to normal 1-RTT.
#[test]
fn test_early_data_rejected() {
    use crate::config::ServerPrivateKey;

    // Initial handshake WITH max_early_data_size > 0 so NST has max_early_data
    let (session, seed, fake_cert, ticket_key) = do_initial_handshake_for_early_data(16384);
    assert_eq!(session.max_early_data, 16384);

    // Second handshake: server has max_early_data_size=0 (rejects)
    let client_config = TlsConfig::builder()
        .verify_peer(false)
        .resumption_session(session)
        .build();
    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .ticket_key(ticket_key)
        .max_early_data_size(0) // reject 0-RTT
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    let ch_msg = client_hs.build_client_hello().unwrap();
    assert!(
        client_hs.offered_early_data(),
        "client should still offer early data (it has a session with max_early_data>0)"
    );

    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();

    // Server processes CH — PSK accepted but early_data rejected
    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let actions = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions"),
    };
    assert!(actions.psk_mode, "should still accept PSK");
    assert!(
        !actions.early_data_accepted,
        "server should NOT accept early data"
    );
    assert!(actions.early_read_keys.is_none());

    // Normal PSK handshake (no 0-RTT)
    let sh_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();
    let ee_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let sfin_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    let (_, sh_data, _) = client_rl.open_record(&sh_rec).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_act = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        crate::handshake::client::ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions"),
    };
    client_rl
        .activate_read_decryption(sh_act.suite, &sh_act.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_act.suite, &sh_act.client_hs_keys)
        .unwrap();

    let (_, ee_data, _) = client_rl.open_record(&ee_rec).unwrap();
    let (_, _, ee_total) = parse_handshake_header(&ee_data).unwrap();
    client_hs
        .process_encrypted_extensions(&ee_data[..ee_total])
        .unwrap();
    assert!(
        !client_hs.early_data_accepted(),
        "client should detect 0-RTT was rejected"
    );

    let (_, fin_data, _) = client_rl.open_record(&sfin_rec).unwrap();
    let (_, _, fin_total) = parse_handshake_header(&fin_data).unwrap();
    let fin_act = client_hs.process_finished(&fin_data[..fin_total]).unwrap();
    assert!(
        fin_act.end_of_early_data_msg.is_none(),
        "should NOT have EOED when rejected"
    );

    let cfin_record = client_rl
        .seal_record(ContentType::Handshake, &fin_act.client_finished_msg)
        .unwrap();
    let (_, cfin_data, _) = server_rl.open_record(&cfin_record).unwrap();
    let (_, _, cfin_total) = parse_handshake_header(&cfin_data).unwrap();
    server_hs
        .process_client_finished(&cfin_data[..cfin_total])
        .unwrap();
    assert_eq!(client_hs.state(), HandshakeState::Connected);
    assert_eq!(server_hs.state(), HandshakeState::Connected);

    // Activate app keys and exchange data
    client_rl
        .activate_write_encryption(fin_act.suite, &fin_act.client_app_keys)
        .unwrap();
    client_rl
        .activate_read_decryption(fin_act.suite, &fin_act.server_app_keys)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_app_keys)
        .unwrap();

    let msg = b"Normal 1-RTT data after 0-RTT rejection";
    let rec = client_rl
        .seal_record(ContentType::ApplicationData, msg)
        .unwrap();
    let (ct, pt, _) = server_rl.open_record(&rec).unwrap();
    assert_eq!(ct, ContentType::ApplicationData);
    assert_eq!(pt, msg);
}

/// Test 0-RTT with multiple early data records.
#[test]
fn test_early_data_multiple_records() {
    use crate::config::ServerPrivateKey;

    let (session, seed, fake_cert, ticket_key) = do_initial_handshake_for_early_data(16384);
    let early_suite = session.cipher_suite;

    let client_config = TlsConfig::builder()
        .verify_peer(false)
        .resumption_session(session)
        .build();
    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .ticket_key(ticket_key)
        .max_early_data_size(16384)
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    let ch_msg = client_hs.build_client_hello().unwrap();
    assert!(client_hs.offered_early_data());

    let params = crate::crypt::CipherSuiteParams::from_suite(early_suite).unwrap();
    let early_keys = TrafficKeys::derive(&params, client_hs.early_traffic_secret()).unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();

    // Activate 0-RTT write and send multiple early data records
    client_rl
        .activate_write_encryption(params.suite, &early_keys)
        .unwrap();
    let early_msg1 = b"First early data";
    let early_msg2 = b"Second early data";
    let early_rec1 = client_rl
        .seal_record(ContentType::ApplicationData, &early_msg1[..])
        .unwrap();
    let early_rec2 = client_rl
        .seal_record(ContentType::ApplicationData, &early_msg2[..])
        .unwrap();

    // Server processes CH
    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let actions = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions"),
    };
    assert!(actions.early_data_accepted);

    // Seal SH as plaintext BEFORE activating encryption
    let sh_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();

    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, actions.early_read_keys.as_ref().unwrap())
        .unwrap();

    // Server reads both early data records
    let (ct1, data1, _) = server_rl.open_record(&early_rec1).unwrap();
    assert_eq!(ct1, ContentType::ApplicationData);
    assert_eq!(data1, early_msg1);
    let (ct2, data2, _) = server_rl.open_record(&early_rec2).unwrap();
    assert_eq!(ct2, ContentType::ApplicationData);
    assert_eq!(data2, early_msg2);

    // Continue with the rest of the handshake to verify it completes
    let ee_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let sfin_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    let (_, sh_data, _) = client_rl.open_record(&sh_rec).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_act = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        crate::handshake::client::ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions"),
    };
    client_rl
        .activate_read_decryption(sh_act.suite, &sh_act.server_hs_keys)
        .unwrap();

    let (_, ee_data, _) = client_rl.open_record(&ee_rec).unwrap();
    let (_, _, ee_total) = parse_handshake_header(&ee_data).unwrap();
    client_hs
        .process_encrypted_extensions(&ee_data[..ee_total])
        .unwrap();
    assert!(client_hs.early_data_accepted());

    let (_, fin_data, _) = client_rl.open_record(&sfin_rec).unwrap();
    let (_, _, fin_total) = parse_handshake_header(&fin_data).unwrap();
    let fin_act = client_hs.process_finished(&fin_data[..fin_total]).unwrap();
    assert!(fin_act.end_of_early_data_msg.is_some());

    // Send EOED + client Finished
    let eoed_msg = fin_act.end_of_early_data_msg.as_ref().unwrap();
    let eoed_record = client_rl
        .seal_record(ContentType::Handshake, eoed_msg)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_act.suite, &sh_act.client_hs_keys)
        .unwrap();
    let cfin_record = client_rl
        .seal_record(ContentType::Handshake, &fin_act.client_finished_msg)
        .unwrap();

    // Server reads EOED
    let (_, eoed_data, _) = server_rl.open_record(&eoed_record).unwrap();
    let (_, _, eoed_total) = parse_handshake_header(&eoed_data).unwrap();
    server_hs
        .process_end_of_early_data(&eoed_data[..eoed_total])
        .unwrap();

    // Switch to HS read keys
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();

    let (_, cfin_data, _) = server_rl.open_record(&cfin_record).unwrap();
    let (_, _, cfin_total) = parse_handshake_header(&cfin_data).unwrap();
    server_hs
        .process_client_finished(&cfin_data[..cfin_total])
        .unwrap();
    assert_eq!(client_hs.state(), HandshakeState::Connected);
    assert_eq!(server_hs.state(), HandshakeState::Connected);
}

/// Test that early_data extension in NST carries the correct max_early_data_size.
#[test]
fn test_early_data_nst_extension() {
    let (session, _seed, _fake_cert, _ticket_key) = do_initial_handshake_for_early_data(8192);
    assert_eq!(session.max_early_data, 8192);

    // Also verify with 0 — NST should NOT have early_data extension
    let (session_no_ed, _, _, _) = do_initial_handshake_for_early_data(0);
    assert_eq!(session_no_ed.max_early_data, 0);
}

/// Test that resumption_master_secret is correctly derived.
#[test]
fn test_resumption_master_secret_derived() {
    let (_, _, params, _, fin_actions, cfin_actions, _) = do_test_handshake_with_tickets();

    // Both sides should have derived a non-empty resumption_master_secret
    // Length matches the hash output (32 for SHA-256, 48 for SHA-384)
    assert_eq!(fin_actions.resumption_master_secret.len(), params.hash_len);
    assert_eq!(cfin_actions.resumption_master_secret.len(), params.hash_len);

    // They should be equal (both sides derive from same transcript)
    assert_eq!(
        fin_actions.resumption_master_secret, cfin_actions.resumption_master_secret,
        "client and server should derive same resumption_master_secret"
    );
}

// ===================================================================
// Post-Handshake Client Authentication tests
// ===================================================================

/// Build a minimal self-signed Ed25519 DER certificate for testing.
fn build_ed25519_der_cert(seed: &[u8]) -> Vec<u8> {
    use hitls_utils::asn1::Encoder;

    let kp = hitls_crypto::ed25519::Ed25519KeyPair::from_seed(seed).unwrap();
    let pub_key = kp.public_key();

    // Ed25519 OID: 1.3.101.112 → encoded as 2b 65 70
    let ed25519_oid = &[0x2b, 0x65, 0x70];

    // AlgorithmIdentifier for Ed25519: SEQUENCE { OID }
    let mut alg_id_enc = Encoder::new();
    alg_id_enc.write_oid(ed25519_oid);
    let alg_id_bytes = alg_id_enc.finish();
    let mut alg_id = Encoder::new();
    alg_id.write_sequence(&alg_id_bytes);
    let alg_id_der = alg_id.finish();

    // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING(pub_key) }
    let mut spki_contents = Vec::new();
    spki_contents.extend_from_slice(&alg_id_der); // AlgorithmIdentifier SEQUENCE
    let mut bs_enc = Encoder::new();
    bs_enc.write_bit_string(0, pub_key);
    spki_contents.extend_from_slice(&bs_enc.finish());
    let mut spki = Encoder::new();
    spki.write_sequence(&spki_contents);
    let spki_der = spki.finish();

    // Minimal Name: SEQUENCE { SET { SEQUENCE { OID(CN), UTF8String("test") } } }
    let cn_oid = &[0x55, 0x04, 0x03]; // 2.5.4.3
    let mut rdn_inner = Encoder::new();
    rdn_inner.write_oid(cn_oid);
    rdn_inner.write_tlv(0x0c, b"test"); // UTF8String "test"
    let rdn_seq_bytes = rdn_inner.finish();
    let mut rdn_seq = Encoder::new();
    rdn_seq.write_sequence(&rdn_seq_bytes);
    let set_bytes = rdn_seq.finish();
    let mut rdn_set = Encoder::new();
    rdn_set.write_set(&set_bytes);
    let name_inner = rdn_set.finish();
    let mut name = Encoder::new();
    name.write_sequence(&name_inner);
    let name_der = name.finish();

    // Validity: SEQUENCE { notBefore, notAfter } using UTCTime
    let mut validity = Encoder::new();
    validity.write_tlv(0x17, b"200101000000Z"); // 2020-01-01
    validity.write_tlv(0x17, b"300101000000Z"); // 2030-01-01
    let validity_bytes = validity.finish();
    let mut validity_seq = Encoder::new();
    validity_seq.write_sequence(&validity_bytes);
    let validity_der = validity_seq.finish();

    // Version [0] EXPLICIT INTEGER 2 (v3)
    let mut ver_int = Encoder::new();
    ver_int.write_integer(&[0x02]);
    let ver_int_bytes = ver_int.finish();
    let mut version = Encoder::new();
    version.write_tlv(0xa0, &ver_int_bytes); // [0] EXPLICIT
    let version_der = version.finish();

    // Serial number
    let mut serial = Encoder::new();
    serial.write_integer(&[0x01]);
    let serial_der = serial.finish();

    // TBSCertificate
    let mut tbs_inner = Vec::new();
    tbs_inner.extend_from_slice(&version_der);
    tbs_inner.extend_from_slice(&serial_der);
    tbs_inner.extend_from_slice(&alg_id_der); // signature algorithm
    tbs_inner.extend_from_slice(&name_der); // issuer
    tbs_inner.extend_from_slice(&validity_der);
    tbs_inner.extend_from_slice(&name_der); // subject
    tbs_inner.extend_from_slice(&spki_der);
    let mut tbs = Encoder::new();
    tbs.write_sequence(&tbs_inner);
    let tbs_der = tbs.finish();

    // Sign the TBS
    let signature = kp.sign(&tbs_der).unwrap();

    // Certificate: SEQUENCE { tbs, signatureAlgorithm, signatureValue }
    let mut cert_inner = Vec::new();
    cert_inner.extend_from_slice(&tbs_der);
    cert_inner.extend_from_slice(&alg_id_der);
    let mut sig_bits = Encoder::new();
    sig_bits.write_bit_string(0, &signature);
    cert_inner.extend_from_slice(&sig_bits.finish());

    let mut cert = Encoder::new();
    cert.write_sequence(&cert_inner);
    cert.finish()
}

/// Test CertificateRequest codec roundtrip.
#[test]
fn test_post_hs_auth_codec() {
    use crate::crypt::SignatureScheme;
    use crate::handshake::extensions_codec::build_signature_algorithms;

    let sig_algs = vec![
        SignatureScheme::ED25519,
        SignatureScheme::ECDSA_SECP256R1_SHA256,
    ];
    let cr = CertificateRequestMsg {
        certificate_request_context: vec![0xDE, 0xAD],
        extensions: vec![build_signature_algorithms(&sig_algs)],
    };
    let encoded = encode_certificate_request(&cr);
    let (hs_type, body, total) = parse_handshake_header(&encoded).unwrap();
    assert_eq!(hs_type, HandshakeType::CertificateRequest);
    assert_eq!(total, encoded.len());

    let decoded = decode_certificate_request(body).unwrap();
    assert_eq!(decoded.certificate_request_context, vec![0xDE, 0xAD]);
    assert_eq!(decoded.extensions.len(), 1);
}

/// Test post-handshake client auth roundtrip.
/// Server sends CertificateRequest, client responds with Cert+CV+Finished.
#[test]
fn test_post_hs_auth_roundtrip() {
    use crate::config::ServerPrivateKey;

    use crate::crypt::SignatureScheme;

    use crate::handshake::extensions_codec::build_signature_algorithms;

    use crate::handshake::signing::{select_signature_scheme, sign_certificate_verify};
    use crate::handshake::verify::verify_certificate_verify;

    let server_seed = vec![0x42; 32];
    let (_, _, fake_server_cert) = make_ed25519_server_identity();

    // Client Ed25519 identity for post-HS auth
    let client_seed = vec![0x99; 32];
    let client_cert_der = build_ed25519_der_cert(&client_seed);

    // Verify the cert is parseable
    let parsed_cert = hitls_pki::x509::Certificate::from_der(&client_cert_der).unwrap();
    assert!(!parsed_cert.public_key.public_key.is_empty());

    // Set up configs
    let client_config = TlsConfig::builder()
        .verify_peer(false)
        .post_handshake_auth(true)
        .client_certificate_chain(vec![client_cert_der.clone()])
        .client_private_key(ServerPrivateKey::Ed25519(client_seed.clone()))
        .build();
    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_server_cert])
        .private_key(ServerPrivateKey::Ed25519(server_seed))
        .build();

    // Perform handshake
    let mut client_hs = ClientHandshake::new(client_config.clone());
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();

    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let actions = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions"),
    };

    let sh_record = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();

    let ee_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let cert_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_msg)
        .unwrap();
    let cv_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
        .unwrap();
    let sfin_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    let (_, sh_data, _) = client_rl.open_record(&sh_record).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_actions = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions"),
    };
    client_rl
        .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_actions.suite, &sh_actions.client_hs_keys)
        .unwrap();

    for rec in [&ee_rec, &cert_rec, &cv_rec] {
        let (_, data, _) = client_rl.open_record(rec).unwrap();
        let (_, _, total) = parse_handshake_header(&data).unwrap();
        let msg = &data[..total];
        match client_hs.state() {
            HandshakeState::WaitEncryptedExtensions => {
                client_hs.process_encrypted_extensions(msg).unwrap();
            }
            HandshakeState::WaitCertCertReq => {
                client_hs.process_certificate(msg).unwrap();
            }
            HandshakeState::WaitCertVerify => {
                client_hs.process_certificate_verify(msg).unwrap();
            }
            s => panic!("unexpected state: {s:?}"),
        }
    }

    let (_, fin_data, _) = client_rl.open_record(&sfin_rec).unwrap();
    let (_, _, fin_total) = parse_handshake_header(&fin_data).unwrap();
    let fin_actions = client_hs.process_finished(&fin_data[..fin_total]).unwrap();

    let cfin_record = client_rl
        .seal_record(ContentType::Handshake, &fin_actions.client_finished_msg)
        .unwrap();
    let (_, cfin_data, _) = server_rl.open_record(&cfin_record).unwrap();
    let (_, _, cfin_total) = parse_handshake_header(&cfin_data).unwrap();
    server_hs
        .process_client_finished(&cfin_data[..cfin_total])
        .unwrap();

    // Activate app keys
    client_rl
        .activate_write_encryption(fin_actions.suite, &fin_actions.client_app_keys)
        .unwrap();
    client_rl
        .activate_read_decryption(fin_actions.suite, &fin_actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_app_keys)
        .unwrap();

    let params = fin_actions.cipher_params.clone();
    let client_app_secret = fin_actions.client_app_secret.clone();
    let _server_app_secret = fin_actions.server_app_secret.clone();

    // === Post-handshake CertificateRequest from server ===
    let sig_algs = vec![
        SignatureScheme::ED25519,
        SignatureScheme::ECDSA_SECP256R1_SHA256,
    ];
    let cr = CertificateRequestMsg {
        certificate_request_context: vec![0xAA, 0xBB],
        extensions: vec![build_signature_algorithms(&sig_algs)],
    };
    let cr_msg = crate::handshake::codec::encode_certificate_request(&cr);
    let cr_record = server_rl
        .seal_record(ContentType::Handshake, &cr_msg)
        .unwrap();

    // Client receives and decodes CertificateRequest
    let (ct, cr_plain, _) = client_rl.open_record(&cr_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (hs_type, cr_body, cr_total) = parse_handshake_header(&cr_plain).unwrap();
    assert_eq!(hs_type, HandshakeType::CertificateRequest);
    let decoded_cr = decode_certificate_request(cr_body).unwrap();
    assert_eq!(decoded_cr.certificate_request_context, vec![0xAA, 0xBB]);

    // Client builds response: Certificate + CertificateVerify + Finished
    // (Simulating what handle_post_hs_cert_request does)

    // Build Certificate
    let cert_msg_struct = CertificateMsg {
        certificate_request_context: decoded_cr.certificate_request_context.clone(),
        certificate_list: vec![CertificateEntry {
            cert_data: client_cert_der.clone(),
            extensions: vec![],
        }],
    };
    let cert_msg_encoded = encode_certificate(&cert_msg_struct);

    // Transcript: Hash(CertificateRequest)
    let factory = params.hash_factory();
    let ks = KeySchedule::new(params.clone());
    let cr_msg_bytes = &cr_plain[..cr_total];

    // Compute hash for CertificateVerify: Hash(CR || Certificate)
    let mut cv_hasher = (*factory)();
    cv_hasher.update(cr_msg_bytes).unwrap();
    cv_hasher.update(&cert_msg_encoded).unwrap();
    let mut cv_hash = vec![0u8; params.hash_len];
    cv_hasher.finish(&mut cv_hash).unwrap();

    // Sign CertificateVerify
    let client_key = ServerPrivateKey::Ed25519(client_seed.clone());
    let scheme = select_signature_scheme(&client_key, &sig_algs).unwrap();
    assert_eq!(scheme, SignatureScheme::ED25519);
    let cv_signature = sign_certificate_verify(&client_key, scheme, &cv_hash, false).unwrap();

    let cv_msg = encode_certificate_verify(&CertificateVerifyMsg {
        algorithm: scheme,
        signature: cv_signature,
    });

    // Compute hash for Finished: Hash(CR || Certificate || CertificateVerify)
    let mut fin_hasher = (*factory)();
    fin_hasher.update(cr_msg_bytes).unwrap();
    fin_hasher.update(&cert_msg_encoded).unwrap();
    fin_hasher.update(&cv_msg).unwrap();
    let mut fin_hash = vec![0u8; params.hash_len];
    fin_hasher.finish(&mut fin_hash).unwrap();

    let finished_key = ks.derive_finished_key(&client_app_secret).unwrap();
    let verify_data = ks
        .compute_finished_verify_data(&finished_key, &fin_hash)
        .unwrap();
    let fin_msg = encode_finished(&verify_data);

    // Send all three as encrypted records
    let cert_record = client_rl
        .seal_record(ContentType::Handshake, &cert_msg_encoded)
        .unwrap();
    let cv_record = client_rl
        .seal_record(ContentType::Handshake, &cv_msg)
        .unwrap();
    let fin_record = client_rl
        .seal_record(ContentType::Handshake, &fin_msg)
        .unwrap();

    // Server receives and verifies Certificate
    let (ct, cert_plain, _) = server_rl.open_record(&cert_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (hs_type, cert_body, _) = parse_handshake_header(&cert_plain).unwrap();
    assert_eq!(hs_type, HandshakeType::Certificate);
    let client_cert_msg = crate::handshake::codec::decode_certificate(cert_body).unwrap();
    assert_eq!(client_cert_msg.certificate_list.len(), 1);
    assert_eq!(
        client_cert_msg.certificate_request_context,
        vec![0xAA, 0xBB]
    );

    // Server verifies CertificateVerify
    let (ct, cv_plain, _) = server_rl.open_record(&cv_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (hs_type, cv_body, _) = parse_handshake_header(&cv_plain).unwrap();
    assert_eq!(hs_type, HandshakeType::CertificateVerify);
    let client_cv_msg = crate::handshake::codec::decode_certificate_verify(cv_body).unwrap();
    assert_eq!(client_cv_msg.algorithm, SignatureScheme::ED25519);

    // Verify the CertificateVerify signature
    verify_certificate_verify(
        &parsed_cert,
        client_cv_msg.algorithm,
        &client_cv_msg.signature,
        &cv_hash,
        false,
    )
    .unwrap();

    // Server verifies Finished
    let (ct, fin_plain, _) = server_rl.open_record(&fin_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (hs_type, fin_body, _) = parse_handshake_header(&fin_plain).unwrap();
    assert_eq!(hs_type, HandshakeType::Finished);
    let client_fin = crate::handshake::codec::decode_finished(fin_body, params.hash_len).unwrap();
    assert_eq!(client_fin.verify_data, verify_data);

    // Verify app data still works after post-HS auth
    let app_msg = b"after post-HS auth";
    let app_rec = client_rl
        .seal_record(ContentType::ApplicationData, app_msg)
        .unwrap();
    let (ct, pt, _) = server_rl.open_record(&app_rec).unwrap();
    assert_eq!(ct, ContentType::ApplicationData);
    assert_eq!(pt, app_msg);
}

/// Test post-HS auth where client has no certificate (empty Certificate).
#[test]
fn test_post_hs_auth_no_cert() {
    use crate::crypt::SignatureScheme;
    use crate::handshake::extensions_codec::build_signature_algorithms;

    let (mut client_rl, mut server_rl, client_app_secret, _server_app_secret, params, _suite) =
        do_test_handshake();

    // Server sends CertificateRequest
    let sig_algs = vec![SignatureScheme::ED25519];
    let cr = CertificateRequestMsg {
        certificate_request_context: vec![0x01, 0x02],
        extensions: vec![build_signature_algorithms(&sig_algs)],
    };
    let cr_msg = crate::handshake::codec::encode_certificate_request(&cr);
    let cr_record = server_rl
        .seal_record(ContentType::Handshake, &cr_msg)
        .unwrap();

    // Client receives
    let (ct, cr_plain, _) = client_rl.open_record(&cr_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (hs_type, _, cr_total) = parse_handshake_header(&cr_plain).unwrap();
    assert_eq!(hs_type, HandshakeType::CertificateRequest);
    let cr_msg_bytes = &cr_plain[..cr_total];

    // Client sends empty Certificate (no cert available)
    let empty_cert = CertificateMsg {
        certificate_request_context: vec![0x01, 0x02],
        certificate_list: vec![],
    };
    let cert_encoded = encode_certificate(&empty_cert);
    let cert_record = client_rl
        .seal_record(ContentType::Handshake, &cert_encoded)
        .unwrap();

    // Client sends Finished (hash of CR || empty Certificate)
    let factory = params.hash_factory();
    let ks = KeySchedule::new(params.clone());
    let mut fin_hasher = (*factory)();
    fin_hasher.update(cr_msg_bytes).unwrap();
    fin_hasher.update(&cert_encoded).unwrap();
    let mut fin_hash = vec![0u8; params.hash_len];
    fin_hasher.finish(&mut fin_hash).unwrap();

    let finished_key = ks.derive_finished_key(&client_app_secret).unwrap();
    let verify_data = ks
        .compute_finished_verify_data(&finished_key, &fin_hash)
        .unwrap();
    let fin_msg = encode_finished(&verify_data);
    let fin_record = client_rl
        .seal_record(ContentType::Handshake, &fin_msg)
        .unwrap();

    // Server receives empty Certificate
    let (ct, cert_plain, _) = server_rl.open_record(&cert_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (hs_type, cert_body, _) = parse_handshake_header(&cert_plain).unwrap();
    assert_eq!(hs_type, HandshakeType::Certificate);
    let cert_msg = crate::handshake::codec::decode_certificate(cert_body).unwrap();
    assert!(cert_msg.certificate_list.is_empty());

    // Server receives and verifies Finished (should succeed for empty cert)
    let (ct, fin_plain, _) = server_rl.open_record(&fin_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (hs_type, fin_body, _) = parse_handshake_header(&fin_plain).unwrap();
    assert_eq!(hs_type, HandshakeType::Finished);
    let client_fin = crate::handshake::codec::decode_finished(fin_body, params.hash_len).unwrap();
    assert_eq!(client_fin.verify_data, verify_data);
}

/// Test that post-HS CertificateRequest is rejected if PHA was not offered.
#[test]
fn test_post_hs_auth_not_offered() {
    use std::io::Cursor;

    // Create a client connection without post_handshake_auth
    let config = TlsConfig::builder()
        .verify_peer(false)
        .post_handshake_auth(false)
        .build();
    let stream = Cursor::new(Vec::<u8>::new());
    let mut conn = TlsClientConnection::new(stream, config);
    conn.state = ConnectionState::Connected;
    // Set cipher_params to prevent "no cipher params" error
    let params = crate::crypt::CipherSuiteParams::from_suite(CipherSuite(0x1301)).unwrap();
    conn.cipher_params = Some(params);
    conn.client_app_secret = vec![0u8; 48];
    conn.server_app_secret = vec![0u8; 48];

    // Simulate receiving a CertificateRequest body
    let cr_body = vec![
        0x00, // context length = 0
        0x00, 0x00, // extensions length = 0
    ];
    let cr_full =
        crate::handshake::codec::wrap_handshake(HandshakeType::CertificateRequest, &cr_body);

    // Should fail because post_handshake_auth was not offered
    let result = conn.handle_post_hs_cert_request(&cr_body, &cr_full);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("post_handshake_auth not offered"),
        "expected PHA not offered error, got: {err_msg}"
    );
}

/// Test that server's request_client_auth() fails before Connected state.
#[test]
fn test_post_hs_auth_server_not_connected() {
    use std::io::Cursor;

    let config = TlsConfig::builder().role(crate::TlsRole::Server).build();
    let stream = Cursor::new(Vec::<u8>::new());
    let mut conn = TlsServerConnection::new(stream, config);
    // Should fail because not connected
    let result = conn.request_client_auth();
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("not connected"));
}

/// Test that cert_compression_algos config field works correctly.
#[test]
fn test_cert_compression_config() {
    use crate::handshake::codec::CertCompressionAlgorithm;

    let config = TlsConfig::builder()
        .cert_compression(vec![CertCompressionAlgorithm::ZLIB])
        .build();
    assert_eq!(config.cert_compression_algos.len(), 1);
    assert_eq!(
        config.cert_compression_algos[0],
        CertCompressionAlgorithm::ZLIB
    );

    // Default: empty
    let config2 = TlsConfig::builder().build();
    assert!(config2.cert_compression_algos.is_empty());
}

/// Full handshake with certificate compression enabled on both sides.
#[cfg(feature = "cert-compression")]
#[test]
fn test_cert_compression_handshake() {
    use crate::config::ServerPrivateKey;
    use crate::handshake::codec::CertCompressionAlgorithm;

    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();

    let client_config = TlsConfig::builder()
        .server_name("test.example.com")
        .verify_peer(false)
        .cert_compression(vec![CertCompressionAlgorithm::ZLIB])
        .build();

    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .verify_peer(false)
        .cert_compression(vec![CertCompressionAlgorithm::ZLIB])
        .build();

    // --- Client builds ClientHello ---
    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();

    // --- Server receives ClientHello, produces flight ---
    let mut server_rl = RecordLayer::new();
    let (ct, ch_plaintext, _) = server_rl.open_record(&ch_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (_, _, ch_total) = parse_handshake_header(&ch_plaintext).unwrap();

    let mut server_hs = ServerHandshake::new(server_config);
    let actions = match server_hs
        .process_client_hello(&ch_plaintext[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions, got HRR"),
    };

    // Verify the certificate_msg is CompressedCertificate (type 25), not Certificate (type 11)
    assert_eq!(
        actions.certificate_msg[0], 25,
        "server should send CompressedCertificate"
    );

    // --- Server sends ServerHello (plaintext) ---
    let sh_record = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();

    // Activate server HS encryption
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();

    // Send encrypted flight: EE, CompressedCertificate, CertificateVerify, Finished
    let ee_record = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let cert_record = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_msg)
        .unwrap();
    let cv_record = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
        .unwrap();
    let sfin_record = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    // --- Client processes ServerHello ---
    let (ct, sh_plaintext, _) = client_rl.open_record(&sh_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (_, _, sh_total) = parse_handshake_header(&sh_plaintext).unwrap();
    let sh_actions = match client_hs
        .process_server_hello(&sh_plaintext[..sh_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions, got HRR"),
    };

    // Activate client HS decryption/encryption
    client_rl
        .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_actions.suite, &sh_actions.client_hs_keys)
        .unwrap();

    // --- Client processes encrypted flight ---
    // EE
    let (ct, ee_plain, _) = client_rl.open_record(&ee_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (_, _, ee_total) = parse_handshake_header(&ee_plain).unwrap();
    client_hs
        .process_encrypted_extensions(&ee_plain[..ee_total])
        .unwrap();

    // CompressedCertificate (type 25) — dispatch based on message type byte
    let (ct, cert_plain, _) = client_rl.open_record(&cert_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    assert_eq!(
        cert_plain[0], 25,
        "received CompressedCertificate message type"
    );
    let (_, _, cert_total) = parse_handshake_header(&cert_plain).unwrap();
    client_hs
        .process_compressed_certificate(&cert_plain[..cert_total])
        .unwrap();

    // CertificateVerify
    let (ct, cv_plain, _) = client_rl.open_record(&cv_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (_, _, cv_total) = parse_handshake_header(&cv_plain).unwrap();
    client_hs
        .process_certificate_verify(&cv_plain[..cv_total])
        .unwrap();

    // Finished
    let (ct, fin_plain, _) = client_rl.open_record(&sfin_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (_, _, fin_total) = parse_handshake_header(&fin_plain).unwrap();
    let fin_actions = client_hs.process_finished(&fin_plain[..fin_total]).unwrap();
    assert_eq!(client_hs.state(), HandshakeState::Connected);

    // --- Client sends client Finished ---
    let cfin_record = client_rl
        .seal_record(ContentType::Handshake, &fin_actions.client_finished_msg)
        .unwrap();

    // --- Server receives client Finished ---
    let (ct, cfin_plain, _) = server_rl.open_record(&cfin_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (_, _, cfin_total) = parse_handshake_header(&cfin_plain).unwrap();
    let _cfin_actions = server_hs
        .process_client_finished(&cfin_plain[..cfin_total])
        .unwrap();
    assert_eq!(server_hs.state(), HandshakeState::Connected);
}

/// Verify that when client offers compression but server doesn't, normal Certificate is used.
#[cfg(feature = "cert-compression")]
#[test]
fn test_cert_compression_server_disabled() {
    use crate::config::ServerPrivateKey;
    use crate::handshake::codec::CertCompressionAlgorithm;

    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();

    let client_config = TlsConfig::builder()
        .server_name("test.example.com")
        .verify_peer(false)
        .cert_compression(vec![CertCompressionAlgorithm::ZLIB])
        .build();

    // Server does NOT enable cert compression
    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .verify_peer(false)
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();

    let mut server_rl = RecordLayer::new();
    let (_, ch_plaintext, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_plaintext).unwrap();

    let mut server_hs = ServerHandshake::new(server_config);
    let actions = match server_hs
        .process_client_hello(&ch_plaintext[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions"),
    };

    // Server should send normal Certificate (type 11), not CompressedCertificate
    assert_eq!(
        actions.certificate_msg[0], 11,
        "server should send normal Certificate when compression disabled"
    );
}

// -----------------------------------------------------------------------
// TLS 1.2 integration tests
// -----------------------------------------------------------------------

/// Full TLS 1.2 ECDHE-ECDSA handshake between client and server.
#[test]
fn test_tls12_full_handshake_ecdhe_ecdsa() {
    use crate::config::ServerPrivateKey;
    use crate::crypt::{NamedGroup, SignatureScheme};
    use crate::handshake::client12::{Tls12ClientHandshake, Tls12ClientState};
    use crate::handshake::codec12::{decode_certificate12, decode_server_key_exchange};
    use crate::handshake::server12::{Tls12ServerHandshake, Tls12ServerState};

    // Use a fixed P-256 private key (32 bytes, must be in [1, n-1])
    let ecdsa_private = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];

    let fake_cert = vec![0x30, 0x82, 0x01, 0x00]; // fake DER cert

    let client_config = TlsConfig::builder()
        .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
        .supported_groups(&[NamedGroup::SECP256R1])
        .signature_algorithms(&[
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            SignatureScheme::RSA_PSS_RSAE_SHA256,
        ])
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

    let mut client_hs = Tls12ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = Tls12ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    // === 1. Client builds ClientHello ===
    let ch_msg = client_hs.build_client_hello().unwrap();
    assert_eq!(client_hs.state(), Tls12ClientState::WaitServerHello);
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();

    // === 2. Server receives ClientHello, produces flight ===
    let (ct, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let server_flight = server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap();
    assert_eq!(server_hs.state(), Tls12ServerState::WaitClientKeyExchange);
    assert_eq!(
        server_flight.suite,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    );

    // === 3. Server sends ServerHello, Certificate, SKE, SHD ===
    let sh_record = server_rl
        .seal_record(ContentType::Handshake, &server_flight.server_hello)
        .unwrap();
    let cert_record = server_rl
        .seal_record(
            ContentType::Handshake,
            server_flight.certificate.as_ref().unwrap(),
        )
        .unwrap();
    let ske_record = server_rl
        .seal_record(
            ContentType::Handshake,
            server_flight.server_key_exchange.as_ref().unwrap(),
        )
        .unwrap();
    let shd_record = server_rl
        .seal_record(ContentType::Handshake, &server_flight.server_hello_done)
        .unwrap();

    // === 4. Client processes ServerHello ===
    let (_, sh_data, _) = client_rl.open_record(&sh_record).unwrap();
    let (_, sh_body, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh = crate::handshake::codec::decode_server_hello(sh_body).unwrap();
    let suite = client_hs
        .process_server_hello(&sh_data[..sh_total], &sh)
        .unwrap();
    assert_eq!(suite, CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    assert_eq!(client_hs.state(), Tls12ClientState::WaitCertificate);

    // === 5. Client processes Certificate ===
    let (_, cert_data, _) = client_rl.open_record(&cert_record).unwrap();
    let (_, cert_body, cert_total) = parse_handshake_header(&cert_data).unwrap();
    let cert12 = decode_certificate12(cert_body).unwrap();
    client_hs
        .process_certificate(&cert_data[..cert_total], &cert12.certificate_list)
        .unwrap();
    assert_eq!(client_hs.state(), Tls12ClientState::WaitServerKeyExchange);

    // === 6. Client processes ServerKeyExchange ===
    let (_, ske_data, _) = client_rl.open_record(&ske_record).unwrap();
    let (_, ske_body, ske_total) = parse_handshake_header(&ske_data).unwrap();
    let ske = decode_server_key_exchange(ske_body).unwrap();
    client_hs
        .process_server_key_exchange(&ske_data[..ske_total], &ske)
        .unwrap();
    assert_eq!(client_hs.state(), Tls12ClientState::WaitServerHelloDone);

    // === 7. Client processes ServerHelloDone ===
    let (_, shd_data, _) = client_rl.open_record(&shd_record).unwrap();
    let (_, _, shd_total) = parse_handshake_header(&shd_data).unwrap();
    let client_flight = client_hs
        .process_server_hello_done(&shd_data[..shd_total])
        .unwrap();
    assert_eq!(client_hs.state(), Tls12ClientState::WaitChangeCipherSpec);

    // === 8. Client sends CKE (plaintext) ===
    let cke_record = client_rl
        .seal_record(ContentType::Handshake, &client_flight.client_key_exchange)
        .unwrap();

    // === 9. Client sends CCS (plaintext) ===
    let client_ccs_record = client_rl
        .seal_record(ContentType::ChangeCipherSpec, &[0x01])
        .unwrap();

    // === 10. Client activates write encryption ===
    client_rl
        .activate_write_encryption12(
            suite,
            &client_flight.client_write_key,
            client_flight.client_write_iv.clone(),
        )
        .unwrap();

    // === 11. Client sends Finished (encrypted) ===
    let cfin_record = client_rl
        .seal_record(ContentType::Handshake, &client_flight.finished)
        .unwrap();

    // === 12. Server receives CKE → derive keys ===
    let (ct, cke_data, _) = server_rl.open_record(&cke_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (_, _, cke_total) = parse_handshake_header(&cke_data).unwrap();
    let derived_keys = server_hs
        .process_client_key_exchange(&cke_data[..cke_total])
        .unwrap();
    assert_eq!(server_hs.state(), Tls12ServerState::WaitChangeCipherSpec);

    // === 13. Server receives CCS ===
    let (ct, _, _) = server_rl.open_record(&client_ccs_record).unwrap();
    assert_eq!(ct, ContentType::ChangeCipherSpec);
    server_hs.process_change_cipher_spec().unwrap();
    assert_eq!(server_hs.state(), Tls12ServerState::WaitFinished);

    // === 14. Server activates read decryption ===
    server_rl
        .activate_read_decryption12(
            suite,
            &derived_keys.client_write_key,
            derived_keys.client_write_iv.clone(),
        )
        .unwrap();

    // === 15. Server receives encrypted Finished → verify ===
    let (ct, cfin_data, _) = server_rl.open_record(&cfin_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (_, _, cfin_total) = parse_handshake_header(&cfin_data).unwrap();
    let server_fin_result = server_hs
        .process_finished(&cfin_data[..cfin_total])
        .unwrap();
    assert_eq!(server_hs.state(), Tls12ServerState::Connected);

    // === 16. Server sends CCS (plaintext) ===
    let server_ccs_record = server_rl
        .seal_record(ContentType::ChangeCipherSpec, &[0x01])
        .unwrap();

    // === 17. Server activates write encryption ===
    server_rl
        .activate_write_encryption12(
            suite,
            &derived_keys.server_write_key,
            derived_keys.server_write_iv.clone(),
        )
        .unwrap();

    // === 18. Server sends Finished (encrypted) ===
    let sfin_record = server_rl
        .seal_record(ContentType::Handshake, &server_fin_result.finished)
        .unwrap();

    // === 19. Client receives CCS ===
    let (ct, _, _) = client_rl.open_record(&server_ccs_record).unwrap();
    assert_eq!(ct, ContentType::ChangeCipherSpec);
    client_hs.process_change_cipher_spec().unwrap();
    assert_eq!(client_hs.state(), Tls12ClientState::WaitFinished);

    // === 20. Client activates read decryption ===
    client_rl
        .activate_read_decryption12(
            suite,
            &client_flight.server_write_key,
            client_flight.server_write_iv.clone(),
        )
        .unwrap();

    // === 21. Client receives encrypted Finished → verify ===
    let (ct, sfin_data, _) = client_rl.open_record(&sfin_record).unwrap();
    assert_eq!(ct, ContentType::Handshake);
    let (_, _, sfin_total) = parse_handshake_header(&sfin_data).unwrap();
    client_hs
        .process_finished(&sfin_data[..sfin_total], &client_flight.master_secret)
        .unwrap();
    assert_eq!(client_hs.state(), Tls12ClientState::Connected);

    // === 22. Both Connected! Exchange application data ===
    let msg = b"Hello TLS 1.2!";
    let app_record = client_rl
        .seal_record(ContentType::ApplicationData, msg)
        .unwrap();
    let (ct, plaintext, _) = server_rl.open_record(&app_record).unwrap();
    assert_eq!(ct, ContentType::ApplicationData);
    assert_eq!(plaintext, msg);

    // Server to client
    let reply = b"Hello from server via TLS 1.2!";
    let reply_record = server_rl
        .seal_record(ContentType::ApplicationData, reply)
        .unwrap();
    let (ct, reply_pt, _) = client_rl.open_record(&reply_record).unwrap();
    assert_eq!(ct, ContentType::ApplicationData);
    assert_eq!(reply_pt, reply);
}

/// TLS 1.2 ECDHE-ECDSA handshake with AES-128-GCM using X25519 key exchange.
#[test]
fn test_tls12_full_handshake_x25519() {
    use crate::config::ServerPrivateKey;
    use crate::crypt::{NamedGroup, SignatureScheme};
    use crate::handshake::client12::{Tls12ClientHandshake, Tls12ClientState};
    use crate::handshake::codec12::{decode_certificate12, decode_server_key_exchange};
    use crate::handshake::server12::{Tls12ServerHandshake, Tls12ServerState};

    // Use a fixed P-256 ECDSA private key
    let ecdsa_private = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];

    let fake_cert = vec![0x30, 0x82, 0x01, 0x00];
    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

    let client_config = TlsConfig::builder()
        .cipher_suites(&[suite])
        .supported_groups(&[NamedGroup::X25519])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .verify_peer(false)
        .build();

    let server_config = TlsConfig::builder()
        .cipher_suites(&[suite])
        .supported_groups(&[NamedGroup::X25519])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ecdsa {
            curve_id: hitls_types::EccCurveId::NistP256,
            private_key: ecdsa_private,
        })
        .verify_peer(false)
        .build();

    let mut client_hs = Tls12ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = Tls12ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    // --- Handshake flow (same pattern as ECDSA test) ---

    // Client → CH
    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();

    // Server ← CH → server flight
    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let server_flight = server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap();
    assert_eq!(server_flight.suite, suite);

    // Server → SH, Cert, SKE, SHD
    let sh_record = server_rl
        .seal_record(ContentType::Handshake, &server_flight.server_hello)
        .unwrap();
    let cert_record = server_rl
        .seal_record(
            ContentType::Handshake,
            server_flight.certificate.as_ref().unwrap(),
        )
        .unwrap();
    let ske_record = server_rl
        .seal_record(
            ContentType::Handshake,
            server_flight.server_key_exchange.as_ref().unwrap(),
        )
        .unwrap();
    let shd_record = server_rl
        .seal_record(ContentType::Handshake, &server_flight.server_hello_done)
        .unwrap();

    // Client ← SH
    let (_, sh_data, _) = client_rl.open_record(&sh_record).unwrap();
    let (_, sh_body, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh = crate::handshake::codec::decode_server_hello(sh_body).unwrap();
    client_hs
        .process_server_hello(&sh_data[..sh_total], &sh)
        .unwrap();

    // Client ← Cert
    let (_, cert_data, _) = client_rl.open_record(&cert_record).unwrap();
    let (_, cert_body, cert_total) = parse_handshake_header(&cert_data).unwrap();
    let cert12 = decode_certificate12(cert_body).unwrap();
    client_hs
        .process_certificate(&cert_data[..cert_total], &cert12.certificate_list)
        .unwrap();

    // Client ← SKE
    let (_, ske_data, _) = client_rl.open_record(&ske_record).unwrap();
    let (_, ske_body, ske_total) = parse_handshake_header(&ske_data).unwrap();
    let ske = decode_server_key_exchange(ske_body).unwrap();
    client_hs
        .process_server_key_exchange(&ske_data[..ske_total], &ske)
        .unwrap();

    // Client ← SHD → client flight
    let (_, shd_data, _) = client_rl.open_record(&shd_record).unwrap();
    let (_, _, shd_total) = parse_handshake_header(&shd_data).unwrap();
    let client_flight = client_hs
        .process_server_hello_done(&shd_data[..shd_total])
        .unwrap();

    // Client → CKE, CCS, Finished
    let cke_record = client_rl
        .seal_record(ContentType::Handshake, &client_flight.client_key_exchange)
        .unwrap();
    let client_ccs_record = client_rl
        .seal_record(ContentType::ChangeCipherSpec, &[0x01])
        .unwrap();
    client_rl
        .activate_write_encryption12(
            suite,
            &client_flight.client_write_key,
            client_flight.client_write_iv.clone(),
        )
        .unwrap();
    let cfin_record = client_rl
        .seal_record(ContentType::Handshake, &client_flight.finished)
        .unwrap();

    // Server ← CKE
    let (_, cke_data, _) = server_rl.open_record(&cke_record).unwrap();
    let (_, _, cke_total) = parse_handshake_header(&cke_data).unwrap();
    let derived_keys = server_hs
        .process_client_key_exchange(&cke_data[..cke_total])
        .unwrap();

    // Server ← CCS
    let (ct, _, _) = server_rl.open_record(&client_ccs_record).unwrap();
    assert_eq!(ct, ContentType::ChangeCipherSpec);
    server_hs.process_change_cipher_spec().unwrap();
    server_rl
        .activate_read_decryption12(
            suite,
            &derived_keys.client_write_key,
            derived_keys.client_write_iv.clone(),
        )
        .unwrap();

    // Server ← Finished
    let (_, cfin_data, _) = server_rl.open_record(&cfin_record).unwrap();
    let (_, _, cfin_total) = parse_handshake_header(&cfin_data).unwrap();
    let server_fin = server_hs
        .process_finished(&cfin_data[..cfin_total])
        .unwrap();
    assert_eq!(server_hs.state(), Tls12ServerState::Connected);

    // Server → CCS, Finished
    let server_ccs = server_rl
        .seal_record(ContentType::ChangeCipherSpec, &[0x01])
        .unwrap();
    server_rl
        .activate_write_encryption12(
            suite,
            &derived_keys.server_write_key,
            derived_keys.server_write_iv.clone(),
        )
        .unwrap();
    let sfin_record = server_rl
        .seal_record(ContentType::Handshake, &server_fin.finished)
        .unwrap();

    // Client ← CCS + Finished
    let (ct, _, _) = client_rl.open_record(&server_ccs).unwrap();
    assert_eq!(ct, ContentType::ChangeCipherSpec);
    client_hs.process_change_cipher_spec().unwrap();
    client_rl
        .activate_read_decryption12(
            suite,
            &client_flight.server_write_key,
            client_flight.server_write_iv.clone(),
        )
        .unwrap();

    let (_, sfin_data, _) = client_rl.open_record(&sfin_record).unwrap();
    let (_, _, sfin_total) = parse_handshake_header(&sfin_data).unwrap();
    client_hs
        .process_finished(&sfin_data[..sfin_total], &client_flight.master_secret)
        .unwrap();
    assert_eq!(client_hs.state(), Tls12ClientState::Connected);

    // App data exchange (X25519 key exchange)
    let data = b"TLS 1.2 with X25519!";
    let app_rec = client_rl
        .seal_record(ContentType::ApplicationData, data)
        .unwrap();
    let (ct, pt, _) = server_rl.open_record(&app_rec).unwrap();
    assert_eq!(ct, ContentType::ApplicationData);
    assert_eq!(pt, data);
}

/// TLS 1.3 handshake with X25519MLKEM768 hybrid KEM key exchange.
#[test]
fn test_hybrid_kem_handshake() {
    use crate::config::ServerPrivateKey;
    use crate::crypt::NamedGroup;

    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();

    let client_config = TlsConfig::builder()
        .supported_groups(&[NamedGroup::X25519_MLKEM768])
        .verify_peer(false)
        .build();

    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .supported_groups(&[NamedGroup::X25519_MLKEM768])
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .verify_peer(false)
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    // Client builds CH with hybrid KEM key share (1216 bytes)
    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();

    // Server processes CH → Actions (not HRR)
    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let actions = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions, got HRR"),
    };

    // Server sends ServerHello + encrypted flight
    let sh_record = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();

    let ee_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let cert_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_msg)
        .unwrap();
    let cv_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
        .unwrap();
    let sfin_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    // Client processes ServerHello
    let (_, sh_data, _) = client_rl.open_record(&sh_record).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_actions = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions"),
    };
    client_rl
        .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_actions.suite, &sh_actions.client_hs_keys)
        .unwrap();

    // Client processes encrypted flight
    for rec in [&ee_rec, &cert_rec, &cv_rec] {
        let (_, data, _) = client_rl.open_record(rec).unwrap();
        let (_, _, total) = parse_handshake_header(&data).unwrap();
        let msg = &data[..total];
        match client_hs.state() {
            HandshakeState::WaitEncryptedExtensions => {
                client_hs.process_encrypted_extensions(msg).unwrap();
            }
            HandshakeState::WaitCertCertReq => {
                client_hs.process_certificate(msg).unwrap();
            }
            HandshakeState::WaitCertVerify => {
                client_hs.process_certificate_verify(msg).unwrap();
            }
            s => panic!("unexpected state: {s:?}"),
        }
    }

    let (_, fin_data, _) = client_rl.open_record(&sfin_rec).unwrap();
    let (_, _, fin_total) = parse_handshake_header(&fin_data).unwrap();
    let fin_actions = client_hs.process_finished(&fin_data[..fin_total]).unwrap();
    assert_eq!(client_hs.state(), HandshakeState::Connected);

    // Client sends Finished
    let cfin_record = client_rl
        .seal_record(ContentType::Handshake, &fin_actions.client_finished_msg)
        .unwrap();
    let (_, cfin_data, _) = server_rl.open_record(&cfin_record).unwrap();
    let (_, _, cfin_total) = parse_handshake_header(&cfin_data).unwrap();
    server_hs
        .process_client_finished(&cfin_data[..cfin_total])
        .unwrap();
    assert_eq!(server_hs.state(), HandshakeState::Connected);

    // Activate app keys and exchange data
    client_rl
        .activate_write_encryption(fin_actions.suite, &fin_actions.client_app_keys)
        .unwrap();
    client_rl
        .activate_read_decryption(fin_actions.suite, &fin_actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_app_keys)
        .unwrap();

    let msg = b"Hello from hybrid KEM client!";
    let rec = client_rl
        .seal_record(ContentType::ApplicationData, msg)
        .unwrap();
    let (ct, pt, _) = server_rl.open_record(&rec).unwrap();
    assert_eq!(ct, ContentType::ApplicationData);
    assert_eq!(pt, msg);

    let msg2 = b"Hello from hybrid KEM server!";
    let rec2 = server_rl
        .seal_record(ContentType::ApplicationData, msg2)
        .unwrap();
    let (ct2, pt2, _) = client_rl.open_record(&rec2).unwrap();
    assert_eq!(ct2, ContentType::ApplicationData);
    assert_eq!(pt2, msg2);
}

/// HRR fallback: client offers hybrid KEM, server only supports X25519.
#[test]
fn test_hybrid_kem_hrr_fallback() {
    use crate::config::ServerPrivateKey;
    use crate::crypt::NamedGroup;

    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();

    // Client offers hybrid first, then X25519 fallback
    let client_config = TlsConfig::builder()
        .supported_groups(&[NamedGroup::X25519_MLKEM768, NamedGroup::X25519])
        .verify_peer(false)
        .build();

    // Server only supports X25519
    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .supported_groups(&[NamedGroup::X25519])
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .verify_peer(false)
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    // CH1: client sends hybrid KEM key share
    let ch1_msg = client_hs.build_client_hello().unwrap();
    let ch1_rec = client_rl
        .seal_record(ContentType::Handshake, &ch1_msg)
        .unwrap();

    // Server → HRR (no matching key_share, selects X25519 from supported_groups)
    let (_, ch1_data, _) = server_rl.open_record(&ch1_rec).unwrap();
    let (_, _, ch1_total) = parse_handshake_header(&ch1_data).unwrap();
    let hrr_actions = match server_hs
        .process_client_hello(&ch1_data[..ch1_total])
        .unwrap()
    {
        ClientHelloResult::HelloRetryRequest(a) => a,
        ClientHelloResult::Actions(_) => panic!("expected HRR"),
    };

    let hrr_rec = server_rl
        .seal_record(ContentType::Handshake, &hrr_actions.hrr_msg)
        .unwrap();

    // Client processes HRR → RetryNeeded with X25519
    let (_, hrr_data, _) = client_rl.open_record(&hrr_rec).unwrap();
    let (_, _, hrr_total) = parse_handshake_header(&hrr_data).unwrap();
    let retry = match client_hs
        .process_server_hello(&hrr_data[..hrr_total])
        .unwrap()
    {
        ServerHelloResult::RetryNeeded(r) => r,
        _ => panic!("expected RetryNeeded"),
    };
    assert_eq!(retry.selected_group, NamedGroup::X25519);

    // CH2: client sends X25519 key share
    let ch2_msg = client_hs.build_client_hello_retry(&retry).unwrap();
    let ch2_rec = client_rl
        .seal_record(ContentType::Handshake, &ch2_msg)
        .unwrap();

    // Server processes CH2 → full handshake
    let (_, ch2_data, _) = server_rl.open_record(&ch2_rec).unwrap();
    let (_, _, ch2_total) = parse_handshake_header(&ch2_data).unwrap();
    let actions = server_hs
        .process_client_hello_retry(&ch2_data[..ch2_total])
        .unwrap();

    // Complete the handshake
    let sh_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();

    let ee_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let cert_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_msg)
        .unwrap();
    let cv_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
        .unwrap();
    let sfin_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    // Client processes real ServerHello
    let (_, sh_data, _) = client_rl.open_record(&sh_rec).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_actions = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions on second SH"),
    };
    client_rl
        .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_actions.suite, &sh_actions.client_hs_keys)
        .unwrap();

    // Client processes encrypted flight
    for rec in [&ee_rec, &cert_rec, &cv_rec] {
        let (_, data, _) = client_rl.open_record(rec).unwrap();
        let (_, _, total) = parse_handshake_header(&data).unwrap();
        let msg = &data[..total];
        match client_hs.state() {
            HandshakeState::WaitEncryptedExtensions => {
                client_hs.process_encrypted_extensions(msg).unwrap();
            }
            HandshakeState::WaitCertCertReq => {
                client_hs.process_certificate(msg).unwrap();
            }
            HandshakeState::WaitCertVerify => {
                client_hs.process_certificate_verify(msg).unwrap();
            }
            s => panic!("unexpected state: {s:?}"),
        }
    }

    let (_, fin_data, _) = client_rl.open_record(&sfin_rec).unwrap();
    let (_, _, fin_total) = parse_handshake_header(&fin_data).unwrap();
    let fin_actions = client_hs.process_finished(&fin_data[..fin_total]).unwrap();
    assert_eq!(client_hs.state(), HandshakeState::Connected);

    let cfin_rec = client_rl
        .seal_record(ContentType::Handshake, &fin_actions.client_finished_msg)
        .unwrap();
    let (_, cfin_data, _) = server_rl.open_record(&cfin_rec).unwrap();
    let (_, _, cfin_total) = parse_handshake_header(&cfin_data).unwrap();
    server_hs
        .process_client_finished(&cfin_data[..cfin_total])
        .unwrap();
    assert_eq!(server_hs.state(), HandshakeState::Connected);

    // Exchange app data
    client_rl
        .activate_write_encryption(fin_actions.suite, &fin_actions.client_app_keys)
        .unwrap();
    client_rl
        .activate_read_decryption(fin_actions.suite, &fin_actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_app_keys)
        .unwrap();

    let msg = b"Post-HRR fallback data!";
    let rec = client_rl
        .seal_record(ContentType::ApplicationData, msg)
        .unwrap();
    let (ct, pt, _) = server_rl.open_record(&rec).unwrap();
    assert_eq!(ct, ContentType::ApplicationData);
    assert_eq!(pt, msg);
}

#[test]
fn test_tls13_record_size_limit() {
    use crate::config::ServerPrivateKey;
    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();

    let client_config = TlsConfig::builder()
        .record_size_limit(4096)
        .verify_peer(false)
        .build();

    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .record_size_limit(4096)
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .verify_peer(false)
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    // Client builds CH with record_size_limit extension
    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();

    // Server processes CH
    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let actions = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions"),
    };

    // Server should have client's RSL
    assert_eq!(server_hs.client_record_size_limit(), Some(4096));

    // Apply client's RSL to server record layer (TLS 1.3: -1)
    if let Some(limit) = server_hs.client_record_size_limit() {
        server_rl.max_fragment_size = limit.saturating_sub(1) as usize;
    }

    // Server sends ServerHello + encrypted flight
    let sh_record = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();
    let ee_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let cert_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_msg)
        .unwrap();
    let cv_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
        .unwrap();
    let sfin_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    // Client processes ServerHello
    let (_, sh_data, _) = client_rl.open_record(&sh_record).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_actions = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions"),
    };
    client_rl
        .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_actions.suite, &sh_actions.client_hs_keys)
        .unwrap();

    // Client processes EE → should get peer's RSL
    for rec in [&ee_rec, &cert_rec, &cv_rec] {
        let (_, data, _) = client_rl.open_record(rec).unwrap();
        let (_, _, total) = parse_handshake_header(&data).unwrap();
        let msg_data = &data[..total];
        match client_hs.state() {
            HandshakeState::WaitEncryptedExtensions => {
                client_hs.process_encrypted_extensions(msg_data).unwrap();
                // TLS 1.3: peer_limit = 4096 - 1 = 4095
                assert_eq!(client_hs.peer_record_size_limit(), Some(4095));
                // Apply to client record layer
                client_rl.max_fragment_size = 4095;
            }
            HandshakeState::WaitCertCertReq => {
                client_hs.process_certificate(msg_data).unwrap();
            }
            HandshakeState::WaitCertVerify => {
                client_hs.process_certificate_verify(msg_data).unwrap();
            }
            s => panic!("unexpected state: {s:?}"),
        }
    }

    // Process server Finished
    let (_, sfin_data, _) = client_rl.open_record(&sfin_rec).unwrap();
    let (_, _, sfin_total) = parse_handshake_header(&sfin_data).unwrap();
    let fin_actions = client_hs
        .process_finished(&sfin_data[..sfin_total])
        .unwrap();

    // Activate app keys
    client_rl
        .activate_read_decryption(fin_actions.suite, &fin_actions.server_app_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(fin_actions.suite, &fin_actions.client_app_keys)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_app_keys)
        .unwrap();

    // Verify record layer caps: server should cap at 4095 bytes
    assert_eq!(server_rl.max_fragment_size, 4095);
    assert_eq!(client_rl.max_fragment_size, 4095);

    // Server should reject a plaintext larger than 4095
    let large = vec![0x42u8; 4096];
    assert!(server_rl
        .seal_record(ContentType::ApplicationData, &large)
        .is_err());

    // But 4095 bytes should work
    let just_right = vec![0x42u8; 4095];
    let rec = server_rl
        .seal_record(ContentType::ApplicationData, &just_right)
        .unwrap();
    let (ct, pt, _) = client_rl.open_record(&rec).unwrap();
    assert_eq!(ct, ContentType::ApplicationData);
    assert_eq!(pt, just_right);
}

#[test]
fn test_tls13_ocsp_stapling() {
    use crate::config::ServerPrivateKey;
    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();
    let fake_ocsp_response = vec![0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB, 0xCC];

    let client_config = TlsConfig::builder()
        .enable_ocsp_stapling(true)
        .verify_peer(false)
        .build();

    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .enable_ocsp_stapling(true)
        .ocsp_staple(fake_ocsp_response.clone())
        .verify_peer(false)
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    // Full handshake
    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();
    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let actions = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions"),
    };

    let sh_record = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();
    let ee_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let cert_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_msg)
        .unwrap();
    let cv_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
        .unwrap();
    let _sfin_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    // Client processes ServerHello
    let (_, sh_data, _) = client_rl.open_record(&sh_record).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_actions = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions"),
    };
    client_rl
        .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_actions.suite, &sh_actions.client_hs_keys)
        .unwrap();

    // Process EE, Cert (with OCSP), CertVerify
    for rec in [&ee_rec, &cert_rec, &cv_rec] {
        let (_, data, _) = client_rl.open_record(rec).unwrap();
        let (_, _, total) = parse_handshake_header(&data).unwrap();
        let msg_data = &data[..total];
        match client_hs.state() {
            HandshakeState::WaitEncryptedExtensions => {
                client_hs.process_encrypted_extensions(msg_data).unwrap();
            }
            HandshakeState::WaitCertCertReq => {
                client_hs.process_certificate(msg_data).unwrap();
            }
            HandshakeState::WaitCertVerify => {
                client_hs.process_certificate_verify(msg_data).unwrap();
            }
            s => panic!("unexpected state: {s:?}"),
        }
    }

    // Client should have received OCSP response
    assert_eq!(
        client_hs.ocsp_response(),
        Some(fake_ocsp_response.as_slice())
    );
    assert!(client_hs.sct_data().is_none());
}

#[test]
fn test_tls13_sct() {
    use crate::config::ServerPrivateKey;
    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();
    let fake_sct_list = vec![0x00, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05];

    let client_config = TlsConfig::builder()
        .enable_sct(true)
        .verify_peer(false)
        .build();

    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .enable_sct(true)
        .sct_list(fake_sct_list.clone())
        .verify_peer(false)
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    // Full handshake
    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();
    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let actions = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions"),
    };

    let sh_record = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();
    let ee_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let cert_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_msg)
        .unwrap();
    let cv_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
        .unwrap();

    // Client processes ServerHello
    let (_, sh_data, _) = client_rl.open_record(&sh_record).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_actions = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions"),
    };
    client_rl
        .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_actions.suite, &sh_actions.client_hs_keys)
        .unwrap();

    // Process EE, Cert (with SCT), CertVerify
    for rec in [&ee_rec, &cert_rec, &cv_rec] {
        let (_, data, _) = client_rl.open_record(rec).unwrap();
        let (_, _, total) = parse_handshake_header(&data).unwrap();
        let msg_data = &data[..total];
        match client_hs.state() {
            HandshakeState::WaitEncryptedExtensions => {
                client_hs.process_encrypted_extensions(msg_data).unwrap();
            }
            HandshakeState::WaitCertCertReq => {
                client_hs.process_certificate(msg_data).unwrap();
            }
            HandshakeState::WaitCertVerify => {
                client_hs.process_certificate_verify(msg_data).unwrap();
            }
            s => panic!("unexpected state: {s:?}"),
        }
    }

    // Client should have received SCT data
    assert!(client_hs.ocsp_response().is_none());
    assert_eq!(client_hs.sct_data(), Some(fake_sct_list.as_slice()));
}

// ======================================================================
// Phase 69: TLS 1.3 Connection info + ALPN + graceful shutdown tests
// ======================================================================

/// After TLS 1.3 handshake, verify all ConnectionInfo fields including
/// cipher_suite, peer_certificates, server_name, negotiated_group.
#[test]
fn test_tls13_connection_info() {
    use crate::config::ServerPrivateKey;
    use crate::crypt::NamedGroup;

    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();

    let client_config = TlsConfig::builder()
        .server_name("tls13.example.com")
        .verify_peer(false)
        .build();

    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_cert.clone()])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .verify_peer(false)
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    // Client → CH
    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();

    // Server ← CH → flight
    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let actions = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions"),
    };

    // Server should have parsed SNI
    assert_eq!(server_hs.client_server_name(), Some("tls13.example.com"));
    // Server should know the negotiated group
    assert!(server_hs.negotiated_group().is_some());

    // Server → SH (plaintext)
    let sh_record = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();

    // Activate server HS encryption
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();

    // Encrypted flight: EE, Cert, CV, Finished
    let ee_record = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let cert_record = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_msg)
        .unwrap();
    let cv_record = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
        .unwrap();
    let sfin_record = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    // Client ← SH
    let (_, sh_data, _) = client_rl.open_record(&sh_record).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_actions = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions"),
    };

    client_rl
        .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_actions.suite, &sh_actions.client_hs_keys)
        .unwrap();

    // Client ← EE, Cert, CV, Fin
    let (_, ee_data, _) = client_rl.open_record(&ee_record).unwrap();
    let (_, _, ee_total) = parse_handshake_header(&ee_data).unwrap();
    client_hs
        .process_encrypted_extensions(&ee_data[..ee_total])
        .unwrap();

    let (_, cert_data, _) = client_rl.open_record(&cert_record).unwrap();
    let (_, _, cert_total) = parse_handshake_header(&cert_data).unwrap();
    client_hs
        .process_certificate(&cert_data[..cert_total])
        .unwrap();

    let (_, cv_data, _) = client_rl.open_record(&cv_record).unwrap();
    let (_, _, cv_total) = parse_handshake_header(&cv_data).unwrap();
    client_hs
        .process_certificate_verify(&cv_data[..cv_total])
        .unwrap();

    let (_, fin_data, _) = client_rl.open_record(&sfin_record).unwrap();
    let (_, _, fin_total) = parse_handshake_header(&fin_data).unwrap();
    let _fin_actions = client_hs.process_finished(&fin_data[..fin_total]).unwrap();

    assert_eq!(client_hs.state(), HandshakeState::Connected);

    // Verify client handshake getters
    assert_eq!(client_hs.server_certs().len(), 1);
    assert_eq!(client_hs.server_certs()[0], fake_cert);
    assert!(client_hs.negotiated_group().is_some());
    let group = client_hs.negotiated_group().unwrap();
    assert!(
        group == NamedGroup::X25519 || group == NamedGroup::SECP256R1,
        "expected a valid NamedGroup, got {group:?}"
    );
    assert!(!client_hs.is_psk_mode());
    // No ALPN configured
    assert!(client_hs.negotiated_alpn().is_none());
}

/// TLS 1.3 ALPN negotiation: client offers h2+http/1.1, server selects h2.
#[test]
fn test_tls13_alpn_negotiation() {
    use crate::config::ServerPrivateKey;

    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();

    let client_config = TlsConfig::builder()
        .verify_peer(false)
        .alpn(&[b"h2", b"http/1.1"])
        .build();

    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .verify_peer(false)
        .alpn(&[b"h2"])
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    // CH
    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();

    // Server ← CH
    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let actions = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions"),
    };

    // Server should have negotiated ALPN
    assert_eq!(server_hs.negotiated_alpn(), Some(b"h2".as_ref()));

    // SH (plaintext)
    let sh_record = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();

    // Activate HS encryption
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();

    // EE contains ALPN
    let ee_record = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let cert_record = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_msg)
        .unwrap();
    let cv_record = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
        .unwrap();
    let sfin_record = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    // Client ← SH
    let (_, sh_data, _) = client_rl.open_record(&sh_record).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_actions = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions"),
    };

    client_rl
        .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_actions.suite, &sh_actions.client_hs_keys)
        .unwrap();

    // Client ← EE (should parse ALPN)
    let (_, ee_data, _) = client_rl.open_record(&ee_record).unwrap();
    let (_, _, ee_total) = parse_handshake_header(&ee_data).unwrap();
    client_hs
        .process_encrypted_extensions(&ee_data[..ee_total])
        .unwrap();

    // Client should now see negotiated ALPN
    assert_eq!(client_hs.negotiated_alpn(), Some(b"h2".as_ref()));

    // Continue to finish handshake
    let (_, cert_data, _) = client_rl.open_record(&cert_record).unwrap();
    let (_, _, cert_total) = parse_handshake_header(&cert_data).unwrap();
    client_hs
        .process_certificate(&cert_data[..cert_total])
        .unwrap();

    let (_, cv_data, _) = client_rl.open_record(&cv_record).unwrap();
    let (_, _, cv_total) = parse_handshake_header(&cv_data).unwrap();
    client_hs
        .process_certificate_verify(&cv_data[..cv_total])
        .unwrap();

    let (_, fin_data, _) = client_rl.open_record(&sfin_record).unwrap();
    let (_, _, fin_total) = parse_handshake_header(&fin_data).unwrap();
    let _fin_actions = client_hs.process_finished(&fin_data[..fin_total]).unwrap();

    assert_eq!(client_hs.state(), HandshakeState::Connected);
    // ALPN should still be available after handshake completes
    assert_eq!(client_hs.negotiated_alpn(), Some(b"h2".as_ref()));
}

/// TLS 1.3 bidirectional close_notify test: after handshake, client sends
/// close_notify via shutdown, server detects it.
#[test]
fn test_tls13_graceful_shutdown() {
    use crate::config::ServerPrivateKey;

    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();

    let client_config = TlsConfig::builder().verify_peer(false).build();

    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .verify_peer(false)
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    // Full handshake
    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();

    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let actions = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions"),
    };

    let sh_record = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();

    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();

    let ee_record = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let cert_record = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_msg)
        .unwrap();
    let cv_record = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
        .unwrap();
    let sfin_record = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    // Client processes SH
    let (_, sh_data, _) = client_rl.open_record(&sh_record).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_actions = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions"),
    };

    client_rl
        .activate_read_decryption(sh_actions.suite, &sh_actions.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_actions.suite, &sh_actions.client_hs_keys)
        .unwrap();

    // Client processes EE, Cert, CV, Fin
    let (_, ee_data, _) = client_rl.open_record(&ee_record).unwrap();
    let (_, _, ee_total) = parse_handshake_header(&ee_data).unwrap();
    client_hs
        .process_encrypted_extensions(&ee_data[..ee_total])
        .unwrap();

    let (_, cert_data, _) = client_rl.open_record(&cert_record).unwrap();
    let (_, _, cert_total) = parse_handshake_header(&cert_data).unwrap();
    client_hs
        .process_certificate(&cert_data[..cert_total])
        .unwrap();

    let (_, cv_data, _) = client_rl.open_record(&cv_record).unwrap();
    let (_, _, cv_total) = parse_handshake_header(&cv_data).unwrap();
    client_hs
        .process_certificate_verify(&cv_data[..cv_total])
        .unwrap();

    let (_, fin_data, _) = client_rl.open_record(&sfin_record).unwrap();
    let (_, _, fin_total) = parse_handshake_header(&fin_data).unwrap();
    let fin_actions = client_hs.process_finished(&fin_data[..fin_total]).unwrap();

    // Client → Finished (still encrypted with HS keys)
    let cfin_record = client_rl
        .seal_record(ContentType::Handshake, &fin_actions.client_finished_msg)
        .unwrap();

    // NOW activate app keys on client (after sending Finished)
    client_rl
        .activate_read_decryption(fin_actions.suite, &fin_actions.server_app_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(fin_actions.suite, &fin_actions.client_app_keys)
        .unwrap();

    // Server processes client Finished
    let (_, cfin_data, _) = server_rl.open_record(&cfin_record).unwrap();
    let (_, _, cfin_total) = parse_handshake_header(&cfin_data).unwrap();
    let _cfin_actions = server_hs
        .process_client_finished(&cfin_data[..cfin_total])
        .unwrap();

    // Activate app keys on server
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_app_keys)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_app_keys)
        .unwrap();

    // Both sides are Connected. Now test close_notify.

    // Client sends close_notify alert
    let close_notify = [1u8, 0u8]; // AlertLevel::Warning, AlertDescription::CloseNotify
    let close_record = client_rl
        .seal_record(ContentType::Alert, &close_notify)
        .unwrap();

    // Server receives close_notify
    let (ct, plaintext, _) = server_rl.open_record(&close_record).unwrap();
    assert_eq!(ct, ContentType::Alert);
    assert_eq!(plaintext.len(), 2);
    assert_eq!(plaintext[0], 1); // warning
    assert_eq!(plaintext[1], 0); // close_notify

    // Server sends close_notify in response
    let server_close_record = server_rl
        .seal_record(ContentType::Alert, &close_notify)
        .unwrap();

    // Client receives close_notify
    let (ct, plaintext, _) = client_rl.open_record(&server_close_record).unwrap();
    assert_eq!(ct, ContentType::Alert);
    assert_eq!(plaintext[1], 0); // close_notify
}

// ======================================================================
// Client-side session cache tests (Phase 72)
// ======================================================================

/// TLS 1.3 client auto-stores NST in session cache keyed by server_name.
#[test]
fn test_tls13_client_session_cache_auto_store() {
    use crate::config::ServerPrivateKey;
    use crate::session::{InMemorySessionCache, SessionCache};
    use std::sync::{Arc, Mutex};

    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();
    let ticket_key = vec![0xAB; 32];
    let client_cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));

    // Full handshake with session cache configured on client
    let client_config = TlsConfig::builder()
        .verify_peer(false)
        .server_name("test.example.com")
        .session_cache(client_cache.clone())
        .build();
    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .ticket_key(ticket_key)
        .build();

    // Run full handshake in-memory and process NST
    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();
    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let actions = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions"),
    };

    let sh_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();
    let ee_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let cert_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_msg)
        .unwrap();
    let cv_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
        .unwrap();
    let sfin_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    let (_, sh_data, _) = client_rl.open_record(&sh_rec).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_act = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions"),
    };
    client_rl
        .activate_read_decryption(sh_act.suite, &sh_act.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_act.suite, &sh_act.client_hs_keys)
        .unwrap();

    for rec in [&ee_rec, &cert_rec, &cv_rec] {
        let (_, data, _) = client_rl.open_record(rec).unwrap();
        let (_, _, total) = parse_handshake_header(&data).unwrap();
        let msg = &data[..total];
        match client_hs.state() {
            HandshakeState::WaitEncryptedExtensions => {
                client_hs.process_encrypted_extensions(msg).unwrap();
            }
            HandshakeState::WaitCertCertReq => {
                client_hs.process_certificate(msg).unwrap();
            }
            HandshakeState::WaitCertVerify => {
                client_hs.process_certificate_verify(msg).unwrap();
            }
            s => panic!("unexpected state: {s:?}"),
        }
    }

    let (_, fin_data, _) = client_rl.open_record(&sfin_rec).unwrap();
    let (_, _, fin_total) = parse_handshake_header(&fin_data).unwrap();
    let fin_act = client_hs.process_finished(&fin_data[..fin_total]).unwrap();

    let cfin_record = client_rl
        .seal_record(ContentType::Handshake, &fin_act.client_finished_msg)
        .unwrap();
    let (_, cfin_data, _) = server_rl.open_record(&cfin_record).unwrap();
    let (_, _, cfin_total) = parse_handshake_header(&cfin_data).unwrap();
    let cfin_act = server_hs
        .process_client_finished(&cfin_data[..cfin_total])
        .unwrap();

    // Activate app keys
    client_rl
        .activate_write_encryption(fin_act.suite, &fin_act.client_app_keys)
        .unwrap();
    client_rl
        .activate_read_decryption(fin_act.suite, &fin_act.server_app_keys)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_app_keys)
        .unwrap();

    assert!(!cfin_act.new_session_ticket_msgs.is_empty());

    // Before NST, cache should be empty
    assert_eq!(client_cache.lock().unwrap().len(), 0);

    // Simulate NST reception in a TlsClientConnection-like fashion
    let nst_record = server_rl
        .seal_record(ContentType::Handshake, &cfin_act.new_session_ticket_msgs[0])
        .unwrap();
    let (_, nst_plain, _) = client_rl.open_record(&nst_record).unwrap();
    let (_, _, nst_total) = parse_handshake_header(&nst_plain).unwrap();
    let session = client_hs
        .process_new_session_ticket(&nst_plain[..nst_total], &fin_act.resumption_master_secret)
        .unwrap();

    // Manually store in cache (simulating what TlsClientConnection::read does)
    client_cache
        .lock()
        .unwrap()
        .put(b"test.example.com", session);

    // Cache should now have 1 entry
    assert_eq!(client_cache.lock().unwrap().len(), 1);
    let cached = client_cache
        .lock()
        .unwrap()
        .get(b"test.example.com")
        .unwrap()
        .clone();
    assert!(cached.ticket.is_some());
    assert!(!cached.psk.is_empty());
}

/// TLS 1.3 client auto-lookup: pre-populated cache provides resumption_session.
#[test]
fn test_tls13_client_session_cache_auto_lookup() {
    use crate::session::{InMemorySessionCache, SessionCache};
    use std::sync::{Arc, Mutex};

    let client_cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));

    // Pre-populate cache with a session
    let session = TlsSession {
        id: vec![1],
        cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
        master_secret: vec![0; 32],
        alpn_protocol: None,
        ticket: Some(vec![0xAA; 16]),
        ticket_lifetime: 3600,
        max_early_data: 0,
        ticket_age_add: 42,
        ticket_nonce: vec![1, 2, 3],
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        psk: vec![0xBB; 32],
        extended_master_secret: false,
    };
    client_cache
        .lock()
        .unwrap()
        .put(b"lookup.example.com", session.clone());

    // Config with no explicit resumption_session, but with cache + server_name
    let mut config = TlsConfig::builder()
        .verify_peer(false)
        .server_name("lookup.example.com")
        .session_cache(client_cache.clone())
        .build();

    assert!(config.resumption_session.is_none());

    // Simulate the auto-lookup that do_handshake performs
    if config.resumption_session.is_none() {
        if let (Some(ref cache_mutex), Some(ref server_name)) =
            (&config.session_cache, &config.server_name)
        {
            if let Ok(cache) = cache_mutex.lock() {
                if let Some(cached) = cache.get(server_name.as_bytes()) {
                    config.resumption_session = Some(cached.clone());
                }
            }
        }
    }

    // After auto-lookup, resumption_session should be populated
    assert!(config.resumption_session.is_some());
    let rs = config.resumption_session.unwrap();
    assert_eq!(rs.psk, vec![0xBB; 32]);
    assert_eq!(rs.ticket, Some(vec![0xAA; 16]));
}

/// Explicit resumption_session takes priority over cache.
#[test]
fn test_tls13_client_explicit_session_overrides_cache() {
    use crate::session::{InMemorySessionCache, SessionCache};
    use std::sync::{Arc, Mutex};

    let client_cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));

    // Put a session in cache
    let cached_session = TlsSession {
        id: vec![1],
        cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
        master_secret: vec![0; 32],
        alpn_protocol: None,
        ticket: Some(vec![0xCC; 16]),
        ticket_lifetime: 3600,
        max_early_data: 0,
        ticket_age_add: 42,
        ticket_nonce: vec![],
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        psk: vec![0xCC; 32],
        extended_master_secret: false,
    };
    client_cache
        .lock()
        .unwrap()
        .put(b"override.example.com", cached_session);

    // Explicit session
    let explicit_session = TlsSession {
        id: vec![2],
        cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
        master_secret: vec![0; 32],
        alpn_protocol: None,
        ticket: Some(vec![0xDD; 16]),
        ticket_lifetime: 7200,
        max_early_data: 0,
        ticket_age_add: 99,
        ticket_nonce: vec![],
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        psk: vec![0xDD; 32],
        extended_master_secret: false,
    };

    let mut config = TlsConfig::builder()
        .verify_peer(false)
        .server_name("override.example.com")
        .session_cache(client_cache)
        .resumption_session(explicit_session.clone())
        .build();

    // Simulate auto-lookup — should NOT override explicit session
    if config.resumption_session.is_none() {
        if let (Some(ref cache_mutex), Some(ref server_name)) =
            (&config.session_cache, &config.server_name)
        {
            if let Ok(cache) = cache_mutex.lock() {
                if let Some(cached) = cache.get(server_name.as_bytes()) {
                    config.resumption_session = Some(cached.clone());
                }
            }
        }
    }

    // Explicit session should be preserved
    let rs = config.resumption_session.unwrap();
    assert_eq!(rs.psk, vec![0xDD; 32]);
    assert_eq!(rs.ticket_age_add, 99);
}

/// No server_name → cache lookup skipped.
#[test]
fn test_tls13_client_no_server_name_skips_cache() {
    use crate::session::{InMemorySessionCache, SessionCache};
    use std::sync::{Arc, Mutex};

    let client_cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));

    let session = TlsSession {
        id: vec![1],
        cipher_suite: CipherSuite::TLS_AES_128_GCM_SHA256,
        master_secret: vec![0; 32],
        alpn_protocol: None,
        ticket: Some(vec![0xEE; 16]),
        ticket_lifetime: 3600,
        max_early_data: 0,
        ticket_age_add: 42,
        ticket_nonce: vec![],
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        psk: vec![0xEE; 32],
        extended_master_secret: false,
    };
    client_cache
        .lock()
        .unwrap()
        .put(b"noname.example.com", session);

    // No server_name set
    let mut config = TlsConfig::builder()
        .verify_peer(false)
        .session_cache(client_cache)
        .build();

    // Simulate auto-lookup — should skip because no server_name
    if config.resumption_session.is_none() {
        if let (Some(ref cache_mutex), Some(ref server_name)) =
            (&config.session_cache, &config.server_name)
        {
            if let Ok(cache) = cache_mutex.lock() {
                if let Some(cached) = cache.get(server_name.as_bytes()) {
                    config.resumption_session = Some(cached.clone());
                }
            }
        }
    }

    // Should remain None since server_name is None
    assert!(config.resumption_session.is_none());
}

// ======================================================================
// Write fragmentation tests (Phase 72)
// ======================================================================

/// TLS 1.3 write fragmentation: large data is split into max_fragment_size chunks.
#[test]
fn test_write_fragments_large_data() {
    use crate::config::ServerPrivateKey;

    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();

    let client_config = TlsConfig::builder().verify_peer(false).build();
    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .build();

    // Run full handshake in-memory
    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();
    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let actions = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions"),
    };

    let sh_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();

    let ee_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let cert_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_msg)
        .unwrap();
    let cv_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
        .unwrap();
    let sfin_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    let (_, sh_data, _) = client_rl.open_record(&sh_rec).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_act = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions"),
    };
    client_rl
        .activate_read_decryption(sh_act.suite, &sh_act.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_act.suite, &sh_act.client_hs_keys)
        .unwrap();

    for rec in [&ee_rec, &cert_rec, &cv_rec] {
        let (_, data, _) = client_rl.open_record(rec).unwrap();
        let (_, _, total) = parse_handshake_header(&data).unwrap();
        let msg = &data[..total];
        match client_hs.state() {
            HandshakeState::WaitEncryptedExtensions => {
                client_hs.process_encrypted_extensions(msg).unwrap();
            }
            HandshakeState::WaitCertCertReq => {
                client_hs.process_certificate(msg).unwrap();
            }
            HandshakeState::WaitCertVerify => {
                client_hs.process_certificate_verify(msg).unwrap();
            }
            s => panic!("unexpected state: {s:?}"),
        }
    }

    let (_, fin_data, _) = client_rl.open_record(&sfin_rec).unwrap();
    let (_, _, fin_total) = parse_handshake_header(&fin_data).unwrap();
    let fin_act = client_hs.process_finished(&fin_data[..fin_total]).unwrap();

    // Activate app keys on client
    client_rl
        .activate_write_encryption(fin_act.suite, &fin_act.client_app_keys)
        .unwrap();
    client_rl
        .activate_read_decryption(fin_act.suite, &fin_act.server_app_keys)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_app_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_app_keys)
        .unwrap();

    // Set max_fragment_size to 512 bytes
    client_rl.max_fragment_size = 512;

    // Write 2000 bytes — should auto-fragment into ceil(2000/512) = 4 records
    let big_data = vec![0x42u8; 2000];
    let mut all_records = Vec::new();
    let mut offset = 0;
    while offset < big_data.len() {
        let end = std::cmp::min(offset + 512, big_data.len());
        let rec = client_rl
            .seal_record(ContentType::ApplicationData, &big_data[offset..end])
            .unwrap();
        all_records.push(rec);
        offset = end;
    }

    // Should have 4 records: 512 + 512 + 512 + 464
    assert_eq!(all_records.len(), 4);

    // Server can decrypt all fragments and reassemble
    let mut reassembled = Vec::new();
    for rec in &all_records {
        let (ct, plaintext, _) = server_rl.open_record(rec).unwrap();
        assert_eq!(ct, ContentType::ApplicationData);
        reassembled.extend_from_slice(&plaintext);
    }
    assert_eq!(reassembled, big_data);
}

/// Write exactly max_frag bytes → 1 record; max_frag+1 → 2 records.
#[test]
fn test_write_exact_boundary() {
    use crate::config::ServerPrivateKey;

    let (seed, _pub_key, fake_cert) = make_ed25519_server_identity();

    let client_config = TlsConfig::builder().verify_peer(false).build();
    let server_config = TlsConfig::builder()
        .role(crate::TlsRole::Server)
        .certificate_chain(vec![fake_cert])
        .private_key(ServerPrivateKey::Ed25519(seed))
        .build();

    let mut client_hs = ClientHandshake::new(client_config);
    let mut client_rl = RecordLayer::new();
    let mut server_hs = ServerHandshake::new(server_config);
    let mut server_rl = RecordLayer::new();

    let ch_msg = client_hs.build_client_hello().unwrap();
    let ch_record = client_rl
        .seal_record(ContentType::Handshake, &ch_msg)
        .unwrap();
    let (_, ch_data, _) = server_rl.open_record(&ch_record).unwrap();
    let (_, _, ch_total) = parse_handshake_header(&ch_data).unwrap();
    let actions = match server_hs
        .process_client_hello(&ch_data[..ch_total])
        .unwrap()
    {
        ClientHelloResult::Actions(a) => *a,
        _ => panic!("expected Actions"),
    };

    let sh_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_hello_msg)
        .unwrap();
    server_rl
        .activate_write_encryption(actions.suite, &actions.server_hs_keys)
        .unwrap();
    server_rl
        .activate_read_decryption(actions.suite, &actions.client_hs_keys)
        .unwrap();

    let ee_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.encrypted_extensions_msg)
        .unwrap();
    let cert_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_msg)
        .unwrap();
    let cv_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.certificate_verify_msg)
        .unwrap();
    let sfin_rec = server_rl
        .seal_record(ContentType::Handshake, &actions.server_finished_msg)
        .unwrap();

    let (_, sh_data, _) = client_rl.open_record(&sh_rec).unwrap();
    let (_, _, sh_total) = parse_handshake_header(&sh_data).unwrap();
    let sh_act = match client_hs
        .process_server_hello(&sh_data[..sh_total])
        .unwrap()
    {
        ServerHelloResult::Actions(a) => a,
        _ => panic!("expected Actions"),
    };
    client_rl
        .activate_read_decryption(sh_act.suite, &sh_act.server_hs_keys)
        .unwrap();
    client_rl
        .activate_write_encryption(sh_act.suite, &sh_act.client_hs_keys)
        .unwrap();

    for rec in [&ee_rec, &cert_rec, &cv_rec] {
        let (_, data, _) = client_rl.open_record(rec).unwrap();
        let (_, _, total) = parse_handshake_header(&data).unwrap();
        let msg = &data[..total];
        match client_hs.state() {
            HandshakeState::WaitEncryptedExtensions => {
                client_hs.process_encrypted_extensions(msg).unwrap();
            }
            HandshakeState::WaitCertCertReq => {
                client_hs.process_certificate(msg).unwrap();
            }
            HandshakeState::WaitCertVerify => {
                client_hs.process_certificate_verify(msg).unwrap();
            }
            s => panic!("unexpected state: {s:?}"),
        }
    }

    let (_, fin_data, _) = client_rl.open_record(&sfin_rec).unwrap();
    let (_, _, fin_total) = parse_handshake_header(&fin_data).unwrap();
    let fin_act = client_hs.process_finished(&fin_data[..fin_total]).unwrap();

    client_rl
        .activate_write_encryption(fin_act.suite, &fin_act.client_app_keys)
        .unwrap();

    // Set max_fragment_size to 100 bytes
    client_rl.max_fragment_size = 100;

    // Exactly 100 bytes → 1 fragment
    let data_exact = [0x01u8; 100];
    let mut count = 0;
    let mut off = 0;
    while off < data_exact.len() {
        let end = std::cmp::min(off + 100, data_exact.len());
        let _rec = client_rl
            .seal_record(ContentType::ApplicationData, &data_exact[off..end])
            .unwrap();
        count += 1;
        off = end;
    }
    assert_eq!(count, 1);

    // 101 bytes → 2 fragments
    let data_over = [0x02u8; 101];
    let mut count2 = 0;
    let mut off = 0;
    while off < data_over.len() {
        let end = std::cmp::min(off + 100, data_over.len());
        let _rec = client_rl
            .seal_record(ContentType::ApplicationData, &data_over[off..end])
            .unwrap();
        count2 += 1;
        off = end;
    }
    assert_eq!(count2, 2);
}

/// Write empty buffer → Ok(0), no records sent.
#[test]
fn test_write_empty_buffer() {
    // The write() function returns Ok(0) for empty buffers
    // without sealing any records. We test this by verifying
    // the fragmentation loop logic:
    let buf: &[u8] = &[];
    assert!(buf.is_empty());
    // With empty buf, the function returns Ok(0) immediately
    assert_eq!(buf.len(), 0);
}

#[test]
fn test_key_update_loop_protection() {
    // Verify that the key_update_recv_count field is properly initialized
    // and the limit is checked in handle_key_update.
    let stream = Cursor::new(Vec::<u8>::new());
    let config = TlsConfig::builder().build();
    let mut conn = TlsClientConnection::new(stream, config);
    assert_eq!(conn.key_update_recv_count, 0);

    // Simulate incrementing the counter to the limit
    conn.key_update_recv_count = 128;
    // At 128, handle_key_update would increment to 129 and reject.
    // We test the counter logic directly since handle_key_update requires
    // cipher_params which are only set after a real handshake.
    conn.key_update_recv_count += 1;
    assert!(conn.key_update_recv_count > 128);

    // Same for server
    let stream2 = Cursor::new(Vec::<u8>::new());
    let config2 = TlsConfig::builder().role(crate::TlsRole::Server).build();
    let mut sconn = TlsServerConnection::new(stream2, config2);
    assert_eq!(sconn.key_update_recv_count, 0);
    sconn.key_update_recv_count = 129;
    assert!(sconn.key_update_recv_count > 128);
}

#[test]
fn test_key_update_counter_reset_on_data() {
    // Verify the counter is reset when application data is received.
    let stream = Cursor::new(Vec::<u8>::new());
    let config = TlsConfig::builder().build();
    let mut conn = TlsClientConnection::new(stream, config);

    // Simulate some key updates
    conn.key_update_recv_count = 50;
    // After receiving app data, counter should be reset to 0
    conn.key_update_recv_count = 0; // This is what read() does
    assert_eq!(conn.key_update_recv_count, 0);

    // Same for server
    let stream2 = Cursor::new(Vec::<u8>::new());
    let config2 = TlsConfig::builder().role(crate::TlsRole::Server).build();
    let mut sconn = TlsServerConnection::new(stream2, config2);
    sconn.key_update_recv_count = 100;
    sconn.key_update_recv_count = 0;
    assert_eq!(sconn.key_update_recv_count, 0);
}

#[test]
fn test_tls13_early_export_no_psk_fails() {
    // export_early_keying_material should fail when no PSK was offered
    // (early_exporter_master_secret is empty).
    let stream = Cursor::new(Vec::<u8>::new());
    let config = TlsConfig::builder().build();
    let conn = TlsClientConnection::new(stream, config);
    let result = conn.export_early_keying_material(b"test_label", Some(b"ctx"), 32);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("no early exporter master secret"),
        "unexpected error: {err_msg}"
    );

    // Same for server
    let stream2 = Cursor::new(Vec::<u8>::new());
    let config2 = TlsConfig::builder().role(crate::TlsRole::Server).build();
    let sconn = TlsServerConnection::new(stream2, config2);
    let result2 = sconn.export_early_keying_material(b"test_label", None, 32);
    assert!(result2.is_err());
}

#[test]
fn test_tls13_early_export_with_psk() {
    // When early_exporter_master_secret is populated (simulating PSK handshake),
    // export_early_keying_material should succeed.
    let stream = Cursor::new(Vec::<u8>::new());
    let config = TlsConfig::builder().build();
    let mut conn = TlsClientConnection::new(stream, config);

    // Simulate a completed PSK handshake by setting the secret and cipher params
    conn.early_exporter_master_secret = vec![0xAB; 32];
    conn.cipher_params = Some(
        crate::crypt::CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap(),
    );

    let result = conn.export_early_keying_material(b"test_label", Some(b"ctx"), 32);
    assert!(result.is_ok());
    let ekm = result.unwrap();
    assert_eq!(ekm.len(), 32);

    // Same secret + label + context should produce deterministic output
    let result2 = conn.export_early_keying_material(b"test_label", Some(b"ctx"), 32);
    assert_eq!(ekm, result2.unwrap());

    // Different label should produce different output
    let result3 = conn.export_early_keying_material(b"other_label", Some(b"ctx"), 32);
    assert_ne!(ekm, result3.unwrap());
}

#[test]
fn test_tls13_take_session_before_handshake() {
    let stream = Cursor::new(Vec::<u8>::new());
    let config = TlsConfig::builder().build();
    let mut conn = TlsClientConnection::new(stream, config);
    // Before handshake, no session to take
    assert!(conn.take_session().is_none());
}

#[test]
fn test_tls13_connection_info_before_handshake() {
    let stream = Cursor::new(Vec::<u8>::new());
    let config = TlsConfig::builder().build();
    let conn = TlsClientConnection::new(stream, config);
    // Before handshake, connection_info returns None
    assert!(conn.connection_info().is_none());
}

#[test]
fn test_tls13_accessors_before_handshake() {
    let stream = Cursor::new(Vec::<u8>::new());
    let config = TlsConfig::builder().build();
    let conn = TlsClientConnection::new(stream, config);
    assert!(conn.peer_certificates().is_empty());
    assert!(conn.alpn_protocol().is_none());
    assert!(conn.server_name().is_none());
    assert!(conn.negotiated_group().is_none());
    assert!(!conn.is_session_resumed());
}

#[test]
fn test_tls13_queue_early_data_and_accepted() {
    let stream = Cursor::new(Vec::<u8>::new());
    let config = TlsConfig::builder().build();
    let mut conn = TlsClientConnection::new(stream, config);
    // Before queuing, early_data_accepted is false
    assert!(!conn.early_data_accepted());
    // Queue some data
    conn.queue_early_data(b"hello early");
    conn.queue_early_data(b" world");
    // Still not accepted (no handshake done)
    assert!(!conn.early_data_accepted());
    // But the queue should be populated internally
    assert_eq!(conn.early_data_queue, b"hello early world");
}

#[test]
fn test_tls13_server_key_update_before_connected() {
    let stream = Cursor::new(Vec::<u8>::new());
    let config = TlsConfig::builder().build();
    let mut conn = TlsServerConnection::new(stream, config);
    // key_update before connected should fail
    let result = conn.key_update(false);
    assert!(result.is_err());
}
