//! Concurrency stress tests (Phase T157).
//!
//! Verifies thread-safety under concurrent access for session cache,
//! DRBG, TLS handshakes, key generation, and hash operations.

use std::sync::{Arc, Mutex};
use std::thread;

// ============================================================
// Tests 1-3: Session cache concurrency
// ============================================================

fn make_test_session() -> hitls_tls::session::TlsSession {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    hitls_tls::session::TlsSession {
        id: vec![],
        cipher_suite: hitls_tls::CipherSuite::TLS_AES_128_GCM_SHA256,
        master_secret: vec![0x42; 32],
        alpn_protocol: None,
        ticket: Some(vec![0xAB; 32]),
        ticket_lifetime: 3600,
        max_early_data: 0,
        ticket_age_add: 0,
        ticket_nonce: vec![],
        created_at: now,
        psk: vec![],
        extended_master_secret: false,
    }
}

#[test]
fn test_session_cache_concurrent_insert_lookup() {
    use hitls_tls::session::{InMemorySessionCache, SessionCache};

    // Capacity larger than total insertions to avoid eviction races
    let cache: Arc<Mutex<InMemorySessionCache>> =
        Arc::new(Mutex::new(InMemorySessionCache::new(2000)));
    let mut handles = vec![];

    // 10 threads × 100 insert+lookup operations
    for thread_id in 0..10u32 {
        let cache = Arc::clone(&cache);
        handles.push(thread::spawn(move || {
            for i in 0..100u32 {
                let key = format!("thread{thread_id}-key{i}");
                let session = make_test_session();
                // Atomically insert and lookup under same lock to avoid eviction race
                let mut c = cache.lock().unwrap();
                c.put(key.as_bytes(), session);
                let found = c.get(key.as_bytes()).is_some();
                assert!(found, "Session should be found for {key}");
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // Total insertions: 10 × 100 = 1000 (within capacity of 2000)
    let cache = cache.lock().unwrap();
    assert!(!cache.is_empty() && cache.len() <= 2000);
}

#[test]
fn test_session_cache_concurrent_eviction() {
    use hitls_tls::session::{InMemorySessionCache, SessionCache};

    // Small capacity to force eviction
    let cache: Arc<Mutex<InMemorySessionCache>> =
        Arc::new(Mutex::new(InMemorySessionCache::new(50)));
    let mut handles = vec![];

    // 10 threads × 50 insertions = 500 total, capacity 50 → heavy eviction
    for thread_id in 0..10u32 {
        let cache = Arc::clone(&cache);
        handles.push(thread::spawn(move || {
            for i in 0..50u32 {
                let key = format!("t{thread_id}-k{i}");
                let session = make_test_session();
                cache.lock().unwrap().put(key.as_bytes(), session);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let cache = cache.lock().unwrap();
    assert!(cache.len() <= 50, "Cache should not exceed max_size");
}

#[test]
fn test_session_cache_concurrent_remove() {
    use hitls_tls::session::{InMemorySessionCache, SessionCache};

    let cache: Arc<Mutex<InMemorySessionCache>> =
        Arc::new(Mutex::new(InMemorySessionCache::new(200)));

    // Pre-populate
    for i in 0..200u32 {
        let key = format!("key{i}");
        let session = make_test_session();
        cache.lock().unwrap().put(key.as_bytes(), session);
    }

    let mut handles = vec![];

    // 5 threads inserting, 5 threads removing (different keys)
    for thread_id in 0..5u32 {
        let cache = Arc::clone(&cache);
        handles.push(thread::spawn(move || {
            for i in 0..20u32 {
                let key = format!("new-t{thread_id}-k{i}");
                let session = make_test_session();
                cache.lock().unwrap().put(key.as_bytes(), session);
            }
        }));
    }
    for thread_id in 0..5u32 {
        let cache = Arc::clone(&cache);
        handles.push(thread::spawn(move || {
            for i in 0..20u32 {
                let key = format!("key{}", thread_id * 20 + i);
                cache.lock().unwrap().remove(key.as_bytes());
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // Should not panic; exact count depends on interleaving
    let cache = cache.lock().unwrap();
    assert!(cache.len() <= 200);
}

// ============================================================
// Tests 4-5: DRBG concurrency
// ============================================================

#[test]
fn test_drbg_concurrent_generate() {
    use hitls_crypto::drbg::HmacDrbg;

    let drbg: Arc<Mutex<HmacDrbg>> =
        Arc::new(Mutex::new(HmacDrbg::from_system_entropy(48).unwrap()));
    let mut handles = vec![];

    // 10 threads each generating random bytes
    for _ in 0..10 {
        let drbg = Arc::clone(&drbg);
        handles.push(thread::spawn(move || {
            let mut output = vec![0u8; 100];
            for _ in 0..10 {
                drbg.lock().unwrap().generate(&mut output, None).unwrap();
                // Output should not be all zeros
                assert!(output.iter().any(|&b| b != 0));
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_drbg_concurrent_reseed_generate() {
    use hitls_crypto::drbg::HmacDrbg;

    let drbg: Arc<Mutex<HmacDrbg>> =
        Arc::new(Mutex::new(HmacDrbg::from_system_entropy(48).unwrap()));
    let mut handles = vec![];

    // 5 threads generating, 5 threads reseeding
    for _ in 0..5 {
        let drbg = Arc::clone(&drbg);
        handles.push(thread::spawn(move || {
            let mut output = vec![0u8; 64];
            for _ in 0..20 {
                drbg.lock().unwrap().generate(&mut output, None).unwrap();
            }
        }));
    }
    for _ in 0..5 {
        let drbg = Arc::clone(&drbg);
        handles.push(thread::spawn(move || {
            let mut entropy = [0u8; 48];
            for _ in 0..10 {
                // Use the DRBG itself to generate entropy for reseeding
                // (simulates entropy refresh)
                drbg.lock().unwrap().generate(&mut entropy, None).unwrap();
                drbg.lock().unwrap().reseed(&entropy, None).unwrap();
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}

// ============================================================
// Tests 6-7: Concurrent TLS handshakes
// ============================================================

#[test]
fn test_concurrent_tls13_handshakes() {
    use hitls_tls::CipherSuite;

    let mut handles = vec![];

    // 10 parallel TLS 1.3 handshakes
    for _ in 0..10 {
        handles.push(thread::spawn(|| {
            let (client_suite, server_suite) = hitls_integration_tests::run_tls13_tcp_loopback(
                CipherSuite::TLS_AES_128_GCM_SHA256,
            );
            assert_eq!(client_suite, CipherSuite::TLS_AES_128_GCM_SHA256);
            assert_eq!(server_suite, CipherSuite::TLS_AES_128_GCM_SHA256);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_concurrent_tls12_handshakes() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::{TlsRole, TlsVersion};

    // Use ECDSA identity (Ed25519 not compatible with TLS 1.2 cipher suites)
    let (cert_chain, server_key) = hitls_integration_tests::make_ecdsa_server_identity();
    let suite = hitls_tls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    let mut handles = vec![];

    // 10 parallel TLS 1.2 handshakes
    for _ in 0..10 {
        let cert = cert_chain.clone();
        let key = server_key.clone();
        handles.push(thread::spawn(move || {
            let client_config = TlsConfig::builder()
                .role(TlsRole::Client)
                .min_version(TlsVersion::Tls12)
                .max_version(TlsVersion::Tls12)
                .cipher_suites(&[suite])
                .verify_peer(false)
                .build();
            let server_config = TlsConfig::builder()
                .role(TlsRole::Server)
                .min_version(TlsVersion::Tls12)
                .max_version(TlsVersion::Tls12)
                .cipher_suites(&[suite])
                .certificate_chain(cert)
                .private_key(key)
                .verify_peer(false)
                .build();
            let (cs, ss) =
                hitls_integration_tests::run_tls12_tcp_loopback(client_config, server_config);
            assert_eq!(cs, ss);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}

// ============================================================
// Test 8: Concurrent data transfer on TLS 1.3
// ============================================================

#[test]
fn test_concurrent_tls13_data_transfer() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::time::Duration;

    let (cert_chain, server_key) = hitls_integration_tests::make_ed25519_server_identity();

    let mut handles = vec![];

    // 5 connections transferring data in parallel
    for conn_id in 0u32..5 {
        let cert = cert_chain.clone();
        let key = server_key.clone();
        handles.push(thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();

            let server_config = TlsConfig::builder()
                .role(TlsRole::Server)
                .min_version(TlsVersion::Tls13)
                .max_version(TlsVersion::Tls13)
                .cipher_suites(&[CipherSuite::TLS_AES_128_GCM_SHA256])
                .certificate_chain(cert)
                .private_key(key)
                .verify_peer(false)
                .build();

            let server = thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut conn = TlsServerConnection::new(stream, server_config);
                conn.handshake().unwrap();

                // Echo back data
                let mut buf = [0u8; 1024];
                let n = conn.read(&mut buf).unwrap();
                conn.write(&buf[..n]).unwrap();
                let _ = conn.shutdown();
            });

            let client_config = TlsConfig::builder()
                .role(TlsRole::Client)
                .min_version(TlsVersion::Tls13)
                .max_version(TlsVersion::Tls13)
                .cipher_suites(&[CipherSuite::TLS_AES_128_GCM_SHA256])
                .verify_peer(false)
                .build();

            let stream = std::net::TcpStream::connect(addr).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut client = TlsClientConnection::new(stream, client_config);
            client.handshake().unwrap();

            let msg = format!("hello from connection {conn_id}");
            client.write(msg.as_bytes()).unwrap();
            let mut buf = [0u8; 1024];
            let n = client.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
            let _ = client.shutdown();

            server.join().unwrap();
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}

// ============================================================
// Test 9: Concurrent key generation
// ============================================================

#[test]
fn test_concurrent_key_generation() {
    use hitls_crypto::ecdsa::EcdsaKeyPair;
    use hitls_types::EccCurveId;

    let mut handles = vec![];

    // 10 threads generating ECDSA P-256 key pairs simultaneously
    for _ in 0..10 {
        handles.push(thread::spawn(|| {
            let kp = EcdsaKeyPair::generate(EccCurveId::NistP256).unwrap();
            // Verify the key pair works
            let digest = [0x42u8; 32];
            let sig = kp.sign(&digest).unwrap();
            assert!(kp.verify(&digest, &sig).unwrap());
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}

// ============================================================
// Test 10: Concurrent hash operations
// ============================================================

#[test]
fn test_concurrent_hash_operations() {
    use hitls_crypto::sha2::Sha256;

    let mut handles = vec![];

    // 20 threads hashing different data with SHA-256
    for thread_id in 0u32..20 {
        handles.push(thread::spawn(move || {
            let data = vec![thread_id as u8; 1000];
            let mut hasher = Sha256::new();
            hasher.update(&data).unwrap();
            let hash = hasher.finish().unwrap();
            assert_eq!(hash.len(), 32);

            // Verify deterministic: same input → same output
            let mut hasher2 = Sha256::new();
            hasher2.update(&data).unwrap();
            let hash2 = hasher2.finish().unwrap();
            assert_eq!(hash, hash2);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}
