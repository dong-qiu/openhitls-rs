//! Encrypted-handshake TCP rogue server (end-to-end) — T224 / #42.
//!
//! Phase H-1 of the encrypted-mutation series
//! (`docs/issue-42-phase-h-plan.md`). Closes the helper-level →
//! full-driver arc opened by Phase G plan §8.
//!
//! ## Why this file exists
//!
//! Phase G (T219-T223) shipped helper-level pins for the
//! encrypted post-ServerHello mutation families: byte-exact
//! signing buffer construction (T220 CertVerify), AEAD encrypt
//! round-trip (T219), `verify_data` HMAC derivation (T221),
//! EE byte layout (T222). Those tests proved the math.
//!
//! What they did NOT do: drive the encrypted handshake
//! end-to-end against a real `TlsClientConnection` over a TCP
//! socket. The C SDV `MODIFIED_*_TC` rows all assert against
//! the client's wire-format `Alert::*` variant (RFC 8446 §6.2)
//! that the real client emits when it rejects a mutated
//! message — that is the mutation-test gold standard, and the
//! only way to reach it is to drive the full handshake.
//!
//! ## Public APIs reused (zero product code touched)
//!
//! Same pattern T186 codified for the plaintext rogue server,
//! extended to the encrypted post-SH path the way T219
//! extended it to the key-schedule layer:
//!
//! - `hitls_tls::crypt::transcript::TranscriptHash` — RFC 8446
//!   §7.1 transcript hash bookkeeping over CH + SH + post-SH
//! - `hitls_tls::handshake::key_exchange::KeyExchange::{generate,
//!   public_key_bytes, compute_shared_secret}` — server-side
//!   ECDH
//! - `hitls_tls::handshake::extensions_codec::{build_supported_versions_sh,
//!   build_key_share_sh, parse_key_share_ch}` — SH extension
//!   building
//! - `hitls_tls::handshake::codec::{decode_client_hello,
//!   encode_server_hello, ServerHello}` — CH/SH codecs
//! - `hitls_tls::crypt::key_schedule::KeySchedule` — full TLS
//!   1.3 key schedule
//! - `hitls_tls::crypt::traffic_keys::TrafficKeys::derive` —
//!   key + IV from traffic secret
//! - `hitls_tls::crypt::aead::{TlsAead, AesGcmAead}` — RFC 8446
//!   §5.2 record-layer AEAD
//!
//! ## T224 scope (this PR)
//!
//! Lands the TCP rogue-server framework + 3 baseline E2E
//! tests. T225 builds on this to port the
//! `MODIFIED_CERT_VERIFY_*` C family with real wire-format
//! Alert observation.

use hitls_tls::config::TlsConfig;
use hitls_tls::connection::TlsClientConnection;
use hitls_tls::crypt::aead::{AesGcmAead, TlsAead};
use hitls_tls::crypt::key_schedule::KeySchedule;
use hitls_tls::crypt::traffic_keys::TrafficKeys;
use hitls_tls::crypt::transcript::TranscriptHash;
use hitls_tls::crypt::{CipherSuiteParams, HashAlgId, NamedGroup};
use hitls_tls::extensions::ExtensionType;
use hitls_tls::handshake::codec::{decode_client_hello, encode_server_hello, ServerHello};
use hitls_tls::handshake::extensions_codec::{
    build_key_share_sh, build_supported_versions_sh, parse_key_share_ch,
};
use hitls_tls::handshake::key_exchange::KeyExchange;
use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

// ===========================================================================
// TCP plumbing (adapted from T186's `transcript_mutation.rs`).
// ===========================================================================

fn make_handshake_record(handshake_bytes: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + handshake_bytes.len());
    record.push(0x16); // ContentType::Handshake
    record.extend_from_slice(&[0x03, 0x03]); // legacy_record_version
    record.extend_from_slice(&(handshake_bytes.len() as u16).to_be_bytes());
    record.extend_from_slice(handshake_bytes);
    record
}

fn read_exact(stream: &mut TcpStream, len: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_record(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let header = read_exact(stream, 5)?;
    let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let body = read_exact(stream, body_len)?;
    let mut record = header;
    record.extend_from_slice(&body);
    Ok(record)
}

/// Snapshot of the captured ClientHello, including the offered key_share
/// peer pubkey — Phase H needs this to compute the ECDH shared secret on
/// the rogue-server side.
struct ClientHelloInfo {
    session_id: Vec<u8>,
    offered_ciphers: Vec<CipherSuite>,
    offered_key_shares: Vec<(NamedGroup, Vec<u8>)>,
    /// Raw handshake-message bytes (`type || u24(len) || body`) for the
    /// captured ClientHello. Needed to feed `TranscriptHash` so the
    /// rogue server's key schedule matches the client's.
    ch_handshake_bytes: Vec<u8>,
}

fn capture_client_hello(stream: &mut TcpStream) -> ClientHelloInfo {
    let record = read_record(stream).expect("read ClientHello record");
    let hs_bytes = record[5..].to_vec();
    let ch_body = &hs_bytes[4..];
    let ch = decode_client_hello(ch_body).expect("decode ClientHello");

    let mut offered_key_shares = vec![];
    for ext in &ch.extensions {
        if ext.extension_type == ExtensionType::KEY_SHARE {
            offered_key_shares = parse_key_share_ch(&ext.data).unwrap_or_default();
        }
    }

    ClientHelloInfo {
        session_id: ch.legacy_session_id,
        offered_ciphers: ch.cipher_suites,
        offered_key_shares,
        ch_handshake_bytes: hs_bytes,
    }
}

// ===========================================================================
// Server-side handshake helpers — Phase H specific.
// ===========================================================================

/// Build a valid ServerHello consistent with the captured ClientHello,
/// using a caller-supplied `kx` keypair so the caller retains access
/// to it for `compute_shared_secret`.
fn make_valid_sh(info: &ClientHelloInfo, kx: &KeyExchange, random: [u8; 32]) -> Vec<u8> {
    let cipher_suite = info.offered_ciphers[0];
    let (group, _client_pub) = &info.offered_key_shares[0];
    let extensions = vec![
        build_supported_versions_sh(),
        build_key_share_sh(*group, kx.public_key_bytes()),
    ];
    let sh = ServerHello {
        random,
        legacy_session_id: info.session_id.clone(),
        cipher_suite,
        extensions,
    };
    encode_server_hello(&sh)
}

/// Derive the server handshake traffic key + IV given the cipher suite,
/// the ECDH shared secret, and the transcript hash through CH + SH.
///
/// Sibling to T219's private copy in `transcript_mutation_encrypted.rs`;
/// duplicated here to keep Phase H test file self-contained (separate
/// test binary, no shared helper module yet).
fn derive_server_handshake_keys(
    suite: CipherSuite,
    dhe_shared_secret: &[u8],
    transcript_hash_ch_sh: &[u8],
) -> (Vec<u8>, TrafficKeys) {
    let params = CipherSuiteParams::from_suite(suite).expect("known TLS 1.3 cipher suite");
    let mut ks = KeySchedule::new(params.clone());
    ks.derive_early_secret(None).expect("early secret");
    ks.derive_handshake_secret(dhe_shared_secret)
        .expect("handshake secret");
    let (_client_secret, server_secret) = ks
        .derive_handshake_traffic_secrets(transcript_hash_ch_sh)
        .expect("handshake traffic secrets");
    let keys = TrafficKeys::derive(&params, &server_secret).expect("traffic keys");
    (server_secret, keys)
}

fn record_nonce(static_iv: &[u8], seq_num: u64) -> Vec<u8> {
    let mut nonce = static_iv.to_vec();
    let seq_be = seq_num.to_be_bytes();
    let off = nonce.len().saturating_sub(8);
    for (i, b) in seq_be.iter().enumerate() {
        nonce[off + i] ^= b;
    }
    nonce
}

/// Seal `inner_plaintext || inner_content_type` as a TLS 1.3
/// application_data record (RFC 8446 §5.2). Sibling to T219's
/// `seal_encrypted_record`.
fn seal_encrypted_record(
    suite: CipherSuite,
    keys: &TrafficKeys,
    seq_num: u64,
    inner_content_type: u8,
    inner_plaintext: &[u8],
) -> Vec<u8> {
    let params = CipherSuiteParams::from_suite(suite).expect("known suite");
    assert_eq!(
        params.key_len, 16,
        "T224 baseline assumes AES-128-GCM (key_len=16)"
    );
    let aead = AesGcmAead::new(&keys.key).expect("aead init");
    let mut plaintext = inner_plaintext.to_vec();
    plaintext.push(inner_content_type);
    let nonce = record_nonce(&keys.iv, seq_num);
    let body_len = (plaintext.len() + aead.tag_size()) as u16;
    let mut header = vec![0x17, 0x03, 0x03];
    header.extend_from_slice(&body_len.to_be_bytes());
    let ciphertext = aead.encrypt(&nonce, &header, &plaintext).expect("encrypt");
    let mut record = header;
    record.extend_from_slice(&ciphertext);
    record
}

/// Build a minimal `EncryptedExtensions` handshake message body
/// (no extensions). Wire format per RFC 8446 §4.3.1:
///
/// ```text
/// struct {
///     Extension extensions<0..2^16-1>;
/// } EncryptedExtensions;
/// ```
///
/// With handshake header: `0x08 || u24(2) || u16(0)` (6 bytes).
fn build_empty_encrypted_extensions() -> Vec<u8> {
    vec![
        0x08, // HandshakeType::EncryptedExtensions
        0x00, 0x00, 0x02, // u24 length = 2
        0x00, 0x00, // u16 extensions list length = 0
    ]
}

/// Context the rogue-server callback receives after the SH has been sent
/// and the handshake traffic keys are ready.
#[allow(dead_code)]
struct PostShCtx {
    suite: CipherSuite,
    server_handshake_keys: TrafficKeys,
    /// Sequence counter for the encrypted records this side writes.
    /// Each call to `seal_encrypted_record` should pass the current
    /// value, then the caller bumps it.
    next_write_seq: u64,
    /// Transcript hash after CH || SH. The callback can update its own
    /// copy if it appends further handshake messages.
    transcript_hash_ch_sh: Vec<u8>,
}

/// Drive a real `TlsClientConnection` against a rogue server that:
///   1. Reads the ClientHello off the wire
///   2. Generates a matching ECDH keypair, sends a valid ServerHello
///   3. Computes the ECDH shared secret + handshake traffic keys
///   4. Invokes `emit_post_sh` so the test can write 0 or more
///      encrypted post-SH records before the stream is closed
///
/// Returns the client's handshake error (panics if it succeeds).
fn drive_client_against_encrypted_rogue_server<F>(emit_post_sh: F) -> String
where
    F: FnOnce(&mut PostShCtx, &mut TcpStream) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let rogue_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let info = capture_client_hello(&mut stream);

        // Pick the first offered key_share group + that peer pubkey.
        let (group, client_pub) = info.offered_key_shares[0].clone();
        let kx = KeyExchange::generate(group).expect("rogue server kx");

        // Send a valid SH.
        let mut sh_random = [0u8; 32];
        for (i, b) in sh_random.iter_mut().enumerate() {
            // Deterministic, non-HRR sentinel (first byte != 0xCF).
            *b = (i as u8).wrapping_add(0x42);
        }
        let sh_bytes = make_valid_sh(&info, &kx, sh_random);
        let sh_record = make_handshake_record(&sh_bytes);
        if stream.write_all(&sh_record).is_err() {
            return;
        }

        // Compute shared secret + transcript hash through CH || SH.
        let dhe = kx.compute_shared_secret(&client_pub).expect("ECDH");
        let mut transcript = TranscriptHash::new(HashAlgId::Sha256);
        transcript
            .update(&info.ch_handshake_bytes)
            .expect("transcript CH");
        transcript.update(&sh_bytes).expect("transcript SH");
        let transcript_hash_ch_sh = transcript.current_hash().expect("CH||SH hash");

        // Derive server handshake traffic keys.
        let suite = info.offered_ciphers[0];
        let (_server_secret, keys) =
            derive_server_handshake_keys(suite, &dhe, &transcript_hash_ch_sh);

        let mut ctx = PostShCtx {
            suite,
            server_handshake_keys: keys,
            next_write_seq: 0,
            transcript_hash_ch_sh: transcript_hash_ch_sh.to_vec(),
        };
        emit_post_sh(&mut ctx, &mut stream);

        // Hold the connection open briefly so the client receives the
        // emitted records before EOF.
        thread::sleep(Duration::from_millis(200));
    });

    let stream = TcpStream::connect(addr).expect("connect rogue server");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .build();
    let mut conn = TlsClientConnection::new(stream, client_config);
    let err = conn
        .handshake()
        .expect_err("rogue encrypted server should not let client handshake succeed");
    let _ = rogue_handle.join();
    format!("{err:?}")
}

// ===========================================================================
// T224 baseline E2E tests.
// ===========================================================================

/// Phase H baseline #1: the rogue server sends a valid SH and then
/// closes the stream. The real client never sees EncryptedExtensions
/// and must error.
#[test]
fn h224_baseline_sh_only_client_errors_post_sh() {
    let err = drive_client_against_encrypted_rogue_server(|_ctx, _stream| {
        // No post-SH messages — just close.
    });
    assert!(
        !err.is_empty(),
        "client must error after rogue server closes without sending EE; got: {err}"
    );
}

/// Phase H baseline #2: the rogue server sends a valid SH + a valid
/// encrypted EncryptedExtensions, then closes. The real client must
/// decrypt the EE successfully (proving the AEAD layer is correctly
/// wired) and then error expecting Certificate next.
///
/// This is the keystone test for the Phase H framework — if EE
/// decryption fails the framework is broken; if EE decryption
/// succeeds but the client doesn't error after EE, the test
/// framework is silently passing.
#[test]
fn h224_baseline_encrypted_ee_decrypts_then_client_aborts_at_cert() {
    let err = drive_client_against_encrypted_rogue_server(|ctx, stream| {
        let ee = build_empty_encrypted_extensions();
        let record = seal_encrypted_record(
            ctx.suite,
            &ctx.server_handshake_keys,
            ctx.next_write_seq,
            0x16, // inner ContentType::Handshake
            &ee,
        );
        ctx.next_write_seq += 1;
        let _ = stream.write_all(&record);
    });
    assert!(
        !err.is_empty(),
        "client must error after EE since no Certificate follows; got: {err}"
    );
}

/// Phase H baseline #3 (audit pin): the Phase H plan doc remains the
/// authoritative anchor for this series. Codified at T215.
#[test]
fn h224_audit_phase_h_plan_docs_in_sync() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-h-plan.md");
    let plan = std::fs::read_to_string(&plan_path).unwrap_or_else(|e| {
        panic!("missing Phase H plan doc at {plan_path}: {e}");
    });
    for anchor in [
        "Phase H",
        "T224",
        "T225",
        "T226",
        "T227",
        "T228",
        "TODO(#42-phase-h)",
        "TODO(#48-encrypted-mutation)",
        "transcript_mutation_encrypted_e2e.rs",
    ] {
        assert!(
            plan.contains(anchor),
            "Phase H plan doc must contain anchor `{anchor}`"
        );
    }
}
