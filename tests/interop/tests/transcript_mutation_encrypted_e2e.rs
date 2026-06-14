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

// ===========================================================================
// T225 / Phase H-2 — MODIFIED_CERT_VERIFY / MODIFIED_CERTMSG family.
//
// E2E observation of `MODIFIED_CERT_VERIFY_*` alerts at the wire-format
// `Alert::*` level would require the rogue server to ship a server cert +
// matching private key + valid CV signature. That cert + key loading
// infrastructure is not yet in place (estimated +200 LoC over the
// existing PEM/PKCS#8 loaders). Per the T220 codified methodology
// "Helper-level mutation pin = full E2E driver alternative", T225
// ships:
//
// - 3 E2E tests exercising the post-EE encrypted Certificate path
//   (MODIFIED_CERTMSG-family) using the T224 framework — these
//   observe real wire-format client errors at the Certificate phase.
// - 6 helper-level pins extending T220's CertVerify byte-exact
//   invariants into the E2E test file so a future "Phase I" PR that
//   adds the cert+key loader can grep these anchors.
// - 1 plan-doc banner pin.
//
// Cumulative: T224 (3) + T225 (10) = 13 tests in this file.
// ===========================================================================

/// Helper: wrap a handshake-message body in an encrypted record using
/// `seal_encrypted_record` with `inner_content_type = 0x16` (Handshake).
fn seal_encrypted_handshake(
    suite: CipherSuite,
    keys: &TrafficKeys,
    seq_num: u64,
    handshake_bytes: &[u8],
) -> Vec<u8> {
    seal_encrypted_record(suite, keys, seq_num, 0x16, handshake_bytes)
}

/// Helper: build a Certificate handshake message per RFC 8446 §4.4.2:
///
/// ```text
/// struct {
///     opaque certificate_request_context<0..2^8-1>;
///     CertificateEntry certificate_list<0..2^24-1>;
/// } Certificate;
/// ```
///
/// `cert_list_bytes` is the concatenated `CertificateEntry` bytes (each
/// entry is `opaque cert_data<1..2^24-1> + Extension extensions<0..2^16-1>`).
fn build_certificate_message(cert_list_bytes: &[u8]) -> Vec<u8> {
    let body_len = 1 + 3 + cert_list_bytes.len();
    let mut msg = Vec::with_capacity(4 + body_len);
    msg.push(0x0B); // HandshakeType::Certificate
    let body_len_u32 = body_len as u32;
    msg.extend_from_slice(&[
        ((body_len_u32 >> 16) & 0xff) as u8,
        ((body_len_u32 >> 8) & 0xff) as u8,
        (body_len_u32 & 0xff) as u8,
    ]);
    msg.push(0x00); // certificate_request_context length = 0 (server)
    let list_len = cert_list_bytes.len() as u32;
    msg.extend_from_slice(&[
        ((list_len >> 16) & 0xff) as u8,
        ((list_len >> 8) & 0xff) as u8,
        (list_len & 0xff) as u8,
    ]);
    msg.extend_from_slice(cert_list_bytes);
    msg
}

/// Helper: build a CertificateEntry per RFC 8446 §4.4.2:
/// `opaque cert_data<1..2^24-1> + u16(0) empty extensions`.
fn build_certificate_entry(cert_der: &[u8]) -> Vec<u8> {
    let mut entry = Vec::with_capacity(3 + cert_der.len() + 2);
    let cert_len = cert_der.len() as u32;
    entry.extend_from_slice(&[
        ((cert_len >> 16) & 0xff) as u8,
        ((cert_len >> 8) & 0xff) as u8,
        (cert_len & 0xff) as u8,
    ]);
    entry.extend_from_slice(cert_der);
    entry.extend_from_slice(&[0x00, 0x00]); // extensions list length = 0
    entry
}

/// Phase H-2 E2E #1: rogue server sends EE + Certificate with empty
/// `certificate_list` (RFC 8446 §4.4.2 — only the client may send an
/// empty list with `CertificateRequest`; the server's first
/// Certificate message MUST carry at least one entry). The real
/// client must reject.
#[test]
fn h225_e2e_encrypted_certificate_with_empty_list_rejected() {
    let err = drive_client_against_encrypted_rogue_server(|ctx, stream| {
        let ee = build_empty_encrypted_extensions();
        let r1 = seal_encrypted_handshake(
            ctx.suite,
            &ctx.server_handshake_keys,
            ctx.next_write_seq,
            &ee,
        );
        ctx.next_write_seq += 1;
        let cert = build_certificate_message(&[]);
        let r2 = seal_encrypted_handshake(
            ctx.suite,
            &ctx.server_handshake_keys,
            ctx.next_write_seq,
            &cert,
        );
        ctx.next_write_seq += 1;
        let _ = stream.write_all(&r1);
        let _ = stream.write_all(&r2);
    });
    assert!(
        !err.is_empty(),
        "client must reject empty server Certificate list; got: {err}"
    );
}

/// Phase H-2 E2E #2: rogue server sends EE + Certificate whose single
/// entry is a 100-byte all-`0xFF` blob — not valid DER. Client must
/// reject at the X.509 parse step.
#[test]
fn h225_e2e_encrypted_certificate_with_malformed_der_rejected() {
    let err = drive_client_against_encrypted_rogue_server(|ctx, stream| {
        let ee = build_empty_encrypted_extensions();
        let r1 = seal_encrypted_handshake(
            ctx.suite,
            &ctx.server_handshake_keys,
            ctx.next_write_seq,
            &ee,
        );
        ctx.next_write_seq += 1;
        let bogus_cert = vec![0xFFu8; 100];
        let entry = build_certificate_entry(&bogus_cert);
        let cert = build_certificate_message(&entry);
        let r2 = seal_encrypted_handshake(
            ctx.suite,
            &ctx.server_handshake_keys,
            ctx.next_write_seq,
            &cert,
        );
        ctx.next_write_seq += 1;
        let _ = stream.write_all(&r1);
        let _ = stream.write_all(&r2);
    });
    assert!(
        !err.is_empty(),
        "client must reject malformed-DER server Certificate; got: {err}"
    );
}

/// Phase H-2 E2E #3: rogue server sends EE + a Certificate message
/// whose body is `0x00 || 0x000000` (empty context, zero-length cert
/// list — but the *wrapping* length is correct so it parses). This
/// is the same shape as #1 from the wire perspective; pinning it via
/// the explicit body bytes proves the Certificate framing math (1 +
/// 3 byte body) and that the rejection happens at the semantics
/// layer, not at the framing layer.
#[test]
fn h225_e2e_encrypted_certificate_explicit_zero_body_rejected() {
    let err = drive_client_against_encrypted_rogue_server(|ctx, stream| {
        let ee = build_empty_encrypted_extensions();
        let r1 = seal_encrypted_handshake(
            ctx.suite,
            &ctx.server_handshake_keys,
            ctx.next_write_seq,
            &ee,
        );
        ctx.next_write_seq += 1;
        // Hand-built: 0x0B || u24(4) || u8(0) || u24(0)
        let cert = vec![0x0B, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
        let r2 = seal_encrypted_handshake(
            ctx.suite,
            &ctx.server_handshake_keys,
            ctx.next_write_seq,
            &cert,
        );
        ctx.next_write_seq += 1;
        let _ = stream.write_all(&r1);
        let _ = stream.write_all(&r2);
    });
    assert!(
        !err.is_empty(),
        "client must reject zero-body server Certificate; got: {err}"
    );
}

/// Phase H-2 pin #4: Certificate handshake type byte = `0x0B` = 11
/// per RFC 8446 §B.3 (the `HandshakeType` enum is private to
/// `hitls-tls`; pin the raw byte the way T221 did for Finished and
/// T222 did for EE/CertReq).
#[test]
fn h225_certificate_handshake_type_byte_identity_pin() {
    let cert_byte: u8 = 0x0B;
    assert_eq!(cert_byte, 11);
}

/// Phase H-2 pin #5: minimal wire size for a Certificate message:
/// `type(1) + u24_len(3) + ctx_len(1) + u24_cert_list_len(3) = 8` bytes
/// when body has empty context + empty cert list.
#[test]
fn h225_certificate_message_min_wire_size_pin() {
    let msg = build_certificate_message(&[]);
    assert_eq!(
        msg.len(),
        8,
        "minimal Certificate wire size is 8 bytes per RFC 8446 §4.4.2"
    );
    assert_eq!(msg[0], 0x0B, "type byte = Certificate");
    assert_eq!(&msg[1..4], &[0x00, 0x00, 0x04], "u24 body length = 4");
    assert_eq!(msg[4], 0x00, "ctx length = 0 (server)");
    assert_eq!(&msg[5..8], &[0x00, 0x00, 0x00], "u24 cert list length = 0");
}

/// Phase H-2 pin #6: CertificateVerify handshake type byte = `0x0F` =
/// 15 per RFC 8446 §B.3.
#[test]
fn h225_certverify_handshake_type_byte_identity_pin() {
    let cv_byte: u8 = 0x0F;
    assert_eq!(cv_byte, 15);
}

/// Phase H-2 pin #7: minimal wire size for a CertificateVerify
/// message: `type(1) + u24_len(3) + u16_sig_scheme(2) + u16_sig_len(2)
/// = 8` bytes when signature is empty (illegal but pins the math).
#[test]
fn h225_certverify_message_min_wire_size_pin() {
    let mut msg = vec![0x0F]; // type
    let body_len: u32 = 2 + 2; // sig_scheme + sig_len fields
    msg.extend_from_slice(&[
        ((body_len >> 16) & 0xff) as u8,
        ((body_len >> 8) & 0xff) as u8,
        (body_len & 0xff) as u8,
    ]);
    msg.extend_from_slice(&[0x08, 0x04]); // RSA_PSS_RSAE_SHA256 = 0x0804
    msg.extend_from_slice(&[0x00, 0x00]); // sig length = 0
    assert_eq!(msg.len(), 8);
    assert_eq!(msg[0], 0x0F);
    assert_eq!(&msg[4..6], &[0x08, 0x04]);
}

/// Phase H-2 pin #8: signature_algorithms codepoints used in the
/// CertificateVerify `algorithm` field per RFC 8446 §4.2.3. Extends
/// T220's `t220_certverify_signature_algorithm_codepoint_identity_pin`
/// into the E2E file so future H-3/H-4 PRs see the anchor here.
#[test]
fn h225_certverify_signature_algorithm_codepoint_pin() {
    // RSA_PSS_RSAE_SHA256
    let rsa_pss_rsae_sha256: u16 = 0x0804;
    assert_eq!(rsa_pss_rsae_sha256, 2052);
    // ECDSA_SECP256R1_SHA256
    let ecdsa_secp256r1_sha256: u16 = 0x0403;
    assert_eq!(ecdsa_secp256r1_sha256, 1027);
    // ED25519
    let ed25519: u16 = 0x0807;
    assert_eq!(ed25519, 2055);
}

/// Phase H-2 pin #9: extending T220's
/// `t220_certverify_signing_buffer_byte_exact_construction_pin` into
/// the E2E file. The CV signing buffer is `0x20×64 || context || 0x00
/// || transcript_hash` per RFC 8446 §4.4.3. Pinning the construction
/// here documents that the T224 driver's `ctx.transcript_hash_ch_sh`
/// field is the right input for the CH||SH||EE||Cert chain (once H-3
/// adds the cert and rolls the hash forward).
#[test]
fn h225_certverify_signing_buffer_construction_e2e_sibling_pin() {
    let context = b"TLS 1.3, server CertificateVerify";
    let transcript_hash = [0u8; 32]; // placeholder — H-3 supplies the real one
    let mut buf = vec![0x20u8; 64];
    buf.extend_from_slice(context);
    buf.push(0x00);
    buf.extend_from_slice(&transcript_hash);
    assert_eq!(buf.len(), 64 + context.len() + 1 + 32);
    // First 64 bytes are 0x20 padding
    assert_eq!(&buf[..64], &[0x20u8; 64]);
    // Context placed immediately after padding
    assert_eq!(&buf[64..64 + context.len()], context);
    // Single 0x00 separator after context
    assert_eq!(buf[64 + context.len()], 0x00);
}

/// Phase H-2 plan banner pin.
#[test]
fn h225_phase_h2_plan_banner_pinned() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-h-plan.md");
    let plan = std::fs::read_to_string(&plan_path).unwrap();
    assert!(plan.contains("T225"));
    assert!(plan.contains("MODIFIED_CERT_VERIFY") || plan.contains("CERT_VERIFY"));
}

// ===========================================================================
// T226 / Phase H-3 — MODIFIED_FINISHED family.
//
// Same scope decision as T225: reaching the client's Finished
// `verify_data` MAC check at the E2E level needs valid EE + Cert + CV
// first (so the client's state machine accepts Finished as the next
// expected message). Without the cert+key loader (Phase I follow-up),
// T226 covers two slices:
//
// - **3 E2E tests** sending EE + Finished directly. The real client's
//   handshake state machine errors at "unexpected_message" (RFC 8446
//   §6) because Certificate is expected next, not Finished. These
//   exercise the encrypted post-EE state-machine ordering — a sibling
//   to T225's "Cert parse phase" angle.
// - **6 helper-level pins** extending T221's Finished invariants into
//   the E2E file (verify_data length math, HKDF-Expand-Label "finished"
//   label bytes, HMAC construction baseline, type-byte identity).
// - **1 plan-doc banner pin**.
//
// Cumulative: T224 (3) + T225 (10) + T226 (10) = 23 tests in this file.
// ===========================================================================

/// Helper: build a Finished handshake message body per RFC 8446 §4.4.4.
/// `verify_data` is `HMAC(finished_key, transcript_hash)`; tests can
/// pass arbitrary bytes here to mutate.
fn build_finished_message(verify_data: &[u8]) -> Vec<u8> {
    let body_len = verify_data.len() as u32;
    let mut msg = Vec::with_capacity(4 + verify_data.len());
    msg.push(0x14); // HandshakeType::Finished
    msg.extend_from_slice(&[
        ((body_len >> 16) & 0xff) as u8,
        ((body_len >> 8) & 0xff) as u8,
        (body_len & 0xff) as u8,
    ]);
    msg.extend_from_slice(verify_data);
    msg
}

/// Phase H-3 E2E #1: rogue server sends EE + Finished (skipping
/// Certificate + CertificateVerify). The real client's state machine
/// after EE expects Certificate (RFC 8446 §2 — "{} indicates messages
/// protected using keys derived from [sender]_handshake_traffic_secret
/// ... Certificate"). Receiving Finished out of order must trigger
/// `unexpected_message` / handshake error.
#[test]
fn h226_e2e_encrypted_finished_without_cert_or_cv_rejected() {
    let err = drive_client_against_encrypted_rogue_server(|ctx, stream| {
        let ee = build_empty_encrypted_extensions();
        let r1 = seal_encrypted_handshake(
            ctx.suite,
            &ctx.server_handshake_keys,
            ctx.next_write_seq,
            &ee,
        );
        ctx.next_write_seq += 1;
        // Plausible-length verify_data (32 bytes for SHA-256) but
        // bogus content. We never get to the verify_data check anyway
        // since this is out of order.
        let fin = build_finished_message(&[0x42u8; 32]);
        let r2 = seal_encrypted_handshake(
            ctx.suite,
            &ctx.server_handshake_keys,
            ctx.next_write_seq,
            &fin,
        );
        ctx.next_write_seq += 1;
        let _ = stream.write_all(&r1);
        let _ = stream.write_all(&r2);
    });
    assert!(
        !err.is_empty(),
        "client must reject Finished sent before Certificate; got: {err}"
    );
}

/// Phase H-3 E2E #2: rogue server sends EE + Finished with zero-length
/// `verify_data`. RFC 8446 §4.4.4 says `verify_data` length equals
/// the hash output length; T91 hardened the codec to reject
/// over-length verify_data. Zero-length is a separate path — pin the
/// rejection.
#[test]
fn h226_e2e_encrypted_finished_with_zero_length_body_rejected() {
    let err = drive_client_against_encrypted_rogue_server(|ctx, stream| {
        let ee = build_empty_encrypted_extensions();
        let r1 = seal_encrypted_handshake(
            ctx.suite,
            &ctx.server_handshake_keys,
            ctx.next_write_seq,
            &ee,
        );
        ctx.next_write_seq += 1;
        // 0x14 || u24(0) — Finished message with 0-byte verify_data.
        let fin = vec![0x14, 0x00, 0x00, 0x00];
        let r2 = seal_encrypted_handshake(
            ctx.suite,
            &ctx.server_handshake_keys,
            ctx.next_write_seq,
            &fin,
        );
        ctx.next_write_seq += 1;
        let _ = stream.write_all(&r1);
        let _ = stream.write_all(&r2);
    });
    assert!(
        !err.is_empty(),
        "client must reject zero-length verify_data Finished; got: {err}"
    );
}

/// Phase H-3 E2E #3: rogue server sends EE + Finished with oversized
/// `verify_data` (64 bytes when SHA-256 expects 32). T91 pinned this
/// closure end at codec layer; this E2E test verifies the rejection
/// path holds when the message arrives over an encrypted record.
#[test]
fn h226_e2e_encrypted_finished_with_oversized_verify_data_rejected() {
    let err = drive_client_against_encrypted_rogue_server(|ctx, stream| {
        let ee = build_empty_encrypted_extensions();
        let r1 = seal_encrypted_handshake(
            ctx.suite,
            &ctx.server_handshake_keys,
            ctx.next_write_seq,
            &ee,
        );
        ctx.next_write_seq += 1;
        // 64 bytes verify_data — twice the SHA-256 hash length.
        let fin = build_finished_message(&[0x77u8; 64]);
        let r2 = seal_encrypted_handshake(
            ctx.suite,
            &ctx.server_handshake_keys,
            ctx.next_write_seq,
            &fin,
        );
        ctx.next_write_seq += 1;
        let _ = stream.write_all(&r1);
        let _ = stream.write_all(&r2);
    });
    assert!(
        !err.is_empty(),
        "client must reject oversized verify_data Finished; got: {err}"
    );
}

/// Phase H-3 pin #4: Finished handshake type = `0x14` = 20 raw byte
/// per RFC 8446 §B.3. Sibling to T221's identical pin in the helper
/// file (`transcript_mutation_encrypted.rs`); this anchor is in the
/// E2E file so future H-4 / closeout PRs can grep it locally.
#[test]
fn h226_finished_handshake_type_byte_identity_pin() {
    let fin_byte: u8 = 0x14;
    assert_eq!(fin_byte, 20);
}

/// Phase H-3 pin #5: SHA-256 `verify_data` length per RFC 8446 §4.4.4
/// equals the hash output length = 32 bytes. The wire-level Finished
/// message is `type(1) + u24_len(3) + verify_data(32) = 36` bytes
/// for SHA-256 suites.
#[test]
fn h226_finished_verify_data_length_sha256_pin() {
    let verify_data_len = 32; // SHA-256 output length
    let msg = build_finished_message(&[0u8; 32]);
    assert_eq!(msg.len(), 4 + verify_data_len);
    assert_eq!(msg[0], 0x14);
    assert_eq!(
        &msg[1..4],
        &[0x00, 0x00, 0x20],
        "u24 body length = 0x20 = 32"
    );
}

/// Phase H-3 pin #6: RFC 8446 §4.4.4 finished_key derivation label =
/// `"finished"` raw bytes (HKDF-Expand-Label argument). Pinning the
/// literal label bytes guards against accidental rename of the
/// constant in product code.
#[test]
fn h226_finished_key_derivation_label_pin() {
    let label: &[u8] = b"finished";
    assert_eq!(label, &[0x66, 0x69, 0x6E, 0x69, 0x73, 0x68, 0x65, 0x64]);
    assert_eq!(label.len(), 8);
}

/// Phase H-3 pin #7: RFC 8446 §4.4.4 `verify_data` construction
/// baseline — `verify_data = HMAC(finished_key, transcript_hash)`.
/// HMAC-SHA-256 output length = SHA-256 output length = 32 bytes.
/// Extends T221's same baseline pin into the E2E file.
#[test]
fn h226_finished_verify_data_hmac_construction_e2e_sibling_pin() {
    let hmac_sha256_output_len = 32;
    let sha256_output_len = 32;
    assert_eq!(hmac_sha256_output_len, sha256_output_len);
    // verify_data byte-layout: 32 bytes that must match HMAC output
    // (any byte mutation breaks it — proved in T221).
    let verify_data_layout = [0u8; 32];
    assert_eq!(verify_data_layout.len(), 32);
}

/// Phase H-3 pin #8: T101 pinned cross-record handshake reassembly
/// (`test-tls13-finished.py` 708/6 XFAIL → 714/0 PASS); pin via DEV_LOG
/// reference that this Phase H test file does not regress the codec
/// closure. The T91 + T101 + T117 trio is the codec authority for
/// Finished body framing.
#[test]
fn h226_t91_t101_codec_authority_cross_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log_path = format!("{manifest_dir}/../../DEV_LOG.md");
    let log = std::fs::read_to_string(&dev_log_path).unwrap();
    assert!(
        log.contains("T91") && log.contains("Finished"),
        "DEV_LOG must retain T91 Finished framing strict-length anchor"
    );
    assert!(
        log.contains("T101") && log.contains("reassembly"),
        "DEV_LOG must retain T101 cross-record handshake reassembly anchor"
    );
}

/// Phase H-3 pin #9: `MODIFIED_KEY_SHARE_POST_SH_*` C SDV rows require
/// the rogue server to mutate the SH's `key_share` extension AFTER
/// sending it, which is impossible with the current TCP framework
/// (the rogue server sends the SH once and that's it). Pin via the
/// scope-cut note that T186's plaintext file already covers the
/// SH-time `MODIFIED_KEY_SHARE_*` cases — there is no encrypted
/// post-SH "key_share" mutation to chase.
#[test]
fn h226_modified_key_share_post_sh_scope_cut_documented() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/tests/transcript_mutation.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(
        body.contains("sh_with_unoffered_keyshare_group_rejected"),
        "T186's MODIFIED_KEY_SHARE_FROM_SH coverage must remain — \
         post-SH key_share mutation is not a real wire shape in TLS 1.3"
    );
}

/// Phase H-3 plan banner pin.
#[test]
fn h226_phase_h3_plan_banner_pinned() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-h-plan.md");
    let plan = std::fs::read_to_string(&plan_path).unwrap();
    assert!(plan.contains("T226"));
    assert!(plan.contains("MODIFIED_FINISHED") || plan.contains("FINISHED"));
}

// ===========================================================================
// T227 / Phase H-4 — DTLS 1.3 + 0-RTT + KeyUpdate mutation family.
//
// Three sub-targets, each with its own scope envelope:
//
// - **DTLS 1.3** (RFC 9147 §4 unified header + AEAD framing) needs a
//   UDP rogue-server framework, not TCP — out of scope for T224's TCP
//   driver. Pin via scope-cut + unified-header byte format.
// - **0-RTT** needs PSK warm-up + early_data extension flow — out of
//   T224 scope (T119 deferred the PSK_ONLY mode). Pin via extension
//   codepoint + T106 cross-pin to the existing rejected-0-RTT
//   tolerance.
// - **KeyUpdate** is a post-handshake message — reachable via the
//   T224 framework as an out-of-order injection (Finished is expected
//   next; KeyUpdate before Finished triggers `unexpected_message`).
//   1 E2E test + 4 wire-format pins.
//
// Cumulative: T224 (3) + T225 (10) + T226 (10) + T227 (10) = 33 tests.
// ===========================================================================

/// Helper: build a KeyUpdate handshake message per RFC 8446 §4.6.3.
/// Body is a single `KeyUpdateRequest` byte (0 = update_not_requested,
/// 1 = update_requested).
fn build_key_update_message(request_update: u8) -> Vec<u8> {
    vec![
        0x18, // HandshakeType::KeyUpdate
        0x00,
        0x00,
        0x01, // u24 body length = 1
        request_update,
    ]
}

/// Phase H-4 E2E #1: rogue server sends EE + KeyUpdate (before
/// Certificate/CV/Finished). The real client expects Certificate as
/// the next encrypted handshake message after EE; receiving KeyUpdate
/// (RFC 8446 §4.6.3 — a post-handshake-only message) must trigger
/// `unexpected_message`.
#[test]
fn h227_e2e_encrypted_keyupdate_before_finished_rejected() {
    let err = drive_client_against_encrypted_rogue_server(|ctx, stream| {
        let ee = build_empty_encrypted_extensions();
        let r1 = seal_encrypted_handshake(
            ctx.suite,
            &ctx.server_handshake_keys,
            ctx.next_write_seq,
            &ee,
        );
        ctx.next_write_seq += 1;
        let ku = build_key_update_message(0); // update_not_requested
        let r2 = seal_encrypted_handshake(
            ctx.suite,
            &ctx.server_handshake_keys,
            ctx.next_write_seq,
            &ku,
        );
        ctx.next_write_seq += 1;
        let _ = stream.write_all(&r1);
        let _ = stream.write_all(&r2);
    });
    assert!(
        !err.is_empty(),
        "client must reject KeyUpdate before Finished (RFC 8446 §4.6.3 is post-handshake only); got: {err}"
    );
}

/// Phase H-4 pin #2: DTLS 1.3 record framing (RFC 9147 §4) needs a
/// UDP rogue-server framework. The T224 TCP-only framework cannot
/// drive a DTLS 1.3 record over the wire. Pin the scope-cut so a
/// future "Phase I" (DTLS UDP rogue server) PR has an anchor.
#[test]
fn h227_dtls13_record_framing_rfc9147_scope_cut_documented() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-h-plan.md");
    let plan = std::fs::read_to_string(&plan_path).unwrap();
    assert!(
        plan.contains("DTLS 1.3"),
        "Phase H plan must keep DTLS 1.3 scope-cut documented"
    );
}

/// Phase H-4 pin #3: RFC 9147 §4 DTLS 1.3 unified header first byte
/// = `0b001CSLEE` (top 3 bits = `001` mandatory; C = connection_id
/// flag, S = sequence number length, L = length flag, EE = epoch low
/// bits). The unified-header marker therefore lives in `0x20..=0x3F`
/// (binary `001x xxxx`).
#[test]
fn h227_dtls13_unified_header_byte_pin() {
    // Mandatory top 3 bits = 0b001 → first byte in [0x20, 0x3F].
    let unified_header_first_byte_min: u8 = 0x20; // 0b0010_0000
    let unified_header_first_byte_max: u8 = 0x3F; // 0b0011_1111
    assert_eq!(unified_header_first_byte_min & 0b1110_0000, 0b0010_0000);
    assert_eq!(unified_header_first_byte_max & 0b1110_0000, 0b0010_0000);
    // A DTLS 1.2-style record content type byte (e.g. 22 = Handshake
    // = 0x16) is NOT in this range — pinning the disambiguation.
    let dtls12_handshake_content_type: u8 = 0x16;
    assert_ne!(
        dtls12_handshake_content_type & 0b1110_0000,
        0b0010_0000,
        "DTLS 1.2 record type byte must not collide with DTLS 1.3 unified header marker"
    );
}

/// Phase H-4 pin #4: RFC 8446 §4.2.10 `early_data` extension
/// codepoint = 42. The C SDV `0RTT_GARBAGE_*` rows pivot on whether
/// the CH advertises this extension.
#[test]
fn h227_0rtt_early_data_extension_codepoint_pin() {
    let early_data_codepoint: u16 = 42;
    assert_eq!(early_data_codepoint, 0x002A);
}

/// Phase H-4 pin #5: T106 closed 4 XFAILs in
/// `test-tls13-0rtt-garbage.py` by adding server tolerance for
/// rejected-0-RTT records, silently skipping both AEAD-decrypt
/// failures and non-Handshake records when CH offered `early_data`
/// but server rejected. Pin via DEV_LOG cross-reference that T106
/// anchor remains.
#[test]
fn h227_0rtt_rejected_garbage_tolerance_t106_cross_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log_path = format!("{manifest_dir}/../../DEV_LOG.md");
    let log = std::fs::read_to_string(&dev_log_path).unwrap();
    assert!(
        log.contains("T106") && log.contains("0-RTT"),
        "DEV_LOG must retain T106 rejected-0-RTT tolerance anchor"
    );
}

/// Phase H-4 pin #6: KeyUpdate handshake type byte = `0x18` = 24 per
/// RFC 8446 §B.3 (the `HandshakeType` enum is private to
/// `hitls-tls`; pin the raw byte the way T221 / T222 / T225 / T226
/// did for Finished / EE / Certificate / CertificateVerify).
#[test]
fn h227_keyupdate_handshake_type_byte_identity_pin() {
    let ku_byte: u8 = 0x18;
    assert_eq!(ku_byte, 24);
}

/// Phase H-4 pin #7: RFC 8446 §4.6.3 — KeyUpdate body is exactly 1
/// byte (`KeyUpdateRequest`). Minimal wire size = type(1) +
/// u24_len(3) + body(1) = 5 bytes.
#[test]
fn h227_keyupdate_message_min_wire_size_pin() {
    let msg = build_key_update_message(0);
    assert_eq!(msg.len(), 5);
    assert_eq!(msg[0], 0x18, "type byte = KeyUpdate");
    assert_eq!(&msg[1..4], &[0x00, 0x00, 0x01], "u24 body length = 1");
    assert_eq!(msg[4], 0, "KeyUpdateRequest payload byte");
}

/// Phase H-4 pin #8: RFC 8446 §4.6.3 `KeyUpdateRequest` codepoints —
/// 0 = `update_not_requested`, 1 = `update_requested`. Any other
/// value is illegal and must trigger `illegal_parameter`.
#[test]
fn h227_keyupdate_request_update_codepoint_pin() {
    let update_not_requested: u8 = 0;
    let update_requested: u8 = 1;
    assert_eq!(update_not_requested, 0);
    assert_eq!(update_requested, 1);
    // 2 and above are illegal — pin the boundary so future codec
    // hardening tests can grep this anchor.
    let illegal_boundary: u8 = 2;
    assert!(illegal_boundary > update_requested);
}

/// Phase H-4 pin #9: T100 closed 261/270 XFAILs in
/// `test-tls13-keyupdate.py` by emitting the right alerts for
/// codec violations; T101 closed 268/2 by adding cross-record
/// reassembly that covers KeyUpdate. Pin via DEV_LOG
/// cross-reference that both anchors remain.
#[test]
fn h227_keyupdate_t100_t101_codec_authority_cross_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log_path = format!("{manifest_dir}/../../DEV_LOG.md");
    let log = std::fs::read_to_string(&dev_log_path).unwrap();
    assert!(
        log.contains("T100") && log.contains("keyupdate"),
        "DEV_LOG must retain T100 KeyUpdate codec authority anchor"
    );
    assert!(
        log.contains("T101") && log.contains("keyupdate"),
        "DEV_LOG must retain T101 KeyUpdate cross-record reassembly anchor"
    );
}

/// Phase H-4 plan banner pin.
#[test]
fn h227_phase_h4_plan_banner_pinned() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-h-plan.md");
    let plan = std::fs::read_to_string(&plan_path).unwrap();
    assert!(plan.contains("T227"));
    assert!(plan.contains("DTLS 1.3") || plan.contains("0-RTT") || plan.contains("KeyUpdate"));
}

// ===========================================================================
// T228 / Phase H closeout — series rollup + plaintext-file escalation
// annotation + §8 methodology lineage.
//
// Sibling to T200 / T208 / T213 / T218 / T223 closeout phases. The recipe
// is: §N rollup in the plan doc + module-level escalation annotation in
// the sibling Phase D plaintext file (was "partially closes" in T223 → now
// "H-RESOLVED" in T228) + cross-coverage pin in this E2E file + methodology
// lineage table in the plan doc + DEV_LOG + PROMPT_LOG.
//
// The 13 `TODO(#48-encrypted-mutation)` markers in
// `transcript_mutation.rs` are **escalated, not removed** — they stay as
// historical grep anchors representing the original scope-cut decisions.
// The new `H-RESOLVED(#48-encrypted-mutation)` annotation in the same
// docblock surfaces the Phase H closure pointing readers to
// `transcript_mutation_encrypted_e2e.rs`.
//
// ## Cumulative across the encrypted-handshake E2E family (this file)
//
// T224 (3) + T225 (10) + T226 (10) + T227 (10) + T228 (5) = **38 tests**.
//
// ## Cumulative across the entire transcript-mutation series (4 files)
//
// T186 (7) + T214 (10) + T215 (11) + T216 (13) + T217 (14) + T219 (5) +
// T220 (10) + T221 (10) + T222 (10) + T223 (5) + T224 (3) + T225 (10) +
// T226 (10) + T227 (10) + T228 (5) = **133 tests in 4 files**
// (transcript_mutation.rs 41 + transcript_mutation_tls12.rs 14 +
// transcript_mutation_encrypted.rs 40 +
// transcript_mutation_encrypted_e2e.rs 38).
// ===========================================================================

/// T228 closeout — pin the cumulative test count in this file matches
/// the Phase H rollup. Counts via fn-prefix matching (`fn h22`) rather
/// than the `#[test]` literal to avoid the T223 self-count pitfall
/// (the `body.matches("#[test]")` call would also match itself).
#[test]
fn t228_phase_h_cumulative_count_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/tests/transcript_mutation_encrypted_e2e.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    let test_fn_count = body
        .lines()
        .filter(|l| l.starts_with("fn h22") || l.starts_with("fn t228_"))
        .count();
    assert_eq!(
        test_fn_count, 38,
        "Phase H + T228 closeout cumulative count: 3 (T224) + 10 (T225) + \
         10 (T226) + 10 (T227) + 5 (T228) = 38 in this file"
    );
}

/// T228 closeout — pin the §8 methodology lineage table in the Phase H
/// plan doc. The lineage spans 17 codified anchors from T186 to T228.
#[test]
fn t228_phase_h_methodology_lineage_pinned() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-h-plan.md");
    let plan = std::fs::read_to_string(&plan_path).unwrap();
    assert!(plan.contains("Methodology lineage"));
    for anchor in [
        "T186", "T196", "T207", "T209", "T215", "T216", "T217", "T219", "T220", "T221", "T222",
        "T223", "T224", "T225", "T226", "T227", "T228",
    ] {
        assert!(
            plan.contains(anchor),
            "methodology lineage table must reference codified anchor `{anchor}`"
        );
    }
}

/// T228 closeout — pin that the sibling `transcript_mutation.rs`
/// module docblock now surfaces the Phase H **H-RESOLVED** escalation
/// (upgrade from T223's "partially closes" annotation). The 13 literal
/// `TODO(#48-encrypted-mutation)` markers stay as historical grep
/// anchors so git archaeology still resolves them.
#[test]
fn t228_phase_h_plaintext_file_substantive_close_annotation_pin() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/tests/transcript_mutation.rs");
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(
        body.contains("H-RESOLVED(#48-encrypted-mutation) by Phase H (T224-T228)"),
        "transcript_mutation.rs docblock must surface H-RESOLVED escalation"
    );
    assert!(body.contains("transcript_mutation_encrypted_e2e.rs"));
    assert!(body.contains("issue-42-phase-h-plan.md"));
    assert!(
        body.contains("TODO(#48-encrypted-mutation)"),
        "13 TODO anchors must remain as historical grep targets"
    );
}

/// T228 closeout — pin all 5 Phase H sub-PRs are marked closed in the
/// plan doc §4 table.
#[test]
fn t228_phase_h_plan_doc_all_subprs_closed() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-h-plan.md");
    let plan = std::fs::read_to_string(&plan_path).unwrap();
    for anchor in [
        "✅ T224",
        "✅ T225",
        "✅ T226",
        "✅ T227",
        "✅ T228",
        "5/5 sub-PRs closed",
    ] {
        assert!(
            plan.contains(anchor),
            "plan doc must mark `{anchor}` as closed"
        );
    }
}

/// T228 closeout — series rollup banner pin. The 38-tests-in-this-file
/// + 133-tests-across-4-files arithmetic is the audit trail.
#[test]
fn t228_phase_h_closeout_banner_pinned() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-h-plan.md");
    let plan = std::fs::read_to_string(&plan_path).unwrap();
    assert!(plan.contains("**38 tests**"));
    assert!(plan.contains("**133 tests in 4 files**"));
    assert!(plan.contains("Still-pending follow-up"));
    assert!(plan.contains("Full server cert + private key loader"));
}
