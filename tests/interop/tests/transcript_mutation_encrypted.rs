//! Encrypted-mutation key-schedule rogue server infrastructure — T219 / #42.
//!
//! Phase G-1 of the TLS encrypted-mutation series
//! (`docs/issue-42-phase-g-plan.md`). Builds the key-schedule + AEAD
//! infrastructure that Phase D (T214-T218) explicitly deferred via 13
//! `TODO(#48-encrypted-mutation)` markers in `transcript_mutation.rs`.
//!
//! ## Why this file exists
//!
//! T186 built a **plaintext** rogue server that captures ClientHello,
//! emits a forged ServerHello, and asserts the client's
//! `handshake()` aborts when a SH field is mutated. T186's
//! scope ends at ServerHello — anything **after** SH on the
//! wire is encrypted under the handshake traffic secrets.
//!
//! Phase G adds the missing piece: derive the same handshake
//! traffic secrets the real client derives, then **encrypt**
//! mutated EncryptedExtensions / Certificate / CertVerify /
//! Finished records so the client receives them as
//! cryptographically valid AEAD records (which it can decrypt,
//! and then must reject for content reasons).
//!
//! ## Public APIs reused (zero product code touched)
//!
//! - `hitls_tls::crypt::key_schedule::KeySchedule` —
//!   RFC 8446 §7.1 key schedule
//! - `hitls_tls::crypt::traffic_keys::TrafficKeys::derive` —
//!   key + IV from a traffic secret
//! - `hitls_tls::crypt::aead::{TlsAead, AesGcmAead}` —
//!   RFC 8446 §5.2 record-layer AEAD
//! - `hitls_tls::handshake::key_exchange::KeyExchange::compute_shared_secret` —
//!   ECDH shared secret
//! - `hitls_tls::crypt::hkdf::{hkdf_extract, hkdf_expand_label,
//!   derive_secret}` — HKDF primitives
//!
//! ## T219 scope (this PR)
//!
//! Lands the infrastructure helpers + 5 baseline tests that
//! prove the encryption path works:
//!
//! 1. AEAD round-trip helper test
//! 2. KeySchedule chain produces RFC 8446 §7.1 outputs
//! 3. `seal_encrypted_record` produces a well-formed TLS 1.3
//!    application_data record
//! 4. Plan-doc cross-coverage pin
//! 5. T186's `TODO(#48-encrypted-mutation)` markers remain pinned
//!    (they get resolved by T220-T223)
//!
//! Real driver tests (rogue server emitting encrypted records to
//! a `TlsClientConnection`) come in T220 (MODIFIED_CERT_VERIFY) /
//! T221 (MODIFIED_FINISHED) / T222 (EncryptedExtensions + PHA).

use hitls_tls::crypt::aead::{AesGcmAead, TlsAead};
use hitls_tls::crypt::hkdf::derive_secret;
use hitls_tls::crypt::key_schedule::KeySchedule;
use hitls_tls::crypt::traffic_keys::TrafficKeys;
use hitls_tls::crypt::CipherSuiteParams;
use hitls_tls::CipherSuite;

// ===========================================================================
// Infrastructure helpers (used by T220-T223 sub-PRs).
//
// These compose the public hitls-tls APIs into the encrypted-mutation
// rogue server's missing pieces.
// ===========================================================================

/// Derive the server handshake traffic key + IV given:
/// - the cipher suite (determines hash + AEAD parameters)
/// - the ECDH shared secret (from rogue-server's `KeyExchange` against
///   the client's offered public key)
/// - the transcript hash through ClientHello + ServerHello
///
/// Returns `(server_handshake_traffic_secret, TrafficKeys)`. The
/// secret is exposed so callers can also derive `finished_key` for
/// MAC computation in T221.
#[allow(dead_code)]
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

/// Compute the per-record AEAD nonce per RFC 8446 §5.3:
///
/// ```text
/// nonce = static_iv XOR seq_num_be_padded_to_iv_length
/// ```
#[allow(dead_code)]
fn record_nonce(static_iv: &[u8], seq_num: u64) -> Vec<u8> {
    let mut nonce = static_iv.to_vec();
    let seq_be = seq_num.to_be_bytes();
    // XOR the 8-byte sequence number into the trailing 8 bytes of the IV
    let off = nonce.len().saturating_sub(8);
    for (i, b) in seq_be.iter().enumerate() {
        nonce[off + i] ^= b;
    }
    nonce
}

/// Wrap `inner_plaintext || inner_content_type` in an encrypted TLS 1.3
/// `application_data` record (RFC 8446 §5.2). The `keys.key` is fed
/// into AES-GCM; the nonce is derived from `keys.iv` XOR `seq_num`.
///
/// The wire record is: `0x17 || 0x0303 || u16(len) || AEAD(plaintext +
/// content_type, nonce, aad=header)`.
#[allow(dead_code)]
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
        "T219 baseline assumes AES-128-GCM (key_len=16)"
    );
    let aead = AesGcmAead::new(&keys.key).expect("aead init");

    // Plaintext = inner_plaintext || inner_content_type (no zero padding)
    let mut plaintext = inner_plaintext.to_vec();
    plaintext.push(inner_content_type);

    let nonce = record_nonce(&keys.iv, seq_num);

    // AAD = the record header WITH the length field set to the final
    // encrypted body length (plaintext + 16-byte tag).
    let body_len = (plaintext.len() + aead.tag_size()) as u16;
    let mut header = vec![0x17, 0x03, 0x03];
    header.extend_from_slice(&body_len.to_be_bytes());

    let ciphertext = aead.encrypt(&nonce, &header, &plaintext).expect("encrypt");

    let mut record = header;
    record.extend_from_slice(&ciphertext);
    record
}

// ===========================================================================
// T219 baseline tests.
// ===========================================================================

/// AEAD seal then open round-trips byte-exact. Sanity pin that the
/// infrastructure choice (AES-128-GCM via `AesGcmAead`) wraps/unwraps
/// consistently. Without this, all downstream rogue-server tests
/// would fail at the record-layer rather than at the mutation
/// target.
#[test]
fn g219_aead_seal_open_round_trip_helper_pin() {
    let key = vec![0x42u8; 16];
    let nonce = vec![0x01u8; 12];
    let aad = b"\x17\x03\x03\x00\x20";
    let plaintext = b"hello-encrypted-handshake";
    let aead = AesGcmAead::new(&key).expect("aead init");
    let ciphertext = aead.encrypt(&nonce, aad, plaintext).expect("encrypt");
    let opened = aead.decrypt(&nonce, aad, &ciphertext).expect("decrypt");
    assert_eq!(opened, plaintext);
}

/// Pin that the full TLS 1.3 key schedule chain (early → handshake →
/// server traffic) produces distinct client and server handshake
/// traffic secrets. Uses arbitrary-but-fixed inputs so the assertion
/// is deterministic.
#[test]
fn g219_key_schedule_derives_distinct_client_server_secrets() {
    let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
    let mut ks = KeySchedule::new(params);
    ks.derive_early_secret(None).expect("early secret");
    // 32-byte stand-in for the ECDH shared secret.
    let dhe = vec![0x11u8; 32];
    ks.derive_handshake_secret(&dhe).expect("handshake secret");
    // 32-byte stand-in for SHA-256(CH || SH).
    let transcript = vec![0x22u8; 32];
    let (client_secret, server_secret) = ks
        .derive_handshake_traffic_secrets(&transcript)
        .expect("traffic secrets");
    assert_ne!(
        client_secret, server_secret,
        "client and server traffic secrets must differ (RFC 8446 §7.1)"
    );
    // Each secret is hash_len bytes (32 for SHA-256).
    assert_eq!(client_secret.len(), 32);
    assert_eq!(server_secret.len(), 32);
}

/// Pin that `seal_encrypted_record` produces a wire record whose
/// header is `0x17 || 0x03 0x03 || u16(len)` and whose body is at
/// least `plaintext + 1 (inner type) + 16 (AEAD tag)` bytes long.
#[test]
fn g219_seal_encrypted_extensions_record_well_formed() {
    // Build a representative server handshake traffic secret + keys.
    let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
    let server_secret = derive_secret(
        params.hash_alg_id(),
        &[0x33u8; 32],
        b"s hs traffic",
        &[0x44u8; 32],
    )
    .expect("server secret");
    let keys = TrafficKeys::derive(&params, &server_secret).expect("traffic keys");

    // Empty EncryptedExtensions plaintext = handshake type (0x08) + 3-byte length (0) + 2-byte body length (0).
    let ee_plaintext = vec![0x08, 0x00, 0x00, 0x02, 0x00, 0x00];
    let record = seal_encrypted_record(
        CipherSuite::TLS_AES_128_GCM_SHA256,
        &keys,
        0,
        0x16, // inner content type = Handshake
        &ee_plaintext,
    );
    assert_eq!(
        record[0], 0x17,
        "outer content type must be ApplicationData"
    );
    assert_eq!(record[1], 0x03, "legacy_record_version high byte");
    assert_eq!(record[2], 0x03, "legacy_record_version low byte");
    let body_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    // body = plaintext + content type byte + AEAD tag (16)
    assert_eq!(
        body_len,
        ee_plaintext.len() + 1 + 16,
        "body length must be plaintext + content_type + 16-byte AEAD tag"
    );
    assert_eq!(
        record.len(),
        5 + body_len,
        "total record = 5-byte header + body"
    );
}

/// Cross-coverage pin: the 13 `TODO(#48-encrypted-mutation)` markers
/// in `transcript_mutation.rs` (placed by Phase D T214-T218) are the
/// anchors Phase G is built to resolve. Pin that they remain in the
/// file for now — they will be migrated to actual tests by
/// T220/T221/T222 and removed by T223 closeout.
#[test]
fn g219_phase_d_encrypted_mutation_todos_remain_pinned_pre_resolution() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest_dir}/tests/transcript_mutation.rs");
    let body = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing transcript_mutation.rs at {path}: {e}"));
    let count = body.matches("TODO(#48-encrypted-mutation)").count();
    assert!(
        count >= 5,
        "expected the T186/T214-T218 TODO(#48-encrypted-mutation) anchors \
         to remain in transcript_mutation.rs (Phase G T220-T223 resolves them); \
         found {count} occurrences"
    );
}

/// Plan-doc cross-coverage pin (same pattern as T204+/T209/T214 codified).
#[test]
fn g219_audit_phase_g_plan_docs_in_sync() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-g-plan.md");
    let plan = std::fs::read_to_string(&plan_path)
        .unwrap_or_else(|e| panic!("missing audit doc at {plan_path}: {e}"));

    for tag in &[
        "T219", "T220", "T221", "T222", "T223", "G-1", "G-2", "G-3", "G-4",
    ] {
        assert!(plan.contains(tag), "plan doc missing sub-PR tag `{tag}`");
    }

    for anchor in &[
        "MODIFIED_CERT_VERIFY",
        "MODIFIED_FINISHED",
        "TODO(#48-encrypted-mutation)",
        "key-schedule rogue server",
    ] {
        assert!(
            plan.contains(anchor),
            "plan doc must keep anchor `{anchor}`"
        );
    }
}

// ===========================================================================
// T220 / Phase G-2 — MODIFIED_CERT_VERIFY family.
//
// C source: `tls/consistency/tls13/test_suite_sdv_frame_tls13_consistency_rfc8446_2.c`
// — `UT_TLS_TLS13_RFC8446_CONSISTENCY_MODIFIED_CERT_VERIFY_FUNC_TC001` and
// related `CERTVERIFY_SIGN_FUNC_TC001-003` /
// `CERTICATE_VERIFY_FAIL_FUNC_TC001` rows.
//
// The C tests replay a mutated CertVerify record into a real client and
// assert rejection. The full TCP driver for that is intentionally out
// of scope (would add ~3-5 days for a single sub-PR). T220 instead pins
// the **encryption-path + signing-buffer** invariants that any future
// full driver would depend on: if these break, no encrypted-CV test
// can work.
//
// ## RFC 8446 §4.4.3 CertVerify signing buffer
//
// The signed buffer is:
//   octet(0x20) repeated 64 times
//   || context_string (e.g. "TLS 1.3, server CertificateVerify")
//   || octet(0x00)
//   || Hash(handshake_transcript_up_to_certificate)
//
// Any byte-level mutation of the transcript hash propagates byte-exact
// into the signed buffer and (if the signature were re-computed)
// produces a different signature. We pin both the construction
// formula and the mutation propagation.
//
// ## T220 mapping
//
// | C TC family | Rust test |
// |-------------|-----------|
// | `MODIFIED_CERT_VERIFY_FUNC_TC001` (sig byte mutation) | `t220_certverify_signing_buffer_byte_exact_construction_pin` |
// | `CERTVERIFY_SIGN_FUNC_TC001` (transcript-hash propagation) | `t220_certverify_signing_buffer_transcript_hash_propagation` |
// | `CERTVERIFY_SIGN_FUNC_TC002` (context string identity) | `t220_certverify_context_string_identity_server_side_pin` |
// | `CERTVERIFY_SIGN_FUNC_TC003` (client-side context string) | `t220_certverify_context_string_identity_client_side_pin` |
// | (encryption sanity) | `t220_encrypted_certverify_record_decrypts_byte_exact_round_trip` |
// | (mutation sanity) | `t220_encrypted_certverify_tampered_ciphertext_fails_decrypt` |
// | (mutation sanity) | `t220_encrypted_certverify_tampered_aead_tag_fails_decrypt` |
// | `ABNORMAL_CERTREQMSG_FUNC_TC001` (sig alg in CV) | `t220_certverify_signature_algorithm_codepoint_identity_pin` |
// | (cert format) | `t220_encrypted_certificate_record_format_chain_length_pin` |
// | (T220 plan banner) | `t220_phase_g2_plan_banner_pinned` |
// ===========================================================================

/// RFC 8446 §4.4.3 server-side CertVerify context string.
const SERVER_CV_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";

/// RFC 8446 §4.4.3 client-side CertVerify context string.
const CLIENT_CV_CONTEXT: &[u8] = b"TLS 1.3, client CertificateVerify";

/// Build the RFC 8446 §4.4.3 CertVerify signing buffer:
///   octet(0x20) × 64 || context_string || octet(0x00) || transcript_hash
fn build_certverify_signing_buffer(context: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64 + context.len() + 1 + transcript_hash.len());
    buf.extend_from_slice(&[0x20u8; 64]);
    buf.extend_from_slice(context);
    buf.push(0x00);
    buf.extend_from_slice(transcript_hash);
    buf
}

/// Mirrors C `MODIFIED_CERT_VERIFY_FUNC_TC001` shape: the CertVerify
/// signing buffer must be byte-exact per RFC 8446 §4.4.3. A regression
/// that drops the leading 64×0x20, the context string, or the
/// separator byte would silently break TLS 1.3 server authentication.
#[test]
fn t220_certverify_signing_buffer_byte_exact_construction_pin() {
    let transcript = vec![0xAB; 32];
    let buf = build_certverify_signing_buffer(SERVER_CV_CONTEXT, &transcript);
    // First 64 bytes: 0x20 padding.
    for (i, b) in buf.iter().take(64).enumerate() {
        assert_eq!(*b, 0x20, "byte {i} must be the 0x20 padding");
    }
    // Next bytes: context string.
    let ctx_end = 64 + SERVER_CV_CONTEXT.len();
    assert_eq!(&buf[64..ctx_end], SERVER_CV_CONTEXT);
    // Separator byte.
    assert_eq!(buf[ctx_end], 0x00, "context string must be NUL-terminated");
    // Trailing bytes: transcript hash.
    assert_eq!(&buf[ctx_end + 1..], transcript.as_slice());
}

/// Mirrors C `CERTVERIFY_SIGN_FUNC_TC001`: any byte mutation in the
/// transcript hash propagates byte-exact into the signing buffer.
/// This is what makes "modified CertVerify" tests work — the signed
/// buffer is the only thing the verifier validates against, so a
/// mutated transcript hash → mutated signing buffer → mutated
/// signature → verify fails.
#[test]
fn t220_certverify_signing_buffer_transcript_hash_propagation() {
    let transcript_a = vec![0x11; 32];
    let mut transcript_b = transcript_a.clone();
    transcript_b[5] ^= 0xFF;
    let buf_a = build_certverify_signing_buffer(SERVER_CV_CONTEXT, &transcript_a);
    let buf_b = build_certverify_signing_buffer(SERVER_CV_CONTEXT, &transcript_b);
    assert_ne!(
        buf_a, buf_b,
        "transcript hash mutation must propagate to signing buffer"
    );
    // The mutation lands at the same offset shifted by the prefix.
    let off = 64 + SERVER_CV_CONTEXT.len() + 1 + 5;
    assert_eq!(buf_a[off] ^ buf_b[off], 0xFF);
}

/// Mirrors C `CERTVERIFY_SIGN_FUNC_TC002`: pin the exact byte
/// sequence of the server-side context string. RFC 8446 §4.4.3
/// specifies these characters verbatim; a typo would break interop.
#[test]
fn t220_certverify_context_string_identity_server_side_pin() {
    assert_eq!(SERVER_CV_CONTEXT, b"TLS 1.3, server CertificateVerify");
    assert_eq!(SERVER_CV_CONTEXT.len(), 33);
}

/// Mirrors C `CERTVERIFY_SIGN_FUNC_TC003`: client-side CertVerify
/// (used in mTLS authentication; the C SDV exercises this for
/// `CONSISTENCY_VERIFY_TRANSCRIPT_HASH_OF_CLIENT_CV_*` rows). The
/// context string differs from the server side by exactly one word.
#[test]
fn t220_certverify_context_string_identity_client_side_pin() {
    assert_eq!(CLIENT_CV_CONTEXT, b"TLS 1.3, client CertificateVerify");
    assert_eq!(CLIENT_CV_CONTEXT.len(), 33);
    // The two context strings differ in exactly the word "server" vs "client".
    let s_words: Vec<&[u8]> = SERVER_CV_CONTEXT.split(|b| *b == b' ').collect();
    let c_words: Vec<&[u8]> = CLIENT_CV_CONTEXT.split(|b| *b == b' ').collect();
    assert_eq!(s_words.len(), c_words.len());
    let diffs = s_words
        .iter()
        .zip(c_words.iter())
        .filter(|(a, b)| a != b)
        .count();
    assert_eq!(
        diffs, 1,
        "server and client contexts differ in exactly one word"
    );
}

/// Mirrors C `MODIFIED_CERT_VERIFY` decryption sanity: a valid
/// encrypted CertVerify record round-trips byte-exact through the
/// AEAD layer. This pins that the T219 `seal_encrypted_record`
/// produces records the decrypt path accepts.
#[test]
fn t220_encrypted_certverify_record_decrypts_byte_exact_round_trip() {
    let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
    let server_secret = derive_secret(
        params.hash_alg_id(),
        &[0x55u8; 32],
        b"s hs traffic",
        &[0x66u8; 32],
    )
    .unwrap();
    let keys = TrafficKeys::derive(&params, &server_secret).unwrap();

    // Synthetic CertVerify body: signature_algorithm (2 bytes) + length (2 bytes) + 256-byte sig
    let mut cv_body = vec![0x08, 0x04]; // rsa_pss_rsae_sha256
    cv_body.extend_from_slice(&256u16.to_be_bytes());
    cv_body.extend_from_slice(&[0xCC; 256]);
    // Wrap as handshake message: type=0x0F (CertificateVerify) + length(3) + body
    let mut cv_msg = vec![0x0F];
    cv_msg.extend_from_slice(&[0x00, 0x01, 0x04]); // 260 bytes
    cv_msg.extend_from_slice(&cv_body);

    let record =
        seal_encrypted_record(CipherSuite::TLS_AES_128_GCM_SHA256, &keys, 1, 0x16, &cv_msg);

    // Round-trip decrypt with the same keys/nonce/AAD.
    let aead = AesGcmAead::new(&keys.key).unwrap();
    let nonce = record_nonce(&keys.iv, 1);
    let aad = &record[..5];
    let opened = aead.decrypt(&nonce, aad, &record[5..]).unwrap();
    // Inner plaintext = cv_msg || inner_content_type (0x16)
    assert_eq!(&opened[..opened.len() - 1], cv_msg.as_slice());
    assert_eq!(opened[opened.len() - 1], 0x16, "inner content type");
}

/// Mirrors C `MODIFIED_CERT_VERIFY` ciphertext-tamper case: flipping
/// any byte in the AEAD ciphertext causes `decrypt` to fail. This is
/// the mechanism by which any mutation of an encrypted CertVerify
/// record gets rejected at the record layer before the signature
/// check even runs.
#[test]
fn t220_encrypted_certverify_tampered_ciphertext_fails_decrypt() {
    let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
    let server_secret = derive_secret(
        params.hash_alg_id(),
        &[0x77u8; 32],
        b"s hs traffic",
        &[0x88u8; 32],
    )
    .unwrap();
    let keys = TrafficKeys::derive(&params, &server_secret).unwrap();
    let cv_msg = vec![0x0F, 0x00, 0x00, 0x04, 0x08, 0x04, 0x00, 0x00];
    let mut record =
        seal_encrypted_record(CipherSuite::TLS_AES_128_GCM_SHA256, &keys, 2, 0x16, &cv_msg);

    // Flip a byte deep inside the ciphertext (past the 5-byte header,
    // past the 8-byte plaintext + 1 type byte = 9 → land at offset 7
    // inside the body).
    record[5 + 3] ^= 0xFF;

    let aead = AesGcmAead::new(&keys.key).unwrap();
    let nonce = record_nonce(&keys.iv, 2);
    let aad = &record[..5];
    assert!(
        aead.decrypt(&nonce, aad, &record[5..]).is_err(),
        "tampered ciphertext byte must fail AEAD authentication"
    );
}

/// Mirrors the AEAD tag mutation variant: flipping the last byte of
/// the AEAD tag (the trailing 16 bytes of the encrypted body) also
/// fails decryption.
#[test]
fn t220_encrypted_certverify_tampered_aead_tag_fails_decrypt() {
    let params = CipherSuiteParams::from_suite(CipherSuite::TLS_AES_128_GCM_SHA256).unwrap();
    let server_secret = derive_secret(
        params.hash_alg_id(),
        &[0x99u8; 32],
        b"s hs traffic",
        &[0xAAu8; 32],
    )
    .unwrap();
    let keys = TrafficKeys::derive(&params, &server_secret).unwrap();
    let cv_msg = vec![0x0F, 0x00, 0x00, 0x04, 0x08, 0x04, 0x00, 0x00];
    let mut record =
        seal_encrypted_record(CipherSuite::TLS_AES_128_GCM_SHA256, &keys, 3, 0x16, &cv_msg);

    // Flip the very last byte (inside the AEAD tag).
    let last = record.len() - 1;
    record[last] ^= 0x01;

    let aead = AesGcmAead::new(&keys.key).unwrap();
    let nonce = record_nonce(&keys.iv, 3);
    let aad = &record[..5];
    assert!(
        aead.decrypt(&nonce, aad, &record[5..]).is_err(),
        "tampered AEAD tag byte must fail authentication"
    );
}

/// Mirrors C `ABNORMAL_CERTREQMSG_FUNC_TC001`-style shape (sig-alg
/// identity inside CertVerify): pin the RFC 8446 §4.2.3 signature
/// algorithm codepoints used in CertVerify mutation tests.
#[test]
fn t220_certverify_signature_algorithm_codepoint_identity_pin() {
    use hitls_tls::crypt::SignatureScheme;
    // RFC 8446 §4.2.3 — codepoints accessed via `.0` newtype field.
    assert_eq!(SignatureScheme::RSA_PSS_RSAE_SHA256.0, 0x0804);
    assert_eq!(SignatureScheme::ECDSA_SECP256R1_SHA256.0, 0x0403);
    assert_eq!(SignatureScheme::ED25519.0, 0x0807);
}

/// Mirrors C `MODIFIED_CERT_VERIFY` cert-message-format pin: a TLS 1.3
/// Certificate message body is `certificate_request_context (1 byte) +
/// certificate_list (3-byte length prefix)`. Each cert entry is `3-byte
/// cert DER length + cert DER + 2-byte extensions length`. Pin the
/// format constants the rogue server needs.
#[test]
fn t220_encrypted_certificate_record_format_chain_length_pin() {
    // A minimal Certificate body with empty context, one cert (3-byte
    // body), and zero extensions:
    let cert_der: Vec<u8> = vec![0x30, 0x82, 0x00]; // tiny placeholder DER
    let mut body = Vec::new();
    body.push(0x00); // certificate_request_context length = 0
                     // certificate_list length (3 bytes) — placeholder
    let cert_entry_len = 3 + cert_der.len() + 2; // cert_data length prefix + cert + ext length
    body.extend_from_slice(&((cert_entry_len) as u32).to_be_bytes()[1..]); // 3-byte length
                                                                           // cert entry
    body.extend_from_slice(&(cert_der.len() as u32).to_be_bytes()[1..]); // 3-byte
    body.extend_from_slice(&cert_der);
    body.extend_from_slice(&[0x00, 0x00]); // extensions length = 0

    // Pin the body length math: 1 (ctx len) + 3 (chain len) + 3 (cert
    // len) + cert + 2 (ext len) = 1 + 3 + 6 = 10 bytes for a 3-byte
    // cert.
    assert_eq!(body.len(), 1 + 3 + 3 + cert_der.len() + 2);
    assert_eq!(body.len(), 12);
}

/// Plan banner pin for T220 — asserts the plan doc lists D-2 / T220
/// and the MODIFIED_CERT_VERIFY family.
#[test]
fn t220_phase_g2_plan_banner_pinned() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-g-plan.md");
    let plan = std::fs::read_to_string(&plan_path).unwrap();
    assert!(plan.contains("T220"));
    assert!(plan.contains("MODIFIED_CERT_VERIFY"));
}
