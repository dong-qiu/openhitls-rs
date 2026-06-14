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
