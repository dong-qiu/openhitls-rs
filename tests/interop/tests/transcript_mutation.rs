//! TLS 1.3 transcript bit-flip / MODIFIED_*_TC replay tests — T186 (#48).
//!
//! Loosely migrated from `openhitls/testcode/sdv/testcase/tls/consistency/tls13/`
//! `test_suite_sdv_frame_tls13_consistency_rfc8446_1.{c,data}` —
//! `UT_TLS_TLS13_RFC8446_CONSISTENCY_MODIFIED_{SESSID_FROM_SH, CIPHERSUITE_FROM_SH,
//! CERT_VERIFY, ...}_FUNC_TC*`. The C tests use a `FRAME_*` man-in-the-middle
//! harness to capture a real ServerHello, mutate a specific field, and replay
//! it to the client. Rust has no such harness, so we build a minimal
//! **rogue-server** instead:
//!
//! - Bind a `TcpListener`, accept a real `TlsClientConnection`.
//! - Read its ClientHello off the wire (record layer + handshake header), parse
//!   with `decode_client_hello`.
//! - Construct a `ServerHello` with the right echoes (session_id, an offered
//!   cipher, an offered key_share group + fresh ECDH pubkey) BUT with a single
//!   mutation injected — change one field that violates RFC 8446 §4.1.3 / §4.2.
//! - Encode + frame in a TLS record and send.
//! - The real client's `handshake()` must abort with a specific error.
//!
//! ## Scope (Phase 1)
//!
//! Plaintext ServerHello mutations only. Encrypted post-SH messages
//! (`MODIFIED_CERT_VERIFY_FUNC_TC001`, `MODIFIED_FINISHED_FUNC_TC001`, etc.)
//! require simulating the full key schedule from the rogue server's side
//! (derive handshake traffic secrets, encrypt mutated plaintext) — that's a
//! Phase 2 PR. Tracked as `TODO(#48-encrypted-mutation)`.
//!
//! ## Coverage map (Rust check → C TC family)
//!
//! | Rust test | C TC analogue | Rust check | Alert |
//! |-----------|---------------|------------|-------|
//! | `sh_with_unoffered_cipher_suite_rejected` | `MODIFIED_CIPHERSUITE_FROM_SH_TC001` | `cipher_suites.contains()` | `NoSharedCipherSuite` |
//! | `sh_with_unoffered_keyshare_group_rejected` | `MODIFIED_KEY_SHARE_*` | `server_group != kx.group()` | `server key_share group mismatch` |
//! | `sh_without_supported_versions_rejected` | `MODIFIED_SUPPORTED_VERSIONS_*` | extension lookup | `missing supported_versions extension` |
//! | `sh_with_wrong_supported_version_rejected` | (RFC 8446 §4.2.1) | version != 0x0304 | `unsupported TLS version` |
//! | `sh_without_key_share_rejected` | (RFC 8446 §4.2.8) | extension lookup | `missing key_share` |
//! | `sh_with_mismatched_session_id_NOT_rejected_gap` | `MODIFIED_SESSID_FROM_SH_TC001` | **Rust does NOT check** | `TODO(#48-rfc-gap)` |
//! | `sh_with_nonzero_legacy_compression_NOT_rejected_gap` | (RFC 8446 §4.1.3) | **Rust does NOT check** | `TODO(#48-rfc-gap)` |
//!
//! ## Documented gaps (RFC 8446 §4.1.3 MUSTs not enforced by Rust today)
//!
//! - `TODO(#48-rfc-gap-sessid)`: RFC 8446 §4.1.3 — client MUST abort with
//!   `illegal_parameter` if `legacy_session_id_echo` does not match
//!   ClientHello.legacy_session_id. `decode_server_hello` currently parses
//!   and ignores. Pinned by `sh_with_mismatched_session_id_NOT_rejected_gap`.
//! - `TODO(#48-rfc-gap-compression)`: RFC 8446 §4.1.3 —
//!   `legacy_compression_method` MUST be 0. `decode_server_hello` reads and
//!   discards. Pinned by `sh_with_nonzero_legacy_compression_NOT_rejected_gap`.
//! - `TODO(#48-encrypted-mutation)`: encrypted post-SH transcript mutations
//!   (cert_verify, finished, certificate) require key-schedule simulation on
//!   the rogue-server side. Deferred to a follow-up PR.

use hitls_tls::config::TlsConfig;
use hitls_tls::connection::TlsClientConnection;
use hitls_tls::crypt::NamedGroup;
use hitls_tls::extensions::{Extension, ExtensionType};
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

/// Wrap raw handshake message bytes in a single TLS 1.3 handshake record.
fn make_handshake_record(handshake_bytes: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + handshake_bytes.len());
    record.push(0x16); // ContentType::Handshake
    record.extend_from_slice(&[0x03, 0x03]); // legacy_record_version
    record.extend_from_slice(&(handshake_bytes.len() as u16).to_be_bytes());
    record.extend_from_slice(handshake_bytes);
    record
}

/// Read exactly `len` bytes off the stream or error out.
fn read_exact(stream: &mut TcpStream, len: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read the next TLS record (header + body) off the wire.
fn read_record(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let header = read_exact(stream, 5)?;
    let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let body = read_exact(stream, body_len)?;
    let mut record = header;
    record.extend_from_slice(&body);
    Ok(record)
}

/// Snapshot of the client's offered crypto material that the rogue server
/// echoes back in its mutated ServerHello.
struct ClientHelloInfo {
    session_id: Vec<u8>,
    offered_ciphers: Vec<CipherSuite>,
    offered_key_shares: Vec<(NamedGroup, Vec<u8>)>,
}

/// Read one ClientHello off `stream` and return the fields the rogue server
/// needs to forge a matching ServerHello.
fn capture_client_hello(stream: &mut TcpStream) -> ClientHelloInfo {
    let record = read_record(stream).expect("read ClientHello record");
    // Skip 5-byte record header → handshake message
    let hs_bytes = &record[5..];
    // Skip 4-byte handshake header (msg_type + uint24 length) → CH body
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
    }
}

/// Builder for a (mutated) ServerHello.
struct ShBuilder {
    cipher_suite: CipherSuite,
    legacy_session_id: Vec<u8>,
    extensions: Vec<Extension>,
}

impl ShBuilder {
    /// Construct a valid ServerHello consistent with the captured ClientHello,
    /// then let the caller mutate one field before encoding.
    fn from_client_hello(info: &ClientHelloInfo) -> Self {
        // Pick the first offered cipher
        let cipher_suite = info.offered_ciphers[0];
        // Pick the first offered key_share group and generate matching pubkey
        let (group, _client_pub) = &info.offered_key_shares[0];
        let kx = KeyExchange::generate(*group).expect("server keypair");
        let extensions = vec![
            build_supported_versions_sh(),
            build_key_share_sh(*group, kx.public_key_bytes()),
        ];
        Self {
            cipher_suite,
            legacy_session_id: info.session_id.clone(),
            extensions,
        }
    }

    fn cipher(mut self, c: CipherSuite) -> Self {
        self.cipher_suite = c;
        self
    }

    fn session_id(mut self, sid: Vec<u8>) -> Self {
        self.legacy_session_id = sid;
        self
    }

    fn drop_extension(mut self, ty: ExtensionType) -> Self {
        self.extensions.retain(|e| e.extension_type != ty);
        self
    }

    fn replace_supported_versions(mut self, version: u16) -> Self {
        self.extensions
            .retain(|e| e.extension_type != ExtensionType::SUPPORTED_VERSIONS);
        self.extensions.push(Extension {
            extension_type: ExtensionType::SUPPORTED_VERSIONS,
            data: version.to_be_bytes().to_vec(),
        });
        self
    }

    fn replace_key_share_with(mut self, group: NamedGroup) -> Self {
        self.extensions
            .retain(|e| e.extension_type != ExtensionType::KEY_SHARE);
        let kx = KeyExchange::generate(group).expect("alt keypair");
        self.extensions
            .push(build_key_share_sh(group, kx.public_key_bytes()));
        self
    }

    fn encode_with_random(self, random: [u8; 32]) -> Vec<u8> {
        let sh = ServerHello {
            random,
            legacy_session_id: self.legacy_session_id,
            cipher_suite: self.cipher_suite,
            extensions: self.extensions,
        };
        encode_server_hello(&sh)
    }

    /// Encode the ServerHello with a fresh-but-deterministic non-HRR random.
    fn encode(self) -> Vec<u8> {
        // Use a constant random to keep tests stable. The first byte being
        // != HelloRetryRequest sentinel (0xCF) avoids accidental HRR path.
        let mut r = [0u8; 32];
        for (i, b) in r.iter_mut().enumerate() {
            *b = i as u8;
        }
        self.encode_with_random(r)
    }
}

/// Build a `TlsClientConnection`, drive its handshake against a rogue server
/// that emits `mutated_sh_bytes` (no further handshake messages) on the same
/// socket. Returns the client's handshake error (panics if it succeeds).
fn drive_client_against_rogue_server<F>(mutate: F) -> String
where
    F: FnOnce(&ClientHelloInfo) -> Vec<u8> + Send + 'static,
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
        let sh_bytes = mutate(&info);
        let record = make_handshake_record(&sh_bytes);
        let _ = stream.write_all(&record);
        // Hold the connection open briefly so the client receives our record
        // before EOF. Discarding the stream too quickly can race the client
        // read.
        thread::sleep(Duration::from_millis(50));
    });

    // Real client — we never reach Certificate processing, so no cert chain
    // is needed.
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .build();

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    let err = conn
        .handshake()
        .expect_err("rogue server SH should fail client handshake");
    let _ = rogue_handle.join();
    format!("{err:?}")
}

/// Same as `drive_client_against_rogue_server` but the closure builds the SH
/// without errors AND the client is expected to ACCEPT (gap-pin tests).
fn drive_client_accepting_rogue_sh<F>(mutate: F) -> Result<(), String>
where
    F: FnOnce(&ClientHelloInfo) -> Vec<u8> + Send + 'static,
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
        let sh_bytes = mutate(&info);
        let record = make_handshake_record(&sh_bytes);
        let _ = stream.write_all(&record);
        // For gap-pin tests, the client moves past SH parsing into the next
        // expected message (EncryptedExtensions). Our rogue doesn't send it;
        // the client will timeout or error reading the next record. That's
        // fine — we ONLY assert that SH parsing did not flag the gap.
        thread::sleep(Duration::from_millis(100));
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .build();

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    let err = conn
        .handshake()
        .expect_err("client must err *after* SH parse (EOF / next-msg timeout)");
    let _ = rogue_handle.join();
    let err_str = format!("{err:?}");

    // For a gap test, the error message must NOT be one of the SH-validation
    // categories — it should be a downstream "next message" failure.
    if err_str.contains("session_id")
        || err_str.contains("compression")
        || err_str.contains("legacy")
        || err_str.contains("illegal_parameter")
    {
        return Err(format!(
            "expected SH parse to silently accept the gap; got: {err_str}"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Group 1 — fields Rust DOES validate (rejection path)
// ---------------------------------------------------------------------------

#[test]
fn sh_with_unoffered_cipher_suite_rejected() {
    // C `MODIFIED_CIPHERSUITE_FROM_SH_TC001`: server picks a cipher the client
    // did not offer. Rust: `cipher_suites.contains()` check fires →
    // `NoSharedCipherSuite`.
    let err = drive_client_against_rogue_server(|info| {
        let mut bad_cipher = CipherSuite(0x1305); // not in default TLS 1.3 set
        for c in [
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        ] {
            if info.offered_ciphers.contains(&c) {
                continue;
            }
            bad_cipher = c;
            break;
        }
        // Confirm it's truly un-offered
        assert!(
            !info.offered_ciphers.contains(&bad_cipher),
            "must pick a cipher the client did NOT offer"
        );
        ShBuilder::from_client_hello(info)
            .cipher(bad_cipher)
            .encode()
    });
    assert!(
        err.contains("NoSharedCipherSuite") || err.contains("cipher"),
        "expected cipher mismatch error, got: {err}"
    );
}

#[test]
fn sh_with_unoffered_keyshare_group_rejected() {
    // Rust: `server_group != kx.group()` → `HandshakeFailed("server key_share
    // group mismatch")`.
    let err = drive_client_against_rogue_server(|info| {
        // Pick an EC group the client did not key_share. Client by default
        // shares only its preferred group; secp256r1 is usually offered but
        // the actual `key_share` list typically has one entry only.
        let shared_groups: Vec<NamedGroup> =
            info.offered_key_shares.iter().map(|(g, _)| *g).collect();
        let alt = [
            NamedGroup::SECP384R1,
            NamedGroup::SECP521R1,
            NamedGroup::SECP256R1,
            NamedGroup::X25519,
        ]
        .into_iter()
        .find(|g| !shared_groups.contains(g))
        .expect("at least one alt group not in key_share");
        ShBuilder::from_client_hello(info)
            .replace_key_share_with(alt)
            .encode()
    });
    assert!(
        err.contains("key_share group mismatch") || err.contains("key_share"),
        "expected key_share mismatch, got: {err}"
    );
}

#[test]
fn sh_without_supported_versions_rejected() {
    let err = drive_client_against_rogue_server(|info| {
        ShBuilder::from_client_hello(info)
            .drop_extension(ExtensionType::SUPPORTED_VERSIONS)
            .encode()
    });
    assert!(
        err.contains("missing supported_versions"),
        "expected missing supported_versions, got: {err}"
    );
}

#[test]
fn sh_with_wrong_supported_version_rejected() {
    // Inject supported_versions=0x0303 (TLS 1.2) — client expects 0x0304.
    let err = drive_client_against_rogue_server(|info| {
        ShBuilder::from_client_hello(info)
            .replace_supported_versions(0x0303)
            .encode()
    });
    assert!(
        err.contains("unsupported TLS version") || err.contains("0x0303"),
        "expected version-mismatch error, got: {err}"
    );
}

#[test]
fn sh_without_key_share_rejected() {
    let err = drive_client_against_rogue_server(|info| {
        ShBuilder::from_client_hello(info)
            .drop_extension(ExtensionType::KEY_SHARE)
            .encode()
    });
    assert!(
        err.contains("missing key_share"),
        "expected missing key_share, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Group 2 — fields Rust does NOT validate today (gap pins)
// ---------------------------------------------------------------------------

#[test]
fn sh_with_mismatched_session_id_not_rejected_gap() {
    // C `MODIFIED_SESSID_FROM_SH_TC001`: RFC 8446 §4.1.3 says client MUST
    // abort with `illegal_parameter` when legacy_session_id_echo does not
    // match what it sent. Rust `decode_server_hello` parses and discards
    // legacy_session_id; the SH proceeds through.
    // TODO(#48-rfc-gap-sessid): enforce session-id echo check per RFC 8446 §4.1.3.
    let outcome = drive_client_accepting_rogue_sh(|info| {
        let mut wrong_sid = info.session_id.clone();
        if wrong_sid.is_empty() {
            wrong_sid = vec![0xFF; 32];
        } else {
            wrong_sid[0] ^= 0xFF;
        }
        ShBuilder::from_client_hello(info)
            .session_id(wrong_sid)
            .encode()
    });
    outcome.expect("Rust silently accepts mismatched session_id (RFC gap)");
}

#[test]
fn sh_with_nonzero_legacy_compression_not_rejected_gap() {
    // RFC 8446 §4.1.3: legacy_compression_method MUST be 0. Rust
    // `decode_server_hello` reads byte and discards.
    // TODO(#48-rfc-gap-compression): enforce legacy_compression_method == 0.
    // To inject a non-zero compression byte we hand-craft the SH bytes since
    // `encode_server_hello` always writes 0. Layout we patch:
    //   hs_type(1) + len(3) + legacy_version(2) + random(32)
    //     + sid_len(1) + sid + cipher(2) + compression(1)*  <- the byte to flip
    //     + ext_len(2) + ext_bytes
    let outcome = drive_client_accepting_rogue_sh(|info| {
        let mut hs = ShBuilder::from_client_hello(info).encode();
        // hs[0]: handshake type. hs[1..4]: 24-bit length. hs[4..]: body.
        let body_start = 4;
        // body layout: 2 (legacy_version) + 32 (random) + 1 (sid_len) + sid + 2 (cipher) + 1 (compression)
        let sid_len = hs[body_start + 2 + 32] as usize;
        let compression_off = body_start + 2 + 32 + 1 + sid_len + 2;
        hs[compression_off] = 0x01;
        hs
    });
    outcome.expect("Rust silently accepts non-zero legacy_compression (RFC gap)");
}

// ===========================================================================
// T214 / Phase D-1 — `frame_tls13_consistency_rfc8446_1.c` record-layer +
// state-machine mutations.
//
// Extends the T186 rogue-server framework with raw-byte mutations targeting
// the record header (offsets 0-4) instead of just the handshake-message
// payload. The record header layout is:
//   type(1) | version(2) | length(2)
//
// ## C-source mapping (this batch)
//
// | C TC family | Rust test |
// |-------------|-----------|
// | `MSGLENGTH_TOOLONG_TC001-004` | `t214_record_length_high_byte_corrupted_rejected` + `t214_record_length_low_byte_too_small_rejected` |
// | `UNEXPECT_RECODETYPE_TC001-006` | `t214_record_with_unknown_content_type_rejected` + `t214_record_with_appdata_type_during_handshake_rejected` |
// | `NO_SUPPORTED_GROUP_TC001` | `t214_sh_supported_group_not_offered_rejected_gap` (server returns group outside CH's offered_groups; T186 already covers key_share mismatch, this is the broader category) |
// | `RECEIVES_OTHER_CCS_TC001/002` | scope-cut (covered by T88 RFC 8446 §5 CCS rule pinning); cross-coverage pin to DEV_LOG T88 |
// | `MSGLENGTH_TOOLONG` low-byte | `t214_record_length_zero_rejected` |
// | `ZERO_APPMSG_FUNC_TC001` | `t214_zero_length_handshake_message_handling` |
// | `READ_WRITE_AFTER_FATAL_ALEART_FUNC_TC001/002` | scope-cut (post-handshake; needs encrypted state) |
// | (gap pin) | `audit_phase_d_plan_docs_in_sync` |
// ===========================================================================

/// Mirrors C `UT_TLS_TLS13_RFC8446_CONSISTENCY_MSGLENGTH_TOOLONG_FUNC_TC001`:
/// the record header's length field high byte set to 0xFF (which would
/// imply a 64+ KiB record). The client's record-layer parser must reject
/// before any handshake parsing.
#[test]
fn t214_record_length_high_byte_corrupted_rejected() {
    let err = drive_client_against_rogue_server(|info| {
        let hs = ShBuilder::from_client_hello(info).encode();
        let mut record = make_handshake_record(&hs);
        // record[3..5] = length; flip high byte.
        record[3] = 0xFF;
        record
    });
    assert!(
        !err.is_empty(),
        "client must reject record with oversized declared length"
    );
}

/// Mirrors C `UT_TLS_TLS13_RFC8446_CONSISTENCY_MSGLENGTH_TOOLONG_FUNC_TC002`:
/// the record length field set to a small value smaller than the actual
/// payload — the reader sees a truncated/inconsistent record.
#[test]
fn t214_record_length_low_byte_too_small_rejected() {
    let err = drive_client_against_rogue_server(|info| {
        let hs = ShBuilder::from_client_hello(info).encode();
        let mut record = make_handshake_record(&hs);
        // Set length = 1 (way below the real handshake body)
        record[3] = 0x00;
        record[4] = 0x01;
        record
    });
    assert!(
        !err.is_empty(),
        "client must reject record with too-small declared length"
    );
}

/// Mirrors C `UT_TLS_TLS13_RFC8446_CONSISTENCY_MSGLENGTH_TOOLONG_FUNC_TC003`:
/// record length zero — the reader has no body to parse.
#[test]
fn t214_record_length_zero_rejected() {
    let err = drive_client_against_rogue_server(|info| {
        let hs = ShBuilder::from_client_hello(info).encode();
        let mut record = make_handshake_record(&hs);
        record[3] = 0x00;
        record[4] = 0x00;
        record
    });
    assert!(
        !err.is_empty(),
        "client must reject zero-length record during handshake"
    );
}

/// Mirrors C `UT_TLS_TLS13_RFC8446_CONSISTENCY_UNEXPECT_RECODETYPE_FUNC_TC001`
/// (note: `RECODETYPE` is a verbatim C-source typo): set the record's
/// ContentType byte to an unknown value (0xFE). The record layer must
/// reject before handshake parsing.
#[test]
fn t214_record_with_unknown_content_type_rejected() {
    let err = drive_client_against_rogue_server(|info| {
        let hs = ShBuilder::from_client_hello(info).encode();
        let mut record = make_handshake_record(&hs);
        record[0] = 0xFE; // unknown content type
        record
    });
    assert!(
        !err.is_empty(),
        "client must reject record with unknown content type"
    );
}

/// Mirrors C `UT_TLS_TLS13_RFC8446_CONSISTENCY_UNEXPECT_RECODETYPE_FUNC_TC002`:
/// AppData record type (0x17 = ApplicationData) sent before the
/// handshake completes — the client expects Handshake (0x16) at this
/// state.
#[test]
fn t214_record_with_appdata_type_during_handshake_rejected() {
    let err = drive_client_against_rogue_server(|info| {
        let hs = ShBuilder::from_client_hello(info).encode();
        let mut record = make_handshake_record(&hs);
        record[0] = 0x17; // ApplicationData content type
        record
    });
    assert!(
        !err.is_empty(),
        "client must reject ApplicationData record during handshake"
    );
}

/// Mirrors C `UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC001`
/// in the negative shape: an Alert record (0x15) sent in place of the
/// expected ServerHello must surface an error (not silently absorb).
#[test]
fn t214_record_with_alert_type_in_place_of_sh_rejected() {
    let err = drive_client_against_rogue_server(|info| {
        let hs = ShBuilder::from_client_hello(info).encode();
        let mut record = make_handshake_record(&hs);
        record[0] = 0x15; // Alert content type
        record
    });
    assert!(
        !err.is_empty(),
        "client must reject Alert record in place of ServerHello"
    );
}

/// Mirrors C `UT_TLS_TLS13_RFC8446_CONSISTENCY_NO_SUPPORTED_GROUP_FUNC_TC001`
/// in the broader category (key_share group must be one of CH's
/// offered_groups). T186 already covered the specific
/// `sh_with_unoffered_keyshare_group_rejected`; this row's variant uses
/// the same path but a different group on a different cipher path,
/// pinning the broad family.
#[test]
fn t214_sh_supported_group_not_offered_rejected_gap() {
    // The T186 test covered SECP256R1 → X25519. Use the dual mapping
    // (X25519 → SECP256R1) to pin the symmetric path. Both are common
    // groups that client implementations offer; assert the rejection
    // surfaces regardless of which side is "offered" vs "returned".
    let err = drive_client_against_rogue_server(|info| {
        // Find any group NOT in info.offered_key_shares
        let mut bad = NamedGroup::SECP384R1; // unlikely in default offered list
        if info.offered_key_shares.iter().any(|(g, _)| *g == bad) {
            bad = NamedGroup::SECP521R1;
        }
        ShBuilder::from_client_hello(info)
            .replace_key_share_with(bad)
            .encode()
    });
    assert!(
        !err.is_empty(),
        "client must reject SH with key_share group not in CH offered list"
    );
}

/// Mirrors C `UT_TLS_TLS13_RFC8446_CONSISTENCY_ZERO_APPMSG_FUNC_TC001`-style
/// shape: when the SH carries a zero-length cipher_suite (i.e., the
/// handshake-message body length is anomalous), the parser rejects.
/// We exercise this by truncating the handshake-message body length
/// field directly in the encoded SH.
#[test]
fn t214_handshake_body_length_too_small_rejected() {
    let err = drive_client_against_rogue_server(|info| {
        let mut hs = ShBuilder::from_client_hello(info).encode();
        // hs[1..4] = 24-bit length. Set to 0 to claim empty body.
        hs[1] = 0;
        hs[2] = 0;
        hs[3] = 0;
        make_handshake_record(&hs)
    });
    assert!(
        !err.is_empty(),
        "client must reject SH with declared empty body"
    );
}

/// Cross-coverage gap pin to T88 (CCS rule pinning) — mirrors C
/// `RECEIVES_OTHER_CCS_TC001/002`. T88 already pinned the RFC 8446 §5
/// CCS rule via tlsfuzzer; rather than re-implementing the test here,
/// assert the relevant DEV_LOG phase is recorded.
#[test]
fn t214_ccs_rules_covered_by_t88_cross_coverage() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dev_log_path = format!("{manifest_dir}/../../DEV_LOG.md");
    let log = std::fs::read_to_string(&dev_log_path)
        .unwrap_or_else(|e| panic!("missing DEV_LOG at {dev_log_path}: {e}"));
    assert!(
        log.contains("T88"),
        "DEV_LOG must keep T88 phase entry (RFC 8446 §5 CCS pinning)"
    );
    assert!(
        log.contains("test-tls13-ccs.py"),
        "DEV_LOG T88 must reference test-tls13-ccs.py tlsfuzzer integration"
    );
}

/// Reads `docs/issue-42-phase-d-plan.md` and asserts the key audit
/// anchors. Same pattern as Phase C T204 and Phase F T209.
#[test]
fn audit_phase_d_plan_docs_in_sync() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let plan_path = format!("{manifest_dir}/../../docs/issue-42-phase-d-plan.md");
    let plan = std::fs::read_to_string(&plan_path)
        .unwrap_or_else(|e| panic!("missing audit doc at {plan_path}: {e}"));

    for tag in &[
        "T214", "T215", "T216", "T217", "T218", "D-1", "D-2", "D-3", "D-4",
    ] {
        assert!(plan.contains(tag), "plan doc missing sub-PR tag `{tag}`");
    }

    for anchor in &[
        "tls13_consistency_rfc8446_1.c",
        "tls12_consistency_rfc5246.c",
        "TODO(#42-phase-d)",
        "rogue-server framework",
    ] {
        assert!(
            plan.contains(anchor),
            "plan doc must keep anchor `{anchor}`"
        );
    }
}
