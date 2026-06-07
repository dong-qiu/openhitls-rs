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
