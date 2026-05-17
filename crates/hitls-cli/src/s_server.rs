//! TLS server command (`s_server`).

use hitls_pki::pkcs8::{parse_pkcs8_pem, Pkcs8PrivateKey};
use hitls_pki::x509::verify::parse_certs_pem;
use hitls_tls::config::{ServerPrivateKey, TlsConfig};
use hitls_tls::crypt::NamedGroup;
use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
use std::net::{TcpListener, TcpStream};

#[allow(clippy::too_many_arguments)] // Phase T96 — CLI flags are intentionally per-knob.
pub fn run(
    port: u16,
    cert_path: &str,
    key_path: &str,
    tls_version: &str,
    quiet: bool,
    cipher_suites_arg: Option<&str>,
    require_client_cert_ca: Option<&str>,
    verify_client_cert_ca: Option<&str>,
    max_early_data_size: u32,
    ticket_key_hex: Option<&str>,
    psk_hex: Option<&str>,
    psk_identity: Option<&str>,
    key_update: bool,
    post_handshake_auth: bool,
    no_middlebox_compat: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Phase I100 — accepted `--tls` values: pinned "1.2" / "1.3" or
    // "auto" (peek each ClientHello and dispatch per connection).
    if !matches!(tls_version, "1.2" | "1.3" | "auto") {
        return Err(format!(
            "unsupported TLS version '{tls_version}' (use \"1.2\", \"1.3\", or \"auto\")"
        )
        .into());
    }
    // Phase T122/T125 — `--key-update` / `--post-handshake-auth` drive
    // TLS 1.3-only post-handshake messages; reject them up front for a
    // TLS 1.2 listener rather than silently ignoring. They stay legal
    // under `--tls auto` (they only fire when a 1.3 client connects).
    if tls_version == "1.2" && (key_update || post_handshake_auth) {
        return Err("--key-update / --post-handshake-auth require TLS 1.3".into());
    }
    // Load certificate chain
    let cert_pem = std::fs::read_to_string(cert_path)
        .map_err(|e| format!("cannot read certificate file '{cert_path}': {e}"))?;
    let certs =
        parse_certs_pem(&cert_pem).map_err(|e| format!("failed to parse certificate(s): {e}"))?;
    if certs.is_empty() {
        return Err("no certificates found in file".into());
    }
    let cert_chain: Vec<Vec<u8>> = certs.iter().map(|c| c.raw.clone()).collect();

    // Load private key
    let key_pem = std::fs::read_to_string(key_path)
        .map_err(|e| format!("cannot read key file '{key_path}': {e}"))?;
    let pkcs8_key =
        parse_pkcs8_pem(&key_pem).map_err(|e| format!("failed to parse private key: {e}"))?;
    // Phase T107 — capture the PSS-OID flag before we convert the
    // PKCS#8 key into the wire-shaped `ServerPrivateKey` (which
    // doesn't carry the OID itself).
    let is_pss_oid = matches!(pkcs8_key, Pkcs8PrivateKey::RsaPss(_));
    let server_key = pkcs8_to_server_key(pkcs8_key)?;

    // Phase T96 — `--cipher-suites` overrides the per-version defaults
    // when set. Accept comma-separated names or `0xNNNN` hex codepoints.
    let custom_ciphers: Option<Vec<CipherSuite>> = match cipher_suites_arg {
        Some(s) => Some(parse_cipher_suite_list(s)?),
        None => None,
    };

    // Phase T96/T98 — resolve the mTLS client-CA bundle once, up front,
    // so a bad path / empty file fails at startup rather than once per
    // connection. `--require-client-cert` and `--verify-client-cert`
    // both send a CertificateRequest; only the former rejects an empty
    // client Certificate, and the two are mutually exclusive.
    if require_client_cert_ca.is_some() && verify_client_cert_ca.is_some() {
        return Err("--verify-client-cert and --require-client-cert are mutually exclusive".into());
    }
    let (client_ca_path, require_client_cert) =
        match (require_client_cert_ca, verify_client_cert_ca) {
            (Some(p), _) => (Some(p), true),
            (_, Some(p)) => (Some(p), false),
            _ => (None, false),
        };
    let trusted_client_cas: Vec<Vec<u8>> = match client_ca_path {
        Some(ca_path) => {
            let ca_pem = std::fs::read_to_string(ca_path)
                .map_err(|e| format!("cannot read client-CA file '{ca_path}': {e}"))?;
            let ca_certs = parse_certs_pem(&ca_pem)
                .map_err(|e| format!("failed to parse client-CA certificate(s): {e}"))?;
            if ca_certs.is_empty() {
                return Err("no client-CA certificates found in file".into());
            }
            ca_certs.iter().map(|c| c.raw.clone()).collect()
        }
        None => Vec::new(),
    };
    let verify_client_cert = client_ca_path.is_some();

    // Phase T96 — `--ticket-key <hex>`: exactly 32 bytes (AES-256-GCM key).
    let ticket_key: Option<Vec<u8>> = match ticket_key_hex {
        Some(hex_str) => {
            let key_bytes = hitls_utils::hex::hex(hex_str);
            if key_bytes.len() != 32 {
                return Err(format!(
                    "--ticket-key must be exactly 32 bytes (64 hex chars); got {} bytes",
                    key_bytes.len()
                )
                .into());
            }
            Some(key_bytes)
        }
        None => None,
    };

    // Phase T119 — `--psk <hex>` + `--psk-identity <id>` for TLS 1.3
    // external PSK (RFC 8446 §4.2.11). Both flags must be set together;
    // identity is an opaque UTF-8 string matched literally against the
    // wire bytes the client sends in `pre_shared_key`. PSK length
    // validation is deferred to the handshake layer.
    let psk: Option<(Vec<u8>, Vec<u8>)> = match (psk_hex, psk_identity) {
        (Some(hex_str), Some(id)) => {
            let psk_bytes = hitls_utils::hex::hex(hex_str);
            if psk_bytes.is_empty() {
                return Err("--psk: empty / invalid hex value".into());
            }
            Some((psk_bytes, id.as_bytes().to_vec()))
        }
        (Some(_), None) => return Err("--psk requires --psk-identity".into()),
        (None, Some(_)) => return Err("--psk-identity requires --psk".into()),
        (None, None) => None,
    };

    // Phase I100 — build a finished `TlsConfig` pinned to a single TLS
    // version. Pulled into a closure so `--tls auto` can hold one config
    // per version and pick per-connection after peeking the ClientHello;
    // `--tls 1.2` / `--tls 1.3` call it exactly once.
    //
    // Accepts the four interop-relevant groups (X25519, P-256, P-384,
    // P-521) by default so external test tools (openssl s_client,
    // tlsfuzzer, browsers) don't trigger HRR-on-no-common-group when
    // their first key_share happens to be P-256 / P-384.
    let make_config = |want_tls13: bool| -> TlsConfig {
        let mut builder = TlsConfig::builder()
            .role(TlsRole::Server)
            .certificate_chain(cert_chain.clone())
            .private_key(server_key.clone())
            .server_cert_is_rsa_pss(is_pss_oid)
            .supported_groups(&[
                NamedGroup::X25519,
                NamedGroup::SECP256R1,
                NamedGroup::SECP384R1,
                NamedGroup::SECP521R1,
            ])
            .verify_peer(false);

        let suites = custom_ciphers.clone().unwrap_or_else(|| {
            if want_tls13 {
                default_tls13_suites()
            } else {
                default_tls12_suites()
            }
        });
        let (min, max) = if want_tls13 {
            (TlsVersion::Tls13, TlsVersion::Tls13)
        } else {
            (TlsVersion::Tls12, TlsVersion::Tls12)
        };
        builder = builder
            .min_version(min)
            .max_version(max)
            .cipher_suites(&suites);

        for ca in &trusted_client_cas {
            builder = builder.trusted_cert(ca.clone());
        }
        if verify_client_cert {
            builder = builder.verify_client_cert(true);
        }
        if require_client_cert {
            builder = builder.require_client_cert(true);
        }
        if max_early_data_size > 0 {
            builder = builder.max_early_data_size(max_early_data_size);
        }
        if let Some(k) = &ticket_key {
            builder = builder.ticket_key(k.clone());
        }
        if let Some((p, id)) = &psk {
            builder = builder.psk(p.clone()).psk_identity(id.clone());
        }
        if no_middlebox_compat {
            builder = builder.middlebox_compat(false);
        }
        builder.build()
    };

    // Phase I100 — `--tls auto` keeps one config per version and chooses
    // per connection; the pinned modes build only the one they need.
    let cfg_tls13: Option<TlsConfig> = (tls_version != "1.2").then(|| make_config(true));
    let cfg_tls12: Option<TlsConfig> = (tls_version != "1.3").then(|| make_config(false));

    // Bind TCP listener
    let bind_addr = format!("0.0.0.0:{port}");
    let listener =
        TcpListener::bind(&bind_addr).map_err(|e| format!("cannot bind to '{bind_addr}': {e}"))?;

    if !quiet {
        eprintln!("Listening on {bind_addr} (TLS {tls_version})");
        eprintln!("Press Ctrl+C to stop.");
    }

    // Accept loop
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                if !quiet {
                    eprintln!("Accept error: {e}");
                }
                continue;
            }
        };

        let peer = stream.peer_addr().ok();
        if !quiet {
            if let Some(addr) = &peer {
                eprintln!("Accepted connection from {addr}");
            }
        }

        // Set timeouts for the connection
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(30)));

        // Phase I100 — `--tls auto` peeks the pending ClientHello to
        // pick the per-connection handler; the pinned modes already
        // know which one they want.
        let want_tls13 = match tls_version {
            "1.3" => true,
            "1.2" => false,
            _ => peek_client_wants_tls13(&stream),
        };
        let result = if want_tls13 {
            let mut conn = hitls_tls::connection::TlsServerConnection::new(
                stream,
                cfg_tls13
                    .clone()
                    .expect("TLS 1.3 config built for any non-1.2 mode"),
            );
            handle_connection_tls13(&mut conn, quiet, key_update, post_handshake_auth)
        } else {
            let mut conn = hitls_tls::connection12::Tls12ServerConnection::new(
                stream,
                cfg_tls12
                    .clone()
                    .expect("TLS 1.2 config built for any non-1.3 mode"),
            );
            handle_connection(&mut conn, quiet)
        };

        if let Err(e) = result {
            if !quiet {
                eprintln!("Connection error: {e}");
            }
        }

        if !quiet {
            eprintln!("Connection closed.");
        }
    }

    Ok(())
}

/// Print the negotiated protocol / cipher once the handshake completes.
fn print_established(conn: &dyn TlsConnection, quiet: bool) {
    if quiet {
        return;
    }
    eprintln!("--- TLS connection established ---");
    if let Some(version) = conn.version() {
        eprintln!("  Protocol: {version:?}");
    }
    if let Some(cs) = conn.cipher_suite() {
        eprintln!("  Cipher:   0x{:04X}", cs.0);
    }
    eprintln!("---------------------------------");
}

/// True if `needle` occurs anywhere in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Default TLS 1.3 cipher-suite list for `s-server` (Phase T105 — the
/// two AES-CCM suites the crypto layer has always supported are
/// included). Overridden by `--cipher-suites`.
fn default_tls13_suites() -> Vec<CipherSuite> {
    vec![
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_AES_128_CCM_SHA256,
        CipherSuite::TLS_AES_128_CCM_8_SHA256,
    ]
}

/// Default TLS 1.2 cipher-suite list for `s-server` (Phase T96 — the
/// legacy ECDHE-CBC-SHA suites tlsfuzzer hard-codes are included
/// alongside the AEAD suites). Overridden by `--cipher-suites`.
fn default_tls12_suites() -> Vec<CipherSuite> {
    vec![
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    ]
}

/// Phase I100 — peek the pending ClientHello (without consuming it) and
/// decide whether the client is a TLS 1.3 client. Used by `--tls auto`
/// to pick the per-connection handler. The ClientHello almost always
/// arrives in one TCP segment; we retry a few times in case the first
/// `peek` catches a partial write. Any read error / parse failure /
/// short read falls back to `false` (TLS 1.2) — the 1.2 connection's
/// own record parser then rejects a genuinely malformed handshake with
/// a proper alert, so a wrong guess never silently corrupts state.
fn peek_client_wants_tls13(stream: &TcpStream) -> bool {
    let mut buf = [0u8; 2048];
    let mut n = 0usize;
    for attempt in 0..8 {
        match stream.peek(&mut buf) {
            Ok(got) => {
                n = got;
                // Stop once the full first record is buffered (or the
                // peek buffer is saturated — enough to find the
                // supported_versions extension in any sane ClientHello).
                if got >= 5 {
                    let rec_len = ((buf[3] as usize) << 8) | buf[4] as usize;
                    if got >= 5 + rec_len || got == buf.len() {
                        break;
                    }
                }
            }
            Err(_) => return false,
        }
        if attempt < 7 {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    client_hello_offers_tls13(&buf[..n])
}

/// Walk a raw TLS record + ClientHello far enough to locate the
/// `supported_versions` extension (RFC 8446 §4.2.1). Returns `true`
/// iff that extension is present and lists `0x0304` (TLS 1.3). Every
/// step is bounds-checked; a truncated / malformed buffer returns
/// `false` rather than panicking. Pure (`&[u8] -> bool`) so it is
/// unit-testable without a socket.
fn client_hello_offers_tls13(buf: &[u8]) -> bool {
    // TLS record header: content_type(1) legacy_version(2) length(2).
    if buf.len() < 5 || buf[0] != 0x16 {
        return false; // not a Handshake record
    }
    let body = &buf[5..];
    // Handshake header: msg_type(1) length(3).
    if body.len() < 4 || body[0] != 0x01 {
        return false; // not a ClientHello
    }
    let ch = &body[4..];
    // ClientHello body: client_version(2) random(32) then variable fields.
    let mut o = 2 + 32;
    // legacy_session_id: opaque<0..32> with a u8 length prefix.
    if ch.len() < o + 1 {
        return false;
    }
    o += 1 + ch[o] as usize;
    // cipher_suites: with a u16 length prefix.
    if ch.len() < o + 2 {
        return false;
    }
    o += 2 + (((ch[o] as usize) << 8) | ch[o + 1] as usize);
    // legacy_compression_methods: with a u8 length prefix.
    if ch.len() < o + 1 {
        return false;
    }
    o += 1 + ch[o] as usize;
    // extensions: with a u16 length prefix.
    if ch.len() < o + 2 {
        return false;
    }
    let ext_total = ((ch[o] as usize) << 8) | ch[o + 1] as usize;
    o += 2;
    let ext_end = (o + ext_total).min(ch.len());
    while o + 4 <= ext_end {
        let etype = ((ch[o] as usize) << 8) | ch[o + 1] as usize;
        let elen = ((ch[o + 2] as usize) << 8) | ch[o + 3] as usize;
        let data_start = o + 4;
        let data_end = data_start + elen;
        if data_end > ch.len() {
            return false;
        }
        if etype == 0x002b {
            // supported_versions (ClientHello form): a u8-length-prefixed
            // list of u16 versions. TLS 1.3 == 0x0304.
            let d = &ch[data_start..data_end];
            if d.is_empty() {
                return false;
            }
            let list = &d[1..(1 + d[0] as usize).min(d.len())];
            return list.chunks_exact(2).any(|v| v[0] == 0x03 && v[1] == 0x04);
        }
        o = data_end;
    }
    false
}

fn handle_connection(
    conn: &mut dyn TlsConnection,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    conn.handshake()?;
    print_established(conn, quiet);

    // Echo loop: read data from client, echo it back
    let mut buf = vec![0u8; 16384];
    loop {
        match conn.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if !quiet {
                    let text = String::from_utf8_lossy(&buf[..n]);
                    eprint!("< {text}");
                }
                conn.write(&buf[..n])?;
            }
            Err(hitls_types::TlsError::ConnectionClosed) => break,
            Err(hitls_types::TlsError::AlertReceived(_)) => break,
            Err(hitls_types::TlsError::IoError(ref e))
                if e.kind() == std::io::ErrorKind::ConnectionReset =>
            {
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }

    let _ = conn.shutdown();
    Ok(())
}

/// TLS 1.3 connection handler with the post-handshake triggers.
/// Identical echo behaviour to [`handle_connection`], but before echoing
/// a request it inspects the bytes for a path marker:
///
/// - `/keyupdate` (when `key_update` is set, Phase T122) → send a
///   post-handshake KeyUpdate (`update_requested`);
/// - `/secret` (when `post_handshake_auth` is set, Phase T125) → send a
///   post-handshake CertificateRequest and read the client's response.
///
/// A plain `GET /` matches neither marker, so tlsfuzzer sanity steps —
/// which send `GET / HTTP/1.0` — are echoed without any extra message;
/// the discriminator is the request path, not the presence of
/// application data.
fn handle_connection_tls13(
    conn: &mut hitls_tls::connection::TlsServerConnection<std::net::TcpStream>,
    quiet: bool,
    key_update: bool,
    post_handshake_auth: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    conn.handshake()?;
    print_established(conn, quiet);

    let mut buf = vec![0u8; 16384];
    loop {
        match conn.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if !quiet {
                    eprint!("< {}", String::from_utf8_lossy(&buf[..n]));
                }
                if key_update && contains(&buf[..n], b"/keyupdate") {
                    if !quiet {
                        eprintln!("[T122] /keyupdate -> post-handshake KeyUpdate");
                    }
                    conn.key_update(true)?;
                }
                if post_handshake_auth && contains(&buf[..n], b"/secret") {
                    if !quiet {
                        eprintln!("[T125] /secret -> post-handshake client auth");
                    }
                    conn.request_client_auth()?;
                }
                conn.write(&buf[..n])?;
            }
            Err(hitls_types::TlsError::ConnectionClosed) => break,
            Err(hitls_types::TlsError::AlertReceived(_)) => break,
            Err(hitls_types::TlsError::IoError(ref e))
                if e.kind() == std::io::ErrorKind::ConnectionReset =>
            {
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }

    let _ = conn.shutdown();
    Ok(())
}

/// Parse a comma-separated cipher-suite list (Phase T96).
///
/// Each token is either:
/// - an IANA name (e.g. `TLS_RSA_WITH_AES_128_CBC_SHA`,
///   `TLS_AES_128_GCM_SHA256`) — case-insensitive prefix match against
///   the `CipherSuite::*` constants, or
/// - a 16-bit hex codepoint (e.g. `0xC02F`, `0x002F`).
///
/// Whitespace around commas is ignored. Empty tokens are skipped.
fn parse_cipher_suite_list(s: &str) -> Result<Vec<CipherSuite>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for raw in s.split(',') {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        // Hex codepoint?
        if let Some(hex) = token
            .strip_prefix("0x")
            .or_else(|| token.strip_prefix("0X"))
        {
            let v = u16::from_str_radix(hex, 16)
                .map_err(|e| format!("--cipher-suites: bad hex '{token}': {e}"))?;
            out.push(CipherSuite(v));
            continue;
        }
        // Named lookup — case-insensitive against the IANA names tracked
        // in `CipherSuite` constants. We hand-roll the table to avoid
        // pulling in a reflection crate; the listed entries are the
        // tlsfuzzer-relevant ones (TLS 1.2 + 1.3 ECDHE / RSA / CBC / GCM /
        // CHACHA20). Add to this map as new tlsfuzzer scripts surface
        // additional cipher requirements.
        let upper = token.to_ascii_uppercase();
        let suite = match upper.as_str() {
            // TLS 1.3
            "TLS_AES_128_GCM_SHA256" => CipherSuite::TLS_AES_128_GCM_SHA256,
            "TLS_AES_256_GCM_SHA384" => CipherSuite::TLS_AES_256_GCM_SHA384,
            "TLS_CHACHA20_POLY1305_SHA256" => CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
            // TLS 1.2 — ECDHE-AEAD
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => {
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            }
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => {
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            }
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => {
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            }
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => {
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            }
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
                CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            }
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => {
                CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            }
            // TLS 1.2 — ECDHE-CBC-SHA / SHA256 / SHA384
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" => CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" => CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" => {
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
            }
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" => {
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
            }
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" => {
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
            }
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" => {
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
            }
            // TLS 1.2 — RSA static / DHE (legacy, mostly for tlsfuzzer)
            "TLS_RSA_WITH_AES_128_CBC_SHA" => CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" => CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            // SCSV (used by tlsfuzzer ClientHello to signal renegotiation
            // info — we ignore it server-side; including for completeness)
            "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" => CipherSuite(0x00FF),
            other => {
                return Err(format!(
                    "--cipher-suites: unknown cipher name '{other}'; \
                     use a 0xNNNN hex codepoint or extend `parse_cipher_suite_list`"
                )
                .into());
            }
        };
        out.push(suite);
    }
    if out.is_empty() {
        return Err("--cipher-suites: empty list (after trimming)".into());
    }
    Ok(out)
}

fn pkcs8_to_server_key(
    key: Pkcs8PrivateKey,
) -> Result<ServerPrivateKey, Box<dyn std::error::Error>> {
    match key {
        Pkcs8PrivateKey::Rsa(rsa) | Pkcs8PrivateKey::RsaPss(rsa) => {
            // Phase T107 — both PSS-OID and rsaEncryption-OID PKCS#8
            // RSA keys map to the same `ServerPrivateKey::Rsa` wire
            // representation. The OID difference is captured
            // separately on `TlsConfig::server_cert_is_rsa_pss` so
            // the handshake layer can pick the right sig-alg family.
            Ok(ServerPrivateKey::Rsa {
                n: rsa.n_bytes(),
                d: rsa.d_bytes(),
                e: rsa.e_bytes(),
                p: rsa.p_bytes(),
                q: rsa.q_bytes(),
            })
        }
        Pkcs8PrivateKey::Ec { curve_id, key_pair } => Ok(ServerPrivateKey::Ecdsa {
            curve_id,
            private_key: key_pair.private_key_bytes(),
        }),
        Pkcs8PrivateKey::Ed25519(kp) => Ok(ServerPrivateKey::Ed25519(kp.seed().to_vec())),
        Pkcs8PrivateKey::Ed448(kp) => Ok(ServerPrivateKey::Ed448(kp.seed().to_vec())),
        Pkcs8PrivateKey::Sm2(_) => {
            // s_server is built without TLCP today (only tls12 + tls13 features
            // on hitls-tls), so SM2 server keys are not supported here.
            Err("SM2 server keys are not supported by s_server (TLCP feature not enabled)".into())
        }
        Pkcs8PrivateKey::X25519(_)
        | Pkcs8PrivateKey::X448(_)
        | Pkcs8PrivateKey::Dsa { .. }
        | Pkcs8PrivateKey::Dh { .. } => Err(
            "unsupported key type for TLS server (X25519/X448/DSA/DH not valid for signing)".into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_pki::pkcs8;

    use hitls_utils::hex::hex;

    #[test]
    fn test_pkcs8_to_server_key_ed25519() {
        let seed = [0x42u8; 32];
        let der = pkcs8::encode_ed25519_pkcs8_der(&seed);
        let key = pkcs8::parse_pkcs8_der(&der).unwrap();
        let server_key = pkcs8_to_server_key(key).unwrap();
        match &server_key {
            ServerPrivateKey::Ed25519(s) => assert_eq!(*s, seed.to_vec()),
            _ => panic!("expected Ed25519"),
        }
    }

    #[test]
    fn test_pkcs8_to_server_key_rsa() {
        let pem = "\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCvU/3U/Xy0GV9p
alx4PRscBL/vllV808hJ6RKS8dDDqQYghIkqhSAMZTWltzM6J9zPzbaHGp99mrhC
yuUpWCt74SLYhpc1b2a4Oro8VWIihRpPQ1EGgjWZ8tShKDLtmhh+ewYMwHawX5RE
3KynwTfS1ajHLRvxTaftn5ZdVfIVpoiIiBpZ73QFABhZxI6dxvu6TDbcDTjqTExj
HjmsyEvUa2PyL+JSglg/MZNBONYSFIaezkpcdFa6FMx6XW4iVz561IMBdVBEc6II
7qWoQJa+lPsKEFQ8P+iG2uvZQSIboddLdOl9IEGZ4EHcMJTzxh17GaCA7BE/Mlsc
7BYph9wTAgMBAAECggEAVHY2ZGpfLlXAyIQ0Grp5OlSxcAZwlWti4/QzffWfN/rP
mE+w0nqCV2ZUY0ovk/cLIVJ8+XXiWnx0Ar1Ci1nNzOZGxp+D7XqGtf6YpCMP3QhZ
BdEskeGdV9YLB73ZVuwym4/BeNgo9Ut+HnReeowSy+8g2R7KhML/wHHuWnViY3nj
hRnd2tit+y8MQcz8fOcgTT6Uuk6XeEutDMN7FoiLIyNX+mKWtsJbeLFWpHVm9ZM/
R7wa4T/NeFVhfJbJ9YTrZDeLX2dm+F6ynYTJXZvl5KX/pDtQDMkCjadtDOVoc3S1
LYEXAq6F7rcw+S8T0sDrZxGOUw8xAWUmUlL2oSKpOQKBgQDIrom9u3bdJrzglRDP
QuA/dx4IFuZOUaVYPG3NgG/XGtx1yKF2p+XqSWI1wb4fe59S6oJj9KhUKpEZYFoW
c9zgVtl9NsU1gtXfSAuy0pAwTOTdFDzO+b9IIg6zGrh0UT83Ett/zoU2OZWej7xk
ZxCLTZ7lXav+OwquIMMsjFW3KQKBgQDfqFNOwGrWrPyLQGBS9uz4IAOysY0Nydd3
9et7ivzgVAj2p3pb8OuCuMhHmCMd7ocIrijCtF5ppNQ9UhkNhq6crlA9L5jRVLd4
GJTjYnnnA2qNGklu51Q/5XHPMTndXmbrE+jq1VLmx7pGd/XEy83gDXNsB4sLsYgH
OLZd+bRM2wKBgE0H0g9mGeYhrHZ4QY+NGA7EZl6si5KcfF82Mt+i4UssIFuFu5SU
NgiMSopf596l0S4+nfZIPySvgiq/dVUQ/EOQksMhdulnYzjlqrflYztnCKJj1kOM
UgQaLpJJO2xKk31MW7zfRPrfd7L5cVMIzKzsCoX4QsC/YQYdxU0gQPahAoGAenii
/bmyB1H8jIg49tVOF+T4AW7mTYmcWo0oYKNQK8r4iZBWGWiInjFvQn0VpbtK6D7u
BQhdtr3Slq2RGG4KybNOLuMUbHRWbwYO6aCwHgcp3pBpa7hy0vZiZtGO3SBnfQyO
+6DK36K45wOjahsr5ieXb62Fv2Z8lW/BtR4aVAcCgYEAicMLTwUle3fprqZy/Bwr
yoGhy+CaKyBWDwF2/JBMFzze9LiOqHkjW4zps4RBaHvRv84AALX0c68HUEuXZUWj
zwS7ekmeex/ZRkHXaFTKnywwOraGSJAlcwAwlMNLCrkZn9wm79fcuaRoBCCYpCZL
5U2HZPvTIa7Iry46elKZq3g=
-----END PRIVATE KEY-----";
        let key = pkcs8::parse_pkcs8_pem(pem).unwrap();
        let server_key = pkcs8_to_server_key(key).unwrap();
        match &server_key {
            ServerPrivateKey::Rsa { n, d, e, p, q } => {
                assert!(!n.is_empty());
                assert!(!d.is_empty());
                assert!(!e.is_empty());
                assert!(!p.is_empty());
                assert!(!q.is_empty());
            }
            _ => panic!("expected RSA"),
        }
    }

    #[test]
    fn test_pkcs8_to_server_key_ec() {
        let private_key = hex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let der = pkcs8::encode_ec_pkcs8_der(hitls_types::EccCurveId::NistP256, &private_key);
        let key = pkcs8::parse_pkcs8_der(&der).unwrap();
        let server_key = pkcs8_to_server_key(key).unwrap();
        match &server_key {
            ServerPrivateKey::Ecdsa {
                curve_id,
                private_key: pk,
            } => {
                assert_eq!(*curve_id, hitls_types::EccCurveId::NistP256);
                assert!(!pk.is_empty());
            }
            _ => panic!("expected ECDSA"),
        }
    }

    #[test]
    fn test_pkcs8_to_server_key_unsupported() {
        let key_bytes = [0x42u8; 32];
        let der = pkcs8::encode_x25519_pkcs8_der(&key_bytes);
        let key = pkcs8::parse_pkcs8_der(&der).unwrap();
        assert!(pkcs8_to_server_key(key).is_err());
    }

    #[test]
    fn test_pkcs8_to_server_key_ed448() {
        let seed = [0x42u8; 57];
        let der = pkcs8::encode_ed448_pkcs8_der(&seed);
        let key = pkcs8::parse_pkcs8_der(&der).unwrap();
        let server_key = pkcs8_to_server_key(key).unwrap();
        match &server_key {
            ServerPrivateKey::Ed448(s) => assert_eq!(s.len(), 57),
            _ => panic!("expected Ed448"),
        }
    }

    #[test]
    fn test_pkcs8_to_server_key_x448_unsupported() {
        let key_bytes = [0x42u8; 56];
        let der = pkcs8::encode_x448_pkcs8_der(&key_bytes);
        let key = pkcs8::parse_pkcs8_der(&der).unwrap();
        assert!(
            pkcs8_to_server_key(key).is_err(),
            "X448 not valid for TLS server signing"
        );
    }

    #[test]
    fn test_pkcs8_to_server_key_ec_p384() {
        // P-384 key
        let private_key = [0x42u8; 48]; // 48 bytes for P-384
        let der = pkcs8::encode_ec_pkcs8_der(hitls_types::EccCurveId::NistP384, &private_key);
        let key = pkcs8::parse_pkcs8_der(&der).unwrap();
        let server_key = pkcs8_to_server_key(key).unwrap();
        match &server_key {
            ServerPrivateKey::Ecdsa {
                curve_id,
                private_key: _,
            } => {
                assert_eq!(*curve_id, hitls_types::EccCurveId::NistP384);
            }
            _ => panic!("expected ECDSA P-384"),
        }
    }

    #[test]
    fn test_s_server_invalid_version() {
        let result = run(
            0,
            "/nonexistent/cert.pem",
            "/nonexistent/key.pem",
            "1.1",
            true,
            None,
            None,
            None,
            0,
            None,
            None,
            None,
            false,
            false,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_s_server_missing_cert() {
        let result = run(
            0,
            "/nonexistent/cert.pem",
            "/nonexistent/key.pem",
            "1.3",
            true,
            None,
            None,
            None,
            0,
            None,
            None,
            None,
            false,
            false,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_s_server_missing_key() {
        // Create a temp cert file to get past cert loading, but key file doesn't exist
        let result = run(
            0,
            "/nonexistent/cert.pem",
            "/nonexistent/key.pem",
            "1.2",
            true,
            None,
            None,
            None,
            0,
            None,
            None,
            None,
            false,
            false,
            false,
        );
        assert!(result.is_err());
    }

    // Phase T96 — `--cipher-suites` parser tests.

    #[test]
    fn test_parse_cipher_suite_list_named() {
        let r = parse_cipher_suite_list("TLS_RSA_WITH_AES_128_CBC_SHA, TLS_AES_128_GCM_SHA256")
            .unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0], CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA);
        assert_eq!(r[1], CipherSuite::TLS_AES_128_GCM_SHA256);
    }

    #[test]
    fn test_parse_cipher_suite_list_hex() {
        let r = parse_cipher_suite_list("0xC02F, 0x002F").unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0], CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        assert_eq!(r[1], CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA);
    }

    #[test]
    fn test_parse_cipher_suite_list_mixed() {
        let r = parse_cipher_suite_list("0xc02b , TLS_AES_256_GCM_SHA384").unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0], CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        assert_eq!(r[1], CipherSuite::TLS_AES_256_GCM_SHA384);
    }

    #[test]
    fn test_parse_cipher_suite_list_unknown_name() {
        assert!(parse_cipher_suite_list("UNKNOWN_NAME").is_err());
    }

    #[test]
    fn test_parse_cipher_suite_list_empty() {
        assert!(parse_cipher_suite_list("  ").is_err());
        assert!(parse_cipher_suite_list("").is_err());
    }

    #[test]
    fn test_parse_cipher_suite_list_bad_hex() {
        assert!(parse_cipher_suite_list("0xZZZZ").is_err());
    }

    // Phase I100 — `--tls auto` ClientHello version sniffing.

    /// Encode a `supported_versions` ClientHello extension body:
    /// a u8-length-prefixed list of u16 versions.
    fn sv_ext(versions: &[u16]) -> Vec<u8> {
        let mut d = vec![(versions.len() * 2) as u8];
        for v in versions {
            d.extend_from_slice(&v.to_be_bytes());
        }
        d
    }

    /// Build a minimal ClientHello wrapped in a TLS plaintext Handshake
    /// record, carrying exactly the given `(ext_type, ext_data)` list.
    fn make_client_hello(exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut ch = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]); // legacy client_version
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0x00); // empty legacy_session_id
        ch.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
        ch.extend_from_slice(&[0x01, 0x00]); // compression: [null]
        let mut ext_blob = Vec::new();
        for (ty, data) in exts {
            ext_blob.extend_from_slice(&ty.to_be_bytes());
            ext_blob.extend_from_slice(&(data.len() as u16).to_be_bytes());
            ext_blob.extend_from_slice(data);
        }
        ch.extend_from_slice(&(ext_blob.len() as u16).to_be_bytes());
        ch.extend_from_slice(&ext_blob);

        let l = ch.len();
        let mut hs = vec![0x01, (l >> 16) as u8, (l >> 8) as u8, l as u8];
        hs.extend_from_slice(&ch);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn test_ch_offers_tls13_true() {
        let rec = make_client_hello(&[(0x002b, sv_ext(&[0x0304, 0x0303]))]);
        assert!(client_hello_offers_tls13(&rec));
    }

    #[test]
    fn test_ch_offers_tls13_false_tls12_only() {
        // supported_versions present but lists only TLS 1.2.
        let rec = make_client_hello(&[(0x002b, sv_ext(&[0x0303]))]);
        assert!(!client_hello_offers_tls13(&rec));
    }

    #[test]
    fn test_ch_offers_tls13_false_no_supported_versions() {
        // A genuine TLS 1.2 ClientHello carries no supported_versions
        // extension at all — must fall back to the 1.2 handler.
        let rec = make_client_hello(&[(0x000d, vec![0x00, 0x02, 0x04, 0x01])]);
        assert!(!client_hello_offers_tls13(&rec));
    }

    #[test]
    fn test_ch_offers_tls13_after_other_extension() {
        // supported_versions located after walking past an unrelated
        // extension proves the extension-list walk is correct.
        let rec = make_client_hello(&[(0x0000, vec![0x00, 0x00]), (0x002b, sv_ext(&[0x0304]))]);
        assert!(client_hello_offers_tls13(&rec));
    }

    #[test]
    fn test_ch_offers_tls13_rejects_truncated() {
        let rec = make_client_hello(&[(0x002b, sv_ext(&[0x0304]))]);
        for cut in [0, 4, 8, 20, rec.len() - 1] {
            assert!(
                !client_hello_offers_tls13(&rec[..cut]),
                "truncated buffer (len {cut}) must not be read as TLS 1.3"
            );
        }
    }

    #[test]
    fn test_ch_offers_tls13_rejects_non_handshake() {
        // An ApplicationData record (0x17), not a Handshake record.
        assert!(!client_hello_offers_tls13(&[
            0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5
        ]));
        assert!(!client_hello_offers_tls13(&[]));
    }

    #[test]
    fn test_s_server_auto_version_accepted() {
        // `--tls auto` is a valid version string: it must get past
        // version validation and fail only at (missing) cert loading.
        let err = run(
            0,
            "/nonexistent/cert.pem",
            "/nonexistent/key.pem",
            "auto",
            true,
            None,
            None,
            None,
            0,
            None,
            None,
            None,
            false,
            false,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("certificate"),
            "auto must reach cert loading, got: {err}"
        );
    }
}
