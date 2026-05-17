//! TLS server command (`s_server`).

use hitls_pki::pkcs8::{parse_pkcs8_pem, Pkcs8PrivateKey};
use hitls_pki::x509::verify::parse_certs_pem;
use hitls_tls::config::{ServerPrivateKey, TlsConfig};
use hitls_tls::crypt::NamedGroup;
use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
use std::net::TcpListener;

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
    // Phase T122/T125 — `--key-update` / `--post-handshake-auth` drive
    // TLS 1.3-only post-handshake messages; reject them up front for a
    // TLS 1.2 listener rather than silently ignoring.
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

    // Build TLS config. Accept the four interop-relevant groups (X25519,
    // P-256, P-384, P-521) by default so external test tools (openssl
    // s_client, tlsfuzzer scripts, browsers, …) don't trigger HRR-on-no-
    // common-group when their first key_share happens to be P-256 / P-384.
    let mut builder = TlsConfig::builder()
        .role(TlsRole::Server)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .server_cert_is_rsa_pss(is_pss_oid)
        .supported_groups(&[
            NamedGroup::X25519,
            NamedGroup::SECP256R1,
            NamedGroup::SECP384R1,
            NamedGroup::SECP521R1,
        ])
        .verify_peer(false);

    // Phase T96 — `--cipher-suites` overrides the per-version defaults
    // when set. Accept comma-separated names or `0xNNNN` hex codepoints.
    let custom_ciphers: Option<Vec<CipherSuite>> = match cipher_suites_arg {
        Some(s) => Some(parse_cipher_suite_list(s)?),
        None => None,
    };

    match tls_version {
        "1.3" => {
            let default_13 = vec![
                CipherSuite::TLS_AES_256_GCM_SHA384,
                CipherSuite::TLS_AES_128_GCM_SHA256,
                CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
                // Phase T105 — register the two AES-CCM TLS 1.3
                // suites in the default list. The crypto layer
                // (`hitls_crypto::modes::ccm`) and AEAD plumbing
                // (`crypt::aead::TlsAeadImpl::AesCcm[8]`) have
                // supported these since project start; only the
                // server's default-cipher list and the CCM-16
                // entry in `CipherSuiteParams::from_suite` were
                // missing pre-T105. Closes 386 conversations in
                // `test-tls13-symetric-ciphers.py`.
                CipherSuite::TLS_AES_128_CCM_SHA256,
                CipherSuite::TLS_AES_128_CCM_8_SHA256,
            ];
            let suites = custom_ciphers.clone().unwrap_or(default_13);
            builder = builder
                .min_version(TlsVersion::Tls13)
                .max_version(TlsVersion::Tls13)
                .cipher_suites(&suites);
        }
        "1.2" => {
            // Phase T96 — pre-T96 the default was ECDHE-AEAD-only, which
            // collides with tlsfuzzer's hardcoded `TLS_RSA_WITH_AES_128_CBC_SHA`.
            // We now also include the legacy CBC-SHA suites so out-of-the-box
            // `s-server --tls 1.2` covers the same surface tlsfuzzer expects.
            // (`--cipher-suites` still overrides if the user wants to pin.)
            let default_12 = vec![
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
            ];
            let suites = custom_ciphers.clone().unwrap_or(default_12);
            builder = builder
                .min_version(TlsVersion::Tls12)
                .max_version(TlsVersion::Tls12)
                .cipher_suites(&suites);
        }
        other => {
            return Err(
                format!("unsupported TLS version '{other}' (use \"1.2\" or \"1.3\")").into(),
            );
        }
    }

    // Phase T96 — `--require-client-cert <CA>` mTLS support.
    if let Some(ca_path) = require_client_cert_ca {
        let ca_pem = std::fs::read_to_string(ca_path)
            .map_err(|e| format!("cannot read client-CA file '{ca_path}': {e}"))?;
        let ca_certs = parse_certs_pem(&ca_pem)
            .map_err(|e| format!("failed to parse client-CA certificate(s): {e}"))?;
        if ca_certs.is_empty() {
            return Err("no client-CA certificates found in file".into());
        }
        for ca in &ca_certs {
            builder = builder.trusted_cert(ca.raw.clone());
        }
        builder = builder.verify_client_cert(true).require_client_cert(true);
    }

    // Phase T98 — `--verify-client-cert <CA>` (optional mTLS, no require).
    // Mutually exclusive with `--require-client-cert`; sending CR is the
    // same, but the server still accepts an empty client Certificate.
    if let Some(ca_path) = verify_client_cert_ca {
        if require_client_cert_ca.is_some() {
            return Err(
                "--verify-client-cert and --require-client-cert are mutually exclusive".into(),
            );
        }
        let ca_pem = std::fs::read_to_string(ca_path)
            .map_err(|e| format!("cannot read client-CA file '{ca_path}': {e}"))?;
        let ca_certs = parse_certs_pem(&ca_pem)
            .map_err(|e| format!("failed to parse client-CA certificate(s): {e}"))?;
        if ca_certs.is_empty() {
            return Err("no client-CA certificates found in file".into());
        }
        for ca in &ca_certs {
            builder = builder.trusted_cert(ca.raw.clone());
        }
        builder = builder.verify_client_cert(true);
    }

    // Phase T96 — `--max-early-data-size N`.
    if max_early_data_size > 0 {
        builder = builder.max_early_data_size(max_early_data_size);
    }

    // Phase T96 — `--ticket-key <hex>`. 32 bytes (AES-256-GCM key).
    if let Some(hex_str) = ticket_key_hex {
        let key_bytes = hitls_utils::hex::hex(hex_str);
        if key_bytes.len() != 32 {
            return Err(format!(
                "--ticket-key must be exactly 32 bytes (64 hex chars); got {} bytes",
                key_bytes.len()
            )
            .into());
        }
        builder = builder.ticket_key(key_bytes);
    }

    // Phase T119 — `--psk <hex>` + `--psk-identity <id>` for TLS 1.3 external
    // PSK (RFC 8446 §4.2.11). Both flags must be set together; identity is
    // an opaque UTF-8 string matched literally against the wire bytes the
    // client sends in `pre_shared_key`. Length validation is deferred to
    // the handshake layer (must equal the negotiated suite's hash output).
    match (psk_hex, psk_identity) {
        (Some(hex_str), Some(id)) => {
            let psk_bytes = hitls_utils::hex::hex(hex_str);
            if psk_bytes.is_empty() {
                return Err("--psk: empty / invalid hex value".into());
            }
            builder = builder.psk(psk_bytes).psk_identity(id.as_bytes().to_vec());
        }
        (Some(_), None) => return Err("--psk requires --psk-identity".into()),
        (None, Some(_)) => return Err("--psk-identity requires --psk".into()),
        (None, None) => {}
    }

    // Phase T96 — `--no-middlebox-compat`.
    if no_middlebox_compat {
        builder = builder.middlebox_compat(false);
    }

    let config = builder.build();

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

        let result = match tls_version {
            "1.3" => {
                let mut conn =
                    hitls_tls::connection::TlsServerConnection::new(stream, config.clone());
                handle_connection_tls13(&mut conn, quiet, key_update, post_handshake_auth)
            }
            "1.2" => {
                let mut conn =
                    hitls_tls::connection12::Tls12ServerConnection::new(stream, config.clone());
                handle_connection(&mut conn, quiet)
            }
            _ => unreachable!(),
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
}
