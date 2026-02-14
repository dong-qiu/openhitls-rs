//! TLS server command (`s_server`).

use hitls_pki::pkcs8::{parse_pkcs8_pem, Pkcs8PrivateKey};
use hitls_pki::x509::verify::parse_certs_pem;
use hitls_tls::config::{ServerPrivateKey, TlsConfig};
use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
use std::net::TcpListener;

pub fn run(
    port: u16,
    cert_path: &str,
    key_path: &str,
    tls_version: &str,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
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
    let server_key = pkcs8_to_server_key(pkcs8_key)?;

    // Build TLS config
    let mut builder = TlsConfig::builder()
        .role(TlsRole::Server)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false);

    match tls_version {
        "1.3" => {
            builder = builder
                .min_version(TlsVersion::Tls13)
                .max_version(TlsVersion::Tls13)
                .cipher_suites(&[
                    CipherSuite::TLS_AES_256_GCM_SHA384,
                    CipherSuite::TLS_AES_128_GCM_SHA256,
                    CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
                ]);
        }
        "1.2" => {
            builder = builder
                .min_version(TlsVersion::Tls12)
                .max_version(TlsVersion::Tls12)
                .cipher_suites(&[
                    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                    CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                ]);
        }
        other => {
            return Err(
                format!("unsupported TLS version '{other}' (use \"1.2\" or \"1.3\")").into(),
            );
        }
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
                handle_connection(&mut conn, quiet)
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

fn handle_connection(
    conn: &mut dyn TlsConnection,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    conn.handshake()?;

    if !quiet {
        eprintln!("--- TLS connection established ---");
        if let Some(version) = conn.version() {
            eprintln!("  Protocol: {version:?}");
        }
        if let Some(cs) = conn.cipher_suite() {
            eprintln!("  Cipher:   0x{:04X}", cs.0);
        }
        eprintln!("---------------------------------");
    }

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

fn pkcs8_to_server_key(
    key: Pkcs8PrivateKey,
) -> Result<ServerPrivateKey, Box<dyn std::error::Error>> {
    match key {
        Pkcs8PrivateKey::Rsa(rsa) => Ok(ServerPrivateKey::Rsa {
            n: rsa.n_bytes(),
            d: rsa.d_bytes(),
            e: rsa.e_bytes(),
            p: rsa.p_bytes(),
            q: rsa.q_bytes(),
        }),
        Pkcs8PrivateKey::Ec { curve_id, key_pair } => Ok(ServerPrivateKey::Ecdsa {
            curve_id,
            private_key: key_pair.private_key_bytes(),
        }),
        Pkcs8PrivateKey::Ed25519(kp) => Ok(ServerPrivateKey::Ed25519(kp.seed().to_vec())),
        Pkcs8PrivateKey::Ed448(kp) => Ok(ServerPrivateKey::Ed448(kp.seed().to_vec())),
        Pkcs8PrivateKey::X25519(_) | Pkcs8PrivateKey::X448(_) | Pkcs8PrivateKey::Dsa { .. } => Err(
            "unsupported key type for TLS server (X25519/X448/DSA not valid for signing)".into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_pki::pkcs8;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

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
}
