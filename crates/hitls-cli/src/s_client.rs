//! TLS client connection command (`s_client`).

use hitls_tls::config::TlsConfig;
use hitls_tls::{CipherSuite, TlsConnection, TlsVersion};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

pub fn run(
    connect: &str,
    alpn: Option<&str>,
    tls_version: &str,
    ca_file: Option<&str>,
    insecure: bool,
    http: bool,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (host, addr) = parse_connect(connect)?;

    if !quiet {
        eprintln!("Connecting to {addr}...");
    }

    // Resolve and connect with a 10-second timeout
    let socket_addr = addr
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve '{addr}': {e}"))?
        .next()
        .ok_or_else(|| format!("cannot resolve '{addr}': no addresses found"))?;
    let stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))
        .map_err(|e| format!("cannot connect to '{addr}': {e}"))?;

    // Set read/write timeouts for the handshake
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    if !quiet {
        eprintln!("Connected to {}", stream.peer_addr()?);
    }

    // Build TLS config
    let mut builder = TlsConfig::builder().server_name(&host);

    // Certificate verification
    if insecure {
        builder = builder.verify_peer(false);
    } else if let Some(ca_path) = ca_file {
        let ca_pem = std::fs::read_to_string(ca_path)
            .map_err(|e| format!("cannot read CA file '{ca_path}': {e}"))?;
        let ca_cert = hitls_pki::x509::Certificate::from_pem(&ca_pem)
            .map_err(|e| format!("failed to parse CA certificate: {e}"))?;
        builder = builder.trusted_cert(ca_cert.raw);
    } else {
        // No CA file and not insecure — disable verification with a warning
        if !quiet {
            eprintln!("Warning: no --CAfile specified, disabling certificate verification");
            eprintln!("         use --insecure to suppress this warning");
        }
        builder = builder.verify_peer(false);
    }

    // ALPN protocols
    if let Some(alpn_str) = alpn {
        let protos: Vec<&[u8]> = alpn_str.split(',').map(|s| s.trim().as_bytes()).collect();
        builder = builder.alpn(&protos);
    }

    // Cipher suites and version-specific config
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

    // Dispatch by version — use separate match branches since concrete types differ
    match tls_version {
        "1.3" => {
            let mut conn = hitls_tls::connection::TlsClientConnection::new(stream, config);
            conn.handshake()?;
            if !quiet {
                print_connection_info(&conn);
            }
            if http {
                do_http(&host, &mut conn)?;
            }
            let _ = conn.shutdown();
        }
        "1.2" => {
            let mut conn = hitls_tls::connection12::Tls12ClientConnection::new(stream, config);
            conn.handshake()?;
            if !quiet {
                print_connection_info(&conn);
            }
            if http {
                do_http(&host, &mut conn)?;
            }
            let _ = conn.shutdown();
        }
        _ => unreachable!(),
    }

    if !quiet {
        eprintln!("Connection closed.");
    }

    Ok(())
}

/// Parse "host:port" or "host" (defaults to port 443).
fn parse_connect(connect: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
    if let Some(idx) = connect.rfind(':') {
        let host = &connect[..idx];
        let port = &connect[idx + 1..];
        port.parse::<u16>()
            .map_err(|_| format!("invalid port in '{connect}'"))?;
        Ok((host.to_string(), connect.to_string()))
    } else {
        Ok((connect.to_string(), format!("{connect}:443")))
    }
}

fn print_connection_info(conn: &dyn TlsConnection) {
    eprintln!("--- TLS connection established ---");
    if let Some(version) = conn.version() {
        eprintln!("  Protocol: {version:?}");
    }
    if let Some(cs) = conn.cipher_suite() {
        eprintln!("  Cipher:   0x{:04X}", cs.0);
    }
    eprintln!("---------------------------------");
}

fn do_http(host: &str, conn: &mut dyn TlsConnection) -> Result<(), Box<dyn std::error::Error>> {
    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    conn.write(request.as_bytes())?;

    let mut buf = vec![0u8; 16384];
    loop {
        match conn.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let text = String::from_utf8_lossy(&buf[..n]);
                print!("{text}");
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
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect_with_port() {
        let (host, addr) = parse_connect("google.com:443").unwrap();
        assert_eq!(host, "google.com");
        assert_eq!(addr, "google.com:443");
    }

    #[test]
    fn test_parse_connect_without_port() {
        let (host, addr) = parse_connect("google.com").unwrap();
        assert_eq!(host, "google.com");
        assert_eq!(addr, "google.com:443");
    }

    #[test]
    fn test_parse_connect_custom_port() {
        let (host, addr) = parse_connect("example.com:8443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(addr, "example.com:8443");
    }

    #[test]
    fn test_parse_connect_invalid_port() {
        assert!(parse_connect("example.com:abc").is_err());
    }

    #[test]
    #[ignore] // Requires internet access
    fn test_s_client_tls13_google() {
        run("google.com:443", None, "1.3", None, true, false, true).unwrap();
    }

    #[test]
    #[ignore] // Requires internet access
    fn test_s_client_tls12_google() {
        run("google.com:443", None, "1.2", None, true, false, true).unwrap();
    }

    #[test]
    #[ignore] // Requires internet access
    fn test_s_client_http_get_tls13() {
        run("httpbin.org:443", None, "1.3", None, true, true, true).unwrap();
    }

    #[test]
    #[ignore] // Requires internet access
    fn test_s_client_tls13_cloudflare() {
        run("cloudflare.com:443", None, "1.3", None, true, false, true).unwrap();
    }

    #[test]
    #[ignore] // Requires internet access
    fn test_s_client_tls12_with_alpn() {
        run(
            "google.com:443",
            Some("http/1.1"),
            "1.2",
            None,
            true,
            false,
            true,
        )
        .unwrap();
    }
}
