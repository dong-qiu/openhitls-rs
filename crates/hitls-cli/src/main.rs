use clap::{Parser, Subcommand};

mod crl;
mod dgst;
mod enc;
mod genpkey;
mod kdf;
mod list;
mod mac;
mod pkcs12;
mod pkey;
mod pkeyutl;
mod prime;
mod rand_cmd;
mod req;
mod s_client;
mod s_server;
mod speed;
mod verify;
mod x509cmd;

/// openHiTLS command-line tool for cryptographic operations.
#[derive(Parser)]
#[command(name = "hitls")]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Hash/digest operations.
    Dgst {
        /// Hash algorithm (sha256, sha384, sha512, sm3, md5, sha1, sha3-256, sha3-512).
        #[arg(short, long, default_value = "sha256")]
        algorithm: String,
        /// Input file (use - for stdin).
        file: String,
    },
    /// Symmetric encryption/decryption.
    Enc {
        /// Cipher algorithm (aes-256-gcm).
        #[arg(short, long)]
        cipher: String,
        /// Decrypt mode.
        #[arg(short, long)]
        decrypt: bool,
        /// Input file.
        #[arg(short, long)]
        input: String,
        /// Output file.
        #[arg(short, long)]
        output: String,
    },
    /// Generate a private key.
    Genpkey {
        /// Algorithm (rsa, ec, ed25519, x25519, ml-kem, ml-dsa).
        #[arg(short, long)]
        algorithm: String,
        /// Key size in bits (for RSA).
        #[arg(short = 'b', long)]
        bits: Option<u32>,
        /// Named curve or parameter set (for EC: P-256, P-384; for PQ: 512, 768, 1024, 44, 65, 87).
        #[arg(short, long)]
        curve: Option<String>,
        /// Output file.
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Display or convert a private/public key.
    Pkey {
        /// Input file.
        #[arg(short, long)]
        input: String,
        /// Output public key only.
        #[arg(long)]
        pubout: bool,
        /// Print key details.
        #[arg(short, long)]
        text: bool,
    },
    /// Create a certificate signing request (CSR).
    Req {
        /// Generate a new key and CSR.
        #[arg(long)]
        new: bool,
        /// Key file for CSR signing.
        #[arg(short, long)]
        key: Option<String>,
        /// Subject distinguished name.
        #[arg(short, long)]
        subj: Option<String>,
        /// Output file.
        #[arg(short, long)]
        output: Option<String>,
    },
    /// X.509 certificate operations.
    X509 {
        /// Input certificate file.
        #[arg(short, long)]
        input: String,
        /// Print certificate details.
        #[arg(short, long)]
        text: bool,
        /// Print certificate fingerprint.
        #[arg(long)]
        fingerprint: bool,
    },
    /// Verify a certificate chain.
    Verify {
        /// CA certificate file.
        #[arg(long)]
        ca_file: String,
        /// Certificate to verify.
        cert: String,
    },
    /// CRL operations.
    Crl {
        /// Input CRL file.
        #[arg(short, long)]
        input: String,
        /// Print CRL details.
        #[arg(short, long)]
        text: bool,
    },
    /// TLS client connection.
    SClient {
        /// Host:port to connect to (default port 443).
        connect: String,
        /// ALPN protocols (comma-separated, e.g. "h2,http/1.1").
        #[arg(long)]
        alpn: Option<String>,
        /// TLS version: "1.2" or "1.3".
        #[arg(long = "tls", default_value = "1.3")]
        tls_version: String,
        /// CA certificate file (PEM) for server verification.
        #[arg(long = "CAfile")]
        ca_file: Option<String>,
        /// Skip server certificate verification.
        #[arg(long)]
        insecure: bool,
        /// Send HTTP GET / after handshake and print response.
        #[arg(long)]
        http: bool,
        /// Quiet mode: suppress connection info.
        #[arg(long, short)]
        quiet: bool,
    },
    /// TLS server.
    SServer {
        /// Port to listen on.
        #[arg(short, long, default_value = "4433")]
        port: u16,
        /// Certificate chain file (PEM).
        #[arg(long)]
        cert: String,
        /// Private key file (PEM, PKCS#8).
        #[arg(long)]
        key: String,
        /// TLS version: "1.2", "1.3", or "auto" (peek each
        /// ClientHello and negotiate 1.2 / 1.3 per connection).
        #[arg(long = "tls", default_value = "1.3")]
        tls_version: String,
        /// Quiet mode: suppress connection info.
        #[arg(long, short)]
        quiet: bool,
        // ----- Phase T96 (Tier-1 tlsfuzzer-coverage) flags -----
        /// Comma-separated cipher suite names or hex codepoints
        /// (e.g. `TLS_RSA_WITH_AES_128_CBC_SHA,0xC02F`). Falls back
        /// to per-version defaults when omitted. Used to drive
        /// tlsfuzzer scripts that hard-code legacy CBC-SHA suites.
        #[arg(long = "cipher-suites")]
        cipher_suites: Option<String>,
        /// Require + verify a client certificate (mTLS). The argument
        /// is a path to a CA bundle (PEM) used to validate the
        /// client cert chain. Implies `verify_client_cert=true` AND
        /// `require_client_cert=true`.
        #[arg(long = "require-client-cert")]
        require_client_cert: Option<String>,
        /// Verify a client certificate **only when offered** (optional
        /// mTLS). Same CA-bundle argument as `--require-client-cert`,
        /// but the server still accepts handshakes from peers that
        /// reply with an empty Certificate. Used by tlsfuzzer scripts
        /// that exercise both the present-cert and no-cert paths
        /// (e.g. `test-tls13-certificate-request.py` sanity).
        #[arg(long = "verify-client-cert")]
        verify_client_cert: Option<String>,
        /// Maximum size (bytes) the server advertises for TLS 1.3
        /// `early_data` in NewSessionTicket. Default 0 (no 0-RTT).
        /// Set to e.g. 16384 to accept 0-RTT data.
        #[arg(long = "max-early-data-size", default_value = "0")]
        max_early_data_size: u32,
        /// 32-byte hex resumption ticket key (TLS 1.3 NST encryption).
        /// When set, deterministic key enables session resumption
        /// across processes; when omitted a fresh random key is used.
        #[arg(long = "ticket-key")]
        ticket_key: Option<String>,
        /// External pre-shared key (hex), used with `--psk-identity`
        /// for TLS 1.3 out-of-band PSK authentication (RFC 8446 §4.2.11,
        /// Phase T119). Length MUST equal the negotiated suite's hash
        /// output: 32 bytes for SHA-256 suites, 48 bytes for SHA-384.
        #[arg(long = "psk")]
        psk: Option<String>,
        /// Identity string sent by the client in the `pre_shared_key`
        /// extension. Matched literally against the configured `--psk`.
        #[arg(long = "psk-identity")]
        psk_identity: Option<String>,
        /// Phase T122 — server-initiated post-handshake KeyUpdate.
        /// When set, a client request whose bytes contain the path
        /// marker `/keyupdate` makes the server send a KeyUpdate
        /// (`update_requested`) before echoing. A plain `GET /` is
        /// echoed with no KeyUpdate, so tlsfuzzer sanity steps still
        /// pass — the discriminator is the request path, not the
        /// mere presence of application data. TLS 1.3 only.
        #[arg(long = "key-update")]
        key_update: bool,
        /// Phase T125 — server-initiated post-handshake client
        /// authentication (RFC 8446 §4.6.2). When set, a client request
        /// whose bytes contain the path marker `/secret` makes the
        /// server send a post-handshake CertificateRequest and read +
        /// verify the client's Certificate / CertificateVerify /
        /// Finished. A plain `GET /` is echoed untouched, so sanity
        /// steps still pass. TLS 1.3 only.
        #[arg(long = "post-handshake-auth")]
        post_handshake_auth: bool,
        /// Disable RFC 8446 §D.4 middlebox-compat dummy CCS. By
        /// default the server emits the fake CCS after ServerHello /
        /// HelloRetryRequest; with this flag set we skip it (and
        /// reject any CCS the peer sends).
        #[arg(long = "no-middlebox-compat")]
        no_middlebox_compat: bool,
        /// Listen as a DTLS 1.2 server over UDP instead of TLS over
        /// TCP. The cert/key and cipher-suite flags apply unchanged;
        /// `--tls` is ignored (DTLS 1.2 only).
        #[arg(long)]
        dtls: bool,
        /// Advertise TLS Certificate Compression (RFC 8879, zlib). When
        /// set, if the client offers `compress_certificate` with zlib the
        /// server sends a CompressedCertificate instead of Certificate.
        #[arg(long = "cert-compression")]
        cert_compression: bool,
    },
    /// List supported algorithms and cipher suites.
    List {
        /// Filter: all, ciphers, hashes, curves, kex.
        #[arg(short, long, default_value = "all")]
        filter: String,
    },
    /// Generate random bytes.
    Rand {
        /// Number of bytes to generate.
        #[arg(short, long, default_value = "32")]
        num: usize,
        /// Output format: hex or base64.
        #[arg(short, long, default_value = "hex")]
        format: String,
    },
    /// Public key utility (sign/verify/encrypt/decrypt/derive).
    Pkeyutl {
        /// Operation: sign, verify, encrypt, decrypt, derive.
        #[arg(short = 'O', long)]
        op: String,
        /// Input file.
        #[arg(short, long)]
        input: String,
        /// Output file.
        #[arg(short, long)]
        output: Option<String>,
        /// Private key file (PKCS#8 PEM).
        #[arg(long)]
        inkey: String,
        /// Peer public key file (for derive).
        #[arg(long)]
        peerkey: Option<String>,
        /// Signature file (for verify).
        #[arg(long)]
        sigfile: Option<String>,
    },
    /// PKCS#12 operations (parse, extract, create).
    Pkcs12 {
        /// Input P12 file.
        #[arg(short, long)]
        input: Option<String>,
        /// Password for the P12 file.
        #[arg(short, long, default_value = "")]
        password: String,
        /// Display P12 info (num certs, key presence).
        #[arg(long)]
        info: bool,
        /// Suppress private key output.
        #[arg(long)]
        nokeys: bool,
        /// Suppress certificate output.
        #[arg(long)]
        nocerts: bool,
        /// Export mode: create P12 from key + cert.
        #[arg(long)]
        export: bool,
        /// Private key file (PEM) for export.
        #[arg(long)]
        inkey: Option<String>,
        /// Certificate file (PEM) for export.
        #[arg(long)]
        cert: Option<String>,
        /// Output file.
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Compute MAC (HMAC/CMAC) over a file.
    Mac {
        /// MAC algorithm (hmac-sha256, hmac-sha384, hmac-sha512, hmac-sm3, hmac-sha1, cmac-aes128, cmac-aes256).
        #[arg(short, long, default_value = "hmac-sha256")]
        algorithm: String,
        /// Key in hexadecimal.
        #[arg(short, long)]
        key: String,
        /// Input file (use - for stdin).
        file: String,
    },
    /// Prime number generation and testing.
    Prime {
        /// Generate a prime number.
        #[arg(long)]
        generate: bool,
        /// Number of bits for generated prime.
        #[arg(short, long)]
        bits: Option<usize>,
        /// Generate a safe prime (p and (p-1)/2 both prime).
        #[arg(long)]
        safe: bool,
        /// Use hexadecimal format for input/output.
        #[arg(long)]
        hex: bool,
        /// Number of Miller-Rabin checks (default 20).
        #[arg(long)]
        checks: Option<usize>,
        /// Number to test for primality.
        number: Option<String>,
    },
    /// Key derivation function (PBKDF2).
    Kdf {
        /// KDF algorithm (pbkdf2).
        #[arg(default_value = "pbkdf2")]
        algorithm: String,
        /// MAC algorithm (hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512, hmac-sm3).
        #[arg(long, default_value = "hmac-sha256")]
        mac: String,
        /// Password.
        #[arg(long)]
        pass: String,
        /// Salt.
        #[arg(long)]
        salt: String,
        /// Number of iterations.
        #[arg(long, default_value = "10000")]
        iter: u32,
        /// Output key length in bytes.
        #[arg(long, default_value = "32")]
        keylen: usize,
        /// Output file (default: stdout).
        #[arg(long)]
        out: Option<String>,
        /// Output raw binary instead of hex.
        #[arg(long)]
        binary: bool,
        /// Interpret --pass as hex.
        #[arg(long)]
        hexpass: bool,
        /// Interpret --salt as hex.
        #[arg(long)]
        hexsalt: bool,
    },
    /// Benchmark cryptographic algorithm throughput.
    Speed {
        /// Algorithm: aes-128-gcm, aes-256-gcm, chacha20-poly1305, sha256, sha384, sha512, sm3, all.
        #[arg(default_value = "all")]
        algorithm: String,
        /// Duration in seconds.
        #[arg(short, long, default_value = "3")]
        seconds: u64,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::Dgst { algorithm, file } => dgst::run(algorithm, file),
        Commands::Enc {
            cipher,
            decrypt,
            input,
            output,
        } => enc::run(cipher, *decrypt, input, output),
        Commands::Genpkey {
            algorithm,
            bits,
            curve,
            output,
        } => genpkey::run(algorithm, *bits, curve.as_deref(), output.as_deref()),
        Commands::Pkey {
            input,
            pubout,
            text,
        } => pkey::run(input, *pubout, *text),
        Commands::Req {
            new,
            key,
            subj,
            output,
        } => req::run(*new, key.as_deref(), subj.as_deref(), output.as_deref()),
        Commands::X509 {
            input,
            text,
            fingerprint,
        } => x509cmd::run(input, *text, *fingerprint),
        Commands::Verify { ca_file, cert } => verify::run(ca_file, cert),
        Commands::Crl { input, text } => crl::run(input, *text),
        Commands::SClient {
            connect,
            alpn,
            tls_version,
            ca_file,
            insecure,
            http,
            quiet,
        } => s_client::run(
            connect,
            alpn.as_deref(),
            tls_version,
            ca_file.as_deref(),
            *insecure,
            *http,
            *quiet,
        ),
        Commands::SServer {
            port,
            cert,
            key,
            tls_version,
            quiet,
            cipher_suites,
            require_client_cert,
            verify_client_cert,
            max_early_data_size,
            ticket_key,
            psk,
            psk_identity,
            key_update,
            post_handshake_auth,
            no_middlebox_compat,
            dtls,
            cert_compression,
        } => s_server::run(
            *port,
            cert,
            key,
            tls_version,
            *quiet,
            cipher_suites.as_deref(),
            require_client_cert.as_deref(),
            verify_client_cert.as_deref(),
            *max_early_data_size,
            ticket_key.as_deref(),
            psk.as_deref(),
            psk_identity.as_deref(),
            *key_update,
            *post_handshake_auth,
            *no_middlebox_compat,
            *dtls,
            *cert_compression,
        ),
        Commands::List { filter } => list::run(filter),
        Commands::Rand { num, format } => rand_cmd::run(*num, format),
        Commands::Pkeyutl {
            op,
            input,
            output,
            inkey,
            peerkey,
            sigfile,
        } => pkeyutl::run(
            op,
            input,
            output.as_deref(),
            inkey,
            peerkey.as_deref(),
            sigfile.as_deref(),
        ),
        Commands::Pkcs12 {
            input,
            password,
            info,
            nokeys,
            nocerts,
            export,
            inkey,
            cert,
            output,
        } => pkcs12::run(&pkcs12::Pkcs12Options {
            input: input.as_deref(),
            password,
            info: *info,
            nokeys: *nokeys,
            nocerts: *nocerts,
            export: *export,
            inkey: inkey.as_deref(),
            cert_file: cert.as_deref(),
            output: output.as_deref(),
        }),
        Commands::Mac {
            algorithm,
            key,
            file,
        } => mac::run(algorithm, key, file),
        Commands::Prime {
            generate,
            bits,
            safe,
            hex,
            checks,
            number,
        } => prime::run(&prime::PrimeArgs {
            generate: *generate,
            bits: *bits,
            safe: *safe,
            hex: *hex,
            checks: *checks,
            number: number.clone(),
        }),
        Commands::Kdf {
            algorithm,
            mac,
            pass,
            salt,
            iter,
            keylen,
            out,
            binary,
            hexpass,
            hexsalt,
        } => kdf::run(&kdf::KdfArgs {
            algorithm: algorithm.clone(),
            mac: mac.clone(),
            pass: pass.clone(),
            salt: salt.clone(),
            iter: *iter,
            keylen: *keylen,
            out: out.clone(),
            binary: *binary,
            hexpass: *hexpass,
            hexsalt: *hexsalt,
        }),
        Commands::Speed { algorithm, seconds } => speed::run(algorithm, *seconds),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
