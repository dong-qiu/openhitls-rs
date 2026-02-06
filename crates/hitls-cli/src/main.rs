use clap::{Parser, Subcommand};

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
        /// Hash algorithm (sha256, sha384, sha512, sm3, etc.).
        #[arg(short, long, default_value = "sha256")]
        algorithm: String,
        /// Input file (use - for stdin).
        file: String,
    },
    /// Symmetric encryption/decryption.
    Enc {
        /// Cipher algorithm (aes-128-cbc, aes-256-gcm, sm4-cbc, etc.).
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
        /// Algorithm (rsa, ec, ed25519, sm2, ml-kem, ml-dsa, etc.).
        #[arg(short, long)]
        algorithm: String,
        /// Key size in bits (for RSA).
        #[arg(short = 'b', long)]
        bits: Option<u32>,
        /// Named curve (for EC algorithms).
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
        /// Host:port to connect to.
        connect: String,
        /// ALPN protocols.
        #[arg(long)]
        alpn: Option<String>,
    },
    /// TLS server.
    SServer {
        /// Port to listen on.
        #[arg(short, long, default_value = "4433")]
        port: u16,
        /// Certificate file.
        #[arg(long)]
        cert: String,
        /// Private key file.
        #[arg(long)]
        key: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Dgst { algorithm, file } => {
            eprintln!("TODO: hash {file} with {algorithm}");
        }
        Commands::Enc {
            cipher,
            decrypt,
            input,
            output,
        } => {
            let op = if *decrypt { "decrypt" } else { "encrypt" };
            eprintln!("TODO: {op} {input} -> {output} with {cipher}");
        }
        Commands::Genpkey {
            algorithm,
            bits,
            curve,
            output,
        } => {
            eprintln!(
                "TODO: generate {algorithm} key (bits={bits:?}, curve={curve:?}, out={output:?})"
            );
        }
        Commands::Pkey {
            input,
            pubout,
            text,
        } => {
            eprintln!("TODO: show key {input} (pubout={pubout}, text={text})");
        }
        Commands::Req {
            new,
            key,
            subj,
            output,
        } => {
            eprintln!("TODO: CSR (new={new}, key={key:?}, subj={subj:?}, out={output:?})");
        }
        Commands::X509 {
            input,
            text,
            fingerprint,
        } => {
            eprintln!("TODO: x509 {input} (text={text}, fp={fingerprint})");
        }
        Commands::Verify { ca_file, cert } => {
            eprintln!("TODO: verify {cert} against {ca_file}");
        }
        Commands::Crl { input, text } => {
            eprintln!("TODO: CRL {input} (text={text})");
        }
        Commands::SClient { connect, alpn } => {
            eprintln!("TODO: TLS client connect to {connect} (alpn={alpn:?})");
        }
        Commands::SServer { port, cert, key } => {
            eprintln!("TODO: TLS server on :{port} (cert={cert}, key={key})");
        }
    }
}
