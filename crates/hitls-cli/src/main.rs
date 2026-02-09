use clap::{Parser, Subcommand};

mod crl;
mod dgst;
mod enc;
mod genpkey;
mod pkey;
mod req;
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
        Commands::SClient { connect, alpn } => {
            eprintln!("TLS client is not yet implemented (connect={connect}, alpn={alpn:?})");
            Ok(())
        }
        Commands::SServer { port, cert, key } => {
            eprintln!("TLS server is not yet implemented (port={port}, cert={cert}, key={key})");
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
