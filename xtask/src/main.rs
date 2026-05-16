mod cipher;
mod curve25519;
mod dh;
mod digest;
mod dsa;
mod mac;
mod parser;
mod sm4;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::parser::parse_data_file;

#[derive(Parser)]
#[command(version, about = "openHiTLS-rs developer task runner")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    MigrateCTests {
        #[arg(long)]
        algo: String,

        #[arg(
            long,
            default_value = "/Users/dongqiu/Dev/code/openhitls/testcode/sdv/testcase"
        )]
        c_root: PathBuf,

        #[arg(long)]
        out: Option<PathBuf>,

        #[arg(long)]
        check: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::MigrateCTests {
            algo,
            c_root,
            out,
            check,
        } => match migrate(&algo, &c_root, out.as_deref(), check) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

fn migrate(
    algo: &str,
    c_root: &Path,
    out: Option<&Path>,
    check: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (data_file, default_out, generator): (PathBuf, PathBuf, GenFn) = match algo {
        "sha2" => (
            c_root.join("crypto/sha2/test_suite_sdv_eal_md_sha2.data"),
            workspace_root()?.join("crates/hitls-crypto/tests/migrated_sha2.rs"),
            digest::emit_sha2_kat,
        ),
        "hmac" => (
            c_root.join("crypto/hmac/test_suite_sdv_eal_mac_hmac.data"),
            workspace_root()?.join("crates/hitls-crypto/tests/migrated_hmac.rs"),
            mac::emit_hmac_kat,
        ),
        "cmac" => (
            c_root.join("crypto/cmac/test_suite_sdv_eal_mac_cmac.data"),
            workspace_root()?.join("crates/hitls-crypto/tests/migrated_cmac.rs"),
            mac::emit_cmac_kat,
        ),
        "aes" => (
            c_root.join("crypto/aes/test_suite_sdv_eal_aes.data"),
            workspace_root()?.join("crates/hitls-crypto/tests/migrated_aes.rs"),
            cipher::emit_aes_kat,
        ),
        "curve25519" => (
            c_root.join("crypto/curve25519/test_suite_sdv_eal_curve25519.data"),
            workspace_root()?.join("crates/hitls-crypto/tests/migrated_curve25519.rs"),
            curve25519::emit_curve25519_kat,
        ),
        "dsa" => (
            c_root.join("crypto/dsa/test_suite_sdv_eal_dsa.data"),
            workspace_root()?.join("crates/hitls-crypto/tests/migrated_dsa.rs"),
            dsa::emit_dsa_kat,
        ),
        "dh" => (
            c_root.join("crypto/dh/test_suite_sdv_eal_dh.data"),
            workspace_root()?.join("crates/hitls-crypto/tests/migrated_dh.rs"),
            dh::emit_dh_kat,
        ),
        "sm4" => (
            c_root.join("crypto/sm4/test_suite_sdv_eal_sm4.data"),
            workspace_root()?.join("crates/hitls-crypto/tests/migrated_sm4.rs"),
            sm4::emit_sm4_kat,
        ),
        other => {
            return Err(format!(
                "algo '{other}' not yet supported. Available: sha2, hmac, cmac, aes, curve25519, dsa, dh, sm4"
            )
            .into());
        }
    };

    if !data_file.exists() {
        return Err(format!("C data file not found: {}", data_file.display()).into());
    }

    eprintln!("Parsing {}", data_file.display());
    let cases = parse_data_file(&data_file)?;
    eprintln!("  parsed {} TC rows", cases.len());

    let (source, stats) = generator(&cases);
    eprintln!(
        "  emitted {} tests, skipped {} API-surface, {} unknown, {} unsupported-alg",
        stats.emitted, stats.skipped_api, stats.skipped_unknown, stats.skipped_unsupported_alg
    );

    let target = out.map(PathBuf::from).unwrap_or(default_out);
    // Apply rustfmt for both --check and write paths so drift detection
    // matches what gets committed (committed files always go through
    // rustfmt; comparing un-formatted `source` would false-positive).
    let formatted = rustfmt_pass(&source).unwrap_or(source);

    if check {
        if !target.exists() {
            return Err(format!("--check: target does not exist: {}", target.display()).into());
        }
        let current = fs::read_to_string(&target)?;
        if current == formatted {
            eprintln!("up-to-date: {}", target.display());
            Ok(())
        } else {
            Err(format!(
                "out-of-date: {} differs from generator output",
                target.display()
            )
            .into())
        }
    } else {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, &formatted)?;
        eprintln!("Wrote {}", target.display());
        Ok(())
    }
}

/// Pipe `src` through `rustfmt --emit stdout --edition 2021` so generated
/// files match the workspace's rustfmt config. Falls back to the
/// unformatted source if rustfmt is unavailable.
fn rustfmt_pass(src: &str) -> Option<String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("rustfmt")
        .args(["--emit", "stdout", "--edition", "2021"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    child.stdin.as_mut()?.write_all(src.as_bytes()).ok()?;
    let output = child.wait_with_output().ok()?;
    if output.status.success() {
        String::from_utf8(output.stdout).ok()
    } else {
        None
    }
}

type GenFn = fn(&[parser::TestCase]) -> (String, digest::EmitStats);

fn workspace_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Ok(Path::new(manifest)
        .parent()
        .ok_or("xtask Cargo.toml has no parent")?
        .to_path_buf())
}
