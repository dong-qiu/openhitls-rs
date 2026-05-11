mod digest;
mod mac;
mod parser;

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
        other => {
            return Err(format!("algo '{other}' not yet supported. Available: sha2, hmac").into());
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

    if check {
        if !target.exists() {
            return Err(format!("--check: target does not exist: {}", target.display()).into());
        }
        let current = fs::read_to_string(&target)?;
        if current == source {
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
        let formatted = rustfmt_pass(&source).unwrap_or(source);
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
