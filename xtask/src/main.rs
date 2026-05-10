use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

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
        } => migrate_c_tests(&algo, &c_root, out.as_deref(), check),
    }
}

fn migrate_c_tests(
    algo: &str,
    c_root: &std::path::Path,
    out: Option<&std::path::Path>,
    check: bool,
) -> ExitCode {
    eprintln!("xtask migrate-c-tests");
    eprintln!("  algo:   {algo}");
    eprintln!("  c-root: {}", c_root.display());
    eprintln!(
        "  out:    {}",
        out.map(|p| p.display().to_string())
            .unwrap_or_else(|| "<auto>".to_string())
    );
    eprintln!("  check:  {check}");
    eprintln!();
    eprintln!("Skeleton only — Phase A.1 implementation pending.");
    eprintln!("See docs/c-test-migration-plan.md §2.1 for design.");
    ExitCode::SUCCESS
}
