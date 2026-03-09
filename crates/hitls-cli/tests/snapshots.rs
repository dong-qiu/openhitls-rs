//! Snapshot tests for CLI output stability using insta.
//!
//! Run with: cargo test -p hitls-cli --test snapshots
//! Update snapshots: cargo insta review

use std::process::Command;

fn cli(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_hitls"))
        .args(args)
        .output()
        .expect("failed to run hitls CLI");
    String::from_utf8(output.stdout).expect("non-UTF8 output")
}

#[test]
fn snapshot_list_hashes() {
    insta::assert_snapshot!(cli(&["list", "hashes"]));
}

#[test]
fn snapshot_list_ciphers() {
    insta::assert_snapshot!(cli(&["list", "ciphers"]));
}

#[test]
fn snapshot_list_curves() {
    insta::assert_snapshot!(cli(&["list", "curves"]));
}

#[test]
fn snapshot_dgst_sha256() {
    // Deterministic: SHA-256 of empty input
    let output = Command::new(env!("CARGO_BIN_EXE_hitls"))
        .args(["dgst", "-sha256"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|child| child.wait_with_output())
        .expect("failed to run hitls dgst");
    let stdout = String::from_utf8(output.stdout).expect("non-UTF8");
    insta::assert_snapshot!(stdout);
}
