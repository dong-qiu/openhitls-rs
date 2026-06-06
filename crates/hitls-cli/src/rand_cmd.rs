//! Generate random bytes and output as hex, base64, or raw binary.

use std::fs;
use std::io::Write;

pub fn run(num: usize, format: &str, out: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    if num == 0 || num > 1_048_576 {
        return Err("num must be between 1 and 1048576".into());
    }

    let mut buf = vec![0u8; num];
    getrandom::fill(&mut buf).map_err(|e| format!("getrandom failed: {e}"))?;

    match format {
        "hex" => write_text(&hitls_utils::hex::to_hex(&buf), out),
        "base64" => write_text(&hitls_utils::base64::encode(&buf), out),
        "binary" => write_binary(&buf, out),
        _ => Err(format!("unsupported format: {format} (use hex, base64, or binary)").into()),
    }
}

fn write_text(s: &str, out: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    match out {
        Some(path) => Ok(fs::write(path, s)?),
        None => {
            println!("{s}");
            Ok(())
        }
    }
}

fn write_binary(buf: &[u8], out: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    match out {
        Some(path) => Ok(fs::write(path, buf)?),
        None => Ok(std::io::stdout().write_all(buf)?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("hitls_rand_test_{name}"))
    }

    #[test]
    fn test_cli_rand_hex() {
        run(16, "hex", None).unwrap();
    }

    #[test]
    fn test_cli_rand_base64() {
        run(16, "base64", None).unwrap();
    }

    #[test]
    fn test_cli_rand_zero_bytes() {
        let err = run(0, "hex", None).unwrap_err();
        assert_eq!(err.to_string(), "num must be between 1 and 1048576");
    }

    // ---- C SDV migrated / boundary tests ----

    // num upper bound + 1 → INVALID_ARG (C TC003 spirit: out-of-range size)
    #[test]
    fn test_cli_rand_too_large() {
        let err = run(1_048_577, "hex", None).unwrap_err();
        assert_eq!(err.to_string(), "num must be between 1 and 1048576");
    }

    // num at lower bound (1) → SUCCESS
    #[test]
    fn test_cli_rand_at_lower_bound() {
        run(1, "hex", None).unwrap();
    }

    // num at upper bound (1 MiB) → SUCCESS
    #[test]
    fn test_cli_rand_at_upper_bound() {
        run(1_048_576, "hex", None).unwrap();
    }

    // unknown format → specific error message (C TC003 spirit)
    #[test]
    fn test_cli_rand_unknown_format() {
        let err = run(16, "yaml", None).unwrap_err();
        assert_eq!(
            err.to_string(),
            "unsupported format: yaml (use hex, base64, or binary)"
        );
    }

    // binary stdout path → SUCCESS (C TC001: `rand 10` defaults to binary)
    #[test]
    fn test_cli_rand_binary_stdout() {
        run(16, "binary", None).unwrap();
    }

    // -out hex (C TC001 / TC0013: `rand -out TC001_hex.txt -hex 10`)
    #[test]
    fn test_cli_rand_hex_to_file() {
        let path = tmp("hex.txt");
        let path_s = path.to_str().unwrap();
        run(32, "hex", Some(path_s)).unwrap();
        let written = fs::read_to_string(&path).unwrap();
        assert_eq!(written.trim().len(), 64, "32 bytes → 64 hex chars");
        assert!(written.chars().all(|c| c.is_ascii_hexdigit()));
        let _ = fs::remove_file(&path);
    }

    // -out base64 (C TC001 / TC0013)
    #[test]
    fn test_cli_rand_base64_to_file() {
        let path = tmp("b64.txt");
        let path_s = path.to_str().unwrap();
        run(33, "base64", Some(path_s)).unwrap();
        let written = fs::read_to_string(&path).unwrap();
        let decoded = hitls_utils::base64::decode(written.trim()).unwrap();
        assert_eq!(decoded.len(), 33);
        let _ = fs::remove_file(&path);
    }

    // -out binary (C TC001 / TC0013: `rand -out TC001_binary.txt 10`)
    #[test]
    fn test_cli_rand_binary_to_file() {
        let path = tmp("bin.dat");
        let path_s = path.to_str().unwrap();
        run(32, "binary", Some(path_s)).unwrap();
        let written = fs::read(&path).unwrap();
        assert_eq!(written.len(), 32);
        let _ = fs::remove_file(&path);
    }

    // -out to an unwritable path → I/O error (C TC007 spirit: UIO_FAIL).
    // Use a path that does not exist as a parent directory; assertion accepts
    // both POSIX "No such file or directory" (errno 2) and Windows
    // "The system cannot find the path specified. (os error 3)".
    #[test]
    fn test_cli_rand_out_unwritable_dir() {
        let path = tmp("nonexistent_subdir").join("out.txt");
        let err = run(16, "hex", path.to_str()).unwrap_err();
        let s = err.to_string();
        assert!(
            s.contains("No such file") || s.contains("cannot find"),
            "expected POSIX/Windows 'path not found' I/O error, got: {s}"
        );
    }
}
