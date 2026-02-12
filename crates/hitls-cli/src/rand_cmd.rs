//! Generate random bytes and output as hex or base64.

pub fn run(num: usize, format: &str) -> Result<(), Box<dyn std::error::Error>> {
    if num == 0 || num > 1_048_576 {
        return Err("num must be between 1 and 1048576".into());
    }

    let mut buf = vec![0u8; num];
    getrandom::getrandom(&mut buf).map_err(|e| format!("getrandom failed: {e}"))?;

    match format {
        "hex" => {
            let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
            println!("{hex}");
        }
        "base64" => {
            let encoded = hitls_utils::base64::encode(&buf);
            println!("{encoded}");
        }
        _ => {
            return Err(format!("unsupported format: {format} (use hex or base64)").into());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_rand_hex() {
        // Should not error; output goes to stdout
        run(16, "hex").unwrap();
    }

    #[test]
    fn test_cli_rand_base64() {
        run(16, "base64").unwrap();
    }

    #[test]
    fn test_cli_rand_zero_bytes() {
        assert!(run(0, "hex").is_err());
    }
}
