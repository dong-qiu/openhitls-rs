//! Key display/conversion command (partial implementation).

use std::fs;

pub fn run(input: &str, pubout: bool, text: bool) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read_to_string(input)?;
    let blocks = hitls_utils::pem::parse(&data)?;

    if blocks.is_empty() {
        return Err(format!("no PEM blocks found in {input}").into());
    }

    for block in &blocks {
        println!("--- {} ({} bytes) ---", block.label, block.data.len());
        if text {
            // Hex dump of key data
            for (i, chunk) in block.data.chunks(16).enumerate() {
                print!("    {:04x}: ", i * 16);
                for b in chunk {
                    print!("{b:02x}");
                }
                println!();
            }
        }
        if pubout {
            // Re-encode as PEM
            let pem = hitls_utils::pem::encode(&block.label, &block.data);
            print!("{pem}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_ed25519_key_pem() -> String {
        let seed = [0x42u8; 32];
        let der = hitls_pki::pkcs8::encode_ed25519_pkcs8_der(&seed);
        hitls_utils::pem::encode("PRIVATE KEY", &der)
    }

    #[test]
    fn test_run_no_flags() {
        let pem = make_ed25519_key_pem();
        let tmp = std::env::temp_dir().join("test_pkey_no_flags.pem");
        fs::write(&tmp, &pem).unwrap();
        assert!(run(tmp.to_str().unwrap(), false, false).is_ok());
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_run_text_flag() {
        let pem = make_ed25519_key_pem();
        let tmp = std::env::temp_dir().join("test_pkey_text.pem");
        fs::write(&tmp, &pem).unwrap();
        assert!(run(tmp.to_str().unwrap(), false, true).is_ok());
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_run_pubout_flag() {
        let pem = make_ed25519_key_pem();
        let tmp = std::env::temp_dir().join("test_pkey_pubout.pem");
        fs::write(&tmp, &pem).unwrap();
        assert!(run(tmp.to_str().unwrap(), true, false).is_ok());
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_run_empty_file_error() {
        let tmp = std::env::temp_dir().join("test_pkey_empty.pem");
        fs::write(&tmp, b"").unwrap();
        // Empty file has no PEM blocks → error
        assert!(run(tmp.to_str().unwrap(), false, false).is_err());
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_run_nonexistent_file() {
        assert!(run("/nonexistent_pkey_test/key.pem", false, false).is_err());
    }
}
