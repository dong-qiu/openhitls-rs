//! MAC computation command implementation.

use std::fs;
use std::io::{self, Read};

pub fn run(algorithm: &str, key_hex: &str, file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let key = hex_decode(key_hex)?;

    let data = if file == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        fs::read(file)?
    };

    let (mac_value, alg_name) = compute_mac(algorithm, &key, &data)?;

    let hex = mac_value
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if file == "-" {
        println!("{alg_name}(stdin)= {hex}");
    } else {
        println!("{alg_name}({file})= {hex}");
    }
    Ok(())
}

fn hex_decode(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if s.len() % 2 != 0 {
        return Err("hex key must have even length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at offset {i}: {e}").into())
        })
        .collect()
}

fn compute_mac(
    algorithm: &str,
    key: &[u8],
    data: &[u8],
) -> Result<(Vec<u8>, &'static str), Box<dyn std::error::Error>> {
    use hitls_crypto::hmac::Hmac;
    use hitls_crypto::provider::Digest;

    match algorithm.to_lowercase().as_str() {
        "hmac-sha1" => {
            let mac = Hmac::mac(
                || -> Box<dyn Digest> { Box::new(hitls_crypto::sha1::Sha1::new()) },
                key,
                data,
            )?;
            Ok((mac, "HMAC-SHA1"))
        }
        "hmac-sha256" => {
            let mac = Hmac::mac(
                || -> Box<dyn Digest> { Box::new(hitls_crypto::sha2::Sha256::new()) },
                key,
                data,
            )?;
            Ok((mac, "HMAC-SHA256"))
        }
        "hmac-sha384" => {
            let mac = Hmac::mac(
                || -> Box<dyn Digest> { Box::new(hitls_crypto::sha2::Sha384::new()) },
                key,
                data,
            )?;
            Ok((mac, "HMAC-SHA384"))
        }
        "hmac-sha512" => {
            let mac = Hmac::mac(
                || -> Box<dyn Digest> { Box::new(hitls_crypto::sha2::Sha512::new()) },
                key,
                data,
            )?;
            Ok((mac, "HMAC-SHA512"))
        }
        "hmac-sm3" => {
            let mac = Hmac::mac(
                || -> Box<dyn Digest> { Box::new(hitls_crypto::sm3::Sm3::new()) },
                key,
                data,
            )?;
            Ok((mac, "HMAC-SM3"))
        }
        "cmac-aes128" => {
            if key.len() != 16 {
                return Err("CMAC-AES128 requires a 16-byte key".into());
            }
            let mut cmac = hitls_crypto::cmac::Cmac::new(key)?;
            cmac.update(data)?;
            let mut out = vec![0u8; 16];
            cmac.finish(&mut out)?;
            Ok((out, "CMAC-AES128"))
        }
        "cmac-aes256" => {
            if key.len() != 32 {
                return Err("CMAC-AES256 requires a 32-byte key".into());
            }
            let mut cmac = hitls_crypto::cmac::Cmac::new(key)?;
            cmac.update(data)?;
            let mut out = vec![0u8; 16];
            cmac.finish(&mut out)?;
            Ok((out, "CMAC-AES256"))
        }
        _ => Err(format!(
            "unsupported MAC algorithm: {algorithm}\n\
             Supported: hmac-sha1, hmac-sha256, hmac-sha384, hmac-sha512, hmac-sm3, \
             cmac-aes128, cmac-aes256"
        )
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_hmac_sha256() {
        let tmp = std::env::temp_dir().join("test_mac_hmac256.dat");
        std::fs::write(&tmp, b"test data").unwrap();
        let result = run(
            "hmac-sha256",
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            tmp.to_str().unwrap(),
        );
        assert!(result.is_ok());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_mac_hmac_sha384() {
        let tmp = std::env::temp_dir().join("test_mac_hmac384.dat");
        std::fs::write(&tmp, b"test data").unwrap();
        let result = run(
            "hmac-sha384",
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            tmp.to_str().unwrap(),
        );
        assert!(result.is_ok());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_mac_cmac_aes128() {
        let tmp = std::env::temp_dir().join("test_mac_cmac128.dat");
        std::fs::write(&tmp, b"test data").unwrap();
        // 16-byte key for AES-128
        let result = run(
            "cmac-aes128",
            "000102030405060708090a0b0c0d0e0f",
            tmp.to_str().unwrap(),
        );
        assert!(result.is_ok());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_mac_cmac_aes256() {
        let tmp = std::env::temp_dir().join("test_mac_cmac256.dat");
        std::fs::write(&tmp, b"test data").unwrap();
        // 32-byte key for AES-256
        let result = run(
            "cmac-aes256",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            tmp.to_str().unwrap(),
        );
        assert!(result.is_ok());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_mac_unsupported_algorithm() {
        let tmp = std::env::temp_dir().join("test_mac_unsup.dat");
        std::fs::write(&tmp, b"test data").unwrap();
        let result = run("hmac-md5", "aabbccdd", tmp.to_str().unwrap());
        assert!(result.is_err());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_mac_cmac_wrong_key_length() {
        let tmp = std::env::temp_dir().join("test_mac_wrongkey.dat");
        std::fs::write(&tmp, b"test data").unwrap();
        // 8-byte key (too short for AES-128)
        let result = run("cmac-aes128", "0011223344556677", tmp.to_str().unwrap());
        assert!(result.is_err());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_hex_decode() {
        assert_eq!(hex_decode("0011ff").unwrap(), vec![0x00, 0x11, 0xff]);
        assert!(hex_decode("0g").is_err()); // invalid hex
        assert!(hex_decode("0").is_err()); // odd length
    }
}
