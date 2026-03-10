//! KDF (Key Derivation Function) command implementation.

use hitls_crypto::pbkdf2::pbkdf2_with_hmac;
use hitls_crypto::provider::Digest;

pub fn run(args: &KdfArgs) -> Result<(), Box<dyn std::error::Error>> {
    match args.algorithm.to_lowercase().as_str() {
        "pbkdf2" => run_pbkdf2(args),
        _ => Err(format!("unsupported KDF algorithm: {}", args.algorithm).into()),
    }
}

fn run_pbkdf2(args: &KdfArgs) -> Result<(), Box<dyn std::error::Error>> {
    let factory = match args.mac.to_lowercase().as_str() {
        "hmac-sha1" | "hmac-sha-1" => sha1_factory as fn() -> Box<dyn Digest>,
        "hmac-sha224" | "hmac-sha-224" => sha224_factory as fn() -> Box<dyn Digest>,
        "hmac-sha256" | "hmac-sha-256" => sha256_factory as fn() -> Box<dyn Digest>,
        "hmac-sha384" | "hmac-sha-384" => sha384_factory as fn() -> Box<dyn Digest>,
        "hmac-sha512" | "hmac-sha-512" => sha512_factory as fn() -> Box<dyn Digest>,
        "hmac-sm3" => sm3_factory as fn() -> Box<dyn Digest>,
        _ => return Err(format!("unsupported MAC: {}", args.mac).into()),
    };

    let password = if args.hexpass {
        decode_hex(&args.pass)?
    } else {
        args.pass.as_bytes().to_vec()
    };

    let salt = if args.hexsalt {
        decode_hex(&args.salt)?
    } else {
        args.salt.as_bytes().to_vec()
    };

    let dk = pbkdf2_with_hmac(factory, &password, &salt, args.iter, args.keylen)?;

    if args.binary {
        if let Some(ref path) = args.out {
            std::fs::write(path, &dk)?;
        } else {
            use std::io::Write;
            std::io::stdout().write_all(&dk)?;
        }
    } else {
        let hex = hitls_utils::hex::to_hex(&dk);
        if let Some(ref path) = args.out {
            std::fs::write(path, format!("{hex}\n"))?;
        } else {
            println!("{hex}");
        }
    }

    Ok(())
}

fn decode_hex(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("hex string must have even length".into());
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|_| format!("invalid hex at position {i}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn sha1_factory() -> Box<dyn Digest> {
    Box::new(hitls_crypto::sha1::Sha1::new())
}

fn sha224_factory() -> Box<dyn Digest> {
    Box::new(hitls_crypto::sha2::Sha224::new())
}

fn sha256_factory() -> Box<dyn Digest> {
    Box::new(hitls_crypto::sha2::Sha256::new())
}

fn sha384_factory() -> Box<dyn Digest> {
    Box::new(hitls_crypto::sha2::Sha384::new())
}

fn sha512_factory() -> Box<dyn Digest> {
    Box::new(hitls_crypto::sha2::Sha512::new())
}

fn sm3_factory() -> Box<dyn Digest> {
    Box::new(hitls_crypto::sm3::Sm3::new())
}

pub struct KdfArgs {
    pub algorithm: String,
    pub mac: String,
    pub pass: String,
    pub salt: String,
    pub iter: u32,
    pub keylen: usize,
    pub out: Option<String>,
    pub binary: bool,
    pub hexpass: bool,
    pub hexsalt: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_pbkdf2_sha256() {
        // RFC 7914 vector: password="passwd", salt="salt", c=1, dkLen=64
        let args = KdfArgs {
            algorithm: "pbkdf2".to_string(),
            mac: "hmac-sha256".to_string(),
            pass: "passwd".to_string(),
            salt: "salt".to_string(),
            iter: 1,
            keylen: 64,
            out: None,
            binary: false,
            hexpass: false,
            hexsalt: false,
        };
        assert!(run(&args).is_ok());
    }

    #[test]
    fn test_kdf_pbkdf2_sha1() {
        let args = KdfArgs {
            algorithm: "pbkdf2".to_string(),
            mac: "hmac-sha1".to_string(),
            pass: "password".to_string(),
            salt: "salt".to_string(),
            iter: 1,
            keylen: 20,
            out: None,
            binary: false,
            hexpass: false,
            hexsalt: false,
        };
        assert!(run(&args).is_ok());
    }

    #[test]
    fn test_kdf_pbkdf2_hexpass() {
        let args = KdfArgs {
            algorithm: "pbkdf2".to_string(),
            mac: "hmac-sha256".to_string(),
            pass: "70617373776f7264".to_string(), // "password" in hex
            salt: "salt".to_string(),
            iter: 1,
            keylen: 32,
            out: None,
            binary: false,
            hexpass: true,
            hexsalt: false,
        };
        assert!(run(&args).is_ok());
    }

    #[test]
    fn test_kdf_pbkdf2_hexsalt() {
        let args = KdfArgs {
            algorithm: "pbkdf2".to_string(),
            mac: "hmac-sha256".to_string(),
            pass: "password".to_string(),
            salt: "73616c74".to_string(), // "salt" in hex
            iter: 1,
            keylen: 32,
            out: None,
            binary: false,
            hexpass: false,
            hexsalt: true,
        };
        assert!(run(&args).is_ok());
    }

    #[test]
    fn test_kdf_pbkdf2_file_output() {
        let tmp = std::env::temp_dir().join("hitls_kdf_test.bin");
        let args = KdfArgs {
            algorithm: "pbkdf2".to_string(),
            mac: "hmac-sha256".to_string(),
            pass: "password".to_string(),
            salt: "salt".to_string(),
            iter: 1,
            keylen: 32,
            out: Some(tmp.to_string_lossy().to_string()),
            binary: false,
            hexpass: false,
            hexsalt: false,
        };
        assert!(run(&args).is_ok());
        let content = std::fs::read_to_string(&tmp).unwrap();
        assert!(content.trim().len() == 64); // 32 bytes = 64 hex chars
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_kdf_invalid_mac() {
        let args = KdfArgs {
            algorithm: "pbkdf2".to_string(),
            mac: "hmac-md4".to_string(),
            pass: "password".to_string(),
            salt: "salt".to_string(),
            iter: 1,
            keylen: 32,
            out: None,
            binary: false,
            hexpass: false,
            hexsalt: false,
        };
        assert!(run(&args).is_err());
    }

    #[test]
    fn test_kdf_invalid_algorithm() {
        let args = KdfArgs {
            algorithm: "scrypt".to_string(),
            mac: "hmac-sha256".to_string(),
            pass: "password".to_string(),
            salt: "salt".to_string(),
            iter: 1,
            keylen: 32,
            out: None,
            binary: false,
            hexpass: false,
            hexsalt: false,
        };
        assert!(run(&args).is_err());
    }

    #[test]
    fn test_kdf_pbkdf2_sha512() {
        let args = KdfArgs {
            algorithm: "pbkdf2".to_string(),
            mac: "hmac-sha512".to_string(),
            pass: "password".to_string(),
            salt: "salt".to_string(),
            iter: 1,
            keylen: 64,
            out: None,
            binary: false,
            hexpass: false,
            hexsalt: false,
        };
        assert!(run(&args).is_ok());
    }
}
