//! Hash/digest command implementation.

use std::fs;
use std::io::{self, Read};

pub fn run(algorithm: &str, file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = if file == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        fs::read(file)?
    };

    let (digest, alg_name) = hash_data(algorithm, &data)?;

    let hex = digest
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

fn hash_data(
    algorithm: &str,
    data: &[u8],
) -> Result<(Vec<u8>, &'static str), Box<dyn std::error::Error>> {
    match algorithm.to_lowercase().as_str() {
        "md5" => {
            let h = hitls_crypto::md5::Md5::digest(data)?;
            Ok((h.to_vec(), "MD5"))
        }
        "sha1" | "sha-1" => {
            let h = hitls_crypto::sha1::Sha1::digest(data)?;
            Ok((h.to_vec(), "SHA1"))
        }
        "sha224" | "sha-224" => {
            let h = hitls_crypto::sha2::Sha224::digest(data)?;
            Ok((h.to_vec(), "SHA224"))
        }
        "sha256" | "sha-256" => {
            let h = hitls_crypto::sha2::Sha256::digest(data)?;
            Ok((h.to_vec(), "SHA256"))
        }
        "sha384" | "sha-384" => {
            let h = hitls_crypto::sha2::Sha384::digest(data)?;
            Ok((h.to_vec(), "SHA384"))
        }
        "sha512" | "sha-512" => {
            let h = hitls_crypto::sha2::Sha512::digest(data)?;
            Ok((h.to_vec(), "SHA512"))
        }
        "sm3" => {
            let h = hitls_crypto::sm3::Sm3::digest(data)?;
            Ok((h.to_vec(), "SM3"))
        }
        "sha3-256" => {
            let h = hitls_crypto::sha3::Sha3_256::digest(data)?;
            Ok((h.to_vec(), "SHA3-256"))
        }
        "sha3-512" => {
            let h = hitls_crypto::sha3::Sha3_512::digest(data)?;
            Ok((h.to_vec(), "SHA3-512"))
        }
        _ => Err(format!("unsupported hash algorithm: {algorithm}").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn test_hash_data_md5_empty() {
        let (digest, name) = hash_data("md5", b"").unwrap();
        assert_eq!(name, "MD5");
        assert_eq!(digest.len(), 16);
        assert_eq!(to_hex(&digest), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_hash_data_sha1_empty() {
        let (digest, name) = hash_data("sha1", b"").unwrap();
        assert_eq!(name, "SHA1");
        assert_eq!(digest.len(), 20);
    }

    #[test]
    fn test_hash_data_sha1_alias() {
        let (d1, _) = hash_data("sha1", b"test").unwrap();
        let (d2, _) = hash_data("sha-1", b"test").unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_hash_data_sha224_empty() {
        let (digest, name) = hash_data("sha224", b"").unwrap();
        assert_eq!(name, "SHA224");
        assert_eq!(digest.len(), 28);
    }

    #[test]
    fn test_hash_data_sha256_empty() {
        let (digest, name) = hash_data("sha256", b"").unwrap();
        assert_eq!(name, "SHA256");
        assert_eq!(digest.len(), 32);
        assert_eq!(
            to_hex(&digest),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hash_data_sha256_alias() {
        let (d1, _) = hash_data("sha256", b"hello").unwrap();
        let (d2, _) = hash_data("sha-256", b"hello").unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_hash_data_sha384_empty() {
        let (digest, name) = hash_data("sha384", b"").unwrap();
        assert_eq!(name, "SHA384");
        assert_eq!(digest.len(), 48);
    }

    #[test]
    fn test_hash_data_sha512_empty() {
        let (digest, name) = hash_data("sha512", b"").unwrap();
        assert_eq!(name, "SHA512");
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn test_hash_data_sm3_empty() {
        let (digest, name) = hash_data("sm3", b"").unwrap();
        assert_eq!(name, "SM3");
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_hash_data_sha3_256_empty() {
        let (digest, name) = hash_data("sha3-256", b"").unwrap();
        assert_eq!(name, "SHA3-256");
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_hash_data_sha3_512_empty() {
        let (digest, name) = hash_data("sha3-512", b"").unwrap();
        assert_eq!(name, "SHA3-512");
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn test_hash_data_case_insensitive() {
        let (d1, _) = hash_data("SHA256", b"data").unwrap();
        let (d2, _) = hash_data("sha256", b"data").unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_hash_data_unsupported_algorithm() {
        let result = hash_data("blake2b", b"data");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported hash algorithm"));
    }

    #[test]
    fn test_hash_data_different_inputs_differ() {
        let (d1, _) = hash_data("sha256", b"hello").unwrap();
        let (d2, _) = hash_data("sha256", b"world").unwrap();
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_run_file() {
        use std::fs;
        let tmp = std::env::temp_dir().join("test_dgst_run.txt");
        fs::write(&tmp, b"test data for dgst").unwrap();
        let result = run("sha256", tmp.to_str().unwrap());
        assert!(result.is_ok());
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_run_nonexistent_file() {
        let result = run("sha256", "/nonexistent_dgst_test/file.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_run_unsupported_algorithm() {
        use std::fs;
        let tmp = std::env::temp_dir().join("test_dgst_bad_alg.txt");
        fs::write(&tmp, b"test").unwrap();
        let result = run("unknownalg", tmp.to_str().unwrap());
        assert!(result.is_err());
        let _ = fs::remove_file(&tmp);
    }
}
