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

    let hex = digest.iter().map(|b| format!("{b:02x}")).collect::<String>();
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
