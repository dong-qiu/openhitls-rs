//! Symmetric encryption/decryption command.
//!
//! Supported ciphers: aes-256-gcm, aes-128-gcm, chacha20-poly1305, sm4-gcm

use std::fs;

pub fn run(
    cipher: &str,
    decrypt: bool,
    input: &str,
    output: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let op = if decrypt { "Decrypting" } else { "Encrypting" };
    eprintln!("{op} {input} -> {output} with {cipher}");

    let data = fs::read(input)?;

    let params = cipher_params(cipher)?;

    if decrypt {
        aead_decrypt(&data, output, &params)?;
    } else {
        aead_encrypt(&data, output, &params)?;
    }

    Ok(())
}

struct CipherParams {
    name: &'static str,
    key_len: usize,
    nonce_len: usize,
}

fn cipher_params(name: &str) -> Result<CipherParams, Box<dyn std::error::Error>> {
    match name.to_lowercase().as_str() {
        "aes-256-gcm" => Ok(CipherParams {
            name: "aes-256-gcm",
            key_len: 32,
            nonce_len: 12,
        }),
        "aes-128-gcm" => Ok(CipherParams {
            name: "aes-128-gcm",
            key_len: 16,
            nonce_len: 12,
        }),
        "chacha20-poly1305" => Ok(CipherParams {
            name: "chacha20-poly1305",
            key_len: 32,
            nonce_len: 12,
        }),
        "sm4-gcm" => Ok(CipherParams {
            name: "sm4-gcm",
            key_len: 16,
            nonce_len: 12,
        }),
        _ => Err(format!(
            "cipher '{name}' not supported. Supported: \
             aes-256-gcm, aes-128-gcm, chacha20-poly1305, sm4-gcm"
        )
        .into()),
    }
}

fn aead_encrypt_raw(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    cipher_name: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match cipher_name {
        "aes-256-gcm" | "aes-128-gcm" => Ok(hitls_crypto::modes::gcm::gcm_encrypt(
            key, nonce, b"", plaintext,
        )?),
        "chacha20-poly1305" => {
            let cipher = hitls_crypto::chacha20::ChaCha20Poly1305::new(key)?;
            Ok(cipher.encrypt(nonce, b"", plaintext)?)
        }
        "sm4-gcm" => Ok(hitls_crypto::modes::gcm::sm4_gcm_encrypt(
            key, nonce, b"", plaintext,
        )?),
        _ => unreachable!(),
    }
}

fn aead_decrypt_raw(
    key: &[u8],
    nonce: &[u8],
    ct_with_tag: &[u8],
    cipher_name: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match cipher_name {
        "aes-256-gcm" | "aes-128-gcm" => Ok(hitls_crypto::modes::gcm::gcm_decrypt(
            key,
            nonce,
            b"",
            ct_with_tag,
        )?),
        "chacha20-poly1305" => {
            let cipher = hitls_crypto::chacha20::ChaCha20Poly1305::new(key)?;
            Ok(cipher.decrypt(nonce, b"", ct_with_tag)?)
        }
        "sm4-gcm" => Ok(hitls_crypto::modes::gcm::sm4_gcm_decrypt(
            key,
            nonce,
            b"",
            ct_with_tag,
        )?),
        _ => unreachable!(),
    }
}

fn aead_encrypt(
    data: &[u8],
    output: &str,
    params: &CipherParams,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut key = vec![0u8; params.key_len];
    let mut nonce = vec![0u8; params.nonce_len];
    getrandom::getrandom(&mut key).map_err(|e| format!("random failed: {e}"))?;
    getrandom::getrandom(&mut nonce).map_err(|e| format!("random failed: {e}"))?;

    let ct_with_tag = aead_encrypt_raw(&key, &nonce, data, params.name)?;

    // Output format: nonce || ct_with_tag
    let mut out = Vec::with_capacity(params.nonce_len + ct_with_tag.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct_with_tag);
    fs::write(output, &out)?;

    let key_hex = hitls_utils::hex::to_hex(&key);
    eprintln!("Key (save this): {key_hex}");
    Ok(())
}

fn aead_decrypt(
    data: &[u8],
    output: &str,
    params: &CipherParams,
) -> Result<(), Box<dyn std::error::Error>> {
    let min_len = params.nonce_len + 16; // nonce + tag
    if data.len() < min_len {
        return Err(
            format!("ciphertext too short (need at least nonce + tag = {min_len} bytes)").into(),
        );
    }

    let nonce = &data[..params.nonce_len];
    let ct_with_tag = &data[params.nonce_len..];

    let key_hex = std::env::var("HITLS_KEY")
        .map_err(|_| "set HITLS_KEY environment variable to the hex key")?;
    let key = hex_decode(&key_hex)?;
    if key.len() != params.key_len {
        return Err(format!(
            "key must be {} bytes ({} hex chars)",
            params.key_len,
            params.key_len * 2
        )
        .into());
    }

    let plaintext = aead_decrypt_raw(&key, nonce, ct_with_tag, params.name)?;
    fs::write(output, &plaintext)?;
    eprintln!("Decrypted {} bytes", plaintext.len());
    Ok(())
}

fn hex_decode(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("hex string must have even length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at position {i}: {e}").into())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn roundtrip_test(cipher_name: &str) {
        let params = cipher_params(cipher_name).unwrap();
        let plaintext = b"Hello, symmetric encryption test!";

        // Encrypt
        let mut key = vec![0u8; params.key_len];
        let mut nonce = vec![0u8; params.nonce_len];
        getrandom::getrandom(&mut key).unwrap();
        getrandom::getrandom(&mut nonce).unwrap();

        let ct = aead_encrypt_raw(&key, &nonce, plaintext, params.name).unwrap();

        // Decrypt
        let pt = aead_decrypt_raw(&key, &nonce, &ct, params.name).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_enc_aes256gcm() {
        roundtrip_test("aes-256-gcm");
    }

    #[test]
    fn test_enc_aes128gcm() {
        roundtrip_test("aes-128-gcm");
    }

    #[test]
    fn test_enc_chacha20poly1305() {
        roundtrip_test("chacha20-poly1305");
    }

    #[test]
    fn test_enc_sm4gcm() {
        roundtrip_test("sm4-gcm");
    }

    #[test]
    fn test_enc_unknown_cipher() {
        assert!(cipher_params("rc4").is_err());
        assert!(cipher_params("des-cbc").is_err());
    }

    #[test]
    fn test_enc_file_roundtrip() {
        let dir = std::env::temp_dir().join("hitls_enc_test");
        let _ = fs::create_dir_all(&dir);
        let input_path = dir.join("input.bin");
        let encrypted_path = dir.join("encrypted.bin");
        let decrypted_path = dir.join("decrypted.bin");

        let plaintext = b"file-level encryption test data";
        fs::write(&input_path, plaintext).unwrap();

        // Encrypt
        let params = cipher_params("aes-128-gcm").unwrap();
        let data = fs::read(&input_path).unwrap();

        let mut key = vec![0u8; params.key_len];
        let mut nonce = vec![0u8; params.nonce_len];
        getrandom::getrandom(&mut key).unwrap();
        getrandom::getrandom(&mut nonce).unwrap();

        let ct = aead_encrypt_raw(&key, &nonce, &data, params.name).unwrap();
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        fs::write(&encrypted_path, &out).unwrap();

        // Decrypt
        let enc_data = fs::read(&encrypted_path).unwrap();
        let dec_nonce = &enc_data[..12];
        let dec_ct = &enc_data[12..];
        let pt = aead_decrypt_raw(&key, dec_nonce, dec_ct, params.name).unwrap();
        fs::write(&decrypted_path, &pt).unwrap();

        assert_eq!(fs::read(&decrypted_path).unwrap(), plaintext);

        // Cleanup
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_hex_decode_valid() {
        assert_eq!(hex_decode("48656c6c6f").unwrap(), b"Hello");
        assert_eq!(hex_decode("AABB").unwrap(), vec![0xAA, 0xBB]);
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_hex_decode_odd_length() {
        assert!(hex_decode("abc").is_err());
        assert!(hex_decode("1").is_err());
    }

    #[test]
    fn test_hex_decode_invalid_chars() {
        assert!(hex_decode("ZZZZ").is_err());
        assert!(hex_decode("gg").is_err());
    }

    #[test]
    fn test_hex_decode_whitespace_trimmed() {
        assert_eq!(hex_decode("  aabb  ").unwrap(), vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_cipher_params_case_insensitive() {
        assert!(cipher_params("AES-256-GCM").is_ok());
        assert!(cipher_params("Aes-128-Gcm").is_ok());
        assert!(cipher_params("CHACHA20-POLY1305").is_ok());
        assert!(cipher_params("SM4-GCM").is_ok());
    }

    #[test]
    fn test_cipher_params_key_nonce_lengths() {
        let p = cipher_params("aes-256-gcm").unwrap();
        assert_eq!(p.key_len, 32);
        assert_eq!(p.nonce_len, 12);

        let p = cipher_params("aes-128-gcm").unwrap();
        assert_eq!(p.key_len, 16);
        assert_eq!(p.nonce_len, 12);

        let p = cipher_params("chacha20-poly1305").unwrap();
        assert_eq!(p.key_len, 32);
        assert_eq!(p.nonce_len, 12);

        let p = cipher_params("sm4-gcm").unwrap();
        assert_eq!(p.key_len, 16);
        assert_eq!(p.nonce_len, 12);
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let key = vec![0x42u8; 16];
        let nonce = vec![0x01u8; 12];
        let ct = aead_encrypt_raw(&key, &nonce, b"secret", "aes-128-gcm").unwrap();

        // Flip a bit in the ciphertext
        let mut tampered = ct.clone();
        tampered[0] ^= 0x01;
        assert!(aead_decrypt_raw(&key, &nonce, &tampered, "aes-128-gcm").is_err());
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key = vec![0x42u8; 16];
        let wrong_key = vec![0x43u8; 16];
        let nonce = vec![0x01u8; 12];
        let ct = aead_encrypt_raw(&key, &nonce, b"secret", "aes-128-gcm").unwrap();

        assert!(aead_decrypt_raw(&wrong_key, &nonce, &ct, "aes-128-gcm").is_err());
    }

    #[test]
    fn test_encrypt_decrypt_empty_plaintext() {
        let key = vec![0x42u8; 32];
        let nonce = vec![0x01u8; 12];
        let ct = aead_encrypt_raw(&key, &nonce, b"", "aes-256-gcm").unwrap();
        let pt = aead_decrypt_raw(&key, &nonce, &ct, "aes-256-gcm").unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn test_sm4_gcm_roundtrip() {
        let key = vec![0x42u8; 16];
        let nonce = vec![0x01u8; 12];
        let pt = b"sm4 test data";
        let ct = aead_encrypt_raw(&key, &nonce, pt, "sm4-gcm").unwrap();
        let recovered = aead_decrypt_raw(&key, &nonce, &ct, "sm4-gcm").unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn test_chacha20_roundtrip() {
        let key = vec![0x42u8; 32];
        let nonce = vec![0x01u8; 12];
        let pt = b"chacha20 test";
        let ct = aead_encrypt_raw(&key, &nonce, pt, "chacha20-poly1305").unwrap();
        let recovered = aead_decrypt_raw(&key, &nonce, &ct, "chacha20-poly1305").unwrap();
        assert_eq!(recovered, pt);
    }
}
