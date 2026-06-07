//! Symmetric encryption/decryption command.
//!
//! Supported ciphers:
//! * AEAD (key from `HITLS_KEY` env var or random on encrypt):
//!   `aes-128-gcm`, `aes-256-gcm`, `chacha20-poly1305`, `sm4-gcm`.
//! * Non-AEAD CBC (PBKDF2-derived key+IV from `--pass`):
//!   `aes-128-cbc`, `aes-256-cbc`.
//!
//! For CBC modes the file format mirrors OpenSSL `enc`:
//!   `"Salted__"` (8 bytes) || salt (8 bytes) || ciphertext (PKCS#7-padded).

use std::fs;

const SALTED_MAGIC: &[u8; 8] = b"Salted__";
const SALT_LEN: usize = 8;
const PBKDF2_ITERATIONS: u32 = 10_000;

pub fn run(
    cipher: &str,
    decrypt: bool,
    input: &str,
    output: &str,
    pass: Option<&str>,
    md: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let op = if decrypt { "Decrypting" } else { "Encrypting" };
    eprintln!("{op} {input} -> {output} with {cipher}");

    let data = fs::read(input)?;
    let params = cipher_params(cipher)?;

    match params.kind {
        CipherKind::Aead => {
            if decrypt {
                aead_decrypt(&data, output, &params)?;
            } else {
                aead_encrypt(&data, output, &params)?;
            }
        }
        CipherKind::Cbc => {
            let password =
                pass.ok_or("CBC ciphers require --pass <password> for PBKDF2 key derivation")?;
            if decrypt {
                cbc_decrypt_with_pass(&data, output, &params, password, md)?;
            } else {
                cbc_encrypt_with_pass(&data, output, &params, password, md)?;
            }
        }
    }

    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CipherKind {
    Aead,
    Cbc,
}

struct CipherParams {
    name: &'static str,
    kind: CipherKind,
    key_len: usize,
    /// AEAD nonce length, or CBC IV length.
    nonce_len: usize,
}

fn cipher_params(name: &str) -> Result<CipherParams, Box<dyn std::error::Error>> {
    match name.to_lowercase().as_str() {
        "aes-256-gcm" => Ok(CipherParams {
            name: "aes-256-gcm",
            kind: CipherKind::Aead,
            key_len: 32,
            nonce_len: 12,
        }),
        "aes-128-gcm" => Ok(CipherParams {
            name: "aes-128-gcm",
            kind: CipherKind::Aead,
            key_len: 16,
            nonce_len: 12,
        }),
        "chacha20-poly1305" => Ok(CipherParams {
            name: "chacha20-poly1305",
            kind: CipherKind::Aead,
            key_len: 32,
            nonce_len: 12,
        }),
        "sm4-gcm" => Ok(CipherParams {
            name: "sm4-gcm",
            kind: CipherKind::Aead,
            key_len: 16,
            nonce_len: 12,
        }),
        "aes-128-cbc" => Ok(CipherParams {
            name: "aes-128-cbc",
            kind: CipherKind::Cbc,
            key_len: 16,
            nonce_len: 16,
        }),
        "aes-256-cbc" => Ok(CipherParams {
            name: "aes-256-cbc",
            kind: CipherKind::Cbc,
            key_len: 32,
            nonce_len: 16,
        }),
        _ => Err(format!(
            "cipher '{name}' not supported. Supported: \
             aes-256-gcm, aes-128-gcm, chacha20-poly1305, sm4-gcm, \
             aes-128-cbc, aes-256-cbc"
        )
        .into()),
    }
}

// ---------------------------------------------------------------------------
// CBC mode — PBKDF2 + OpenSSL-compatible `Salted__` format.
// ---------------------------------------------------------------------------

fn pbkdf2_derive_key_iv(
    password: &str,
    salt: &[u8],
    md: &str,
    key_len: usize,
    iv_len: usize,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let factory: fn() -> Box<dyn hitls_crypto::provider::Digest> = match md.to_lowercase().as_str()
    {
        "sha256" => || Box::new(hitls_crypto::sha2::Sha256::new()),
        other => {
            return Err(
                format!("PBKDF2 hash '{other}' not supported. Currently supported: sha256").into(),
            )
        }
    };
    let dk = hitls_crypto::pbkdf2::pbkdf2_with_hmac(
        factory,
        password.as_bytes(),
        salt,
        PBKDF2_ITERATIONS,
        key_len + iv_len,
    )?;
    let (key, iv) = dk.split_at(key_len);
    Ok((key.to_vec(), iv.to_vec()))
}

fn cbc_encrypt_raw(
    cipher_name: &str,
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match cipher_name {
        "aes-128-cbc" | "aes-256-cbc" => {
            Ok(hitls_crypto::modes::cbc::cbc_encrypt(key, iv, plaintext)?)
        }
        _ => unreachable!("non-CBC cipher routed through CBC path"),
    }
}

fn cbc_decrypt_raw(
    cipher_name: &str,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match cipher_name {
        "aes-128-cbc" | "aes-256-cbc" => {
            Ok(hitls_crypto::modes::cbc::cbc_decrypt(key, iv, ciphertext)?)
        }
        _ => unreachable!("non-CBC cipher routed through CBC path"),
    }
}

fn cbc_encrypt_with_pass(
    data: &[u8],
    output: &str,
    params: &CipherParams,
    password: &str,
    md: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|e| format!("random failed: {e}"))?;
    let (key, iv) = pbkdf2_derive_key_iv(password, &salt, md, params.key_len, params.nonce_len)?;
    let ct = cbc_encrypt_raw(params.name, &key, &iv, data)?;

    // OpenSSL-compatible: "Salted__" || salt(8) || ciphertext
    let mut out = Vec::with_capacity(SALTED_MAGIC.len() + SALT_LEN + ct.len());
    out.extend_from_slice(SALTED_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&ct);
    fs::write(output, &out)?;
    Ok(())
}

fn cbc_decrypt_with_pass(
    data: &[u8],
    output: &str,
    params: &CipherParams,
    password: &str,
    md: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let header_len = SALTED_MAGIC.len() + SALT_LEN;
    if data.len() < header_len {
        return Err(format!(
            "ciphertext too short (need at least Salted__ + salt = {header_len} bytes)"
        )
        .into());
    }
    if &data[..SALTED_MAGIC.len()] != SALTED_MAGIC {
        return Err("ciphertext missing OpenSSL 'Salted__' magic header".into());
    }
    let salt = &data[SALTED_MAGIC.len()..header_len];
    let ct = &data[header_len..];
    let (key, iv) = pbkdf2_derive_key_iv(password, salt, md, params.key_len, params.nonce_len)?;
    let pt = cbc_decrypt_raw(params.name, &key, &iv, ct)?;
    fs::write(output, &pt)?;
    Ok(())
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
    getrandom::fill(&mut key).map_err(|e| format!("random failed: {e}"))?;
    getrandom::fill(&mut nonce).map_err(|e| format!("random failed: {e}"))?;

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
        getrandom::fill(&mut key).unwrap();
        getrandom::fill(&mut nonce).unwrap();

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
        getrandom::fill(&mut key).unwrap();
        getrandom::fill(&mut nonce).unwrap();

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

    // ---- CBC + PBKDF2 (#43 restore non-AEAD ciphers) ----

    fn cbc_file_roundtrip(cipher_name: &str) {
        let dir = std::env::temp_dir().join(format!("hitls_enc_cbc_{cipher_name}"));
        let _ = fs::create_dir_all(&dir);
        let input_path = dir.join("input.bin");
        let encrypted_path = dir.join("encrypted.bin");
        let decrypted_path = dir.join("decrypted.bin");

        let plaintext = b"CBC + PBKDF2 file-level roundtrip data, more than 16 bytes!";
        fs::write(&input_path, plaintext).unwrap();

        run(
            cipher_name,
            false,
            input_path.to_str().unwrap(),
            encrypted_path.to_str().unwrap(),
            Some("hunter2"),
            "sha256",
        )
        .unwrap();

        // Output must start with Salted__
        let enc_bytes = fs::read(&encrypted_path).unwrap();
        assert!(
            enc_bytes.starts_with(SALTED_MAGIC),
            "CBC output missing Salted__ header"
        );
        assert!(enc_bytes.len() > SALTED_MAGIC.len() + SALT_LEN);

        run(
            cipher_name,
            true,
            encrypted_path.to_str().unwrap(),
            decrypted_path.to_str().unwrap(),
            Some("hunter2"),
            "sha256",
        )
        .unwrap();

        assert_eq!(fs::read(&decrypted_path).unwrap(), plaintext);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cbc_aes128_roundtrip() {
        cbc_file_roundtrip("aes-128-cbc");
    }

    #[test]
    fn test_cbc_aes256_roundtrip() {
        cbc_file_roundtrip("aes-256-cbc");
    }

    #[test]
    fn test_cbc_requires_pass() {
        let dir = std::env::temp_dir().join("hitls_enc_cbc_nopass");
        let _ = fs::create_dir_all(&dir);
        let input_path = dir.join("input.bin");
        let output_path = dir.join("out.bin");
        fs::write(&input_path, b"x").unwrap();
        let err = run(
            "aes-128-cbc",
            false,
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
            None,
            "sha256",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("--pass"),
            "expected --pass diagnostic, got: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cbc_wrong_password_rejected() {
        let dir = std::env::temp_dir().join("hitls_enc_cbc_wrongpass");
        let _ = fs::create_dir_all(&dir);
        let input_path = dir.join("input.bin");
        let encrypted_path = dir.join("out.bin");
        let decrypted_path = dir.join("dec.bin");
        fs::write(
            &input_path,
            b"secret message that is long enough to span blocks",
        )
        .unwrap();

        run(
            "aes-128-cbc",
            false,
            input_path.to_str().unwrap(),
            encrypted_path.to_str().unwrap(),
            Some("correct"),
            "sha256",
        )
        .unwrap();

        let err = run(
            "aes-128-cbc",
            true,
            encrypted_path.to_str().unwrap(),
            decrypted_path.to_str().unwrap(),
            Some("wrong"),
            "sha256",
        )
        .unwrap_err();
        // PBKDF2 with the wrong password produces a wrong key/IV → CBC decrypt
        // either produces invalid PKCS#7 padding or garbage. Either way: Err.
        assert!(!err.to_string().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cbc_decrypt_missing_salted_header() {
        let dir = std::env::temp_dir().join("hitls_enc_cbc_noheader");
        let _ = fs::create_dir_all(&dir);
        let input_path = dir.join("input.bin");
        let output_path = dir.join("out.bin");
        // 32 bytes of garbage — no Salted__ header.
        fs::write(&input_path, [0xFFu8; 32]).unwrap();
        let err = run(
            "aes-128-cbc",
            true,
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
            Some("any"),
            "sha256",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("Salted__"),
            "expected Salted__ diagnostic, got: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cbc_unsupported_md() {
        let dir = std::env::temp_dir().join("hitls_enc_cbc_badmd");
        let _ = fs::create_dir_all(&dir);
        let input_path = dir.join("input.bin");
        let output_path = dir.join("out.bin");
        fs::write(&input_path, b"x").unwrap();
        let err = run(
            "aes-128-cbc",
            false,
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
            Some("p"),
            "md5",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("PBKDF2 hash 'md5'"),
            "expected PBKDF2 hash diagnostic, got: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cipher_params_cbc_entries() {
        let p = cipher_params("aes-128-cbc").unwrap();
        assert_eq!(p.kind, CipherKind::Cbc);
        assert_eq!(p.key_len, 16);
        assert_eq!(p.nonce_len, 16);

        let p = cipher_params("aes-256-cbc").unwrap();
        assert_eq!(p.kind, CipherKind::Cbc);
        assert_eq!(p.key_len, 32);
        assert_eq!(p.nonce_len, 16);
    }
}
