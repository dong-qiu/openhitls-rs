//! Symmetric encryption/decryption command.
//!
//! Supported ciphers:
//! * AEAD (key from `HITLS_KEY` env var or random on encrypt):
//!   `aes-128-gcm`, `aes-256-gcm`, `chacha20-poly1305`, `sm4-gcm`.
//! * Non-AEAD (PBKDF2-derived key+IV from `--pass`):
//!   * CBC (PKCS#7-padded): `aes-128-cbc`, `aes-256-cbc`.
//!   * CTR (no padding): `aes-128-ctr`, `aes-256-ctr`.
//!   * ECB (PKCS#7-padded, no IV): `aes-128-ecb`, `aes-256-ecb`.
//!   * CFB (no padding): `sm4-cfb`.
//!
//! For all PBKDF2 modes the file format mirrors OpenSSL `enc`:
//!   `"Salted__"` (8 bytes) || salt (8 bytes) || ciphertext.

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
        CipherKind::Cbc | CipherKind::Ctr | CipherKind::Ecb | CipherKind::Cfb => {
            let password =
                pass.ok_or("non-AEAD ciphers require --pass <password> for PBKDF2 key derivation")?;
            if decrypt {
                pass_decrypt(&data, output, &params, password, md)?;
            } else {
                pass_encrypt(&data, output, &params, password, md)?;
            }
        }
    }

    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CipherKind {
    Aead,
    /// CBC: block cipher with PKCS#7 padding + 16-byte IV.
    Cbc,
    /// CTR: stream cipher (no padding) + 16-byte counter/nonce.
    Ctr,
    /// ECB: block cipher with PKCS#7 padding, no IV.
    Ecb,
    /// CFB: stream-like cipher (no padding) + 16-byte IV.
    Cfb,
}

impl CipherKind {
    /// Whether the cipher mode requires an IV / nonce derived from PBKDF2 in
    /// addition to the key. Used to compute the PBKDF2 `dk_len`.
    fn needs_iv(self) -> bool {
        matches!(self, Self::Cbc | Self::Ctr | Self::Cfb)
    }
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
        "aes-128-ctr" => Ok(CipherParams {
            name: "aes-128-ctr",
            kind: CipherKind::Ctr,
            key_len: 16,
            nonce_len: 16,
        }),
        "aes-256-ctr" => Ok(CipherParams {
            name: "aes-256-ctr",
            kind: CipherKind::Ctr,
            key_len: 32,
            nonce_len: 16,
        }),
        "aes-128-ecb" => Ok(CipherParams {
            name: "aes-128-ecb",
            kind: CipherKind::Ecb,
            key_len: 16,
            nonce_len: 0,
        }),
        "aes-256-ecb" => Ok(CipherParams {
            name: "aes-256-ecb",
            kind: CipherKind::Ecb,
            key_len: 32,
            nonce_len: 0,
        }),
        "sm4-cfb" => Ok(CipherParams {
            name: "sm4-cfb",
            kind: CipherKind::Cfb,
            key_len: 16,
            nonce_len: 16,
        }),
        _ => Err(format!(
            "cipher '{name}' not supported. Supported: \
             aes-256-gcm, aes-128-gcm, chacha20-poly1305, sm4-gcm, \
             aes-128-cbc, aes-256-cbc, aes-128-ctr, aes-256-ctr, \
             aes-128-ecb, aes-256-ecb, sm4-cfb"
        )
        .into()),
    }
}

// ---------------------------------------------------------------------------
// Non-AEAD modes — PBKDF2 + OpenSSL-compatible `Salted__` format.
//
// `pass_encrypt` / `pass_decrypt` are the generic entry points; the per-mode
// raw-encrypt / raw-decrypt helpers below delegate to the right `hitls_crypto`
// primitive based on the cipher name. ECB has no IV and adds PKCS#7 padding;
// CTR / CFB are streaming modes (no padding); CBC has both an IV and PKCS#7
// padding (handled by `hitls_crypto::modes::cbc`).
// ---------------------------------------------------------------------------

const AES_BLOCK_SIZE: usize = 16;

/// PKCS#7-pad `data` to a multiple of `block` bytes. Used for the ECB mode
/// (whose Rust primitive requires block-aligned input).
fn pkcs7_pad(data: &[u8], block: usize) -> Vec<u8> {
    let pad_len = block - (data.len() % block);
    let mut out = Vec::with_capacity(data.len() + pad_len);
    out.extend_from_slice(data);
    out.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    out
}

/// Strip PKCS#7 padding from `data`, returning the unpadded slice. Errors on
/// malformed padding (wrong length byte, length > block size, length 0).
fn pkcs7_unpad(data: &[u8], block: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if data.is_empty() || data.len() % block != 0 {
        return Err("PKCS#7 input length not block-aligned".into());
    }
    let pad_len = *data.last().unwrap() as usize;
    if pad_len == 0 || pad_len > block || pad_len > data.len() {
        return Err("PKCS#7 padding byte out of range".into());
    }
    let cut = data.len() - pad_len;
    if data[cut..].iter().any(|&b| b as usize != pad_len) {
        return Err("PKCS#7 padding bytes inconsistent".into());
    }
    Ok(data[..cut].to_vec())
}

fn pbkdf2_derive_key_iv(
    password: &str,
    salt: &[u8],
    md: &str,
    key_len: usize,
    iv_len: usize,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    // Supported PBKDF2 hashes. Names follow openssl `enc -md` conventions
    // (lowercase, no separators), so a CLI script targeting either tool
    // accepts the same `-md sha1` / `-md sha256` / `-md sm3` etc.
    let factory: fn() -> Box<dyn hitls_crypto::provider::Digest> = match md.to_lowercase().as_str()
    {
        "md5" => || Box::new(hitls_crypto::md5::Md5::new()),
        "sha1" => || Box::new(hitls_crypto::sha1::Sha1::new()),
        "sha224" => || Box::new(hitls_crypto::sha2::Sha224::new()),
        "sha256" => || Box::new(hitls_crypto::sha2::Sha256::new()),
        "sha384" => || Box::new(hitls_crypto::sha2::Sha384::new()),
        "sha512" => || Box::new(hitls_crypto::sha2::Sha512::new()),
        "sm3" => || Box::new(hitls_crypto::sm3::Sm3::new()),
        other => {
            return Err(format!(
                "PBKDF2 hash '{other}' not supported. Supported: \
                 md5, sha1, sha224, sha256, sha384, sha512, sm3"
            )
            .into())
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

/// Encrypt `plaintext` under the given non-AEAD mode. `iv` is consulted only
/// for IV-bearing modes; for ECB it is ignored.
fn pass_encrypt_raw(
    params: &CipherParams,
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(match params.name {
        "aes-128-cbc" | "aes-256-cbc" => hitls_crypto::modes::cbc::cbc_encrypt(key, iv, plaintext)?,
        "aes-128-ctr" | "aes-256-ctr" => {
            let mut buf = plaintext.to_vec();
            hitls_crypto::modes::ctr::ctr_crypt(key, iv, &mut buf)?;
            buf
        }
        "aes-128-ecb" | "aes-256-ecb" => {
            // The Rust ECB primitive requires block-aligned input — add
            // PKCS#7 padding here so we accept arbitrary plaintext sizes.
            let padded = pkcs7_pad(plaintext, AES_BLOCK_SIZE);
            hitls_crypto::modes::ecb::ecb_encrypt(key, &padded)?
        }
        "sm4-cfb" => hitls_crypto::modes::cfb::sm4_cfb_encrypt(key, iv, plaintext)?,
        other => unreachable!("non-PBKDF2 cipher '{other}' routed through pass path"),
    })
}

/// Decrypt `ciphertext` under the given non-AEAD mode.
fn pass_decrypt_raw(
    params: &CipherParams,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(match params.name {
        "aes-128-cbc" | "aes-256-cbc" => {
            hitls_crypto::modes::cbc::cbc_decrypt(key, iv, ciphertext)?
        }
        "aes-128-ctr" | "aes-256-ctr" => {
            let mut buf = ciphertext.to_vec();
            hitls_crypto::modes::ctr::ctr_crypt(key, iv, &mut buf)?;
            buf
        }
        "aes-128-ecb" | "aes-256-ecb" => {
            let padded = hitls_crypto::modes::ecb::ecb_decrypt(key, ciphertext)?;
            pkcs7_unpad(&padded, AES_BLOCK_SIZE)?
        }
        "sm4-cfb" => hitls_crypto::modes::cfb::sm4_cfb_decrypt(key, iv, ciphertext)?,
        other => unreachable!("non-PBKDF2 cipher '{other}' routed through pass path"),
    })
}

fn pass_encrypt(
    data: &[u8],
    output: &str,
    params: &CipherParams,
    password: &str,
    md: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|e| format!("random failed: {e}"))?;
    let iv_len = if params.kind.needs_iv() {
        params.nonce_len
    } else {
        0
    };
    let (key, iv) = pbkdf2_derive_key_iv(password, &salt, md, params.key_len, iv_len)?;
    let ct = pass_encrypt_raw(params, &key, &iv, data)?;

    // OpenSSL-compatible: "Salted__" || salt(8) || ciphertext
    let mut out = Vec::with_capacity(SALTED_MAGIC.len() + SALT_LEN + ct.len());
    out.extend_from_slice(SALTED_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&ct);
    fs::write(output, &out)?;
    Ok(())
}

fn pass_decrypt(
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
    let iv_len = if params.kind.needs_iv() {
        params.nonce_len
    } else {
        0
    };
    let (key, iv) = pbkdf2_derive_key_iv(password, salt, md, params.key_len, iv_len)?;
    let pt = pass_decrypt_raw(params, &key, &iv, ct)?;
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
        // `ripemd160` is a real PBKDF2-eligible hash but not in our supported
        // set; pick it as a stable "definitely unsupported" sentinel even
        // after T181 broadens the set to md5/sha1/sha224/sha256/sha384/
        // sha512/sm3.
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
            "ripemd160",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("PBKDF2 hash 'ripemd160'"),
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

    // ---- CTR / ECB / CFB (#43 T180) ----

    /// Round-trip via the public `run()` entry point. Used to exercise all
    /// non-AEAD modes uniformly.
    fn pass_file_roundtrip(cipher_name: &str, pt: &[u8]) {
        let dir = std::env::temp_dir().join(format!("hitls_enc_pass_{cipher_name}"));
        let _ = fs::create_dir_all(&dir);
        let input_path = dir.join("input.bin");
        let enc_path = dir.join("encrypted.bin");
        let dec_path = dir.join("decrypted.bin");
        fs::write(&input_path, pt).unwrap();

        run(
            cipher_name,
            false,
            input_path.to_str().unwrap(),
            enc_path.to_str().unwrap(),
            Some("hunter2"),
            "sha256",
        )
        .unwrap();
        let enc_bytes = fs::read(&enc_path).unwrap();
        assert!(
            enc_bytes.starts_with(SALTED_MAGIC),
            "{cipher_name} output missing Salted__ header"
        );
        assert!(enc_bytes.len() > SALTED_MAGIC.len() + SALT_LEN);

        run(
            cipher_name,
            true,
            enc_path.to_str().unwrap(),
            dec_path.to_str().unwrap(),
            Some("hunter2"),
            "sha256",
        )
        .unwrap();
        assert_eq!(fs::read(&dec_path).unwrap(), pt);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_ctr_aes128_roundtrip() {
        pass_file_roundtrip(
            "aes-128-ctr",
            b"CTR stream cipher, no padding, arbitrary length 0xAA",
        );
    }

    #[test]
    fn test_ctr_aes256_roundtrip() {
        pass_file_roundtrip(
            "aes-256-ctr",
            b"CTR-256 stream cipher round-trip with longer plaintext",
        );
    }

    /// CTR is a stream cipher: ciphertext length == plaintext length, so the
    /// total output is exactly `Salted__(8) + salt(8) + plaintext.len()`.
    #[test]
    fn test_ctr_no_padding_overhead() {
        let dir = std::env::temp_dir().join("hitls_enc_ctr_nopad");
        let _ = fs::create_dir_all(&dir);
        let input_path = dir.join("input.bin");
        let enc_path = dir.join("out.bin");
        let pt = b"exactly 25 bytes of plaintext.";
        assert_eq!(pt.len(), 30);
        fs::write(&input_path, pt).unwrap();
        run(
            "aes-128-ctr",
            false,
            input_path.to_str().unwrap(),
            enc_path.to_str().unwrap(),
            Some("p"),
            "sha256",
        )
        .unwrap();
        let enc_bytes = fs::read(&enc_path).unwrap();
        assert_eq!(
            enc_bytes.len(),
            SALTED_MAGIC.len() + SALT_LEN + pt.len(),
            "CTR ciphertext should not introduce padding overhead"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_ecb_aes128_roundtrip() {
        pass_file_roundtrip("aes-128-ecb", b"ECB block cipher with PKCS#7 padding");
    }

    #[test]
    fn test_ecb_aes256_roundtrip() {
        pass_file_roundtrip(
            "aes-256-ecb",
            b"ECB-256 with arbitrary length payload spanning blocks",
        );
    }

    /// ECB output is PKCS#7-padded to a multiple of 16 bytes, so an empty
    /// plaintext produces exactly one 16-byte ciphertext block.
    #[test]
    fn test_ecb_empty_plaintext_pads_one_block() {
        let dir = std::env::temp_dir().join("hitls_enc_ecb_empty");
        let _ = fs::create_dir_all(&dir);
        let input_path = dir.join("input.bin");
        let enc_path = dir.join("out.bin");
        let dec_path = dir.join("dec.bin");
        fs::write(&input_path, b"").unwrap();
        run(
            "aes-128-ecb",
            false,
            input_path.to_str().unwrap(),
            enc_path.to_str().unwrap(),
            Some("p"),
            "sha256",
        )
        .unwrap();
        let enc_bytes = fs::read(&enc_path).unwrap();
        assert_eq!(
            enc_bytes.len(),
            SALTED_MAGIC.len() + SALT_LEN + AES_BLOCK_SIZE,
            "empty plaintext PKCS#7-pads to one block"
        );
        run(
            "aes-128-ecb",
            true,
            enc_path.to_str().unwrap(),
            dec_path.to_str().unwrap(),
            Some("p"),
            "sha256",
        )
        .unwrap();
        assert!(fs::read(&dec_path).unwrap().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sm4_cfb_roundtrip() {
        pass_file_roundtrip(
            "sm4-cfb",
            b"SM4-CFB GM/T 0002-2012 streaming roundtrip data",
        );
    }

    #[test]
    fn test_cipher_params_ctr_ecb_cfb_entries() {
        let p = cipher_params("aes-128-ctr").unwrap();
        assert_eq!(p.kind, CipherKind::Ctr);
        assert!(p.kind.needs_iv());
        assert_eq!((p.key_len, p.nonce_len), (16, 16));

        let p = cipher_params("aes-256-ctr").unwrap();
        assert_eq!((p.key_len, p.nonce_len), (32, 16));

        let p = cipher_params("aes-128-ecb").unwrap();
        assert_eq!(p.kind, CipherKind::Ecb);
        assert!(!p.kind.needs_iv());
        assert_eq!((p.key_len, p.nonce_len), (16, 0));

        let p = cipher_params("aes-256-ecb").unwrap();
        assert_eq!((p.key_len, p.nonce_len), (32, 0));

        let p = cipher_params("sm4-cfb").unwrap();
        assert_eq!(p.kind, CipherKind::Cfb);
        assert!(p.kind.needs_iv());
        assert_eq!((p.key_len, p.nonce_len), (16, 16));
    }

    #[test]
    fn test_pkcs7_pad_unpad_roundtrip() {
        for n in 0..=33 {
            let v: Vec<u8> = (0..n).map(|i| i as u8).collect();
            let padded = pkcs7_pad(&v, 16);
            assert_eq!(padded.len() % 16, 0);
            assert!(padded.len() > v.len(), "PKCS#7 always adds at least 1 byte");
            let unpadded = pkcs7_unpad(&padded, 16).unwrap();
            assert_eq!(unpadded, v);
        }
    }

    // ---- T181: `--md` extension (sha1/sha224/sha384/sha512/md5/sm3) ----

    /// Encrypt + decrypt with the given `md` to confirm PBKDF2 dispatch works
    /// for that hash. We use AES-128-CBC for all rounds since the dispatch
    /// itself is what varies; the cipher mode is incidental.
    fn pbkdf2_md_roundtrip(md: &str) {
        let dir = std::env::temp_dir().join(format!("hitls_enc_md_{md}"));
        let _ = fs::create_dir_all(&dir);
        let input_path = dir.join("input.bin");
        let enc_path = dir.join("encrypted.bin");
        let dec_path = dir.join("decrypted.bin");

        let plaintext = b"PBKDF2 md-extension round-trip data";
        fs::write(&input_path, plaintext).unwrap();

        run(
            "aes-128-cbc",
            false,
            input_path.to_str().unwrap(),
            enc_path.to_str().unwrap(),
            Some("hunter2"),
            md,
        )
        .unwrap();
        run(
            "aes-128-cbc",
            true,
            enc_path.to_str().unwrap(),
            dec_path.to_str().unwrap(),
            Some("hunter2"),
            md,
        )
        .unwrap();
        assert_eq!(fs::read(&dec_path).unwrap(), plaintext);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_pbkdf2_md_md5() {
        pbkdf2_md_roundtrip("md5");
    }

    /// C TC003 explicitly exercises `-md sha1` — pinning this matches the
    /// openhitls-C reference behaviour we are restoring under #43.
    #[test]
    fn test_pbkdf2_md_sha1() {
        pbkdf2_md_roundtrip("sha1");
    }

    #[test]
    fn test_pbkdf2_md_sha224() {
        pbkdf2_md_roundtrip("sha224");
    }

    #[test]
    fn test_pbkdf2_md_sha384() {
        pbkdf2_md_roundtrip("sha384");
    }

    #[test]
    fn test_pbkdf2_md_sha512() {
        pbkdf2_md_roundtrip("sha512");
    }

    #[test]
    fn test_pbkdf2_md_sm3() {
        pbkdf2_md_roundtrip("sm3");
    }

    /// PBKDF2 hash names are matched case-insensitively (`to_lowercase()`),
    /// so `--md SHA256` and `--md sha256` MUST be interchangeable end-to-end.
    /// Encrypt with one casing and decrypt with the other to prove that the
    /// dispatch normalises the input correctly.
    #[test]
    fn test_pbkdf2_md_case_insensitive() {
        let dir = std::env::temp_dir().join("hitls_enc_md_case_test");
        let _ = fs::create_dir_all(&dir);
        let input_path = dir.join("input.bin");
        let enc_path = dir.join("encrypted.bin");
        let dec_path = dir.join("decrypted.bin");
        let plaintext = b"case-insensitive PBKDF2 md handling test data";
        fs::write(&input_path, plaintext).unwrap();
        // Encrypt with "SHA256" (uppercase)...
        run(
            "aes-128-cbc",
            false,
            input_path.to_str().unwrap(),
            enc_path.to_str().unwrap(),
            Some("hunter2"),
            "SHA256",
        )
        .unwrap();
        // ...decrypt with "sha256" (lowercase) — same hash, both must accept.
        run(
            "aes-128-cbc",
            true,
            enc_path.to_str().unwrap(),
            dec_path.to_str().unwrap(),
            Some("hunter2"),
            "sha256",
        )
        .unwrap();
        assert_eq!(fs::read(&dec_path).unwrap(), plaintext);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Different `--md` values MUST produce different ciphertexts on the same
    /// password+plaintext (a wrong-md decrypt MUST fail). Pins that the hash
    /// choice actually flows into the key+iv derivation.
    #[test]
    fn test_pbkdf2_md_mismatch_fails_decrypt() {
        let dir = std::env::temp_dir().join("hitls_enc_md_mismatch");
        let _ = fs::create_dir_all(&dir);
        let input_path = dir.join("input.bin");
        let enc_path = dir.join("encrypted.bin");
        let dec_path = dir.join("decrypted.bin");

        let plaintext = b"PBKDF2 md mismatch -- encryption vs decryption hash differ";
        fs::write(&input_path, plaintext).unwrap();

        run(
            "aes-128-cbc",
            false,
            input_path.to_str().unwrap(),
            enc_path.to_str().unwrap(),
            Some("hunter2"),
            "sha256",
        )
        .unwrap();
        // Encrypt with sha256, decrypt with sha1 → PBKDF2 derives a different
        // key/iv → CBC decrypt surfaces invalid PKCS#7 padding.
        let err = run(
            "aes-128-cbc",
            true,
            enc_path.to_str().unwrap(),
            dec_path.to_str().unwrap(),
            Some("hunter2"),
            "sha1",
        )
        .unwrap_err();
        assert!(!err.to_string().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_pkcs7_unpad_rejects_malformed() {
        // Length-byte > block size.
        assert!(pkcs7_unpad(&[0x00; 16], 16).is_err());
        assert!(pkcs7_unpad(&[0xFF; 16], 16).is_err());
        // Inconsistent padding bytes.
        let mut buf = vec![0u8; 16];
        buf[15] = 3;
        buf[14] = 3;
        buf[13] = 2; // wrong
        assert!(pkcs7_unpad(&buf, 16).is_err());
        // Non-block-aligned length.
        assert!(pkcs7_unpad(&[1, 2, 3], 16).is_err());
    }
}
