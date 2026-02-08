//! Symmetric encryption/decryption command (partial implementation).

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

    match cipher.to_lowercase().as_str() {
        "aes-256-gcm" => {
            if decrypt {
                aes_gcm_decrypt(&data, output)?;
            } else {
                aes_gcm_encrypt(&data, output)?;
            }
        }
        _ => {
            return Err(
                format!("cipher '{cipher}' not yet implemented. Supported: aes-256-gcm").into(),
            );
        }
    }

    Ok(())
}

fn aes_gcm_encrypt(data: &[u8], output: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut key = [0u8; 32];
    let mut iv = [0u8; 12];
    getrandom::getrandom(&mut key).map_err(|e| format!("random failed: {e}"))?;
    getrandom::getrandom(&mut iv).map_err(|e| format!("random failed: {e}"))?;

    // gcm_encrypt returns ciphertext with tag appended
    let ct_with_tag = hitls_crypto::modes::gcm::gcm_encrypt(&key, &iv, b"", data)?;

    // Output format: iv(12) || ct_with_tag
    let mut out = Vec::with_capacity(12 + ct_with_tag.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct_with_tag);
    fs::write(output, &out)?;

    let key_hex = key.iter().map(|b| format!("{b:02x}")).collect::<String>();
    eprintln!("Key (save this): {key_hex}");
    Ok(())
}

fn aes_gcm_decrypt(data: &[u8], output: &str) -> Result<(), Box<dyn std::error::Error>> {
    if data.len() < 12 + 16 {
        return Err("ciphertext too short (need at least iv + tag = 28 bytes)".into());
    }

    let iv = &data[..12];
    let ct_with_tag = &data[12..];

    let key_hex = std::env::var("HITLS_KEY")
        .map_err(|_| "set HITLS_KEY environment variable to the hex key")?;
    let key = hex_decode(&key_hex)?;
    if key.len() != 32 {
        return Err("key must be 32 bytes (64 hex chars)".into());
    }

    let plaintext = hitls_crypto::modes::gcm::gcm_decrypt(&key, iv, b"", ct_with_tag)?;
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
