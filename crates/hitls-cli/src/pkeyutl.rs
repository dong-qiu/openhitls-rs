//! Public key utility: sign, verify, encrypt, decrypt, derive.

use std::fs;

pub fn run(
    op: &str,
    input: &str,
    output: Option<&str>,
    inkey: &str,
    peerkey: Option<&str>,
    sigfile: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_pem = fs::read_to_string(inkey)?;
    let input_data = fs::read(input)?;

    let result = match op {
        "sign" => do_sign(&key_pem, &input_data)?,
        "verify" => {
            let sig_path = sigfile.ok_or("--sigfile required for verify")?;
            let sig_data = fs::read(sig_path)?;
            return do_verify(&key_pem, &input_data, &sig_data);
        }
        "encrypt" => do_encrypt(&key_pem, &input_data)?,
        "decrypt" => do_decrypt(&key_pem, &input_data)?,
        "derive" => {
            let peer_path = peerkey.ok_or("--peerkey required for derive")?;
            let peer_pem = fs::read_to_string(peer_path)?;
            do_derive(&key_pem, &peer_pem)?
        }
        _ => {
            return Err(
                format!("unknown operation: {op} (use sign/verify/encrypt/decrypt/derive)").into(),
            )
        }
    };

    if let Some(out_path) = output {
        fs::write(out_path, &result)?;
        eprintln!("Output written to {out_path} ({} bytes)", result.len());
    } else {
        let hex: String = result.iter().map(|b| format!("{b:02x}")).collect();
        println!("{hex}");
    }

    Ok(())
}

fn do_sign(key_pem: &str, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = parse_pkcs8_key(key_pem)?;
    match key {
        hitls_pki::pkcs8::Pkcs8PrivateKey::Rsa(priv_key) => {
            let digest = hitls_crypto::sha2::Sha256::digest(data)?;
            let sig = priv_key.sign(hitls_crypto::rsa::RsaPadding::Pss, &digest)?;
            Ok(sig)
        }
        hitls_pki::pkcs8::Pkcs8PrivateKey::Ed25519(kp) => {
            let sig = kp.sign(data)?;
            Ok(sig.to_vec())
        }
        _ => Err("sign not supported for this key type".into()),
    }
}

fn do_verify(key_pem: &str, data: &[u8], sig: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let key = parse_pkcs8_key(key_pem)?;
    let valid = match key {
        hitls_pki::pkcs8::Pkcs8PrivateKey::Ed25519(kp) => kp.verify(data, sig)?,
        _ => return Err("verify: only Ed25519 supported in this version".into()),
    };
    if valid {
        println!("Signature Verified Successfully");
        Ok(())
    } else {
        Err("Verification Failure".into())
    }
}

fn do_encrypt(key_pem: &str, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = parse_pkcs8_key(key_pem)?;
    match key {
        hitls_pki::pkcs8::Pkcs8PrivateKey::Rsa(priv_key) => {
            let pub_key = priv_key.public_key();
            let ct = pub_key.encrypt(hitls_crypto::rsa::RsaPadding::Oaep, data)?;
            Ok(ct)
        }
        _ => Err("encrypt only supported for RSA keys".into()),
    }
}

fn do_decrypt(key_pem: &str, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = parse_pkcs8_key(key_pem)?;
    match key {
        hitls_pki::pkcs8::Pkcs8PrivateKey::Rsa(priv_key) => {
            let pt = priv_key.decrypt(hitls_crypto::rsa::RsaPadding::Oaep, data)?;
            Ok(pt)
        }
        _ => Err("decrypt only supported for RSA keys".into()),
    }
}

fn do_derive(_key_pem: &str, _peer_pem: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Err("key derivation not yet supported in pkeyutl".into())
}

fn parse_pkcs8_key(
    pem_str: &str,
) -> Result<hitls_pki::pkcs8::Pkcs8PrivateKey, Box<dyn std::error::Error>> {
    hitls_pki::pkcs8::parse_pkcs8_pem(pem_str)
        .map_err(|e| format!("PKCS#8 parse failed: {e}").into())
}
