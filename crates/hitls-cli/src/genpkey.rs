//! Key generation command implementation.

use std::fs;

pub fn run(
    algorithm: &str,
    bits: Option<u32>,
    curve: Option<&str>,
    output: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let pem = match algorithm.to_lowercase().as_str() {
        "rsa" => generate_rsa(bits.unwrap_or(2048))?,
        "ec" | "ecdsa" => generate_ec(curve.unwrap_or("P-256"))?,
        "ed25519" => generate_ed25519()?,
        "x25519" => generate_x25519()?,
        "ml-kem" | "mlkem" => generate_mlkem(curve.unwrap_or("768"))?,
        "ml-dsa" | "mldsa" => generate_mldsa(curve.unwrap_or("65"))?,
        _ => return Err(format!("unsupported algorithm: {algorithm}").into()),
    };

    if let Some(path) = output {
        fs::write(path, &pem)?;
        eprintln!("Key written to {path}");
    } else {
        print!("{pem}");
    }
    Ok(())
}

fn generate_rsa(bits: u32) -> Result<String, Box<dyn std::error::Error>> {
    eprintln!("Generating RSA private key, {bits} bit long modulus...");
    let key = hitls_crypto::rsa::RsaPrivateKey::generate(bits as usize)?;
    let pub_key = key.public_key();
    eprintln!("RSA key generated ({} bits)", pub_key.bits());
    let pem = hitls_utils::pem::encode(
        "RSA PUBLIC KEY",
        &format!("bits={}", pub_key.bits()).into_bytes(),
    );
    Ok(pem)
}

fn generate_ec(curve_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let curve_id = parse_curve_id(curve_name)?;
    eprintln!("Generating EC key for curve {curve_name}...");
    let kp = hitls_crypto::ecdsa::EcdsaKeyPair::generate(curve_id)?;
    let pub_bytes = kp.public_key_bytes()?;
    let pem = hitls_utils::pem::encode("PUBLIC KEY", &pub_bytes);
    Ok(pem)
}

fn generate_ed25519() -> Result<String, Box<dyn std::error::Error>> {
    eprintln!("Generating Ed25519 key...");
    let kp = hitls_crypto::ed25519::Ed25519KeyPair::generate()?;
    let pub_bytes = kp.public_key();
    let pem = hitls_utils::pem::encode("ED25519 PUBLIC KEY", pub_bytes);
    Ok(pem)
}

fn generate_x25519() -> Result<String, Box<dyn std::error::Error>> {
    eprintln!("Generating X25519 key...");
    let sk = hitls_crypto::x25519::X25519PrivateKey::generate()?;
    let pk = sk.public_key();
    let pem = hitls_utils::pem::encode("X25519 PUBLIC KEY", pk.as_bytes());
    Ok(pem)
}

fn generate_mlkem(param: &str) -> Result<String, Box<dyn std::error::Error>> {
    let ps = parse_mlkem_param(param)?;
    eprintln!("Generating ML-KEM-{ps} key...");
    let kp = hitls_crypto::mlkem::MlKemKeyPair::generate(ps)?;
    let ek = kp.encapsulation_key();
    let pem = hitls_utils::pem::encode("ML-KEM PUBLIC KEY", ek);
    Ok(pem)
}

fn generate_mldsa(param: &str) -> Result<String, Box<dyn std::error::Error>> {
    let ps = parse_mldsa_param(param)?;
    eprintln!("Generating ML-DSA-{ps} key...");
    let kp = hitls_crypto::mldsa::MlDsaKeyPair::generate(ps)?;
    let vk = kp.public_key();
    let pem = hitls_utils::pem::encode("ML-DSA PUBLIC KEY", vk);
    Ok(pem)
}

fn parse_curve_id(name: &str) -> Result<hitls_types::EccCurveId, Box<dyn std::error::Error>> {
    match name.to_lowercase().as_str() {
        "p-256" | "p256" | "prime256v1" | "secp256r1" => Ok(hitls_types::EccCurveId::NistP256),
        "p-384" | "p384" | "secp384r1" => Ok(hitls_types::EccCurveId::NistP384),
        "sm2" | "sm2p256v1" => Ok(hitls_types::EccCurveId::Sm2Prime256),
        _ => Err(format!("unsupported curve: {name}").into()),
    }
}

fn parse_mlkem_param(name: &str) -> Result<u32, Box<dyn std::error::Error>> {
    match name
        .to_uppercase()
        .replace('-', "")
        .replace("MLKEM", "")
        .as_str()
    {
        "512" => Ok(512),
        "768" | "" => Ok(768),
        "1024" => Ok(1024),
        _ => Err(format!("unsupported ML-KEM parameter set: {name}").into()),
    }
}

fn parse_mldsa_param(name: &str) -> Result<u32, Box<dyn std::error::Error>> {
    match name
        .to_uppercase()
        .replace('-', "")
        .replace("MLDSA", "")
        .as_str()
    {
        "44" => Ok(44),
        "65" | "" => Ok(65),
        "87" => Ok(87),
        _ => Err(format!("unsupported ML-DSA parameter set: {name}").into()),
    }
}
