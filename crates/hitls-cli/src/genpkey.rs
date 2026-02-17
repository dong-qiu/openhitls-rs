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

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_curve_id
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_curve_id_p256_aliases() {
        for name in &["P-256", "p256", "prime256v1", "secp256r1"] {
            let id = parse_curve_id(name).unwrap();
            assert_eq!(id, hitls_types::EccCurveId::NistP256, "failed for {name}");
        }
    }

    #[test]
    fn test_parse_curve_id_p384() {
        assert_eq!(
            parse_curve_id("P-384").unwrap(),
            hitls_types::EccCurveId::NistP384
        );
        assert_eq!(
            parse_curve_id("secp384r1").unwrap(),
            hitls_types::EccCurveId::NistP384
        );
    }

    #[test]
    fn test_parse_curve_id_sm2() {
        assert_eq!(
            parse_curve_id("sm2").unwrap(),
            hitls_types::EccCurveId::Sm2Prime256
        );
        assert_eq!(
            parse_curve_id("SM2P256V1").unwrap(),
            hitls_types::EccCurveId::Sm2Prime256
        );
    }

    #[test]
    fn test_parse_curve_id_unknown() {
        assert!(parse_curve_id("P-521").is_err());
        assert!(parse_curve_id("brainpool").is_err());
    }

    // -----------------------------------------------------------------------
    // parse_mlkem_param
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_mlkem_param_512() {
        assert_eq!(parse_mlkem_param("512").unwrap(), 512);
    }

    #[test]
    fn test_parse_mlkem_param_768() {
        assert_eq!(parse_mlkem_param("768").unwrap(), 768);
    }

    #[test]
    fn test_parse_mlkem_param_1024() {
        assert_eq!(parse_mlkem_param("1024").unwrap(), 1024);
    }

    #[test]
    fn test_parse_mlkem_param_default_empty() {
        // Empty string maps to 768
        assert_eq!(parse_mlkem_param("").unwrap(), 768);
    }

    #[test]
    fn test_parse_mlkem_param_unknown() {
        assert!(parse_mlkem_param("256").is_err());
    }

    // -----------------------------------------------------------------------
    // parse_mldsa_param
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_mldsa_param_44() {
        assert_eq!(parse_mldsa_param("44").unwrap(), 44);
    }

    #[test]
    fn test_parse_mldsa_param_65() {
        assert_eq!(parse_mldsa_param("65").unwrap(), 65);
    }

    #[test]
    fn test_parse_mldsa_param_87() {
        assert_eq!(parse_mldsa_param("87").unwrap(), 87);
    }

    #[test]
    fn test_parse_mldsa_param_unknown() {
        assert!(parse_mldsa_param("128").is_err());
    }

    // -----------------------------------------------------------------------
    // run() — fast key types only (RSA excluded: too slow for unit tests)
    // -----------------------------------------------------------------------

    #[test]
    fn test_run_ec_p256() {
        let result = run("ec", None, Some("P-256"), None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_ecdsa_p384() {
        let result = run("ecdsa", None, Some("P-384"), None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_ed25519() {
        let result = run("ed25519", None, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_x25519() {
        let result = run("x25519", None, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_mlkem_768() {
        let result = run("ml-kem", None, Some("768"), None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_mldsa_65() {
        let result = run("ml-dsa", None, Some("65"), None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_unknown_algorithm() {
        let result = run("unknown-algo", None, None, None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported algorithm"));
    }

    #[test]
    fn test_run_output_to_file() {
        use std::fs;
        let tmp = std::env::temp_dir().join("test_genpkey_ed25519.pem");
        let result = run("ed25519", None, None, Some(tmp.to_str().unwrap()));
        assert!(result.is_ok());
        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("PUBLIC KEY"));
        let _ = fs::remove_file(&tmp);
    }
}
