//! Encrypted PKCS#8 (EncryptedPrivateKeyInfo) support — PBES2 with PBKDF2 + AES-CBC.
//!
//! Implements RFC 5958 EncryptedPrivateKeyInfo parsing and encoding.
//!
//! ```text
//! EncryptedPrivateKeyInfo ::= SEQUENCE {
//!     encryptionAlgorithm  AlgorithmIdentifier,
//!     encryptedData        OCTET STRING
//! }
//! ```

use hitls_crypto::modes::cbc;
use hitls_crypto::pbkdf2;
use hitls_types::CryptoError;
use hitls_utils::asn1::{Decoder, Encoder};
use hitls_utils::oid::{known, Oid};

/// Default PBKDF2 iteration count for encryption.
const DEFAULT_ITERATIONS: u32 = 2048;

/// Decrypt an EncryptedPrivateKeyInfo DER structure.
///
/// Returns the decrypted PrivateKeyInfo DER bytes.
pub fn decrypt_pkcs8_der(der: &[u8], password: &str) -> Result<Vec<u8>, CryptoError> {
    let mut outer = Decoder::new(der);
    let mut seq = outer.read_sequence()?;

    // encryptionAlgorithm AlgorithmIdentifier
    let mut alg = seq.read_sequence()?;
    let alg_oid_bytes = alg.read_oid()?;
    let alg_oid = Oid::from_der_value(alg_oid_bytes)?;
    let alg_params = alg.remaining().to_vec();

    // encryptedData OCTET STRING
    let encrypted = seq.read_octet_string()?.to_vec();

    if alg_oid != known::pbes2() {
        return Err(CryptoError::DecodeUnknownOid);
    }

    let decrypted = decrypt_pbes2(&alg_params, &encrypted, password)?;

    // Validate that decrypted bytes form a valid ASN.1 SEQUENCE (PrivateKeyInfo).
    // CBC padding alone is insufficient — ~1/256 chance random garbage has valid padding.
    let mut check = Decoder::new(&decrypted);
    check.read_sequence().map_err(|_| CryptoError::InvalidPadding)?;

    Ok(decrypted)
}

/// Decrypt a PEM-encoded EncryptedPrivateKeyInfo ("ENCRYPTED PRIVATE KEY" label).
pub fn decrypt_pkcs8_pem(pem: &str, password: &str) -> Result<Vec<u8>, CryptoError> {
    let blocks = hitls_utils::pem::parse(pem)?;
    for block in &blocks {
        if block.label == "ENCRYPTED PRIVATE KEY" {
            return decrypt_pkcs8_der(&block.data, password);
        }
    }
    Err(CryptoError::DecodeAsn1Fail)
}

/// Encrypt a PrivateKeyInfo DER to EncryptedPrivateKeyInfo DER.
///
/// Uses PBES2 with PBKDF2-HMAC-SHA256 + AES-256-CBC (default).
pub fn encrypt_pkcs8_der(private_key_info: &[u8], password: &str) -> Result<Vec<u8>, CryptoError> {
    encrypt_pkcs8_der_with(private_key_info, password, 32, DEFAULT_ITERATIONS)
}

/// Encrypt a PrivateKeyInfo DER with specified key length (16=AES-128, 32=AES-256).
pub fn encrypt_pkcs8_der_with(
    private_key_info: &[u8],
    password: &str,
    key_len: usize,
    iterations: u32,
) -> Result<Vec<u8>, CryptoError> {
    // Generate random salt and IV
    let mut salt = vec![0u8; 16];
    getrandom::getrandom(&mut salt).map_err(|_| CryptoError::DrbgEntropyFail)?;
    let mut iv = vec![0u8; 16];
    getrandom::getrandom(&mut iv).map_err(|_| CryptoError::DrbgEntropyFail)?;

    // Derive key using PBKDF2-HMAC-SHA256
    let key = pbkdf2::pbkdf2(password.as_bytes(), &salt, iterations, key_len)?;

    // Encrypt with AES-CBC
    let encrypted = cbc::cbc_encrypt(&key, &iv, private_key_info)?;

    // Select cipher OID based on key length
    let cipher_oid = match key_len {
        16 => known::aes128_cbc(),
        32 => known::aes256_cbc(),
        _ => return Err(CryptoError::InvalidArg),
    };

    // Build the EncryptedPrivateKeyInfo ASN.1 structure
    encode_encrypted_pkcs8(&salt, iterations, &cipher_oid, &iv, &encrypted)
}

/// Encrypt and encode as PEM with "ENCRYPTED PRIVATE KEY" label.
pub fn encrypt_pkcs8_pem(private_key_info: &[u8], password: &str) -> Result<String, CryptoError> {
    let der = encrypt_pkcs8_der(private_key_info, password)?;
    Ok(hitls_utils::pem::encode("ENCRYPTED PRIVATE KEY", &der))
}

// ─── Internal helpers ───────────────────────────────────────────────────

fn decrypt_pbes2(
    alg_params: &[u8],
    encrypted: &[u8],
    password: &str,
) -> Result<Vec<u8>, CryptoError> {
    let mut dec = Decoder::new(alg_params);
    let mut params = dec.read_sequence()?;

    // KDF algorithm
    let mut kdf = params.read_sequence()?;
    let kdf_oid_bytes = kdf.read_oid()?;
    let kdf_oid = Oid::from_der_value(kdf_oid_bytes)?;
    if kdf_oid != known::pbkdf2_oid() {
        return Err(CryptoError::DecodeUnknownOid);
    }

    // PBKDF2 parameters
    let mut pbkdf2_params = kdf.read_sequence()?;
    let salt = pbkdf2_params.read_octet_string()?.to_vec();
    let iter_bytes = pbkdf2_params.read_integer()?;
    let iterations = bytes_to_u32(iter_bytes);

    // Encryption scheme
    let mut enc = params.read_sequence()?;
    let enc_oid_bytes = enc.read_oid()?;
    let enc_oid = Oid::from_der_value(enc_oid_bytes)?;

    let key_len = if enc_oid == known::aes256_cbc() {
        32
    } else if enc_oid == known::aes128_cbc() {
        16
    } else if enc_oid == known::aes192_cbc() {
        24
    } else {
        return Err(CryptoError::DecodeUnknownOid);
    };

    let iv = enc.read_octet_string()?.to_vec();

    let key = pbkdf2::pbkdf2(password.as_bytes(), &salt, iterations, key_len)?;
    cbc::cbc_decrypt(&key, &iv, encrypted)
}

fn bytes_to_u32(bytes: &[u8]) -> u32 {
    let mut result: u32 = 0;
    for &b in bytes {
        result = (result << 8) | b as u32;
    }
    result
}

/// Encode EncryptedPrivateKeyInfo ASN.1:
///
/// ```text
/// SEQUENCE {
///   SEQUENCE {                          -- AlgorithmIdentifier (PBES2)
///     OID 1.2.840.113549.1.5.13        -- id-PBES2
///     SEQUENCE {                        -- PBES2-params
///       SEQUENCE {                      -- keyDerivationFunc (PBKDF2)
///         OID 1.2.840.113549.1.5.12    -- id-PBKDF2
///         SEQUENCE { OCTET STRING salt, INTEGER iterations }
///       }
///       SEQUENCE {                      -- encryptionScheme
///         OID (aes-256-cbc / aes-128-cbc)
///         OCTET STRING iv
///       }
///     }
///   }
///   OCTET STRING encryptedData
/// }
/// ```
fn encode_encrypted_pkcs8(
    salt: &[u8],
    iterations: u32,
    cipher_oid: &Oid,
    iv: &[u8],
    encrypted: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // PBKDF2 params: SEQUENCE { salt, iterations }
    let mut pbkdf2_body = Encoder::new();
    pbkdf2_body.write_octet_string(salt);
    let iter_bytes = iterations.to_be_bytes();
    let iter_trimmed = trim_leading_zeros(&iter_bytes);
    pbkdf2_body.write_integer(iter_trimmed);
    let pbkdf2_body_bytes = pbkdf2_body.finish();

    // KDF: SEQUENCE { OID(PBKDF2), SEQUENCE(params) }
    let mut kdf_body = Encoder::new();
    kdf_body.write_oid(&known::pbkdf2_oid().to_der_value());
    kdf_body.write_sequence(&pbkdf2_body_bytes);
    let kdf_bytes = kdf_body.finish();

    // Enc scheme: SEQUENCE { OID(cipher), OCTET STRING(iv) }
    let mut enc_body = Encoder::new();
    enc_body.write_oid(&cipher_oid.to_der_value());
    enc_body.write_octet_string(iv);
    let enc_bytes = enc_body.finish();

    // PBES2-params: SEQUENCE { KDF, Enc }
    let mut pbes2_body = Encoder::new();
    pbes2_body.write_sequence(&kdf_bytes);
    pbes2_body.write_sequence(&enc_bytes);
    let pbes2_bytes = pbes2_body.finish();

    // AlgorithmIdentifier: SEQUENCE { OID(PBES2), SEQUENCE(PBES2-params) }
    let mut alg_body = Encoder::new();
    alg_body.write_oid(&known::pbes2().to_der_value());
    alg_body.write_sequence(&pbes2_bytes);
    let alg_bytes = alg_body.finish();

    // EncryptedPrivateKeyInfo: SEQUENCE { AlgId, OCTET STRING }
    let mut outer_body = Encoder::new();
    outer_body.write_sequence(&alg_bytes);
    outer_body.write_octet_string(encrypted);
    let body = outer_body.finish();

    let mut final_enc = Encoder::new();
    final_enc.write_sequence(&body);
    Ok(final_enc.finish())
}

fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < bytes.len() - 1 && bytes[i] == 0 {
        i += 1;
    }
    &bytes[i..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkcs8::{
        encode_ec_pkcs8_der, encode_ed25519_pkcs8_der, parse_pkcs8_der, Pkcs8PrivateKey,
    };
    use hitls_types::EccCurveId;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_encrypted_pkcs8_roundtrip_ed25519() {
        let seed = [0x42u8; 32];
        let pki_der = encode_ed25519_pkcs8_der(&seed);

        let encrypted = encrypt_pkcs8_der(&pki_der, "test-password").unwrap();
        let decrypted = decrypt_pkcs8_der(&encrypted, "test-password").unwrap();

        assert_eq!(pki_der, decrypted);

        // Verify the decrypted key is usable
        let key = parse_pkcs8_der(&decrypted).unwrap();
        match key {
            Pkcs8PrivateKey::Ed25519(_) => {}
            _ => panic!("Expected Ed25519"),
        }
    }

    #[test]
    fn test_encrypted_pkcs8_roundtrip_ec() {
        let private_key = hex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let pki_der = encode_ec_pkcs8_der(EccCurveId::NistP256, &private_key);

        let encrypted = encrypt_pkcs8_der(&pki_der, "my-secret").unwrap();
        let decrypted = decrypt_pkcs8_der(&encrypted, "my-secret").unwrap();

        assert_eq!(pki_der, decrypted);
    }

    #[test]
    fn test_encrypted_pkcs8_wrong_password() {
        let seed = [0x55u8; 32];
        let pki_der = encode_ed25519_pkcs8_der(&seed);

        let encrypted = encrypt_pkcs8_der(&pki_der, "correct").unwrap();
        // Wrong password should fail during decryption (bad padding)
        assert!(decrypt_pkcs8_der(&encrypted, "wrong").is_err());
    }

    #[test]
    fn test_encrypted_pkcs8_aes128_compat() {
        let seed = [0x42u8; 32];
        let pki_der = encode_ed25519_pkcs8_der(&seed);

        // Encrypt with AES-128-CBC
        let encrypted = encrypt_pkcs8_der_with(&pki_der, "pass128", 16, 1000).unwrap();
        let decrypted = decrypt_pkcs8_der(&encrypted, "pass128").unwrap();

        assert_eq!(pki_der, decrypted);
    }

    #[test]
    fn test_encrypted_pkcs8_pem_roundtrip() {
        let seed = [0x42u8; 32];
        let pki_der = encode_ed25519_pkcs8_der(&seed);

        let pem = encrypt_pkcs8_pem(&pki_der, "pem-pass").unwrap();
        assert!(pem.contains("ENCRYPTED PRIVATE KEY"));

        let decrypted = decrypt_pkcs8_pem(&pem, "pem-pass").unwrap();
        assert_eq!(pki_der, decrypted);
    }
}
