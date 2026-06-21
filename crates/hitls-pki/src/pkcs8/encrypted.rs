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
use hitls_crypto::pbkdf2::{self, Pbkdf2Prf};
use hitls_types::CryptoError;
use hitls_utils::asn1::{Decoder, Encoder};

use crate::encoding::bytes_to_u32;
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
    check
        .read_sequence()
        .map_err(|_| CryptoError::InvalidPadding)?;

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
    getrandom::fill(&mut salt).map_err(|_| CryptoError::DrbgEntropyFail)?;
    let mut iv = vec![0u8; 16];
    getrandom::fill(&mut iv).map_err(|_| CryptoError::DrbgEntropyFail)?;

    // Derive key using PBKDF2-HMAC-SHA256
    let key = pbkdf2::pbkdf2(password.as_bytes(), &salt, iterations, key_len)?;

    // Encrypt with AES-CBC
    let encrypted = cbc::cbc_encrypt(&key, &iv, private_key_info)?;

    // Select cipher OID based on key length
    let cipher_oid = match key_len {
        16 => known::aes128_cbc(),
        32 => known::aes256_cbc(),
        _ => return Err(CryptoError::InvalidArg("")),
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

    // PBKDF2 parameters — RFC 8018 §5.2:
    //   PBKDF2-params ::= SEQUENCE {
    //       salt OCTET STRING, iterationCount INTEGER,
    //       keyLength INTEGER OPTIONAL,
    //       prf AlgorithmIdentifier DEFAULT hmacWithSHA1 }
    let mut pbkdf2_params = kdf.read_sequence()?;
    let salt = pbkdf2_params.read_octet_string()?.to_vec();
    let iter_bytes = pbkdf2_params.read_integer()?;
    let iterations = bytes_to_u32(iter_bytes);

    // The PRF defaults to HMAC-SHA-1 when the optional `prf` field is absent
    // (this is exactly what OpenSSL emits for its legacy default). Previously
    // this field was ignored and the key was always derived with HMAC-SHA-256
    // — silently unable to decrypt HMAC-SHA1/384/512/SM3 keys produced by
    // OpenSSL and other implementations.
    let mut prf = Pbkdf2Prf::HmacSha1;
    while !pbkdf2_params.is_empty() {
        match pbkdf2_params.peek_tag()?.number {
            0x02 => {
                // keyLength INTEGER — the cipher determines the key length, so
                // read and ignore (rarely present for AES schemes).
                let _ = pbkdf2_params.read_integer()?;
            }
            0x10 => {
                // prf AlgorithmIdentifier SEQUENCE { OID [, NULL] }
                let mut prf_alg = pbkdf2_params.read_sequence()?;
                let prf_oid = Oid::from_der_value(prf_alg.read_oid()?)?;
                prf = prf_from_oid(&prf_oid)?;
                break;
            }
            _ => return Err(CryptoError::DecodeAsn1Fail),
        }
    }

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

    let key = pbkdf2::pbkdf2_prf(prf, password.as_bytes(), &salt, iterations, key_len)?;
    cbc::cbc_decrypt(&key, &iv, encrypted)
}

/// Map a PBKDF2 `prf` AlgorithmIdentifier OID to the PRF selector
/// (RFC 8018 / GM/T). Unknown OIDs are rejected rather than silently
/// downgraded.
fn prf_from_oid(oid: &Oid) -> Result<Pbkdf2Prf, CryptoError> {
    Ok(if *oid == known::hmac_sha1_oid() {
        Pbkdf2Prf::HmacSha1
    } else if *oid == known::hmac_sha224_oid() {
        Pbkdf2Prf::HmacSha224
    } else if *oid == known::hmac_sha256_oid() {
        Pbkdf2Prf::HmacSha256
    } else if *oid == known::hmac_sha384_oid() {
        Pbkdf2Prf::HmacSha384
    } else if *oid == known::hmac_sha512_oid() {
        Pbkdf2Prf::HmacSha512
    } else if *oid == known::hmac_sm3_oid() {
        Pbkdf2Prf::HmacSm3
    } else {
        return Err(CryptoError::DecodeUnknownOid);
    })
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
    // PBKDF2 params: SEQUENCE { salt, iterations, prf=hmacWithSHA256 }.
    // The explicit `prf` field is required for self-consistency: we derive the
    // key with HMAC-SHA-256 (see `encrypt_pkcs8_der_with`), so omitting `prf`
    // (which implies the RFC 8018 default HMAC-SHA-1) would make the output
    // undecryptable by any standards-conformant peer (e.g. OpenSSL).
    let mut pbkdf2_body = Encoder::new();
    pbkdf2_body.write_octet_string(salt);
    let iter_bytes = iterations.to_be_bytes();
    let iter_trimmed = trim_leading_zeros(&iter_bytes);
    pbkdf2_body.write_integer(iter_trimmed);
    let mut prf_alg = Encoder::new();
    prf_alg.write_oid(&known::hmac_sha256_oid().to_der_value());
    prf_alg.write_null();
    let prf_bytes = prf_alg.finish();
    pbkdf2_body.write_sequence(&prf_bytes);
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

    use hitls_utils::hex::{hex, to_hex};

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
        // Wrong password → PBKDF2 derives a different AES key →
        // CBC-decrypt either yields random bytes that fail the
        // post-decrypt SEQUENCE-validation check (mapped to
        // `CryptoError::InvalidPadding` in `decrypt_pkcs8_der`'s
        // map_err arm) or the AES-CBC unpadding itself rejects the
        // garbage trailing byte. Either path surfaces
        // `CryptoError::InvalidPadding`.
        assert!(matches!(
            decrypt_pkcs8_der(&encrypted, "wrong").unwrap_err(),
            CryptoError::InvalidPadding
        ));
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

    #[test]
    fn test_encrypted_pkcs8_invalid_key_len() {
        let seed = [0x42u8; 32];
        let pki_der = encode_ed25519_pkcs8_der(&seed);
        // key_len = 24 (AES-192) is not supported for PKCS#8 encryption
        // — PBKDF2 derives a 24-byte key OK; AES-192 CBC then accepts
        // it; only the `match key_len` cipher-OID lookup at the bottom
        // of `encrypt_pkcs8_der_with` rejects it with
        // `CryptoError::InvalidArg("")`.
        assert!(matches!(
            encrypt_pkcs8_der_with(&pki_der, "pass", 24, 2048).unwrap_err(),
            CryptoError::InvalidArg(_)
        ));
        // key_len = 8 fails earlier — PBKDF2 derives 8 bytes, but the
        // AES key constructor inside `cbc_encrypt` rejects a
        // non-{16,24,32} key with `CryptoError::InvalidKey` (the
        // unit-discriminant variant, not the `InvalidKeyLength`
        // struct-variant — AES rejects the size class outright rather
        // than reporting expected/got).
        assert!(matches!(
            encrypt_pkcs8_der_with(&pki_der, "pass", 8, 2048).unwrap_err(),
            CryptoError::InvalidKey
        ));
    }

    #[test]
    fn test_encrypted_pkcs8_empty_password() {
        let seed = [0x42u8; 32];
        let pki_der = encode_ed25519_pkcs8_der(&seed);
        // Empty password should roundtrip successfully
        let encrypted = encrypt_pkcs8_der(&pki_der, "").unwrap();
        let decrypted = decrypt_pkcs8_der(&encrypted, "").unwrap();
        assert_eq!(pki_der, decrypted);
    }

    #[test]
    fn test_encrypted_pkcs8_custom_iterations() {
        let seed = [0x42u8; 32];
        let pki_der = encode_ed25519_pkcs8_der(&seed);
        // Low iterations (1) and high iterations (10000) should both work
        for iters in [1u32, 100, 10000] {
            let encrypted = encrypt_pkcs8_der_with(&pki_der, "pass", 32, iters).unwrap();
            let decrypted = decrypt_pkcs8_der(&encrypted, "pass").unwrap();
            assert_eq!(
                pki_der, decrypted,
                "roundtrip failed for iterations={iters}"
            );
        }
    }

    #[test]
    fn test_encrypted_pkcs8_different_encryptions_differ() {
        let seed = [0x42u8; 32];
        let pki_der = encode_ed25519_pkcs8_der(&seed);
        // Two encryptions of the same key with the same password produce different DER
        // (due to random salt and IV)
        let enc1 = encrypt_pkcs8_der(&pki_der, "same").unwrap();
        let enc2 = encrypt_pkcs8_der(&pki_der, "same").unwrap();
        assert_ne!(enc1, enc2);
        // But both decrypt to the same plaintext
        let dec1 = decrypt_pkcs8_der(&enc1, "same").unwrap();
        let dec2 = decrypt_pkcs8_der(&enc2, "same").unwrap();
        assert_eq!(dec1, dec2);
        assert_eq!(dec1, pki_der);
    }

    // ── OpenSSL interop vectors (independent oracle) ──────────────────────
    // Generated with OpenSSL 3.6.2 from one EC P-256 key:
    //   openssl pkcs8 -topk8 -in k.pem -v2 <cipher> -v2prf <prf> -passout pass:interop-test
    // The decrypted inner PrivateKeyInfo is byte-identical across all three
    // (same key), and equals the `-topk8 -nocrypt` DER below. These cannot
    // false-pass: a wrong PRF derives a wrong AES key and CBC-unpad fails.
    const OPENSSL_PLAINTEXT_DER: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420a4429b5ea635d90701b6e8b1bf9d22f48b888389112914a05cb820161768ccaca1440342000460cdf520f8d7d4db79477a468105bd4f88d232f348264f581122e5d0d92cc556188fe9ff8119becf31fc93a19b43c152b3112307d6bddc95a82f49d026c7d71c";
    const OPENSSL_PW: &str = "interop-test";

    /// HMAC-SHA1 PRF, AES-256-CBC — OpenSSL's *omitted-prf* legacy default
    /// (the case the old SHA-256-hardcoded decryptor could not read).
    const OPENSSL_ENC_SHA1: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n\
MIHmMFEGCSqGSIb3DQEFDTBEMCMGCSqGSIb3DQEFDDAWBBDRst8Vh/X1UwZlz3lJ\n\
LmT/AgIIADAdBglghkgBZQMEASoEEBp0sW7+scH37DqkY8tR9dMEgZBkTsESlAST\n\
qPXQeU2eQwaeE8y8Uv4wjuz/6xQMB0g5iWRFee7D/6DfexMHPNncVTZVujKCSPsJ\n\
yoUwLLCZiV0nQXini8BIcuLv7tFFWoPPxuhkyANtQN3tAK10CVodIsjbMaiC9UYh\n\
ynkHjzSKPOe+RBNHIQg73z529hvWOGu7K7bph+eztU8pRdh28njXZB8=\n\
-----END ENCRYPTED PRIVATE KEY-----\n";

    /// HMAC-SHA384 PRF (explicit), AES-256-CBC.
    const OPENSSL_ENC_SHA384: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n\
MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBCm9VJOWzMVZboqY+/z\n\
NpXDAgIIADAMBggqhkiG9w0CCgUAMB0GCWCGSAFlAwQBKgQQTdGXI7c+D8SVWfkb\n\
UzdDZwSBkPg6rGwikq4pif/RS8G4ZD4XUIrYX8LQgWoRU2+G0pUV+8AaJaZVjMFS\n\
QnB3hH0Wpf/xRYMMWX888M2B1RttfIwU7seOugYO/2Cz21Pl82ZvPv7filKD4R8D\n\
hGn+7s0LkdwiTrRPTEdTFbAf2PC2WyO0rXMb+Boku7A+CCKhB+pkZjXdCulx7Rt+\n\
MF5E/FnIfA==\n\
-----END ENCRYPTED PRIVATE KEY-----\n";

    /// HMAC-SHA512 PRF (explicit), AES-128-CBC.
    const OPENSSL_ENC_SHA512: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n\
MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBBcjKPJ5rXLc3qzQDtB\n\
wEibAgIIADAMBggqhkiG9w0CCwUAMB0GCWCGSAFlAwQBAgQQc6BrydUWoWCZYjZS\n\
28TcxASBkGjOMZLTb/lTs1oqF1k91NhKweJFGxZWwf2d5C6vH/YzT0PfjDlu31aJ\n\
ovuRMgoZKFkv3D4BoGDQK/ZwqxbD2qeZ/h0wV2dbUeZoUkUyGUhQo1pc8vZOihvh\n\
T06AVX+AVADsK4KjB3chRck5Q9HIFVl8g8S1eMQqfuX1FvzTKFrzX/cSCU2sgyiZ\n\
SHalmKkWZA==\n\
-----END ENCRYPTED PRIVATE KEY-----\n";

    fn assert_decrypts_to_openssl_plaintext(pem: &str) {
        let got = decrypt_pkcs8_pem(pem, OPENSSL_PW).expect("decrypt OpenSSL PBES2 key");
        assert_eq!(
            to_hex(&got),
            OPENSSL_PLAINTEXT_DER,
            "decrypted inner PrivateKeyInfo must match the OpenSSL -nocrypt DER"
        );
        // And it must parse as the EC key it is.
        let key = parse_pkcs8_der(&got).expect("decrypted key parses");
        assert!(matches!(key, Pkcs8PrivateKey::Ec { .. }));
    }

    #[test]
    fn test_pbes2_openssl_interop_hmac_sha1() {
        // The regression target: HMAC-SHA1 with the prf field omitted.
        assert_decrypts_to_openssl_plaintext(OPENSSL_ENC_SHA1);
    }

    #[test]
    fn test_pbes2_openssl_interop_hmac_sha384() {
        assert_decrypts_to_openssl_plaintext(OPENSSL_ENC_SHA384);
    }

    #[test]
    fn test_pbes2_openssl_interop_hmac_sha512() {
        assert_decrypts_to_openssl_plaintext(OPENSSL_ENC_SHA512);
    }

    #[test]
    fn test_pbes2_wrong_password_on_openssl_key_rejected() {
        assert!(decrypt_pkcs8_pem(OPENSSL_ENC_SHA1, "wrong-pw").is_err());
    }

    #[test]
    fn test_pbes2_encrypt_emits_explicit_sha256_prf() {
        // Our own output must carry an explicit hmacWithSHA256 prf so it is
        // self-consistent + decryptable by standards-conformant peers. The
        // hmacWithSHA256 OID DER value is 2a 86 48 86 f7 0d 02 09.
        let seed = [0x42u8; 32];
        let pki = encode_ed25519_pkcs8_der(&seed);
        let enc = encrypt_pkcs8_der(&pki, "pw").unwrap();
        let needle = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09];
        assert!(
            enc.windows(needle.len()).any(|w| w == needle),
            "encrypted PKCS#8 must embed the hmacWithSHA256 prf OID"
        );
    }

    #[test]
    fn test_encrypted_pkcs8_decrypt_twice_same_result() {
        let seed = [0x42u8; 32];
        let pki_der = encode_ed25519_pkcs8_der(&seed);
        let encrypted = encrypt_pkcs8_der(&pki_der, "pass").unwrap();
        // Decrypting the same ciphertext twice yields identical plaintext
        let dec1 = decrypt_pkcs8_der(&encrypted, "pass").unwrap();
        let dec2 = decrypt_pkcs8_der(&encrypted, "pass").unwrap();
        assert_eq!(dec1, dec2);
    }
}
