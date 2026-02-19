//! PKCS#8 Private Key Parsing and Encoding (RFC 5958).
//!
//! Supports parsing and encoding of PrivateKeyInfo structures for:
//! - RSA (PKCS#1)
//! - ECDSA (P-224, P-256, P-384, P-521, Brainpool)
//! - Ed25519 (RFC 8032)
//! - Ed448 (RFC 8032)
//! - X25519 (RFC 7748)
//! - X448 (RFC 7748)
//! - DSA (FIPS 186-4)
//!
//! Also supports Encrypted PKCS#8 (EncryptedPrivateKeyInfo) via the `encrypted` submodule.

pub mod encrypted;

use hitls_crypto::dsa::{DsaKeyPair, DsaParams};
use hitls_crypto::ecdsa::EcdsaKeyPair;
use hitls_crypto::ed25519::Ed25519KeyPair;
use hitls_crypto::ed448::Ed448KeyPair;
use hitls_crypto::rsa::RsaPrivateKey;
use hitls_crypto::x25519::X25519PrivateKey;
use hitls_crypto::x448::X448PrivateKey;
use hitls_types::{CryptoError, EccCurveId};
use hitls_utils::asn1::{Decoder, Encoder};
use hitls_utils::oid::{known, Oid};

/// A parsed PKCS#8 private key.
pub enum Pkcs8PrivateKey {
    /// RSA private key (PKCS#1).
    Rsa(RsaPrivateKey),
    /// ECDSA private key with curve identifier.
    Ec {
        curve_id: EccCurveId,
        key_pair: EcdsaKeyPair,
    },
    /// Ed25519 private key.
    Ed25519(Ed25519KeyPair),
    /// Ed448 private key.
    Ed448(Ed448KeyPair),
    /// X25519 private key.
    X25519(X25519PrivateKey),
    /// X448 private key.
    X448(X448PrivateKey),
    /// DSA private key with domain parameters.
    Dsa {
        params: DsaParams,
        key_pair: DsaKeyPair,
    },
}

/// A parsed SPKI (SubjectPublicKeyInfo) public key.
///
/// Used for peer public key parsing in key agreement (e.g., `pkeyutl derive`).
pub enum SpkiPublicKey {
    /// X25519 public key (32 bytes).
    X25519(Vec<u8>),
    /// X448 public key (56 bytes).
    X448(Vec<u8>),
    /// EC public key with curve identifier (uncompressed point).
    Ec {
        curve_id: EccCurveId,
        public_key: Vec<u8>,
    },
}

/// Parse a DER-encoded PKCS#8 PrivateKeyInfo.
///
/// ```text
/// PrivateKeyInfo ::= SEQUENCE {
///     version                   INTEGER,
///     privateKeyAlgorithm       AlgorithmIdentifier,
///     privateKey                OCTET STRING
/// }
/// ```
pub fn parse_pkcs8_der(der: &[u8]) -> Result<Pkcs8PrivateKey, CryptoError> {
    let mut outer = Decoder::new(der);
    let mut seq = outer.read_sequence()?;

    // version (INTEGER, must be 0 or 1)
    let version_bytes = seq.read_integer()?;
    let version = parse_small_int(version_bytes);
    if version > 1 {
        return Err(CryptoError::DecodeAsn1Fail);
    }

    // privateKeyAlgorithm (AlgorithmIdentifier SEQUENCE)
    let mut alg_id = seq.read_sequence()?;
    let oid_bytes = alg_id.read_oid()?;
    let algorithm_oid = Oid::from_der_value(oid_bytes)?;

    // Optional algorithm parameters (rest of AlgorithmIdentifier)
    let alg_params = alg_id.remaining().to_vec();

    // privateKey (OCTET STRING)
    let private_key_bytes = seq.read_octet_string()?;

    // Dispatch on algorithm OID
    if algorithm_oid == known::rsa_encryption() {
        parse_rsa_private_key(private_key_bytes)
    } else if algorithm_oid == known::ec_public_key() {
        parse_ec_private_key(&alg_params, private_key_bytes)
    } else if algorithm_oid == known::ed25519() {
        parse_ed25519_private_key(private_key_bytes)
    } else if algorithm_oid == known::ed448() {
        parse_ed448_private_key(private_key_bytes)
    } else if algorithm_oid == known::x25519() {
        parse_x25519_private_key(private_key_bytes)
    } else if algorithm_oid == known::x448() {
        parse_x448_private_key(private_key_bytes)
    } else if algorithm_oid == known::dsa() {
        parse_dsa_private_key(&alg_params, private_key_bytes)
    } else {
        Err(CryptoError::DecodeUnknownOid)
    }
}

/// Parse a PEM-encoded PKCS#8 private key ("PRIVATE KEY" label).
pub fn parse_pkcs8_pem(pem: &str) -> Result<Pkcs8PrivateKey, CryptoError> {
    let blocks = hitls_utils::pem::parse(pem)?;
    for block in &blocks {
        if block.label == "PRIVATE KEY" {
            return parse_pkcs8_der(&block.data);
        }
    }
    Err(CryptoError::DecodeAsn1Fail)
}

/// Encode a PKCS#8 PrivateKeyInfo to DER given the raw components.
///
/// This is a low-level function. Use it when you have the raw key bytes
/// and algorithm OID ready.
pub fn encode_pkcs8_der_raw(
    algorithm_oid: &Oid,
    algorithm_params: Option<&[u8]>,
    private_key_der: &[u8],
) -> Vec<u8> {
    // Build AlgorithmIdentifier SEQUENCE
    let mut alg_enc = Encoder::new();
    alg_enc.write_oid(&algorithm_oid.to_der_value());
    if let Some(params) = algorithm_params {
        // Write raw param bytes (already DER-encoded)
        alg_enc.write_raw(params);
    } else {
        alg_enc.write_null();
    }
    let alg_bytes = alg_enc.finish();

    // Build PrivateKeyInfo SEQUENCE
    let mut outer_enc = Encoder::new();
    outer_enc.write_integer(&[0]); // version = 0
    outer_enc.write_sequence(&alg_bytes);
    outer_enc.write_octet_string(private_key_der);
    let body = outer_enc.finish();

    let mut final_enc = Encoder::new();
    final_enc.write_sequence(&body);
    final_enc.finish()
}

/// Encode a PKCS#8 PrivateKeyInfo to PEM.
pub fn encode_pkcs8_pem_raw(
    algorithm_oid: &Oid,
    algorithm_params: Option<&[u8]>,
    private_key_der: &[u8],
) -> String {
    let der = encode_pkcs8_der_raw(algorithm_oid, algorithm_params, private_key_der);
    hitls_utils::pem::encode("PRIVATE KEY", &der)
}

// ===== RSA =====

/// Parse an RSAPrivateKey SEQUENCE (PKCS#1 format inside PKCS#8).
///
/// ```text
/// RSAPrivateKey ::= SEQUENCE {
///     version           INTEGER,
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER,  -- e
///     privateExponent   INTEGER,  -- d
///     prime1            INTEGER,  -- p
///     prime2            INTEGER,  -- q
///     exponent1         INTEGER,  -- dp (ignored, recomputed)
///     exponent2         INTEGER,  -- dq (ignored, recomputed)
///     coefficient       INTEGER   -- qinv (ignored, recomputed)
/// }
/// ```
fn parse_rsa_private_key(data: &[u8]) -> Result<Pkcs8PrivateKey, CryptoError> {
    let mut dec = Decoder::new(data);
    let mut seq = dec.read_sequence()?;

    // version
    let _version = seq.read_integer()?;

    // n, e, d, p, q
    let n = strip_leading_zero(seq.read_integer()?);
    let e = strip_leading_zero(seq.read_integer()?);
    let d = strip_leading_zero(seq.read_integer()?);
    let p = strip_leading_zero(seq.read_integer()?);
    let q = strip_leading_zero(seq.read_integer()?);

    // dp, dq, qinv are present but we let RsaPrivateKey::new recompute them
    // (read them to advance the decoder)
    let _dp = seq.read_integer()?;
    let _dq = seq.read_integer()?;
    let _qinv = seq.read_integer()?;

    let key = RsaPrivateKey::new(n, d, e, p, q)?;
    Ok(Pkcs8PrivateKey::Rsa(key))
}

// ===== EC =====

/// Parse EC algorithm parameters to extract curve OID → EccCurveId.
fn parse_ec_curve_oid(params: &[u8]) -> Result<EccCurveId, CryptoError> {
    if params.is_empty() {
        return Err(CryptoError::DecodeAsn1Fail);
    }

    let mut dec = Decoder::new(params);
    let oid_bytes = dec.read_oid()?;
    let curve_oid = Oid::from_der_value(oid_bytes)?;

    oid_to_curve_id(&curve_oid)
}

/// Map a curve OID to an EccCurveId.
fn oid_to_curve_id(oid: &Oid) -> Result<EccCurveId, CryptoError> {
    if *oid == known::secp224r1() {
        Ok(EccCurveId::NistP224)
    } else if *oid == known::prime256v1() {
        Ok(EccCurveId::NistP256)
    } else if *oid == known::secp384r1() {
        Ok(EccCurveId::NistP384)
    } else if *oid == known::secp521r1() {
        Ok(EccCurveId::NistP521)
    } else if *oid == known::brainpool_p256r1() {
        Ok(EccCurveId::BrainpoolP256r1)
    } else if *oid == known::brainpool_p384r1() {
        Ok(EccCurveId::BrainpoolP384r1)
    } else if *oid == known::brainpool_p512r1() {
        Ok(EccCurveId::BrainpoolP512r1)
    } else {
        Err(CryptoError::DecodeUnknownOid)
    }
}

/// Map an EccCurveId to its OID.
fn curve_id_to_oid(curve_id: EccCurveId) -> Oid {
    match curve_id {
        EccCurveId::NistP224 => known::secp224r1(),
        EccCurveId::NistP256 => known::prime256v1(),
        EccCurveId::NistP384 => known::secp384r1(),
        EccCurveId::NistP521 => known::secp521r1(),
        EccCurveId::BrainpoolP256r1 => known::brainpool_p256r1(),
        EccCurveId::BrainpoolP384r1 => known::brainpool_p384r1(),
        EccCurveId::BrainpoolP512r1 => known::brainpool_p512r1(),
        _ => known::prime256v1(), // fallback
    }
}

/// Parse an ECPrivateKey (RFC 5915) from the PKCS#8 privateKey OCTET STRING.
///
/// ```text
/// ECPrivateKey ::= SEQUENCE {
///     version        INTEGER { ecPrivkeyVer1(1) },
///     privateKey     OCTET STRING,
///     parameters [0] ECParameters OPTIONAL,
///     publicKey  [1] BIT STRING OPTIONAL
/// }
/// ```
fn parse_ec_private_key(alg_params: &[u8], data: &[u8]) -> Result<Pkcs8PrivateKey, CryptoError> {
    let curve_id = parse_ec_curve_oid(alg_params)?;

    let mut dec = Decoder::new(data);
    let mut seq = dec.read_sequence()?;

    // version (must be 1)
    let _version = seq.read_integer()?;

    // privateKey (OCTET STRING)
    let private_key = seq.read_octet_string()?;

    let key_pair = EcdsaKeyPair::from_private_key(curve_id, private_key)?;
    Ok(Pkcs8PrivateKey::Ec { curve_id, key_pair })
}

// ===== Ed25519 =====

/// Parse an Ed25519 private key from PKCS#8.
///
/// The privateKey OCTET STRING contains another OCTET STRING wrapping the 32-byte seed.
fn parse_ed25519_private_key(data: &[u8]) -> Result<Pkcs8PrivateKey, CryptoError> {
    // The data is an OCTET STRING wrapping the 32-byte seed
    let mut dec = Decoder::new(data);
    let seed = dec.read_octet_string()?;
    if seed.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    let key_pair = Ed25519KeyPair::from_seed(seed)?;
    Ok(Pkcs8PrivateKey::Ed25519(key_pair))
}

// ===== X25519 =====

/// Parse an X25519 private key from PKCS#8.
///
/// Same structure as Ed25519 — OCTET STRING wrapping 32-byte key.
fn parse_x25519_private_key(data: &[u8]) -> Result<Pkcs8PrivateKey, CryptoError> {
    let mut dec = Decoder::new(data);
    let key_bytes = dec.read_octet_string()?;
    if key_bytes.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    let key = X25519PrivateKey::new(key_bytes)?;
    Ok(Pkcs8PrivateKey::X25519(key))
}

// ===== Ed448 =====

/// Parse an Ed448 private key from PKCS#8.
///
/// The privateKey OCTET STRING contains another OCTET STRING wrapping the 57-byte seed.
fn parse_ed448_private_key(data: &[u8]) -> Result<Pkcs8PrivateKey, CryptoError> {
    let mut dec = Decoder::new(data);
    let seed = dec.read_octet_string()?;
    if seed.len() != 57 {
        return Err(CryptoError::InvalidKey);
    }
    let key_pair = Ed448KeyPair::from_seed(seed)?;
    Ok(Pkcs8PrivateKey::Ed448(key_pair))
}

// ===== X448 =====

/// Parse an X448 private key from PKCS#8.
///
/// Same structure as X25519 — OCTET STRING wrapping 56-byte key.
fn parse_x448_private_key(data: &[u8]) -> Result<Pkcs8PrivateKey, CryptoError> {
    let mut dec = Decoder::new(data);
    let key_bytes = dec.read_octet_string()?;
    if key_bytes.len() != 56 {
        return Err(CryptoError::InvalidKey);
    }
    let key = X448PrivateKey::new(key_bytes)?;
    Ok(Pkcs8PrivateKey::X448(key))
}

// ===== DSA =====

/// Parse DSA algorithm parameters.
///
/// ```text
/// DSAParameters ::= SEQUENCE {
///     p INTEGER,
///     q INTEGER,
///     g INTEGER
/// }
/// ```
fn parse_dsa_params(params: &[u8]) -> Result<DsaParams, CryptoError> {
    if params.is_empty() {
        return Err(CryptoError::DecodeAsn1Fail);
    }

    let mut dec = Decoder::new(params);
    let mut seq = dec.read_sequence()?;

    let p = strip_leading_zero(seq.read_integer()?);
    let q = strip_leading_zero(seq.read_integer()?);
    let g = strip_leading_zero(seq.read_integer()?);

    DsaParams::new(p, q, g)
}

/// Parse a DSA private key from PKCS#8.
///
/// The privateKey OCTET STRING contains a DER-encoded INTEGER (the private key x).
fn parse_dsa_private_key(alg_params: &[u8], data: &[u8]) -> Result<Pkcs8PrivateKey, CryptoError> {
    let params = parse_dsa_params(alg_params)?;

    let mut dec = Decoder::new(data);
    let x = strip_leading_zero(dec.read_integer()?);

    let key_pair = DsaKeyPair::from_private_key(params.clone(), x)?;
    Ok(Pkcs8PrivateKey::Dsa { params, key_pair })
}

// ===== Helpers =====

/// Strip leading zero byte from DER integer (used for unsigned big-endian values).
fn strip_leading_zero(bytes: &[u8]) -> &[u8] {
    if bytes.len() > 1 && bytes[0] == 0 {
        &bytes[1..]
    } else {
        bytes
    }
}

/// Parse a small integer from DER integer bytes.
fn parse_small_int(bytes: &[u8]) -> u32 {
    let mut result: u32 = 0;
    for &b in bytes {
        result = (result << 8) | b as u32;
    }
    result
}

// ===== Encoding helpers =====

/// Encode an Ed25519 seed as a PKCS#8 DER PrivateKeyInfo.
pub fn encode_ed25519_pkcs8_der(seed: &[u8; 32]) -> Vec<u8> {
    // The privateKey is OCTET STRING wrapping the seed
    let mut inner_enc = Encoder::new();
    inner_enc.write_octet_string(seed);
    let private_key_der = inner_enc.finish();

    encode_pkcs8_der_raw(&known::ed25519(), None, &private_key_der)
}

/// Encode an X25519 key as a PKCS#8 DER PrivateKeyInfo.
pub fn encode_x25519_pkcs8_der(key: &[u8; 32]) -> Vec<u8> {
    let mut inner_enc = Encoder::new();
    inner_enc.write_octet_string(key);
    let private_key_der = inner_enc.finish();

    encode_pkcs8_der_raw(&known::x25519(), None, &private_key_der)
}

/// Encode an EC private key as a PKCS#8 DER PrivateKeyInfo.
pub fn encode_ec_pkcs8_der(curve_id: EccCurveId, private_key: &[u8]) -> Vec<u8> {
    let curve_oid = curve_id_to_oid(curve_id);

    // Build ECPrivateKey SEQUENCE
    let mut ec_enc = Encoder::new();
    ec_enc.write_integer(&[1]); // version = 1
    ec_enc.write_octet_string(private_key);
    let ec_body = ec_enc.finish();

    let mut ec_seq_enc = Encoder::new();
    ec_seq_enc.write_sequence(&ec_body);
    let private_key_der = ec_seq_enc.finish();

    // Algorithm params = curve OID
    let mut param_enc = Encoder::new();
    param_enc.write_oid(&curve_oid.to_der_value());
    let params = param_enc.finish();

    encode_pkcs8_der_raw(&known::ec_public_key(), Some(&params), &private_key_der)
}

/// Encode an Ed448 seed as a PKCS#8 DER PrivateKeyInfo.
pub fn encode_ed448_pkcs8_der(seed: &[u8]) -> Vec<u8> {
    let mut inner_enc = Encoder::new();
    inner_enc.write_octet_string(seed);
    let private_key_der = inner_enc.finish();

    encode_pkcs8_der_raw(&known::ed448(), None, &private_key_der)
}

/// Encode an X448 key as a PKCS#8 DER PrivateKeyInfo.
pub fn encode_x448_pkcs8_der(seed: &[u8]) -> Vec<u8> {
    let mut inner_enc = Encoder::new();
    inner_enc.write_octet_string(seed);
    let private_key_der = inner_enc.finish();

    encode_pkcs8_der_raw(&known::x448(), None, &private_key_der)
}

// ===== SPKI (SubjectPublicKeyInfo) Parsing =====

/// Parse a PEM-encoded SubjectPublicKeyInfo ("PUBLIC KEY" label).
///
/// Returns `SpkiPublicKey` identifying the key type and raw public key bytes.
pub fn parse_spki_pem(pem: &str) -> Result<SpkiPublicKey, CryptoError> {
    let blocks = hitls_utils::pem::parse(pem)?;
    for block in &blocks {
        if block.label == "PUBLIC KEY" {
            return parse_spki_der(&block.data);
        }
    }
    Err(CryptoError::DecodeAsn1Fail)
}

/// Parse a DER-encoded SubjectPublicKeyInfo.
///
/// ```text
/// SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm       AlgorithmIdentifier,
///     subjectPublicKey BIT STRING
/// }
/// ```
pub fn parse_spki_der(der: &[u8]) -> Result<SpkiPublicKey, CryptoError> {
    let mut outer = Decoder::new(der);
    let mut seq = outer.read_sequence()?;

    // AlgorithmIdentifier SEQUENCE
    let mut alg_id = seq.read_sequence()?;
    let oid_bytes = alg_id.read_oid()?;
    let algorithm_oid = Oid::from_der_value(oid_bytes)?;
    let alg_params = alg_id.remaining().to_vec();

    // subjectPublicKey BIT STRING
    let (_unused_bits, bit_string) = seq.read_bit_string()?;

    if algorithm_oid == known::x25519() {
        if bit_string.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        Ok(SpkiPublicKey::X25519(bit_string.to_vec()))
    } else if algorithm_oid == known::x448() {
        if bit_string.len() != 56 {
            return Err(CryptoError::InvalidKey);
        }
        Ok(SpkiPublicKey::X448(bit_string.to_vec()))
    } else if algorithm_oid == known::ec_public_key() {
        let curve_id = parse_ec_curve_oid(&alg_params)?;
        Ok(SpkiPublicKey::Ec {
            curve_id,
            public_key: bit_string.to_vec(),
        })
    } else {
        Err(CryptoError::DecodeUnknownOid)
    }
}

/// Encode an X25519 public key as a DER-encoded SubjectPublicKeyInfo.
pub fn encode_x25519_spki_der(public_key: &[u8; 32]) -> Vec<u8> {
    encode_spki_der_raw(&known::x25519(), None, public_key)
}

/// Encode an X448 public key as a DER-encoded SubjectPublicKeyInfo.
pub fn encode_x448_spki_der(public_key: &[u8; 56]) -> Vec<u8> {
    encode_spki_der_raw(&known::x448(), None, public_key)
}

/// Encode an EC public key as a DER-encoded SubjectPublicKeyInfo.
pub fn encode_ec_spki_der(curve_id: EccCurveId, public_key: &[u8]) -> Vec<u8> {
    let curve_oid = curve_id_to_oid(curve_id);
    let mut param_enc = Encoder::new();
    param_enc.write_oid(&curve_oid.to_der_value());
    let params = param_enc.finish();

    encode_spki_der_raw(&known::ec_public_key(), Some(&params), public_key)
}

/// Low-level SPKI encoding helper.
fn encode_spki_der_raw(
    algorithm_oid: &Oid,
    algorithm_params: Option<&[u8]>,
    public_key: &[u8],
) -> Vec<u8> {
    let mut alg_enc = Encoder::new();
    alg_enc.write_oid(&algorithm_oid.to_der_value());
    if let Some(params) = algorithm_params {
        alg_enc.write_raw(params);
    }
    let alg_bytes = alg_enc.finish();

    let mut body_enc = Encoder::new();
    body_enc.write_sequence(&alg_bytes);
    body_enc.write_bit_string(0, public_key);
    let body = body_enc.finish();

    let mut final_enc = Encoder::new();
    final_enc.write_sequence(&body);
    final_enc.finish()
}

/// Encode an SPKI to PEM format.
pub fn encode_spki_pem(der: &[u8]) -> String {
    hitls_utils::pem::encode("PUBLIC KEY", der)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to build a test PKCS#8 Ed25519 key
    fn build_ed25519_test_pkcs8() -> Vec<u8> {
        let seed = [0x42u8; 32];
        encode_ed25519_pkcs8_der(&seed)
    }

    // Helper to build a test PKCS#8 X25519 key
    fn build_x25519_test_pkcs8() -> Vec<u8> {
        let key = [0x42u8; 32];
        encode_x25519_pkcs8_der(&key)
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_parse_ed25519_pkcs8_der() {
        let der = build_ed25519_test_pkcs8();
        let key = parse_pkcs8_der(&der).unwrap();
        match key {
            Pkcs8PrivateKey::Ed25519(_) => {}
            _ => panic!("Expected Ed25519 key"),
        }
    }

    #[test]
    fn test_parse_x25519_pkcs8_der() {
        let der = build_x25519_test_pkcs8();
        let key = parse_pkcs8_der(&der).unwrap();
        match key {
            Pkcs8PrivateKey::X25519(_) => {}
            _ => panic!("Expected X25519 key"),
        }
    }

    #[test]
    fn test_parse_rsa_pkcs8_pem() {
        // Real RSA 2048-bit PKCS#8 key from openHiTLS test data
        let pem = "\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCvU/3U/Xy0GV9p
alx4PRscBL/vllV808hJ6RKS8dDDqQYghIkqhSAMZTWltzM6J9zPzbaHGp99mrhC
yuUpWCt74SLYhpc1b2a4Oro8VWIihRpPQ1EGgjWZ8tShKDLtmhh+ewYMwHawX5RE
3KynwTfS1ajHLRvxTaftn5ZdVfIVpoiIiBpZ73QFABhZxI6dxvu6TDbcDTjqTExj
HjmsyEvUa2PyL+JSglg/MZNBONYSFIaezkpcdFa6FMx6XW4iVz561IMBdVBEc6II
7qWoQJa+lPsKEFQ8P+iG2uvZQSIboddLdOl9IEGZ4EHcMJTzxh17GaCA7BE/Mlsc
7BYph9wTAgMBAAECggEAVHY2ZGpfLlXAyIQ0Grp5OlSxcAZwlWti4/QzffWfN/rP
mE+w0nqCV2ZUY0ovk/cLIVJ8+XXiWnx0Ar1Ci1nNzOZGxp+D7XqGtf6YpCMP3QhZ
BdEskeGdV9YLB73ZVuwym4/BeNgo9Ut+HnReeowSy+8g2R7KhML/wHHuWnViY3nj
hRnd2tit+y8MQcz8fOcgTT6Uuk6XeEutDMN7FoiLIyNX+mKWtsJbeLFWpHVm9ZM/
R7wa4T/NeFVhfJbJ9YTrZDeLX2dm+F6ynYTJXZvl5KX/pDtQDMkCjadtDOVoc3S1
LYEXAq6F7rcw+S8T0sDrZxGOUw8xAWUmUlL2oSKpOQKBgQDIrom9u3bdJrzglRDP
QuA/dx4IFuZOUaVYPG3NgG/XGtx1yKF2p+XqSWI1wb4fe59S6oJj9KhUKpEZYFoW
c9zgVtl9NsU1gtXfSAuy0pAwTOTdFDzO+b9IIg6zGrh0UT83Ett/zoU2OZWej7xk
ZxCLTZ7lXav+OwquIMMsjFW3KQKBgQDfqFNOwGrWrPyLQGBS9uz4IAOysY0Nydd3
9et7ivzgVAj2p3pb8OuCuMhHmCMd7ocIrijCtF5ppNQ9UhkNhq6crlA9L5jRVLd4
GJTjYnnnA2qNGklu51Q/5XHPMTndXmbrE+jq1VLmx7pGd/XEy83gDXNsB4sLsYgH
OLZd+bRM2wKBgE0H0g9mGeYhrHZ4QY+NGA7EZl6si5KcfF82Mt+i4UssIFuFu5SU
NgiMSopf596l0S4+nfZIPySvgiq/dVUQ/EOQksMhdulnYzjlqrflYztnCKJj1kOM
UgQaLpJJO2xKk31MW7zfRPrfd7L5cVMIzKzsCoX4QsC/YQYdxU0gQPahAoGAenii
/bmyB1H8jIg49tVOF+T4AW7mTYmcWo0oYKNQK8r4iZBWGWiInjFvQn0VpbtK6D7u
BQhdtr3Slq2RGG4KybNOLuMUbHRWbwYO6aCwHgcp3pBpa7hy0vZiZtGO3SBnfQyO
+6DK36K45wOjahsr5ieXb62Fv2Z8lW/BtR4aVAcCgYEAicMLTwUle3fprqZy/Bwr
yoGhy+CaKyBWDwF2/JBMFzze9LiOqHkjW4zps4RBaHvRv84AALX0c68HUEuXZUWj
zwS7ekmeex/ZRkHXaFTKnywwOraGSJAlcwAwlMNLCrkZn9wm79fcuaRoBCCYpCZL
5U2HZPvTIa7Iry46elKZq3g=
-----END PRIVATE KEY-----";

        let key = parse_pkcs8_pem(pem).unwrap();
        match key {
            Pkcs8PrivateKey::Rsa(rsa_key) => {
                // Verify the key can sign
                use hitls_crypto::rsa::RsaPadding;
                let digest = [0xABu8; 32];
                let sig = rsa_key.sign(RsaPadding::Pkcs1v15Sign, &digest).unwrap();
                assert!(!sig.is_empty());
            }
            _ => panic!("Expected RSA key"),
        }
    }

    #[test]
    fn test_parse_ec_p256_pkcs8_der() {
        // Build a test EC P-256 PKCS#8 key
        let private_key = [0x42u8; 32];
        let der = encode_ec_pkcs8_der(EccCurveId::NistP256, &private_key);

        let key = parse_pkcs8_der(&der).unwrap();
        match key {
            Pkcs8PrivateKey::Ec { curve_id, .. } => {
                assert_eq!(curve_id, EccCurveId::NistP256);
            }
            _ => panic!("Expected EC key"),
        }
    }

    #[test]
    fn test_parse_ec_p384_pkcs8_der() {
        let private_key = [0x42u8; 48];
        let der = encode_ec_pkcs8_der(EccCurveId::NistP384, &private_key);

        let key = parse_pkcs8_der(&der).unwrap();
        match key {
            Pkcs8PrivateKey::Ec { curve_id, .. } => {
                assert_eq!(curve_id, EccCurveId::NistP384);
            }
            _ => panic!("Expected EC key"),
        }
    }

    #[test]
    fn test_parse_dsa_pkcs8_der() {
        // Build a minimal DSA PKCS#8 structure with small test params
        // p=255, q=11, g=2, x=5
        let p = hex("00ff");
        let q = hex("0b");
        let g = hex("02");
        let x = hex("05");

        let mut params_enc = Encoder::new();
        params_enc.write_integer(&p);
        params_enc.write_integer(&q);
        params_enc.write_integer(&g);
        let params_body = params_enc.finish();

        let mut params_seq = Encoder::new();
        params_seq.write_sequence(&params_body);
        let params_der = params_seq.finish();

        // privateKey = DER INTEGER(x)
        let mut x_enc = Encoder::new();
        x_enc.write_integer(&x);
        let x_der = x_enc.finish();

        let der = encode_pkcs8_der_raw(&known::dsa(), Some(&params_der), &x_der);

        let key = parse_pkcs8_der(&der).unwrap();
        match key {
            Pkcs8PrivateKey::Dsa { .. } => {}
            _ => panic!("Expected DSA key"),
        }
    }

    #[test]
    fn test_pkcs8_pem_roundtrip() {
        let seed = [0x42u8; 32];
        let der = encode_ed25519_pkcs8_der(&seed);
        let pem = hitls_utils::pem::encode("PRIVATE KEY", &der);

        let key = parse_pkcs8_pem(&pem).unwrap();
        match key {
            Pkcs8PrivateKey::Ed25519(_) => {}
            _ => panic!("Expected Ed25519 key"),
        }
    }

    #[test]
    fn test_pkcs8_ec_roundtrip() {
        // Create EC P-256 key, encode to PKCS#8, parse back, verify usable
        let private_key_bytes =
            hex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let der = encode_ec_pkcs8_der(EccCurveId::NistP256, &private_key_bytes);
        let key = parse_pkcs8_der(&der).unwrap();

        match key {
            Pkcs8PrivateKey::Ec { curve_id, key_pair } => {
                assert_eq!(curve_id, EccCurveId::NistP256);
                // Verify the key pair can sign
                let digest = [0xABu8; 32];
                let sig = key_pair.sign(&digest).unwrap();
                assert!(!sig.is_empty());
            }
            _ => panic!("Expected EC key"),
        }
    }

    #[test]
    fn test_pkcs8_invalid_version() {
        // Build a PKCS#8 with version = 5 (invalid)
        let mut body_enc = Encoder::new();
        body_enc.write_integer(&[5]); // invalid version

        // Minimal AlgorithmIdentifier
        let mut alg_enc = Encoder::new();
        alg_enc.write_oid(&known::ed25519().to_der_value());
        let alg_bytes = alg_enc.finish();
        body_enc.write_sequence(&alg_bytes);

        body_enc.write_octet_string(&[0u8; 34]); // dummy key
        let body = body_enc.finish();

        let mut outer_enc = Encoder::new();
        outer_enc.write_sequence(&body);
        let der = outer_enc.finish();

        assert!(parse_pkcs8_der(&der).is_err());
    }

    #[test]
    fn test_pkcs8_ed25519_roundtrip() {
        // Create Ed25519 key, encode to PKCS#8, parse back, verify can sign
        let seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let seed_arr: [u8; 32] = seed.try_into().unwrap();

        let der = encode_ed25519_pkcs8_der(&seed_arr);
        let key = parse_pkcs8_der(&der).unwrap();

        match key {
            Pkcs8PrivateKey::Ed25519(kp) => {
                let msg = b"test message for ed25519 signing";
                let sig = kp.sign(msg).unwrap();
                assert_eq!(sig.len(), 64);
                assert!(kp.verify(msg, &sig).is_ok());
            }
            _ => panic!("Expected Ed25519 key"),
        }
    }

    #[test]
    fn test_pkcs8_ed448_roundtrip() {
        let seed = [0x55u8; 57];
        let der = encode_ed448_pkcs8_der(&seed);
        let key = parse_pkcs8_der(&der).unwrap();
        match key {
            Pkcs8PrivateKey::Ed448(kp) => {
                let msg = b"test message for ed448 signing";
                let sig = kp.sign(msg).unwrap();
                assert_eq!(sig.len(), 114);
                assert!(kp.verify(msg, &sig).unwrap());
            }
            _ => panic!("Expected Ed448 key"),
        }
    }

    #[test]
    fn test_pkcs8_x448_roundtrip() {
        let key_bytes = [0x42u8; 56];
        let der = encode_x448_pkcs8_der(&key_bytes);
        let key = parse_pkcs8_der(&der).unwrap();
        match key {
            Pkcs8PrivateKey::X448(_) => {}
            _ => panic!("Expected X448 key"),
        }
    }

    #[test]
    fn test_spki_x25519_roundtrip() {
        let priv_key = X25519PrivateKey::new(&[0x77u8; 32]).unwrap();
        let pub_key = priv_key.public_key();
        let spki_der = encode_x25519_spki_der(pub_key.as_bytes());
        let spki_pem = encode_spki_pem(&spki_der);

        let parsed = parse_spki_pem(&spki_pem).unwrap();
        match parsed {
            SpkiPublicKey::X25519(bytes) => {
                assert_eq!(bytes.as_slice(), pub_key.as_bytes());
            }
            _ => panic!("Expected X25519 public key"),
        }
    }

    #[test]
    fn test_spki_ec_p256_roundtrip() {
        let kp = EcdsaKeyPair::generate(EccCurveId::NistP256).unwrap();
        let pub_bytes = kp.public_key_bytes().unwrap();
        let spki_der = encode_ec_spki_der(EccCurveId::NistP256, &pub_bytes);

        let parsed = parse_spki_der(&spki_der).unwrap();
        match parsed {
            SpkiPublicKey::Ec {
                curve_id,
                public_key,
            } => {
                assert_eq!(curve_id, EccCurveId::NistP256);
                assert_eq!(public_key, pub_bytes);
            }
            _ => panic!("Expected EC public key"),
        }
    }
}
