//! TLS 1.3 HKDF primitives (RFC 8446 Section 7.1).
//!
//! Implemented directly using inline HMAC to support both SHA-256 and SHA-384.
//! The hitls-crypto `Hmac` struct requires `'static` closures, so we implement
//! HMAC inline here to work with borrowed `&dyn Fn()` factory references.

use hitls_crypto::provider::Digest;
use hitls_types::TlsError;
use zeroize::Zeroize;

type Factory = dyn Fn() -> Box<dyn Digest> + Send + Sync;

/// Prepare the HMAC key block: hash if longer than block_size, else zero-pad.
fn prepare_key_block(factory: &Factory, key: &[u8]) -> Result<(Vec<u8>, usize, usize), TlsError> {
    let sample = factory();
    let block_size = sample.block_size();
    let output_size = sample.output_size();
    drop(sample);

    let mut key_block = vec![0u8; block_size];
    if key.len() > block_size {
        let mut hasher = factory();
        hasher.update(key).map_err(TlsError::CryptoError)?;
        let mut hashed = vec![0u8; output_size];
        hasher.finish(&mut hashed).map_err(TlsError::CryptoError)?;
        key_block[..output_size].copy_from_slice(&hashed);
        hashed.zeroize();
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    Ok((key_block, block_size, output_size))
}

/// One-shot HMAC: `HMAC(key, data)`.
pub(crate) fn hmac_hash(factory: &Factory, key: &[u8], data: &[u8]) -> Result<Vec<u8>, TlsError> {
    let (mut key_block, _block_size, output_size) = prepare_key_block(factory, key)?;

    // Inner: H((K XOR ipad) || data)
    let mut inner = factory();
    let ipad_key: Vec<u8> = key_block.iter().map(|b| b ^ 0x36).collect();
    inner.update(&ipad_key).map_err(TlsError::CryptoError)?;
    inner.update(data).map_err(TlsError::CryptoError)?;
    let mut inner_hash = vec![0u8; output_size];
    inner
        .finish(&mut inner_hash)
        .map_err(TlsError::CryptoError)?;

    // Outer: H((K XOR opad) || inner_hash)
    let mut outer = factory();
    let opad_key: Vec<u8> = key_block.iter().map(|b| b ^ 0x5c).collect();
    outer.update(&opad_key).map_err(TlsError::CryptoError)?;
    outer.update(&inner_hash).map_err(TlsError::CryptoError)?;
    let mut out = vec![0u8; output_size];
    outer.finish(&mut out).map_err(TlsError::CryptoError)?;

    key_block.zeroize();
    inner_hash.zeroize();
    Ok(out)
}

/// HKDF-Extract(salt, IKM) -> PRK.
///
/// This is `HMAC-Hash(salt, IKM)`. If salt is empty, uses `hash_len` zero bytes.
pub fn hkdf_extract(factory: &Factory, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, TlsError> {
    let effective_salt = if salt.is_empty() {
        let hash_len = factory().output_size();
        vec![0u8; hash_len]
    } else {
        salt.to_vec()
    };
    hmac_hash(factory, &effective_salt, ikm)
}

/// HKDF-Expand(PRK, info, length) -> OKM.
///
/// Iterative HMAC expansion per RFC 5869.
pub fn hkdf_expand(
    factory: &Factory,
    prk: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, TlsError> {
    let (mut key_block, _block_size, output_size) = prepare_key_block(factory, prk)?;

    let n = length.div_ceil(output_size);
    if n > 255 {
        return Err(TlsError::HandshakeFailed(
            "HKDF-Expand: output length too large".into(),
        ));
    }

    let ipad_key: Vec<u8> = key_block.iter().map(|b| b ^ 0x36).collect();
    let opad_key: Vec<u8> = key_block.iter().map(|b| b ^ 0x5c).collect();

    let mut okm = Vec::with_capacity(length);
    let mut t_prev: Vec<u8> = Vec::new();

    for i in 1..=n {
        // Inner: H((K XOR ipad) || T(i-1) || info || [i])
        let mut inner = factory();
        inner.update(&ipad_key).map_err(TlsError::CryptoError)?;
        inner.update(&t_prev).map_err(TlsError::CryptoError)?;
        inner.update(info).map_err(TlsError::CryptoError)?;
        inner.update(&[i as u8]).map_err(TlsError::CryptoError)?;
        let mut inner_hash = vec![0u8; output_size];
        inner
            .finish(&mut inner_hash)
            .map_err(TlsError::CryptoError)?;

        // Outer: H((K XOR opad) || inner_hash)
        let mut outer = factory();
        outer.update(&opad_key).map_err(TlsError::CryptoError)?;
        outer.update(&inner_hash).map_err(TlsError::CryptoError)?;
        let mut out = vec![0u8; output_size];
        outer.finish(&mut out).map_err(TlsError::CryptoError)?;

        inner_hash.zeroize();
        t_prev = out.clone();
        okm.extend_from_slice(&out);
    }

    key_block.zeroize();
    okm.truncate(length);
    Ok(okm)
}

/// Encode the HkdfLabel structure per RFC 8446 Section 7.1:
///
/// ```text
/// struct {
///     uint16 length;
///     opaque label<7..255>;   // "tls13 " + label
///     opaque context<0..255>;
/// } HkdfLabel;
/// ```
fn encode_hkdf_label(length: u16, label: &[u8], context: &[u8]) -> Vec<u8> {
    let full_label_len = 6 + label.len(); // "tls13 " prefix = 6 bytes
    let mut buf = Vec::with_capacity(2 + 1 + full_label_len + 1 + context.len());
    buf.extend_from_slice(&length.to_be_bytes());
    buf.push(full_label_len as u8);
    buf.extend_from_slice(b"tls13 ");
    buf.extend_from_slice(label);
    buf.push(context.len() as u8);
    buf.extend_from_slice(context);
    buf
}

/// HKDF-Expand-Label(Secret, Label, Context, Length).
///
/// `= HKDF-Expand(Secret, HkdfLabel, Length)`
pub fn hkdf_expand_label(
    factory: &Factory,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>, TlsError> {
    let hkdf_label = encode_hkdf_label(length as u16, label, context);
    hkdf_expand(factory, secret, &hkdf_label, length)
}

/// Derive-Secret(Secret, Label, TranscriptHash).
///
/// `= HKDF-Expand-Label(Secret, Label, TranscriptHash, Hash.length)`
///
/// The `transcript_hash` should be the already-computed hash of the messages.
pub fn derive_secret(
    factory: &Factory,
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>, TlsError> {
    hkdf_expand_label(
        factory,
        secret,
        label,
        transcript_hash,
        transcript_hash.len(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_crypto::sha2::{Sha256, Sha384};

    fn sha256_factory() -> Box<dyn Digest> {
        Box::new(Sha256::new())
    }

    fn sha384_factory() -> Box<dyn Digest> {
        Box::new(Sha384::new())
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    // RFC 5869 Test Case 1 (SHA-256)
    #[test]
    fn test_hkdf_extract_sha256() {
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex("000102030405060708090a0b0c");
        let expected_prk = hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");

        let prk = hkdf_extract(&sha256_factory, &salt, &ikm).unwrap();
        assert_eq!(to_hex(&prk), to_hex(&expected_prk));
    }

    #[test]
    fn test_hkdf_expand_sha256() {
        let prk = hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let expected_okm = hex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );

        let okm = hkdf_expand(&sha256_factory, &prk, &info, 42).unwrap();
        assert_eq!(to_hex(&okm), to_hex(&expected_okm));
    }

    // RFC 5869 Test Case 3 (SHA-256, zero-length salt/info)
    #[test]
    fn test_hkdf_extract_empty_salt() {
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let expected_prk = hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");

        let prk = hkdf_extract(&sha256_factory, &[], &ikm).unwrap();
        assert_eq!(to_hex(&prk), to_hex(&expected_prk));
    }

    #[test]
    fn test_hkdf_extract_sha384() {
        // HMAC-SHA384(salt, ikm) — verify it produces 48-byte output
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex("000102030405060708090a0b0c");
        let prk = hkdf_extract(&sha384_factory, &salt, &ikm).unwrap();
        assert_eq!(prk.len(), 48);
    }

    #[test]
    fn test_encode_hkdf_label() {
        // HKDF-Expand-Label with label="key", context="", length=16
        let label = encode_hkdf_label(16, b"key", b"");
        // Expected: [0x00, 0x10, 0x09, "tls13 key", 0x00]
        assert_eq!(label[0], 0x00); // length high byte
        assert_eq!(label[1], 0x10); // length low byte = 16
        assert_eq!(label[2], 0x09); // label length = 6 ("tls13 ") + 3 ("key")
        assert_eq!(&label[3..12], b"tls13 key");
        assert_eq!(label[12], 0x00); // context length = 0
        assert_eq!(label.len(), 13);
    }

    #[test]
    fn test_derive_secret_empty_context() {
        // TLS 1.3 key schedule: Derive-Secret(secret, "derived", "")
        // where context is Hash("") for SHA-256
        // Hash("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let empty_hash = hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        // Use the early_secret from RFC 8448 as the base secret
        let early_secret = hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");

        let derived =
            derive_secret(&sha256_factory, &early_secret, b"derived", &empty_hash).unwrap();
        assert_eq!(derived.len(), 32);
    }

    #[test]
    fn test_hmac_hash_basic() {
        // RFC 2202 Test Case 1: HMAC-SHA256 with known key and data
        let key = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let result = hmac_hash(&sha256_factory, &key, data).unwrap();
        assert_eq!(result.len(), 32);
        // Verify determinism
        let result2 = hmac_hash(&sha256_factory, &key, data).unwrap();
        assert_eq!(result, result2);
    }

    #[test]
    fn test_hmac_hash_long_key() {
        // Key longer than block size (64 bytes for SHA-256) gets hashed first
        let long_key = vec![0xAA; 131]; // > 64 bytes
        let data = b"Test With Long Key";
        let result = hmac_hash(&sha256_factory, &long_key, data).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hkdf_expand_long_output() {
        // Request output longer than hash length (> 32 bytes for SHA-256)
        // This exercises multiple HMAC iterations
        let prk = hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let info = b"long expansion test";

        let okm = hkdf_expand(&sha256_factory, &prk, info, 80).unwrap();
        assert_eq!(okm.len(), 80);

        // First 32 bytes should match a 32-byte expansion (T(1) is the same)
        let okm_short = hkdf_expand(&sha256_factory, &prk, info, 32).unwrap();
        assert_eq!(&okm[..32], &okm_short[..]);
    }

    #[test]
    fn test_hkdf_expand_too_large() {
        // Output length > 255 * hash_len should fail
        let prk = vec![0x42; 32];
        let result = hkdf_expand(&sha256_factory, &prk, b"", 255 * 32 + 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_expand_label_with_context() {
        // HKDF-Expand-Label with non-empty context
        let secret = vec![0xAA; 32];
        let context = b"some transcript hash data";
        let result = hkdf_expand_label(&sha256_factory, &secret, b"key", context, 16).unwrap();
        assert_eq!(result.len(), 16);

        // Different context → different output
        let result2 =
            hkdf_expand_label(&sha256_factory, &secret, b"key", b"different ctx", 16).unwrap();
        assert_ne!(result, result2);
    }

    #[test]
    fn test_derive_secret_sha384() {
        let secret = vec![0xBB; 48];
        let transcript = vec![0xCC; 48]; // SHA-384 hash length
        let derived = derive_secret(&sha384_factory, &secret, b"c hs traffic", &transcript).unwrap();
        assert_eq!(derived.len(), 48);
    }

    #[test]
    fn test_hkdf_extract_deterministic() {
        let salt = hex("000102030405060708090a0b0c");
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let prk1 = hkdf_extract(&sha256_factory, &salt, &ikm).unwrap();
        let prk2 = hkdf_extract(&sha256_factory, &salt, &ikm).unwrap();
        assert_eq!(prk1, prk2);
    }

    #[test]
    fn test_hkdf_expand_single_byte() {
        // Edge case: request exactly 1 byte of output
        let prk = vec![0x42; 32];
        let okm = hkdf_expand(&sha256_factory, &prk, b"info", 1).unwrap();
        assert_eq!(okm.len(), 1);
    }
}
