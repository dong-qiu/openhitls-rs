//! TLS 1.3 HKDF primitives (RFC 8446 Section 7.1).
//!
//! Uses `DigestVariant` enum dispatch for stack-allocated hash operations.

use super::{DigestVariant, HashAlgId};
use hitls_crypto::provider::Digest;
use hitls_types::TlsError;
use zeroize::Zeroize;

/// Maximum block size of any TLS hash (SHA-512 = 128).
const MAX_BLOCK_SIZE: usize = 128;
/// Maximum output size of any TLS hash (SHA-512 = 64).
const MAX_OUTPUT_SIZE: usize = 64;

/// Prepare the HMAC key block: hash if longer than block_size, else zero-pad.
/// Returns stack-allocated key_block, block_size, and output_size.
fn prepare_key_block(
    alg: HashAlgId,
    key: &[u8],
) -> Result<([u8; MAX_BLOCK_SIZE], usize, usize), TlsError> {
    let block_size = DigestVariant::new(alg).block_size();
    let output_size = DigestVariant::output_size_for(alg);

    let mut key_block = [0u8; MAX_BLOCK_SIZE];
    if key.len() > block_size {
        let mut hasher = DigestVariant::new(alg);
        hasher.update(key).map_err(TlsError::CryptoError)?;
        let mut hashed = [0u8; MAX_OUTPUT_SIZE];
        hasher
            .finish(&mut hashed[..output_size])
            .map_err(TlsError::CryptoError)?;
        key_block[..output_size].copy_from_slice(&hashed[..output_size]);
        hashed.zeroize();
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    Ok((key_block, block_size, output_size))
}

/// One-shot HMAC: `HMAC(key, data)`. All buffers are stack-allocated.
pub(crate) fn hmac_hash(alg: HashAlgId, key: &[u8], data: &[u8]) -> Result<Vec<u8>, TlsError> {
    let (mut key_block, block_size, output_size) = prepare_key_block(alg, key)?;

    // Inner: H((K XOR ipad) || data) — XOR in-place into stack buffer
    let mut inner = DigestVariant::new(alg);
    let mut xor_key = [0u8; MAX_BLOCK_SIZE];
    for i in 0..block_size {
        xor_key[i] = key_block[i] ^ 0x36;
    }
    inner
        .update(&xor_key[..block_size])
        .map_err(TlsError::CryptoError)?;
    inner.update(data).map_err(TlsError::CryptoError)?;
    let mut inner_hash = [0u8; MAX_OUTPUT_SIZE];
    inner
        .finish(&mut inner_hash[..output_size])
        .map_err(TlsError::CryptoError)?;

    // Outer: H((K XOR opad) || inner_hash)
    let mut outer = DigestVariant::new(alg);
    for i in 0..block_size {
        xor_key[i] = key_block[i] ^ 0x5c;
    }
    outer
        .update(&xor_key[..block_size])
        .map_err(TlsError::CryptoError)?;
    outer
        .update(&inner_hash[..output_size])
        .map_err(TlsError::CryptoError)?;
    let mut out = vec![0u8; output_size];
    outer.finish(&mut out).map_err(TlsError::CryptoError)?;

    key_block.zeroize();
    xor_key.zeroize();
    inner_hash.zeroize();
    Ok(out)
}

/// HKDF-Extract(salt, IKM) -> PRK.
///
/// This is `HMAC-Hash(salt, IKM)`. If salt is empty, uses `hash_len` zero bytes.
pub fn hkdf_extract(alg: HashAlgId, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, TlsError> {
    if salt.is_empty() {
        let zero_salt = [0u8; MAX_OUTPUT_SIZE];
        let hash_len = DigestVariant::output_size_for(alg);
        hmac_hash(alg, &zero_salt[..hash_len], ikm)
    } else {
        hmac_hash(alg, salt, ikm)
    }
}

/// HKDF-Expand(PRK, info, length) -> OKM.
///
/// Iterative HMAC expansion per RFC 5869.
pub fn hkdf_expand(
    alg: HashAlgId,
    prk: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, TlsError> {
    let (mut key_block, block_size, output_size) = prepare_key_block(alg, prk)?;

    let n = length.div_ceil(output_size);
    if n > 255 {
        return Err(TlsError::HandshakeFailed(
            "HKDF-Expand: output length too large".into(),
        ));
    }

    // Pre-compute ipad/opad keys once (stack arrays)
    let mut ipad_key = [0u8; MAX_BLOCK_SIZE];
    let mut opad_key = [0u8; MAX_BLOCK_SIZE];
    for i in 0..block_size {
        ipad_key[i] = key_block[i] ^ 0x36;
        opad_key[i] = key_block[i] ^ 0x5c;
    }

    let mut okm = Vec::with_capacity(length);
    let mut t_prev = [0u8; MAX_OUTPUT_SIZE]; // Stack buffer for T(i-1)
    let mut t_len = 0usize; // 0 for first iteration

    for i in 1..=n {
        // Inner: H((K XOR ipad) || T(i-1) || info || [i])
        let mut inner = DigestVariant::new(alg);
        inner
            .update(&ipad_key[..block_size])
            .map_err(TlsError::CryptoError)?;
        if t_len > 0 {
            inner
                .update(&t_prev[..t_len])
                .map_err(TlsError::CryptoError)?;
        }
        inner.update(info).map_err(TlsError::CryptoError)?;
        inner.update(&[i as u8]).map_err(TlsError::CryptoError)?;
        let mut inner_hash = [0u8; MAX_OUTPUT_SIZE];
        inner
            .finish(&mut inner_hash[..output_size])
            .map_err(TlsError::CryptoError)?;

        // Outer: H((K XOR opad) || inner_hash)
        let mut outer = DigestVariant::new(alg);
        outer
            .update(&opad_key[..block_size])
            .map_err(TlsError::CryptoError)?;
        outer
            .update(&inner_hash[..output_size])
            .map_err(TlsError::CryptoError)?;
        outer
            .finish(&mut t_prev[..output_size])
            .map_err(TlsError::CryptoError)?;
        t_len = output_size;

        inner_hash.zeroize();
        okm.extend_from_slice(&t_prev[..output_size]);
    }

    key_block.zeroize();
    ipad_key.zeroize();
    opad_key.zeroize();
    t_prev.zeroize();
    okm.truncate(length);
    Ok(okm)
}

/// Maximum HkdfLabel size for stack allocation.
/// Covers: 2 (length) + 1 (label_len) + 6 ("tls13 ") + 30 (max label) + 1 (ctx_len) + 48 (SHA-384)
const MAX_HKDF_LABEL: usize = 128;

/// HKDF-Expand-Label(Secret, Label, Context, Length).
///
/// `= HKDF-Expand(Secret, HkdfLabel, Length)`
///
/// Encodes the HkdfLabel structure per RFC 8446 Section 7.1 into a stack buffer:
/// ```text
/// struct { uint16 length; opaque label<7..255>; opaque context<0..255>; } HkdfLabel;
/// ```
pub fn hkdf_expand_label(
    alg: HashAlgId,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>, TlsError> {
    let full_label_len = 6 + label.len(); // "tls13 " prefix = 6 bytes
    let total = 2 + 1 + full_label_len + 1 + context.len();

    if total <= MAX_HKDF_LABEL {
        let mut buf = [0u8; MAX_HKDF_LABEL];
        let len_bytes = (length as u16).to_be_bytes();
        buf[0] = len_bytes[0];
        buf[1] = len_bytes[1];
        buf[2] = full_label_len as u8;
        buf[3..9].copy_from_slice(b"tls13 ");
        buf[9..9 + label.len()].copy_from_slice(label);
        let ctx_off = 9 + label.len();
        buf[ctx_off] = context.len() as u8;
        buf[ctx_off + 1..ctx_off + 1 + context.len()].copy_from_slice(context);
        hkdf_expand(alg, secret, &buf[..total], length)
    } else {
        // Fallback for unusually large labels (should not occur in TLS 1.3)
        let mut buf = Vec::with_capacity(total);
        buf.extend_from_slice(&(length as u16).to_be_bytes());
        buf.push(full_label_len as u8);
        buf.extend_from_slice(b"tls13 ");
        buf.extend_from_slice(label);
        buf.push(context.len() as u8);
        buf.extend_from_slice(context);
        hkdf_expand(alg, secret, &buf, length)
    }
}

/// Derive-Secret(Secret, Label, TranscriptHash).
///
/// `= HKDF-Expand-Label(Secret, Label, TranscriptHash, Hash.length)`
///
/// The `transcript_hash` should be the already-computed hash of the messages.
pub fn derive_secret(
    alg: HashAlgId,
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>, TlsError> {
    hkdf_expand_label(alg, secret, label, transcript_hash, transcript_hash.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_utils::hex::{hex, to_hex};

    // RFC 5869 Test Case 1 (SHA-256)
    #[test]
    fn test_hkdf_extract_sha256() {
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex("000102030405060708090a0b0c");
        let expected_prk = hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");

        let prk = hkdf_extract(HashAlgId::Sha256, &salt, &ikm).unwrap();
        assert_eq!(to_hex(&prk), to_hex(&expected_prk));
    }

    #[test]
    fn test_hkdf_expand_sha256() {
        let prk = hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let expected_okm = hex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );

        let okm = hkdf_expand(HashAlgId::Sha256, &prk, &info, 42).unwrap();
        assert_eq!(to_hex(&okm), to_hex(&expected_okm));
    }

    // RFC 5869 Test Case 3 (SHA-256, zero-length salt/info)
    #[test]
    fn test_hkdf_extract_empty_salt() {
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let expected_prk = hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");

        let prk = hkdf_extract(HashAlgId::Sha256, &[], &ikm).unwrap();
        assert_eq!(to_hex(&prk), to_hex(&expected_prk));
    }

    #[test]
    fn test_hkdf_extract_sha384() {
        // HMAC-SHA384(salt, ikm) — verify it produces 48-byte output
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex("000102030405060708090a0b0c");
        let prk = hkdf_extract(HashAlgId::Sha384, &salt, &ikm).unwrap();
        assert_eq!(prk.len(), 48);
    }

    #[test]
    fn test_hkdf_label_encoding() {
        // Verify the stack-encoded HkdfLabel produces correct HKDF-Expand-Label output.
        // label="key", context="", length=16 → encoded as:
        //   [0x00, 0x10, 0x09, "tls13 key", 0x00]  (13 bytes)
        // We verify by checking that hkdf_expand_label produces deterministic output.
        let secret = vec![0xAA; 32];
        let result = hkdf_expand_label(HashAlgId::Sha256, &secret, b"key", b"", 16).unwrap();
        assert_eq!(result.len(), 16);
        // Deterministic
        let result2 = hkdf_expand_label(HashAlgId::Sha256, &secret, b"key", b"", 16).unwrap();
        assert_eq!(result, result2);
        // Different label → different output
        let result3 = hkdf_expand_label(HashAlgId::Sha256, &secret, b"iv", b"", 16).unwrap();
        assert_ne!(result, result3);
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
            derive_secret(HashAlgId::Sha256, &early_secret, b"derived", &empty_hash).unwrap();
        assert_eq!(derived.len(), 32);
    }

    #[test]
    fn test_hmac_hash_basic() {
        // RFC 2202 Test Case 1: HMAC-SHA256 with known key and data
        let key = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let result = hmac_hash(HashAlgId::Sha256, &key, data).unwrap();
        assert_eq!(result.len(), 32);
        // Verify determinism
        let result2 = hmac_hash(HashAlgId::Sha256, &key, data).unwrap();
        assert_eq!(result, result2);
    }

    #[test]
    fn test_hmac_hash_long_key() {
        // Key longer than block size (64 bytes for SHA-256) gets hashed first
        let long_key = vec![0xAA; 131]; // > 64 bytes
        let data = b"Test With Long Key";
        let result = hmac_hash(HashAlgId::Sha256, &long_key, data).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hkdf_expand_long_output() {
        // Request output longer than hash length (> 32 bytes for SHA-256)
        // This exercises multiple HMAC iterations
        let prk = hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let info = b"long expansion test";

        let okm = hkdf_expand(HashAlgId::Sha256, &prk, info, 80).unwrap();
        assert_eq!(okm.len(), 80);

        // First 32 bytes should match a 32-byte expansion (T(1) is the same)
        let okm_short = hkdf_expand(HashAlgId::Sha256, &prk, info, 32).unwrap();
        assert_eq!(&okm[..32], &okm_short[..]);
    }

    #[test]
    fn test_hkdf_expand_too_large() {
        // Output length > 255 * hash_len should fail
        let prk = vec![0x42; 32];
        let result = hkdf_expand(HashAlgId::Sha256, &prk, b"", 255 * 32 + 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_expand_label_with_context() {
        // HKDF-Expand-Label with non-empty context
        let secret = vec![0xAA; 32];
        let context = b"some transcript hash data";
        let result = hkdf_expand_label(HashAlgId::Sha256, &secret, b"key", context, 16).unwrap();
        assert_eq!(result.len(), 16);

        // Different context → different output
        let result2 =
            hkdf_expand_label(HashAlgId::Sha256, &secret, b"key", b"different ctx", 16).unwrap();
        assert_ne!(result, result2);
    }

    #[test]
    fn test_derive_secret_sha384() {
        let secret = vec![0xBB; 48];
        let transcript = vec![0xCC; 48]; // SHA-384 hash length
        let derived =
            derive_secret(HashAlgId::Sha384, &secret, b"c hs traffic", &transcript).unwrap();
        assert_eq!(derived.len(), 48);
    }

    #[test]
    fn test_hkdf_extract_deterministic() {
        let salt = hex("000102030405060708090a0b0c");
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let prk1 = hkdf_extract(HashAlgId::Sha256, &salt, &ikm).unwrap();
        let prk2 = hkdf_extract(HashAlgId::Sha256, &salt, &ikm).unwrap();
        assert_eq!(prk1, prk2);
    }

    #[test]
    fn test_hkdf_expand_single_byte() {
        // Edge case: request exactly 1 byte of output
        let prk = vec![0x42; 32];
        let okm = hkdf_expand(HashAlgId::Sha256, &prk, b"info", 1).unwrap();
        assert_eq!(okm.len(), 1);
    }

    #[test]
    fn test_hkdf_expand_empty_info() {
        // Expand with empty info (valid per RFC 5869)
        let prk = hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let okm = hkdf_expand(HashAlgId::Sha256, &prk, b"", 32).unwrap();
        assert_eq!(okm.len(), 32);
        // Deterministic
        let okm2 = hkdf_expand(HashAlgId::Sha256, &prk, b"", 32).unwrap();
        assert_eq!(okm, okm2);
    }

    #[test]
    fn test_hkdf_expand_label_sha384() {
        let secret = vec![0xBB; 48];
        let result =
            hkdf_expand_label(HashAlgId::Sha384, &secret, b"s hs traffic", b"hash384", 48).unwrap();
        assert_eq!(result.len(), 48);
        // Different label → different output
        let result2 =
            hkdf_expand_label(HashAlgId::Sha384, &secret, b"c hs traffic", b"hash384", 48).unwrap();
        assert_ne!(result, result2);
    }

    #[test]
    fn test_hmac_hash_empty_data() {
        let key = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let result = hmac_hash(HashAlgId::Sha256, &key, b"").unwrap();
        assert_eq!(result.len(), 32);
        // HMAC with empty data should still produce deterministic output
        let result2 = hmac_hash(HashAlgId::Sha256, &key, b"").unwrap();
        assert_eq!(result, result2);
        // Should differ from HMAC with non-empty data
        let result3 = hmac_hash(HashAlgId::Sha256, &key, b"data").unwrap();
        assert_ne!(result, result3);
    }

    #[test]
    fn test_hkdf_expand_exact_hash_length() {
        // Request exactly hash_len bytes (32 for SHA-256) — single iteration
        let prk = vec![0x42; 32];
        let okm = hkdf_expand(HashAlgId::Sha256, &prk, b"test", 32).unwrap();
        assert_eq!(okm.len(), 32);
    }

    #[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
    #[test]
    fn test_hmac_hash_sm3() {
        let key = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let result = hmac_hash(HashAlgId::Sm3, &key, data).unwrap();
        assert_eq!(result.len(), 32); // SM3 output is 32 bytes

        // Deterministic
        let result2 = hmac_hash(HashAlgId::Sm3, &key, data).unwrap();
        assert_eq!(result, result2);

        // Differs from HMAC-SHA256 with same inputs
        let sha256_result = hmac_hash(HashAlgId::Sha256, &key, data).unwrap();
        assert_ne!(result, sha256_result);
    }

    #[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
    #[test]
    fn test_hkdf_extract_sm3() {
        let salt = hex("000102030405060708090a0b0c");
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let prk = hkdf_extract(HashAlgId::Sm3, &salt, &ikm).unwrap();
        assert_eq!(prk.len(), 32); // SM3 output is 32 bytes

        // Deterministic
        let prk2 = hkdf_extract(HashAlgId::Sm3, &salt, &ikm).unwrap();
        assert_eq!(prk, prk2);

        // Differs from SHA-256
        let sha256_prk = hkdf_extract(HashAlgId::Sha256, &salt, &ikm).unwrap();
        assert_ne!(prk, sha256_prk);
    }

    #[cfg(any(feature = "tlcp", feature = "sm_tls13"))]
    #[test]
    fn test_hkdf_expand_sm3_various_lengths() {
        let prk = vec![0x42; 32];
        let info = b"test info";
        let lengths = [1, 16, 32, 33, 64, 100];
        let mut results = Vec::new();
        for &len in &lengths {
            let okm = hkdf_expand(HashAlgId::Sm3, &prk, info, len).unwrap();
            assert_eq!(okm.len(), len);
            results.push(okm);
        }

        // Prefix consistency: shorter outputs are prefixes of longer ones
        assert_eq!(&results[0][..1], &results[1][..1]); // 1 ⊂ 16
        assert_eq!(&results[1][..16], &results[2][..16]); // 16 ⊂ 32
        assert_eq!(&results[2][..32], &results[3][..32]); // 32 ⊂ 33
        assert_eq!(&results[3][..33], &results[4][..33]); // 33 ⊂ 64
        assert_eq!(&results[4][..64], &results[5][..64]); // 64 ⊂ 100
    }

    #[test]
    fn test_hmac_hash_key_at_block_boundary() {
        let data = b"boundary test data";

        // Key exactly 64 bytes (SHA-256 block_size): NOT hashed, used directly
        let key_64 = vec![0xAA; 64];
        let result_64 = hmac_hash(HashAlgId::Sha256, &key_64, data).unwrap();
        assert_eq!(result_64.len(), 32);

        // Key 65 bytes: IS hashed (key > block_size triggers hash)
        let key_65 = vec![0xAA; 65];
        let result_65 = hmac_hash(HashAlgId::Sha256, &key_65, data).unwrap();
        assert_eq!(result_65.len(), 32);

        // Results must differ (different effective keys)
        assert_ne!(result_64, result_65);
    }

    #[test]
    fn test_hkdf_expand_multi_iteration_boundaries() {
        let prk = vec![0x42; 32];
        let info = b"multi iter boundary";

        // 32 bytes: 1 iteration (1 × 32)
        let okm_32 = hkdf_expand(HashAlgId::Sha256, &prk, info, 32).unwrap();
        assert_eq!(okm_32.len(), 32);

        // 64 bytes: 2 iterations (2 × 32)
        let okm_64 = hkdf_expand(HashAlgId::Sha256, &prk, info, 64).unwrap();
        assert_eq!(okm_64.len(), 64);

        // 96 bytes: 3 iterations (3 × 32)
        let okm_96 = hkdf_expand(HashAlgId::Sha256, &prk, info, 96).unwrap();
        assert_eq!(okm_96.len(), 96);

        // Prefix consistency
        assert_eq!(&okm_64[..32], &okm_32[..]);
        assert_eq!(&okm_96[..64], &okm_64[..]);
    }
}
