//! PKCS#1 v1.5 padding for RSA signatures and encryption (RFC 8017).

use hitls_types::CryptoError;
use subtle::ConstantTimeEq;

/// DigestInfo DER prefix for SHA-256 (OID 2.16.840.1.101.3.4.2.1).
const DIGEST_INFO_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// DigestInfo DER prefix for SHA-384 (OID 2.16.840.1.101.3.4.2.2).
const DIGEST_INFO_SHA384: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];

/// DigestInfo DER prefix for SHA-512 (OID 2.16.840.1.101.3.4.2.3).
const DIGEST_INFO_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// DigestInfo DER prefix for SHA-1 (OID 1.3.14.3.2.26).
const DIGEST_INFO_SHA1: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];

/// Return the DigestInfo prefix for a given hash digest length.
/// Supports SHA-1 (20), SHA-256 (32), SHA-384 (48), SHA-512 (64).
fn digest_info_prefix(digest_len: usize) -> Result<&'static [u8], CryptoError> {
    match digest_len {
        20 => Ok(DIGEST_INFO_SHA1),
        32 => Ok(DIGEST_INFO_SHA256),
        48 => Ok(DIGEST_INFO_SHA384),
        64 => Ok(DIGEST_INFO_SHA512),
        _ => Err(CryptoError::InvalidArg("")),
    }
}

/// EMSA-PKCS1-v1_5 encoding for signatures (RFC 8017 §9.2).
///
/// EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo
/// where PS consists of 0xFF bytes with length >= 8.
pub(crate) fn pkcs1v15_sign_pad(digest: &[u8], k: usize) -> Result<Vec<u8>, CryptoError> {
    let prefix = digest_info_prefix(digest.len())?;
    let t_len = prefix.len() + digest.len();

    // k must be at least t_len + 11 (3 header bytes + 8 min padding)
    if k < t_len + 11 {
        return Err(CryptoError::RsaInvalidPadding);
    }

    let ps_len = k - t_len - 3;
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x01);
    em.extend(std::iter::repeat(0xFF).take(ps_len));
    em.push(0x00);
    em.extend_from_slice(prefix);
    em.extend_from_slice(digest);

    debug_assert_eq!(em.len(), k);
    Ok(em)
}

/// EMSA-PKCS1-v1_5 verification (RFC 8017 §9.2).
///
/// Checks that `em` has the structure: 0x00 || 0x01 || PS || 0x00 || DigestInfo
/// and that the embedded digest matches.
pub(crate) fn pkcs1v15_verify_unpad(
    em: &[u8],
    expected_digest: &[u8],
    k: usize,
) -> Result<bool, CryptoError> {
    // Reconstruct the expected EM and compare
    let expected_em = pkcs1v15_sign_pad(expected_digest, k)?;

    // Constant-time comparison
    Ok(em.ct_eq(&expected_em).into())
}

/// RSAES-PKCS1-v1_5 encryption padding (RFC 8017 §7.2.1).
///
/// EM = 0x00 || 0x02 || PS || 0x00 || M
/// where PS consists of random non-zero bytes with length >= 8.
pub(crate) fn pkcs1v15_encrypt_pad(msg: &[u8], k: usize) -> Result<Vec<u8>, CryptoError> {
    // mLen must be <= k - 11
    if msg.len() > k.saturating_sub(11) {
        return Err(CryptoError::InputOverflow);
    }

    let ps_len = k - msg.len() - 3;
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x02);

    // Generate random non-zero padding
    let mut ps = vec![0u8; ps_len];
    fill_nonzero_random(&mut ps)?;
    em.extend_from_slice(&ps);

    em.push(0x00);
    em.extend_from_slice(msg);

    debug_assert_eq!(em.len(), k);
    Ok(em)
}

/// RSAES-PKCS1-v1_5 decryption unpadding (RFC 8017 §7.2.2).
///
/// Parses EM = 0x00 || 0x02 || PS || 0x00 || M and returns M.
/// Uses constant-time scan to avoid timing side-channels.
pub(crate) fn pkcs1v15_decrypt_unpad(em: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if em.len() < 11 {
        return Err(CryptoError::RsaInvalidPadding);
    }

    // Constant-time header check
    let header_ok = em[0].ct_eq(&0x00).unwrap_u8() & em[1].ct_eq(&0x02).unwrap_u8();

    // Constant-time separator scan: always iterate all bytes after header.
    // Record the position of the first 0x00 byte without early exit.
    let mut found_sep = 0u8;
    let mut sep_idx = 0usize;
    for (i, &byte) in em.iter().enumerate().skip(2) {
        let is_zero = byte.ct_eq(&0x00).unwrap_u8();
        let is_first = is_zero & !found_sep;
        if is_first == 1 {
            sep_idx = i;
        }
        found_sep |= is_zero;
    }

    // PS must be at least 8 bytes (separator at index >= 10)
    let ps_ok = if sep_idx >= 10 { 1u8 } else { 0u8 };

    if header_ok & found_sep & ps_ok != 1 {
        return Err(CryptoError::RsaInvalidPadding);
    }

    Ok(em[sep_idx + 1..].to_vec())
}

/// Fill a buffer with random non-zero bytes.
fn fill_nonzero_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    let mut byte = [0u8; 1];
    for slot in buf.iter_mut() {
        // Rejection-sample until non-zero
        loop {
            getrandom::getrandom(&mut byte).map_err(|_| CryptoError::BnRandGenFail)?;
            if byte[0] != 0 {
                *slot = byte[0];
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // PKCS1v15 Signature Padding
    // -----------------------------------------------------------------------

    #[test]
    fn test_sign_pad_sha256_structure() {
        let digest = vec![0xAA; 32]; // SHA-256 length
        let k = 128; // RSA-1024 modulus length
        let em = pkcs1v15_sign_pad(&digest, k).unwrap();

        assert_eq!(em.len(), k);
        assert_eq!(em[0], 0x00);
        assert_eq!(em[1], 0x01);

        // PS should be all 0xFF
        let t_len = DIGEST_INFO_SHA256.len() + 32;
        let ps_len = k - t_len - 3;
        for &b in &em[2..2 + ps_len] {
            assert_eq!(b, 0xFF);
        }

        // Separator
        assert_eq!(em[2 + ps_len], 0x00);

        // DigestInfo prefix
        assert_eq!(
            &em[3 + ps_len..3 + ps_len + DIGEST_INFO_SHA256.len()],
            DIGEST_INFO_SHA256
        );

        // Digest
        assert_eq!(&em[3 + ps_len + DIGEST_INFO_SHA256.len()..], &digest[..]);
    }

    #[test]
    fn test_sign_pad_sha384() {
        let digest = vec![0xBB; 48]; // SHA-384 length
        let em = pkcs1v15_sign_pad(&digest, 128).unwrap();
        assert_eq!(em.len(), 128);
        assert!(em.ends_with(&digest));
    }

    #[test]
    fn test_sign_pad_sha512() {
        let digest = vec![0xCC; 64]; // SHA-512 length
        let em = pkcs1v15_sign_pad(&digest, 128).unwrap();
        assert_eq!(em.len(), 128);
        assert!(em.ends_with(&digest));
    }

    #[test]
    fn test_sign_pad_sha1() {
        let digest = vec![0xDD; 20]; // SHA-1 length
        let em = pkcs1v15_sign_pad(&digest, 128).unwrap();
        assert_eq!(em.len(), 128);
        assert!(em.ends_with(&digest));
    }

    #[test]
    fn test_sign_pad_unsupported_digest_length() {
        let digest = vec![0xEE; 28]; // SHA-224, not supported
        assert!(pkcs1v15_sign_pad(&digest, 128).is_err());
    }

    #[test]
    fn test_sign_pad_k_too_small() {
        let digest = vec![0xAA; 32];
        // For SHA-256: t_len = 19 + 32 = 51, need k >= 51 + 11 = 62
        assert!(pkcs1v15_sign_pad(&digest, 61).is_err());
        assert!(pkcs1v15_sign_pad(&digest, 62).is_ok());
    }

    #[test]
    fn test_verify_unpad_roundtrip() {
        let digest = vec![0x42; 32];
        let k = 128;
        let em = pkcs1v15_sign_pad(&digest, k).unwrap();
        let ok = pkcs1v15_verify_unpad(&em, &digest, k).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_verify_unpad_wrong_digest() {
        let digest = vec![0x42; 32];
        let k = 128;
        let em = pkcs1v15_sign_pad(&digest, k).unwrap();

        let wrong = vec![0x43; 32];
        let ok = pkcs1v15_verify_unpad(&em, &wrong, k).unwrap();
        assert!(!ok);
    }

    // -----------------------------------------------------------------------
    // PKCS1v15 Encryption Padding
    // -----------------------------------------------------------------------

    #[test]
    fn test_encrypt_pad_structure() {
        let msg = b"test";
        let k = 128;
        let em = pkcs1v15_encrypt_pad(msg, k).unwrap();

        assert_eq!(em.len(), k);
        assert_eq!(em[0], 0x00);
        assert_eq!(em[1], 0x02);

        // PS (random non-zero) should be at least 8 bytes
        let ps_len = k - msg.len() - 3;
        assert!(ps_len >= 8);
        for &b in &em[2..2 + ps_len] {
            assert_ne!(b, 0x00, "PS byte must be non-zero");
        }

        // Separator
        assert_eq!(em[2 + ps_len], 0x00);

        // Message
        assert_eq!(&em[3 + ps_len..], msg);
    }

    #[test]
    fn test_encrypt_pad_message_too_long() {
        let k = 128;
        // max msg len = k - 11 = 117
        let long_msg = vec![0xAA; 118];
        assert!(pkcs1v15_encrypt_pad(&long_msg, k).is_err());

        let ok_msg = vec![0xAA; 117];
        assert!(pkcs1v15_encrypt_pad(&ok_msg, k).is_ok());
    }

    #[test]
    fn test_encrypt_decrypt_unpad_roundtrip() {
        let msg = b"Hello PKCS1";
        let k = 128;
        let em = pkcs1v15_encrypt_pad(msg, k).unwrap();
        let recovered = pkcs1v15_decrypt_unpad(&em).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn test_decrypt_unpad_too_short() {
        let em = vec![0u8; 10];
        assert!(pkcs1v15_decrypt_unpad(&em).is_err());
    }

    #[test]
    fn test_decrypt_unpad_bad_header() {
        // Wrong first byte
        let mut em = vec![0x00; 128];
        em[0] = 0x01;
        em[1] = 0x02;
        assert!(pkcs1v15_decrypt_unpad(&em).is_err());

        // Wrong second byte
        let mut em = vec![0x00; 128];
        em[0] = 0x00;
        em[1] = 0x01;
        assert!(pkcs1v15_decrypt_unpad(&em).is_err());
    }

    #[test]
    fn test_decrypt_unpad_ps_too_short() {
        // PS less than 8 bytes: separator at index 9 means PS = em[2..9] = 7 bytes
        let mut em = vec![0xFF; 128];
        em[0] = 0x00;
        em[1] = 0x02;
        em[9] = 0x00; // separator at position 9 => PS only 7 bytes
        assert!(pkcs1v15_decrypt_unpad(&em).is_err());
    }

    #[test]
    fn test_decrypt_unpad_no_separator() {
        // No 0x00 separator after PS
        let mut em = vec![0xFF; 128];
        em[0] = 0x00;
        em[1] = 0x02;
        // All remaining bytes are 0xFF, no separator
        assert!(pkcs1v15_decrypt_unpad(&em).is_err());
    }

    #[test]
    fn test_pkcs1v15_decrypt_varied_separator_positions() {
        // Verify that messages with separator at various valid positions
        // (>= index 10) all decrypt successfully.
        for &sep_pos in &[10usize, 50, 100, 200] {
            let k = 256; // RSA-2048 modulus length
            if sep_pos >= k - 1 {
                continue;
            }
            let msg_len = k - sep_pos - 1;
            let msg: Vec<u8> = (0..msg_len).map(|i| (i & 0xFF) as u8).collect();

            // Build EM: 0x00 || 0x02 || PS(non-zero) || 0x00 || M
            let mut em = Vec::with_capacity(k);
            em.push(0x00);
            em.push(0x02);
            // PS: non-zero random bytes from index 2 to sep_pos-1
            let ps_len = sep_pos - 2;
            for i in 0..ps_len {
                em.push(((i % 254) + 1) as u8); // 1..255, never 0
            }
            em.push(0x00); // separator at sep_pos
            em.extend_from_slice(&msg);
            assert_eq!(em.len(), k);

            let recovered = pkcs1v15_decrypt_unpad(&em).unwrap();
            assert_eq!(recovered, msg, "Failed at separator position {sep_pos}");
        }
    }

    #[test]
    fn test_encrypt_pad_empty_message() {
        let msg = b"";
        let k = 128;
        let em = pkcs1v15_encrypt_pad(msg, k).unwrap();
        let recovered = pkcs1v15_decrypt_unpad(&em).unwrap();
        assert_eq!(recovered, msg);
    }
}
