//! PKCS#1 v1.5 padding for RSA signatures and encryption (RFC 8017).

use hitls_types::CryptoError;

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
        _ => Err(CryptoError::InvalidArg),
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
    use subtle::ConstantTimeEq;
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
pub(crate) fn pkcs1v15_decrypt_unpad(em: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if em.len() < 11 {
        return Err(CryptoError::RsaInvalidPadding);
    }

    // Check header bytes
    if em[0] != 0x00 || em[1] != 0x02 {
        return Err(CryptoError::RsaInvalidPadding);
    }

    // Find the 0x00 separator after PS (PS must be at least 8 bytes)
    let mut sep_idx = None;
    for (i, &byte) in em.iter().enumerate().skip(2) {
        if byte == 0x00 {
            if i < 10 {
                // PS too short (less than 8 bytes)
                return Err(CryptoError::RsaInvalidPadding);
            }
            sep_idx = Some(i);
            break;
        }
    }

    let sep = sep_idx.ok_or(CryptoError::RsaInvalidPadding)?;
    Ok(em[sep + 1..].to_vec())
}

/// Fill a buffer with random non-zero bytes.
fn fill_nonzero_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    let mut tmp = vec![0u8; buf.len()];
    for slot in buf.iter_mut() {
        // Rejection-sample until non-zero
        loop {
            getrandom::getrandom(&mut tmp[..1]).map_err(|_| CryptoError::BnRandGenFail)?;
            if tmp[0] != 0 {
                *slot = tmp[0];
                break;
            }
        }
    }
    Ok(())
}
