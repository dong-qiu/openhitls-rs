//! RSASSA-PSS signature padding (RFC 8017 §9.1).
//!
//! Uses SHA-256 as the hash function and MGF1 as the mask generation function.
//! Default salt length equals the hash output length (32 bytes).

use hitls_types::CryptoError;

use crate::sha2::Sha256;

use super::mgf1_sha256;

/// SHA-256 output length in bytes.
const H_LEN: usize = 32;

/// EMSA-PSS encoding (RFC 8017 §9.1.1).
///
/// `digest` is the pre-computed message hash (mHash).
/// `em_bits` is the maximum bit length of the encoded message (modBits - 1).
pub(crate) fn pss_sign_pad(digest: &[u8], em_bits: usize) -> Result<Vec<u8>, CryptoError> {
    pss_sign_pad_with_salt(digest, em_bits, H_LEN)
}

/// EMSA-PSS encoding with explicit salt length.
pub(crate) fn pss_sign_pad_with_salt(
    digest: &[u8],
    em_bits: usize,
    salt_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    if digest.len() != H_LEN {
        return Err(CryptoError::InvalidArg);
    }

    let em_len = em_bits.div_ceil(8);

    // emLen must be >= hLen + sLen + 2
    if em_len < H_LEN + salt_len + 2 {
        return Err(CryptoError::RsaInvalidPadding);
    }

    // Generate random salt
    let mut salt = vec![0u8; salt_len];
    if salt_len > 0 {
        getrandom::getrandom(&mut salt).map_err(|_| CryptoError::BnRandGenFail)?;
    }

    pss_encode(digest, em_bits, &salt)
}

/// Core PSS encoding with a provided salt (for deterministic testing).
fn pss_encode(digest: &[u8], em_bits: usize, salt: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let em_len = em_bits.div_ceil(8);
    let salt_len = salt.len();

    // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    let mut m_prime = Vec::with_capacity(8 + H_LEN + salt_len);
    m_prime.extend_from_slice(&[0u8; 8]);
    m_prime.extend_from_slice(digest);
    m_prime.extend_from_slice(salt);

    // H = Hash(M')
    let mut hasher = Sha256::new();
    hasher.update(&m_prime).unwrap();
    let h = hasher.finish().unwrap();

    // DB = PS || 0x01 || salt
    // PS = zero octets, length = emLen - hLen - sLen - 2
    let db_len = em_len - H_LEN - 1;
    let ps_len = db_len - salt_len - 1;
    let mut db = Vec::with_capacity(db_len);
    db.extend(std::iter::repeat(0x00).take(ps_len));
    db.push(0x01);
    db.extend_from_slice(salt);
    debug_assert_eq!(db.len(), db_len);

    // dbMask = MGF1(H, emLen - hLen - 1)
    let db_mask = mgf1_sha256(&h, db_len);

    // maskedDB = DB XOR dbMask
    let mut masked_db: Vec<u8> = db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();

    // Set the leftmost 8*emLen - emBits bits of maskedDB to zero
    let top_bits = 8 * em_len - em_bits;
    if top_bits > 0 {
        masked_db[0] &= 0xFF >> top_bits;
    }

    // EM = maskedDB || H || 0xbc
    let mut em = Vec::with_capacity(em_len);
    em.extend_from_slice(&masked_db);
    em.extend_from_slice(&h);
    em.push(0xbc);
    debug_assert_eq!(em.len(), em_len);

    Ok(em)
}

/// EMSA-PSS verification (RFC 8017 §9.1.2).
///
/// `em` is the decrypted signature.
/// `digest` is the pre-computed message hash (mHash).
/// `em_bits` is the maximum bit length (modBits - 1).
pub(crate) fn pss_verify_unpad(
    em: &[u8],
    digest: &[u8],
    em_bits: usize,
) -> Result<bool, CryptoError> {
    pss_verify_unpad_with_salt(em, digest, em_bits, H_LEN)
}

/// EMSA-PSS verification with explicit salt length.
pub(crate) fn pss_verify_unpad_with_salt(
    em: &[u8],
    digest: &[u8],
    em_bits: usize,
    salt_len: usize,
) -> Result<bool, CryptoError> {
    if digest.len() != H_LEN {
        return Err(CryptoError::InvalidArg);
    }

    let em_len = em_bits.div_ceil(8);

    if em.len() < em_len {
        return Ok(false);
    }
    // Use the rightmost em_len bytes (in case em is padded with a leading zero)
    let em = &em[em.len() - em_len..];

    // emLen must be >= hLen + sLen + 2
    if em_len < H_LEN + salt_len + 2 {
        return Ok(false);
    }

    // Check the rightmost octet is 0xbc
    if em[em_len - 1] != 0xbc {
        return Ok(false);
    }

    // Split: maskedDB || H
    let db_len = em_len - H_LEN - 1;
    let masked_db = &em[..db_len];
    let h = &em[db_len..db_len + H_LEN];

    // Check the leftmost 8*emLen - emBits bits of maskedDB are zero
    let top_bits = 8 * em_len - em_bits;
    if top_bits > 0 && (masked_db[0] & (0xFF << (8 - top_bits))) != 0 {
        return Ok(false);
    }

    // dbMask = MGF1(H, emLen - hLen - 1)
    let db_mask = mgf1_sha256(h, db_len);

    // DB = maskedDB XOR dbMask
    let mut db: Vec<u8> = masked_db
        .iter()
        .zip(db_mask.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    // Set the leftmost 8*emLen - emBits bits of DB to zero
    if top_bits > 0 {
        db[0] &= 0xFF >> top_bits;
    }

    // Check DB = PS || 0x01 || salt
    // PS should be all zeros
    let ps_len = db_len - salt_len - 1;
    for &b in &db[..ps_len] {
        if b != 0x00 {
            return Ok(false);
        }
    }
    if db[ps_len] != 0x01 {
        return Ok(false);
    }

    let salt = &db[ps_len + 1..];

    // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    let mut m_prime = Vec::with_capacity(8 + H_LEN + salt_len);
    m_prime.extend_from_slice(&[0u8; 8]);
    m_prime.extend_from_slice(digest);
    m_prime.extend_from_slice(salt);

    // H' = Hash(M')
    let mut hasher = Sha256::new();
    hasher.update(&m_prime).unwrap();
    let h_prime = hasher.finish().unwrap();

    // Compare H == H' (constant-time)
    use subtle::ConstantTimeEq;
    Ok(h.ct_eq(&h_prime).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256(data: &[u8]) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(data).unwrap();
        h.finish().unwrap().to_vec()
    }

    #[test]
    fn test_pss_sign_pad_wrong_digest_length() {
        // PSS requires exactly 32-byte (SHA-256) digest
        let short = vec![0u8; 20];
        assert!(pss_sign_pad(&short, 1023).is_err());

        let long = vec![0u8; 64];
        assert!(pss_sign_pad(&long, 1023).is_err());
    }

    #[test]
    fn test_pss_sign_pad_em_too_small() {
        let digest = sha256(b"hello");
        // em_bits must allow em_len >= H_LEN + salt_len + 2 = 32 + 32 + 2 = 66
        // em_len = ceil(em_bits/8), so em_bits = 65*8 = 520 gives em_len=65 (too small)
        assert!(pss_sign_pad(&digest, 520).is_err());
    }

    #[test]
    fn test_pss_encode_and_verify_roundtrip() {
        let digest = sha256(b"test message");
        let salt = vec![0xAB; 32];
        let em_bits = 1023; // 128 bytes em_len

        let em = pss_encode(&digest, em_bits, &salt).unwrap();
        assert_eq!(em.len(), 128);
        assert_eq!(em[127], 0xbc);

        // Top bit must be zero (8*128 - 1023 = 1 top bit cleared)
        assert_eq!(em[0] & 0x80, 0);

        // Verify should succeed
        let ok = pss_verify_unpad(&em, &digest, em_bits).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_pss_verify_wrong_digest() {
        let digest = sha256(b"message A");
        let salt = vec![0xCD; 32];
        let em_bits = 1023;

        let em = pss_encode(&digest, em_bits, &salt).unwrap();

        let wrong_digest = sha256(b"message B");
        let ok = pss_verify_unpad(&em, &wrong_digest, em_bits).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_pss_verify_tampered_em() {
        let digest = sha256(b"data");
        let salt = vec![0x11; 32];
        let em_bits = 1023;

        let mut em = pss_encode(&digest, em_bits, &salt).unwrap();

        // Tamper with a byte in the middle
        em[60] ^= 0x01;
        let ok = pss_verify_unpad(&em, &digest, em_bits).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_pss_verify_bad_trailer() {
        let digest = sha256(b"data");
        let salt = vec![0x22; 32];
        let em_bits = 1023;

        let mut em = pss_encode(&digest, em_bits, &salt).unwrap();

        // Replace trailer byte 0xbc with something else
        let last = em.len() - 1;
        em[last] = 0xAA;
        let ok = pss_verify_unpad(&em, &digest, em_bits).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_pss_zero_salt_roundtrip() {
        let digest = sha256(b"zero salt");
        let em_bits = 1023;

        let em = pss_encode(&digest, em_bits, &[]).unwrap();
        let ok = pss_verify_unpad_with_salt(&em, &digest, em_bits, 0).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_pss_verify_wrong_digest_length() {
        let em = vec![0u8; 128];
        let short_digest = vec![0u8; 20];
        assert!(pss_verify_unpad(&em, &short_digest, 1023).is_err());
    }

    #[test]
    fn test_pss_verify_em_too_short() {
        let digest = sha256(b"x");
        // em shorter than em_len
        let em = vec![0u8; 10];
        let ok = pss_verify_unpad(&em, &digest, 1023).unwrap();
        assert!(!ok);
    }
}
