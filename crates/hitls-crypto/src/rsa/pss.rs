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
