//! RSAES-OAEP encryption padding (RFC 8017 §7.1).
//!
//! Uses SHA-256 as the hash function and MGF1 as the mask generation function.

use hitls_types::CryptoError;

use crate::sha2::Sha256;

use super::mgf1_sha256;

/// SHA-256 output length in bytes.
const H_LEN: usize = 32;

/// Compute lHash = SHA-256("") for the default empty label.
fn l_hash() -> [u8; H_LEN] {
    let mut hasher = Sha256::new();
    hasher.finish().unwrap()
}

/// EME-OAEP encoding (RFC 8017 §7.1.1 step 2).
///
/// EM = 0x00 || maskedSeed || maskedDB
pub(crate) fn oaep_encrypt_pad(msg: &[u8], k: usize) -> Result<Vec<u8>, CryptoError> {
    // mLen <= k - 2*hLen - 2
    let max_msg_len = k.saturating_sub(2 * H_LEN + 2);
    if msg.len() > max_msg_len {
        return Err(CryptoError::InputOverflow);
    }

    let lhash = l_hash();

    // DB = lHash || PS || 0x01 || M
    let db_len = k - H_LEN - 1;
    let mut db = Vec::with_capacity(db_len);
    db.extend_from_slice(&lhash);
    // PS = zero padding
    let ps_len = db_len - H_LEN - 1 - msg.len();
    db.extend(std::iter::repeat(0x00).take(ps_len));
    db.push(0x01);
    db.extend_from_slice(msg);
    debug_assert_eq!(db.len(), db_len);

    // Generate random seed
    let mut seed = vec![0u8; H_LEN];
    getrandom::getrandom(&mut seed).map_err(|_| CryptoError::BnRandGenFail)?;

    // dbMask = MGF1(seed, k - hLen - 1)
    let db_mask = mgf1_sha256(&seed, db_len);

    // maskedDB = DB XOR dbMask
    let masked_db: Vec<u8> = db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();

    // seedMask = MGF1(maskedDB, hLen)
    let seed_mask = mgf1_sha256(&masked_db, H_LEN);

    // maskedSeed = seed XOR seedMask
    let masked_seed: Vec<u8> = seed
        .iter()
        .zip(seed_mask.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    // EM = 0x00 || maskedSeed || maskedDB
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.extend_from_slice(&masked_seed);
    em.extend_from_slice(&masked_db);
    debug_assert_eq!(em.len(), k);

    Ok(em)
}

/// EME-OAEP decoding (RFC 8017 §7.1.2 step 3).
///
/// Parses EM = 0x00 || maskedSeed || maskedDB and returns the original message.
pub(crate) fn oaep_decrypt_unpad(em: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let k = em.len();
    if k < 2 * H_LEN + 2 {
        return Err(CryptoError::RsaInvalidPadding);
    }

    // Split EM
    let y = em[0];
    let masked_seed = &em[1..1 + H_LEN];
    let masked_db = &em[1 + H_LEN..];
    let db_len = masked_db.len();

    // seedMask = MGF1(maskedDB, hLen)
    let seed_mask = mgf1_sha256(masked_db, H_LEN);

    // seed = maskedSeed XOR seedMask
    let seed: Vec<u8> = masked_seed
        .iter()
        .zip(seed_mask.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    // dbMask = MGF1(seed, k - hLen - 1)
    let db_mask = mgf1_sha256(&seed, db_len);

    // DB = maskedDB XOR dbMask
    let db: Vec<u8> = masked_db
        .iter()
        .zip(db_mask.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    // Verify: y must be 0x00
    // DB = lHash' || PS || 0x01 || M
    let lhash = l_hash();

    // Check lHash matches (constant-time)
    use subtle::ConstantTimeEq;
    let lhash_valid: bool = db[..H_LEN].ct_eq(&lhash).into();

    // Find the 0x01 separator
    let mut found_one = false;
    let mut msg_start = 0;
    for (i, &byte) in db.iter().enumerate().take(db_len).skip(H_LEN) {
        if byte == 0x01 && !found_one {
            found_one = true;
            msg_start = i + 1;
            break;
        } else if byte != 0x00 {
            return Err(CryptoError::RsaInvalidPadding);
        }
    }

    if y != 0x00 || !lhash_valid || !found_one {
        return Err(CryptoError::RsaInvalidPadding);
    }

    Ok(db[msg_start..].to_vec())
}
