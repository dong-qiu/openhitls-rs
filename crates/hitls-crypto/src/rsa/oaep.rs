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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_l_hash_is_sha256_of_empty() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(l_hash(), expected);
    }

    #[test]
    fn test_oaep_encrypt_pad_structure() {
        let msg = b"OAEP test";
        let k = 128;
        let em = oaep_encrypt_pad(msg, k).unwrap();

        assert_eq!(em.len(), k);
        assert_eq!(em[0], 0x00); // Leading zero byte
    }

    #[test]
    fn test_oaep_message_too_long() {
        let k = 128;
        // max_msg_len = k - 2*H_LEN - 2 = 128 - 64 - 2 = 62
        let long_msg = vec![0xAA; 63];
        assert!(oaep_encrypt_pad(&long_msg, k).is_err());

        let ok_msg = vec![0xAA; 62];
        assert!(oaep_encrypt_pad(&ok_msg, k).is_ok());
    }

    #[test]
    fn test_oaep_encrypt_decrypt_roundtrip() {
        let msg = b"roundtrip check";
        let k = 128;
        let em = oaep_encrypt_pad(msg, k).unwrap();
        let recovered = oaep_decrypt_unpad(&em).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn test_oaep_encrypt_decrypt_empty_message() {
        let msg = b"";
        let k = 128;
        let em = oaep_encrypt_pad(msg, k).unwrap();
        let recovered = oaep_decrypt_unpad(&em).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn test_oaep_decrypt_too_short() {
        // Minimum: 2*H_LEN + 2 = 66 bytes
        let em = vec![0u8; 65];
        assert!(oaep_decrypt_unpad(&em).is_err());
    }

    #[test]
    fn test_oaep_decrypt_bad_first_byte() {
        let msg = b"test";
        let k = 128;
        let mut em = oaep_encrypt_pad(msg, k).unwrap();
        em[0] = 0x01; // Should be 0x00
        assert!(oaep_decrypt_unpad(&em).is_err());
    }

    #[test]
    fn test_oaep_decrypt_tampered_masked_db() {
        let msg = b"data";
        let k = 128;
        let mut em = oaep_encrypt_pad(msg, k).unwrap();
        // Tamper with maskedDB region (after maskedSeed)
        em[1 + H_LEN + 5] ^= 0xFF;
        // Decryption should fail (lHash mismatch or structural error)
        assert!(oaep_decrypt_unpad(&em).is_err());
    }

    #[test]
    fn test_oaep_randomness() {
        // Two encryptions of the same message should produce different ciphertexts
        let msg = b"same message";
        let k = 128;
        let em1 = oaep_encrypt_pad(msg, k).unwrap();
        let em2 = oaep_encrypt_pad(msg, k).unwrap();
        assert_ne!(em1, em2, "OAEP should be randomized");

        // But both should decrypt to the same message
        let r1 = oaep_decrypt_unpad(&em1).unwrap();
        let r2 = oaep_decrypt_unpad(&em2).unwrap();
        assert_eq!(r1, msg);
        assert_eq!(r2, msg);
    }
}
