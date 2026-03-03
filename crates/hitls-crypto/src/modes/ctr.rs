//! CTR (Counter) mode of operation.

use crate::aes::{AesKey, AES_BLOCK_SIZE};
use hitls_types::CryptoError;

/// Increment a 128-bit big-endian counter by 1.
fn increment_counter(counter: &mut [u8]) {
    for byte in counter.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

/// Encrypt or decrypt data using CTR mode with AES.
/// `nonce` must be 16 bytes (used as the initial counter value).
pub fn ctr_crypt(key: &[u8], nonce: &[u8], data: &mut [u8]) -> Result<(), CryptoError> {
    if nonce.len() != AES_BLOCK_SIZE {
        return Err(CryptoError::InvalidIvLength);
    }
    if data.is_empty() {
        return Ok(());
    }
    let cipher = AesKey::new(key)?;
    let mut counter = [0u8; AES_BLOCK_SIZE];
    counter.copy_from_slice(nonce);

    let mut offset = 0;

    // 4-block pipeline: process 64 bytes at a time
    while offset + 64 <= data.len() {
        let mut blocks = [counter; 4];
        increment_counter(&mut counter);
        blocks[1] = counter;
        increment_counter(&mut counter);
        blocks[2] = counter;
        increment_counter(&mut counter);
        blocks[3] = counter;
        increment_counter(&mut counter);

        cipher.encrypt_4_blocks(&mut blocks)?;

        for (i, block) in blocks.iter().enumerate() {
            let base = offset + i * AES_BLOCK_SIZE;
            for j in 0..AES_BLOCK_SIZE {
                data[base + j] ^= block[j];
            }
        }
        offset += 64;
    }

    // Tail: single-block loop for remaining data
    while offset < data.len() {
        let mut keystream = counter;
        cipher.encrypt_block(&mut keystream)?;
        let remaining = (data.len() - offset).min(AES_BLOCK_SIZE);
        for j in 0..remaining {
            data[offset + j] ^= keystream[j];
        }
        increment_counter(&mut counter);
        offset += remaining;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_utils::hex::{hex, to_hex};

    // NIST SP 800-38A F.5.1: AES-128 CTR
    #[test]
    fn test_ctr_aes128() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let nonce = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let pt = hex("6bc1bee22e409f96e93d7e117393172a");
        let expected = "874d6191b620e3261bef6864990db6ce";

        let mut data = pt.clone();
        ctr_crypt(&key, &nonce, &mut data).unwrap();
        assert_eq!(to_hex(&data), expected);

        // Decrypt (same operation)
        ctr_crypt(&key, &nonce, &mut data).unwrap();
        assert_eq!(data, pt);
    }

    // Multi-block CTR
    #[test]
    fn test_ctr_multi_block() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let nonce = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let pt = hex(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        );
        let expected = "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee";

        let mut data = pt.clone();
        ctr_crypt(&key, &nonce, &mut data).unwrap();
        assert_eq!(to_hex(&data), expected);
    }

    // Partial block
    #[test]
    fn test_ctr_partial_block() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let nonce = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let pt = b"Hello";

        let mut data = pt.to_vec();
        ctr_crypt(&key, &nonce, &mut data).unwrap();
        assert_ne!(data, pt.as_slice());
        ctr_crypt(&key, &nonce, &mut data).unwrap();
        assert_eq!(data, pt);
    }

    #[test]
    fn test_ctr_empty() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let nonce = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let mut data = vec![];
        assert!(ctr_crypt(&key, &nonce, &mut data).is_ok());
    }

    #[test]
    fn test_ctr_invalid_nonce_length() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let mut data = vec![0u8; 16];
        // 15 bytes — too short
        assert!(matches!(
            ctr_crypt(&key, &[0u8; 15], &mut data),
            Err(CryptoError::InvalidIvLength)
        ));
        // 0 bytes
        assert!(matches!(
            ctr_crypt(&key, &[], &mut data),
            Err(CryptoError::InvalidIvLength)
        ));
        // 12 bytes
        assert!(matches!(
            ctr_crypt(&key, &[0u8; 12], &mut data),
            Err(CryptoError::InvalidIvLength)
        ));
        // 17 bytes — too long
        assert!(matches!(
            ctr_crypt(&key, &[0u8; 17], &mut data),
            Err(CryptoError::InvalidIvLength)
        ));
    }

    #[test]
    fn test_ctr_invalid_key_length() {
        let nonce = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let mut data = vec![0u8; 16];
        // 15 bytes — not a valid AES key length
        assert!(ctr_crypt(&[0u8; 15], &nonce, &mut data).is_err());
        // 17 bytes
        assert!(ctr_crypt(&[0u8; 17], &nonce, &mut data).is_err());
        // 0 bytes
        assert!(ctr_crypt(&[], &nonce, &mut data).is_err());
    }

    // NIST SP 800-38A F.5.5: AES-256-CTR
    #[test]
    fn test_ctr_aes256_roundtrip() {
        let key = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let nonce = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let pt = hex("6bc1bee22e409f96e93d7e117393172a");
        let expected_ct = "601ec313775789a5b7a7f504bbf3d228";

        let mut data = pt.clone();
        ctr_crypt(&key, &nonce, &mut data).unwrap();
        assert_eq!(to_hex(&data), expected_ct);

        // Decrypt (same operation) — roundtrip
        ctr_crypt(&key, &nonce, &mut data).unwrap();
        assert_eq!(data, pt);
    }
}
