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

    for chunk in data.chunks_mut(AES_BLOCK_SIZE) {
        let mut keystream = counter;
        cipher.encrypt_block(&mut keystream)?;
        for (d, &k) in chunk.iter_mut().zip(keystream.iter()) {
            *d ^= k;
        }
        increment_counter(&mut counter);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // NIST SP 800-38A F.5.1: AES-128 CTR
    #[test]
    fn test_ctr_aes128() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let nonce = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let pt = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a");
        let expected = "874d6191b620e3261bef6864990db6ce";

        let mut data = pt.clone();
        ctr_crypt(&key, &nonce, &mut data).unwrap();
        assert_eq!(hex(&data), expected);

        // Decrypt (same operation)
        ctr_crypt(&key, &nonce, &mut data).unwrap();
        assert_eq!(data, pt);
    }

    // Multi-block CTR
    #[test]
    fn test_ctr_multi_block() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let nonce = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let pt = hex_to_bytes(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        );
        let expected = "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee";

        let mut data = pt.clone();
        ctr_crypt(&key, &nonce, &mut data).unwrap();
        assert_eq!(hex(&data), expected);
    }

    // Partial block
    #[test]
    fn test_ctr_partial_block() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let nonce = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let pt = b"Hello";

        let mut data = pt.to_vec();
        ctr_crypt(&key, &nonce, &mut data).unwrap();
        assert_ne!(data, pt.as_slice());
        ctr_crypt(&key, &nonce, &mut data).unwrap();
        assert_eq!(data, pt);
    }

    #[test]
    fn test_ctr_empty() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let nonce = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let mut data = vec![];
        assert!(ctr_crypt(&key, &nonce, &mut data).is_ok());
    }
}
