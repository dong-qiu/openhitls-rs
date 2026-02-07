//! OFB (Output Feedback) mode of operation.
//!
//! Implements OFB mode as defined in NIST SP 800-38A §6.4.
//! Encryption and decryption are the same operation (XOR with keystream).

use crate::aes::{AesKey, AES_BLOCK_SIZE};
use hitls_types::CryptoError;

/// Encrypt or decrypt data using OFB mode (symmetric operation).
///
/// OFB mode generates a keystream by repeatedly encrypting the output
/// feedback value. Both encryption and decryption XOR data with the
/// same keystream, making them identical operations.
pub fn ofb_crypt(key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), CryptoError> {
    if iv.len() != AES_BLOCK_SIZE {
        return Err(CryptoError::InvalidIvLength);
    }
    let cipher = AesKey::new(key)?;

    let mut feedback = [0u8; AES_BLOCK_SIZE];
    feedback.copy_from_slice(iv);

    for chunk in data.chunks_mut(AES_BLOCK_SIZE) {
        // O_i = E_K(O_{i-1})
        cipher.encrypt_block(&mut feedback)?;

        // C_i = P_i XOR O_i (or P_i = C_i XOR O_i)
        for (d, &k) in chunk.iter_mut().zip(feedback.iter()) {
            *d ^= k;
        }
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

    // NIST SP 800-38A F.4.1 OFB-AES128.Encrypt
    #[test]
    fn test_ofb_aes128_nist_vector() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        let pt_hex = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
        let expected_ct = "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e";

        let mut data = hex_to_bytes(pt_hex);
        let original_pt = data.clone();
        ofb_crypt(&key, &iv, &mut data).unwrap();
        assert_eq!(hex(&data), expected_ct);

        // Decrypt (same operation)
        ofb_crypt(&key, &iv, &mut data).unwrap();
        assert_eq!(data, original_pt);
    }

    #[test]
    fn test_ofb_partial_block() {
        let key = [0x42u8; 16];
        let iv = [0u8; 16];
        let original = b"Hello, OFB!".to_vec(); // 11 bytes

        let mut data = original.clone();
        ofb_crypt(&key, &iv, &mut data).unwrap();
        assert_ne!(data, original);

        // Decrypt
        ofb_crypt(&key, &iv, &mut data).unwrap();
        assert_eq!(data, original);
    }
}
