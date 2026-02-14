//! XTS (XEX-based Tweaked-codebook mode with ciphertext Stealing).
//!
//! XTS mode is designed for disk encryption (IEEE P1619 / NIST SP 800-38E).
//! It requires two keys of equal size: K1 for data encryption, K2 for tweak
//! encryption.

use crate::aes::{AesKey, AES_BLOCK_SIZE};
use hitls_types::CryptoError;

/// Multiply a 128-bit tweak value by α in GF(2^128).
/// Polynomial: x^128 + x^7 + x^2 + x + 1 (reduction constant 0x87).
fn gf_mul_alpha(tweak: &mut [u8; AES_BLOCK_SIZE]) {
    let mut carry = 0u8;
    for byte in tweak.iter_mut() {
        let new_carry = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = new_carry;
    }
    // If the most significant bit was set, XOR with reduction constant
    if carry != 0 {
        tweak[0] ^= 0x87;
    }
}

/// Encrypt a data unit using XTS mode.
///
/// # Parameters
/// - `key1`: Key for data encryption.
/// - `key2`: Key for tweak encryption.
/// - `tweak`: 16-byte tweak (typically the sector number).
/// - `plaintext`: Must be at least 16 bytes.
pub fn xts_encrypt(
    key1: &[u8],
    key2: &[u8],
    tweak: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if tweak.len() != AES_BLOCK_SIZE {
        return Err(CryptoError::InvalidArg);
    }
    if plaintext.len() < AES_BLOCK_SIZE {
        return Err(CryptoError::InvalidArg);
    }
    let cipher1 = AesKey::new(key1)?;
    let cipher2 = AesKey::new(key2)?;

    // Encrypt tweak
    let mut t = [0u8; AES_BLOCK_SIZE];
    t.copy_from_slice(tweak);
    cipher2.encrypt_block(&mut t)?;

    let full_blocks = plaintext.len() / AES_BLOCK_SIZE;
    let remainder = plaintext.len() % AES_BLOCK_SIZE;
    let data_blocks = if remainder > 0 {
        full_blocks - 1
    } else {
        full_blocks
    };

    let mut ciphertext = vec![0u8; plaintext.len()];

    // Process complete blocks
    for i in 0..data_blocks {
        let start = i * AES_BLOCK_SIZE;
        let mut block = [0u8; AES_BLOCK_SIZE];
        block.copy_from_slice(&plaintext[start..start + AES_BLOCK_SIZE]);

        // PP = P XOR T
        for (b, &ti) in block.iter_mut().zip(t.iter()) {
            *b ^= ti;
        }
        // CC = E(PP)
        cipher1.encrypt_block(&mut block)?;
        // C = CC XOR T
        for (b, &ti) in block.iter_mut().zip(t.iter()) {
            *b ^= ti;
        }
        ciphertext[start..start + AES_BLOCK_SIZE].copy_from_slice(&block);

        gf_mul_alpha(&mut t);
    }

    // Handle ciphertext stealing for partial last block
    if remainder > 0 {
        // Encrypt the second-to-last block (block m-1) with current tweak
        let m1_start = data_blocks * AES_BLOCK_SIZE;
        let mut block_m1 = [0u8; AES_BLOCK_SIZE];
        block_m1.copy_from_slice(&plaintext[m1_start..m1_start + AES_BLOCK_SIZE]);

        for (b, &ti) in block_m1.iter_mut().zip(t.iter()) {
            *b ^= ti;
        }
        cipher1.encrypt_block(&mut block_m1)?;
        for (b, &ti) in block_m1.iter_mut().zip(t.iter()) {
            *b ^= ti;
        }

        // The last ciphertext block Cm = first `remainder` bytes of C_{m-1}
        let cm_start = (data_blocks + 1) * AES_BLOCK_SIZE;
        ciphertext[cm_start..cm_start + remainder].copy_from_slice(&block_m1[..remainder]);

        // Build the second-to-last ciphertext block using stolen ciphertext
        gf_mul_alpha(&mut t);
        let mut block_m = [0u8; AES_BLOCK_SIZE];
        block_m[..remainder].copy_from_slice(&plaintext[m1_start + AES_BLOCK_SIZE..]);
        block_m[remainder..].copy_from_slice(&block_m1[remainder..]);

        for (b, &ti) in block_m.iter_mut().zip(t.iter()) {
            *b ^= ti;
        }
        cipher1.encrypt_block(&mut block_m)?;
        for (b, &ti) in block_m.iter_mut().zip(t.iter()) {
            *b ^= ti;
        }

        ciphertext[m1_start..m1_start + AES_BLOCK_SIZE].copy_from_slice(&block_m);
    }

    Ok(ciphertext)
}

/// Decrypt a data unit using XTS mode.
pub fn xts_decrypt(
    key1: &[u8],
    key2: &[u8],
    tweak: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if tweak.len() != AES_BLOCK_SIZE {
        return Err(CryptoError::InvalidArg);
    }
    if ciphertext.len() < AES_BLOCK_SIZE {
        return Err(CryptoError::InvalidArg);
    }
    let cipher1 = AesKey::new(key1)?;
    let cipher2 = AesKey::new(key2)?;

    // Encrypt tweak
    let mut t = [0u8; AES_BLOCK_SIZE];
    t.copy_from_slice(tweak);
    cipher2.encrypt_block(&mut t)?;

    let full_blocks = ciphertext.len() / AES_BLOCK_SIZE;
    let remainder = ciphertext.len() % AES_BLOCK_SIZE;
    let data_blocks = if remainder > 0 {
        full_blocks - 1
    } else {
        full_blocks
    };

    let mut plaintext = vec![0u8; ciphertext.len()];

    // Process complete blocks
    for i in 0..data_blocks {
        let start = i * AES_BLOCK_SIZE;
        let mut block = [0u8; AES_BLOCK_SIZE];
        block.copy_from_slice(&ciphertext[start..start + AES_BLOCK_SIZE]);

        for (b, &ti) in block.iter_mut().zip(t.iter()) {
            *b ^= ti;
        }
        cipher1.decrypt_block(&mut block)?;
        for (b, &ti) in block.iter_mut().zip(t.iter()) {
            *b ^= ti;
        }
        plaintext[start..start + AES_BLOCK_SIZE].copy_from_slice(&block);

        gf_mul_alpha(&mut t);
    }

    // Handle ciphertext stealing
    if remainder > 0 {
        let m1_start = data_blocks * AES_BLOCK_SIZE;

        // Decrypt C_{m-1} with tweak T_{m} (next tweak)
        let t_m1 = t;
        gf_mul_alpha(&mut t);

        let mut block_m = [0u8; AES_BLOCK_SIZE];
        block_m.copy_from_slice(&ciphertext[m1_start..m1_start + AES_BLOCK_SIZE]);

        for (b, &ti) in block_m.iter_mut().zip(t.iter()) {
            *b ^= ti;
        }
        cipher1.decrypt_block(&mut block_m)?;
        for (b, &ti) in block_m.iter_mut().zip(t.iter()) {
            *b ^= ti;
        }

        // Last plaintext block = first `remainder` bytes of decrypted block_m
        let cm_start = (data_blocks + 1) * AES_BLOCK_SIZE;
        plaintext[cm_start..cm_start + remainder].copy_from_slice(&block_m[..remainder]);

        // Reconstruct second-to-last block
        let mut block_m1 = [0u8; AES_BLOCK_SIZE];
        block_m1[..remainder].copy_from_slice(&ciphertext[m1_start + AES_BLOCK_SIZE..]);
        block_m1[remainder..].copy_from_slice(&block_m[remainder..]);

        for (b, &ti) in block_m1.iter_mut().zip(t_m1.iter()) {
            *b ^= ti;
        }
        cipher1.decrypt_block(&mut block_m1)?;
        for (b, &ti) in block_m1.iter_mut().zip(t_m1.iter()) {
            *b ^= ti;
        }

        plaintext[m1_start..m1_start + AES_BLOCK_SIZE].copy_from_slice(&block_m1);
    }

    Ok(plaintext)
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

    // IEEE P1619 Vector 1: 256-bit data unit key, 128-bit tweak
    #[test]
    fn test_xts_ieee_vector1() {
        let key1 = hex_to_bytes("00000000000000000000000000000000");
        let key2 = hex_to_bytes("00000000000000000000000000000000");
        let tweak = hex_to_bytes("00000000000000000000000000000000");
        let pt = hex_to_bytes("0000000000000000000000000000000000000000000000000000000000000000");
        let expected_ct = "917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e";

        let ct = xts_encrypt(&key1, &key2, &tweak, &pt).unwrap();
        assert_eq!(hex(&ct), expected_ct);

        let decrypted = xts_decrypt(&key1, &key2, &tweak, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_xts_roundtrip_multi_block() {
        let key1 = [0x01u8; 16];
        let key2 = [0x02u8; 16];
        let tweak = [0u8; 16];
        let pt = vec![0x42u8; 64]; // 4 blocks

        let ct = xts_encrypt(&key1, &key2, &tweak, &pt).unwrap();
        assert_eq!(ct.len(), pt.len());
        assert_ne!(ct, pt);

        let decrypted = xts_decrypt(&key1, &key2, &tweak, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_xts_ciphertext_stealing() {
        let key1 = [0x01u8; 16];
        let key2 = [0x02u8; 16];
        let tweak = [0u8; 16];
        // 20 bytes: one full block + 4 bytes partial
        let pt = vec![0x42u8; 20];

        let ct = xts_encrypt(&key1, &key2, &tweak, &pt).unwrap();
        assert_eq!(ct.len(), pt.len());

        let decrypted = xts_decrypt(&key1, &key2, &tweak, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_xts_invalid_input() {
        let key1 = [0u8; 16];
        let key2 = [0u8; 16];
        let tweak = [0u8; 16];
        // Less than one block
        assert!(xts_encrypt(&key1, &key2, &tweak, &[0u8; 15]).is_err());
    }

    #[test]
    fn test_xts_too_short_plaintext() {
        let key1 = [0x42u8; 16];
        let key2 = [0x43u8; 16];
        let tweak = [0u8; 16];
        // Various lengths below minimum 16
        for len in [0, 1, 8, 15] {
            let data = vec![0u8; len];
            assert!(
                xts_encrypt(&key1, &key2, &tweak, &data).is_err(),
                "encrypt should reject plaintext of length {len}"
            );
            if len > 0 {
                assert!(
                    xts_decrypt(&key1, &key2, &tweak, &data).is_err(),
                    "decrypt should reject ciphertext of length {len}"
                );
            }
        }
    }
}
