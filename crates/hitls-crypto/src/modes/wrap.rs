//! AES Key Wrap (RFC 3394) and Key Unwrap.
//!
//! Implements the AES Key Wrap algorithm defined in RFC 3394.
//! Supports 128-bit, 192-bit, and 256-bit KEKs.

use crate::aes::AesKey;
use hitls_types::CryptoError;
use subtle::ConstantTimeEq;

/// Default Initial Value (IV) for AES Key Wrap (RFC 3394 §2.2.3.1).
const DEFAULT_IV: [u8; 8] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

/// Wrap a key using AES Key Wrap (RFC 3394).
///
/// The `plaintext_key` must be at least 16 bytes and a multiple of 8 bytes.
/// Returns the wrapped key (8 bytes longer than `plaintext_key`).
pub fn key_wrap(kek: &[u8], plaintext_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if plaintext_key.len() < 16 || plaintext_key.len() % 8 != 0 {
        return Err(CryptoError::InvalidArg);
    }

    let n = plaintext_key.len() / 8;
    let cipher = AesKey::new(kek)?;

    // Initialize: A = IV, R[i] = P[i]
    let mut a = DEFAULT_IV;
    let mut r: Vec<[u8; 8]> = plaintext_key
        .chunks_exact(8)
        .map(|c| {
            let mut block = [0u8; 8];
            block.copy_from_slice(c);
            block
        })
        .collect();

    // Wrap: 6 rounds
    for j in 0..6u64 {
        for (i, ri) in r.iter_mut().enumerate() {
            // B = AES(K, A || R[i])
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&a);
            block[8..].copy_from_slice(ri.as_ref());
            cipher.encrypt_block(&mut block)?;

            // A = MSB(64, B) XOR t where t = n*j + i + 1
            let t = (n as u64 * j + i as u64 + 1).to_be_bytes();
            for k in 0..8 {
                a[k] = block[k] ^ t[k];
            }
            // R[i] = LSB(64, B)
            ri.copy_from_slice(&block[8..]);
        }
    }

    // Output: C = A || R[1] || ... || R[n]
    let mut output = Vec::with_capacity(8 + plaintext_key.len());
    output.extend_from_slice(&a);
    for block in &r {
        output.extend_from_slice(block);
    }
    Ok(output)
}

/// Unwrap a key using AES Key Wrap (RFC 3394).
///
/// The `wrapped_key` must be at least 24 bytes and a multiple of 8 bytes.
/// Returns the unwrapped key (8 bytes shorter than `wrapped_key`).
pub fn key_unwrap(kek: &[u8], wrapped_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if wrapped_key.len() < 24 || wrapped_key.len() % 8 != 0 {
        return Err(CryptoError::InvalidArg);
    }

    let n = wrapped_key.len() / 8 - 1;
    let cipher = AesKey::new(kek)?;

    // Initialize: A = C[0], R[i] = C[i]
    let mut a = [0u8; 8];
    a.copy_from_slice(&wrapped_key[..8]);
    let mut r: Vec<[u8; 8]> = wrapped_key[8..]
        .chunks_exact(8)
        .map(|c| {
            let mut block = [0u8; 8];
            block.copy_from_slice(c);
            block
        })
        .collect();

    // Unwrap: 6 rounds in reverse
    for j in (0..6u64).rev() {
        for i in (0..n).rev() {
            // A XOR t
            let t = (n as u64 * j + i as u64 + 1).to_be_bytes();
            let mut a_xor = [0u8; 8];
            for k in 0..8 {
                a_xor[k] = a[k] ^ t[k];
            }

            // B = AES^{-1}(K, (A XOR t) || R[i])
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&a_xor);
            block[8..].copy_from_slice(&r[i]);
            cipher.decrypt_block(&mut block)?;

            // A = MSB(64, B)
            a.copy_from_slice(&block[..8]);
            // R[i] = LSB(64, B)
            r[i].copy_from_slice(&block[8..]);
        }
    }

    // Verify IV (constant-time)
    if a.ct_eq(&DEFAULT_IV).unwrap_u8() != 1 {
        return Err(CryptoError::AeadTagVerifyFail);
    }

    // Output: P = R[1] || ... || R[n]
    let mut output = Vec::with_capacity(n * 8);
    for block in &r {
        output.extend_from_slice(block);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // RFC 3394 §4.1: Wrap 128 bits with 128-bit KEK
    #[test]
    fn test_wrap_128_kek_128() {
        let kek = hex("000102030405060708090A0B0C0D0E0F");
        let key_data = hex("00112233445566778899AABBCCDDEEFF");
        let expected = hex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");

        let wrapped = key_wrap(&kek, &key_data).unwrap();
        assert_eq!(to_hex(&wrapped), to_hex(&expected));

        let unwrapped = key_unwrap(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped, key_data);
    }

    // RFC 3394 §4.2: Wrap 128 bits with 192-bit KEK
    #[test]
    fn test_wrap_192_kek_128() {
        let kek = hex("000102030405060708090A0B0C0D0E0F1011121314151617");
        let key_data = hex("00112233445566778899AABBCCDDEEFF");
        let expected = hex("96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D");

        let wrapped = key_wrap(&kek, &key_data).unwrap();
        assert_eq!(to_hex(&wrapped), to_hex(&expected));

        let unwrapped = key_unwrap(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped, key_data);
    }

    // RFC 3394 §4.3: Wrap 128 bits with 256-bit KEK
    #[test]
    fn test_wrap_256_kek_128() {
        let kek = hex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let key_data = hex("00112233445566778899AABBCCDDEEFF");
        let expected = hex("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7");

        let wrapped = key_wrap(&kek, &key_data).unwrap();
        assert_eq!(to_hex(&wrapped), to_hex(&expected));

        let unwrapped = key_unwrap(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped, key_data);
    }
}
