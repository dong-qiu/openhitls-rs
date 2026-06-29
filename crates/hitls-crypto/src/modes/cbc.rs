//! CBC (Cipher Block Chaining) mode of operation.

use crate::aes::{AesKey, AES_BLOCK_SIZE};
use crate::provider::BlockCipher;
use hitls_types::CryptoError;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Encrypt data using CBC mode with AES and PKCS#7 padding.
pub fn cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if iv.len() != AES_BLOCK_SIZE {
        return Err(CryptoError::InvalidIvLength);
    }
    let cipher = AesKey::new(key)?;

    // PKCS#7 padding (stack array, no heap allocation for padding bytes)
    let pad_len = AES_BLOCK_SIZE - (plaintext.len() % AES_BLOCK_SIZE);
    let mut data = Vec::with_capacity(plaintext.len() + pad_len);
    data.extend_from_slice(plaintext);
    let mut pad_buf = [0u8; AES_BLOCK_SIZE];
    pad_buf[..pad_len].fill(pad_len as u8);
    data.extend_from_slice(&pad_buf[..pad_len]);

    let mut prev = [0u8; AES_BLOCK_SIZE];
    prev.copy_from_slice(iv);

    for chunk in data.chunks_mut(AES_BLOCK_SIZE) {
        for i in 0..AES_BLOCK_SIZE {
            chunk[i] ^= prev[i];
        }
        cipher.encrypt_block(chunk)?;
        prev.copy_from_slice(chunk);
    }
    Ok(data)
}

/// Decrypt data using CBC mode with AES and remove PKCS#7 padding.
pub fn cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if iv.len() != AES_BLOCK_SIZE {
        return Err(CryptoError::InvalidIvLength);
    }
    if ciphertext.len() % AES_BLOCK_SIZE != 0 || ciphertext.is_empty() {
        return Err(CryptoError::InvalidArg("CBC input not block-aligned"));
    }
    let cipher = AesKey::new(key)?;

    let mut output = ciphertext.to_vec();
    let mut prev = [0u8; AES_BLOCK_SIZE];
    prev.copy_from_slice(iv);

    for chunk in output.chunks_exact_mut(AES_BLOCK_SIZE) {
        let mut ct_copy = [0u8; AES_BLOCK_SIZE];
        ct_copy.copy_from_slice(chunk);
        cipher.decrypt_block(chunk)?;
        for i in 0..AES_BLOCK_SIZE {
            chunk[i] ^= prev[i];
        }
        prev = ct_copy;
    }

    // PKCS#7 unpad (constant-time check)
    let pad_val = *output.last().ok_or(CryptoError::InvalidPadding)? as usize;
    if pad_val == 0 || pad_val > AES_BLOCK_SIZE {
        output.zeroize();
        return Err(CryptoError::InvalidPadding);
    }
    let pad_byte = pad_val as u8;
    let mut valid = 1u8;
    for &b in &output[output.len() - pad_val..] {
        valid &= b.ct_eq(&pad_byte).unwrap_u8();
    }
    if valid != 1 {
        output.zeroize();
        return Err(CryptoError::InvalidPadding);
    }
    output.truncate(output.len() - pad_val);
    Ok(output)
}

/// Encrypt data using CBC mode with a generic block cipher and PKCS#7 padding.
pub fn cbc_encrypt_with<C: BlockCipher>(
    cipher: &C,
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let bs = cipher.block_size();
    if iv.len() != bs {
        return Err(CryptoError::InvalidIvLength);
    }

    // PKCS#7 padding (stack array, no heap allocation for padding bytes)
    let pad_len = bs - (plaintext.len() % bs);
    let mut data = Vec::with_capacity(plaintext.len() + pad_len);
    data.extend_from_slice(plaintext);
    let mut pad_buf = [0u8; 16];
    pad_buf[..pad_len].fill(pad_len as u8);
    data.extend_from_slice(&pad_buf[..pad_len]);

    let mut prev = [0u8; 16];
    prev[..bs].copy_from_slice(iv);

    for chunk in data.chunks_mut(bs) {
        for i in 0..bs {
            chunk[i] ^= prev[i];
        }
        cipher.encrypt_block(chunk)?;
        prev[..bs].copy_from_slice(chunk);
    }
    Ok(data)
}

/// In-place CBC decryption of a 16-byte-block ciphertext buffer (no padding
/// handling): `output` enters as ciphertext and leaves as plaintext.
///
/// Pipelined: CBC decryption parallelizes because each `P_i = D(C_i) XOR C_{i-1}`
/// and all the `C_i` are known up front, so 4 blocks are decrypted in one batch
/// (`decrypt_4_blocks`, which hides the inverse-cipher instruction latency) and
/// then XORed with their preceding ciphertext blocks. (CBC *encryption* can't do
/// this — it is serial on the previous ciphertext.) The 1-3 trailing blocks fall
/// back to single-block. Shared by the padded and raw CBC-decrypt entry points.
///
/// Preconditions (callers validate): `iv.len() == 16` and `output.len() % 16 == 0`.
fn cbc_decrypt_in_place_16<C: BlockCipher>(
    cipher: &C,
    iv: &[u8],
    output: &mut [u8],
) -> Result<(), CryptoError> {
    let mut prev = [0u8; 16];
    prev.copy_from_slice(&iv[..16]);

    let mut offset = 0;
    while offset + 64 <= output.len() {
        let mut blocks = [[0u8; 16]; 4];
        for j in 0..4 {
            blocks[j].copy_from_slice(&output[offset + j * 16..offset + (j + 1) * 16]);
        }
        // Snapshot the ciphertext blocks before in-place decryption: they are the
        // XOR operands (C_{i-1}) and the chaining value for the next group.
        let cts = blocks;
        cipher.decrypt_4_blocks(&mut blocks)?;
        for k in 0..16 {
            blocks[0][k] ^= prev[k];
            blocks[1][k] ^= cts[0][k];
            blocks[2][k] ^= cts[1][k];
            blocks[3][k] ^= cts[2][k];
        }
        prev = cts[3];
        for j in 0..4 {
            output[offset + j * 16..offset + (j + 1) * 16].copy_from_slice(&blocks[j]);
        }
        offset += 64;
    }
    // Tail: remaining 1-3 blocks, single-block.
    while offset < output.len() {
        let mut ct_copy = [0u8; 16];
        ct_copy.copy_from_slice(&output[offset..offset + 16]);
        cipher.decrypt_block(&mut output[offset..offset + 16])?;
        for k in 0..16 {
            output[offset + k] ^= prev[k];
        }
        prev = ct_copy;
        offset += 16;
    }
    Ok(())
}

/// Decrypt data using CBC mode with a generic block cipher and remove PKCS#7 padding.
pub fn cbc_decrypt_with<C: BlockCipher>(
    cipher: &C,
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let bs = cipher.block_size();
    if iv.len() != bs {
        return Err(CryptoError::InvalidIvLength);
    }
    if ciphertext.len() % bs != 0 || ciphertext.is_empty() {
        return Err(CryptoError::InvalidArg("CBC input not block-aligned"));
    }

    let mut output = ciphertext.to_vec();

    if bs == 16 {
        cbc_decrypt_in_place_16(cipher, iv, &mut output)?;
    } else {
        // Generic single-block path for any non-128-bit block cipher.
        let mut prev = [0u8; 16];
        prev[..bs].copy_from_slice(iv);
        for chunk in output.chunks_mut(bs) {
            let mut ct_copy = [0u8; 16];
            ct_copy[..bs].copy_from_slice(chunk);
            cipher.decrypt_block(chunk)?;
            for i in 0..bs {
                chunk[i] ^= prev[i];
            }
            prev = ct_copy;
        }
    }

    // PKCS#7 unpad (constant-time check)
    let pad_val = *output.last().ok_or(CryptoError::InvalidPadding)? as usize;
    if pad_val == 0 || pad_val > bs {
        output.zeroize();
        return Err(CryptoError::InvalidPadding);
    }
    let pad_byte = pad_val as u8;
    let mut valid = 1u8;
    for &b in &output[output.len() - pad_val..] {
        valid &= b.ct_eq(&pad_byte).unwrap_u8();
    }
    if valid != 1 {
        output.zeroize();
        return Err(CryptoError::InvalidPadding);
    }
    output.truncate(output.len() - pad_val);
    Ok(output)
}

/// Encrypt data using CBC mode with SM4 and PKCS#7 padding.
#[cfg(feature = "sm4")]
pub fn sm4_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = crate::sm4::Sm4Key::new(key)?;
    cbc_encrypt_with(&cipher, iv, plaintext)
}

/// Decrypt data using CBC mode with SM4 and remove PKCS#7 padding.
#[cfg(feature = "sm4")]
pub fn sm4_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = crate::sm4::Sm4Key::new(key)?;
    cbc_decrypt_with(&cipher, iv, ciphertext)
}

/// Encrypt block-aligned data using SM4-CBC with **no padding**.
///
/// Mirrors [`cbc_encrypt_raw`] but with SM4 (GM/T 0002-2012) as the
/// block cipher. `plaintext.len()` must be a multiple of 16 and > 0.
#[cfg(feature = "sm4")]
pub fn sm4_cbc_encrypt_raw(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = crate::sm4::Sm4Key::new(key)?;
    cbc_encrypt_raw_with(&cipher, iv, plaintext)
}

/// Decrypt block-aligned data using SM4-CBC with **no padding**.
///
/// Mirrors [`cbc_decrypt_raw`] but with SM4 (GM/T 0002-2012) as the
/// block cipher. `ciphertext.len()` must be a multiple of 16 and > 0.
#[cfg(feature = "sm4")]
pub fn sm4_cbc_decrypt_raw(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = crate::sm4::Sm4Key::new(key)?;
    cbc_decrypt_raw_with(&cipher, iv, ciphertext)
}

// ---------------------------------------------------------------------------
// Raw (no-padding) CBC helpers.
//
// NIST SP 800-38A §6.2 defines CBC without prescribing a padding scheme.
// Standard KAT vectors (NIST CAVP, FIPS 197 Annex C) publish block-aligned
// plaintext / ciphertext directly, so the PKCS#7-wrapping `cbc_encrypt` /
// `cbc_decrypt` cannot reproduce them: their output is always 16 bytes
// longer than the input, and their decrypt path rejects the unpadded
// ciphertext as having "invalid padding".
//
// The raw helpers below require `input.len() % block_size == 0` and skip
// the PKCS#7 wrap/unwrap step entirely. They are the right entry point
// for byte-exact NIST KAT reproduction; production code should keep using
// the padded `cbc_encrypt` / `cbc_decrypt` (or higher-level AEAD modes)
// unless the caller already guarantees alignment.
// ---------------------------------------------------------------------------

/// Encrypt block-aligned data using AES-CBC with **no padding**.
///
/// `plaintext.len()` must be a multiple of `AES_BLOCK_SIZE`. Returns the
/// ciphertext of identical length. Use this for NIST CAVP / FIPS 197
/// KAT reproduction; for everyday encryption prefer the PKCS#7-padded
/// [`cbc_encrypt`].
pub fn cbc_encrypt_raw(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = AesKey::new(key)?;
    cbc_encrypt_raw_with(&cipher, iv, plaintext)
}

/// Decrypt block-aligned data using AES-CBC with **no padding**.
///
/// `ciphertext.len()` must be a multiple of `AES_BLOCK_SIZE`. Returns
/// the plaintext of identical length. Use this for NIST CAVP / FIPS 197
/// KAT reproduction; for everyday decryption prefer the PKCS#7-padded
/// [`cbc_decrypt`].
pub fn cbc_decrypt_raw(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = AesKey::new(key)?;
    cbc_decrypt_raw_with(&cipher, iv, ciphertext)
}

/// Raw (no-padding) CBC encrypt over a generic block cipher.
///
/// Constrained to **128-bit (16-byte) block ciphers** — AES and SM4 today.
/// Wider blocks would require a `Vec`-backed state buffer; rather than pay
/// the allocation cost on every encrypted block (the hot path), the
/// internal staging arrays are stack-sized to 16 bytes and the function
/// rejects ciphers whose `block_size()` would index out of bounds.
pub fn cbc_encrypt_raw_with<C: BlockCipher>(
    cipher: &C,
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let bs = cipher.block_size();
    if bs != 16 {
        return Err(CryptoError::InvalidArg(
            "raw CBC requires a 128-bit block cipher",
        ));
    }
    if iv.len() != bs {
        return Err(CryptoError::InvalidIvLength);
    }
    if plaintext.is_empty() || plaintext.len() % bs != 0 {
        return Err(CryptoError::InvalidArg("CBC input not block-aligned"));
    }

    let mut data = plaintext.to_vec();
    let mut prev = [0u8; 16];
    prev[..bs].copy_from_slice(iv);

    for chunk in data.chunks_mut(bs) {
        for i in 0..bs {
            chunk[i] ^= prev[i];
        }
        cipher.encrypt_block(chunk)?;
        prev[..bs].copy_from_slice(chunk);
    }
    Ok(data)
}

/// Raw (no-padding) CBC decrypt over a generic block cipher.
///
/// Constrained to **128-bit (16-byte) block ciphers** — see
/// [`cbc_encrypt_raw_with`] for rationale.
pub fn cbc_decrypt_raw_with<C: BlockCipher>(
    cipher: &C,
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let bs = cipher.block_size();
    if bs != 16 {
        return Err(CryptoError::InvalidArg(
            "raw CBC requires a 128-bit block cipher",
        ));
    }
    if iv.len() != bs {
        return Err(CryptoError::InvalidIvLength);
    }
    if ciphertext.is_empty() || ciphertext.len() % bs != 0 {
        return Err(CryptoError::InvalidArg("CBC input not block-aligned"));
    }

    let mut output = ciphertext.to_vec();
    // bs == 16 enforced above; use the pipelined in-place CBC decrypt.
    cbc_decrypt_in_place_16(cipher, iv, &mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_utils::hex::{hex, to_hex};

    // NIST SP 800-38A F.2.1: AES-128 CBC (without padding — aligned input)
    #[test]
    fn test_cbc_aes128_roundtrip() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        let pt = hex("6bc1bee22e409f96e93d7e117393172a");

        let ct = cbc_encrypt(&key, &iv, &pt).unwrap();
        // ct has padding block appended
        let decrypted = cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_cbc_roundtrip_all_lengths_exercises_4block_tail() {
        // The pipelined CBC decrypt processes full groups of 4 blocks then a
        // 1-3 block tail. Sweep plaintext lengths so the resulting ciphertexts
        // span 1..6 blocks (every tail remainder + multi-group cases) and assert
        // round-trip recovery for both padded and raw CBC.
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        for n in 0usize..=80 {
            let pt: Vec<u8> = (0..n).map(|i| (i * 3 + 7) as u8).collect();
            let ct = cbc_encrypt(&key, &iv, &pt).unwrap();
            let rt = cbc_decrypt(&key, &iv, &ct).unwrap();
            assert_eq!(rt, pt, "padded CBC round-trip failed at len {n}");
        }
        // Raw (no padding): block-aligned inputs of 1..9 blocks.
        for blocks in 1usize..=9 {
            let pt: Vec<u8> = (0..blocks * 16).map(|i| (i ^ 0x5a) as u8).collect();
            let ct = cbc_encrypt_raw(&key, &iv, &pt).unwrap();
            let rt = cbc_decrypt_raw(&key, &iv, &ct).unwrap();
            assert_eq!(rt, pt, "raw CBC round-trip failed at {blocks} blocks");
        }
    }

    #[test]
    fn test_cbc_padding_short() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        let pt = b"Hello, World!"; // 13 bytes, needs 3 bytes padding

        let ct = cbc_encrypt(&key, &iv, pt).unwrap();
        assert_eq!(ct.len(), 16); // One padded block
        let decrypted = cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_cbc_padding_aligned() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        let pt = [0xaau8; 16]; // Exactly one block — gets full padding block

        let ct = cbc_encrypt(&key, &iv, &pt).unwrap();
        assert_eq!(ct.len(), 32); // Original block + padding block
        let decrypted = cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_cbc_empty() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex("000102030405060708090a0b0c0d0e0f");

        let ct = cbc_encrypt(&key, &iv, b"").unwrap();
        assert_eq!(ct.len(), 16); // Padding-only block
        let decrypted = cbc_decrypt(&key, &iv, &ct).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_cbc_invalid_iv() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        assert!(cbc_encrypt(&key, &[0u8; 15], b"test").is_err());
    }

    #[cfg(feature = "sm4")]
    #[test]
    fn test_sm4_cbc_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 16]; // SM4 128-bit key
        let iv = [0x01u8; 16];
        let plaintext = b"hello SM4-CBC with PKCS7 padding";

        let ct = sm4_cbc_encrypt(&key, &iv, plaintext).unwrap();
        // 32 bytes plaintext → 32 bytes + 16 bytes padding block = 48 bytes
        assert_eq!(ct.len(), 48);

        let pt = sm4_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[cfg(feature = "sm4")]
    #[test]
    fn test_sm4_cbc_pkcs7_padding() {
        let key = [0x55u8; 16];
        let iv = [0xaau8; 16];

        // Test short input (5 bytes → needs 11 bytes padding → 1 block)
        let pt_short = b"ABCDE";
        let ct = sm4_cbc_encrypt(&key, &iv, pt_short).unwrap();
        assert_eq!(ct.len(), 16);
        let decrypted = sm4_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(decrypted, pt_short);

        // Test aligned input (16 bytes → gets full 16-byte padding block → 2 blocks)
        let pt_aligned = [0xbbu8; 16];
        let ct = sm4_cbc_encrypt(&key, &iv, &pt_aligned).unwrap();
        assert_eq!(ct.len(), 32);
        let decrypted = sm4_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(decrypted, pt_aligned);

        // Test empty input (→ 16 bytes padding-only block)
        let ct = sm4_cbc_encrypt(&key, &iv, b"").unwrap();
        assert_eq!(ct.len(), 16);
        let decrypted = sm4_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert!(decrypted.is_empty());
    }

    // NIST SP 800-38A F.2.1: verify first ciphertext block
    #[test]
    fn test_cbc_aes128_nist_vector() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        let pt = hex(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        );
        // Expected ciphertext blocks (without padding)
        let expected_ct = "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7";

        let ct = cbc_encrypt(&key, &iv, &pt).unwrap();
        // First 64 bytes of ct should match (the last 16 bytes are padding)
        assert_eq!(to_hex(&ct[..64]), expected_ct);
    }

    // NIST SP 800-38A F.2.1 / F.2.2 / F.2.3: AES-128/192/256 CBC, raw mode.
    // Plaintext is block-aligned, so reproducing the published ciphertext
    // requires the no-padding helper. The padded `cbc_encrypt` cannot
    // reproduce these vectors — its output is always +16 bytes.
    #[test]
    fn test_cbc_encrypt_raw_aes128_nist_f_2_1() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        let pt = hex(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        );
        let expected_ct = hex(
            "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
        );
        let ct = cbc_encrypt_raw(&key, &iv, &pt).unwrap();
        assert_eq!(ct, expected_ct);
        let pt2 = cbc_decrypt_raw(&key, &iv, &ct).unwrap();
        assert_eq!(pt2, pt);
    }

    #[test]
    fn test_cbc_encrypt_raw_rejects_unaligned() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        // 13 bytes — not block-aligned.
        assert!(cbc_encrypt_raw(&key, &iv, b"Hello, World!").is_err());
        assert!(cbc_encrypt_raw(&key, &iv, b"").is_err());
    }

    #[test]
    fn test_cbc_decrypt_raw_rejects_unaligned() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        assert!(cbc_decrypt_raw(&key, &iv, &[0u8; 13]).is_err());
        assert!(cbc_decrypt_raw(&key, &iv, &[]).is_err());
    }

    /// Defensive: a `BlockCipher` whose `block_size()` exceeds 16 must be
    /// rejected — the raw helpers' internal staging arrays are stack-sized
    /// to 16 bytes and would index out of bounds otherwise.
    #[test]
    fn test_cbc_raw_with_rejects_non_128bit_cipher() {
        struct WideCipher;
        impl crate::provider::BlockCipher for WideCipher {
            fn block_size(&self) -> usize {
                32
            }
            fn key_size(&self) -> usize {
                32
            }
            fn set_encrypt_key(&mut self, _key: &[u8]) -> Result<(), CryptoError> {
                Ok(())
            }
            fn set_decrypt_key(&mut self, _key: &[u8]) -> Result<(), CryptoError> {
                Ok(())
            }
            fn encrypt_block(&self, _block: &mut [u8]) -> Result<(), CryptoError> {
                unreachable!("should be rejected before encrypt_block runs")
            }
            fn decrypt_block(&self, _block: &mut [u8]) -> Result<(), CryptoError> {
                unreachable!("should be rejected before decrypt_block runs")
            }
        }
        let iv = [0u8; 32];
        let pt = [0u8; 32];
        assert!(matches!(
            cbc_encrypt_raw_with(&WideCipher, &iv, &pt),
            Err(CryptoError::InvalidArg(_))
        ));
        assert!(matches!(
            cbc_decrypt_raw_with(&WideCipher, &iv, &pt),
            Err(CryptoError::InvalidArg(_))
        ));
    }

    mod proptests {
        use super::super::{cbc_decrypt, cbc_decrypt_raw, cbc_encrypt, cbc_encrypt_raw};
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            #[test]
            fn prop_cbc_encrypt_decrypt(
                key in prop::array::uniform16(any::<u8>()),
                iv in prop::array::uniform16(any::<u8>()),
                pt in proptest::collection::vec(any::<u8>(), 1..128),
            ) {
                let ct = cbc_encrypt(&key, &iv, &pt).unwrap();
                let recovered = cbc_decrypt(&key, &iv, &ct).unwrap();
                prop_assert_eq!(recovered, pt);
            }

            /// Raw CBC roundtrip — block-aligned input only.
            #[test]
            fn prop_cbc_raw_encrypt_decrypt(
                key in prop::array::uniform16(any::<u8>()),
                iv in prop::array::uniform16(any::<u8>()),
                blocks in 1usize..8,
            ) {
                let pt: Vec<u8> = (0..blocks * 16).map(|i| (i as u8).wrapping_mul(31)).collect();
                let ct = cbc_encrypt_raw(&key, &iv, &pt).unwrap();
                prop_assert_eq!(ct.len(), pt.len());
                let recovered = cbc_decrypt_raw(&key, &iv, &ct).unwrap();
                prop_assert_eq!(recovered, pt);
            }
        }
    }
}
