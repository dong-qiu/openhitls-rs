//! AES Key Wrap (RFC 3394) and AES Key Wrap with Padding (RFC 5649).
//!
//! - [`key_wrap`] / [`key_unwrap`]: RFC 3394 NOPAD — input must be a
//!   multiple of 8 bytes, ≥ 16 bytes.
//! - [`key_wrap_pad`] / [`key_unwrap_pad`]: RFC 5649 PAD — input may be
//!   any length ≥ 1 byte (≤ 2^32 − 1 bytes per the AIV's 4-byte MLI
//!   field). Padding is zero-bytes; the AIV `0xA65959A6 ‖ MLI` records
//!   the original byte length so unwrap can strip the padding.
//!
//! Supports 128-bit, 192-bit, and 256-bit KEKs.

use crate::aes::AesKey;
use hitls_types::CryptoError;
use subtle::ConstantTimeEq;

/// Default Initial Value (IV) for AES Key Wrap (RFC 3394 §2.2.3.1).
const DEFAULT_IV: [u8; 8] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

/// RFC 5649 §3 Alternative Initial Value prefix: `A6 59 59 A6`. The
/// trailing 4 bytes record the message-length indicator (MLI), the
/// original plaintext byte length in big-endian.
const RFC5649_AIV_PREFIX: [u8; 4] = [0xA6, 0x59, 0x59, 0xA6];

/// Run RFC 3394 §2.2.1 wrap-step over `plaintext_blocks` (caller-supplied
/// 64-bit blocks, n ≥ 2) using `iv` as the initial `A`. Returns
/// `iv-final ‖ R[0..n]` (`8*(n+1)` bytes).
fn wrap_inner(
    cipher: &AesKey,
    iv: [u8; 8],
    plaintext_blocks: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let n = plaintext_blocks.len() / 8;
    debug_assert!(n >= 2 && plaintext_blocks.len() % 8 == 0);

    let mut a = iv;
    let mut r: Vec<[u8; 8]> = plaintext_blocks
        .chunks_exact(8)
        .map(|c| {
            let mut block = [0u8; 8];
            block.copy_from_slice(c);
            block
        })
        .collect();

    for j in 0..6u64 {
        for (i, ri) in r.iter_mut().enumerate() {
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&a);
            block[8..].copy_from_slice(ri.as_ref());
            cipher.encrypt_block(&mut block)?;

            let t = (n as u64 * j + i as u64 + 1).to_be_bytes();
            for k in 0..8 {
                a[k] = block[k] ^ t[k];
            }
            ri.copy_from_slice(&block[8..]);
        }
    }

    let mut output = Vec::with_capacity(8 + plaintext_blocks.len());
    output.extend_from_slice(&a);
    for block in &r {
        output.extend_from_slice(block);
    }
    Ok(output)
}

/// Inverse of [`wrap_inner`]. Takes `wrapped` (len ≥ 24, multiple of 8)
/// and returns `(iv-recovered, plaintext_blocks)`. The caller verifies
/// the IV.
fn unwrap_inner(cipher: &AesKey, wrapped: &[u8]) -> Result<([u8; 8], Vec<u8>), CryptoError> {
    debug_assert!(wrapped.len() >= 24 && wrapped.len() % 8 == 0);
    let n = wrapped.len() / 8 - 1;

    let mut a = [0u8; 8];
    a.copy_from_slice(&wrapped[..8]);
    let mut r: Vec<[u8; 8]> = wrapped[8..]
        .chunks_exact(8)
        .map(|c| {
            let mut block = [0u8; 8];
            block.copy_from_slice(c);
            block
        })
        .collect();

    for j in (0..6u64).rev() {
        for i in (0..n).rev() {
            let t = (n as u64 * j + i as u64 + 1).to_be_bytes();
            let mut a_xor = [0u8; 8];
            for k in 0..8 {
                a_xor[k] = a[k] ^ t[k];
            }

            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&a_xor);
            block[8..].copy_from_slice(&r[i]);
            cipher.decrypt_block(&mut block)?;

            a.copy_from_slice(&block[..8]);
            r[i].copy_from_slice(&block[8..]);
        }
    }

    let mut plaintext = Vec::with_capacity(n * 8);
    for block in &r {
        plaintext.extend_from_slice(block);
    }
    Ok((a, plaintext))
}

/// Wrap a key using AES Key Wrap (RFC 3394).
///
/// The `plaintext_key` must be at least 16 bytes and a multiple of 8 bytes.
/// Returns the wrapped key (8 bytes longer than `plaintext_key`).
pub fn key_wrap(kek: &[u8], plaintext_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if plaintext_key.len() < 16 || plaintext_key.len() % 8 != 0 {
        return Err(CryptoError::InvalidArg(""));
    }
    let cipher = AesKey::new(kek)?;
    wrap_inner(&cipher, DEFAULT_IV, plaintext_key)
}

/// Unwrap a key using AES Key Wrap (RFC 3394).
///
/// The `wrapped_key` must be at least 24 bytes and a multiple of 8 bytes.
/// Returns the unwrapped key (8 bytes shorter than `wrapped_key`).
pub fn key_unwrap(kek: &[u8], wrapped_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if wrapped_key.len() < 24 || wrapped_key.len() % 8 != 0 {
        return Err(CryptoError::InvalidArg(""));
    }
    let cipher = AesKey::new(kek)?;
    let (a, plaintext) = unwrap_inner(&cipher, wrapped_key)?;
    if a.ct_eq(&DEFAULT_IV).unwrap_u8() != 1 {
        return Err(CryptoError::AeadTagVerifyFail);
    }
    Ok(plaintext)
}

/// Wrap a key using AES Key Wrap with Padding (RFC 5649).
///
/// Unlike RFC 3394 NOPAD, the input may be any byte length in
/// `1..=u32::MAX`. The plaintext is zero-padded up to the next 8-byte
/// boundary and the original byte length is recorded in the AIV:
/// `A65959A6 ‖ MLI` (RFC 5649 §3). For inputs ≤ 8 bytes, the spec
/// specialises to a single AES block: `AES_Encrypt(K, AIV ‖ padded)`.
///
/// Returns `8 * ceil(len(plaintext)/8) + 8` bytes (≥ 16).
pub fn key_wrap_pad(kek: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if plaintext.is_empty() || plaintext.len() > u32::MAX as usize {
        return Err(CryptoError::InvalidArg(""));
    }
    let cipher = AesKey::new(kek)?;

    // Build AIV = 0xA65959A6 ‖ MLI (big-endian byte length).
    let mli = u32::try_from(plaintext.len())
        .map_err(|_| CryptoError::InvalidArg(""))?
        .to_be_bytes();
    let mut aiv = [0u8; 8];
    aiv[..4].copy_from_slice(&RFC5649_AIV_PREFIX);
    aiv[4..].copy_from_slice(&mli);

    // Zero-pad plaintext to a multiple of 8 bytes.
    let n = plaintext.len().div_ceil(8);
    let mut padded = Vec::with_capacity(n * 8);
    padded.extend_from_slice(plaintext);
    padded.resize(n * 8, 0);

    if n == 1 {
        // Single-block: ciphertext = AES_Encrypt(K, AIV ‖ padded).
        let mut block = [0u8; 16];
        block[..8].copy_from_slice(&aiv);
        block[8..].copy_from_slice(&padded);
        cipher.encrypt_block(&mut block)?;
        Ok(block.to_vec())
    } else {
        // Multi-block: same 6-round wrap as RFC 3394 but with AIV.
        wrap_inner(&cipher, aiv, &padded)
    }
}

/// Unwrap a key using AES Key Wrap with Padding (RFC 5649).
///
/// `wrapped` must be a multiple of 8 bytes, ≥ 16 bytes. Returns the
/// original (un-padded) plaintext. Verifies:
/// 1. AIV prefix == `A65959A6`,
/// 2. MLI ∈ `8*(n-1)+1 ..= 8*n` where `n = len(wrapped)/8 - 1`,
/// 3. trailing pad bytes (positions `MLI..8*n`) are all zero.
pub fn key_unwrap_pad(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if wrapped.len() < 16 || wrapped.len() % 8 != 0 {
        return Err(CryptoError::InvalidArg(""));
    }
    let cipher = AesKey::new(kek)?;

    let (aiv, padded_plaintext) = if wrapped.len() == 16 {
        // Single-block case: 16 bytes wrapped → 1 block in & out.
        let mut block = [0u8; 16];
        block.copy_from_slice(wrapped);
        cipher.decrypt_block(&mut block)?;
        let mut aiv = [0u8; 8];
        aiv.copy_from_slice(&block[..8]);
        let mut padded = Vec::with_capacity(8);
        padded.extend_from_slice(&block[8..]);
        (aiv, padded)
    } else {
        unwrap_inner(&cipher, wrapped)?
    };

    // 1) AIV prefix.
    if aiv[..4].ct_eq(&RFC5649_AIV_PREFIX).unwrap_u8() != 1 {
        return Err(CryptoError::AeadTagVerifyFail);
    }
    // 2) MLI range.
    let n = padded_plaintext.len() / 8;
    let mli = u32::from_be_bytes([aiv[4], aiv[5], aiv[6], aiv[7]]) as usize;
    if mli == 0 || mli > 8 * n || mli + 7 < 8 * n {
        return Err(CryptoError::AeadTagVerifyFail);
    }
    // 3) Trailing pad bytes are zero (constant-time accumulate).
    let mut pad_acc = 0u8;
    for &b in &padded_plaintext[mli..] {
        pad_acc |= b;
    }
    if pad_acc != 0 {
        return Err(CryptoError::AeadTagVerifyFail);
    }

    let mut plaintext = padded_plaintext;
    plaintext.truncate(mli);
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_utils::hex::{hex, to_hex};

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

    #[test]
    fn test_wrap_too_short_plaintext() {
        let kek = hex("000102030405060708090A0B0C0D0E0F");
        // 8-byte plaintext — min is 16
        assert!(matches!(
            key_wrap(&kek, &[0u8; 8]),
            Err(CryptoError::InvalidArg(_))
        ));
        // 0 bytes
        assert!(matches!(
            key_wrap(&kek, &[]),
            Err(CryptoError::InvalidArg(_))
        ));
    }

    #[test]
    fn test_wrap_non_multiple_of_8() {
        let kek = hex("000102030405060708090A0B0C0D0E0F");
        // 17-byte plaintext — not a multiple of 8
        assert!(matches!(
            key_wrap(&kek, &[0u8; 17]),
            Err(CryptoError::InvalidArg(""))
        ));
        // 25-byte wrapped — not a multiple of 8 for unwrap
        assert!(matches!(
            key_unwrap(&kek, &[0u8; 25]),
            Err(CryptoError::InvalidArg(""))
        ));
    }

    #[test]
    fn test_wrap_corrupted_unwrap() {
        let kek = hex("000102030405060708090A0B0C0D0E0F");
        let key_data = hex("00112233445566778899AABBCCDDEEFF");
        let mut wrapped = key_wrap(&kek, &key_data).unwrap();
        // Flip a middle byte — IV check should fail on unwrap
        wrapped[12] ^= 0xff;
        assert!(key_unwrap(&kek, &wrapped).is_err());
    }

    // RFC 3394 §4.6: 256-bit KEK wrapping 256-bit key
    #[test]
    fn test_wrap_aes256_rfc3394() {
        let kek = hex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let key_data = hex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
        let expected =
            hex("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21");

        let wrapped = key_wrap(&kek, &key_data).unwrap();
        assert_eq!(to_hex(&wrapped), to_hex(&expected));

        let unwrapped = key_unwrap(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped, key_data);
    }

    // RFC 5649 §6 / openHiTLS SDV: multi-block (AES-192 KEK, 20-byte input).
    #[test]
    fn test_wrap_pad_aes192_rfc5649_multi() {
        let kek = hex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
        let plaintext = hex("c37b7e6492584340bed12207808941155068f738");
        let expected = hex("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a");

        let wrapped = key_wrap_pad(&kek, &plaintext).unwrap();
        assert_eq!(to_hex(&wrapped), to_hex(&expected));

        let unwrapped = key_unwrap_pad(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped, plaintext);
    }

    // RFC 5649 §6 / openHiTLS SDV: single-block (AES-192 KEK, 7-byte input).
    #[test]
    fn test_wrap_pad_aes192_rfc5649_single() {
        let kek = hex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
        let plaintext = hex("466f7250617369");
        let expected = hex("afbeb0f07dfbf5419200f2ccb50bb24f");

        let wrapped = key_wrap_pad(&kek, &plaintext).unwrap();
        assert_eq!(to_hex(&wrapped), to_hex(&expected));

        let unwrapped = key_unwrap_pad(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped, plaintext);
    }

    #[test]
    fn test_wrap_pad_rejects_empty_plaintext() {
        let kek = hex("000102030405060708090A0B0C0D0E0F");
        assert!(matches!(
            key_wrap_pad(&kek, &[]),
            Err(CryptoError::InvalidArg(""))
        ));
    }

    #[test]
    fn test_unwrap_pad_rejects_bad_aiv_prefix() {
        let kek = hex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
        let plaintext = hex("c37b7e6492584340bed12207808941155068f738");
        let mut wrapped = key_wrap_pad(&kek, &plaintext).unwrap();
        // Flipping the first ciphertext byte randomises the recovered AIV.
        wrapped[0] ^= 0xff;
        assert!(matches!(
            key_unwrap_pad(&kek, &wrapped),
            Err(CryptoError::AeadTagVerifyFail)
        ));
    }

    #[test]
    fn test_unwrap_pad_rejects_oob_mli_single_block() {
        // Single-block wrapped value with AIV prefix OK but MLI=9 (>8 for n=1).
        let kek = hex("000102030405060708090A0B0C0D0E0F");
        let mut block = [0u8; 16];
        block[..4].copy_from_slice(&RFC5649_AIV_PREFIX);
        block[4..8].copy_from_slice(&9u32.to_be_bytes());
        let cipher = AesKey::new(&kek).unwrap();
        cipher.encrypt_block(&mut block).unwrap();
        assert!(matches!(
            key_unwrap_pad(&kek, &block),
            Err(CryptoError::AeadTagVerifyFail)
        ));
    }
}
