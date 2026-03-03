//! HCTR mode — a length-preserving tweakable wide-block cipher.
//!
//! HCTR combines AES-ECB, AES-CTR, and a GF(2^128) universal hash (UHash)
//! to provide a tweakable enciphering scheme. The plaintext must be at
//! least 16 bytes. Output length always equals input length.

use crate::aes::{AesKey, AES_BLOCK_SIZE};
use hitls_types::CryptoError;

const BLOCK: usize = AES_BLOCK_SIZE; // 16

// ── GF(2^128) multiplication (4-bit table, reduction x^128 + x^7 + x^2 + x + 1) ──

/// Reduction table for 4-bit GHASH: TABLE_R4[i] = i * R >> 120, where R = 0xE1 << 120.
const TABLE_R4: [u64; 16] = [
    0x0000000000000000,
    0x1c20000000000000,
    0x3840000000000000,
    0x2460000000000000,
    0x7080000000000000,
    0x6ca0000000000000,
    0x48c0000000000000,
    0x54e0000000000000,
    0xe100000000000000,
    0xfd20000000000000,
    0xd940000000000000,
    0xc560000000000000,
    0x9180000000000000,
    0x8da0000000000000,
    0xa9c0000000000000,
    0xb5e0000000000000,
];

/// Multiply two 128-bit elements in GF(2^128) using 4-bit table lookup.
///
/// Builds a 16-entry table for `a` (4-bit multiples), then processes `b`
/// nibble-by-nibble from low byte to high byte, shifting and reducing.
pub fn gf128_mul(a: &[u8; BLOCK], b: &[u8; BLOCK]) -> [u8; BLOCK] {
    // Build 4-bit multiplication table for a: table[i] = i * a in GF(2^128)
    let a_h = u64::from_be_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]]);
    let a_l = u64::from_be_bytes([a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]]);

    let mut tab_h = [0u64; 16];
    let mut tab_l = [0u64; 16];

    // table[0] = 0 (default), table[8] = a
    tab_h[8] = a_h;
    tab_l[8] = a_l;

    // Build by halving: table[4], table[2], table[1]
    let mut cur_h = a_h;
    let mut cur_l = a_l;
    for &idx in &[4usize, 2, 1] {
        let carry = (cur_l & 1) != 0;
        cur_l = (cur_l >> 1) | (cur_h << 63);
        cur_h >>= 1;
        if carry {
            cur_h ^= 0xe100000000000000;
        }
        tab_h[idx] = cur_h;
        tab_l[idx] = cur_l;
    }

    // Fill remaining entries by XOR
    for i in 2u8..16 {
        if i.count_ones() > 1 {
            let msb = 1u8 << (7 - i.leading_zeros());
            let j = i as usize;
            let m = msb as usize;
            tab_h[j] = tab_h[m] ^ tab_h[j ^ m];
            tab_l[j] = tab_l[m] ^ tab_l[j ^ m];
        }
    }

    // Multiply: process b nibble-by-nibble from low byte to high byte
    let mut z_h: u64 = 0;
    let mut z_l: u64 = 0;

    for &byte in b.iter().rev() {
        // Low nibble
        let lo = (byte & 0x0f) as usize;
        let rem = (z_l & 0x0f) as usize;
        z_l = (z_l >> 4) | (z_h << 60);
        z_h >>= 4;
        z_h ^= TABLE_R4[rem];
        z_h ^= tab_h[lo];
        z_l ^= tab_l[lo];

        // High nibble
        let hi = (byte >> 4) as usize;
        let rem = (z_l & 0x0f) as usize;
        z_l = (z_l >> 4) | (z_h << 60);
        z_h >>= 4;
        z_h ^= TABLE_R4[rem];
        z_h ^= tab_h[hi];
        z_l ^= tab_l[hi];
    }

    let mut result = [0u8; BLOCK];
    result[..8].copy_from_slice(&z_h.to_be_bytes());
    result[8..].copy_from_slice(&z_l.to_be_bytes());
    result
}

// ── Universal hash ──

/// UHash(K2, data, tweak) → 16-byte hash.
///
/// Uses Horner's method to evaluate the polynomial over GF(2^128) without
/// precomputing key powers or heap allocation:
///   hash = (...((block_0 * K + block_1) * K + block_2) * K ...) * K + len * K
fn uhash(k2: &[u8; BLOCK], data: &[u8], tweak: &[u8]) -> [u8; BLOCK] {
    let effective_len = data.len() + tweak.len();

    // Build a virtual stream of data || tweak, process in 16-byte blocks
    // using Horner's method: hash = ((b0*K + b1)*K + b2)*K + ... + len*K
    let mut hash_val = [0u8; BLOCK];
    let mut global_pos = 0usize; // position in the virtual data||tweak stream

    while global_pos < effective_len {
        let chunk_len = BLOCK.min(effective_len - global_pos);
        let mut block = [0u8; BLOCK];

        // Fill block from the virtual stream (may span data/tweak boundary)
        let mut filled = 0;
        if global_pos < data.len() {
            let data_avail = data.len() - global_pos;
            let take = chunk_len.min(data_avail);
            block[..take].copy_from_slice(&data[global_pos..global_pos + take]);
            filled = take;
        }
        if filled < chunk_len {
            let tweak_start = if global_pos + filled >= data.len() {
                global_pos + filled - data.len()
            } else {
                0
            };
            let take = chunk_len - filled;
            block[filled..filled + take].copy_from_slice(&tweak[tweak_start..tweak_start + take]);
        }

        xor_block(&mut hash_val, &block);
        hash_val = gf128_mul(&hash_val, k2);
        global_pos += chunk_len;
    }

    // Length block: 128-bit BE encoding of total bit length
    let total_bits = (effective_len as u64) * 8;
    let mut len_block = [0u8; BLOCK];
    len_block[8..16].copy_from_slice(&total_bits.to_be_bytes());
    xor_block(&mut hash_val, &len_block);
    hash_val = gf128_mul(&hash_val, k2);

    hash_val
}

// ── XOR helpers ──

#[inline]
fn xor_block(dst: &mut [u8; BLOCK], src: &[u8; BLOCK]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= s;
    }
}

#[inline]
fn xor_bytes(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= s;
    }
}

// ── CTR keystream (using ctr_base XOR counter) ──

/// Apply AES-CTR keystream to `data` in-place, using `ctr_base` XOR BE counter.
fn apply_ctr(cipher: &AesKey, ctr_base: &[u8; BLOCK], data: &mut [u8]) -> Result<(), CryptoError> {
    let mut counter = 1u64;
    for chunk in data.chunks_mut(BLOCK) {
        let mut ctr_block = *ctr_base;
        // XOR BE counter into last 8 bytes
        let counter_be = counter.to_be_bytes();
        xor_bytes(&mut ctr_block[8..], &counter_be);
        cipher.encrypt_block(&mut ctr_block)?;
        xor_bytes(chunk, &ctr_block);
        counter += 1;
    }
    Ok(())
}

// ── Public API ──

/// Encrypt data using HCTR mode.
///
/// - `key`: AES key (16, 24, or 32 bytes) used as K1 for ECB/CTR.
/// - `hash_key`: 16-byte key K2 for the GF(2^128) universal hash.
/// - `tweak`: arbitrary-length tweak (typically 16 bytes).
/// - `plaintext`: at least 16 bytes; output length equals input length.
pub fn hctr_encrypt(
    key: &[u8],
    hash_key: &[u8; BLOCK],
    tweak: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if plaintext.len() < BLOCK {
        return Err(CryptoError::InvalidArg(""));
    }
    let cipher = AesKey::new(key)?;
    let p0 = &plaintext[..BLOCK];
    let p_rest = &plaintext[BLOCK..];

    // Step 1: S = P[0] XOR UHash(K2, P_rest, tweak)
    let h1 = uhash(hash_key, p_rest, tweak);
    let mut s = [0u8; BLOCK];
    s.copy_from_slice(p0);
    xor_block(&mut s, &h1);

    // Step 2: CC = AES-ECB(K1, S)
    let mut cc = s;
    cipher.encrypt_block(&mut cc)?;

    // Step 3: ctr_base = S XOR CC
    let mut ctr_base = [0u8; BLOCK];
    ctr_base.copy_from_slice(&s);
    xor_block(&mut ctr_base, &cc);

    // Step 4: C_rest = CTR(K1, ctr_base, P_rest)
    let mut c_rest = p_rest.to_vec();
    apply_ctr(&cipher, &ctr_base, &mut c_rest)?;

    // Step 5: C[0] = CC XOR UHash(K2, C_rest, tweak)
    let h2 = uhash(hash_key, &c_rest, tweak);
    let mut c0 = cc;
    xor_block(&mut c0, &h2);

    // Output: C[0] || C_rest
    let mut out = Vec::with_capacity(plaintext.len());
    out.extend_from_slice(&c0);
    out.extend_from_slice(&c_rest);
    Ok(out)
}

/// Decrypt data using HCTR mode.
///
/// - `key`: AES key (16, 24, or 32 bytes) used as K1.
/// - `hash_key`: 16-byte key K2 for the GF(2^128) universal hash.
/// - `tweak`: arbitrary-length tweak.
/// - `ciphertext`: at least 16 bytes; output length equals input length.
pub fn hctr_decrypt(
    key: &[u8],
    hash_key: &[u8; BLOCK],
    tweak: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < BLOCK {
        return Err(CryptoError::InvalidArg(""));
    }
    let cipher = AesKey::new(key)?;
    let c0 = &ciphertext[..BLOCK];
    let c_rest = &ciphertext[BLOCK..];

    // Step 1: z2 = C[0] XOR UHash(K2, C_rest, tweak)
    let h1 = uhash(hash_key, c_rest, tweak);
    let mut z2 = [0u8; BLOCK];
    z2.copy_from_slice(c0);
    xor_block(&mut z2, &h1);

    // Step 2: z1 = AES-ECB-Decrypt(K1, z2)  =>  z1 = S (original)
    let mut z1 = z2;
    cipher.decrypt_block(&mut z1)?;

    // Step 3: ctr_base = z1 XOR z2
    let mut ctr_base = [0u8; BLOCK];
    ctr_base.copy_from_slice(&z1);
    xor_block(&mut ctr_base, &z2);

    // Step 4: P_rest = CTR(K1, ctr_base, C_rest)
    let mut p_rest = c_rest.to_vec();
    apply_ctr(&cipher, &ctr_base, &mut p_rest)?;

    // Step 5: P[0] = z1 XOR UHash(K2, P_rest, tweak)
    let h2 = uhash(hash_key, &p_rest, tweak);
    let mut p0 = z1;
    xor_block(&mut p0, &h2);

    // Output: P[0] || P_rest
    let mut out = Vec::with_capacity(ciphertext.len());
    out.extend_from_slice(&p0);
    out.extend_from_slice(&p_rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    use hitls_utils::hex::hex;

    #[test]
    fn test_gf128_mul_basic() {
        // Multiplying by 1 (0x80...0 in MSB-first = polynomial 1) returns the same value
        let a: [u8; 16] = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let one = {
            let mut v = [0u8; 16];
            v[0] = 0x80; // x^0 = 1 in MSB-first representation
            v
        };
        let result = gf128_mul(&a, &one);
        assert_eq!(result, a);

        // Multiplying by zero gives zero
        let zero = [0u8; 16];
        let result = gf128_mul(&a, &zero);
        assert_eq!(result, zero);
    }

    #[test]
    fn test_hctr_encrypt_decrypt_roundtrip() {
        let key = hex("000102030405060708090a0b0c0d0e0f");
        let hash_key: [u8; 16] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];
        let tweak = hex("aabbccdd11223344aabbccdd11223344");
        let plaintext = vec![0x42u8; 64];

        let ct = hctr_encrypt(&key, &hash_key, &tweak, &plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len());
        assert_ne!(ct, plaintext);

        let pt = hctr_decrypt(&key, &hash_key, &tweak, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_hctr_single_block() {
        let key = hex("000102030405060708090a0b0c0d0e0f");
        let hash_key: [u8; 16] = [0xaa; 16];
        let tweak = [0xbb; 16];
        let plaintext = [0xcc; 16]; // Exactly one block — no CTR portion

        let ct = hctr_encrypt(&key, &hash_key, &tweak, &plaintext).unwrap();
        assert_eq!(ct.len(), 16);
        assert_ne!(ct, plaintext.to_vec());

        let pt = hctr_decrypt(&key, &hash_key, &tweak, &ct).unwrap();
        assert_eq!(pt, plaintext.to_vec());
    }

    #[test]
    fn test_hctr_multi_block() {
        let key = hex("0011223344556677889900112233445566778899001122330011223344556677");
        let hash_key: [u8; 16] = [0x55; 16];
        let tweak = b"my custom tweak!".to_vec();
        let plaintext: Vec<u8> = (0..=255).collect(); // 256 bytes

        let ct = hctr_encrypt(&key, &hash_key, &tweak, &plaintext).unwrap();
        assert_eq!(ct.len(), 256);

        let pt = hctr_decrypt(&key, &hash_key, &tweak, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_hctr_length_preserving() {
        let key = hex("000102030405060708090a0b0c0d0e0f");
        let hash_key: [u8; 16] = [0x01; 16];
        let tweak = [0x02; 8];

        // Test various lengths: 16, 17, 31, 32, 48, 100
        for len in &[16, 17, 31, 32, 48, 100] {
            let plaintext = vec![0xab; *len];
            let ct = hctr_encrypt(&key, &hash_key, &tweak, &plaintext).unwrap();
            assert_eq!(ct.len(), *len, "length mismatch for input size {len}");

            let pt = hctr_decrypt(&key, &hash_key, &tweak, &ct).unwrap();
            assert_eq!(pt, plaintext);
        }
    }

    #[test]
    fn test_hctr_different_tweaks() {
        let key = hex("000102030405060708090a0b0c0d0e0f");
        let hash_key: [u8; 16] = [0x77; 16];
        let plaintext = vec![0xee; 48];

        let tweak1 = [0x01; 16];
        let tweak2 = [0x02; 16];

        let ct1 = hctr_encrypt(&key, &hash_key, &tweak1, &plaintext).unwrap();
        let ct2 = hctr_encrypt(&key, &hash_key, &tweak2, &plaintext).unwrap();

        assert_ne!(
            ct1, ct2,
            "different tweaks must produce different ciphertexts"
        );
    }

    #[test]
    fn test_hctr_too_short() {
        let key = hex("000102030405060708090a0b0c0d0e0f");
        let hash_key: [u8; 16] = [0; 16];
        let tweak = [0; 16];
        let short = [0u8; 15]; // Less than one block

        assert!(hctr_encrypt(&key, &hash_key, &tweak, &short).is_err());
        assert!(hctr_decrypt(&key, &hash_key, &tweak, &short).is_err());
    }
}
