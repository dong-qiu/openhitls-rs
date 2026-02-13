//! HCTR mode — a length-preserving tweakable wide-block cipher.
//!
//! HCTR combines AES-ECB, AES-CTR, and a GF(2^128) universal hash (UHash)
//! to provide a tweakable enciphering scheme. The plaintext must be at
//! least 16 bytes. Output length always equals input length.

use crate::aes::{AesKey, AES_BLOCK_SIZE};
use hitls_types::CryptoError;

const BLOCK: usize = AES_BLOCK_SIZE; // 16

// ── GF(2^128) multiplication (MSB-first, reduction x^128 + x^7 + x^2 + x + 1) ──

/// Multiply two 128-bit elements in GF(2^128).
///
/// Uses the schoolbook algorithm: iterate over bits of `b` from MSB to LSB,
/// accumulate `a` into the result when the current bit is 1, then right-shift
/// `a` and reduce when the LSB was set (XOR with 0xE1 in the top byte).
pub fn gf128_mul(a: &[u8; BLOCK], b: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut result = [0u8; BLOCK];
    let mut z = *a;

    for i in 0..128 {
        // Check bit i of b (MSB-first: bit 0 = bit 7 of byte 0)
        if (b[i / 8] >> (7 - (i % 8))) & 1 == 1 {
            xor_block(&mut result, &z);
        }
        // Right-shift z by 1 and reduce
        let lsb_set = z[15] & 1;
        for j in (1..BLOCK).rev() {
            z[j] = (z[j] >> 1) | (z[j - 1] << 7);
        }
        z[0] >>= 1;
        if lsb_set != 0 {
            z[0] ^= 0xE1;
        }
    }
    result
}

// ── Universal hash ──

/// UHash(K2, data, tweak) → 16-byte hash.
///
/// Concatenates `data || tweak`, pads to 16-byte blocks, evaluates the
/// polynomial `sum(block_i * K^(m-i+1)) + len_block * K` over GF(2^128).
fn uhash(k2: &[u8; BLOCK], data: &[u8], tweak: &[u8]) -> [u8; BLOCK] {
    // Build effective data = data || tweak
    let effective_len = data.len() + tweak.len();
    let mut all_data = Vec::with_capacity(effective_len);
    all_data.extend_from_slice(data);
    all_data.extend_from_slice(tweak);

    // Number of 16-byte blocks (ceiling)
    let m = if effective_len == 0 {
        0
    } else {
        effective_len.div_ceil(BLOCK)
    };

    // Pre-compute K powers: K^2, K^3, ..., K^(m+1)
    let mut k_powers: Vec<[u8; BLOCK]> = Vec::with_capacity(m);
    if m > 0 {
        // k_powers[0] = K^2
        k_powers.push(gf128_mul(k2, k2));
        for i in 1..m {
            let prev = k_powers[i - 1];
            k_powers.push(gf128_mul(&prev, k2));
        }
    }

    // Polynomial evaluation: sum(block_i * K^(m - i + 1))
    // block_i uses k_powers[m-1-i] = K^(m-i+1)
    let mut hash_val = [0u8; BLOCK];
    for i in 0..m {
        let offset = i * BLOCK;
        let chunk_len = std::cmp::min(BLOCK, effective_len - offset);
        let mut block = [0u8; BLOCK];
        block[..chunk_len].copy_from_slice(&all_data[offset..offset + chunk_len]);

        let term = gf128_mul(&block, &k_powers[m - 1 - i]);
        xor_block(&mut hash_val, &term);
    }

    // Length block: 128-bit BE encoding of total bit length
    let total_bits = (effective_len as u64) * 8;
    let mut len_block = [0u8; BLOCK];
    len_block[8..16].copy_from_slice(&total_bits.to_be_bytes());

    let len_term = gf128_mul(&len_block, k2);
    xor_block(&mut hash_val, &len_term);

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
        return Err(CryptoError::InvalidArg);
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
        return Err(CryptoError::InvalidArg);
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

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

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
