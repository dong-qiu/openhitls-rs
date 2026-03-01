//! SM4 block cipher implementation.
//!
//! SM4 is a 128-bit block cipher standardized by the Chinese government
//! (GB/T 32907-2016). It uses a 128-bit key and 32 rounds.
//!
//! This implementation uses precomputed T-tables (XBOX/KBOX) that fuse
//! S-box substitution and linear transform into single u32 lookups,
//! yielding ~2× throughput vs per-byte S-box + rotate/XOR.

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// SM4 block size in bytes (128 bits).
pub const SM4_BLOCK_SIZE: usize = 16;

/// SM4 key size in bytes (128 bits).
pub const SM4_KEY_SIZE: usize = 16;

// SM4 S-box (GB/T 32907-2016).
const SBOX: [u8; 256] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

// System parameters FK.
const FK: [u32; 4] = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];

// Constant key CK.
const CK: [u32; 32] = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
];

// --- Compile-time T-table generation ---

/// L(x) = x ^ (x<<<2) ^ (x<<<10) ^ (x<<<18) ^ (x<<<24)
const fn l_const(x: u32) -> u32 {
    x ^ x.rotate_left(2) ^ x.rotate_left(10) ^ x.rotate_left(18) ^ x.rotate_left(24)
}

/// L'(x) = x ^ (x<<<13) ^ (x<<<23)  (key expansion variant)
const fn l_prime_const(x: u32) -> u32 {
    x ^ x.rotate_left(13) ^ x.rotate_left(23)
}

/// Generate XBOX_0: L(SBOX[i]) with SBOX[i] in the low byte position.
const fn gen_xbox0() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = l_const(SBOX[i] as u32);
        i += 1;
    }
    t
}

/// Generate XBOX_k by rotating XBOX_0 entries left by k*8 bits.
const fn gen_xbox_rotated(base: &[u32; 256], shift: u32) -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = base[i].rotate_left(shift);
        i += 1;
    }
    t
}

/// Generate KBOX_0: L'(SBOX[i]) with SBOX[i] in the low byte position.
const fn gen_kbox0() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = l_prime_const(SBOX[i] as u32);
        i += 1;
    }
    t
}

// Precomputed T-tables: XBOX_k[i] = L(SBOX[i]).rotate_left(k*8)
// Each table is 1KB, total 8KB in .rodata.
const XBOX_0: [u32; 256] = gen_xbox0();
const XBOX_1: [u32; 256] = gen_xbox_rotated(&XBOX_0, 8);
const XBOX_2: [u32; 256] = gen_xbox_rotated(&XBOX_0, 16);
const XBOX_3: [u32; 256] = gen_xbox_rotated(&XBOX_0, 24);

// Precomputed T'-tables for key expansion: KBOX_k[i] = L'(SBOX[i]).rotate_left(k*8)
const KBOX_0: [u32; 256] = gen_kbox0();
const KBOX_1: [u32; 256] = gen_xbox_rotated(&KBOX_0, 8);
const KBOX_2: [u32; 256] = gen_xbox_rotated(&KBOX_0, 16);
const KBOX_3: [u32; 256] = gen_xbox_rotated(&KBOX_0, 24);

/// T-table round function: T(A) = XBOX_3[a0] ^ XBOX_2[a1] ^ XBOX_1[a2] ^ XBOX_0[a3]
/// where a = A.to_be_bytes() = [a0, a1, a2, a3].
#[inline(always)]
fn t_table(a: u32) -> u32 {
    let b = a.to_be_bytes();
    XBOX_3[b[0] as usize] ^ XBOX_2[b[1] as usize] ^ XBOX_1[b[2] as usize] ^ XBOX_0[b[3] as usize]
}

/// T'-table key expansion function.
#[inline(always)]
fn t_table_key(a: u32) -> u32 {
    let b = a.to_be_bytes();
    KBOX_3[b[0] as usize] ^ KBOX_2[b[1] as usize] ^ KBOX_1[b[2] as usize] ^ KBOX_0[b[3] as usize]
}

// --- Scalar reference functions (used in tests for cross-validation) ---

#[cfg(test)]
fn tau(a: u32) -> u32 {
    let b = a.to_be_bytes();
    u32::from_be_bytes([
        SBOX[b[0] as usize],
        SBOX[b[1] as usize],
        SBOX[b[2] as usize],
        SBOX[b[3] as usize],
    ])
}

#[cfg(test)]
fn l_transform(b: u32) -> u32 {
    b ^ b.rotate_left(2) ^ b.rotate_left(10) ^ b.rotate_left(18) ^ b.rotate_left(24)
}

#[cfg(test)]
fn l_prime(b: u32) -> u32 {
    b ^ b.rotate_left(13) ^ b.rotate_left(23)
}

#[cfg(test)]
fn t_transform(a: u32) -> u32 {
    l_transform(tau(a))
}

#[cfg(test)]
fn t_prime(a: u32) -> u32 {
    l_prime(tau(a))
}

/// An SM4 key with precomputed round keys.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Sm4Key {
    round_keys_enc: [u32; 32],
    round_keys_dec: [u32; 32],
}

impl Sm4Key {
    /// Create a new SM4 key from 16 raw bytes.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != SM4_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: SM4_KEY_SIZE,
                got: key.len(),
            });
        }

        let mut k = [0u32; 4];
        for i in 0..4 {
            k[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])
                ^ FK[i];
        }

        // Key expansion with KBOX T-tables + 4-way unroll
        let mut rk = [0u32; 32];
        let mut i = 0;
        while i < 32 {
            k[0] ^= t_table_key(k[1] ^ k[2] ^ k[3] ^ CK[i]);
            rk[i] = k[0];
            k[1] ^= t_table_key(k[0] ^ k[2] ^ k[3] ^ CK[i + 1]);
            rk[i + 1] = k[1];
            k[2] ^= t_table_key(k[0] ^ k[1] ^ k[3] ^ CK[i + 2]);
            rk[i + 2] = k[2];
            k[3] ^= t_table_key(k[0] ^ k[1] ^ k[2] ^ CK[i + 3]);
            rk[i + 3] = k[3];
            i += 4;
        }

        // Precompute reversed decrypt keys
        let mut rk_dec = [0u32; 32];
        let mut j = 0;
        while j < 32 {
            rk_dec[j] = rk[31 - j];
            j += 1;
        }

        Ok(Self {
            round_keys_enc: rk,
            round_keys_dec: rk_dec,
        })
    }

    /// Encrypt a single 16-byte block in place.
    pub fn encrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError> {
        if block.len() != SM4_BLOCK_SIZE {
            return Err(CryptoError::InvalidArg("invalid SM4 block size"));
        }
        self.crypt_block(block, &self.round_keys_enc)
    }

    /// Decrypt a single 16-byte block in place.
    pub fn decrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError> {
        if block.len() != SM4_BLOCK_SIZE {
            return Err(CryptoError::InvalidArg("invalid SM4 block size"));
        }
        self.crypt_block(block, &self.round_keys_dec)
    }

    #[inline(always)]
    fn crypt_block(&self, block: &mut [u8], rk: &[u32; 32]) -> Result<(), CryptoError> {
        let mut x0 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
        let mut x1 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
        let mut x2 = u32::from_be_bytes([block[8], block[9], block[10], block[11]]);
        let mut x3 = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);

        // 32 rounds, unrolled 4-way to eliminate rotate_left(1) on the state array
        let mut i = 0;
        while i < 32 {
            x0 ^= t_table(x1 ^ x2 ^ x3 ^ rk[i]);
            x1 ^= t_table(x0 ^ x2 ^ x3 ^ rk[i + 1]);
            x2 ^= t_table(x0 ^ x1 ^ x3 ^ rk[i + 2]);
            x3 ^= t_table(x0 ^ x1 ^ x2 ^ rk[i + 3]);
            i += 4;
        }

        // Output in reverse order: (x3, x2, x1, x0)
        block[0..4].copy_from_slice(&x3.to_be_bytes());
        block[4..8].copy_from_slice(&x2.to_be_bytes());
        block[8..12].copy_from_slice(&x1.to_be_bytes());
        block[12..16].copy_from_slice(&x0.to_be_bytes());
        Ok(())
    }
}

impl crate::provider::BlockCipher for Sm4Key {
    fn block_size(&self) -> usize {
        SM4_BLOCK_SIZE
    }
    fn key_size(&self) -> usize {
        SM4_KEY_SIZE
    }
    fn set_encrypt_key(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        *self = Sm4Key::new(key)?;
        Ok(())
    }
    fn set_decrypt_key(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        self.set_encrypt_key(key)
    }
    fn encrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError> {
        self.encrypt_block(block)
    }
    fn decrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError> {
        self.decrypt_block(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_utils::hex::{hex, to_hex};

    // GB/T 32907-2016 Appendix A
    #[test]
    fn test_sm4_encrypt() {
        let key = hex("0123456789abcdeffedcba9876543210");
        let pt = hex("0123456789abcdeffedcba9876543210");
        let expected = "681edf34d206965e86b3e94f536e4246";

        let cipher = Sm4Key::new(&key).unwrap();
        let mut block = pt;
        cipher.encrypt_block(&mut block).unwrap();
        assert_eq!(to_hex(&block), expected);
    }

    #[test]
    fn test_sm4_decrypt() {
        let key = hex("0123456789abcdeffedcba9876543210");
        let ct = hex("681edf34d206965e86b3e94f536e4246");
        let expected = "0123456789abcdeffedcba9876543210";

        let cipher = Sm4Key::new(&key).unwrap();
        let mut block = ct;
        cipher.decrypt_block(&mut block).unwrap();
        assert_eq!(to_hex(&block), expected);
    }

    #[test]
    fn test_sm4_roundtrip() {
        let key = hex("0123456789abcdeffedcba9876543210");
        let pt = hex("aabbccddeeff00112233445566778899");

        let cipher = Sm4Key::new(&key).unwrap();
        let mut block = pt.clone();
        cipher.encrypt_block(&mut block).unwrap();
        assert_ne!(block, pt.as_slice());
        cipher.decrypt_block(&mut block).unwrap();
        assert_eq!(block, pt.as_slice());
    }

    #[test]
    fn test_sm4_invalid_key_len() {
        assert!(Sm4Key::new(&[0u8; 15]).is_err());
        assert!(Sm4Key::new(&[0u8; 32]).is_err());
    }

    /// GB/T 32907-2016 Appendix A.2: Encrypt block 1,000,000 times.
    #[test]
    fn test_sm4_1million_iterations() {
        let key = hex("0123456789abcdeffedcba9876543210");
        let cipher = Sm4Key::new(&key).unwrap();
        let mut block = hex("0123456789abcdeffedcba9876543210");
        for _ in 0..1_000_000 {
            cipher.encrypt_block(&mut block).unwrap();
        }
        assert_eq!(to_hex(&block), "595298c7c6fd271f0402f804c33d3f66");
    }

    /// Encrypt all-zeros key and plaintext.
    #[test]
    fn test_sm4_all_zeros() {
        let key = [0u8; 16];
        let cipher = Sm4Key::new(&key).unwrap();
        let mut block = [0u8; 16];
        cipher.encrypt_block(&mut block).unwrap();
        // Verify it produces a non-zero ciphertext and decrypts back
        assert_ne!(block, [0u8; 16]);
        let ct = block;
        cipher.decrypt_block(&mut block).unwrap();
        assert_eq!(block, [0u8; 16]);
        // Re-encrypt should match
        cipher.encrypt_block(&mut block).unwrap();
        assert_eq!(block, ct);
    }

    /// Invalid block length should return error.
    #[test]
    fn test_sm4_invalid_block_len() {
        let key = [0u8; 16];
        let cipher = Sm4Key::new(&key).unwrap();
        assert!(cipher.encrypt_block(&mut [0u8; 15]).is_err());
        assert!(cipher.decrypt_block(&mut [0u8; 17]).is_err());
    }

    #[test]
    fn test_sm4_consecutive_encrypt_decrypt_encrypt() {
        let key = [0x01u8; 16];
        let pt = [0x42u8; 16];
        let cipher = Sm4Key::new(&key).unwrap();

        let mut block = pt;
        cipher.encrypt_block(&mut block).unwrap();
        let ct = block;

        cipher.decrypt_block(&mut block).unwrap();
        assert_eq!(block, pt);

        // Re-encrypt must be deterministic
        cipher.encrypt_block(&mut block).unwrap();
        assert_eq!(block, ct);
    }

    #[test]
    fn test_sm4_all_ff_roundtrip() {
        let key = [0xFFu8; 16];
        let pt = [0xFFu8; 16];
        let cipher = Sm4Key::new(&key).unwrap();

        let mut block = pt;
        cipher.encrypt_block(&mut block).unwrap();
        assert_ne!(block, pt, "ciphertext should differ from plaintext");

        cipher.decrypt_block(&mut block).unwrap();
        assert_eq!(block, pt);
    }

    // --- T-table cross-validation tests ---

    /// Verify XBOX_0 matches hand-computed L(SBOX[i]) for all 256 entries.
    #[test]
    fn test_xbox0_spot_check() {
        // SBOX[0] = 0xd6
        let expected_0 = l_transform(0xd6);
        assert_eq!(XBOX_0[0], expected_0);

        // SBOX[0x71] (index 0x71 = 113) = SBOX[113] = 0x21
        let expected_113 = l_transform(SBOX[113] as u32);
        assert_eq!(XBOX_0[113], expected_113);

        // Verify all 256 entries
        for i in 0..256 {
            let expected = l_transform(SBOX[i] as u32);
            assert_eq!(XBOX_0[i], expected, "XBOX_0[{i}] mismatch");
        }
    }

    /// Verify T-table lookup matches scalar t_transform for all 256 single-byte inputs
    /// and a set of random u32 inputs.
    #[test]
    fn test_t_table_matches_scalar() {
        // Single-byte inputs (only low byte nonzero)
        for i in 0u32..256 {
            assert_eq!(t_table(i), t_transform(i), "t_table mismatch for {i:#x}");
        }

        // Multi-byte test vectors
        let test_vals: [u32; 8] = [
            0x0123_4567,
            0x89ab_cdef,
            0xfedc_ba98,
            0x7654_3210,
            0xdead_beef,
            0xcafe_babe,
            0x0000_0000,
            0xffff_ffff,
        ];
        for &v in &test_vals {
            assert_eq!(t_table(v), t_transform(v), "t_table mismatch for {v:#010x}");
        }
    }

    /// Verify T'-table key expansion matches scalar t_prime for all 256 entries.
    #[test]
    fn test_t_table_key_matches_scalar() {
        for i in 0u32..256 {
            assert_eq!(
                t_table_key(i),
                t_prime(i),
                "t_table_key mismatch for {i:#x}"
            );
        }

        let test_vals: [u32; 4] = [0x0123_4567, 0x89ab_cdef, 0xfedc_ba98, 0xffff_ffff];
        for &v in &test_vals {
            assert_eq!(
                t_table_key(v),
                t_prime(v),
                "t_table_key mismatch for {v:#010x}"
            );
        }
    }

    /// Verify precomputed decrypt keys == reversed encrypt keys.
    #[test]
    fn test_decrypt_precomputed_keys() {
        let keys: &[&[u8; 16]] = &[
            &[0u8; 16],
            &[0xFFu8; 16],
            b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10",
        ];
        for key in keys {
            let sm4 = Sm4Key::new(key.as_slice()).unwrap();
            let mut expected_dec = sm4.round_keys_enc;
            expected_dec.reverse();
            assert_eq!(
                sm4.round_keys_dec, expected_dec,
                "decrypt keys mismatch for key {key:?}"
            );
        }
    }

    /// Verify unrolled crypt produces identical results to GB/T vectors
    /// (implicitly tested by existing tests, but this confirms the 4-way unroll
    /// matches the original rotate_left(1) loop semantics).
    #[test]
    fn test_sm4_unrolled_consistency() {
        // Use two different key/plaintext combos to cover different code paths
        let cases: &[(&str, &str, &str)] = &[
            (
                "0123456789abcdeffedcba9876543210",
                "0123456789abcdeffedcba9876543210",
                "681edf34d206965e86b3e94f536e4246",
            ),
            (
                "fedcba98765432100123456789abcdef",
                "000102030405060708090a0b0c0d0e0f",
                "f766678f13f01adeac1b3ea955adb594",
            ),
        ];
        for &(key_hex, pt_hex, ct_hex) in cases {
            let key = hex(key_hex);
            let cipher = Sm4Key::new(&key).unwrap();

            let mut block = hex(pt_hex);
            cipher.encrypt_block(&mut block).unwrap();
            assert_eq!(to_hex(&block), ct_hex, "encrypt mismatch for key={key_hex}");

            cipher.decrypt_block(&mut block).unwrap();
            assert_eq!(to_hex(&block), pt_hex, "decrypt mismatch for key={key_hex}");
        }
    }

    mod proptests {
        use super::super::Sm4Key;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            #[test]
            fn prop_sm4_block_roundtrip(
                key in prop::array::uniform16(any::<u8>()),
                block in prop::array::uniform16(any::<u8>()),
            ) {
                let cipher = Sm4Key::new(&key).unwrap();
                let mut buf = block;
                cipher.encrypt_block(&mut buf).unwrap();
                cipher.decrypt_block(&mut buf).unwrap();
                prop_assert_eq!(buf, block);
            }
        }
    }
}
