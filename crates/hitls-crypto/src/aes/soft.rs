//! Software (S-box table lookup) AES implementation.
//!
//! Pure-Rust fallback used when hardware AES instructions are not available.

use hitls_types::CryptoError;
use zeroize::Zeroize;

use super::AES_BLOCK_SIZE;

// Forward S-box (FIPS 197).
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// Inverse S-box.
const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

// Round constants for key expansion.
const RCON: [u32; 10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000,
];

fn xtime(x: u8) -> u8 {
    ((x as u16) << 1 ^ if x & 0x80 != 0 { 0x1b } else { 0 }) as u8
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    result
}

fn sub_word(w: u32) -> u32 {
    let b = w.to_be_bytes();
    u32::from_be_bytes([
        SBOX[b[0] as usize],
        SBOX[b[1] as usize],
        SBOX[b[2] as usize],
        SBOX[b[3] as usize],
    ])
}

/// Software AES key with precomputed round keys (S-box table-lookup).
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub(crate) struct SoftAesKey {
    key: Vec<u8>,
    round_keys: Vec<u32>,
    rounds: usize,
}

impl SoftAesKey {
    /// Create a new software AES key from raw bytes (16, 24, or 32 bytes).
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let nk = match key.len() {
            16 => 4,
            24 => 6,
            32 => 8,
            _ => return Err(CryptoError::InvalidKey),
        };
        let nr = nk + 6;
        let total_words = 4 * (nr + 1);
        let mut w = vec![0u32; total_words];

        for i in 0..nk {
            w[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
        }

        for i in nk..total_words {
            let mut temp = w[i - 1];
            if i % nk == 0 {
                temp = sub_word(temp.rotate_left(8)) ^ RCON[i / nk - 1];
            } else if nk > 6 && i % nk == 4 {
                temp = sub_word(temp);
            }
            w[i] = w[i - nk] ^ temp;
        }

        Ok(Self {
            key: key.to_vec(),
            round_keys: w,
            rounds: nr,
        })
    }

    /// Encrypt a single 16-byte block in place.
    pub fn encrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError> {
        if block.len() != AES_BLOCK_SIZE {
            return Err(CryptoError::InvalidArg);
        }
        let mut s = [0u8; 16];
        s.copy_from_slice(block);

        add_round_key(&mut s, &self.round_keys, 0);

        for r in 1..self.rounds {
            sub_bytes(&mut s);
            shift_rows(&mut s);
            mix_columns(&mut s);
            add_round_key(&mut s, &self.round_keys, r);
        }

        sub_bytes(&mut s);
        shift_rows(&mut s);
        add_round_key(&mut s, &self.round_keys, self.rounds);

        block.copy_from_slice(&s);
        Ok(())
    }

    /// Decrypt a single 16-byte block in place.
    pub fn decrypt_block(&self, block: &mut [u8]) -> Result<(), CryptoError> {
        if block.len() != AES_BLOCK_SIZE {
            return Err(CryptoError::InvalidArg);
        }
        let mut s = [0u8; 16];
        s.copy_from_slice(block);

        add_round_key(&mut s, &self.round_keys, self.rounds);

        for r in (1..self.rounds).rev() {
            inv_shift_rows(&mut s);
            inv_sub_bytes(&mut s);
            add_round_key(&mut s, &self.round_keys, r);
            inv_mix_columns(&mut s);
        }

        inv_shift_rows(&mut s);
        inv_sub_bytes(&mut s);
        add_round_key(&mut s, &self.round_keys, 0);

        block.copy_from_slice(&s);
        Ok(())
    }

    /// Return the key length in bytes.
    pub fn key_len(&self) -> usize {
        self.key.len()
    }
}

fn sub_bytes(s: &mut [u8; 16]) {
    for b in s.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

fn inv_sub_bytes(s: &mut [u8; 16]) {
    for b in s.iter_mut() {
        *b = INV_SBOX[*b as usize];
    }
}

// State layout (column-major): s[row + 4*col]
fn shift_rows(s: &mut [u8; 16]) {
    // Row 1: shift left by 1
    let t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;
    // Row 2: shift left by 2
    let (t0, t1) = (s[2], s[6]);
    s[2] = s[10];
    s[6] = s[14];
    s[10] = t0;
    s[14] = t1;
    // Row 3: shift left by 3 (= right by 1)
    let t = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t;
}

fn inv_shift_rows(s: &mut [u8; 16]) {
    // Row 1: shift right by 1
    let t = s[13];
    s[13] = s[9];
    s[9] = s[5];
    s[5] = s[1];
    s[1] = t;
    // Row 2: shift right by 2
    let (t0, t1) = (s[10], s[14]);
    s[10] = s[2];
    s[14] = s[6];
    s[2] = t0;
    s[6] = t1;
    // Row 3: shift right by 3 (= left by 1)
    let t = s[3];
    s[3] = s[7];
    s[7] = s[11];
    s[11] = s[15];
    s[15] = t;
}

fn mix_columns(s: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let (a0, a1, a2, a3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
        s[i] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
        s[i + 1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
        s[i + 2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
        s[i + 3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
    }
}

fn inv_mix_columns(s: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let (a0, a1, a2, a3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
        s[i] = gf_mul(a0, 0x0e) ^ gf_mul(a1, 0x0b) ^ gf_mul(a2, 0x0d) ^ gf_mul(a3, 0x09);
        s[i + 1] = gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0e) ^ gf_mul(a2, 0x0b) ^ gf_mul(a3, 0x0d);
        s[i + 2] = gf_mul(a0, 0x0d) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0e) ^ gf_mul(a3, 0x0b);
        s[i + 3] = gf_mul(a0, 0x0b) ^ gf_mul(a1, 0x0d) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0e);
    }
}

fn add_round_key(s: &mut [u8; 16], rk: &[u32], round: usize) {
    for col in 0..4 {
        let w = rk[round * 4 + col].to_be_bytes();
        let i = col * 4;
        s[i] ^= w[0];
        s[i + 1] ^= w[1];
        s[i + 2] ^= w[2];
        s[i + 3] ^= w[3];
    }
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

    /// FIPS 197 Appendix B — AES-128 test vector
    #[test]
    fn aes128_fips197_appendix_b() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let pt = hex("3243f6a8885a308d313198a2e0370734");
        let expected_ct = hex("3925841d02dc09fbdc118597196a0b32");
        let aes = SoftAesKey::new(&key).unwrap();
        let mut block = pt.clone();
        aes.encrypt_block(&mut block).unwrap();
        assert_eq!(block, expected_ct);
    }

    #[test]
    fn aes128_encrypt_decrypt_roundtrip() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let pt = hex("6bc1bee22e409f96e93d7e117393172a");
        let aes = SoftAesKey::new(&key).unwrap();
        let mut block = pt.clone();
        aes.encrypt_block(&mut block).unwrap();
        assert_ne!(block, pt);
        aes.decrypt_block(&mut block).unwrap();
        assert_eq!(block, pt);
    }

    #[test]
    fn aes192_encrypt_decrypt_roundtrip() {
        let key = hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
        let pt = hex("6bc1bee22e409f96e93d7e117393172a");
        let aes = SoftAesKey::new(&key).unwrap();
        assert_eq!(aes.key_len(), 24);
        let mut block = pt.clone();
        aes.encrypt_block(&mut block).unwrap();
        assert_ne!(block, pt);
        aes.decrypt_block(&mut block).unwrap();
        assert_eq!(block, pt);
    }

    /// FIPS 197 Appendix C.3 — AES-256 test vector
    #[test]
    fn aes256_fips197_appendix_c3() {
        let key = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let pt = hex("6bc1bee22e409f96e93d7e117393172a");
        let expected_ct = hex("f3eed1bdb5d2a03c064b5a7e3db181f8");
        let aes = SoftAesKey::new(&key).unwrap();
        assert_eq!(aes.key_len(), 32);
        let mut block = pt.clone();
        aes.encrypt_block(&mut block).unwrap();
        assert_eq!(block, expected_ct);
        // decrypt back
        aes.decrypt_block(&mut block).unwrap();
        assert_eq!(block, pt);
    }

    #[test]
    fn invalid_key_length_rejected() {
        assert!(SoftAesKey::new(&[0u8; 15]).is_err());
        assert!(SoftAesKey::new(&[0u8; 17]).is_err());
        assert!(SoftAesKey::new(&[0u8; 0]).is_err());
        assert!(SoftAesKey::new(&[0u8; 33]).is_err());
    }

    #[test]
    fn invalid_block_size_rejected() {
        let key = [0u8; 16];
        let aes = SoftAesKey::new(&key).unwrap();
        let mut short = [0u8; 8];
        assert!(aes.encrypt_block(&mut short).is_err());
        assert!(aes.decrypt_block(&mut short).is_err());
        let mut long = [0u8; 32];
        assert!(aes.encrypt_block(&mut long).is_err());
        assert!(aes.decrypt_block(&mut long).is_err());
    }

    #[test]
    fn sbox_inv_sbox_are_inverses() {
        for i in 0u8..=255 {
            assert_eq!(INV_SBOX[SBOX[i as usize] as usize], i);
            assert_eq!(SBOX[INV_SBOX[i as usize] as usize], i);
        }
    }

    #[test]
    fn key_len_accessor() {
        assert_eq!(SoftAesKey::new(&[0u8; 16]).unwrap().key_len(), 16);
        assert_eq!(SoftAesKey::new(&[0u8; 24]).unwrap().key_len(), 24);
        assert_eq!(SoftAesKey::new(&[0u8; 32]).unwrap().key_len(), 32);
    }
}
