//! SipHash-2-4 implementation.
//!
//! SipHash is a fast, short-input pseudorandom function family designed
//! by Jean-Philippe Aumasson and Daniel J. Bernstein. Commonly used
//! for hash table protection against hash-flooding DoS attacks.

use hitls_types::CryptoError;
use zeroize::Zeroize;

/// SipHash-2-4 context.
pub struct SipHash {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    /// Buffer for partial word.
    buf: [u8; 8],
    buf_len: usize,
    /// Total message length (mod 256).
    msg_len: usize,
    /// Original key for reset.
    k0: u64,
    k1: u64,
}

impl Drop for SipHash {
    fn drop(&mut self) {
        self.v0.zeroize();
        self.v1.zeroize();
        self.v2.zeroize();
        self.v3.zeroize();
        self.buf.zeroize();
        self.k0.zeroize();
        self.k1.zeroize();
    }
}

#[inline]
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
}

impl SipHash {
    /// Create a new SipHash-2-4 instance with a 16-byte key.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidArg(""));
        }

        let k0 = u64::from_le_bytes(key[..8].try_into().expect("key length validated above"));
        let k1 = u64::from_le_bytes(key[8..].try_into().expect("key length validated above"));

        Ok(SipHash {
            v0: k0 ^ 0x736f6d6570736575,
            v1: k1 ^ 0x646f72616e646f6d,
            v2: k0 ^ 0x6c7967656e657261,
            v3: k1 ^ 0x7465646279746573,
            buf: [0; 8],
            buf_len: 0,
            msg_len: 0,
            k0,
            k1,
        })
    }

    fn process_word(&mut self, m: u64) {
        self.v3 ^= m;
        // 2 rounds (SipHash-2-4)
        sip_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        sip_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        self.v0 ^= m;
    }

    /// Feed data into the SipHash computation.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let mut pos = 0;
        self.msg_len += data.len();

        // Fill buffer first
        if self.buf_len > 0 {
            let want = 8 - self.buf_len;
            if data.len() < want {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return Ok(());
            }
            self.buf[self.buf_len..8].copy_from_slice(&data[..want]);
            let m = u64::from_le_bytes(self.buf);
            self.process_word(m);
            self.buf_len = 0;
            pos = want;
        }

        // Process 8-byte words
        while pos + 8 <= data.len() {
            let m = u64::from_le_bytes(data[pos..pos + 8].try_into().expect("exact 8-byte slice"));
            self.process_word(m);
            pos += 8;
        }

        // Buffer remainder
        if pos < data.len() {
            let remaining = data.len() - pos;
            self.buf[..remaining].copy_from_slice(&data[pos..]);
            self.buf_len = remaining;
        }

        Ok(())
    }

    /// Finalize and return the 64-bit SipHash value.
    pub fn finish(&self) -> Result<u64, CryptoError> {
        let mut v0 = self.v0;
        let mut v1 = self.v1;
        let mut v2 = self.v2;
        let mut v3 = self.v3;

        // Build last word: remaining bytes + length byte in MSB
        let mut last = [0u8; 8];
        last[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
        last[7] = (self.msg_len & 0xff) as u8;
        let m = u64::from_le_bytes(last);

        v3 ^= m;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;

        // Finalization: 4 rounds
        v2 ^= 0xff;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);

        Ok(v0 ^ v1 ^ v2 ^ v3)
    }

    /// Reset the state for a new computation with the same key.
    pub fn reset(&mut self) {
        self.v0 = self.k0 ^ 0x736f6d6570736575;
        self.v1 = self.k1 ^ 0x646f72616e646f6d;
        self.v2 = self.k0 ^ 0x6c7967656e657261;
        self.v3 = self.k1 ^ 0x7465646279746573;
        self.buf = [0; 8];
        self.buf_len = 0;
        self.msg_len = 0;
    }

    /// One-shot SipHash computation.
    pub fn hash(key: &[u8], data: &[u8]) -> Result<u64, CryptoError> {
        let mut ctx = Self::new(key)?;
        ctx.update(data)?;
        ctx.finish()
    }
}

// ---------------------------------------------------------------------------
// SipHash-2-4-128 — same core permutation, 128-bit output.
//
// Per Aumasson & Bernstein (the original SipHash paper, §A) the 128-bit
// variant differs from the 64-bit one in three places only:
//
//  1. Initialization: `v1 ^= 0xee` (in addition to the `k1` XOR).
//  2. Finalization XOR: `v2 ^= 0xee` (instead of `0xff`).
//  3. After the standard 4 finalization rounds, the first 8 bytes of
//     output are `v0 ^ v1 ^ v2 ^ v3` (little-endian); then `v1 ^= 0xdd`
//     and another 4 rounds produce the second 8 bytes of output.
//
// The message-processing core (`sip_round`, `process_word`, `update`'s
// 8-byte feed loop) is bit-identical to the 64-bit variant. Rather than
// share state (which would couple two distinct keyed PRFs), the 128-bit
// path lives in its own struct here.
// ---------------------------------------------------------------------------

/// SipHash-2-4-128 context (16-byte output).
pub struct SipHash128 {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    buf: [u8; 8],
    buf_len: usize,
    msg_len: usize,
    k0: u64,
    k1: u64,
}

impl Drop for SipHash128 {
    fn drop(&mut self) {
        self.v0.zeroize();
        self.v1.zeroize();
        self.v2.zeroize();
        self.v3.zeroize();
        self.buf.zeroize();
        self.k0.zeroize();
        self.k1.zeroize();
    }
}

impl SipHash128 {
    /// Create a new SipHash-2-4-128 instance with a 16-byte key.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidArg(""));
        }
        let k0 = u64::from_le_bytes(key[..8].try_into().expect("key length validated above"));
        let k1 = u64::from_le_bytes(key[8..].try_into().expect("key length validated above"));

        // v1 picks up an extra 0xee XOR vs the 64-bit variant.
        Ok(SipHash128 {
            v0: k0 ^ 0x736f6d6570736575,
            v1: k1 ^ 0x646f72616e646f6d ^ 0xee,
            v2: k0 ^ 0x6c7967656e657261,
            v3: k1 ^ 0x7465646279746573,
            buf: [0; 8],
            buf_len: 0,
            msg_len: 0,
            k0,
            k1,
        })
    }

    fn process_word(&mut self, m: u64) {
        self.v3 ^= m;
        sip_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        sip_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        self.v0 ^= m;
    }

    /// Feed data into the SipHash-128 computation.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let mut pos = 0;
        self.msg_len += data.len();

        if self.buf_len > 0 {
            let want = 8 - self.buf_len;
            if data.len() < want {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return Ok(());
            }
            self.buf[self.buf_len..8].copy_from_slice(&data[..want]);
            let m = u64::from_le_bytes(self.buf);
            self.process_word(m);
            self.buf_len = 0;
            pos = want;
        }

        while pos + 8 <= data.len() {
            let m = u64::from_le_bytes(data[pos..pos + 8].try_into().expect("exact 8-byte slice"));
            self.process_word(m);
            pos += 8;
        }

        if pos < data.len() {
            let remaining = data.len() - pos;
            self.buf[..remaining].copy_from_slice(&data[pos..]);
            self.buf_len = remaining;
        }

        Ok(())
    }

    /// Finalize and return the 16-byte SipHash-128 value.
    pub fn finish(&self) -> Result<[u8; 16], CryptoError> {
        let mut v0 = self.v0;
        let mut v1 = self.v1;
        let mut v2 = self.v2;
        let mut v3 = self.v3;

        let mut last = [0u8; 8];
        last[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
        last[7] = (self.msg_len & 0xff) as u8;
        let m = u64::from_le_bytes(last);

        v3 ^= m;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;

        // First 8 bytes: v2 ^= 0xee, 4 rounds, output v0^v1^v2^v3.
        v2 ^= 0xee;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        let lo = v0 ^ v1 ^ v2 ^ v3;

        // Next 8 bytes: v1 ^= 0xdd, 4 more rounds, output v0^v1^v2^v3.
        v1 ^= 0xdd;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        let hi = v0 ^ v1 ^ v2 ^ v3;

        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&lo.to_le_bytes());
        out[8..].copy_from_slice(&hi.to_le_bytes());
        Ok(out)
    }

    /// Reset the state for a new computation with the same key.
    pub fn reset(&mut self) {
        self.v0 = self.k0 ^ 0x736f6d6570736575;
        self.v1 = self.k1 ^ 0x646f72616e646f6d ^ 0xee;
        self.v2 = self.k0 ^ 0x6c7967656e657261;
        self.v3 = self.k1 ^ 0x7465646279746573;
        self.buf = [0; 8];
        self.buf_len = 0;
        self.msg_len = 0;
    }

    /// One-shot SipHash-128 computation.
    pub fn hash(key: &[u8], data: &[u8]) -> Result<[u8; 16], CryptoError> {
        let mut ctx = Self::new(key)?;
        ctx.update(data)?;
        ctx.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference test vectors from the SipHash paper (Appendix A).
    // Key: 00 01 02 ... 0f
    // Input: 00 (empty), 00, 00 01, 00 01 02, ... up to 00 01 ... 0e
    #[test]
    fn test_siphash_reference_vectors() {
        let key: Vec<u8> = (0..16).collect();

        // Expected outputs for inputs of length 0..15
        let expected: [u64; 16] = [
            0x726fdb47dd0e0e31,
            0x74f839c593dc67fd,
            0x0d6c8009d9a94f5a,
            0x85676696d7fb7e2d,
            0xcf2794e0277187b7,
            0x18765564cd99a68d,
            0xcbc9466e58fee3ce,
            0xab0200f58b01d137,
            0x93f5f5799a932462,
            0x9e0082df0ba9e4b0,
            0x7a5dbbc594ddb9f3,
            0xf4b32f46226bada7,
            0x751e8fbc860ee5fb,
            0x14ea5627c0843d90,
            0xf723ca908e7af2ee,
            0xa129ca6149be45e5,
        ];

        for (i, &exp) in expected.iter().enumerate() {
            let input: Vec<u8> = (0..i as u8).collect();
            let result = SipHash::hash(&key, &input).unwrap();
            assert_eq!(
                result, exp,
                "SipHash mismatch for input length {i}: got {result:#018x}, expected {exp:#018x}"
            );
        }
    }

    #[test]
    fn test_siphash_incremental() {
        let key: Vec<u8> = (0..16).collect();
        let data: Vec<u8> = (0..15).collect();

        // One-shot
        let oneshot = SipHash::hash(&key, &data).unwrap();

        // Incremental (split at various points)
        for split in 1..data.len() {
            let mut ctx = SipHash::new(&key).unwrap();
            ctx.update(&data[..split]).unwrap();
            ctx.update(&data[split..]).unwrap();
            let incremental = ctx.finish().unwrap();
            assert_eq!(oneshot, incremental, "mismatch for split at {split}");
        }
    }

    #[test]
    fn test_siphash_reset() {
        let key: Vec<u8> = (0..16).collect();
        let data = b"hello";

        let mut ctx = SipHash::new(&key).unwrap();
        ctx.update(data).unwrap();
        let hash1 = ctx.finish().unwrap();

        ctx.reset();
        ctx.update(data).unwrap();
        let hash2 = ctx.finish().unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_siphash_invalid_key_length() {
        // Key must be exactly 16 bytes
        for len in [0, 8, 15, 17, 32] {
            let key = vec![0u8; len];
            assert!(
                SipHash::new(&key).is_err(),
                "should reject key of length {len}"
            );
        }
    }

    #[test]
    fn test_siphash_empty_input() {
        let key: Vec<u8> = (0..16).collect();
        let result = SipHash::hash(&key, b"").unwrap();
        // From the reference vectors (length-0 entry)
        assert_eq!(result, 0x726fdb47dd0e0e31);
    }

    #[test]
    fn test_siphash_long_input_split() {
        let key: Vec<u8> = (0..16).collect();
        let data: Vec<u8> = (0..=255).cycle().take(1024).collect();

        // One-shot
        let oneshot = SipHash::hash(&key, &data).unwrap();

        // Split at 511 (non-word-aligned boundary)
        let mut ctx = SipHash::new(&key).unwrap();
        ctx.update(&data[..511]).unwrap();
        ctx.update(&data[511..]).unwrap();
        let split = ctx.finish().unwrap();

        assert_eq!(oneshot, split);
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(20))]

            #[test]
            fn prop_siphash_incremental_equiv(
                data in prop::collection::vec(any::<u8>(), 0..256),
                split in 0usize..256,
            ) {
                let key: Vec<u8> = (0..16).collect();
                let split = split.min(data.len());

                let oneshot = SipHash::hash(&key, &data).unwrap();

                let mut ctx = SipHash::new(&key).unwrap();
                ctx.update(&data[..split]).unwrap();
                ctx.update(&data[split..]).unwrap();
                let incremental = ctx.finish().unwrap();

                prop_assert_eq!(oneshot, incremental);
            }

            #[test]
            fn prop_siphash_different_keys_different_hashes(
                data in prop::collection::vec(any::<u8>(), 1..64),
            ) {
                let key1 = [0u8; 16];
                let key2 = [1u8; 16];
                let h1 = SipHash::hash(&key1, &data).unwrap();
                let h2 = SipHash::hash(&key2, &data).unwrap();
                prop_assert_ne!(h1, h2);
            }
        }
    }

    // -----------------------------------------------------------------------
    // SipHash-128 tests.
    // -----------------------------------------------------------------------

    /// First 5 reference vectors from the SipHash author's
    /// `vectors_sip128.h` (Aumasson & Bernstein; <https://github.com/veorq/SipHash>).
    /// Key = `00 01 02 … 0f`; input length grows 0, 1, 2, 3, 4.
    #[test]
    fn test_siphash128_reference_vectors() {
        let key: Vec<u8> = (0..16).collect();
        let expected: [[u8; 16]; 5] = [
            [
                0xa3, 0x81, 0x7f, 0x04, 0xba, 0x25, 0xa8, 0xe6, 0x6d, 0xf6, 0x72, 0x14, 0xc7, 0x55,
                0x02, 0x93,
            ],
            [
                0xda, 0x87, 0xc1, 0xd8, 0x6b, 0x99, 0xaf, 0x44, 0x34, 0x76, 0x59, 0x11, 0x9b, 0x22,
                0xfc, 0x45,
            ],
            [
                0x81, 0x77, 0x22, 0x8d, 0xa4, 0xa4, 0x5d, 0xc7, 0xfc, 0xa3, 0x8b, 0xde, 0xf6, 0x0a,
                0xff, 0xe4,
            ],
            [
                0x9c, 0x70, 0xb6, 0x0c, 0x52, 0x67, 0xa9, 0x4e, 0x5f, 0x33, 0xb6, 0xb0, 0x29, 0x85,
                0xed, 0x51,
            ],
            [
                0xf8, 0x81, 0x64, 0xc1, 0x2d, 0x9c, 0x8f, 0xaf, 0x7d, 0x0f, 0x6e, 0x7c, 0x7b, 0xcd,
                0x55, 0x79,
            ],
        ];
        for (i, exp) in expected.iter().enumerate() {
            let input: Vec<u8> = (0..i as u8).collect();
            let result = SipHash128::hash(&key, &input).unwrap();
            assert_eq!(&result, exp, "SipHash-128 mismatch for input length {i}");
        }
    }

    /// openHiTLS C SDV `SDV_CRYPT_EAL_SIPHASH_SAMEADDR_FUNC_TC001` row with
    /// `CRYPT_MAC_SIPHASH128` — pinned here as a regression-quality lib KAT
    /// so the migration emitter can route the row byte-exactly.
    #[test]
    fn test_siphash128_openhitls_sdv_vector() {
        let key = [0xffu8; 16];
        let data = [
            0xc0, 0x38, 0x3b, 0x4d, 0x9c, 0x7f, 0x00, 0x00, 0xc0, 0xe9, 0xa2, 0x01, 0x00, 0x00,
            0x00, 0x00, 0xe0, 0x83, 0xf8, 0x35,
        ];
        let expected = [
            0x97, 0x13, 0x24, 0xc1, 0x0b, 0x6f, 0x31, 0x27, 0x1e, 0xb4, 0x2d, 0x5b, 0x12, 0xc9,
            0xea, 0x62,
        ];
        let mac = SipHash128::hash(&key, &data).unwrap();
        assert_eq!(mac, expected);
    }

    #[test]
    fn test_siphash128_incremental_equiv() {
        let key: Vec<u8> = (0..16).collect();
        let data: Vec<u8> = (0..15).collect();
        let oneshot = SipHash128::hash(&key, &data).unwrap();
        for split in 1..data.len() {
            let mut ctx = SipHash128::new(&key).unwrap();
            ctx.update(&data[..split]).unwrap();
            ctx.update(&data[split..]).unwrap();
            let incremental = ctx.finish().unwrap();
            assert_eq!(oneshot, incremental, "split={split}");
        }
    }

    #[test]
    fn test_siphash128_reset() {
        let key: Vec<u8> = (0..16).collect();
        let mut ctx = SipHash128::new(&key).unwrap();
        ctx.update(b"hello").unwrap();
        let h1 = ctx.finish().unwrap();
        ctx.reset();
        ctx.update(b"hello").unwrap();
        let h2 = ctx.finish().unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_siphash128_rejects_wrong_key_length() {
        for len in [0, 8, 15, 17, 32] {
            let key = vec![0u8; len];
            assert!(SipHash128::new(&key).is_err(), "len={len}");
        }
    }

    /// SipHash-64 and SipHash-128 use different initialization, so their
    /// first 8 bytes of output must differ for the same (key, message).
    #[test]
    fn test_siphash128_diverges_from_64() {
        let key: Vec<u8> = (0..16).collect();
        let data = b"hello";
        let h64 = SipHash::hash(&key, data).unwrap();
        let h128 = SipHash128::hash(&key, data).unwrap();
        assert_ne!(h64.to_le_bytes()[..], h128[..8]);
    }
}
