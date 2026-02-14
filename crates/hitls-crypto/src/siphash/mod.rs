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
            return Err(CryptoError::InvalidArg);
        }

        let k0 = u64::from_le_bytes(key[..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(key[8..].try_into().unwrap());

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
            let m = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
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
}
