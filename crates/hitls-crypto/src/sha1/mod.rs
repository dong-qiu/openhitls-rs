//! SHA-1 message digest algorithm.
//!
//! SHA-1 produces a 160-bit (20-byte) hash value. It is defined in FIPS 180-4.
//!
//! **Security warning**: SHA-1 is considered cryptographically weak due to
//! demonstrated collision attacks. It is provided for legacy compatibility
//! and should not be used for new security applications.

use hitls_types::CryptoError;

/// SHA-1 output size in bytes.
pub const SHA1_OUTPUT_SIZE: usize = 20;

/// SHA-1 block size in bytes.
pub const SHA1_BLOCK_SIZE: usize = 64;

/// SHA-1 initial hash values (FIPS 180-4 Section 5.3.1).
const H_SHA1: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

/// SHA-1 round constants.
const K_SHA1: [u32; 4] = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

fn sha1_compress(state: &mut [u32; 5], block: &[u8]) {
    let mut w = [0u32; 80];

    // Parse 16 big-endian words
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[4 * i],
            block[4 * i + 1],
            block[4 * i + 2],
            block[4 * i + 3],
        ]);
    }

    // Message expansion
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let [mut a, mut b, mut c, mut d, mut e] = *state;

    for (j, &wj) in w.iter().enumerate() {
        let (f, k) = match j {
            0..=19 => ((b & c) | (!b & d), K_SHA1[0]),
            20..=39 => (b ^ c ^ d, K_SHA1[1]),
            40..=59 => ((b & c) | (b & d) | (c & d), K_SHA1[2]),
            _ => (b ^ c ^ d, K_SHA1[3]),
        };

        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(wj);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

/// SHA-1 hash context.
#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    count: u64,
    buffer: [u8; SHA1_BLOCK_SIZE],
    buffer_len: usize,
}

impl Sha1 {
    pub fn new() -> Self {
        Self {
            state: H_SHA1,
            count: 0,
            buffer: [0u8; SHA1_BLOCK_SIZE],
            buffer_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let mut offset = 0;
        if self.buffer_len > 0 {
            let need = 64 - self.buffer_len;
            if data.len() < need {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                self.count += data.len() as u64;
                return Ok(());
            }
            self.buffer[self.buffer_len..64].copy_from_slice(&data[..need]);
            let buf = self.buffer;
            sha1_compress(&mut self.state, &buf);
            offset = need;
            self.buffer_len = 0;
        }

        while offset + 64 <= data.len() {
            sha1_compress(&mut self.state, &data[offset..offset + 64]);
            offset += 64;
        }

        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
        self.count += data.len() as u64;
        Ok(())
    }

    pub fn finish(&mut self) -> Result<[u8; SHA1_OUTPUT_SIZE], CryptoError> {
        let bit_len = self.count * 8;
        let mut pad_buf = [0u8; 128];
        let mut pad_len = self.buffer_len;
        pad_buf[..pad_len].copy_from_slice(&self.buffer[..self.buffer_len]);

        pad_buf[pad_len] = 0x80;
        pad_len += 1;

        if pad_len > 56 {
            while pad_len < 64 {
                pad_buf[pad_len] = 0;
                pad_len += 1;
            }
            sha1_compress(&mut self.state, &pad_buf[..64]);
            pad_buf = [0u8; 128];
            pad_len = 0;
        }

        while pad_len < 56 {
            pad_buf[pad_len] = 0;
            pad_len += 1;
        }

        pad_buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        sha1_compress(&mut self.state, &pad_buf[..64]);

        let mut out = [0u8; SHA1_OUTPUT_SIZE];
        for (i, &word) in self.state.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
        }
        Ok(out)
    }

    pub fn reset(&mut self) {
        self.state = H_SHA1;
        self.count = 0;
        self.buffer = [0u8; SHA1_BLOCK_SIZE];
        self.buffer_len = 0;
    }

    pub fn digest(data: &[u8]) -> Result<[u8; SHA1_OUTPUT_SIZE], CryptoError> {
        let mut ctx = Self::new();
        ctx.update(data)?;
        ctx.finish()
    }
}

impl crate::provider::Digest for Sha1 {
    fn output_size(&self) -> usize {
        SHA1_OUTPUT_SIZE
    }
    fn block_size(&self) -> usize {
        SHA1_BLOCK_SIZE
    }
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.update(data)
    }
    fn finish(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        let digest = Sha1::finish(self)?;
        out[..SHA1_OUTPUT_SIZE].copy_from_slice(&digest);
        Ok(())
    }
    fn reset(&mut self) {
        self.reset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // RFC 3174 test vector: "abc"
    #[test]
    fn test_sha1_abc() {
        let expected = "a9993e364706816aba3e25717850c26c9cd0d89d";
        let digest = Sha1::digest(b"abc").unwrap();
        assert_eq!(hex(&digest), expected);
    }

    // RFC 3174 test vector: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    #[test]
    fn test_sha1_two_blocks() {
        let expected = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let digest = Sha1::digest(input).unwrap();
        assert_eq!(hex(&digest), expected);
    }

    #[test]
    fn test_sha1_empty() {
        let expected = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        let digest = Sha1::digest(b"").unwrap();
        assert_eq!(hex(&digest), expected);
    }

    // Incremental update test
    #[test]
    fn test_sha1_incremental() {
        let mut ctx = Sha1::new();
        ctx.update(b"abc").unwrap();
        ctx.update(b"dbcdecdefdefg").unwrap();
        ctx.update(b"efghfghighijhijkijkljklmklmnlmnomnopnopq")
            .unwrap();
        let digest = ctx.finish().unwrap();
        let expected = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";
        assert_eq!(hex(&digest), expected);
    }

    #[test]
    fn test_sha1_reset_and_reuse() {
        let mut ctx = Sha1::new();
        ctx.update(b"abc").unwrap();
        let d1 = ctx.finish().unwrap();
        assert_eq!(hex(&d1), "a9993e364706816aba3e25717850c26c9cd0d89d");

        // Reset and hash "abc" again — should get same result
        ctx.reset();
        ctx.update(b"abc").unwrap();
        let d2 = ctx.finish().unwrap();
        assert_eq!(d1, d2);

        // Reset and hash empty string
        ctx.reset();
        let d3 = ctx.finish().unwrap();
        assert_eq!(hex(&d3), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    // NIST vector: SHA-1 of one million "a" characters
    #[test]
    #[ignore] // slow (~0.3s)
    fn test_sha1_million_a() {
        let mut ctx = Sha1::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            ctx.update(&chunk).unwrap();
        }
        let digest = ctx.finish().unwrap();
        assert_eq!(hex(&digest), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    }
}
