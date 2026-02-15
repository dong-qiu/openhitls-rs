//! MD5 message digest algorithm.
//!
//! MD5 produces a 128-bit (16-byte) hash value. It is defined in RFC 1321.
//!
//! **Security warning**: MD5 is cryptographically broken and should not be
//! used for security purposes. It is provided only for legacy compatibility
//! and non-security applications (e.g., checksums).

use hitls_types::CryptoError;

/// MD5 output size in bytes.
pub const MD5_OUTPUT_SIZE: usize = 16;

/// MD5 block size in bytes.
pub const MD5_BLOCK_SIZE: usize = 64;

/// MD5 initial hash values (RFC 1321).
const H_MD5: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

/// MD5 per-round shift amounts.
const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, // round 1
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, // round 2
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, // round 3
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, // round 4
];

/// MD5 sin-based constants T[i] = floor(2^32 * abs(sin(i+1))).
const T: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// Message word index schedule per round.
const G_IDX: [usize; 64] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, // round 1: i
    1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, // round 2: (5i+1) mod 16
    5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2, // round 3: (3i+5) mod 16
    0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9, // round 4: (7i) mod 16
];

fn md5_compress(state: &mut [u32; 4], block: &[u8]) {
    // Parse 16 little-endian words
    let mut w = [0u32; 16];
    for i in 0..16 {
        w[i] = u32::from_le_bytes([
            block[4 * i],
            block[4 * i + 1],
            block[4 * i + 2],
            block[4 * i + 3],
        ]);
    }

    let [mut a, mut b, mut c, mut d] = *state;

    for j in 0..64 {
        let f = match j {
            0..=15 => (b & c) | (!b & d),
            16..=31 => (d & b) | (!d & c),
            32..=47 => b ^ c ^ d,
            _ => c ^ (b | !d),
        };

        let temp = a
            .wrapping_add(f)
            .wrapping_add(w[G_IDX[j]])
            .wrapping_add(T[j]);
        a = d;
        d = c;
        c = b;
        b = b.wrapping_add(temp.rotate_left(S[j]));
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

/// MD5 hash context.
#[derive(Clone)]
pub struct Md5 {
    state: [u32; 4],
    count: u64,
    buffer: [u8; MD5_BLOCK_SIZE],
    buffer_len: usize,
}

impl Md5 {
    pub fn new() -> Self {
        Self {
            state: H_MD5,
            count: 0,
            buffer: [0u8; MD5_BLOCK_SIZE],
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
            md5_compress(&mut self.state, &buf);
            offset = need;
            self.buffer_len = 0;
        }

        while offset + 64 <= data.len() {
            md5_compress(&mut self.state, &data[offset..offset + 64]);
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

    pub fn finish(&mut self) -> Result<[u8; MD5_OUTPUT_SIZE], CryptoError> {
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
            md5_compress(&mut self.state, &pad_buf[..64]);
            pad_buf = [0u8; 128];
            pad_len = 0;
        }

        while pad_len < 56 {
            pad_buf[pad_len] = 0;
            pad_len += 1;
        }

        // MD5 uses little-endian length encoding
        pad_buf[56..64].copy_from_slice(&bit_len.to_le_bytes());
        md5_compress(&mut self.state, &pad_buf[..64]);

        // Output in little-endian
        let mut out = [0u8; MD5_OUTPUT_SIZE];
        for (i, &word) in self.state.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
        }
        Ok(out)
    }

    pub fn reset(&mut self) {
        self.state = H_MD5;
        self.count = 0;
        self.buffer = [0u8; MD5_BLOCK_SIZE];
        self.buffer_len = 0;
    }

    pub fn digest(data: &[u8]) -> Result<[u8; MD5_OUTPUT_SIZE], CryptoError> {
        let mut ctx = Self::new();
        ctx.update(data)?;
        ctx.finish()
    }
}

impl crate::provider::Digest for Md5 {
    fn output_size(&self) -> usize {
        MD5_OUTPUT_SIZE
    }
    fn block_size(&self) -> usize {
        MD5_BLOCK_SIZE
    }
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.update(data)
    }
    fn finish(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        let digest = Md5::finish(self)?;
        out[..MD5_OUTPUT_SIZE].copy_from_slice(&digest);
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

    // RFC 1321 test vectors
    #[test]
    fn test_md5_empty() {
        let expected = "d41d8cd98f00b204e9800998ecf8427e";
        let digest = Md5::digest(b"").unwrap();
        assert_eq!(hex(&digest), expected);
    }

    #[test]
    fn test_md5_a() {
        let expected = "0cc175b9c0f1b6a831c399e269772661";
        let digest = Md5::digest(b"a").unwrap();
        assert_eq!(hex(&digest), expected);
    }

    #[test]
    fn test_md5_abc() {
        let expected = "900150983cd24fb0d6963f7d28e17f72";
        let digest = Md5::digest(b"abc").unwrap();
        assert_eq!(hex(&digest), expected);
    }

    #[test]
    fn test_md5_message_digest() {
        let expected = "f96b697d7cb7938d525a2f31aaf161d0";
        let digest = Md5::digest(b"message digest").unwrap();
        assert_eq!(hex(&digest), expected);
    }

    #[test]
    fn test_md5_alphabet() {
        let expected = "c3fcd3d76192e4007dfb496cca67e13b";
        let digest = Md5::digest(b"abcdefghijklmnopqrstuvwxyz").unwrap();
        assert_eq!(hex(&digest), expected);
    }

    #[test]
    fn test_md5_alphanumeric() {
        let expected = "d174ab98d277d9f5a5611c2c9f419d9f";
        let digest =
            Md5::digest(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").unwrap();
        assert_eq!(hex(&digest), expected);
    }

    #[test]
    fn test_md5_numeric() {
        let expected = "57edf4a22be3c955ac49da2e2107b67a";
        let digest = Md5::digest(
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        )
        .unwrap();
        assert_eq!(hex(&digest), expected);
    }

    // Incremental update
    #[test]
    fn test_md5_incremental() {
        let mut ctx = Md5::new();
        ctx.update(b"message").unwrap();
        ctx.update(b" ").unwrap();
        ctx.update(b"digest").unwrap();
        let digest = ctx.finish().unwrap();
        let expected = "f96b697d7cb7938d525a2f31aaf161d0";
        assert_eq!(hex(&digest), expected);
    }

    #[test]
    fn test_md5_reset_reuse() {
        let mut ctx = Md5::new();
        ctx.update(b"abc").unwrap();
        let d1 = ctx.finish().unwrap();

        // Reset and hash same data → same digest
        ctx.reset();
        ctx.update(b"abc").unwrap();
        let d2 = ctx.finish().unwrap();
        assert_eq!(d1, d2);

        // Reset and hash empty → matches one-shot empty digest
        ctx.reset();
        let d_empty = ctx.finish().unwrap();
        let expected_empty = Md5::digest(b"").unwrap();
        assert_eq!(d_empty, expected_empty);
    }

    #[test]
    fn test_md5_block_boundary() {
        // Test at block boundaries: 64, 65, 128, 127 bytes
        let data_64: Vec<u8> = (0u8..64).collect();
        let data_65: Vec<u8> = (0u8..65).collect();
        let data_128: Vec<u8> = (0..128u8).cycle().take(128).collect();
        let data_127: Vec<u8> = (0..127u8).collect();

        let datasets = [&data_64[..], &data_65[..], &data_128[..], &data_127[..]];
        let mut digests = Vec::new();

        for data in &datasets {
            // Incremental matches one-shot
            let mut ctx = Md5::new();
            ctx.update(data).unwrap();
            let incr = ctx.finish().unwrap();
            let oneshot = Md5::digest(data).unwrap();
            assert_eq!(incr, oneshot);
            digests.push(incr);
        }

        // All four digests must differ
        for i in 0..digests.len() {
            for j in (i + 1)..digests.len() {
                assert_ne!(digests[i], digests[j], "digests {i} and {j} should differ");
            }
        }
    }
}
