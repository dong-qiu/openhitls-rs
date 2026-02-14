//! SM3 cryptographic hash algorithm (GB/T 32905-2016).
//!
//! SM3 is a 256-bit cryptographic hash function standardized by the Chinese
//! government. It is structurally similar to SHA-256 and is used with SM2/SM4.

use hitls_types::CryptoError;

/// SM3 output size in bytes.
pub const SM3_OUTPUT_SIZE: usize = 32;

/// SM3 block size in bytes.
pub const SM3_BLOCK_SIZE: usize = 64;

/// SM3 initial hash values.
const IV: [u32; 8] = [
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
];

/// SM3 round constant T_j.
const fn t_j(j: usize) -> u32 {
    if j < 16 {
        0x79cc4519
    } else {
        0x7a879d8a
    }
}

fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

fn ff(x: u32, y: u32, z: u32, j: usize) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (x & z) | (y & z)
    }
}

fn gg(x: u32, y: u32, z: u32, j: usize) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (!x & z)
    }
}

fn sm3_compress(state: &mut [u32; 8], block: &[u8]) {
    // Parse 16 words (big-endian)
    let mut w = [0u32; 68];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[4 * i],
            block[4 * i + 1],
            block[4 * i + 2],
            block[4 * i + 3],
        ]);
    }

    // Message expansion
    for i in 16..68 {
        w[i] = p1(w[i - 16] ^ w[i - 9] ^ w[i - 3].rotate_left(15))
            ^ w[i - 13].rotate_left(7)
            ^ w[i - 6];
    }

    // W' array
    let mut wp = [0u32; 64];
    for i in 0..64 {
        wp[i] = w[i] ^ w[i + 4];
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for j in 0..64 {
        let ss1 = (a
            .rotate_left(12)
            .wrapping_add(e)
            .wrapping_add(t_j(j).rotate_left(j as u32 % 32)))
        .rotate_left(7);
        let ss2 = ss1 ^ a.rotate_left(12);
        let tt1 = ff(a, b, c, j)
            .wrapping_add(d)
            .wrapping_add(ss2)
            .wrapping_add(wp[j]);
        let tt2 = gg(e, f, g, j)
            .wrapping_add(h)
            .wrapping_add(ss1)
            .wrapping_add(w[j]);

        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
    }

    state[0] ^= a;
    state[1] ^= b;
    state[2] ^= c;
    state[3] ^= d;
    state[4] ^= e;
    state[5] ^= f;
    state[6] ^= g;
    state[7] ^= h;
}

/// SM3 hash context.
#[derive(Clone)]
pub struct Sm3 {
    state: [u32; 8],
    count: u64,
    buffer: [u8; SM3_BLOCK_SIZE],
    buffer_len: usize,
}

impl Sm3 {
    pub fn new() -> Self {
        Self {
            state: IV,
            count: 0,
            buffer: [0u8; SM3_BLOCK_SIZE],
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
            sm3_compress(&mut self.state, &buf);
            offset = need;
            self.buffer_len = 0;
        }

        while offset + 64 <= data.len() {
            sm3_compress(&mut self.state, &data[offset..offset + 64]);
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

    pub fn finish(&mut self) -> Result<[u8; SM3_OUTPUT_SIZE], CryptoError> {
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
            sm3_compress(&mut self.state, &pad_buf[..64]);
            pad_buf = [0u8; 128];
            pad_len = 0;
        }

        while pad_len < 56 {
            pad_buf[pad_len] = 0;
            pad_len += 1;
        }

        pad_buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        sm3_compress(&mut self.state, &pad_buf[..64]);

        let mut out = [0u8; SM3_OUTPUT_SIZE];
        for (i, &word) in self.state.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
        }
        Ok(out)
    }

    pub fn reset(&mut self) {
        self.state = IV;
        self.count = 0;
        self.buffer = [0u8; SM3_BLOCK_SIZE];
        self.buffer_len = 0;
    }

    pub fn digest(data: &[u8]) -> Result<[u8; SM3_OUTPUT_SIZE], CryptoError> {
        let mut ctx = Self::new();
        ctx.update(data)?;
        ctx.finish()
    }
}

impl crate::provider::Digest for Sm3 {
    fn output_size(&self) -> usize {
        SM3_OUTPUT_SIZE
    }
    fn block_size(&self) -> usize {
        SM3_BLOCK_SIZE
    }
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.update(data)
    }
    fn finish(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        let digest = Sm3::finish(self)?;
        out[..SM3_OUTPUT_SIZE].copy_from_slice(&digest);
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

    // GB/T 32905-2016 test vector 1: "abc"
    #[test]
    fn test_sm3_abc() {
        let expected = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
        let digest = Sm3::digest(b"abc").unwrap();
        assert_eq!(hex(&digest), expected);
    }

    // GB/T 32905-2016 test vector 2: "abcd" repeated 16 times (64 bytes)
    #[test]
    fn test_sm3_64bytes() {
        let expected = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732";
        let input = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
        let digest = Sm3::digest(input).unwrap();
        assert_eq!(hex(&digest), expected);
    }

    #[test]
    fn test_sm3_empty() {
        let expected = "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b";
        let digest = Sm3::digest(b"").unwrap();
        assert_eq!(hex(&digest), expected);
    }

    /// Incremental update should produce the same hash as one-shot digest.
    #[test]
    fn test_sm3_incremental() {
        let mut ctx = Sm3::new();
        ctx.update(b"a").unwrap();
        ctx.update(b"b").unwrap();
        ctx.update(b"c").unwrap();
        let incremental = ctx.finish().unwrap();

        let one_shot = Sm3::digest(b"abc").unwrap();
        assert_eq!(incremental, one_shot);
    }

    /// GB/T 32905-2016 test: Hash 1,000,000 × 'a'.
    #[test]
    #[ignore] // slow (~2s)
    fn test_sm3_1million_a() {
        let expected = "c8aaf89429554029e231941a2acc0ad61ff2a5acd8fadd25847a3a732b3b02c3";
        let mut ctx = Sm3::new();
        // Feed in chunks for efficiency
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            ctx.update(&chunk).unwrap();
        }
        let digest = ctx.finish().unwrap();
        assert_eq!(hex(&digest), expected);
    }
}
