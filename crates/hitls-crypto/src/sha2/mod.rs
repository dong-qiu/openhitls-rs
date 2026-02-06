//! SHA-2 family of hash algorithms.
//!
//! Provides SHA-224, SHA-256, SHA-384, and SHA-512 as defined in FIPS 180-4.

use hitls_types::CryptoError;

// ===== SHA-256 constants =====

/// SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes).
const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 initial hash values.
const H256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-224 initial hash values.
const H224: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];

// ===== SHA-512 constants =====

/// SHA-512 round constants (first 64 bits of fractional parts of cube roots of first 80 primes).
const K512: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// SHA-512 initial hash values.
const H512: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// SHA-384 initial hash values.
const H384: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

// ===== SHA-256 compression =====

fn sha256_compress(state: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];

    // Parse block into 16 big-endian u32 words
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[4 * i],
            block[4 * i + 1],
            block[4 * i + 2],
            block[4 * i + 3],
        ]);
    }

    // Expand to 64 words
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K256[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

// ===== SHA-512 compression =====

fn sha512_compress(state: &mut [u64; 8], block: &[u8]) {
    let mut w = [0u64; 80];

    for i in 0..16 {
        w[i] = u64::from_be_bytes([
            block[8 * i],
            block[8 * i + 1],
            block[8 * i + 2],
            block[8 * i + 3],
            block[8 * i + 4],
            block[8 * i + 5],
            block[8 * i + 6],
            block[8 * i + 7],
        ]);
    }

    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K512[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

// ===== Helper: MD-padding update/finish for 32-bit hash (SHA-256/SHA-224) =====

fn update_32(
    state: &mut [u32; 8],
    buffer: &mut [u8; 64],
    buffer_len: &mut usize,
    count: &mut u64,
    data: &[u8],
) {
    let mut offset = 0;
    // Fill buffer if partially filled
    if *buffer_len > 0 {
        let need = 64 - *buffer_len;
        if data.len() < need {
            buffer[*buffer_len..*buffer_len + data.len()].copy_from_slice(data);
            *buffer_len += data.len();
            *count += data.len() as u64;
            return;
        }
        buffer[*buffer_len..64].copy_from_slice(&data[..need]);
        sha256_compress(state, buffer);
        offset = need;
        *buffer_len = 0;
    }

    // Process full blocks
    while offset + 64 <= data.len() {
        sha256_compress(state, &data[offset..offset + 64]);
        offset += 64;
    }

    // Buffer remaining
    let remaining = data.len() - offset;
    if remaining > 0 {
        buffer[..remaining].copy_from_slice(&data[offset..]);
        *buffer_len = remaining;
    }
    *count += data.len() as u64;
}

fn finish_32(
    state: &mut [u32; 8],
    buffer: &mut [u8; 64],
    buffer_len: usize,
    count: u64,
    out: &mut [u8],
    output_size: usize,
) {
    let bit_len = count * 8;
    let mut pad_buf = [0u8; 128]; // max 2 blocks for padding
    let mut pad_len = buffer_len;
    pad_buf[..pad_len].copy_from_slice(&buffer[..buffer_len]);

    // Append 0x80
    pad_buf[pad_len] = 0x80;
    pad_len += 1;

    // If not enough room for 8-byte length, pad to 64 and process
    if pad_len > 56 {
        while pad_len < 64 {
            pad_buf[pad_len] = 0;
            pad_len += 1;
        }
        sha256_compress(state, &pad_buf[..64]);
        pad_buf = [0u8; 128];
        pad_len = 0;
    }

    // Pad with zeros up to byte 56
    while pad_len < 56 {
        pad_buf[pad_len] = 0;
        pad_len += 1;
    }

    // Append 64-bit big-endian bit length
    pad_buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
    sha256_compress(state, &pad_buf[..64]);

    // Write state as big-endian bytes
    let words_needed = output_size.div_ceil(4);
    for (i, &word) in state.iter().enumerate().take(words_needed) {
        let bytes = word.to_be_bytes();
        let start = i * 4;
        let end = (start + 4).min(output_size);
        out[start..end].copy_from_slice(&bytes[..end - start]);
    }
}

// ===== Helper: MD-padding update/finish for 64-bit hash (SHA-512/SHA-384) =====

fn update_64(
    state: &mut [u64; 8],
    buffer: &mut [u8; 128],
    buffer_len: &mut usize,
    count: &mut u128,
    data: &[u8],
) {
    let mut offset = 0;
    if *buffer_len > 0 {
        let need = 128 - *buffer_len;
        if data.len() < need {
            buffer[*buffer_len..*buffer_len + data.len()].copy_from_slice(data);
            *buffer_len += data.len();
            *count += data.len() as u128;
            return;
        }
        buffer[*buffer_len..128].copy_from_slice(&data[..need]);
        sha512_compress(state, buffer);
        offset = need;
        *buffer_len = 0;
    }

    while offset + 128 <= data.len() {
        sha512_compress(state, &data[offset..offset + 128]);
        offset += 128;
    }

    let remaining = data.len() - offset;
    if remaining > 0 {
        buffer[..remaining].copy_from_slice(&data[offset..]);
        *buffer_len = remaining;
    }
    *count += data.len() as u128;
}

fn finish_64(
    state: &mut [u64; 8],
    buffer: &mut [u8; 128],
    buffer_len: usize,
    count: u128,
    out: &mut [u8],
    output_size: usize,
) {
    let bit_len = count * 8;
    let mut pad_buf = [0u8; 256];
    let mut pad_len = buffer_len;
    pad_buf[..pad_len].copy_from_slice(&buffer[..buffer_len]);

    pad_buf[pad_len] = 0x80;
    pad_len += 1;

    if pad_len > 112 {
        while pad_len < 128 {
            pad_buf[pad_len] = 0;
            pad_len += 1;
        }
        sha512_compress(state, &pad_buf[..128]);
        pad_buf = [0u8; 256];
        pad_len = 0;
    }

    while pad_len < 112 {
        pad_buf[pad_len] = 0;
        pad_len += 1;
    }

    // Append 128-bit big-endian bit length
    pad_buf[112..128].copy_from_slice(&bit_len.to_be_bytes());
    sha512_compress(state, &pad_buf[..128]);

    let words_needed = output_size.div_ceil(8);
    for (i, &word) in state.iter().enumerate().take(words_needed) {
        let bytes = word.to_be_bytes();
        let start = i * 8;
        let end = (start + 8).min(output_size);
        out[start..end].copy_from_slice(&bytes[..end - start]);
    }
}

// ===== SHA-224 =====

/// SHA-224 output size in bytes.
pub const SHA224_OUTPUT_SIZE: usize = 28;

/// SHA-224 hash context.
#[derive(Clone)]
pub struct Sha224 {
    state: [u32; 8],
    count: u64,
    buffer: [u8; 64],
    buffer_len: usize,
}

impl Sha224 {
    pub fn new() -> Self {
        Self {
            state: H224,
            count: 0,
            buffer: [0u8; 64],
            buffer_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        update_32(
            &mut self.state,
            &mut self.buffer,
            &mut self.buffer_len,
            &mut self.count,
            data,
        );
        Ok(())
    }

    pub fn finish(&mut self) -> Result<[u8; SHA224_OUTPUT_SIZE], CryptoError> {
        let mut full = [0u8; 32];
        finish_32(
            &mut self.state,
            &mut self.buffer,
            self.buffer_len,
            self.count,
            &mut full,
            32,
        );
        let mut out = [0u8; SHA224_OUTPUT_SIZE];
        out.copy_from_slice(&full[..28]);
        Ok(out)
    }

    pub fn reset(&mut self) {
        self.state = H224;
        self.count = 0;
        self.buffer = [0u8; 64];
        self.buffer_len = 0;
    }

    pub fn digest(data: &[u8]) -> Result<[u8; SHA224_OUTPUT_SIZE], CryptoError> {
        let mut ctx = Self::new();
        ctx.update(data)?;
        ctx.finish()
    }
}

// ===== SHA-256 =====

/// SHA-256 output size in bytes.
pub const SHA256_OUTPUT_SIZE: usize = 32;

/// SHA-256 hash context.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    count: u64,
    buffer: [u8; 64],
    buffer_len: usize,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: H256,
            count: 0,
            buffer: [0u8; 64],
            buffer_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        update_32(
            &mut self.state,
            &mut self.buffer,
            &mut self.buffer_len,
            &mut self.count,
            data,
        );
        Ok(())
    }

    pub fn finish(&mut self) -> Result<[u8; SHA256_OUTPUT_SIZE], CryptoError> {
        let mut out = [0u8; SHA256_OUTPUT_SIZE];
        finish_32(
            &mut self.state,
            &mut self.buffer,
            self.buffer_len,
            self.count,
            &mut out,
            SHA256_OUTPUT_SIZE,
        );
        Ok(out)
    }

    pub fn reset(&mut self) {
        self.state = H256;
        self.count = 0;
        self.buffer = [0u8; 64];
        self.buffer_len = 0;
    }

    pub fn digest(data: &[u8]) -> Result<[u8; SHA256_OUTPUT_SIZE], CryptoError> {
        let mut ctx = Self::new();
        ctx.update(data)?;
        ctx.finish()
    }
}

// ===== SHA-384 =====

/// SHA-384 output size in bytes.
pub const SHA384_OUTPUT_SIZE: usize = 48;

/// SHA-384 hash context.
#[derive(Clone)]
pub struct Sha384 {
    state: [u64; 8],
    count: u128,
    buffer: [u8; 128],
    buffer_len: usize,
}

impl Sha384 {
    pub fn new() -> Self {
        Self {
            state: H384,
            count: 0,
            buffer: [0u8; 128],
            buffer_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        update_64(
            &mut self.state,
            &mut self.buffer,
            &mut self.buffer_len,
            &mut self.count,
            data,
        );
        Ok(())
    }

    pub fn finish(&mut self) -> Result<[u8; SHA384_OUTPUT_SIZE], CryptoError> {
        let mut full = [0u8; 64];
        finish_64(
            &mut self.state,
            &mut self.buffer,
            self.buffer_len,
            self.count,
            &mut full,
            64,
        );
        let mut out = [0u8; SHA384_OUTPUT_SIZE];
        out.copy_from_slice(&full[..48]);
        Ok(out)
    }

    pub fn reset(&mut self) {
        self.state = H384;
        self.count = 0;
        self.buffer = [0u8; 128];
        self.buffer_len = 0;
    }

    pub fn digest(data: &[u8]) -> Result<[u8; SHA384_OUTPUT_SIZE], CryptoError> {
        let mut ctx = Self::new();
        ctx.update(data)?;
        ctx.finish()
    }
}

// ===== SHA-512 =====

/// SHA-512 output size in bytes.
pub const SHA512_OUTPUT_SIZE: usize = 64;

/// SHA-512 hash context.
#[derive(Clone)]
pub struct Sha512 {
    state: [u64; 8],
    count: u128,
    buffer: [u8; 128],
    buffer_len: usize,
}

impl Sha512 {
    pub fn new() -> Self {
        Self {
            state: H512,
            count: 0,
            buffer: [0u8; 128],
            buffer_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        update_64(
            &mut self.state,
            &mut self.buffer,
            &mut self.buffer_len,
            &mut self.count,
            data,
        );
        Ok(())
    }

    pub fn finish(&mut self) -> Result<[u8; SHA512_OUTPUT_SIZE], CryptoError> {
        let mut out = [0u8; SHA512_OUTPUT_SIZE];
        finish_64(
            &mut self.state,
            &mut self.buffer,
            self.buffer_len,
            self.count,
            &mut out,
            SHA512_OUTPUT_SIZE,
        );
        Ok(out)
    }

    pub fn reset(&mut self) {
        self.state = H512;
        self.count = 0;
        self.buffer = [0u8; 128];
        self.buffer_len = 0;
    }

    pub fn digest(data: &[u8]) -> Result<[u8; SHA512_OUTPUT_SIZE], CryptoError> {
        let mut ctx = Self::new();
        ctx.update(data)?;
        ctx.finish()
    }
}

// ===== Digest trait implementations =====

impl crate::provider::Digest for Sha256 {
    fn output_size(&self) -> usize {
        SHA256_OUTPUT_SIZE
    }
    fn block_size(&self) -> usize {
        64
    }
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.update(data)
    }
    fn finish(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        let digest = Sha256::finish(self)?;
        out[..SHA256_OUTPUT_SIZE].copy_from_slice(&digest);
        Ok(())
    }
    fn reset(&mut self) {
        self.reset()
    }
}

impl crate::provider::Digest for Sha224 {
    fn output_size(&self) -> usize {
        SHA224_OUTPUT_SIZE
    }
    fn block_size(&self) -> usize {
        64
    }
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.update(data)
    }
    fn finish(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        let digest = Sha224::finish(self)?;
        out[..SHA224_OUTPUT_SIZE].copy_from_slice(&digest);
        Ok(())
    }
    fn reset(&mut self) {
        self.reset()
    }
}

impl crate::provider::Digest for Sha512 {
    fn output_size(&self) -> usize {
        SHA512_OUTPUT_SIZE
    }
    fn block_size(&self) -> usize {
        128
    }
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.update(data)
    }
    fn finish(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        let digest = Sha512::finish(self)?;
        out[..SHA512_OUTPUT_SIZE].copy_from_slice(&digest);
        Ok(())
    }
    fn reset(&mut self) {
        self.reset()
    }
}

impl crate::provider::Digest for Sha384 {
    fn output_size(&self) -> usize {
        SHA384_OUTPUT_SIZE
    }
    fn block_size(&self) -> usize {
        128
    }
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.update(data)
    }
    fn finish(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        let digest = Sha384::finish(self)?;
        out[..SHA384_OUTPUT_SIZE].copy_from_slice(&digest);
        Ok(())
    }
    fn reset(&mut self) {
        self.reset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6234 test vectors

    #[test]
    fn test_sha256_empty() {
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let digest = Sha256::digest(b"").unwrap();
        assert_eq!(hex(&digest), expected);
    }

    #[test]
    fn test_sha256_abc() {
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let digest = Sha256::digest(b"abc").unwrap();
        assert_eq!(hex(&digest), expected);
    }

    #[test]
    fn test_sha256_two_blocks() {
        let expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
        let digest =
            Sha256::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").unwrap();
        assert_eq!(hex(&digest), expected);
    }

    #[test]
    fn test_sha256_incremental() {
        let mut ctx = Sha256::new();
        ctx.update(b"abc").unwrap();
        ctx.update(b"dbcdecdefdefg").unwrap();
        ctx.update(b"efghfghighijhijkijkljklmklmnlmnomnopnopq")
            .unwrap();
        let digest = ctx.finish().unwrap();
        let expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
        assert_eq!(hex(&digest), expected);
    }

    #[test]
    fn test_sha224_abc() {
        let expected = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7";
        let digest = Sha224::digest(b"abc").unwrap();
        assert_eq!(hex(&digest), expected);
    }

    #[test]
    fn test_sha512_empty() {
        let expected = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        let digest = Sha512::digest(b"").unwrap();
        assert_eq!(hex(&digest), expected);
    }

    #[test]
    fn test_sha512_abc() {
        let expected = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
        let digest = Sha512::digest(b"abc").unwrap();
        assert_eq!(hex(&digest), expected);
    }

    #[test]
    fn test_sha384_abc() {
        let expected = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";
        let digest = Sha384::digest(b"abc").unwrap();
        assert_eq!(hex(&digest), expected);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
