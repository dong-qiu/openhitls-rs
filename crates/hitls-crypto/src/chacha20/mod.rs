//! ChaCha20 stream cipher, Poly1305 MAC, and ChaCha20-Poly1305 AEAD.
//!
//! Implements RFC 8439 (ChaCha20 and Poly1305 for IETF Protocols).

#[cfg(target_arch = "aarch64")]
mod chacha20_neon;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod chacha20_x86;

use hitls_types::CryptoError;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// ChaCha20 key size in bytes (256 bits).
pub const CHACHA20_KEY_SIZE: usize = 32;

/// ChaCha20 nonce size in bytes (96 bits).
pub const CHACHA20_NONCE_SIZE: usize = 12;

/// ChaCha20-Poly1305 tag size in bytes.
pub const CHACHA20_POLY1305_TAG_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// ChaCha20 quarter round and block function
// ---------------------------------------------------------------------------

#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// Generate a 64-byte keystream block, dispatching to SIMD when available.
fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            return unsafe { chacha20_neon::chacha20_block_neon(key, counter, nonce) };
        }
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("sse2") {
            return unsafe { chacha20_x86::chacha20_block_x86(key, counter, nonce) };
        }
    }
    chacha20_block_soft(key, counter, nonce)
}

/// Generate two 64-byte keystream blocks (128 bytes) for consecutive counters.
fn chacha20_2_blocks(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 128] {
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            return unsafe { chacha20_neon::chacha20_2_blocks_neon(key, counter, nonce) };
        }
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("sse2") {
            return unsafe { chacha20_x86::chacha20_2_blocks_x86(key, counter, nonce) };
        }
    }
    // Software fallback: two sequential blocks
    let mut out = [0u8; 128];
    let b0 = chacha20_block_soft(key, counter, nonce);
    let b1 = chacha20_block_soft(key, counter.wrapping_add(1), nonce);
    out[..64].copy_from_slice(&b0);
    out[64..].copy_from_slice(&b1);
    out
}

/// Software-only 64-byte keystream block generation.
pub(crate) fn chacha20_block_soft(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];

    // Constants: "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key (8 words)
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(
            key[4 * i..4 * i + 4]
                .try_into()
                .expect("exact 4-byte slice"),
        );
    }

    // Counter
    state[12] = counter;

    // Nonce (3 words)
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes(
            nonce[4 * i..4 * i + 4]
                .try_into()
                .expect("exact 4-byte slice"),
        );
    }

    let initial = state;

    // 20 rounds (10 double rounds)
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    // Add initial state
    for i in 0..16 {
        state[i] = state[i].wrapping_add(initial[i]);
    }

    // Serialize to bytes
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

/// ChaCha20 stream cipher context.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct ChaCha20 {
    key: [u8; CHACHA20_KEY_SIZE],
}

impl ChaCha20 {
    /// Create a new ChaCha20 cipher with the given 32-byte key.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != CHACHA20_KEY_SIZE {
            return Err(CryptoError::InvalidArg("key must be 32 bytes"));
        }
        let mut k = [0u8; CHACHA20_KEY_SIZE];
        k.copy_from_slice(key);
        Ok(ChaCha20 { key: k })
    }

    /// Encrypt or decrypt data in place (XOR with keystream).
    pub fn apply_keystream(
        &self,
        nonce: &[u8],
        counter: u32,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        if nonce.len() != CHACHA20_NONCE_SIZE {
            return Err(CryptoError::InvalidArg("nonce must be 12 bytes"));
        }
        let nonce_arr: [u8; 12] = nonce.try_into().expect("nonce length validated above");

        let mut offset = 0;
        let mut block_counter = counter;

        // Process 128-byte (2-block) chunks
        while offset + 128 <= data.len() {
            let blocks = chacha20_2_blocks(&self.key, block_counter, &nonce_arr);
            for i in 0..128 {
                data[offset + i] ^= blocks[i];
            }
            offset += 128;
            block_counter = block_counter.wrapping_add(2);
        }

        // Process remaining single blocks
        while offset < data.len() {
            let block = chacha20_block(&self.key, block_counter, &nonce_arr);
            let remaining = data.len() - offset;
            let copy_len = remaining.min(64);
            for i in 0..copy_len {
                data[offset + i] ^= block[i];
            }
            offset += copy_len;
            block_counter = block_counter.wrapping_add(1);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Poly1305 MAC
// ---------------------------------------------------------------------------

/// Poly1305 one-time MAC (RFC 8439 §2.5).
pub struct Poly1305 {
    r: [u32; 5],   // clamped r in radix-2^26 limbs
    r2: [u32; 5],  // r² in radix-2^26 limbs (precomputed for 2-block batch)
    s: [u32; 4],   // s as 4×u32
    acc: [u32; 5], // accumulator in radix-2^26 limbs
    buf: [u8; 16],
    buf_len: usize,
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.r.zeroize();
        self.s.zeroize();
        self.acc.zeroize();
        self.buf.zeroize();
    }
}

impl Poly1305 {
    /// Create a Poly1305 instance from a 32-byte one-time key.
    pub fn new(key: &[u8; 32]) -> Self {
        // Clamp r in byte space (RFC 8439 §2.5)
        let mut r_bytes = [0u8; 16];
        r_bytes.copy_from_slice(&key[..16]);
        r_bytes[3] &= 15;
        r_bytes[7] &= 15;
        r_bytes[11] &= 15;
        r_bytes[15] &= 15;
        r_bytes[4] &= 252;
        r_bytes[8] &= 252;
        r_bytes[12] &= 252;

        // Decompose clamped r into radix-2^26 limbs
        let t0 = u32::from_le_bytes(r_bytes[0..4].try_into().expect("exact 4-byte slice"));
        let t1 = u32::from_le_bytes(r_bytes[4..8].try_into().expect("exact 4-byte slice"));
        let t2 = u32::from_le_bytes(r_bytes[8..12].try_into().expect("exact 4-byte slice"));
        let t3 = u32::from_le_bytes(r_bytes[12..16].try_into().expect("exact 4-byte slice"));

        let r0 = t0 & 0x03ff_ffff;
        let r1 = ((t0 >> 26) | (t1 << 6)) & 0x03ff_ffff;
        let r2 = ((t1 >> 20) | (t2 << 12)) & 0x03ff_ffff;
        let r3 = ((t2 >> 14) | (t3 << 18)) & 0x03ff_ffff;
        let r4 = t3 >> 8;

        // s = key[16..32]
        let s0 = u32::from_le_bytes(key[16..20].try_into().expect("exact 4-byte slice"));
        let s1 = u32::from_le_bytes(key[20..24].try_into().expect("exact 4-byte slice"));
        let s2 = u32::from_le_bytes(key[24..28].try_into().expect("exact 4-byte slice"));
        let s3 = u32::from_le_bytes(key[28..32].try_into().expect("exact 4-byte slice"));

        // Precompute r² = r * r in radix-2^26
        let r_limbs = [r0, r1, r2, r3, r4];
        let r2_limbs = Self::mul_r_squared(r_limbs);

        Poly1305 {
            r: r_limbs,
            r2: r2_limbs,
            s: [s0, s1, s2, s3],
            acc: [0; 5],
            buf: [0; 16],
            buf_len: 0,
        }
    }

    /// Compute r² = r * r in radix-2^26 representation.
    fn mul_r_squared(r: [u32; 5]) -> [u32; 5] {
        let r0 = u64::from(r[0]);
        let r1 = u64::from(r[1]);
        let r2 = u64::from(r[2]);
        let r3 = u64::from(r[3]);
        let r4 = u64::from(r[4]);
        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let d0 = r0 * r0 + r1 * s4 * 2 + r2 * s3 * 2;
        let mut d1 = r0 * r1 * 2 + r2 * s4 * 2 + r3 * s3;
        let mut d2 = r0 * r2 * 2 + r1 * r1 + r3 * s4 * 2;
        let mut d3 = r0 * r3 * 2 + r1 * r2 * 2 + r4 * s4;
        let mut d4 = r0 * r4 * 2 + r1 * r3 * 2 + r2 * r2;

        let mut c: u64;
        let o0 = (d0 & 0x03ff_ffff) as u32;
        c = d0 >> 26;
        d1 += c;
        let o1 = (d1 & 0x03ff_ffff) as u32;
        c = d1 >> 26;
        d2 += c;
        let o2 = (d2 & 0x03ff_ffff) as u32;
        c = d2 >> 26;
        d3 += c;
        let o3 = (d3 & 0x03ff_ffff) as u32;
        c = d3 >> 26;
        d4 += c;
        let mut o4 = (d4 & 0x03ff_ffff) as u32;
        c = d4 >> 26;
        let mut o0 = o0.wrapping_add((c * 5) as u32);
        c = u64::from(o0 >> 26);
        o0 &= 0x03ff_ffff;
        let o1 = o1.wrapping_add(c as u32);
        // Limb carry may leave o4 slightly above 2^26, acceptable for precompute
        o4 &= 0x03ff_ffff;

        [o0, o1, o2, o3, o4]
    }

    fn process_block(&mut self, block: &[u8], hibit: u32) {
        let t0 = u32::from_le_bytes(block[0..4].try_into().expect("exact 4-byte slice"));
        let t1 = u32::from_le_bytes(block[4..8].try_into().expect("exact 4-byte slice"));
        let t2 = u32::from_le_bytes(block[8..12].try_into().expect("exact 4-byte slice"));
        let t3 = u32::from_le_bytes(block[12..16].try_into().expect("exact 4-byte slice"));

        // Add to accumulator (radix-2^26)
        self.acc[0] = self.acc[0].wrapping_add(t0 & 0x03ff_ffff);
        self.acc[1] = self.acc[1].wrapping_add(((t0 >> 26) | (t1 << 6)) & 0x03ff_ffff);
        self.acc[2] = self.acc[2].wrapping_add(((t1 >> 20) | (t2 << 12)) & 0x03ff_ffff);
        self.acc[3] = self.acc[3].wrapping_add(((t2 >> 14) | (t3 << 18)) & 0x03ff_ffff);
        self.acc[4] = self.acc[4].wrapping_add((t3 >> 8) | hibit);

        // Multiply accumulator by r
        let r0 = u64::from(self.r[0]);
        let r1 = u64::from(self.r[1]);
        let r2 = u64::from(self.r[2]);
        let r3 = u64::from(self.r[3]);
        let r4 = u64::from(self.r[4]);
        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let a0 = u64::from(self.acc[0]);
        let a1 = u64::from(self.acc[1]);
        let a2 = u64::from(self.acc[2]);
        let a3 = u64::from(self.acc[3]);
        let a4 = u64::from(self.acc[4]);

        let d0 = a0 * r0 + a1 * s4 + a2 * s3 + a3 * s2 + a4 * s1;
        let mut d1 = a0 * r1 + a1 * r0 + a2 * s4 + a3 * s3 + a4 * s2;
        let mut d2 = a0 * r2 + a1 * r1 + a2 * r0 + a3 * s4 + a4 * s3;
        let mut d3 = a0 * r3 + a1 * r2 + a2 * r1 + a3 * r0 + a4 * s4;
        let mut d4 = a0 * r4 + a1 * r3 + a2 * r2 + a3 * r1 + a4 * r0;

        // Carry propagation
        let mut c: u64;
        c = d0 >> 26;
        self.acc[0] = (d0 & 0x03ff_ffff) as u32;
        d1 += c;
        c = d1 >> 26;
        self.acc[1] = (d1 & 0x03ff_ffff) as u32;
        d2 += c;
        c = d2 >> 26;
        self.acc[2] = (d2 & 0x03ff_ffff) as u32;
        d3 += c;
        c = d3 >> 26;
        self.acc[3] = (d3 & 0x03ff_ffff) as u32;
        d4 += c;
        c = d4 >> 26;
        self.acc[4] = (d4 & 0x03ff_ffff) as u32;
        self.acc[0] = self.acc[0].wrapping_add((c * 5) as u32);
        c = u64::from(self.acc[0] >> 26);
        self.acc[0] &= 0x03ff_ffff;
        self.acc[1] = self.acc[1].wrapping_add(c as u32);
    }

    /// Process 2 blocks at once using r² precomputation.
    ///
    /// Computes acc_new = (acc + b0) * r² + b1 * r, which equals the
    /// sequential result ((acc + b0) * r + b1) * r.
    fn process_2_blocks(&mut self, b0: &[u8], b1: &[u8]) {
        // Decode b0 into radix-2^26 and add to accumulator
        let t0_0 = u32::from_le_bytes(b0[0..4].try_into().expect("exact 4-byte slice"));
        let t1_0 = u32::from_le_bytes(b0[4..8].try_into().expect("exact 4-byte slice"));
        let t2_0 = u32::from_le_bytes(b0[8..12].try_into().expect("exact 4-byte slice"));
        let t3_0 = u32::from_le_bytes(b0[12..16].try_into().expect("exact 4-byte slice"));

        let a0 = u64::from(self.acc[0] + (t0_0 & 0x03ff_ffff));
        let a1 = u64::from(self.acc[1] + (((t0_0 >> 26) | (t1_0 << 6)) & 0x03ff_ffff));
        let a2 = u64::from(self.acc[2] + (((t1_0 >> 20) | (t2_0 << 12)) & 0x03ff_ffff));
        let a3 = u64::from(self.acc[3] + (((t2_0 >> 14) | (t3_0 << 18)) & 0x03ff_ffff));
        let a4 = u64::from(self.acc[4] + ((t3_0 >> 8) | (1 << 24)));

        // Compute (acc + b0) * r²
        let r20 = u64::from(self.r2[0]);
        let r21 = u64::from(self.r2[1]);
        let r22 = u64::from(self.r2[2]);
        let r23 = u64::from(self.r2[3]);
        let r24 = u64::from(self.r2[4]);
        let s21 = r21 * 5;
        let s22 = r22 * 5;
        let s23 = r23 * 5;
        let s24 = r24 * 5;

        let mut d0 = a0 * r20 + a1 * s24 + a2 * s23 + a3 * s22 + a4 * s21;
        let mut d1 = a0 * r21 + a1 * r20 + a2 * s24 + a3 * s23 + a4 * s22;
        let mut d2 = a0 * r22 + a1 * r21 + a2 * r20 + a3 * s24 + a4 * s23;
        let mut d3 = a0 * r23 + a1 * r22 + a2 * r21 + a3 * r20 + a4 * s24;
        let mut d4 = a0 * r24 + a1 * r23 + a2 * r22 + a3 * r21 + a4 * r20;

        // Decode b1 into radix-2^26
        let t0_1 = u32::from_le_bytes(b1[0..4].try_into().expect("exact 4-byte slice"));
        let t1_1 = u32::from_le_bytes(b1[4..8].try_into().expect("exact 4-byte slice"));
        let t2_1 = u32::from_le_bytes(b1[8..12].try_into().expect("exact 4-byte slice"));
        let t3_1 = u32::from_le_bytes(b1[12..16].try_into().expect("exact 4-byte slice"));

        let b0v = u64::from(t0_1 & 0x03ff_ffff);
        let b1v = u64::from(((t0_1 >> 26) | (t1_1 << 6)) & 0x03ff_ffff);
        let b2v = u64::from(((t1_1 >> 20) | (t2_1 << 12)) & 0x03ff_ffff);
        let b3v = u64::from(((t2_1 >> 14) | (t3_1 << 18)) & 0x03ff_ffff);
        let b4v = u64::from((t3_1 >> 8) | (1 << 24));

        // Compute b1 * r and add to d0..d4
        let r0 = u64::from(self.r[0]);
        let r1 = u64::from(self.r[1]);
        let rr2 = u64::from(self.r[2]);
        let r3 = u64::from(self.r[3]);
        let r4 = u64::from(self.r[4]);
        let sr1 = r1 * 5;
        let sr2 = rr2 * 5;
        let sr3 = r3 * 5;
        let sr4 = r4 * 5;

        d0 += b0v * r0 + b1v * sr4 + b2v * sr3 + b3v * sr2 + b4v * sr1;
        d1 += b0v * r1 + b1v * r0 + b2v * sr4 + b3v * sr3 + b4v * sr2;
        d2 += b0v * rr2 + b1v * r1 + b2v * r0 + b3v * sr4 + b4v * sr3;
        d3 += b0v * r3 + b1v * rr2 + b2v * r1 + b3v * r0 + b4v * sr4;
        d4 += b0v * r4 + b1v * r3 + b2v * rr2 + b3v * r1 + b4v * r0;

        // Carry propagation
        let mut c: u64;
        c = d0 >> 26;
        self.acc[0] = (d0 & 0x03ff_ffff) as u32;
        d1 += c;
        c = d1 >> 26;
        self.acc[1] = (d1 & 0x03ff_ffff) as u32;
        d2 += c;
        c = d2 >> 26;
        self.acc[2] = (d2 & 0x03ff_ffff) as u32;
        d3 += c;
        c = d3 >> 26;
        self.acc[3] = (d3 & 0x03ff_ffff) as u32;
        d4 += c;
        c = d4 >> 26;
        self.acc[4] = (d4 & 0x03ff_ffff) as u32;
        self.acc[0] = self.acc[0].wrapping_add((c * 5) as u32);
        c = u64::from(self.acc[0] >> 26);
        self.acc[0] &= 0x03ff_ffff;
        self.acc[1] = self.acc[1].wrapping_add(c as u32);
    }

    /// Feed data into the MAC computation.
    pub fn update(&mut self, data: &[u8]) {
        let mut pos = 0;

        // Process buffered data first
        if self.buf_len > 0 {
            let want = 16 - self.buf_len;
            if data.len() < want {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buf[self.buf_len..16].copy_from_slice(&data[..want]);
            let block = self.buf;
            self.process_block(&block, 1 << 24);
            self.buf_len = 0;
            pos = want;
        }

        // Process pairs of 16-byte blocks using r² precomputation
        while pos + 32 <= data.len() {
            self.process_2_blocks(&data[pos..pos + 16], &data[pos + 16..pos + 32]);
            pos += 32;
        }

        // Process remaining single full block
        while pos + 16 <= data.len() {
            let mut block = [0u8; 16];
            block.copy_from_slice(&data[pos..pos + 16]);
            self.process_block(&block, 1 << 24);
            pos += 16;
        }

        // Buffer remainder
        if pos < data.len() {
            let remaining = data.len() - pos;
            self.buf[..remaining].copy_from_slice(&data[pos..]);
            self.buf_len = remaining;
        }
    }

    /// Finalize and return the 16-byte tag.
    pub fn finish(mut self) -> [u8; 16] {
        // Process final partial block
        if self.buf_len > 0 {
            let mut block = [0u8; 16];
            block[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            block[self.buf_len] = 0x01; // padding bit
            self.process_block(&block, 0); // hibit = 0 for final partial block
        }

        // Full carry
        let mut c: u32;
        c = self.acc[1] >> 26;
        self.acc[1] &= 0x03ff_ffff;
        self.acc[2] = self.acc[2].wrapping_add(c);
        c = self.acc[2] >> 26;
        self.acc[2] &= 0x03ff_ffff;
        self.acc[3] = self.acc[3].wrapping_add(c);
        c = self.acc[3] >> 26;
        self.acc[3] &= 0x03ff_ffff;
        self.acc[4] = self.acc[4].wrapping_add(c);
        c = self.acc[4] >> 26;
        self.acc[4] &= 0x03ff_ffff;
        self.acc[0] = self.acc[0].wrapping_add(c * 5);
        c = self.acc[0] >> 26;
        self.acc[0] &= 0x03ff_ffff;
        self.acc[1] = self.acc[1].wrapping_add(c);

        // Compute acc - p (p = 2^130 - 5)
        let mut g = [0u32; 5];
        g[0] = self.acc[0].wrapping_add(5);
        c = g[0] >> 26;
        g[0] &= 0x03ff_ffff;
        g[1] = self.acc[1].wrapping_add(c);
        c = g[1] >> 26;
        g[1] &= 0x03ff_ffff;
        g[2] = self.acc[2].wrapping_add(c);
        c = g[2] >> 26;
        g[2] &= 0x03ff_ffff;
        g[3] = self.acc[3].wrapping_add(c);
        c = g[3] >> 26;
        g[3] &= 0x03ff_ffff;
        g[4] = self.acc[4].wrapping_add(c).wrapping_sub(1 << 26);

        // If g >= 0 (i.e., bit 31 of g[4] is 0), use g; else use acc
        let mask = (g[4] >> 31).wrapping_sub(1); // 0xFFFFFFFF if g >= 0, 0 otherwise
        for (a, &gi) in self.acc.iter_mut().zip(g.iter()) {
            *a = (*a & !mask) | (gi & mask);
        }

        // Convert radix-2^26 limbs to 4 × u32 (base 2^32)
        let h0 = self.acc[0] | self.acc[1].wrapping_shl(26);
        let h1 = (self.acc[1] >> 6) | self.acc[2].wrapping_shl(20);
        let h2 = (self.acc[2] >> 12) | self.acc[3].wrapping_shl(14);
        let h3 = (self.acc[3] >> 18) | self.acc[4].wrapping_shl(8);

        // Add s
        let mut f: u64;
        f = u64::from(h0) + u64::from(self.s[0]);
        let t0 = f as u32;
        f >>= 32;
        f += u64::from(h1) + u64::from(self.s[1]);
        let t1 = f as u32;
        f >>= 32;
        f += u64::from(h2) + u64::from(self.s[2]);
        let t2 = f as u32;
        f >>= 32;
        f += u64::from(h3) + u64::from(self.s[3]);
        let t3 = f as u32;

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&t0.to_le_bytes());
        tag[4..8].copy_from_slice(&t1.to_le_bytes());
        tag[8..12].copy_from_slice(&t2.to_le_bytes());
        tag[12..16].copy_from_slice(&t3.to_le_bytes());
        tag
    }
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 AEAD
// ---------------------------------------------------------------------------

/// ChaCha20-Poly1305 AEAD (RFC 8439 §2.8).
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

impl ChaCha20Poly1305 {
    /// Create a new ChaCha20-Poly1305 AEAD with the given 32-byte key.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidArg("key must be 32 bytes"));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        Ok(ChaCha20Poly1305 { key: k })
    }

    /// Encrypt plaintext with AEAD. Returns ciphertext || 16-byte tag.
    pub fn encrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidArg("nonce must be 12 bytes"));
        }
        let nonce_arr: [u8; 12] = nonce.try_into().expect("nonce length validated above");

        // Generate Poly1305 key from block 0
        let poly_key_block = chacha20_block(&self.key, 0, &nonce_arr);
        let poly_key: [u8; 32] = poly_key_block[..32]
            .try_into()
            .expect("exact 32-byte slice from 64-byte block");

        // Encrypt plaintext starting at counter 1
        let mut ciphertext = plaintext.to_vec();
        let cipher = ChaCha20::new(&self.key)?;
        cipher.apply_keystream(nonce, 1, &mut ciphertext)?;

        // Compute Poly1305 tag
        let tag = self.compute_tag(&poly_key, aad, &ciphertext);

        ciphertext.extend_from_slice(&tag);
        Ok(ciphertext)
    }

    /// Decrypt ciphertext (with appended tag) using AEAD.
    pub fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidArg("nonce must be 12 bytes"));
        }
        if ciphertext_and_tag.len() < 16 {
            return Err(CryptoError::InvalidArg("invalid tag length"));
        }
        let nonce_arr: [u8; 12] = nonce.try_into().expect("nonce length validated above");

        let ct_len = ciphertext_and_tag.len() - 16;
        let ciphertext = &ciphertext_and_tag[..ct_len];
        let tag = &ciphertext_and_tag[ct_len..];

        // Generate Poly1305 key
        let poly_key_block = chacha20_block(&self.key, 0, &nonce_arr);
        let poly_key: [u8; 32] = poly_key_block[..32]
            .try_into()
            .expect("exact 32-byte slice from 64-byte block");

        // Verify tag
        let expected_tag = self.compute_tag(&poly_key, aad, ciphertext);
        if tag.ct_eq(&expected_tag).into() {
            // Decrypt
            let mut plaintext = ciphertext.to_vec();
            let cipher = ChaCha20::new(&self.key)?;
            cipher.apply_keystream(nonce, 1, &mut plaintext)?;
            Ok(plaintext)
        } else {
            Err(CryptoError::AeadTagVerifyFail)
        }
    }

    fn compute_tag(&self, poly_key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        // Stack zero buffer for padding (max 15 bytes needed)
        const ZEROS: [u8; 15] = [0u8; 15];

        let mut mac = Poly1305::new(poly_key);

        // AAD + padding
        mac.update(aad);
        if aad.len() % 16 != 0 {
            mac.update(&ZEROS[..16 - aad.len() % 16]);
        }

        // Ciphertext + padding
        mac.update(ciphertext);
        if ciphertext.len() % 16 != 0 {
            mac.update(&ZEROS[..16 - ciphertext.len() % 16]);
        }

        // Lengths as u64 LE
        mac.update(&(aad.len() as u64).to_le_bytes());
        mac.update(&(ciphertext.len() as u64).to_le_bytes());

        mac.finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_utils::hex::to_hex;

    fn from_hex(h: &str) -> Vec<u8> {
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_chacha20_rfc8439_test_vector() {
        // RFC 8439 §2.4.2
        let key = from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce = from_hex("000000000000004a00000000");
        let plaintext = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";

        let mut data = plaintext.to_vec();
        let cipher = ChaCha20::new(&key).unwrap();
        cipher.apply_keystream(&nonce, 1, &mut data).unwrap();

        let expected = from_hex(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"
        );
        assert_eq!(data, expected);
    }

    #[test]
    fn test_poly1305_rfc8439_test_vector() {
        // RFC 8439 §2.5.2
        let key = from_hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        let msg = b"Cryptographic Forum Research Group";

        let key_arr: [u8; 32] = key.try_into().unwrap();
        let mut mac = Poly1305::new(&key_arr);
        mac.update(msg);
        let tag = mac.finish();

        assert_eq!(to_hex(&tag), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    #[test]
    fn test_chacha20_poly1305_aead_encrypt() {
        // RFC 8439 §2.8.2
        let key = from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = from_hex("070000004041424344454647");
        let aad = from_hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";

        let aead = ChaCha20Poly1305::new(&key).unwrap();
        let ct = aead.encrypt(&nonce, &aad, plaintext).unwrap();

        // Expected ciphertext (without tag)
        let expected_ct = from_hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
        );
        let expected_tag = from_hex("1ae10b594f09e26a7e902ecbd0600691");

        assert_eq!(&ct[..ct.len() - 16], &expected_ct[..]);
        assert_eq!(&ct[ct.len() - 16..], &expected_tag[..]);
    }

    #[test]
    fn test_chacha20_poly1305_aead_decrypt() {
        let key = from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = from_hex("070000004041424344454647");
        let aad = from_hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";

        let aead = ChaCha20Poly1305::new(&key).unwrap();
        let ct = aead.encrypt(&nonce, &aad, plaintext).unwrap();
        let pt = aead.decrypt(&nonce, &aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_chacha20_poly1305_auth_failure() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let aead = ChaCha20Poly1305::new(&key).unwrap();

        let ct = aead.encrypt(&nonce, b"aad", b"plaintext").unwrap();

        // Tamper with ciphertext
        let mut tampered = ct.clone();
        tampered[0] ^= 0xff;
        assert!(aead.decrypt(&nonce, b"aad", &tampered).is_err());
    }

    #[test]
    fn test_chacha20_poly1305_empty_plaintext() {
        let key = [0x01u8; 32];
        let nonce = [0u8; 12];
        let aead = ChaCha20Poly1305::new(&key).unwrap();

        let ct = aead.encrypt(&nonce, b"some aad", b"").unwrap();
        assert_eq!(ct.len(), 16); // tag only

        let pt = aead.decrypt(&nonce, b"some aad", &ct).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn test_chacha20_poly1305_empty_aad() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let aead = ChaCha20Poly1305::new(&key).unwrap();
        let plaintext = b"Hello, ChaCha20!";

        let ct = aead.encrypt(&nonce, b"", plaintext).unwrap();
        let pt = aead.decrypt(&nonce, b"", &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_chacha20_poly1305_empty_both() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let aead = ChaCha20Poly1305::new(&key).unwrap();

        let ct = aead.encrypt(&nonce, b"", b"").unwrap();
        assert_eq!(ct.len(), 16); // tag only
        let pt = aead.decrypt(&nonce, b"", &ct).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn test_chacha20_poly1305_invalid_key_size() {
        assert!(ChaCha20Poly1305::new(&[0u8; 31]).is_err());
        assert!(ChaCha20Poly1305::new(&[0u8; 33]).is_err());
    }

    #[test]
    fn test_chacha20_poly1305_invalid_nonce_size() {
        let aead = ChaCha20Poly1305::new(&[0u8; 32]).unwrap();
        assert!(aead.encrypt(&[0u8; 11], b"", b"test").is_err());
        assert!(aead.encrypt(&[0u8; 13], b"", b"test").is_err());
        assert!(aead.decrypt(&[0u8; 11], b"", &[0u8; 20]).is_err());
    }

    // ===================================================================
    // Phase T154 — HW↔SW cross-validation: ChaCha20 block
    // ===================================================================

    /// Verify chacha20_block_soft matches auto-dispatched chacha20_block for many counters.
    #[test]
    fn test_chacha20_soft_vs_dispatch_stress() {
        let key: [u8; 32] = core::array::from_fn(|i| (i * 0x13 + 0x42) as u8);
        let nonce: [u8; 12] = core::array::from_fn(|i| (i * 7) as u8);

        for counter in 0..64u32 {
            let dispatch = chacha20_block(&key, counter, &nonce);
            let soft = chacha20_block_soft(&key, counter, &nonce);
            assert_eq!(
                dispatch, soft,
                "ChaCha20 block mismatch at counter={counter}"
            );
        }
    }

    /// Verify that a full 256-byte keystream is consistent between paths.
    #[test]
    fn test_chacha20_keystream_256_bytes_consistency() {
        let key = [0xABu8; 32];
        let nonce = [0xCDu8; 12];

        let mut stream_dispatch = Vec::new();
        let mut stream_soft = Vec::new();

        for counter in 0..4u32 {
            stream_dispatch.extend_from_slice(&chacha20_block(&key, counter, &nonce));
            stream_soft.extend_from_slice(&chacha20_block_soft(&key, counter, &nonce));
        }

        assert_eq!(stream_dispatch.len(), 256);
        assert_eq!(stream_dispatch, stream_soft);
    }

    mod proptests {
        use super::super::ChaCha20Poly1305;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            #[test]
            fn prop_chacha20_poly1305_roundtrip(
                key in prop::array::uniform32(any::<u8>()),
                nonce in proptest::collection::vec(any::<u8>(), 12..=12),
                aad in proptest::collection::vec(any::<u8>(), 0..64),
                pt in proptest::collection::vec(any::<u8>(), 0..128),
            ) {
                let aead = ChaCha20Poly1305::new(&key).unwrap();
                let ct = aead.encrypt(&nonce, &aad, &pt).unwrap();
                let recovered = aead.decrypt(&nonce, &aad, &ct).unwrap();
                prop_assert_eq!(recovered, pt);
            }
        }
    }
}
