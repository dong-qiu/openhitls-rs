//! SHA-3 family of hash algorithms and extendable-output functions (XOFs).
//!
//! Provides SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, and SHAKE256
//! as defined in FIPS 202. SHA-3 is based on the Keccak sponge construction.

use hitls_types::CryptoError;

// ---------------------------------------------------------------------------
// Keccak-f[1600] permutation
// ---------------------------------------------------------------------------

/// 24 round constants for Keccak-f[1600].
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Rotation offsets for the ρ step, indexed as ROTATIONS[x + 5*y].
const ROTATIONS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// The Keccak-f[1600] permutation on a 25-lane state.
fn keccak_f1600(state: &mut [u64; 25]) {
    for &rc in &RC {
        // θ (theta)
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        // ρ (rho) and π (pi) combined
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                let src = x + 5 * y;
                let dst = y + 5 * ((2 * x + 3 * y) % 5);
                b[dst] = state[src].rotate_left(ROTATIONS[src]);
            }
        }

        // χ (chi)
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] =
                    b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }

        // ι (iota)
        state[0] ^= rc;
    }
}

// ---------------------------------------------------------------------------
// Keccak sponge state (shared by all SHA-3/SHAKE variants)
// ---------------------------------------------------------------------------

struct KeccakState {
    state: [u64; 25],
    buf: Vec<u8>,
    rate: usize,
    suffix: u8,
    squeezed: bool,
}

impl KeccakState {
    fn new(rate: usize, suffix: u8) -> Self {
        KeccakState {
            state: [0u64; 25],
            buf: Vec::new(),
            rate,
            suffix,
            squeezed: false,
        }
    }

    fn reset(&mut self) {
        self.state = [0u64; 25];
        self.buf.clear();
        self.squeezed = false;
    }

    fn absorb(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        while self.buf.len() >= self.rate {
            // Inline XOR of rate bytes into state to avoid borrow conflict
            for i in 0..self.rate / 8 {
                let word = u64::from_le_bytes(self.buf[i * 8..(i + 1) * 8].try_into().unwrap());
                self.state[i] ^= word;
            }
            let remaining = self.rate % 8;
            if remaining > 0 {
                let full_words = self.rate / 8;
                let mut last = [0u8; 8];
                last[..remaining]
                    .copy_from_slice(&self.buf[full_words * 8..full_words * 8 + remaining]);
                self.state[full_words] ^= u64::from_le_bytes(last);
            }
            keccak_f1600(&mut self.state);
            self.buf.drain(..self.rate);
        }
    }

    fn xor_block(&mut self, block: &[u8]) {
        for i in 0..block.len() / 8 {
            let word = u64::from_le_bytes(block[i * 8..(i + 1) * 8].try_into().unwrap());
            self.state[i] ^= word;
        }
        // Handle remaining bytes (if rate not multiple of 8)
        let full_words = block.len() / 8;
        let remaining = block.len() % 8;
        if remaining > 0 {
            let mut last = [0u8; 8];
            last[..remaining].copy_from_slice(&block[full_words * 8..]);
            self.state[full_words] ^= u64::from_le_bytes(last);
        }
    }

    /// Pad and switch to squeeze phase.
    fn pad_and_switch(&mut self) {
        // Pad: suffix byte + zero padding + 0x80 at end
        let mut padded = vec![0u8; self.rate];
        let buf_len = self.buf.len();
        padded[..buf_len].copy_from_slice(&self.buf);
        padded[buf_len] = self.suffix;
        padded[self.rate - 1] |= 0x80;

        self.xor_block(&padded);
        keccak_f1600(&mut self.state);
        self.buf.clear();
        self.squeezed = true;
    }

    /// Squeeze output bytes.
    fn squeeze(&mut self, output: &mut [u8]) {
        if !self.squeezed {
            self.pad_and_switch();
        }

        let mut offset = 0;
        // First, use any remaining bytes from current state
        let state_bytes = self.state_to_bytes();
        let buf_offset = self.buf.len(); // how many bytes already squeezed from this block

        if buf_offset > 0 && buf_offset < self.rate {
            let available = self.rate - buf_offset;
            let copy_len = available.min(output.len());
            output[..copy_len].copy_from_slice(&state_bytes[buf_offset..buf_offset + copy_len]);
            offset = copy_len;
            if buf_offset + copy_len < self.rate {
                // Track how many bytes we've consumed from current state
                self.buf = vec![0u8; buf_offset + copy_len];
                return;
            }
            self.buf.clear();
        }

        while offset < output.len() {
            if offset > 0 || buf_offset > 0 {
                keccak_f1600(&mut self.state);
            }
            let state_bytes = self.state_to_bytes();
            let remaining = output.len() - offset;
            let copy_len = remaining.min(self.rate);
            output[offset..offset + copy_len].copy_from_slice(&state_bytes[..copy_len]);
            offset += copy_len;

            if copy_len < self.rate {
                // Track partial consumption
                self.buf = vec![0u8; copy_len];
            }
        }
    }

    fn state_to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(200);
        for &lane in &self.state {
            bytes.extend_from_slice(&lane.to_le_bytes());
        }
        bytes
    }

    /// Squeeze exactly `output_len` bytes for fixed-output hash.
    fn finalize(&mut self, output: &mut [u8]) {
        if !self.squeezed {
            self.pad_and_switch();
        }
        let state_bytes = self.state_to_bytes();
        output.copy_from_slice(&state_bytes[..output.len()]);
    }
}

// ---------------------------------------------------------------------------
// SHA3-224
// ---------------------------------------------------------------------------

/// SHA3-224 output size in bytes.
pub const SHA3_224_OUTPUT_SIZE: usize = 28;

/// SHA3-224 hash context.
pub struct Sha3_224 {
    inner: KeccakState,
}

impl Clone for Sha3_224 {
    fn clone(&self) -> Self {
        Sha3_224 {
            inner: KeccakState {
                state: self.inner.state,
                buf: self.inner.buf.clone(),
                rate: self.inner.rate,
                suffix: self.inner.suffix,
                squeezed: self.inner.squeezed,
            },
        }
    }
}

impl Sha3_224 {
    pub fn new() -> Self {
        Sha3_224 {
            inner: KeccakState::new(144, 0x06),
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if self.inner.squeezed {
            return Err(CryptoError::InvalidArg);
        }
        self.inner.absorb(data);
        Ok(())
    }

    pub fn finish(&mut self) -> Result<[u8; SHA3_224_OUTPUT_SIZE], CryptoError> {
        let mut out = [0u8; SHA3_224_OUTPUT_SIZE];
        self.inner.finalize(&mut out);
        Ok(out)
    }

    pub fn reset(&mut self) {
        self.inner.reset();
    }

    pub fn digest(data: &[u8]) -> Result<[u8; SHA3_224_OUTPUT_SIZE], CryptoError> {
        let mut ctx = Self::new();
        ctx.update(data)?;
        ctx.finish()
    }
}

// ---------------------------------------------------------------------------
// SHA3-256
// ---------------------------------------------------------------------------

/// SHA3-256 output size in bytes.
pub const SHA3_256_OUTPUT_SIZE: usize = 32;

/// SHA3-256 hash context.
pub struct Sha3_256 {
    inner: KeccakState,
}

impl Clone for Sha3_256 {
    fn clone(&self) -> Self {
        Sha3_256 {
            inner: KeccakState {
                state: self.inner.state,
                buf: self.inner.buf.clone(),
                rate: self.inner.rate,
                suffix: self.inner.suffix,
                squeezed: self.inner.squeezed,
            },
        }
    }
}

impl Sha3_256 {
    pub fn new() -> Self {
        Sha3_256 {
            inner: KeccakState::new(136, 0x06),
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if self.inner.squeezed {
            return Err(CryptoError::InvalidArg);
        }
        self.inner.absorb(data);
        Ok(())
    }

    pub fn finish(&mut self) -> Result<[u8; SHA3_256_OUTPUT_SIZE], CryptoError> {
        let mut out = [0u8; SHA3_256_OUTPUT_SIZE];
        self.inner.finalize(&mut out);
        Ok(out)
    }

    pub fn reset(&mut self) {
        self.inner.reset();
    }

    pub fn digest(data: &[u8]) -> Result<[u8; SHA3_256_OUTPUT_SIZE], CryptoError> {
        let mut ctx = Self::new();
        ctx.update(data)?;
        ctx.finish()
    }
}

// ---------------------------------------------------------------------------
// SHA3-384
// ---------------------------------------------------------------------------

/// SHA3-384 output size in bytes.
pub const SHA3_384_OUTPUT_SIZE: usize = 48;

/// SHA3-384 hash context.
pub struct Sha3_384 {
    inner: KeccakState,
}

impl Clone for Sha3_384 {
    fn clone(&self) -> Self {
        Sha3_384 {
            inner: KeccakState {
                state: self.inner.state,
                buf: self.inner.buf.clone(),
                rate: self.inner.rate,
                suffix: self.inner.suffix,
                squeezed: self.inner.squeezed,
            },
        }
    }
}

impl Sha3_384 {
    pub fn new() -> Self {
        Sha3_384 {
            inner: KeccakState::new(104, 0x06),
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if self.inner.squeezed {
            return Err(CryptoError::InvalidArg);
        }
        self.inner.absorb(data);
        Ok(())
    }

    pub fn finish(&mut self) -> Result<[u8; SHA3_384_OUTPUT_SIZE], CryptoError> {
        let mut out = [0u8; SHA3_384_OUTPUT_SIZE];
        self.inner.finalize(&mut out);
        Ok(out)
    }

    pub fn reset(&mut self) {
        self.inner.reset();
    }

    pub fn digest(data: &[u8]) -> Result<[u8; SHA3_384_OUTPUT_SIZE], CryptoError> {
        let mut ctx = Self::new();
        ctx.update(data)?;
        ctx.finish()
    }
}

// ---------------------------------------------------------------------------
// SHA3-512
// ---------------------------------------------------------------------------

/// SHA3-512 output size in bytes.
pub const SHA3_512_OUTPUT_SIZE: usize = 64;

/// SHA3-512 hash context.
pub struct Sha3_512 {
    inner: KeccakState,
}

impl Clone for Sha3_512 {
    fn clone(&self) -> Self {
        Sha3_512 {
            inner: KeccakState {
                state: self.inner.state,
                buf: self.inner.buf.clone(),
                rate: self.inner.rate,
                suffix: self.inner.suffix,
                squeezed: self.inner.squeezed,
            },
        }
    }
}

impl Sha3_512 {
    pub fn new() -> Self {
        Sha3_512 {
            inner: KeccakState::new(72, 0x06),
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if self.inner.squeezed {
            return Err(CryptoError::InvalidArg);
        }
        self.inner.absorb(data);
        Ok(())
    }

    pub fn finish(&mut self) -> Result<[u8; SHA3_512_OUTPUT_SIZE], CryptoError> {
        let mut out = [0u8; SHA3_512_OUTPUT_SIZE];
        self.inner.finalize(&mut out);
        Ok(out)
    }

    pub fn reset(&mut self) {
        self.inner.reset();
    }

    pub fn digest(data: &[u8]) -> Result<[u8; SHA3_512_OUTPUT_SIZE], CryptoError> {
        let mut ctx = Self::new();
        ctx.update(data)?;
        ctx.finish()
    }
}

// ---------------------------------------------------------------------------
// SHAKE128
// ---------------------------------------------------------------------------

/// SHAKE128 extendable-output function (XOF) context.
pub struct Shake128 {
    inner: KeccakState,
}

impl Clone for Shake128 {
    fn clone(&self) -> Self {
        Shake128 {
            inner: KeccakState {
                state: self.inner.state,
                buf: self.inner.buf.clone(),
                rate: self.inner.rate,
                suffix: self.inner.suffix,
                squeezed: self.inner.squeezed,
            },
        }
    }
}

impl Shake128 {
    pub fn new() -> Self {
        Shake128 {
            inner: KeccakState::new(168, 0x1F),
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if self.inner.squeezed {
            return Err(CryptoError::InvalidArg);
        }
        self.inner.absorb(data);
        Ok(())
    }

    pub fn squeeze(&mut self, output_len: usize) -> Result<Vec<u8>, CryptoError> {
        let mut output = vec![0u8; output_len];
        self.inner.squeeze(&mut output);
        Ok(output)
    }

    pub fn reset(&mut self) {
        self.inner.reset();
    }
}

// ---------------------------------------------------------------------------
// SHAKE256
// ---------------------------------------------------------------------------

/// SHAKE256 extendable-output function (XOF) context.
pub struct Shake256 {
    inner: KeccakState,
}

impl Clone for Shake256 {
    fn clone(&self) -> Self {
        Shake256 {
            inner: KeccakState {
                state: self.inner.state,
                buf: self.inner.buf.clone(),
                rate: self.inner.rate,
                suffix: self.inner.suffix,
                squeezed: self.inner.squeezed,
            },
        }
    }
}

impl Shake256 {
    pub fn new() -> Self {
        Shake256 {
            inner: KeccakState::new(136, 0x1F),
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if self.inner.squeezed {
            return Err(CryptoError::InvalidArg);
        }
        self.inner.absorb(data);
        Ok(())
    }

    pub fn squeeze(&mut self, output_len: usize) -> Result<Vec<u8>, CryptoError> {
        let mut output = vec![0u8; output_len];
        self.inner.squeeze(&mut output);
        Ok(output)
    }

    pub fn reset(&mut self) {
        self.inner.reset();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn test_sha3_256_empty() {
        let out = Sha3_256::digest(b"").unwrap();
        assert_eq!(
            hex(&out),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    #[test]
    fn test_sha3_256_abc() {
        let out = Sha3_256::digest(b"abc").unwrap();
        assert_eq!(
            hex(&out),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn test_sha3_256_two_blocks() {
        // 200-byte input to exercise multi-block absorption
        let data = vec![0x61u8; 200]; // 200 × 'a'
        let out = Sha3_256::digest(&data).unwrap();
        assert_eq!(out.len(), 32);
        // Verify incrementally produces same result
        let mut ctx = Sha3_256::new();
        ctx.update(&data[..100]).unwrap();
        ctx.update(&data[100..]).unwrap();
        let out2 = ctx.finish().unwrap();
        assert_eq!(out, out2);
    }

    #[test]
    fn test_sha3_512_empty() {
        let out = Sha3_512::digest(b"").unwrap();
        assert_eq!(
            hex(&out),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
             15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
    }

    #[test]
    fn test_sha3_512_abc() {
        let out = Sha3_512::digest(b"abc").unwrap();
        assert_eq!(
            hex(&out),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
             10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
    }

    #[test]
    fn test_sha3_224_abc() {
        let out = Sha3_224::digest(b"abc").unwrap();
        assert_eq!(
            hex(&out),
            "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
        );
    }

    #[test]
    fn test_sha3_384_abc() {
        let out = Sha3_384::digest(b"abc").unwrap();
        assert_eq!(
            hex(&out),
            "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2\
             98d88cea927ac7f539f1edf228376d25"
        );
    }

    #[test]
    fn test_shake128_variable_output() {
        let mut xof = Shake128::new();
        xof.update(b"").unwrap();
        let out32 = xof.squeeze(32).unwrap();
        assert_eq!(out32.len(), 32);

        // Known SHAKE128("") first 32 bytes
        assert_eq!(
            hex(&out32),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
    }

    #[test]
    fn test_shake256_variable_output() {
        let mut xof = Shake256::new();
        xof.update(b"").unwrap();
        let out32 = xof.squeeze(32).unwrap();

        // Known SHAKE256("") first 32 bytes
        assert_eq!(
            hex(&out32),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
    }
}
