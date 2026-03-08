//! SHA-3 family of hash algorithms and extendable-output functions (XOFs).
//!
//! Provides SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, and SHAKE256
//! as defined in FIPS 202. SHA-3 is based on the Keccak sponge construction.

use hitls_types::CryptoError;
use zeroize::Zeroize;

#[cfg(all(target_arch = "aarch64", has_sha3_keccak_intrinsics))]
mod keccak_arm;

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

/// Keccak-f[1600] dispatch: use SHA-3 crypto extensions on ARMv8.2+ when available.
fn keccak_f1600(state: &mut [u64; 25]) {
    #[cfg(all(target_arch = "aarch64", has_sha3_keccak_intrinsics))]
    {
        if std::arch::is_aarch64_feature_detected!("sha3") {
            // SAFETY: feature detection ensures SHA-3 crypto extensions are available.
            unsafe { keccak_arm::keccak_f1600_arm(state) };
            return;
        }
    }
    keccak_f1600_soft(state);
}

/// Precomputed π destination table: for each src index (x + 5*y),
/// PI_DEST[src] = y + 5*((2*x + 3*y) % 5).
const PI_DEST: [usize; 25] = {
    let mut table = [0usize; 25];
    let mut x = 0;
    while x < 5 {
        let mut y = 0;
        while y < 5 {
            table[x + 5 * y] = y + 5 * ((2 * x + 3 * y) % 5);
            y += 1;
        }
        x += 1;
    }
    table
};

/// Software fallback: Keccak-f[1600] permutation on a 25-lane state.
fn keccak_f1600_soft(state: &mut [u64; 25]) {
    for &rc in &RC {
        // θ (theta) — column parities and diff
        let c0 = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
        let c1 = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
        let c2 = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
        let c3 = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
        let c4 = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        let d0 = c4 ^ c1.rotate_left(1);
        let d1 = c0 ^ c2.rotate_left(1);
        let d2 = c1 ^ c3.rotate_left(1);
        let d3 = c2 ^ c4.rotate_left(1);
        let d4 = c3 ^ c0.rotate_left(1);

        state[0] ^= d0;
        state[5] ^= d0;
        state[10] ^= d0;
        state[15] ^= d0;
        state[20] ^= d0;
        state[1] ^= d1;
        state[6] ^= d1;
        state[11] ^= d1;
        state[16] ^= d1;
        state[21] ^= d1;
        state[2] ^= d2;
        state[7] ^= d2;
        state[12] ^= d2;
        state[17] ^= d2;
        state[22] ^= d2;
        state[3] ^= d3;
        state[8] ^= d3;
        state[13] ^= d3;
        state[18] ^= d3;
        state[23] ^= d3;
        state[4] ^= d4;
        state[9] ^= d4;
        state[14] ^= d4;
        state[19] ^= d4;
        state[24] ^= d4;

        // ρ (rho) and π (pi) combined — precomputed destination table
        let mut b = [0u64; 25];
        for i in 0..25 {
            b[PI_DEST[i]] = state[i].rotate_left(ROTATIONS[i]);
        }

        // χ (chi) — unrolled by row to avoid % 5
        state[0] = b[0] ^ (!b[1] & b[2]);
        state[1] = b[1] ^ (!b[2] & b[3]);
        state[2] = b[2] ^ (!b[3] & b[4]);
        state[3] = b[3] ^ (!b[4] & b[0]);
        state[4] = b[4] ^ (!b[0] & b[1]);

        state[5] = b[5] ^ (!b[6] & b[7]);
        state[6] = b[6] ^ (!b[7] & b[8]);
        state[7] = b[7] ^ (!b[8] & b[9]);
        state[8] = b[8] ^ (!b[9] & b[5]);
        state[9] = b[9] ^ (!b[5] & b[6]);

        state[10] = b[10] ^ (!b[11] & b[12]);
        state[11] = b[11] ^ (!b[12] & b[13]);
        state[12] = b[12] ^ (!b[13] & b[14]);
        state[13] = b[13] ^ (!b[14] & b[10]);
        state[14] = b[14] ^ (!b[10] & b[11]);

        state[15] = b[15] ^ (!b[16] & b[17]);
        state[16] = b[16] ^ (!b[17] & b[18]);
        state[17] = b[17] ^ (!b[18] & b[19]);
        state[18] = b[18] ^ (!b[19] & b[15]);
        state[19] = b[19] ^ (!b[15] & b[16]);

        state[20] = b[20] ^ (!b[21] & b[22]);
        state[21] = b[21] ^ (!b[22] & b[23]);
        state[22] = b[22] ^ (!b[23] & b[24]);
        state[23] = b[23] ^ (!b[24] & b[20]);
        state[24] = b[24] ^ (!b[20] & b[21]);

        // ι (iota)
        state[0] ^= rc;
    }
}

// ---------------------------------------------------------------------------
// Keccak sponge state (shared by all SHA-3/SHAKE variants)
// ---------------------------------------------------------------------------

/// Maximum rate for any Keccak variant is 168 bytes (SHAKE128).
/// We use 200 (= 25 × 8, the full state size) for the absorb buffer.
#[derive(Clone)]
struct KeccakState {
    state: [u64; 25],
    buf: [u8; 200],
    buf_len: usize,
    rate: usize,
    suffix: u8,
    squeezed: bool,
}

impl Drop for KeccakState {
    fn drop(&mut self) {
        self.state.zeroize();
        self.buf.zeroize();
    }
}

impl KeccakState {
    fn new(rate: usize, suffix: u8) -> Self {
        KeccakState {
            state: [0u64; 25],
            buf: [0u8; 200],
            buf_len: 0,
            rate,
            suffix,
            squeezed: false,
        }
    }

    fn reset(&mut self) {
        self.state = [0u64; 25];
        self.buf_len = 0;
        self.squeezed = false;
    }

    fn absorb(&mut self, data: &[u8]) {
        let mut src = 0;
        // If we have buffered data, fill up to one rate block
        if self.buf_len > 0 {
            let need = self.rate - self.buf_len;
            if data.len() < need {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buf[self.buf_len..self.buf_len + need].copy_from_slice(&data[..need]);
            // XOR buf into state inline (avoids buf.clone() to work around borrow)
            let rate = self.rate;
            for i in 0..rate / 8 {
                let word = u64::from_le_bytes(self.buf[i * 8..(i + 1) * 8].try_into().expect("exact 8-byte slice"));
                self.state[i] ^= word;
            }
            keccak_f1600(&mut self.state);
            src = need;
            self.buf_len = 0;
        }

        // Process full blocks directly from input
        while src + self.rate <= data.len() {
            self.xor_rate_bytes_from(&data[src..]);
            keccak_f1600(&mut self.state);
            src += self.rate;
        }

        // Buffer remaining bytes
        let remaining = data.len() - src;
        if remaining > 0 {
            self.buf[..remaining].copy_from_slice(&data[src..]);
            self.buf_len = remaining;
        }
    }

    /// XOR the first `rate` bytes from a buffer into state.
    fn xor_rate_bytes(&mut self, block: &[u8]) {
        for i in 0..self.rate / 8 {
            let word = u64::from_le_bytes(block[i * 8..(i + 1) * 8].try_into().expect("exact 8-byte slice"));
            self.state[i] ^= word;
        }
        let remaining = self.rate % 8;
        if remaining > 0 {
            let full_words = self.rate / 8;
            let mut last = [0u8; 8];
            last[..remaining].copy_from_slice(&block[full_words * 8..full_words * 8 + remaining]);
            self.state[full_words] ^= u64::from_le_bytes(last);
        }
    }

    /// XOR rate bytes from a slice (which may be longer than rate) into state.
    fn xor_rate_bytes_from(&mut self, data: &[u8]) {
        for i in 0..self.rate / 8 {
            let word = u64::from_le_bytes(data[i * 8..(i + 1) * 8].try_into().expect("exact 8-byte slice"));
            self.state[i] ^= word;
        }
        let remaining = self.rate % 8;
        if remaining > 0 {
            let full_words = self.rate / 8;
            let mut last = [0u8; 8];
            last[..remaining].copy_from_slice(&data[full_words * 8..full_words * 8 + remaining]);
            self.state[full_words] ^= u64::from_le_bytes(last);
        }
    }

    fn xor_block(&mut self, block: &[u8]) {
        for i in 0..block.len() / 8 {
            let word = u64::from_le_bytes(block[i * 8..(i + 1) * 8].try_into().expect("exact 8-byte slice"));
            self.state[i] ^= word;
        }
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
        // Pad: suffix byte + zero padding + 0x80 at end (all on the stack)
        let mut padded = [0u8; 200];
        let blen = self.buf_len;
        padded[..blen].copy_from_slice(&self.buf[..blen]);
        padded[blen] = self.suffix;
        padded[self.rate - 1] |= 0x80;

        self.xor_block(&padded[..self.rate]);
        keccak_f1600(&mut self.state);
        self.buf_len = 0;
        self.squeezed = true;
    }

    /// Write state as 200 little-endian bytes into a caller-provided buffer.
    #[inline]
    fn state_to_bytes_into(&self, out: &mut [u8; 200]) {
        for (i, &lane) in self.state.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&lane.to_le_bytes());
        }
    }

    /// Squeeze output bytes.
    fn squeeze(&mut self, output: &mut [u8]) {
        if !self.squeezed {
            self.pad_and_switch();
        }

        let mut state_bytes = [0u8; 200];
        let mut offset = 0;

        // Handle leftover bytes from a previous squeeze (partial block consumed)
        if self.buf_len > 0 && self.buf_len < self.rate {
            self.state_to_bytes_into(&mut state_bytes);
            let available = self.rate - self.buf_len;
            let copy_len = available.min(output.len());
            output[..copy_len].copy_from_slice(&state_bytes[self.buf_len..self.buf_len + copy_len]);
            offset = copy_len;
            self.buf_len += copy_len;
            if self.buf_len < self.rate {
                return;
            }
            // buf_len == rate: block fully consumed, fall through to main loop
        }

        while offset < output.len() {
            // Permute unless this is the very first block (buf_len == 0 only on first squeeze)
            if self.buf_len > 0 {
                keccak_f1600(&mut self.state);
            }
            self.state_to_bytes_into(&mut state_bytes);
            let remaining = output.len() - offset;
            let copy_len = remaining.min(self.rate);
            output[offset..offset + copy_len].copy_from_slice(&state_bytes[..copy_len]);
            offset += copy_len;
            self.buf_len = copy_len;
        }
    }

    /// Squeeze exactly `output_len` bytes for fixed-output hash.
    fn finalize(&mut self, output: &mut [u8]) {
        if !self.squeezed {
            self.pad_and_switch();
        }
        let mut state_bytes = [0u8; 200];
        self.state_to_bytes_into(&mut state_bytes);
        output.copy_from_slice(&state_bytes[..output.len()]);
    }
}

// ---------------------------------------------------------------------------
// SHA3-224
// ---------------------------------------------------------------------------

/// SHA3-224 output size in bytes.
pub const SHA3_224_OUTPUT_SIZE: usize = 28;

/// SHA3-224 hash context.
#[derive(Clone)]
pub struct Sha3_224 {
    inner: KeccakState,
}

impl Sha3_224 {
    pub fn new() -> Self {
        Sha3_224 {
            inner: KeccakState::new(144, 0x06),
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if self.inner.squeezed {
            return Err(CryptoError::InvalidArg(""));
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
#[derive(Clone)]
pub struct Sha3_256 {
    inner: KeccakState,
}

impl Sha3_256 {
    pub fn new() -> Self {
        Sha3_256 {
            inner: KeccakState::new(136, 0x06),
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if self.inner.squeezed {
            return Err(CryptoError::InvalidArg(""));
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
#[derive(Clone)]
pub struct Sha3_384 {
    inner: KeccakState,
}

impl Sha3_384 {
    pub fn new() -> Self {
        Sha3_384 {
            inner: KeccakState::new(104, 0x06),
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if self.inner.squeezed {
            return Err(CryptoError::InvalidArg(""));
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
#[derive(Clone)]
pub struct Sha3_512 {
    inner: KeccakState,
}

impl Sha3_512 {
    pub fn new() -> Self {
        Sha3_512 {
            inner: KeccakState::new(72, 0x06),
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if self.inner.squeezed {
            return Err(CryptoError::InvalidArg(""));
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
#[derive(Clone)]
pub struct Shake128 {
    inner: KeccakState,
}

impl Shake128 {
    pub fn new() -> Self {
        Shake128 {
            inner: KeccakState::new(168, 0x1F),
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if self.inner.squeezed {
            return Err(CryptoError::InvalidArg(""));
        }
        self.inner.absorb(data);
        Ok(())
    }

    pub fn squeeze(&mut self, output_len: usize) -> Result<Vec<u8>, CryptoError> {
        let mut output = vec![0u8; output_len];
        self.inner.squeeze(&mut output);
        Ok(output)
    }

    /// Squeeze output directly into a caller-provided buffer (zero-allocation).
    pub fn squeeze_into(&mut self, output: &mut [u8]) {
        self.inner.squeeze(output);
    }

    pub fn reset(&mut self) {
        self.inner.reset();
    }
}

// ---------------------------------------------------------------------------
// SHAKE256
// ---------------------------------------------------------------------------

/// SHAKE256 extendable-output function (XOF) context.
#[derive(Clone)]
pub struct Shake256 {
    inner: KeccakState,
}

impl Shake256 {
    pub fn new() -> Self {
        Shake256 {
            inner: KeccakState::new(136, 0x1F),
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if self.inner.squeezed {
            return Err(CryptoError::InvalidArg(""));
        }
        self.inner.absorb(data);
        Ok(())
    }

    pub fn squeeze(&mut self, output_len: usize) -> Result<Vec<u8>, CryptoError> {
        let mut output = vec![0u8; output_len];
        self.inner.squeeze(&mut output);
        Ok(output)
    }

    /// Squeeze output directly into a caller-provided buffer (zero-allocation).
    pub fn squeeze_into(&mut self, output: &mut [u8]) {
        self.inner.squeeze(output);
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
    use hitls_utils::hex::to_hex;

    #[test]
    fn test_sha3_256_empty() {
        let out = Sha3_256::digest(b"").unwrap();
        assert_eq!(
            to_hex(&out),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    #[test]
    fn test_sha3_256_abc() {
        let out = Sha3_256::digest(b"abc").unwrap();
        assert_eq!(
            to_hex(&out),
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
            to_hex(&out),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
             15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
    }

    #[test]
    fn test_sha3_512_abc() {
        let out = Sha3_512::digest(b"abc").unwrap();
        assert_eq!(
            to_hex(&out),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
             10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
    }

    #[test]
    fn test_sha3_224_abc() {
        let out = Sha3_224::digest(b"abc").unwrap();
        assert_eq!(
            to_hex(&out),
            "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
        );
    }

    #[test]
    fn test_sha3_384_abc() {
        let out = Sha3_384::digest(b"abc").unwrap();
        assert_eq!(
            to_hex(&out),
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
            to_hex(&out32),
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
            to_hex(&out32),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
    }

    #[test]
    fn test_sha3_256_reset_reuse() {
        let mut ctx = Sha3_256::new();
        ctx.update(b"abc").unwrap();
        let _d1 = ctx.finish().unwrap();

        // Reset and hash "test" → matches one-shot
        ctx.reset();
        ctx.update(b"test").unwrap();
        let d2 = ctx.finish().unwrap();
        assert_eq!(d2, Sha3_256::digest(b"test").unwrap());

        // Reset and hash empty → matches one-shot empty
        ctx.reset();
        let d_empty = ctx.finish().unwrap();
        assert_eq!(d_empty, Sha3_256::digest(b"").unwrap());
    }

    #[test]
    fn test_shake128_multiple_squeeze() {
        let mut xof = Shake128::new();
        xof.update(b"test").unwrap();
        let s1 = xof.squeeze(32).unwrap();
        let s2 = xof.squeeze(32).unwrap();

        // Two successive squeezes should produce different bytes
        assert_ne!(s1, s2);

        // Concatenation should match a single 64-byte squeeze
        let mut xof2 = Shake128::new();
        xof2.update(b"test").unwrap();
        let s_full = xof2.squeeze(64).unwrap();
        let mut combined = s1;
        combined.extend_from_slice(&s2);
        assert_eq!(combined, s_full);
    }

    #[test]
    fn test_shake128_squeeze_into_matches_squeeze() {
        let mut xof1 = Shake128::new();
        xof1.update(b"squeeze_into test").unwrap();
        let vec_out = xof1.squeeze(504).unwrap();

        let mut xof2 = Shake128::new();
        xof2.update(b"squeeze_into test").unwrap();
        let mut buf = [0u8; 504];
        xof2.squeeze_into(&mut buf);

        assert_eq!(vec_out, buf.as_slice());
    }

    #[test]
    fn test_shake256_squeeze_into_incremental() {
        // Verify incremental squeeze_into matches contiguous squeeze
        let mut xof1 = Shake256::new();
        xof1.update(b"incremental").unwrap();
        let full = xof1.squeeze(272).unwrap();

        let mut xof2 = Shake256::new();
        xof2.update(b"incremental").unwrap();
        let mut part1 = [0u8; 136];
        let mut part2 = [0u8; 136];
        xof2.squeeze_into(&mut part1);
        xof2.squeeze_into(&mut part2);

        assert_eq!(&full[..136], &part1);
        assert_eq!(&full[136..], &part2);
    }

    // -------------------------------------------------------
    // HW↔SW cross-validation: Keccak-f[1600] ARM vs software
    // -------------------------------------------------------

    #[test]
    #[cfg(all(target_arch = "aarch64", has_sha3_keccak_intrinsics))]
    fn test_keccak_arm_matches_software_zero_state() {
        if !std::arch::is_aarch64_feature_detected!("sha3") {
            return;
        }
        let mut state_hw = [0u64; 25];
        let mut state_sw = [0u64; 25];
        unsafe { super::keccak_arm::keccak_f1600_arm(&mut state_hw) };
        keccak_f1600_soft(&mut state_sw);
        assert_eq!(
            state_hw, state_sw,
            "Keccak ARM must match software on zero state"
        );
    }

    #[test]
    #[cfg(all(target_arch = "aarch64", has_sha3_keccak_intrinsics))]
    fn test_keccak_arm_matches_software_nonzero_state() {
        if !std::arch::is_aarch64_feature_detected!("sha3") {
            return;
        }
        let mut state_hw = [0u64; 25];
        let mut state_sw = [0u64; 25];
        for i in 0..25 {
            let v = (i as u64).wrapping_mul(0xDEAD_BEEF_CAFE_BABE);
            state_hw[i] = v;
            state_sw[i] = v;
        }
        unsafe { super::keccak_arm::keccak_f1600_arm(&mut state_hw) };
        keccak_f1600_soft(&mut state_sw);
        assert_eq!(
            state_hw, state_sw,
            "Keccak ARM must match software on non-zero state"
        );
    }

    #[test]
    #[cfg(all(target_arch = "aarch64", has_sha3_keccak_intrinsics))]
    fn test_keccak_arm_matches_software_all_ones() {
        if !std::arch::is_aarch64_feature_detected!("sha3") {
            return;
        }
        let mut state_hw = [u64::MAX; 25];
        let mut state_sw = [u64::MAX; 25];
        unsafe { super::keccak_arm::keccak_f1600_arm(&mut state_hw) };
        keccak_f1600_soft(&mut state_sw);
        assert_eq!(
            state_hw, state_sw,
            "Keccak ARM must match software on all-ones"
        );
    }

    #[test]
    #[cfg(all(target_arch = "aarch64", has_sha3_keccak_intrinsics))]
    fn test_keccak_arm_matches_software_multi_round() {
        if !std::arch::is_aarch64_feature_detected!("sha3") {
            return;
        }
        let mut state_hw = [0u64; 25];
        let mut state_sw = [0u64; 25];
        // Absorb some data then permute multiple times
        state_hw[0] = 0x0102030405060708;
        state_hw[1] = 0xFFEEDDCCBBAA9988;
        state_sw[0] = state_hw[0];
        state_sw[1] = state_hw[1];
        for _ in 0..5 {
            unsafe { super::keccak_arm::keccak_f1600_arm(&mut state_hw) };
            keccak_f1600_soft(&mut state_sw);
        }
        assert_eq!(
            state_hw, state_sw,
            "Keccak ARM must match software after multiple rounds"
        );
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(20))]

            #[test]
            fn prop_sha3_256_incremental_equiv(
                data in prop::collection::vec(any::<u8>(), 0..512),
                split in 0..512usize,
            ) {
                let split = split % (data.len() + 1);
                let one_shot = Sha3_256::digest(&data).unwrap();
                let mut h = Sha3_256::new();
                h.update(&data[..split]).unwrap();
                h.update(&data[split..]).unwrap();
                let incremental = h.finish().unwrap();
                prop_assert_eq!(one_shot, incremental);
            }

            #[test]
            fn prop_shake128_deterministic(
                data in prop::collection::vec(any::<u8>(), 0..256),
            ) {
                let mut s1 = Shake128::new();
                s1.update(&data).unwrap();
                let out1 = s1.squeeze(64).unwrap();
                let mut s2 = Shake128::new();
                s2.update(&data).unwrap();
                let out2 = s2.squeeze(64).unwrap();
                prop_assert_eq!(out1, out2);
            }
        }
    }
}
