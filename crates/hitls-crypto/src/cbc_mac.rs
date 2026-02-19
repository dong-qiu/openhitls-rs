//! CBC-MAC with SM4 block cipher.
//!
//! Implements the CBC-MAC algorithm using SM4 as the underlying cipher.
//! Uses zero-padding for the final incomplete block.
//! Output is always 16 bytes (one SM4 block).

use crate::sm4::{Sm4Key, SM4_BLOCK_SIZE, SM4_KEY_SIZE};
use hitls_types::CryptoError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// CBC-MAC context using SM4 as the underlying block cipher.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CbcMacSm4 {
    /// SM4 cipher key.
    cipher: Sm4Key,
    /// CBC chain state (accumulates XOR'd encrypted blocks).
    state: [u8; SM4_BLOCK_SIZE],
    /// Buffer for incomplete block data.
    buf: [u8; SM4_BLOCK_SIZE],
    /// Number of bytes in the buffer.
    buf_len: usize,
    /// Whether the context is ready for use (false after finish).
    active: bool,
}

impl CbcMacSm4 {
    /// Create a new CBC-MAC-SM4 context with the given key.
    ///
    /// Key must be exactly 16 bytes (128 bits).
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != SM4_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: SM4_KEY_SIZE,
                got: key.len(),
            });
        }
        let cipher = Sm4Key::new(key)?;
        Ok(Self {
            cipher,
            state: [0u8; SM4_BLOCK_SIZE],
            buf: [0u8; SM4_BLOCK_SIZE],
            buf_len: 0,
            active: true,
        })
    }

    /// Feed data into the CBC-MAC computation.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if !self.active {
            return Err(CryptoError::InvalidArg);
        }

        let mut offset = 0;

        // If we have buffered data, try to complete a block
        if self.buf_len > 0 {
            let need = SM4_BLOCK_SIZE - self.buf_len;
            if data.len() < need {
                // Not enough to complete the block — just buffer
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return Ok(());
            }
            // Complete the block
            self.buf[self.buf_len..SM4_BLOCK_SIZE].copy_from_slice(&data[..need]);
            self.process_block()?;
            self.buf_len = 0;
            offset = need;
        }

        // Process full blocks
        while offset + SM4_BLOCK_SIZE <= data.len() {
            self.buf[..SM4_BLOCK_SIZE].copy_from_slice(&data[offset..offset + SM4_BLOCK_SIZE]);
            self.process_block()?;
            offset += SM4_BLOCK_SIZE;
        }

        // Buffer remaining bytes
        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buf[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }

        Ok(())
    }

    /// Finalize the CBC-MAC computation and write the MAC to `out`.
    ///
    /// `out` must be at least 16 bytes.
    pub fn finish(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        if !self.active {
            return Err(CryptoError::InvalidArg);
        }
        if out.len() < SM4_BLOCK_SIZE {
            return Err(CryptoError::BufferTooSmall {
                need: SM4_BLOCK_SIZE,
                got: out.len(),
            });
        }

        // Zero-pad the final incomplete block
        if self.buf_len < SM4_BLOCK_SIZE {
            for i in self.buf_len..SM4_BLOCK_SIZE {
                self.buf[i] = 0;
            }
        }

        // Process the final (possibly padded) block
        self.process_block()?;

        // Output the MAC
        out[..SM4_BLOCK_SIZE].copy_from_slice(&self.state);
        self.active = false;

        Ok(())
    }

    /// Reset the context for reuse with the same key.
    pub fn reset(&mut self) {
        self.state = [0u8; SM4_BLOCK_SIZE];
        self.buf = [0u8; SM4_BLOCK_SIZE];
        self.buf_len = 0;
        self.active = true;
    }

    /// Returns the output size (always 16 bytes for SM4).
    pub fn output_size(&self) -> usize {
        SM4_BLOCK_SIZE
    }

    /// Process one complete block: state = E_K(state XOR block).
    fn process_block(&mut self) -> Result<(), CryptoError> {
        // XOR buffer into state
        for i in 0..SM4_BLOCK_SIZE {
            self.state[i] ^= self.buf[i];
        }
        // Encrypt state in-place
        self.cipher.encrypt_block(&mut self.state)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbc_mac_sm4_single_block() {
        // Single 16-byte block: MAC = E_K(0 XOR block) = E_K(block)
        let key = [0x01u8; SM4_KEY_SIZE];
        let data = [0x02u8; SM4_BLOCK_SIZE];

        let mut mac = CbcMacSm4::new(&key).unwrap();
        mac.update(&data).unwrap();
        let mut out = [0u8; SM4_BLOCK_SIZE];
        mac.finish(&mut out).unwrap();

        // Verify by computing E_K(data) directly
        let cipher = Sm4Key::new(&key).unwrap();
        let mut expected = data;
        cipher.encrypt_block(&mut expected).unwrap();
        // For a single full block, the final pass pads an empty buffer with zeros
        // and processes it: state = E_K(E_K(data) XOR 0) = E_K(E_K(data))
        // Actually, after update processes the full block, buf_len=0.
        // In finish, the final block is all-zeros (buf_len=0, zero-padded).
        // So final = E_K(state XOR zeros) = E_K(state)
        let mut expected2 = expected;
        cipher.encrypt_block(&mut expected2).unwrap();
        assert_eq!(out, expected2);
    }

    #[test]
    fn test_cbc_mac_sm4_empty_message() {
        // Empty message: just the zero-padded empty block
        // MAC = E_K(0 XOR 0) = E_K(0)
        let key = [0xAAu8; SM4_KEY_SIZE];

        let mut mac = CbcMacSm4::new(&key).unwrap();
        let mut out = [0u8; SM4_BLOCK_SIZE];
        mac.finish(&mut out).unwrap();

        // Expected: E_K(zeros)
        let cipher = Sm4Key::new(&key).unwrap();
        let mut expected = [0u8; SM4_BLOCK_SIZE];
        cipher.encrypt_block(&mut expected).unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn test_cbc_mac_sm4_multi_block() {
        // Two full blocks
        let key = [0x55u8; SM4_KEY_SIZE];
        let block1 = [0x11u8; SM4_BLOCK_SIZE];
        let block2 = [0x22u8; SM4_BLOCK_SIZE];

        let mut data = Vec::new();
        data.extend_from_slice(&block1);
        data.extend_from_slice(&block2);

        let mut mac = CbcMacSm4::new(&key).unwrap();
        mac.update(&data).unwrap();
        let mut out = [0u8; SM4_BLOCK_SIZE];
        mac.finish(&mut out).unwrap();

        // Manual computation:
        // state0 = 0
        // state1 = E_K(state0 XOR block1) = E_K(block1)
        // state2 = E_K(state1 XOR block2)
        // final pad block = zeros (buf_len=0)
        // MAC = E_K(state2 XOR zeros) = E_K(state2)
        let cipher = Sm4Key::new(&key).unwrap();
        let mut state = block1;
        cipher.encrypt_block(&mut state).unwrap();
        for i in 0..SM4_BLOCK_SIZE {
            state[i] ^= block2[i];
        }
        cipher.encrypt_block(&mut state).unwrap();
        // final zero-padded block
        cipher.encrypt_block(&mut state).unwrap();
        assert_eq!(out, state);
    }

    #[test]
    fn test_cbc_mac_sm4_partial_block() {
        // Partial block: 10 bytes → zero-padded to 16
        let key = [0xBBu8; SM4_KEY_SIZE];
        let data = [0xCC; 10];

        let mut mac = CbcMacSm4::new(&key).unwrap();
        mac.update(&data).unwrap();
        let mut out = [0u8; SM4_BLOCK_SIZE];
        mac.finish(&mut out).unwrap();

        // Expected: padded = [0xCC]*10 + [0]*6
        // MAC = E_K(0 XOR padded) = E_K(padded)
        let cipher = Sm4Key::new(&key).unwrap();
        let mut padded = [0u8; SM4_BLOCK_SIZE];
        padded[..10].copy_from_slice(&data);
        cipher.encrypt_block(&mut padded).unwrap();
        assert_eq!(out, padded);
    }

    #[test]
    fn test_cbc_mac_sm4_incremental_update() {
        // Feed data byte-by-byte should produce same result as bulk
        let key = [0x42u8; SM4_KEY_SIZE];
        let data = [0x13u8; 20]; // 1 full block + 4 bytes partial

        let mut mac1 = CbcMacSm4::new(&key).unwrap();
        mac1.update(&data).unwrap();
        let mut out1 = [0u8; SM4_BLOCK_SIZE];
        mac1.finish(&mut out1).unwrap();

        let mut mac2 = CbcMacSm4::new(&key).unwrap();
        for &b in &data {
            mac2.update(&[b]).unwrap();
        }
        let mut out2 = [0u8; SM4_BLOCK_SIZE];
        mac2.finish(&mut out2).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_cbc_mac_sm4_reset() {
        let key = [0xDDu8; SM4_KEY_SIZE];
        let data = [0xEE; 16];

        let mut mac = CbcMacSm4::new(&key).unwrap();
        mac.update(&data).unwrap();
        let mut out1 = [0u8; SM4_BLOCK_SIZE];
        mac.finish(&mut out1).unwrap();

        // Reset and compute again — should get same result
        mac.reset();
        mac.update(&data).unwrap();
        let mut out2 = [0u8; SM4_BLOCK_SIZE];
        mac.finish(&mut out2).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_cbc_mac_sm4_invalid_key_length() {
        assert!(CbcMacSm4::new(&[0u8; 15]).is_err());
        assert!(CbcMacSm4::new(&[0u8; 17]).is_err());
        assert!(CbcMacSm4::new(&[]).is_err());
    }

    #[test]
    fn test_cbc_mac_sm4_output_size() {
        let mac = CbcMacSm4::new(&[0u8; SM4_KEY_SIZE]).unwrap();
        assert_eq!(mac.output_size(), 16);
    }

    #[test]
    fn test_cbc_mac_sm4_buffer_too_small() {
        let mut mac = CbcMacSm4::new(&[0u8; SM4_KEY_SIZE]).unwrap();
        let mut out = [0u8; 8]; // too small
        assert!(mac.finish(&mut out).is_err());
    }

    #[test]
    fn test_cbc_mac_sm4_deterministic() {
        let key = [0x77u8; SM4_KEY_SIZE];
        let data = b"Hello CBC-MAC SM4!";

        let mut mac1 = CbcMacSm4::new(&key).unwrap();
        mac1.update(data).unwrap();
        let mut out1 = [0u8; SM4_BLOCK_SIZE];
        mac1.finish(&mut out1).unwrap();

        let mut mac2 = CbcMacSm4::new(&key).unwrap();
        mac2.update(data).unwrap();
        let mut out2 = [0u8; SM4_BLOCK_SIZE];
        mac2.finish(&mut out2).unwrap();

        assert_eq!(out1, out2);
    }
}
