//! CMAC (Cipher-based Message Authentication Code) implementation.
//!
//! CMAC provides message authentication using AES as defined in
//! NIST SP 800-38B and RFC 4493.

use crate::aes::{AesKey, AES_BLOCK_SIZE};
use hitls_types::CryptoError;
use zeroize::Zeroize;

/// CMAC context.
pub struct Cmac {
    cipher: AesKey,
    /// Subkey K1 derived from the block cipher.
    k1: [u8; AES_BLOCK_SIZE],
    /// Subkey K2 derived from the block cipher.
    k2: [u8; AES_BLOCK_SIZE],
    /// CBC chain value.
    state: [u8; AES_BLOCK_SIZE],
    /// Buffer for incomplete block.
    buf: [u8; AES_BLOCK_SIZE],
    buf_len: usize,
}

impl Drop for Cmac {
    fn drop(&mut self) {
        self.k1.zeroize();
        self.k2.zeroize();
        self.state.zeroize();
        self.buf.zeroize();
    }
}

/// Left-shift a 128-bit block by 1 bit; if MSB was 1, XOR with Rb (0x87).
fn dbl(block: &[u8; AES_BLOCK_SIZE]) -> [u8; AES_BLOCK_SIZE] {
    let mut result = [0u8; AES_BLOCK_SIZE];
    let mut carry = 0u8;
    for i in (0..AES_BLOCK_SIZE).rev() {
        result[i] = (block[i] << 1) | carry;
        carry = block[i] >> 7;
    }
    // If MSB of original was set, XOR with Rb
    if block[0] & 0x80 != 0 {
        result[AES_BLOCK_SIZE - 1] ^= 0x87;
    }
    result
}

impl Cmac {
    /// Create a new CMAC instance with the given AES key.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        let cipher = AesKey::new(key)?;

        // L = E_K(0^n)
        let mut l = [0u8; AES_BLOCK_SIZE];
        cipher.encrypt_block(&mut l)?;

        // K1 = dbl(L)
        let k1 = dbl(&l);
        // K2 = dbl(K1)
        let k2 = dbl(&k1);

        l.zeroize();

        Ok(Cmac {
            cipher,
            k1,
            k2,
            state: [0u8; AES_BLOCK_SIZE],
            buf: [0u8; AES_BLOCK_SIZE],
            buf_len: 0,
        })
    }

    /// Feed data into the CMAC computation.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let mut pos = 0;

        // Fill buffer
        if self.buf_len > 0 {
            let want = AES_BLOCK_SIZE - self.buf_len;
            if data.len() <= want {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return Ok(());
            }
            self.buf[self.buf_len..AES_BLOCK_SIZE].copy_from_slice(&data[..want]);
            // Process this block (but only if more data follows — we need
            // to know if this is the last block for finish())
            pos = want;
            self.buf_len = AES_BLOCK_SIZE;
        }

        // Process full blocks, but always keep last block in buffer
        while pos + AES_BLOCK_SIZE < data.len()
            || (pos < data.len() && self.buf_len == AES_BLOCK_SIZE)
        {
            if self.buf_len == AES_BLOCK_SIZE {
                // Process buffered block
                for (s, &b) in self.state.iter_mut().zip(self.buf.iter()) {
                    *s ^= b;
                }
                self.cipher.encrypt_block(&mut self.state)?;
                self.buf_len = 0;
            }

            if pos + AES_BLOCK_SIZE < data.len() {
                // We have at least one more full block after this
                for (s, &d) in self
                    .state
                    .iter_mut()
                    .zip(data[pos..pos + AES_BLOCK_SIZE].iter())
                {
                    *s ^= d;
                }
                self.cipher.encrypt_block(&mut self.state)?;
                pos += AES_BLOCK_SIZE;
            } else {
                break;
            }
        }

        // Buffer remaining data
        if pos < data.len() {
            let remaining = data.len() - pos;
            if self.buf_len == AES_BLOCK_SIZE {
                // Flush buffer first
                for (s, &b) in self.state.iter_mut().zip(self.buf.iter()) {
                    *s ^= b;
                }
                self.cipher.encrypt_block(&mut self.state)?;
                self.buf_len = 0;
            }
            self.buf[..remaining].copy_from_slice(&data[pos..]);
            self.buf_len = remaining;
        }

        Ok(())
    }

    /// Finalize the CMAC computation and write the result to `out`.
    pub fn finish(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() < AES_BLOCK_SIZE {
            return Err(CryptoError::InvalidArg);
        }

        let mut last_block = [0u8; AES_BLOCK_SIZE];

        if self.buf_len == AES_BLOCK_SIZE {
            // Complete block: XOR with K1
            for (lb, (&b, &k)) in last_block
                .iter_mut()
                .zip(self.buf.iter().zip(self.k1.iter()))
            {
                *lb = b ^ k;
            }
        } else {
            // Incomplete block: pad with 10*0 and XOR with K2
            last_block[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            last_block[self.buf_len] = 0x80;
            // Rest is already zero — XOR with K2
            for (lb, &k) in last_block.iter_mut().zip(self.k2.iter()) {
                *lb ^= k;
            }
        }

        // Final CBC-MAC step
        for (s, &b) in self.state.iter_mut().zip(last_block.iter()) {
            *s ^= b;
        }
        self.cipher.encrypt_block(&mut self.state)?;

        out[..AES_BLOCK_SIZE].copy_from_slice(&self.state);
        Ok(())
    }

    /// Reset the CMAC state for reuse with the same key.
    pub fn reset(&mut self) {
        self.state = [0u8; AES_BLOCK_SIZE];
        self.buf = [0u8; AES_BLOCK_SIZE];
        self.buf_len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // RFC 4493 Test Vectors for AES-CMAC with 128-bit key
    // Key: 2b7e1516 28aed2a6 abf71588 09cf4f3c

    #[test]
    fn test_cmac_rfc4493_empty() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let mut cmac = Cmac::new(&key).unwrap();
        cmac.update(&[]).unwrap();
        let mut tag = [0u8; 16];
        cmac.finish(&mut tag).unwrap();
        assert_eq!(hex(&tag), "bb1d6929e95937287fa37d129b756746");
    }

    #[test]
    fn test_cmac_rfc4493_16bytes() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let msg = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a");
        let mut cmac = Cmac::new(&key).unwrap();
        cmac.update(&msg).unwrap();
        let mut tag = [0u8; 16];
        cmac.finish(&mut tag).unwrap();
        assert_eq!(hex(&tag), "070a16b46b4d4144f79bdd9dd04a287c");
    }

    #[test]
    fn test_cmac_rfc4493_40bytes() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let msg = hex_to_bytes(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
        );
        let mut cmac = Cmac::new(&key).unwrap();
        cmac.update(&msg).unwrap();
        let mut tag = [0u8; 16];
        cmac.finish(&mut tag).unwrap();
        assert_eq!(hex(&tag), "dfa66747de9ae63030ca32611497c827");
    }

    #[test]
    fn test_cmac_rfc4493_64bytes() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let msg = hex_to_bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
        let mut cmac = Cmac::new(&key).unwrap();
        cmac.update(&msg).unwrap();
        let mut tag = [0u8; 16];
        cmac.finish(&mut tag).unwrap();
        assert_eq!(hex(&tag), "51f0bebf7e3b9d92fc49741779363cfe");
    }

    #[test]
    fn test_cmac_reset() {
        let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        let mut cmac = Cmac::new(&key).unwrap();

        // First computation
        cmac.update(&[]).unwrap();
        let mut tag1 = [0u8; 16];
        cmac.finish(&mut tag1).unwrap();

        // Reset and do again
        cmac.reset();
        cmac.update(&[]).unwrap();
        let mut tag2 = [0u8; 16];
        cmac.finish(&mut tag2).unwrap();

        assert_eq!(tag1, tag2);
    }
}
