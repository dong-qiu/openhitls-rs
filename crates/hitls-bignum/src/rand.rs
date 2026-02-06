//! Random big number generation using OS randomness.

use crate::bignum::BigNum;
use hitls_types::CryptoError;

impl BigNum {
    /// Generate a random BigNum with the specified number of bits.
    ///
    /// If `odd` is true, the least significant bit is forced to 1.
    /// The most significant bit is always set to ensure exactly `bits` bits.
    pub fn random(bits: usize, odd: bool) -> Result<BigNum, CryptoError> {
        if bits == 0 {
            return Ok(BigNum::zero());
        }

        let num_bytes = bits.div_ceil(8);
        let mut buf = vec![0u8; num_bytes];
        getrandom::getrandom(&mut buf).map_err(|_| CryptoError::BnRandGenFail)?;

        // Mask excess bits in the most significant byte
        let excess = num_bytes * 8 - bits;
        if excess > 0 {
            buf[0] &= 0xFF >> excess;
        }

        // Set the MSB to ensure exactly `bits` bits
        let msb_byte = (bits - 1) / 8;
        let msb_bit = (bits - 1) % 8;
        // msb_byte is relative to big-endian layout: byte 0 is MSB
        buf[num_bytes - 1 - msb_byte] |= 1u8 << msb_bit;

        let mut result = BigNum::from_bytes_be(&buf);

        if odd {
            result.limbs_mut()[0] |= 1;
        }

        Ok(result)
    }

    /// Generate a random BigNum uniformly in [1, upper).
    ///
    /// Uses rejection sampling to ensure uniform distribution.
    pub fn random_range(upper: &BigNum) -> Result<BigNum, CryptoError> {
        if upper.is_zero() || upper.is_one() {
            return Err(CryptoError::InvalidArg);
        }

        let bits = upper.bit_len();

        // Rejection sampling: generate random values until one is in range
        loop {
            let num_bytes = bits.div_ceil(8);
            let mut buf = vec![0u8; num_bytes];
            getrandom::getrandom(&mut buf).map_err(|_| CryptoError::BnRandGenFail)?;

            // Mask excess bits
            let excess = num_bytes * 8 - bits;
            if excess > 0 {
                buf[0] &= 0xFF >> excess;
            }

            let candidate = BigNum::from_bytes_be(&buf);

            // Accept if 0 < candidate < upper
            if !candidate.is_zero() && candidate < *upper {
                return Ok(candidate);
            }
        }
    }

    /// Generate a random BigNum uniformly in [0, upper).
    pub fn random_range_inclusive_zero(upper: &BigNum) -> Result<BigNum, CryptoError> {
        if upper.is_zero() {
            return Err(CryptoError::InvalidArg);
        }

        let bits = upper.bit_len();

        loop {
            let num_bytes = bits.div_ceil(8);
            let mut buf = vec![0u8; num_bytes];
            getrandom::getrandom(&mut buf).map_err(|_| CryptoError::BnRandGenFail)?;

            let excess = num_bytes * 8 - bits;
            if excess > 0 {
                buf[0] &= 0xFF >> excess;
            }

            let candidate = BigNum::from_bytes_be(&buf);
            if candidate < *upper {
                return Ok(candidate);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bits() {
        let r = BigNum::random(128, false).unwrap();
        assert_eq!(r.bit_len(), 128);
    }

    #[test]
    fn test_random_odd() {
        let r = BigNum::random(128, true).unwrap();
        assert!(r.is_odd());
        assert_eq!(r.bit_len(), 128);
    }

    #[test]
    fn test_random_range() {
        let upper = BigNum::from_u64(1000);
        for _ in 0..50 {
            let r = BigNum::random_range(&upper).unwrap();
            assert!(r > BigNum::zero());
            assert!(r < upper);
        }
    }

    #[test]
    fn test_random_various_sizes() {
        for bits in [1, 7, 8, 15, 16, 31, 32, 63, 64, 65, 127, 128, 256] {
            let r = BigNum::random(bits, false).unwrap();
            assert_eq!(r.bit_len(), bits, "random({bits}) produced wrong bit_len");
        }
    }
}
