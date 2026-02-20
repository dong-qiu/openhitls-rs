//! Bit vector utilities for Classic McEliece.

/// Set a bit in a byte vector.
#[inline]
pub(crate) fn vec_set_bit(vec: &mut [u8], bit_idx: usize, value: u8) {
    let byte_idx = bit_idx >> 3;
    let bit_pos = bit_idx & 7;
    if value != 0 {
        vec[byte_idx] |= 1u8 << bit_pos;
    } else {
        vec[byte_idx] &= !(1u8 << bit_pos);
    }
}

/// Get a bit from a byte vector.
#[inline]
pub(crate) fn vec_get_bit(vec: &[u8], bit_idx: usize) -> u8 {
    let byte_idx = bit_idx >> 3;
    let bit_pos = bit_idx & 7;
    (vec[byte_idx] >> bit_pos) & 1
}

/// Compute Hamming weight of a byte vector.
pub(crate) fn vec_weight(vec: &[u8]) -> usize {
    vec.iter().map(|b| b.count_ones() as usize).sum()
}

/// Flip a bit in a byte vector.
#[inline]
pub(crate) fn vec_flip(v: &mut [u8], idx: usize) {
    v[idx >> 3] ^= 1u8 << (idx & 7);
}

/// SWAR popcount for u64.
#[inline]
pub(crate) fn pop64(x: u64) -> u32 {
    x.count_ones()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_bit_roundtrip() {
        let mut buf = vec![0u8; 4];
        // Set bits 0, 7, 15, 31
        vec_set_bit(&mut buf, 0, 1);
        vec_set_bit(&mut buf, 7, 1);
        vec_set_bit(&mut buf, 15, 1);
        vec_set_bit(&mut buf, 31, 1);
        assert_eq!(vec_get_bit(&buf, 0), 1);
        assert_eq!(vec_get_bit(&buf, 7), 1);
        assert_eq!(vec_get_bit(&buf, 15), 1);
        assert_eq!(vec_get_bit(&buf, 31), 1);
        // Unset bits should be 0
        assert_eq!(vec_get_bit(&buf, 1), 0);
        assert_eq!(vec_get_bit(&buf, 8), 0);
        // Clear a set bit
        vec_set_bit(&mut buf, 7, 0);
        assert_eq!(vec_get_bit(&buf, 7), 0);
    }

    #[test]
    fn flip_bit() {
        let mut buf = vec![0u8; 2];
        vec_flip(&mut buf, 3);
        assert_eq!(vec_get_bit(&buf, 3), 1);
        vec_flip(&mut buf, 3);
        assert_eq!(vec_get_bit(&buf, 3), 0);
    }

    #[test]
    fn hamming_weight() {
        assert_eq!(vec_weight(&[0u8; 4]), 0);
        assert_eq!(vec_weight(&[0xFF]), 8);
        assert_eq!(vec_weight(&[0xFF, 0xFF]), 16);
        assert_eq!(vec_weight(&[0x01, 0x80]), 2);
    }

    #[test]
    fn pop64_count_ones() {
        assert_eq!(pop64(0), 0);
        assert_eq!(pop64(1), 1);
        assert_eq!(pop64(u64::MAX), 64);
        assert_eq!(pop64(0xAAAAAAAAAAAAAAAA), 32);
    }
}
