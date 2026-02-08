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
