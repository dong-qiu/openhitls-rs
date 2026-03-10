//! Matrix operations for Classic McEliece.
//!
//! Binary matrix stored as rows of byte arrays with bit-level access.

use hitls_types::CryptoError;

use super::gf::{self, GfElement};
use super::params::{McElieceParams, MU};
use super::poly::GfPoly;

/// Binary matrix (row-major, bit-packed).
pub(crate) struct BitMatrix {
    pub data: Vec<u8>,
    pub rows: usize,
    pub cols: usize,
    pub cols_bytes: usize,
}

impl BitMatrix {
    pub fn new(rows: usize, cols: usize) -> Self {
        let cols_bytes = cols.div_ceil(8);
        Self {
            data: vec![0u8; rows * cols_bytes],
            rows,
            cols,
            cols_bytes,
        }
    }

    #[inline]
    pub fn get_bit(&self, row: usize, col: usize) -> u8 {
        let idx = row * self.cols_bytes + (col >> 3);
        (self.data[idx] >> (col & 7)) & 1
    }

    #[inline]
    pub fn set_bit(&mut self, row: usize, col: usize, bit: u8) {
        let idx = row * self.cols_bytes + (col >> 3);
        if bit != 0 {
            self.data[idx] |= 1u8 << (col & 7);
        } else {
            self.data[idx] &= !(1u8 << (col & 7));
        }
    }

    fn row_slice(&self, row: usize) -> &[u8] {
        let start = row * self.cols_bytes;
        &self.data[start..start + self.cols_bytes]
    }

    fn row_slice_mut(&mut self, row: usize) -> &mut [u8] {
        let start = row * self.cols_bytes;
        &mut self.data[start..start + self.cols_bytes]
    }
}

/// Build parity check matrix H from Goppa polynomial and support.
pub(crate) fn build_parity_check_matrix(
    g: &GfPoly,
    support: &[GfElement],
    params: &McElieceParams,
) -> Result<BitMatrix, CryptoError> {
    let t = params.t;
    let m = params.m;
    let n = params.n;
    let mt = params.mt;

    let mut mat_h = BitMatrix::new(mt, n);

    // inv[j] = 1 / g(support[j])
    let mut inv = vec![0u16; n];
    for j in 0..n {
        let a = support[j] & ((1u16 << m) - 1);
        // Evaluate monic polynomial: start at 1 (implicit leading coeff)
        let mut val: GfElement = 1;
        for d in (0..t).rev() {
            val = gf::gf_mul(val, a);
            val ^= g.coeffs[d];
        }
        if val == 0 {
            return Err(CryptoError::McElieceKeygenFail);
        }
        inv[j] = gf::gf_inv(val);
    }

    // Fill rows: for each power i (0..t), for each bit k (0..m)
    for i in 0..t {
        for j in (0..n).step_by(8) {
            let block_len = if j + 8 <= n { 8 } else { n - j };
            for k in 0..m {
                let mut b: u8 = 0;
                for tbit in (0..block_len).rev() {
                    b <<= 1;
                    b |= ((inv[j + tbit] >> k) & 1) as u8;
                }
                let row = i * m + k;
                mat_h.data[row * mat_h.cols_bytes + j / 8] = b;
            }
        }
        // Multiply inv by support for next power
        for j in 0..n {
            let a = support[j] & ((1u16 << m) - 1);
            inv[j] = gf::gf_mul(inv[j], a);
        }
    }

    Ok(mat_h)
}

/// Reduce matrix to systematic form [I | T] via Gaussian elimination.
pub(crate) fn reduce_to_systematic(mat: &mut BitMatrix) -> Result<(), CryptoError> {
    let mt = mat.rows;
    let left_bytes = mt.div_ceil(8);
    let cols_bytes = mat.cols_bytes;

    for byte_idx in 0..left_bytes {
        for bit_in_byte in 0..8 {
            let row = byte_idx * 8 + bit_in_byte;
            if row >= mt {
                break;
            }

            // Find pivot
            for r in (row + 1)..mt {
                let piv_byte = mat.data[row * cols_bytes + byte_idx];
                let cur_byte = mat.data[r * cols_bytes + byte_idx];
                let x = piv_byte ^ cur_byte;
                let m = (x >> bit_in_byte) & 1;
                if m == 0 {
                    continue;
                }
                // XOR rows from byte_idx onward
                xor_row_masked(&mut mat.data, row, r, byte_idx, bit_in_byte, cols_bytes);
            }

            let piv_byte = mat.data[row * cols_bytes + byte_idx];
            if ((piv_byte >> bit_in_byte) & 1) == 0 {
                return Err(CryptoError::McElieceKeygenFail);
            }

            // Eliminate all other rows
            for r in 0..mt {
                if r == row {
                    continue;
                }
                let m = (mat.data[r * cols_bytes + byte_idx] >> bit_in_byte) & 1;
                if m == 0 {
                    continue;
                }
                // XOR entire row
                for c in 0..cols_bytes {
                    let piv_val = mat.data[row * cols_bytes + c];
                    mat.data[r * cols_bytes + c] ^= piv_val;
                }
            }
        }
    }
    Ok(())
}

fn xor_row_masked(
    data: &mut [u8],
    dst_row: usize,
    src_row: usize,
    byte_idx: usize,
    bit_in_byte: usize,
    cols_bytes: usize,
) {
    let lo_mask = (1u8 << bit_in_byte) - 1;
    let dst_off = dst_row * cols_bytes;
    let src_off = src_row * cols_bytes;
    // High bits of current byte
    data[dst_off + byte_idx] ^= data[src_off + byte_idx] & !lo_mask;
    for c in (byte_idx + 1)..cols_bytes {
        data[dst_off + c] ^= data[src_off + c];
    }
}

/// Extract T from systematic matrix [I_mt | T].
pub(crate) fn extract_t(sys_h: &BitMatrix, params: &McElieceParams) -> Vec<u8> {
    let mt = params.mt;
    let k = params.n - mt;
    let t_cols_bytes = k.div_ceil(8);
    let mut t_data = vec![0u8; mt * t_cols_bytes];

    for i in 0..mt {
        for j in 0..k {
            let bit = sys_h.get_bit(i, mt + j);
            if bit != 0 {
                let idx = i * t_cols_bytes + (j >> 3);
                t_data[idx] |= 1u8 << (j & 7);
            }
        }
    }
    t_data
}

/// Semi-systematic Gaussian elimination with column permutation.
pub(crate) fn gauss_semi_systematic(
    mat: &mut BitMatrix,
    pi: &mut [i16],
    params: &McElieceParams,
) -> Result<u64, CryptoError> {
    let mt = params.mt;
    let cols_bytes = mat.cols_bytes;
    let mut pivots: u64 = 0;

    let mt_bytes = mt.div_ceil(8);
    for i in 0..mt_bytes {
        for j in 0..8usize {
            let row = i * 8 + j;
            if row >= mt {
                break;
            }

            // Trigger column permutation at mt - 32
            if row == mt - MU {
                cols_permutation(&mut mat.data, cols_bytes, pi, &mut pivots, mt)?;
            }

            // Lower triangular elimination
            for k in (row + 1)..mt {
                let m = ((mat.data[row * cols_bytes + i] ^ mat.data[k * cols_bytes + i]) >> j) & 1;
                if m == 0 {
                    continue;
                }
                for c in 0..cols_bytes {
                    let src = mat.data[k * cols_bytes + c];
                    mat.data[row * cols_bytes + c] ^= src;
                }
            }

            let pivot_bit = (mat.data[row * cols_bytes + i] >> j) & 1;
            if pivot_bit == 0 {
                return Err(CryptoError::McElieceKeygenFail);
            }

            // Upper triangular elimination
            for k in 0..mt {
                if k == row {
                    continue;
                }
                let m = (mat.data[k * cols_bytes + i] >> j) & 1;
                if m == 0 {
                    continue;
                }
                for c in 0..cols_bytes {
                    let src = mat.data[row * cols_bytes + c];
                    mat.data[k * cols_bytes + c] ^= src;
                }
            }
        }
    }
    Ok(pivots)
}

/// Extract T for semi-systematic form.
pub(crate) fn extract_t_semi(mat: &BitMatrix, params: &McElieceParams) -> Vec<u8> {
    let mt = params.mt;
    let tail = mt & 7;
    let k = params.n - mt;
    let t_bytes = k.div_ceil(8);
    let cols_bytes = mat.cols_bytes;
    let mut t_data = vec![0u8; mt * t_bytes];

    for i in 0..mt {
        let row = &mat.data[i * cols_bytes..i * cols_bytes + cols_bytes];
        let out = &mut t_data[i * t_bytes..(i + 1) * t_bytes];
        let start = mt / 8;
        let end = (params.n - 1) / 8;
        let mut o = 0;
        for j in start..end {
            out[o] = (row[j] >> tail) | (row[j + 1] << (8 - tail));
            o += 1;
        }
        if o < t_bytes {
            out[o] = row[end] >> tail;
        }
    }
    t_data
}

/// Column permutation for semi-systematic form.
fn cols_permutation(
    mat_data: &mut [u8],
    cols_bytes: usize,
    pi: &mut [i16],
    pivots: &mut u64,
    mt: usize,
) -> Result<(), CryptoError> {
    let row = mt - MU;
    let block_idx = row >> 3;
    let tail = row & 7;

    // Extract 32x64 submatrix
    let mut buf = [0u64; MU];
    for i in 0..MU {
        let src_off = (row + i) * cols_bytes + block_idx;
        let mut tmp = [0u8; 9];
        for k in 0..9 {
            if src_off + k < mat_data.len() {
                tmp[k] = mat_data[src_off + k];
            }
        }
        // Shift
        for k in 0..8 {
            tmp[k] = (tmp[k] >> tail) | (tmp[k + 1] << (8 - tail));
        }
        buf[i] = u64::from_le_bytes([
            tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7],
        ]);
    }

    // Gaussian elimination on submatrix
    let mut ctz_list = [0u32; MU];
    *pivots = 0;
    for i in 0..MU {
        let mut t = buf[i];
        for j in (i + 1)..MU {
            t |= buf[j];
        }
        if t == 0 {
            return Err(CryptoError::McElieceKeygenFail);
        }
        let s = t.trailing_zeros();
        ctz_list[i] = s;
        *pivots |= 1u64 << s;

        // Swap to make buf[i] have bit s set
        for j in (i + 1)..MU {
            let mask = ((buf[i] >> s) & 1).wrapping_sub(1); // 0 if set, all-1s if not
            buf[i] ^= buf[j] & mask;
        }
        // Eliminate
        for j in (i + 1)..MU {
            let mask = 0u64.wrapping_sub((buf[j] >> s) & 1);
            buf[j] ^= buf[i] & mask;
        }
    }

    // Update permutation
    for j in 0..MU {
        for k in (j + 1)..64 {
            let same = same_mask(k as u32, ctz_list[j]);
            let d = i64::from(pi[row + j] ^ pi[row + k]) & (same as i64);
            pi[row + j] ^= d as i16;
            pi[row + k] ^= d as i16;
        }
    }

    // Apply column swap to full matrix
    for i in 0..mt {
        let dst_off = i * cols_bytes + block_idx;
        let mut tmp = [0u8; 9];
        for k in 0..9 {
            if dst_off + k < mat_data.len() {
                tmp[k] = mat_data[dst_off + k];
            }
        }
        for k in 0..8 {
            tmp[k] = (tmp[k] >> tail) | (tmp[k + 1] << (8 - tail));
        }
        let mut t = u64::from_le_bytes([
            tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7],
        ]);

        for j in 0..MU {
            let d = ((t >> j) ^ (t >> ctz_list[j])) & 1;
            t ^= d << ctz_list[j];
            t ^= d << j;
        }

        let bytes = t.to_le_bytes();
        // Store back with shift
        let lo_mask = (1u8 << tail) - 1;
        mat_data[dst_off] = (mat_data[dst_off] & lo_mask) | (bytes[0] << tail);
        for k in 1..8 {
            if dst_off + k < mat_data.len() {
                mat_data[dst_off + k] = (bytes[k] << tail) | (bytes[k - 1] >> (8 - tail));
            }
        }
        if dst_off + 8 < mat_data.len() {
            let hi_mask = !((1u8 << tail) - 1);
            mat_data[dst_off + 8] = (mat_data[dst_off + 8] & hi_mask) | (bytes[7] >> (8 - tail));
        }
    }

    Ok(())
}

#[inline]
fn same_mask(k: u32, val: u32) -> u64 {
    let diff = k ^ val;
    let nz = (i64::from(diff) >> 63) | ((-i64::from(diff)) >> 63);
    !(nz as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitmatrix_set_get_bit() {
        let mut m = BitMatrix::new(8, 16);
        assert_eq!(m.rows, 8);
        assert_eq!(m.cols, 16);
        assert_eq!(m.cols_bytes, 2);

        // Initially all zeros
        assert_eq!(m.get_bit(0, 0), 0);
        assert_eq!(m.get_bit(7, 15), 0);

        // Set and get various positions
        m.set_bit(0, 0, 1);
        assert_eq!(m.get_bit(0, 0), 1);
        assert_eq!(m.get_bit(0, 1), 0);

        m.set_bit(3, 7, 1);
        assert_eq!(m.get_bit(3, 7), 1);

        m.set_bit(7, 15, 1);
        assert_eq!(m.get_bit(7, 15), 1);

        // Clear a bit
        m.set_bit(3, 7, 0);
        assert_eq!(m.get_bit(3, 7), 0);

        // Verify row_slice gives correct data
        assert_eq!(m.row_slice(0), &[0x01, 0x00]);
        assert_eq!(m.row_slice(7), &[0x00, 0x80]);
    }

    #[test]
    fn test_bitmatrix_new_all_zeros() {
        let m = BitMatrix::new(16, 32);
        assert_eq!(m.rows, 16);
        assert_eq!(m.cols, 32);
        assert_eq!(m.cols_bytes, 4);
        // All data bytes must be zero
        assert!(m.data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_bitmatrix_identity_diagonal() {
        let n = 8;
        let mut m = BitMatrix::new(n, n);
        for i in 0..n {
            m.set_bit(i, i, 1);
        }
        for i in 0..n {
            for j in 0..n {
                let expected = if i == j { 1 } else { 0 };
                assert_eq!(m.get_bit(i, j), expected, "i={}, j={}", i, j);
            }
        }
    }

    #[test]
    fn test_reduce_to_systematic_on_identity() {
        // 4x8 matrix: [I_4 | 0]
        let mut m = BitMatrix::new(4, 8);
        for i in 0..4 {
            m.set_bit(i, i, 1);
        }
        reduce_to_systematic(&mut m).unwrap();
        // Left 4x4 should still be identity
        for i in 0..4 {
            for j in 0..4 {
                let expected = if i == j { 1 } else { 0 };
                assert_eq!(m.get_bit(i, j), expected, "i={}, j={}", i, j);
            }
        }
        // Right 4x4 should be all zeros
        for i in 0..4 {
            for j in 4..8 {
                assert_eq!(m.get_bit(i, j), 0, "i={}, j={}", i, j);
            }
        }
    }

    #[test]
    fn test_same_mask_equal_returns_all_ones() {
        for &k in &[0u32, 1, 7, 31, 63, 100, u32::MAX] {
            assert_eq!(same_mask(k, k), u64::MAX, "k={}", k);
        }
    }

    #[test]
    fn test_same_mask_unequal_returns_zero() {
        assert_eq!(same_mask(0, 1), 0);
        assert_eq!(same_mask(1, 0), 0);
        assert_eq!(same_mask(5, 10), 0);
        assert_eq!(same_mask(u32::MAX, 0), 0);
    }

    /// Singular matrix → error from reduce_to_systematic.
    #[test]
    fn test_reduce_to_systematic_singular() {
        // 4x8 matrix where row 0 and row 1 are identical → singular
        let mut m = BitMatrix::new(4, 8);
        m.set_bit(0, 0, 1);
        m.set_bit(0, 4, 1);
        m.set_bit(1, 0, 1); // same pivot as row 0
        m.set_bit(1, 4, 1);
        m.set_bit(2, 2, 1);
        m.set_bit(3, 3, 1);
        // After pivot for col 0, rows 0 and 1 will XOR to zero on col 0.
        // Then pivot for col 1 is missing → McElieceKeygenFail.
        let result = reduce_to_systematic(&mut m);
        assert!(result.is_err(), "singular matrix should fail");
    }

    /// Reduce a nontrivial matrix that requires row swapping.
    #[test]
    fn test_reduce_to_systematic_nontrivial() {
        // 3×6 matrix (rows=3, cols=6, cols_bytes=1)
        // Row 0: 010 110 = bits [1,4,5] set
        // Row 1: 100 010 = bits [0,4] set  (but after XOR becomes pivot row 0)
        // Row 2: 001 001 = bits [2,5] set
        // After elimination, left 3×3 should be identity
        let mut m = BitMatrix::new(3, 6);
        // Row 0: bits 1,4,5
        m.set_bit(0, 1, 1);
        m.set_bit(0, 4, 1);
        m.set_bit(0, 5, 1);
        // Row 1: bits 0,4
        m.set_bit(1, 0, 1);
        m.set_bit(1, 4, 1);
        // Row 2: bits 2,5
        m.set_bit(2, 2, 1);
        m.set_bit(2, 5, 1);

        let result = reduce_to_systematic(&mut m);
        assert!(result.is_ok(), "nontrivial matrix should succeed");
        // Left 3×3 should be identity
        for i in 0..3 {
            for j in 0..3 {
                let expected = if i == j { 1 } else { 0 };
                assert_eq!(m.get_bit(i, j), expected, "({i},{j})");
            }
        }
    }

    /// Test extract_t from systematic form.
    #[test]
    fn test_extract_t_from_systematic() {
        use super::super::params::McElieceParams;
        // Create a small "systematic" 4×8 matrix [I_4 | T]
        // with T = [[1,1,0,0],[0,1,1,0],[0,0,1,1],[1,0,0,1]]
        let mut m = BitMatrix::new(4, 8);
        // Identity part
        for i in 0..4 {
            m.set_bit(i, i, 1);
        }
        // T part (cols 4..8)
        m.set_bit(0, 4, 1);
        m.set_bit(0, 5, 1);
        m.set_bit(1, 5, 1);
        m.set_bit(1, 6, 1);
        m.set_bit(2, 6, 1);
        m.set_bit(2, 7, 1);
        m.set_bit(3, 4, 1);
        m.set_bit(3, 7, 1);

        // Use a minimal params struct that has n=8, mt=4
        let params = McElieceParams {
            n: 8,
            t: 4,
            m: 1,
            mt: 4,
            k: 4,
            n_bytes: 1,
            mt_bytes: 1,
            k_bytes: 1,
            private_key_bytes: 0,
            public_key_bytes: 0,
            cipher_bytes: 0,
            shared_key_bytes: 0,
            semi: false,
            pc: false,
        };
        let t_data = extract_t(&m, &params);
        // T submatrix: k=4 columns, 4 rows
        // Row 0: bits 4→0, 5→1 → 0b11 = 0x03
        // Row 1: bits 5→1, 6→2 → 0b110 = 0x06
        // Row 2: bits 6→2, 7→3 → 0b1100 = 0x0C
        // Row 3: bits 4→0, 7→3 → 0b1001 = 0x09
        assert_eq!(t_data[0], 0x03, "T row 0");
        assert_eq!(t_data[1], 0x06, "T row 1");
        assert_eq!(t_data[2], 0x0C, "T row 2");
        assert_eq!(t_data[3], 0x09, "T row 3");
    }

    /// Test xor_row_masked with partial byte mask.
    #[test]
    fn test_xor_row_masked_partial_byte() {
        // 2×2 matrix (2 bytes per row)
        let mut data = vec![0b11001100u8, 0xFF, 0b10101010, 0xAA];
        // XOR row 0 with row 1 from byte_idx=0, bit_in_byte=4
        // lo_mask = 0x0F, so only bits 4..7 of byte 0 get XORed
        xor_row_masked(&mut data, 0, 1, 0, 4, 2);
        // Byte 0 of row 0: 0b11001100 ^ (0b10101010 & 0xF0) = 0b11001100 ^ 0b10100000 = 0b01101100
        assert_eq!(data[0], 0b01101100);
        // Byte 1 of row 0: 0xFF ^ 0xAA = 0x55
        assert_eq!(data[1], 0x55);
    }

    /// Test mutable row slice access.
    #[test]
    fn test_bitmatrix_row_slice_mut() {
        let mut m = BitMatrix::new(2, 16);
        let row1 = m.row_slice_mut(1);
        row1[0] = 0xAB;
        row1[1] = 0xCD;
        assert_eq!(m.row_slice(1), &[0xAB, 0xCD]);
        assert_eq!(m.row_slice(0), &[0x00, 0x00]);
    }
}
