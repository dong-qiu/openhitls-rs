//! FrodoKEM utility functions: pack/unpack, encode/decode, noise sampling, CT ops.

use hitls_types::CryptoError;

use super::params::FrodoParams;

/// Pack a matrix of u16 values into bytes with `logq` bits per element.
pub(crate) fn pack(input: &[u16], logq: u8) -> Vec<u8> {
    let n = input.len();
    let out_len = (n * logq as usize).div_ceil(8);
    let mut out = vec![0u8; out_len];

    if logq == 16 {
        // Simple case: 2 bytes per element (little-endian)
        for (i, &val) in input.iter().enumerate() {
            out[2 * i] = val as u8;
            out[2 * i + 1] = (val >> 8) as u8;
        }
    } else if logq == 15 {
        // Bit-pack 8 values into 15 bytes
        let chunks = n / 8;
        for i in 0..chunks {
            let base_in = i * 8;
            let base_out = i * 15;
            let v = &input[base_in..base_in + 8];

            out[base_out] = (v[0]) as u8;
            out[base_out + 1] = ((v[0] >> 8) | (v[1] << 7)) as u8;
            out[base_out + 2] = (v[1] >> 1) as u8;
            out[base_out + 3] = ((v[1] >> 9) | (v[2] << 6)) as u8;
            out[base_out + 4] = (v[2] >> 2) as u8;
            out[base_out + 5] = ((v[2] >> 10) | (v[3] << 5)) as u8;
            out[base_out + 6] = (v[3] >> 3) as u8;
            out[base_out + 7] = ((v[3] >> 11) | (v[4] << 4)) as u8;
            out[base_out + 8] = (v[4] >> 4) as u8;
            out[base_out + 9] = ((v[4] >> 12) | (v[5] << 3)) as u8;
            out[base_out + 10] = (v[5] >> 5) as u8;
            out[base_out + 11] = ((v[5] >> 13) | (v[6] << 2)) as u8;
            out[base_out + 12] = (v[6] >> 6) as u8;
            out[base_out + 13] = ((v[6] >> 14) | (v[7] << 1)) as u8;
            out[base_out + 14] = (v[7] >> 7) as u8;
        }
    }
    out
}

/// Unpack bytes into u16 values with `logq` bits per element.
pub(crate) fn unpack(input: &[u8], count: usize, logq: u8) -> Vec<u16> {
    let mut out = vec![0u16; count];
    let mask = ((1u32 << logq) - 1) as u16;

    if logq == 16 {
        for i in 0..count {
            out[i] = u16::from_le_bytes([input[2 * i], input[2 * i + 1]]);
        }
    } else if logq == 15 {
        let chunks = count / 8;
        for i in 0..chunks {
            let base_in = i * 15;
            let base_out = i * 8;
            let b = &input[base_in..base_in + 15];

            out[base_out] = (b[0] as u16 | ((b[1] as u16) << 8)) & mask;
            out[base_out + 1] = ((b[1] as u16) >> 7 | ((b[2] as u16) << 1)
                | ((b[3] as u16) << 9))
                & mask;
            out[base_out + 2] = ((b[3] as u16) >> 6 | ((b[4] as u16) << 2)
                | ((b[5] as u16) << 10))
                & mask;
            out[base_out + 3] = ((b[5] as u16) >> 5 | ((b[6] as u16) << 3)
                | ((b[7] as u16) << 11))
                & mask;
            out[base_out + 4] = ((b[7] as u16) >> 4 | ((b[8] as u16) << 4)
                | ((b[9] as u16) << 12))
                & mask;
            out[base_out + 5] = ((b[9] as u16) >> 3 | ((b[10] as u16) << 5)
                | ((b[11] as u16) << 13))
                & mask;
            out[base_out + 6] = ((b[11] as u16) >> 2 | ((b[12] as u16) << 6)
                | ((b[13] as u16) << 14))
                & mask;
            out[base_out + 7] = ((b[13] as u16) >> 1 | ((b[14] as u16) << 7)) & mask;
        }
    }
    out
}

/// Encode a message (mu) into a matrix nBar×nBar by placing each bit into
/// the high position of a q-element.
/// Each bit of mu maps to `extracted_bits` positions in logq-bit space.
#[allow(clippy::needless_range_loop)]
pub(crate) fn encode(mu: &[u8], params: &FrodoParams) -> Vec<u16> {
    let n_bar = params.n_bar;
    let count = n_bar * n_bar; // 64
    let mut out = vec![0u16; count];
    let shift = params.logq - params.extracted_bits;

    for i in 0..count {
        // Extract `extracted_bits` bits from mu for position i
        let mut val = 0u16;
        for b in 0..params.extracted_bits {
            let bit_idx = i * params.extracted_bits as usize + b as usize;
            let byte_idx = bit_idx / 8;
            let bit_pos = bit_idx % 8;
            if byte_idx < mu.len() {
                val |= (((mu[byte_idx] >> bit_pos) & 1) as u16) << b;
            }
        }
        out[i] = val << shift;
    }
    out
}

/// Decode a matrix nBar×nBar back to a message (mu).
#[allow(clippy::needless_range_loop)]
pub(crate) fn decode(input: &[u16], params: &FrodoParams) -> Vec<u8> {
    let n_bar = params.n_bar;
    let count = n_bar * n_bar;
    let mu_len = params.mu_len;
    let mut mu = vec![0u8; mu_len];
    let shift = params.logq - params.extracted_bits;
    let mask = (1u16 << params.extracted_bits) - 1;
    let round = 1u16 << (shift - 1); // rounding offset

    for i in 0..count {
        let val = ((input[i].wrapping_add(round)) >> shift) & mask;
        for b in 0..params.extracted_bits {
            let bit_idx = i * params.extracted_bits as usize + b as usize;
            let byte_idx = bit_idx / 8;
            let bit_pos = bit_idx % 8;
            if byte_idx < mu_len {
                mu[byte_idx] |= (((val >> b) & 1) as u8) << bit_pos;
            }
        }
    }
    mu
}

/// Sample noise from the CDF distribution using random bytes from SHAKE output.
/// `r` must have length >= 2 * count.
/// Returns `count` signed noise values stored as u16 (mod q via q_mask).
pub(crate) fn sample_noise(
    r: &[u8],
    count: usize,
    cdf_table: &[u16],
    q_mask: u16,
) -> Vec<u16> {
    let mut out = vec![0u16; count];
    for i in 0..count {
        let sample = u16::from_le_bytes([r[2 * i], r[2 * i + 1]]);
        let prnd = sample >> 1; // 15-bit value
        let sign = sample & 1; // sign bit

        // Count how many CDF entries are less than prnd
        let mut t: u16 = 0;
        for &c in cdf_table {
            t = t.wrapping_add(c.wrapping_sub(prnd) >> 15);
        }

        // Apply sign: if sign=1, negate
        out[i] = (((!sign).wrapping_add(1)) ^ t).wrapping_add(sign) & q_mask;
    }
    out
}

/// Constant-time comparison of two byte slices. Returns 0 if equal, non-zero otherwise.
pub(crate) fn ct_verify(a: &[u8], b: &[u8]) -> u8 {
    use subtle::ConstantTimeEq;
    // ct_eq returns Choice(1) if equal, Choice(0) if not
    let eq: bool = a.ct_eq(b).into();
    if eq { 0 } else { 1 }
}

/// Constant-time select: if selector == 0, return a; else return b.
pub(crate) fn ct_select(a: &[u8], b: &[u8], selector: u8) -> Vec<u8> {
    let mask = (selector as u16).wrapping_neg() as u8; // 0x00 or 0xFF
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| x ^ (mask & (x ^ y)))
        .collect()
}

/// SHAKE-based hash: SHAKE(prefix || input, output_len).
pub(crate) fn shake_hash(
    prefix: &[u8],
    input: &[u8],
    output_len: usize,
    params: &FrodoParams,
) -> Result<Vec<u8>, CryptoError> {
    use crate::sha3::{Shake128, Shake256};
    // FrodoKEM-640 uses SHAKE128; 976/1344 use SHAKE256
    if params.ss_len <= 16 {
        let mut xof = Shake128::new();
        xof.update(prefix)?;
        xof.update(input)?;
        xof.squeeze(output_len)
    } else {
        let mut xof = Shake256::new();
        xof.update(prefix)?;
        xof.update(input)?;
        xof.squeeze(output_len)
    }
}

/// Multi-input SHAKE hash: SHAKE(a || b || c, output_len).
pub(crate) fn shake_hash3(
    a: &[u8],
    b: &[u8],
    c: &[u8],
    output_len: usize,
    params: &FrodoParams,
) -> Result<Vec<u8>, CryptoError> {
    use crate::sha3::{Shake128, Shake256};
    if params.ss_len <= 16 {
        let mut xof = Shake128::new();
        xof.update(a)?;
        xof.update(b)?;
        xof.update(c)?;
        xof.squeeze(output_len)
    } else {
        let mut xof = Shake256::new();
        xof.update(a)?;
        xof.update(b)?;
        xof.update(c)?;
        xof.squeeze(output_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params_640() -> &'static FrodoParams {
        use hitls_types::FrodoKemParamId;
        super::super::params::get_params(FrodoKemParamId::FrodoKem640Shake)
    }

    #[test]
    fn test_pack_unpack_logq15() {
        let params = test_params_640();
        let input: Vec<u16> = (0..64).map(|i| (i * 100) & params.q_mask()).collect();
        let packed = pack(&input, 15);
        let unpacked = unpack(&packed, 64, 15);
        assert_eq!(input, unpacked);
    }

    #[test]
    fn test_pack_unpack_logq16() {
        let input: Vec<u16> = (0..64).map(|i| i * 1000).collect();
        let packed = pack(&input, 16);
        let unpacked = unpack(&packed, 64, 16);
        assert_eq!(input, unpacked);
    }

    #[test]
    fn test_encode_decode() {
        let params = test_params_640();
        let mu = vec![0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A,
                      0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55];
        let encoded = encode(&mu, params);
        let decoded = decode(&encoded, params);
        assert_eq!(mu, decoded);
    }

    #[test]
    fn test_ct_verify_equal() {
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 3, 4];
        assert_eq!(ct_verify(&a, &b), 0);
    }

    #[test]
    fn test_ct_verify_unequal() {
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 3, 5];
        assert_ne!(ct_verify(&a, &b), 0);
    }

    #[test]
    fn test_ct_select() {
        let a = vec![0xAA; 4];
        let b = vec![0xBB; 4];
        assert_eq!(ct_select(&a, &b, 0), vec![0xAA; 4]);
        assert_eq!(ct_select(&a, &b, 1), vec![0xBB; 4]);
    }
}
