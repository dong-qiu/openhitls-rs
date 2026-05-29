//! FrodoKEM utility functions: pack/unpack, encode/decode, noise sampling, CT ops.

use hitls_types::CryptoError;

use super::params::FrodoParams;

/// Pack a matrix of u16 values into bytes with `logq` bits per element.
pub(crate) fn pack(input: &[u16], logq: u8) -> Vec<u8> {
    let n = input.len();
    let out_len = (n * logq as usize).div_ceil(8);
    let mut out = vec![0u8; out_len];

    // MSB-first / big-endian bit packing, matching the FrodoKEM reference
    // (`FrodoCommonPack`). The earlier LSB-first packing was self-consistent
    // with the old `unpack` but NOT reference-compatible — see I145.
    if logq == 16 {
        for (i, &val) in input.iter().enumerate() {
            out[2 * i] = (val >> 8) as u8;
            out[2 * i + 1] = (val & 0xFF) as u8;
        }
    } else if logq == 15 {
        // Pack 8 values (15 bits each) into 15 bytes.
        let chunks = n / 8;
        for c in 0..chunks {
            let base_in = c * 8;
            let base_out = c * 15;
            let v = &input[base_in..base_in + 8];
            let mut a = [0u16; 8];
            for k in 0..8 {
                a[k] = v[k] & 0x7FFF;
            }
            let a7 = a[7];
            a[0] = (a[0] << 1) | (a[1] >> 14);
            a[1] = (a[1] << 2) | (a[2] >> 13);
            a[2] = (a[2] << 3) | (a[3] >> 12);
            a[3] = (a[3] << 4) | (a[4] >> 11);
            a[4] = (a[4] << 5) | (a[5] >> 10);
            a[5] = (a[5] << 6) | (a[6] >> 9);
            a[6] = (a[6] << 7) | (a7 >> 8);
            for k in 0..7 {
                out[base_out + 2 * k] = (a[k] >> 8) as u8;
                out[base_out + 2 * k + 1] = (a[k] & 0xFF) as u8;
            }
            out[base_out + 14] = (a7 & 0xFF) as u8;
        }
    }
    out
}

/// Unpack bytes into u16 values with `logq` bits per element.
pub(crate) fn unpack(input: &[u8], count: usize, logq: u8) -> Vec<u16> {
    let mut out = vec![0u16; count];

    // MSB-first / big-endian bit unpacking, matching the FrodoKEM reference
    // (`FrodoCommonUnpack`) — inverse of the `pack` above.
    if logq == 16 {
        for i in 0..count {
            out[i] = (u16::from(input[2 * i]) << 8) | u16::from(input[2 * i + 1]);
        }
    } else if logq == 15 {
        let chunks = count / 8;
        for c in 0..chunks {
            let bi = c * 15;
            let bo = c * 8;
            let b = &input[bi..bi + 15];
            let u = |x: u8| u16::from(x);
            out[bo] = (u(b[0]) << 7) | (u(b[1]) >> 1);
            out[bo + 1] = ((u(b[1]) & 0x01) << 14) | (u(b[2]) << 6) | (u(b[3]) >> 2);
            out[bo + 2] = ((u(b[3]) & 0x03) << 13) | (u(b[4]) << 5) | (u(b[5]) >> 3);
            out[bo + 3] = ((u(b[5]) & 0x07) << 12) | (u(b[6]) << 4) | (u(b[7]) >> 4);
            out[bo + 4] = ((u(b[7]) & 0x0F) << 11) | (u(b[8]) << 3) | (u(b[9]) >> 5);
            out[bo + 5] = ((u(b[9]) & 0x1F) << 10) | (u(b[10]) << 2) | (u(b[11]) >> 6);
            out[bo + 6] = ((u(b[11]) & 0x3F) << 9) | (u(b[12]) << 1) | (u(b[13]) >> 7);
            out[bo + 7] = ((u(b[13]) & 0x7F) << 8) | u(b[14]);
        }
    }
    out
}

/// Encode a message (mu) into a matrix nBar×nBar by placing each bit into
/// the high position of a q-element.
/// Each bit of mu maps to `extracted_bits` positions in logq-bit space.
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
                val |= u16::from((mu[byte_idx] >> bit_pos) & 1) << b;
            }
        }
        out[i] = val << shift;
    }
    out
}

/// Decode a matrix nBar×nBar back to a message (mu).
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
pub(crate) fn sample_noise(r: &[u8], count: usize, cdf_table: &[u16], q_mask: u16) -> Vec<u16> {
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
    if eq {
        0
    } else {
        1
    }
}

/// Constant-time select: if selector == 0, return a; else return b.
pub(crate) fn ct_select(a: &[u8], b: &[u8], selector: u8) -> Vec<u8> {
    let mask = u16::from(selector).wrapping_neg() as u8; // 0x00 or 0xFF
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
        let mu = vec![
            0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33,
            0x44, 0x55,
        ];
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
