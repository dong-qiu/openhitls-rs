//! Encoding and error vector generation for Classic McEliece.

use hitls_types::CryptoError;

use super::params::{McElieceParams, Q_1};
use super::vector::{vec_get_bit, vec_set_bit};

/// Encode: compute C = H*e where H = [I_mt | T].
/// The ciphertext is the mt-bit syndrome.
pub(crate) fn encode_vector(
    error_vector: &[u8],
    t_data: &[u8],
    params: &McElieceParams,
) -> Result<Vec<u8>, CryptoError> {
    let mt = params.mt;
    let k = params.n - mt;
    let k_bytes = k.div_ceil(8);
    let n_bytes = params.n_bytes;
    let mut ciphertext = vec![0u8; params.mt_bytes];

    // For each row of H (= each parity bit):
    // bit_i = e_i XOR sum_j(T[i][j] * e[mt+j])
    // The identity part: bit_i = e[i]
    // The T part: XOR with T[i][j] * e[mt+j]
    for i in 0..mt {
        let mut bit = vec_get_bit(error_vector, i);
        let t_row = &t_data[i * k_bytes..(i + 1) * k_bytes];

        // Compute dot product of T row with e[mt..n]
        let mut dot = 0u8;
        #[allow(clippy::needless_range_loop)]
        for byte_idx in 0..k_bytes {
            let e_byte_idx = (mt >> 3) + byte_idx;
            let shift = mt & 7;
            // Get the corresponding error vector byte (shifted by mt bits)
            let mut e_byte = 0u8;
            if shift == 0 {
                if e_byte_idx < n_bytes {
                    e_byte = error_vector[e_byte_idx];
                }
            } else {
                if e_byte_idx < n_bytes {
                    e_byte = error_vector[e_byte_idx] >> shift;
                }
                if e_byte_idx + 1 < n_bytes {
                    e_byte |= error_vector[e_byte_idx + 1] << (8 - shift);
                }
            }
            // Mask last byte
            if byte_idx == k_bytes - 1 {
                let remaining = k - byte_idx * 8;
                if remaining < 8 {
                    e_byte &= (1u8 << remaining) - 1;
                }
            }
            let product = t_row[byte_idx] & e_byte;
            dot ^= product.count_ones() as u8;
        }
        bit ^= dot & 1;
        if bit != 0 {
            vec_set_bit(&mut ciphertext, i, 1);
        }
    }

    Ok(ciphertext)
}

/// Generate a random error vector with exactly t bits set.
pub(crate) fn fixed_weight_vector(params: &McElieceParams) -> Result<Vec<u8>, CryptoError> {
    let t = params.t;
    let n = params.n;
    let n_bytes = params.n_bytes;
    let max_tries = 50;

    for _ in 0..max_tries {
        // Generate 2*t random 16-bit values
        let sample_cnt = 2 * t;
        let rand_bytes_len = sample_cnt * 2;
        let mut rand_bytes = vec![0u8; rand_bytes_len];
        getrandom::getrandom(&mut rand_bytes).map_err(|_| CryptoError::McElieceKeygenFail)?;

        let mut pos_list = Vec::with_capacity(t);

        // Extract valid positions (< n)
        for i in 0..sample_cnt {
            if pos_list.len() >= t {
                break;
            }
            let v = (rand_bytes[i * 2] as u16 | ((rand_bytes[i * 2 + 1] as u16) << 8)) & Q_1;
            if (v as usize) < n {
                pos_list.push(v);
            }
        }

        if pos_list.len() < t {
            continue;
        }

        // Check for duplicates
        let mut duplicate = false;
        'outer: for i in 1..t {
            for j in 0..i {
                if pos_list[i] == pos_list[j] {
                    duplicate = true;
                    break 'outer;
                }
            }
        }

        if duplicate {
            continue;
        }

        // Build error vector
        let mut e = vec![0u8; n_bytes];
        for &pos in pos_list.iter().take(t) {
            vec_set_bit(&mut e, pos as usize, 1);
        }
        return Ok(e);
    }

    Err(CryptoError::McElieceKeygenFail)
}
