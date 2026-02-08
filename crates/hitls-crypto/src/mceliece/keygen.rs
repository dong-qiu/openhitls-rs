//! Key generation for Classic McEliece.

use hitls_types::CryptoError;

use super::benes;
use super::gf::GfElement;
use super::matrix;
use super::params::{McElieceParams, L_BYTES, Q, Q_1, SIGMA1, SIGMA2};
use super::poly::{self, GfPoly};

/// Internal key generation result.
pub(crate) struct KeyPairInternal {
    pub pk_t: Vec<u8>,            // Public key T matrix
    pub sk_delta: Vec<u8>,        // Random seed
    pub sk_c: u64,                // Pivot mask (semi-systematic only)
    pub sk_g: GfPoly,             // Goppa polynomial
    pub sk_alpha: Vec<GfElement>, // Field ordering
    pub sk_s: Vec<u8>,            // Random string for implicit rejection
    pub sk_controlbits: Vec<u8>,  // Benes network control bits
}

/// Perform seeded key generation.
pub(crate) fn seeded_keygen(
    delta: &[u8],
    params: &McElieceParams,
) -> Result<KeyPairInternal, CryptoError> {
    let s_bit_len = params.n;
    let irr_poly_bit_len = SIGMA1 * params.t;
    let field_ord_bit_len = SIGMA2 * Q;
    let delta_prime_bit_len = 256;

    let prg_output_bit_len = s_bit_len + field_ord_bit_len + irr_poly_bit_len + delta_prime_bit_len;
    let prg_output_byte_len = prg_output_bit_len.div_ceil(8);
    let s_byte_len = s_bit_len.div_ceil(8);
    let field_ord_byte_len = field_ord_bit_len.div_ceil(8);
    let irr_poly_byte_len = irr_poly_bit_len.div_ceil(8);
    let delta_prime_byte_len = delta_prime_bit_len.div_ceil(8);

    let mut current_delta = delta.to_vec();
    let max_attempts = 50;

    for _ in 0..max_attempts {
        // PRG: SHAKE256(64 || delta)
        let prg_output = mceliece_prg(&current_delta, prg_output_byte_len)?;

        // Extract delta' for next iteration
        let delta_prime = prg_output[prg_output_byte_len - delta_prime_byte_len..].to_vec();

        let s_bits = &prg_output[..s_byte_len];
        let field_ord_bits = &prg_output[s_byte_len..s_byte_len + field_ord_byte_len];
        let irr_poly_bits = &prg_output
            [s_byte_len + field_ord_byte_len..s_byte_len + field_ord_byte_len + irr_poly_byte_len];

        // Try to generate key
        match systematic_loop(
            s_bits,
            field_ord_bits,
            irr_poly_bits,
            &current_delta,
            params,
        ) {
            Ok(kp) => return Ok(kp),
            Err(_) => {
                current_delta = delta_prime;
                continue;
            }
        }
    }

    Err(CryptoError::McElieceKeygenFail)
}

/// PRG: SHAKE256(64 || seed)
fn mceliece_prg(seed: &[u8], output_len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut temp_seed = vec![0u8; 33];
    temp_seed[0] = 64; // prefix byte
    let copy_len = seed.len().min(L_BYTES);
    temp_seed[1..1 + copy_len].copy_from_slice(&seed[..copy_len]);

    shake256(&temp_seed, output_len)
}

/// SHAKE256 XOF.
fn shake256(input: &[u8], output_len: usize) -> Result<Vec<u8>, CryptoError> {
    use crate::sha3::Shake256;

    let mut hasher = Shake256::new();
    hasher.update(input)?;
    let output = hasher.squeeze(output_len)?;
    Ok(output)
}

fn systematic_loop(
    s_bits: &[u8],
    field_ord_bits: &[u8],
    irr_poly_bits: &[u8],
    delta: &[u8],
    params: &McElieceParams,
) -> Result<KeyPairInternal, CryptoError> {
    // Generate Goppa polynomial
    let g = generate_irreducible_poly(irr_poly_bits, params)?;

    // Generate field ordering
    let alpha = generate_field_ordering(field_ord_bits, params)?;

    // Validate: g(alpha[i]) != 0 for i < n
    #[allow(clippy::needless_range_loop)]
    for i in 0..params.n {
        if g.eval(alpha[i]) == 0 {
            return Err(CryptoError::McElieceKeygenFail);
        }
    }

    // Build pi from alpha (bit-reversed)
    let mut pi = vec![0i16; Q];
    for j in 0..params.n {
        pi[j] = bitrev_u16(alpha[j], params.m) as i16;
    }
    for i in params.n..Q {
        pi[i] = bitrev_u16(alpha[i], params.m) as i16;
    }

    // Build parity check matrix
    let mut mat_h = matrix::build_parity_check_matrix(&g, &alpha, params)?;

    let (pk_t, c) = if params.semi {
        // Semi-systematic
        let pivots = matrix::gauss_semi_systematic(&mut mat_h, &mut pi, params)?;
        let t_data = matrix::extract_t_semi(&mat_h, params);
        (t_data, pivots)
    } else {
        // Standard systematic
        matrix::reduce_to_systematic(&mut mat_h)?;
        let t_data = matrix::extract_t(&mat_h, params);
        (t_data, 0u64)
    };

    // Generate control bits from pi
    let controlbits = benes::cbits_from_perm(&pi, params.m, Q)?;

    // Random string s
    let mut sk_s = vec![0u8; params.n_bytes];
    sk_s[..params.n_bytes.min(s_bits.len())]
        .copy_from_slice(&s_bits[..params.n_bytes.min(s_bits.len())]);

    let mut sk_delta = vec![0u8; L_BYTES];
    sk_delta[..delta.len().min(L_BYTES)].copy_from_slice(&delta[..delta.len().min(L_BYTES)]);

    Ok(KeyPairInternal {
        pk_t,
        sk_delta,
        sk_c: c,
        sk_g: g,
        sk_alpha: alpha,
        sk_s,
        sk_controlbits: controlbits,
    })
}

fn generate_irreducible_poly(
    random_bits: &[u8],
    params: &McElieceParams,
) -> Result<GfPoly, CryptoError> {
    let t = params.t;
    let m = params.m;

    // Read t little-endian 16-bit values, mask to m bits
    let mut f = vec![0u16; t];
    for i in 0..t {
        if i * 2 + 1 < random_bits.len() {
            let le = random_bits[2 * i] as u16 | ((random_bits[2 * i + 1] as u16) << 8);
            f[i] = le & ((1u16 << m) - 1);
        }
    }
    if f[t - 1] == 0 {
        f[t - 1] = 1;
    }

    let gl = poly::gen_poly_over_gf(&f, t)?;

    // Form monic g(x) = x^t + sum gl[i] x^i
    let mut g = GfPoly::new(t);
    #[allow(clippy::needless_range_loop)]
    for i in 0..t {
        g.set_coeff(i, gl[i]);
    }
    g.set_coeff(t, 1);

    Ok(g)
}

fn generate_field_ordering(
    random_bits: &[u8],
    params: &McElieceParams,
) -> Result<Vec<GfElement>, CryptoError> {
    let m = params.m;

    // Read Q 32-bit values
    let mut pairs: Vec<(u32, u16)> = Vec::with_capacity(Q);
    for i in 0..Q {
        let off = i * 4;
        if off + 3 < random_bits.len() {
            let val = u32::from_le_bytes([
                random_bits[off],
                random_bits[off + 1],
                random_bits[off + 2],
                random_bits[off + 3],
            ]);
            pairs.push((val, i as u16));
        } else {
            pairs.push((0, i as u16));
        }
    }

    // Check for duplicates
    let mut sorted_vals: Vec<u32> = pairs.iter().map(|p| p.0).collect();
    sorted_vals.sort();
    for i in 0..sorted_vals.len() - 1 {
        if sorted_vals[i] == sorted_vals[i + 1] {
            return Err(CryptoError::McElieceKeygenFail);
        }
    }

    // Sort by value
    pairs.sort_by_key(|p| p.0);

    let mut alpha = vec![0u16; Q];
    for i in 0..Q {
        let v = pairs[i].1 & Q_1;
        alpha[i] = bitrev_u16(v, m);
    }

    Ok(alpha)
}

fn bitrev_u16(x: u16, m: usize) -> u16 {
    let mut r: u16 = 0;
    for j in 0..m {
        r = (r << 1) | ((x >> j) & 1);
    }
    r & ((1u16 << m) - 1)
}
