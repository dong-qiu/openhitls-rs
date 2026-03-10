//! Goppa code decoding for Classic McEliece.
//!
//! Implements Berlekamp-Massey + Chien search.

use hitls_types::CryptoError;

use super::gf::{self, GfElement};
use super::params::McElieceParams;
use super::poly::GfPoly;
use super::vector::{vec_get_bit, vec_weight};

/// Decode a received vector using the Goppa code.
/// Returns (error_vector, success) where success indicates successful decoding.
pub(crate) fn decode_goppa(
    received: &[u8],
    g: &GfPoly,
    alpha: &[GfElement],
    params: &McElieceParams,
) -> Result<(Vec<u8>, bool), CryptoError> {
    let n = params.n;
    let t = params.t;
    let n_bytes = params.n_bytes;

    // Compute syndrome
    let syndrome = compute_syndrome(received, g, alpha, params)?;

    // Check for zero syndrome
    if syndrome.iter().all(|&s| s == 0) {
        return Ok((vec![0u8; n_bytes], true));
    }

    // Berlekamp-Massey to find error locator polynomial
    let sigma = berlekamp_massey(&syndrome, params)?;

    // Chien search to find error positions
    let mut images = vec![0u16; n];
    GfPoly::eval_roots(&mut images, &sigma.coeffs, alpha, n, t);

    let mut error_positions = Vec::new();
    for j in 0..n {
        if images[j] == 0 {
            error_positions.push(j);
            if error_positions.len() >= t {
                break;
            }
        }
    }

    // Build error vector
    let mut error_vec = vec![0u8; n_bytes];
    for &pos in &error_positions {
        if pos < n {
            super::vector::vec_set_bit(&mut error_vec, pos, 1);
        }
    }

    // Verify: recompute syndrome and check match + weight
    let check_syn = compute_syndrome(&error_vec, g, alpha, params)?;
    let syndromes_match = syndrome.iter().zip(check_syn.iter()).all(|(a, b)| a == b);
    let weight_ok = vec_weight(&error_vec) == t;
    let success = syndromes_match && weight_ok;

    Ok((error_vec, success))
}

/// Compute syndrome from received vector.
fn compute_syndrome(
    received: &[u8],
    g: &GfPoly,
    alpha: &[GfElement],
    params: &McElieceParams,
) -> Result<Vec<GfElement>, CryptoError> {
    let n = params.n;
    let t = params.t;
    let synd_len = t * 2;

    // g_alpha[i] = g(alpha[i]), inv_g2[i] = 1/g(alpha[i])^2
    let mut g_alpha = vec![0u16; n];
    let mut inv_g2 = vec![0u16; n];
    for i in 0..n {
        g_alpha[i] = g.eval(alpha[i]);
        inv_g2[i] = gf::gf_inv(gf::gf_mul(g_alpha[i], g_alpha[i]));
    }

    let mut syndrome = vec![0u16; synd_len];
    for j in 0..synd_len {
        let mut acc: GfElement = 0;
        for i in 0..n {
            if vec_get_bit(received, i) != 0 {
                let alpha_pow = gf::gf_pow(alpha[i], j as i32);
                let term = gf::gf_mul(alpha_pow, inv_g2[i]);
                acc = gf::gf_add(acc, term);
            }
        }
        syndrome[j] = acc;
    }
    Ok(syndrome)
}

/// Berlekamp-Massey algorithm.
/// Returns error locator polynomial sigma.
fn berlekamp_massey(
    syndrome: &[GfElement],
    params: &McElieceParams,
) -> Result<GfPoly, CryptoError> {
    let t = params.t;
    let mut poly_c = GfPoly::new(t);
    let mut poly_b = GfPoly::new(t);
    let mut poly_t = GfPoly::new(t);

    // Initialize: C(x) = 1, B(x) = 1, L = 0, m = 1, b = 1
    poly_c.set_coeff(0, 1);
    poly_b.set_coeff(0, 1);
    let mut lfsr_len: i32 = 0;
    let mut m: i32 = 1;
    let mut b: GfElement = 1;

    for n_idx in 0..(2 * t as i32) {
        // Compute discrepancy
        let mut d = syndrome[n_idx as usize];
        for i in 1..=lfsr_len {
            if i <= poly_c.degree && poly_c.coeffs[i as usize] != 0 && (n_idx - i) >= 0 {
                d = gf::gf_add(
                    d,
                    gf::gf_mul(poly_c.coeffs[i as usize], syndrome[(n_idx - i) as usize]),
                );
            }
        }

        if d == 0 {
            m += 1;
        } else {
            // Save C
            poly_t.coeffs.copy_from_slice(&poly_c.coeffs);
            poly_t.degree = poly_c.degree;

            // C(x) -= (d/b) * x^m * B(x)
            if b != 0 {
                let corr = gf::gf_div(d, b);
                for i in 0..=poly_b.degree.max(0) as usize {
                    if poly_b.coeffs[i] != 0 && (i as i32 + m) <= t as i32 {
                        let term = gf::gf_mul(corr, poly_b.coeffs[i]);
                        let idx = (i as i32 + m) as usize;
                        let cur = if (idx as i32) <= poly_c.degree {
                            poly_c.coeffs[idx]
                        } else {
                            0
                        };
                        poly_c.set_coeff(idx, gf::gf_add(cur, term));
                    }
                }
            }

            if 2 * lfsr_len <= n_idx {
                lfsr_len = n_idx + 1 - lfsr_len;
                poly_b.coeffs.copy_from_slice(&poly_t.coeffs);
                poly_b.degree = poly_t.degree;
                b = d;
                m = 1;
            } else {
                m += 1;
            }
        }
    }

    // Export sigma: sigma[i] = C[t - i]
    let mut sigma = GfPoly::new(t);
    for i in 0..=t {
        sigma.coeffs[i] = poly_c.coeffs[t - i];
    }
    sigma.degree = t as i32;
    // Trim trailing zeros
    while sigma.degree >= 0 && sigma.coeffs[sigma.degree as usize] == 0 {
        sigma.degree -= 1;
    }

    Ok(sigma)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mceliece::params::get_params;
    use hitls_types::algorithm::McElieceParamId;

    fn test_params() -> McElieceParams {
        get_params(McElieceParamId::McEliece6688128)
    }

    /// Helper: create a dummy Goppa polynomial of degree t.
    fn dummy_goppa(t: usize) -> GfPoly {
        let mut g = GfPoly::new(t);
        g.set_coeff(t, 1); // monic x^t
        g.set_coeff(0, 2); // constant term
        g
    }

    #[test]
    fn test_decode_zero_received() {
        let params = test_params();
        let g = dummy_goppa(params.t);
        let alpha: Vec<GfElement> = (0..params.n as u16).collect();
        let received = vec![0u8; params.n_bytes];
        let (error, success) = decode_goppa(&received, &g, &alpha, &params).unwrap();
        assert!(success, "zero received should decode successfully");
        assert!(
            error.iter().all(|&b| b == 0),
            "error vector should be all zeros"
        );
    }

    #[test]
    fn test_berlekamp_massey_zero_syndrome() {
        let params = test_params();
        let syndrome = vec![0u16; 2 * params.t];
        let sigma = berlekamp_massey(&syndrome, &params).unwrap();
        // With zero syndrome, C stays [1,0,...]. sigma[i]=C[t-i], so sigma[t]=1.
        assert_eq!(sigma.coeffs[params.t], 1);
        assert_eq!(sigma.degree, params.t as i32);
    }

    #[test]
    fn test_berlekamp_massey_degree_bounded() {
        let params = test_params();
        let mut syndrome = vec![0u16; 2 * params.t];
        syndrome[0] = 1;
        syndrome[1] = 1;
        let sigma = berlekamp_massey(&syndrome, &params).unwrap();
        assert!(sigma.degree <= params.t as i32, "sigma degree must be <= t");
        assert!(sigma.degree >= 0, "sigma must have non-negative degree");
    }

    #[test]
    fn test_compute_syndrome_zero_received() {
        let params = test_params();
        let g = dummy_goppa(params.t);
        let alpha: Vec<GfElement> = (0..params.n as u16).collect();
        let received = vec![0u8; params.n_bytes];
        let syn = compute_syndrome(&received, &g, &alpha, &params).unwrap();
        assert!(
            syn.iter().all(|&s| s == 0),
            "zero received must give zero syndrome"
        );
    }

    #[test]
    fn test_compute_syndrome_length() {
        let params = test_params();
        let g = dummy_goppa(params.t);
        let alpha: Vec<GfElement> = (0..params.n as u16).collect();
        let received = vec![0u8; params.n_bytes];
        let syn = compute_syndrome(&received, &g, &alpha, &params).unwrap();
        assert_eq!(syn.len(), 2 * params.t, "syndrome must have 2*t elements");
    }
}
