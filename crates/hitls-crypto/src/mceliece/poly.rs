//! Polynomial operations over GF(2^13) for Classic McEliece.

use hitls_types::CryptoError;

use super::gf::{self, GfElement};

/// Polynomial over GF(2^13).
#[derive(Clone)]
pub(crate) struct GfPoly {
    pub coeffs: Vec<GfElement>,
    pub degree: i32,
}

impl GfPoly {
    pub fn new(max_degree: usize) -> Self {
        Self {
            coeffs: vec![0; max_degree + 1],
            degree: -1,
        }
    }

    pub fn set_coeff(&mut self, deg: usize, coeff: GfElement) {
        self.coeffs[deg] = coeff;
        if coeff != 0 && deg as i32 > self.degree {
            self.degree = deg as i32;
        } else if coeff == 0 && deg as i32 == self.degree {
            self.degree = -1;
            for i in (0..self.coeffs.len()).rev() {
                if self.coeffs[i] != 0 {
                    self.degree = i as i32;
                    break;
                }
            }
        }
    }

    /// Evaluate polynomial at x using Horner's method.
    pub fn eval(&self, x: GfElement) -> GfElement {
        if self.degree < 0 {
            return 0;
        }
        let mut result = self.coeffs[self.degree as usize];
        if result == 0 {
            return 0;
        }
        for i in (0..self.degree as usize).rev() {
            result = gf::gf_mul(result, x);
            result = gf::gf_add(result, self.coeffs[i]);
        }
        result
    }

    /// Evaluate polynomial given as coefficient slice at all support points.
    /// out[i] = f(L[i]) where f has degree t with f[t] as leading coefficient.
    #[allow(clippy::needless_range_loop)]
    pub fn eval_roots(out: &mut [GfElement], f: &[GfElement], support: &[GfElement], n: usize, t: usize) {
        for i in 0..n {
            let mut r = f[t];
            let a = support[i];
            for k in (0..t).rev() {
                r = gf::gf_add(gf::gf_mul(r, a), f[k]);
            }
            out[i] = r;
        }
    }
}

/// Generate irreducible Goppa polynomial from random bits.
/// Implements the GenPolyOverGF approach: build matrix of powers of f,
/// then Gaussian elimination to find the minimal polynomial.
#[allow(clippy::needless_range_loop)]
pub(crate) fn gen_poly_over_gf(f: &[GfElement], t: usize) -> Result<Vec<GfElement>, CryptoError> {
    // Build (t+1) x t matrix: mat[r][c]
    // mat[0] = [1, 0, ..., 0]
    // mat[1] = f
    // mat[r] = f * mat[r-1] (polynomial multiplication mod fixed reduction poly)
    let mut mat = vec![0u16; (t + 1) * t];
    mat[0] = 1; // mat[0][0] = 1

    // mat[1] = f
    mat[t..t + t].copy_from_slice(&f[..t]);

    // mat[2..t] by polynomial multiplication
    for r in 2..=t {
        let prev_row = mat[(r - 1) * t..r * t].to_vec();
        gf_vec_mul(&mut mat[r * t..(r + 1) * t], &prev_row, f, t);
    }

    // Gaussian elimination
    for j in 0..t {
        // Pivot search with mask-based fix
        for k in (j + 1)..t {
            if mat[j * t + j] == 0 {
                for r in j..=t {
                    mat[r * t + j] ^= mat[r * t + k];
                }
            }
        }
        if mat[j * t + j] == 0 {
            return Err(CryptoError::McElieceKeygenFail);
        }
        let inv = gf::gf_inv(mat[j * t + j]);
        for r in j..=t {
            mat[r * t + j] = gf::gf_mul(mat[r * t + j], inv);
        }
        for k in 0..t {
            if k != j {
                let tk = mat[j * t + k];
                for r in j..=t {
                    mat[r * t + k] ^= gf::gf_mul(mat[r * t + j], tk);
                }
            }
        }
    }

    // Output last row
    let mut out = vec![0u16; t];
    for i in 0..t {
        out[i] = mat[t * t + i];
    }
    Ok(out)
}

/// Vector multiplication in GF((2^m)^t) with reduction by fixed pentanomial.
#[allow(clippy::needless_range_loop)]
fn gf_vec_mul(out: &mut [GfElement], in0: &[GfElement], in1: &[GfElement], t: usize) {
    let prod_len = t * 2 - 1;
    let mut prod = vec![0u16; prod_len];

    // Convolution
    for i in 0..t {
        for j in 0..t {
            prod[i + j] ^= gf::gf_mul(in0[i], in1[j]);
        }
    }

    // Reduce using fixed reduction polynomial
    if t == 128 {
        // x^128 + x^7 + x^2 + x + 1
        for i in ((t)..prod_len).rev() {
            let v = prod[i];
            prod[i - t + 7] ^= v;
            prod[i - t + 2] ^= v;
            prod[i - t + 1] ^= v;
            prod[i - t] ^= v;
        }
    } else if t == 119 {
        // x^119 + x^8 + 1
        for i in ((t)..prod_len).rev() {
            let v = prod[i];
            prod[i - t + 8] ^= v;
            prod[i - t] ^= v;
        }
    }

    out[..t].copy_from_slice(&prod[..t]);
}
