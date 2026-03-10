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
    pub fn eval_roots(
        out: &mut [GfElement],
        f: &[GfElement],
        support: &[GfElement],
        n: usize,
        t: usize,
    ) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gfpoly_eval_known_values() {
        // f(x) = x + 1 → coeffs[0]=1, coeffs[1]=1, degree=1
        // In GF(2^m): f(0)=1, f(1)=0 (XOR), f(2)=3, f(3)=2
        let mut f = GfPoly::new(4);
        f.set_coeff(0, 1);
        f.set_coeff(1, 1);
        assert_eq!(f.degree, 1);

        assert_eq!(f.eval(0), 1);
        assert_eq!(f.eval(1), 0); // 1 XOR 1 = 0
        assert_eq!(f.eval(2), 3); // 2 XOR 1 = 3
        assert_eq!(f.eval(3), 2); // 3 XOR 1 = 2

        // Constant polynomial f(x) = 5
        let mut g = GfPoly::new(4);
        g.set_coeff(0, 5);
        assert_eq!(g.eval(0), 5);
        assert_eq!(g.eval(100), 5);

        // Zero polynomial
        let h = GfPoly::new(4);
        assert_eq!(h.degree, -1);
        assert_eq!(h.eval(42), 0);
    }

    #[test]
    fn test_gfpoly_set_coeff_degree_tracking() {
        let mut p = GfPoly::new(8);
        assert_eq!(p.degree, -1);

        // Set degree-3 term
        p.set_coeff(3, 7);
        assert_eq!(p.degree, 3);

        // Set higher degree term
        p.set_coeff(5, 2);
        assert_eq!(p.degree, 5);

        // Set lower degree term — degree should not decrease
        p.set_coeff(1, 4);
        assert_eq!(p.degree, 5);

        // Clear highest term — degree should drop
        p.set_coeff(5, 0);
        assert_eq!(p.degree, 3);

        // Clear remaining terms
        p.set_coeff(3, 0);
        assert_eq!(p.degree, 1);
        p.set_coeff(1, 0);
        assert_eq!(p.degree, -1);
    }

    #[test]
    fn test_gfpoly_eval_roots_matches_eval() {
        // f(x) = 3x^2 + 5x + 7
        let mut f = GfPoly::new(4);
        f.set_coeff(0, 7);
        f.set_coeff(1, 5);
        f.set_coeff(2, 3);

        let support: Vec<GfElement> = vec![0, 1, 2, 3, 10, 100, 255, 8191];
        let mut out = vec![0u16; support.len()];
        let coeffs = [7u16, 5, 3];
        GfPoly::eval_roots(&mut out, &coeffs, &support, support.len(), 2);

        for (i, &x) in support.iter().enumerate() {
            assert_eq!(out[i], f.eval(x), "mismatch at x={}", x);
        }
    }

    #[test]
    fn test_gf_vec_mul_by_identity() {
        // [1, 0, 0, 0] * [a0, a1, a2, a3] should give [a0, a1, a2, a3]
        // since there's no reduction for t=4
        let t = 4;
        let identity = [1u16, 0, 0, 0];
        let input = [42u16, 7, 1000, 3];
        let mut out = [0u16; 4];
        gf_vec_mul(&mut out, &identity, &input, t);
        assert_eq!(out, input);

        // Commutativity: swap arguments
        let mut out2 = [0u16; 4];
        gf_vec_mul(&mut out2, &input, &identity, t);
        assert_eq!(out2, input);
    }

    #[test]
    fn test_gf_vec_mul_constants() {
        // [c, 0, 0, 0] * [d, 0, 0, 0] = [gf_mul(c, d), 0, 0, 0]
        let t = 4;
        let a = [7u16, 0, 0, 0];
        let b = [13u16, 0, 0, 0];
        let mut out = [0u16; 4];
        gf_vec_mul(&mut out, &a, &b, t);
        assert_eq!(out[0], gf::gf_mul(7, 13));
        assert!(out[1..].iter().all(|&v| v == 0));
    }

    #[test]
    fn test_gfpoly_eval_quadratic() {
        // f(x) = x^2 + x + 1
        let mut f = GfPoly::new(4);
        f.set_coeff(0, 1);
        f.set_coeff(1, 1);
        f.set_coeff(2, 1);
        assert_eq!(f.degree, 2);

        // f(0) = 0 + 0 + 1 = 1
        assert_eq!(f.eval(0), 1);
        // f(1) = gf_mul(1,1) ^ 1 ^ 1 = 1 ^ 1 ^ 1 = 1
        assert_eq!(f.eval(1), 1);
        // f(2) = gf_mul(2,2) ^ 2 ^ 1 = 4 ^ 2 ^ 1 = 7
        assert_eq!(f.eval(2), 7);
        // f(3) = gf_mul(3,3) ^ 3 ^ 1 = 5 ^ 3 ^ 1 = 7
        // gf_mul(3,3): 3*3 in GF(2^13). 3 = x+1, (x+1)^2 = x^2+1 = 5
        assert_eq!(f.eval(3), 7);
    }

    #[test]
    fn test_gfpoly_eval_identity_polynomial() {
        // f(x) = x → coeffs[0]=0, coeffs[1]=1
        let mut f = GfPoly::new(4);
        f.set_coeff(1, 1);
        assert_eq!(f.degree, 1);

        // f(k) = k for all k
        for k in [0u16, 1, 2, 5, 100, 255, 1000, 8191] {
            assert_eq!(f.eval(k), k, "f({}) should equal {}", k, k);
        }
    }
}
