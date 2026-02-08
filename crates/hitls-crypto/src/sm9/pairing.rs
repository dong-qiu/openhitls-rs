//! R-ate pairing on BN256 for SM9.
//!
//! Computes e(P, Q) where P ∈ E(Fp), Q ∈ E'(Fp²).
//! Uses Miller's algorithm with parameter 6t+2 and final exponentiation.

use hitls_types::CryptoError;

use super::curve;
use super::ecp::EcPointG1;
use super::ecp2::EcPointG2;
use super::fp::Fp;
use super::fp12::Fp12;
use super::fp2::Fp2;
use super::fp4::Fp4;

/// Compute the R-ate pairing e(P, Q).
/// P is a point on E(Fp), Q is a point on E'(Fp²).
#[allow(clippy::needless_range_loop)]
pub(crate) fn pairing(p: &EcPointG1, q: &EcPointG2) -> Result<Fp12, CryptoError> {
    if p.is_infinity() || q.is_infinity() {
        return Ok(Fp12::one());
    }

    // Convert P to affine
    let (px, py) = p.to_affine()?;
    // Convert Q to affine
    let (qx, qy) = q.to_affine()?;

    // Miller loop with parameter 6t + 2
    let param = curve::miller_param();
    let param_bytes = param.to_bytes_be();
    let mut param_bits = Vec::new();
    for byte in &param_bytes {
        for bit in (0..8).rev() {
            param_bits.push((byte >> bit) & 1);
        }
    }
    // Strip leading zeros
    while !param_bits.is_empty() && param_bits[0] == 0 {
        param_bits.remove(0);
    }

    // T starts as Q (affine copy into Jacobian)
    let mut t = EcPointG2::from_affine(qx.clone(), qy.clone());
    let mut f = Fp12::one();

    // Main loop (skip the first bit which is 1)
    for i in 1..param_bits.len() {
        // Square f
        f = f.sqr()?;

        // Line evaluation for doubling
        let (line, t_new) = line_double(&t, &px, &py)?;
        f = f.mul(&line)?;
        t = t_new;

        if param_bits[i] == 1 {
            // Line evaluation for addition
            let q_pt = EcPointG2::from_affine(qx.clone(), qy.clone());
            let (line, t_new) = line_add(&t, &q_pt, &px, &py)?;
            f = f.mul(&line)?;
            t = t_new;
        }
    }

    // Frobenius steps: Q1 = π(Q), Q2 = π²(Q) with negation
    let q1 = frobenius_map_g2(&qx, &qy)?;
    let (line, t_new) = line_add(&t, &q1, &px, &py)?;
    f = f.mul(&line)?;
    t = t_new;

    let q2 = frobenius_map_g2_neg(&qx, &qy)?;
    let (line, _t_new) = line_add(&t, &q2, &px, &py)?;
    f = f.mul(&line)?;

    // Final exponentiation
    final_exp(&f)
}

/// Line evaluation for point doubling.
/// Returns (line_value, 2T).
///
/// For M-type sextic twist, the line value at P is:
///   l = (λ·xT - yT) + yP·v - λ·xP·w²
/// where v = w³ in our tower (Fp12 = Fp4[w]/(w³-v)).
///
/// Embedding into Fp12 = c0 + c1·w + c2·w²:
///   c0 = Fp4(λ·xT - yT, Fp2(yP, 0))   — constant + yP in v-slot
///   c1 = Fp4::zero()                     — no w term
///   c2 = Fp4(-λ·xP, Fp2::zero())       — negated in w² slot
fn line_double(t: &EcPointG2, px: &Fp, py: &Fp) -> Result<(Fp12, EcPointG2), CryptoError> {
    let (tx, ty) = t.to_affine()?;

    // Tangent line at T: λ = (3·tx²) / (2·ty)  (since a=0)
    let tx_sq = tx.sqr()?;
    let lambda_num = tx_sq.double()?.add(&tx_sq)?; // 3·tx²
    let lambda_den = ty.double()?; // 2·ty
    let lambda = lambda_num.mul(&lambda_den.inv()?)?;

    // l = (λ·xT - yT) + yP·v - λ·xP·w²
    let lxt_minus_yt = lambda.mul(&tx)?.sub(&ty)?; // λ·xT - yT (in Fp2)
    let yp_fp2 = Fp2::new(py.clone(), Fp::zero()); // yP as Fp2 (v-coefficient)
    let neg_l_xp = lambda.mul_fp(px)?.neg()?; // -λ·xP (in Fp2)

    let c0 = Fp4::new(lxt_minus_yt, yp_fp2);
    let c1 = Fp4::zero();
    let c2 = Fp4::new(neg_l_xp, Fp2::zero());

    let line = Fp12::new(c0, c1, c2);

    // Compute 2T
    let t2 = t.double()?;

    Ok((line, t2))
}

/// Line evaluation for point addition T + Q.
///
/// Same embedding as line_double:
///   l = (λ·xT - yT) + yP·v - λ·xP·w²
/// with λ = (yQ - yT) / (xQ - xT).
fn line_add(
    t: &EcPointG2,
    q: &EcPointG2,
    px: &Fp,
    py: &Fp,
) -> Result<(Fp12, EcPointG2), CryptoError> {
    let (tx, ty) = t.to_affine()?;
    let (qx, qy) = q.to_affine()?;

    if tx == qx {
        if ty == qy {
            return line_double(t, px, py);
        }
        // Vertical line — return trivial
        return Ok((Fp12::one(), EcPointG2::infinity()));
    }

    // Chord through T and Q: λ = (yQ - yT) / (xQ - xT)
    let lambda_num = qy.sub(&ty)?;
    let lambda_den = qx.sub(&tx)?;
    let lambda = lambda_num.mul(&lambda_den.inv()?)?;

    // l = (λ·xT - yT) + yP·v - λ·xP·w²
    let lxt_minus_yt = lambda.mul(&tx)?.sub(&ty)?;
    let yp_fp2 = Fp2::new(py.clone(), Fp::zero());
    let neg_l_xp = lambda.mul_fp(px)?.neg()?;

    let c0 = Fp4::new(lxt_minus_yt, yp_fp2);
    let c1 = Fp4::zero();
    let c2 = Fp4::new(neg_l_xp, Fp2::zero());

    let line = Fp12::new(c0, c1, c2);

    let t_plus_q = t.add(q)?;

    Ok((line, t_plus_q))
}

/// Apply Frobenius map to a G2 point (twist coordinates).
/// Q1 = (x^q · ξ^((q-1)/3), y^q · ξ^((q-1)/2))
/// For SM9 BN256, the Frobenius map on the twist uses specific constants.
pub(crate) fn frobenius_map_g2(qx: &Fp2, qy: &Fp2) -> Result<EcPointG2, CryptoError> {
    // For the sextic twist, the Frobenius endomorphism maps:
    // φ(x, y) = (x^q · ξ^{(q-1)/3}, y^q · ξ^{(q-1)/2})
    // x^q for Fp2 element: conjugate (a0, -a1)
    // Then multiply by precomputed constants.
    //
    // We compute via the general approach: raise coordinates to p-th power
    // and apply twist corrections.

    let p = curve::p();

    // Conjugate = Frobenius on Fp2
    let x_frob = qx.frobenius()?;
    let y_frob = qy.frobenius()?;

    // Frobenius constants for SM9 BN256 twist
    // These are ξ^((p-1)/3) and ξ^((p-1)/2) where ξ = u (the Fp2 generator)
    // For u² = -2, ξ = u
    // ξ^((p-1)/3) and ξ^((p-1)/2) are elements of Fp2
    // We compute them directly
    let xi = Fp2::new(Fp::zero(), Fp::one()); // u
    let p_minus_1 = p.sub(&hitls_bignum::BigNum::from_u64(1));
    let (p_minus_1_div_3, _) = p_minus_1.div_rem(&hitls_bignum::BigNum::from_u64(3))?;
    let (p_minus_1_div_2, _) = p_minus_1.div_rem(&hitls_bignum::BigNum::from_u64(2))?;

    let xi_pow_3 = fp2_pow(&xi, &p_minus_1_div_3)?;
    let xi_pow_2 = fp2_pow(&xi, &p_minus_1_div_2)?;

    // For M-type twist, the induced Frobenius on E'(Fp²) uses
    // the INVERSE constants: α^(-1) and β^(-1), because the
    // untwisting map divides by ξ^(1/3) and ξ^(1/2).
    let alpha_inv = xi_pow_3.inv()?;
    let beta_inv = xi_pow_2.inv()?;

    let new_x = x_frob.mul(&alpha_inv)?;
    let new_y = y_frob.mul(&beta_inv)?;

    Ok(EcPointG2::from_affine(new_x, new_y))
}

/// Frobenius map with negation for Q2 = -π²(Q).
fn frobenius_map_g2_neg(qx: &Fp2, qy: &Fp2) -> Result<EcPointG2, CryptoError> {
    // π²(Q) applies Frobenius twice
    let q1 = frobenius_map_g2(qx, qy)?;
    let (q1x, q1y) = q1.to_affine()?;
    let q2 = frobenius_map_g2(&q1x, &q1y)?;
    let (q2x, q2y) = q2.to_affine()?;
    // Negate y
    Ok(EcPointG2::from_affine(q2x, q2y.neg()?))
}

/// Fp2 exponentiation.
pub(crate) fn fp2_pow(base: &Fp2, exp: &hitls_bignum::BigNum) -> Result<Fp2, CryptoError> {
    let bits = exp.to_bytes_be();
    let mut result = Fp2::one();
    let mut started = false;
    for byte in &bits {
        for bit in (0..8).rev() {
            if started {
                result = result.sqr()?;
            }
            if (byte >> bit) & 1 == 1 {
                if started {
                    result = result.mul(base)?;
                } else {
                    result = base.clone();
                    started = true;
                }
            }
        }
    }
    Ok(result)
}

/// Final exponentiation: f^((p¹²-1)/n).
/// Factored as: (p⁶-1) · (p²+1) · (p⁴-p²+1)/n
fn final_exp(f: &Fp12) -> Result<Fp12, CryptoError> {
    // Step 1: Easy part — f^(p⁶-1)
    // For our tower Fp4[w]/(w³-v), the p⁶-th Frobenius maps:
    //   w → -w  (since w^(p⁶) = -w for BN curves)
    //   v → -v  (since v = w³ and (-w)³ = -v)
    // On Fp4 elements: σ_p^6(a0 + a1·v) = a0 - a1·v (conjugation)
    // On Fp12: σ_p^6(c0 + c1·w + c2·w²) = conj4(c0) - conj4(c1)·w + conj4(c2)·w²
    let f_conj = Fp12::new(
        f.c0.conjugate()?,
        f.c1.conjugate()?.neg()?,
        f.c2.conjugate()?,
    );
    let f_inv = f.inv()?;
    let mut r = f_conj.mul(&f_inv)?; // f^(p⁶-1)

    // Step 2: f^(p²+1)
    let r_frob2 = r.frobenius2()?;
    r = r_frob2.mul(&r)?; // f^((p⁶-1)(p²+1))

    // Step 3: Hard part — f^((p⁴-p²+1)/n)
    // This is the most expensive part. We use the BN-specific
    // formula based on the parameter t.
    r = hard_part(&r)?;

    Ok(r)
}

/// Hard part of final exponentiation for BN curves.
/// Computes f^((p⁴-p²+1)/n) using the Devegili et al. method.
fn hard_part(f: &Fp12) -> Result<Fp12, CryptoError> {
    // For BN curves, (p⁴-p²+1)/n can be decomposed using the trace t.
    // We use: (p⁴-p²+1)/n = (p+1-t) · p³ + (p²-pt+t²-1)
    // But the standard approach is to compute via a sequence of
    // squarings/multiplications with Frobenius.
    //
    // Simple approach: compute the full exponent (p⁴-p²+1)/n directly.
    let p = curve::p();
    let n = curve::order();

    let p2 = p.mul(&p);
    let p4 = p2.mul(&p2);

    // exp = (p⁴ - p² + 1) / n
    let num = p4.sub(&p2).add(&hitls_bignum::BigNum::from_u64(1));
    let (exp, _rem) = num.div_rem(&n)?;

    f.pow(&exp)
}
