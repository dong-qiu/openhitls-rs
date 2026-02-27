//! NEON-vectorized NTT, INTT, and polynomial utilities for ML-DSA.
//!
//! Processes 4 i32 coefficients per SIMD operation using ARMv8 NEON intrinsics.
//! Montgomery multiplication uses the `vqdmulhq_s32` + `vhsubq_s32` trick.

use core::arch::aarch64::*;

use super::ntt::{fqmul, Poly, N, ZETAS};

const QINV_I32: i32 = 58728449;
const Q_I32: i32 = 8380417;
const F_INV256: i32 = 41978;
const R2_MOD_Q_I32: i32 = 2365951;

/// 4-wide Montgomery multiplication: (a * b * R^{-1}) mod q, where R = 2^32.
///
/// Uses `vqdmulhq_s32` which computes `(2*a*b) >> 32` and `vhsubq_s32`
/// which computes `(a-b)/2`. Combined: `((2*a*b >> 32) - (2*t*Q >> 32)) / 2`
/// = `(a*b - t*Q) >> 32`, which is exactly Montgomery reduction.
#[inline(always)]
unsafe fn fqmul_neon(a: int32x4_t, b: int32x4_t) -> int32x4_t {
    let ab_lo = vmulq_s32(a, b); // a*b mod 2^32
    let ab_hi = vqdmulhq_s32(a, b); // (2*a*b) >> 32
    let qinv = vdupq_n_s32(QINV_I32);
    let q = vdupq_n_s32(Q_I32);
    let t = vmulq_s32(ab_lo, qinv); // ab_lo * QINV mod 2^32
    let tq_hi = vqdmulhq_s32(t, q); // (2*t*Q) >> 32
    vhsubq_s32(ab_hi, tq_hi) // (ab_hi - tq_hi) / 2
}

/// 4-wide Barrett reduction: reduce each lane modulo q.
///
/// Computes t = (a + 2^22) >> 23, then a - t*q.
#[inline(always)]
unsafe fn reduce32_neon(a: int32x4_t) -> int32x4_t {
    let round = vdupq_n_s32(1 << 22);
    let q = vdupq_n_s32(Q_I32);
    let t = vshrq_n_s32::<23>(vaddq_s32(a, round));
    vmlsq_s32(a, t, q) // a - t * q
}

/// Forward NTT using NEON (Cooley-Tukey butterflies).
///
/// # Safety
/// Requires the `neon` target feature.
#[target_feature(enable = "neon")]
pub(super) unsafe fn ntt_neon(a: &mut Poly) {
    let mut k: usize = 0;
    let mut len = 128;

    // Stages with len >= 4: process 4 butterflies at a time
    while len >= 4 {
        let mut start = 0;
        while start < N {
            k += 1;
            let zeta = vdupq_n_s32(ZETAS[k]);
            let mut j = start;
            while j < start + len {
                let rj = vld1q_s32(a[j..].as_ptr());
                let rj_len = vld1q_s32(a[j + len..].as_ptr());
                let t = fqmul_neon(zeta, rj_len);
                vst1q_s32(a[j..].as_mut_ptr(), vaddq_s32(rj, t));
                vst1q_s32(a[j + len..].as_mut_ptr(), vsubq_s32(rj, t));
                j += 4;
            }
            start += 2 * len;
        }
        len >>= 1;
    }

    // Stage len=2: each group has 2 top + 2 bottom = 4 elements
    {
        let mut start = 0;
        while start < N {
            k += 1;
            let zeta = ZETAS[k];
            let v = vld1q_s32(a[start..].as_ptr());
            let top = vget_low_s32(v);
            let bot = vget_high_s32(v);

            let zeta_full = vcombine_s32(vdup_n_s32(zeta), vdup_n_s32(0));
            let bot_full = vcombine_s32(bot, vdup_n_s32(0));
            let t_full = fqmul_neon(zeta_full, bot_full);
            let t = vget_low_s32(t_full);

            vst1q_s32(
                a[start..].as_mut_ptr(),
                vcombine_s32(vadd_s32(top, t), vsub_s32(top, t)),
            );
            start += 4;
        }
    }

    // Stage len=1: pure scalar
    {
        let mut start = 0;
        while start < N {
            k += 1;
            let zeta = ZETAS[k];
            let t = fqmul(zeta, a[start + 1]);
            a[start + 1] = a[start] - t;
            a[start] += t;
            start += 2;
        }
    }
}

/// Inverse NTT using NEON (Gentleman-Sande butterflies).
///
/// # Safety
/// Requires the `neon` target feature.
#[target_feature(enable = "neon")]
pub(super) unsafe fn invntt_neon(a: &mut Poly) {
    let mut k: usize = 256;

    // Stage len=1: pure scalar
    {
        let mut start = 0;
        while start < N {
            k -= 1;
            let zeta = -ZETAS[k];
            let t = a[start];
            a[start] = t + a[start + 1];
            a[start + 1] = fqmul(zeta, t - a[start + 1]);
            start += 2;
        }
    }

    // Stage len=2: half-register trick
    {
        let mut start = 0;
        while start < N {
            k -= 1;
            let neg_zeta = -ZETAS[k];
            let v = vld1q_s32(a[start..].as_ptr());
            let top = vget_low_s32(v);
            let bot = vget_high_s32(v);

            let sum = vadd_s32(top, bot);
            let diff = vsub_s32(top, bot);

            let zeta_full = vcombine_s32(vdup_n_s32(neg_zeta), vdup_n_s32(0));
            let diff_full = vcombine_s32(diff, vdup_n_s32(0));
            let mul = fqmul_neon(zeta_full, diff_full);
            let mul_half = vget_low_s32(mul);

            vst1q_s32(a[start..].as_mut_ptr(), vcombine_s32(sum, mul_half));
            start += 4;
        }
    }

    // Stages with len >= 4: 4-wide vectorized
    let mut len = 4;
    while len <= 128 {
        let mut start = 0;
        while start < N {
            k -= 1;
            let neg_zeta = vdupq_n_s32(-ZETAS[k]);
            let mut j = start;
            while j < start + len {
                let rj = vld1q_s32(a[j..].as_ptr());
                let rj_len = vld1q_s32(a[j + len..].as_ptr());
                vst1q_s32(a[j..].as_mut_ptr(), vaddq_s32(rj, rj_len));
                vst1q_s32(
                    a[j + len..].as_mut_ptr(),
                    fqmul_neon(neg_zeta, vsubq_s32(rj, rj_len)),
                );
                j += 4;
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    // Final normalization by F_INV256
    let f_inv = vdupq_n_s32(F_INV256);
    for i in (0..N).step_by(4) {
        let v = vld1q_s32(a[i..].as_ptr());
        vst1q_s32(a[i..].as_mut_ptr(), fqmul_neon(v, f_inv));
    }
}

/// Vectorized pointwise multiplication: c[i] = fqmul(a[i], b[i]).
///
/// # Safety
/// Requires the `neon` target feature.
#[target_feature(enable = "neon")]
pub(super) unsafe fn pointwise_mul_neon(c: &mut Poly, a: &Poly, b: &Poly) {
    for i in (0..N).step_by(4) {
        let va = vld1q_s32(a[i..].as_ptr());
        let vb = vld1q_s32(b[i..].as_ptr());
        vst1q_s32(c[i..].as_mut_ptr(), fqmul_neon(va, vb));
    }
}

/// Vectorized pointwise multiply-accumulate: c[i] += fqmul(a[i], b[i]).
///
/// # Safety
/// Requires the `neon` target feature.
#[target_feature(enable = "neon")]
pub(super) unsafe fn pointwise_mul_acc_neon(c: &mut Poly, a: &Poly, b: &Poly) {
    for i in (0..N).step_by(4) {
        let vc = vld1q_s32(c[i..].as_ptr());
        let va = vld1q_s32(a[i..].as_ptr());
        let vb = vld1q_s32(b[i..].as_ptr());
        vst1q_s32(c[i..].as_mut_ptr(), vaddq_s32(vc, fqmul_neon(va, vb)));
    }
}

/// Vectorized conversion to Montgomery form: r[i] = fqmul(r[i], R2_MOD_Q).
///
/// # Safety
/// Requires the `neon` target feature.
#[target_feature(enable = "neon")]
pub(super) unsafe fn to_mont_neon(r: &mut Poly) {
    let r2 = vdupq_n_s32(R2_MOD_Q_I32);
    for i in (0..N).step_by(4) {
        let v = vld1q_s32(r[i..].as_ptr());
        vst1q_s32(r[i..].as_mut_ptr(), fqmul_neon(v, r2));
    }
}

/// Vectorized Barrett reduction of all coefficients.
///
/// # Safety
/// Requires the `neon` target feature.
#[target_feature(enable = "neon")]
pub(super) unsafe fn reduce_poly_neon(r: &mut Poly) {
    for i in (0..N).step_by(4) {
        let v = vld1q_s32(r[i..].as_ptr());
        vst1q_s32(r[i..].as_mut_ptr(), reduce32_neon(v));
    }
}

/// Vectorized polynomial addition: r = a + b.
///
/// # Safety
/// Requires the `neon` target feature.
#[target_feature(enable = "neon")]
pub(super) unsafe fn poly_add_neon(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in (0..N).step_by(4) {
        let va = vld1q_s32(a[i..].as_ptr());
        let vb = vld1q_s32(b[i..].as_ptr());
        vst1q_s32(r[i..].as_mut_ptr(), vaddq_s32(va, vb));
    }
}

/// Vectorized polynomial subtraction: r = a - b.
///
/// # Safety
/// Requires the `neon` target feature.
#[target_feature(enable = "neon")]
pub(super) unsafe fn poly_sub_neon(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in (0..N).step_by(4) {
        let va = vld1q_s32(a[i..].as_ptr());
        let vb = vld1q_s32(b[i..].as_ptr());
        vst1q_s32(r[i..].as_mut_ptr(), vsubq_s32(va, vb));
    }
}

/// Expose fqmul_neon for testing.
#[cfg(test)]
#[target_feature(enable = "neon")]
pub(super) unsafe fn fqmul_neon_scalar(a: i32, b: i32) -> i32 {
    let va = vdupq_n_s32(a);
    let vb = vdupq_n_s32(b);
    let result = fqmul_neon(va, vb);
    vgetq_lane_s32::<0>(result)
}
