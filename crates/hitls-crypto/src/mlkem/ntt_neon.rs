//! NEON-vectorized NTT, INTT, basemul, and polynomial utilities for ML-KEM.
//!
//! Processes 8 i16 coefficients per SIMD operation using ARMv8 NEON intrinsics.
//! Montgomery multiplication uses the `vqdmulhq_s16` + `vhsubq_s16` trick.

use core::arch::aarch64::*;

use super::ntt::{barrett_reduce, fqmul, Poly, N, ZETAS};

const QINV_I16: i16 = -3327;
const Q_I16: i16 = 3329;
const F_INV128: i16 = 1441;
const R2_MOD_Q: i16 = 1353;

/// 8-wide Montgomery multiplication: (a * b * R^{-1}) mod q.
///
/// Uses `vqdmulhq_s16` which computes `(2*a*b) >> 16` and `vhsubq_s16`
/// which computes `(a-b)/2`. Combined: `((2*a*b >> 16) - (2*t*Q >> 16)) / 2`
/// = `(a*b - t*Q) >> 16`, which is exactly Montgomery reduction.
#[inline(always)]
unsafe fn fqmul_neon(a: int16x8_t, b: int16x8_t) -> int16x8_t {
    let ab_lo = vmulq_s16(a, b); // a*b mod 2^16
    let ab_hi = vqdmulhq_s16(a, b); // (2*a*b) >> 16
    let qinv = vdupq_n_s16(QINV_I16);
    let q = vdupq_n_s16(Q_I16);
    let t = vmulq_s16(ab_lo, qinv); // ab_lo * QINV mod 2^16
    let tq_hi = vqdmulhq_s16(t, q); // (2*t*Q) >> 16
    vhsubq_s16(ab_hi, tq_hi) // (ab_hi - tq_hi) / 2
}

/// 8-wide Barrett reduction: reduce each lane modulo q to near [-q/2, q/2].
///
/// Barrett constant v = 20159. Computes t = round(a * v / 2^26), then a - t*q.
#[inline(always)]
unsafe fn barrett_reduce_neon(a: int16x8_t) -> int16x8_t {
    // Use widening multiply to avoid overflow: a * 20159 can exceed i16 range
    let v = vdup_n_s16(20159);
    let round = vdupq_n_s32(1 << 25);
    let q = vdupq_n_s16(Q_I16);

    let a_lo = vget_low_s16(a);
    let a_hi = vget_high_s16(a);

    // Widening multiply + rounding: int16x4 * int16x4 -> int32x4
    let prod_lo = vmlal_s16(round, a_lo, v);
    let prod_hi = vmlal_s16(round, a_hi, v);

    // Shift right by 26 (full-width), then narrow to i16
    let t_lo = vmovn_s32(vshrq_n_s32::<26>(prod_lo));
    let t_hi = vmovn_s32(vshrq_n_s32::<26>(prod_hi));
    let t = vcombine_s16(t_lo, t_hi);

    // a - t * q
    vmlsq_s16(a, t, q)
}

/// Forward NTT using NEON (Cooley-Tukey butterflies).
///
/// # Safety
/// Requires the `neon` target feature.
#[target_feature(enable = "neon")]
pub(super) unsafe fn ntt_neon(r: &mut Poly) {
    let mut k: usize = 1;
    let mut len = 128;

    // Stages with len >= 8: process 8 butterflies at a time
    while len >= 8 {
        let mut start = 0;
        while start < N {
            let zeta = vdupq_n_s16(ZETAS[k]);
            k += 1;
            let mut j = start;
            while j < start + len {
                let rj = vld1q_s16(r[j..].as_ptr());
                let rj_len = vld1q_s16(r[j + len..].as_ptr());
                let t = fqmul_neon(zeta, rj_len);
                vst1q_s16(r[j..].as_mut_ptr(), vaddq_s16(rj, t));
                vst1q_s16(r[j + len..].as_mut_ptr(), vsubq_s16(rj, t));
                j += 8;
            }
            start += 2 * len;
        }
        len >>= 1;
    }

    // Stage len=4: each group has 4 top + 4 bottom = 8 elements
    // Load 8 contiguous elements; low half = top, high half = bottom
    {
        let mut start = 0;
        while start < N {
            let zeta = vdupq_n_s16(ZETAS[k]);
            k += 1;
            // Elements: r[start..start+4] (top) and r[start+4..start+8] (bottom)
            let v = vld1q_s16(r[start..].as_ptr());
            let top = vget_low_s16(v);
            let bot = vget_high_s16(v);
            let t_half = fqmul_neon(
                vcombine_s16(vget_low_s16(zeta), vdup_n_s16(0)),
                vcombine_s16(bot, vdup_n_s16(0)),
            );
            let t = vget_low_s16(t_half);
            let new_top = vadd_s16(top, t);
            let new_bot = vsub_s16(top, t);
            vst1q_s16(r[start..].as_mut_ptr(), vcombine_s16(new_top, new_bot));
            start += 8;
        }
    }

    // Stage len=2: each group has 2 top + 2 bottom = 4 elements
    // Process 2 groups at once (8 elements): groups at [start..start+4] and [start+4..start+8]
    {
        let mut start = 0;
        while start < N {
            // Load 8 elements spanning 2 groups
            let v = vld1q_s16(r[start..].as_ptr());
            // Group 1: elements [0,1] top, [2,3] bottom, zeta = ZETAS[k]
            // Group 2: elements [4,5] top, [6,7] bottom, zeta = ZETAS[k+1]
            let z1 = ZETAS[k];
            let z2 = ZETAS[k + 1];
            k += 2;

            // Create zeta vector: [z1, z1, z1, z1, z2, z2, z2, z2]
            // We need to multiply bottom elements by zeta
            // bottom elements are at positions 2,3,6,7
            // top elements are at positions 0,1,4,5

            // Extract elements manually for 2-element groups
            let e0 = vgetq_lane_s16::<0>(v);
            let e1 = vgetq_lane_s16::<1>(v);
            let e2 = vgetq_lane_s16::<2>(v);
            let e3 = vgetq_lane_s16::<3>(v);
            let e4 = vgetq_lane_s16::<4>(v);
            let e5 = vgetq_lane_s16::<5>(v);
            let e6 = vgetq_lane_s16::<6>(v);
            let e7 = vgetq_lane_s16::<7>(v);

            // Group 1: t = fqmul(z1, [e2,e3])
            let t0 = fqmul(z1, e2);
            let t1 = fqmul(z1, e3);
            // Group 2: t = fqmul(z2, [e6,e7])
            let t2 = fqmul(z2, e6);
            let t3 = fqmul(z2, e7);

            // Store back
            let result = [
                e0 + t0,
                e1 + t1,
                e0 - t0,
                e1 - t1,
                e4 + t2,
                e5 + t3,
                e4 - t2,
                e5 - t3,
            ];
            vst1q_s16(r[start..].as_mut_ptr(), vld1q_s16(result.as_ptr()));
            start += 8;
        }
    }
}

/// Inverse NTT using NEON (Gentleman-Sande butterflies).
///
/// # Safety
/// Requires the `neon` target feature.
#[target_feature(enable = "neon")]
pub(super) unsafe fn invntt_neon(r: &mut Poly) {
    let mut k: usize = 127;

    // Stage len=2: process 2 groups at once (8 elements)
    {
        let mut start = 0;
        while start < N {
            let v = vld1q_s16(r[start..].as_ptr());
            let z1 = ZETAS[k];
            let z2 = ZETAS[k - 1];
            k -= 2;

            let e0 = vgetq_lane_s16::<0>(v);
            let e1 = vgetq_lane_s16::<1>(v);
            let e2 = vgetq_lane_s16::<2>(v);
            let e3 = vgetq_lane_s16::<3>(v);
            let e4 = vgetq_lane_s16::<4>(v);
            let e5 = vgetq_lane_s16::<5>(v);
            let e6 = vgetq_lane_s16::<6>(v);
            let e7 = vgetq_lane_s16::<7>(v);

            // GS butterfly: t = r[j]; r[j] = barrett(t + r[j+len]); r[j+len] = fqmul(z, r[j+len] - t)
            // Group 1 (z1): top=[e0,e1], bot=[e2,e3]
            let r0 = barrett_reduce(e0 + e2);
            let r1 = barrett_reduce(e1 + e3);
            let r2 = fqmul(z1, e2 - e0);
            let r3 = fqmul(z1, e3 - e1);
            // Group 2 (z2): top=[e4,e5], bot=[e6,e7]
            let r4 = barrett_reduce(e4 + e6);
            let r5 = barrett_reduce(e5 + e7);
            let r6 = fqmul(z2, e6 - e4);
            let r7 = fqmul(z2, e7 - e5);

            let result = [r0, r1, r2, r3, r4, r5, r6, r7];
            vst1q_s16(r[start..].as_mut_ptr(), vld1q_s16(result.as_ptr()));
            start += 8;
        }
    }

    // Stage len=4: each group has 8 elements (4 top + 4 bottom)
    {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k -= 1;
            let v = vld1q_s16(r[start..].as_ptr());
            let top = vget_low_s16(v);
            let bot = vget_high_s16(v);

            // GS butterfly on half-registers
            let sum = vadd_s16(top, bot);
            let diff = vsub_s16(bot, top);

            // Barrett reduce the sum
            let sum_full = vcombine_s16(sum, vdup_n_s16(0));
            let sum_reduced = barrett_reduce_neon(sum_full);
            let sum_half = vget_low_s16(sum_reduced);

            // fqmul the diff by zeta
            let zeta_v = vcombine_s16(vdup_n_s16(zeta), vdup_n_s16(0));
            let diff_full = vcombine_s16(diff, vdup_n_s16(0));
            let diff_mul = fqmul_neon(zeta_v, diff_full);
            let diff_half = vget_low_s16(diff_mul);

            vst1q_s16(r[start..].as_mut_ptr(), vcombine_s16(sum_half, diff_half));
            start += 8;
        }
    }

    // Stages with len >= 8: process 8 elements at a time
    let mut len = 8;
    while len <= 128 {
        let mut start = 0;
        while start < N {
            let zeta = vdupq_n_s16(ZETAS[k]);
            k = k.wrapping_sub(1);
            let mut j = start;
            while j < start + len {
                let rj = vld1q_s16(r[j..].as_ptr());
                let rj_len = vld1q_s16(r[j + len..].as_ptr());
                let sum = vaddq_s16(rj, rj_len);
                let diff = vsubq_s16(rj_len, rj);
                vst1q_s16(r[j..].as_mut_ptr(), barrett_reduce_neon(sum));
                vst1q_s16(r[j + len..].as_mut_ptr(), fqmul_neon(zeta, diff));
                j += 8;
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    // Normalize by 128^{-1} in Montgomery form
    let f_inv = vdupq_n_s16(F_INV128);
    for i in (0..N).step_by(8) {
        let v = vld1q_s16(r[i..].as_ptr());
        vst1q_s16(r[i..].as_mut_ptr(), fqmul_neon(v, f_inv));
    }
}

/// Vectorized basemul accumulation.
///
/// # Safety
/// Requires the `neon` target feature.
#[target_feature(enable = "neon")]
pub(super) unsafe fn basemul_acc_neon(r: &mut Poly, a: &[Poly], b: &[Poly]) {
    *r = [0i16; N];
    for (ap, bp) in a.iter().zip(b.iter()) {
        let mut t = [0i16; N];
        for i in 0..64 {
            let idx = 4 * i;
            let zeta = ZETAS[64 + i];
            let neg_zeta = -zeta; // wrapping neg is fine for i16 in range

            // Pair 1: basemul(t[idx..idx+2], a[idx..idx+2], b[idx..idx+2], zeta)
            let a0 = ap[idx];
            let a1 = ap[idx + 1];
            let b0 = bp[idx];
            let b1 = bp[idx + 1];
            t[idx] = fqmul(fqmul(a1, b1), zeta) + fqmul(a0, b0);
            t[idx + 1] = fqmul(a0, b1) + fqmul(a1, b0);

            // Pair 2: basemul(t[idx+2..idx+4], a[idx+2..idx+4], b[idx+2..idx+4], -zeta)
            let a2 = ap[idx + 2];
            let a3 = ap[idx + 3];
            let b2 = bp[idx + 2];
            let b3 = bp[idx + 3];
            t[idx + 2] = fqmul(fqmul(a3, b3), neg_zeta) + fqmul(a2, b2);
            t[idx + 3] = fqmul(a2, b3) + fqmul(a3, b2);
        }
        // Accumulate with Barrett reduction — vectorized
        for i in (0..N).step_by(8) {
            let rv = vld1q_s16(r[i..].as_ptr());
            let tv = vld1q_s16(t[i..].as_ptr());
            vst1q_s16(r[i..].as_mut_ptr(), barrett_reduce_neon(vaddq_s16(rv, tv)));
        }
    }
}

/// Vectorized polynomial addition: r = a + b.
///
/// # Safety
/// Requires the `neon` target feature.
#[target_feature(enable = "neon")]
pub(super) unsafe fn poly_add_neon(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in (0..N).step_by(8) {
        let va = vld1q_s16(a[i..].as_ptr());
        let vb = vld1q_s16(b[i..].as_ptr());
        vst1q_s16(r[i..].as_mut_ptr(), vaddq_s16(va, vb));
    }
}

/// Vectorized polynomial subtraction: r = a - b.
///
/// # Safety
/// Requires the `neon` target feature.
#[target_feature(enable = "neon")]
pub(super) unsafe fn poly_sub_neon(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in (0..N).step_by(8) {
        let va = vld1q_s16(a[i..].as_ptr());
        let vb = vld1q_s16(b[i..].as_ptr());
        vst1q_s16(r[i..].as_mut_ptr(), vsubq_s16(va, vb));
    }
}

/// Vectorized conversion to Montgomery form.
///
/// # Safety
/// Requires the `neon` target feature.
#[target_feature(enable = "neon")]
pub(super) unsafe fn to_mont_neon(r: &mut Poly) {
    let r2 = vdupq_n_s16(R2_MOD_Q);
    for i in (0..N).step_by(8) {
        let v = vld1q_s16(r[i..].as_ptr());
        vst1q_s16(r[i..].as_mut_ptr(), fqmul_neon(v, r2));
    }
}

/// Vectorized Barrett reduction of all polynomial coefficients.
///
/// # Safety
/// Requires the `neon` target feature.
#[target_feature(enable = "neon")]
pub(super) unsafe fn reduce_poly_neon(r: &mut Poly) {
    for i in (0..N).step_by(8) {
        let v = vld1q_s16(r[i..].as_ptr());
        vst1q_s16(r[i..].as_mut_ptr(), barrett_reduce_neon(v));
    }
}

/// Expose fqmul_neon for testing.
#[cfg(test)]
#[target_feature(enable = "neon")]
pub(super) unsafe fn fqmul_neon_scalar(a: i16, b: i16) -> i16 {
    let va = vdupq_n_s16(a);
    let vb = vdupq_n_s16(b);
    let result = fqmul_neon(va, vb);
    vgetq_lane_s16::<0>(result)
}

/// Expose barrett_reduce_neon for testing.
#[cfg(test)]
#[target_feature(enable = "neon")]
pub(super) unsafe fn barrett_reduce_neon_scalar(a: i16) -> i16 {
    let va = vdupq_n_s16(a);
    let result = barrett_reduce_neon(va);
    vgetq_lane_s16::<0>(result)
}
