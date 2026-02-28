//! ARMv8.2-A SHA-3 Crypto Extensions accelerated Keccak-f[1600].
//!
//! Uses EOR3, BCAX, and RAX1 instructions for accelerated Keccak permutation.
//! Requires `target_feature = "sha3"` (ARMv8.2-A Crypto Extensions).

#![allow(clippy::too_many_lines, clippy::incompatible_msrv)]

use core::arch::aarch64::*;

/// Round constants for Keccak-f[1600].
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Pack two u64 values into a uint64x2_t vector.
#[inline(always)]
unsafe fn pack(a: u64, b: u64) -> uint64x2_t {
    vcombine_u64(vcreate_u64(a), vcreate_u64(b))
}

/// Extract low lane from uint64x2_t.
#[inline(always)]
unsafe fn lo(v: uint64x2_t) -> u64 {
    vgetq_lane_u64(v, 0)
}

/// Extract high lane from uint64x2_t.
#[inline(always)]
unsafe fn hi(v: uint64x2_t) -> u64 {
    vgetq_lane_u64(v, 1)
}

/// Keccak-f[1600] using ARMv8.2-A SHA-3 Crypto Extensions.
///
/// Uses `veor3q_u64` (EOR3: 3-input XOR), `vbcaxq_u64` (BCAX: bit-clear and XOR),
/// and `vrax1q_u64` (RAX1: rotate-1 and XOR).
///
/// # Safety
/// Requires `sha3` target feature (ARMv8.2-A Crypto Extensions).
#[target_feature(enable = "sha3,neon")]
pub(crate) unsafe fn keccak_f1600_arm(state: &mut [u64; 25]) {
    let s = state;

    for rc in &RC {
        // ── θ (theta) ──
        // c[x] = s[x] ^ s[x+5] ^ s[x+10] ^ s[x+15] ^ s[x+20]
        // Use EOR3 for 3-way XOR: veor3(a,b,c) = a ^ b ^ c
        // 5-way = veor3(veor3(a,b,c), d, e) = 2 EOR3 per column pair

        // Column pairs (0,1) and (2,3)
        let c01 = veor3q_u64(
            veor3q_u64(pack(s[0], s[1]), pack(s[5], s[6]), pack(s[10], s[11])),
            pack(s[15], s[16]),
            pack(s[20], s[21]),
        );
        let c23 = veor3q_u64(
            veor3q_u64(pack(s[2], s[3]), pack(s[7], s[8]), pack(s[12], s[13])),
            pack(s[17], s[18]),
            pack(s[22], s[23]),
        );
        let c0 = lo(c01);
        let c1 = hi(c01);
        let c2 = lo(c23);
        let c3 = hi(c23);
        // Column 4 (scalar: 5-way XOR)
        let c4 = s[4] ^ s[9] ^ s[14] ^ s[19] ^ s[24];

        // d[x] = c[(x+4)%5] ^ rotate_left(c[(x+1)%5], 1)
        // Use RAX1: vrax1(a, b) = a ^ rotate_left(b, 1)
        let d01 = vrax1q_u64(pack(c4, c0), pack(c1, c2));
        let d23 = vrax1q_u64(pack(c1, c2), pack(c3, c4));
        let d4_v = vrax1q_u64(vdupq_n_u64(c3), vdupq_n_u64(c0));
        let d0 = lo(d01);
        let d1 = hi(d01);
        let d2 = lo(d23);
        let d3 = hi(d23);
        let d4 = lo(d4_v);

        // Apply theta: s[i] ^= d[i % 5]
        s[0] ^= d0;
        s[1] ^= d1;
        s[2] ^= d2;
        s[3] ^= d3;
        s[4] ^= d4;
        s[5] ^= d0;
        s[6] ^= d1;
        s[7] ^= d2;
        s[8] ^= d3;
        s[9] ^= d4;
        s[10] ^= d0;
        s[11] ^= d1;
        s[12] ^= d2;
        s[13] ^= d3;
        s[14] ^= d4;
        s[15] ^= d0;
        s[16] ^= d1;
        s[17] ^= d2;
        s[18] ^= d3;
        s[19] ^= d4;
        s[20] ^= d0;
        s[21] ^= d1;
        s[22] ^= d2;
        s[23] ^= d3;
        s[24] ^= d4;

        // ── ρ (rho) + π (pi) ──
        // b[pi(i)] = rotate_left(s[i], ROTATION[i])
        // Each ARM rotate_left is a single ROR instruction.
        let b0 = s[0]; // rot 0
        let b10 = s[1].rotate_left(1);
        let b20 = s[2].rotate_left(62);
        let b5 = s[3].rotate_left(28);
        let b15 = s[4].rotate_left(27);
        let b16 = s[5].rotate_left(36);
        let b1 = s[6].rotate_left(44);
        let b11 = s[7].rotate_left(6);
        let b21 = s[8].rotate_left(55);
        let b6 = s[9].rotate_left(20);
        let b7 = s[10].rotate_left(3);
        let b17 = s[11].rotate_left(10);
        let b2 = s[12].rotate_left(43);
        let b12 = s[13].rotate_left(25);
        let b22 = s[14].rotate_left(39);
        let b23 = s[15].rotate_left(41);
        let b8 = s[16].rotate_left(45);
        let b18 = s[17].rotate_left(15);
        let b3 = s[18].rotate_left(21);
        let b13 = s[19].rotate_left(8);
        let b14 = s[20].rotate_left(18);
        let b24 = s[21].rotate_left(2);
        let b9 = s[22].rotate_left(61);
        let b19 = s[23].rotate_left(56);
        let b4 = s[24].rotate_left(14);

        // ── χ (chi) using BCAX ──
        // s[x+5y] = b[x+5y] ^ (b[(x+2)%5+5y] & ~b[(x+1)%5+5y])
        // BCAX(a, b, c) = a ^ (b & ~c)
        // Process pairs per row: lanes (0,1), (2,3), and lane 4

        // Row 0: lanes 0-4
        let chi_r0_01 = vbcaxq_u64(pack(b0, b1), pack(b2, b3), pack(b1, b2));
        let chi_r0_23 = vbcaxq_u64(pack(b2, b3), pack(b4, b0), pack(b3, b4));
        let chi_r0_4 = vbcaxq_u64(vdupq_n_u64(b4), vdupq_n_u64(b1), vdupq_n_u64(b0));
        s[0] = lo(chi_r0_01);
        s[1] = hi(chi_r0_01);
        s[2] = lo(chi_r0_23);
        s[3] = hi(chi_r0_23);
        s[4] = lo(chi_r0_4);

        // Row 1: lanes 5-9
        let chi_r1_01 = vbcaxq_u64(pack(b5, b6), pack(b7, b8), pack(b6, b7));
        let chi_r1_23 = vbcaxq_u64(pack(b7, b8), pack(b9, b5), pack(b8, b9));
        let chi_r1_4 = vbcaxq_u64(vdupq_n_u64(b9), vdupq_n_u64(b6), vdupq_n_u64(b5));
        s[5] = lo(chi_r1_01);
        s[6] = hi(chi_r1_01);
        s[7] = lo(chi_r1_23);
        s[8] = hi(chi_r1_23);
        s[9] = lo(chi_r1_4);

        // Row 2: lanes 10-14
        let chi_r2_01 = vbcaxq_u64(pack(b10, b11), pack(b12, b13), pack(b11, b12));
        let chi_r2_23 = vbcaxq_u64(pack(b12, b13), pack(b14, b10), pack(b13, b14));
        let chi_r2_4 = vbcaxq_u64(vdupq_n_u64(b14), vdupq_n_u64(b11), vdupq_n_u64(b10));
        s[10] = lo(chi_r2_01);
        s[11] = hi(chi_r2_01);
        s[12] = lo(chi_r2_23);
        s[13] = hi(chi_r2_23);
        s[14] = lo(chi_r2_4);

        // Row 3: lanes 15-19
        let chi_r3_01 = vbcaxq_u64(pack(b15, b16), pack(b17, b18), pack(b16, b17));
        let chi_r3_23 = vbcaxq_u64(pack(b17, b18), pack(b19, b15), pack(b18, b19));
        let chi_r3_4 = vbcaxq_u64(vdupq_n_u64(b19), vdupq_n_u64(b16), vdupq_n_u64(b15));
        s[15] = lo(chi_r3_01);
        s[16] = hi(chi_r3_01);
        s[17] = lo(chi_r3_23);
        s[18] = hi(chi_r3_23);
        s[19] = lo(chi_r3_4);

        // Row 4: lanes 20-24
        let chi_r4_01 = vbcaxq_u64(pack(b20, b21), pack(b22, b23), pack(b21, b22));
        let chi_r4_23 = vbcaxq_u64(pack(b22, b23), pack(b24, b20), pack(b23, b24));
        let chi_r4_4 = vbcaxq_u64(vdupq_n_u64(b24), vdupq_n_u64(b21), vdupq_n_u64(b20));
        s[20] = lo(chi_r4_01);
        s[21] = hi(chi_r4_01);
        s[22] = lo(chi_r4_23);
        s[23] = hi(chi_r4_23);
        s[24] = lo(chi_r4_4);

        // ── ι (iota) ──
        s[0] ^= rc;
    }
}
