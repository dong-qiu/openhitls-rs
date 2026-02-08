//! Benes network control bits for Classic McEliece.
//!
//! Generates control bits from a permutation and applies the Benes
//! network to reconstruct the support ordering.

use hitls_types::CryptoError;

use super::gf::GfElement;

/// Compute control bits for a Benes network from permutation pi of size n=2^w.
pub(crate) fn cbits_from_perm(pi: &[i16], w: usize, n: usize) -> Result<Vec<u8>, CryptoError> {
    let out_bits = (2 * w - 1) * n / 2;
    let out_bytes = out_bits.div_ceil(8);
    let mut out = vec![0u8; out_bytes];
    let mut temp = vec![0i32; 2 * n];
    benes_controlbits(&mut out, 0, 1, pi, w as u32, n as u32, &mut temp)?;
    Ok(out)
}

/// Reconstruct support L[0..len_n-1] from control bits.
#[allow(clippy::needless_range_loop)]
pub(crate) fn support_from_cbits(
    cbits: &[u8],
    w: usize,
    len_n: usize,
) -> Result<Vec<GfElement>, CryptoError> {
    let n = 1usize << w;
    let layer_bytes = n >> 4; // (n/2) bits per layer → n/16 bytes (requires n >= 16)
    let plane_bytes = n >> 3; // n bits → n/8 bytes

    // Allocate bit planes
    let mut planes: Vec<Vec<u8>> = (0..w).map(|_| vec![0u8; plane_bytes]).collect();

    // Initialize with bit-reversed values
    for i in 0..n {
        let br = bitrev(i as u16, w);
        for b in 0..w {
            if (br >> b) & 1 != 0 {
                set_bit_in_vec(&mut planes[b], i, 1);
            }
        }
    }

    // Apply Benes layers
    let mut ptr = 0;
    // Forward layers 0..w-1
    for s in 0..w {
        let layer = &cbits[ptr..ptr + layer_bytes];
        for b in 0..w {
            layer_bits(&mut planes[b], layer, s, n);
        }
        ptr += layer_bytes;
    }
    // Backward layers w-2..0
    for s in (0..w - 1).rev() {
        let layer = &cbits[ptr..ptr + layer_bytes];
        for b in 0..w {
            layer_bits(&mut planes[b], layer, s, n);
        }
        ptr += layer_bytes;
    }

    // Reconstruct support
    let mut gf_l = vec![0u16; len_n];
    for j in 0..len_n {
        let mut val: u16 = 0;
        for b in (0..w).rev() {
            val <<= 1;
            val |= get_bit_from_vec(&planes[b], j) as u16;
        }
        gf_l[j] = val;
    }
    Ok(gf_l)
}

/// Apply one Benes layer to a bit-vector using control bits.
fn layer_bits(bitvec: &mut [u8], layer_cbits: &[u8], s: usize, n_bits: usize) {
    let stride = 1usize << s;
    let mut index = 0;
    let mut i = 0;
    while i < n_bits {
        for j in 0..stride {
            let ctrl = (layer_cbits[index >> 3] >> (index & 7)) & 1;
            if ctrl != 0 {
                let a = i + j;
                let b = i + j + stride;
                let ba = get_bit_from_vec(bitvec, a);
                let bb = get_bit_from_vec(bitvec, b);
                set_bit_in_vec(bitvec, a, bb);
                set_bit_in_vec(bitvec, b, ba);
            }
            index += 1;
        }
        i += stride * 2;
    }
}

fn get_bit_from_vec(vec: &[u8], idx: usize) -> u8 {
    (vec[idx >> 3] >> (idx & 7)) & 1
}

fn set_bit_in_vec(vec: &mut [u8], idx: usize, bit: u8) {
    let byte_idx = idx >> 3;
    let mask = 1u8 << (idx & 7);
    if bit != 0 {
        vec[byte_idx] |= mask;
    } else {
        vec[byte_idx] &= !mask;
    }
}

fn bitrev(x: u16, m: usize) -> u16 {
    let mut r: u16 = 0;
    for j in 0..m {
        r = (r << 1) | ((x >> j) & 1);
    }
    r & ((1u16 << m) - 1)
}

/// Write a single bit in little-endian bit order.
fn write_1bit_le(buf: &mut [u8], bit_pos: u32, bit: u8) {
    buf[(bit_pos >> 3) as usize] ^= bit << (bit_pos & 7);
}

/// Recursive Benes network control bit generator.
#[allow(clippy::needless_range_loop)]
fn benes_controlbits(
    out: &mut [u8],
    pos: u32,
    step: u32,
    pi: &[i16],
    w: u32,
    n: u32,
    temp: &mut [i32],
) -> Result<(), CryptoError> {
    if w == 1 {
        write_1bit_le(out, pos, (pi[0] & 1) as u8);
        return Ok(());
    }

    let nu = n as usize;
    let area_a = unsafe { std::slice::from_raw_parts_mut(temp.as_mut_ptr() as *mut u32, nu) };
    let area_b =
        unsafe { std::slice::from_raw_parts_mut(temp.as_mut_ptr().add(nu) as *mut u32, nu) };

    // Build 32-bit keys
    for i in 0..nu {
        let lo = (pi[i] ^ 1) as u32;
        let hi = pi[i ^ 1] as u32;
        area_a[i] = (lo << 16) | hi;
    }
    sort_u32_le(area_a)?;

    // Extract min index
    for i in 0..nu {
        let px = area_a[i] & 0xFFFF;
        let cx = if px < i as u32 { px } else { i as u32 };
        area_b[i] = (px << 16) | cx;
    }
    sort_u32_le(area_a)?;

    // Tag original index
    for i in 0..nu {
        area_a[i] = (area_a[i] << 16) | i as u32;
    }
    sort_u32_le(area_a)?;

    // Tag parent key
    for i in 0..nu {
        area_a[i] = (area_a[i] << 16) | (area_b[i] >> 16);
    }
    sort_u32_le(area_a)?;

    // Process based on alphabet size
    if w <= 10 {
        process_small_alphabet(area_a, area_b, nu, w)?;
    } else {
        process_large_alphabet(area_a, area_b, nu, w)?;
    }

    // Prepare parent keys
    for i in 0..nu {
        area_a[i] = ((pi[i] as i32 as u32) << 16).wrapping_add(i as u32);
    }
    sort_u32_le(area_a)?;

    // Emit first half
    let mut current_pos = pos;
    for j in 0..nu / 2 {
        let x = 2 * j;
        let fj = (area_b[x] & 1) as u8;
        let tmp_fx = x as u32 + fj as u32;
        let tmp_fx1 = tmp_fx ^ 1;

        write_1bit_le(out, current_pos, fj);
        current_pos += step;

        area_b[x] = (area_a[x] << 16) | tmp_fx;
        area_b[x + 1] = (area_a[x + 1] << 16) | tmp_fx1;
    }
    sort_u32_le(area_b)?;

    current_pos += (2 * w - 3) * step * (n / 2);

    // Emit second half
    for k in 0..nu / 2 {
        let y = 2 * k;
        let lk = (area_b[y] & 1) as u8;
        let tmp_ly = y as u32 + lk as u32;
        let tmp_ly1 = tmp_ly ^ 1;

        write_1bit_le(out, current_pos, lk);
        current_pos += step;

        area_a[y] = (tmp_ly << 16) | (area_b[y] & 0xFFFF);
        area_a[y + 1] = (tmp_ly1 << 16) | (area_b[y + 1] & 0xFFFF);
    }
    sort_u32_le(area_a)?;

    current_pos -= (2 * w - 2) * step * (n / 2);

    // Build child permutations
    let q_len = nu;
    let mut q = vec![0i16; q_len];
    for j in 0..nu / 2 {
        q[j] = ((area_a[2 * j] & 0xFFFF) >> 1) as i16;
        q[j + nu / 2] = ((area_a[2 * j + 1] & 0xFFFF) >> 1) as i16;
    }

    // Recurse
    let mut child_temp = vec![0i32; nu]; // reuse temp space
    benes_controlbits(
        out,
        current_pos,
        step * 2,
        &q[..nu / 2],
        w - 1,
        n / 2,
        &mut child_temp,
    )?;
    benes_controlbits(
        out,
        current_pos + step,
        step * 2,
        &q[nu / 2..],
        w - 1,
        n / 2,
        &mut child_temp,
    )?;

    Ok(())
}

#[allow(clippy::needless_range_loop)]
fn process_small_alphabet(
    area_a: &mut [u32],
    area_b: &mut [u32],
    n: usize,
    w: u32,
) -> Result<(), CryptoError> {
    for i in 0..n {
        area_b[i] = ((area_a[i] & 0x3FF) << 10) | (area_b[i] & 0x3FF);
    }
    for _lvl in 1..(w - 1) {
        for i in 0..n {
            area_a[i] = ((area_b[i] & !0x3FF) << 6) | i as u32;
        }
        sort_u32_le(area_a)?;
        for i in 0..n {
            area_a[i] = (area_a[i] << 20) | (area_b[i] & 0xFFFFF);
        }
        sort_u32_le(area_a)?;
        for i in 0..n {
            let ppcpx = area_a[i] & 0xFFFFF;
            let ppcx = (area_a[i] & 0xFFC00) | (area_b[i] & 0x3FF);
            area_b[i] = if ppcx < ppcpx { ppcx } else { ppcpx };
        }
    }
    for i in 0..n {
        area_b[i] &= 0x3FF;
    }
    Ok(())
}

#[allow(clippy::needless_range_loop)]
fn process_large_alphabet(
    area_a: &mut [u32],
    area_b: &mut [u32],
    n: usize,
    w: u32,
) -> Result<(), CryptoError> {
    for i in 0..n {
        area_b[i] = (area_a[i] << 16) | (area_b[i] & 0xFFFF);
    }
    for lvl in 1..(w - 1) {
        for i in 0..n {
            area_a[i] = (area_b[i] & !0xFFFF) | i as u32;
        }
        sort_u32_le(area_a)?;
        for i in 0..n {
            area_a[i] = (area_a[i] << 16) | (area_b[i] & 0xFFFF);
        }
        if lvl < w - 2 {
            for i in 0..n {
                area_b[i] = (area_a[i] & !0xFFFF) | (area_b[i] >> 16);
            }
            sort_u32_le(area_b)?;
            for i in 0..n {
                area_b[i] = (area_b[i] << 16) | (area_a[i] & 0xFFFF);
            }
        }
        sort_u32_le(area_a)?;
        for i in 0..n {
            let cpx = (area_b[i] & !0xFFFF) | (area_a[i] & 0xFFFF);
            area_b[i] = if area_b[i] < cpx { area_b[i] } else { cpx };
        }
    }
    for i in 0..n {
        area_b[i] &= 0xFFFF;
    }
    Ok(())
}

/// Radix sort for u32 values.
fn sort_u32_le(a: &mut [u32]) -> Result<(), CryptoError> {
    let n = a.len();
    let mut tmp = vec![0u32; n];

    for pass in 0..4u32 {
        let mut cnt = [0usize; 256];
        let shift = pass * 8;
        for &val in a.iter() {
            let key = val ^ 0x80000000; // bias for signed order
            let b = ((key >> shift) & 0xFF) as usize;
            cnt[b] += 1;
        }
        let mut pref = [0usize; 256];
        for r in 1..256 {
            pref[r] = pref[r - 1] + cnt[r - 1];
        }
        for &val in a.iter() {
            let key = val ^ 0x80000000;
            let b = ((key >> shift) & 0xFF) as usize;
            tmp[pref[b]] = val;
            pref[b] += 1;
        }
        a.copy_from_slice(&tmp);
    }
    Ok(())
}
