//! FrodoKEM matrix operations: A generation (SHAKE/AES) and matrix arithmetic.

use hitls_types::CryptoError;

use super::params::{FrodoParams, PrgMode};

/// Generate matrix A (n×n) from seed_a using SHAKE128, then compute out = A·s + e.
/// s is n×n_bar, e is n×n_bar. Result out is n×n_bar.
fn gen_a_mul_add_shake(
    seed_a: &[u8],
    s: &[u16],
    e: &[u16],
    params: &FrodoParams,
) -> Result<Vec<u16>, CryptoError> {
    use crate::sha3::Shake128;

    let n = params.n;
    let n_bar = params.n_bar;
    let q_mask = params.q_mask();
    let mut out = vec![0u16; n * n_bar];

    // Copy e into out
    out.copy_from_slice(&e[..n * n_bar]);

    // Generate A row-by-row and accumulate A·s
    // Process 4 rows at a time for efficiency (matching C code)
    for i in (0..n).step_by(4) {
        let rows_this = core::cmp::min(4, n - i);
        // Generate 4 rows of A using SHAKE128(row_index_le16 || seed_a)
        let mut a_rows = vec![0u16; rows_this * n];

        for r in 0..rows_this {
            let row_idx = (i + r) as u16;
            let mut xof = Shake128::new();
            xof.update(&row_idx.to_le_bytes())?;
            xof.update(seed_a)?;
            let row_bytes = xof.squeeze(n * 2)?;
            for j in 0..n {
                a_rows[r * n + j] =
                    u16::from_le_bytes([row_bytes[2 * j], row_bytes[2 * j + 1]]) & q_mask;
            }
        }

        // Multiply: out[i+r][k] += sum_j a_rows[r][j] * s[j][k]
        for r in 0..rows_this {
            for j in 0..n {
                let a_val = a_rows[r * n + j] as u32;
                for k in 0..n_bar {
                    let s_val = s[j * n_bar + k] as u32;
                    out[(i + r) * n_bar + k] = out[(i + r) * n_bar + k]
                        .wrapping_add((a_val.wrapping_mul(s_val)) as u16)
                        & q_mask;
                }
            }
        }
    }

    Ok(out)
}

/// Generate matrix A using AES-128-ECB, then compute out = A·s + e.
fn gen_a_mul_add_aes(
    seed_a: &[u8],
    s: &[u16],
    e: &[u16],
    params: &FrodoParams,
) -> Result<Vec<u16>, CryptoError> {
    use crate::aes::AesKey;

    let n = params.n;
    let n_bar = params.n_bar;
    let q_mask = params.q_mask();
    let mut out = vec![0u16; n * n_bar];
    out.copy_from_slice(&e[..n * n_bar]);

    let cipher = AesKey::new(seed_a)?;

    // Generate A row-by-row using AES-128-ECB with counter blocks
    // Each block: row_le16(2) || col_le16(2) || 0(12) → encrypt → 8 u16 values
    for i in (0..n).step_by(4) {
        let rows_this = core::cmp::min(4, n - i);
        let mut a_rows = vec![0u16; rows_this * n];

        for r in 0..rows_this {
            let row_idx = (i + r) as u16;
            // Each row needs n values, AES produces 8 per block → n/8 blocks
            for j in (0..n).step_by(8) {
                let mut block = [0u8; 16];
                block[0..2].copy_from_slice(&row_idx.to_le_bytes());
                block[2..4].copy_from_slice(&(j as u16).to_le_bytes());
                cipher.encrypt_block(&mut block)?;
                for k in 0..8 {
                    if j + k < n {
                        a_rows[r * n + j + k] =
                            u16::from_le_bytes([block[2 * k], block[2 * k + 1]]) & q_mask;
                    }
                }
            }
        }

        for r in 0..rows_this {
            for j in 0..n {
                let a_val = a_rows[r * n + j] as u32;
                for k in 0..n_bar {
                    let s_val = s[j * n_bar + k] as u32;
                    out[(i + r) * n_bar + k] = out[(i + r) * n_bar + k]
                        .wrapping_add((a_val.wrapping_mul(s_val)) as u16)
                        & q_mask;
                }
            }
        }
    }

    Ok(out)
}

/// Compute B = A·S + E where A is generated from seed_a.
/// S is n×n_bar, E is n×n_bar. Returns B (n×n_bar).
pub(crate) fn mul_add_as_plus_e(
    seed_a: &[u8],
    s: &[u16],
    e: &[u16],
    params: &FrodoParams,
) -> Result<Vec<u16>, CryptoError> {
    match params.prg {
        PrgMode::Shake => gen_a_mul_add_shake(seed_a, s, e, params),
        PrgMode::Aes => gen_a_mul_add_aes(seed_a, s, e, params),
    }
}

/// Compute C1 = S'·A + E' where A is generated from seed_a.
/// S' is n_bar×n, E' is n_bar×n. Returns C1 (n_bar×n).
pub(crate) fn mul_add_sa_plus_e(
    seed_a: &[u8],
    sp: &[u16],
    ep: &[u16],
    params: &FrodoParams,
) -> Result<Vec<u16>, CryptoError> {
    let n = params.n;
    let n_bar = params.n_bar;
    let q_mask = params.q_mask();
    let mut out = vec![0u16; n_bar * n];
    out.copy_from_slice(&ep[..n_bar * n]);

    match params.prg {
        PrgMode::Shake => {
            use crate::sha3::Shake128;
            // Generate A row-by-row, accumulate S'·A
            for i in (0..n).step_by(4) {
                let rows_this = core::cmp::min(4, n - i);
                let mut a_rows = vec![0u16; rows_this * n];

                for r in 0..rows_this {
                    let row_idx = (i + r) as u16;
                    let mut xof = Shake128::new();
                    xof.update(&row_idx.to_le_bytes())?;
                    xof.update(seed_a)?;
                    let row_bytes = xof.squeeze(n * 2)?;
                    for j in 0..n {
                        a_rows[r * n + j] =
                            u16::from_le_bytes([row_bytes[2 * j], row_bytes[2 * j + 1]]) & q_mask;
                    }
                }

                // out[k][j] += S'[k][i+r] * A[i+r][j]
                for r in 0..rows_this {
                    for k in 0..n_bar {
                        let sp_val = sp[k * n + i + r] as u32;
                        for j in 0..n {
                            let a_val = a_rows[r * n + j] as u32;
                            out[k * n + j] = out[k * n + j]
                                .wrapping_add((sp_val.wrapping_mul(a_val)) as u16)
                                & q_mask;
                        }
                    }
                }
            }
        }
        PrgMode::Aes => {
            use crate::aes::AesKey;
            let cipher = AesKey::new(seed_a)?;

            for i in (0..n).step_by(4) {
                let rows_this = core::cmp::min(4, n - i);
                let mut a_rows = vec![0u16; rows_this * n];

                for r in 0..rows_this {
                    let row_idx = (i + r) as u16;
                    for j in (0..n).step_by(8) {
                        let mut block = [0u8; 16];
                        block[0..2].copy_from_slice(&row_idx.to_le_bytes());
                        block[2..4].copy_from_slice(&(j as u16).to_le_bytes());
                        cipher.encrypt_block(&mut block)?;
                        for k in 0..8 {
                            if j + k < n {
                                a_rows[r * n + j + k] =
                                    u16::from_le_bytes([block[2 * k], block[2 * k + 1]]) & q_mask;
                            }
                        }
                    }
                }

                for r in 0..rows_this {
                    for k in 0..n_bar {
                        let sp_val = sp[k * n + i + r] as u32;
                        for j in 0..n {
                            let a_val = a_rows[r * n + j] as u32;
                            out[k * n + j] = out[k * n + j]
                                .wrapping_add((sp_val.wrapping_mul(a_val)) as u16)
                                & q_mask;
                        }
                    }
                }
            }
        }
    }

    Ok(out)
}

/// Compute V = S'·B + E'' where B is n×n_bar, S' is n_bar×n.
/// E'' is n_bar×n_bar. Returns V (n_bar×n_bar).
pub(crate) fn mul_add_sb_plus_e(
    sp: &[u16],
    b: &[u16],
    epp: &[u16],
    params: &FrodoParams,
) -> Vec<u16> {
    let n = params.n;
    let n_bar = params.n_bar;
    let q_mask = params.q_mask();
    let mut out = vec![0u16; n_bar * n_bar];
    out.copy_from_slice(&epp[..n_bar * n_bar]);

    // V = S'(n_bar×n) · B(n×n_bar) + E''(n_bar×n_bar)
    for i in 0..n_bar {
        for j in 0..n {
            let sp_val = sp[i * n + j] as u32;
            for k in 0..n_bar {
                let b_val = b[j * n_bar + k] as u32;
                out[i * n_bar + k] = out[i * n_bar + k]
                    .wrapping_add((sp_val.wrapping_mul(b_val)) as u16)
                    & q_mask;
            }
        }
    }
    out
}

/// Compute M = V - S^T · C1, where S is n×n_bar (stored as S^T: n_bar×n in sk),
/// C1 is n_bar×n. Returns M (n_bar×n_bar).
pub(crate) fn mul_bs(s_t: &[u16], c1: &[u16], params: &FrodoParams) -> Vec<u16> {
    let n = params.n;
    let n_bar = params.n_bar;
    let q_mask = params.q_mask();

    // S^T is n_bar×n, C1 is n_bar×n
    // We need S^T^T · C1^T ... actually:
    // M = C2 - S · C1 where S is n_bar×n (transposed form)
    // The sk stores S transposed. So s_t[i*n+j] = S^T[i][j] = S[j][i]
    // We need S · C1 where S is n×n_bar (original), but we compute from S^T:
    // Actually in the C code: mul_bs computes B·s where B is n_bar×n and s is n×n_bar
    // Here: s_t is the transposed secret (n_bar×n), c1 is n_bar×n
    // Result = s_t^T · c1^T ... Let me follow the C code exactly.
    //
    // C code does: out[i][j] = sum_k s_t[k][i] * c1[k][j] for S^T × C1 pattern
    // s_t is n_bar×n stored row-major, c1 is n_bar×n stored row-major
    // We want: result[i][j] = sum_k s_t[i][k] * c1_transposed... no.
    //
    // Actually the formula is simpler. The decryption needs:
    // M = C2 - S·C1 where S (n_bar×n) is s_t, C1 is (n_bar×n)
    // Wait, in FrodoKEM: S is n×n_bar, C1 is n_bar×n
    // So S^T is n_bar×n, and S^T · C1^T doesn't make sense dimensionally.
    //
    // Let me re-read: C1 is n_bar×n, S is n×n_bar
    // We need: S^T(n_bar×n) × C1^T(n×n_bar) = result(n_bar×n_bar)
    // Or equivalently: (C1 × S)^T ... but we can compute directly:
    // result[i][j] = sum_k s_t[i][k] * c1_col_j[k]
    // where s_t is n_bar×n, and we need c1 columns
    //
    // Actually in the C code mul_bs: result = s * b where
    // s is n_bar×n, b is n_bar×n → doesn't match...
    //
    // Let me just implement: result[i][j] = sum_k s_t[i][k] * c1[k_row][j_col]
    // where c1 is treated as... c1 has n_bar rows and n columns.
    // s_t has n_bar rows and n columns.
    // We want result = s_t · c1^T? That's (n_bar×n) · (n×n_bar) = (n_bar×n_bar). Yes!

    let mut result = vec![0u16; n_bar * n_bar];

    // result[i][j] = sum_k c1[i][k] * s_t[j][k]
    // = sum_k C1[i][k] * S^T[j][k] = sum_k C1[i][k] * S[k][j] = (C1 · S)[i][j]
    for i in 0..n_bar {
        for j in 0..n_bar {
            let mut sum = 0u32;
            for k in 0..n {
                sum = sum.wrapping_add(
                    (c1[i * n + k] as u32).wrapping_mul(s_t[j * n + k] as u32),
                );
            }
            result[i * n_bar + j] = (sum as u16) & q_mask;
        }
    }
    result
}

/// Add two matrices element-wise mod q.
pub(crate) fn matrix_add(a: &[u16], b: &[u16], q_mask: u16) -> Vec<u16> {
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| x.wrapping_add(y) & q_mask)
        .collect()
}

/// Subtract two matrices element-wise mod q: a - b.
pub(crate) fn matrix_sub(a: &[u16], b: &[u16], q_mask: u16) -> Vec<u16> {
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| x.wrapping_sub(y) & q_mask)
        .collect()
}
