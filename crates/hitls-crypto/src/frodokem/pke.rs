//! FrodoKEM inner PKE (CPA-secure public-key encryption).
//!
//! This is the core lattice-based encryption used inside the FO transform.

use hitls_types::CryptoError;

use super::matrix;
use super::params::FrodoParams;
use super::util;

/// PKE public key: (seed_a, b_packed).
/// PKE secret key: S transposed (n_bar × n matrix).
/// PKE key generation.
/// Input: seed_a (16 bytes), seed_se (seed for noise generation).
/// Returns: (pk_b_packed, s_transposed) where:
///   - pk_b_packed is the packed B matrix
///   - s_transposed is S^T (n_bar × n) as u16 values
pub(crate) fn pke_keygen(
    seed_a: &[u8],
    seed_se: &[u8],
    params: &FrodoParams,
) -> Result<(Vec<u8>, Vec<u16>), CryptoError> {
    let n = params.n;
    let n_bar = params.n_bar;
    let q_mask = params.q_mask();

    // Generate noise samples from seed_se
    // r = SHAKE(0x5F || seed_se, 2*(2*n*n_bar) bytes) for S and E
    let r_len = 2 * (2 * n * n_bar);
    let mut shake_input = Vec::with_capacity(1 + seed_se.len());
    shake_input.push(0x5F);
    shake_input.extend_from_slice(seed_se);
    let r = util::shake_hash(&shake_input, &[], r_len, params)?;

    // Sample S (n × n_bar) and E (n × n_bar)
    let s = util::sample_noise(&r[..2 * n * n_bar], n * n_bar, params.cdf_table, q_mask);
    let e = util::sample_noise(
        &r[2 * n * n_bar..],
        n * n_bar,
        params.cdf_table,
        q_mask,
    );

    // B = A·S + E
    let b = matrix::mul_add_as_plus_e(seed_a, &s, &e, params)?;

    // Pack B
    let b_packed = util::pack(&b, params.logq);

    // Transpose S → S^T (n_bar × n)
    let mut s_t = vec![0u16; n_bar * n];
    for i in 0..n {
        for j in 0..n_bar {
            s_t[j * n + i] = s[i * n_bar + j];
        }
    }

    Ok((b_packed, s_t))
}

/// PKE encryption.
/// Inputs: pk = (seed_a, b_packed), seed_se, mu (message to encode).
/// Returns: (c1_packed, c2_packed) ciphertext components.
pub(crate) fn pke_encrypt(
    seed_a: &[u8],
    b_packed: &[u8],
    seed_se: &[u8],
    mu: &[u8],
    params: &FrodoParams,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let n = params.n;
    let n_bar = params.n_bar;
    let q_mask = params.q_mask();

    // Generate noise: r = SHAKE(0x96 || seed_se, 2*(n_bar*n + n_bar*n + n_bar*n_bar))
    let r_len = 2 * (n_bar * n + n_bar * n + n_bar * n_bar);
    let mut shake_input = Vec::with_capacity(1 + seed_se.len());
    shake_input.push(0x96);
    shake_input.extend_from_slice(seed_se);
    let r = util::shake_hash(&shake_input, &[], r_len, params)?;

    // Sample S' (n_bar × n), E' (n_bar × n), E'' (n_bar × n_bar)
    let sp = util::sample_noise(&r[..2 * n_bar * n], n_bar * n, params.cdf_table, q_mask);
    let ep = util::sample_noise(
        &r[2 * n_bar * n..2 * (n_bar * n + n_bar * n)],
        n_bar * n,
        params.cdf_table,
        q_mask,
    );
    let epp = util::sample_noise(
        &r[2 * (n_bar * n + n_bar * n)..],
        n_bar * n_bar,
        params.cdf_table,
        q_mask,
    );

    // C1 = S'·A + E'
    let c1 = matrix::mul_add_sa_plus_e(seed_a, &sp, &ep, params)?;

    // Unpack B from pk
    let b = util::unpack(b_packed, n * n_bar, params.logq);

    // V = S'·B + E''
    let v = matrix::mul_add_sb_plus_e(&sp, &b, &epp, params);

    // Encode mu → matrix
    let mu_encoded = util::encode(mu, params);

    // C2 = V + encode(mu)
    let c2 = matrix::matrix_add(&v, &mu_encoded, q_mask);

    // Pack C1 and C2
    let c1_packed = util::pack(&c1, params.logq);
    let c2_packed = util::pack(&c2, params.logq);

    Ok((c1_packed, c2_packed))
}

/// PKE decryption.
/// Inputs: s_t (secret: S^T, n_bar×n), c1_packed, c2_packed.
/// Returns: decoded message mu.
pub(crate) fn pke_decrypt(
    s_t: &[u16],
    c1_packed: &[u8],
    c2_packed: &[u8],
    params: &FrodoParams,
) -> Vec<u8> {
    let n = params.n;
    let n_bar = params.n_bar;
    let q_mask = params.q_mask();

    // Unpack C1 (n_bar × n) and C2 (n_bar × n_bar)
    let c1 = util::unpack(c1_packed, n_bar * n, params.logq);
    let c2 = util::unpack(c2_packed, n_bar * n_bar, params.logq);

    // M = C2 - S^T · C1^T  (using mul_bs which computes s_t · c1^T)
    let sc1 = matrix::mul_bs(s_t, &c1, params);
    let m = matrix::matrix_sub(&c2, &sc1, q_mask);

    // Decode M → mu
    util::decode(&m, params)
}
