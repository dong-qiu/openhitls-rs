//! SLH-DSA WOTS+ (Winternitz One-Time Signature) implementation (FIPS 205 Section 5).
//!
//! W=16 (4 bits per digit). wots_len = len_1 + len_2 where len_1 = 2*n, len_2 = 3.

use hitls_types::CryptoError;

use super::address::{Adrs, AdrsType};
use super::hash::SlhHashFunctions;
use super::params::SlhDsaParams;

/// Convert byte array to base-b representation.
/// Each output value is in [0, 2^b - 1].
pub(crate) fn base_b(x: &[u8], b: u32, out_len: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(out_len);
    let mut bit: u32 = 0;
    let mut o: u64 = 0;
    let mut xi: usize = 0;

    for _ in 0..out_len {
        while bit < b && xi < x.len() {
            o = (o << 8) | (x[xi] as u64);
            bit += 8;
            xi += 1;
        }
        bit -= b;
        out.push((o >> bit) as u32);
        o &= (1u64 << bit) - 1;
    }
    out
}

/// Convert message to base-W with checksum (W=16, b=4).
fn msg_to_base_w(msg: &[u8], n: usize) -> Vec<u32> {
    let w: u32 = 16;
    let len_1 = 2 * n;
    let len_2 = 3;

    // Step 1: convert message to base-16 values
    let mut values = base_b(msg, 4, len_1);

    // Step 2: compute checksum
    let mut csum: u32 = 0;
    for &v in &values {
        csum += (w - 1) - v;
    }
    csum <<= 4; // left-shift by log2(w)

    // Step 3: convert checksum to base-16
    let csum_bytes = [(csum >> 8) as u8, (csum & 0xff) as u8];
    let csum_vals = base_b(&csum_bytes, 4, len_2);
    values.extend_from_slice(&csum_vals);

    values
}

/// WOTS+ chain function: apply F `steps` times starting from position `start`.
fn wots_chain(
    h: &dyn SlhHashFunctions,
    x: &[u8],
    start: u32,
    steps: u32,
    adrs: &mut Adrs,
) -> Result<Vec<u8>, CryptoError> {
    let mut tmp = x.to_vec();
    for i in start..start + steps {
        adrs.set_hash_addr(i);
        tmp = h.f(adrs, &tmp)?;
    }
    Ok(tmp)
}

/// Generate WOTS+ public key (compressed via T_l).
pub(crate) fn wots_pk_gen(
    h: &dyn SlhHashFunctions,
    sk_seed: &[u8],
    adrs: &mut Adrs,
    p: &SlhDsaParams,
) -> Result<Vec<u8>, CryptoError> {
    let n = p.n;
    let w = 15u32; // W-1

    // Generate each chain endpoint
    let mut tmp = Vec::with_capacity(p.wots_len * n);
    let mut sk_adrs = adrs.clone();
    sk_adrs.set_type(AdrsType::WotsPrf);
    sk_adrs.copy_key_pair_addr(adrs);

    for i in 0..p.wots_len {
        sk_adrs.set_chain_addr(i as u32);
        let sk_i = h.prf(&sk_adrs, sk_seed)?;

        adrs.set_chain_addr(i as u32);
        let pk_i = wots_chain(h, &sk_i, 0, w, adrs)?;
        tmp.extend_from_slice(&pk_i);
    }

    // Compress with T_l
    let mut pk_adrs = adrs.clone();
    pk_adrs.set_type(AdrsType::WotsPk);
    pk_adrs.copy_key_pair_addr(adrs);
    h.t_l(&pk_adrs, &tmp)
}

/// Generate WOTS+ signature for message `msg` (n bytes).
pub(crate) fn wots_sign(
    h: &dyn SlhHashFunctions,
    msg: &[u8],
    sk_seed: &[u8],
    adrs: &mut Adrs,
    p: &SlhDsaParams,
) -> Result<Vec<u8>, CryptoError> {
    let n = p.n;
    let msgw = msg_to_base_w(msg, n);

    let mut sig = Vec::with_capacity(p.wots_len * n);
    let mut sk_adrs = adrs.clone();
    sk_adrs.set_type(AdrsType::WotsPrf);
    sk_adrs.copy_key_pair_addr(adrs);

    for (i, &mw) in msgw.iter().enumerate().take(p.wots_len) {
        sk_adrs.set_chain_addr(i as u32);
        let sk_i = h.prf(&sk_adrs, sk_seed)?;

        adrs.set_chain_addr(i as u32);
        let sig_i = wots_chain(h, &sk_i, 0, mw, adrs)?;
        sig.extend_from_slice(&sig_i);
    }

    Ok(sig)
}

/// Recover WOTS+ public key from signature and message.
pub(crate) fn wots_pk_from_sig(
    h: &dyn SlhHashFunctions,
    sig: &[u8],
    msg: &[u8],
    adrs: &mut Adrs,
    p: &SlhDsaParams,
) -> Result<Vec<u8>, CryptoError> {
    let n = p.n;
    let w = 15u32; // W-1
    let msgw = msg_to_base_w(msg, n);

    let mut tmp = Vec::with_capacity(p.wots_len * n);

    for i in 0..p.wots_len {
        adrs.set_chain_addr(i as u32);
        let sig_i = &sig[i * n..(i + 1) * n];
        let remaining = w - msgw[i];
        let pk_i = wots_chain(h, sig_i, msgw[i], remaining, adrs)?;
        tmp.extend_from_slice(&pk_i);
    }

    // Compress with T_l
    let mut pk_adrs = adrs.clone();
    pk_adrs.set_type(AdrsType::WotsPk);
    pk_adrs.copy_key_pair_addr(adrs);
    h.t_l(&pk_adrs, &tmp)
}
