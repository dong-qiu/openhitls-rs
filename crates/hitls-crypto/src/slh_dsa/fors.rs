//! SLH-DSA FORS (Forest of Random Subsets) implementation (FIPS 205 Section 8).
//!
//! FORS provides a few-time signature scheme using k trees of height a.

use hitls_types::CryptoError;

use super::address::{Adrs, AdrsType};
use super::hash::SlhHashFunctions;
use super::params::SlhDsaParams;
use super::wots::base_b;

/// Generate FORS private key element for given index.
fn fors_sk_gen(
    h: &dyn SlhHashFunctions,
    sk_seed: &[u8],
    adrs: &Adrs,
    idx: u32,
) -> Result<Vec<u8>, CryptoError> {
    let mut sk_adrs = adrs.clone();
    sk_adrs.set_type(AdrsType::ForsPrf);
    sk_adrs.copy_key_pair_addr(adrs);
    sk_adrs.set_tree_index(idx);
    h.prf(&sk_adrs, sk_seed)
}

/// Compute a FORS tree node recursively.
fn fors_node(
    h: &dyn SlhHashFunctions,
    sk_seed: &[u8],
    idx: u32,
    height: u32,
    adrs: &mut Adrs,
) -> Result<Vec<u8>, CryptoError> {
    if height == 0 {
        // Leaf: F(sk)
        let sk = fors_sk_gen(h, sk_seed, adrs, idx)?;
        adrs.set_tree_height(0);
        adrs.set_tree_index(idx);
        h.f(adrs, &sk)
    } else {
        // Internal node: H(left || right)
        let left = fors_node(h, sk_seed, 2 * idx, height - 1, adrs)?;
        let right = fors_node(h, sk_seed, 2 * idx + 1, height - 1, adrs)?;
        adrs.set_tree_height(height);
        adrs.set_tree_index(idx);
        let mut combined = left;
        combined.extend_from_slice(&right);
        h.h(adrs, &combined)
    }
}

/// Generate FORS signature for message digest `md`.
///
/// Returns signature of size k * (1 + a) * n bytes.
pub(crate) fn fors_sign(
    h: &dyn SlhHashFunctions,
    sk_seed: &[u8],
    md: &[u8],
    adrs: &mut Adrs,
    p: &SlhDsaParams,
) -> Result<Vec<u8>, CryptoError> {
    let n = h.n();
    let a = p.a;
    let k = p.k;

    // Extract k indices from message digest, each a bits wide
    let indices = base_b(md, a as u32, k);

    let mut sig = Vec::with_capacity(k * (1 + a) * n);

    for (i, &idx_val) in indices.iter().enumerate().take(k) {
        let tree_base = (i as u32) << (a as u32); // i * 2^a

        // Private key element
        let sk = fors_sk_gen(h, sk_seed, adrs, idx_val + tree_base)?;
        sig.extend_from_slice(&sk);

        // Authentication path: a sibling nodes
        for j in 0..a {
            let s = (idx_val >> (j as u32)) ^ 1; // sibling index at height j
            let node_idx = ((i as u32) << ((a - j) as u32)) + s;
            let node = fors_node(h, sk_seed, node_idx, j as u32, adrs)?;
            sig.extend_from_slice(&node);
        }
    }

    Ok(sig)
}

/// Recover FORS public key from signature.
pub(crate) fn fors_pk_from_sig(
    h: &dyn SlhHashFunctions,
    sig: &[u8],
    md: &[u8],
    adrs: &mut Adrs,
    p: &SlhDsaParams,
) -> Result<Vec<u8>, CryptoError> {
    let n = h.n();
    let a = p.a;
    let k = p.k;

    let indices = base_b(md, a as u32, k);
    let mut roots = Vec::with_capacity(k * n);

    for (i, &idx_val) in indices.iter().enumerate().take(k) {
        let sig_offset = i * (1 + a) * n;

        // Recover leaf from private key
        let sk = &sig[sig_offset..sig_offset + n];
        adrs.set_tree_height(0);
        adrs.set_tree_index(((i as u32) << (a as u32)) + idx_val);
        let mut node = h.f(adrs, sk)?;

        // Climb tree using auth path
        let auth_base = sig_offset + n;
        for j in 0..a {
            adrs.set_tree_height((j + 1) as u32);
            let sibling = &sig[auth_base + j * n..auth_base + (j + 1) * n];

            if (idx_val >> (j as u32)) & 1 == 1 {
                // Current node is right child
                let tree_idx = (adrs.get_tree_index() - 1) >> 1;
                adrs.set_tree_index(tree_idx);
                let mut combined = sibling.to_vec();
                combined.extend_from_slice(&node);
                node = h.h(adrs, &combined)?;
            } else {
                // Current node is left child
                let tree_idx = adrs.get_tree_index() >> 1;
                adrs.set_tree_index(tree_idx);
                let mut combined = node;
                combined.extend_from_slice(sibling);
                node = h.h(adrs, &combined)?;
            }
        }

        roots.extend_from_slice(&node);
    }

    // Compress all roots via T_l
    let mut fors_pk_adrs = adrs.clone();
    fors_pk_adrs.set_type(AdrsType::ForsRoots);
    fors_pk_adrs.copy_key_pair_addr(adrs);
    h.t_l(&fors_pk_adrs, &roots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slh_dsa::hash::make_hasher;
    use crate::slh_dsa::params::get_params;
    use hitls_types::SlhDsaParamId;

    #[test]
    fn test_fors_sign_pk_recovery() {
        let p = get_params(SlhDsaParamId::Shake128f);
        let pk_seed = vec![0xAAu8; p.n];
        let pk_root = vec![0xBBu8; p.n];
        let sk_seed = vec![0xCCu8; p.n];
        let h = make_hasher(p, &pk_seed, &pk_root);

        // Message digest: m bytes (34 for Shake128f)
        let md = vec![0x42u8; p.m];

        let mut adrs1 = Adrs::new(false);
        adrs1.set_type(AdrsType::ForsTree);
        adrs1.set_key_pair_addr(0);
        let sig = fors_sign(&*h, &sk_seed, &md, &mut adrs1, p).unwrap();

        let mut adrs2 = Adrs::new(false);
        adrs2.set_type(AdrsType::ForsTree);
        adrs2.set_key_pair_addr(0);
        let pk1 = fors_pk_from_sig(&*h, &sig, &md, &mut adrs2, p).unwrap();

        // Repeat with same inputs → determinism
        let mut adrs3 = Adrs::new(false);
        adrs3.set_type(AdrsType::ForsTree);
        adrs3.set_key_pair_addr(0);
        let sig2 = fors_sign(&*h, &sk_seed, &md, &mut adrs3, p).unwrap();

        let mut adrs4 = Adrs::new(false);
        adrs4.set_type(AdrsType::ForsTree);
        adrs4.set_key_pair_addr(0);
        let pk2 = fors_pk_from_sig(&*h, &sig2, &md, &mut adrs4, p).unwrap();

        assert_eq!(pk1, pk2);
        assert_eq!(sig, sig2);
    }
}
