//! XMSS Merkle tree operations (RFC 8391 Section 4).
//!
//! Single-tree XMSS: compute root, sign (WOTS+ + auth path), verify.
//! Multi-tree XMSS-MT: hypertree sign and verify.

use hitls_types::CryptoError;

use super::address::{XmssAdrs, XmssAdrsType};
use super::hash::XmssHasher;
use super::params::{XmssMtParams, XmssParams};
use super::wots;

/// Build the full Merkle tree and return (root, auth_path for leaf_idx).
///
/// auth_path has h * n bytes (one sibling per level).
pub(crate) fn compute_root_with_auth(
    h: &XmssHasher,
    leaf_idx: u32,
    adrs: &mut XmssAdrs,
    p: &XmssParams,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let n = p.n;
    let height = p.h;
    let num_leaves = 1u32 << height;

    // Compute all leaf nodes (WOTS+ public keys)
    let mut nodes: Vec<Vec<u8>> = Vec::with_capacity(num_leaves as usize);
    for i in 0..num_leaves {
        let pk = wots::wots_pk_gen(h, i, adrs, p)?;
        nodes.push(pk);
    }

    // Build tree bottom-up, collecting auth path
    let mut auth_path = Vec::with_capacity(height * n);
    let mut current_idx = leaf_idx;

    for level in 0..height as u32 {
        // Sibling of current_idx
        let sibling_idx = current_idx ^ 1;
        auth_path.extend_from_slice(&nodes[sibling_idx as usize]);

        // Build next level
        let num_nodes = nodes.len() / 2;
        let mut next_level = Vec::with_capacity(num_nodes);
        for j in 0..num_nodes {
            let mut tree_adrs = adrs.clone();
            tree_adrs.set_type(XmssAdrsType::HashTree);
            tree_adrs.set_tree_height(level);
            tree_adrs.set_tree_index(j as u32);

            let parent = h.h(&tree_adrs, &nodes[2 * j], &nodes[2 * j + 1])?;
            next_level.push(parent);
        }
        nodes = next_level;
        current_idx >>= 1;
    }

    Ok((nodes[0].clone(), auth_path))
}

/// Compute just the XMSS tree root (no auth path needed).
pub(crate) fn compute_root(
    h: &XmssHasher,
    adrs: &mut XmssAdrs,
    p: &XmssParams,
) -> Result<Vec<u8>, CryptoError> {
    let height = p.h;
    let num_leaves = 1u32 << height;

    let mut nodes: Vec<Vec<u8>> = Vec::with_capacity(num_leaves as usize);
    for i in 0..num_leaves {
        let pk = wots::wots_pk_gen(h, i, adrs, p)?;
        nodes.push(pk);
    }

    for level in 0..height as u32 {
        let num_nodes = nodes.len() / 2;
        let mut next_level = Vec::with_capacity(num_nodes);
        for j in 0..num_nodes {
            let mut tree_adrs = adrs.clone();
            tree_adrs.set_type(XmssAdrsType::HashTree);
            tree_adrs.set_tree_height(level);
            tree_adrs.set_tree_index(j as u32);

            let parent = h.h(&tree_adrs, &nodes[2 * j], &nodes[2 * j + 1])?;
            next_level.push(parent);
        }
        nodes = next_level;
    }

    Ok(nodes[0].clone())
}

/// XMSS sign: WOTS+ signature + authentication path.
///
/// Returns (signature, root) where signature = WOTS_sig || auth_path.
pub(crate) fn xmss_sign(
    h: &XmssHasher,
    msg: &[u8],
    leaf_idx: u32,
    adrs: &mut XmssAdrs,
    p: &XmssParams,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let n = p.n;

    // WOTS+ signature
    let wots_sig = wots::wots_sign(h, msg, leaf_idx, adrs, p)?;

    // Compute tree root and auth path
    let (root, auth) = compute_root_with_auth(h, leaf_idx, adrs, p)?;

    // Concatenate: WOTS_sig || auth_path
    let mut sig = Vec::with_capacity(p.wots_len * n + p.h * n);
    sig.extend_from_slice(&wots_sig);
    sig.extend_from_slice(&auth);

    Ok((sig, root))
}

/// XMSS verify: recover root from WOTS+ signature + auth path.
///
/// Returns the computed root (caller must compare with expected root).
pub(crate) fn xmss_root_from_sig(
    h: &XmssHasher,
    msg: &[u8],
    sig: &[u8],
    leaf_idx: u32,
    adrs: &mut XmssAdrs,
    p: &XmssParams,
) -> Result<Vec<u8>, CryptoError> {
    let n = p.n;
    let wots_sig_len = p.wots_len * n;

    // Recover WOTS+ public key (leaf node)
    let wots_sig = &sig[..wots_sig_len];
    let leaf = wots::wots_pk_from_sig(h, wots_sig, msg, leaf_idx, adrs, p)?;

    // Climb tree using auth path
    let auth = &sig[wots_sig_len..];
    let mut node = leaf;
    let mut idx = leaf_idx;

    for k in 0..p.h {
        let mut tree_adrs = adrs.clone();
        tree_adrs.set_type(XmssAdrsType::HashTree);
        tree_adrs.set_tree_height(k as u32);
        tree_adrs.set_tree_index(idx >> 1);

        let sibling = &auth[k * n..(k + 1) * n];

        if (idx & 1) == 1 {
            // Right child
            node = h.h(&tree_adrs, sibling, &node)?;
        } else {
            // Left child
            node = h.h(&tree_adrs, &node, sibling)?;
        }
        idx >>= 1;
    }

    Ok(node)
}

/// Create single-layer XmssParams from MT params for use in per-layer operations.
pub(crate) fn layer_params(mt: &XmssMtParams) -> XmssParams {
    XmssParams {
        n: mt.n,
        h: mt.hp,
        wots_len: mt.wots_len,
        sig_bytes: 4 + mt.n + (mt.wots_len + mt.hp) * mt.n,
        padding_len: mt.padding_len,
    }
}

/// XMSS-MT hypertree sign (RFC 8391 Section 4.2.4).
///
/// Signs `msg` (n bytes, already hashed) using the multi-tree structure.
/// Returns the concatenation of d single-tree signatures.
pub(crate) fn hypertree_sign(
    hasher: &XmssHasher,
    msg: &[u8],
    global_idx: u64,
    mt: &XmssMtParams,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let lp = layer_params(mt);
    let hp = mt.hp;
    let d = mt.d;
    let layer_sig_len = (mt.wots_len + hp) * mt.n;

    let mut leaf_idx = (global_idx & ((1u64 << hp) - 1)) as u32;
    let mut tree_idx = global_idx >> hp;

    let mut sig = Vec::with_capacity(d * layer_sig_len);
    let mut current_msg = msg.to_vec();

    for j in 0..d {
        let mut adrs = XmssAdrs::new();
        adrs.set_layer_addr(j as u32);
        adrs.set_tree_addr(tree_idx);

        let (layer_sig, root) = xmss_sign(hasher, &current_msg, leaf_idx, &mut adrs, &lp)?;
        sig.extend_from_slice(&layer_sig);

        current_msg = root;

        if j + 1 < d {
            leaf_idx = (tree_idx & ((1u64 << hp) - 1)) as u32;
            tree_idx >>= hp;
        }
    }

    Ok((sig, current_msg))
}

/// XMSS-MT hypertree verify (RFC 8391 Section 4.2.5).
///
/// Recovers root from multi-tree signature. Caller compares with pk_root via ct_eq.
pub(crate) fn hypertree_verify(
    hasher: &XmssHasher,
    msg: &[u8],
    sig: &[u8],
    global_idx: u64,
    mt: &XmssMtParams,
) -> Result<Vec<u8>, CryptoError> {
    let lp = layer_params(mt);
    let hp = mt.hp;
    let d = mt.d;
    let layer_sig_len = (mt.wots_len + hp) * mt.n;

    let mut leaf_idx = (global_idx & ((1u64 << hp) - 1)) as u32;
    let mut tree_idx = global_idx >> hp;

    let mut current_msg = msg.to_vec();

    for j in 0..d {
        let layer_sig = &sig[j * layer_sig_len..(j + 1) * layer_sig_len];

        let mut adrs = XmssAdrs::new();
        adrs.set_layer_addr(j as u32);
        adrs.set_tree_addr(tree_idx);

        let node = xmss_root_from_sig(hasher, &current_msg, layer_sig, leaf_idx, &mut adrs, &lp)?;
        current_msg = node;

        if j + 1 < d {
            leaf_idx = (tree_idx & ((1u64 << hp) - 1)) as u32;
            tree_idx >>= hp;
        }
    }

    Ok(current_msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xmss::address::XmssAdrs;
    use crate::xmss::hash::XmssHasher;
    use crate::xmss::params::{get_params, XmssHashMode};
    use hitls_types::XmssParamId;

    fn make_hasher() -> XmssHasher {
        XmssHasher {
            n: 32,
            padding_len: 32,
            mode: XmssHashMode::Shake256,
            sk_seed: vec![0xAAu8; 32],
            pk_seed: vec![0xBBu8; 32],
        }
    }

    fn test_params() -> XmssParams {
        get_params(XmssParamId::Shake256_10_256)
    }

    #[test]
    fn test_compute_root_deterministic() {
        let h = make_hasher();
        let p = test_params();
        let mut adrs1 = XmssAdrs::new();
        let mut adrs2 = XmssAdrs::new();
        let root1 = compute_root(&h, &mut adrs1, &p).unwrap();
        let root2 = compute_root(&h, &mut adrs2, &p).unwrap();
        assert_eq!(root1, root2);
        assert_eq!(root1.len(), p.n);
    }

    #[test]
    fn test_compute_root_with_auth_path_length() {
        let h = make_hasher();
        let p = test_params();
        let mut adrs = XmssAdrs::new();
        let (root, auth) = compute_root_with_auth(&h, 0, &mut adrs, &p).unwrap();
        assert_eq!(root.len(), p.n);
        assert_eq!(auth.len(), p.h * p.n);
    }

    #[test]
    fn test_compute_root_with_auth_matches_compute_root() {
        let h = make_hasher();
        let p = test_params();
        let mut adrs1 = XmssAdrs::new();
        let mut adrs2 = XmssAdrs::new();
        let root1 = compute_root(&h, &mut adrs1, &p).unwrap();
        let (root2, _) = compute_root_with_auth(&h, 5, &mut adrs2, &p).unwrap();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_xmss_sign_signature_length() {
        let h = make_hasher();
        let p = test_params();
        let msg = vec![0x42u8; p.n];
        let mut adrs = XmssAdrs::new();
        let (sig, root) = xmss_sign(&h, &msg, 0, &mut adrs, &p).unwrap();
        assert_eq!(sig.len(), (p.wots_len + p.h) * p.n);
        assert_eq!(root.len(), p.n);
    }

    #[test]
    fn test_xmss_sign_verify_roundtrip() {
        let h = make_hasher();
        let p = test_params();
        let msg = vec![0x42u8; p.n];
        let leaf_idx = 3;
        let mut adrs1 = XmssAdrs::new();
        let (sig, root) = xmss_sign(&h, &msg, leaf_idx, &mut adrs1, &p).unwrap();
        let mut adrs2 = XmssAdrs::new();
        let recovered = xmss_root_from_sig(&h, &msg, &sig, leaf_idx, &mut adrs2, &p).unwrap();
        assert_eq!(root, recovered);
    }
}
