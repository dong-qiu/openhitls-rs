//! XMSS Merkle tree operations (RFC 8391 Section 4).
//!
//! Single-tree XMSS: compute root, sign (WOTS+ + auth path), verify.

use hitls_types::CryptoError;

use super::address::{XmssAdrs, XmssAdrsType};
use super::hash::XmssHasher;
use super::params::XmssParams;
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
